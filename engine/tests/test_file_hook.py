"""File requests in the core (validation.md H-03, H-07, H-08, H-10, H-19, H-20, H-21; the core's side of H-09; plan
engine-v3-n16-file-read 2.3a).

The test plays the file worker on the worker end of a socketpair (the file judgment port, SPEC link H): FILE_ASK goes
out with the kernel's own credential (the test's uid, registered as the worker uid), FILE_ALLOW comes back with the
opened target as its one descriptor. The hook is the one of test_hook (the in-process FakePdp, a fake management port)
with the real library's w2_open_beneath as its opener.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import select
import socket
import stat
import threading
import time

import pytest

from conftest import OVERFLOWUID, settled_fds as open_fds
from connector import canonical as c
from engine import fileobjects as fo
from engine.fileport import FilePort
from engine.hook import VERDICT_ALLOW_CELL, VERDICT_ALLOW_ONCE, VERDICT_DENY_CELL, VERDICT_DENY_ONCE
from engine.workspaces import Approval, EntryState, KeyKind, make_entry
from test_hook import Harness, judge_frame, memfd, recv_frame, send

DIR, FILE = c.FILE_TYPE_DIR, c.FILE_TYPE_FILE
READ_OP, LIST_OP, OBJECTS_OP = c.FILE_OP_READ, c.FILE_OP_LIST, c.FILE_OP_OBJECTS
READ, LIST = c.FILE_OPS_READ, c.FILE_OPS_LIST
MODES = {'allow': (1, 1), 'ask': (1, 2), 'deny': (2, 1)}
R = {name: code for code, name in enumerate(c.FILE_REASONS, 1)}
CONTENT = b'line one\nMARKER-A-7f3c\n'


class FileHarness(Harness):
    def __init__(self, tmp_path: Path, native, evidence: str | None = None) -> None:
        super().__init__(tmp_path, native, evidence)
        self.opened: list[tuple[bytes, int]] = []
        real = native.open_beneath

        def opener(dirfd: int, path: bytes, want: int) -> int:
            self.opened.append((path, want))
            return real(dirfd, path, want)

        self.hook.opener = opener
        self.host = tmp_path / 'host'
        (self.host / 'sub').mkdir(parents=True)
        (self.host / 'notes.txt').write_bytes(CONTENT)
        (self.host / 'sub' / 'MARKER-NAME-91d0.txt').write_bytes(b'x')
        (tmp_path / 'outside').mkdir()
        (tmp_path / 'outside' / 'secret').write_bytes(b'MARKER-B-outside')
        (self.host / 'escape').symlink_to(tmp_path / 'outside' / 'secret')
        self.file_rows: dict[str, tuple[FilePort, socket.socket]] = {}

    def file_row(self, i: int = 0, transfer: str = '', policy_context: bytes = b'', workspace: str = 'work0') -> tuple:
        ex, conn = self.row(i, workspace=workspace, transfer=transfer, policy_context=policy_context)
        _, port, _ = self.rows[ex.execution_id]
        core_end, worker_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        core_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        fport = FilePort(self.loop, self.native, ex, core_end, os.getuid(), OVERFLOWUID, self.hook,
                         lambda row, why: self.faults.append((row.execution_id, why)), self.recorder.diagnostic)
        self.hook.register(ex, port, fport)
        self.file_rows[ex.execution_id] = (fport, worker_end)
        worker_end.settimeout(2)
        return ex, conn, worker_end

    def obj(self, alias: str, path, type_: int = DIR, ops: int = READ | LIST, mode: str = 'allow'):
        return self.tables.register_object('work0', alias, str(path), type_, ops, *MODES[mode])

    def close(self) -> None:
        """The anchors and the record writer's pipe are plain descriptors: released here, not left to the end of the
        run (the suite would run out of descriptors)."""
        for fport, worker in self.file_rows.values():
            fport.close()
            worker.close()
        self.tables.close()
        self.recorder.close()


def ask(seq: int, uid: int, op: int, alias: bytes = b'', path: bytes = b'', start: int = 0, length: int = 0) -> bytes:
    return c.pack_frame(c.FILE_ASK, [c.u64(seq), c.u32(uid), c.u8(op), alias, path, c.u64(start), c.u32(length)])


def read(seq: int, ex, alias: bytes = b'notes', path: bytes = b'notes.txt', start: int = 0, length: int = 4096) -> bytes:
    return ask(seq, ex.lease.uid, READ_OP, alias, path, start, length)


def recv_file(sock: socket.socket) -> tuple[int, list[bytes], list[int]]:
    head, fds, _, _ = socket.recv_fds(sock, 4, 2, socket.MSG_WAITALL)
    body = b''
    while len(body) < int.from_bytes(head, 'big'):
        chunk, more, _, _ = socket.recv_fds(sock, int.from_bytes(head, 'big') - len(body), 2)
        body, fds = body + chunk, fds + more
    return body[0], c.unpack_payload(body[0], body[1:]), fds


def silent(sock: socket.socket, s: float = 0.2) -> bool:
    r, _, _ = select.select([sock], [], [], s)
    return not r


def denied(h: FileHarness, worker: socket.socket, seq: int, word: str) -> None:
    h.pump()
    kind, fields, fds = recv_file(worker)
    assert (kind, c.read_uint(fields[0], 8), c.FILE_REASONS[c.read_uint(fields[1], 1) - 1], fds) == \
        (c.FILE_DENY, seq, word, [])


def allowed(h: FileHarness, worker: socket.socket, seq: int, op: int = READ_OP) -> int:
    h.pump()
    kind, fields, fds = recv_file(worker)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1), len(fds)) == (c.FILE_ALLOW, seq, op, 1)
    return fds[0]


def decided(h: FileHarness) -> list[tuple[str, str]]:
    return [(e['outcome'], e['reason_code']) for e in h.events('request_decided')]


def fds_naming(path: Path) -> list[str]:
    out = []
    for name in os.listdir('/proc/self/fd'):
        try:
            if os.readlink(f'/proc/self/fd/{name}') == str(path):
                out.append(name)
        except OSError:
            pass
    return out


@pytest.fixture
def h(native, tmp_path: Path):
    harness = FileHarness(tmp_path, native)
    yield harness
    harness.close()


# ---- the allowed path (H-07, H-08, H-20) ---------------------------------------------------------------------------------
def test_a_read_goes_through_the_pdp_and_the_fd_is_the_file(h: FileHarness) -> None:
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex))
    fd = allowed(h, worker, 1)
    assert os.pread(fd, 4096, 0) == CONTENT and os.fstat(fd).st_ino == os.stat(h.host / 'notes.txt').st_ino
    os.close(fd)
    assert fds_naming(h.host / 'notes.txt') == []                     # H-08: the core keeps no target descriptor
    [f] = h.pdp.requests
    assert len(f) == c.FIELD_COUNT[c.PDP_REQUEST] == 28 and f[21] == b''
    assert (c.read_uint(f[16], 1), f[17]) == (c.KEY_KIND_FILE, b'notes')
    assert (c.read_uint(f[22], 1), f[23], f[24], c.read_uint(f[25], 8), c.read_uint(f[26], 8)) == \
        (READ_OP, b'notes', b'notes.txt', 0, 4096)
    assert c.unpack_list(f[27]) == [str(h.host).encode(), c.u8(DIR), c.u8(READ | LIST)]
    assert f[5:16] == [b'', b'', b'', c.u16(0), b'', b'', c.pack_list([]), c.pack_list([]), b'', c.pack_list([]), c.u64(0)]
    assert decided(h) == [('allow', 'recorded_allow')]
    assert h.events('request_decided')[0]['detail']['actual_length'] == len(CONTENT)
    assert not h.faults


def test_a_list_hands_over_the_directory(h: FileHarness) -> None:
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    worker.sendall(ask(1, ex.lease.uid, LIST_OP, b'notes', b'', 0, 0))
    fd = allowed(h, worker, 1, LIST_OP)
    assert stat.S_ISDIR(os.fstat(fd).st_mode) and sorted(e.name for e in os.scandir(fd)) == sorted(os.listdir(h.host))
    os.close(fd)
    worker.sendall(ask(2, ex.lease.uid, LIST_OP, b'notes', b'sub', 7, 0))
    fd = allowed(h, worker, 2, LIST_OP)
    assert os.fstat(fd).st_ino == os.stat(h.host / 'sub').st_ino
    os.close(fd)
    allow = h.events('request_decided')[-1]['detail']
    assert allow['start'] == 7 and 'actual_length' not in allow


# ---- the first checkpoint: every refusal recorded, none reaches the PDP (H-07) ----------------------------------------
@pytest.mark.parametrize('case,word', [
    ('unknown_alias', 'not_registered'), ('alias_grammar', 'not_registered'), ('alias_too_long', 'not_registered'),
    ('object_unavailable', 'unavailable'), ('recorded_deny', 'recorded_deny'), ('op_not_granted', 'op_not_granted'),
    ('dotdot', 'bad_path'), ('absolute', 'bad_path'), ('empty_segment', 'bad_path'), ('trailing_slash', 'bad_path'),
    ('dot', 'bad_path'), ('nul', 'bad_path'), ('path_4097', 'bad_path'), ('file_object_with_path', 'bad_path'),
    ('too_large', 'too_large'), ('zero_length', 'too_large'), ('transfer_row', 'not_registered'),
    ('workspace_unavailable', 'unavailable')])
def test_each_first_checkpoint_refusal_is_recorded_and_never_asked(h: FileHarness, case: str, word: str) -> None:
    h.obj('notes', h.host)
    h.obj('ro', h.host, DIR, READ)
    h.obj('gone', h.host / 'sub')
    h.obj('no', h.host, mode='deny')
    h.obj('one', h.host / 'notes.txt', FILE, READ)
    h.tables.tables['work0'].unavailable_objects.add('gone')
    ex, conn, worker = h.file_row(transfer='push' if case == 'transfer_row' else '')
    if case == 'workspace_unavailable':
        h.tables.tables['work0'].unavailable = True
    alias, op, path, length = {
        'unknown_alias': (b'nope', READ_OP, b'notes.txt', 10), 'alias_grammar': (b'no/tes', READ_OP, b'', 10),
        'alias_too_long': (b'x' * 65, READ_OP, b'', 10), 'object_unavailable': (b'gone', READ_OP, b'x', 10),
        'recorded_deny': (b'no', READ_OP, b'notes.txt', 10), 'op_not_granted': (b'ro', LIST_OP, b'', 0),
        'dotdot': (b'notes', READ_OP, b'../outside/secret', 10), 'absolute': (b'notes', READ_OP, b'/etc/hostname', 10),
        'empty_segment': (b'notes', READ_OP, b'sub//x', 10), 'trailing_slash': (b'notes', LIST_OP, b'sub/', 0),
        'dot': (b'notes', LIST_OP, b'.', 0), 'nul': (b'notes', READ_OP, b'notes.txt\x00', 10),
        'path_4097': (b'notes', READ_OP, b'x' * 4097, 10), 'file_object_with_path': (b'one', READ_OP, b'x', 10),
        'too_large': (b'notes', READ_OP, b'notes.txt', 262145), 'zero_length': (b'notes', READ_OP, b'notes.txt', 0),
        'transfer_row': (b'notes', READ_OP, b'notes.txt', 10),
        'workspace_unavailable': (b'notes', READ_OP, b'notes.txt', 10)}[case]
    worker.sendall(ask(1, ex.lease.uid, op, alias, path, 0, length))
    denied(h, worker, 1, word)
    assert h.pdp.requests == [] and h.opened == [] and h.admin.questions == []
    [d] = h.events('request_decided')
    assert d['outcome'] == 'deny' and d['detail']['deny_reason'] == R[word] and d['detail']['deny_word'] == word
    assert not h.faults


def test_the_limits_are_inclusive(h: FileHarness) -> None:
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex, length=262144))
    os.close(allowed(h, worker, 1))
    deep = b'/'.join([b'd'] * 2047) + b'/xx'                          # 4096 bytes: passes the rule and goes to the PDP
    assert len(deep) == 4096
    worker.sendall(read(2, ex, path=deep))
    denied(h, worker, 2, 'bad_path')                                  # the kernel's PATH_MAX counts the NUL
    assert len(h.pdp.requests) == 2 and h.events('request_decided')[-1]['detail']['errno'] == 'ENAMETOOLONG'


# ---- after the PDP: the open (H-10, H-11) ------------------------------------------------------------------------------
@pytest.mark.parametrize('case,word', [('symlink_out', 'outside_or_symlink'), ('symlink_in', 'outside_or_symlink'),
                                       ('symlink_mid', 'outside_or_symlink'), ('missing', 'not_found'),
                                       ('read_dir', 'wrong_type'), ('fifo', 'wrong_type'), ('list_file', 'wrong_type'),
                                       ('missing_mid', 'not_found')])
def test_an_open_refused_after_the_pdp_allowed_leaves_only_a_deny_record(h: FileHarness, case: str, word: str) -> None:
    (h.host / 'inner').symlink_to('notes.txt')
    (h.host / 'via').symlink_to('sub')
    os.mkfifo(h.host / 'fifo')
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    op, path = {'symlink_out': (READ_OP, b'escape'), 'symlink_in': (READ_OP, b'inner'),
                'symlink_mid': (READ_OP, b'via/MARKER-NAME-91d0.txt'), 'missing': (READ_OP, b'nope'),
                'read_dir': (READ_OP, b'sub'), 'fifo': (READ_OP, b'fifo'), 'list_file': (LIST_OP, b'notes.txt'),
                'missing_mid': (READ_OP, b'nope/x')}[case]
    fds = open_fds()
    started = time.monotonic()
    worker.sendall(ask(1, ex.lease.uid, op, b'notes', path, 0, 10 if op == READ_OP else 0))
    denied(h, worker, 1, word)
    assert time.monotonic() - started < 2 and len(h.pdp.requests) == 1 and len(h.opened) == 1
    assert decided(h) == [('deny', 'open_failed')] and 'errno' in h.events('request_decided')[0]['detail']
    assert open_fds() == fds


def test_a_file_swapped_for_an_outside_symlink_after_registration_is_refused(h: FileHarness) -> None:
    h.obj('one', h.host / 'notes.txt', FILE, READ)
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex, b'one', b''))
    os.close(allowed(h, worker, 1))
    os.unlink(h.host / 'notes.txt')
    (h.host / 'notes.txt').symlink_to(h.host.parent / 'outside' / 'secret')
    worker.sendall(read(2, ex, b'one', b''))
    denied(h, worker, 2, 'outside_or_symlink')


def test_a_file_object_replaced_by_rename_reads_the_new_content(h: FileHarness) -> None:
    """H-03: a file object pins its directory, not the file's own inode."""
    h.obj('one', h.host / 'notes.txt', FILE, READ)
    ex, conn, worker = h.file_row()
    (h.host / 'new.txt').write_bytes(b'second version')
    os.rename(h.host / 'new.txt', h.host / 'notes.txt')
    worker.sendall(read(1, ex, b'one', b''))
    fd = allowed(h, worker, 1)
    assert os.pread(fd, 100, 0) == b'second version'
    os.close(fd)


def test_without_a_pdp_a_file_request_waits_and_nothing_is_opened(h: FileHarness) -> None:
    """K-47 for a file request: no PDP, no answer, no open; the core keeps no timer (the worker's total limit
    withdraws it, H-13); a PDP that connects is asked and its allow opens and releases."""
    h.obj('notes', h.host)
    h.pdp.link = None
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex))
    h.pump()
    h.clock.advance(3_600_000)
    h.pump()
    assert silent(worker) and h.pdp.requests == [] and h.opened == []
    h.pdp.link = object()
    h.hook.pdp_connected(h.pdp.link)
    os.close(allowed(h, worker, 1))
    assert len(h.opened) == 1


def test_the_pdp_deny_opens_nothing(h: FileHarness) -> None:
    h.obj('notes', h.host)
    h.pdp.allow = False
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex))
    denied(h, worker, 1, 'pdp_denied')
    assert h.opened == [] and decided(h) == [('deny', 'pdp_denied')]


def test_a_target_deleted_before_the_pdp_answers_gets_only_a_deny_record(h: FileHarness) -> None:
    h.obj('notes', h.host)
    h.pdp.hold = True
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex))
    h.pump()
    os.unlink(h.host / 'notes.txt')
    h.pdp.answer(h.pdp.requests[0])
    denied(h, worker, 1, 'not_found')
    assert decided(h) == [('deny', 'open_failed')]


# ---- restart (H-03) ------------------------------------------------------------------------------------------------------
def test_after_a_restart_an_unavailable_object_is_refused_and_the_rest_works(h: FileHarness) -> None:
    (h.host.parent / 'other').mkdir()
    (h.host.parent / 'other' / 'o.txt').write_bytes(b'other')
    h.obj('a', h.host / 'sub')
    h.obj('b', h.host.parent / 'other')
    os.rename(h.host / 'sub', h.host / 'sub-old')
    (h.host / 'sub').mkdir()
    h.tables.load()                                                   # the engine starts again on the same mirrors
    assert h.tables.tables['work0'].unavailable_objects == {'a'}
    ex, conn, worker = h.file_row()
    worker.sendall(ask(1, ex.lease.uid, LIST_OP, b'a', b'', 0, 0))
    denied(h, worker, 1, 'unavailable')
    worker.sendall(read(2, ex, b'b', b'o.txt'))
    os.close(allowed(h, worker, 2))
    send(conn, judge_frame(1, ex.lease.uid, host=b'unknown.example'), memfd(b''))     # the fallback GET still works
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED


# ---- asking the user (H-07 step 2, H-09 on the hook's side) ------------------------------------------------------------
def test_ask_every_time_and_the_four_answers_act_on_the_object(h: FileHarness) -> None:
    h.obj('notes', h.host, mode='ask')
    h.obj('two', h.host / 'sub', mode='ask')
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex))
    h.pump()
    q = h.admin.questions[-1]
    assert q[5] == 1 and q[9].alias == 'notes' and q[6] == -1          # the object, and no memfd
    assert h.hook.answer(q[0], VERDICT_ALLOW_ONCE) == (None, b'')
    os.close(allowed(h, worker, 1))
    worker.sendall(read(2, ex))
    h.pump()
    assert h.hook.answer(h.admin.questions[-1][0], VERDICT_DENY_ONCE) == (None, b'')
    denied(h, worker, 2, 'user_denied')
    worker.sendall(read(3, ex))
    h.pump()
    assert h.hook.answer(h.admin.questions[-1][0], VERDICT_ALLOW_CELL) == (None, b'persisted')
    os.close(allowed(h, worker, 3))
    assert h.tables.tables['work0'].objects['notes'].approval is Approval.NEVER
    worker.sendall(read(4, ex))
    os.close(allowed(h, worker, 4))
    assert len(h.admin.questions) == 3                                # no more questions on that object
    worker.sendall(ask(5, ex.lease.uid, LIST_OP, b'two', b'', 0, 0))
    h.pump()
    assert h.hook.answer(h.admin.questions[-1][0], VERDICT_DENY_CELL) == (None, b'persisted')
    denied(h, worker, 5, 'user_denied')
    two = h.tables.tables['work0'].objects['two']
    assert (two.state, two.dir_path, two.ops) == (EntryState.DENY, str(h.host / 'sub'), READ | LIST)
    worker.sendall(ask(6, ex.lease.uid, LIST_OP, b'two', b'', 0, 0))
    denied(h, worker, 6, 'recorded_deny')
    assert [e['detail']['matched_key_kind'] for e in h.events('question_asked')] == [c.KEY_KIND_FILE] * 4


@pytest.mark.parametrize('change', ['re_registered', 'ops', 'other_dir', 'deleted'])
def test_a_change_to_the_object_while_asked_voids_the_answer(h: FileHarness, change: str) -> None:
    h.obj('notes', h.host, mode='ask')
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex))
    h.pump()
    if change == 're_registered':
        h.obj('notes', h.host, mode='ask')                            # the same five items: still a change
    elif change == 'ops':
        h.obj('notes', h.host, DIR, READ, mode='ask')
    elif change == 'other_dir':
        h.obj('notes', h.host / 'sub', mode='ask')
    else:
        h.tables.delete_object('work0', 'notes')
    assert h.hook.answer(h.admin.questions[-1][0], VERDICT_ALLOW_ONCE) == ('superseded', b'')
    denied(h, worker, 1, 'policy_changed')
    assert h.opened == []


# ---- the third checkpoint, durable before the fd goes (H-07, H-08) -----------------------------------------------------
@pytest.mark.parametrize('change', ['deleted', 'other_dir_same_alias', 'read_removed_for_list', 'denied', 'unavailable'])
def test_a_change_while_the_pdp_judges_is_caught_before_the_open(h: FileHarness, change: str) -> None:
    h.obj('notes', h.host)
    h.pdp.hold = True
    ex, conn, worker = h.file_row()
    op = LIST_OP if change == 'read_removed_for_list' else READ_OP
    worker.sendall(ask(1, ex.lease.uid, op, b'notes', b'sub' if op == LIST_OP else b'notes.txt', 0,
                       0 if op == LIST_OP else 10))
    h.pump()
    if change == 'deleted':
        h.tables.delete_object('work0', 'notes')
    elif change == 'other_dir_same_alias':
        h.obj('notes', h.host / 'sub')
    elif change == 'read_removed_for_list':
        h.obj('notes', h.host, DIR, READ)
    elif change == 'denied':
        h.tables.set_object_mode('work0', 'notes', EntryState.DENY, Approval.NEVER)
    else:
        h.tables.tables['work0'].unavailable_objects.add('notes')
    fds = open_fds()
    h.pdp.answer(h.pdp.requests[0])
    denied(h, worker, 1, 'policy_changed')
    assert open_fds() == fds and h.opened == []


@pytest.fixture
def d(native, tmp_path: Path):
    evidence = tmp_path / 'events.jsonl'
    evidence.write_bytes(b'')
    harness = FileHarness(tmp_path, native, str(evidence))
    harness.evidence = evidence
    yield harness
    harness.close()


def all_durable(d: FileHarness, seconds: float = 3.0) -> None:
    """Wait until the writer's receipt covers every record so far (a deny record follows its frame)."""
    until = time.monotonic() + seconds
    while d.recorder.status()[1] < d.recorder.seq and time.monotonic() < until:
        time.sleep(0.01)
    assert d.recorder.status()[1] == d.recorder.seq


def stall(d: FileHarness) -> threading.Event:
    gate = threading.Event()
    real = d.recorder.fsync
    d.recorder.fsync = lambda fd: (gate.wait(10), real(fd))[1]
    return gate


def pump_until(d: FileHarness, sock: socket.socket, seconds: float = 3.0):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        d.loop.run_once(0.05)
        if not silent(sock, 0):
            return recv_file(sock)
    return None


def on_disk(d: FileHarness) -> list[dict]:
    return [json.loads(x) for x in d.evidence.read_bytes().splitlines() if x.strip()]


def test_no_fd_goes_before_its_allow_record_is_durable(d: FileHarness) -> None:
    d.obj('notes', d.host)
    gate = stall(d)
    ex, conn, worker = d.file_row()
    worker.sendall(read(1, ex))
    for _ in range(20):
        d.loop.run_once(0.02)
    assert silent(worker) and d.hook.durable and len(d.opened) == 1      # opened, waiting for the record's fsync
    gate.set()
    kind, fields, fds = pump_until(d, worker)
    assert kind == c.FILE_ALLOW and len(fds) == 1
    os.close(fds[0])
    allow = [e for e in on_disk(d) if e['kind'] == 'request_decided' and e['outcome'] == 'allow']
    assert [e['detail']['actual_length'] for e in allow] == [len(CONTENT)]


def test_a_record_fault_refuses_and_closes_the_target(d: FileHarness) -> None:
    d.obj('notes', d.host)
    d.recorder.fsync = lambda fd: (_ for _ in ()).throw(OSError(5, 'EIO'))
    ex, conn, worker = d.file_row()
    worker.sendall(read(1, ex))
    kind, fields, fds = pump_until(d, worker)
    assert (kind, c.FILE_REASONS[c.read_uint(fields[1], 1) - 1], fds) == (c.FILE_DENY, 'unavailable', [])
    assert fds_naming(d.host / 'notes.txt') == []


@pytest.mark.parametrize('change', ['deleted', 'other_dir_same_alias', 'denied', 'read_removed'])
def test_a_change_after_the_open_is_caught_at_the_third_checkpoint(d: FileHarness, change: str) -> None:
    d.obj('notes', d.host)
    gate = stall(d)
    ex, conn, worker = d.file_row()
    worker.sendall(ask(1, ex.lease.uid, LIST_OP if change == 'read_removed' else READ_OP, b'notes',
                       b'sub' if change == 'read_removed' else b'notes.txt', 0, 0 if change == 'read_removed' else 10))
    for _ in range(20):
        d.loop.run_once(0.02)
    assert d.hook.durable and len(d.opened) == 1
    if change == 'deleted':
        d.tables.delete_object('work0', 'notes')
    elif change == 'other_dir_same_alias':
        d.obj('notes', d.host / 'sub')
    elif change == 'denied':
        d.tables.set_object_mode('work0', 'notes', EntryState.DENY, Approval.NEVER)
    else:
        d.obj('notes', d.host, DIR, READ)
    gate.set()
    kind, fields, fds = pump_until(d, worker)
    assert (kind, c.FILE_REASONS[c.read_uint(fields[1], 1) - 1], fds) == (c.FILE_DENY, 'policy_changed', [])
    assert fds_naming(d.host / 'notes.txt') == []
    assert len(fds_naming(d.host / 'sub')) == (1 if change == 'other_dir_same_alias' else 0)    # only a new anchor
    all_durable(d)                                                   # the deny record follows the frame
    outcomes = [(e['outcome'], e['reason_code']) for e in on_disk(d) if e['kind'] == 'request_decided']
    assert outcomes == [('allow', 'recorded_allow'), ('deny', 'recheck_failed')]


def test_an_unrelated_change_after_the_open_still_releases(d: FileHarness) -> None:
    d.obj('notes', d.host)
    gate = stall(d)
    ex, conn, worker = d.file_row()
    worker.sendall(read(1, ex))
    for _ in range(20):
        d.loop.run_once(0.02)
    d.obj('other', d.host / 'sub')                                     # the table version moves, this object does not
    gate.set()
    kind, fields, fds = pump_until(d, worker)
    assert kind == c.FILE_ALLOW and len(fds) == 1
    os.close(fds[0])


@pytest.mark.parametrize('end', ['withdraw', 'row_closed'])
def test_a_withdrawal_or_a_row_close_after_the_open_closes_the_target(d: FileHarness, end: str) -> None:
    d.obj('notes', d.host)
    gate = stall(d)
    ex, conn, worker = d.file_row()
    worker.sendall(read(1, ex))
    for _ in range(20):
        d.loop.run_once(0.02)
    assert d.hook.durable and fds_naming(d.host / 'notes.txt')
    if end == 'withdraw':
        worker.sendall(c.pack_frame(c.FILE_WITHDRAW, [c.u64(1)]))
        for _ in range(5):
            d.loop.run_once(0.02)
        assert [e['detail']['stage'] for e in d.events('request_withdrawn')] == ['durable']
    else:
        d.hook.row_closed(ex)
    assert fds_naming(d.host / 'notes.txt') == []
    gate.set()
    for _ in range(20):
        d.loop.run_once(0.02)
    if end == 'withdraw':
        assert silent(worker)
    else:
        kind, fields, fds = recv_file(worker)
        assert (kind, c.FILE_REASONS[c.read_uint(fields[1], 1) - 1], fds) == (c.FILE_DENY, 'unavailable', [])


# ---- one row, two ports (H-06 on the core's side, done in 2.3a because both kinds share the row's queue) -------------
def test_file_requests_share_the_rows_queue_and_withdrawals_go_by_port(h: FileHarness) -> None:
    allow_entry = make_entry(KeyKind.EXACT, 'ask.example:443', EntryState.ALLOW, ('GET',), (), (), Approval.ALWAYS)
    h.tables.put('work0', allow_entry)
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'ask.example'), memfd(b''))     # asks: the row's path is taken
    worker.sendall(read(1, ex))                                                    # the same seq on the file port
    h.pump()
    assert silent(worker)                                             # queued behind the network question
    worker.sendall(c.pack_frame(c.FILE_WITHDRAW, [c.u64(1)]))         # withdraws the file request, not the network one
    h.pump()
    assert [e['detail']['stage'] for e in h.events('request_withdrawn')] == ['queued']
    assert h.hook.answer(h.admin.questions[-1][0], VERDICT_ALLOW_ONCE) == (None, b'')
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED
    worker.sendall(read(2, ex))
    os.close(allowed(h, worker, 2))


def test_a_network_withdrawal_leaves_the_file_request_with_the_same_number(h: FileHarness) -> None:
    """H-06, 2.3b (裁定单风险第 1 条): the connector's WITHDRAW(1) takes its own request 1 out, at the question; the
    worker's request 1, queued behind it, goes on to its allow."""
    h.tables.put('work0', make_entry(KeyKind.EXACT, 'ask.example:443', EntryState.ALLOW, ('GET',), (), (),
                                     Approval.ALWAYS))
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'ask.example'), memfd(b''))
    worker.sendall(read(1, ex))
    h.pump()
    assert silent(worker)
    conn.sendall(c.pack_frame(c.WITHDRAW, [c.u64(1)]))
    h.pump()
    assert [(e['detail']['stage'], e['detail']['admission']) for e in h.events('request_withdrawn')] == [('asking', 1)]
    os.close(allowed(h, worker, 1))
    assert decided(h)[-1] == ('allow', 'recorded_allow') and not h.faults


def test_a_file_withdrawal_or_a_report_never_reaches_the_other_ports_request(h: FileHarness) -> None:
    """H-06: a network request 1 allowed and in flight waits for its REPORT (K-38); the worker's WITHDRAW(1) is not
    for it (noted and dropped, the in-flight entry kept); the worker's own request 1 then runs to its allow, and the
    connector's REPORT(1) frees the network request, not anything of the file port."""
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'example.org'), memfd(b''))    # the fallback entry allows it
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED
    row = h.hook.rows[ex.execution_id]
    assert list(row.inflight) == [1]
    worker.sendall(c.pack_frame(c.FILE_WITHDRAW, [c.u64(1)]))
    h.pump()
    assert list(row.inflight) == [1] and h.events('request_withdrawn') == []
    assert noted(h, 'withdraw_ignored') == [1]
    [note] = [e['detail'] for e in h.recorder.events if e['kind'] == 'diagnostic' and e['name'] == 'withdraw_ignored']
    assert note['port'] == 'file'                                     # the note says which port's 1 it was
    worker.sendall(read(1, ex))
    os.close(allowed(h, worker, 1))
    conn.sendall(c.pack_frame(c.REPORT, [c.u64(1), c.u8(c.RES_REMOTE), c.u16(200)]))
    h.pump()
    assert row.inflight == {} and noted(h, 'report_ignored') == [] and not h.faults
    conn.sendall(c.pack_frame(c.REPORT, [c.u64(1), c.u8(c.RES_REMOTE), c.u16(200)]))   # 1 again: no request of
    h.pump()                                                                          # either port is left under it
    assert noted(h, 'report_ignored') == [1]


def noted(h: FileHarness, name: str) -> list[int]:
    """The seq of every diagnostic of this name."""
    return [e['detail']['seq'] for e in h.recorder.events if e['kind'] == 'diagnostic' and e['name'] == name]


# ---- revocation (H-19)---------------------------------------------------------------------------------------------------
def test_a_change_takes_effect_from_the_next_request(h: FileHarness) -> None:
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex))
    kept = allowed(h, worker, 1)
    h.tables.delete_object('work0', 'notes')
    worker.sendall(read(2, ex))
    denied(h, worker, 2, 'not_registered')
    assert os.pread(kept, 4, 0) == CONTENT[:4]                        # the one already handed over completes
    os.close(kept)
    h.obj('notes', h.host, mode='ask')
    worker.sendall(read(3, ex))
    h.pump()
    assert h.admin.questions and h.admin.questions[-1][5] == 3
    h.hook.answer(h.admin.questions[-1][0], VERDICT_ALLOW_ONCE)
    os.close(allowed(h, worker, 3))
    h.obj('notes', h.host)
    h.pdp.hold = True
    worker.sendall(read(4, ex))
    h.pump()
    h.tables.set_object_mode('work0', 'notes', EntryState.DENY, Approval.NEVER)
    h.pdp.answer(h.pdp.requests[-1])
    denied(h, worker, 4, 'policy_changed')


# ---- the trace (H-20) -----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize('start,length,actual', [(0, 4096, len(CONTENT)), (9, 4, 4), (9, 4096, len(CONTENT) - 9),
                                                 (len(CONTENT), 10, 0), (len(CONTENT) + 50, 10, 0)])
def test_the_records_carry_the_shape_and_never_the_content(d: FileHarness, start: int, length: int, actual: int) -> None:
    d.obj('notes', d.host)
    ex, conn, worker = d.file_row()
    worker.sendall(read(1, ex, start=start, length=length))
    kind, _, fds = pump_until(d, worker)
    assert kind == c.FILE_ALLOW
    os.close(fds[0])
    worker.sendall(ask(2, ex.lease.uid, LIST_OP, b'notes', b'sub', 0, 0))
    kind, _, fds = pump_until(d, worker)
    assert kind == c.FILE_ALLOW
    os.close(fds[0])
    all_durable(d)
    events = on_disk(d)
    admitted = [e['detail'] for e in events if e['kind'] == 'request_admitted']
    assert [(a['request_kind'], a['file_op'], a['alias'], a['path'], a['start'], a['length']) for a in admitted] == \
        [('file', 'read', 'notes', 'notes.txt', start, length), ('file', 'list', 'notes', 'sub', 0, 0)]
    allows = [e['detail'] for e in events if e['kind'] == 'request_decided' and e['outcome'] == 'allow']
    assert allows[0]['actual_length'] == actual and allows[1]['start'] == 0 and 'actual_length' not in allows[1]
    raw = d.evidence.read_bytes()
    assert b'MARKER-A' not in raw and b'MARKER-NAME' not in raw and b'MARKER-B' not in raw


def test_alias_and_path_bytes_come_back_from_the_record(h: FileHarness) -> None:
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    odd = b'caf\xe9/\xff\x01"q"'
    worker.sendall(read(1, ex, path=odd))
    denied(h, worker, 1, 'not_found')
    a = h.events('request_admitted')[0]['detail']
    assert a['path'].encode('latin-1') == odd and a['alias'].encode('latin-1') == b'notes'


# ---- list objects (H-21) ----------------------------------------------------------------------------------------------
def test_list_objects_answers_from_the_table_at_once(h: FileHarness) -> None:
    h.obj('a-allow', h.host)
    h.obj('b-ask', h.host / 'notes.txt', FILE, READ, mode='ask')
    h.obj('c-deny', h.host, mode='deny')
    h.obj('d-gone', h.host / 'sub')
    h.tables.tables['work0'].unavailable_objects.add('d-gone')
    h.tables.put('work0', make_entry(KeyKind.EXACT, 'ask.example:443', EntryState.ALLOW, ('GET',), (), (), Approval.ALWAYS))
    ex, conn, worker = h.file_row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'ask.example'), memfd(b''))     # a question holds the row's path
    h.pump()
    for seq in (1, 2):
        worker.sendall(ask(seq, ex.lease.uid, OBJECTS_OP))
        h.pump()
        kind, fields, fds = recv_file(worker)
        assert (kind, c.read_uint(fields[0], 8), fds) == (c.FILE_OBJECT_LIST, seq, [])
        items = [c.unpack_list(x) for x in c.unpack_list(fields[1])]
        assert items == [[b'a-allow', str(h.host).encode(), c.u8(DIR), c.u8(READ | LIST), c.u8(c.FILE_MODE_ALLOW)],
                         [b'b-ask', str(h.host / 'notes.txt').encode(), c.u8(FILE), c.u8(READ), c.u8(c.FILE_MODE_ASK)]]
    assert h.pdp.requests == [] and len(h.admin.questions) == 1
    listed = h.events('file_objects_listed')
    assert [e['detail']['aliases'] for e in listed] == [['a-allow', 'b-ask']] * 2
    assert all(e['detail'].get('request_kind') != 'file' for e in h.events('request_admitted'))   # never queued
    assert 'MARKER' not in json.dumps(list(h.recorder.events))       # (the items above hold no anchor path or inode)


def test_a_transfer_row_lists_no_objects(h: FileHarness) -> None:
    h.obj('a-allow', h.host)
    ex, conn, worker = h.file_row(transfer='push')
    worker.sendall(ask(1, ex.lease.uid, OBJECTS_OP))
    h.pump()
    kind, fields, _ = recv_file(worker)
    assert kind == c.FILE_OBJECT_LIST and c.unpack_list(fields[1]) == []


def test_an_object_of_another_workspace_is_not_registered_here(h: FileHarness, tmp_path: Path) -> None:
    """H-18: what a refusal says depends on the row's own workspace only. The same alias and host path registered in
    work1 leave a work0 row's object list empty and its read refused not_registered, as with nothing registered at all;
    a work1 row reads it."""
    (tmp_path / 'root1').mkdir()
    h.tables.register('work1', str(tmp_path / 'root1'))
    h.tables.register_object('work1', 'notes', str(h.host), DIR, READ | LIST, *MODES['allow'])
    ex, conn, worker = h.file_row(0)
    worker.sendall(ask(1, ex.lease.uid, OBJECTS_OP))
    h.pump()
    kind, fields, _ = recv_file(worker)
    assert kind == c.FILE_OBJECT_LIST and c.unpack_list(fields[1]) == []
    worker.sendall(read(2, ex))
    denied(h, worker, 2, 'not_registered')
    other, _, other_worker = h.file_row(1, workspace='work1')
    other_worker.sendall(read(1, other))
    os.close(allowed(h, other_worker, 1))


def test_the_file_reasons_cover_the_core_refusals(h: FileHarness) -> None:
    """The core's refusals that also happen to network requests use the network side's words (proposal 第二节)."""
    from engine import judgment as j
    assert {fo.wire_reason(x) for x in (j.DENY_RECORDED, j.DENY_USER, j.DENY_TIMEOUT, j.DENY_UNAVAILABLE, j.DENY_PDP,
                                        j.DENY_POLICY_CHANGED, j.DENY_NOT_AUTHORIZED)} == \
        {R['recorded_deny'], R['user_denied'], R['timeout'], R['unavailable'], R['pdp_denied'], R['policy_changed'],
         R['not_registered']}
    assert fo.wire_reason(fo.FileReason.BAD_PATH) == R['bad_path']
    assert fo.wire_reason(j.DENY_CLAUSE) == fo.wire_reason(j.DENY_CREDENTIAL) == R['unavailable']   # never expected


def test_errno_detail_is_in_the_record_only(h: FileHarness) -> None:
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    worker.sendall(read(1, ex, path=b'escape'))
    denied(h, worker, 1, 'outside_or_symlink')
    assert h.events('request_decided')[0]['detail']['errno'] == errno.errorcode[errno.ELOOP]
