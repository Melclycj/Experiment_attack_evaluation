"""The row's file worker (validation.md H-04, H-05, H-13, H-15, H-16, H-18; plan engine-v3-n16-file-read 2.3b).

The worker runs in-process on a PASSCRED listener and a socketpair standing in for the file judgment port (SPEC link H):
the test plays the MCP server on the file port (link G, its own uid as the row's uid) and the core on the other end of
the pair, answering FILE_ASK with FILE_ALLOW (an opened descriptor), FILE_DENY or FILE_OBJECT_LIST. Kernel credentials of
other senders need root: tests/test_fileworker_root.py.
"""
from __future__ import annotations

import array
import os
from pathlib import Path
import re
import select
import socket
import stat
import time

import pytest

from conftest import OVERFLOWUID, settled_fds as open_fds
from connector import canonical as c
from connector.reader import Native
from fileworker import channel
from fileworker.main import CONNECTIONS_MAX, Worker
from fileworker.session import entry_type

ENGINE = Path(__file__).resolve().parents[1]
R = {name: code for code, name in enumerate(c.FILE_REASONS, 1)}
READ_OP, LIST_OP, OBJECTS_OP = c.FILE_OP_READ, c.FILE_OP_LIST, c.FILE_OP_OBJECTS


class WorkerRig:
    def __init__(self, tmp_path: Path, library: Path, passcred: bool = True, **kw) -> None:
        self.path = tmp_path / 'file.sock'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if passcred:
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.listener.bind(str(self.path))
        self.listener.listen(CONNECTIONS_MAX)
        self.core, worker_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.core.settimeout(3)
        self.fatal: list[str] = []
        self.logs: list[tuple[str, dict]] = []
        self.worker = Worker(self.listener, worker_end, os.getuid(), 'e', Native(library), OVERFLOWUID,
                             on_fatal=self.fatal.append, log=lambda event, **f: self.logs.append((event, f)), **kw)
        self.worker.start()
        self.clients: list[socket.socket] = []

    def client(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(self.path))
        s.settimeout(3)
        self.clients.append(s)
        return s

    def ask(self) -> tuple[int, list[bytes]]:
        """The next frame the worker sends to the core."""
        return read_frame(self.core)

    def answer(self, kind: int, fields: list[bytes], fds: tuple[int, ...] = ()) -> None:
        frame = c.pack_frame(kind, fields)
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
        assert self.core.sendmsg([frame], ancillary) == len(frame)

    def core_silent(self, s: float = 0.3) -> bool:
        r, _, _ = select.select([self.core], [], [], s)
        return not r

    def idle(self, timeout: float = 3) -> None:
        """Every session has ended (its socket closed)."""
        until = time.monotonic() + timeout
        while self.worker.sessions:
            assert time.monotonic() < until, 'sessions did not end'
            time.sleep(0.01)

    def close(self) -> None:
        for s in self.clients:
            s.close()
        self.worker.stop()
        self.core.close()


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError(f'{len(data)} of {n} bytes')
        data += chunk
    return data


def read_frame(sock: socket.socket) -> tuple[int, list[bytes]]:
    length = int.from_bytes(recv_exactly(sock, 4), 'big')
    body = recv_exactly(sock, length)
    return body[0], c.unpack_payload(body[0], body[1:])


def eof(sock: socket.socket) -> bool:
    try:
        return sock.recv(1) == b''
    except ConnectionResetError:
        return True
    except socket.timeout:
        return False


def frame(kind: int, fields: list[bytes]) -> bytes:
    """A frame of any kind and field list, bypassing pack_frame's field-count check."""
    payload = bytes([kind]) + b''.join(c.u32(len(f)) + f for f in fields)
    return c.u32(len(payload)) + payload


def read_req(alias: bytes = b'notes', path: bytes = b'a.txt', offset: int = 0, length: int = 4096) -> bytes:
    return c.pack_frame(c.FILE_READ, [alias, path, c.u64(offset), c.u32(length)])


def list_req(alias: bytes = b'notes', path: bytes = b'', start: int = 0) -> bytes:
    return c.pack_frame(c.FILE_LIST, [alias, path, c.u32(start)])


def ask_fields(fields: list[bytes]) -> tuple:
    """FILE_ASK as a tuple: seq, sender_uid, op, alias, path, start, length."""
    return (c.read_uint(fields[0], 8), c.read_uint(fields[1], 4), c.read_uint(fields[2], 1), fields[3], fields[4],
            c.read_uint(fields[5], 8), c.read_uint(fields[6], 4))


@pytest.fixture
def rig(library: Path, tmp_path: Path):
    r = WorkerRig(tmp_path, library)
    yield r
    r.close()


@pytest.fixture
def notes(tmp_path: Path) -> Path:
    p = tmp_path / 'notes.txt'
    p.write_bytes(b'0123456789')
    return p


def allow_file(rig: WorkerRig, seq: int, path: Path, op: int = READ_OP) -> None:
    fd = os.open(path, os.O_RDONLY | (os.O_DIRECTORY if op == LIST_OP else 0))
    try:
        rig.answer(c.FILE_ALLOW, [c.u64(seq), c.u8(op)], (fd,))
    finally:
        os.close(fd)


def served(rig: WorkerRig, s: socket.socket, request: bytes, target: Path, op: int) -> tuple[int, list[bytes]]:
    """One request through the core's allow of ``target``; the worker's reply."""
    s.sendall(request)
    kind, fields = rig.ask()
    assert kind == c.FILE_ASK
    allow_file(rig, c.read_uint(fields[0], 8), target, op)
    return read_frame(s)


# ---- H-04: the frame's shape only; the content goes to the core unchanged ---------------------------------------------
def test_a_read_goes_to_the_core_as_it_came_and_is_served_from_the_descriptor(rig: WorkerRig, notes: Path) -> None:
    s = rig.client()
    s.sendall(read_req(b'notes', b'sub/x.txt', 2, 5))
    kind, fields = rig.ask()
    assert kind == c.FILE_ASK and ask_fields(fields) == (1, os.getuid(), READ_OP, b'notes', b'sub/x.txt', 2, 5)
    allow_file(rig, 1, notes)
    kind, fields = read_frame(s)
    assert (kind, c.read_uint(fields[0], 8), fields[1]) == (c.FILE_DATA, 10, b'23456')


@pytest.mark.parametrize('request_, expected', [
    (read_req(b'bad alias!', b'x'), (READ_OP, b'bad alias!', b'x', 0, 4096)),                 # alias grammar
    (read_req(b'notes', b'a/../b'), (READ_OP, b'notes', b'a/../b', 0, 4096)),                 # a .. segment
    (read_req(b'notes', b'/etc/passwd'), (READ_OP, b'notes', b'/etc/passwd', 0, 4096)),       # absolute
    (read_req(b'notes', b'a\x00b'), (READ_OP, b'notes', b'a\x00b', 0, 4096)),                 # NUL
    (read_req(b'notes', b'x', 0, 0), (READ_OP, b'notes', b'x', 0, 0)),                        # length 0
    (read_req(b'notes', b'x', 0, 262145), (READ_OP, b'notes', b'x', 0, 262145)),              # over 256 KiB
    (read_req(b'', b'', 2 ** 64 - 1, 2 ** 32 - 1), (READ_OP, b'', b'', 2 ** 64 - 1, 2 ** 32 - 1)),
    (list_req(b'notes', b'a//b', 2 ** 32 - 1), (LIST_OP, b'notes', b'a//b', 2 ** 32 - 1, 0)),
    (c.pack_frame(c.FILE_LIST_OBJECTS, []), (OBJECTS_OP, b'', b'', 0, 0)),
], ids=['alias', 'dotdot', 'absolute', 'nul', 'length0', 'length-over', 'extremes', 'list', 'objects'])
def test_content_rules_are_the_cores_the_worker_passes_the_fields_on(rig: WorkerRig, request_: bytes,
                                                                      expected: tuple) -> None:
    """H-04: whatever reads as a frame reaches the core, field for field (the first checkpoint judges it, H-07)."""
    s = rig.client()
    s.sendall(request_)
    kind, fields = rig.ask()
    assert kind == c.FILE_ASK and ask_fields(fields)[1:] == (os.getuid(), *expected)
    rig.answer(c.FILE_DENY, [fields[0], c.u8(R['bad_path'])])
    assert read_frame(s) == (c.FILE_REFUSED, [c.u8(R['bad_path'])])


ONE_FD_FRAME = 'descriptor'


@pytest.mark.parametrize('bad', [
    frame(c.FILE_LIST, [b'notes', b'']),                                   # a field short
    frame(c.FILE_READ, [b'notes', b'x', c.u64(0), c.u32(1), b'']),          # a field over
    frame(c.FILE_LIST_OBJECTS, [b'']),                                     # objects takes none
    frame(c.FILE_LIST, [b'notes', b'', c.u64(0)]),                          # start is u32
    frame(c.FILE_READ, [b'notes', b'x', c.u32(0), c.u32(1)]),               # offset is u64
    frame(c.FILE_READ, [b'notes', b'x', c.u64(0), c.u64(1)]),               # length is u32
    frame(c.FILE_ASK, [b''] * 7),                                          # a link H kind
    frame(c.FILE_DATA, [c.u64(0), b'']),                                   # a reply kind
    frame(c.REQUEST, [b''] * 8),                                           # a link A kind
    c.u32(0),                                                              # length 0
    c.u32(8193) + bytes([c.FILE_READ]),                                    # over the 8 KiB request frame
    ONE_FD_FRAME,                                                          # a descriptor with the frame
], ids=['short', 'over', 'objects-field', 'start-width', 'offset-width', 'length-width', 'link-h', 'reply-kind',
        'link-a', 'zero-length', 'over-8k', 'descriptor'])
def test_a_frame_that_does_not_read_ends_the_connection_unanswered(rig: WorkerRig, bad) -> None:
    """H-04, H-05: no reply, nothing to the core, the connection closed; the worker serves the next one."""
    s = rig.client()
    if bad == ONE_FD_FRAME:
        r, w = os.pipe()
        data = list_req()
        s.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [w]))])
        os.close(r)
        os.close(w)
    else:
        s.sendall(bad)
    assert eof(s) and rig.core_silent()
    t = rig.client()
    t.sendall(c.pack_frame(c.FILE_LIST_OBJECTS, []))
    assert rig.ask()[0] == c.FILE_ASK and not rig.fatal


def test_the_request_frame_limit_is_8_kib_inclusive(rig: WorkerRig) -> None:
    """H-13: a FILE_READ of exactly 8192 bytes after the length word is passed on (its 8162-byte path is the core's to
    refuse); one byte more and the connection closes before the body is read."""
    ok = read_req(b'a', b'p' * 8162)
    assert int.from_bytes(ok[:4], 'big') == 8192
    s = rig.client()
    s.sendall(ok)
    kind, fields = rig.ask()
    assert kind == c.FILE_ASK and len(fields[4]) == 8162
    over = read_req(b'a', b'p' * 8163)
    t = rig.client()
    t.sendall(over)
    assert eof(t) and rig.core_silent()


# ---- H-16: reading and listing from the descriptor alone -----------------------------------------------------------------
@pytest.mark.parametrize('offset, length, data', [(0, 4, b'0123'), (3, 4, b'3456'), (8, 4, b'89'), (10, 4, b''),
                                                  (11, 1, b''), (2 ** 64 - 1, 262144, b''), (0, 262144, b'0123456789')])
def test_a_read_returns_the_bytes_at_the_offset_and_the_file_size(rig: WorkerRig, notes: Path, offset: int,
                                                                  length: int, data: bytes) -> None:
    s = rig.client()
    kind, fields = served(rig, s, read_req(offset=offset, length=length), notes, READ_OP)
    assert (kind, c.read_uint(fields[0], 8), fields[1]) == (c.FILE_DATA, 10, data)


def test_a_read_returns_at_most_256_kib(rig: WorkerRig, tmp_path: Path) -> None:
    big = tmp_path / 'big'
    big.write_bytes(bytes(range(256)) * 1200)                        # 307,200 bytes
    s = rig.client()
    kind, fields = served(rig, s, read_req(length=262144), big, READ_OP)
    assert (kind, c.read_uint(fields[0], 8), len(fields[1])) == (c.FILE_DATA, 307200, 262144)
    kind, fields = served(rig, s, read_req(offset=262144, length=262144), big, READ_OP)
    assert fields[1] == (bytes(range(256)) * 1200)[262144:]


def entries(fields: list[bytes]) -> list[tuple[bytes, int]]:
    items = c.unpack_list(fields[1])
    assert len(items) % 2 == 0 and all(len(t) == 1 for t in items[1::2])
    return [(items[i], items[i + 1][0]) for i in range(0, len(items), 2)]


@pytest.mark.parametrize('count', [1000, 1001])
def test_a_list_pages_by_1000_with_the_more_mark(rig: WorkerRig, tmp_path: Path, count: int) -> None:
    """H-13, H-16: at most 1000 entries a page; "more" is set exactly when entry start+1000 exists; past the end the
    page is empty; the pages together are the directory, each name once."""
    d = tmp_path / 'many'
    d.mkdir()
    for i in range(count):
        (d / f'f{i:04d}').write_bytes(b'')
    s = rig.client()
    seen, pages = [], []
    for start in (0, 1000, count, count + 5):
        kind, fields = served(rig, s, list_req(start=start), d, LIST_OP)
        assert kind == c.FILE_ENTRIES and len(fields) == 2                          # more and entries; no sizes
        page = entries(fields)
        pages.append((start, c.read_uint(fields[0], 1), len(page)))
        if start < count:
            seen += [name for name, _ in page]
    assert pages == [(0, 1 if count > 1000 else 0, 1000), (1000, 0, count - 1000), (count, 0, 0), (count + 5, 0, 0)]
    assert sorted(seen) == sorted(f'f{i:04d}'.encode() for i in range(count))


def test_a_list_gives_names_as_raw_bytes_and_types_from_the_entry(rig: WorkerRig, tmp_path: Path) -> None:
    """H-16: regular file, directory, symlink, other (a FIFO); a name that is not UTF-8 comes back byte for byte."""
    d = tmp_path / 'kinds'
    d.mkdir()
    (d / 'file').write_bytes(b'x')
    (d / 'dir').mkdir()
    (d / 'link').symlink_to('/etc/passwd')
    os.mkfifo(d / 'fifo')
    os.close(os.open(os.fsencode(d) + b'/caf\xe9', os.O_CREAT | os.O_WRONLY, 0o600))
    s = rig.client()
    kind, fields = served(rig, s, list_req(), d, LIST_OP)
    assert dict(entries(fields)) == {b'file': c.FILE_ENTRY_FILE, b'dir': c.FILE_ENTRY_DIR,
                                     b'link': c.FILE_ENTRY_SYMLINK, b'fifo': c.FILE_ENTRY_OTHER,
                                     b'caf\xe9': c.FILE_ENTRY_FILE}


class _NoType:
    """A DirEntry whose type needs another look the worker may not take (d_type unknown, no search permission)."""

    name = 'x'

    def is_symlink(self) -> bool:
        raise PermissionError(13, 'Permission denied')

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        raise PermissionError(13, 'Permission denied')

    def is_file(self, follow_symlinks: bool = True) -> bool:
        raise PermissionError(13, 'Permission denied')


def test_an_entry_whose_type_cannot_be_had_is_unknown() -> None:
    assert entry_type(_NoType()) == c.FILE_ENTRY_UNKNOWN


# ---- H-15: only the core's descriptor, closed after use -------------------------------------------------------------------
def test_the_descriptor_is_closed_after_a_read_and_a_list(rig: WorkerRig, notes: Path, tmp_path: Path) -> None:
    rig.idle()
    before = open_fds()
    s = rig.client()
    assert served(rig, s, read_req(), notes, READ_OP)[0] == c.FILE_DATA
    assert served(rig, s, list_req(), tmp_path, LIST_OP)[0] == c.FILE_ENTRIES
    s.close()
    rig.clients.remove(s)
    rig.idle()
    assert open_fds() == before


@pytest.mark.parametrize('op, target, granted', [(READ_OP, 'dir', READ_OP), (LIST_OP, 'file', LIST_OP),
                                                 (READ_OP, 'file', LIST_OP)], ids=['read-a-dir', 'list-a-file', 'op'])
def test_a_descriptor_that_does_not_fit_the_request_ends_it_as_unavailable(rig: WorkerRig, notes: Path,
                                                                           tmp_path: Path, op: int, target: str,
                                                                           granted: int) -> None:
    rig.idle()
    before = open_fds()
    s = rig.client()
    s.sendall(read_req() if op == READ_OP else list_req())
    seq = c.read_uint(rig.ask()[1][0], 8)
    fd = os.open(notes if target == 'file' else tmp_path, os.O_RDONLY)
    rig.answer(c.FILE_ALLOW, [c.u64(seq), c.u8(granted)], (fd,))
    os.close(fd)
    assert read_frame(s) == (c.FILE_REFUSED, [c.u8(R['unavailable'])])
    s.close()
    rig.clients.remove(s)
    rig.idle()
    assert open_fds() == before


# ---- H-18: the core's refusal reaches the MCP server as its code ---------------------------------------------------------
def test_every_refusal_code_passes_through(rig: WorkerRig) -> None:
    s = rig.client()
    for code in range(1, len(c.FILE_REASONS) + 1):
        s.sendall(read_req())
        seq = c.read_uint(rig.ask()[1][0], 8)
        rig.answer(c.FILE_DENY, [c.u64(seq), c.u8(code)])
        assert read_frame(s) == (c.FILE_REFUSED, [c.u8(code)])


def test_listing_the_objects_returns_the_cores_list(rig: WorkerRig) -> None:
    items = c.pack_list([c.pack_list([b'notes', b'/home/u/notes', c.u8(2), c.u8(3), c.u8(1)]),
                         c.pack_list([b'cfg', b'/etc/app.conf', c.u8(1), c.u8(1), c.u8(2)])])
    s = rig.client()
    s.sendall(c.pack_frame(c.FILE_LIST_OBJECTS, []))
    kind, fields = rig.ask()
    assert ask_fields(fields)[2:] == (OBJECTS_OP, b'', b'', 0, 0)
    rig.answer(c.FILE_OBJECT_LIST, [fields[0], items])
    assert read_frame(s) == (c.FILE_OBJECTS, [items])


def test_requests_on_one_connection_go_one_after_another_with_increasing_numbers(rig: WorkerRig, notes: Path) -> None:
    s = rig.client()
    t = rig.client()
    for client, expected in ((s, 1), (t, 2), (s, 3)):
        client.sendall(read_req())
        kind, fields = rig.ask()
        assert c.read_uint(fields[0], 8) == expected
        allow_file(rig, expected, notes)
        assert read_frame(client)[0] == c.FILE_DATA


# ---- waiting: the client leaves, the core is late (H-13: the connector's total limit) ------------------------------------
def test_a_client_that_leaves_while_waiting_withdraws_its_request(rig: WorkerRig) -> None:
    s = rig.client()
    s.sendall(read_req())
    seq = c.read_uint(rig.ask()[1][0], 8)
    s.close()
    rig.clients.remove(s)
    assert rig.ask() == (c.FILE_WITHDRAW, [c.u64(seq)])


def test_no_answer_in_time_is_withdrawn_and_refused_as_timeout_and_a_late_allow_is_closed(library: Path,
                                                                                         tmp_path: Path,
                                                                                         notes: Path) -> None:
    rig = WorkerRig(tmp_path, library, wait_timeout=0.3)
    try:
        rig.idle()
        s = rig.client()
        s.sendall(read_req())
        seq = c.read_uint(rig.ask()[1][0], 8)
        assert rig.ask() == (c.FILE_WITHDRAW, [c.u64(seq)])
        assert read_frame(s) == (c.FILE_REFUSED, [c.u8(R['timeout'])])
        before = open_fds()
        allow_file(rig, seq, notes)                                  # crosses the withdrawal: nobody waits for it
        until = time.monotonic() + 3
        while not any(e == 'answer_without_waiter' for e, _ in rig.logs):
            assert time.monotonic() < until
            time.sleep(0.01)
        assert open_fds() == before and not rig.fatal
    finally:
        rig.close()


# ---- the core breaking link H ends the worker (as C-28 ends the connector) -----------------------------------------------
@pytest.mark.parametrize('breach', ['allow-no-fd', 'allow-two-fds', 'deny-with-fd', 'kind', 'reason-0', 'reason-14',
                                    'too-long', 'fields', 'fd-mid-frame', 'objects-list'])
def test_a_core_frame_off_the_protocol_is_fatal_and_its_descriptors_closed(rig: WorkerRig, breach: str) -> None:
    rig.idle()
    s = rig.client()
    s.sendall(read_req())
    seq = c.u64(c.read_uint(rig.ask()[1][0], 8))
    f, g = os.open('/dev/null', os.O_RDONLY), os.open('/dev/null', os.O_RDONLY)
    before = open_fds()
    if breach == 'allow-no-fd':
        rig.answer(c.FILE_ALLOW, [seq, c.u8(READ_OP)])
    elif breach == 'allow-two-fds':
        rig.answer(c.FILE_ALLOW, [seq, c.u8(READ_OP)], (f, g))
    elif breach == 'deny-with-fd':
        rig.answer(c.FILE_DENY, [seq, c.u8(1)], (f,))
    elif breach == 'kind':
        rig.core.sendall(frame(c.FILE_ASK, [b''] * 7))
    elif breach.startswith('reason'):
        rig.answer(c.FILE_DENY, [seq, c.u8(int(breach.split('-')[1]))])
    elif breach == 'too-long':
        rig.core.sendall(c.u32(c.LIMITS.frame_h + 1) + bytes([c.FILE_DENY]))
    elif breach == 'fields':
        rig.core.sendall(frame(c.FILE_DENY, [seq, c.u8(1), b'']))
    elif breach == 'fd-mid-frame':
        whole = c.pack_frame(c.FILE_DENY, [seq, c.u8(1)])
        rig.core.sendall(whole[:6])
        rig.core.sendmsg([whole[6:]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [f]))])
    else:
        rig.answer(c.FILE_OBJECT_LIST, [seq, b'\x00\x00\x00\x05'])          # a list that does not read
    os.close(f)
    os.close(g)
    until = time.monotonic() + 3
    while not rig.fatal:
        assert time.monotonic() < until, 'no fatal'
        time.sleep(0.01)
    rig.idle()
    assert open_fds() - (before - {f, g}) == set(), 'a descriptor from the core was kept'


class CloseCounter:
    """Counts os.close by descriptor number while a CoreLink reads (fileworker.channel closes through os.close)."""

    def __init__(self, monkeypatch) -> None:
        self.closed: list[int] = []
        real = os.close

        def counting(fd: int) -> None:
            self.closed.append(fd)
            real(fd)
        monkeypatch.setattr(channel.os, 'close', counting)


def run_link(sock: socket.socket) -> list[str]:
    fatal: list[str] = []
    link = channel.CoreLink(sock, fatal.append, lambda event, **f: None)
    link.run()                                         # returns once the link is dead
    return fatal


def test_a_frame_cut_after_a_descriptor_in_its_head_closes_that_descriptor_once(monkeypatch) -> None:
    """H-06, H-15 (Codex review, minor 3): a descriptor arrives with a frame's length word and the port closes inside
    the body. Every descriptor received is held in one place and closed at the one way out, exactly once (a second close
    of the same number could close what another thread opened under it meanwhile)."""
    core, worker_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    whole = c.pack_frame(c.FILE_ALLOW, [c.u64(1), c.u8(READ_OP)])
    target = os.open('/dev/null', os.O_RDONLY)
    core.sendmsg([whole[:4]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [target]))])
    core.sendall(whole[4:7])                                         # part of the body, then the end of the stream
    core.shutdown(socket.SHUT_WR)
    os.close(target)
    received: list[int] = []
    real_recv = channel.socket.recv_fds

    def recording(*args, **kw):
        out = real_recv(*args, **kw)
        received.extend(out[1])
        return out
    monkeypatch.setattr(channel.socket, 'recv_fds', recording)
    counter = CloseCounter(monkeypatch)
    try:
        assert run_link(worker_end) == ['core protocol: core port closed inside a frame']
    finally:
        core.close()
        worker_end.close()
    assert len(received) == 1 and counter.closed.count(received[0]) == 1


def test_a_read_error_between_two_pieces_of_a_head_closes_the_descriptor_already_received(monkeypatch) -> None:
    """H-06, H-15 (Codex review, minor 3): the length word comes in two pieces, the first with a descriptor, and the
    next receive fails. The descriptor is closed (once) at the way out, not dropped with a local list."""
    core, worker_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    target = os.open('/dev/null', os.O_RDONLY)
    calls: list[int] = []

    def scripted(sock, bufsize, maxfds, flags=0):
        calls.append(bufsize)
        if len(calls) == 1:
            return b'\x00\x00', [target], 0, None                     # half the length word, with the descriptor
        raise ConnectionResetError(104, 'reset')
    monkeypatch.setattr(channel.socket, 'recv_fds', scripted)
    counter = CloseCounter(monkeypatch)
    try:
        assert run_link(worker_end) == ['core port read failed']
    finally:
        core.close()
        worker_end.close()
    assert calls == [4, 2] and counter.closed.count(target) == 1
    with pytest.raises(OSError):
        os.fstat(target)


def test_the_core_port_closing_ends_the_worker(rig: WorkerRig) -> None:
    rig.core.shutdown(socket.SHUT_RDWR)
    until = time.monotonic() + 3
    while not rig.fatal:
        assert time.monotonic() < until
        time.sleep(0.01)
    assert rig.fatal == ['core port closed']


# ---- H-14: the worker process is not dumpable ------------------------------------------------------------------------------
def test_the_worker_turns_itself_not_dumpable(tmp_path: Path) -> None:
    """H-14 (cold review, minor 1): every row's worker runs as the one worker uid; once started it is not dumpable, so
    another process of that uid cannot read its /proc/<pid>/fd (the targets it is reading). The control: the same
    process without the call can be read by its uid. Run as uid 1000 by the engine checks; as root only the dumpable
    flag itself is checked (root may read any /proc)."""
    import subprocess
    import sys
    probe = ('import ctypes, sys\n'
             f'sys.path.insert(0, {str(ENGINE)!r})\n'
             'from fileworker.main import not_dumpable\n'
             'if sys.argv[1] == "call":\n'
             '    not_dumpable()\n'
             'print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0), flush=True)\n'          # PR_GET_DUMPABLE
             'sys.stdin.read()\n')
    for call, dumpable in (('call', '0'), ('control', '1')):
        child = subprocess.Popen([sys.executable, '-I', '-c', probe, call], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, text=True)
        try:
            assert child.stdout.readline().strip() == dumpable
            if os.geteuid() != 0:
                if call == 'call':
                    with pytest.raises(PermissionError):
                        os.listdir(f'/proc/{child.pid}/fd')
                    assert os.stat(f'/proc/{child.pid}/fd').st_uid == 0        # the kernel shows it as root's
                else:
                    assert os.listdir(f'/proc/{child.pid}/fd')
        finally:
            child.stdin.close()
            child.wait(5)
            child.stdout.close()


# ---- H-05, H-13: admission ------------------------------------------------------------------------------------------------
def test_a_listener_without_passcred_gets_no_request_through(library: Path, tmp_path: Path) -> None:
    rig = WorkerRig(tmp_path, library, passcred=False)
    try:
        s = rig.client()
        try:                                          # the worker may close it before the frame is even written
            s.sendall(c.pack_frame(c.FILE_LIST_OBJECTS, []))
        except (BrokenPipeError, ConnectionResetError):
            pass
        assert eof(s) and rig.core_silent()
        assert ('connection_refused', {'why': 'no_passcred'}) in rig.logs
    finally:
        rig.close()


def test_the_17th_connection_is_closed_at_accept(rig: WorkerRig) -> None:
    held = [rig.client() for _ in range(CONNECTIONS_MAX)]
    until = time.monotonic() + 3
    while len(rig.worker.sessions) < CONNECTIONS_MAX:
        assert time.monotonic() < until
        time.sleep(0.01)
    extra = rig.client()
    assert eof(extra)
    # the worker closes the 17th and then logs it, on its accept thread, so the close can reach the client first: wait
    # for the log rather than assume it is already there
    until = time.monotonic() + 3
    while ('connection_refused', {'why': 'limit'}) not in rig.logs:
        assert time.monotonic() < until, rig.logs
        time.sleep(0.01)
    held[0].sendall(c.pack_frame(c.FILE_LIST_OBJECTS, []))
    assert rig.ask()[0] == c.FILE_ASK


# ---- H-15: the source opens nothing by path ------------------------------------------------------------------------------
FORBIDDEN = [r'(?<![\w.])open\(', r'os\.open\(', r'os\.(l)?stat\(', r'os\.listdir', r'os\.walk', r'\bglob\b',
             r'os\.scandir\((?!fd\))', r'os\.readlink', r'\.write_text\(', r'\.write_bytes\(', r'\.read_bytes\(',
             r'\.read_text\(', r'setsockopt\([^)]*SO_PASSCRED']
# the two reads by name the worker may make, both at start: the kernel's overflow uid, and the library (by ctypes, in
# connector/reader.py, which the worker reuses)
ALLOWED = {('main.py', r'\.read_text\('): 1}


def test_the_worker_touches_no_path_and_never_sets_passcred() -> None:
    found: dict[tuple[str, str], int] = {}
    for path in sorted((ENGINE / 'fileworker').glob('*.py')):
        code = '\n'.join(line.split('#', 1)[0] for line in path.read_text(encoding='utf-8').splitlines())
        code = re.sub(r'"""[\s\S]*?"""', '', code)
        for pattern in FORBIDDEN:
            n = len(re.findall(pattern, code))
            if n:
                found[(path.name, pattern)] = n
    assert found == ALLOWED
    assert 'overflowuid' in (ENGINE / 'fileworker/main.py').read_text(encoding='utf-8')
