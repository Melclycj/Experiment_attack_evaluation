"""The file judgment port's core end (SPEC link H; validation.md H-04's core reading, H-06's frame rules on the core's
side, H-08's FILE_ALLOW; plan engine-v3-n16-file-read 2.3a). The worker is in the TCB, so a frame from it that does not
read by the field table is a defect: the port faults and the row closes. Content rules are the core's first checkpoint
(test_file_hook), never the port's.
"""
from __future__ import annotations

import array
import os
from pathlib import Path
import socket

import pytest

from conftest import settled_fds as open_fds
from connector import canonical as c
from engine.workspaces import Approval, EntryState
from test_file_hook import FileHarness, allowed, ask, decided, denied, fds_naming, noted, read, recv_file, silent


@pytest.fixture
def h(native, tmp_path: Path):
    harness = FileHarness(tmp_path, native)
    yield harness
    harness.close()


def frame(kind: int, fields: list[bytes]) -> bytes:
    payload = c.u8(kind) + b''.join(c.u32(len(f)) + f for f in fields)
    return c.u32(len(payload)) + payload


@pytest.mark.parametrize('case', ['field_count', 'seq_width', 'uid_width', 'op_width', 'length_width', 'foreign_kind',
                                  'core_kind', 'admin_verb', 'with_fd', 'seq_repeat', 'seq_zero', 'other_sender',
                                  'unknown_op', 'objects_with_fields', 'list_with_length', 'oversized'])
def test_a_frame_that_does_not_read_closes_the_row(h: FileHarness, case: str) -> None:
    ex, conn, worker = h.file_row()
    uid = ex.lease.uid
    good = [c.u64(1), c.u32(uid), c.u8(3), b'notes', b'notes.txt', c.u64(0), c.u32(10)]
    if case == 'field_count':
        worker.sendall(frame(c.FILE_ASK, good[:6]))
    elif case == 'seq_width':
        worker.sendall(frame(c.FILE_ASK, [c.u32(1)] + good[1:]))
    elif case == 'uid_width':
        worker.sendall(frame(c.FILE_ASK, [good[0], c.u64(uid)] + good[2:]))
    elif case == 'op_width':
        worker.sendall(frame(c.FILE_ASK, good[:2] + [c.u16(3)] + good[3:]))
    elif case == 'length_width':
        worker.sendall(frame(c.FILE_ASK, good[:6] + [c.u64(10)]))
    elif case == 'foreign_kind':
        worker.sendall(c.pack_frame(c.JUDGE, [b''] * 13))
    elif case == 'core_kind':
        worker.sendall(c.pack_frame(c.FILE_ALLOW, [c.u64(1), c.u8(3)]))
    elif case == 'admin_verb':                                       # H-01: no registration verb on this port
        worker.sendall(c.pack_frame(c.OBJ_PUT, [b'work0', b'x', b'/', c.u8(2), c.u8(1), c.u8(1), c.u8(1)]))
    elif case == 'with_fd':
        fd = os.open('/dev/null', os.O_RDONLY)
        worker.sendmsg([read(1, ex)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
        os.close(fd)
    elif case == 'seq_repeat':
        worker.sendall(ask(5, uid, c.FILE_OP_OBJECTS) + ask(5, uid, c.FILE_OP_OBJECTS))
    elif case == 'seq_zero':
        worker.sendall(ask(0, uid, c.FILE_OP_OBJECTS))
    elif case == 'other_sender':
        worker.sendall(ask(1, uid + 1, c.FILE_OP_OBJECTS))
    elif case == 'unknown_op':
        worker.sendall(ask(1, uid, 4, b'notes', b'', 0, 0))
    elif case == 'objects_with_fields':
        worker.sendall(ask(1, uid, c.FILE_OP_OBJECTS, b'notes'))
    elif case == 'list_with_length':
        worker.sendall(ask(1, uid, c.FILE_OP_LIST, b'notes', b'', 0, 5))
    else:
        worker.sendall(c.u32(c.LIMITS.frame_h + 1) + c.u8(c.FILE_ASK))
    h.pump()
    assert h.faults and h.faults[0][0] == ex.execution_id
    assert any(e['kind'] == 'diagnostic' and e['name'] == 'file_port_fault' for e in h.recorder.events)
    assert h.events('request_admitted') == []


def test_a_readable_frame_with_bad_content_reaches_the_first_checkpoint(h: FileHarness) -> None:
    """H-04: alias, path and length are the core's to judge: a frame that reads is admitted and refused with a record."""
    ex, conn, worker = h.file_row()
    worker.sendall(ask(1, ex.lease.uid, c.FILE_OP_READ, b'\x00\xff' * 40, b'../../etc/passwd', 0, 2 ** 32 - 1))
    h.pump()
    kind, fields, _ = recv_file(worker)
    assert kind == c.FILE_DENY and not h.faults and len(h.events('request_admitted')) == 1


def test_unknown_withdrawals_are_noted_not_faulted(h: FileHarness) -> None:
    """K-36 on this port; the note names the port it came from, since both ports of a row count from 1 (H-06)."""
    ex, conn, worker = h.file_row()
    worker.sendall(c.pack_frame(c.FILE_WITHDRAW, [c.u64(9)]))
    h.pump()
    assert not h.faults
    [d] = [e for e in h.recorder.events if e['kind'] == 'diagnostic' and e['name'] == 'withdraw_ignored']
    assert (d['detail']['seq'], d['detail']['known'], d['detail']['port']) == (9, False, 'file')


def test_an_allow_that_has_to_wait_sends_its_own_copy_of_the_target(h: FileHarness) -> None:
    """The FILE_ALLOW is queued while the worker does not read; the hook has closed its descriptor by then, so the queue
    holds a copy, which goes with the frame and is closed once sent."""
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    fport, _ = h.file_rows[ex.execution_id]
    junk = 0
    while True:
        try:
            junk += fport.sock.send(b'\0' * 65536, socket.MSG_DONTWAIT)
        except BlockingIOError:
            break
    worker.sendall(read(1, ex))
    h.pump()
    assert fport.out and fport.out[0][1] is not None
    before = open_fds()
    got = b''
    while len(got) < junk:
        got += worker.recv(junk - len(got))
    fd = allowed(h, worker, 1)
    assert os.pread(fd, 8, 0) == b'line one' and fport.out == []
    os.close(fd)
    assert len(open_fds()) == len(before) - 1                         # the queued copy is gone too


def fill(fport) -> int:
    """Fill the core's end of the port until a send would block; the bytes the worker end must read first."""
    junk = 0
    while True:
        try:
            junk += fport.sock.send(b'\0' * 65536, socket.MSG_DONTWAIT)
        except BlockingIOError:
            return junk


def drain(worker: socket.socket, junk: int) -> None:
    got = 0
    while got < junk:
        got += len(worker.recv(min(junk - got, 1 << 20)))


def queued_allow(h: FileHarness) -> tuple:
    """A read allowed while the port is full: its FILE_ALLOW and its copy of the target wait in the port's queue."""
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    fport, _ = h.file_rows[ex.execution_id]
    junk = fill(fport)
    worker.sendall(read(1, ex))
    h.pump()
    assert fport.out and fport.out[0][1] is not None and fds_naming(h.host / 'notes.txt')
    assert decided(h) == [('allow', 'recorded_allow')]
    return ex, worker, fport, junk


def test_a_withdrawal_while_the_allow_waits_in_the_queue_takes_it_back(h: FileHarness) -> None:
    """H-07, H-08 (Codex review, important 1): until the FILE_ALLOW's descriptor has gone, the request is still the
    worker's to withdraw by port and seq: the queued copy is closed, the frame never goes, the withdrawal is recorded
    at its stage."""
    ex, worker, fport, junk = queued_allow(h)
    worker.sendall(c.pack_frame(c.FILE_WITHDRAW, [c.u64(1)]))
    h.pump()
    assert [e['detail']['stage'] for e in h.events('request_withdrawn')] == ['delivering']
    assert noted(h, 'withdraw_ignored') == [] and fport.out == []
    assert fds_naming(h.host / 'notes.txt') == []                     # the queued copy is closed at once
    drain(worker, junk)
    h.pump()
    assert silent(worker) and not h.faults                            # nothing goes once the port drains


@pytest.mark.parametrize('change', ['deleted', 'denied', 'ask', 'other_dir_same_alias', 'row_closed'])
def test_a_change_while_the_allow_waits_in_the_queue_is_caught_before_it_goes(h: FileHarness, change: str) -> None:
    """H-07, H-08, H-19 (Codex review, important 1): right before the queued descriptor would go, the authority is
    checked again by the version numbers; an object deleted, denied, turned to ask, or re-registered elsewhere since
    has the copy closed and FILE_DENY(policy_changed) sent in its place, with a deny record after the allow record. A
    row closed meanwhile closes the copy and refuses the request as unavailable."""
    ex, worker, fport, junk = queued_allow(h)
    if change == 'deleted':
        h.tables.delete_object('work0', 'notes')
    elif change == 'denied':
        h.tables.set_object_mode('work0', 'notes', EntryState.DENY, Approval.NEVER)
    elif change == 'ask':
        h.tables.set_object_mode('work0', 'notes', EntryState.ALLOW, Approval.ALWAYS)
    elif change == 'other_dir_same_alias':
        h.obj('notes', h.host / 'sub')
    else:
        h.hook.row_closed(ex)
        assert fds_naming(h.host / 'notes.txt') == []                 # closed with the row, not when the port drains
    drain(worker, junk)
    denied(h, worker, 1, 'unavailable' if change == 'row_closed' else 'policy_changed')
    assert fds_naming(h.host / 'notes.txt') == [] and fport.out == []
    assert decided(h) == [('allow', 'recorded_allow'),
                          ('deny', 'row_closed' if change == 'row_closed' else 'recheck_failed')]
    assert h.events('request_decided')[-1]['detail']['stage'] == 'delivering'
    assert silent(worker)


def test_a_row_closed_with_two_allows_in_the_queue_sends_one_deny_for_each(h: FileHarness) -> None:
    """H-08, K-22 (Fable recheck, minor 1): two FILE_ALLOWs wait in the port's queue when the row closes. Every queued
    copy is taken back before any refusal goes out, so sending one refusal never makes the port judge the other allow
    at the head of its queue: the worker gets exactly one FILE_DENY(unavailable) per seq, in order, no descriptor;
    one row_closed record each; no copy left open."""
    ex, worker, fport, junk = queued_allow(h)
    worker.sendall(read(2, ex))
    h.pump()
    assert [item[3] for item in fport.out] == [1, 2] and all(item[1] is not None for item in fport.out)
    h.hook.row_closed(ex)
    assert fds_naming(h.host / 'notes.txt') == []
    drain(worker, junk)
    h.pump()
    frames = []
    while not silent(worker):
        kind, fields, fds = recv_file(worker)
        frames.append((kind, c.read_uint(fields[0], 8), c.FILE_REASONS[c.read_uint(fields[1], 1) - 1], fds))
    assert frames == [(c.FILE_DENY, 1, 'unavailable', []), (c.FILE_DENY, 2, 'unavailable', [])]
    assert decided(h) == [('allow', 'recorded_allow')] * 2 + [('deny', 'row_closed')] * 2
    assert [e['detail']['seq'] for e in h.events('request_decided')[2:]] == [1, 2] and fport.out == []


def test_an_unrelated_change_while_the_allow_waits_still_hands_it_over(h: FileHarness) -> None:
    """The check before the descriptor goes is the third checkpoint's: a change elsewhere in the table moves the version
    and is judged again, and the request still goes."""
    ex, worker, fport, junk = queued_allow(h)
    h.obj('other', h.host / 'sub')
    drain(worker, junk)
    fd = allowed(h, worker, 1)
    assert os.pread(fd, 8, 0) == b'line one' and fport.out == []
    os.close(fd)
    assert decided(h) == [('allow', 'recorded_allow')] and h.events('request_withdrawn') == []


def test_closing_the_port_closes_queued_descriptors(h: FileHarness) -> None:
    h.obj('notes', h.host)
    ex, conn, worker = h.file_row()
    fport, _ = h.file_rows[ex.execution_id]
    while True:
        try:
            fport.sock.send(b'\0' * 65536, socket.MSG_DONTWAIT)
        except BlockingIOError:
            break
    worker.sendall(read(1, ex))
    h.pump()
    assert fport.out and fport.out[0][1] is not None
    queued = fport.out[0][1]
    fport.close()
    with pytest.raises(OSError):
        os.fstat(queued)
    assert silent(worker, 0) is False                                 # the junk is still there to read; nothing hangs
