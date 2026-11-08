"""Receive pipeline against real kernel credentials of chosen senders (conn E-02 R1/R3 判据). Needs root to
send as other uids; the integration runner runs this file as root, the unprivileged suite skips it."""
from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
from typing import Any, Callable, Iterator

import pytest

from conftest import OVERFLOWUID
from engine.loop import Clock
from engine.objects import Channel, Session
from engine.receive import FrameReader, Hello, NeedMore, Reject, receive_step

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='sends as other uids')

EXPECTED = 60000
BODY = json.dumps({'v': 2, 'type': 'hello', 'protocol': 'w2-local/2', 'adapter_id': 'fixture'},
                  separators=(',', ':')).encode()
HELLO = struct.pack('>I', len(BODY)) + BODY


@pytest.fixture
def make(native) -> Iterator[Callable[[int], tuple[Channel, socket.socket]]]:
    made: list[tuple[Channel, socket.socket]] = []

    def build(expected: int = EXPECTED) -> tuple[Channel, socket.socket]:
        engine_end, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        engine_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        engine_end.setblocking(False)
        session = Session('e:1:s', 'e:1', expected_uid=expected, local_agent_id='agent-0')
        channel = Channel('e:1:c', engine_end, 1, session, frame_reader=FrameReader(native))
        made.append((channel, peer))
        return channel, peer

    yield build
    for channel, peer in made:
        channel.frame_reader.free()
        channel.owned_fd.close()
        peer.close()


def send_as(peer: socket.socket, uid: int, data: bytes) -> None:
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setresgid(uid, uid, uid)
            os.setresuid(uid, uid, uid)
            peer.sendall(data)
            os._exit(0)
        except BaseException:
            os._exit(1)
    assert os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 0


def drain(channel: Channel) -> Any:
    """Receive steps until a whole message or a rejection; every sent byte is already queued."""
    result: Any = None
    for _ in range(200):
        result = receive_step(channel, OVERFLOWUID, Clock(), lambda body: None)
        if not isinstance(result, NeedMore):
            break
    return result


def test_pool_uid_sender_accepted(make) -> None:
    channel, peer = make()
    send_as(peer, EXPECTED, HELLO)
    message = drain(channel)
    assert isinstance(message, Hello)
    assert (message.context.sender_uid, message.context.expected_uid, message.context.sender_pid) == \
        (EXPECTED, EXPECTED, None)


def test_root_sender_rejected(make) -> None:
    """uid 0 differs from the expected uid here; the sentinel-before-equality order is shown with the overflow
    uid below, since an expected uid of 0 cannot be passed at all (the FFI refuses it, test_ffi_uid_bounds)."""
    channel, peer = make()
    peer.sendall(HELLO)
    assert drain(channel) == Reject('receive_rejected')


@pytest.mark.parametrize('expected', [EXPECTED, OVERFLOWUID])
def test_overflow_uid_sender_rejected_even_when_equal(make, expected: int) -> None:
    channel, peer = make(expected)
    send_as(peer, OVERFLOWUID, HELLO)
    assert drain(channel) == Reject('receive_rejected')


def test_other_pool_uid_rejected(make) -> None:
    channel, peer = make()
    send_as(peer, EXPECTED + 1, HELLO)
    assert drain(channel) == Reject('receive_rejected')


@pytest.mark.parametrize('split', [2, 4, 9])
def test_uid_change_inside_one_frame_rejected_before_completion(make, split: int) -> None:
    channel, peer = make()
    send_as(peer, EXPECTED, HELLO[:split])
    assert isinstance(drain(channel), NeedMore)
    send_as(peer, EXPECTED + 1, HELLO[split:])
    assert drain(channel) == Reject('receive_rejected')


def test_two_same_uid_processes_compose_one_frame(make) -> None:
    """Same uid, different pids: one execution; no pid subject is derived (P01)."""
    channel, peer = make()
    send_as(peer, EXPECTED, HELLO[:10])
    assert isinstance(drain(channel), NeedMore)
    send_as(peer, EXPECTED, HELLO[10:])
    message = drain(channel)
    assert isinstance(message, Hello) and message.context.sender_pid is None


# R-G2-13: the comparison sits before every phase rule and every error path; a wrong-uid frame never reaches the
# parse, the schema or the phase rule, whatever the row's state (BUILD-PLAN §5).
REQUEST = json.dumps({'v': 2, 'type': 'request', 'id': '1', 'task_call_id': '1', 'task_id': 't1',
                      'resource_id': 'test-doc', 'action': 'document.read', 'args': {}}, separators=(',', ':')).encode()
BODIES = {'hello': HELLO, 'request': struct.pack('>I', len(REQUEST)) + REQUEST,
          'not-json': struct.pack('>I', 7) + b'{"v": 2',            # refused by the Python parse (the C reader frames and compares only)
          'bad-type': struct.pack('>I', 21) + b'{"v":2,"type":"nope"}'}  # valid JSON, refused by the Python schema


def phase_rule(state: str) -> tuple[Callable[[dict[str, Any]], str | None], list[str]]:
    from types import SimpleNamespace
    from engine.objects import ExecState
    from engine.phases import DataPlane
    seen: list[str] = []
    ex = SimpleNamespace(state=ExecState[state], plan=SimpleNamespace(adapter_id='fixture'))
    channel = SimpleNamespace(hello_seen=False)

    def rule(body: dict[str, Any]) -> str | None:
        seen.append(body['type'])
        return DataPlane._phase(ex, channel, body)   # type: ignore[arg-type]
    return rule, seen


def drain_with(channel: Channel, rule: Callable[[dict[str, Any]], str | None]) -> Any:
    result: Any = None
    for _ in range(200):
        result = receive_step(channel, OVERFLOWUID, Clock(), rule)
        if not isinstance(result, NeedMore):
            break
    return result


@pytest.mark.parametrize('state', ['STARTING', 'ACTIVE', 'DRAINING'])
@pytest.mark.parametrize('body', ['hello', 'request', 'bad-type'])
@pytest.mark.parametrize('wrong', ['header', 'body'])
def test_wrong_uid_rejected_before_every_phase_rule(make, state: str, body: str, wrong: str) -> None:
    """'header': the whole frame comes from another pool uid and fails at its first fragment. 'body': the four
    header bytes come from the expected uid and pass; the body comes from another uid and fails at that fragment,
    a later point on the same path. Either way the parse, the schema and the phase rule are never reached."""
    channel, peer = make()
    rule, seen = phase_rule(state)
    data = BODIES[body]
    if wrong == 'body':
        send_as(peer, EXPECTED, data[:4])
        assert isinstance(drain_with(channel, rule), NeedMore)
        send_as(peer, EXPECTED + 1, data[4:])
    else:
        send_as(peer, EXPECTED + 1, data)
    assert drain_with(channel, rule) == Reject('receive_rejected') and seen == []


@pytest.mark.parametrize('state, body, expected', [
    ('STARTING', 'hello', Hello), ('ACTIVE', 'hello', Reject('phase', 'hello_repeated')),
    ('DRAINING', 'request', Reject('phase', 'request_in_draining')), ('ACTIVE', 'not-json', Reject('invalid', 'json')),
    ('ACTIVE', 'bad-type', Reject('invalid', 'type'))])
def test_right_uid_reaches_parse_and_phase_after_the_comparison(make, state: str, body: str, expected: Any) -> None:
    """Control for the test above: with the expected uid the same frames reach the parse and the phase rule."""
    channel, peer = make()
    rule, seen = phase_rule(state)
    send_as(peer, EXPECTED, BODIES[body])
    result = drain_with(channel, rule)
    assert isinstance(result, expected) if isinstance(expected, type) else result == expected
    assert seen == ([] if body in ('not-json', 'bad-type') else [body])


# R-G2-06: uids above 2^31 cross the FFI and the C comparison as unsigned 32-bit values. HIGH and its low-31-bit twin
# EXPECTED differ only in the sign bit; TOP is the highest uid a task can hold (0xFFFFFFFF is the invalid uid).
HIGH, TOP = 2**31 + EXPECTED, 2**32 - 2


@pytest.mark.parametrize('expected', [HIGH, HIGH + 1, TOP])
def test_pool_uid_above_2_31_accepted(make, expected: int) -> None:
    channel, peer = make(expected)
    send_as(peer, expected, HELLO)
    message = drain(channel)
    assert isinstance(message, Hello)
    assert (message.context.sender_uid, message.context.expected_uid) == (expected, expected)


@pytest.mark.parametrize('expected, sender', [
    (HIGH, HIGH + 1), (HIGH + 1, HIGH),          # neighbours above 2^31
    (HIGH, EXPECTED), (EXPECTED, HIGH),          # equal in the low 31 bits, differ in the sign bit
    (TOP, TOP - 2**31), (TOP, HIGH)])
def test_pool_uid_above_2_31_other_uid_rejected(make, expected: int, sender: int) -> None:
    channel, peer = make(expected)
    send_as(peer, sender, HELLO)
    assert drain(channel) == Reject('receive_rejected')


# R-G2-07: the change of sender falls on the frame's last byte, so every earlier fragment passed the comparison.
def test_uid_change_at_last_byte_rejected(make) -> None:
    channel, peer = make()
    send_as(peer, EXPECTED, HELLO[:-1])
    assert isinstance(drain(channel), NeedMore)
    send_as(peer, EXPECTED + 1, HELLO[-1:])
    assert drain(channel) == Reject('receive_rejected')


def test_same_uid_last_byte_completes_the_frame(make) -> None:
    """Control for the test above: the same split from one uid forms the frame."""
    channel, peer = make()
    send_as(peer, EXPECTED, HELLO[:-1])
    assert isinstance(drain(channel), NeedMore)
    send_as(peer, EXPECTED, HELLO[-1:])
    assert isinstance(drain(channel), Hello)


# R-G2-08: two live rows whose expected uids are swapped relative to the senders on their channels. Each frame must
# end its own row's channel, and no row (its own or the other) may take it as that row's message.
def two_rows_sending(native, swapped: bool) -> tuple[Any, Any, Any]:
    from conftest import Harness
    h = Harness(native)
    rows = []
    for i in (0, 1):
        ex = h.launch(i)
        rows.append((ex, h.spawner.prepared(ex)))
    h.pump()
    (a, child_a), (b, child_b) = rows
    assert (a.session.expected_uid, b.session.expected_uid) == (EXPECTED, EXPECTED + 1)
    send_as(child_a, b.session.expected_uid if swapped else a.session.expected_uid, HELLO)
    send_as(child_b, a.session.expected_uid if swapped else b.session.expected_uid, HELLO)
    h.pump(20)
    child_a.close()
    child_b.close()
    return h, a, b


def test_swapped_expected_uids_reject_both_frames_and_select_no_row(native) -> None:
    h, a, b = two_rows_sending(native, swapped=True)
    rejected = h.events('receive_rejected')
    assert sorted(e['connection_ref'] for e in rejected) == sorted([a.execution_id + ':c', b.execution_id + ':c'])
    assert h.events('message_received') == []
    assert (a.close_reason, b.close_reason) == ('receive_rejected', 'receive_rejected')
    assert (a.session.expected_uid, b.session.expected_uid) == (EXPECTED, EXPECTED + 1)   # comparands untouched


def test_unswapped_senders_each_reach_their_own_row(native) -> None:
    """Control for the test above: with each channel's own uid both frames are accepted, each on its own row."""
    h, a, b = two_rows_sending(native, swapped=False)
    subjects = {e['verified_subject']['execution_id']: e['verified_subject'] for e in h.events('message_received')}
    assert set(subjects) == {a.execution_id, b.execution_id} and h.events('receive_rejected') == []
    assert (subjects[a.execution_id]['sender_uid'], subjects[b.execution_id]['sender_uid']) == (EXPECTED, EXPECTED + 1)


# R-G2-09: a task at another uid holds a duplicate of X's agent end itself, received from a task of X over SCM_RIGHTS,
# and sends a valid frame whose delivered pid is that task of X. Naming another task's pid needs CAP_SYS_ADMIN, so
# the sender keeps only that capability across its uid change (not CAP_SETUID: its uid stays its own). A probe socket
# reads back the credential the kernel delivers for the same sendmsg.
CAP_SYS_ADMIN = 21


def _keep_only_sys_admin() -> None:
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)            # _LINUX_CAPABILITY_VERSION_3, this task
    data = (ctypes.c_uint32 * 6)(1 << CAP_SYS_ADMIN, 1 << CAP_SYS_ADMIN, 0, 0, 0, 0)
    if libc.capset(header, data) != 0:
        raise OSError(ctypes.get_errno(), 'capset')


@contextlib.contextmanager
def holder_sent(peer: socket.socket, x_uid: int, holder_uid: int, claimed_pid: Callable[[int], int]) -> Iterator[dict]:
    """A task of X (uid x_uid) passes its copy of the agent end to a holder at holder_uid, which sends HELLO with
    pid = claimed_pid(x_task_pid). Yields the credential the kernel delivered on the probe socket; the task of X
    stays alive until the block ends, so the pid it names is a live task of X when the engine reads."""
    side_x, side_h = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    probe_rx, probe_tx = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    probe_rx.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    x_task = os.fork()
    if x_task == 0:                     # the task of X: holds the agent end, hands a copy over, stays alive
        try:
            side_h.close()
            os.setgroups([])
            os.setresgid(x_uid, x_uid, x_uid)
            os.setresuid(x_uid, x_uid, x_uid)
            socket.send_fds(side_x, [b'e'], [peer.fileno()])
            side_x.recv(1)              # alive until the caller's block ends (EOF)
            os._exit(0)
        except BaseException:
            os._exit(1)
    holder = os.fork()
    if holder == 0:
        try:
            peer.close()                # its only copy is the one received from X
            side_x.close()
            import ctypes
            ctypes.CDLL(None).prctl(8, 1, 0, 0, 0)          # PR_SET_KEEPCAPS
            os.setgroups([])
            os.setresgid(holder_uid, holder_uid, holder_uid)
            os.setresuid(holder_uid, holder_uid, holder_uid)
            _keep_only_sys_admin()
            _, fds, _, _ = socket.recv_fds(side_h, 1, 1)
            agent_end = socket.socket(fileno=fds[0])
            cred = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
                     struct.pack('iII', claimed_pid(x_task), holder_uid, holder_uid))]
            probe_tx.sendmsg([b'p'], cred)
            assert agent_end.sendmsg([HELLO], cred) == len(HELLO)
            os._exit(0)
        except BaseException:
            os._exit(1)
    try:
        assert os.waitstatus_to_exitcode(os.waitpid(holder, 0)[1]) == 0
        _, ancdata, _, _ = probe_rx.recvmsg(1, socket.CMSG_SPACE(12))
        pid, uid, gid = struct.unpack('iII', ancdata[0][2])
        yield dict(pid=pid, uid=uid, gid=gid, x_task=x_task)
    finally:
        side_h.close()                  # the last copy: EOF releases the task of X
        assert os.waitstatus_to_exitcode(os.waitpid(x_task, 0)[1]) == 0
        for s in (side_x, probe_rx, probe_tx):
            s.close()


def test_other_uid_holder_naming_a_task_of_x_rejected(make) -> None:
    channel, peer = make()
    with holder_sent(peer, EXPECTED, EXPECTED + 1, lambda x_task: x_task) as delivered:
        assert (delivered['pid'], delivered['uid']) == (delivered['x_task'], EXPECTED + 1)
        assert drain(channel) == Reject('receive_rejected')


def test_same_uid_holder_naming_a_foreign_pid_accepted(make) -> None:
    """Control: the pid is not consulted either way. A holder at X's own uid naming a task outside X (this test
    process, uid 0) is accepted, and no pid reaches the context."""
    channel, peer = make()
    outside = os.getpid()               # read here: the lambda runs in the holder
    with holder_sent(peer, EXPECTED, EXPECTED, lambda x_task: outside) as delivered:
        assert (delivered['pid'], delivered['uid']) == (outside, EXPECTED)
        message = drain(channel)
    assert isinstance(message, Hello) and message.context.sender_pid is None
