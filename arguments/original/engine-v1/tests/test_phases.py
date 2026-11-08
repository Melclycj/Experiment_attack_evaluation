"""Receive pipeline and phase rules through the lifecycle, on real AF_UNIX stream pairs with PASSCRED and the
real C FrameReader (conn E-01 启动时序 step 6; E-02). Credentials are the kernel's: the SELF workspace's uid is
this process's, every other workspace's is not."""
from __future__ import annotations

import array
import json
import os
import socket
import struct
from typing import Any

import pytest

from conftest import OVERFLOWUID, SELF, Harness, open_fds
from engine.lifecycle import COMMIT
from engine.objects import ExecState, Phase
from engine.receive import Reject, receive_step
from engine.writer import Written

HELLO = {'v': 2, 'type': 'hello', 'protocol': 'w2-local/2', 'adapter_id': 'fixture'}
BYE = {'v': 2, 'type': 'bye', 'reason': 'normal'}
CANCEL = {'v': 2, 'type': 'cancel', 'reply_to': '1', 'reason': 'user'}
TASK_RESULT = {'v': 2, 'type': 'task_result', 'reply_to': '1', 'status': 'ok', 'output': ''}
REQUEST = {'v': 2, 'type': 'request', 'id': '1', 'task_call_id': '1', 'task_id': 'task-1',
           'resource_id': 'test-doc', 'action': 'document.read', 'args': {}}
WELCOME = b'{"v":2,"type":"welcome","protocol":"w2-local/2"}'


def ACCEPT(body: Any) -> None:
    return None


def frame(body: Any) -> bytes:
    data = body if isinstance(body, bytes) else json.dumps(body, separators=(',', ':')).encode()
    return struct.pack('>I', len(data)) + data


def to_hello(h: Harness, i: int = SELF):
    ex = h.launch(i)
    child = h.spawner.prepared(ex)
    h.pump()
    assert child.recv(64) == COMMIT and ex.channel.phase is Phase.HELLO
    return ex, child


def read_frame(sock: socket.socket) -> bytes:
    head = b''
    while len(head) < 4:
        head += sock.recv(4 - len(head))
    size, body = struct.unpack('>I', head)[0], b''
    while len(body) < size:
        body += sock.recv(size - len(body))
    return body


def to_active(h: Harness):
    ex, child = to_hello(h)
    child.sendall(frame(HELLO))
    h.pump()
    assert ex.state is ExecState.ACTIVE and read_frame(child) == WELCOME
    return ex, child


def stop_reasons(h: Harness, ex) -> list[str]:
    h.spawner.drain()
    return [r['reason'] for r in h.spawner.received if r['type'] == 'stop' and r['execution_id'] == ex.execution_id]


def closed(h: Harness, ex, reason: str, stop: str) -> None:
    assert ex.state is ExecState.CLOSED and ex.close_reason == reason, (ex.state, ex.close_reason)
    assert ex.channel.phase is Phase.CLOSED and ex.channel.frame_reader is None
    assert stop_reasons(h, ex) == [stop]


def test_hello_byte_by_byte_then_welcome_and_active(h: Harness) -> None:
    ex, child = to_hello(h)
    wire = frame(HELLO)
    for byte in wire[:-1]:
        child.send(bytes([byte]))
        h.pump(2)
        assert ex.state is ExecState.STARTING and not h.events('message_received')
    child.send(wire[-1:])
    h.pump()
    assert read_frame(child) == WELCOME
    assert (ex.state, ex.channel.phase, ex.session.dispatch_open, ex.session.task_admission) == \
        (ExecState.ACTIVE, Phase.DATA, True, True)
    subject = h.events('message_received')[0]['verified_subject']
    assert subject == {'execution_id': ex.execution_id, 'local_agent_id': f'agent-{SELF}',
                       'session_id': ex.session.session_id, 'channel_id': ex.channel.channel_id,
                       'receiver_generation': ex.channel.receiver_generation, 'expected_uid': os.getuid(),
                       'sender_uid': os.getuid(), 'sender_pid': None}


def test_two_frames_in_one_send(h: Harness) -> None:
    ex, child = to_hello(h)
    child.sendall(frame(HELLO) + frame(BYE))
    h.pump(10)
    assert [e['message']['type'] for e in h.events('message_received')] == ['Hello', 'Bye']
    assert h.events('session_active')
    closed(h, ex, 'agent_bye', 'normal')


def test_wrong_uid_rejected_at_first_fragment(h: Harness) -> None:
    ex, child = to_hello(h, 0)   # expected uid 60000; the kernel stamps this process's uid
    child.send(frame(HELLO)[:1])
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')
    assert not h.events('message_received') and not h.events('session_active')
    assert 'verified_subject' not in h.events('receive_rejected')[0]


@pytest.mark.parametrize('head', [b'\x00\x00\x00\x00', struct.pack('>I', 65537), b'W2BP'])
def test_bad_length_rejected(h: Harness, head: bytes) -> None:
    ex, child = to_hello(h)
    child.sendall(head)
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')


def test_max_body_accepted(h: Harness) -> None:
    ex, child = to_hello(h)
    body = json.dumps(HELLO, separators=(',', ':')).encode()
    child.sendall(frame(body + b' ' * (65536 - len(body))))
    h.pump(20)
    assert ex.state is ExecState.ACTIVE


@pytest.mark.parametrize('body,reason', [
    ({**HELLO, 'uid': 60000}, 'protocol_error'),
    ({**HELLO, 'agent_id': 'other'}, 'protocol_error'),
    ({**HELLO, 'v': 1}, 'protocol_error'),
    ({**HELLO, 'protocol': 'w2-local/1'}, 'protocol_error'),
    ({**HELLO, 'adapter_id': 'other'}, 'protocol_error'),
    # Malformed bodies pass the C reader (framing and comparison only) and are rejected by the Python parse.
    (b'{"v":2,"type":"hello"} {}', 'protocol_error'),
    (b'{"v":2,"type":"hello","type":"bye"}', 'protocol_error'),
    (b'\xef\xbb\xbf{}', 'protocol_error'),
])
def test_invalid_hello_never_active(h: Harness, body: Any, reason: str) -> None:
    ex, child = to_hello(h)
    child.sendall(frame(body))
    h.pump()
    closed(h, ex, reason, 'protocol_error')
    assert not h.events('session_active')


@pytest.mark.parametrize('first', [REQUEST, BYE, CANCEL, TASK_RESULT])
def test_starting_accepts_only_hello(h: Harness, first: dict) -> None:
    ex, child = to_hello(h)
    child.sendall(frame(first) + frame(HELLO))
    h.pump(10)
    closed(h, ex, 'protocol_error', 'protocol_error')
    assert not h.events('session_active') and not h.events('message_received')


@pytest.mark.parametrize('state,body,code', [
    ('STARTING', REQUEST, 'request_in_starting'),
    ('STARTING', {**HELLO, 'adapter_id': 'other'}, 'adapter_mismatch'),
    ('ACTIVE', HELLO, 'hello_repeated'),
    ('DRAINING', REQUEST, 'request_in_draining'),
    ('DRAINING', HELLO, 'hello_in_draining'),
])
def test_phase_refusal_builds_no_subject(h: Harness, state: str, body: dict, code: str) -> None:
    """The phase rule runs before any VerifiedContext exists (conn E-02 steps 5–6)."""
    ex, child = to_hello(h) if state == 'STARTING' else to_active(h)
    if state == 'DRAINING':
        ex.state = ExecState.DRAINING
    before = len(h.events('message_received'))
    child.sendall(frame(body))
    h.pump()
    closed(h, ex, 'protocol_error', 'protocol_error')
    assert len(h.events('message_received')) == before
    rejected = h.events('receive_rejected')[-1]
    assert (rejected['reject']['cause'], rejected['reject']['detail']) == ('phase', code)
    assert 'verified_subject' not in rejected
    assert set(rejected['reject']) == {'cause', 'detail'}   # no execution label on a rejection (si E-09)


def test_rejection_diagnostic_carries_no_agent_text(h: Harness) -> None:
    ex, child = to_hello(h)
    child.sendall(frame({**HELLO, 'AGENT_CHOSEN_TEXT': 'AGENT_CHOSEN_VALUE'}))
    h.pump()
    closed(h, ex, 'protocol_error', 'protocol_error')
    assert h.events('receive_rejected')[-1]['reject']['detail'] == 'hello.fields'
    assert 'AGENT_CHOSEN' not in json.dumps(list(h.recorder.events))


@pytest.mark.parametrize('body,reason,stop', [
    (HELLO, 'protocol_error', 'protocol_error'),
    (TASK_RESULT, 'protocol_error', 'protocol_error'),
    (BYE, 'agent_bye', 'normal'),
])
def test_active_rules_that_close(h: Harness, body: dict, reason: str, stop: str) -> None:
    ex, child = to_active(h)
    child.sendall(frame(body))
    h.pump()
    closed(h, ex, reason, stop)


def test_active_cancel_ignored(h: Harness) -> None:
    ex, child = to_active(h)
    child.sendall(frame(CANCEL) + frame(CANCEL))
    h.pump(10)
    assert ex.state is ExecState.ACTIVE and len(h.events('cancel_ignored')) == 2


@pytest.mark.parametrize('body,reason', [(CANCEL, None), (BYE, 'agent_bye'), (REQUEST, 'protocol_error'),
                                         (HELLO, 'protocol_error'), (TASK_RESULT, 'protocol_error')])
def test_draining_rules(h: Harness, body: dict, reason: str | None) -> None:
    ex, child = to_active(h)
    ex.state = ExecState.DRAINING   # set as finish_execution will (build step 3)
    child.sendall(frame(body))
    h.pump()
    if reason is None:
        assert ex.state is ExecState.DRAINING
    else:
        assert ex.state is ExecState.CLOSED and ex.close_reason == reason


def test_rights_closed_and_never_kept(h: Harness) -> None:
    ex, child = to_active(h)
    passed = os.open('/dev/null', os.O_RDONLY)
    before = open_fds()
    child.sendmsg([frame(CANCEL)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [passed]))])
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')
    assert open_fds() - before == set()
    os.close(passed)


@pytest.mark.parametrize('active', [False, True])
def test_out_of_band_byte_closes(h: Harness, active: bool) -> None:
    """AF_UNIX stream carries MSG_OOB on this kernel; POLLPRI shuts the channel, never resynchronises it."""
    ex, child = to_active(h) if active else to_hello(h)
    child.send(frame(CANCEL)[:3])
    child.send(b'x', socket.MSG_OOB)
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')


def test_partial_frame_times_out_idle_does_not(h: Harness) -> None:
    ex, child = to_active(h)
    h.clock.advance(60_000)
    h.pump()
    assert ex.state is ExecState.ACTIVE   # no byte, no frame timer
    child.send(frame(CANCEL)[:2])
    h.pump()
    h.clock.advance(4_999)
    h.pump()
    assert ex.state is ExecState.ACTIVE
    h.clock.advance(1)
    h.pump()
    closed(h, ex, 'frame_timeout', 'timeout')


def test_progress_does_not_reset_the_frame_period(h: Harness) -> None:
    ex, child = to_active(h)
    wire = frame(CANCEL)
    child.send(wire[:2])
    h.pump()
    h.clock.advance(3_000)
    child.send(wire[2:4])     # header complete, body still missing
    h.pump()
    child.send(wire[4:10])
    h.pump()
    h.clock.advance(1_999)
    h.pump()
    assert ex.state is ExecState.ACTIVE
    h.clock.advance(1)
    h.pump()
    closed(h, ex, 'frame_timeout', 'timeout')


def test_frame_timer_restarts_per_frame(h: Harness) -> None:
    ex, child = to_active(h)
    child.send(frame(CANCEL)[:2])
    h.pump()
    h.clock.advance(4_000)
    child.send(frame(CANCEL)[2:])
    h.pump()
    assert ex.channel.frame_timer is None
    child.send(frame(CANCEL)[:2])
    h.pump()
    h.clock.advance(4_000)
    h.pump()
    assert ex.state is ExecState.ACTIVE


@pytest.mark.parametrize('partial', [b'', frame(CANCEL)[:7]])
def test_eof_closes(h: Harness, partial: bytes) -> None:
    ex, child = to_active(h)
    child.sendall(partial)
    child.close()
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')


def block_welcome(ex) -> None:
    """Injected at the writer boundary: every send attempt reports EAGAIN (nothing sent)."""
    ex.channel.frame_writer.flush = lambda: Written.BLOCKED


@pytest.mark.parametrize('second', [HELLO, REQUEST, CANCEL, BYE])
def test_welcome_still_queued_stays_starting(h: Harness, second: dict) -> None:
    ex, child = to_hello(h)
    block_welcome(ex)
    child.sendall(frame(HELLO))
    h.pump()
    assert ex.state is ExecState.STARTING and ex.channel.hello_seen
    child.sendall(frame(second))
    h.pump()
    closed(h, ex, 'protocol_error', 'protocol_error')
    assert not h.events('session_active')


def test_welcome_blocked_until_startup_deadline(h: Harness) -> None:
    ex, child = to_hello(h)
    block_welcome(ex)
    child.sendall(frame(HELLO))
    h.pump()
    h.clock.advance(30_000)
    h.pump()
    closed(h, ex, 'startup_deadline', 'timeout')
    assert not h.events('session_active')


def test_welcome_send_failure_closes_with_startup_error(h: Harness) -> None:
    ex, child = to_hello(h)
    child.sendall(frame(HELLO))
    child.shutdown(socket.SHUT_RD)
    h.pump()
    closed(h, ex, 'welcome_send_failed', 'startup_error')
    assert not h.events('session_active')


def test_pre_read_check_reads_nothing_on_closed_session(h: Harness, native) -> None:
    calls: list[int] = []

    class Counting:
        def __init__(self, inner) -> None:
            self.inner = inner

        def __getattr__(self, name: str) -> Any:
            return getattr(self.inner, name)

        def frame_receive(self, *args: Any) -> Any:
            calls.append(1)
            return self.inner.frame_receive(*args)

    h = Harness(native, wrap=Counting)
    ex, child = to_active(h)
    child.sendall(frame(CANCEL))
    seen = len(calls)
    ex.session.admission = 'CLOSED'   # close step 1 alone, before step 2 retires the Channel
    assert receive_step(ex.channel, OVERFLOWUID, h.clock, ACCEPT) == Reject('closed') and len(calls) == seen
    h.lc.close_session(ex)
    assert ex.channel.frame_reader is None
    assert receive_step(ex.channel, OVERFLOWUID, h.clock, ACCEPT) == Reject('closed') and len(calls) == seen


def test_old_callbacks_do_not_reach_new_channel_on_reused_fd(h: Harness) -> None:
    from test_lifecycle import occupy_below
    first, first_child = to_active(h)
    old_channel, old_fd = first.channel, first.channel.owned_fd.fileno()
    h.lc.close_session(first)
    h.spawner.empty(first)
    h.spawner.runtime(first)
    h.pump()
    holes = occupy_below(old_fd)
    second, child = to_hello(h)
    for fd in holes:
        os.close(fd)
    assert second.lease.uid == first.lease.uid and second.channel.owned_fd.fileno() == old_fd
    child.sendall(frame(HELLO))
    for stale in (h.lc.data._readable, h.lc.data._flush, h.lc.data._welcomed, h.lc.data._frame_expired):
        stale(first, old_channel)
    assert second.state is ExecState.STARTING and not h.events('receive_rejected')
    h.pump()
    assert second.state is ExecState.ACTIVE and read_frame(child) == WELCOME
    contexts = [e['verified_subject'] for e in h.events('message_received')]
    assert contexts[-1]['channel_id'] == second.channel.channel_id != contexts[0]['channel_id']
    assert contexts[-1]['receiver_generation'] > contexts[0]['receiver_generation']
