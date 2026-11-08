"""Receive pipeline and the control channel's answers through the lifecycle, on real AF_UNIX stream pairs with PASSCRED
and the real C FrameReader (conn E-02; validation.md K-04). The row is ACTIVE from the whole COMMIT; there is no
handshake, and every well-formed message is answered 'unsupported_kind'. Credentials are the kernel's: the SELF
workspace's uid is this process's, every other workspace's is not."""
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
from engine.receive import ECHO_MAX, Reject, receive_step
from engine.writer import Written

REQUEST = {'v': 2, 'type': 'request', 'id': '1'}


def answer(reply_to: Any) -> dict[str, Any]:
    return {'v': 2, 'type': 'error', 'reply_to': reply_to, 'code': 'unsupported_kind'}


def frame(body: Any) -> bytes:
    data = body if isinstance(body, bytes) else json.dumps(body, separators=(',', ':')).encode()
    return struct.pack('>I', len(data)) + data


def read_frame(sock: socket.socket) -> bytes:
    head = b''
    while len(head) < 4:
        head += sock.recv(4 - len(head))
    size, body = struct.unpack('>I', head)[0], b''
    while len(body) < size:
        body += sock.recv(size - len(body))
    return body


def to_active(h: Harness, i: int = SELF):
    ex = h.launch(i)
    child = h.spawner.prepared(ex)
    h.pump()
    assert child.recv(64) == COMMIT and ex.state is ExecState.ACTIVE and ex.channel.phase is Phase.DATA
    return ex, child


def stop_reasons(h: Harness, ex) -> list[str]:
    h.spawner.drain()
    return [r['reason'] for r in h.spawner.received if r['type'] == 'stop' and r['execution_id'] == ex.execution_id]


def closed(h: Harness, ex, reason: str, stop: str) -> None:
    assert ex.state is ExecState.CLOSED and ex.close_reason == reason, (ex.state, ex.close_reason)
    assert ex.channel.phase is Phase.CLOSED and ex.channel.frame_reader is None
    assert stop_reasons(h, ex) == [stop]


def test_active_on_the_whole_commit(h: Harness) -> None:
    """STARTING -> ACTIVE when the whole COMMIT is sent, before the agent says anything; the startup deadline ends."""
    ex, child = to_active(h)
    active = h.events('session_active')
    assert [e['control_binding']['execution_id'] for e in active] == [ex.execution_id]
    assert not h.events('message_received')
    h.clock.advance(60_000)                    # past the 30 s startup budget: an ACTIVE row is not closed by it
    h.pump()
    assert ex.state is ExecState.ACTIVE


def test_request_byte_by_byte_then_answered(h: Harness) -> None:
    ex, child = to_active(h)
    wire = frame(REQUEST)
    for byte in wire[:-1]:
        child.send(bytes([byte]))
        h.pump(2)
        assert not h.events('message_received')
    child.send(wire[-1:])
    h.pump()
    assert json.loads(read_frame(child)) == answer('1')
    assert ex.state is ExecState.ACTIVE
    subject = h.events('message_received')[0]['verified_subject']
    assert subject == {'execution_id': ex.execution_id, 'local_agent_id': f'agent-{SELF}',
                       'session_id': ex.session.session_id, 'channel_id': ex.channel.channel_id,
                       'receiver_generation': ex.channel.receiver_generation, 'expected_uid': os.getuid(),
                       'sender_uid': os.getuid(), 'sender_pid': None}


@pytest.mark.parametrize('body,reply_to', [
    ({'v': 2, 'type': 'hello', 'protocol': 'w2-local/2', 'adapter_id': 'fixture'}, None),
    ({'v': 2, 'type': 'bye', 'reason': 'normal'}, None),
    ({'v': 2, 'type': 'cancel', 'reply_to': '1', 'reason': 'user'}, '1'),
    ({'v': 2, 'type': 'task_result', 'reply_to': '7', 'status': 'ok', 'output': ''}, '7'),
    ({'v': 2, 'type': 'request', 'id': '1', 'task_call_id': '1', 'args': {}}, '1'),
    ({'type': 'anything'}, None),                                   # no version, no other field
    ({'type': ''}, None),
    ({'type': 'x', 'id': 5, 'reply_to': '9'}, 5),                   # id first, an integer is echoed
    ({'type': 'x', 'id': 'i' * ECHO_MAX}, 'i' * ECHO_MAX),
    ({'type': 'x', 'id': 'i' * (ECHO_MAX + 1)}, None),              # too long for the reply: null
    ({'type': 'x', 'id': {'nested': 1}}, None),
    ({'type': 'x', 'id': None, 'reply_to': 'r'}, 'r'),
])
def test_any_type_answered_unsupported(h: Harness, body: dict, reply_to: Any) -> None:
    """agent-rm-model 3.9 两条口的先后: the first build's verb set is empty. Whatever the type, the answer is
    'unsupported_kind' on the same channel and the row stays ACTIVE (validation.md K-04)."""
    ex, child = to_active(h)
    child.sendall(frame(body))
    h.pump()
    assert json.loads(read_frame(child)) == answer(reply_to)
    assert ex.state is ExecState.ACTIVE and len(h.events('message_received')) == 1


def test_identity_like_fields_are_not_read(h: Harness) -> None:
    """No field of a message labels it: the subject comes from the channel the bytes arrived on."""
    ex, child = to_active(h)
    child.sendall(frame({'type': 'request', 'id': '1', 'uid': 60000, 'execution_id': 'other:1', 'agent_id': 'x',
                         'session_id': 'other'}))
    h.pump()
    assert json.loads(read_frame(child)) == answer('1')
    subject = h.events('message_received')[0]['verified_subject']
    assert (subject['execution_id'], subject['sender_uid'], subject['session_id']) == \
        (ex.execution_id, os.getuid(), ex.session.session_id)


def test_two_frames_in_one_send(h: Harness) -> None:
    ex, child = to_active(h)
    child.sendall(frame(REQUEST) + frame({**REQUEST, 'id': '2'}))
    h.pump(10)
    assert [json.loads(read_frame(child)) for _ in range(2)] == [answer('1'), answer('2')]
    assert ex.state is ExecState.ACTIVE and len(h.events('message_received')) == 2


def test_wrong_uid_rejected_at_first_fragment(h: Harness) -> None:
    h.launch(SELF)                # takes this process's uid (the first of the range); the row under test gets the next
    ex, child = to_active(h, 0)   # expected uid is not this process's, which the kernel stamps on every byte
    child.send(frame(REQUEST)[:1])
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')
    assert not h.events('message_received')
    assert 'verified_subject' not in h.events('receive_rejected')[0]


@pytest.mark.parametrize('head', [b'\x00\x00\x00\x00', struct.pack('>I', 65537), b'W2BP'])
def test_bad_length_rejected(h: Harness, head: bytes) -> None:
    """b'W2BP' is how the bootstrap's FAIL record reads after COMMIT: an oversize length, a close, never a message."""
    ex, child = to_active(h)
    child.sendall(head)
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')
    assert not h.events('message_received')


def test_max_body_accepted(h: Harness) -> None:
    ex, child = to_active(h)
    body = json.dumps(REQUEST, separators=(',', ':')).encode()
    child.sendall(frame(body + b' ' * (65536 - len(body))))
    h.pump(20)
    assert json.loads(read_frame(child)) == answer('1')
    assert ex.state is ExecState.ACTIVE


@pytest.mark.parametrize('body', [
    # Malformed bodies pass the C reader (framing and comparison only) and are rejected by the Python parse.
    b'{"type":"request"} {}',
    b'{"type":"a","type":"b"}',
    b'\xef\xbb\xbf{"type":"request"}',
    b'not json',
    b'["type"]',
    {'v': 2},                       # no type
    {'type': 7},                    # type not a string
    {'type': 'request', 'n': 1.5},  # no floats
])
def test_invalid_body_closes(h: Harness, body: Any) -> None:
    ex, child = to_active(h)
    child.sendall(frame(body))
    h.pump()
    closed(h, ex, 'protocol_error', 'protocol_error')
    assert not h.events('message_received')
    rejected = h.events('receive_rejected')[-1]
    assert rejected['reject']['cause'] == 'invalid' and 'verified_subject' not in rejected
    assert set(rejected['reject']) == {'cause', 'detail'}   # no execution label on a rejection (si E-09)


def test_rejection_diagnostic_carries_no_agent_text(h: Harness) -> None:
    ex, child = to_active(h)
    child.sendall(frame(b'{"type":"AGENT_CHOSEN_TYPE","AGENT_CHOSEN_TEXT":1,"AGENT_CHOSEN_TEXT":2}'))
    h.pump()
    closed(h, ex, 'protocol_error', 'protocol_error')
    assert h.events('receive_rejected')[-1]['reject']['detail'] == 'duplicate_key'
    assert 'AGENT_CHOSEN' not in json.dumps(list(h.recorder.events))


def test_accepted_message_records_no_agent_text(h: Harness) -> None:
    """The record of an accepted message holds fixed values only; a type of any length cannot overflow a record."""
    ex, child = to_active(h)
    child.sendall(frame({'type': 'AGENT_CHOSEN_' + 'T' * 60_000, 'id': 'AGENT_CHOSEN_ID'}))
    h.pump(20)
    assert json.loads(read_frame(child)) == answer('AGENT_CHOSEN_ID')
    assert ex.state is ExecState.ACTIVE and h.recorder.failed is None
    assert 'AGENT_CHOSEN' not in json.dumps(list(h.recorder.events))


def test_rights_closed_and_never_kept(h: Harness) -> None:
    ex, child = to_active(h)
    passed = os.open('/dev/null', os.O_RDONLY)
    before = open_fds()
    child.sendmsg([frame(REQUEST)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [passed]))])
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')
    assert open_fds() - before == set()
    os.close(passed)


def test_out_of_band_byte_closes(h: Harness) -> None:
    """AF_UNIX stream carries MSG_OOB on this kernel; POLLPRI shuts the channel, never resynchronises it."""
    ex, child = to_active(h)
    child.send(frame(REQUEST)[:3])
    child.send(b'x', socket.MSG_OOB)
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')


def test_partial_frame_times_out_idle_does_not(h: Harness) -> None:
    ex, child = to_active(h)
    h.clock.advance(60_000)
    h.pump()
    assert ex.state is ExecState.ACTIVE   # no byte, no frame timer
    child.send(frame(REQUEST)[:2])
    h.pump()
    h.clock.advance(4_999)
    h.pump()
    assert ex.state is ExecState.ACTIVE
    h.clock.advance(1)
    h.pump()
    closed(h, ex, 'frame_timeout', 'timeout')


def test_progress_does_not_reset_the_frame_period(h: Harness) -> None:
    ex, child = to_active(h)
    wire = frame(REQUEST)
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
    child.send(frame(REQUEST)[:2])
    h.pump()
    h.clock.advance(4_000)
    child.send(frame(REQUEST)[2:])
    h.pump()
    assert ex.channel.frame_timer is None
    child.send(frame(REQUEST)[:2])
    h.pump()
    h.clock.advance(4_000)
    h.pump()
    assert ex.state is ExecState.ACTIVE


@pytest.mark.parametrize('partial', [b'', frame(REQUEST)[:7]])
def test_eof_closes(h: Harness, partial: bytes) -> None:
    ex, child = to_active(h)
    child.sendall(partial)
    child.close()
    h.pump()
    closed(h, ex, 'receive_rejected', 'protocol_error')


def test_answer_blocked_closes_after_the_stall_period(h: Harness) -> None:
    """Injected at the writer boundary: every send attempt reports EAGAIN (nothing sent); the answer waits for space
    at most 5,000 ms (conn E-03)."""
    ex, child = to_active(h)
    ex.channel.frame_writer.flush = lambda: Written.BLOCKED
    child.sendall(frame(REQUEST))
    h.pump()
    h.clock.advance(4_999)
    h.pump()
    assert ex.state is ExecState.ACTIVE
    h.clock.advance(1)
    h.pump()
    closed(h, ex, 'send_stalled', 'timeout')


def test_answer_send_failure_closes(h: Harness) -> None:
    ex, child = to_active(h)
    child.shutdown(socket.SHUT_RD)
    child.sendall(frame(REQUEST))
    h.pump()
    closed(h, ex, 'channel_send_failed', 'protocol_error')


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
    child.sendall(frame(REQUEST))
    seen = len(calls)
    ex.session.admission = 'CLOSED'   # close step 1 alone, before step 2 retires the Channel
    assert receive_step(ex.channel, OVERFLOWUID, h.clock) == Reject('closed') and len(calls) == seen
    h.lc.close_session(ex)
    assert ex.channel.frame_reader is None
    assert receive_step(ex.channel, OVERFLOWUID, h.clock) == Reject('closed') and len(calls) == seen


def test_old_callbacks_do_not_reach_new_channel_on_reused_fd(h: Harness) -> None:
    from test_lifecycle import occupy_below
    first, first_child = to_active(h)
    old_channel, old_fd = first.channel, first.channel.owned_fd.fileno()
    h.lc.close_session(first)
    h.spawner.empty(first)
    h.spawner.runtime(first)
    h.pump()
    holes = occupy_below(old_fd)
    second, child = to_active(h)
    for fd in holes:
        os.close(fd)
    # v2: the fd number is reused, the uid is not (K-21): the second row expects the next uid of the range
    assert second.lease.uid != first.lease.uid and second.channel.owned_fd.fileno() == old_fd
    child.sendall(frame(REQUEST))
    for stale in (h.lc.data._readable, h.lc.data._flush, h.lc.data._frame_expired):
        stale(first, old_channel)
    assert second.state is ExecState.ACTIVE and not h.events('receive_rejected')
    h.pump()
    # The frame carries this process's uid, which is the first row's expectation, not the second's: the second
    # row's own reader rejects it and the rejection is attributed to the new channel object, never the retired one.
    assert second.state is ExecState.CLOSED and second.close_reason == 'receive_rejected'
    rejected = h.events('receive_rejected')
    assert rejected and rejected[-1]['connection_ref'] == second.channel.channel_id != old_channel.channel_id
    assert second.channel.receiver_generation > old_channel.receiver_generation
