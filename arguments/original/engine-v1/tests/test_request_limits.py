"""Resource bounds and decision branches of the request path (conn E-03 容量、调度; rr E-06 final decision; E-04
close order): grant capacity across executions, cancelled timers, each final-check branch on its own, send-failure
ordering, the per-send budget check, data without a demand, control facts before dispatch."""
from __future__ import annotations

import gc
import selectors
import socket

from conftest import Harness
from engine import handlers
from engine.loop import Loop
from engine.objects import ExecState
from engine.requests import RequestEntry
from engine.tasks import GRANTS_ENGINE_MAX, CallState
from reqkit import DOC_RULE, MODEL_RULE, frames, harness, request, running, send
from test_phases import to_active


def reclaim(h: Harness, ex) -> None:
    h.lc.close_session(ex)
    h.spawner.empty(ex)
    h.spawner.runtime(ex)
    h.pump()
    assert ex.execution_id not in h.lc.executions


def test_grant_capacity_returns_when_executions_close(native) -> None:
    h = harness(native)
    for _ in range(GRANTS_ENGINE_MAX // 16 + 1):
        ex, _child = to_active(h)
        for _ in range(16):
            h.lc.grant_task(ex, [], 60_000)
        reclaim(h, ex)
    assert h.lc.tasks.grants_live == 0
    ex, _child = to_active(h)
    assert h.lc.grant_task(ex, [], 60_000) is not None


def test_cancelled_timers_hold_no_request(native) -> None:
    """Denied requests return their slots at once; their 300 s deadline timers must not keep them alive."""
    h = harness(native)
    ex, child, binding, call = running(h)
    for i in range(1, 201):
        send(child, request(str(i), call, resource='missing', timeout_ms=300_000, args={}))
        frames(h, child, rounds=3)
    assert h.lc.requests.live == 0 and not ex.session.requests
    gc.collect()
    assert not [o for o in gc.get_objects() if isinstance(o, RequestEntry)]
    assert len(h.loop.timers) < 1024


def test_loop_compacts_cancelled_timers() -> None:
    loop = Loop(type('C', (), {'real': False, 'now_ns': staticmethod(lambda: 0)})())  # type: ignore[arg-type]
    for _ in range(5000):
        loop.call_at(10 ** 15, lambda: None).cancel()
    assert len(loop.timers) <= 1024


def test_revoked_grant_denies_a_new_request(native) -> None:
    h = harness(native)
    ex, child, binding, call = running(h)
    h.lc.revoke(binding)
    started = []
    real = handlers.start
    handlers.start = lambda *a: started.append(a) or real(*a)
    try:
        send(child, request('1', call))
        fs = frames(h, child)
    finally:
        handlers.start = real
    assert [(f['code'], f['effect']) for f in fs if f.get('reply_to') == '1'] == [('permission_denied',
                                                                                  'not_dispatched')]
    assert started == [] and not h.events('dispatch_started')


def final_branch(native, mutate) -> tuple[list, list]:
    """Change state from the pre_egress observer without the cancel propagation, so that only the final
    decision can see it."""
    h = harness(native)
    ex, child, binding, call = running(h, rules=[MODEL_RULE])
    started = []
    real = handlers.start
    h.lc.requests.observers.append(lambda candidate: mutate(h, ex, binding, call))
    handlers.start = lambda *a: started.append(a) or real(*a)
    try:
        send(child, request('1', call, resource='test-model', action='model.generate',
                            args={'messages': [{'role': 'user', 'text': 'hi'}], 'max_output_tokens': 16}))
        h.pump(4)
    finally:
        handlers.start = real
    reasons = [e['reason_code'] for e in h.events('authorization_decided')]
    return started, reasons


def test_final_check_sees_a_revoked_grant_state(native) -> None:
    def revoke(h, ex, binding, call):
        binding.grant_state.state = 'revoked'
    assert final_branch(native, revoke) == ([], ['grant'])


def test_final_check_sees_a_closed_binding(native) -> None:
    def close(h, ex, binding, call):
        binding.state = 'closed'
    assert final_branch(native, close) == ([], ['binding'])


def test_final_check_sees_a_call_no_longer_running(native) -> None:
    def decide(h, ex, binding, call):
        call.outcome = 'cancelled'
    assert final_branch(native, decide) == ([], ['call_not_running'])


def test_no_record_room_means_no_start(native) -> None:
    def full(h, ex, binding, call):
        h.recorder.has_room = lambda count: False
    started, reasons = final_branch(native, full)
    assert started == [] and reasons == []


def test_send_failure_closes_before_queued_records_drop(native) -> None:
    """A queued task_start meeting a send error ends as closed, decided after the session is sealed."""
    h = harness(native)
    ex, child = to_active(h)
    binding = h.lc.grant_task(ex, [DOC_RULE(h.lc.requests.resources)], 60_000)
    child.close()
    call = h.lc.task_start(binding, 'x')
    h.pump(4)
    assert ex.close_reason in ('channel_send_failed', 'receive_rejected')
    assert (call.state, call.outcome) == (CallState.RESOLVED, 'closed') and not call.start_sent


def test_task_start_budget_checked_at_the_send(native) -> None:
    h = harness(native)
    ex, child = to_active(h)
    binding = h.lc.grant_task(ex, [DOC_RULE(h.lc.requests.resources)], 60_000)
    call = h.lc.task_start(binding, 'x', 1)
    h.clock.advance(2)                       # no loop round: the call's timer has not run
    fs = frames(h, child)
    assert not [f for f in fs if f['type'] == 'task_start'] and not call.start_sent
    assert (call.state, call.outcome) == (CallState.RESOLVED, 'deadline') and ex.state is ExecState.ACTIVE


def test_data_without_a_demand_fails_the_request(native, monkeypatch) -> None:
    h = harness(native)
    sinks = []
    monkeypatch.setattr(handlers.DocumentReadHandler, '_produce', lambda self, limit: sinks.append(self.sink))
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    h.pump(4)
    entry = ex.session.requests['1']
    sinks[0].chunk('first')                  # answers the demand
    sinks[0].chunk('second')                 # no demand behind it
    fs = frames(h, child)
    assert entry.terminal == 'error' and entry.code == 'internal_error'
    # The error withdraws the request's unstarted chunk and takes its seq (conn E-03).
    assert [(f['type'], f['seq']) for f in fs if f.get('reply_to') == '1'] == [('error', 0)]


def test_control_readiness_runs_before_channels() -> None:
    clock = type('C', (), {'real': False, 'now_ns': staticmethod(lambda: 0)})()
    loop = Loop(clock)  # type: ignore[arg-type]
    pairs = [socket.socketpair() for _ in range(3)]
    order = []
    for i, (a, b) in enumerate(pairs):
        b.send(b'x')
        loop.watch(a.fileno(), selectors.EVENT_READ, lambda i=i: order.append(i))
    loop.priority.add(pairs[2][0].fileno())
    loop.run_once(0)
    assert order[0] == 2 and sorted(order) == [0, 1, 2]


def test_half_sent_task_start_past_its_budget_ends_as_deadline(native) -> None:
    """The send-time check commits deadline before the half-sent task_start closes the session."""
    h = harness(native)
    ex, child = to_active(h)
    child.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    ex.channel.owned_fd.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    binding = h.lc.grant_task(ex, [DOC_RULE(h.lc.requests.resources)], 60_000)
    call = h.lc.task_start(binding, 'x' * 60_000, 1_000)
    h.pump(3)
    assert ex.channel.frame_writer.started and not call.start_sent
    h.clock.advance(1_000)                   # past the budget; call the send directly so no timer runs first
    h.lc.data._flush(ex, ex.channel)
    assert ex.close_reason == 'task_start_partial' and call.outcome == 'deadline'


def test_emptied_queue_is_not_a_send_stall(native) -> None:
    h = harness(native)
    ex, child = to_active(h)
    binding = h.lc.grant_task(ex, [DOC_RULE(h.lc.requests.resources)], 60_000)
    call = h.lc.task_start(binding, 'x')     # pending output arms the stall clock
    h.lc.cancel_task(call)                   # withdrawn before its first byte: the queue is empty
    assert ex.channel.stall_timer is None
    h.clock.advance(5_000)
    h.pump()
    assert ex.state is ExecState.ACTIVE


def test_task_input_that_is_not_text_is_refused_at_the_entry(native) -> None:
    import pytest
    from engine.tasks import EntryRefused
    h = harness(native)
    ex, child = to_active(h)
    binding = h.lc.grant_task(ex, [], 60_000)
    with pytest.raises(EntryRefused):
        h.lc.task_start(binding, '\ud800')
    assert ex.session.current_task_call is None
