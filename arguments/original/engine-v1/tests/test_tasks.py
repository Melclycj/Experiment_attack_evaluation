"""Calls and their end barrier, trusted entries and finish (conn E-03 连续任务与调用结束屏障; E-04 close_session,
finish_execution; rr E-06 TaskBinding / Grant), on the SELF workspace's real stream pair."""
from __future__ import annotations

import pytest

from conftest import Harness
from engine import handlers
from engine.objects import ExecState
from engine.tasks import CallState, EntryRefused
from reqkit import DOC_RULE, MODEL_RULE, frames, harness, request, running, send, task_result
from test_phases import BYE, closed, frame


@pytest.fixture
def rh(native) -> Harness:
    return harness(native)


def errors(fs: list[dict], rid: str) -> list[tuple[str, str]]:
    return [(f['code'], f['effect']) for f in fs if f['type'] == 'error' and f['reply_to'] == rid]


def test_followup_reuses_the_binding_and_old_call_id_is_denied(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, request('1', call, resource='other-doc'))
    send(child, task_result(call))
    frames(h, child)
    assert call.state is CallState.RESOLVED and h.lc.tasks.take_result(call)['outcome'] == 'success'
    second = h.lc.task_start(binding, 'follow up')
    fs = frames(h, child)
    assert [f['id'] for f in fs if f['type'] == 'task_start'] == [second.call_id] and second.call_id == '2'
    old = request('2', call)                         # the previous call's id, the same task and grant
    send(child, old)
    send(child, request('3', second))
    fs = frames(h, child)
    assert errors(fs, '2') == [('permission_denied', 'not_dispatched')]
    assert [f['type'] for f in fs if f.get('reply_to') == '3'][-1] == 'result'


def test_result_not_taken_blocks_the_next_task(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, task_result(call))
    frames(h, child)
    with pytest.raises(EntryRefused):
        h.lc.task_start(binding, 'again')
    h.lc.tasks.take_result(call)
    with pytest.raises(EntryRefused):
        h.lc.tasks.take_result(call)


def test_task_result_before_children_end(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    h.pump(3)
    send(child, task_result(call))
    fs = frames(h, child)
    assert errors(fs, '1') == [('cancelled', 'unknown')]
    assert call.state is CallState.RESOLVED and (call.outcome, call.outcome_reason) == ('error', 'children_cancelled')
    assert call.agent_status == 'ok'      # the agent's report kept apart from the engine's outcome


def test_task_result_reply_to_stale_is_dropped_and_future_closes(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, task_result(call))
    send(child, task_result(call, 'error'))         # second report for the same call: stale
    frames(h, child)
    assert call.agent_status == 'ok' and ex.state is ExecState.ACTIVE and h.events('stale_or_unrecognized')
    send(child, {**task_result(call), 'reply_to': '5'})
    frames(h, child)
    closed(h, ex, 'protocol_error', 'protocol_error')


def test_trusted_cancel_sends_cancel_and_waits_for_the_agent(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    h.lc.cancel_task(call)
    fs = frames(h, child)
    assert [f for f in fs if f['type'] == 'cancel'] == [{'v': 2, 'type': 'cancel', 'reply_to': call.call_id,
                                                        'reason': 'user'}]
    assert call.state is CallState.DRAINING
    send(child, task_result(call, 'cancelled'))
    frames(h, child)
    assert (call.state, call.outcome, call.agent_status) == (CallState.RESOLVED, 'cancelled', 'cancelled')


def test_late_reply_after_resolution_does_not_overwrite(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h, timeout_ms=1_000)
    h.clock.advance(1_000)
    fs = frames(h, child)
    assert [f['reason'] for f in fs if f['type'] == 'cancel'] == ['timeout'] and call.outcome == 'deadline'
    send(child, task_result(call, 'ok'))
    frames(h, child)
    assert (call.state, call.outcome, call.agent_status) == (CallState.RESOLVED, 'deadline', 'ok')


def test_uncooperative_call_closes_after_the_drain_grace(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h, timeout_ms=1_000)
    h.clock.advance(1_000)
    frames(h, child)
    h.clock.advance(5_000)
    h.pump()
    closed(h, ex, 'task_drain_timeout', 'timeout')
    assert call.state is CallState.RESOLVED and call.outcome == 'deadline'


def test_queued_task_start_withdrawn_is_never_sent(rh: Harness) -> None:
    from test_phases import to_active
    h = rh
    ex, child = to_active(h)
    binding = h.lc.grant_task(ex, [DOC_RULE(h.lc.requests.resources)], 60_000)
    call = h.lc.task_start(binding, 'x')
    h.lc.cancel_task(call)                           # before any loop round: offset 0
    fs = frames(h, child)
    assert not [f for f in fs if f['type'] == 'task_start'] and not call.start_sent
    assert (call.state, call.outcome) == (CallState.RESOLVED, 'cancelled')
    # Never sent: above the sent high-water mark, so a reply naming it is a protocol error (conn E-02).
    send(child, {**task_result(call), 'reply_to': call.call_id})
    frames(h, child)
    closed(h, ex, 'protocol_error', 'protocol_error')


def test_close_with_a_request_in_flight(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    h.pump(3)
    entry = ex.session.requests['1']
    h.lc.close_session(ex)
    assert (entry.terminal, entry.wire_state) == ('closed', 'abandoned') and entry.effect == 'unknown'
    h.pump()
    assert entry.worker_state == 'released' and not ex.session.requests
    assert call.state is CallState.RESOLVED and call.outcome == 'closed'
    h.spawner.empty(ex)
    h.spawner.runtime(ex)
    h.pump()
    assert ex.execution_id not in h.lc.executions


def test_slot_waits_for_a_held_worker(rh: Harness, monkeypatch) -> None:
    """conn E-04 step 6: the uid may be reclaimed, the execution slot waits for the worker's release."""
    h = rh
    held = []
    monkeypatch.setattr(handlers.Handle, 'release', lambda self: held.append(self))
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    h.pump(3)
    h.lc.close_session(ex)
    h.spawner.empty(ex)
    h.spawner.runtime(ex)
    h.pump()
    assert ex.lease_released and ex.execution_id in h.lc.executions
    held[0].sink.released()
    h.pump()
    assert ex.execution_id not in h.lc.executions


def test_finish_execution(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    with pytest.raises(EntryRefused):
        h.lc.finish_execution(ex)                    # a call is unresolved
    send(child, task_result(call))
    frames(h, child)
    h.lc.finish_execution(ex)
    fs = frames(h, child)
    assert fs[-1] == {'v': 2, 'type': 'shutdown', 'reason': 'normal'} and ex.state is ExecState.DRAINING
    with pytest.raises(EntryRefused):
        h.lc.task_start(binding, 'more')
    child.sendall(frame(BYE))
    h.pump()
    closed(h, ex, 'agent_bye', 'normal')


def test_finish_grace_closes(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, task_result(call))
    frames(h, child)
    h.lc.finish_execution(ex)
    frames(h, child)
    h.clock.advance(5_000)
    h.pump()
    closed(h, ex, 'finish_grace', 'timeout')


@pytest.mark.parametrize('rules', [
    [{'resource_id': 'test-doc', 'action': 'document.read', 'limits': {'max_output_bytes': 10}}],
    [{**MODEL_RULE, 'limits': {**MODEL_RULE['limits'], 'max_output_tokens': 5000}}],
    [MODEL_RULE, MODEL_RULE],
    [{'resource_id': 'missing', 'action': 'document.read', 'limits': {'max_output_bytes': 1}}],
    [{'resource_id': 'test-doc', 'action': 'document.read', 'limits': {'max_output_bytes': 10 ** 6}, 'extra': 1}],
])
def test_grant_rules_are_checked_at_the_trusted_entry(rh: Harness, rules) -> None:
    from test_phases import to_active
    h = rh
    ex, _ = to_active(h)
    with pytest.raises(EntryRefused):
        h.lc.grant_task(ex, rules, 60_000)
    assert not ex.session.task_bindings


def test_task_and_grant_ids_are_engine_assigned_and_unique(rh: Harness) -> None:
    from test_phases import to_active
    h = rh
    ex, _ = to_active(h)
    bindings = [h.lc.grant_task(ex, [], 60_000) for _ in range(16)]
    assert len({b.task_id for b in bindings}) == 16 and len({b.grant_state.grant.grant_ref for b in bindings}) == 16
    with pytest.raises(EntryRefused):
        h.lc.grant_task(ex, [], 60_000)
    h.lc.tasks.close_task(bindings[0])
    again = h.lc.grant_task(ex, [], 60_000)
    assert again.task_id not in {b.task_id for b in bindings}
