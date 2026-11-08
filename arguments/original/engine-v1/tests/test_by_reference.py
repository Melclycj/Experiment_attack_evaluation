"""Consumers by object reference and the Channel → Session association (BUILD-PLAN §5: R-G3-05, R-GX-06;
engine-requirements §7 consumers, §2 the Channel → Session link, §3 unknown-field rejection).

R-G3-05: admission → authorize → dispatch → handler → result → E-09 records follow the objects the frame arrived on.
The negative: a decoy row is put under the request's execution_id before the frame is sent, so any consumer that
looked a row up by that id (admission, prepare, final decision, dispatch, results) would reach the decoy; the request
must finish on its own objects regardless. A control shows the decoy is hit by a keyed lookup at each stage.
R-GX-06: the association is made at reservation, installed with the prepared fd and cleared at close step 2.
"""
from __future__ import annotations

import json
import selectors
from typing import Any

import pytest

from conftest import Harness
from engine import handlers
from engine.objects import ExecState, Phase
from engine.receive import SCHEMAS, Invalid, validate
from engine.records import VerifiedSubject
from reqkit import frames, harness, request, running, send
from test_phases import to_hello


class Decoy:
    """Stands in for a row found by key: any use of it fails the test."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f'a consumer reached a row by execution_id ({name})')


def test_request_path_carries_objects_by_reference(native, monkeypatch) -> None:
    h = harness(native)
    ex, child, binding, call = running(h)
    started: list[tuple[Any, Any]] = []
    real_start = handlers.start

    def spy(loop: Any, op: Any, sink: Any) -> Any:
        started.append((op, sink))
        return real_start(loop, op, sink)

    monkeypatch.setattr(handlers, 'start', spy)
    real_row = h.lc.executions[ex.execution_id]
    h.lc.executions[ex.execution_id] = Decoy()       # from before the frame: admission on, a key lookup hits it
    send(child, request('1', call))
    for _ in range(5):
        h.pump(1)
        if '1' in ex.session.requests:
            break
    entry = ex.session.requests['1']                 # parse, admission, authorization and start in one round
    assert len(started) == 1
    context = entry.message.context
    assert context.session_ref is ex.session and context.channel_ref is ex.channel
    assert entry.session is ex.session and entry.channel is ex.channel and entry.execution is ex
    assert entry.call is call and entry.binding is binding and entry.grant_state is binding.grant_state
    assert entry.subject == VerifiedSubject.from_context(context)
    (op, sink), = started
    assert op.candidate.request is entry and sink._entry is entry
    out = frames(h, child)
    h.lc.executions[ex.execution_id] = real_row
    assert [f['type'] for f in out][-1] == 'result' and {f['reply_to'] for f in out} == {'1'}
    assert ''.join(f['text'] for f in out if f['type'] == 'chunk') == h.lc.requests.resources['test-doc'].blob.decode()
    assert '1' not in ex.session.requests            # returned through its own entry
    subjects = [e['verified_subject'] for e in h.recorder.events
                if e.get('request_key') == entry.request_key and 'verified_subject' in e]
    assert len(subjects) >= 6 and all(s == VerifiedSubject.from_context(context).__dict__ for s in subjects)


@pytest.mark.parametrize('stage', ['on_request', '_prepare', '_final', '_drive'])
def test_decoy_catches_a_lookup_by_execution_id(native, monkeypatch, stage: str) -> None:
    """Control for the test above: a consumer at any stage (admission, prepare, final decision and dispatch,
    result driving) that reaches its row by execution_id does hit the decoy."""
    from engine.requests import Requests
    h = harness(native)
    ex, child, binding, call = running(h)
    real = getattr(Requests, stage)

    def keyed(self: Requests, item: Any) -> None:
        execution_id = item.context.execution_id if stage == 'on_request' else item.execution.execution_id
        h.lc.executions[execution_id].channel        # the lookup the design forbids
        real(self, item)

    monkeypatch.setattr(Requests, stage, keyed)
    h.lc.executions[ex.execution_id] = Decoy()
    send(child, request('1', call))
    with pytest.raises(AssertionError, match='by execution_id'):
        frames(h, child)


def test_association_made_installed_and_cleared_by_object(h: Harness) -> None:
    ex = h.launch()
    assert ex.state is ExecState.PREPARING and ex.session.execution_ref is ex   # made at reservation
    assert ex.channel is None and ex.session.channel_id is None
    child = h.spawner.prepared(ex)
    h.pump()
    channel = ex.channel                                                       # installed with the prepared fd
    assert channel.session is ex.session and ex.session.channel_id == channel.channel_id
    fd = channel.owned_fd.fileno()
    assert fd in h.lc.loop.selector.get_map()
    h.lc.close_session(ex)                                                     # cleared at close step 2
    assert channel.session is None and channel.phase is Phase.CLOSED and ex.channel_retired
    assert fd not in h.lc.loop.handlers and all(key.fileobj != fd for key in h.lc.loop.selector.get_map().values())
    assert channel.frame_reader is None and channel.frame_writer is None
    assert ex.session.channel_id == channel.channel_id                         # the write-once id stays, the link goes
    child.close()


def test_closed_channel_object_is_never_reinstalled(h: Harness) -> None:
    ex, child = to_hello(h)
    first = ex.channel
    h.lc.close_session(ex)
    h.spawner.prepared(ex)                           # a second prepared for the row: fd shut, link faults
    assert h.faulted() and ex.channel is first and first.phase is Phase.CLOSED
    child.close()


IDENTITY_FIELDS = ('uid', 'sender_uid', 'expected_uid', 'pid', 'sender_pid', 'execution_id', 'session_id',
                   'channel_id', 'local_agent_id', 'lease_id', 'grant_ref', 'subject', 'verified_subject')
VALID = {
    'hello': {'protocol': 'w2-local/2', 'adapter_id': 'fixture'},
    'request': {'id': '1', 'task_call_id': '1', 'task_id': 't1', 'resource_id': 'test-doc', 'action': 'document.read',
                'args': {}},
    'cancel': {'reply_to': '1', 'reason': 'user'},
    'task_result': {'reply_to': '1', 'status': 'ok', 'output': ''},
    'bye': {'reason': 'normal'},
}


def test_new_execution_binds_nothing_of_an_old_row_whose_slot_is_still_held(h: Harness) -> None:
    """engine-requirements §2 (no inheritance; conn E-01 101–102): the old row's uid and workspace are back while its
    slot still waits for the runtime copy; a new execution on the same workspace and uid gets new objects only, and
    the old row's late storage fact reaches only the old row."""
    first = h.launch()
    h.spawner.prepared(first).close()
    h.pump()
    h.lc.close_session(first)
    h.spawner.empty(first)
    h.pump()
    assert first.lease_released and first.workspace_released and not first.slot_released
    second = h.launch()                              # same workspace, same uid, old slot still held
    assert second.lease.uid == first.lease.uid and second.lease is not first.lease
    for name in ('session', 'runtime_copy_view', 'workspace_lease'):
        assert getattr(second, name) is not getattr(first, name), name
    assert second.runtime_copy_view.copy_id != first.runtime_copy_view.copy_id
    assert second.workspace_lease.generation > first.workspace_lease.generation
    assert first.execution_id in h.lc.executions and second.channel is None
    h.spawner.runtime(first)                         # the old row's storage fact
    h.pump()
    assert first.slot_released and first.execution_id not in h.lc.executions
    assert second.state is ExecState.PREPARING and second.runtime_copy_view.state.value == 'pending'
    assert not h.lc.control.dead


@pytest.mark.parametrize('kind', sorted(SCHEMAS))
@pytest.mark.parametrize('field', IDENTITY_FIELDS)
def test_identity_like_field_rejects_every_message_type(kind: str, field: str) -> None:
    body = {'v': 2, 'type': kind, **VALID[kind]}
    validate(dict(body))                             # the base message is valid
    with pytest.raises(Invalid):
        validate(json.loads(json.dumps({**body, field: '60000'})))
