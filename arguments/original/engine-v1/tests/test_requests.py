"""Request admission, authorization, dispatch and results (conn E-02/E-03, rr E-06/E-07, si E-09), on a real AF_UNIX
stream pair whose kernel credentials are this process's (the SELF workspace). The attack focus: the binding is
reached only through the arriving Session, deny is the default, the final decision re-reads all state, and every
result lands only on the request it belongs to."""
from __future__ import annotations

import json
import os
import socket
from typing import Any

import pytest

from conftest import Harness
from engine import handlers
from engine.objects import ExecState
from engine.records import CONTROL_KINDS, VERIFIED_KINDS
from engine.requests import RPhase
from reqkit import (DOC_TEXT, MODEL_RULE, TOOLS, digest, frames, harness, kinds, request, running, send,
                    task_result, tool_catalog)
from test_phases import closed


def by_reply(fs: list[dict[str, Any]], rid: str) -> list[dict[str, Any]]:
    return [f for f in fs if f.get('reply_to') == rid and f['type'] in ('chunk', 'result', 'error')]


def text_of(fs: list[dict[str, Any]]) -> str:
    return ''.join(f['text'] for f in fs if f['type'] == 'chunk')


@pytest.fixture
def rh(native) -> Harness:
    return harness(native)


def test_document_read_full_path_and_records(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    fs = by_reply(frames(h, child), '1')
    assert text_of(fs) == DOC_TEXT and fs[-1]['type'] == 'result' and fs[-1]['value'] == {}
    assert [f['seq'] for f in fs] == list(range(len(fs))) and len(fs) > 3      # contiguous, result after chunks
    assert all(len(f['text'].encode()) <= 8192 for f in fs[:-1])
    assert not ex.session.requests and h.lc.requests.live == 0                 # slot returned
    order = [k for k in kinds(h) if k in ('request_received', 'authorization_decided', 'dispatch_started',
                                          'operation_completed', 'request_terminal', 'response_sent',
                                          'request_released')]
    assert order == ['request_received', 'authorization_decided', 'dispatch_started', 'operation_completed',
                     'request_terminal', 'response_sent', 'request_released']
    done = h.events('operation_completed')[0]
    assert done['completion']['kind'] == 'document_snapshot_delivered'
    assert done['completion']['output_digest'] == digest(DOC_TEXT.encode())
    assert len(h.events('post_read')) == len(fs) - 1
    assert all(e['flow']['destination'] == ex.execution_id for e in h.events('post_read'))
    send(child, task_result(call))
    h.pump(5)
    assert h.lc.tasks.take_result(call) == {'outcome': 'success', 'reason': 'agent_result', 'agent_status': 'ok',
                                            'output': 'done'}


def test_every_record_subject_is_a_copy_of_the_verified_context(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    send(child, request('2', call, resource='nope'))
    frames(h, child)
    for e in h.recorder.events:
        if e['kind'] in VERIFIED_KINDS:
            s = e['verified_subject']
            assert (s['sender_uid'], s['expected_uid'], s['execution_id'], s['channel_id']) == \
                (os.getuid(), os.getuid(), ex.execution_id, ex.channel.channel_id)
            assert 'control_binding' not in e
        else:
            assert 'verified_subject' not in e
        if e['kind'] in CONTROL_KINDS:
            assert e['control_binding']['execution_id'] == ex.execution_id


@pytest.mark.parametrize('field,value', [('task_call_id', '9'), ('task_id', 'someone-else')])
def test_binding_mismatch_is_denied_without_a_slot(rh: Harness, field: str, value: str) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, {**request('1', call), field: value})
    fs = by_reply(frames(h, child), '1')
    assert fs == [{'v': 2, 'type': 'error', 'reply_to': '1', 'seq': 0, 'code': 'permission_denied',
                   'effect': 'not_dispatched'}]
    assert not h.events('dispatch_started') and h.lc.requests.live == 0
    assert h.events('request_received')[0]['outcome'] == 'rejected' and ex.state is ExecState.ACTIVE


def test_request_with_no_call_is_denied(rh: Harness) -> None:
    from test_phases import to_active
    h = rh
    ex, child = to_active(h)
    send(child, {'v': 2, 'type': 'request', 'id': '1', 'task_call_id': '1', 'task_id': 'x', 'resource_id': 'test-doc',
                 'action': 'document.read', 'args': {}})
    assert by_reply(frames(h, child), '1')[0]['code'] == 'permission_denied'
    assert ex.state is ExecState.ACTIVE and not h.events('dispatch_started')


@pytest.mark.parametrize('rules,resource,action,args,code', [
    ([], 'test-doc', 'document.read', {}, 'permission_denied'),                 # empty grant denies all
    (None, 'other-doc', 'document.read', {}, 'permission_denied'),             # a resource outside the grant
    (None, 'missing', 'document.read', {}, 'not_found'),
    (None, 'test-doc', 'document.write', {}, 'unsupported_action'),
    (None, 'test-doc', 'document.read', {'path': '/etc/passwd'}, 'invalid_request'),
    (None, 'test-model', 'model.generate', {'messages': [{'role': 'user', 'text': 'x'}],
                                            'max_output_tokens': 5}, 'permission_denied'),
])
def test_default_deny_and_catalog_refusals(rh: Harness, rules, resource, action, args, code) -> None:
    h = rh
    ex, child, binding, call = running(h, rules=rules)
    send(child, request('1', call, resource=resource, action=action, args=args))
    fs = by_reply(frames(h, child), '1')
    assert [(f['type'], f['code'], f['effect']) for f in fs] == [('error', code, 'not_dispatched')]
    assert not h.events('dispatch_started') and not ex.session.requests
    assert h.events('authorization_decided')[0]['authorization']['decision'] == 'deny'


def test_expired_and_revoked_grants_deny(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h, ttl_ms=1000)
    h.clock.advance(1500)
    send(child, request('1', call))
    assert by_reply(frames(h, child), '1')[0]['code'] == 'permission_denied'
    h2_binding = h.lc.grant_task(ex, [{'resource_id': 'other-doc', 'action': 'document.read',
                                       'limits': {'max_output_bytes': 100}}], 60_000)
    h.lc.tasks.revoke(h2_binding)
    assert h2_binding.grant_state.state == 'revoked' and h2_binding.grant_state.generation == 2
    assert not h.events('dispatch_started')


def test_revoke_after_dispatch_cancels_with_unknown_effect(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    h.pump(4)
    entry = ex.session.requests['1']
    assert entry.phase is RPhase.DISPATCHED
    h.lc.tasks.revoke(binding)
    fs = by_reply(frames(h, child), '1')
    assert fs[-1]['type'] == 'error' and fs[-1]['code'] == 'cancelled' and fs[-1]['effect'] == 'unknown'
    assert [f['seq'] for f in fs] == list(range(len(fs))) and not ex.session.requests


@pytest.mark.parametrize('inject,code', [
    ('revoke', 'cancelled'), ('expire', 'permission_denied'), ('deadline', 'deadline_exceeded'),
    ('cancel_call', 'cancelled'), ('close', None), ('record_fault', 'internal_error'),
])
def test_final_decision_rereads_state_after_the_observer(native, monkeypatch, inject: str, code) -> None:
    """rr E-06 step 2–3: whatever happens between prepare / pre_egress and the final decision is seen there."""
    h = harness(native)
    ex, child, binding, call = running(h, rules=[MODEL_RULE], ttl_ms=10_000)
    started = []
    monkeypatch.setattr(handlers, 'start', lambda *a: started.append(a))

    def observe(candidate) -> None:
        if inject == 'revoke':
            h.lc.tasks.revoke(binding)
        elif inject == 'expire':
            h.clock.advance(10_001)
        elif inject == 'deadline':
            h.clock.advance(60_000)
        elif inject == 'cancel_call':
            h.lc.cancel_task(call)
        elif inject == 'close':
            h.lc.close_session(ex)
        else:
            h.recorder.fail('injected')

    h.lc.requests.observers.append(observe)
    send(child, request('1', call, resource='test-model', action='model.generate',
                        args={'messages': [{'role': 'user', 'text': 'hi'}], 'max_output_tokens': 16},
                        timeout_ms=30_000))
    h.pump(4)
    assert started == [] and not h.events('dispatch_started') and h.events('pre_egress')
    if inject == 'record_fault':        # nothing more is accepted; the round hook closes the session
        assert ex.state is ExecState.CLOSED and ex.close_reason == 'record_fault'
        return
    assert h.events('request_terminal')
    if code is not None:
        fs = by_reply(frames(h, child), '1')
        assert fs[0]['code'] == code and fs[0]['effect'] == 'not_dispatched'


def test_old_or_repeated_request_id_closes(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, request('2', call, resource='missing'))
    send(child, request('2', call, resource='missing'))
    frames(h, child)
    closed(h, ex, 'protocol_error', 'protocol_error')


def test_agent_cancel_in_flight_and_unknown(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, {'v': 2, 'type': 'cancel', 'reply_to': '77', 'reason': 'user'})   # unknown: ignored
    send(child, request('1', call))
    send(child, {'v': 2, 'type': 'cancel', 'reply_to': '1', 'reason': 'user'})
    fs = by_reply(frames(h, child), '1')
    assert fs[-1]['type'] == 'error' and fs[-1]['code'] == 'cancelled' and fs[-1]['effect'] == 'unknown'
    assert [f['seq'] for f in fs] == list(range(len(fs)))                    # no gap, no second terminal
    assert len([f for f in fs if f['type'] in ('result', 'error')]) == 1
    assert ex.state is ExecState.ACTIVE and h.events('cancel_ignored') and not ex.session.requests


def test_request_deadline(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h)
    send(child, request('1', call, timeout_ms=1))
    h.pump(3)
    h.clock.advance(2)
    fs = by_reply(frames(h, child), '1')
    assert fs[-1]['code'] == 'deadline_exceeded' and fs[-1]['effect'] == 'unknown'


def test_late_completion_does_not_rewrite_the_terminal(rh: Harness, monkeypatch) -> None:
    """A completion after a decided cancel only adds late_completion; no second terminal goes out."""
    h = rh
    captured = []
    real = handlers.start
    monkeypatch.setattr(handlers, 'start', lambda loop, op, sink: captured.append(sink) or real(loop, op, sink))
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    send(child, {'v': 2, 'type': 'cancel', 'reply_to': '1', 'reason': 'user'})
    fs = by_reply(frames(h, child), '1')
    captured[0].complete({}, {'operation_id': 'late', 'kind': 'document_snapshot_delivered', 'output_digest': 'x',
                              'output_bytes': '0', 'observed_at_ns': '0'})
    fs += by_reply(frames(h, child), '1')
    assert [f['type'] for f in fs if f['type'] != 'chunk'] == ['error']
    assert h.events('late_completion') and not h.events('operation_completed')


def test_stale_sink_after_close_reaches_nothing_new(rh: Harness, monkeypatch) -> None:
    """R-GX-06: a handler callback of a closed execution never lands on the next execution of the same uid."""
    h = rh
    captured = []
    real = handlers.start
    monkeypatch.setattr(handlers, 'start', lambda loop, op, sink: captured.append(sink) or real(loop, op, sink))
    ex, child, binding, call = running(h)
    send(child, request('1', call))
    h.pump(3)
    old_sink = captured[0]
    h.lc.close_session(ex)
    h.spawner.empty(ex)
    h.spawner.runtime(ex)
    h.pump()
    assert ex.execution_id not in h.lc.executions
    ex2, child2, binding2, call2 = running(h)
    assert ex2.lease.uid == ex.lease.uid
    send(child2, request('1', call2, resource='other-doc'))   # the same request id, denied by its grant
    frames(h, child2)
    before = (dict(ex2.session.requests), list(h.recorder.events))
    old_sink.chunk('INJECTED')
    old_sink.complete({}, {'operation_id': 'x', 'kind': 'document_snapshot_delivered', 'output_digest': 'x',
                           'output_bytes': '0', 'observed_at_ns': '0'})
    old_sink.released()
    fs = frames(h, child2)
    assert not any('INJECTED' in json.dumps(f) for f in fs)
    assert ex2.session.requests == before[0] and ex2.state is ExecState.ACTIVE
    assert all(e.get('verified_subject', {}).get('execution_id') != ex2.execution_id
               for e in list(h.recorder.events)[len(before[1]):])


def test_model_stub_text_and_tools(native) -> None:
    h = harness(native, catalog_=tool_catalog())
    ex, child, binding, call = running(h, rules=[MODEL_RULE])
    seen = []
    h.lc.requests.observers.append(seen.append)
    args = {'messages': [{'role': 'user', 'text': 'hi'}], 'max_output_tokens': 16}
    send(child, request('1', call, resource='test-model', action='model.generate', args=args))
    fs = by_reply(frames(h, child), '1')
    assert text_of(fs) == handlers.STUB.text and fs[-1]['type'] == 'result' and fs[-1]['value'] == {}
    body = json.loads(seen[0].body_bytes)
    assert body['tools'][0]['function']['name'] == TOOLS[0]['name'] and body['stream'] is True
    assert set(body) == {'model', 'messages', 'tools', 'tool_choice', 'max_tokens', 'stream', 'n', 'temperature',
                         'stream_options'}


@pytest.mark.parametrize('name,outcome', [('read_file', 'result'), ('undeclared', 'error')])
def test_model_stub_tool_calls_checked_against_the_declared_set(native, monkeypatch, name, outcome) -> None:
    monkeypatch.setattr(handlers, 'STUB', handlers.StubConfig('', ({'id': 'c1', 'name': name,
                                                                     'arguments': {'path': 'a'}},)))
    h = harness(native, catalog_=tool_catalog())
    ex, child, binding, call = running(h, rules=[MODEL_RULE])
    send(child, request('1', call, resource='test-model', action='model.generate',
                        args={'messages': [{'role': 'user', 'text': 'hi'}], 'max_output_tokens': 16}))
    fs = by_reply(frames(h, child), '1')
    assert fs[-1]['type'] == outcome
    if outcome == 'result':
        assert fs[-1]['value'] == {'tool_calls': [{'id': 'c1', 'name': 'read_file', 'arguments': {'path': 'a'}}]}
        assert [e['flow']['part'] for e in h.events('post_read')] == ['terminal_value']
    else:
        assert fs[-1]['code'] == 'upstream_error'


def test_no_tools_declared_sends_no_tool_fields(rh: Harness) -> None:
    h = rh
    ex, child, binding, call = running(h, rules=[MODEL_RULE])
    seen = []
    h.lc.requests.observers.append(seen.append)
    send(child, request('1', call, resource='test-model', action='model.generate',
                        args={'messages': [{'role': 'user', 'text': 'hi'}], 'max_output_tokens': 16}))
    frames(h, child)
    assert 'tools' not in json.loads(seen[0].body_bytes) and 'tool_choice' not in json.loads(seen[0].body_bytes)


def test_cleanup_stalled_holds_the_slot_and_closes_admission(rh: Harness, monkeypatch) -> None:
    h = rh
    held = []
    monkeypatch.setattr(handlers.Handle, 'release', lambda self: held.append(self))
    ex, child, binding, call = running(h)
    send(child, request('1', call, resource='other-doc'))   # denied before any handle: releases at once
    send(child, request('2', call))
    send(child, {'v': 2, 'type': 'cancel', 'reply_to': '2', 'reason': 'user'})
    frames(h, child)
    entry = ex.session.requests['2']
    assert entry.worker_state == 'releasing' and held
    h.clock.advance(5_000)
    h.pump()
    assert entry.stalled and not h.lc.accepting_new and ex.close_reason == 'cleanup_stalled'
    assert h.events('cleanup_stalled')
    held[0].released = True
    held[0].sink.released()
    h.pump()
    assert not entry.stalled and not ex.session.requests and h.lc.accepting_new


def test_slow_reader_closes_on_send_stall(native) -> None:
    h = harness(native)
    ex, child, binding, call = running(h)
    child.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    ex.channel.owned_fd.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    for i in range(1, 9):
        send(child, request(str(i), call))
    h.pump(200)
    assert ex.state is ExecState.ACTIVE and ex.channel.stall_timer is not None
    h.clock.advance(5_000)
    h.pump()
    assert ex.state is ExecState.CLOSED and ex.close_reason in ('send_stalled', 'partial_frame_timeout')
