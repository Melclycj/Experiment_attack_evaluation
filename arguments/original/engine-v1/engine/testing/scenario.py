"""Integration scenarios (build steps 1–3), run inside a real engine process exec'd by w2-cell.

The driver calls the engine's internal trusted API in-process (launch, grant_task, task_start, cancel_task,
finish_execution, close_session) and observes lifecycle objects and the E-09 events; channel bytes reach the engine
only through its receive pipeline. The agent is the native fixture; its own record of what it sent and received is
checked by the runner after the execution is empty.

usage: engine-scenario LIBW2SANDBOX ROOT CATALOG BUSINESS EVIDENCE SCENARIO [ARGUMENT]
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
import traceback
from typing import Any, Callable

from ..lifecycle import Refused
from ..main import Engine, build, refused
from ..objects import ExecState, Execution, LeaseState, Phase, ViewState, WorkspaceState
from ..startup import StartupRefused
from ..tasks import CallState

WAIT_S = 20.0
DOC = 'test-doc'


class Driver:
    def __init__(self, engine: Engine) -> None:
        self.engine, self.lc, self.recorder = engine, engine.lifecycle, engine.recorder
        self.checks: dict[str, Any] = {}

    def wait(self, predicate: Callable[[], bool], what: str, timeout: float = WAIT_S) -> None:
        if not self.engine.loop.run_until(predicate, timeout):
            raise AssertionError(f'timed out waiting for {what}')

    def check(self, name: str, value: Any, expected: Any = True) -> None:
        self.checks[name] = value
        if value != expected:
            raise AssertionError(f'{name}: {value!r} != {expected!r}')

    def events(self, name: str) -> list[dict[str, Any]]:
        return [e if e['kind'] != 'diagnostic' else {**e, **e['detail']} for e in self.recorder.events
                if e['kind'] == name or (e['kind'] == 'diagnostic' and e['name'] == name)]

    def of(self, ex: Execution, name: str) -> list[dict[str, Any]]:
        def owner(e: dict[str, Any]) -> str | None:
            for group in ('verified_subject', 'control_binding'):
                if group in e:
                    return e[group]['execution_id']
            return e.get('execution_id')
        return [e for e in self.events(name) if owner(e) == ex.execution_id]

    def launch(self, workspace: str, plan: str) -> Execution:
        return self.lc.launch(workspace, plan, local_agent_id='agent-' + workspace)

    def active(self, ex: Execution) -> None:
        """A valid hello received through the pipeline and the whole welcome sent. Not proof of which program
        runs; the runner checks the report the fixture writes after exec."""
        self.wait(lambda: ex.state not in (ExecState.RESERVED, ExecState.PREPARING, ExecState.STARTING),
                  f'{ex.execution_id} leaves start-up')
        if ex.state is not ExecState.ACTIVE:
            raise AssertionError(f'{ex.execution_id} closed in start-up: {ex.close_reason}')

    def messages(self, ex: Execution) -> list[dict[str, Any]]:
        return self.of(ex, 'message_received')

    def attributed(self, ex: Execution, name: str) -> None:
        """Every accepted message and request carries the row's identifiers and the comparison result, no pid."""
        subjects = [e['verified_subject'] for e in self.of(ex, 'message_received') + self.of(ex, 'request_received')]
        self.checks[name + '.types'] = [m['message']['type'] for m in self.messages(ex)]
        self.check(name + '.attributed', all(
            (s['sender_uid'], s['expected_uid'], s['sender_pid'], s['channel_id'], s['local_agent_id'])
            == (ex.lease.uid, ex.lease.uid, None, ex.channel.channel_id, ex.local_agent_id) for s in subjects))

    def released(self, ex: Execution) -> None:
        self.wait(lambda: ex.execution_id not in self.lc.executions, f'slot release of {ex.execution_id}')

    def sent_stop(self, ex: Execution) -> dict[str, Any] | None:
        return next((e['record'] for e in self.events('control_sent')
                     if e['record']['type'] == 'stop' and e['record']['execution_id'] == ex.execution_id), None)

    def refused(self, workspace: str, plan: str) -> bool:
        try:
            self.launch(workspace, plan)
        except Refused:
            return True
        return False

    # ---- tasks --------------------------------------------------------------------------
    def rule(self, resource_id: str) -> dict[str, Any]:
        resource = self.engine.business.resources[resource_id]
        if resource_id == 'test-model':
            return {'resource_id': resource_id, 'action': 'model.generate',
                    'limits': {'max_input_bytes': resource.max_input_bytes,
                               'max_output_tokens': resource.max_output_tokens,
                               'max_output_bytes': resource.max_output_bytes}}
        return {'resource_id': resource_id, 'action': 'document.read',
                'limits': {'max_output_bytes': resource.byte_length}}

    def run_call(self, binding: Any, script: str, timeout_ms: int = 60_000) -> dict[str, Any]:
        call = self.lc.task_start(binding, script, timeout_ms)
        self.wait(lambda: call.state is CallState.RESOLVED, f'call {call.call_id} resolved')
        return self.lc.tasks.take_result(call)

    def request_events(self, ex: Execution, rid: str) -> dict[str, list[str]]:
        key = f'{ex.session.session_id}:a:{rid}'
        out: dict[str, list[str]] = {}
        for e in self.recorder.events:
            if e.get('request_key') == key:
                out.setdefault('kinds', []).append(e['kind'])
                if e['kind'] in ('request_received', 'request_terminal', 'authorization_decided'):
                    out.setdefault('outcomes', []).append(f"{e['kind']}:{e['outcome']}:{e['reason_code']}")
        return out


# ---- build steps 1–2 ---------------------------------------------------------------------------
def normal(d: Driver, _: str) -> None:
    first = d.launch('work0', 'agent-welcome-0')
    d.active(first)
    d.attributed(first, 'first')
    d.check('first.types', d.checks['first.types'], ['Hello'])
    d.check('first.phase', (first.channel.phase, first.session.dispatch_open, first.session.task_admission),
            (Phase.DATA, True, True))
    old_channel, old_fd = first.channel, first.channel.owned_fd.fileno()
    d.lc.close_session(first)
    d.released(first)
    d.check('first.stop_reason', d.sent_stop(first)['reason'], 'normal')
    d.check('first.empty', first.empty_basis, 'pid1_reaped')
    # The fixture exits on channel EOF (close step 2) and may beat the spawner's SIGKILL; either is recorded.
    d.checks['first.exit'] = {k: first.empty_fact[k] for k in ('exit_code', 'signal')}
    d.check('first.runtime', (first.runtime_copy_view.state, first.runtime_copy_view.last_status['basis']),
            (ViewState.RELEASED, 'tree_removed'))
    d.check('first.lease', first.lease.state, LeaseState.FREE)
    d.check('first.channel_retired', (old_channel.phase, old_channel.session), (Phase.CLOSED, None))
    second = d.launch('work0', 'agent-welcome-0')
    d.check('same_uid_new_lease', (second.lease.uid == first.lease.uid, second.lease is not first.lease,
                                   second.execution_id != first.execution_id), (True, True, True))
    d.active(second)
    d.attributed(second, 'second')
    d.checks['fd_number_reused'] = second.channel.owned_fd.fileno() == old_fd
    d.check('new_channel_object', (second.channel is not old_channel,
            second.channel.receiver_generation > old_channel.receiver_generation,
            second.session.channel_id != first.session.channel_id), (True, True, True))
    # Callbacks bound to the old objects act on nothing of the new execution.
    d.lc._drive_commit(first, old_channel)
    d.lc._startup_deadline(first)
    d.lc._empty_deadline(first)
    for stale in (d.lc.data._readable, d.lc.data._flush, d.lc.data._welcomed, d.lc.data._frame_expired):
        stale(first, old_channel)
    d.check('stale_callbacks_inert', (second.state, second.lease.state, first.state, len(d.messages(second))),
            (ExecState.ACTIVE, LeaseState.HELD, ExecState.CLOSED, 1))
    d.lc.close_session(second)
    d.released(second)
    d.check('second.empty', second.empty_basis, 'pid1_reaped')
    d.check('workspace_available', (d.lc.workspaces['work0'].state, d.lc.workspaces['work0'].lease_generation),
            (WorkspaceState.AVAILABLE, 2))
    d.check('no_uid_held', d.lc.holders, {})


def parallel(d: Driver, _: str) -> None:
    a, b = d.launch('work0', 'agent-welcome-0'), d.launch('work1', 'agent-welcome-1')
    d.active(a)
    d.active(b)
    d.attributed(a, 'a')
    d.attributed(b, 'b')
    d.check('types', (d.checks['a.types'], d.checks['b.types']), (['Hello'], ['Hello']))
    d.check('distinct', (a.lease.uid != b.lease.uid, a.channel.owned_fd.fileno() != b.channel.owned_fd.fileno()),
            (True, True))
    d.lc.close_session(b)
    d.released(b)
    d.check('a_unaffected', (a.state, a.lease.state), (ExecState.ACTIVE, LeaseState.HELD))
    d.lc.close_session(a)
    d.released(a)
    d.check('no_uid_held', d.lc.holders, {})


def startup_fault(d: Driver, expected: str) -> None:
    """expected: 'stage=<name>' (spawn_failed) or 'post-commit' (prepared, COMMIT, then empty)."""
    ex = d.launch('work0', 'observe-0')
    d.released(ex)
    if expected == 'post-commit':
        d.check('installed_and_committed', ex.channel is not None and ex.channel.commit_offset == 16)
        d.check('no_spawn_failed', ex.spawn_failures, [])
        # A post-COMMIT FAIL record reads as an oversize length in the hello phase: a close, never a message.
        d.check('no_message', d.messages(ex), [])
        d.checks['close_reason'] = ex.close_reason
    else:
        d.check('failure_stage', ex.spawn_failures[0]['stage'], expected.removeprefix('stage='))
        d.check('no_channel', ex.channel, None)
    d.check('closed_and_empty', (ex.state, ex.membership_empty, ex.lease.state),
            (ExecState.CLOSED, True, LeaseState.FREE))
    d.checks['empty_basis'] = ex.empty_basis


def close_preparing(d: Driver, _: str) -> None:
    ex = d.launch('work0', 'observe-0')
    d.check('submitted', ex.state, ExecState.PREPARING)
    d.lc.close_session(ex)
    d.released(ex)
    d.check('stop_sent', d.sent_stop(ex)['reason'], 'normal')
    d.check('lease_free', ex.lease.state, LeaseState.FREE)
    d.checks['empty_basis'] = ex.empty_basis
    d.checks['prepared_refused'] = bool(d.events('prepared_refused'))


def kill_error(d: Driver, _: str) -> None:
    ex = d.launch('work0', 'linger-0')
    d.active(ex)
    d.lc.close_session(ex)
    d.wait(lambda: ex.spawn_failures, 'reap-stage spawn_failed')
    d.check('reap_failure', ex.spawn_failures[-1]['stage'], 'reap')
    d.check('quarantined', (ex.lease.state, d.lc.workspaces['work0'].state, ex.membership_empty),
            (LeaseState.QUARANTINED, WorkspaceState.QUARANTINED, False))
    d.check('uid_not_reused', d.refused('work0', 'observe-0'))


def kill_no_fact(d: Driver, _: str) -> None:
    ex = d.launch('work0', 'linger-0')
    d.active(ex)
    d.lc.close_session(ex)
    sent_at = time.monotonic()
    d.wait(lambda: ex.lease.state is LeaseState.QUARANTINED, 'quarantine after the empty wait', 10)
    d.checks['quarantine_after_s'] = round(time.monotonic() - sent_at, 3)
    d.check('waited_full_period', d.checks['quarantine_after_s'] >= 4.9)
    d.check('no_empty', ex.membership_empty, False)
    d.check('uid_not_reused', d.refused('work0', 'observe-0'))


def control_loss(d: Driver, plan: str) -> None:
    """Spawner-side loss (reap error or worker loss) closes control; the engine quarantines."""
    ex = d.launch('work0', plan or 'observe-0')
    if plan == 'linger-0':
        d.active(ex)
        d.lc.close_session(ex)
    d.wait(lambda: d.lc.control.dead, 'control loss')
    d.check('closed', ex.state, ExecState.CLOSED)
    d.check('quarantined', (ex.lease.state, ex.membership_empty), (LeaseState.QUARANTINED, False))
    d.check('admission_closed', (d.lc.accepting_new, d.refused('work1', 'observe-1')), (False, True))


# Misbehaving agents (fixture "agent <mode>"): mode -> (close reason, stop.reason, reached ACTIVE, messages that
# passed the receive pipeline). A message the phase rule refuses gets no context and is not among them.
AGENT_FAULTS = {
    'bad-adapter': ('protocol_error', 'protocol_error', False, []),
    'early-request': ('protocol_error', 'protocol_error', False, []),
    'double-hello': ('protocol_error', 'protocol_error', True, ['Hello']),
    'bye': ('agent_bye', 'normal', True, ['Hello', 'Bye']),
    'partial': ('frame_timeout', 'timeout', True, ['Hello']),
    'oversize': ('receive_rejected', 'protocol_error', True, ['Hello']),
    'rights': ('receive_rejected', 'protocol_error', True, ['Hello']),
    'oob': ('receive_rejected', 'protocol_error', True, ['Hello']),
    'fork-sender': ('agent_bye', 'normal', True, ['Hello', 'Cancel', 'Cancel', 'Bye']),
}


def agent_fault(d: Driver, mode: str) -> None:
    reason, stop, reaches_active, messages = AGENT_FAULTS[mode]
    fds_before = sorted(os.listdir('/proc/self/fd'))
    ex = d.launch('work0', f'agent-{mode}-0')
    active_at = None
    if reaches_active:
        d.active(ex)
        active_at = time.monotonic()
    d.wait(lambda: ex.state is ExecState.CLOSED, f'close of {ex.execution_id}', 30)
    if active_at is not None:
        d.checks['closed_after_active_s'] = round(time.monotonic() - active_at, 3)
    d.released(ex)
    d.check('close_reason', ex.close_reason, reason)
    d.check('stop_reason', d.sent_stop(ex)['reason'], stop)
    d.check('reached_active', bool(d.of(ex, 'session_active')), reaches_active)
    d.check('lease_free', ex.lease.state, LeaseState.FREE)
    d.check('no_fd_left', sorted(os.listdir('/proc/self/fd')), fds_before)
    d.attributed(ex, 'accepted')
    d.check('accepted.types', d.checks['accepted.types'], messages)
    # a rejection names its connection only (si E-09): match it to this row by the row's channel
    d.checks['rejections'] = [e['reject'] for e in d.events('receive_rejected')
                              if e['connection_ref'] == ex.session.channel_id]
    if mode in ('bad-adapter', 'early-request', 'double-hello'):
        d.check('refused_by_phase', [(r['cause'], r['detail']) for r in d.checks['rejections']],
                [('phase', {'bad-adapter': 'adapter_mismatch', 'early-request': 'request_in_starting',
                            'double-hello': 'hello_repeated'}[mode])])
    if mode == 'partial':
        d.check('waited_frame_period', d.checks['closed_after_active_s'] >= 4.9)


# ---- build step 3: requests and tasks -----------------------------------------------------------------
def task_read(d: Driver, _: str) -> None:
    """Full read path, a followup that reuses the binding with the previous call's id, refusals, the model stub,
    then the normal finish."""
    ex = d.launch('work0', 'agent-task-0')
    d.active(ex)
    binding = d.lc.grant_task(ex, [d.rule(DOC), d.rule('test-model')], 600_000)
    first = d.run_call(binding, f'req 1 {DOC} document.read {{}};wait 1;result ok')
    d.check('first.result', (first['outcome'], first['agent_status']), ('success', 'ok'))
    d.check('r1.kinds', d.request_events(ex, '1')['kinds'][:3],
            ['request_received', 'authorization_decided', 'dispatch_started'])
    done = d.of(ex, 'operation_completed')
    d.check('r1.evidence', (done[0]['completion']['kind'], done[0]['completion']['output_digest']),
            ('document_snapshot_delivered', d.engine.business.resources[DOC].content_identity))
    d.checks['r1.post_reads'] = len(d.of(ex, 'post_read'))
    second = d.run_call(binding, f'oldreq 2 {DOC} document.read {{}};wait 2;req 3 {DOC} document.read {{}};wait 3;'
                                 'result ok')
    d.check('second.result', second['outcome'], 'success')
    d.check('r2.old_call_denied', d.request_events(ex, '2')['outcomes'],
            ['request_received:rejected:permission_denied'])
    d.check('r3.dispatched', 'dispatch_started' in d.request_events(ex, '3')['kinds'])
    third = d.run_call(binding, 'req 4 other-doc document.read {};wait 4;req 5 missing document.read {};wait 5;'
                                f'req 6 {DOC} document.write {{}};wait 6;req 7 test-model model.generate M;wait 7;'
                                'result ok')
    d.check('third.result', third['outcome'], 'success')
    d.check('refusals', [d.request_events(ex, r)['outcomes'][-1] for r in ('4', '5', '6')],
            ['request_terminal:observed:permission_denied', 'request_terminal:observed:not_found',
             'request_terminal:observed:unsupported_action'])
    d.check('r7.model_stub', 'operation_completed' in d.request_events(ex, '7')['kinds'])
    d.attributed(ex, 'all')
    d.lc.finish_execution(ex)
    d.wait(lambda: ex.state is ExecState.CLOSED, 'finish')
    d.check('close_reason', ex.close_reason, 'agent_bye')
    d.released(ex)
    d.check('stop_reason', d.sent_stop(ex)['reason'], 'normal')
    d.check('lease_free', ex.lease.state, LeaseState.FREE)


def task_parallel(d: Driver, _: str) -> None:
    """Two executions both use request id 1 at once; each result reaches only its own channel (E-03-R1)."""
    a, b = d.launch('work0', 'agent-task-0'), d.launch('work1', 'agent-task-1')
    d.active(a)
    d.active(b)
    ba = d.lc.grant_task(a, [d.rule(DOC)], 60_000)
    bb = d.lc.grant_task(b, [d.rule('other-doc')], 60_000)
    ca = d.lc.task_start(ba, f'req 1 {DOC} document.read {{}};wait 1;result ok')
    cb = d.lc.task_start(bb, 'req 1 other-doc document.read {};wait 1;result ok')
    d.wait(lambda: ca.state is CallState.RESOLVED and cb.state is CallState.RESOLVED, 'both calls')
    d.check('outcomes', (ca.outcome, cb.outcome), ('success', 'success'))
    for ex, resource in ((a, DOC), (b, 'other-doc')):
        done = d.of(ex, 'operation_completed')
        d.check(f'{ex.execution_id}.digest', done[0]['completion']['output_digest'],
                d.engine.business.resources[resource].content_identity)
    d.attributed(a, 'a')
    d.attributed(b, 'b')
    for ex in (a, b):
        d.lc.close_session(ex)
        d.released(ex)


def task_cancel(d: Driver, _: str) -> None:
    ex = d.launch('work0', 'agent-task-0')
    d.active(ex)
    binding = d.lc.grant_task(ex, [d.rule(DOC)], 60_000)
    call = d.lc.task_start(binding, 'hold')
    d.wait(lambda: call.state is CallState.RUNNING, 'running')
    d.lc.cancel_task(call)
    d.wait(lambda: call.state is CallState.RESOLVED, 'cancelled call resolved')
    d.check('cancelled', (call.outcome, call.agent_status), ('cancelled', 'cancelled'))
    d.lc.tasks.take_result(call)
    timed = d.lc.task_start(binding, 'hold', 1_000)
    d.wait(lambda: timed.state is CallState.RESOLVED, 'deadline call resolved')
    d.check('deadline', (timed.outcome, timed.agent_status), ('deadline', 'cancelled'))
    d.lc.close_session(ex)
    d.released(ex)


def task_protocol(d: Driver, mode: str) -> None:
    script = {'dup': 'req 2 missing document.read {};wait 2;req 2 missing document.read {}',
              'future': 'futureresult'}[mode]
    ex = d.launch('work0', 'agent-task-0')
    d.active(ex)
    binding = d.lc.grant_task(ex, [d.rule(DOC)], 60_000)
    d.lc.task_start(binding, script)
    d.wait(lambda: ex.state is ExecState.CLOSED, 'protocol close')
    d.check('close_reason', ex.close_reason, 'protocol_error')
    d.released(ex)
    d.check('stop_reason', d.sent_stop(ex)['reason'], 'protocol_error')


def task_close_inflight(d: Driver, _: str) -> None:
    ex = d.launch('work0', 'agent-task-0')
    d.active(ex)
    binding = d.lc.grant_task(ex, [d.rule(DOC)], 60_000)
    call = d.lc.task_start(binding, f'req 1 {DOC} document.read {{}};hold')
    d.wait(lambda: '1' in ex.session.requests, 'request admitted')
    entry = ex.session.requests['1']
    d.lc.close_session(ex)
    d.checks['terminal_at_close'] = (entry.terminal, entry.wire_state, entry.effect)
    d.released(ex)
    d.check('call', (call.state, call.outcome), (CallState.RESOLVED, 'closed'))
    d.check('request_returned', (entry.returned, entry.worker_state in ('none', 'released')), (True, True))
    d.check('lease_free', ex.lease.state, LeaseState.FREE)


# ---- two-epoch run (R-GX-04; registry §5 item 27) ------------------------------------------------
def two_epoch_first(d: Driver, _: str) -> None:
    """Epoch 1: agent A lingers (a setsid descendant included); the runner SIGKILLs the spawner while A runs. The
    engine sees control loss, quarantines A's lease and ends; A is left in the cell's cgroup for the release gate."""
    ex = d.launch('work0', 'linger-0')
    d.active(ex)
    d.checks['a'] = {'execution_id': ex.execution_id, 'uid': ex.lease.uid, 'channel_id': ex.channel.channel_id}
    d.wait(lambda: d.lc.control.dead, 'control loss after the spawner is killed', 60)
    d.check('closed', ex.state, ExecState.CLOSED)
    d.check('quarantined', (ex.lease.state, ex.membership_empty), (LeaseState.QUARANTINED, False))
    d.check('admission_closed', (d.lc.accepting_new, d.refused('work1', 'observe-1')), (False, True))


def two_epoch_second(d: Driver, _: str) -> None:
    """Epoch 2: a new engine, started by the runner only after its gate read populated 0, leases the same uid. Every
    message it accepts is on its own row, and nothing is rejected."""
    ex = d.launch('work0', 'agent-welcome-0')
    d.active(ex)
    d.checks['b'] = {'execution_id': ex.execution_id, 'uid': ex.lease.uid, 'channel_id': ex.channel.channel_id}
    d.attributed(ex, 'b')
    d.check('b.types', d.checks['b.types'], ['Hello'])
    d.check('every_message_on_b', sorted({e['verified_subject']['execution_id']
                                          for e in d.events('message_received') + d.events('request_received')}),
            [ex.execution_id])
    d.check('no_rejection', d.events('receive_rejected'), [])
    d.lc.close_session(ex)
    d.released(ex)
    d.check('b.empty', ex.empty_basis, 'pid1_reaped')
    d.check('no_uid_held', d.lc.holders, {})

SCENARIOS = {'normal': normal, 'parallel': parallel, 'startup-fault': startup_fault,
             'close-preparing': close_preparing, 'kill-error': kill_error, 'kill-no-fact': kill_no_fact,
             'control-loss': control_loss, 'agent-fault': agent_fault, 'task-read': task_read,
             'task-parallel': task_parallel, 'task-cancel': task_cancel, 'task-protocol': task_protocol,
             'task-close-inflight': task_close_inflight, 'two-epoch-first': two_epoch_first,
             'two-epoch-second': two_epoch_second}


def reap_spawner(d: Driver) -> int | None:
    """The engine is the spawner's direct parent; record the spawner's actual exit status."""
    children = Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()
    if not children:
        return None
    pid, until = int(children[0]), time.monotonic() + WAIT_S
    while time.monotonic() < until:
        got, status = os.waitpid(pid, os.WNOHANG)
        if got:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.02)
    return None


def main(argv: list[str]) -> int:
    library, root, catalog, business, evidence, name = argv[:6]
    argument = argv[6] if len(argv) > 6 else ''
    result: dict[str, Any] = {'scenario': name, 'argument': argument, 'result': 'failed'}
    try:
        engine = build(Path(library), Path(root), catalog, business, evidence, keep=100_000)
    except StartupRefused as error:
        return refused(error)
    d = Driver(engine)
    try:
        d.wait(lambda: d.lc.control.ready, 'control_ready', 60)
        SCENARIOS[name](d, argument)
        result['result'] = 'passed'
    except BaseException as error:
        result['error'] = repr(error)
        result['traceback'] = traceback.format_exc()
    finally:
        if not d.lc.control.dead:
            d.lc.control.fault('scenario complete')
        result['checks'] = d.checks
        result['spawner_exit'] = reap_spawner(d)
        result['receipt'] = engine.recorder.close()
        result['diagnostics_dropped'] = engine.recorder.dropped
        sys.stdout.write(json.dumps({'event': 'scenario_result', **result}, default=str) + '\n')
    return 0 if result['result'] == 'passed' else 1
