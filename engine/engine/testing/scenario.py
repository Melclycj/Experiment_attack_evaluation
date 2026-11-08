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
import stat
import sys
import time
import traceback
from typing import Any, Callable

from ..lifecycle import Refused
from ..main import Engine, build, refused
from ..objects import ExecState, Execution, LeaseState, Phase, ViewState, WorkspaceState
from ..startup import StartupRefused

WAIT_S = 20.0
DOC = 'test-doc'


class Driver:
    def __init__(self, engine: Engine, root: Path | None = None) -> None:
        self.engine, self.lc, self.recorder = engine, engine.lifecycle, engine.recorder
        self.root = root                       # the deployment root: the row directories under rows/ (H-05)
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
        """The whole COMMIT sent: the row is ACTIVE from there (no handshake). Not proof of which program runs; the
        runner checks the report the fixture writes after exec."""
        self.wait(lambda: ex.state not in (ExecState.RESERVED, ExecState.PREPARING, ExecState.STARTING),
                  f'{ex.execution_id} leaves start-up')
        if ex.state is not ExecState.ACTIVE:
            raise AssertionError(f'{ex.execution_id} closed in start-up: {ex.close_reason}')

    def messages(self, ex: Execution) -> list[dict[str, Any]]:
        return self.of(ex, 'message_received')

    def running(self, ex: Execution) -> None:
        """ACTIVE and the agent exec'd: its first frame passed the receive pipeline. ACTIVE alone is the whole COMMIT,
        which comes before the bootstrap starts the helpers and execs the agent."""
        self.active(ex)
        self.answered(ex, 1)

    def answered(self, ex: Execution, count: int) -> None:
        """Wait until ``count`` messages of this row passed the receive pipeline (each is answered unsupported_kind). The
        fixture's last message is its acknowledgement, sent once the answers it read are logged; close only after it."""
        self.wait(lambda: len(self.messages(ex)) >= count, f'{count} message(s) on {ex.execution_id}')

    def attributed(self, ex: Execution, name: str) -> None:
        """Every accepted message and request carries the row's identifiers and the comparison result, no pid."""
        subjects = [e['verified_subject'] for e in self.of(ex, 'message_received') + self.of(ex, 'request_received')]
        self.checks[name + '.count'] = len(self.messages(ex))
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


# ---- build steps 1–2 ---------------------------------------------------------------------------
def normal(d: Driver, _: str) -> None:
    first = d.launch('work0', 'agent-basic-0')
    d.active(first)
    d.check('first.phase', first.channel.phase, Phase.DATA)
    d.answered(first, 2)                       # its request and the acknowledgement
    d.attributed(first, 'first')
    d.check('first.count', d.checks['first.count'], 2)
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
    second = d.launch('work0', 'agent-basic-0')
    # v2: a uid is never reused within one engine start (validation.md K-21); the second row gets the next one.
    d.check('new_uid_new_lease', (second.lease.uid != first.lease.uid, second.lease is not first.lease,
                                  second.execution_id != first.execution_id), (True, True, True))
    d.active(second)
    d.answered(second, 2)
    d.attributed(second, 'second')
    d.checks['fd_number_reused'] = second.channel.owned_fd.fileno() == old_fd
    d.check('new_channel_object', (second.channel is not old_channel,
            second.channel.receiver_generation > old_channel.receiver_generation,
            second.session.channel_id != first.session.channel_id), (True, True, True))
    # Callbacks bound to the old objects act on nothing of the new execution.
    d.lc._drive_commit(first, old_channel)
    d.lc._startup_deadline(first)
    d.lc._empty_deadline(first)
    for stale in (d.lc.data._readable, d.lc.data._flush, d.lc.data._frame_expired):
        stale(first, old_channel)
    d.check('stale_callbacks_inert', (second.state, second.lease.state, first.state, len(d.messages(second))),
            (ExecState.ACTIVE, LeaseState.HELD, ExecState.CLOSED, 2))
    d.lc.close_session(second)
    d.released(second)
    d.check('second.empty', second.empty_basis, 'pid1_reaped')
    d.check('workspace_available', (d.lc.workspaces['work0'].state, d.lc.workspaces['work0'].lease_generation),
            (WorkspaceState.AVAILABLE, 2))
    d.check('no_uid_held', d.lc.holders, {})


def parallel(d: Driver, _: str) -> None:
    a, b = d.launch('work0', 'agent-basic-0'), d.launch('work1', 'agent-basic-1')
    d.active(a)
    d.active(b)
    d.answered(a, 2)
    d.answered(b, 2)
    d.attributed(a, 'a')
    d.attributed(b, 'b')
    d.check('count', (d.checks['a.count'], d.checks['b.count']), (2, 2))
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
        # A post-COMMIT FAIL record reads as an oversize length on the ACTIVE row: a close, never a message.
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
    d.running(ex)
    d.lc.close_session(ex)
    d.wait(lambda: ex.spawn_failures, 'reap-stage spawn_failed')
    d.check('reap_failure', ex.spawn_failures[-1]['stage'], 'reap')
    d.check('quarantined', (ex.lease.state, d.lc.workspaces['work0'].state, ex.membership_empty),
            (LeaseState.QUARANTINED, WorkspaceState.QUARANTINED, False))
    d.check('uid_not_reused', d.refused('work0', 'observe-0'))


def kill_no_fact(d: Driver, _: str) -> None:
    ex = d.launch('work0', 'linger-0')
    d.running(ex)
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
        d.running(ex)
        d.lc.close_session(ex)
    d.wait(lambda: d.lc.control.dead, 'control loss')
    d.check('closed', ex.state, ExecState.CLOSED)
    d.check('quarantined', (ex.lease.state, ex.membership_empty), (LeaseState.QUARANTINED, False))
    d.check('admission_closed', (d.lc.accepting_new, d.refused('work1', 'observe-1')), (False, True))


# Agents at the edge of the control channel (fixture "agent <mode>"): mode -> (close reason, stop.reason, number of
# messages that passed the receive pipeline). Every row reaches ACTIVE at the whole COMMIT, before the agent runs.
# fork-sender: a child's and its parent's frames both carry uid_i, both are accepted and answered; after the parent's
# acknowledgement (the third message) the driver closes the row.
AGENT_FAULTS = {
    'partial': ('frame_timeout', 'timeout', 0),
    'oversize': ('receive_rejected', 'protocol_error', 0),
    'rights': ('receive_rejected', 'protocol_error', 0),
    'oob': ('receive_rejected', 'protocol_error', 0),
    'fork-sender': ('trusted_close', 'normal', 3),
}


def agent_fault(d: Driver, mode: str) -> None:
    reason, stop, messages = AGENT_FAULTS[mode]
    fds_before = sorted(os.listdir('/proc/self/fd'))
    ex = d.launch('work0', f'agent-{mode}-0')
    d.active(ex)
    active_at = time.monotonic()
    if mode == 'fork-sender':
        d.answered(ex, messages)
        d.lc.close_session(ex)
    d.wait(lambda: ex.state is ExecState.CLOSED, f'close of {ex.execution_id}', 30)
    d.checks['closed_after_active_s'] = round(time.monotonic() - active_at, 3)
    d.released(ex)
    d.check('close_reason', ex.close_reason, reason)
    d.check('stop_reason', d.sent_stop(ex)['reason'], stop)
    d.check('reached_active', bool(d.of(ex, 'session_active')), True)
    d.check('lease_free', ex.lease.state, LeaseState.FREE)
    d.check('no_fd_left', sorted(os.listdir('/proc/self/fd')), fds_before)
    d.attributed(ex, 'accepted')
    d.check('accepted.count', d.checks['accepted.count'], messages)
    # a rejection names its connection only (si E-09): match it to this row by the row's channel
    d.checks['rejections'] = [e['reject'] for e in d.events('receive_rejected')
                              if e['connection_ref'] == ex.session.channel_id]
    if mode == 'partial':
        d.check('waited_frame_period', d.checks['closed_after_active_s'] >= 4.9)



def two_epoch_first(d: Driver, _: str) -> None:
    """Epoch 1: agent A lingers (a setsid descendant included); the runner SIGKILLs the spawner while A runs. The
    engine sees control loss, quarantines A's lease and ends; A is left in the cell's cgroup for the release gate."""
    ex = d.launch('work0', 'linger-0')
    d.running(ex)
    d.checks['a'] = {'execution_id': ex.execution_id, 'uid': ex.lease.uid, 'channel_id': ex.channel.channel_id}
    d.wait(lambda: d.lc.control.dead, 'control loss after the spawner is killed', 60)
    d.check('closed', ex.state, ExecState.CLOSED)
    d.check('quarantined', (ex.lease.state, ex.membership_empty), (LeaseState.QUARANTINED, False))
    d.check('admission_closed', (d.lc.accepting_new, d.refused('work1', 'observe-1')), (False, True))


def two_epoch_second(d: Driver, _: str) -> None:
    """Epoch 2: a new engine, started by the runner only after its gate read populated 0, leases the same uid. Every
    message it accepts is on its own row, and nothing is rejected."""
    ex = d.launch('work0', 'agent-basic-0')
    d.active(ex)
    d.checks['b'] = {'execution_id': ex.execution_id, 'uid': ex.lease.uid, 'channel_id': ex.channel.channel_id}
    d.answered(ex, 2)
    d.attributed(ex, 'b')
    d.check('b.count', d.checks['b.count'], 2)
    d.check('every_message_on_b', sorted({e['verified_subject']['execution_id']
                                          for e in d.events('message_received') + d.events('request_received')}),
            [ex.execution_id])
    d.check('no_rejection', d.events('receive_rejected'), [])
    d.lc.close_session(ex)
    d.released(ex)
    d.check('b.empty', ex.empty_basis, 'pid1_reaped')
    d.check('no_uid_held', d.lc.holders, {})


def proxy(d: Driver, _: str) -> None:
    """Block 4 integration: the real connector under the spawner. The agent sends one canonical request over the row's
    proxy path; the core admits it on the judgment port, the fallback entry allows GET without a credential, the
    PDP allows it, the allow record is durable, and only then does the connector resolve localhost and its address
    filter refuse 127.0.0.1 (条款 7): reported 'not sent'; the row then closes normally."""
    ex = d.launch('work0', 'agent-proxy-0')
    d.active(ex)
    completed = lambda: [e for e in d.events('diagnostic') if e['name'] == 'request_completed'   # noqa: E731
                         and e['detail']['execution_id'] == ex.execution_id]
    d.wait(lambda: bool(completed()), 'the connector reports the request', 30)
    admitted, decided = d.of(ex, 'request_admitted'), d.of(ex, 'request_decided')
    d.check('no_completion_record', d.of(ex, 'request_reported'), [])            # 648d60f2 4.3: engine 不记完成
    reported = [{'detail': e['detail']} for e in completed()]
    d.check('admitted', [(e['detail']['method'], e['detail']['scheme'], e['detail']['host'], e['detail']['port'],
                          e['detail']['body_len']) for e in admitted], [('GET', 'http', 'localhost', 80, 0)])
    d.check('pdp', [(e['kind'], e['detail'].get('allow')) for e in d.of(ex, 'pdp_requested') + d.of(ex, 'pdp_answered')],
            [('pdp_requested', None), ('pdp_answered', True)])
    d.check('decided', [(e['outcome'], e['reason_code'], e['detail']['credential']) for e in decided],
            [('allow', 'recorded_allow', 'none')])
    d.check('reported', [(e['detail']['result'], e['detail']['status']) for e in reported], [(4, 0)])
    d.check('no_port_fault', d.events('judgment_port_fault'), [])
    d.check('no_rejection', d.events('receive_rejected'), [])
    read_out(d, ex)
    file_worker_checks(d, ex)
    d.lc.close_session(ex)
    d.released(ex)
    d.check('close_reason', ex.close_reason, 'trusted_close')
    d.check('lease_free', ex.lease.state, LeaseState.FREE)
    d.check('worker_exited', [e['kind'] for e in d.of(ex, 'worker_exited')], ['worker_exited'])


def file_worker_checks(d: Driver, ex: Execution) -> None:
    """2.3b integration (validation.md H-05, H-06, H-14): the row's real file worker runs as its dedicated uid with no
    capability and no_new_privs; the fixture's FILE_LIST_OBJECTS on /run/w2/file.sock went through it to the core, which
    answered from the table (no object here) and recorded it; the file judgment port saw no fault."""
    sock = os.lstat(d.root / 'rows' / ex.execution_id / 'file.sock')      # H-05: the row's file port on the host
    d.check('file_sock', (stat.S_ISSOCK(sock.st_mode), sock.st_uid, sock.st_gid, oct(sock.st_mode & 0o7777)),
            (True, ex.lease.uid, ex.lease.gid, '0o600'))
    status = {k: v.split() for line in Path(f'/proc/{ex.worker_pid}/status').read_text().splitlines()
              if ':' in line for k, v in [line.split(':', 1)]}
    d.check('worker_posture', (status['Uid'], status['Gid'], status['CapEff'], status['NoNewPrivs']),
            (['70996'] * 4, ['70996'] * 4, ['0000000000000000'], ['1']))
    d.check('worker_is_not_connector', ex.worker_pid != ex.connector_pid)
    # H-14: the worker made itself not dumpable at start, so the kernel shows its /proc/<pid>/fd as root's and another
    # process of the worker uid cannot read it (the per-process directory itself keeps the worker's uid)
    d.check('worker_not_dumpable', (os.stat(f'/proc/{ex.worker_pid}').st_uid, os.stat(f'/proc/{ex.worker_pid}/fd').st_uid),
            (70996, 0))
    d.check('objects_listed', [e['detail'].get('aliases') for e in d.of(ex, 'file_objects_listed')], [[]])
    d.check('no_file_port_fault', d.events('file_port_fault'), [])


def read_out(d: Driver, ex: Execution) -> None:
    """The fixture sends one control message once it has read the whole response (end frame included); the row closes
    only after that, so a close does not cut the fixture's reading short."""
    d.wait(lambda: bool(d.of(ex, 'message_received')), f'{ex.execution_id} read the whole response', 30)

def transfer_proxy(d: Driver, _: str) -> None:
    """S-24 against the real connector: the proxy scenario's fixture and request again, from work0's push plan, whose
    runtime is the reserved transfer id. The plan is a transfer plan; the request is refused at the first checkpoint
    (not_authorized, transfer_row), the PDP never hears of it, nothing goes out; the row then closes normally."""
    ex = d.launch('work0', 'work0.push')
    d.check('transfer_plan', ex.plan.transfer, 'push')
    d.active(ex)
    d.wait(lambda: bool(d.of(ex, 'request_decided')), 'the core decides the request', 30)
    d.check('decided', [(e['outcome'], e['reason_code']) for e in d.of(ex, 'request_decided')], [('deny', 'transfer_row')])
    d.check('no_pdp', d.of(ex, 'pdp_requested') + d.of(ex, 'pdp_answered'), [])
    d.check('nothing_completed', [e for e in d.events('diagnostic') if e['name'] == 'request_completed'
                                  and e['detail']['execution_id'] == ex.execution_id], [])
    d.check('no_port_fault', d.events('judgment_port_fault'), [])
    read_out(d, ex)
    d.lc.close_session(ex)
    d.released(ex)
    d.check('close_reason', ex.close_reason, 'trusted_close')


def context_proxy(d: Driver, deny: str) -> None:
    """P-02 and K-56 against the real connector and the run's simple PDP, which checks/run_engine_checks.py starts with
    --deny-context <deny>. The proxy scenario's request, first from a row registered with another context, goes to the
    PDP and through as in the proxy scenario; then from a row registered with <deny>, the PDP refuses it (pdp_denied).
    The context reaches the PDP only in its own row's requests; no event carries it."""
    for name, context, outcome in (('other', b'engine-checks-other', ('allow', 'recorded_allow')),
                                   ('denied', deny.encode(), ('deny', 'pdp_denied'))):
        ex = d.lc.launch('work0', 'agent-proxy-0', local_agent_id='agent-work0', policy_context=context)
        d.active(ex)
        d.wait(lambda: bool(d.of(ex, 'request_decided')), f'the core decides the {name} row', 30)
        if outcome[0] == 'allow':
            d.wait(lambda: any(e['name'] == 'request_completed' and e['detail']['execution_id'] == ex.execution_id
                               for e in d.events('diagnostic')), 'the connector reports the request', 30)
        d.check(f'{name}.decided', [(e['outcome'], e['reason_code']) for e in d.of(ex, 'request_decided')], [outcome])
        d.check(f'{name}.pdp', [(e['kind'], e['detail'].get('allow'))
                                for e in d.of(ex, 'pdp_requested') + d.of(ex, 'pdp_answered')],
                [('pdp_requested', None), ('pdp_answered', outcome[0] == 'allow')])
        read_out(d, ex)
        d.lc.close_session(ex)
        d.released(ex)
        d.check(f'{name}.close_reason', ex.close_reason, 'trusted_close')
    d.check('context_in_no_event', [e['kind'] for e in d.recorder.events if deny in json.dumps(e, default=str)], [])
    d.check('no_port_fault', d.events('judgment_port_fault'), [])


def worker_kill(d: Driver, _: str) -> None:
    """H-17 on the whole machine, with the real file worker: once the agent is up and waiting, the runner (root; the
    engine cannot signal the worker's uid) SIGKILLs the row's worker. The row closes with no trusted close from here,
    by the file judgment port's end or by the worker_exited record, whichever reaches the core first; the record says
    signal 9 and comes before the row's execution_empty; the slot and the workspace are released after both."""
    ex = d.launch('work0', 'agent-basic-0')
    d.active(ex)
    d.answered(ex, 2)                          # its request and the acknowledgement: the fixture now waits for EOF
    d.checks['worker_pid'] = ex.worker_pid
    d.wait(lambda: ex.state is ExecState.CLOSED, 'the row closes after its file worker is killed', 60)
    d.released(ex)
    d.checks['close_reason'] = ex.close_reason
    d.checks['file_port_faults'] = [e['reason'] for e in d.events('file_port_fault') if e['execution_id'] == ex.execution_id]
    d.checks['stop_reason'] = (d.sent_stop(ex) or {}).get('reason')
    d.check('closed_by_its_worker', ex.close_reason in ('protocol_error', 'worker_exited'))
    exited = d.of(ex, 'worker_exited')
    d.check('worker_exit', [(e['detail'].get('exit_code'), e['detail'].get('signal')) for e in exited], [(None, 9)])
    order = sorted(exited + d.of(ex, 'execution_empty'), key=lambda e: int(e['producer_seq']))
    d.check('worker_exit_before_empty', [e['kind'] for e in order], ['worker_exited', 'execution_empty'])
    d.check('released', (ex.lease.state, d.lc.workspaces['work0'].state), (LeaseState.FREE, WorkspaceState.AVAILABLE))


def mcp(d: Driver, notes: str) -> None:
    """2.3c end to end with no real agent (validation.md H-23, H-24; H-07, H-08, H-10, H-18, H-20, H-21 on the way):
    the runner's directory <notes> is registered in work0 as 'notes' (directory, read and list, allowed); the fixture
    ("agent mcp", under the deployment's workload policy) speaks HTTP to the row's real MCP server on 127.0.0.1:3129,
    which asks the row's real file worker, which asks this core. Six tool calls: the objects; the directory; notes.txt;
    notes/../outside.txt (bad_path at the first checkpoint); notes/escape, a symlink out (outside_or_symlink at the
    open); /etc/hostname (not_registered at the MCP server: never here). The runner checks the HTTP side and that the
    two marker strings are in no record. Every FILE_ALLOW left after its allow record was durable."""
    from connector.canonical import FILE_OPS_LIST, FILE_OPS_READ, FILE_TYPE_DIR
    from ..fileport import FilePort
    store = d.engine.hook.workspaces
    result, obj = store.register_object('work0', 'notes', notes, FILE_TYPE_DIR, FILE_OPS_READ | FILE_OPS_LIST, 1, 1)
    d.check('registered', (result.applied, obj.dir_path), (True, os.path.realpath(notes)))
    handed: list[dict[str, Any]] = []
    send_allow = FilePort.send_allow

    def spy(port: Any, seq: int, op: int, fd: int) -> None:
        handed.append({'execution_id': port.ex.execution_id, 'seq': seq, 'op': op, 'durable': d.recorder.status()[1]})
        send_allow(port, seq, op, fd)
    FilePort.send_allow = spy                  # type: ignore[method-assign]
    try:
        ex = d.launch('work0', 'agent-mcp-0')
        d.active(ex)
        read_out(d, ex)                        # the fixture's acknowledgement, sent once every response is logged
        size = os.path.getsize(os.path.join(notes, 'notes.txt'))
        d.check('objects_listed', [e['detail']['aliases'] for e in d.of(ex, 'file_objects_listed')], [['notes']] * 6)
        d.check('admitted', [(e['detail']['file_op'], e['detail']['alias'], e['detail']['path'])
                             for e in d.of(ex, 'request_admitted')],
                [('list', 'notes', ''), ('read', 'notes', 'notes.txt'), ('read', 'notes', '../outside.txt'),
                 ('read', 'notes', 'escape')])
        decided = d.of(ex, 'request_decided')
        d.check('decided', [(e['outcome'], e['detail'].get('deny_word'), e['detail'].get('start'),
                             e['detail'].get('actual_length')) for e in decided],
                [('allow', None, 0, None), ('allow', None, None, size), ('deny', 'bad_path', None, None),
                 ('deny', 'outside_or_symlink', None, None)])
        d.check('escape_refused_at_the_open', (decided[3]['reason_code'], decided[3]['detail'].get('errno')),
                ('open_failed', 'ELOOP'))
        d.check('pdp', [e['detail'].get('allow') for e in d.of(ex, 'pdp_answered')], [True, True, True])
        # H-08: each FILE_ALLOW went out once the receipt covered its allow record, by the records' own numbers
        allows = {e['detail']['seq']: int(e['producer_seq']) for e in decided if e['outcome'] == 'allow'}
        mine = [{**h, 'allow_record': allows.get(h['seq'])} for h in handed if h['execution_id'] == ex.execution_id]
        d.checks['handed'] = mine
        d.check('handed_for_each_allow', sorted(h['seq'] for h in mine), sorted(allows))
        d.check('handed_after_durable', all(h['allow_record'] is not None and h['allow_record'] <= h['durable']
                                            for h in mine))
        d.check('no_file_port_fault', d.events('file_port_fault'), [])
        d.lc.close_session(ex)
        d.released(ex)
        d.check('close_reason', ex.close_reason, 'trusted_close')
    finally:
        FilePort.send_allow = send_allow       # type: ignore[method-assign]
        store.delete_object('work0', 'notes')  # later cases and runs see work0 with no object


SCENARIOS = {'normal': normal, 'parallel': parallel, 'startup-fault': startup_fault,
             'close-preparing': close_preparing, 'kill-error': kill_error, 'kill-no-fact': kill_no_fact,
             'control-loss': control_loss, 'agent-fault': agent_fault, 'two-epoch-first': two_epoch_first,
             'two-epoch-second': two_epoch_second, 'proxy': proxy, 'transfer-proxy': transfer_proxy,
             'context-proxy': context_proxy, 'worker-kill': worker_kill, 'mcp': mcp}


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
    library, root, catalog, evidence, name = argv[:5]
    argument = argv[5] if len(argv) > 5 else ''
    result: dict[str, Any] = {'scenario': name, 'argument': argument, 'result': 'failed'}
    try:
        engine = build(Path(library), Path(root), catalog, evidence, keep=100_000, measure_completion=True)
    except StartupRefused as error:
        return refused(error)
    d = Driver(engine, Path(root))
    try:
        d.wait(lambda: d.lc.control.ready, 'control_ready', 60)
        # the simple PDP of the run (checks/run_engine_checks.py) connects on its own retry; wait for it, so its
        # connection is in place before any scenario takes a snapshot of the engine's descriptors (agent_fault)
        until = time.monotonic() + 10
        while engine.hook_port is not None and engine.hook_port.link is None and time.monotonic() < until:
            engine.loop.run_once(0.05)
        result['pdp_connected'] = engine.hook_port is not None and engine.hook_port.link is not None
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
