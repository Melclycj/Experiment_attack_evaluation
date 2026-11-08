"""Lifecycle manager: reservation, handoff install, close and reclaim (conn E-01, E-04; rr E-08).

Every state change runs inside one loop callback (one decision). Control records reach a row only
through its never-reused execution_id with matching lease_id and epoch; no uid or fd lookup exists.
"""
from __future__ import annotations

from collections import OrderedDict
import os
import selectors
import socket
import struct
from typing import Any, Callable

from .control import ControlClient, ControlFault, Intent
from .ffi import Native
from .loop import MS, Loop
from .objects import (Channel, ExecState, Execution, LeaseState, Phase, RuntimeCopyView, Session,
                      StopState, Submission, UidLease, ViewState, WorkspaceLease, WorkspaceRecord,
                      WorkspaceState)
from .phases import DataPlane
from .receive import FrameReader
from .records import ControlBinding, RecordFault, Recorder, record_lifecycle
from .requests import Requests
from .startup import Catalog
from .tasks import TASK_BUDGET_MS, CallState, Tasks
from .writer import FrameWriter

EXECUTIONS_MAX = 16           # live execution slots, matching the spawner's 16 live records
TOMBSTONES_MAX = 1024
STARTUP_BUDGET_MS = 30_000    # conn E-01 step 5: default 30,000, range 1,000–300,000
EMPTY_WAIT_MS = 5_000         # conn E-04: wait for the empty fact after a whole stop send
SEQ_MAX = 2 ** 64 - 1
COMMIT = struct.pack('>4sHHII', b'W2BP', 1, 2, 0, 0)
ENVELOPE = ('v', 'type', 'engine_epoch', 'seq', 'execution_id', 'lease_id')

# Local close reasons mapped onto the closed stop.reason set (conn E-04).
STOP_REASONS = {
    'trusted_close': 'normal',
    'startup_deadline': 'timeout',
    'spawn_failed': 'startup_error',
    'commit_send_failed': 'startup_error',
    'reap_error': 'control_shutdown',
    'runtime_retained': 'control_shutdown',
    'spawn_uncertain': 'control_shutdown',
    'control_fault': 'control_shutdown',
    'execution_empty': 'normal',
    'agent_bye': 'normal',
    'frame_timeout': 'timeout',
    # The C reader reports EOF, a credential failure, an oversize length and a late fragment alike.
    'receive_rejected': 'protocol_error',
    'protocol_error': 'protocol_error',
    'welcome_send_failed': 'startup_error',
    'channel_send_failed': 'protocol_error',
    # Request and task paths (build step 3).
    'send_stalled': 'timeout',
    'partial_frame_timeout': 'timeout',
    'output_exhausted': 'timeout',          # the agent does not read; the control reserve is full
    'task_drain_timeout': 'timeout',
    'task_start_partial': 'normal',         # a trusted cancel or deadline met a half-sent task_start
    'finish_grace': 'timeout',
    'cleanup_stalled': 'timeout',
    'record_fault': 'control_shutdown',
}


class Refused(Exception):
    """A launch refused before any row was created."""


def _terminal(body: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in body.items() if k not in ENVELOPE}


class Lifecycle:
    def __init__(self, loop: Loop, native: Native, control_fd: int, epoch: str, catalog: Catalog,
                 workspaces: dict[str, WorkspaceRecord], recorder: Recorder, overflowuid: int,
                 resources: Any = None, startup_budget_ms: int = STARTUP_BUDGET_MS) -> None:
        if not 1_000 <= startup_budget_ms <= 300_000:
            raise ValueError('startup budget outside 1,000–300,000 ms')
        self.loop, self.epoch, self.catalog, self.recorder = loop, epoch, catalog, recorder
        self.trace = recorder.diagnostic
        self.native = native
        resources = resources if resources is not None else {}
        self.data = DataPlane(loop, overflowuid, recorder, self._close, self._step)
        self.tasks = Tasks(loop, recorder, resources, lambda: self.accepting_new, self._close, self._step,
                           self._reclaim)
        self.requests = Requests(loop, recorder, resources, self._close, self._step, self._reclaim,
                                 self._recompute_admission)
        self.data.requests = self.tasks.requests = self.requests
        self.data.tasks = self.requests.tasks = self.tasks
        self.tasks.data = self.requests.data = self.data
        self.record_fault_handled = False
        loop.round_hooks.append(self._check_records)
        self.workspaces = workspaces
        self.pool = {w.workspace_uid for w in workspaces.values()}
        self.startup_budget_ms = startup_budget_ms
        self.executions: dict[str, Execution] = {}
        self.tombstones: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.holders: dict[int, UidLease] = {}   # allocator state: uid -> held/quarantined lease
        self.allocation_seq = 0
        self.generation = 0
        self.accepting_new = True
        self.control_healthy = True
        self.control = ControlClient(loop, native, control_fd, epoch, on_record=self.on_record,
                                     on_sent=self._on_sent, on_uncertain=self._on_uncertain,
                                     on_expired=self._on_expired, on_fault=self._on_control_fault,
                                     trace=self.trace)

    def start(self) -> None:
        self.control.send_init(self.catalog.catalog_digest, self.catalog.storage_profile_digest)

    def _step(self, action: Callable[..., None], *args: Any) -> Callable[[], None]:
        """A loop callback that runs one decision and then lets the single writer send."""
        def run() -> None:
            action(*args)
            self.control.flush()
        return run

    # ---- reservation (one decision: lease take, rows, spawn enqueue) -----------------------
    def launch(self, workspace_id: str, launch_plan_id: str, local_agent_id: str) -> Execution:
        def refuse(why: str) -> Refused:
            self.trace('launch_refused', workspace_id=workspace_id, launch_plan_id=launch_plan_id,
                       reason=why)
            return Refused(why)

        if not self.control.ready or self.control.dead or not self.control_healthy:
            raise refuse('control not ready')
        if not self.accepting_new:
            raise refuse('admission closed')
        plan = self.catalog.plans.get(launch_plan_id)
        ws = self.workspaces.get(workspace_id)
        if plan is None or ws is None or plan.workspace_id != workspace_id:
            raise refuse('plan does not name this workspace')
        if len(self.executions) >= EXECUTIONS_MAX:
            raise refuse('execution slots exhausted')
        if ws.state is not WorkspaceState.AVAILABLE or ws.active_lease is not None:
            raise refuse('workspace not available')
        uid, gid = ws.workspace_uid, ws.workspace_gid
        if uid not in self.pool or uid in self.holders:
            raise refuse('uid not leasable')
        previous = ws.last_execution
        if previous is not None and not (previous.state is ExecState.CLOSED and previous.membership_empty):
            raise refuse('previous lease not CLOSED and empty')
        if self.allocation_seq >= SEQ_MAX:
            raise refuse('allocation counter exhausted')
        self.allocation_seq += 1
        eid = f'{self.epoch}:{self.allocation_seq}'
        lease = UidLease(eid + ':u', eid, uid, gid)
        session = Session(eid + ':s', eid, expected_uid=lease.uid, local_agent_id=local_agent_id)
        ws.lease_generation += 1
        wlease = WorkspaceLease(ws, eid, ws.lease_generation)
        ex = Execution(eid, local_agent_id, lease.lease_id, plan.launch_plan_id, plan.launch_plan_digest,
                       lease, session, plan, wlease, RuntimeCopyView(eid + ':r'))
        session.execution_ref = ex
        ws.active_lease, ws.state, ws.last_execution = wlease, WorkspaceState.LEASED, ex
        self.holders[uid] = lease
        self.executions[eid] = ex
        ex.startup_deadline_ns = self.loop.clock.now_ns() + self.startup_budget_ms * MS
        self.control.queue_spawn(ex, dict(uid=uid, gid=gid, launch_plan_id=plan.launch_plan_id,
                                          launch_plan_digest=plan.launch_plan_digest,
                                          startup_deadline_ns=str(ex.startup_deadline_ns)))
        ex.timers.append(self.loop.call_at(ex.startup_deadline_ns, self._step(self._startup_deadline, ex)))
        record_lifecycle(self.recorder, 'spawn_requested', ex, uid=uid, gid=gid, workspace_id=workspace_id,
                         workspace_generation=wlease.generation, launch_plan_id=launch_plan_id)
        self.control.flush()
        return ex

    def _startup_deadline(self, ex: Execution) -> None:
        if ex.state in (ExecState.RESERVED, ExecState.PREPARING, ExecState.STARTING):
            self._close(ex, 'startup_deadline')

    # ---- writer callbacks ---------------------------------------------------------------
    def _on_sent(self, intent: Intent) -> None:
        ex = intent.execution
        if intent.kind == 'spawn':
            ex.spawn_submission = Submission.SUBMITTED
            ex.state = ExecState.PREPARING
        else:
            ex.stop = StopState.SENT
            ex.timers.append(self.loop.call_at(self.loop.clock.now_ns() + EMPTY_WAIT_MS * MS,
                                               self._step(self._empty_deadline, ex)))

    def _on_uncertain(self, intent: Intent) -> None:
        if intent.kind == 'spawn':
            intent.execution.spawn_submission = Submission.UNCERTAIN
            self._close(intent.execution, 'spawn_uncertain')

    def _on_expired(self, intent: Intent) -> None:
        self._close(intent.execution, 'startup_deadline')

    def _empty_deadline(self, ex: Execution) -> None:
        if not ex.membership_empty and ex.lease.state is LeaseState.HELD:
            self._quarantine(ex, 'no empty fact within 5000 ms of stop')

    # ---- control records ----------------------------------------------------------------
    def on_record(self, body: dict[str, Any], fd: int | None) -> None:
        try:
            kind = body['type']
            if kind != 'spawn_prepared' and fd is not None:
                raise ControlFault(f'{kind} carries an fd')
            ex = self._row(body, fd)
            if ex is None:
                return
            if kind == 'spawn_prepared':
                owned, fd = fd, None
                self._prepared(ex, body, owned)
            elif kind == 'spawn_failed':
                self._spawn_failed(ex, body)
            elif kind == 'execution_empty':
                self._empty(ex, body)
            elif kind == 'runtime_status':
                self._runtime(ex, body)
            else:
                raise ControlFault(f'unexpected record type {kind}')
        finally:
            if fd is not None:
                os.close(fd)

    def _row(self, body: dict[str, Any], fd: int | None) -> Execution | None:
        eid, lease_id = body['execution_id'], body['lease_id']
        ex = self.executions.get(eid)
        if ex is None:
            tomb = self.tombstones.get(eid)
            if tomb is None:
                raise ControlFault('record for an unknown execution')
            if tomb['lease_id'] != lease_id or fd is not None or not self._same_terminal(tomb, body):
                raise ControlFault('late record conflicts with the tombstone')
            self.trace('duplicate_terminal_ignored', execution_id=eid, type=body['type'])
            return None
        if ex.lease_id != lease_id:
            raise ControlFault('lease_id does not match the row')
        if ex.spawn_submission is Submission.LOCAL:
            raise ControlFault('fact for a row whose spawn was never submitted')
        return ex

    @staticmethod
    def _same_terminal(tomb: dict[str, Any], body: dict[str, Any]) -> bool:
        fact, kind = _terminal(body), body['type']
        return ((kind == 'execution_empty' and fact == tomb['empty'])
                or (kind == 'spawn_failed' and fact in tomb['failures'])
                or (kind == 'runtime_status' and fact == tomb['runtime']))

    def _prepared(self, ex: Execution, body: dict[str, Any], fd: int | None) -> None:
        try:
            if fd is None:
                raise ControlFault('spawn_prepared without its fd')
            if ex.prepared_consumed:
                raise ControlFault('spawn_prepared for a row that already consumed one')
            ex.prepared_consumed = True
            plan = ex.plan
            if (body['launch_plan_digest'] != ex.launch_plan_digest
                    or body['policy_digest'] != plan.policy_digest
                    or body['isolation_profile_digest'] != plan.isolation_profile_digest
                    or body['copy_id'] != ex.runtime_copy_view.copy_id):
                raise ControlFault('spawn_prepared identity does not match the row')
            if ex.state is not ExecState.PREPARING or self.loop.clock.now_ns() >= ex.startup_deadline_ns:
                os.close(fd)
                fd = None
                self.trace('prepared_refused', execution_id=ex.execution_id, state=ex.state.value)
                if ex.state is ExecState.CLOSED:
                    self._register_stop(ex)
                else:
                    self._close(ex, 'startup_deadline')
                return
            sock = socket.socket(fileno=fd)
            fd = None
            self._install(ex, sock, body['child_pid'])
        finally:
            if fd is not None:
                os.close(fd)

    def _install(self, ex: Execution, sock: socket.socket, child_pid: int) -> None:
        """PREPARING → STARTING: a new Channel object owns the fd; then COMMIT."""
        self.generation += 1
        channel = Channel(ex.execution_id + ':c', sock, self.generation, ex.session,
                          frame_reader=FrameReader(self.native), frame_writer=FrameWriter(sock))
        ex.session.channel_id = channel.channel_id
        ex.channel = channel
        ex.state = ExecState.STARTING
        record_lifecycle(self.recorder, 'spawn_prepared', ex, channel_id=channel.channel_id,
                         receiver_generation=channel.receiver_generation, fd=sock.fileno(), child_pid=child_pid)
        self._drive_commit(ex, channel)

    def _drive_commit(self, ex: Execution, channel: Channel) -> None:
        if ex.channel is not channel or channel.phase is not Phase.BOOTSTRAP_HANDOFF:
            return
        if self.loop.clock.now_ns() >= ex.startup_deadline_ns:   # every continuation obeys the deadline
            self._close(ex, 'startup_deadline')
            return
        fd = channel.owned_fd.fileno()
        while channel.commit_offset < len(COMMIT):
            try:
                sent = channel.owned_fd.send(COMMIT[channel.commit_offset:],
                                             socket.MSG_NOSIGNAL | socket.MSG_DONTWAIT)
            except (BlockingIOError, InterruptedError):
                self.loop.watch(fd, selectors.EVENT_WRITE, self._step(self._drive_commit, ex, channel))
                return
            except OSError as error:
                self.trace('commit_failed', execution_id=ex.execution_id, error=repr(error))
                self._close(ex, 'commit_send_failed')
                return
            channel.commit_offset += sent
        self.loop.watch(fd, selectors.EVENT_WRITE, None)
        channel.phase = Phase.HELLO
        self.trace('commit_sent', execution_id=ex.execution_id, channel_id=channel.channel_id)
        self.data.attach(ex, channel)

    def _spawn_failed(self, ex: Execution, body: dict[str, Any]) -> None:
        fact = _terminal(body)
        if fact in ex.spawn_failures:
            self.trace('duplicate_terminal_ignored', execution_id=ex.execution_id, type='spawn_failed')
            return
        # At most one startup failure, then at most one reap-stage failure (conn E-01 补充).
        follows_startup = (len(ex.spawn_failures) == 1 and ex.spawn_failures[0]['stage'] != 'reap'
                           and fact['stage'] == 'reap')
        if ex.membership_empty or (ex.spawn_failures and not follows_startup):
            raise ControlFault('conflicting spawn_failed')
        ex.spawn_failures.append(fact)
        record_lifecycle(self.recorder, 'spawn_failed', ex, 'failed', fact['stage'], stage=fact['stage'],
                         error_code=fact.get('error_code'))
        if fact['stage'] == 'reap':
            self._quarantine(ex, 'spawner kill/wait error')
            self._close(ex, 'reap_error')
        else:
            self._close(ex, 'spawn_failed')

    def _empty(self, ex: Execution, body: dict[str, Any]) -> None:
        fact = _terminal(body)
        if ex.empty_fact is not None:
            if fact != ex.empty_fact:
                raise ControlFault('conflicting execution_empty')
            self.trace('duplicate_terminal_ignored', execution_id=ex.execution_id, type='execution_empty')
            return
        if fact['basis'] == 'never_created' and ex.prepared_consumed:
            raise ControlFault('never_created after a prepared record that names a child')
        ex.empty_fact = fact
        ex.membership_empty = True
        ex.empty_basis = fact['basis']
        record_lifecycle(self.recorder, 'execution_empty', ex, basis=fact['basis'])
        self.control.withdraw_stop(ex)
        if ex.lease.state is LeaseState.QUARANTINED and self.control_healthy:
            ex.lease.state = LeaseState.HELD
            wlease = ex.workspace_lease
            if wlease.workspace.active_lease is wlease:
                wlease.workspace.state = WorkspaceState.DRAINING
            self.trace('quarantine_lifted', execution_id=ex.execution_id)
        self._close(ex, 'execution_empty')
        self._reclaim(ex)

    def _runtime(self, ex: Execution, body: dict[str, Any]) -> None:
        fact, view = _terminal(body), ex.runtime_copy_view
        if view.state is ViewState.RELEASED:
            if fact != view.last_status:
                raise ControlFault('runtime_status after released')
            self.trace('duplicate_terminal_ignored', execution_id=ex.execution_id, type='runtime_status')
            return
        view.last_status = fact
        try:
            self.recorder.record('runtime_storage', 'observed', fact.get('reason', 'none'),
                                 control_binding=ControlBinding.from_execution(ex),
                                 source_ref={'copy_id': view.copy_id}, runtime_storage={
                'copy_id': view.copy_id, 'state': fact['state'].upper(), 'attempt': fact.get('attempt'),
                'basis': fact.get('basis'), 'reason': fact.get('reason'), 'os_errno': fact.get('os_errno')})
        except RecordFault:
            pass
        if fact['state'] == 'retained':
            view.state = ViewState.RETAINED
            self._close(ex, 'runtime_retained')
        else:
            view.state = ViewState.RELEASED
        self._recompute_admission()
        self._reclaim(ex)

    def _recompute_admission(self) -> None:
        """New admission (executions and task_start) needs every closing cause gone: a healthy control link and
        record path, no retained copy and no cleanup_stalled request (conn E-03 accepting_new)."""
        self.accepting_new = (self.control_healthy and self.recorder.failed is None and not self.requests.stalled
                              and not any(e.runtime_copy_view.state is ViewState.RETAINED
                                          for e in self.executions.values()))

    def _check_records(self) -> None:
        """Round hook: the record latch, read once per round without queueing anything (si E-09 故障状态). A
        failed record path closes every session; stop and reap carry on regardless."""
        if self.record_fault_handled or self.recorder.check() is None:
            return
        self.record_fault_handled = True
        self.accepting_new = False
        for ex in list(self.executions.values()):
            self._close(ex, 'record_fault')
        self.control.flush()

    # ---- trusted entries (conn E-03, E-04; rr E-06) -------------------------------------
    def grant_task(self, ex: Execution, rules: list[dict[str, Any]], ttl_ms: int) -> Any:
        return self.tasks.grant_task(ex, rules, ttl_ms)

    def task_start(self, binding: Any, text: str, timeout_ms: int = TASK_BUDGET_MS) -> Any:
        call = self.tasks.task_start(binding, text, timeout_ms)
        self.control.flush()
        return call

    def cancel_task(self, call: Any) -> None:
        self.tasks.cancel_task(call)
        self.control.flush()

    def finish_execution(self, ex: Execution) -> None:
        self.tasks.finish_execution(ex)
        self.control.flush()

    def revoke(self, binding: Any) -> None:
        self.tasks.revoke(binding)
        self.control.flush()

    def close_task(self, binding: Any) -> None:
        self.tasks.close_task(binding)

    # ---- close (conn E-04 close_session, steps 1–4 in one decision) ----------------------
    def close_session(self, ex: Execution, reason: str = 'trusted_close') -> None:
        """Idempotent forced close; the trusted caller's entry."""
        self._close(ex, reason)
        self.control.flush()

    def _close(self, ex: Execution, reason: str) -> None:
        if reason not in STOP_REASONS:   # checked before step 1 changes anything
            raise ValueError(f'close reason {reason!r} has no stop.reason mapping')
        if ex.state is ExecState.CLOSED:
            return
        previous = ex.state
        # Step 1: admission off; CLOSED is terminal.
        ex.state = ExecState.CLOSED
        ex.close_reason = reason
        ex.session.admission = 'CLOSED'
        ex.session.dispatch_open = False
        ex.session.task_admission = False
        wlease = ex.workspace_lease
        if wlease.workspace.active_lease is wlease and wlease.workspace.state is WorkspaceState.LEASED:
            wlease.workspace.state = WorkspaceState.DRAINING
        # Step 2: retire the Channel object (registrations first, then shutdown and close once).
        self._retire_channel(ex)
        # Step 3: undecided requests take closed, queued terminals are abandoned, holders asked to release;
        # the current call takes closed. Nothing waits for a worker before the stop below.
        self.requests.close_session(ex)
        # Step 4: withdraw an unsent spawn, or register one stop.
        if ex.spawn_submission is Submission.LOCAL:
            if not self.control.withdraw_spawn(ex):
                raise RuntimeError('local spawn neither queued nor sent')
            ex.membership_empty = True
            ex.empty_basis = 'local_never_submitted'
            record_lifecycle(self.recorder, 'spawn_withdrawn', ex, basis='local_never_submitted')
            ex.runtime_copy_view.state = ViewState.RELEASED
            ex.runtime_copy_view.last_status = {'basis': 'not_materialized', 'local': True}
        elif not ex.membership_empty:
            self._register_stop(ex)
        for timer in ex.timers:
            timer.cancel()
        record_lifecycle(self.recorder, 'session_closed', ex, reason=reason, previous=previous.value,
                         submission=ex.spawn_submission.value)
        self._reclaim(ex)

    def _retire_channel(self, ex: Execution) -> None:
        channel = ex.channel
        if channel is not None and channel.phase is not Phase.CLOSED:
            fd = channel.owned_fd.fileno()
            self.loop.forget(fd)
            try:
                channel.owned_fd.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            channel.owned_fd.close()
            channel.phase = Phase.CLOSED
            channel.session = None
            self.data.detach(channel)
            self.trace('channel_retired', execution_id=ex.execution_id, channel_id=channel.channel_id,
                       receiver_generation=channel.receiver_generation, fd=fd)
        ex.channel_retired = True

    def _register_stop(self, ex: Execution) -> None:
        if ex.stop is StopState.NONE and not ex.membership_empty and not self.control.dead:
            reason = STOP_REASONS[ex.close_reason or 'control_fault']
            ex.stop = StopState.PENDING
            self.control.queue_stop(ex, reason)

    def _quarantine(self, ex: Execution, why: str) -> None:
        ex.lease.state = LeaseState.QUARANTINED
        wlease = ex.workspace_lease
        if wlease.workspace.active_lease is wlease:
            wlease.workspace.state = WorkspaceState.QUARANTINED
        self.trace('quarantined', execution_id=ex.execution_id, uid=ex.lease.uid, reason=why)

    # ---- reclaim: three independent, idempotent gates (conn E-04 step 6; rr E-08) -------------
    def _reclaim(self, ex: Execution) -> None:
        if ex.state is not ExecState.CLOSED or not ex.membership_empty:
            return
        lease, wlease = ex.lease, ex.workspace_lease
        ws = wlease.workspace
        # uid: CLOSED AND empty AND close step 2 done; once.
        if not ex.lease_released and ex.channel_retired and lease.state is LeaseState.HELD:
            lease.state = LeaseState.FREE
            ex.lease_released = True
            if self.holders.get(lease.uid) is lease:
                del self.holders[lease.uid]
            record_lifecycle(self.recorder, 'uid_released', ex, uid=lease.uid, basis=ex.empty_basis)
        # workspace: additionally every engine-side I/O reference released.
        if not ex.workspace_released and lease.state is not LeaseState.QUARANTINED and not ws.io_refs:
            if ws.active_lease is wlease:
                ws.active_lease = None
                ws.state = WorkspaceState.AVAILABLE
            ex.workspace_released = True
            self.trace('workspace_released', execution_id=ex.execution_id, workspace_id=ws.workspace_id,
                       generation=wlease.generation)
        # execution slot: also the host runtime copy released, every request returned and no call unresolved
        # (an un-released worker keeps the slot: conn E-04 step 6).
        call = ex.session.current_task_call
        if (not ex.slot_released and ex.lease_released and ex.workspace_released
                and ex.runtime_copy_view.state is ViewState.RELEASED and not ex.session.requests
                and (call is None or call.state is CallState.RESOLVED)):
            ex.slot_released = True
            del self.executions[ex.execution_id]
            self.tombstones[ex.execution_id] = {'lease_id': ex.lease_id, 'empty': ex.empty_fact,
                                                'failures': list(ex.spawn_failures),
                                                'runtime': ex.runtime_copy_view.last_status}
            if len(self.tombstones) > TOMBSTONES_MAX:
                self.tombstones.popitem(last=False)
            self.trace('slot_released', execution_id=ex.execution_id)

    # ---- control loss (conn E-04 控制链路故障) ---------------------------------------------
    def _on_control_fault(self, reason: str) -> None:
        self.control_healthy = False
        self._recompute_admission()
        for ex in list(self.executions.values()):
            self._close(ex, 'control_fault')
            if not ex.membership_empty and ex.lease.state is LeaseState.HELD:
                self._quarantine(ex, 'control lost')
