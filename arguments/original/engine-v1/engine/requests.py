"""Agent requests: admission, prepare, final authorization and dispatch, results, release (conn E-03 请求的四组状态
与分派接口; rr E-06 Grant 规则、操作冻结与最终分派; E-07 接收器交给 router 的边界; conn E-04 关闭第 3 步, 取消与效果).

The request path is one executor decision from the parse to handler.start: admission reaches the TaskCall, the
TaskBinding and the grant only through the Session object the frame arrived on, and the RequestEntry then holds
them by reference. Results reach the entry only through its own Sink; the response goes out on the entry's own
Channel writer. A request slot returns only when the terminal is decided, the terminal record is sent or abandoned,
and the worker is none or released.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Mapping

from . import handlers
from .loop import MS, Loop
from .objects import Channel, ExecState, Execution, Session, WriteOnce
from .operations import ArgsInvalid, authorize, check_args, compact, freeze_operation, sha256, thaw, within_limits
from .records import RecordFault, Recorder, VerifiedSubject
from .receive import Cancel, Request
from .tasks import CallState, GrantState, TaskBinding, TaskCall
from .writer import FRAME_MAX, SEQ_PLACEHOLDER, FrameWriter, make_out

if TYPE_CHECKING:
    from .phases import DataPlane
    from .tasks import Tasks

REQUESTS_SESSION_MAX, REQUESTS_ENGINE_MAX = 16, 256
INPUT_MAX = 16 << 20              # accepted request bodies held at once, engine-wide
REQUEST_BUDGET_MS = 30_000        # E-02 default; the agent may ask for 1–300,000
RELEASE_MS = 5_000


class RPhase(Enum):
    RECEIVED = 'RECEIVED'
    PREPARED = 'PREPARED'
    DISPATCHED = 'DISPATCHED'


@dataclass(eq=False)
class RequestEntry(WriteOnce):
    _write_once: ClassVar[frozenset[str]] = frozenset(
        {'message', 'subject', 'session', 'channel', 'execution', 'call', 'binding', 'grant_state', 'request_key',
         'deadline_ns'})

    message: Request
    subject: VerifiedSubject
    session: Session
    channel: Channel
    execution: Execution
    call: TaskCall
    binding: TaskBinding
    grant_state: GrantState
    request_key: str
    deadline_ns: int
    phase: RPhase = RPhase.RECEIVED
    terminal: str | None = None     # success / error / cancelled / deadline / closed, once
    code: str | None = None
    effect: str = 'not_dispatched'
    wire_state: str = 'none'
    worker_state: str = 'none'
    candidate: Any = None
    summary: dict[str, Any] | None = None
    handle: Any = None
    next_seq: int = 0
    demand: bool = False
    driving: bool = False
    reserved: int = 0
    chunk_index: int = 0
    timers: list[Any] = field(default_factory=list)
    release_timer: Any = None
    stalled: bool = False
    returned: bool = False

    def lifecycle(self) -> dict[str, Any]:
        return {'phase': self.phase.value, 'terminal': self.terminal, 'wire_state': self.wire_state,
                'worker_state': self.worker_state, 'effect': self.effect}


class Sink:
    """Delivers to one RequestEntry; it has no way to name another session, fd or seq."""

    __slots__ = ('_entry', '_manager')

    def __init__(self, manager: Requests, entry: RequestEntry) -> None:
        self._manager, self._entry = manager, entry

    def chunk(self, text: str) -> None:
        self._manager._decision_step(self._manager._on_chunk, self._entry, text)

    def complete(self, value: Mapping[str, Any], evidence: dict[str, Any]) -> None:
        self._manager._decision_step(self._manager._on_complete, self._entry, value, evidence)

    def failure(self, code: str, evidence: dict[str, Any] | None) -> None:
        self._manager._decision_step(self._manager._on_failure, self._entry, code, evidence)

    def released(self) -> None:
        self._manager._decision_step(self._manager._on_released, self._entry)


class Requests:
    def __init__(self, loop: Loop, recorder: Recorder, resources: Mapping[str, Any],
                 close: Callable[[Execution, str], None], step: Callable[..., Callable[[], None]],
                 slot_gate: Callable[[Execution], None], admission_changed: Callable[[], None]) -> None:
        self.loop, self.recorder, self.resources = loop, recorder, resources
        self.close, self.step, self.slot_gate, self.admission_changed = close, step, slot_gate, admission_changed
        self.data: DataPlane
        self.tasks: Tasks
        self.live = 0
        self.input_bytes = 0
        self.stalled: set[RequestEntry] = set()
        self.waiting: dict[Channel, list[RequestEntry]] = {}   # demands paused for output space, per channel
        self.observers: list[Callable[[Any], None]] = []   # observe_only pre_egress hook; none configured

    def _decision_step(self, action: Callable[..., None], *args: Any) -> None:
        self.step(action, *args)()

    # ---- records ------------------------------------------------------------------------
    def _rec(self, kind: str, entry: RequestEntry, outcome: str = 'observed', reason: str = 'none',
             **groups: Any) -> bool:
        """False when the record was not accepted (the latch is then set); close paths ignore it."""
        try:
            source = {'request_key': entry.request_key}
            if entry.summary is not None:
                source['operation_id'] = entry.summary['operation_id']
            self.recorder.record(kind, outcome, reason, verified_subject=entry.subject,
                                 request_key=entry.request_key, task_call_key=entry.call.key,
                                 connection_ref=entry.channel.channel_id, source_ref=source, **groups)
            return True
        except RecordFault:
            return False

    def _decision(self, entry: RequestEntry, decision: str, why: str, decision_id: str | None = None) -> bool:
        state = entry.grant_state
        authorization = {'decision_id': decision_id or entry.request_key + ':d', 'decision': decision,
                         'grant_ref': state.grant.grant_ref, 'grant_state_generation': state.generation,
                         'decided_at_ns': str(self.loop.clock.now_ns()), 'reason_code': why}
        operation = entry.candidate.summary(decision_id) if entry.candidate is not None else None
        return self._rec('authorization_decided', entry, 'accepted' if decision == 'allow' else 'rejected', why,
                         operation=operation, authorization=authorization)

    # ---- admission (one decision with the parse) -------------------------------------------
    def on_request(self, message: Request) -> None:
        context = message.context
        session, channel = context.session_ref, context.channel_ref
        ex = session.execution_ref
        rid = int(message.id)
        if rid <= session.agent_high_water:
            # An old or repeated active id closes the session; a request id never names a new attempt.
            self.recorder.diagnostic('request_id_not_increasing', session_id=session.session_id)
            self.close(ex, 'protocol_error')
            return
        session.agent_high_water = rid
        subject = VerifiedSubject.from_context(context)
        key = f'{session.session_id}:a:{message.id}'
        call = session.current_task_call
        self.tasks.check_deadline(call)
        bound = (call is not None and call.state is CallState.RUNNING and message.task_call_id == call.call_id
                 and message.task_id == call.binding.task_id)
        args = compact(thaw(message.args))
        requested = {'action': message.action, 'resource_id': message.resource_id, 'binding_matched': bound,
                     'payload': {'byte_length': str(len(args)), 'digest': sha256(args)}}
        if not bound:
            self._refuse(subject, session, channel, message, key, 'permission_denied', requested)
            return
        if (len(session.requests) >= REQUESTS_SESSION_MAX or self.live >= REQUESTS_ENGINE_MAX
                or self.input_bytes + message.size > INPUT_MAX):
            self._refuse(subject, session, channel, message, key, 'resource_exhausted', requested)
            return
        budget = message.timeout_ms if message.timeout_ms is not None else REQUEST_BUDGET_MS
        entry = RequestEntry(message, subject, session, channel, ex, call, call.binding, call.binding.grant_state,
                             key, min(context.received_at + budget * MS, call.deadline_ns))
        session.requests[message.id] = entry
        self.live += 1
        self.input_bytes += message.size
        call.children.add(entry)
        call.binding.refs += 1
        self._rec('request_received', entry, 'accepted', requested_operation=requested)
        entry.timers.append(self.loop.call_at(entry.deadline_ns, self.step(self._deadline, entry)))
        self._prepare(entry)
        self.data.flush_soon(ex, channel)

    def _refuse(self, subject: VerifiedSubject, session: Session, channel: Channel, message: Request, key: str,
                code: str, requested: dict[str, Any]) -> None:
        """A correlated refusal that takes no request slot: seq 0, within the control reserve."""
        try:
            self.recorder.record('request_received', 'rejected', code, verified_subject=subject, request_key=key,
                                 connection_ref=channel.channel_id, source_ref={'request_key': key},
                                 requested_operation=requested)
        except RecordFault:
            pass
        out = make_out(body={'v': 2, 'type': 'error', 'reply_to': message.id, 'seq': 0, 'code': code,
                             'effect': 'not_dispatched'}, control=True)
        if channel.frame_writer is None or not channel.frame_writer.queue(out):
            self.close(session.execution_ref, 'output_exhausted')
            return
        self.data.flush_soon(session.execution_ref, channel)

    # ---- prepare, final decision, dispatch ---------------------------------------------------
    def _prepare(self, entry: RequestEntry) -> None:
        message = entry.message
        resource = self.resources.get(message.resource_id)     # exact ID match, no normalisation
        if resource is None:
            return self._deny(entry, 'not_found', 'unknown_resource')
        if message.action not in resource.allowed_actions:
            return self._deny(entry, 'unsupported_action', 'unknown_action')
        try:
            args = check_args(message.action, message.args)
        except ArgsInvalid as error:
            return self._deny(entry, 'invalid_request', str(error))
        state, now = entry.grant_state, self.loop.clock.now_ns()
        grant = state.grant
        rule = grant.rule(resource.resource_id, resource.descriptor_digest, message.action)
        if (state.state != 'active' or now >= grant.expires_at_ns or entry.binding.task_id not in grant.task_ids
                or rule is None or not within_limits(resource, rule.limits, args)):
            return self._deny(entry, 'permission_denied', 'grant')
        try:
            entry.candidate = freeze_operation(entry, resource, rule, args)
        except ArgsInvalid as error:
            return self._deny(entry, 'invalid_request', str(error))
        entry.phase = RPhase.PREPARED
        entry.worker_state = 'owned'
        if message.action == 'model.generate':
            candidate = entry.candidate
            self._rec('pre_egress', entry, operation=candidate.summary(),
                      flow={'source': entry.execution.execution_id, 'destination': resource.resource_id,
                            'direction': 'outbound', 'byte_length': str(len(candidate.body_bytes)),
                            'payload_digest': candidate.body_hash})
            for observe in self.observers:
                observe(candidate)   # observe_only: no verdict, and the decision below re-reads all state
        self._final(entry)

    def _deny(self, entry: RequestEntry, code: str, why: str) -> None:
        self._decision(entry, 'deny', why)
        self._terminal(entry, 'error', code)

    def _final_check(self, entry: RequestEntry, now: int) -> tuple[str, str | None, str] | None:
        """Every condition of rr E-06 step 3, read now; no yield between here and handler.start."""
        ex, session, call, binding, state = entry.execution, entry.session, entry.call, entry.binding, entry.grant_state
        candidate = entry.candidate
        if session.admission != 'OPEN' or ex.state is not ExecState.ACTIVE or not session.dispatch_open:
            return 'closed', None, 'session_closed'
        if now >= entry.deadline_ns:
            return 'deadline', 'deadline_exceeded', 'request_deadline'
        if session.current_task_call is not call or call.state is not CallState.RUNNING or call.outcome is not None:
            return 'error', 'permission_denied', 'call_not_running'
        if (call.binding is not binding or binding.grant_state is not state or binding.state != 'active'
                or binding.session is not session):
            return 'error', 'permission_denied', 'binding'
        grant = state.grant
        if (state.state != 'active' or state.session is not session or grant.session_id != session.session_id
                or binding.task_id not in grant.task_ids or now >= grant.expires_at_ns):
            return 'error', 'permission_denied', 'grant'
        if (all(rule is not candidate.rule for rule in grant.rules)
                or candidate.rule.descriptor_digest != candidate.resource.descriptor_digest):
            return 'error', 'permission_denied', 'rule'
        if self.recorder.failed is not None:
            return 'error', 'internal_error', 'record_fault'
        return None

    def _final(self, entry: RequestEntry) -> None:
        self.tasks.check_deadline(entry.call)   # may already have cancelled this child
        if entry.terminal is not None:
            return
        now = self.loop.clock.now_ns()
        failure = self._final_check(entry, now)
        if failure is not None:
            terminal, code, why = failure
            self._decision(entry, 'deny', why)
            self._terminal(entry, terminal, code)
            return
        candidate = entry.candidate
        decision_id = candidate.operation_id + ':d'
        if not self.recorder.has_room(2) or not self._decision(entry, 'allow', 'none', decision_id):
            self.recorder.fail('no record space for a dispatch')
            self._terminal(entry, 'error', 'internal_error')
            return
        operation = authorize(candidate, decision_id, entry.grant_state.generation, now)
        entry.phase, entry.effect = RPhase.DISPATCHED, 'unknown'
        entry.summary = candidate.summary(decision_id)
        if not self._rec('dispatch_started', entry, operation=entry.summary, lifecycle=entry.lifecycle()):
            self._terminal(entry, 'error', 'internal_error')   # never started; effect stays unknown
            self.close(entry.execution, 'record_fault')
            return
        entry.candidate = None                                 # moved into the one-use operation
        try:
            entry.handle = handlers.start(self.loop, operation, Sink(self, entry))
        except Exception:  # noqa: BLE001 — a failed start may have done anything: unknown, never retried
            self.recorder.diagnostic('handler_start_failed', request_key=entry.request_key)
            self._terminal(entry, 'error', 'internal_error')
            return
        self._drive_soon(entry)

    # ---- demand and results ---------------------------------------------------------------
    def _drive_soon(self, entry: RequestEntry) -> None:
        if not entry.driving and not entry.demand and entry.terminal is None and entry.handle is not None:
            entry.driving = True
            self.loop.soon(self.step(self._drive, entry))

    def _drive(self, entry: RequestEntry) -> None:
        entry.driving = False
        if entry.terminal is not None or entry.demand or entry.handle is None:
            return
        if self.loop.clock.now_ns() >= entry.deadline_ns:
            self._deadline(entry)
            return
        writer = entry.channel.frame_writer
        if writer is None:
            return
        if not writer.reserve(FRAME_MAX):          # no hidden queue: no demand without space for its frame
            self.waiting.setdefault(entry.channel, []).append(entry)
            return
        entry.reserved, entry.demand = FRAME_MAX, True
        entry.handle.pull_one(handlers.CHUNK_MAX)

    def on_space(self, channel: Channel) -> None:
        for entry in self.waiting.pop(channel, []):
            self._drive_soon(entry)

    def _take_reservation(self, entry: RequestEntry) -> int:
        reserved, entry.reserved, entry.demand = entry.reserved, 0, False
        return reserved

    def _on_chunk(self, entry: RequestEntry, text: str) -> None:
        reserved = self._take_reservation(entry)
        writer = entry.channel.frame_writer
        if entry.terminal is not None or writer is None or writer.dead:
            if writer is not None:
                writer.unreserve(reserved)
            return                                  # late: only release, no wire data
        if not reserved:
            # Data without a demand breaks the handler contract (at most one event per demand): the request
            # fails rather than losing or hiding bytes.
            self._terminal(entry, 'error', 'internal_error')
            return
        if self.loop.clock.now_ns() >= entry.deadline_ns:
            writer.unreserve(reserved)
            self._deadline(entry)
            return
        data = text.encode()
        if not self._rec('post_read', entry, operation=entry.summary, flow={
                'source': entry.message.resource_id, 'destination': entry.execution.execution_id,
                'direction': 'inbound', 'delivery_stage': 'accepted_for_queue', 'part': 'chunk',
                'chunk_index': entry.chunk_index, 'byte_length': str(len(data)), 'payload_digest': sha256(data)}):
            writer.unreserve(reserved)
            self.close(entry.execution, 'record_fault')
            return
        reply_to = entry.message.id
        out = make_out(owner=entry, build=lambda: {'v': 2, 'type': 'chunk', 'reply_to': reply_to,
                                                   'seq': entry.next_seq, 'text': text},
                       size_hint={'v': 2, 'type': 'chunk', 'reply_to': reply_to, 'seq': SEQ_PLACEHOLDER, 'text': text},
                       on_sent=lambda: self._advance(entry))
        if not writer.queue(out, from_reserve=reserved):
            self._terminal(entry, 'error', 'internal_error')
            return
        entry.chunk_index += 1
        self.data.flush_soon(entry.execution, entry.channel)
        self._drive_soon(entry)

    def _advance(self, entry: RequestEntry) -> None:
        entry.next_seq += 1   # only a whole send consumes a seq

    def _on_complete(self, entry: RequestEntry, value: Mapping[str, Any], evidence: dict[str, Any]) -> None:
        entry.demand = False
        if entry.terminal is None and self.loop.clock.now_ns() >= entry.deadline_ns:
            self._deadline(entry)
        if entry.terminal is not None:
            self._late(entry, evidence)
            return
        if 'tool_calls' in value:
            data = compact(value)
            if not self._rec('post_read', entry, operation=entry.summary, flow={
                    'source': entry.message.resource_id, 'destination': entry.execution.execution_id,
                    'direction': 'inbound', 'delivery_stage': 'accepted_for_queue', 'part': 'terminal_value',
                    'byte_length': str(len(data)), 'payload_digest': sha256(data)}):
                self._unreserve(entry)
                self.close(entry.execution, 'record_fault')
                return
        self._rec('operation_completed', entry, operation=entry.summary, completion=evidence,
                  lifecycle=entry.lifecycle())
        self._terminal(entry, 'success', value=value, evidence=evidence)

    def _on_failure(self, entry: RequestEntry, code: str, evidence: dict[str, Any] | None) -> None:
        entry.demand = False
        if entry.terminal is None and self.loop.clock.now_ns() >= entry.deadline_ns:
            self._deadline(entry)
        if entry.terminal is not None:
            if evidence is not None:
                self._late(entry, evidence)
            else:
                self._unreserve(entry)
            return
        self._terminal(entry, 'error', code, evidence=evidence)

    def _late(self, entry: RequestEntry, evidence: dict[str, Any]) -> None:
        """A completion after the decided terminal only adds an observation; the wire terminal stays."""
        self._unreserve(entry)
        self._rec('late_completion', entry, completion=evidence, lifecycle=entry.lifecycle())

    def _unreserve(self, entry: RequestEntry) -> None:
        reserved = self._take_reservation(entry)
        if entry.channel.frame_writer is not None:
            entry.channel.frame_writer.unreserve(reserved)

    def _on_released(self, entry: RequestEntry) -> None:
        if entry.worker_state not in ('owned', 'releasing'):
            return
        entry.worker_state = 'released'
        if entry.release_timer is not None:
            entry.release_timer.cancel()
        if entry.stalled:
            entry.stalled = False
            self.stalled.discard(entry)
            self.admission_changed()
        self._try_return(entry)

    # ---- terminals, release, slot return --------------------------------------------------------
    def _deadline(self, entry: RequestEntry) -> None:
        self._terminal(entry, 'deadline', 'deadline_exceeded')

    def _terminal(self, entry: RequestEntry, terminal: str, code: str | None = None,
                  value: Mapping[str, Any] | None = None, evidence: dict[str, Any] | None = None) -> None:
        """The first terminal wins; it is the engine's decision, not delivery and not background completion."""
        if entry.terminal is not None:
            return
        entry.terminal, entry.code = terminal, code
        if terminal == 'success' or evidence is not None:
            entry.effect = 'completed'
        for timer in entry.timers:
            timer.cancel()
        if entry.handle is not None and terminal != 'success':
            entry.handle.cancel(terminal)
        reserved = self._take_reservation(entry)
        writer = entry.channel.frame_writer
        self._rec('request_terminal', entry, reason=code or 'none', lifecycle=entry.lifecycle())
        if terminal == 'closed' or writer is None or writer.dead or entry.session.admission != 'OPEN':
            if writer is not None:
                writer.unreserve(reserved)
            self._abandoned(entry)
        else:
            self._queue_terminal(entry, writer, terminal, code, value, reserved)
        self._release(entry)
        self._try_return(entry)

    def _queue_terminal(self, entry: RequestEntry, writer: FrameWriter, terminal: str, code: str | None,
                        value: Mapping[str, Any] | None, reserved: int) -> None:
        reply_to = entry.message.id
        if terminal == 'success':
            frozen = thaw(value)
            body = {'v': 2, 'type': 'result', 'reply_to': reply_to, 'value': frozen}
            control = False
        else:
            # Unstarted chunks of this request go; a chunk already on the wire completes first, then this error
            # takes the next seq. success after its own chunks, never two terminals queued.
            writer.withdraw_owner(entry)
            code = code if terminal == 'error' else {'cancelled': 'cancelled', 'deadline': 'deadline_exceeded'}[terminal]
            body = {'v': 2, 'type': 'error', 'reply_to': reply_to, 'code': code, 'effect': entry.effect}
            control = True
        out = make_out(owner=entry, build=lambda: dict(body, seq=entry.next_seq), size_hint=dict(body, seq=SEQ_PLACEHOLDER),
                       on_sent=lambda: self._sent(entry), on_drop=lambda: self._abandoned(entry), control=control)
        if reserved >= out.size:
            writer.queue(out, from_reserve=reserved)
            queued = True
        else:
            writer.unreserve(reserved)
            queued = writer.queue(out)
        if not queued:
            self._abandoned(entry)
            self.close(entry.execution, 'output_exhausted')
            return
        entry.wire_state = 'queued'
        self.data.flush_soon(entry.execution, entry.channel)

    def _sent(self, entry: RequestEntry) -> None:
        entry.next_seq += 1
        entry.wire_state = 'sent'
        self._rec('response_sent', entry, lifecycle=entry.lifecycle())
        self._try_return(entry)

    def _abandoned(self, entry: RequestEntry) -> None:
        if entry.wire_state in ('none', 'queued'):
            entry.wire_state = 'abandoned'
            self._rec('response_abandoned', entry, lifecycle=entry.lifecycle())
            self._try_return(entry)

    def _release(self, entry: RequestEntry) -> None:
        """Request release at once; not waited on before a stop (conn E-04 step 3)."""
        if entry.worker_state != 'owned':
            return
        if entry.handle is None:
            entry.candidate = None          # engine-memory references only: dropping them is the release
            entry.worker_state = 'released'
            return
        entry.worker_state = 'releasing'
        entry.handle.release()
        entry.release_timer = self.loop.call_at(self.loop.clock.now_ns() + RELEASE_MS * MS,
                                                self.step(self._release_expired, entry))

    def _release_expired(self, entry: RequestEntry) -> None:
        if entry.worker_state == 'released' or entry.stalled:
            return
        entry.stalled = True
        self.stalled.add(entry)
        self._rec('cleanup_stalled', entry, lifecycle=entry.lifecycle())
        self.admission_changed()
        self.close(entry.execution, 'cleanup_stalled')

    def _try_return(self, entry: RequestEntry) -> None:
        if (entry.returned or entry.terminal is None or entry.wire_state not in ('sent', 'abandoned')
                or entry.worker_state not in ('none', 'released')):
            return
        entry.returned = True
        session, call = entry.session, entry.call
        if session.requests.get(entry.message.id) is entry:
            del session.requests[entry.message.id]
        self.live -= 1
        self.input_bytes -= entry.message.size
        call.children.discard(entry)
        entry.binding.refs -= 1
        self.tasks._maybe_remove(entry.binding)
        entry.handle = None
        self._rec('request_released', entry, lifecycle=entry.lifecycle())
        self.tasks.try_resolve(call)
        self.slot_gate(entry.execution)

    # ---- cancel and close ------------------------------------------------------------------
    def on_agent_cancel(self, message: Cancel) -> None:
        """Only the original session's agent-direction in-flight table; unknown or decided ids are ignored."""
        entry = message.context.session_ref.requests.get(message.reply_to)
        if entry is not None and entry.terminal is None:
            self._terminal(entry, 'cancelled')
            return
        self.recorder.diagnostic('cancel_ignored', session_id=message.context.session_id)

    def cancel_children(self, call: TaskCall) -> None:
        for entry in list(call.children):
            if entry.terminal is None:
                self._terminal(entry, 'cancelled')

    def cancel_under(self, state: GrantState) -> None:
        for entry in list(state.session.requests.values()):
            if entry.grant_state is state and entry.terminal is None:
                self._terminal(entry, 'cancelled')

    def close_session(self, ex: Execution) -> None:
        """Close step 3, after the channel is retired: undecided requests take closed, queued terminals are
        abandoned, every local holder is asked to release; nothing here waits."""
        session = ex.session
        if ex.channel is not None:
            self.waiting.pop(ex.channel, None)
        for entry in list(session.requests.values()):
            self._terminal(entry, 'closed')
            self._abandoned(entry)
            self._release(entry)
            self._try_return(entry)
        self.tasks.on_session_closed(session)
