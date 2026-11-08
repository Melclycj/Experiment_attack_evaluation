"""Tasks, grants and calls, and the trusted entries that create them (conn E-03 连续任务与调用结束屏障;
rr E-06 启动授权与逐请求授权之间的接口, Grant 规则; conn E-04 finish_execution).

A Grant is immutable and engine-internal; only its GrantState changes, active → revoked. A TaskBinding ties one
Session to one task and one grant; a TaskCall is one task_start. Task and grant ids are engine-assigned from a
per-execution counter and never reused. Nothing here is reached by an id table: the trusted caller holds the
objects it was given, and admission reaches the call through the request's own Session.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Mapping

from .business import DocumentResource, ModelResource
from .loop import MS, Loop
from .objects import ExecState, Execution, Session, WriteOnce
from .records import ControlBinding, RecordFault, Recorder

if TYPE_CHECKING:
    from .phases import DataPlane
    from .requests import Requests

TASK_BUDGET_MS = 300_000
BUDGET_RANGE = (1, 3_600_000)
INPUT_MAX = 64 * 1024 - 256          # the task_start body stays within one 64 KiB frame
BINDINGS_MAX = 16                    # per session
GRANTS_SESSION_MAX, GRANTS_ENGINE_MAX = 16, 256
RULES_MAX, TASK_IDS_MAX = 32, 16
DRAIN_GRACE_MS = 5_000
FINISH_GRACE_MS = 5_000
SEQ_MAX = 2 ** 64 - 1


class CallState(Enum):
    QUEUED = 'QUEUED'
    RUNNING = 'RUNNING'
    DRAINING = 'DRAINING'
    RESOLVED = 'RESOLVED'


class EntryRefused(Exception):
    """A trusted entry refused; nothing changed."""


@dataclass(frozen=True, eq=False)
class Rule:
    resource_id: str
    descriptor_digest: str
    action: str
    limits: Mapping[str, int]


@dataclass(frozen=True, eq=False)
class Grant:
    grant_ref: str
    session_id: str
    task_ids: frozenset[str]
    expires_at_ns: int
    rules: tuple[Rule, ...]          # empty denies everything

    def rule(self, resource_id: str, descriptor_digest: str, action: str) -> Rule | None:
        """One rule must match whole; no wildcard, prefix or merge of several rules."""
        for rule in self.rules:
            if (rule.resource_id, rule.descriptor_digest, rule.action) == (resource_id, descriptor_digest, action):
                return rule
        return None


@dataclass(eq=False)
class GrantState:
    grant: Grant
    session: Session
    state: str = 'active'
    generation: int = 1
    bindings: int = 0


@dataclass(eq=False)
class TaskBinding(WriteOnce):
    _write_once: ClassVar[frozenset[str]] = frozenset({'session', 'task_id', 'grant_state'})

    session: Session
    task_id: str
    grant_state: GrantState
    state: str = 'active'
    refs: int = 0                    # live calls and requests holding this binding


@dataclass(eq=False)
class TaskCall(WriteOnce):
    _write_once: ClassVar[frozenset[str]] = frozenset({'call_id', 'binding', 'session', 'execution', 'deadline_ns'})

    call_id: str                     # the task_start id, engine direction
    binding: TaskBinding
    session: Session
    execution: Execution
    input: str
    deadline_ns: int
    state: CallState = CallState.QUEUED
    outcome: str | None = None       # success / error / cancelled / deadline / closed, once
    outcome_reason: str = 'none'
    agent_status: str | None = None  # the agent's own report, kept apart from outcome
    agent_output: str | None = None
    start_sent: bool = False
    start_item: Any = None
    children: set[Any] = field(default_factory=set)
    timers: list[Any] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f'{self.session.session_id}:e:{self.call_id}'


def _digest(text: str) -> str:
    return 'sha256:' + hashlib.sha256(text.encode()).hexdigest()


class Tasks:
    def __init__(self, loop: Loop, recorder: Recorder, resources: Mapping[str, Any],
                 accepting: Callable[[], bool], close: Callable[[Execution, str], None],
                 step: Callable[..., Callable[[], None]], slot_gate: Callable[[Execution], None]) -> None:
        self.loop, self.recorder, self.resources = loop, recorder, resources
        self.accepting, self.close, self.step, self.slot_gate = accepting, close, step, slot_gate
        self.data: DataPlane
        self.requests: Requests
        self.grants_live = 0

    @staticmethod
    def _next_id(ex: Execution, kind: str) -> str:
        ex.session.local_seq += 1
        return f'{ex.execution_id}:{kind}{ex.session.local_seq}'

    # ---- trusted entries ------------------------------------------------------------------
    def grant_task(self, ex: Execution, rules: list[dict[str, Any]], ttl_ms: int) -> TaskBinding:
        """A new task bound to this Session with a new immutable Grant. Rules name resource, action and limits;
        the descriptor identity is taken from the catalog, not from the caller."""
        session = ex.session
        if ex.state in (ExecState.CLOSED, ExecState.DRAINING) or session.admission != 'OPEN':
            raise EntryRefused('session not open')
        if not BUDGET_RANGE[0] <= ttl_ms <= BUDGET_RANGE[1]:
            raise EntryRefused('grant ttl outside 1–3,600,000 ms')
        if (len(session.task_bindings) >= BINDINGS_MAX or len(session.grants) >= GRANTS_SESSION_MAX
                or self.grants_live >= GRANTS_ENGINE_MAX):
            raise EntryRefused('task or grant capacity reached')
        frozen = tuple(self._rule(r) for r in rules)
        if len(frozen) > RULES_MAX or len({(r.resource_id, r.action) for r in frozen}) != len(frozen):
            raise EntryRefused('more than 32 rules, or a repeated resource/action rule')
        task_id, grant_ref = self._next_id(ex, 't'), self._next_id(ex, 'g')
        grant = Grant(grant_ref, session.session_id, frozenset({task_id}),
                      self.loop.clock.now_ns() + ttl_ms * MS, frozen)
        state = GrantState(grant, session, bindings=1)
        binding = TaskBinding(session, task_id, state)
        session.grants.append(state)
        session.task_bindings.append(binding)
        self.grants_live += 1
        self.recorder.diagnostic('task_bound', execution_id=ex.execution_id, task_id=task_id, grant_ref=grant_ref,
                                 rules=[(r.resource_id, r.action) for r in frozen])
        return binding

    def _rule(self, spec: dict[str, Any]) -> Rule:
        if set(spec) != {'resource_id', 'action', 'limits'} or type(spec['limits']) is not dict:
            raise EntryRefused('a rule is {resource_id, action, limits}')
        resource = self.resources.get(spec['resource_id'])
        if resource is None or spec['action'] not in resource.allowed_actions:
            raise EntryRefused('rule names an unknown resource or action')
        limits = spec['limits']
        if any(type(v) is not int or v <= 0 for v in limits.values()):
            raise EntryRefused('limits are positive integers')
        if isinstance(resource, DocumentResource):
            if set(limits) != {'max_output_bytes'} or limits['max_output_bytes'] < resource.byte_length:
                raise EntryRefused('document.read limits must hold the whole snapshot')
        elif isinstance(resource, ModelResource):
            ceiling = {'max_input_bytes': resource.max_input_bytes, 'max_output_tokens': resource.max_output_tokens,
                       'max_output_bytes': resource.max_output_bytes}
            if set(limits) != set(ceiling) or any(limits[k] > ceiling[k] for k in ceiling):
                raise EntryRefused('model.generate limits above the descriptor')
        return Rule(resource.resource_id, resource.descriptor_digest, spec['action'], MappingProxyType(dict(limits)))

    def revoke(self, binding: TaskBinding) -> None:
        """GrantState active → revoked; a request already dispatched under it is cancelled (no rollback)."""
        state = binding.grant_state
        if state.state == 'active':
            state.state = 'revoked'
            state.generation += 1
            self.requests.cancel_under(state)
            self.data.flush_soon_session(binding.session)

    def close_task(self, binding: TaskBinding) -> None:
        if binding.state == 'active':
            binding.state = 'closed'
            self._maybe_remove(binding)

    def _maybe_remove(self, binding: TaskBinding) -> None:
        if binding.state != 'closed' or binding.refs:
            return
        session = binding.session
        if binding in session.task_bindings:
            session.task_bindings.remove(binding)
            state = binding.grant_state
            state.bindings -= 1
            if not state.bindings and state in session.grants:
                session.grants.remove(state)
                self.grants_live -= 1

    def task_start(self, binding: TaskBinding, text: str, timeout_ms: int = TASK_BUDGET_MS) -> TaskCall:
        session = binding.session
        ex = session.execution_ref
        if not self.accepting():
            raise EntryRefused('engine admission closed')
        if ex is None or ex.state is not ExecState.ACTIVE or session.admission != 'OPEN' or not session.task_admission:
            raise EntryRefused('session not ACTIVE with task admission')
        if session.current_task_call is not None or session.last_call is not None:
            raise EntryRefused('previous call unresolved or its result not taken')
        if binding.state != 'active' or binding not in session.task_bindings:
            raise EntryRefused('binding not active in this session')
        if not BUDGET_RANGE[0] <= timeout_ms <= BUDGET_RANGE[1]:
            raise EntryRefused('task budget outside 1–3,600,000 ms')
        try:
            if type(text) is not str or len(text.encode()) > INPUT_MAX:
                raise EntryRefused('task input not a string within the frame limit')
        except UnicodeEncodeError:
            raise EntryRefused('task input is not valid UTF-8 text') from None
        if session.engine_next_id > SEQ_MAX:
            raise EntryRefused('engine id space exhausted; start a new execution')
        call = TaskCall(str(session.engine_next_id), binding, session, ex, text,
                        self.loop.clock.now_ns() + timeout_ms * MS)
        writer = ex.channel.frame_writer if ex.channel is not None else None
        try:
            item = self.data.item(owner=call, build=lambda: self._start_body(call),
                                  size_hint={'v': 2, 'type': 'task_start', 'id': call.call_id,
                                             'task_id': binding.task_id, 'input': text, 'timeout_ms': BUDGET_RANGE[1]},
                                  on_sent=lambda: self._start_sent(call), on_drop=lambda: self._start_dropped(call))
        except ValueError:
            raise EntryRefused('task_start frame over 64 KiB once encoded') from None
        if writer is None or not writer.queue(item):
            raise EntryRefused('no output space for task_start')
        session.engine_next_id += 1   # allocated at the bounded enqueue; a withdrawn start leaves a gap
        call.start_item = item
        session.current_task_call = call
        binding.refs += 1
        call.timers.append(self.loop.call_at(call.deadline_ns, self.step(self._deadline, call)))
        self._record('task_call_started', call, 'accepted')
        self.data.flush_soon(ex, ex.channel)
        return call

    def cancel_task(self, call: TaskCall) -> None:
        """Trusted cancel of the current call."""
        if call.outcome is None and call.state is not CallState.RESOLVED:
            call.outcome = 'cancelled'
            self._drain(call, 'user')

    def take_result(self, call: TaskCall) -> dict[str, Any]:
        """The bounded result of a resolved call; taking it frees the session for the next task_start."""
        if call.state is not CallState.RESOLVED or call.session.last_call is not call:
            raise EntryRefused('call not resolved or result already taken')
        call.session.last_call = None
        return {'outcome': call.outcome, 'reason': call.outcome_reason, 'agent_status': call.agent_status,
                'output': call.agent_output}

    def finish_execution(self, ex: Execution) -> None:
        """Normal end: only ACTIVE with no unresolved call. DRAINING, shutdown, a 5,000 ms exit grace."""
        session = ex.session
        if ex.state is not ExecState.ACTIVE or session.current_task_call is not None:
            raise EntryRefused('busy: not ACTIVE or a call is unresolved')
        ex.state = ExecState.DRAINING
        session.dispatch_open = False
        session.task_admission = False
        ex.timers.append(self.loop.call_at(self.loop.clock.now_ns() + FINISH_GRACE_MS * MS,
                                           self.step(self._finish_grace, ex)))
        item = self.data.item(owner=None, body={'v': 2, 'type': 'shutdown', 'reason': 'normal'}, control=True)
        if not ex.channel.frame_writer.queue(item):
            self.close(ex, 'output_exhausted')
            return
        self.data.flush_soon(ex, ex.channel)

    def _finish_grace(self, ex: Execution) -> None:
        if ex.state is ExecState.DRAINING:
            self.close(ex, 'finish_grace')

    # ---- call progress ------------------------------------------------------------------
    def _start_body(self, call: TaskCall) -> dict[str, Any] | None:
        """Encoded once, at the first send attempt: the remaining budget, floored; under 1 ms it is not sent."""
        remaining = (call.deadline_ns - self.loop.clock.now_ns()) // MS
        if call.outcome is not None or remaining < 1:
            return None
        return {'v': 2, 'type': 'task_start', 'id': call.call_id, 'task_id': call.binding.task_id,
                'input': call.input, 'timeout_ms': min(remaining, BUDGET_RANGE[1])}

    def start_expired(self, out: Any) -> bool:
        """Checked before every send attempt: the current frame is a task_start whose call is decided or past
        its budget (conn E-03: the budget is checked at each actual send, not only by its timer)."""
        call = getattr(out, 'owner', None)
        return (isinstance(call, TaskCall) and call.start_item is out
                and (call.outcome is not None or self.loop.clock.now_ns() >= call.deadline_ns))

    def _start_sent(self, call: TaskCall) -> None:
        call.start_sent = True
        call.start_item = None
        session = call.session
        session.engine_sent_high_water = max(session.engine_sent_high_water, int(call.call_id))
        if call.state is CallState.QUEUED:
            call.state = CallState.RUNNING   # opens this call's child request entry
            self.check_deadline(call)        # a budget that ran out during the send ends the call at once

    def _start_dropped(self, call: TaskCall) -> None:
        """Never sent: withdrawn before its first byte, expired at encode time, or discarded at close."""
        call.start_item = None
        if call.outcome is None:
            call.outcome = 'closed' if call.session.admission != 'OPEN' else 'deadline'
        if call.state is CallState.QUEUED:
            self._enter_draining(call, 'never_sent')
        self.try_resolve(call)

    def check_deadline(self, call: TaskCall | None) -> None:
        """Before every task_start send, child admission and task_result: an expired budget decides first."""
        if call is not None and call.outcome is None and self.loop.clock.now_ns() >= call.deadline_ns:
            call.outcome = 'deadline'
            self._drain(call, 'timeout')

    def _deadline(self, call: TaskCall) -> None:
        self.check_deadline(call)

    def _drain(self, call: TaskCall, reason: str) -> None:
        if call.state is CallState.QUEUED:
            if call.start_item is not None and self.data.withdraw(call.session, call.start_item):
                return   # _start_dropped took the never-sent path
            if call.start_item is not None:
                # Part of task_start is on the wire: neither "never sent" nor a running call.
                self.close(call.execution, 'task_start_partial')
                return
        if call.state is CallState.RUNNING:
            self._enter_draining(call, reason)
            if call.agent_status is None:
                item = self.data.item(owner=None, control=True,
                                      body={'v': 2, 'type': 'cancel', 'reply_to': call.call_id, 'reason': reason})
                writer = call.execution.channel.frame_writer if call.execution.channel else None
                if writer is None or not writer.queue(item):
                    self.close(call.execution, 'output_exhausted')
                    return
                self.data.flush_soon(call.execution, call.execution.channel)
            self.requests.cancel_children(call)
        self.try_resolve(call)

    def _enter_draining(self, call: TaskCall, reason: str) -> None:
        call.state = CallState.DRAINING
        call.outcome_reason = reason if call.outcome_reason == 'none' else call.outcome_reason
        call.timers.append(self.loop.call_at(self.loop.clock.now_ns() + DRAIN_GRACE_MS * MS,
                                             self.step(self._drain_grace, call)))
        self._record('task_call_draining', call)

    def _drain_grace(self, call: TaskCall) -> None:
        if call.state is CallState.DRAINING:
            self.close(call.execution, 'task_drain_timeout')

    def on_task_result(self, message: Any) -> None:
        """reply_to resolves only against the original session's current call, engine direction."""
        session: Session = message.context.session_ref
        call = session.current_task_call
        if (call is not None and message.reply_to == call.call_id and call.start_sent
                and call.agent_status is None and call.state in (CallState.RUNNING, CallState.DRAINING)):
            self.check_deadline(call)
            call.agent_status, call.agent_output = message.status, message.output
            if call.state is CallState.RUNNING:
                open_children = [c for c in call.children if c.terminal is None]
                if call.outcome is None:
                    if open_children:
                        call.outcome, call.outcome_reason = 'error', 'children_cancelled'
                    else:
                        call.outcome = {'ok': 'success', 'error': 'error', 'cancelled': 'cancelled'}[message.status]
                self._enter_draining(call, 'agent_result')
                self.requests.cancel_children(call)
            self.try_resolve(call)
            return
        if int(message.reply_to) <= session.engine_sent_high_water:
            self.recorder.diagnostic('stale_or_unrecognized', session_id=session.session_id, type='task_result')
            return
        self.close(session.execution_ref, 'protocol_error')   # a reply above the sent high-water mark

    def try_resolve(self, call: TaskCall) -> None:
        if call.state is not CallState.DRAINING or call.children:
            return
        if not (call.agent_status is not None or not call.start_sent or call.session.admission != 'OPEN'):
            return
        call.state = CallState.RESOLVED
        for timer in call.timers:
            timer.cancel()
        session = call.session
        if session.current_task_call is call:
            session.current_task_call = None
            session.last_call = call
        call.binding.refs -= 1
        self._maybe_remove(call.binding)
        report = None if call.agent_output is None else {
            'trust': 'agent_report', 'status': call.agent_status, 'output_digest': _digest(call.agent_output),
            'output_bytes': str(len(call.agent_output.encode()))}
        self._record('task_call_resolved', call, agent_report=report)
        self.slot_gate(call.execution)

    def on_session_closed(self, session: Session) -> None:
        """Close step 3: the current call takes outcome closed if none is set and resolves once its children
        are returned; a CLOSED session never starts another call. Its bindings close with it (session close
        forbids new actions, rr E-06), and each is removed with its grant once nothing references it."""
        call = session.current_task_call
        if call is not None:
            if call.outcome is None:
                call.outcome = 'closed'
            if call.state in (CallState.QUEUED, CallState.RUNNING):
                call.state = CallState.DRAINING
            self.try_resolve(call)
        for binding in list(session.task_bindings):
            self.close_task(binding)

    def _record(self, kind: str, call: TaskCall, outcome: str = 'observed', agent_report: Any = None) -> None:
        try:
            self.recorder.record(
                kind, outcome, call.outcome_reason, control_binding=ControlBinding.from_execution(call.execution),
                task_call_key=call.key, source_ref={'launch_plan_digest': call.execution.launch_plan_digest},
                detail={'task_id': call.binding.task_id, 'grant_ref': call.binding.grant_state.grant.grant_ref,
                        'children': len(call.children)},
                lifecycle={'call_state': call.state.value, 'outcome': call.outcome, 'agent_status': call.agent_status},
                agent_report=agent_report)
        except RecordFault:
            pass   # the latch is set; the round hook closes the sessions
