"""Phase rules and the send side of the data channel (conn E-01 启动时序 step 6 and 状态转换与失败裁决; E-02 数据消息
字段、方向与关联, 单 writer 与短写契约; E-03 流接口、序号与背压, 容量、调度与不足语义).

Each readiness callback runs one receive step and, for a whole message, the phase decision and what follows from it
in the same executor decision. Callbacks hold the Execution and Channel objects they act on; a callback whose
Channel is no longer the row's current, unretired one does nothing. Closing goes through the lifecycle's close.
A writable channel gets one sendmsg per round; a whole frame resets the send-stall deadline, a frame whose first
byte went out must complete within its own deadline.
"""
from __future__ import annotations

import selectors
from typing import TYPE_CHECKING, Any, Callable

from .loop import MS, Loop
from .objects import Channel, ExecState, Execution, Phase, Session
from .records import RecordFault, Recorder, VerifiedSubject, record_lifecycle
from .receive import Bye, Cancel, Message, NeedMore, Reject, Request, TaskResult, receive_step
from .startup import PROTOCOL
from .writer import Out, Written, make_out

if TYPE_CHECKING:
    from .requests import Requests
    from .tasks import Tasks

FRAME_MS = 5_000    # a frame is assembled within 5,000 ms of its first byte (conn E-02 step 7)
STALL_MS = 5_000    # output blocked from the first EAGAIN; only a whole send resets it (conn E-03)
PARTIAL_MS = 5_000  # a frame whose first byte went out completes within this, small progress does not extend it
WELCOME = {'v': 2, 'type': 'welcome', 'protocol': PROTOCOL}


class DataPlane:
    def __init__(self, loop: Loop, overflowuid: int, recorder: Recorder,
                 close: Callable[[Execution, str], None],
                 step: Callable[..., Callable[[], None]]) -> None:
        self.loop, self.overflowuid, self.recorder = loop, overflowuid, recorder
        self.close, self.step = close, step
        self.requests: Requests
        self.tasks: Tasks

    def attach(self, ex: Execution, channel: Channel) -> None:
        """After the whole COMMIT: register the channel's one receiver, bound to this Channel object."""
        self.loop.watch(channel.owned_fd.fileno(), selectors.EVENT_READ, self.step(self._readable, ex, channel))

    def detach(self, channel: Channel) -> None:
        """Close step 2, after the registrations are gone: free the reader, drop the writer and the timers."""
        self._cancel(channel, 'frame_timer', 'stall_timer', 'partial_timer')
        if channel.frame_reader is not None:
            channel.frame_reader.free()
            channel.frame_reader = None
        if channel.frame_writer is not None:
            writer, channel.frame_writer = channel.frame_writer, None
            writer.discard()

    @staticmethod
    def _current(ex: Execution, channel: Channel) -> bool:
        return (ex.channel is channel and channel.phase in (Phase.HELLO, Phase.DATA)
                and ex.state in (ExecState.STARTING, ExecState.ACTIVE, ExecState.DRAINING))

    # ---- receive ------------------------------------------------------------------------
    def _readable(self, ex: Execution, channel: Channel) -> None:
        if not self._current(ex, channel):
            return
        result = receive_step(channel, self.overflowuid, self.loop.clock,
                              lambda body: self._phase(ex, channel, body))
        if isinstance(result, NeedMore):
            # C reports progress and "nothing to read" alike; with one level-triggered reader the latter
            # does not follow a readiness event, so a frame is in progress from here. Ceiling: if a readiness
            # event ever yields no byte, an idle channel closes 5,000 ms later (availability only); telling the
            # two apart needs a byte count from C (a second C change, not made).
            if channel.frame_timer is None:
                channel.frame_timer = self.loop.call_at(self.loop.clock.now_ns() + FRAME_MS * MS,
                                                        self.step(self._frame_expired, ex, channel))
            return
        if channel.frame_timer is not None:
            channel.frame_timer.cancel()
            channel.frame_timer = None
        if isinstance(result, Reject):
            # A failed frame has no subject: the record names the connection and the cause only, no execution label,
            # so it cannot be read as a sender claim (si E-09 receive_rejected).
            try:
                self.recorder.record('receive_rejected', 'rejected', result.cause, connection_ref=channel.channel_id,
                                     source_ref={'launch_plan_digest': ex.launch_plan_digest},
                                     reject={'cause': result.cause, 'detail': result.detail})
            except RecordFault:
                pass
            self.close(ex, 'receive_rejected' if result.cause == 'receive_rejected' else 'protocol_error')
            return
        if not isinstance(result, Request):   # a request is recorded by admission as request_received
            try:
                self.recorder.record('message_received', 'accepted',
                                     verified_subject=VerifiedSubject.from_context(result.context),
                                     connection_ref=channel.channel_id,
                                     source_ref={'launch_plan_digest': ex.launch_plan_digest},
                                     message={'type': type(result).__name__})
            except RecordFault:
                pass
        self._decide(ex, channel, result)

    def _frame_expired(self, ex: Execution, channel: Channel) -> None:
        channel.frame_timer = None
        if self._current(ex, channel):
            self.recorder.diagnostic('frame_timeout', execution_id=ex.execution_id, channel_id=channel.channel_id)
            self.close(ex, 'frame_timeout')

    @staticmethod
    def _phase(ex: Execution, channel: Channel, body: dict[str, Any]) -> str | None:
        """Direction and phase rule on the schema-valid body, before any subject exists (conn E-02 step 5;
        E-01 启动时序 step 6). Returns a bounded refusal code, or None when the state accepts the type."""
        kind = body['type']
        if ex.state is ExecState.STARTING:
            if kind != 'hello' or channel.hello_seen:
                return f'{kind}_in_starting'   # one hello, and nothing else before the whole welcome
            if body['adapter_id'] != ex.plan.adapter_id:
                return 'adapter_mismatch'
            return None
        if ex.state is ExecState.ACTIVE:
            return 'hello_repeated' if kind == 'hello' else None
        # DRAINING: bye and idempotently ignorable old terminals or cancels only.
        return None if kind in ('bye', 'cancel', 'task_result') else f'{kind}_in_draining'

    def _decide(self, ex: Execution, channel: Channel, message: Message) -> None:
        """Only messages the phase rule accepted reach here."""
        if ex.state is ExecState.STARTING:   # the first hello, adapter matched
            if self.loop.clock.now_ns() >= ex.startup_deadline_ns:
                self.close(ex, 'startup_deadline')
                return
            channel.hello_seen = True
            welcome = make_out(body=WELCOME, on_sent=lambda: self._welcomed(ex, channel), control=True)
            if not channel.frame_writer.queue(welcome):
                self.close(ex, 'welcome_send_failed')
                return
            self.flush_soon(ex, channel)
            return
        # ACTIVE and DRAINING.
        if isinstance(message, Bye):
            self.close(ex, 'agent_bye')
        elif isinstance(message, Cancel):
            self.requests.on_agent_cancel(message)
        elif isinstance(message, TaskResult):
            self.tasks.on_task_result(message)
        elif isinstance(message, Request):   # ACTIVE only; the phase rule refuses it in DRAINING
            self.requests.on_request(message)
        else:
            raise AssertionError(f'{type(message).__name__} passed the phase rule in {ex.state.value}')

    # ---- send ---------------------------------------------------------------------------
    def item(self, **fields: Any) -> Out:
        return make_out(**fields)

    def withdraw(self, session: Session, out: Out) -> bool:
        ex = session.execution_ref
        channel = ex.channel if ex is not None else None
        writer = channel.frame_writer if channel is not None else None
        if writer is None or not writer.withdraw(out):
            return False
        if not writer.pending:            # nothing left to wait for: no stall clock
            self._cancel(channel, 'stall_timer', 'partial_timer')
        return True

    def flush_soon(self, ex: Execution | None, channel: Channel | None) -> None:
        """Ask for writability; the send itself happens in a later readiness callback, one sendmsg per round.
        Pending output starts the stall clock now: waiting for writability is waiting for space (conn E-03)."""
        if ex is None or channel is None or not self._current(ex, channel) or channel.frame_writer is None:
            return
        if channel.frame_writer.pending:
            self._arm_stall(ex, channel)
            self.loop.watch(channel.owned_fd.fileno(), selectors.EVENT_WRITE, self.step(self._flush, ex, channel))

    def flush_soon_session(self, session: Session) -> None:
        ex = session.execution_ref
        if ex is not None:
            self.flush_soon(ex, ex.channel)

    def _arm_stall(self, ex: Execution, channel: Channel) -> None:
        # In STARTING the welcome is bounded by the startup deadline (conn E-01); the session output deadlines
        # apply from ACTIVE.
        if ex.state is not ExecState.STARTING and channel.stall_timer is None:
            channel.stall_timer = self.loop.call_at(self.loop.clock.now_ns() + STALL_MS * MS,
                                                    self.step(self._stalled, ex, channel))

    @staticmethod
    def _cancel(channel: Channel, *names: str) -> None:
        for name in names:
            timer = getattr(channel, name)
            if timer is not None:
                timer.cancel()
                setattr(channel, name, None)

    def _flush(self, ex: Execution, channel: Channel) -> None:
        if not self._current(ex, channel) or channel.frame_writer is None:
            return
        now = self.loop.clock.now_ns()
        if ex.state is ExecState.STARTING and now >= ex.startup_deadline_ns:
            self.close(ex, 'startup_deadline')
            return
        # Every send attempt re-reads the deadlines, not only their timers.
        for name, reason in (('stall_timer', 'send_stalled'), ('partial_timer', 'partial_frame_timeout')):
            timer = getattr(channel, name)
            if timer is not None and now >= timer.deadline_ns:
                self.close(ex, reason)
                return
        fd, writer = channel.owned_fd.fileno(), channel.frame_writer
        current = writer.current
        if self.tasks.start_expired(current):
            # The budget decides first (outcome deadline), whichever path then ends the call: an unsent
            # task_start is withdrawn, a half-sent one closes the session (conn E-03).
            self.tasks.check_deadline(current.owner)
            if not self._current(ex, channel):
                return
            if writer.current is current:
                if writer.started:
                    self.close(ex, 'task_start_partial')
                    return
                writer.withdraw(current)
        status = writer.flush()
        if not self._current(ex, channel):     # a completion callback closed the row
            return
        if status is Written.FAILED:
            self.close(ex, 'welcome_send_failed' if ex.state is ExecState.STARTING else 'channel_send_failed')
            return
        if status in (Written.BLOCKED, Written.PARTIAL):
            self._arm_stall(ex, channel)       # progress short of a whole frame does not reset it
            if status is Written.PARTIAL and ex.state is not ExecState.STARTING and channel.partial_timer is None:
                channel.partial_timer = self.loop.call_at(now + PARTIAL_MS * MS,
                                                          self.step(self._partial_expired, ex, channel))
            return
        # A whole frame went out (or nothing was sendable): both deadlines reset; what is still queued waits for
        # space from now. Paused producers may go on.
        self._cancel(channel, 'stall_timer', 'partial_timer')
        if writer.pending:
            self._arm_stall(ex, channel)
        else:
            self.loop.watch(fd, selectors.EVENT_WRITE, None)
        self.requests.on_space(channel)

    def _stalled(self, ex: Execution, channel: Channel) -> None:
        channel.stall_timer = None
        writer = channel.frame_writer
        if self._current(ex, channel) and writer is not None and writer.pending:   # an emptied queue is not stalled
            self.close(ex, 'send_stalled')

    def _partial_expired(self, ex: Execution, channel: Channel) -> None:
        channel.partial_timer = None
        if self._current(ex, channel):
            self.close(ex, 'partial_frame_timeout')

    def _welcomed(self, ex: Execution, channel: Channel) -> None:
        """STARTING → ACTIVE only after prepared, the whole COMMIT, a valid hello and the whole welcome."""
        if ex.channel is not channel or ex.state is not ExecState.STARTING:
            return
        if self.loop.clock.now_ns() >= ex.startup_deadline_ns:
            self.close(ex, 'startup_deadline')
            return
        ex.state = ExecState.ACTIVE
        channel.phase = Phase.DATA
        ex.session.dispatch_open = True
        ex.session.task_admission = True
        record_lifecycle(self.recorder, 'session_active', ex, channel_id=channel.channel_id)
