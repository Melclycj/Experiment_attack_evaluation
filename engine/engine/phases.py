"""Receive and send sides of the agent-side control channel (conn E-02 数据消息字段与关联, 单 writer 与短写契约; E-03
流接口、序号与背压). The row is ACTIVE from the whole COMMIT on (lifecycle._drive_commit); there is no handshake.

Each readiness callback runs one receive step and, for a whole message, its answer in the same executor decision. The
first build's verb set is empty (agent-rm-model 3.9 两条口的先后): every message is answered 'unsupported_kind' and
changes nothing. Callbacks hold the Execution and Channel objects they act on; a callback whose Channel is no longer
the row's current, unretired one does nothing. Closing goes through the lifecycle's close. A writable channel gets one
sendmsg per round; a whole frame resets the send-stall deadline, a frame whose first byte went out must complete
within its own deadline.
"""
from __future__ import annotations

import selectors
from typing import Any, Callable

from .loop import MS, Loop
from .objects import Channel, ExecState, Execution, Phase, Session
from .records import RecordFault, Recorder, VerifiedSubject
from .receive import Message, NeedMore, Reject, receive_step
from .writer import Out, Written, make_out

FRAME_MS = 5_000    # a frame is assembled within 5,000 ms of its first byte (conn E-02 step 7)
STALL_MS = 5_000    # output blocked from the first EAGAIN; only a whole send resets it (conn E-03)
PARTIAL_MS = 5_000  # a frame whose first byte went out completes within this, small progress does not extend it


class DataPlane:
    def __init__(self, loop: Loop, overflowuid: int, recorder: Recorder,
                 close: Callable[[Execution, str], None],
                 step: Callable[..., Callable[[], None]]) -> None:
        self.loop, self.overflowuid, self.recorder = loop, overflowuid, recorder
        self.close, self.step = close, step

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
        return (ex.channel is channel and channel.phase is Phase.DATA
                and ex.state in (ExecState.ACTIVE, ExecState.DRAINING))

    # ---- receive ------------------------------------------------------------------------
    def _readable(self, ex: Execution, channel: Channel) -> None:
        if not self._current(ex, channel):
            return
        result = receive_step(channel, self.overflowuid, self.loop.clock)
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
        # The record carries fixed values only: the message's type is agent text and unbounded within the frame.
        try:
            self.recorder.record('message_received', 'accepted',
                                 verified_subject=VerifiedSubject.from_context(result.context),
                                 connection_ref=channel.channel_id,
                                 source_ref={'launch_plan_digest': ex.launch_plan_digest},
                                 message={'size': result.size, 'answer': 'unsupported_kind'})
        except RecordFault:
            pass
        self._unsupported(ex, channel, result)

    def _frame_expired(self, ex: Execution, channel: Channel) -> None:
        channel.frame_timer = None
        if self._current(ex, channel):
            self.recorder.diagnostic('frame_timeout', execution_id=ex.execution_id, channel_id=channel.channel_id)
            self.close(ex, 'frame_timeout')

    def _unsupported(self, ex: Execution, channel: Channel, message: Message) -> None:
        """v2 first build: the agent-side control channel has an empty verb set (agent-rm-model 3.9 两条口的先后;
        validation.md K-04). Every message, whatever its type, is answered 'unsupported_kind' on the same channel and
        changes nothing; the row stays in its state. The identity rule ran before this point."""
        out = make_out(body={'v': 2, 'type': 'error', 'reply_to': message.reply_to, 'code': 'unsupported_kind'},
                       control=True)
        if channel.frame_writer is None or not channel.frame_writer.queue(out):
            self.close(ex, 'channel_send_failed')
            return
        self.flush_soon(ex, channel)

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
        if channel.stall_timer is None:
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
        # Every send attempt re-reads the deadlines, not only their timers.
        for name, reason in (('stall_timer', 'send_stalled'), ('partial_timer', 'partial_frame_timeout')):
            timer = getattr(channel, name)
            if timer is not None and now >= timer.deadline_ns:
                self.close(ex, reason)
                return
        fd, writer = channel.owned_fd.fileno(), channel.frame_writer
        status = writer.flush()
        if not self._current(ex, channel):     # a completion callback closed the row
            return
        if status is Written.FAILED:
            self.close(ex, 'channel_send_failed')
            return
        if status in (Written.BLOCKED, Written.PARTIAL):
            self._arm_stall(ex, channel)       # progress short of a whole frame does not reset it
            if status is Written.PARTIAL and channel.partial_timer is None:
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

    def _stalled(self, ex: Execution, channel: Channel) -> None:
        channel.stall_timer = None
        writer = channel.frame_writer
        if self._current(ex, channel) and writer is not None and writer.pending:   # an emptied queue is not stalled
            self.close(ex, 'send_stalled')

    def _partial_expired(self, ex: Execution, channel: Channel) -> None:
        channel.partial_timer = None
        if self._current(ex, channel):
            self.close(ex, 'partial_frame_timeout')
