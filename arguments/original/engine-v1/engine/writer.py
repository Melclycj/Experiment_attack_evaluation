"""Single writer of one data channel (conn E-02 单 writer 与短写契约; E-03 流接口、序号与背压、容量).

A bounded FIFO of records. A record is encoded when it becomes the current frame, so a stream frame takes its seq
then; the encoded bytes are then immutable and nothing else starts until they are all sent. A positive send
advances only the offset; a short write is normal. Only a record whose first byte has not gone out can be
withdrawn. One flush makes at most one sendmsg. A whole send proves only that the local socket accepted every
byte; there is no application ACK.

Output budget per session: 1 MiB covering the current frame (sent prefix included), every queued record and the
space reserved for outstanding demands; the last 8 KiB admit only control records of at most 1,024 bytes.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
import json
import socket
import struct
from typing import Any, Callable

from .ffi import BODY_MAX

OUTPUT_MAX = 1 << 20
CONTROL_RESERVE = 8 * 1024
CONTROL_FRAME_MAX = 1024
FRAME_MAX = BODY_MAX + 4
SEQ_PLACEHOLDER = 2 ** 53 - 1        # sizing uses the widest seq a frame can carry


class Written(Enum):
    DONE = 'done'          # a whole frame went out (or there was nothing to send) and nothing is left
    MORE = 'more'          # a whole frame went out and more is queued
    PARTIAL = 'partial'    # a positive short send; the current frame continues
    BLOCKED = 'blocked'    # EAGAIN / EINTR: offset kept, wait for writability
    FAILED = 'failed'      # 0, any other error or a closed socket: the channel ends


def encode(body: dict[str, Any]) -> bytes:
    data = json.dumps(body, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    if not 0 < len(data) <= BODY_MAX:
        raise ValueError('frame body length outside 1–65,536')
    return struct.pack('>I', len(data)) + data


@dataclass(eq=False)
class Out:
    owner: Any
    build: Callable[[], dict[str, Any] | None]   # None at encode time: dropped unsent
    size: int                                    # an upper bound of the encoded frame
    control: bool
    on_sent: Callable[[], None] | None
    on_drop: Callable[[], None] | None


def make_out(owner: Any = None, body: dict[str, Any] | None = None,
             build: Callable[[], dict[str, Any] | None] | None = None, size_hint: dict[str, Any] | None = None,
             on_sent: Callable[[], None] | None = None, on_drop: Callable[[], None] | None = None,
             control: bool = False) -> Out:
    if body is not None:
        fixed = body
        size, build = len(encode(body)), (lambda: fixed)
    elif build is None or size_hint is None:
        raise ValueError('a record needs a body, or a build function and a size hint')
    else:
        size = len(encode(size_hint))
    if control and size > CONTROL_FRAME_MAX:
        raise ValueError('a control record is at most 1,024 bytes with its header')
    return Out(owner, build, size, control, on_sent, on_drop)


class FrameWriter:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.frames: deque[Out] = deque()
        self.current: Out | None = None
        self.data = b''
        self.offset = 0
        self.used = 0
        self.reserved = 0
        self.dead = False
        self.discarded = False

    @property
    def pending(self) -> bool:
        return self.current is not None or bool(self.frames)

    @property
    def started(self) -> bool:
        return self.current is not None and self.offset > 0

    def _fits(self, size: int, control: bool) -> bool:
        limit = OUTPUT_MAX if control else OUTPUT_MAX - CONTROL_RESERVE
        return self.used + self.reserved + size <= limit

    def queue(self, out: Out, from_reserve: int = 0) -> bool:
        """Append at the tail. ``from_reserve`` turns a demand's reservation into this record (it was admitted
        when reserved). False when the writer is dead or the budget has no room; the caller decides."""
        if self.dead:
            return False
        if from_reserve:
            if out.size > from_reserve or from_reserve > self.reserved:
                raise ValueError('record larger than its reservation')
            self.reserved -= from_reserve
        elif not self._fits(out.size, out.control):
            return False
        self.used += out.size
        self.frames.append(out)
        return True

    def reserve(self, size: int) -> bool:
        if self.dead or not self._fits(size, False):
            return False
        self.reserved += size
        return True

    def unreserve(self, size: int) -> None:
        self.reserved -= min(size, self.reserved)

    def withdraw(self, out: Out) -> bool:
        """Remove one record whose first byte has not been sent; its on_drop runs."""
        if out is self.current and self.offset == 0:
            self.current, self.data = None, b''
        elif out in self.frames:
            self.frames.remove(out)
        else:
            return False
        self.used -= out.size
        if out.on_drop is not None:
            out.on_drop()
        return True

    def withdraw_owner(self, owner: Any) -> None:
        """Withdraw every unstarted record of one owner (a cancelled request's chunks)."""
        for out in [o for o in ([self.current] if self.current is not None else []) + list(self.frames)
                    if o.owner is owner]:
            self.withdraw(out)

    def flush(self) -> Written:
        while self.current is None:
            if self.dead:
                return Written.FAILED
            if not self.frames:
                return Written.DONE
            out = self.frames.popleft()
            body = out.build()
            if body is None:
                self.used -= out.size
                if out.on_drop is not None:
                    out.on_drop()
                continue
            data = encode(body)
            if len(data) > out.size:
                raise ValueError('encoded frame exceeds its size bound')
            self.current, self.data, self.offset = out, data, 0
        if self.dead:
            return Written.FAILED
        try:
            sent = self.sock.sendmsg([memoryview(self.data)[self.offset:]], [],
                                     socket.MSG_NOSIGNAL | socket.MSG_DONTWAIT)
        except (BlockingIOError, InterruptedError):
            return Written.BLOCKED
        except OSError:
            sent = 0
        if sent <= 0:
            # Dead, but the records stay until close step 2 discards them: their drop callbacks then run after
            # step 1 has sealed the session, never while it is still OPEN.
            self.dead = True
            return Written.FAILED
        self.offset += sent
        if self.offset < len(self.data):
            return Written.PARTIAL
        done = self.current
        self.current, self.data, self.offset = None, b'', 0
        self.used -= done.size
        if done.on_sent is not None:
            done.on_sent()   # may close the channel; the caller re-checks
        if self.dead:
            return Written.FAILED
        return Written.MORE if self.frames else Written.DONE

    def discard(self) -> None:
        """Close step 2: unsent records are dropped (it does not mean sent data was read). Runs once."""
        if self.discarded:
            return
        self.discarded = self.dead = True
        dropped = ([self.current] if self.current is not None else []) + list(self.frames)
        self.frames.clear()
        self.current, self.data, self.offset = None, b'', 0
        self.used = self.reserved = 0
        for out in dropped:
            if out.on_drop is not None:
                out.on_drop()
