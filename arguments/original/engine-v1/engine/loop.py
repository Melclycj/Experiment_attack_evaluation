"""Single-threaded event loop: the only place engine state changes (conn E-03 唯一状态写入者).

Each callback runs to completion; nothing yields inside one decision. Timers hold the object they
act on, never a reusable key. One round: round hooks (the record latch), expired timers, readiness
callbacks (one recvmsg per ready channel, one sendmsg per writable channel), then the work posted before
the posted batch starts (handler events, request driving), each item once (conn E-03 容量、调度).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import heapq
import selectors
import time
from typing import Callable

MS = 1_000_000


class Clock:
    """CLOCK_MONOTONIC, the clock domain shared with the spawner and the child (conn E-01 step 5)."""

    real = True

    def now_ns(self) -> int:
        return time.monotonic_ns()


@dataclass(order=True)
class Timer:
    deadline_ns: int
    order: int
    callback: Callable[[], None] = field(compare=False)
    cancelled: bool = field(default=False, compare=False)

    def cancel(self) -> None:
        """Drop the callback at once: a cancelled timer must not keep the objects it acted on alive."""
        self.cancelled = True
        self.callback = _noop


def _noop() -> None:
    pass


class Loop:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.selector = selectors.DefaultSelector()
        self.handlers: dict[int, dict[int, Callable[[], None]]] = {}
        self.timers: list[Timer] = []
        self.order = 0
        self.posted: deque[Callable[[], None]] = deque()
        self.round_hooks: list[Callable[[], None]] = []
        self.priority: set[int] = set()   # fds whose readiness runs first in a round (the control link)
        self.compact_at = 1024

    def _apply(self, fd: int) -> None:
        handlers = self.handlers.get(fd, {})
        mask = 0
        for event in handlers:
            mask |= event
        registered = fd in self.selector.get_map()
        if not mask:
            if registered:
                self.selector.unregister(fd)
            self.handlers.pop(fd, None)
        elif registered:
            self.selector.modify(fd, mask)
        else:
            self.selector.register(fd, mask)

    def watch(self, fd: int, event: int, callback: Callable[[], None] | None) -> None:
        """Set (callback) or clear (None) the handler for EVENT_READ / EVENT_WRITE on fd."""
        handlers = self.handlers.setdefault(fd, {})
        if callback is None:
            handlers.pop(event, None)
        else:
            handlers[event] = callback
        self._apply(fd)

    def forget(self, fd: int) -> None:
        """Remove every registration for fd; called before the fd is closed."""
        self.handlers[fd] = {}
        self._apply(fd)

    def call_at(self, deadline_ns: int, callback: Callable[[], None]) -> Timer:
        self.order += 1
        timer = Timer(deadline_ns, self.order, callback)
        heapq.heappush(self.timers, timer)
        if len(self.timers) >= self.compact_at:
            # Cancelled entries are dropped once they outnumber live ones, so the heap stays bounded by the
            # live timers rather than by every timer ever armed (conn E-03: no accumulation of stale timers).
            self.timers = [t for t in self.timers if not t.cancelled]
            heapq.heapify(self.timers)
            self.compact_at = max(1024, 2 * len(self.timers))
        return timer

    def soon(self, callback: Callable[[], None]) -> None:
        """Run as its own decision after the readiness callbacks: this round if posted before the posted batch
        starts, else the next. Never inside the current decision."""
        self.posted.append(callback)

    def run_once(self, max_wait_s: float = 0.05) -> None:
        for hook in self.round_hooks:
            hook()
        wait = 0.0 if self.posted else max_wait_s
        if self.timers and self.clock.real:
            wait = min(wait, max(0.0, (self.timers[0].deadline_ns - self.clock.now_ns()) / 1e9))
        # Snapshot the registration each event was selected for; a later callback in this batch may
        # retire that fd and register a new object under the same number.
        ready = [(key.fd, event, self.handlers.get(key.fd, {}).get(event))
                 for key, mask in self.selector.select(wait if self.handlers else 0)
                 for event in (selectors.EVENT_READ, selectors.EVENT_WRITE) if mask & event]
        # Control and close facts decide before this round's new dispatch (conn E-03 调度).
        ready.sort(key=lambda item: item[0] not in self.priority)
        if not self.handlers and wait and self.clock.real:
            time.sleep(wait)
        # Expired deadlines decide before any readiness in the same round.
        self.fire_timers()
        for fd, event, callback in ready:
            if callback is not None and self.handlers.get(fd, {}).get(event) is callback:
                callback()
        for _ in range(len(self.posted)):   # work posted during this batch waits for the next round
            self.posted.popleft()()
        self.fire_timers()

    def fire_timers(self) -> None:
        now = self.clock.now_ns()
        while self.timers and self.timers[0].deadline_ns <= now:
            timer = heapq.heappop(self.timers)
            if not timer.cancelled:
                timer.callback()

    def run_until(self, predicate: Callable[[], bool], timeout_s: float) -> bool:
        until = time.monotonic() + timeout_s
        while not predicate():
            if time.monotonic() >= until:
                return False
            self.run_once()
        return True
