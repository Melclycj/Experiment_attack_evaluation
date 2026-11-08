"""engine ↔ spawner control client (conn E-01 engine ↔ spawner 控制接口; E-04 控制链路故障).

Reader: per-direction seq starting at 1; an old seq is ignored only when it repeats the exact
original record without an fd; gaps, conflicts and fds on old records fault the link.
Writer: one writer; init, then stops, then spawns; seq advances only on a whole send; an
indeterminate send is reported to its owner and then faults the link.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import json
import os
import selectors
from typing import Any, Callable

from .ffi import Native, Received, Sent
from .loop import MS, Loop, Timer
from .objects import Execution
from .startup import PROTOCOL, _strict

HISTORY = 1024
UNWRITABLE_MS = 5000
SEQ_MAX = 2 ** 64 - 1
CONTROL_PER_ROUND = 8
INCOMING = frozenset({'control_ready', 'spawn_prepared', 'spawn_failed', 'execution_empty', 'runtime_status',
                      'connector_exited', 'worker_exited'})   # v2 (build plan item 13); worker_exited: H-17
STORAGE_PROTOCOL = 'w2-runtime-store/1'


class ControlFault(Exception):
    """The control link is no longer trustworthy; the engine runs the E-04 control-loss path."""


@dataclass(eq=False)
class Intent:
    kind: str                    # 'spawn' | 'stop'
    execution: Execution
    fields: dict[str, Any]


class ControlClient:
    def __init__(self, loop: Loop, native: Native, fd: int, epoch: str, *,
                 on_record: Callable[[dict[str, Any], list[int]], None],
                 on_sent: Callable[[Intent], None],
                 on_uncertain: Callable[[Intent], None],
                 on_expired: Callable[[Intent], None],
                 on_fault: Callable[[str], None],
                 trace: Callable[..., None]) -> None:
        self.loop, self.native, self.fd, self.epoch = loop, native, fd, epoch
        self.on_record, self.on_sent, self.on_uncertain = on_record, on_sent, on_uncertain
        self.on_expired, self.on_fault, self.trace = on_expired, on_fault, trace
        self.out_seq = 1
        self.in_seq = 1
        self.history: OrderedDict[int, bytes] = OrderedDict()
        self.init: dict[str, Any] | None = None
        self.ready = False
        self.dead = False
        self.stops: OrderedDict[Execution, Intent] = OrderedDict()
        self.spawns: deque[Intent] = deque()
        self.blocked_since: int | None = None
        self.blocked_timer: Timer | None = None
        loop.watch(fd, selectors.EVENT_READ, self.on_readable)
        loop.priority.add(fd)

    # ---- writer -------------------------------------------------------------------------
    def send_init(self, catalog_digest: str, storage_profile_digest: str) -> None:
        self.init = dict(catalog_digest=catalog_digest, protocol=PROTOCOL,
                         runtime_storage_protocol=STORAGE_PROTOCOL,
                         storage_profile_digest=storage_profile_digest)
        self.flush()

    def queue_spawn(self, execution: Execution, fields: dict[str, Any]) -> None:
        self.spawns.append(Intent('spawn', execution, fields))

    def withdraw_spawn(self, execution: Execution) -> bool:
        """Remove an unsent spawn. Sends happen only inside flush, so an intent still queued here
        is known never to have been sent; withdrawal is irreversible."""
        for intent in self.spawns:
            if intent.execution is execution:
                self.spawns.remove(intent)
                return True
        return False

    def queue_stop(self, execution: Execution, reason: str) -> None:
        """One merged stop intent per execution; a second request does not add a message."""
        if not self.dead and execution not in self.stops:
            self.stops[execution] = Intent('stop', execution, {'reason': reason})

    def withdraw_stop(self, execution: Execution) -> None:
        self.stops.pop(execution, None)

    def _next(self) -> Intent | None:
        if self.stops:
            return next(iter(self.stops.values()))
        return self.spawns[0] if self.spawns else None

    def flush(self) -> None:
        while not self.dead:
            now = self.loop.clock.now_ns()
            # Deadlines are checked at the send boundary too, not only by their timers.
            if self.blocked_timer is not None and now >= self.blocked_since + UNWRITABLE_MS * MS:
                self.fault('control unwritable for 5000 ms')
                return
            if self.out_seq > SEQ_MAX:
                self.fault('outgoing seq exhausted')
                return
            if self.init is not None and self.out_seq == 1:
                body, intent = dict(v=1, type='control_init', engine_epoch=self.epoch,
                                    seq='1', **self.init), None
            elif not self.ready:
                return
            else:
                intent = self._next()
                if intent is None:
                    self._idle()
                    return
                ex = intent.execution
                if intent.kind == 'spawn' and now >= ex.startup_deadline_ns:
                    self.on_expired(intent)   # the owner withdraws it; never sent after its deadline
                    continue
                body = dict(v=1, type=intent.kind, engine_epoch=self.epoch, seq=str(self.out_seq),
                            execution_id=ex.execution_id, lease_id=ex.lease_id, **intent.fields)
            wire = json.dumps(body, separators=(',', ':')).encode()
            result = self.native.send_control(self.fd, wire)
            if result is Sent.NOTHING:
                self._blocked()
                return
            if result is Sent.UNCERTAIN:
                if intent is not None:
                    self._dequeue(intent)
                    self.on_uncertain(intent)
                self.fault('control send error')
                return
            # Bookkeeping first, instrumentation last.
            self.out_seq += 1
            self._sent_whole()
            if intent is not None:
                self._dequeue(intent)
                self.on_sent(intent)
            self.trace('control_sent', record=body)

    def _dequeue(self, intent: Intent) -> None:
        if intent.kind == 'stop':
            self.stops.pop(intent.execution, None)
        else:
            self.spawns.remove(intent)

    def _blocked(self) -> None:
        """A pending record cannot be written. The period runs from the first such moment and is
        reset only by a whole send (conn E-04); blocking again after an idle gap keeps the original start."""
        self.loop.watch(self.fd, selectors.EVENT_WRITE, self.flush)
        if self.blocked_since is None:
            self.blocked_since = self.loop.clock.now_ns()
        if self.blocked_timer is None:   # an already-past expiry fires in the next round
            self.blocked_timer = self.loop.call_at(self.blocked_since + UNWRITABLE_MS * MS, self._stall_expired)

    def _idle(self) -> None:
        """Nothing pending: the queue is not "full", so no fault while idle. The period is wall-clock time
        from the first block; it neither pauses nor resets here."""
        self.loop.watch(self.fd, selectors.EVENT_WRITE, None)
        if self.blocked_timer is not None:
            self.blocked_timer.cancel()
            self.blocked_timer = None

    def _stall_expired(self) -> None:
        self.fault('control unwritable for 5000 ms')

    def _sent_whole(self) -> None:
        """Only a whole send resets the unwritable period (conn E-04)."""
        self.loop.watch(self.fd, selectors.EVENT_WRITE, None)
        self.blocked_since = None
        if self.blocked_timer is not None:
            self.blocked_timer.cancel()
            self.blocked_timer = None

    # ---- reader -------------------------------------------------------------------------
    def on_readable(self) -> None:
        # At most CONTROL_PER_ROUND records per round (conn E-03 调度): the selector is level-triggered, so
        # what remains is read in the next round, after that round's channels and requests had their turn.
        for _ in range(CONTROL_PER_ROUND):
            if self.dead:
                break
            kind, wire, fds, errno = self.native.recv_control(self.fd)
            if kind is Received.RETRY:
                break
            if kind is Received.EOF:
                self.fault('control EOF')
                return
            if kind is Received.FAULT:
                self.fault(f'control record rejected by receiver (errno {errno})')
                return
            try:
                self.accept(wire, fds)
            except ControlFault as error:
                self.fault(str(error))
                return
        self.flush()   # decisions taken above may have queued stops

    def accept(self, wire: bytes, fds: list[int]) -> None:
        """Sequence and correlation rules; every path that rejects the record closes its fds."""
        try:
            try:
                body = _strict(wire)
            except ValueError as error:
                raise ControlFault(f'control record not strict JSON: {error}') from None
            if not isinstance(body, dict) or body.get('engine_epoch') != self.epoch:
                raise ControlFault('engine_epoch mismatch')
            try:
                seq = int(body['seq'])
            except (KeyError, TypeError, ValueError):
                raise ControlFault('control record without a valid seq') from None
            if seq < self.in_seq:
                if fds:
                    raise ControlFault(f'old seq {seq} carries an fd')
                if self.history.get(seq) == wire:
                    self.trace('control_duplicate_ignored', seq=seq)
                    return
                raise ControlFault(f'old seq {seq} conflicts with history')
            if seq > self.in_seq:
                raise ControlFault(f'seq gap: expected {self.in_seq}, got {seq}')
            self.in_seq += 1
            self.history[seq] = wire
            if len(self.history) > HISTORY:
                self.history.popitem(last=False)
            self.trace('control_received', record=body, fd=bool(fds))
            if body.get('type') not in INCOMING:
                raise ControlFault(f'{body.get("type")} is not a spawner-to-engine record')
            if body['type'] == 'control_ready':
                self._ready(body)
                return
            if not self.ready:
                raise ControlFault('record before control_ready')
            owned, fds = fds, []
            self.on_record(body, owned)   # the lifecycle owns the fds from here
        finally:
            for fd in fds:
                os.close(fd)

    def _ready(self, body: dict[str, Any]) -> None:
        if self.ready or self.init is None:
            raise ControlFault('unexpected control_ready')
        for key in ('catalog_digest', 'protocol', 'runtime_storage_protocol', 'storage_profile_digest'):
            if body[key] != self.init[key]:
                raise ControlFault(f'control_ready {key} mismatch')
        self.ready = True
        self.flush()

    # ---- failure ------------------------------------------------------------------------
    def fault(self, reason: str) -> None:
        if self.dead:
            return
        self.dead = True    # nothing is sent from here on, so queued spawns stay provably unsent
        if self.blocked_timer is not None:
            self.blocked_timer.cancel()
        self.loop.forget(self.fd)
        os.close(self.fd)   # a surviving spawner observes EOF (conn E-04)
        self.on_fault(reason)
        self.trace('control_fault', reason=reason)
        self.stops.clear()
        self.spawns.clear()
