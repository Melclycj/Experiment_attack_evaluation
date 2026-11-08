"""Attribution records (si E-09): typed events, one bounded local queue, a log worker and a failure latch.

The owner of a fact builds its event from its own objects. A verified_subject exists only as a copy of a
VerifiedContext, on the kinds of the validated-request path; control facts carry a control_binding, a distinct
type; agent reports are marked as such. record() promises bounded local acceptance only and returns the record's
number; the worker's receipt says what reached storage. Storage I/O never runs on the executor (si E-09 有界记录与故障状态).

Durable before release (648d60f2 4.3 先落盘再放行; validation.md K-52, K-53): numbers are given only by the executor
thread, in the lock, one by one; the worker takes a contiguous run from the head of the queue, appends it in order,
fsyncs once after the whole run and only then moves the receipt to the run's last number; on the first error it
latches and stops, never retrying. After moving the receipt (or latching) it writes one byte to the wake pipe the
executor's loop watches, so no advance goes unseen. ``status()`` reads the latch and the receipt in one lock: that one
read is where a fault and a release are ordered.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import json
import os
import threading
import time
from typing import Any, Callable

from .ffi import UID_INVALID

SCHEMA = 'w2-event/1'
PRODUCER = 'engine'
EVENT_MAX = 1 << 20           # one encoded event: above any record a valid canonical request can produce (K-54)
QUEUE_MAX = 16 << 20          # pending events of this producer, the in-flight batch included
BATCH_MAX = 64 * 1024
DISK_MAX = 64 << 20           # per run, events only (no fixture payloads in this build)
STALL_NS = 5_000 * 1_000_000  # a non-empty queue with no durable progress for 5 s fails the epoch

VERIFIED_KINDS = frozenset({
    'message_received', 'request_received', 'pre_egress', 'authorization_decided', 'dispatch_started',
    'post_read', 'operation_completed', 'request_terminal', 'response_sent', 'response_abandoned',
    'request_released', 'cleanup_stalled', 'late_completion'})
CONTROL_KINDS = frozenset({
    'spawn_requested', 'spawn_prepared', 'spawn_failed', 'spawn_withdrawn', 'session_active', 'session_closed',
    'execution_empty', 'connector_exited', 'worker_exited', 'uid_released', 'runtime_storage', 'task_call_started', 'task_call_draining',
    'task_call_resolved',
    # v2 judgment port, bound to the row the judgment port belongs to (validation.md K-23): admission order, decision,
    # withdrawal, revocation, question and answer, the request to the PDP and its answer; no completion (648d60f2 4.3).
    # Details carry no header value and no truth.
    'request_admitted', 'request_decided', 'request_withdrawn', 'entry_revoked', 'question_asked',
    'question_answered', 'pdp_requested', 'pdp_answered',
    # host file reads (validation.md H-20, H-21): a file request uses the kinds above (request_admitted with
    # request_kind file; request_decided's allow with actual_length or start); listing the objects is answered from the
    # table at once and leaves this one, with the aliases listed and nothing of any file
    'file_objects_listed'})
# v2 management port and hook port: changes to the tables and the credential store, and the PDP connecting and going,
# have no execution binding (K-23, K-27, K-49).
ADMIN_KINDS = frozenset({'table_changed', 'credential_changed', 'workspace_changed', 'admin_rejected', 'pdp_connected',
                         'pdp_disconnected'})
COMMON = frozenset({'connection_ref', 'task_call_key', 'request_key', 'caused_by', 'source_ref'})
GROUPS: dict[str, frozenset[str]] = {
    'message_received': frozenset({'message'}),
    'request_received': frozenset({'requested_operation'}),
    'pre_egress': frozenset({'operation', 'flow'}),
    'authorization_decided': frozenset({'operation', 'authorization'}),
    'dispatch_started': frozenset({'operation', 'lifecycle'}),
    'post_read': frozenset({'operation', 'flow'}),
    'operation_completed': frozenset({'operation', 'completion', 'lifecycle'}),
    'late_completion': frozenset({'completion', 'lifecycle'}),
    'task_call_started': frozenset({'detail', 'lifecycle'}),
    'task_call_draining': frozenset({'detail', 'lifecycle'}),
    'task_call_resolved': frozenset({'detail', 'lifecycle', 'agent_report'}),
    'runtime_storage': frozenset({'runtime_storage'}),
    'receive_rejected': frozenset({'reject'}),
    'diagnostic': frozenset({'name', 'detail'}),
}
for _kind in ('request_terminal', 'response_sent', 'response_abandoned', 'request_released', 'cleanup_stalled'):
    GROUPS[_kind] = frozenset({'lifecycle'})
for _kind in (CONTROL_KINDS | ADMIN_KINDS) - set(GROUPS):
    GROUPS[_kind] = frozenset({'detail'})


@dataclass(frozen=True)
class VerifiedSubject:
    """A copy of a VerifiedContext's sender fields; built only by from_context."""

    execution_id: str
    local_agent_id: str
    session_id: str
    channel_id: str
    receiver_generation: int
    expected_uid: int
    sender_uid: int
    sender_pid: int | None

    @classmethod
    def from_context(cls, context: Any) -> VerifiedSubject:
        return cls(context.execution_id, context.local_agent_id, context.session_id, context.channel_id,
                   context.receiver_generation, context.expected_uid, context.sender_uid, context.sender_pid)


@dataclass(frozen=True)
class ControlBinding:
    """The control relation of a lifecycle fact (Execution / UidLease). Never a sender."""

    execution_id: str
    lease_id: str
    launch_plan_digest: str
    expected_uid: int

    @classmethod
    def from_execution(cls, ex: Any) -> ControlBinding:
        return cls(ex.execution_id, ex.lease_id, ex.launch_plan_digest, ex.lease.uid)


class RecordFault(Exception):
    """A required event could not be accepted; the caller takes the record-fault path."""


class RecordTooLarge(Exception):
    """One event derived from a request is over EVENT_MAX: only that request is refused, the latch stays open (K-54)."""


def _plain(value: Any) -> Any:
    """Group values: engine-owned scalars, lists and dicts only; integers above the safe range as strings."""
    if value is None or type(value) in (bool, str):
        return value
    if type(value) is int:
        return value if abs(value) <= 2 ** 53 - 1 else str(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    raise TypeError(f'record value of type {type(value).__name__}')


class Recorder:
    """``path`` None keeps events in memory and counts them durable at once (unit tests only)."""

    def __init__(self, epoch: str, overflowuid: int, clock: Any, path: str | None = None, keep: int = 0,
                 wall: Callable[[], int] = time.time_ns) -> None:
        self.epoch, self.overflowuid, self.clock, self.wall = epoch, overflowuid, clock, wall
        self.events: deque[dict[str, Any]] = deque(maxlen=keep)
        self.seq = 0
        self.dropped = 0
        self.failed: str | None = None
        self.lock = threading.Condition()
        self.pending: deque[tuple[int, bytes]] = deque()
        self.queued_bytes = 0
        self.durable_seq = 0
        self.written = 0
        self.closing = False
        self.pending_since: int | None = None
        self.seen_durable = 0
        self.worker: threading.Thread | None = None
        self.fd: int | None = None
        self.fsync: Callable[[int], None] = os.fsync          # replaced by tests to stall or fail the worker
        self.wake_r, self.wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        if path is not None:
            self.fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
            self._prepare(path)
            self.worker = threading.Thread(target=self._drain, name='record-writer', daemon=True)
            self.worker.start()

    def _prepare(self, path: str) -> None:
        """The record file exists before the first record (K-53): its directory entry is made durable here. A tail
        left by a crash in the middle of a record is closed with a newline first, so the next run's first record
        starts on a line of its own (工程默认)."""
        size = os.fstat(self.fd).st_size
        if size:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                last = os.pread(fd, 1, size - 1)
            finally:
                os.close(fd)
            if last != b'\n':
                os.write(self.fd, b'\n')
                os.fsync(self.fd)
        directory = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    # ---- executor side --------------------------------------------------------------------
    def has_room(self, count: int) -> bool:
        """Space for ``count`` events, checked before a decision that must record them (dispatch)."""
        with self.lock:
            return self.failed is None and QUEUE_MAX - self.queued_bytes >= count * EVENT_MAX

    def record(self, kind: str, outcome: str = 'observed', reason_code: str = 'none', *,
               verified_subject: VerifiedSubject | None = None, control_binding: ControlBinding | None = None,
               **groups: Any) -> int:
        """A required event; returns its number. Raises RecordFault (and latches the failure) when it cannot be
        accepted, RecordTooLarge (latch untouched) when the event alone is over EVENT_MAX. Absent groups are omitted,
        never written as null."""
        groups = {k: v for k, v in groups.items() if v is not None}
        try:
            self._check_shape(kind, verified_subject, control_binding, groups)
            item = self._envelope(kind, outcome, reason_code)
            if verified_subject is not None:
                item['verified_subject'] = _plain(verified_subject.__dict__)
            if control_binding is not None:
                item['control_binding'] = _plain(control_binding.__dict__)
            item.update({k: _plain(v) for k, v in groups.items() if v is not None})
        except (TypeError, ValueError) as error:
            self.fail(f'malformed {kind}: {error}')
            raise RecordFault(str(error)) from None
        seq = self._enqueue(item)
        if seq is None:
            raise RecordFault(self.failed or 'record unavailable')
        return seq

    def status(self) -> tuple[str | None, int]:
        """The latch and the receipt, read together in the one lock (K-52: the shared linearisation point)."""
        with self.lock:
            return self.failed, self.durable_seq

    def drain_wake(self) -> None:
        """The executor's side of the wake pipe: read until EAGAIN, then the caller reads status() (K-53)."""
        while True:
            try:
                if not os.read(self.wake_r, 4096):
                    return
            except BlockingIOError:
                return
            except InterruptedError:
                continue

    def _wake(self) -> None:
        while True:
            try:
                os.write(self.wake_w, b'\0')
                return
            except InterruptedError:
                continue
            except BlockingIOError:              # the pipe is full: a wake-up is already waiting
                return
            except OSError:
                return

    def diagnostic(self, name: str, **detail: Any) -> None:
        """Best effort: never raises, never latches; a diagnostic that cannot be kept is counted."""
        try:
            item = self._envelope('diagnostic', 'observed', 'none')
            item['name'] = name
            item['detail'] = json.loads(json.dumps(detail, default=str))
        except (TypeError, ValueError):
            self.dropped += 1
            return
        if self._enqueue(item, required=False) is None:
            self.dropped += 1

    def fail(self, reason: str) -> None:
        with self.lock:
            if self.failed is None:
                self.failed = reason
        self._wake()

    def check(self) -> str | None:
        """Read once per round by the executor: the latch, plus the durable-progress deadline."""
        now = self.clock.now_ns()
        with self.lock:
            busy = bool(self.pending)
            progressed = self.durable_seq != self.seen_durable
            self.seen_durable = self.durable_seq
        if not busy:
            self.pending_since = None
        elif progressed or self.pending_since is None:
            self.pending_since = now
        elif now - self.pending_since >= STALL_NS:
            self.fail('no durable progress for 5000 ms')
        return self.failed

    def receipt(self) -> dict[str, Any]:
        with self.lock:
            return {'engine_epoch': self.epoch, 'producer': PRODUCER, 'last_durable_seq': str(self.durable_seq),
                    'evidence_complete': self.failed is None and self.durable_seq == self.seq,
                    'error_code': self.failed}

    def close(self, timeout_s: float = 5.0) -> dict[str, Any]:
        with self.lock:
            self.closing = True
            self.lock.notify_all()
        if self.worker is not None:
            self.worker.join(timeout_s)
        for fd in (self.wake_r, self.wake_w):
            try:
                os.close(fd)
            except OSError:
                pass
        return self.receipt()

    def _check_shape(self, kind: str, subject: VerifiedSubject | None, binding: ControlBinding | None,
                     groups: dict[str, Any]) -> None:
        if kind not in GROUPS or kind == 'diagnostic':
            raise ValueError(f'unknown kind {kind}')
        if type(groups.get('source_ref')) is not dict or not groups['source_ref']:
            raise ValueError(f'{kind} needs a structured source_ref')
        if set(groups) - GROUPS[kind] - COMMON:
            raise ValueError(f'fields {sorted(set(groups) - GROUPS[kind] - COMMON)} not allowed on {kind}')
        if kind in VERIFIED_KINDS:
            if type(subject) is not VerifiedSubject or binding is not None:
                raise ValueError(f'{kind} needs a verified_subject and no control_binding')
            # No sentinel becomes a principal, and the subject is the per-fragment comparison result.
            if (subject.sender_uid in (0, self.overflowuid, UID_INVALID)
                    or subject.sender_uid != subject.expected_uid):
                raise ValueError('sentinel or mismatched sender uid in a verified subject')
        elif subject is not None:
            raise ValueError(f'{kind} carries no verified_subject')
        elif kind in CONTROL_KINDS and type(binding) is not ControlBinding:
            raise ValueError(f'{kind} needs a control_binding')
        elif kind not in CONTROL_KINDS and binding is not None:
            raise ValueError(f'{kind} carries no control_binding')

    def _envelope(self, kind: str, outcome: str, reason_code: str) -> dict[str, Any]:
        return {'event_schema': SCHEMA, 'engine_epoch': self.epoch,
                'event_id': f'{self.epoch}:{PRODUCER}:{self.seq + 1}', 'producer': PRODUCER,
                'producer_seq': str(self.seq + 1), 'monotonic_time': str(self.clock.now_ns()),
                'wall_time': str(self.wall()), 'kind': kind, 'outcome': outcome, 'reason_code': reason_code}

    def _enqueue(self, item: dict[str, Any], required: bool = True) -> int | None:
        data = (json.dumps(item, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode()
        if len(data) > EVENT_MAX:
            if required:
                raise RecordTooLarge(f'{item.get("kind")} over {EVENT_MAX} bytes')
            return None
        with self.lock:
            if self.failed is not None:
                return None
            if QUEUE_MAX - self.queued_bytes < len(data):
                if required:
                    self.failed = 'record queue full'
                return None
            self.seq += 1   # equals the envelope's seq: only the executor thread enqueues
            self.events.append(item)
            if self.worker is None:
                self.durable_seq = self.seq
                return self.seq
            self.pending.append((self.seq, data))
            self.queued_bytes += len(data)
            self.lock.notify()
            return self.seq

    # ---- log worker -----------------------------------------------------------------------
    def _drain(self) -> None:
        while True:
            with self.lock:
                while not self.pending and not self.closing:
                    self.lock.wait()
                if not self.pending:
                    return
                batch, size = [], 0
                for seq, data in self.pending:
                    if batch and size + len(data) > BATCH_MAX:
                        break
                    batch.append((seq, data))
                    size += len(data)
            try:
                if self.written + size > DISK_MAX:
                    raise OSError('run disk quota reached')
                payload = b''.join(data for _, data in batch)
                view = memoryview(payload)
                while view:
                    view = view[os.write(self.fd, view):]
                self.fsync(self.fd)               # once, after the whole run (K-53 前缀落盘)
            except OSError as error:
                self.fail(f'write failed: {error.strerror or error}')     # latches and wakes; never retried
                return
            with self.lock:
                for _ in batch:
                    self.pending.popleft()
                self.queued_bytes -= size
                self.written += size
                self.durable_seq = batch[-1][0]
            self._wake()                              # after the receipt moved (K-53 唤醒不丢)


def record_lifecycle(recorder: Recorder, kind: str, ex: Any, outcome: str = 'observed', reason: str = 'none',
                     **detail: Any) -> int | None:
    """A control fact of one Execution; its number, or None when it was not accepted. Best effort: close, stop and reap
    never wait on or fail with a record; a refused record has already latched the failure. Every record bound to a row
    names the row's workspace (648d60f2 4.1). RecordTooLarge propagates: the caller refuses the one request."""
    workspace = getattr(getattr(ex, 'plan', None), 'workspace_id', None)
    if workspace is not None:
        detail = {'workspace_id': workspace, **detail}
    try:
        return recorder.record(kind, outcome, reason, control_binding=ControlBinding.from_execution(ex),
                               source_ref={'launch_plan_digest': ex.launch_plan_digest}, detail=detail or None)
    except RecordFault:
        return None
