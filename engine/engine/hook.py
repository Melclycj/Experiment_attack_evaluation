"""The hook (agent-rm-model 648d60f2 3.2, 4.3; validation.md K-08, K-09, K-11, K-12, K-13, K-15, K-16, K-22, K-25, K-26,
K-31, K-35, K-37, K-38, K-42, K-43, K-45, K-46, K-47, K-50, K-52, K-58, K-59).

A request's path in the core (648d60f2 4.3 请求的路径与三个检查点): the first checkpoint (条款 10, the table, the
credential binding; the two version numbers noted); on an "ask every time" cell the user is asked and the answer is
checked against the table as it is when it arrives (the second checkpoint); then the PDP is asked; when it allows, the
allow record goes to the record queue, and once its receipt covers it the third checkpoint compares the version numbers
and, if either moved, redoes the first checkpoint without asking; only then does the ALLOW frame go out. That frame is
the consumption point: at most one per sequence number (K-11). One request per row is in this path at a time, from
admission to release or refusal; the row's later requests queue (K-15). The judgment reads only the request object,
the row's own workspace table (reached through the row, K-35), the credential records, the user's answers and the PDP's.

File requests (validation.md H-07, H-08, H-19; plan engine-v3-n16-file-read 2.3a) come in on the row's file judgment port
and take the same path, in the same queue: the first checkpoint is fileobjects.check_file; an "ask every time" object
is asked; the PDP is asked; once it allows, the first checkpoint runs again and the target is opened beneath the
object's anchor, so the allow record carries the length the open makes possible; the third checkpoint; then FILE_ALLOW
hands the opened descriptor to the worker. Every path that ends such a request otherwise closes that descriptor. A
FILE_ALLOW that has to wait in the port's queue (the worker not reading) is not done yet: until its descriptor has gone
the request stays findable by port and seq, a withdrawal or the row closing takes it back, and right before the
descriptor goes the authority is checked again by the version numbers (file_allow_due).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from enum import Enum
import ipaddress
import os
from typing import Any, Callable

from connector.canonical import FILE_OP_READ, FILE_REASONS, KEY_KIND_FILE, NEVER_CONNECT, pack_list, u16, u32, u64, u8
from . import fileobjects as fo
from .credentials import CredentialStore
from .judgment import (DENY_CLAUSE, DENY_CLOSED, DENY_CREDENTIAL, DENY_NOT_AUTHORIZED, DENY_PDP, DENY_POLICY_CHANGED,
                       DENY_QUEUE_FULL, DENY_RECORDED, DENY_UNAVAILABLE, DENY_USER, JudgedRequest, JudgmentPort,
                       check_memfd)
from .matching import (Binding, CredentialRefused, Match, Outcome, credential_for, endpoint_hit, exact_key, token_form,
                       usable_accounts)
from .pdp import entry_fields
from .records import RecordTooLarge, record_lifecycle
from .workspaces import Approval, Entry, EntryInvalid, EntryState, KeyKind, WorkspaceStore

QUEUE_MAX = 32                     # queued requests per row, the one in the path included (工程项 4)
# the four answers (648d60f2 3.2): the persistent two act on the whole cell, its approval mode or its state only
VERDICT_ALLOW_ONCE, VERDICT_ALLOW_CELL, VERDICT_DENY_ONCE, VERDICT_DENY_CELL = 1, 2, 3, 4
WITHDRAWN_BY_CONNECTOR, WITHDRAWN_ROW_CLOSED = 1, 2


def literal_not_named(host: bytes, entry: Entry) -> bool:
    """K-58: the destination is an IP literal that is not globally reachable (a never-connect range counts as not), and
    no address the covering cell names holds it. A host name is judged at connect time (C-19). The literal is judged as
    written: one under a deployment's own NAT64 prefix never reaches here, the connector refuses it at validation as
    the grammar refuses 64:ff9b::/96 (C-35)."""
    try:
        addr = ipaddress.ip_address(host.decode('ascii'))
    except ValueError:                                    # a host name (UnicodeDecodeError is a ValueError)
        return False
    if addr.is_global and not any(addr in n for n in NEVER_CONNECT):
        return False
    return not any(addr in ipaddress.ip_network(n) for n in entry.addresses)


class State(Enum):
    QUEUED = 'queued'
    ASKING = 'asking'
    PDP = 'pdp'            # asked of the PDP (or waiting for one to connect)
    DURABLE = 'durable'    # the PDP allowed; the allow record waits for its receipt
    SENT = 'sent'          # ALLOW / ALLOW_NOCRED went out; the request stays in flight until REPORT (K-38)
    DELIVERING = 'delivering'   # a file request's FILE_ALLOW waits in its port's queue, its descriptor not gone (H-08)
    DONE = 'done'


@dataclass(frozen=True)
class Verdict:
    """One pass of the first checkpoint (648d60f2 4.3): a refusal, or the covering allow cell, its revision and the
    credential binding."""

    refusal: tuple[int, str] | None
    entry: Entry | None = None
    key: str = ''
    rev: int = 0
    binding: Binding | None = None
    detail: tuple[tuple[str, Any], ...] = ()
    obj: fo.FileObject | None = None        # a file request's object (H-07)

    def same_result(self, other: Verdict) -> bool:
        """The second checkpoint: the same cell, unchanged since it was shown, and the same binding. For a file request:
        the same object, unchanged since it was shown (H-07)."""
        if self.obj is not None or other.obj is not None:
            return (self.refusal is None and other.refusal is None and self.obj is not None and other.obj is not None
                    and self.obj.alias == other.obj.alias and self.rev == other.rev)
        return (self.refusal is None and other.refusal is None and self.entry is not None and other.entry is not None
                and self.entry.identity == other.entry.identity and self.rev == other.rev and self.binding == other.binding)

    def same_decision(self, other: Verdict) -> bool:
        """The third checkpoint (the reading the user chose, 2026-11-01): the same cell, the same state and approval
        mode, the same binding, the same named addresses (K-46's fifth item, user 2026-11-05), and 条款 10 still not
        met. A cell whose methods or paths changed but still covers the request passes; one that now asks a request that
        was not asked does not. A file request: H-07's four (fileobjects.same_decision after a first checkpoint that
        passed)."""
        if self.obj is not None or other.obj is not None:
            return self.refusal is None and other.refusal is None and fo.same_decision(self.obj, other.obj)
        return (self.refusal is None and other.refusal is None and self.entry is not None and other.entry is not None
                and self.entry.identity == other.entry.identity and self.entry.state is other.entry.state
                and self.entry.approval is other.entry.approval and self.binding == other.binding
                and self.entry.addresses == other.entry.addresses)


@dataclass(eq=False)
class Pending:
    ex: Any
    port: Any                       # the row's JudgmentPort, or its FilePort for a file request
    request: JudgedRequest | fo.FileRequest
    memfd: int                      # owned until DONE; -1 for a file request
    admission: int                  # the core's admission order (K-42)
    state: State = State.QUEUED
    match: Match | None = None
    question_id: int | None = None
    verdict: Verdict | None = None          # the first checkpoint's result the question showed (K-45)
    answer: int = 0                         # the user's answer, when asked
    basis: str = ''                         # how the table or the user allowed it
    baseline: Verdict | None = None         # the decision the third checkpoint compares with
    versions: tuple[int, int] = (0, 0)      # the table's and the credential store's versions with the baseline
    link: Any = None                        # the PDP connection the request went out on; None while none is up
    record_seq: int = 0                     # the allow record's number (K-52)
    target_fd: int = -1                     # a file request's opened target, from the open to FILE_ALLOW (H-08)
    record_extra: tuple[tuple[str, Any], ...] = ()      # the allow record's actual_length or start (H-20)

    def release_fd(self) -> None:
        for name in ('memfd', 'target_fd'):
            fd = getattr(self, name)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)

    @property
    def is_file(self) -> bool:
        return isinstance(self.request, fo.FileRequest)


@dataclass(eq=False)
class RowState:
    ex: Any
    port: JudgmentPort
    workspace_id: str
    file_port: Any = None                                         # the row's file judgment port (H-06)
    queue: deque[Pending] = field(default_factory=deque)
    current: Pending | None = None                                # the one request between admission and release
    inflight: dict[int, Pending] = field(default_factory=dict)   # seq -> allowed request awaiting REPORT (K-38)
    delivering: dict[int, Pending] = field(default_factory=dict)  # file port seq -> FILE_ALLOW not yet handed over


class Hook:
    def __init__(self, loop: Any, recorder: Any, workspaces: WorkspaceStore, credentials: CredentialStore,
                 trace: Callable[..., None], measure_completion: bool = False,
                 opener: Callable[[int, bytes, int], int] | None = None) -> None:
        """``measure_completion``: the measurement switch of the gate and the integration scenarios (README 完成记录开关);
        off, the default, completion is internal bookkeeping only (648d60f2 4.1, 4.3: engine 不记完成). ``opener``: the
        one way a host file is opened, ffi.Native.open_beneath (H-10); without it every file request is refused."""
        self.loop, self.recorder, self.workspaces, self.credentials, self.trace = loop, recorder, workspaces, credentials, trace
        self.measure_completion = measure_completion
        self.opener = opener
        self.rows: dict[str, RowState] = {}
        self.questions: dict[int, Pending] = {}
        self.admitted = 0
        self.next_question_id = 1
        self.admin: Any = None          # set by the management port: .question(...), .withdrawn(...)
        self.pdp: Any = None            # set by the hook port: .link, .send_request(...)
        self.pdp_waiting: dict[int, Pending] = {}       # admission -> request asked of the PDP, or waiting for one
        self.durable: dict[int, Pending] = {}           # admission -> request whose allow record waits for its receipt

    # ---- rows ----
    def register(self, ex: Any, port: JudgmentPort, file_port: Any = None) -> None:
        self.rows[ex.execution_id] = RowState(ex, port, ex.plan.workspace_id, file_port)

    def row_closed(self, ex: Any) -> None:
        """K-22: queued requests and the one in the path, at whatever stage, get DENY(unavailable), each with its own
        record (so an allow record already written is followed by one, K-46); the question is withdrawn; a FILE_ALLOW
        still waiting in the port's queue is taken back, its copy closed, and refused the same way (H-08); in-flight
        entries are dropped so a late REPORT is only noted."""
        row = self.rows.pop(ex.execution_id, None)
        if row is None:
            return
        # every queued FILE_ALLOW is taken back before any refusal goes out: sending one makes the port flush, and a
        # copy still at the head of its queue would be judged there (the row gone: replaced by a FILE_DENY of its own)
        # and then refused again below; taken back first, each seq gets exactly one FILE_DENY
        delivering = list(row.delivering.items())
        row.delivering.clear()
        for seq, p in delivering:
            p.port.cancel_allow(seq)
        for p in list(row.queue):
            self._deny(row, p, DENY_CLOSED, 'row_closed')
        row.queue.clear()
        if row.current is not None:
            p = row.current
            stage = p.state.value
            self._leave_stage(p, WITHDRAWN_ROW_CLOSED)
            self._deny(row, p, DENY_CLOSED, 'row_closed', stage=stage)
        for seq, p in delivering:
            self._deny(row, p, DENY_CLOSED, 'row_closed', stage=State.DELIVERING.value)
        for p in row.inflight.values():
            p.state = State.DONE
            p.release_fd()
        row.inflight.clear()

    def _leave_stage(self, p: Pending, withdrawn_reason: int) -> None:
        """Take a request out of whichever waiting set its stage put it in."""
        if p.state is State.ASKING:
            self._cancel_question(p, withdrawn_reason)
        elif p.state is State.PDP:
            self.pdp_waiting.pop(p.admission, None)
        elif p.state is State.DURABLE:
            self.durable.pop(p.admission, None)

    # ---- admission (K-15, K-24, K-42, K-54) ----
    def admit(self, ex: Any, port: JudgmentPort, request: JudgedRequest, memfd: int) -> None:
        row = self.rows.get(ex.execution_id)
        if row is None or row.port is not port:
            os.close(memfd)
            port.fault('request for an unregistered row')
            return
        self._enqueue(row, Pending(ex, port, request, memfd, self.admitted + 1))

    def admit_file(self, ex: Any, port: Any, request: fo.FileRequest) -> None:
        """A list or read from the row's file judgment port (H-07): the same admission order, queue and records."""
        row = self.rows.get(ex.execution_id)
        if row is None or row.file_port is not port:
            port.fault('file request for an unregistered row')
            return
        self._enqueue(row, Pending(ex, port, request, -1, self.admitted + 1))

    def _enqueue(self, row: RowState, p: Pending) -> None:
        self.admitted += 1
        try:
            record_lifecycle(self.recorder, 'request_admitted', p.ex, admission=p.admission, **p.request.admission_record())
        except RecordTooLarge:                   # only this request; the latch stays open (K-54)
            self._deny(row, p, DENY_UNAVAILABLE, 'record_too_large')
            return
        if len(row.queue) + (1 if row.current else 0) >= QUEUE_MAX:
            self._deny(row, p, DENY_QUEUE_FULL, 'queue_full')
            return
        if not p.is_file and not check_memfd(p.memfd, p.request.body_len):
            self._deny(row, p, DENY_CLAUSE, 'memfd_unsealed')
            return
        row.queue.append(p)
        self._advance(row)

    def _advance(self, row: RowState) -> None:
        while row.queue and row.current is None and self.rows.get(row.ex.execution_id) is row:
            p = row.queue.popleft()
            row.current = p
            self._decide(row, p)

    # ---- the first checkpoint (648d60f2 3.2, 4.3; K-12, K-25, K-43) ----
    def check(self, row: RowState, p: Pending) -> Verdict:
        """The table first: a request the table refuses is reported with the table's reason only, whether or not it
        also meets 条款 10 (648d60f2 4.3 拒绝回复); a non-global IP literal the covering allow cell does not name is the
        table's refusal too, before 条款 10 and before any question (K-58); then 条款 10, against the endpoints of the
        accounts this row can use only (design 2026-11-02); then the credential binding."""
        r = p.request
        if p.is_file:                   # H-07: the object, its mode, the operation, the path rule, the length
            table = self.workspaces.tables.get(row.workspace_id)
            refusal, obj, detail = fo.check_file(bool(p.ex.plan.transfer), table, r)
            if refusal is not None:
                return Verdict(refusal, detail=detail)
            assert obj is not None and table is not None
            return Verdict(None, key=obj.alias, rev=table.revs.get(('file', obj.alias), 0), obj=obj)
        if p.ex.plan.transfer:          # S-24: a transfer row hangs no entries; every request is refused here, no PDP
            return Verdict((DENY_NOT_AUTHORIZED, 'transfer_row'))
        table = self.workspaces.tables.get(row.workspace_id)
        if table is None or table.unavailable:
            return Verdict((DENY_UNAVAILABLE, 'workspace_unavailable'))
        from .matching import match as match_request
        m = match_request(table.entries, r.host, r.port, r.method, r.path)
        p.match = m
        clause = ('clause10_token_form' if token_form(r.method, r.body_kind, r.form_keys) else
                  'clause10_endpoint' if endpoint_hit(r.host, r.port, r.path, self.credentials.endpoints_of(
                      usable_accounts(table.entries.values(), p.ex.accounts))) else '')
        hit = (('clause10', clause),) if clause else ()
        if m.outcome is Outcome.DENY_RECORDED:
            return Verdict((DENY_RECORDED, 'recorded_deny'), detail=(('key_kind', int(m.key_kind)), ('key', m.key)) + hit)
        if m.outcome is Outcome.NO_RECORD or m.entry is None:
            return Verdict((DENY_NOT_AUTHORIZED, 'not_covered' if m.key_kind else 'no_entry'),
                           detail=(('key_kind', int(m.key_kind) if m.key_kind else 0), ('key', m.key or '')) + hit)
        if literal_not_named(r.host, m.entry):
            return Verdict((DENY_NOT_AUTHORIZED, 'address_not_named'),
                           detail=(('key_kind', int(m.key_kind)), ('key', m.key or '')) + hit)
        if clause:
            return Verdict((DENY_CLAUSE, clause))
        try:
            binding = self.binding(p, m.entry, m.key or '')
        except CredentialRefused as e:
            return Verdict((DENY_CREDENTIAL, 'credential_refused'), detail=(('why', str(e)),))
        return Verdict(None, m.entry, m.key or '', table.revs.get(m.entry.identity, 0), binding)

    def versions(self, row: RowState) -> tuple[int, int]:
        """The table's in-memory version and the credential store's (K-46): either moving sends the third checkpoint
        back to the first."""
        table = self.workspaces.tables.get(row.workspace_id)
        return (table.version if table is not None else -1, self.credentials.version)

    def _decide(self, row: RowState, p: Pending) -> None:
        v = self.check(row, p)
        if v.refusal is not None:
            self._deny(row, p, *v.refusal, **dict(v.detail))
        elif any(x is not None and x.approval is Approval.ALWAYS for x in (v.entry, v.obj)):
            self._ask(row, p, v)
        else:
            self._to_pdp(row, p, v, 'recorded_allow')

    def binding(self, p: Pending, entry: Entry, key: str) -> Binding | None:
        """648d60f2 4.3 凭据: the account from the start-time designation or the entry's only account, the carried
        header by name. Raises CredentialRefused."""
        r = p.request
        return credential_for(entry, key, r.scheme, r.headers, self.credentials.records,
                              p.ex.accounts.get(exact_key(r.host, r.port)))

    def _deny(self, row: RowState, p: Pending, reason: int, basis: str, **detail: Any) -> None:
        """The request ends refused. Leaves the row's path free; the caller advances the row. A file request's reason is
        a FileReason or one of the core's DENY_* codes; it goes out and is recorded as its H-18 word (fo.wire_reason)."""
        p.port.send_deny(p.request.seq, reason)
        self._denied(row, p, reason, basis, **detail)

    def _denied(self, row: RowState, p: Pending, reason: int, basis: str, **detail: Any) -> None:
        """_deny without the frame: for a refusal whose FILE_DENY the port sends itself (file_allow_due)."""
        p.state = State.DONE
        p.release_fd()
        if row.current is p:
            row.current = None
        if p.is_file:
            reason = fo.wire_reason(reason)
            detail = {'deny_word': FILE_REASONS[reason - 1], **detail}
        record_lifecycle(self.recorder, 'request_decided', p.ex, 'deny', basis, seq=p.request.seq, admission=p.admission,
                         deny_reason=int(reason), **detail)

    # ---- asking the user (648d60f2 3.2; K-12, K-13, K-16, K-28, K-45) ----
    def _ask(self, row: RowState, p: Pending, v: Verdict) -> None:
        """No timer here: the connector's total limit covers the wait and withdraws the request (C-15)."""
        p.state = State.ASKING
        p.question_id = self.next_question_id
        self.next_question_id += 1
        p.verdict = v
        self.questions[p.question_id] = p
        record_lifecycle(self.recorder, 'question_asked', p.ex, question_id=p.question_id, seq=p.request.seq,
                         matched_key_kind=KEY_KIND_FILE if v.obj else int(v.entry.key_kind) if v.entry else 0,
                         matched_key=v.key)
        if self.admin is None:
            return
        if v.obj is not None:                    # H-09: the object instead of a match, cell and binding; no memfd
            self.admin.question(p.question_id, p.ex, row.workspace_id, None, p.request, -1, None, None, obj=v.obj)
        else:
            self.admin.question(p.question_id, p.ex, row.workspace_id, p.match, p.request, p.memfd, v.binding, v.entry)

    def _cancel_question(self, p: Pending, reason: int) -> None:
        if p.question_id is not None:
            self.questions.pop(p.question_id, None)
            if self.admin is not None:
                self.admin.withdrawn(p.question_id, reason)

    def answer(self, question_id: int, verdict: int) -> tuple[str | None, bytes]:
        """From the management port (SPEC 3.4 ANSWER): (error name, None when accepted; the reply's note). The second
        checkpoint redoes the first against the table and the records as they are now: the cell shown changed in any way
        (even back to what it was), another cell now covers the request, or the binding differs, and the answer is void
        and the request refused (K-45). An allow goes on to the PDP with the user's answer in the request."""
        p = self.questions.get(question_id)
        if p is None or p.state is not State.ASKING:
            return 'unknown_question', b''
        row = self.rows.get(p.ex.execution_id)
        if row is None or row.current is not p:
            return 'unknown_question', b''
        if verdict not in (VERDICT_ALLOW_ONCE, VERDICT_ALLOW_CELL, VERDICT_DENY_ONCE, VERDICT_DENY_CELL):
            return 'unknown_verdict', b''
        r, shown = p.request, p.verdict
        now = self.check(row, p)
        self._cancel_question(p, 0)              # answered or void: no QUESTION_WITHDRAWN
        if shown is None or not shown.same_result(now):
            record_lifecycle(self.recorder, 'question_answered', p.ex, question_id=question_id, seq=r.seq, verdict=verdict,
                             recorded=False, superseded=True)
            self._deny(row, p, DENY_POLICY_CHANGED, 'answer_void')
            self._advance(row)
            return 'superseded', b''            # the client learns its answer did not take
        note = b''
        p.answer = verdict
        if verdict in (VERDICT_ALLOW_CELL, VERDICT_DENY_CELL):
            note = self._answer_cell(row, p, now, verdict)
        record_lifecycle(self.recorder, 'question_answered', p.ex, question_id=question_id, seq=r.seq, verdict=verdict,
                         recorded=note == b'persisted')
        if verdict in (VERDICT_ALLOW_ONCE, VERDICT_ALLOW_CELL):
            # the persistent answer was written first; the baseline is the table after it (648d60f2 3.2, 4.3)
            after = self.check(row, p) if verdict == VERDICT_ALLOW_CELL else now
            self._to_pdp(row, p, after if after.refusal is None else now,
                         'user_allow_cell' if verdict == VERDICT_ALLOW_CELL else 'user_allow_once')
        else:
            self._deny(row, p, DENY_USER, 'user_deny_cell' if verdict == VERDICT_DENY_CELL else 'user_deny')
            self._advance(row)
        return None, note

    def _answer_cell(self, row: RowState, p: Pending, v: Verdict, verdict: int) -> bytes:
        """A persistent answer changes the whole cell it was asked on, only its approval mode (allow, never ask again)
        or its state (deny from now on, accounts and named addresses cleared: a deny names none, K-57); its key, methods
        and paths stay. Written before the request goes on (648d60f2 3.2: 持久答复先写表). "Never ask again" that does
        not take effect is this-time allow. The note:
        persisted; unpersisted, in effect for this run but not safely on disk (K-18: a tightening, or a write that failed
        only at the directory fsync); not_applied, no effect (a relaxing write that failed before the rename). A file
        request's answer changes only its object's approval mode or state; the object keeps its anchor (H-09)."""
        if v.obj is not None:
            state, approval = ((EntryState.ALLOW, Approval.NEVER) if verdict == VERDICT_ALLOW_CELL
                               else (EntryState.DENY, Approval.NEVER))
            try:
                result = self.workspaces.set_object_mode(row.workspace_id, v.obj.alias, state, approval)
            except Exception:                    # the table or the object went away under the question
                return b'not_applied'
            return b'persisted' if result.persisted else b'unpersisted' if result.applied else b'not_applied'
        old = v.entry
        assert old is not None
        new = (replace(old, approval=Approval.NEVER) if verdict == VERDICT_ALLOW_CELL
               else replace(old, state=EntryState.DENY, accounts=frozenset(), addresses=()))
        try:
            result = self.workspaces.put(row.workspace_id, new)
        except Exception:                        # WorkspaceUnavailable: the table went away under the question
            return b'not_applied'
        if result.applied:
            self.table_changed(row.workspace_id, old, new, persisted=result.persisted)
        return b'persisted' if result.persisted else b'unpersisted' if result.applied else b'not_applied'

    # ---- the PDP (648d60f2 4.2, 4.3 hook; K-47, K-49, K-50) ----
    def _to_pdp(self, row: RowState, p: Pending, v: Verdict, basis: str) -> None:
        """Every request the engine let through is asked of the PDP; without a PDP it waits, until the connector's
        total limit withdraws it (K-47). The request carries what the engine will execute and how it judged it."""
        p.state, p.baseline, p.basis, p.versions = State.PDP, v, basis, self.versions(row)
        try:
            record_lifecycle(self.recorder, 'pdp_requested', p.ex, admission=p.admission,
                             **self._decision_detail(p, v), **p.request.summary())
        except RecordTooLarge:
            self._deny(row, p, DENY_UNAVAILABLE, 'record_too_large')
            self._advance(row)
            return
        self.pdp_waiting[p.admission] = p
        link = getattr(self.pdp, 'link', None)
        if link is not None:
            self._send_pdp(p, link)

    def _decision_detail(self, p: Pending, v: Verdict) -> dict[str, Any]:
        """The record's part that is not the request (K-50): the key of the cell, never its content; the binding; the
        user's answer. A file request: the object's alias and type, never its anchor (H-20)."""
        if v.obj is not None:
            return {'key_kind': KEY_KIND_FILE, 'key': v.obj.alias, 'object_type': fo.TYPE_NAMES[v.obj.type],
                    'answer': p.answer}
        b = v.binding
        return {'key_kind': int(v.entry.key_kind) if v.entry else 0, 'key': v.key,
                'credential': 'placed' if b is not None else 'none',
                'account': b.account if b else None, 'placement': b.placement.value if b else None,
                'account_destination': bool(v.entry.accounts) if v.entry else False, 'answer': p.answer}

    def _send_pdp(self, p: Pending, link: Any) -> None:
        """SPEC §3.6 PDP_REQUEST: the policy context stays the 22nd field; the six file fields follow it (H-09). A file
        request has empty HTTP fields, its object's mode as the cell, and no memfd."""
        r, v = p.request, p.baseline
        head = [self.recorder.epoch.encode('ascii'), u64(p.admission), p.ex.execution_id.encode(),
                p.ex.plan.workspace_id.encode(), u32(r.sender_uid)]
        if v is not None and v.obj is not None:
            fields = head + fo.BLANK_HTTP + [u8(KEY_KIND_FILE), v.obj.alias.encode('ascii'), fo.object_cell(v.obj),
                                             pack_list([]), u8(p.answer), p.ex.policy_context] + \
                fo.request_fields(r, v.obj)
        else:
            assert v is not None and v.entry is not None
            b = v.binding
            fields = head + [r.method, r.scheme, r.host, u16(r.port), r.path, r.query or b'',
                             pack_list([x for pair in r.headers for x in pair]), pack_list(list(r.stripped)),
                             r.body_kind.encode(), pack_list([k.encode('latin-1') for k in r.form_keys]),
                             u64(r.body_len), u8(int(v.entry.key_kind)), v.key.encode(),
                             pack_list(entry_fields(v.entry)),
                             pack_list([] if b is None else [b.host_port.encode(), b.account.encode(),
                                                             u8(b.placement.value)]),
                             u8(p.answer), p.ex.policy_context] + fo.NETWORK_FIELDS   # K-56: the row's own context
        if getattr(link, 'dead', False):         # dropped while a PDP that just connected was being sent the waiting ones:
            return                               # the request stays unsent and goes to the next PDP (K-49)
        p.link = link
        self.pdp.send_request(link, fields, p.memfd if p.memfd >= 0 else None)

    def pdp_connected(self, link: Any) -> None:
        """A PDP that connects is asked about every request waiting for one, in admission order."""
        for p in sorted(self.pdp_waiting.values(), key=lambda x: x.admission):
            if p.link is None:
                self._send_pdp(p, link)

    def pdp_lost(self, link: Any) -> None:
        """The PDP went: its unanswered requests are refused; the new one starts from the requests after (K-49)."""
        for p in sorted(self.pdp_waiting.values(), key=lambda x: x.admission):
            if p.link is link:
                self.pdp_waiting.pop(p.admission, None)
                row = self.rows.get(p.ex.execution_id)
                if row is not None:
                    self._deny(row, p, DENY_UNAVAILABLE, 'pdp_disconnected')
                    self._advance(row)

    def pdp_answer(self, link: Any, epoch: str, admission: int, allow: bool) -> None:
        """K-49: an answer counts once, only for an id of this engine run issued on this connection, unanswered, whose
        request still waits; anything else is dropped and noted."""
        p = self.pdp_waiting.get(admission)
        if epoch != self.recorder.epoch or p is None or p.link is not link:
            self.trace('pdp_answer_ignored', admission=admission, known=p is not None)
            return
        del self.pdp_waiting[admission]
        row = self.rows.get(p.ex.execution_id)
        record_lifecycle(self.recorder, 'pdp_answered', p.ex, seq=p.request.seq, admission=admission, allow=allow)
        if row is None:
            return
        if not allow:
            self._deny(row, p, DENY_PDP, 'pdp_denied')
            self._advance(row)
            return
        if p.is_file and not self._open_file(row, p):
            self._advance(row)
            return
        self._durable(row, p)

    def _open_file(self, row: RowState, p: Pending) -> bool:
        """H-07, H-08, H-10: after the PDP's allow and before the allow record, the first checkpoint once more (the
        object as it is now must be the one the baseline judged), then the open beneath its anchor. The descriptor is
        the request's from here; a refusal here writes only a deny record."""
        base = p.baseline
        assert base is not None and base.obj is not None
        now = self.check(row, p)
        table = self.workspaces.tables.get(row.workspace_id)
        anchor = table.anchors.get(base.obj.alias) if table is not None else None
        if not now.same_decision(base) or anchor is None:
            self._deny(row, p, DENY_POLICY_CHANGED, 'recheck_failed', stage='open')
            return False
        if self.opener is None:
            self._deny(row, p, DENY_UNAVAILABLE, 'no_opener')
            return False
        try:
            p.target_fd, st = fo.open_target(self.opener, anchor, now.obj, p.request)
        except fo.FileRefused as e:
            self._deny(row, p, e.reason, 'open_failed', errno=e.detail)
            return False
        r = p.request
        p.record_extra = ((('actual_length', fo.actual_length(st.st_size, r.start, r.length)),) if r.op == FILE_OP_READ
                          else (('start', r.start),))
        return True

    # ---- durable before release, the third checkpoint (648d60f2 4.3; K-11, K-46, K-52, K-53) ----
    def _durable(self, row: RowState, p: Pending) -> None:
        """The allow record is the release intent: written now, before the third checkpoint; a request it does not
        end up releasing gets a later record of the same admission number."""
        v = p.baseline
        assert v is not None
        try:
            seq = record_lifecycle(self.recorder, 'request_decided', p.ex, 'allow', p.basis, seq=p.request.seq,
                                   admission=p.admission, **self._decision_detail(p, v), **dict(p.record_extra))
        except RecordTooLarge:
            seq = None
        if seq is None:                          # the record path failed (latched) or the record was too large
            self._deny(row, p, DENY_UNAVAILABLE, 'record_fault')
            self._advance(row)
            return
        p.state, p.record_seq = State.DURABLE, seq
        self.durable[p.admission] = p
        self.try_release()

    def on_wake(self) -> None:
        """The record writer moved its receipt or latched (K-53): drain the wake pipe, then read the receipt."""
        self.recorder.drain_wake()
        self.try_release()

    def try_release(self) -> None:
        """K-52: release a waiting request only if the latch is open and the receipt covers its record, both read in
        one lock before each release (one fsync may cover several); a latch closed before that read refuses every
        request still waiting, one closed after it takes effect from the next release (648d60f2 4.3)."""
        for p in sorted(self.durable.values(), key=lambda x: x.record_seq):
            failed, receipt = self.recorder.status()
            if failed is None and p.record_seq > receipt:
                break
            del self.durable[p.admission]
            row = self.rows.get(p.ex.execution_id)
            if row is None:
                continue
            if failed is not None:
                self._deny(row, p, DENY_UNAVAILABLE, 'record_fault')
            else:
                self._third_checkpoint(row, p)
            self._advance(row)

    def _third_checkpoint(self, row: RowState, p: Pending) -> None:
        """Version numbers unchanged: the baseline stands. Moved: the first checkpoint again, without asking; the
        user's answer stands in for asking only, never for the cell or the binding (648d60f2 4.3)."""
        base = p.baseline
        assert base is not None
        if self.versions(row) == p.versions:
            self._release(row, p, base)
            return
        now = self.check(row, p)
        if not now.same_decision(base):
            self._deny(row, p, DENY_POLICY_CHANGED, 'recheck_failed')
            return
        self._release(row, p, now)

    def _release(self, row: RowState, p: Pending, v: Verdict) -> None:
        """The ALLOW frame: the truth is read in this round, from the record the binding names (K-10). A file
        request's FILE_ALLOW carries its opened target; the port sends (or queues) its own copy and the core closes
        this one. The request leaves the row's path and waits, by its seq, among the row's deliveries until the port
        says the descriptor has gone (file_allow_sent), which is mostly at once; a queued copy is the only target
        descriptor the core holds after this (H-08). There is no completion report: the request is done once its
        descriptor is out."""
        if p.is_file:
            fd, p.target_fd = p.target_fd, -1
            p.state = State.DELIVERING
            row.delivering[p.request.seq] = p
            if row.current is p:
                row.current = None
            try:
                p.port.send_allow(p.request.seq, p.request.op, fd)
            finally:
                os.close(fd)
            return
        r, entry, use = p.request, v.entry, v.binding
        assert entry is not None
        # K-59: the named addresses of the cell that passed in this round, as stored; nothing of the request
        if use is None:
            p.port.send_allow_nocred(r.seq, bool(entry.accounts), entry.addresses)
        else:
            record = self.credentials.records.get((use.host_port, use.account))
            try:
                if record is None:
                    raise EntryInvalid('no such credential record')
                truth_a, truth_b = self.credentials.read_truths(use.host_port, use.account)
            except (EntryInvalid, OSError):
                self._deny(row, p, DENY_CREDENTIAL, 'credential_unreadable')
                return
            p.port.send_allow(r.seq, record.placement.value, record.word, truth_a, truth_b, use.account, entry.addresses)
        p.state = State.SENT
        row.inflight[r.seq] = p
        if row.current is p:
            row.current = None

    # ---- a FILE_ALLOW in the port's queue (H-07, H-08, H-19) ----
    def file_allow_due(self, ex: Any, port: Any, seq: int) -> int | None:
        """The port asks right before a FILE_ALLOW's descriptor would go. None: it goes. A refusal reason: the port
        closes its copy and sends FILE_DENY with that reason instead; the request is refused and recorded here. The
        authority is checked as at the third checkpoint: the version numbers unmoved, it stands; moved, the first
        checkpoint again and the same comparison with the baseline. A seq with nothing waiting never has its
        descriptor go."""
        row = self.rows.get(ex.execution_id)
        p = row.delivering.get(seq) if row is not None and row.file_port is port else None
        if p is None:
            return DENY_UNAVAILABLE
        assert p.baseline is not None
        if self.versions(row) == p.versions or self.check(row, p).same_decision(p.baseline):
            return None
        del row.delivering[seq]
        self._denied(row, p, DENY_POLICY_CHANGED, 'recheck_failed', stage=State.DELIVERING.value)
        return DENY_POLICY_CHANGED

    def file_allow_sent(self, ex: Any, port: Any, seq: int) -> None:
        """The port sent the FILE_ALLOW's first bytes with its descriptor: the request is done."""
        row = self.rows.get(ex.execution_id)
        p = row.delivering.pop(seq, None) if row is not None and row.file_port is port else None
        if p is not None:
            p.state = State.DONE

    # ---- withdraw / report (K-16, K-36, K-38) ----
    def withdraw(self, ex: Any, seq: int, port: Any = None) -> None:
        """K-16: a withdrawal takes the request out at any stage; answers and receipts that arrive later release
        nothing. A withdrawn request whose allow record was written gets its own record after it (K-46). The two ports
        of a row number their requests apart, each from 1: a withdrawal matches its own port's request only (H-06);
        ``port`` None is the judgment port. A withdrawn file request's opened target is closed (H-07), and so is the
        port's copy of a FILE_ALLOW still waiting in its queue (H-08)."""
        row = self.rows.get(ex.execution_id)
        if row is None:
            return
        port = row.port if port is None else port
        for p in list(row.queue):
            if p.request.seq == seq and p.port is port:
                row.queue.remove(p)
                p.state = State.DONE
                p.release_fd()
                record_lifecycle(self.recorder, 'request_withdrawn', ex, seq=seq, admission=p.admission, stage='queued')
                return
        p = row.current
        if p is not None and p.request.seq == seq and p.port is port:
            stage = p.state.value
            self._leave_stage(p, WITHDRAWN_BY_CONNECTOR)
            row.current = None
            p.state = State.DONE
            p.release_fd()
            record_lifecycle(self.recorder, 'request_withdrawn', ex, seq=seq, admission=p.admission, stage=stage)
            self._advance(row)
            return
        p = row.delivering.pop(seq, None) if port is row.file_port else None
        if p is not None:
            port.cancel_allow(seq)
            p.state = State.DONE
            record_lifecycle(self.recorder, 'request_withdrawn', ex, seq=seq, admission=p.admission,
                             stage=State.DELIVERING.value)
            return
        p = row.inflight.pop(seq, None) if port is row.port else None      # only network requests wait for REPORT
        if p is not None:
            p.state = State.DONE
            p.release_fd()
            record_lifecycle(self.recorder, 'request_withdrawn', ex, seq=seq, admission=p.admission, stage='sent')
            return
        # K-36: dropped and recorded, no subject; the port admits only increasing numbers, so a known one is at most the
        # last; both ports count from 1, so the note says which port it came from (H-06)
        self.recorder.diagnostic('withdraw_ignored', execution_id=ex.execution_id, seq=seq, known=seq <= port.last_seq,
                                 port='file' if port is row.file_port else 'judgment')

    def report(self, ex: Any, seq: int, result: int, status: int) -> None:
        """The connector's completion report is the core's bookkeeping (frees the request's sequence number and its
        fd's one-request place, K-38); it is not recorded (648d60f2 4.1, 4.3; K-23, C-27). A late or unknown one is
        noted without its result (K-22, K-36)."""
        row = self.rows.get(ex.execution_id)
        p = row.inflight.pop(seq, None) if row is not None else None
        if p is None:
            self.recorder.diagnostic('report_ignored', execution_id=ex.execution_id, seq=seq)
            return
        p.state = State.DONE
        p.release_fd()
        if self.measure_completion:
            self.recorder.diagnostic('request_completed', execution_id=ex.execution_id, seq=seq, result=result,
                                     status=status, measurement_only=True)

    # ---- credential records replaced or deleted (648d60f2 4.3; K-31) ----
    def credential_changed(self, host_port: str, account: str) -> None:
        """The record's account loses its connections everywhere: the credential store is shared by every row. A port whose
        write fails closes its row from inside this loop (the lifecycle's fault handler), so the loop runs over a copy and
        passes over rows already closed."""
        for row in list(self.rows.values()):
            if self.rows.get(row.ex.execution_id) is not row:
                continue
            row.port.send_revoke(int(KeyKind.EXACT), host_port.encode('ascii'), account.encode('utf-8'))
            record_lifecycle(self.recorder, 'entry_revoked', row.ex, key_kind=int(KeyKind.EXACT), key=host_port,
                             account=account, persisted=True)

    # ---- table changes from the management port or an answer (K-14 immediate, K-31 revocation) ----
    def table_changed(self, workspace_id: str, old: Entry | None, new: Entry | None, persisted: bool = True) -> None:
        """K-31: deletion, narrowing below an account, or a recorded deny sends REVOKE(key, account) to the connector of
        every live row on that workspace, for each account that lost its standing; an allow that loses a named address
        sends REVOKE scope 2 for its key."""
        key_entry = new or old
        if key_entry is None:
            return
        # Which connections lose their standing under this key (工程项 11; review B, B8, NB2): a deny that appears or
        # replaces an allow, or an allow that is deleted, cuts every connection under the key, whatever its account and
        # the credential-less ones too (scope 2); so does an allow that loses any named address (user 2026-11-05), and
        # that one frame covers the accounts it may lose in the same change; an allow that only loses accounts cuts
        # those accounts' connections.
        everyone = ((new is not None and new.state is EntryState.DENY)
                    or (new is None and old is not None and old.state is EntryState.ALLOW)
                    or (old is not None and new is not None and old.state is EntryState.ALLOW
                        and not set(old.addresses) <= set(new.addresses)))
        lost = [] if everyone or old is None or old.state is not EntryState.ALLOW or new is None else \
            sorted(set(old.accounts) - set(new.accounts))
        if not everyone and not lost:
            return
        for row in list(self.rows.values()):                 # a copy: a failing port closes its row meanwhile
            if row.workspace_id != workspace_id:
                continue
            for account in (['*'] if everyone else lost):
                if self.rows.get(row.ex.execution_id) is not row:
                    break
                row.port.send_revoke(int(key_entry.key_kind), key_entry.key.encode('ascii'),
                                     b'' if everyone else account.encode('utf-8'), everyone)
                record_lifecycle(self.recorder, 'entry_revoked', row.ex, key_kind=int(key_entry.key_kind), key=key_entry.key,
                                 account=account, persisted=persisted)
