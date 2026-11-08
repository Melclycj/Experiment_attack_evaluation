"""Lifecycle objects of conn E-01 (对象、字段和所有权) and rr E-08 (WorkspaceRecord, RuntimeCopyView).

Objects are identified by reference. Numeric uid / fd values are attributes only; nothing in the
engine looks an object up by them. Reservation fields are write-once (conn E-01 身份补充).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import socket
from types import MappingProxyType
from typing import Any, ClassVar, Mapping


class WriteOnce:
    """Rejects a second assignment to any field named in ``_write_once`` once it holds a value."""

    _write_once: ClassVar[frozenset[str]] = frozenset()

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._write_once and getattr(self, name, None) is not None:
            raise AttributeError(f'{type(self).__name__}.{name} is write-once')
        object.__setattr__(self, name, value)


class ExecState(Enum):
    RESERVED = 'RESERVED'
    PREPARING = 'PREPARING'
    STARTING = 'STARTING'
    ACTIVE = 'ACTIVE'
    DRAINING = 'DRAINING'
    CLOSED = 'CLOSED'


class Submission(Enum):
    LOCAL = 'local'
    SUBMITTED = 'submitted'
    UNCERTAIN = 'uncertain'


class LeaseState(Enum):
    HELD = 'held'
    QUARANTINED = 'quarantined'
    FREE = 'free'


class ViewState(Enum):
    PENDING = 'pending'
    RETAINED = 'retained'
    RELEASED = 'released'


class Phase(Enum):
    BOOTSTRAP_HANDOFF = 'bootstrap-handoff'
    DATA = 'data'
    CLOSED = 'closed'


class WorkspaceState(Enum):
    AVAILABLE = 'available'
    LEASED = 'leased'
    DRAINING = 'draining'
    QUARANTINED = 'quarantined'


class StopState(Enum):
    NONE = 'none'
    PENDING = 'pending'
    SENT = 'sent'


@dataclass(frozen=True)
class Plan:
    """A launch plan from the trusted catalog (si E-10); the engine keeps only what it checks."""

    launch_plan_id: str
    launch_plan_digest: str
    workspace_id: str
    policy_digest: str
    isolation_profile_digest: str
    # Declared tool definitions (rr E-07 工具调用), reached only through this object. Empty in this build: the
    # reused spawner's catalog parser has no tool_definitions_ref field (user ruling 2026-10-19).
    tools: tuple[Any, ...] = ()
    # agent-rm-model 3.1 传送 execution: 'push' or 'export' for a plan whose runtime is a reserved transfer runtime,
    # '' otherwise. A transfer row hangs no entries and carries no account; only the hold's holder starts it (S-24, K-55).
    transfer: str = ''


@dataclass(eq=False)
class UidLease(WriteOnce):
    _write_once: ClassVar[frozenset[str]] = frozenset({'lease_id', 'execution_id', 'uid', 'gid'})

    lease_id: str
    execution_id: str
    uid: int
    gid: int
    state: LeaseState = LeaseState.HELD


@dataclass(frozen=True, eq=False)
class WorkspaceLease:
    """One lease per acquire; carries workspace, execution and a generation that never rolls back."""

    workspace: WorkspaceRecord
    execution_id: str
    generation: int


@dataclass(eq=False)
class WorkspaceRecord:
    workspace_id: str
    layout_id: str
    source_ref: str
    workspace_uid: int
    workspace_gid: int
    state: WorkspaceState = WorkspaceState.AVAILABLE
    lease_generation: int = 0
    active_lease: WorkspaceLease | None = None
    io_refs: set[object] = field(default_factory=set)
    last_execution: Execution | None = None


@dataclass(eq=False)
class RuntimeCopyView:
    copy_id: str
    state: ViewState = ViewState.PENDING
    last_status: dict[str, Any] | None = None


@dataclass(eq=False)
class Channel(WriteOnce):
    """Channel object; the executor installs it once and retires it at close step 2. Its FrameReader and
    writer are created with it, touched only through it, and discarded at close step 2 (conn E-02)."""

    _write_once: ClassVar[frozenset[str]] = frozenset({'channel_id', 'owned_fd', 'receiver_generation'})

    channel_id: str
    owned_fd: socket.socket
    receiver_generation: int
    session: Session | None
    phase: Phase = Phase.BOOTSTRAP_HANDOFF
    commit_offset: int = 0
    frame_reader: Any = None
    frame_writer: Any = None
    frame_timer: Any = None      # armed while a frame is partly received (conn E-02 step 7)
    stall_timer: Any = None      # armed from the first blocked send until a whole frame goes out (conn E-03)
    partial_timer: Any = None    # armed from a frame's first sent byte until its last (conn E-03)


@dataclass(eq=False)
class Session(WriteOnce):
    _write_once: ClassVar[frozenset[str]] = frozenset(
        {'session_id', 'execution_id', 'expected_uid', 'local_agent_id', 'channel_id', 'execution_ref'})

    session_id: str
    execution_id: str
    expected_uid: int
    local_agent_id: str
    channel_id: str | None = None
    admission: str = 'OPEN'
    execution_ref: Execution | None = None   # set once at reservation; admission reaches everything from here
    task_bindings: list[Any] = field(default_factory=list)
    grants: list[Any] = field(default_factory=list)
    current_task_call: Any = None
    last_call: Any = None        # one resolved call whose result the trusted caller has not taken yet
    # Active ids per direction (conn E-02): agent requests and engine task_starts, each strictly increasing.
    agent_high_water: int = 0
    engine_next_id: int = 1
    engine_sent_high_water: int = 0   # highest task_start id whose whole frame was sent
    local_seq: int = 0                # engine-assigned task and grant ids of this session, never reused
    # The original session's in-flight table of agent requests, by their never-reused id; live entries only.
    requests: dict[str, Any] = field(default_factory=dict)


@dataclass(eq=False)
class Execution(WriteOnce):
    _write_once: ClassVar[frozenset[str]] = frozenset(
        {'execution_id', 'local_agent_id', 'lease_id', 'launch_plan_id', 'launch_plan_digest',
         'startup_deadline_ns', 'lease', 'session', 'plan', 'workspace_lease', 'runtime_copy_view', 'accounts',
         'policy_context'})

    execution_id: str
    local_agent_id: str
    lease_id: str
    launch_plan_id: str
    launch_plan_digest: str
    lease: UidLease
    session: Session
    plan: Plan
    workspace_lease: WorkspaceLease
    runtime_copy_view: RuntimeCopyView
    state: ExecState = ExecState.RESERVED
    startup_deadline_ns: int | None = None
    spawn_submission: Submission = Submission.LOCAL
    membership_empty: bool = False
    empty_basis: str | None = None
    # Engine-internal bookkeeping of the close and reclaim gates (conn E-04).
    channel: Channel | None = None
    channel_retired: bool = False
    close_reason: str | None = None
    stop: StopState = StopState.NONE
    prepared_consumed: bool = False
    spawn_failures: list[dict[str, Any]] = field(default_factory=list)
    empty_fact: dict[str, Any] | None = None
    lease_released: bool = False
    workspace_released: bool = False
    slot_released: bool = False
    timers: list[Any] = field(default_factory=list)
    # v2 (build plan items 7, 13): the judgment-port end for this row's connector, and the connector's exit
    judgment: Any = None
    connector_pid: int | None = None
    connector_exited: bool = False
    connector_exit: dict[str, Any] | None = None
    # the row's file worker (validation.md H-06, H-17): its file judgment-port end until the port is built, its exit
    file_judgment: Any = None
    worker_pid: int | None = None
    worker_exited: bool = False
    worker_exit: dict[str, Any] | None = None
    # agent-rm-model 3.1 每个目的地一个账户: host:port -> the one account the user chose when starting this execution
    accounts: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    # agent-rm-model 3.1 策略上下文: opaque bytes the user attached at start, carried unchanged in every request to the
    # PDP of this row and nowhere else; empty when none was given (validation.md K-56)
    policy_context: bytes = field(default_factory=bytes)
