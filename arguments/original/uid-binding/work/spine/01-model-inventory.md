---
title: Step 1 — Model inventory of the local uid binding (state, transitions, inputs, entry check)
date: 2026-10-13
step: 1 of the spine (COV-1)
owner: main session
status: version 11, 2026-10-20, models the fifth design revision of 2026-10-19 (the old cell's domain-empty fact is kernel-held); not yet registered in VERSIONS.md (version 10 `d27d65d7874bbf6c` modeled the third freeze, registered 2026-10-18; version 9 `1461a0f9feb23817` modeled the second freeze of 2026-10-18; version 8 `9efb243354a4e9d6` modeled the 2026-10-12 freeze)
frozen_revision: 2026-10-18, third freeze — the ten files of PLAN.md §Frozen design revision after the fourth design revision of 2026-10-18 (design-revision-2026-10-18.md § Fourth revision), which rewrote four of them in place at unchanged line counts — conn `0c16e567a34aa441`, rr `1a8ea18374b07431` (both since rewritten by the fifth design revision of 2026-10-19, design-revision-2026-10-18.md § Fifth revision and its same-day amendment "cgroup only", which changed no line count: cites into them below are on conn `14625aa4a886a639` and rr `8b0b24552f4a32c2`), si `c8aff1a37d73561b`, optb `e84d0b4255cfa022` — and left six unchanged by that revision — sbx `90766bd3602a1de9`, iv `de1e36678014470c`, mech `3a205e6e10e31fdd`, kub `4a7384b7727abe37` (its evidence-only passage on the writers of a task's uid, added 2026-10-18 after its L632, moves no cite of this file: every kub cite below is a section or a line before it), scope `029a51193e92d38f`, tm `c8e60929f74a3429`; line numbers below refer to these blobs
reading_rule: this file names no defence. Refusal, rejection and close transitions appear as outcomes only. Whether any outcome cuts a route is Step 2's and the group files' question.
vocabulary_note: "CLOSED" is the design's state name and "closed" its fd / row action (conn L366, L851); "Complete" is the handle event (conn L698). Neither is used as a coverage word anywhere in this file.
---

# 01 — Model inventory

**Version 11 models the fifth design revision of 2026-10-19.** It rewrote one paragraph of conn (old L931 → L931–937, later lines 6 lower) and two passages of rr (old L763 → L763–764, old L887–888 → L888–890; later lines 1 and 2 lower); every cite into conn and rr below is on the new blobs (line maps computed with `difflib`), cites into the other eight files are unchanged. The revision states the supervisor's domain-empty method as a kernel-held fact; its same-day amendment keeps only the cgroup form (the cell's own cgroup reporting `populated 0`) and excludes a pid-namespace reap. MM-10 moves from open to stated by design text, AA-04 narrows what is assumed of the supervisor, and T-49, the supervisor actor line, X-08 and X-11 read the new text.
**Version 10 models the third freeze.** The fourth design revision of 2026-10-18 removed `grant_ref` from every agent-facing message and rewrote conn, rr, si and optb in place at unchanged line counts, so every cite below stays valid; MM-06 is resolved by the design text and T-24, T-30, T-33 and A-02 read the revised text.
**Version 9 modeled the second freeze of 2026-10-18.** The three design revisions of 2026-10-18 changed conn, rr, si and
optb; every cite into those four files below is on their current blobs (frozen → current line maps computed
with `difflib`), cites into the other six are unchanged. Native tool calling (first revision) touches no
modeled element; the absorbed engine requirements (second) and the review findings (third) change the rows
recorded with the version-9 row of VERSIONS.md at registration. "Frozen text" below means this freeze.

Scope: the attribution-relevant state and transitions of the frozen design, from launch to uid reuse, as the
ten frozen files state them. IDs are append-only: transitions `T-nn`, attacker inputs `A-nn`, kernel /
spawner events `K-nn`, abstraction assumptions `AA-nn`, missing mappings `MM-nn`, attribution-irrelevant
exclusions `X-nn`. Family letters (L / R / Q / C / K) are reading aids only; the group cut is Step 2's.

Source abbreviations (all ten are the frozen files; the engine-design three live under
`ExperimentLab/lab/experiments/w2/implementation/engine-design/`, the design five under
`Thesis/Work/Design/sandbox-mediated-agent-execution/`): `conn` = `connections.md`; `rr` =
`resources-routing.md`; `si` = `supporting-interfaces.md`; `sbx` =
`ExperimentLab/lab/experiments/w2/implementation/sandbox-design.md`; `iv` =
`ExperimentLab/lab/experiments/w2/implementation-validation.md`; `mech` = `mechanism.md`; `optb` =
`option-b-workload-per-engine.md`; `kub` = `kernel/kernel-uid-binding.md`; `scope` = `scope-and-boundary.md`;
`tm` = `threat-model-derivation-map.md`.

## 0 The two definitions, fixed in writing

**D-GT — the ground-truth send origins of a fragment.** A fragment is the byte run returned by
one `recvmsg` on the engine end (conn L453–455); it need not correspond to one send syscall or one
task. For each contributing byte occurrence retain its actual sending task and send instant as ghost
history. A recvmsg may merge origin segments with equal credentials, including threads with one tgid
(conn L436–442; kub §2.4); the model does not infer a unique task from a diagnostic pid.
The execution of each origin is the unique spawner-created pid namespace `P_X` containing its task
at send time, including membership through descendant pid namespaces (optb step 0; conn L297,
L317–318). An unrelated host task is outside. Ground truth is never derived from a uid or session
lookup. A frame's ground truth is the set of executions of all contributing send origins, including
header bytes. Same-execution siblings/threads are one principal (W2.1); unrelated tasks with an equal
numeric uid are not defined to be the same execution.

**D-ACC — the accepted-attribution event and the label.** The event is the return of `receive_step` with a
`ValidatedMessage` and a constructed `VerifiedContext` (conn L565–575): the moment the engine reads the
session row referenced by the `Channel` object the fragment arrived on and fixes
`label = (execution_id, local_agent_id, session_id, channel_id, receiver_generation, expected_uid)` from that row (conn
L572–573; `local_agent_id` is the logical agent name the row carries, a field that may recur across
executions — added in version 7, addendum F-06, see MM-16). The label is read from engine objects, never from the message (conn L522, L572). Every later
consumer — admission (T-30), authorization and dispatch (T-33), the E-09 `verified_subject` (si L93) —
carries this label by object reference; the design states this for every consumer step, which neither
constructs the context nor looks it up or keys state by name, uid, fd or `local_agent_id` (conn L581–583).

**The property** (PLAN Context (1)): at every D-ACC, the label's execution equals the ground-truth
execution of every contributing send origin of the frame. The uid-equality part concerns the credential
at each send, not the task's current uid at receive. The class-membership part must preserve the
allocation generation between that send history and the accepted label; it must not require a sender
still alive at accept or infer a previous sender from a uid's current holder. Step 2 derives that relation.
This wording departs from the sentence in PLAN Context (1) that the row's uid is "held by exactly that
execution when the engine accepts": under live-at-send a sender may have exited before accept while its
bytes are still queued (K-06), so a condition evaluated at accept time would be vacuous or false for a
correctly attributed frame. The departure entered in version 4 and was accepted by the Step 1 owner on
2026-10-13 (change-requests.md, CR-OWN-01); PLAN Context (1) keeps the user-ruled definitions and gains a
pointer here at its next edit.
Only uid enters this attribution check; pid is diagnostic (conn L573). Kernel uids are rendered in the
engine's user namespace (kub §2.5).

## 1 Objects and state variables

| object / owner (single writer) | state carried | source |
|---|---|---|
| `UidLease` / engine allocator | `lease_id, execution_id, uid, gid, state ∈ {held, quarantined, free}`; uid from the deployer's exclusive pool, bound to the workspace's static `workspace_uid`; excludes 0, overflowuid, invalid, host identities | conn L78; rr L577–588 |
| `Execution` / engine lifecycle manager | `execution_id = engine_epoch:allocation_seq` (never reused), `local_agent_id` (a logical name from the launch request; it may recur across executions, and a new execution under a recurring name inherits no grant or permission — conn L79, L382), `lease_id`, `launch_plan_id`, `launch_plan_digest`, `state ∈ {RESERVED, PREPARING, STARTING, ACTIVE, DRAINING, CLOSED}`, `startup_deadline`, `spawn_submission ∈ {local, submitted, uncertain}`, `membership_empty` (initially false), `empty_basis`, `runtime_copy_view`. The first five are written once by the executor at row creation; afterwards only `state`, `spawn_submission`, `membership_empty`, `empty_basis`, `runtime_copy_view` change, and `startup_deadline` is written once when the spawn is enqueued; the epoch is the `execution_id` prefix, no separate field | conn L71–74, L79, L95–100, L359–367 |
| `Session` / same manager | `session_id, execution_id, expected_uid` (written once at row creation, never overwritten by an observed value), `channel_id` (written once at the Channel install, T-09), `admission, dispatch_open, task_admission, task_bindings, current_task_call` (the mutable fields) | conn L80, L95–100, L103–104; mech L263–266 |
| `Channel` / executor (install, phase, close), receiver (`frame_reader`), the Channel's single writer (`frame_writer`) | `channel_id, session_id, owned_fd, phase ∈ {bootstrap-handoff, hello, data, closed}, receiver_generation, frame_reader, frame_writer`; the first four and `receiver_generation` written once by the executor at install, a new object per install; the Channel → Session link is cleared only by close step 2, by object; `receiver_generation` is an epoch-monotonic counter value, one per Channel, never carried over, void after the step-2 deregistration, after which the fd number may be reused; fd owned by the object, closed exactly once | conn L81, L103–105 |
| `FrameReader` (per channel) / the owning Channel's receiver only | at most a 4-byte header, one bounded body, `offset, frame_started_at`, the frame's common uid, a diagnostic pid summary; in the first build it is C code (`transport.c`, behind FFI) that hands Python only whole-frame bytes whose fragments passed the credential comparison, and not the pid summary or first-byte time | conn L448–450, L482–483, L487–496 |
| `TaskBinding`, `TaskCall` / engine task entry | `TaskCall.state ∈ {QUEUED, RUNNING, DRAINING, RESOLVED}`, `call_key = (session_id, engine_to_agent, task_start.id)`, `start_sent`, `deadline`, `children`, `outcome` | conn L82–83, L747–755 |
| `RequestEntry` / engine request manager | `request_key = (session_id, direction, id)`, `task_call_ref`, `phase ∈ {RECEIVED, PREPARED, DISPATCHED}`, `terminal`, `wire_state`, `worker_state`, `effect` | conn L84, L646–650 |
| `SpawnRecord` / spawner | `execution_id, lease_id, uid, gid, launch_plan_digest, child_pid` (direct child = PID 1 of `P_X`, unreaped), `phase, terminal_event, runtime_copy_ref, clone_forbidden`; a record that has sent `execution_empty` and whose host copy awaits release stays live for control and storage but no longer occupies its uid and lease at spawner admission (T-03) | conn L85, L108–113 |
| control channel / engine ↔ spawner | one `SOCK_SEQPACKET` socketpair, no `SO_PASSCRED`, per-direction `seq`, bounded tombstone window (1,024) | conn L135–147, L170–181 |
| data channel / per execution | one `AF_UNIX SOCK_STREAM` socketpair; engine end has `SO_PASSCRED` set before `clone`; both ends unnamed; child end becomes fd 3 | conn L296, L316, L321–322, L421–424 |
| kernel: task credential | per task `{uid, euid, suid, fsuid, gid…, caps, user_ns}`; `kuid_t` stored namespace-independent | kub §1 |
| kernel: pid namespace `P_X` | the membership set of execution X; destroyed asynchronously after its last reference | optb L205–214; mech L293–301 |
| kernel: socket receive queue | skbs on the engine end, each stamped `{pid, kuid, kgid}` at send time; the queue persists after the sender exits | kub §2.4; kub §4 (N10 queued arm) |
| engine global | `engine_epoch`, `accepting_new`, record-system latch `healthy/failed`, execution slots (16) | conn L71, L635–637; si L184–188 |

## 2 Actors

- **engine** — unprivileged, in the initial user namespace (optb L178; conn L87–89); one state executor
  serializes every local decision (conn L634). "Same decision" = no `await` inside the executor; it gives no
  atomicity with kernel exits, spawner notifications or worker I/O (conn L638–639).
- **spawner** — pre-forked before any sensitive state exists; holds the five spawn capabilities; sole
  `waitpid` consumer for agent PID 1s; serves many `SpawnRecord`s from a bounded event loop (optb L184–197;
  conn L135–138, L319, L353–355).
- **trusted bootstrap** — spawner code running in the cloned child before `execve` (conn L291, L328–334).
- **kernel** — trusted (scope L149–156).
- **adversary** — every task in `P_X` from `execve` onward: arbitrary code at uid `u_X` inside the envelope
  (scope L180–181; tm D1). The model's capability is not an input.
- **trusted caller** — the engine's own task entry (create execution, create task, `finish_execution`,
  `close_session`) (conn L729–731, L847, L882).
- **workers** — prepare / connector / file / log workers; they return facts to the executor and never write
  `Session` / `RequestEntry` (conn L634; si L111–112).
- **supervisor** — trusted only to let a new epoch start on a kernel-held fact that the old cell's domain is
  empty (its own cgroup reporting `populated 0`), keeping no safety-relevant state (AA-04); outside the model except as the source of the new-epoch
  condition (conn L930–940).

## 3 Transition table

Columns: ID · family · source · precondition · reads → writes · actor · atomicity and interruption points ·
permitted interleavings at those points · outcomes. "Outcome" lists what the frozen text says happens; no
sentence here judges whether an outcome cuts a route.

### 3.1 Family L — launch and admission (E-01, optb spawn sequence, E-05/E-08 lease, E-10 plan)

| ID | source | precondition | reads → writes | actor | atomicity / interruption | permitted interleavings | outcomes |
|---|---|---|---|---|---|---|---|
| T-01 reserve | conn L293, L361, L95–102, L106–107; rr L64–69, L569–574, L583–588 | trusted caller asks for an execution of workspace W; `accepting_new`; a free execution slot; W's `WorkspaceRecord.state = available`; the `UidLease` of W's static `workspace_uid` is in the pool, not a sentinel / host id, `free`, and its previous lease satisfied `CLOSED AND empty`. The check reads only the engine's own lease state: it sees neither a task left by an earlier epoch nor a task outside the engine that holds a pool uid; both rest on the pool-exclusivity premise (T-67; conn L106–107) | reads pool, slots, W → writes `UidLease free→held`, `Execution RESERVED` (new `execution_id`, `local_agent_id` from the trusted caller's request, `lease_id`, `launch_plan_id`, `launch_plan_digest`, `submission = local`, `membership_empty = false`), `Session{session_id, execution_id, expected_uid = u, dispatch_open = task_admission = false}` (`channel_id` is written later, at T-09), `WorkspaceRecord leased`; the reserved fields are written once. The new row inherits no object of an earlier execution: a recurring `local_agent_id` brings no state, and the row binds neither an earlier execution's still-occupied runtime slot nor any object in it (conn L101–102) | engine executor | one decision; row creation is RESERVED and shares the decision with the lease acquisition (conn L96–97) | none inside; other executions' events before/after | row RESERVED with `expected_uid = u`; or refusal (no slot / lease not free / workspace busy / pool exhausted) with no row created (conn L74; rr L587) |
| T-02 submit spawn | conn L140–143, L151, L361–362, L197–198, L99–100, L338–340, L119–120 | RESERVED; control writer idle | reads row → the executor writes `startup_deadline` once when it enqueues the spawn; writes `spawn{uid, gid, launch_plan_id, digest, startup_deadline_ns}` record; `submission local→submitted` on a whole-record send, `uncertain` on every other send error; `RESERVED→PREPARING` | engine control writer | `seq` advances only on a whole send; only errors known to have sent nothing (EAGAIN, EINTR) keep `local`, and `uncertain` is never treated as never sent (conn L119–120) | control reads (T-43, T-52) and other rows' events | PREPARING/submitted; or `uncertain` → T-40 trigger (wait for the spawner's empty fact); or withdrawn before send → T-14 |
| T-03 spawner admits spawn | conn L151, L199–203, L313–315, L108–113, L127–130; rr L65; si L267–276; sbx SC-catalog | `control_ready` was sent (it is not when the file worker's privilege drop fails its `getresuid` re-read, conn L129–130); valid record, `seq` expected; plan registered with matching digest; uid/lease not occupied by a spawner record, where a record that has sent `execution_empty` and whose host copy awaits `runtime_status released` does not occupy them (the looser reading, conn L108–113); workspace has no local active `SpawnRecord` (rr L65; whether a record of the looser reading counts as active here is not stated, MM-18); storage budget | → `SpawnRecord{execution_id, lease_id, uid, gid, child_pid = none}`, `RuntimeCopy` reserved; file worker builds the copy to READY | spawner | copy creation is an asynchronous file job; `stop` arriving during it seals `clone` first (conn L201–202) | T-41 stop; other records' events; a predecessor record of the same uid may still await its storage release | READY → T-04, the new record with its own copy (another `copy_id` and inode set) while a predecessor's copy keeps its storage budget and execution slot (conn L109–111); or refusal while such a predecessor exists, if the workspace check counts it (MM-18; the model keeps both outcomes); or `spawn_failed(stage, …)` + `execution_empty(never_created)` + `runtime_status(released, not_materialized)` (conn L199–201, L894), and the record can never clone again |
| T-04 create channel | conn L296, L316–320; optb L188 | READY, deadline not passed, no child exists yet | → kernel: `socketpair(AF_UNIX, SOCK_STREAM)`; `SO_PASSCRED = 1` on the engine end | spawner | two syscalls before `clone` | none involving the execution: no task of `P_X` exists | engine end has `SOCK_PASSCRED` before any sender exists; failure → T-03 failure branch (stage socketpair/passcred) |
| T-05 clone | optb L205–214; conn L297, L317–320; sbx SB-01 | T-04 done; `startup_deadline` not passed | → kernel creates `P_X` with member {child}; child is PID 1 of `P_X`, in fresh mount/net/ipc namespaces; `SpawnRecord.child_pid`; spawner closes its copy of the child end; child closes the spawner's copy of the engine end | spawner / kernel | `clone` is one syscall; SIGCHLD reaping is the spawner's only `waitpid` path | engine continues; other records | child exists (`P_X = {PID1}`); or clone failure → `spawn_failed` + `never_created` |
| T-06 sandbox steps 1–10 | optb L215–245; conn L321–323; sbx SB-02/SB-03 | child running as root inside the new namespaces | → child's mount namespace (private propagation, tmpfs root, runtime ro two-call bind, `/work` rw nosuid nodev, fresh proc, dev/tmp/shm, `pivot_root` + detach, `lo` up); stdio → `/dev/null`; channel dup'd to fd 3 without CLOEXEC; `close_range(4, ~0)` | trusted bootstrap / kernel | each step checks its return value; any failure → best-effort FAIL + `_exit`, no `execve` (conn L325–327) | spawner event loop; engine | child at step 11 with fd table {0,1,2 → /dev/null, 3 → channel}; or child exits with FAIL (stage, errno) |
| T-07 privilege drop (step 11) | optb L246–271; conn L324–327; kub §2.3; sbx SB-04/SB-05 | step 10 done; the policy filter was read, verified and compiled by the spawner before `clone` | → child cred: `no_new_privs = 1`; bounding set empty; `setgroups([])`/`setresgid`; `setresuid(u, u, u)` three equal values; after `setresuid` and before the seccomp install, `getresuid` re-reads the three values (in the drop function the engine and the file worker share, conn L127–130; optb L252–257); remaining capability sets cleared; agent seccomp installed last (S1 three clauses, S2 default-deny as deployed) | trusted bootstrap / kernel | fixed internal order; nothing recoverable after the uid lands (optb L280); a failure before the drop may emit FAIL with root uid, treated as diagnostic (conn L326–327) | as T-06 | child task cred = `{uid = euid = suid = u, caps = ∅, NNP, seccomp}`; or a re-read value unequal to the recorded uid → FAIL(stage = uid) + exit, no filter installed, no SEALED; or another FAIL + exit |
| T-08 SEALED | conn L328–334, L308–311 | all of step 11 succeeded | child sends the 16-byte SEALED on fd 3 (stream, short writes, one deadline); spawner reads the engine end per fragment with a control buffer: ancillary/truncation check, `uid == allocated u`, `pid == child_pid`, then assembles the fixed record; reads no further bytes | trusted bootstrap → spawner (kernel stamps each fragment) | per-fragment `recvmsg`; EINTR/EAGAIN keep progress | spawner serves other records between fragments | SEALED accepted → T-09; mismatch, FAIL, EOF or deadline → record failure (`spawn_failed`), child killed/reaped later (T-41/T-42) |
| T-09 prepared handoff | conn L152, L163–168, L170–176, L265–266, L335, L363 | SEALED consumed; `seq` expected; engine row PREPARING, not CLOSED, deadline not passed | spawner → `spawn_prepared{digests, child_pid, sealed: true, copy_id}` + exactly one `SCM_RIGHTS` fd (engine end) over control; closes its own copy after a whole `sendmsg`. Engine: `recvmsg(MSG_CMSG_CLOEXEC)`; checks record fields, exactly one fd, `AF_UNIX`, `SOCK_STREAM`, connected, both ends unnamed, `SO_PASSCRED == 1`; → a new `Channel{owned_fd, phase = bootstrap-handoff, receiver_generation}` with `receiver_generation` the next value of the epoch-monotonic counter, the Channel → Session link and `Session.channel_id` written once, `PREPARING→STARTING` (conn L103–105) | spawner → engine executor | engine validation, object install and the state move are one decision (conn L265, L103) | `execution_empty` may arrive first (T-43); hello cannot precede this (no fd installed) | STARTING with a Channel; or rejection: every fd received in this message is closed, control fault (conn L164–165, L174–176); or late prepared on a CLOSED row: fd closed, `stop` registered (conn L363) |
| T-10 COMMIT | conn L302, L335–340, L336 | STARTING; identity fields consistent; deadline not passed | engine → 16-byte COMMIT on the channel (stream, partial writes allowed) | engine writer | whole-send gate (conn L343, L1249) | reads on other channels | COMMIT fully sent → child proceeds; send failure or deadline → T-40 |
| T-11 execve | optb L272–273; conn L336, L341–342 | child received the full COMMIT; anything else (other data, EOF, timeout) → child exits | kernel replaces the address space; `/proc/self/*` re-owned; NNP, seccomp, cred and fd 3 survive; **from here every task of `P_X` is the adversary** | trusted bootstrap → kernel | one syscall | none | agent runtime running as PID 1 of `P_X` at uid `u`; or `execve` error → best-effort FAIL + exit (engine treats FAIL bytes in hello phase as an oversize length → close, conn L430–431) |
| T-12 hello / welcome | conn L304–305, L343–345, L364, L522–523, L538 | STARTING; a validated `hello` frame (through T-20…T-25) with `protocol = w2-local/2`, `adapter_id` matching the plan; no earlier hello | → `welcome` enqueued; on the whole `welcome` send: `STARTING→ACTIVE`, `dispatch_open = task_admission = true`, `Channel.phase = data` | engine executor + writer | row stays STARTING while `welcome` is queued; a resource action in that window is refused and closes (conn L344) | `execution_empty` (T-43) may arrive before/after; other channels | ACTIVE; or close on: hello protocol mismatch, duplicate hello, FAIL bytes, data before `welcome`, startup deadline, `welcome` send failure (conn L364, L384) |
| T-13 spawn_failed | conn L153, L194, L341, L894, L121–126 | any T-03/T-06/T-07/T-08 failure; or a kill or wait error at reap (T-41), reported with `stage = reap, error_code = os_error`, possibly after an earlier startup `spawn_failed` of the same record | spawner → `spawn_failed{stage, error_code, os_errno}`; engine → row to CLOSED (T-40 trigger); the row still waits for the terminal fact (`execution_empty`); a reap-stage record is not an empty fact and is consumed as a quarantine trigger, not as a conflicting terminal (T-52) | spawner → engine | one control record | — | row CLOSED; `membership_empty` unchanged until T-43; stage = reap → T-44 |
| T-14 local withdrawal | conn L361–362, L857–858, L893 | RESERVED, or a row CLOSED before any send, with `submission = local` (nothing ever sent); conn L361 moves a row to PREPARING only on a whole send, so PREPARING ∧ local is not a reachable state (version 8, change request CR-F-02) | writer withdraws the pending record in its own ownership domain; → `membership_empty = true`, `empty_basis = local_never_submitted`, CLOSED; no `stop` sent | engine control writer | the withdrawal must be confirmed irreversible before the empty fact is written | — | CLOSED with a local empty fact; no Channel was installed, so the close-step-2 condition of T-45's gate counts as met (conn L872–873); lease release then follows T-45's gate |

### 3.2 Family R — receive and check (E-02; kub §2.4–§2.5, §5)

| ID | source | precondition | reads → writes | actor | atomicity / interruption | permitted interleavings | outcomes |
|---|---|---|---|---|---|---|---|
| T-20 send-side capture | kub §2.4, §5 L470–475, §3 L233–287; conn L435–437 | a task holding a descriptor to the channel's agent end calls a send syscall (`sendmsg`, `write`, …) | reads the caller's live cred inside the syscall → kernel queues an skb on the engine end stamped with the result. Branches by what the caller attaches: **(a)** nothing → `maybe_add_creds` fills `{tgid, real uid, real gid}` because the receiver has `SOCK_PASSCRED`; **(b)** `SCM_CREDENTIALS` selecting a real/effective/saved uid and its own pid → accepted with that selected value; it equals the real uid only under C1; **(c)** an explicit mapped uid outside the caller's real/effective/saved set → `-EPERM` with no skb **if** the caller lacks `CAP_SETUID` in its current user namespace; with that capability and a map naming the foreign kernel uid, the kernel may accept that uid (T-67 configuration departure, kub §2.4/§3); **(d)** an unmappable number → `-EINVAL`, no skb; **(e)** inside a self-made user namespace with map `0 → u` (only reachable where S1 is absent), attaching `0` → resolves to kernel uid `u`, stamped `u`; **(f)** `SCM_RIGHTS` attached → the fds ride in the skb | adversary task → kernel | single synchronous read of the current cred; no check-then-use interval on the capture (kub §4) | several same-uid tasks may send concurrently; byte runs from different senders are delimited per skb; a receive return ends where the stamped credential changes (conn L436, L1230–1231; af_unix.c L2618 at the WSL tag) | an skb with the actual captured/legally selected credential under the corresponding posture, or a failed syscall; kub §5's own-uid result is conditional on C1/C2, not an unconditional result for T-67 departures |
| T-21 one receive step | conn L453–458, L472–475, L481–485, L487–490; kub §2.5 | `Session.admission` not CLOSED (the pre-read check: after close step 1 the Channel issues no further `recvmsg`, conn L481–482); the fd is registered (after close step 2 deregisters it the event library delivers no readiness for that fd number, AA-13); frame deadline not passed (re-read before each step); one scheduling slot per ready channel | one non-blocking `recvmsg` for the remaining header or body length, fresh `msghdr`/control buffer ≥ `CMSG_SPACE(ucred)`, `MSG_CMSG_CLOEXEC`; kernel renders the skb's cred into the engine's user namespace (`from_kuid_munged`; unmapped → overflow uid, kub §6.1) → fragment bytes + `ucred` + flags | engine receiver (in the first build the C FrameReader of `transport.c`, which only the owning Channel's receiver accesses) / kernel | one syscall per step; between steps the executor runs other work (conn L785–788) | timers, control events, other channels, close of this row between two fragments (hence the pre-read check) | fragment delivered → T-22; EAGAIN/EINTR → no change; 0 bytes (EOF) → T-46; POLLPRI/OOB → T-46 |
| T-22 ancillary check | conn L459–461, L163–165 | a fragment returned | reads flags and cmsg list → every `SCM_RIGHTS` fd actually delivered (including under truncation) is closed; other unexpected ancillary, `MSG_TRUNC`, `MSG_CTRUNC`, missing or duplicate `SCM_CREDENTIALS`, wrong `ucred` length → the original session is closed; delivered fds are never dereferenced | engine receiver | same step as T-21 | none | pass → T-23; fail → T-40 with a `receive_rejected` event carrying no `verified_subject` (si L68) |
| T-23 fragment credential comparison | conn L462–464, L573; mech L263–266; optb L177 | T-22 passed; `Session.expected_uid` read through the Channel object | reads `ucred` → requires `pid > 0`, `uid ∉ {0, overflowuid, invalid}`, `uid == expected_uid` (ABI types `pid_t/uid_t/gid_t`, no signed conversion); on pass the bytes enter the header/body buffer; the frame's common uid is fixed on the first fragment, `sender_pid` kept only if equal across fragments else null — in the first build always null, since the C FrameReader hands over no pid summary (conn L470, L494) | engine receiver (C FrameReader in the first build) | same step | none | pass → buffer; fail → the whole partial frame is discarded and the session closed; no lookup of another row by the observed uid (conn L464, L176–177) |
| T-24 frame assembly and parse | conn L426–431, L465–475, L484–485, L487–496, L565–567; si L69, L116 | header's 4 bytes all passed T-23 → length ∈ [1, 65,536] else close; body bytes all passed; 5,000 ms from the first byte, re-read before accepting a fragment and before processing the frame (in the first build the bound is enforced in C); STARTING also under the startup deadline | the C FrameReader hands Python the whole-frame bytes; strict UTF-8 / JSON / schema / direction / phase parse (Python `json` configured as conn L491–494 states) → `ValidatedMessage` with `VerifiedContext{execution_id, local_agent_id, session_id, channel_id, receiver_generation, expected_uid, sender_uid, sender_pid, received_at}` (first build: `received_at` = the engine monotonic time of the whole-frame handover, at most 5,000 ms after the first byte; neither it nor `sender_pid` enters identity, conn L494–496); for `request`: `ValidatedRequest{context, resource_id, action, args}` and an E-09 `request_received` with `verified_subject` | engine receiver → executor | the parse is one step after the last fragment; for a `request` the parse, T-25 and `admit_request` (T-30) are one executor decision with no yield (conn L484–485); `FrameReader` emptied before the next header | between fragments as in T-21 | **D-ACC**: a validated message labelled by the row; or close on length, deadline, parse, phase, direction or unknown-field failure (no subject event); a `request` carrying `grant_ref` is such an unknown-field failure since the fourth revision (conn L4, L467; MM-06 records the text's two readings of its outcome) |
| T-25 phase / type gating | conn L477–479, L538–544, L757–758 | a validated message | reads `Execution.state`, in-flight tables of the original session and direction → STARTING accepts only `hello`; ACTIVE accepts the allowed direction/type set, `hello` only once; DRAINING accepts `bye` and idempotent old terminals / `cancel`; after CLOSED messages are released only; `cancel` / `task_result` / `result` / `error` resolve against the original in-flight table, unknown `reply_to` ignored, future ids are protocol errors | engine executor | one decision | — | hand-off to T-12 (hello), T-30 (request), T-36 (task_result), T-37 (cancel), T-48 (bye); or ignore; or close |
| T-26 outbound frame | conn L500–506, L708–718; kub §7.4 | a queued encoded frame; channel writable | writer `sendmsg(MSG_NOSIGNAL, msg_name = NULL)` of the current frame from `offset`; no credential travels with reads; `seq` frozen before the first byte and advanced only after the whole frame | engine writer | partial writes; one frame at a time; 5,000 ms stall limit from the first EAGAIN | reader, timers, other sessions, spawner continue | frame sent; partial; or 0/other error → T-46. Consequence for the model: the whole send of `task_start` is the QUEUED→RUNNING edge (T-31) |

### 3.3 Family Q — request, authorization and dispatch (E-03; E-06/E-07 as consumers)

| ID | source | precondition | reads → writes | actor | atomicity / interruption | permitted interleavings | outcomes |
|---|---|---|---|---|---|---|---|
| T-30 admit_request | conn L4, L525, L574, L666–667, L673–674, L751, L759–762; rr L176–179, L265 | `ValidatedRequest` in ACTIVE, carrying no grant field (conn L525); `task_call_id == current RUNNING call's task_start.id`; `task_id` matches that call and its valid `TaskBinding` reachable from the *original* session (conn L574, L751); call/task/grant ownership checked at admit (rr L265), the grant being that binding's; quota | reads the label and the session's call state → the context's `grant_ref` taken from the matched call's `TaskBinding`, not from the message (conn L574, L751); `RequestEntry{request_key = (session_id, agent_to_engine, id), task_call_ref, phase = RECEIVED, worker_state = owned}` added to `TaskCall.children`; a new id updates the high-water mark | engine executor | one decision, the same as the frame's parse (T-24; conn L484–485) | — | entry created; or `resource_exhausted` / `permission_denied` with `effect = not_dispatched`; duplicate or old active id → close. Since the fourth revision the request's correlation inputs are `task_call_id` and `task_id` only and no agent input selects the grant (conn L4, L511; rr L132–133); a request carrying `grant_ref` fails T-24's strict parse and never reaches this transition (MM-06) |
| T-31 task_start | conn L729–735, L749–750; rr L176–177 | trusted caller; `Session = ACTIVE`, `task_admission`, previous call RESOLVED | → `TaskCall QUEUED` with `call_key`; whole `task_start` frame sent → `start_sent = true`, RUNNING, child-request entry open | trusted caller → writer | a partially sent `task_start` that is cancelled or expires closes the whole session (conn L750, L1248) | — | RUNNING; or DRAINING/closed |
| T-32 prepare | conn L668, L674; rr L265–266, L230 | an admitted entry | asynchronous worker builds `CandidateOperation{verified_context, task_call_ref, task_binding_ref, grant_ref, …, prepared_handle}` holding the original `RequestEntry`; result returns to the executor | worker → executor | asynchronous; the result carries no permission (rr L189) | close, revoke, deadline, task_result may all land before the result returns | `PREPARED`; or `RequestError` → terminal; or entry already terminal/closed → release only |
| T-33 authorize + try_dispatch | conn L574, L669–670, L675–678, L687–689; rr L185–190, L263–285 | PREPARED entry | in **one** executor decision with no `await`: entry not terminal; `Session = ACTIVE` and `dispatch_open`; `TaskCall = RUNNING`, outcome unset, deadline not passed; task / grant / call equal the original references (rr L270), the grant reference being the engine's, taken from the matched call's `TaskBinding` (conn L574; no agent-chosen grant selector enters the comparison since the fourth revision); `TaskBinding active`; `GrantState active`, session/task match, not expired; descriptor identity, rule and limits, credential version present; E-08 slot; record system healthy → `AuthorizedOperation` constructed and moved; `phase = DISPATCHED`, `effect = unknown`; `authorization_decided` and `dispatch_started` recorded; non-blocking `handler.start(operation, sink)` | engine executor | no yield between the checks and `start` (conn L678); `GrantState.revoke` and `close_session` are ordered by the same executor (rr L282–283) | before this decision: anything; inside: nothing | DISPATCHED with the label carried inside the operation; or deny → `not_dispatched`, release |
| T-34 handler and callbacks | conn L679–680, L694–701; rr L345–349, L436–440, L482–490 | DISPATCHED | handler drives I/O; `Chunk / Complete / Failure / released` are delivered to the original `RequestEntry` through its `sink` (object reference; the handler cannot name a session, fd or `seq`); the model `PREREQ` callback re-reads state before the HTTP send and allows one attempt | worker / connector → executor | callbacks are asynchronous; the executor re-checks the deadline and the terminal before applying each | close, cancel, revoke between callbacks | chunks and a terminal queued to T-26; late events → release only / `late_completion` (never a second terminal) |
| T-35 request terminal and slot return | conn L647–650, L655–661, L683–685 | any terminal cause | `terminal` written once; `wire_state → sent / abandoned`; `worker_state → releasing → released` on the worker's real release; slot returned only when `terminal ∧ wire ∈ {sent, abandoned} ∧ worker ∈ {none, released}`; then removed from `TaskCall.children` | engine executor | three separate facts, never merged | — | slot returned; or `cleanup_stalled` after 5,000 ms without `released` (T-50) |
| T-36 task_result / call barrier | conn L737–745, L752–755, L757–762, L764–770 | RUNNING or DRAINING call; a validated `task_result` matching the original call | deadline re-read first; `outcome` committed once; DRAINING seals the child-request entry; RESOLVED when children returned and the agent's terminal is in or the call never went out or the Session is CLOSED; a followup is a **new** `TaskCall` id; a request citing the previous call's id is `permission_denied / not_dispatched` | engine executor | 5,000 ms DRAINING grace → close execution (conn L755) | — | RESOLVED / closed; a same-uid process learning the current call id is stated as not separating subjects (conn L760–762) |
| T-37 cancel | conn L529, L538–539, L699 | validated `cancel` or trusted cancel | lookup only in the original session's and direction's in-flight table; `reply_to` unknown or terminal → ignored; handle `cancel(reason)` idempotent | engine executor | — | — | request moves toward a terminal; never a new authority |
| T-38 record emission (consumer) | si L56–60, L89–99, L111–122, L184–189 | an executor step with a recordable fact | events carry `verified_subject` copied from the `VerifiedContext` (request-side) or `control_binding` (lifecycle side); `record()` returns `accepted / unavailable`; a failed latch sets `accepting_new = false`, closes affected sessions, forbids new dispatch; `stop / reap` proceed regardless | engine executor → log worker | the reservation for `pre_egress / authorization_decided / dispatch_started` is inside the same decision as T-33 (si L129–131) | — | event queued; or record failure → T-40 trigger for affected sessions (`control_shutdown`). The label never enters by any agent field (si L93, L106) |
| T-39 TaskBinding / Grant association lifecycle | rr L167–174, L180–181, L210–214; conn L769–770 | trusted task entry creates a binding for an original Session; rebind only with no active call/request; removal only when binding closed and no call/request references | reads original Session, binding and references → creates TaskBinding{session_id,task_id,grant_ref,state} and immutable session-scoped Grant; GrantState active→revoked; binding active→closed; trusted rebind selects a new Grant only after the guard; guarded removal | trusted caller / single authorization state executor | creation, state update and guard decisions use the single executor; no worker writes; async old references may exist only where the stated no-reference guard is not yet satisfied | prepare/dispatch/close before or after the decision; rebind/removal refused while guard false | new or rebound association, revoked/closed binding, or safe removal; the relation of original session/context to current references remains a preservation question, not a policy-content analysis |

### 3.4 Family C — close, stop, reap, reclaim (E-04; kernel pid-namespace semantics)

| ID | source | precondition | reads → writes | actor | atomicity / interruption | permitted interleavings | outcomes |
|---|---|---|---|---|---|---|---|
| T-40 close_session | conn L366, L847–868, L870–874, L876–880 | any trigger: necessary launch failure, startup / frame / stall / DRAINING-grace deadline, channel EOF or error, credential or protocol failure, forced stop, `execution_empty`, `cleanup_stalled`, record failure, control loss, `bye`, `runtime_status retained` | step 1 (one decision): `Execution.state` and `Session.admission → CLOSED`, `dispatch_open = task_admission = false`, current `TaskCall` entry sealed; step 2: reader/writer deregistered, non-blocking `shutdown` then `close` of the fd exactly once by object/generation, the Channel → Session link cleared and `receiver_generation` void, unsent frames dropped (which says nothing about whether sent bytes were read by the peer), pending terminals `abandoned`, unexpected received fds closed; a row that never had a Channel (RESERVED withdrawal, `spawn_failed` in PREPARING, a rejected late prepared whose fd was closed on receipt) has nothing to deregister and step 2 counts as done; step 3: unfinished requests → `closed` (effect by evidence), cancel/release issued without waiting for workers; step 4: `submission = local` → T-14; else a `stop` intent registered for the control writer; step 6: on a matching `execution_empty` → `membership_empty = true`; **release of the held lease once when the row is CLOSED, step 2 is done, the empty fact holds and old callbacks are bound to the old objects** (→ T-45) | engine executor (steps 1–4, 6), spawner (step 5 = T-41) | steps 1–4 are one executor decision with no yield (conn L870; MM-09 resolved); steps 5–6 are asynchronous notifications | none between steps 1 and 4; queued skbs (K-06) are not read by any receive step after step 1 (T-21 pre-read check) and step 2 closes the fd in the same decision; worker callbacks and control events before or after the decision | CLOSED is terminal (no return to ACTIVE, conn L366); `stop.reason` mapped to the closed set; 5,000 ms empty-wait after `stop` is fully sent → T-44 on expiry |
| T-41 spawner stop | conn L154, L170–181, L861–863, L908–920, L114–126; iv L50 | `stop{reason}` received for an unreaped record, or the spawner's own control-loss sweep; a `stop` naming a record the spawner never received (T-02 `uncertain` with no record at the spawner) is a control fault (conn L114–118, L170–181) → T-49 → T-44, beside the 5,000 ms empty-wait path of conn L879–880 (version 8, change request CR-F-05; the design now states this reading, its reason and that one such stop ends every parallel execution) | `SIGKILL` to `SpawnRecord.child_pid` (PID 1 of `P_X`, direct child, not yet reaped) then `waitpid`; requires `CAP_KILL` in the target user namespace and `kill/wait` in the spawner's seccomp; terminal records → idempotent; after a reap the numeric pid is never signalled again | spawner / kernel | non-blocking per record; the spawner never waits on one execution | file jobs, other records | child reaped → T-42/T-43 (`pid1_reaped`); a `kill` error → `spawn_failed(stage = reap)` → T-13 → T-44, except after an earlier `spawn_failed` of the record: no second message, and T-40's 5,000 ms empty-wait → T-44; a `wait` error → that record sent best effort, then the spawner treats the control link as lost → T-49 (conn L121–126); `ESRCH`, `ECHILD`, `EIO` → T-44; none of these is an empty fact |
| T-42 PID 1 exit and namespace emptying | mech L275–282; kub §2.6; conn L895, L900–903; optb L190–191 | PID 1 of `P_X` terminates (own exit, `SIGKILL` from T-41, OOM) | kernel terminates every other member of `P_X` with `SIGKILL`; the spawner's `waitpid` returns PID 1's terminal state; `P_X` is destroyed asynchronously once its last reference goes — the design creates none (no ns fd, no bind mount) | kernel / spawner | asynchronous: member tasks die on their own exit path; the socket receive queue on the engine end is **not** part of `P_X` and keeps its queued skbs (K-06) | the engine may read queued fragments stamped by now-dead senders until the T-40 decision (steps 1–4 are one decision); `execution_empty` (T-43) may reach the engine before or after any such read | membership set empty; `pid1_reaped` available to the spawner. The evidence-only kub §2.6 addition resolves MM-01: the namespace-empty ordering precedes PID 1 becoming reapable; destruction of all namespace references is a separate event |
| T-43 execution_empty | conn L155, L170–179, L205, L373–375, L864–866, L896; si L66 | spawner holds `pid1_reaped` or `never_created`; `seq` expected | spawner → `execution_empty{basis, exit_code | signal, last_stage}`; engine matches `engine_epoch / execution_id / lease_id` (never a uid); → `membership_empty = true`, `empty_basis`; a still-open row is closed (T-40) | spawner → engine executor | one control record; duplicates with equal terminal fields are ignored (no second release) | no cross-fd ordering with `spawn_prepared` or `hello`: empty-first → row closed, a later prepared fd is closed and the message does not enable the row (conn L373–374, L896); hello-first → ACTIVE then closed on empty | empty fact recorded; late events beyond the tombstone window → protocol fault, no revival (conn L177–179) |
| T-44 quarantine | conn L170–181, L879–880, L897–898, L925, L121–126; sbx SC-reclaim | `stop` fully sent and no empty fact within 5,000 ms; `kill`/`wait` error, received as `spawn_failed(stage = reap)` (T-13) or, after an earlier `spawn_failed` of the record, through the empty-wait expiry, or through the control loss a `wait` error raises (T-49); control ownership lost, including the control fault raised for a `stop` naming a record the spawner never received (T-41 → T-49; version 8, change request CR-F-05) | → `UidLease held → quarantined`; occupancy kept; a later matching real empty fact in the same healthy control epoch may lift it, after which T-45's gate applies | engine executor | — | — | lease quarantined; errors, timeouts, EOF, `ESRCH`, `ECHILD`, `/proc` scans never make it `free` (conn L900–901) |
| T-45 lease release and reuse | conn L367, L865–868, L870–873, L901–903, L101–102, L108–111; rr L583–592; mech L275–282 | row CLOSED ∧ close step 2 done (registration removed, fd closed; met for a row that never had a Channel) ∧ `membership_empty` ∧ old callbacks bound to old objects (T-40 step 6); not quarantined | → `UidLease held → free`; the uid returns to its workspace's slot; a later T-01 for the same workspace may allocate the same numeric uid under a new `execution_id`, `session_id`, `channel_id`, `lease_id` and `lease_generation`; old `RequestEntry`s and callbacks keep the old session/epoch references and are never re-addressed by uid or fd; the execution **slot** is returned separately only when additionally `runtime_copy_view = released` and all request/call/workspace references ended (conn L206–208); the new row binds neither that slot nor any object in it (conn L101–102), and the old `SpawnRecord` awaiting storage release does not occupy the uid at T-03 (conn L108–111) | engine executor | one release per lease (conn L367) | the old execution's slot, host copy and `SpawnRecord` may still be live when the uid is reused | uid free / reusable; or no release while any gate is unmet |
| T-46 channel EOF, OOB, deadline, stall | conn L457–458, L472–475, L502, L791–793 | reader sees 0 bytes / POLLPRI; frame deadline; send stall 5,000 ms | → unfinished frame discarded; T-40 trigger; EOF is not an empty fact | engine receiver / writer | — | — | row closed; `membership_empty` unchanged |
| T-47 finish_execution | conn L365, L882–887 | ACTIVE, no unresolved `TaskCall` | → DRAINING, both admissions false, `shutdown` queued; 5,000 ms grace from the decision | trusted caller → executor | grace not reset by a late `shutdown` send | `bye`, EOF, `execution_empty` → T-40 immediately | close on bye/EOF/empty or on grace expiry (then T-41) |
| T-48 bye | conn L532, L543, L885 | validated `bye` in ACTIVE or DRAINING | → T-40 for the original row only; the spawner still reaps PID 1 | engine executor | — | — | row closed; membership unchanged until T-42/T-43 |
| T-49 control-link loss and new epoch | conn L925–945, L114–118, L124–126; rr L762–764, L888–890; si L184–189 | control EOF/error; control unwritable for 5,000 ms; record latch failed; a control fault at the spawner, including a `stop` for a record it never received; a `wait` error at reap (T-41) | engine: `accepting_new = false`, all rows → T-40, unconfirmed leases → T-44; spawner (independently): closes its control end, stops and reaps all records, then exits; a new engine process in the same cell must wait until the trusted supervisor has terminated the old engine, spawner, file worker and executions and confirmed the isolation domain empty by a kernel-held fact, never by an engine's or spawner's self-report: the cell's engine, spawner, file worker and all executions sit in one exclusive cgroup, the supervisor writes `cgroup.kill` and waits until `cgroup.events` reports `populated 0`; a pid-namespace reap is not used as this fact, since its result goes once to the init's parent and a restarted releaser cannot re-read it (conn L930–934; rr L762–764); the E-08 store gate also applies (conn L937–939); the first build does no restart recovery (rr L888–890); the old epoch's executions and leases are never recovered | engine / spawner / supervisor / kernel | the two sides act without coordination; `SIGKILL`/OOM of the spawner leaves supervisor residue (conn L940); the supervisor releases only on the kernel fact and keeps no safety-relevant state, so its crash only keeps the new epoch from starting and after a restart it re-reads the kernel fact (conn L934) | a supervisor crash or restart at any point of the hand-over | old epoch dead; new epoch starts from a clean pool only on the kernel-held empty fact, under the deployment precondition that the cell is placed in that cgroup by host init and no agent can leave it (conn L935–936; rr L889–890; its failure is a T-67 input) (MM-10) |
| T-50 cleanup_stalled | conn L947–951 | a terminal request without `released` for 5,000 ms | → `cleanup_stalled`; slot and references retained; owning session closed (T-40); `accepting_new = false` until all stalled items clear and control/record paths are healthy; `stop / reap` continue | engine executor | — | — | bounded unreleased objects; no forced `free` |
| T-51 late callback after release | conn L901–903, L580; rr L551–552 | a worker or connector callback for an old `RequestEntry` arrives after its row is CLOSED or its uid is `free` | the callback holds the old object; no lookup by uid, fd or request id; → release only | worker → executor | — | — | no new dispatch, no new label |
| T-52 control idempotence and tombstones | conn L170–181, L121–123 | any control record | `seq == expected` accepted; smaller `seq` ignored only if byte-identical, without fds, within the bounded history; jumps, conflicts, unknown execution/lease, digest mismatch → control fault (T-49), except that a reap-stage `spawn_failed` following an earlier `spawn_failed` of the same record is consumed as a quarantine trigger (T-13), not judged a conflicting terminal; a consumed `spawn_prepared` arriving again: all fds closed first, then control fault; tombstones (1,024) exist for idempotence only | engine executor | — | — | as stated; no execution is revived from a tombstone |

### 3.5 Family K — kernel-level actions of the adversary and admitted events (not engine code)

| ID | source | what happens | outcome under the frozen text |
|---|---|---|---|
| T-60 fork / clone / threads inside `P_X` | mech L135; conn L442, L1233; si L286–288 | new tasks with the same cred, inside `P_X`; fd 3 inherited unless the adapter set CLOEXEC (no guarantee against the adversary) | all such tasks are execution X (D-GT); frames written jointly by them carry uid `u` per fragment |
| T-61 uid changes within or beyond the own set | kub §3–§6; optb step 11 | Under C1, real/effective/saved kernel uids all equal u; without relevant initial/parent privilege only permitted own-set changes are possible. T-67 departures: unequal slots permit selecting another own-set value; CAP_SETUID in the applicable namespace permits changes to any uid represented by its map. | intended posture: own kernel uid or syscall error; permitted departure: a different real kernel uid, potentially another execution's uid, if the map/privilege predicates allow it; no kernel breach is implied |
| T-62 user-namespace creation and map writes | kub §3/§6 C2; scope S1; optb step 11; iv diagnostic-policy results | unshare(CLONE_NEWUSER), clone(CLONE_NEWUSER), clone3 under deployed S1 fail before namespace creation. Without S1 a child user namespace gains local capabilities; an unprivileged self-map may name only the creator's effective kernel uid. Relevant parent privilege or a privileged map writer can permit broader mappings (T-67). | own-only map plus no parent privilege: renaming to 0 retains the same kernel uid, foreign map/unmapped setuid fails; broader authorized map: a foreign kernel uid can become nameable and usable by T-20/T-61. S1 absence alone does not establish the broader-map branch |
| T-63 descriptor movement | conn L459–461, L595–597; kub §7.2; mech L573 (discharge row 1); scope S5 L466 | `dup`, `SCM_RIGHTS` to a task in `P_X`, `pidfd_getfd`, `ptrace`, `/proc/<pid>/fd` reopen, `getsockname`/`getpeername`, `setsockopt` on the agent end, `shutdown`/`close` of fd 3 | same-execution copies stay in X; `SCM_RIGHTS` fds delivered on the channel are closed by the engine (T-22 outcome); cross-uid `pidfd_getfd` / ptrace / fd reopen are governed by seccomp, DAC and `ptrace_scope` (S5) — the attack-side evidence belongs to Stream E, the attribution outcome of a *held* foreign descriptor is attacker input A-07 |
| T-64 naming and alternate write paths | conn L350–352, L423–424; si L280–285; iv L46 | `bind` / `connect` / `listen` / `socket` / `io_uring_*` → denied under the diagnostic S2 (`EPERM`); `splice`, `vmsplice`, `sendfile`, `sendmmsg` into fd 3 — not named in the frozen text | both endpoints stay unnamed on the measured substrate (conn L1261); every write path into fd 3 stamps the sender's cred per skb (MM-14, kernel half resolved; kub §2.4); which of these calls the production allow-set admits is the S2 `[S]` item |
| T-65 exit timing | mech L268–273; kub §8; conn L373–375 | a task sends then exits at once; PID 1 exits while queued bytes remain; notifications lag the kernel event | the send is attributed at send time (live-at-send); the queue persists (K-06); the engine may act after the sender is gone (the named send→act window) |
| T-66 kernel breach (N1) and hardware fault (N9) | scope L149–173; kub §8 | arbitrary read / write / execute through a kernel defect reached from the syscall face, or a hardware mechanism | out-of-model input: the stamped uid can be made arbitrary; the model records the input for Step 2's declared-exclusion branches and judges nothing |
| T-67 configuration failure | scope L165–169; tm D6 L172–174; kub §6; conn L87, L106–107; rr L387–389, L886–887; iv L93–95 | a required item of S1–S14 or C1–C4, or the exclusive-uid-pool deployment premise (02 §0.3 and U-05: a trusted deployment supplies the pool-exclusivity constraint before start, and a `/proc` scan cannot establish it — conn L87, iv L93–95, EV-81; its failure is R-G5-06's), absent on the deployed host (version 8, change request CR-F-06). The design now writes the premise's limit: T-01 reads only the engine's own lease state, so neither a task left by an earlier epoch nor a task outside the engine holding a pool uid is visible to it (conn L106–107). It also writes, as a deployment precondition the engine does not check, that the local model instance is an external process that runs under no pool uid and belongs to no execution's process domain (rr L387–389, L886–887); its failure is one more configuration failure (examples: S1 absent → T-62 second branch; unequal uid slots after `setresuid` → T-07's re-read outcome; C3 violated → every unmapped agent renders as the same overflow uid, kub §6 C3; C4 collected half absent → `MSG_CTRUNC` and no credential) | in-model input tagged *configuration failure*; never a kernel breach |

Admitted kernel / spawner events: **K-01** any agent task exits, is killed or OOM-killed at any instant;
**K-02** PID 1's death kills every member of `P_X` (T-42); **K-03** namespace teardown is asynchronous and
has no reference-holder query (mech L295–299); **K-04** arbitrary scheduling delay between a kernel event and
its processing by the spawner or engine; **K-05** the spawner's single reaper serializes `waitpid` results in
its event loop; **K-06** an skb queued on the engine end survives its sender's death until the fd is closed
or read; **K-07** short reads and writes, EAGAIN/EINTR on every socket; **K-08** engine or spawner crash
(T-49), with supervisor residue; **K-09** one `CLOCK_MONOTONIC` domain for engine, spawner and child (no
time namespace, conn L339–340); **K-10** numeric pid reuse in the host namespace after a reap (the spawner
signals no numeric pid after reaping it, conn L862).

## 4 Attacker inputs admitted by the threat model

The adversary is every task of `P_X` from T-11 on (scope L180–181). Its inputs that reach modeled state:

- **A-01 bytes and ancillary on fd 3**: any byte sequence, fragmentation and timing; `SCM_CREDENTIALS` with
  any `{pid, uid, gid}` it chooses (T-20 b–e); `SCM_RIGHTS` carrying any descriptor it holds (T-20 f);
  `MSG_OOB`; other cmsg types; `SO_PASSCRED` / `SO_SNDBUF` on its own end.
- **A-02 protocol content**: a `hello` with any `adapter_id` / `protocol`; messages before `welcome`; a second
  `hello`; `request` with any `id`, `task_call_id`, `task_id`, `resource_id`, `action`, `args`,
  or with a field outside its schema, among them a `grant_ref` field (an unknown field since the fourth
  revision, rejected at T-24: conn L4, L467; MM-06); `cancel` with any `reply_to`; `task_result` with any status; `bye`; W2BP / FAIL bytes
  after `execve`; oversize or malformed frames; frames left half-sent.
- **A-03 process structure**: fork / clone / threads (T-60); `execve` of anything in the runtime; exit at
  any instant (T-65); keeping descendants alive; letting PID 1 exit; pid reuse inside `P_X`.
- **A-04 credential-level calls**: T-61 and T-62; `setgroups`, `capset`, `prctl`, `uid_map` writes in a
  self-made namespace.
- **A-05 descriptor-level calls**: T-63 and T-64.
- **A-06 resource and timing**: floods, slow reads (stall), withheld `task_result`, frame-slot and output
  exhaustion, CPU saturation, sleeping across deadlines.
- **A-07 held-foreign-descriptor hypothesis**: a task of execution Y holds a descriptor to execution X's
  channel. No transition of the frozen text produces this state (T-04/T-05/T-06 step 10, conn L386, optb
  L245 and the spawner's pre-fork construction are the stated facts); the lab's d2 naive-spawn leak is the
  measured origin of the hypothesis (optb L194; kub §7.2). It is admitted as an **input** so that
  Step 2 can derive the routes through it; this file does not judge it.
- **A-08 boundary and configuration inputs**: T-66 (N1 / N9) is outside the normal actor model;
  T-67 (legitimate configuration failure) remains a modeled departure, not a kernel breach.
- **A-09 what is not an input of this model** (reachability facts owned by the W2 / CCT lines, carried here
  as premises): the control channel, the spawner, the engine's memory and files, other executions' sockets,
  the model server, the run-evidence directory and the host filesystem outside the mounts are not reachable
  from `P_X` under the deployed configuration (conn L137, L386; si L161; optb L168–173; rr L55–58).

## 5 Entry check — agent-reachable listeners or session entries

Question (PLAN COV-1): does the frozen design give the engine any agent-reachable listener or session entry
other than the pre-created unnamed socketpair, and how does each admit and bind callers?

| candidate entry | agent-reachable? | how callers are admitted and bound | source |
|---|---|---|---|
| per-execution data socketpair (fd 3) | **yes — the only one** | created by the spawner before the child exists (T-04); the engine end arrives as the single `SCM_RIGHTS` fd of `spawn_prepared` and is bound to exactly one `Channel → Session → expected_uid` at install (T-09); callers are whichever tasks hold a copy of the child end: by construction the members of `P_X` (T-05, T-06 step 10, T-60); every fragment is bound by T-21–T-23; no `bind`/`listen`/`connect` by either side, both ends unnamed (conn L423–424, L1261) | conn L152, L296, L316, L423–424; optb L172–173 |
| engine ↔ spawner control socketpair | no | in no agent fd table; closed by `close_range` at step 10; `SEQPACKET`, no `SO_PASSCRED`; trusted by construction, requests validated as input | conn L135–138, L386 |
| spawner ↔ file-worker private socketpair | no | private, CLOEXEC, created before the agent; parent/child close copies not their own | conn L222–225 |
| E-10 switchable runtime entry | no new entry | the registry and `LaunchPlan` are static trusted inputs read before fork; the adapter runs *inside* the sandbox and speaks only fd 3; replacing the descriptor changes the executable/argv/env, not the channel; S2 must deny `bind`/`connect`/`io_uring` and cover every enabled ABI; the tool-definition artefact added on 2026-10-18 is a read-only file in the runtime tree, its digest checked at the combined check, not an engine entry | si L242–247, L278–289, L351–355, L360, L413–419, L430 |
| E-07 connector | no | the engine's outbound HTTP to a fixed `ProviderConfig` endpoint; agents have a private `lo`-only netns; a local model instance (C-LS / C-LP) is an external process the deployment configures and the engine connects to like a remote endpoint, its lifecycle not managed by the engine (rr L387–389, L818–819); a remote one through the connector (C-R) | rr L95, L114–118, L418–425, L387–389, L818–819; optb L172 |
| E-09 hook and export | no | the observer is an in-process built-in; export goes to a run-evidence directory agents do not mount; no agent-facing log API | si L140–145, L161–165 |
| credential-bearing MCP server (consumer pending design) | not in the frozen text | stated as *another execution in its own compartment under its own uid, started by the spawner, reached only through the engine* (mech L137–143); if realised as a further socketpair it enters through T-01…T-12 as a new execution class; whether it gives the engine a second agent-reachable entry is decided at the freeze that designs it (the 2026-10-18 revisions do not) | mech L137–147 |
| engine-forwarded inter-agent messages (consumer pending design) | not in the frozen text | input side unchanged; a new consumer of the label (mech L316) | mech L316 |
| signals, `/proc`, ptrace toward the engine | no | fresh procfs in a private pid namespace; cross-uid signals and ptrace governed by DAC / `ptrace_scope` | optb L226; scope S5 L466 |

**Answer:** under the frozen revision the engine has exactly one agent-reachable entry per execution — the
unnamed `SOCK_STREAM` socketpair end delivered by `spawn_prepared` — and it admits and binds callers by
construction (T-04 → T-09) plus the per-fragment comparison (T-21 → T-23). The pending consumers have no concrete entry design in this freeze; if they use the same socketpair
construction they add instances, but this is not presumed. Their entry check re-runs at the freeze that designs them. The 2026-10-18 revisions add no entry: the tool-definition file is read-only inside the sandbox and the local model instance is reached only by the engine's connector (rows E-10 and E-07).

## 6 Abstraction assumptions

- **AA-01 single executor.** All engine-local decisions are serialized by one state executor; "one decision"
  means no `await`; kernel exits, spawner notifications and worker I/O are concurrent with it (conn
  L634–639). Interleavings are therefore modeled at executor-turn granularity plus the kernel-level events
  of §3.5.
- **AA-02 kernel semantics at the pinned tag.** Credential capture, translation and queueing are taken from
  `kub` at `linux-msft-wsl-6.6.87.2`; the measured runs are on that kernel (iv L17). Nothing certifies another
  build (tm D8).
- **AA-03 no count collapse.** Executions, requests, recycles and fragments are modeled as arbitrary within
  the stated bounds (16 slots, 16 requests per session, one in-flight call); any collapse is Stream Q's to
  justify.
- **AA-04 trusted actors.** Spawner, trusted bootstrap, kernel, supervisor and the trusted caller behave as
  specified; their inputs are not adversary inputs (scope L149–156). Since the fifth design revision the
  supervisor makes no stateful judgement: what is assumed of it is only that it lets a new epoch start
  after the kernel reports the old cell's domain empty (its exclusive cgroup, after `cgroup.kill`, reporting
  `populated 0`; a pid-namespace reap is excluded as this fact, conn L933–934) and the E-08 store gate holds,
  and never on an engine's or spawner's self-report (conn L930–934, L937–939). It keeps no safety-relevant
  state, so its crash or restart is assumed to delay the new epoch, not to yield an "empty" (conn L934).
  The emptiness itself is the kernel's (trusted, as above). The placement of the old engine, spawner, file
  worker and every execution in that cgroup by host init, and that no agent can leave it (no
  /sys in the sandbox, no write access to move a cgroup), are deployment preconditions the engine does not
  check (conn L935–936; rr L888–890); their failure is a T-67 input. The engine is honest but its unbuilt
  parts are `[S]`. That includes the memory safety of the frame reader and the parser, for which the design
  now names the means — a C FrameReader in `transport.c` behind FFI that writes within the Python-allocated
  buffer and returns no pointer into its own, fuzzed under ASan/UBSan as evidence rather than as the
  property, and a strictly configured Python `json` (conn L487–494).
- **AA-05 time as events.** Deadlines, grace periods and stall limits are modeled as events in one monotonic
  clock domain (K-09); their numeric values do not enter the model.
- **AA-06 D7 common abstraction.** C-LS / C-LP / C-R share one model because the agent ↔ engine leg (§5) is
  identical in all three; the `[S]` items the abstraction rests on (production S2 allow-set, E-07 plaintext
  rule, no business fd-pass in the first version) are carried, not dropped (PLAN §Frozen design revision).
  The two C-LP items PLAN carries from Stream Q are now design text: provider selection per execution is
  keyed by `execution_id` as an object reference, never by uid or `local_agent_id` (rr L386–387); the local
  model instance runs under no pool uid and belongs to no execution's process domain, a deployment
  precondition the engine does not check (rr L387–389, L886–887; its failure is a T-67 input).
- **AA-07 fragment granularity.** A fragment is one `recvmsg` return and may contain several send-origin
  segments with equal credentials; a frame is a sequence of fragments. Keep per-origin send times and
  execution membership in the ghost history; credentials are compared per receive fragment (conn L436, L462).
- **AA-08 control channel.** Records are atomic and `seq`-ordered; one epoch; no reconnect or replay (conn
  L170–172).
- **AA-09 adversary start.** The adversary begins at T-11. Only pre-exec bytes are from trusted bootstrap
  (SEALED consumed at T-08). After exec, bytes before or instead of hello are arbitrary adversary input;
  they still traverse T-21…T-25. The spawner reads only SEALED (conn L334).
- **AA-10 execution granularity.** Tasks in `P_X` (including descendant pid-namespace membership) are one
  principal by definition. Equal uid across unrelated tasks does not imply equal execution; that is an
  allocation/lifecycle condition for Step 2, not an abstraction assumption (D-GT; W2.1).
- **AA-11 policy as deployed.** S1 / S2 facts are the diagnostic policy of the 2026-09-11 run (iv L46); the
  production allow-set is `[S]` (tm D2).
- **AA-12 adversary strength.** No assumption about the model's capability; the adversary is arbitrary code
  at `u` within the envelope (scope L175–187).
- **AA-13 event-library deregistration (added in version 9).** After close step 2 deregisters an fd, the
  event library delivers no further readiness notification for that fd number; the design requires the
  property to be checked against the chosen library at implementation and the library not to be admitted
  otherwise (conn L483–484). The model takes it as given, like the other unbuilt engine parts (`[S]`);
  with `receiver_generation` (T-09, T-40 step 2) it is the design's statement on how a reused fd number
  relates to an old Channel.

## 7 Missing mappings (interfaces or claims the frozen text uses without stating their source)

- **MM-01 pid-namespace ordering — resolved 2026-10-13 (user-requested fetch).** The gate `pid1_reaped ⇒
  membership empty` is kernel semantics: `zap_pid_ns_processes` runs in PID 1's exit path before the task
  becomes a zombie and waits until every other pid of the namespace is freed; the source lines, the kernel's
  own invariant comment and the two conditions (outside-parent processes, ptrace from the parent namespace)
  now sit in kub §2.6 (paragraph added 2026-10-13, read at the pinned tag, byte-identical to upstream
  `v6.6.87`). Stream E registers it as an `[R]` item with file:line; Step 3 may use it.
- **MM-02 per-fragment credential uniformity.** "A receive return ends where the credential changes" is cited
  by file and line at the WSL tag (conn L436) and probed (conn L1263); the model relies on it as a kernel
  fact; Stream E registers it with the kernel line.
- **MM-03 send-origin resolution within a receive fragment.** A fragment may combine equal-credential
  origin segments. D-GT retains them all; same-execution is a condition to establish, not an assumption
  derived from equality of uid. Diagnostic sender_pid does not establish a unique thread or syscall.
- **MM-04 stamping on non-`sendmsg` paths — resolved together with MM-14 on 2026-10-13.**
  The evidence-only kub §2.4 addition covers the stream write paths and stamping per skb. This is the
  same source dependency as MM-14, not a second unresolved kernel question. Production S2 remains open.

- **MM-05 peer identity of the delivered fd.** The engine's checks at T-09 (type, connected, unnamed,
  `SO_PASSCRED`) do not and cannot establish that the fd's peer is the child's fd 3; the model carries this as
  AA-04 (spawner trusted). No kernel query answers it.
- **MM-06 grant lookup inputs — resolved 2026-10-18 (fourth design revision).** No agent-facing message
  carries `grant_ref`: `task_start` and `request` list no grant field (conn L511, L524–525; wire example
  L555), and a request that carries one is rejected as an unknown field (conn L4) by the strict parse, which
  admits no unknown field (conn L466–468; T-24). The engine takes the grant from the matched call's
  `TaskBinding`: the `VerifiedContext` row states that `grant_ref` comes from that binding and not from the
  message (conn L574), and the E-03 RUNNING row (conn L751), the E-06 `task_start` sentence (rr L176) and the
  E-10 adapter handoff (si L361–362; optb L72) read the same. T-30, T-33 and A-02 read accordingly. Two
  points the text leaves open are recorded. First, the outcome of that rejection: T-24 closes on an
  unknown-field failure, while conn L546–548 returns an associated error for a business request whose
  credential, schema and id can be determined; the text does not say which applies to a request whose only
  fault is a `grant_ref` field, so the model keeps both outcomes, and under either no `RequestEntry` is
  created and no subject event emitted (conn L468–469). Second, two sentences the revision did not rewrite
  still pair task and grant on the agent's side: a late request of the previous call "with the same
  task/grant" (conn L759) and a followup that keeps using a valid task/grant (si L365); the model reads both
  as the task and its binding's grant, since no request carries a grant field (conn L525).
- **MM-07 engine-side C3 / overflowuid start-up check.** Stated (conn L87–89), unbuilt (`[S]`); the model
  assumes C3 (AA-04, S13).
- **MM-08 the control-buffer half of C4 in the final receiver.** Stated as a rule (conn L454–455; optb L177
  `[U]`); the transport library's `recv_credential` was exercised (iv L48) but the product receive path is
  unbuilt. The 2026-10-18 freeze places that path in the C FrameReader of `transport.c` (conn L487–490); it
  stays unbuilt.
- **MM-09 atomicity of close steps 2–4 — resolved 2026-10-18 (second design revision).** The design now
  states that steps 1–4 run in one executor decision with no yield, step 2's `shutdown`/`close` being
  non-blocking calls (conn L870). T-40's atomicity and interleaving columns read accordingly.
- **MM-10 supervisor hand-over — stated 2026-10-19 (fifth design revision).** A new engine epoch reuses the
  uid pool only after the trusted supervisor has terminated the old engine, spawner, file worker and
  executions and confirmed the isolation domain empty (conn L930–931). The design now states the method:
  the confirmation rests on a kernel-held fact, never on an engine's or spawner's self-report — the cell's
  engine, spawner, file worker and all executions sit in one exclusive cgroup, the supervisor writes
  `cgroup.kill` and waits until `cgroup.events` reports `populated 0` (conn L931–933). The supervisor releases only on that fact
  and keeps no safety-relevant state; its crash only keeps the new epoch from starting, and after a restart
  it re-reads the kernel fact (conn L934). The rr clean-shutdown flow points at the same fact (rr L762–764),
  and the deployment-input list records the method as decided, the cgroup managed by host init
  and supplied by the deployment, with no restart recovery in the first build (rr L888–890). The E-08 store
  gate still applies (conn L937–939); `w2-recover` covers storage only (iv L59).
  What stays a deployment precondition, unchecked by the engine and a T-67 input on failure: that the cell is
  actually placed in such a cgroup by host init, and that no agent can leave it — the design's
  reasons are that the sandbox mounts no /sys and the agent has no write access to move a cgroup (conn
  L935–936). The dev-host probe the revision record cites (run 20261019T142200Z, outside the freeze) bears on
  the kernel behaviours only, not on a production placement; it did not test a task holding `CAP_SYS_ADMIN`
  or a mounted cgroup filesystem, so the no-leave precondition also rests on the S1 / C1 posture (AA-11); its
  registration is Stream E's.
  A pid-namespace reap is excluded as this fact by the design text: its result goes once to the init's
  parent, so a releasing party that restarts could not re-read it (conn L933–934; same-day amendment of the
  fifth revision, user ruling). That exclusion answers the one point an earlier draft of this version
  recorded as design unstated (the re-read after a restart in a namespace form); the probe's restart case
  exercised the cgroup form, the only one the design keeps.
  Relation recorded, not a gap: T-01 still reads only the engine's own lease state and the text still
  assigns a task left by an earlier epoch to the pool-exclusivity premise (conn L106–107); this gate is the
  stated means by which such a task is absent from the old cell at a new epoch, under its own deployment
  precondition.
- **MM-11 drained vs closed — resolved 2026-10-18 (second design revision).** Lease release now also requires
  close step 2 done (registration removed, fd closed), so the reclamation gate implies the channel is closed;
  a row that never had a Channel meets the condition trivially (conn L870–873). The stated condition is
  "closed", not "drained": unread queued skbs are not read after step 1 (T-21) and the fd is closed in the
  same decision. The design adds that step 2's discard of unsent data does not mean sent bytes were read by
  the peer (conn L873–874), an outbound matter (X-10). The qmsg observation (kub §4, N10 queued-message
  discussion) stays G4's and Step 3's to argue against this gate.
- **MM-12 numeric-uid reuse across the execution-slot gap — stated 2026-10-18 (second design revision).**
  T-45 frees the uid while the old execution's slot can still be held (`view != released`); the design
  states the two gates are independent (conn L206–208) and now also that a new row binds neither that slot
  nor any object in it (conn L101–102), and, at spawner admission, that a terminal record awaiting storage
  release no longer occupies the uid and lease (conn L108–113). These are design statements, not an
  invariant; Step 3 decides whether to carry them as guards.
- **MM-13 `clone` clause of S1 and the ambient/permitted clear.** Man-page-derived and unexercised (optb
  L264–271; scope S1); the model treats S1 as deployed (AA-11).
- **MM-14 alternate write paths into fd 3 — kernel half resolved 2026-10-13 (user-requested fetch).** At
  the pinned tag every write syscall into a `SOCK_STREAM` AF_UNIX socket (`write` / `writev`, `send` /
  `sendto`, `sendmsg` / `sendmmsg`, `splice`, `sendfile`, and the `MSG_OOB` byte) reaches
  `unix_stream_sendmsg` or `queue_oob`, each of which stamps every skb through `maybe_add_creds`; `vmsplice`
  fills only a pipe. Source lines in kub §2.4 (paragraph added 2026-10-13). What remains is not a kernel
  question: whether the production allow-set admits those calls is the S2 `[S]` item already carried
  (AA-11); T-64's outcome column reads accordingly.
- **MM-15 `receiver_generation` semantics — resolved 2026-10-18 (second design revision).** Named in the
  `Channel` object and the label (conn L81, L572); the design now states that the executor sets it at
  install to the next value of a counter that increases monotonically within the engine epoch, one per
  Channel and never carried over, and that it is void after close step 2's deregistration, after which the
  fd number may be reused (conn L103–105). This matches the version-8 reading "one per Channel object".
- **MM-16 `local_agent_id` assignment and consumer keying (added in version 7, addendum F-06) — resolved
  2026-10-18 (second design revision).** The field sits in the `Execution` row, the `VerifiedContext` and
  the E-09 `verified_subject` (conn L79, L572; si L93). The design now states that the executor writes it
  once at row creation (conn L95–97), that a recurring name brings no state (conn L101), that every consumer
  step reaches the `VerifiedContext` by object reference and neither looks it up nor keys state by name, uid,
  fd or `local_agent_id` (conn L581–583), and, for the two keyed consumers it names, that provider selection
  is keyed by `execution_id` (rr L386–387) and the tool definitions are reached through the
  RequestEntry → Session → Execution → LaunchPlan chain, never by uid or `local_agent_id` (rr L245–247).
  The version-8 reading — a label field written once at T-01 and carried by reference — is now design
  text; Step 2's selector q30 (a lookup by the name after reuse) names a departure from it.
- **MM-17 the `hello` value of `Channel.phase` (added in version 7, addendum F-07).** The frozen text names
  the phase (conn L81, L341, L430) but states no event that moves a `Channel` from `bootstrap-handoff` to
  `hello`; T-09 sets the first value and T-12 the `data` value. Since 2026-10-18 the design names the writer
  (the executor advances `phase`, conn L81) but still not the event. The model reads the move as the whole
  COMMIT send (T-10), the last trusted write on the channel; recorded, not resolved.
- **MM-18 the workspace check under the looser spawner-admission reading (added in version 9).** The third
  design revision lets a `SpawnRecord` that has sent `execution_empty` and awaits its storage release stop
  occupying its uid and lease at spawner admission, and keeps it a live object for control and storage
  (conn L108–113). The spawner's separate workspace check requires "no local active `SpawnRecord`" for the
  workspace (rr L65), and with the static workspace ↔ uid map the only successor of that uid is the same
  workspace's next execution. Whether such a record counts as active for that check is not stated. The model
  keeps both outcomes at T-03 (admission with the predecessor still live, or refusal until its storage
  release); the choice is the design's.

## 8 Attribution-irrelevant exclusions (with the reason each does not enter the model)

Rule applied: a family is excluded iff none of its transitions reads or writes the stamped credential, a
session row's `expected_uid` / channel binding, the membership set `P_X`, a `UidLease` state, or an object
reference that carries the label — except as a *trigger* of T-40, which is already a modeled transition.

- **X-01 RuntimeCopy, storage budget, file worker, `runtime_status`** (conn L184–256; rr E-08 runtime
  lifecycle). Never produces `membership_empty`, never frees a uid (conn L156, L205–206); `retained` is a
  T-40 trigger and `released` gates the execution slot (T-45 note), both already modeled.
- **X-02 E-03 capacity, round-robin, backpressure, output quotas** (conn L773–799). Liveness and bounded
  work; affects *when* T-21/T-26 run, not what they bind. Stream Q may reopen it for interleaving.
- **X-03 E-04 effect classification and the no-retry rule** (conn L959–993). Concerns external effects after
  D-ACC; the label is fixed before.
- **X-04 E-07 HTTP / SSE / libcurl mapping and completion evidence** (rr L392–507). Downstream of T-33; the
  label travels by object reference (T-34). Native tool calling of 2026-10-18 falls here and is considered
  and not modeled: the `model.generate` schema and `tool_choice` (rr L359), the outbound mapping, profiles
  and `llama-chat-tools` fixed fields (rr L397, L403–405, L408–416), the format-only check of returned tool
  calls with its own tool-call id type and number limits (rr L374–386), SSE `delta.tool_calls` assembly
  and its buffer (rr L453–462, L833), the success condition and completion evidence (rr L469–471, L475,
  L478), the tool-call value carried across the release barrier and committed once (rr L483, L487), the
  descriptor budgets on the mapped form (rr L95–96), the heading and link changes (rr L304, L354) and the
  provider-surface paragraph (optb L349–361). None reads or writes the stamped credential, a session row's
  binding, `P_X` or a lease; the operation keeps its label by reference.
- **X-05 E-09 export, receipts, hook payload borrowing, failure latch internals** (si L138–195). Consumer of
  the label; only the emission with `verified_subject` and the latch's close trigger are kept (T-38). The
  tool-call fields of `completion`, the `terminal_value` part of `post_read` and of hook payload borrowing
  (si L98, L120, L154) add record content, not a subject source.
- **X-06 E-10 registry, `LaunchPlan`, Node/Pi adapter internals, workspace shell** (si L242–346, L387–700).
  Static trusted inputs to T-03 or agent-side code (adversary); the only modeled facts are fd 3 and the S2
  obligations (§5). The 2026-10-18 tool-definition artefact and its digest checks (si L413–419, L430), the
  Node receiver's result value (si L476–477), the Pi native-tool-calling bridge (si L234, L496–572) and the
  acceptance-table rows (si L707–708) fall here.
- **X-07 E-05 business catalog and document loading** (rr L79–127). Resource identity, not caller identity.
- **X-08 E-08 provider leases, workspace layout and re-mount** (rr L566–604, L606–898). Only the
  `WorkspaceLease` precondition of T-01 and the `workspace_uid` static map enter (T-01, T-45), and, since
  2026-10-18, the local-instance deployment precondition (rr L818–819, L886–887; AA-06, T-67) and the
  supervisor method, stated since 2026-10-19 (rr L762–764, L888–890; MM-10). The local-instance
  cache-isolation requirements, now deployment preconditions (rr L812–816), are considered and not modeled: they bear on what one execution's model call
  can learn from another's, not on the label.
- **X-09 E-06 grant rule content, operation freezing, `argument_hash`** (rr L204–262). Consumer: decides
  *what* the labelled execution may do; CRA-F32 is a separate parked obligation. Freezing the declared tool
  set into the outbound body (rr L245–247) falls here; its object-reference route is cited in MM-16. TaskBinding/Grant
  session-association creation, rebind, revoke/close and reference-safe removal are not excluded: T-39.
- **X-10 outbound confidentiality** (kub §7.4). The property is inbound attribution; what a holder of fd 3
  can *read* is a different property, owned by the descriptor derivation.
- **X-11 supervisor and recovery tooling** (iv L59; conn L930–940). Trusted for its release rule only
  (AA-04); enters only through T-49 and MM-10. Its internals, the store recovery sweep and the host init that
  manages the cell's cgroup are not modeled.
- **X-12 FAR arms and the arm3 demo engine** (mech L214, L567–580). Evidence, not design; Stream E.
- **X-13 dated supersession notes on review records (added in version 9).** The 2026-10-18 notes that mark
  text-bridge judgements in earlier review records as superseded (conn L1515–1516, L1749–1750; rr L900–901,
  L1002–1003, L1181–1182; si L721–722, L837–838, L948–949). Historical records, not design statements.

## 9 One permitted successful request (the model must represent it)

Execution X for workspace W, `u = workspace_uid(W)`:

```text
T-01 reserve (lease held, row RESERVED, expected_uid = u)
→ T-02 spawn submitted → T-03 spawner admits, copy READY
→ T-04 socketpair, PASSCRED on the engine end → T-05 clone: P_X = {PID1}
→ T-06 steps 1–10 → T-07 step 11: cred = {u,u,u}, caps ∅, seccomp
→ T-08 SEALED (spawner reads uid u, pid = child_pid) → T-09 prepared + fd → Channel, STARTING
→ T-10 COMMIT → T-11 execve (adversary begins)
→ agent writes hello: T-20(a) stamps {pid, u, g} per skb → T-21 → T-22 → T-23 (u == expected_uid)
  → T-24 D-ACC: label = (X, s_X, c_X, gen, u); hello → T-12 welcome → ACTIVE
→ T-31 task_start sent → TaskCall RUNNING
→ agent writes request{task_call_id = that id}: T-20(a) → T-21 → T-22 → T-23 → T-24 D-ACC (label X)
  → T-25 (ACTIVE, request) → T-30 admitted (task_call matches) → T-32 prepare
  → T-33 one decision: ACTIVE ∧ dispatch_open ∧ RUNNING ∧ binding/grant valid → DISPATCHED, handler.start
→ T-34 chunks / Complete → T-26 result frame → T-35 slot returned
→ agent writes task_result: T-20…T-24 (label X) → T-36 RESOLVED
→ T-47 finish → shutdown → agent bye: T-48 → T-40 (CLOSED, fd closed, stop sent)
→ T-41 SIGKILL PID1 (idempotent if already exited) → T-42 P_X empty → T-43 execution_empty
→ T-45 lease free; a later T-01 for W may reuse u under a new execution_id.
```

At both D-ACC points the label names X and the ground-truth sender is a member of `P_X` (PID 1 or a
descendant): the two definitions agree on this path. A second execution Y with its own `u_Y`, `P_Y` and
socketpair runs the same sequence concurrently; the model keeps the two rows, two queues and two membership
sets distinct by object, never by number.

## 10 Source correspondence (where each modeled element lives in the frozen text)

| modeled element | frozen location |
|---|---|
| objects, lease states, numbering, identity supplements (write-once fields, no inheritance, Channel link, pool-premise limit, looser spawner admission, unknown-record stop, reap errors, uid re-read) | conn L71–85, L93–130; rr L569–588 |
| control protocol and idempotence | conn L133–181 (`spawn_failed` with stage reap: L153) |
| spawn sequence, PASSCRED timing, namespaces, step 11, `execve` | optb L166–284; conn L285–355; sbx SB-01…SB-05 |
| state table and notification ordering | conn L357–375 |
| wire, per-fragment check, receive-side supplements, `VerifiedContext`, consumers by reference | conn L3–4, L418–583; kub §2.4–§2.5 |
| request states, dispatch decision, call barrier | conn L642–770; rr L165–285 |
| close, stop, reap, quarantine, release, control loss | conn L837–957 (close steps 1–4 and the release condition: L870–874; control loss and the domain-empty method: L925–945) |
| kernel capture, forge and race arguments, C1–C4, limits | kub §2–§8 |
| adversary, non-goals, kernel-breach definition, S1–S14 | scope L132–249, L453–476 |
| expected-uid rule, live-at-send, reclamation gate, one clock | mech L257–301 |
| D4 / D6 / D7 premises | tm L113–130, L156–190; rr L386–389, L886–890 (provider keying, local instance, supervisor method) |
| measured substrate and run | iv L17, L45–50 |

Nothing in this file is a route, a defence or a disposition. Step 2 derives conditions and routes from
§0–§5; Step 3 takes §3.4 and §3.5 with §6–§7 for the invariant and the bounded check; Stream E registers the
evidence behind every `[M]` / `[R]` / `[S]` tag referenced here.
