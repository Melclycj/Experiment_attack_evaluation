---
role: reconcile-draft
status: superseded-as-requirement-list   # 2026-10-19 (step 4): kept as the 2026-10-15 aggregation record; promoted 2026-10-16 by the reconcile role
# header ids: aggregated 2026-10-15 from the route and preservation files at the gate ids, before the owners'
# re-reads; the spine versions of 2026-10-15/16 changed no obligation (they refine IG-10, add paths to T-41/T-44,
# a premise to T-67 and a selector to q32) — checked by the reconcile role against the re-read files, 2026-10-16 (R3 F-06).
date: 2026-10-15
based_on:
  model_blob: "7345e9c5d8face07"
  decomposition_blob: "558f035982198c7c"
  invariant_blob: "af8662ca14b83598"
  registry_blob: "b868512116d812f0"
---

# Obligations for the engine — reconcile draft

**Superseded as the requirement list (2026-10-19).** The engine requirements are in engine-requirements.md
(design folder; 14 requirements over 97 musts, derived from this file and the other step-2 sources), and
their realization in the engine prototype is recorded must by must in the engine's validation record. This file
is kept unchanged below as the 2026-10-15 aggregation; its counts and line cites refer to that date's blobs.

Aggregated from (a) section 6 "Design obligations" of all 38 route files, (b) the G4 preservation file's
§D4 obligation sentences and its "not stopped by E-04" / "design unstated" lines, (c) the G5 preservation
file's T-67 branch obligations and the deployment premises its conclusion lines name, (d) every "design
unstated" item in the open column of a preservation row. Duplicates by meaning are merged; each bullet
names the transition (T-ID with its 01 name), states the obligation in one sentence, and lists in
parentheses the route and preservation IDs that surfaced it ("G4 preservation T-45 open" = the open column
of that row; "G4 preservation §D4" = the sort table and its obligation list). Three classes, each
obligation in exactly one: **design unstated** (the frozen text must say something it does not say);
**stated but unbuilt** (the design states it and routes rely on it as `[S]`; the EV ID is cited where the
registry already carries the statement); **deployment precondition** (the engine cannot check it and a
deployment must supply it). No bullet judges difficulty or proposes a mechanism; where a route named a
candidate mechanism, only the gap it fills is recorded. Line references (conn, rr, si, sbx, optb, kub,
mech, scope, tm) follow the 01 abbreviations.

## 1 Design unstated

- **T-01 reserve** — Whether every reservation field of Execution and Session (execution_id, lease_id,
  expected_uid, local_agent_id, epoch) is written once by the executor in one decision, with no later step
  writing any of them except the state field, is stated only for expected_uid (conn L80). (R-GX-06,
  R-G1-02; G1 preservation T-01)
- **T-01 reserve** — That local_agent_id is written once at T-01 and that no consumer keys state by it is
  not stated; the frozen text names the field only in the no-inheritance rule (conn L79) (MM-16). (R-G2-10,
  R-GX-05, R-GX-06, R-G3-05; G2 preservation T-24 open; G3 conclusion lines)
- **T-01 reserve** — That the reservation cannot check for survivors of an earlier engine epoch, nor for a
  host, other-compartment or other-engine holder of a pool uid, is not stated as the precondition it is
  (conn L87–89; EV-81; U-05). (R-GX-04, R-G5-06; G4 preservation §D4; G5 preservation T-67 open, conclusion
  lines; CR-G5-01)
- **T-01 reserve / T-45 lease release and reuse** — The slot-versus-uid reuse relation — no new row binds to
  any object of an old execution, whether or not that execution's slot is still held — is design text and
  not a stated invariant (MM-12). (R-GX-06; G4 preservation T-45 open, J-06; G1 preservation T-01)
- **T-03 spawner admits spawn** — Whether "uid and lease unused in the spawner's records" counts a
  process-terminal record still awaiting its storage release is not stated (conn L112); both readings
  preserve I, the strict one at an availability cost. (R-G1-05; G1 preservation T-03 open)
- **T-07 privilege drop (step 11)** — C1's three-equal-values requirement carries no runtime check and no
  post-drop re-read in the frozen text (EV-30); the T-08 SEALED comparison (conn L289–293) checks the stamped
  uid and the child pid, so it detects a wrong real uid but not an unequal effective or saved uid, and a
  post-drop three-value verification (or equal-argument assertion) remains an obligation. (R-G5-03, R-G5-07; G5 preservation T-61 open, T-67 open)
- **T-09 prepared handoff** — That the Channel → Session link is written once at install and only ever
  cleared at T-40 step 2 is not stated. (R-GX-06)
- **T-09 prepared handoff / T-40 close_session step 2** — The event that increments receiver_generation,
  and that no callback bound to an older generation can act on a new channel, is not stated; routes read it
  as one generation per Channel object (MM-15). (G4 preservation §D4; R-GX-03, R-GX-06, R-G1-03, R-G2-04,
  R-G2-10; G1 preservation T-09 open; G2 preservation T-24 open)
- **T-21 one receive step / T-40 close_session** — Which object field the pre-read check of conn L413
  consults — the Session state set at step 1 or the Channel phase set at step 2 — is not stated, so whether
  any read can follow step 1 rests on a reading (IG-13's letter; G4 change request 1). (G4 preservation
  §D4, T-40 open, J-07; G2 preservation T-21 open; R-GX-01, R-GX-03)
- **T-21 one receive step** — Which engine paths may touch a FrameReader besides its own Channel's receiver
  is not stated: conn L574 and si L111–112 keep workers from writing Session and RequestEntry but do not
  name the FrameReader. (R-G2-11)
- **T-24 frame assembly and parse** — The memory safety of the parser and the FrameReader is not a property
  the frozen text states; it is an evidence item of the engine build (U-04). (R-G2-11)
- **T-40 close_session / T-45 lease release and reuse** — Whether the fd shut of close step 2 is a condition
  of the lease release at step 6, or whether release may precede it with correctness resting on the
  pre-read check and a fresh socketpair per execution, is not stated, and the frozen text does not say
  that the reclamation gate implies a shut-and-drained channel (MM-09, MM-11). (G4 preservation §D4, T-40
  open, T-45 open; R-G4-01, R-GX-01, R-GX-03)
- **T-41 spawner stop / T-44 quarantine** — What the spawner answers to a stop naming a record it never
  received is not stated; both readings (silence until the wait expires, or a control fault on the unknown
  id) end in quarantine, and a never_created answer, if ever added, would need its own never-cloned
  guarantee (J-05; G4 change request 2). (G4 preservation §D4, T-41 open, T-44 open, J-05; R-G4-01,
  R-GX-02; G1 preservation T-02 open)
- **T-49 control-link loss and new epoch** — How the supervisor establishes that every pid namespace of the
  old epoch is zapped before a new engine's pool restarts free — what it enumerates, by what record, and
  against what "empty" is checked — is not stated (MM-10; X-11). (G4 preservation §D4, T-49 open, J-09;
  R-GX-04)
- **T-64 naming and alternate write paths** — The production S2 allow-set — which write syscalls into fd 3,
  which asynchronous submission interfaces, and which creation and send calls the agent can reach in the
  deployed runtime — is not stated; only the diagnostic policy is measured (AA-11; EV-75, EV-92, EV-93).
  (R-G2-05, R-G2-02, R-G5-04; G2 preservation T-20 open, T-64 open)

## 2 Stated but unbuilt

- **T-01 reserve** — expected_uid is written at T-01 from the lease object in the same decision as the lease
  take, never from the request body, and is never overwritten by an observed or payload value (EV-03,
  EV-41, EV-96; conn L80, L254, L322; rr L560–561). (R-G1-02, R-G2-08; G1 preservation T-01)
- **T-01 reserve** — session, channel and lease identifiers are derived once from a never-reused
  execution_id, one of each per execution (conn L71–73). (R-G1-03, R-GX-02, R-GX-06)
- **T-01 reserve** — the reservation requires the previous lease's row to read CLOSED AND membership_empty,
  not only the allocator's free flag (rr L560–561). (R-G1-05; G1 preservation T-01)
- **T-01 reserve** — the allocator leases a workspace nothing but its registered uid, one execution per
  workspace at a time, refusing a concurrent acquire and a held or quarantined lease, and refuses to start
  on pool exhaustion rather than reuse (rr L551, L562, L564; conn L74; EV-02, EV-16). (R-G1-05; G1
  preservation T-01; G4 preservation T-44)
- **T-01 reserve** — the UidLease pool excludes 0, the overflow uid, invalid values and host identities, so
  no row's expected_uid is a sentinel (conn L78; rr L554–565). (R-G5-05, R-G1-02)
- **T-02 submit spawn** — the control writer's whole-send / indeterminate classification: an indeterminate
  send makes the row uncertain and CLOSED and sends a stop, and uncertain is never turned into a local
  basis (conn L322–323, L799–800). (G1 preservation T-02 open; R-GX-02; G4 preservation §D4)
- **T-03 spawner admits spawn** — the spawner refuses a spawn whose uid or lease is in a live SpawnRecord or
  whose workspace has an active SpawnRecord (conn L112; rr L65). (R-G1-05, R-G1-06; G1 preservation T-03)
- **T-03 spawner admits spawn** — the spawner cross-checks the spawn's uid/gid against the workspace's
  registered static uid/gid from the clean start-up directory before clone (si L271–272; sbx SC-catalog).
  (R-G1-05, R-G1-06; G1 preservation T-03, T-08)
- **T-04 create channel** — SO_PASSCRED is set on the engine end at socketpair creation before clone, with
  no later check of that ordering, so the engine-build acceptance must observe it (EV-34; kub L613–614;
  conn L257, L277). (R-G1-01, R-G2-03; G1 preservation T-04 open)
- **T-07 privilege drop (step 11)** — the S1 clone clause and the ambient/permitted clear of step 11 are
  stated and unexercised (MM-13; optb L263–268). (R-G5-04; G1 preservation T-07 open; G5 preservation T-62
  open)
- **T-08 SEALED** — the spawner reads SEALED per fragment with a control buffer and requires uid == the
  record's uid as stored at T-03 (never re-derived from the child) and pid == child_pid, failing the record
  before COMMIT on mismatch, FAIL, EOF or deadline (conn L289–295). (R-G1-06; G1 preservation T-08 open)
- **T-08 SEALED** — a FAIL emitted before the drop may carry the root uid and is a failure diagnostic only,
  never SEALED or an admission fact (conn L287–288). (R-G1-06; G1 preservation T-07)
- **T-09 prepared handoff** — the engine requires SO_PASSCRED == 1 on the delivered fd and fails the handoff
  rather than setting the option itself; the unnamed-socket and PASSCRED checks are the engine's own
  structural verification at handoff (conn L127–128; EV-76 for the P2a receiver). (R-G1-01, R-G2-03,
  R-G2-09)
- **T-09 prepared handoff** — the install keys on the row object found by execution_id, lease_id and
  engine_epoch in PREPARING, validating and installing in one decision and never by uid or fd number; on a
  CLOSED row the fd is shut, nothing is installed and a stop is registered (conn L133, L226, L231, L324,
  L334–335). (R-G1-03, R-GX-02; G1 preservation T-09)
- **T-09 prepared handoff** — every install creates a new Channel object with its own owned_fd and
  generation; no old Channel object or generation value is reused for a new fd (conn L73, L81). (R-GX-01,
  R-GX-03; G1 preservation T-09)
- **T-14 local withdrawal** — local_never_submitted is written only after the writer confirms in its own
  ownership domain that nothing was sent and the withdrawal is irreversible; an uncertain submission waits
  for the spawner's fact (conn L103–104, L323, L797–800). (R-G1-05, R-GX-02; G1 preservation T-14 open; G4
  preservation §D4)
- **T-21 one receive step** — the engine never clears PASSCRED on its end for the channel's life (conn
  L385). (R-G1-01; G1 preservation T-04)
- **T-21 one receive step** — every recvmsg supplies a control buffer sized for SCM_CREDENTIALS (C4(b),
  MM-08; EV-34), and the forbidden-API list — read, recv, stdio, MSG_PEEK, MSG_WAITALL, a second reader —
  is enforced by code structure (conn L413–418). (R-G2-01, R-G2-03, R-G5-05; G2 preservation T-21 open)
- **T-21 one receive step** — the POLLPRI/OOB outcome shuts the channel rather than resynchronising (conn
  L416–417). (R-G2-02)
- **T-21 one receive step** — every step re-initialises msghdr, iovec and the control buffer and keeps no
  decoded credential across steps (conn L414–415). (R-G2-06, R-GX-01, R-G2-03)
- **T-21 one receive step** — the reader is registered by Channel object and generation, a readiness event
  is mapped to the object that registered it and never number → object, and the pre-read check runs on
  that object before any recvmsg (conn L81, L413). (R-G2-04, R-GX-03)
- **T-22 ancillary check** — every delivered SCM_RIGHTS fd is shut under truncation before the error is
  processed (conn L419–421). (R-G2-03)
- **T-22 ancillary check** — the receive_rejected event is built without the Channel's row and carries no
  verified_subject (si L68). (R-G3-04; G2 preservation T-22)
- **T-23 fragment credential comparison** — the four header bytes pass the same comparison as body bytes
  before the length is decoded, and a frame is constructed only after every fragment passed its own
  comparison (conn L397, L422–425). (R-G2-02, R-G2-07)
- **T-23 fragment credential comparison** — pid > 0 and a non-sentinel uid are required before the
  equality, on the compare path and on the record paths (D4; EV-40; conn L422). (R-G2-03, R-G2-06, R-G5-05,
  R-G3-04; G2 preservation T-22 open, T-23 open)
- **T-23 fragment credential comparison** — the uid is decoded as unsigned uid_t with no pid lookup, and
  the pid summary is never promoted to a subject (conn L422–423, L430, L516; si L93). (R-G2-06)
- **T-23 fragment credential comparison** — the FrameReader's common-uid field stays a derived check result
  and never becomes the comparand of a later fragment (conn L397, L410). (R-G2-07)
- **T-23 fragment credential comparison** — no code path searches the session table by the observed uid or
  writes the observed value into any row; the comparison is the only identity decision, with no
  SO_PEERCRED read on the data channel and no pid consultation (conn L80, L98–99, L424, L516). (R-G2-08,
  R-G2-09, R-GX-03)
- **T-23 fragment credential comparison / T-25 phase and type gating** — exactly one comparison point sits
  on the only path from recvmsg to the buffer with no bypass on any phase or error path, and phase gating
  runs after it, never instead of it (conn L437, L486). (R-G2-13)
- **T-24 frame assembly and parse** — receive_step is the only constructor of VerifiedContext and takes
  every label field from the Channel object it was invoked on and from nothing else (conn L508–509, L515;
  EV-78). (R-G2-01, R-G2-10, R-G3-01, R-GX-06; G2 preservation T-24 open)
- **T-24 frame assembly and parse** — the FrameReader is emptied before the next header, belongs to one
  Channel object, is discarded with it and is never handed to another Channel or TaskCall (conn L409–410,
  L434–435, L438). (R-G2-04, R-GX-01)
- **T-24 frame assembly and parse** — the parser's unknown-field rejection covers identity-like fields in
  every message type (conn L427, L465). (R-G2-08)
- **T-30 admit_request** — admission takes the ValidatedRequest object and builds no context, indexing
  TaskCall and TaskBinding only through the Session object reached from the request's session_ref and
  never through an engine-wide id table (conn L517, L607, L691). (R-G3-01, R-G3-02)
- **T-33 authorize + try_dispatch** — the Grant is resolved through the TaskBinding reachable from that
  Session and a Grant whose session_id differs is refused; operation_id and OperationSummary derive from
  the entry's request_key and carried context, never from a session or grant lookup (conn L615–617; rr
  L171, L187, L230–234; si L95). (R-G3-02, R-G3-03)
- **T-33 authorize + try_dispatch / T-34 handler and callbacks / T-35 request terminal and slot return** —
  no retry or replay re-submits a stored request; a failure yields a terminal and a new request traverses
  T-20 … T-24 under its own label (conn L649, L896, L898, L906–921; rr L407). (R-G3-01)
- **T-34 handler and callbacks** — the writer is selected only by the RequestEntry's original Channel object
  and connector results apply only to the entry the sink names (conn L523, L641; rr L339–340). (R-G3-03,
  R-GX-05)
- **T-34 handler and callbacks / T-51 late callback after release** — a callback without a live RequestEntry
  yields a release and no event with a subject; after the row is CLOSED or the uid released, a late fact is
  release-only or the late-result event of the original request, applied only to the object it holds (conn
  L620–625, L656, L835–837; si L72). (R-G3-04, R-GX-05; G4 preservation T-51)
- **T-35 request terminal and slot return** — only the original entry's request slot is returned, never a
  slot to another TaskCall (conn L718). (R-GX-05)
- **T-36 task_result / call barrier / T-37 cancel** — reply_to is resolved only in the original session's
  and direction's in-flight table (conn L481–485, L697–700). (R-G3-02)
- **T-38 record emission (consumer)** — verified_subject is obtained only by copying the carried
  VerifiedContext; no event kind builds one from the row, the connection, a stored message or a rejected
  fragment; control_binding and verified_subject are distinct types; the constructor refuses a
  verified_subject on every kind not owned by the validated-request path (si L59–60, L68, L91, L93, L96,
  L99, L106). (R-G3-01, R-G3-03, R-G3-04, R-GX-05, R-G3-05)
- **T-38 record emission (consumer)** — correlation keys are copied from the objects the decision used and
  the post_read flow's destination is the original request's execution_id (si L90, L120). (R-G3-02,
  R-G3-03)
- **T-39 TaskBinding / Grant association lifecycle** — rebind or removal happens only under the stated
  guards and never selects a Grant of another session (rr L213–214, L226; conn L709–710). (R-G3-02)
- **T-40 close_session** — CLOSED is terminal: no later control event, hello or flag re-enters an open
  state (conn L327, L334–335, L577). (R-GX-02; G4 preservation T-40)
- **T-40 close_session** — step 2 removes every registration for the Channel object before the fd's close,
  shuts the fd and performs the close once by object and generation, dropping unsent frames (conn
  L791–793). (R-GX-01, R-GX-03; G4 preservation T-40)
- **T-43 execution_empty / T-52 control idempotence and tombstones** — execution_empty and every control
  record are matched by execution_id, lease_id and engine_epoch and never by uid or fd; an equal-terminal
  duplicate is ignored with no second release; an unknown id or an event beyond the window faults; no
  execution is revived from a tombstone; a basis for a row whose record was never submitted is refused
  (conn L116, L131–142, L830). (R-G4-01, R-GX-02, R-GX-03; G4 preservation T-43, T-52)
- **T-44 quarantine / T-45 lease release and reuse** — the release decision reads membership_empty only as
  written from T-43's spawner basis or T-14's local basis — never from EOF, a timeout, a kill result or a
  scan — and releases once per lease; errors and timeouts quarantine (conn L328, L834–835; EV-16).
  (R-G4-01; G4 preservation T-44, T-45)
- **T-49 control-link loss and new epoch** — on control loss a surviving spawner stops and reaps every
  SpawnRecord and exits, a new spawner's self-report lifts no old quarantine, and the supervisor takes no
  old engine's, old spawner's or new spawner's self-report as the domain-empty fact (conn L832, L859–861,
  L868). (R-GX-04; G4 preservation T-49)
- **T-50 cleanup_stalled** — the stalled entry and its references are retained, never freed or re-addressed
  (conn L875–879). (R-GX-05; G4 preservation T-50)
- **engine start (no 01 transition)** — the start-up self-check that /proc/self/uid_map is the identity map
  and the overflow uid is readable refuses service and does not substitute for S13 (conn L87–89; MM-07;
  EV-33). (R-G1-02, R-G2-06, R-G2-12, R-G5-05; G5 preservation T-67 open)
- **engine start (no 01 transition)** — the S14 per-task opt-in — prctl for the indirect-branch mitigation
  before the engine holds secrets — is stated in the S14 row and unbuilt. (R-G5-02)

## 3 Deployment precondition

- **T-01 reserve** — the exclusive uid pool: no host, other-compartment or other-engine task holds a pool
  uid, and one engine runs per pool at a time (conn L87–89; EV-81, EV-02; U-05). (R-G5-06, R-G1-05,
  R-G4-01, R-GX-02, R-GX-04; G4 preservation §D4; G5 preservation T-67 open, conclusion lines)
- **T-01 reserve** — the workspace ↔ uid directory is prepared offline by the trusted deployer, one uid per
  workspace (rr L562, L564–565). (R-G1-05; G1 preservation justification row 4, T-01 open)
- **T-07 privilege drop (step 11)** — C1: setresuid with three equal values (EV-30). (R-G5-03, R-G5-07,
  R-G1-06; G5 preservation T-61, T-67, conclusion lines)
- **T-07 privilege drop (step 11)** — the first half of C2 / S4: no CAP_SETUID in the initial user namespace
  by the cleared bounding set and no_new_privs, with the runtime and /work mounted nosuid (EV-31, EV-05;
  optb steps 3–4); R-G2-05 uses the same clear for CAP_NET_ADMIN and CAP_SYS_ADMIN (the sockmap and
  in-kernel-sender gates, EV-145, EV-146), so the clear must stay the clear of every capability.
  (R-G5-04, R-G5-07, R-G2-05; G5 preservation conclusion lines)
- **T-62 user-namespace creation and map writes** — no privileged actor writes a broader map or changes the
  agent's uid on its behalf, in particular no set-user-ID map-writing helper whose subordinate range covers
  the pool's uids is installed on the host — a condition not named in S1–S14. (R-G5-04, R-G5-07)
- **T-21 one receive step** — C3 / S13: the engine in the initial user namespace with the identity map; the
  start-up self-check cannot establish this for an arbitrary deployment (EV-33; EV-80 note). (R-G1-02,
  R-G2-06, R-G2-12, R-G5-05; G5 preservation T-67 branch d)
- **T-41 spawner stop** — CAP_KILL in the agent's user namespace for the spawner's sweep; its absence leaves
  survivors for the supervisor (conn L842–854; EV-79). (R-GX-04)
- **T-49 control-link loss and new epoch** — a trusted supervisor tracking the whole process domain that
  terminates the old engine, spawner, file worker and executions and confirms the domain empty before a new
  engine starts (conn L864–868; EV-81; X-11). (R-GX-04; G4 preservation T-49, §D4)
- **T-63 descriptor movement** — S5: the descriptor-acquisition surface (seccomp denial of pidfd_getfd and
  ptrace, ptrace_scope, DAC) under which A-07 remains a stipulated input rather than a produced state. (G2
  preservation T-63; G5 preservation T-67 branch h; R-G2-09, R-G5-06)
- **T-66 kernel breach (N1) and hardware fault (N9)** — a deployment states its build and the exposure
  items at it (tm D8), and the sysfs transient-execution readings of its production host (S14's host
  half). (R-G5-01, R-G5-02; G5 preservation T-66 open)

## 4 Counts

- design unstated: 15
- stated but unbuilt: 50
- deployment precondition: 10
