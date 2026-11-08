---------------------------- MODULE Invariant03 ----------------------------
(***************************************************************************)
(* Step 3 of the uid-binding security argument                              *)
(* (Thesis/Work/Research/uid-binding/work/spine/03-invariant.md).           *)
(*                                                                          *)
(* Lifecycle subset of the Step 1 model inventory (01-model-inventory.md,   *)
(* version 7) with the candidate invariant I of 03-invariant.md.  Families  *)
(* L (launch and admission) and C (close, stop, reap, reclaim) are encoded; *)
(* receive is one abstract action over its input relation; the adversary is *)
(* every member of P_X after T-11: it sends, forks, exits.  The action ->   *)
(* transition map is 03-invariant.md section 5.1.                           *)
(*                                                                          *)
(* This is a bounded TLC reachability check of I within the stated bounds.  *)
(* It is not an inductiveness proof, not a result about the real system,    *)
(* and the E-04 double gate is the candidate under test (MembershipGate).   *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
  Execs,                      \* execution ids; run bound {1, 2}: two executions sharing one uid slot
  Tasks,                      \* task ids inside one pid namespace P_X; run bound {1, 2, 3}; task 1 is PID 1
  MaxQ,                       \* bound on one channel's receive queue (skbs); run bound 2
  U,                          \* the one uid of the deployer's exclusive pool (model value)
  NoUid,                      \* "no uid yet" (model value)
  A07,                        \* BOOLEAN  01 A-07 stipulated: a task may hold the peer end of ANOTHER execution's channel
  MembershipGate,             \* BOOLEAN  T-45 requires membership_empty (TRUE = frozen E-04 double gate; FALSE = run-2 variant)
  MM09_ReleaseNeedsFdShut,  \* BOOLEAN  T-45 also requires T-40 step 2 done (01 MM-09 branch; FALSE = adversary-favourable)
  MM10_SupervisorFactSound    \* BOOLEAN  the supervisor's "isolation domain empty" fact implies every old task is dead (01 MM-10)

ASSUME /\ Execs \subseteq Nat /\ 0 \notin Execs
       /\ Tasks \subseteq Nat /\ 1 \in Tasks
       /\ MaxQ \in Nat
       /\ A07 \in BOOLEAN /\ MembershipGate \in BOOLEAN
       /\ MM09_ReleaseNeedsFdShut \in BOOLEAN /\ MM10_SupervisorFactSound \in BOOLEAN

VARIABLES
  (* engine objects, 01 section 1 *)
  exState,        \* Execs -> row state (01 Execution.state; DRAINING folded into ACTIVE)
  submission,     \* Execs -> spawn_submission
  memEmpty,       \* Execs -> membership_empty
  emptyBasis,     \* Execs -> empty_basis
  expectedUid,    \* Execs -> Session.expected_uid, written once at T-01
  epochOf,        \* Execs -> engine_epoch of the reservation (0 = none)
  chanInstalled,  \* Execs -> the engine holds the channel fd (installed at T-09, given up at T-40 step 2)
  stopSent,       \* Execs -> a stop record has reached the spawner (T-40 step 4, second branch)
  lease,          \* the one UidLease: "free" | "held" | "quarantined"
  holder,         \* the execution the lease is held or quarantined for; 0 when free
  epoch,          \* engine_epoch of the live engine process
  acceptingNew,   \* engine global
  controlLost,    \* the control link is lost (T-49); the old epoch is dying
  (* spawner and kernel, 01 sections 1, 3.4, 3.5 *)
  spawnRec,       \* Execs -> SpawnRecord phase
  uidOf,          \* Execs -> the real kernel uid the spawner applied at T-07 (NoUid before clone)
  alive,          \* Execs -> SUBSET Tasks: the live members of P_X
  pid1Dead,       \* Execs -> PID 1 has exited (K-02: the namespace zap has begun)
  reaped,         \* Execs -> the spawner's waitpid returned PID 1's terminal state (pid1_reaped)
  execd,          \* Execs -> T-11 happened: every member of P_X is the adversary
  sock,           \* Execs -> kernel socket of the engine end: "none" | "open" | "shut" (shut = the engine end's last reference is gone)
  queue,          \* Execs -> Seq of skb; skb = [orig: sending execution, stamp: stamped uid, inJ: send instant in J_f]
  (* ghost *)
  badAccept       \* a D-ACC accepted a byte whose origin is not the row's execution or whose send instant is outside J_r

vars == <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
          lease, holder, epoch, acceptingNew, controlLost,
          spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock, queue, badAccept>>

RowStates   == {"NONE", "RESERVED", "PREPARING", "STARTING", "ACTIVE", "CLOSED"}
Submissions == {"none", "local", "submitted", "uncertain"}
Bases       == {"none", "local_never_submitted", "never_created", "pid1_reaped"}
RecPhases   == {"none", "admitted", "failed_before_clone", "launched", "failed_after_clone"}
Skb         == [orig : Execs, stamp : {U}, inJ : BOOLEAN]

OpenRow(e) == exState[e] \in {"RESERVED", "PREPARING", "STARTING", "ACTIVE"}

\* J_f is open at this instant: f holds the one lease (held or quarantined) in the live epoch.
\* J_f runs from T-01 to T-45 release or to retirement by a new epoch (02 section 1).
InJ(f) == holder = f /\ epochOf[f] = epoch

TypeOK ==
  /\ exState \in [Execs -> RowStates]
  /\ submission \in [Execs -> Submissions]
  /\ memEmpty \in [Execs -> BOOLEAN]
  /\ emptyBasis \in [Execs -> Bases]
  /\ expectedUid \in [Execs -> {NoUid, U}]
  /\ epochOf \in [Execs -> 0..2]
  /\ chanInstalled \in [Execs -> BOOLEAN]
  /\ stopSent \in [Execs -> BOOLEAN]
  /\ lease \in {"free", "held", "quarantined"}
  /\ holder \in Execs \cup {0}
  /\ epoch \in 1..2
  /\ acceptingNew \in BOOLEAN
  /\ controlLost \in BOOLEAN
  /\ spawnRec \in [Execs -> RecPhases]
  /\ uidOf \in [Execs -> {NoUid, U}]
  /\ alive \in [Execs -> SUBSET Tasks]
  /\ pid1Dead \in [Execs -> BOOLEAN]
  /\ reaped \in [Execs -> BOOLEAN]
  /\ execd \in [Execs -> BOOLEAN]
  /\ sock \in [Execs -> {"none", "open", "shut"}]
  /\ \A e \in Execs : Len(queue[e]) <= MaxQ /\ \A i \in 1..Len(queue[e]) : queue[e][i] \in Skb
  /\ badAccept \in BOOLEAN

-----------------------------------------------------------------------------
(* Initial state: no execution exists, the pool's one uid is free, epoch 1. *)

Init ==
  /\ exState = [e \in Execs |-> "NONE"]
  /\ submission = [e \in Execs |-> "none"]
  /\ memEmpty = [e \in Execs |-> FALSE]
  /\ emptyBasis = [e \in Execs |-> "none"]
  /\ expectedUid = [e \in Execs |-> NoUid]
  /\ epochOf = [e \in Execs |-> 0]
  /\ chanInstalled = [e \in Execs |-> FALSE]
  /\ stopSent = [e \in Execs |-> FALSE]
  /\ lease = "free"
  /\ holder = 0
  /\ epoch = 1
  /\ acceptingNew = TRUE
  /\ controlLost = FALSE
  /\ spawnRec = [e \in Execs |-> "none"]
  /\ uidOf = [e \in Execs |-> NoUid]
  /\ alive = [e \in Execs |-> {}]
  /\ pid1Dead = [e \in Execs |-> FALSE]
  /\ reaped = [e \in Execs |-> FALSE]
  /\ execd = [e \in Execs |-> FALSE]
  /\ sock = [e \in Execs |-> "none"]
  /\ queue = [e \in Execs |-> << >>]
  /\ badAccept = FALSE

-----------------------------------------------------------------------------
(* Family L: launch and admission (01 section 3.1)                          *)

\* T-01 reserve: the trusted caller asks for an execution; the one free lease becomes held by e;
\* the row is RESERVED with expected_uid = U, written here and never again.
Reserve(e) ==
  /\ acceptingNew /\ ~controlLost
  /\ exState[e] = "NONE" /\ lease = "free"
  /\ exState' = [exState EXCEPT ![e] = "RESERVED"]
  /\ submission' = [submission EXCEPT ![e] = "local"]
  /\ expectedUid' = [expectedUid EXCEPT ![e] = U]
  /\ epochOf' = [epochOf EXCEPT ![e] = epoch]
  /\ lease' = "held"
  /\ holder' = e
  /\ UNCHANGED <<memEmpty, emptyBasis, chanInstalled, stopSent, epoch, acceptingNew, controlLost,
                 spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock, queue, badAccept>>

\* T-02 submit spawn, with the successful T-03 admission folded (addendum F-06): the record exists at the
\* spawner; T-03's admission checks (occupancy, plan digest, seq, workspace, budget) are not encoded
\* (03 section 5.2, relaxations).
\* Whole send: submitted, PREPARING, the spawner holds the record.  Indeterminate
\* send: uncertain and the row becomes CLOSED and waits for the spawner's empty fact (conn state table), the
\* record having reached the spawner (second disjunct) or not (third disjunct).
Submit(e) ==
  /\ exState[e] = "RESERVED" /\ submission[e] = "local" /\ ~controlLost
  /\ \/ /\ submission' = [submission EXCEPT ![e] = "submitted"]
        /\ exState' = [exState EXCEPT ![e] = "PREPARING"]
        /\ spawnRec' = [spawnRec EXCEPT ![e] = "admitted"]
     \/ /\ submission' = [submission EXCEPT ![e] = "uncertain"]
        /\ exState' = [exState EXCEPT ![e] = "CLOSED"]
        /\ spawnRec' = [spawnRec EXCEPT ![e] = "admitted"]
     \/ /\ submission' = [submission EXCEPT ![e] = "uncertain"]
        /\ exState' = [exState EXCEPT ![e] = "CLOSED"]
        /\ UNCHANGED spawnRec
  /\ UNCHANGED <<memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent, lease, holder, epoch,
                 acceptingNew, controlLost, uidOf, alive, pid1Dead, reaped, execd, sock, queue, badAccept>>

\* T-03 failure branch, or a stop that reaches the spawner before clone (conn: "stop ... seals clone
\* first"): the record can never clone again; the spawner will report never_created (T-43).
SpawnFailBeforeClone(e) ==
  /\ spawnRec[e] = "admitted"
  /\ spawnRec' = [spawnRec EXCEPT ![e] = "failed_before_clone"]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-04 socketpair + T-05 clone + T-06/T-07 drop, folded into one launch-with-uid action: P_X = {PID 1},
\* every member's real uid is the record's uid U, the peer end is held by P_X.  The spawner does not read
\* the engine's row state; it launches any admitted record that no stop has sealed.
Launch(e) ==
  /\ spawnRec[e] = "admitted" /\ ~stopSent[e]
  /\ spawnRec' = [spawnRec EXCEPT ![e] = "launched"]
  /\ sock' = [sock EXCEPT ![e] = "open"]
  /\ alive' = [alive EXCEPT ![e] = {1}]
  /\ uidOf' = [uidOf EXCEPT ![e] = U]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, pid1Dead, reaped, execd, queue, badAccept>>

\* T-08 SEALED mismatch, FAIL, EOF or deadline before handoff: record failure; the spawner drops its
\* engine-end copy; the child (still trusted bootstrap, not the adversary) is killed and reaped later.
SpawnFailAfterClone(e) ==
  /\ spawnRec[e] = "launched" /\ ~execd[e] /\ ~chanInstalled[e]
  /\ spawnRec' = [spawnRec EXCEPT ![e] = "failed_after_clone"]
  /\ sock' = [sock EXCEPT ![e] = "shut"]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, uidOf, alive, pid1Dead, reaped, execd,
                 queue, badAccept>>

\* T-09 prepared handoff, folded with T-10 COMMIT and T-11 execve when the row is PREPARING: the engine
\* installs the channel, the row is STARTING, and from here every member of P_X is the adversary.
\* The successful T-08 (SEALED consumed: uid == allocated u, pid == child_pid, a trusted-bootstrap fact)
\* is this action's folded precondition (addendum F-06); its failure branch is SpawnFailAfterClone.
\* Late prepared on a CLOSED row: the engine closes the received fd; the stop follows through SendStop.
\* T-09 states no liveness condition on the child (version 2, R2 F-02): a handoff after PID 1 died installs
\* a channel for an empty P_X (before handoff P_X holds at most PID 1); execd is set regardless
\* (over-approximation: an empty P_X enables no action).
Handoff(e) ==
  /\ spawnRec[e] = "launched" /\ ~execd[e] /\ ~chanInstalled[e] /\ sock[e] = "open"
  /\ ~controlLost
  /\ \/ /\ exState[e] = "PREPARING"
        /\ exState' = [exState EXCEPT ![e] = "STARTING"]
        /\ chanInstalled' = [chanInstalled EXCEPT ![e] = TRUE]
        /\ execd' = [execd EXCEPT ![e] = TRUE]
        /\ UNCHANGED sock
     \/ /\ exState[e] = "CLOSED"
        /\ sock' = [sock EXCEPT ![e] = "shut"]
        /\ UNCHANGED <<exState, chanInstalled, execd>>
  /\ UNCHANGED <<submission, memEmpty, emptyBasis, expectedUid, epochOf, stopSent, lease, holder, epoch,
                 acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, queue, badAccept>>

\* T-13 spawn_failed: closes a still-open row; membership_empty waits for T-43.
SpawnFailedNotice(e) ==
  /\ spawnRec[e] \in {"failed_before_clone", "failed_after_clone"} /\ OpenRow(e) /\ ~controlLost
  /\ exState' = [exState EXCEPT ![e] = "CLOSED"]
  /\ UNCHANGED <<submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent, lease,
                 holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-14 local withdrawal: the only empty fact the engine makes itself, allowed only while the spawn was
\* never sent (submission = local); from RESERVED, or from a row CLOSED before submission.
Withdraw(e) ==
  /\ submission[e] = "local" /\ exState[e] \in {"RESERVED", "CLOSED"} /\ ~memEmpty[e]
  /\ exState' = [exState EXCEPT ![e] = "CLOSED"]
  /\ memEmpty' = [memEmpty EXCEPT ![e] = TRUE]
  /\ emptyBasis' = [emptyBasis EXCEPT ![e] = "local_never_submitted"]
  /\ UNCHANGED <<submission, expectedUid, epochOf, chanInstalled, stopSent, lease, holder, epoch,
                 acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock, queue,
                 badAccept>>

-----------------------------------------------------------------------------
(* Family R, abstracted (01 section 3.2): the receive input relation only.  *)

\* T-21..T-24 at row r: one queued skb of the row's own channel is taken; if its stamp equals the row's
\* expected_uid the bytes are accepted and labelled with row r (D-ACC); in STARTING this is the hello
\* (T-12) and the row becomes ACTIVE.  A stamp mismatch closes the row (T-23 failure -> T-40 step 1).
\* The G2 check logic (framing, parse, phase) is not modeled.  The ghost records a false attribution.
Accept(r) ==
  /\ chanInstalled[r] /\ exState[r] \in {"STARTING", "ACTIVE"} /\ queue[r] # << >>
  /\ LET s == Head(queue[r]) IN
       /\ queue' = [queue EXCEPT ![r] = Tail(@)]
       /\ IF s.stamp = expectedUid[r]
            THEN /\ badAccept' = (badAccept \/ (s.orig # r) \/ ~s.inJ)
                 /\ exState' = [exState EXCEPT ![r] = "ACTIVE"]
            ELSE /\ badAccept' = badAccept
                 /\ exState' = [exState EXCEPT ![r] = "CLOSED"]
  /\ UNCHANGED <<submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent, lease,
                 holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 sock>>

-----------------------------------------------------------------------------
(* The adversary and admitted kernel events (01 section 3.5, K-01, K-06)   *)

\* T-20 (a): a live member t of P_X writes into channel f; the kernel stamps the skb with the sender's real
\* uid (uidOf[e]); the skb joins f's queue and survives the sender's death (K-06).  f = e by construction
\* (T-04..T-06, T-60); f # e only under the stipulated A-07.  The ghost field inJ records whether f's
\* allocation interval is open at the send instant.
Send(e, t, f) ==
  /\ t \in alive[e] /\ execd[e]
  /\ (f = e \/ A07)
  /\ sock[f] = "open" /\ Len(queue[f]) < MaxQ
  /\ queue' = [queue EXCEPT ![f] = Append(@, [orig |-> e, stamp |-> uidOf[e], inJ |-> InJ(f)])]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped,
                 execd, sock, badAccept>>

\* T-60: fork / clone / thread inside P_X; the new task has the same credential and is a member of P_X.
\* Over-approximation: allowed even after PID 1 died (the kernel refuses new tasks in a zapped
\* namespace; the model does not rely on that).
Fork(e, t, n) ==
  /\ t \in alive[e] /\ n \notin alive[e] /\ execd[e]
  /\ alive' = [alive EXCEPT ![e] = @ \cup {n}]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* K-01: any member exits at any instant; if PID 1 exits, the kernel zap of P_X begins (K-02) and the
\* other members die through their own Exit steps (asynchronously, K-04).
Exit(e, t) ==
  /\ t \in alive[e]
  /\ alive' = [alive EXCEPT ![e] = @ \ {t}]
  /\ pid1Dead' = [pid1Dead EXCEPT ![e] = @ \/ (t = 1)]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, reaped, execd, sock,
                 queue, badAccept>>

\* T-65: a task sends and exits at once; the queued skb outlives it (K-06).
SendExit(e, t, f) ==
  /\ t \in alive[e] /\ execd[e]
  /\ (f = e \/ A07)
  /\ sock[f] = "open" /\ Len(queue[f]) < MaxQ
  /\ queue' = [queue EXCEPT ![f] = Append(@, [orig |-> e, stamp |-> uidOf[e], inJ |-> InJ(f)])]
  /\ alive' = [alive EXCEPT ![e] = @ \ {t}]
  /\ pid1Dead' = [pid1Dead EXCEPT ![e] = @ \/ (t = 1)]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, reaped, execd, sock,
                 badAccept>>

-----------------------------------------------------------------------------
(* Family C: close, stop, reap, reclaim (01 section 3.4)                    *)

\* T-40 step 1, from any trigger (deadline, EOF T-46, bye T-48, protocol or credential failure, forced
\* stop, spawn_failed T-13, execution_empty T-43): the row is CLOSED, terminal.
CloseRow(e) ==
  /\ OpenRow(e)
  /\ exState' = [exState EXCEPT ![e] = "CLOSED"]
  /\ UNCHANGED <<submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent, lease,
                 holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-40 step 2, a later executor turn (MM-09 branch: steps 1 and 2 are separate actions): the engine
\* shuts down and closes the channel fd once; the engine end's last reference goes, so the kernel frees
\* the queue (K-06 ends here) and the peer sees EOF.
CloseFd(e) ==
  /\ exState[e] = "CLOSED" /\ chanInstalled[e]
  /\ chanInstalled' = [chanInstalled EXCEPT ![e] = FALSE]
  /\ sock' = [sock EXCEPT ![e] = "shut"]
  /\ queue' = [queue EXCEPT ![e] = << >>]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, stopSent, lease, holder,
                 epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 badAccept>>

\* T-40 step 4, second branch: a submitted or uncertain spawn with no empty fact gets one stop intent,
\* which the control writer sends; this action is the instant the stop record reaches the spawner.
SendStop(e) ==
  /\ exState[e] = "CLOSED" /\ submission[e] \in {"submitted", "uncertain"}
  /\ ~memEmpty[e] /\ ~stopSent[e] /\ ~controlLost
  /\ stopSent' = [stopSent EXCEPT ![e] = TRUE]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, lease,
                 holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-41: SIGKILL to PID 1 of P_X.  The spawner acts on a stop for a launched record, on its own record
\* failure after clone, or on its control-loss sweep.  Other members die through Exit (K-02, K-04).
Kill(e) ==
  /\ spawnRec[e] \in {"launched", "failed_after_clone"} /\ ~pid1Dead[e]
  /\ (stopSent[e] \/ spawnRec[e] = "failed_after_clone" \/ controlLost)
  /\ pid1Dead' = [pid1Dead EXCEPT ![e] = TRUE]
  /\ alive' = [alive EXCEPT ![e] = @ \ {1}]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, reaped, execd, sock,
                 queue, badAccept>>

\* T-42: the spawner's waitpid returns PID 1's terminal state.  Kernel ordering (kub 2.6, MM-01):
\* zap_pid_ns_processes makes PID 1 reapable only after every other member of P_X is gone.
Reap(e) ==
  /\ pid1Dead[e] /\ alive[e] = {} /\ ~reaped[e]
  /\ reaped' = [reaped EXCEPT ![e] = TRUE]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, execd,
                 sock, queue, badAccept>>

\* T-43 execution_empty: the spawner reports pid1_reaped or never_created; the engine matches the record
\* by execution id and epoch (never by uid), records the empty fact, closes a still-open row, and a
\* matching real empty fact in the same healthy control epoch lifts a quarantine (conn E-04 table).
ExecutionEmpty(e) ==
  /\ ~memEmpty[e] /\ ~controlLost /\ epochOf[e] = epoch
  /\ \/ /\ reaped[e]
        /\ emptyBasis' = [emptyBasis EXCEPT ![e] = "pid1_reaped"]
     \/ /\ spawnRec[e] = "failed_before_clone"
        /\ emptyBasis' = [emptyBasis EXCEPT ![e] = "never_created"]
  /\ memEmpty' = [memEmpty EXCEPT ![e] = TRUE]
  /\ exState' = [exState EXCEPT ![e] = "CLOSED"]
  /\ lease' = IF lease = "quarantined" /\ holder = e THEN "held" ELSE lease
  /\ UNCHANGED <<submission, expectedUid, epochOf, chanInstalled, stopSent, holder, epoch, acceptingNew,
                 controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock, queue, badAccept>>

\* T-44 quarantine, two alternatives (version 3, addendum F-03): the stop is sent and no empty fact arrives
\* within the wait; or the spawner reports a kill/wait error while acting on a stop or on its own
\* failed-record cleanup.  Timeouts and errors are events (AA-05).  Occupancy is kept; nothing here makes
\* the lease free.  A failed kill or wait has no effect of its own in the model: members surviving and an
\* unreturned waitpid are the behaviours in which Kill / Reap are not taken.
Quarantine(e) ==
  /\ (stopSent[e] \/ spawnRec[e] = "failed_after_clone")
  /\ ~memEmpty[e] /\ lease = "held" /\ holder = e
  /\ lease' = "quarantined"
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-45 lease release: once, when the row is CLOSED, the lease is held (not quarantined) by e, and the
\* gate under test holds.  MembershipGate is the E-04 double gate's membership half (candidate under
\* test); MM09_ReleaseNeedsFdShut is the unstated step-2 ordering (01 MM-09).
Release(e) ==
  /\ exState[e] = "CLOSED" /\ lease = "held" /\ holder = e
  /\ (MembershipGate => memEmpty[e])
  /\ (MM09_ReleaseNeedsFdShut => ~chanInstalled[e])
  /\ lease' = "free"
  /\ holder' = 0
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock,
                 queue, badAccept>>

\* T-49 control-link loss, engine side: no new admission, every row CLOSED, an unconfirmed held lease
\* quarantined.  The spawner's side is Kill under controlLost (its independent sweep).
ControlLoss ==
  /\ ~controlLost
  /\ controlLost' = TRUE
  /\ acceptingNew' = FALSE
  /\ exState' = [e \in Execs |-> IF exState[e] = "NONE" THEN "NONE" ELSE "CLOSED"]
  /\ lease' = IF lease = "held" /\ holder \in Execs /\ ~memEmpty[holder] THEN "quarantined" ELSE lease
  /\ UNCHANGED <<submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent, holder,
                 epoch, spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock, queue, badAccept>>

\* T-49 tail (01 MM-10): a new engine process in the same cell starts only on the trusted supervisor's
\* fact that the old engine, spawner and executions are terminated and the isolation domain is empty.
\* The old epoch's leases are never recovered: the pool restarts free; old rows stay CLOSED; records the
\* old spawner never cloned are sealed.  MM10_SupervisorFactSound = TRUE makes the fact imply that every
\* old task is dead; FALSE would let the fact be asserted while old tasks live (not run; R-GX-04's subject).
NewEpoch ==
  /\ controlLost /\ epoch = 1
  /\ (MM10_SupervisorFactSound => \A e \in Execs : alive[e] = {})
  /\ epoch' = 2
  /\ controlLost' = FALSE
  /\ acceptingNew' = TRUE
  /\ lease' = "free"
  /\ holder' = 0
  /\ chanInstalled' = [e \in Execs |-> FALSE]
  /\ sock' = [e \in Execs |-> IF sock[e] = "none" THEN "none" ELSE "shut"]
  /\ queue' = [e \in Execs |-> << >>]
  /\ spawnRec' = [e \in Execs |-> IF spawnRec[e] = "admitted" THEN "failed_before_clone" ELSE spawnRec[e]]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, stopSent, uidOf, alive,
                 pid1Dead, reaped, execd, badAccept>>

-----------------------------------------------------------------------------

Next ==
  \/ \E e \in Execs :
       \/ Reserve(e) \/ Submit(e) \/ SpawnFailBeforeClone(e) \/ Launch(e) \/ SpawnFailAfterClone(e)
       \/ Handoff(e) \/ SpawnFailedNotice(e) \/ Withdraw(e)
       \/ Accept(e)
       \/ CloseRow(e) \/ CloseFd(e) \/ SendStop(e) \/ Kill(e) \/ Reap(e) \/ ExecutionEmpty(e)
       \/ Quarantine(e) \/ Release(e)
       \/ \E t \in Tasks :
            \/ Exit(e, t)
            \/ \E n \in Tasks : Fork(e, t, n)
            \/ \E f \in Execs : Send(e, t, f) \/ SendExit(e, t, f)
  \/ ControlLoss
  \/ NewEpoch

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The candidate invariant I (03-invariant.md sections 1 and 2).            *)

\* I_acc, the accepted-byte part: no D-ACC accepted a byte whose sending execution differs from the
\* row's execution or whose send instant lies outside the row's allocation interval.
Goal == ~badAccept

\* IG-01 an open row holds the lease: its allocation interval is open in the live epoch.
IG01 == \A e \in Execs : OpenRow(e) => lease # "free" /\ holder = e /\ epochOf[e] = epoch

\* IG-02 uid exclusivity (02 C-06 p62 as a state guard): every live task whose real uid is U is a member of
\* the lease holder's P_X; when the lease is free no such task exists.
IG02 == \A e \in Execs : alive[e] # {} => lease # "free" /\ holder = e

\* IG-03 the empty fact is sound: membership_empty implies no live member and a stated basis.
IG03 == \A e \in Execs : memEmpty[e] => alive[e] = {} /\ emptyBasis[e] # "none"

\* IG-04 each basis names the event that justifies it (T-43 pid1_reaped / never_created, T-14 local).
IG04 == \A e \in Execs :
          /\ emptyBasis[e] = "pid1_reaped" => reaped[e]
          /\ emptyBasis[e] = "never_created" => spawnRec[e] = "failed_before_clone"
          /\ emptyBasis[e] = "local_never_submitted" => submission[e] = "local" /\ spawnRec[e] = "none"

\* IG-05 a reaped PID 1 means the namespace is empty (kub 2.6 ordering, MM-01).
IG05 == \A e \in Execs : reaped[e] => pid1Dead[e] /\ alive[e] = {}

\* IG-06 one lease, one holder: free iff no holder; a holder is a reserved execution.
IG06 == /\ (lease = "free") <=> (holder = 0)
        /\ (holder \in Execs) => exState[holder] # "NONE"

\* IG-07 expected_uid is written once at T-01 and equals the lease's uid.
IG07 == \A e \in Execs : expectedUid[e] = (IF exState[e] = "NONE" THEN NoUid ELSE U)

\* IG-08 the queue of an open row holds only skbs sent inside its interval, and a matching stamp means the
\* row's own execution sent it (the queued-byte distinction: a stale skb never sits on an open row's channel).
IG08 == \A e \in Execs : OpenRow(e) /\ chanInstalled[e] =>
          \A i \in 1..Len(queue[e]) : queue[e][i].inJ /\ (queue[e][i].stamp = expectedUid[e] => queue[e][i].orig = e)

\* IG-09 an installed channel belongs to a row that reached STARTING and to a live kernel socket.
IG09 == \A e \in Execs : chanInstalled[e] => exState[e] \in {"STARTING", "ACTIVE", "CLOSED"} /\ sock[e] = "open"

\* IG-10 tasks exist only for launched records of reserved executions, at the record's uid.
IG10 == \A e \in Execs : alive[e] # {} =>
          spawnRec[e] \in {"launched", "failed_after_clone"} /\ exState[e] # "NONE" /\ uidOf[e] = U

\* IG-11 the adversary exists only for a launched record; PID 1 leaves P_X only through its death.
IG11 == \A e \in Execs : /\ execd[e] => spawnRec[e] = "launched"
                         /\ (spawnRec[e] \in {"launched", "failed_after_clone"} /\ 1 \notin alive[e]) => pid1Dead[e]

I == Goal /\ IG01 /\ IG02 /\ IG03 /\ IG04 /\ IG05 /\ IG06 /\ IG07 /\ IG08 /\ IG09 /\ IG10 /\ IG11

=============================================================================
