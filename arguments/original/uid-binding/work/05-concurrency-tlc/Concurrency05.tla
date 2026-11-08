---------------------------- MODULE Concurrency05 ----------------------------
(***************************************************************************)
(* Stream Q follow-up of the uid-binding security argument                   *)
(* (Thesis/Work/Research/uid-binding/work/05-concurrency.md, section 5).     *)
(*                                                                          *)
(* A copy of Invariant03.tla version 3 (blob 204f383dcc147004) with ONE     *)
(* structural change and no new action: the one UidLease becomes one lease  *)
(* per pool uid, and each execution's uid is fixed by the static map        *)
(* UidOfExec (the workspace -> uid one-to-one map, resources-routing.md     *)
(* L560-565).  lease and holder are functions over Uids; Reserve takes the  *)
(* lease of UidOfExec[e]; Launch applies that uid; InJ reads the holder of  *)
(* the execution's own uid; Quarantine, Release, ExecutionEmpty,            *)
(* ControlLoss and NewEpoch act on the execution's own lease; the skb stamp *)
(* ranges over Uids; IG01, IG02, IG06, IG07, IG10 are restated per uid with *)
(* the same meaning.  Everything else is Invariant03 unchanged, so the runs *)
(* inherit its limits: a bounded TLC reachability check, not an             *)
(* inductiveness proof, not a result about the real system.                 *)
(***************************************************************************)
EXTENDS Naturals, Sequences, TLC

CONSTANTS
  Execs,                      \* execution ids; run bound {1, 2, 3} (5a, 5b, 5d) or {1, 2} (5c)
  Tasks,                      \* task ids inside one pid namespace P_X; run bound {1, 2, 3}; task 1 is PID 1
  MaxQ,                       \* bound on one channel's receive queue (skbs); run bound 2
  Uids,                       \* the pool uids of this run (model values), e.g. {U1, U2}
  U1, U2,                     \* the uid model values named by the maps below
  UidOfExec,                  \* Execs -> Uids: the static workspace -> uid map, fixed before any run
  NoUid,                      \* "no uid yet" (model value)
  A07,                        \* BOOLEAN  01 A-07 stipulated: a task may hold the peer end of ANOTHER execution's channel
  MembershipGate,             \* BOOLEAN  T-45 requires membership_empty (TRUE = frozen E-04 double gate; FALSE = variant)
  MM09_ReleaseNeedsFdShut,  \* BOOLEAN  T-45 also requires T-40 step 2 done (01 MM-09 branch; FALSE = adversary-favourable)
  MM10_SupervisorFactSound    \* BOOLEAN  the supervisor's "isolation domain empty" fact implies every old task is dead (01 MM-10)

\* The static maps the configurations select with "UidOfExec <- ...".
MapTwo      == (1 :> U1) @@ (2 :> U2) @@ (3 :> U1)     \* 5a, 5d: two uids, execution 3 reuses execution 1's uid
MapOne      == [e \in Execs |-> U1]                     \* 5b: one uid, three generations
MapDistinct == (1 :> U1) @@ (2 :> U2)                   \* 5c: two uids, no reuse

ASSUME /\ Execs \subseteq Nat /\ 0 \notin Execs
       /\ Tasks \subseteq Nat /\ 1 \in Tasks
       /\ MaxQ \in Nat
       /\ UidOfExec \in [Execs -> Uids]
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
  lease,          \* Uids -> "free" | "held" | "quarantined"   (one UidLease per pool uid)
  holder,         \* Uids -> the execution the lease is held or quarantined for; 0 when free
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
  sock,           \* Execs -> kernel socket of the engine end: "none" | "open" | "shut"
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
Skb         == [orig : Execs, stamp : Uids, inJ : BOOLEAN]

OpenRow(e) == exState[e] \in {"RESERVED", "PREPARING", "STARTING", "ACTIVE"}

\* J_f is open at this instant: f holds the lease of its own uid in the live epoch.
InJ(f) == holder[UidOfExec[f]] = f /\ epochOf[f] = epoch

TypeOK ==
  /\ exState \in [Execs -> RowStates]
  /\ submission \in [Execs -> Submissions]
  /\ memEmpty \in [Execs -> BOOLEAN]
  /\ emptyBasis \in [Execs -> Bases]
  /\ expectedUid \in [Execs -> Uids \cup {NoUid}]
  /\ epochOf \in [Execs -> 0..2]
  /\ chanInstalled \in [Execs -> BOOLEAN]
  /\ stopSent \in [Execs -> BOOLEAN]
  /\ lease \in [Uids -> {"free", "held", "quarantined"}]
  /\ holder \in [Uids -> Execs \cup {0}]
  /\ epoch \in 1..2
  /\ acceptingNew \in BOOLEAN
  /\ controlLost \in BOOLEAN
  /\ spawnRec \in [Execs -> RecPhases]
  /\ uidOf \in [Execs -> Uids \cup {NoUid}]
  /\ alive \in [Execs -> SUBSET Tasks]
  /\ pid1Dead \in [Execs -> BOOLEAN]
  /\ reaped \in [Execs -> BOOLEAN]
  /\ execd \in [Execs -> BOOLEAN]
  /\ sock \in [Execs -> {"none", "open", "shut"}]
  /\ \A e \in Execs : Len(queue[e]) <= MaxQ /\ \A i \in 1..Len(queue[e]) : queue[e][i] \in Skb
  /\ badAccept \in BOOLEAN

-----------------------------------------------------------------------------
(* Initial state: no execution exists, every pool uid is free, epoch 1.    *)

Init ==
  /\ exState = [e \in Execs |-> "NONE"]
  /\ submission = [e \in Execs |-> "none"]
  /\ memEmpty = [e \in Execs |-> FALSE]
  /\ emptyBasis = [e \in Execs |-> "none"]
  /\ expectedUid = [e \in Execs |-> NoUid]
  /\ epochOf = [e \in Execs |-> 0]
  /\ chanInstalled = [e \in Execs |-> FALSE]
  /\ stopSent = [e \in Execs |-> FALSE]
  /\ lease = [u \in Uids |-> "free"]
  /\ holder = [u \in Uids |-> 0]
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

\* T-01 reserve: the free lease of the execution's own workspace uid becomes held by e;
\* the row is RESERVED with expected_uid = that uid, written here and never again.
Reserve(e) ==
  LET u == UidOfExec[e] IN
  /\ acceptingNew /\ ~controlLost
  /\ exState[e] = "NONE" /\ lease[u] = "free"
  /\ exState' = [exState EXCEPT ![e] = "RESERVED"]
  /\ submission' = [submission EXCEPT ![e] = "local"]
  /\ expectedUid' = [expectedUid EXCEPT ![e] = u]
  /\ epochOf' = [epochOf EXCEPT ![e] = epoch]
  /\ lease' = [lease EXCEPT ![u] = "held"]
  /\ holder' = [holder EXCEPT ![u] = e]
  /\ UNCHANGED <<memEmpty, emptyBasis, chanInstalled, stopSent, epoch, acceptingNew, controlLost,
                 spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock, queue, badAccept>>

\* T-02 submit spawn, with the successful T-03 admission folded (03 section 5.2, relaxations).
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

\* T-03 failure branch, or a stop that reaches the spawner before clone.
SpawnFailBeforeClone(e) ==
  /\ spawnRec[e] = "admitted"
  /\ spawnRec' = [spawnRec EXCEPT ![e] = "failed_before_clone"]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-04 socketpair + T-05 clone + T-06/T-07 drop, folded: P_X = {PID 1} at the record's uid, which is the
\* execution's own workspace uid; the peer end is held by P_X.
Launch(e) ==
  /\ spawnRec[e] = "admitted" /\ ~stopSent[e]
  /\ spawnRec' = [spawnRec EXCEPT ![e] = "launched"]
  /\ sock' = [sock EXCEPT ![e] = "open"]
  /\ alive' = [alive EXCEPT ![e] = {1}]
  /\ uidOf' = [uidOf EXCEPT ![e] = UidOfExec[e]]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, pid1Dead, reaped, execd, queue, badAccept>>

\* T-08 failure before handoff: record failure; the spawner drops its engine-end copy.
SpawnFailAfterClone(e) ==
  /\ spawnRec[e] = "launched" /\ ~execd[e] /\ ~chanInstalled[e]
  /\ spawnRec' = [spawnRec EXCEPT ![e] = "failed_after_clone"]
  /\ sock' = [sock EXCEPT ![e] = "shut"]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, uidOf, alive, pid1Dead, reaped, execd,
                 queue, badAccept>>

\* T-09 prepared handoff, folded with T-10 COMMIT and T-11 execve when the row is PREPARING;
\* late prepared on a CLOSED row: the engine closes the received fd.
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

\* T-14 local withdrawal: the only empty fact the engine makes itself, only while submission = local.
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

\* T-21..T-24 at row r: one queued skb of the row's own channel; stamp = expected_uid -> D-ACC labelled by
\* the row (ghost records a foreign origin or a send outside J_r); mismatch -> CLOSED (T-23 failure).
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

\* T-20 (a): a live member t of P_X writes into channel f; the kernel stamps the sender's real uid.
Send(e, t, f) ==
  /\ t \in alive[e] /\ execd[e]
  /\ (f = e \/ A07)
  /\ sock[f] = "open" /\ Len(queue[f]) < MaxQ
  /\ queue' = [queue EXCEPT ![f] = Append(@, [orig |-> e, stamp |-> uidOf[e], inJ |-> InJ(f)])]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped,
                 execd, sock, badAccept>>

\* T-60: fork / clone / thread inside P_X (over-approximation: allowed after PID 1 died).
Fork(e, t, n) ==
  /\ t \in alive[e] /\ n \notin alive[e] /\ execd[e]
  /\ alive' = [alive EXCEPT ![e] = @ \cup {n}]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* K-01: any member exits at any instant; PID 1's exit begins the zap (K-02).
Exit(e, t) ==
  /\ t \in alive[e]
  /\ alive' = [alive EXCEPT ![e] = @ \ {t}]
  /\ pid1Dead' = [pid1Dead EXCEPT ![e] = @ \/ (t = 1)]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, reaped, execd, sock,
                 queue, badAccept>>

\* T-65: send then exit at once; the queued skb outlives the sender (K-06).
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

\* T-40 step 1, from any trigger: the row is CLOSED, terminal.
CloseRow(e) ==
  /\ OpenRow(e)
  /\ exState' = [exState EXCEPT ![e] = "CLOSED"]
  /\ UNCHANGED <<submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent, lease,
                 holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-40 step 2, a later executor turn: the engine closes the channel fd once; the kernel frees the queue.
CloseFd(e) ==
  /\ exState[e] = "CLOSED" /\ chanInstalled[e]
  /\ chanInstalled' = [chanInstalled EXCEPT ![e] = FALSE]
  /\ sock' = [sock EXCEPT ![e] = "shut"]
  /\ queue' = [queue EXCEPT ![e] = << >>]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, stopSent, lease, holder,
                 epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 badAccept>>

\* T-40 step 4, second branch: the stop record reaches the spawner.
SendStop(e) ==
  /\ exState[e] = "CLOSED" /\ submission[e] \in {"submitted", "uncertain"}
  /\ ~memEmpty[e] /\ ~stopSent[e] /\ ~controlLost
  /\ stopSent' = [stopSent EXCEPT ![e] = TRUE]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, lease,
                 holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-41: SIGKILL to PID 1 of P_X on a stop, a failed record after clone, or the control-loss sweep.
Kill(e) ==
  /\ spawnRec[e] \in {"launched", "failed_after_clone"} /\ ~pid1Dead[e]
  /\ (stopSent[e] \/ spawnRec[e] = "failed_after_clone" \/ controlLost)
  /\ pid1Dead' = [pid1Dead EXCEPT ![e] = TRUE]
  /\ alive' = [alive EXCEPT ![e] = @ \ {1}]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, reaped, execd, sock,
                 queue, badAccept>>

\* T-42: waitpid returns PID 1's terminal state only after every other member is gone (kub 2.6, MM-01).
Reap(e) ==
  /\ pid1Dead[e] /\ alive[e] = {} /\ ~reaped[e]
  /\ reaped' = [reaped EXCEPT ![e] = TRUE]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 lease, holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, execd,
                 sock, queue, badAccept>>

\* T-43 execution_empty: matched by execution id and epoch (never by uid); closes a still-open row; a
\* matching real empty fact in the same healthy control epoch lifts a quarantine of the execution's own lease.
ExecutionEmpty(e) ==
  LET u == UidOfExec[e] IN
  /\ ~memEmpty[e] /\ ~controlLost /\ epochOf[e] = epoch
  /\ \/ /\ reaped[e]
        /\ emptyBasis' = [emptyBasis EXCEPT ![e] = "pid1_reaped"]
     \/ /\ spawnRec[e] = "failed_before_clone"
        /\ emptyBasis' = [emptyBasis EXCEPT ![e] = "never_created"]
  /\ memEmpty' = [memEmpty EXCEPT ![e] = TRUE]
  /\ exState' = [exState EXCEPT ![e] = "CLOSED"]
  /\ lease' = IF lease[u] = "quarantined" /\ holder[u] = e THEN [lease EXCEPT ![u] = "held"] ELSE lease
  /\ UNCHANGED <<submission, expectedUid, epochOf, chanInstalled, stopSent, holder, epoch, acceptingNew,
                 controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock, queue, badAccept>>

\* T-44 quarantine of the execution's own lease (two alternatives, 03 version 3).
Quarantine(e) ==
  LET u == UidOfExec[e] IN
  /\ (stopSent[e] \/ spawnRec[e] = "failed_after_clone")
  /\ ~memEmpty[e] /\ lease[u] = "held" /\ holder[u] = e
  /\ lease' = [lease EXCEPT ![u] = "quarantined"]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 holder, epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd,
                 sock, queue, badAccept>>

\* T-45 lease release of the execution's own lease: once, when the row is CLOSED, held by e, and the gate
\* under test holds.
Release(e) ==
  LET u == UidOfExec[e] IN
  /\ exState[e] = "CLOSED" /\ lease[u] = "held" /\ holder[u] = e
  /\ (MembershipGate => memEmpty[e])
  /\ (MM09_ReleaseNeedsFdShut => ~chanInstalled[e])
  /\ lease' = [lease EXCEPT ![u] = "free"]
  /\ holder' = [holder EXCEPT ![u] = 0]
  /\ UNCHANGED <<exState, submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent,
                 epoch, acceptingNew, controlLost, spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock,
                 queue, badAccept>>

\* T-49 control-link loss, engine side: no new admission, every row CLOSED, every unconfirmed held lease
\* quarantined.
ControlLoss ==
  /\ ~controlLost
  /\ controlLost' = TRUE
  /\ acceptingNew' = FALSE
  /\ exState' = [e \in Execs |-> IF exState[e] = "NONE" THEN "NONE" ELSE "CLOSED"]
  /\ lease' = [u \in Uids |-> IF lease[u] = "held" /\ holder[u] \in Execs /\ ~memEmpty[holder[u]]
                              THEN "quarantined" ELSE lease[u]]
  /\ UNCHANGED <<submission, memEmpty, emptyBasis, expectedUid, epochOf, chanInstalled, stopSent, holder,
                 epoch, spawnRec, uidOf, alive, pid1Dead, reaped, execd, sock, queue, badAccept>>

\* T-49 tail (01 MM-10): a new engine epoch on the supervisor's fact; every pool uid restarts free.
NewEpoch ==
  /\ controlLost /\ epoch = 1
  /\ (MM10_SupervisorFactSound => \A e \in Execs : alive[e] = {})
  /\ epoch' = 2
  /\ controlLost' = FALSE
  /\ acceptingNew' = TRUE
  /\ lease' = [u \in Uids |-> "free"]
  /\ holder' = [u \in Uids |-> 0]
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
(* The candidate invariant I (03-invariant.md sections 1 and 2), per uid.  *)

\* I_acc: no D-ACC accepted a byte whose sending execution differs from the row's execution or whose send
\* instant lies outside the row's allocation interval.
Goal == ~badAccept

\* IG-01 an open row holds the lease of its own uid: its allocation interval is open in the live epoch.
IG01 == \A e \in Execs : OpenRow(e) =>
          LET u == UidOfExec[e] IN lease[u] # "free" /\ holder[u] = e /\ epochOf[e] = epoch

\* IG-02 uid exclusivity (02 C-06 p62 as a state guard): every live task at uid u is a member of the P_X
\* of the execution that holds u's lease; when u's lease is free no such task exists.
IG02 == \A e \in Execs : alive[e] # {} =>
          LET u == UidOfExec[e] IN lease[u] # "free" /\ holder[u] = e

\* IG-03 the empty fact is sound.
IG03 == \A e \in Execs : memEmpty[e] => alive[e] = {} /\ emptyBasis[e] # "none"

\* IG-04 each basis names the event that justifies it.
IG04 == \A e \in Execs :
          /\ emptyBasis[e] = "pid1_reaped" => reaped[e]
          /\ emptyBasis[e] = "never_created" => spawnRec[e] = "failed_before_clone"
          /\ emptyBasis[e] = "local_never_submitted" => submission[e] = "local" /\ spawnRec[e] = "none"

\* IG-05 a reaped PID 1 means the namespace is empty.
IG05 == \A e \in Execs : reaped[e] => pid1Dead[e] /\ alive[e] = {}

\* IG-06 one lease, one holder, per uid: free iff no holder; a holder is a reserved execution of that uid.
IG06 == \A u \in Uids : /\ (lease[u] = "free") <=> (holder[u] = 0)
                        /\ (holder[u] \in Execs) => exState[holder[u]] # "NONE" /\ UidOfExec[holder[u]] = u

\* IG-07 expected_uid is written once at T-01 and equals the lease's uid.
IG07 == \A e \in Execs : expectedUid[e] = (IF exState[e] = "NONE" THEN NoUid ELSE UidOfExec[e])

\* IG-08 the queue of an open row holds only skbs sent inside its interval, and a matching stamp means the
\* row's own execution sent it.
IG08 == \A e \in Execs : OpenRow(e) /\ chanInstalled[e] =>
          \A i \in 1..Len(queue[e]) : queue[e][i].inJ /\ (queue[e][i].stamp = expectedUid[e] => queue[e][i].orig = e)

\* IG-09 an installed channel belongs to a row that reached STARTING and to a live kernel socket.
IG09 == \A e \in Execs : chanInstalled[e] => exState[e] \in {"STARTING", "ACTIVE", "CLOSED"} /\ sock[e] = "open"

\* IG-10 tasks exist only for launched records of reserved executions, at the record's uid.
IG10 == \A e \in Execs : alive[e] # {} =>
          spawnRec[e] \in {"launched", "failed_after_clone"} /\ exState[e] # "NONE" /\ uidOf[e] = UidOfExec[e]

\* IG-11 the adversary exists only for a launched record; PID 1 leaves P_X only through its death.
IG11 == \A e \in Execs : /\ execd[e] => spawnRec[e] = "launched"
                         /\ (spawnRec[e] \in {"launched", "failed_after_clone"} /\ 1 \notin alive[e]) => pid1Dead[e]

I == Goal /\ IG01 /\ IG02 /\ IG03 /\ IG04 /\ IG05 /\ IG06 /\ IG07 /\ IG08 /\ IG09 /\ IG10 /\ IG11

=============================================================================
