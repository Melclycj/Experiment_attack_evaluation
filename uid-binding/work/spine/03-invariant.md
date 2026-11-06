---
title: Step 3 — Invariant I of the local uid binding (statement, guard list, initial-state and goal-entailment arguments, TLC run record)
date: 2026-10-14
step: 3 of the spine (COV-3, first half)
owner: main session (Fable), executing the Step 3 plan accepted on 2026-10-14 (PLAN resume pointer)
status: R2 and cross-family addendum adjudicated candidate (version 3, change-requests CR-R2-01…37; frozen by blob id in VERSIONS.md at commit after the targeted recheck)
inventory: 01-model-inventory.md version 7, blob 7345e9c5d8face07
decomposition: 02-conditions-and-decomposition.md version 3, blob 558f035982198c7c
frozen_revision: 2026-10-12 — the ten files and blob ids in PLAN.md §Frozen design revision; kernel-uid-binding.md at the 2026-10-13 evidence-only blob 131fce72d01a5df8
reading_rule: I is a candidate under test. "Preserves" is the word of the group preservation files, not of this file. The TLC runs are bounded reachability checks of I over a lifecycle subset of 01, not inductiveness proofs and not results about the real system. The E-04 double gate is the candidate, not an assumed result. No sentence here says that anything stops a route.
vocabulary_note: CLOSED is the design's state name (01 vocabulary_note) and is not used as a coverage word; "the engine closes the fd" is the T-40 step 2 action.
---

# 03 — Invariant

Scope: the identity and lifetime conditions the lifecycle must maintain so that the per-fragment check of
G2 labels every accepted byte with the execution that sent it, written as one invariant I over the 01 state;
the argument that the initial state satisfies I; the argument that I together with the G2 check facts
entails P_acc (02 §0.1); and the record of a bounded TLC check of I on the lifecycle subset of 01. IDs are
append-only: guards `IG-nn`. Source abbreviations follow 01 (`conn`, `optb`, `kub`, `mech`, `iv`, `sbx`).
Nothing here assigns a defence or a disposition to a route, claims that any transition preserves I, or
claims correspondence of the real system to the model M-UID-2026-10-12.

Relation to the inductive method (PLAN Context (3)): the three obligations are Init ⇒ I (§3 here), I ⇒ goal
(§4 here) and I ∧ T ⇒ I′ for every transition T (the preservation files of G1–G5, using the column "must be
preserved by" of §2). The TLC run of §5 checks I on every reachable state of a bounded subset; it is a
reachability check that can refute I or exhibit a missing transition, not the inductive step.

## 1 The statement of I

### 1.1 The accepted-byte part, I_acc

For every D-ACC event a at row r (01 D-ACC) and every byte b ∈ Bytes(a) with ghost origin (task_b, send_b)
(02 §0.1), with A_r, u_r, X_r and J_r as 02 §1 defines them:

- **(i) uid at send.** The sending task's real kernel uid at the send instant equals the uid of the lease
  that row r's reservation took: u(task_b, send_b) = u_r. In the chain of 02 §3 this is the joint
  consequence of C-02 (p22: the stamp the kernel queued is the sender's real uid) with C-03 and C-04 (the
  accepted stamp renders to e_r = r(u_r), r injective); it stands in I so that the lifecycle facts (ii) and
  (iii) are stated about the same byte. It is not a reading of C-02 alone.
- **(ii) membership at send.** task_b is a member of P_Xr at send_b, membership through descendant pid
  namespaces included (C-06 p62 instantiated at the send instant for the sending task).
- **(iii) time.** send_b ∈ J_r (C-07 p71): the send instant lies between row r's reservation (T-01) and
  the release or retirement of its lease (T-45, or the end of its engine epoch at T-49) — in the model. For
  the cell assignment of 02 §4 an unreleased lease of a lost epoch keeps its interval open (02 §1,
  "open-ended while not released"), so the epoch-survivor history is R-GX-04's (D_61 ∧ q33) and not
  R-G4-01's; the model's `NewEpoch` retirement is the modelling device whose soundness is the MM-10 premise
  (version 4, change request CR-F-07).

I_acc is the conjunction (i) ∧ (ii) ∧ (iii) for every accepted byte. It states, per accepted byte, the three
facts the chain of 02 §3 establishes — the uid fact from C-02 with C-03 and C-04, the membership fact from
C-06 (p62) and the time fact from C-07 (p71). The check facts C-01 … C-05 themselves are premises of §4,
not restated in I.

### 1.2 The state part, I_state

I_state is the conjunction of the guards IG-01 … IG-13 of §2: what I_acc needs in order to be maintained
across launch, reuse, close and reclaim — the one-holder rule for a uid, the immutability of `expected_uid`,
the soundness of the empty fact and its basis, the release gate, the survival of a queued skb until the
engine closes the fd, the new-epoch rule, and the correspondence of a row's channel to its execution's
socketpair. IG-01 … IG-11 are state predicates checked by TLC; the last clause of IG-06 (one release per
lease) is an action property, IG-12 holds by construction of the model, and IG-13 is an action precondition
(the model column of §2 says which).

**I := I_acc ∧ I_state.**

### 1.3 What I does not say

- No live-at-accept premise: a sender may have exited before the engine accepts its bytes (K-06, T-65); I
  speaks about the send instant (01 §0, CR-OWN-01).
- No drain requirement: I does not require the old channel's queue to be empty before release (MM-11; 01 v9
  resolves it as the fd's close, not a drained queue: the design's release also requires close step 2, T-45). The
  queued-byte distinction is kept by IG-08's form — an open row's channel never carries a stale skb —
  together with IG-13, not by draining.
- The surviving-task distinction is IG-02: it speaks about live tasks, not about notifications received;
  the empty fact's soundness is IG-03/IG-04/IG-05 separately.
- Generations are kept apart by IG-01 (epoch of the row) and by one channel object per execution (MM-15,
  resolved in 01 v9 with this reading: one `receiver_generation` per Channel, set at install and void after
  close step 2).
- Consumer continuity (C-08) is outside I: Step 3 concerns D-ACC; the consumers are G3's P_carry (02 §3).
- Nothing about the uid changing after T-07 (T-61, T-62, T-67) or about descriptor movement (T-63) is in I;
  those are G5 and G2 inputs. The model of §5 stipulates descriptor possession (A-07) as a parameter and keeps
  every task's uid fixed at the record's uid.

## 2 The guard list

Columns: guard ID · the guard as prose · model predicate (`Invariant03.tla` operator, or "action
precondition" / "by construction" when TLC does not check it as a state predicate) · derived from (01 and 02
locations) · must be preserved by (transition IDs, by 02 §7 group) · how an MM item enters.

| guard | prose | model | derived from | must be preserved by | MM entry |
|---|---|---|---|---|---|
| IG-01 | An open row (RESERVED, PREPARING, STARTING, ACTIVE or DRAINING — the row states other than NONE and CLOSED; DRAINING is abstracted to ACTIVE in the model's `OpenRow`, §5.1) holds its lease in the live engine epoch: its allocation interval J_r is open. | `IG01`: `OpenRow(e) ⇒ lease ≠ free ∧ holder = e ∧ epochOf[e] = epoch` | 01 §1 Session/UidLease, T-01 (lease held before the row exists), T-45 (release only when CLOSED), T-49 (every row CLOSED at control loss); 02 §1 J_r, C-07 | G1: T-01, T-13, T-14; G4: T-40, T-43, T-44, T-45, T-49 | — |
| IG-02 | uid exclusivity, C-06 p62 as a state guard: every live task whose real kernel uid is the pool uid u is a member of the P_X of the execution that holds u's lease (held or quarantined); when the lease is free no such task exists. | `IG02`: `alive[e] ≠ {} ⇒ lease ≠ free ∧ holder = e` | 01 T-05/T-07 (members are created by T-05 and hold the record's uid from T-07 on; the pre-drop member has another credential, IG-10), T-42/K-02 (PID 1's death kills every member), T-43/T-45 (release after the empty fact); 02 C-06 p62, U-03, D4 (tm) | G1: T-01, T-05, T-07; G2: T-60; G4: T-41, T-42, T-43, T-44, T-45, T-49, T-65; G5: T-61, T-62, T-67 (the lifecycle subset keeps the uid fixed; the departures are G5's) | MM-10: the new-epoch action keeps IG-02 only if the supervisor's empty fact implies every old task is dead (`MM10_SupervisorFactSound`, TRUE in the runs; the FALSE branch is not run and is R-GX-04's subject) |
| IG-03 | The empty fact is sound: `membership_empty` implies P_X has no live member and `empty_basis` is set. | `IG03`: `memEmpty[e] ⇒ alive[e] = {} ∧ emptyBasis[e] ≠ none` | 01 T-14 (local basis only while nothing was sent), T-43 (spawner basis), MM-01 resolved (kub §2.6); 02 U-03 | G1: T-02 (`uncertain` never becomes a local basis), T-14; G4: T-43, T-52 (no revival from a tombstone) | MM-01 enters through IG-05 |
| IG-04 | Each basis names the event that justifies it: `pid1_reaped` only after the spawner's `waitpid` (T-42); `never_created` only for a record sealed before clone; `local_never_submitted` only while `submission = local` and no SpawnRecord exists. | `IG04` | 01 T-03 failure branch, T-14, T-42, T-43; conn E-04 table "空集合依据" | G1: T-02, T-03, T-14; G4: T-41, T-42, T-43 | — |
| IG-05 | A reaped PID 1 means the namespace is empty: `waitpid` returns PID 1's terminal state only after every other member of P_X is gone. | `IG05`: `reaped[e] ⇒ pid1Dead[e] ∧ alive[e] = {}` | 01 T-42, K-02, MM-01 (kub §2.6 `zap_pid_ns_processes` ordering, evidence-only addition of 2026-10-13) | G4: T-41, T-42 (kernel semantics; a Stream E `[R]` item with file:line) | MM-01 (resolved) |
| IG-06 | One lease, one holder: the lease is free iff it has no holder, and a holder is a reserved execution; release happens once per lease. | `IG06` | 01 §1 UidLease (`held / quarantined / free`), T-01, T-44, T-45 ("one release per lease", conn L328) | G1: T-01; G4: T-43 (the quarantine lift), T-44, T-45, T-49 | — |
| IG-07 | `expected_uid` is written once at T-01 with the lease's uid and never overwritten by an observed value. | `IG07`: `expectedUid[e] = (IF exState[e] = NONE THEN NoUid ELSE U)` | 01 §1 Session ("immutable after creation"), T-01, T-23 (no lookup of another row by the observed uid, conn L424); 02 C-03 p33 (the stored field is the comparand's source) | G1: T-01; G2: T-23, T-24 | — |
| IG-08 | The queue of an open row's installed channel holds only skbs sent while the row's interval was open, and an skb whose stamp equals the row's `expected_uid` was sent by the row's own execution. A stale skb never sits on an open row's channel. | `IG08` | 01 K-06 (an skb survives its sender until the engine reads it or closes the fd), T-04 (a new socketpair per execution), T-40 steps 1–2 (MM-09), A-07; 02 §4.1 item 3, C-01 p13, C-07 | G1: T-04, T-09; G2: T-20, T-21, T-24, T-60; G4: T-40, T-42, T-45, T-65 | MM-09: steps 1 and 2 of T-40 are separate actions in the model (01 v9 makes steps 1–4 one design decision and release follow step 2, so the model's split is more permissive than the design); MM-11: no drain condition — the queue dies with the fd (01 v9: release requires the fd's close, not a drained queue) |
| IG-09 | An installed channel belongs to a row that reached STARTING (it may since have become CLOSED) and to a live kernel socket (the engine end's reference is held). | `IG09` | 01 T-08 (record failure drops the spawner's copy before any install), T-09 (install is one decision), T-40 step 2 (the engine closes the fd once, by object and generation) | G1: T-08, T-09; G4: T-40 | MM-15: one `receiver_generation` per Channel object (resolved in 01 v9 with this reading) |
| IG-10 | Tasks exist only for a launched SpawnRecord of a reserved execution, and the uid clause holds in two halves (version 4, change request CR-F-01): (a) for every live SpawnRecord, `SpawnRecord.uid` equals the uid of the UidLease its `lease_id` names — written at T-03 from the T-02 record and never changed, preserved by the spawner's cross-check of the spawn's uid against the workspace's registered static uid before clone (si L271–272); (b) after T-07 succeeded every member's real uid is `SpawnRecord.uid`, preserved by the spawner's SEALED check (conn L292–293). In the model, with one pool uid, (a) is trivial and (b) is the `uidOf` clause; with a pool of more than one uid, (a) is the guard a T-03 miscopy would break (R-G1-06, cell D_53). Between T-05 and T-07 the single member is the trusted bootstrap at the spawner-side credential, not u (01 T-06); no byte of it reaches the engine — the spawner reads its SEALED bytes (AA-09, 01 T-08) and a pre-drop FAIL ends in record failure (01 T-07, T-13). `Launch` is the post-drop abstraction boundary: it folds T-04 … T-07 and creates the member already at u (addendum F-01). | `IG10`: `alive[e] ≠ {} ⇒ spawnRec[e] ∈ {launched, failed_after_clone} ∧ exState[e] ≠ NONE ∧ uidOf[e] = U` | 01 T-01 → T-02 → T-03 → T-05/T-07 ordering, SpawnRecord `{execution_id, lease_id, uid}` (conn L85), T-60 (a new member carries the same credential); 02 §1 first G1 preservation guard ("X_r itself was launched with A_r.uid") | G1: T-01, T-02, T-03, T-05, T-07; G2: T-60 | — |
| IG-11 | The adversary exists only for a launched record (T-11 follows T-09), and PID 1 leaves P_X only through its death. | `IG11` | 01 T-09, T-10, T-11, K-01, K-02 | G1: T-09, T-11; G4: T-41, T-42 | — |
| IG-12 | Channel correspondence: the engine end installed for row r is the engine end of the socketpair created at T-04 for X_r's SpawnRecord, and the peer end went to X_r's clone and to no other task (02 §1, second and third G1 preservation guards). | by construction: `sock[e]`, `chanInstalled[e]` and `queue[e]` are indexed by the execution; not a TLC-checked predicate | 01 T-04, T-05, T-06 step 10 (`close_range`), T-09 (one `SCM_RIGHTS` fd, type/unnamed/`SO_PASSCRED` checks), MM-05 (no kernel query establishes the peer), AA-04 (spawner trusted) | G1: T-04, T-05, T-06, T-09 | MM-05: carried as AA-04 |
| IG-13 | Acceptance reads only from an open row: every byte of a D-ACC at row r was read while r was not CLOSED — STARTING, ACTIVE or DRAINING (T-47 keeps the channel, and T-25 admits `bye`, idempotent old terminals and `cancel` in DRAINING; addendum F-02) — the check before each read of conn L413 (T-21 precondition "Channel not CLOSED", re-read before each step). A D-ACC whose last read preceded a close may finish on a CLOSED row (T-24's parse is one step after the last fragment) and carries the row's own label, which is not false attribution (02 §4.1 item 3). Of the former p72 (addendum F-01) this is the post-CLOSED half; the generation half is carried by p13 with IG-08 and IG-12 (one channel per execution); the phase half is not carried, because a phase error with the right label does not bear on attribution (02 §2, note after the table). | action precondition of `Accept`: `exState[r] ∈ {STARTING, ACTIVE}` (the model folds read and acceptance into one step and abstracts DRAINING to ACTIVE) | 01 T-21 (precondition re-read before each step), T-24, T-25, T-47, T-40 step 1 (CLOSED is terminal, conn L327) | G1: T-09; G2: T-21, T-24, T-25; G4: T-40, T-47, T-48 | MM-09: the window between steps 1 and 2 is modeled; no read occurs in it — on the reading that the pre-read check of conn L413 consults the original Session held by the FrameReader (conn L409–410), whose state is CLOSED from T-40 step 1. Under the other reading (the Channel's phase, set at step 2) a read in the window would carry the row's own label while the row still holds its lease (IG-02 at the send instant), so P_acc is unaffected but IG-13's letter needs the first reading (version 4, change request CR-F-04; G4 preservation row T-40). 01 v9 resolves MM-09 and states the first reading: steps 1–4 of T-40 are one executor decision (conn L870) and the pre-read check is `Session.admission` not CLOSED (T-21, conn L481–482), so the design has no such window; the model's window is more permissive than the design and the result carries over |

Why IG-13 makes IG-08's restriction to open rows sufficient: a byte enters a label only if it was read while
its row was open, so only the queues of open rows need the stale-skb guard; the queues of CLOSED rows may
hold skbs sent after release (the model reaches such states when release precedes the fd close, §5.4) and
nothing is read from them. The design since 01 v9 releases only after close step 2 (T-45), so those states
belong to the model's more permissive release.

## 3 Initial-state argument

The state before any T-01 is the engine's start state as read from the frozen text: no `Execution`,
`Session` or `Channel` object exists (conn L71–78); the pool's leases are read as `free` and `accepting_new`
as true — two readings, not quoted facts: rr L560–561 states the reuse precondition and conn L575 the
conditions that make `accepting_new` false, and neither names an earlier state; the spawner is pre-forked
with no `SpawnRecord` (optb L184–197; conn L96–99); no pid namespace of any execution exists (T-05 has not
run), hence no task with a pool uid under the stated premise that the pool is exclusive to this engine
(02 U-05); and no D-ACC has happened.

- I_acc holds vacuously: there is no accepted byte.
- IG-01, IG-07, IG-09, IG-10, IG-11 hold vacuously: no row is open or installed, no task exists.
- IG-02 holds: no task exists; the lease is free (the premise of U-05 is what excludes a pre-existing host
  holder of a pool uid; its failure is R-G5-06's subject, not refuted here).
- IG-03, IG-04, IG-05 hold vacuously: no empty fact, no basis, nothing reaped.
- IG-06 holds: `free` with no holder.
- IG-08, IG-12, IG-13 hold vacuously: no channel, no queue.

A second initial-like state is the start of a new engine epoch (T-49 tail, 01 MM-10): the pool restarts
free, every old row is CLOSED, the old leases are never recovered. Whether that state satisfies IG-02
rests on the supervisor's fact that the isolation domain is empty; under the premise that the fact is
sound (every old task is dead, the old spawner terminated), it is an I-state. The premise is recorded as
such and not derived (MM-10 unresolved; §5.2 parameter `MM10_SupervisorFactSound`). The other guards hold
at that state by the effects the T-49 tail states — every old row CLOSED (IG-01), the pool free with no
holder (IG-06), no installed channel and no queue in the new engine process (IG-08, IG-09), the old
executions' empty facts and bases unchanged (IG-03 … IG-05). TLC checks the initial predicate against
every invariant of the configuration (§5.4, every run).

## 4 Goal-entailment argument

Claim, in two parts, for every D-ACC event a at row r. **(1)** I_state ∧ C-01 ∧ C-02 ∧ C-03 ∧ C-04 ∧ C-05 ⇒
I_acc(a): the state guards together with the G1/G2 check facts at a yield the three per-byte facts; this is
the form the G2 preservation of I_acc at T-24 needs. **(2)** I_acc(a) ∧ C-01 p11 ∧ C-05 ⇒ P_acc(a). I is
assumed in every state of the history prefix through a — what the inductive obligations Init ⇒ I and
I ∧ T ⇒ I′ deliver — so a step below uses a guard at the send instant where it says so and at the read or
accept instant otherwise. Condition IDs are cited, not restated (02 §2).

1. Let b ∈ Bytes(a). By C-01 (p11–p13), b has an actual send origin (task_b, send_b), a current `recvmsg`
   witness, and that witness belongs to row r's original channel and generation; by IG-13 the skb
   containing b was read while row r was not CLOSED (STARTING, ACTIVE or DRAINING), from the queue of its
   installed channel.
2. **(iii) send_b ∈ J_r.** By IG-08 at the read instant, every skb on an open row's channel was sent while
   that row's interval was open; so send_b ∈ J_r. (IG-01 gives the same at the read instant; IG-08 carries
   it back to the send instant, which is what C-07 p71 asks.)
3. **(i) u(task_b, send_b) = u_r.** By C-03 (p31–p33) and C-04 (p41–p42), the accepted stamp rendered to
   v(f(b)) = e_r = r(u_r), and r is injective on the relevant uids; so the queued stamp k(b) is u_r. By
   C-02 p22 (the kernel stamps the sender's real uid at send, T-20 (a), kub §2.4), k(b) = u(task_b,
   send_b); so u(task_b, send_b) = u_r. This step uses check facts only; it is the uid part of the 02 §3
   chain. In the model it is the receive relation of `Accept`: the stamp is the sender's `uidOf`, and
   acceptance requires it to equal `expectedUid[r]`, which IG-07 ties to the lease's uid.
4. **(ii) task_b ∈ P_Xr at send_b.** At send_b the task is live (it executes the send) and by (i) its real
   uid is u_r. By IG-08 (`inJ`) the lease of u_r was held or quarantined for r at that instant, so by IG-02
   in the state at send_b every live task with uid u_r is a member of P_Xr. Hence task_b ∈ P_Xr. Steps 2–4
   give I_acc(a), part (1).
5. **Conclusion, part (2).** By 02 §1, Exec(b) is the execution whose P_X contains task_b at send_b, which is X_r by
   (ii). By C-05 (p51, p52) the label read at a is A_r's: L(a).execution = A_r.execution, and X_r is by
   definition the clone event of the SpawnRecord whose execution_id is A_r.execution. So Exec(b) =
   L(a).execution for every b, and Bytes(a) is nonempty with actual origins by C-01 p11. P_acc(a) holds.

Where descriptor possession does not enter: step 4 never uses the fact that task_b holds only its own
execution's peer end. Given IG-02 across reuse, the stamp comparison alone decides membership. In the
bounded subset of §5, which encodes neither T-01's nor T-03's own reuse checks, IG-02 across reuse rests on
the membership half of the E-04 gate (§5.4, runs 2a–2c); in the design, T-01 and T-03 carry their own
reuse checks, which G1 and G4 examine (§5.2). Nothing here establishes C-01 … C-05 — those are the G1 and
G2 check facts, taken as premises — and nothing here concerns P_carry (C-08, G3). The entailment is
relative to M-UID-2026-10-12 (01 version 7).

## 5 TLC run record

### 5.1 Action table

The lifecycle subset encoded in `Invariant03.tla` (module name `Invariant03`; the planned file name
03-invariant.tla is not a legal TLA+ module name, so the spec and its configurations live in the spine
subfolder `03-tlc`). One row per action reachable from `Next`; "stands for" lists the 01 IDs the action
folds; "touches" lists the guards whose preservation the action's owning group must argue.

| action | stands for (01 IDs) | group | touches | notes |
|---|---|---|---|---|
| `Reserve` | T-01 | G1 | IG-01, IG-02, IG-06, IG-07, IG-10 | the one free lease becomes `held` by e; `expected_uid = U` written once; `epochOf = epoch` |
| `Submit` | T-02, with the successful T-03 admission folded (the record exists at the spawner; T-03's admission checks are the relaxation of §5.2; addendum F-06) | G1 | IG-03, IG-04 | three branches: whole send (PREPARING, record at the spawner); indeterminate send with the record at the spawner (row CLOSED, waits for the empty fact); indeterminate send with no record (row CLOSED) |
| `SpawnFailBeforeClone` | T-03 failure branch; T-41 reaching an unlaunched record ("stop seals clone first") | G1 | IG-04 | the record can never clone again; `never_created` follows through `ExecutionEmpty` |
| `Launch` | T-04, T-05, T-06, T-07 folded | G1 | IG-02, IG-08, IG-10, IG-12 | P_X = {PID 1} at the record's uid; the socketpair exists; the spawner does not read the row state and launches any admitted record no stop has sealed |
| `SpawnFailAfterClone` | T-08 failure (SEALED mismatch, FAIL, EOF, deadline) | G1 | IG-09 | the spawner drops its engine-end copy; the bootstrap child is killed and reaped later |
| `Handoff` | T-09, with the successful T-08 as its folded precondition (SEALED consumed: `uid == allocated u`, `pid == child_pid` — a trusted-bootstrap fact, AA-04/AA-09; the failure branch is `SpawnFailAfterClone`; addendum F-06); T-10 and T-11 folded when the row is PREPARING; late prepared on a CLOSED row | G1 | IG-09, IG-11, IG-12, IG-13 | STARTING and the adversary begins; or the engine closes the received fd. No liveness condition on the child, as T-09 states none (version 2, R2 F-02): a handoff after PID 1 died installs a channel for an empty P_X (before handoff P_X has at most PID 1), and `execd` is set regardless — an over-approximation, since an empty P_X enables no action |
| `SpawnFailedNotice` | T-13 | G1 | IG-01 | closes a still-open row; the empty fact waits for T-43 |
| `Withdraw` | T-14 | G1 | IG-03, IG-04 | the only engine-made empty fact, allowed only while `submission = local` |
| `Accept` | T-21, T-22, T-23, T-24 as their input relation; T-12 on the first acceptance in STARTING | G2 | IG-08, IG-13, I_acc | one skb of the row's own channel; stamp = `expected_uid` → D-ACC labelled by the row (ghost `badAccept` records a foreign origin or a send outside J_r); mismatch → CLOSED (T-23 failure, T-40 step 1) |
| `Send` | T-20 (a) | G2 | IG-08 | a live member writes into channel f; the kernel stamps the sender's real uid; f = e by construction, f ≠ e only under A-07 |
| `Fork` | T-60 | G2 | IG-02, IG-10 | a new member with the same credential; allowed after PID 1's death as an over-approximation |
| `Exit` | K-01; K-02 when PID 1 exits | G4 (T-65 owner) | IG-02, IG-05, IG-11 | members die on their own exit path, asynchronously (K-04) |
| `SendExit` | T-65 | G4 | IG-08 | send then exit at once; the skb outlives the sender (K-06) |
| `CloseRow` | T-40 step 1, from any trigger (T-46, T-47 grace, T-48, T-23 failure, deadlines, T-13, T-43) | G4 | IG-01, IG-13 | CLOSED is terminal |
| `CloseFd` | T-40 step 2 | G4 | IG-08, IG-09 | the engine closes the fd once; the kernel frees the queue; the peer sees EOF |
| `SendStop` | T-40 step 4, second branch | G4 | — | the stop record reaches the spawner |
| `Kill` | T-41 | G4 | IG-02, IG-05, IG-11 | SIGKILL to PID 1 on a stop, on the spawner's own record failure after clone, or on its control-loss sweep |
| `Reap` | T-42 | G4 | IG-05 | `waitpid` returns only when every other member is gone (kub §2.6, MM-01) |
| `ExecutionEmpty` | T-43 | G4 | IG-01, IG-03, IG-04, IG-06 | matched by execution id and epoch, never by uid; closes a still-open row; a matching real empty fact lifts a quarantine in the same healthy epoch |
| `Quarantine` | T-44 | G4 | IG-06 | two alternatives (version 3, addendum F-03): the stop was sent and no empty fact arrived within the wait, or the spawner reported a kill/wait error while acting on a stop or on its own failed-record cleanup (`stopSent ∨ failed_after_clone`); timeouts and errors are events (AA-05); occupancy kept. A failed kill or wait has no modeled effect of its own: the members' survival and an unreturned `waitpid` are already behaviours of the model (`Kill` / `Reap` not taken) |
| `Release` | T-45 | G4 | IG-01, IG-02, IG-06 | once, when CLOSED and held by e; `MembershipGate ⇒ memEmpty[e]`; `MM09_ReleaseNeedsFdShut ⇒ ¬chanInstalled[e]` |
| `ControlLoss` | T-49, engine side; K-08 | G4 | IG-01, IG-06 | no new admission, every row CLOSED, an unconfirmed held lease quarantined; the spawner's sweep is `Kill` under `controlLost` |
| `NewEpoch` | T-49 tail, MM-10 | G4 | IG-01, IG-02, IG-06 | a new engine process after the supervisor's fact; pool free, old rows CLOSED, old leases never recovered, unlaunched records sealed |

Not modeled, and why: T-25 beyond the not-CLOSED distinction, T-26 and T-30 … T-39 (G3 consumers and
outbound; outside D-ACC); T-47 (DRAINING is abstracted to ACTIVE: the row keeps its channel and reads
continue — `bye`, idempotent old terminals and `cancel` per T-25 — while the admission flags it clears do not
bear on attribution) and T-48 (`bye` is a `CloseRow` trigger); the success branches of T-03 and T-08, folded
into `Submit` and `Handoff` (§5.1 rows);
T-50, T-51, T-52 (slot and callback bookkeeping, control idempotence — AA-08; no attribution state); T-61,
T-62, T-63, T-64, T-66, T-67 (G5 and G2 inputs outside the lifecycle subset: the uid never changes in the
model, descriptor movement is the parameter A07, alternate write paths stamp alike by MM-14); K-03, K-05,
K-07, K-09 (abstracted by the asynchronous action structure); K-10 (the spawner signals no reaped numeric
pid, T-41, so pid reuse has no modeled effect).

### 5.2 Abstractions, parameters and bounds

- **Bounds.** Two executions `{1, 2}` sharing one pool uid `U`, so reuse must occur; at most three tasks per
  execution (task 1 is PID 1); a receive queue of at most two skbs per channel; at most two allocation
  generations (each execution id is reserved at most once, T-45 → T-01 reuses the uid under the other id);
  at most two engine epochs. Two consequences of the one-uid bound: `Accept`'s stamp-mismatch branch (the
  T-23 failure outcome) is never exercised in this file's runs — its coverage is 0 in run 1 — and at most
  one row is open at a time; the action-level reachability of §5.4 says nothing about either. Stream Q's
  two-uid runs reach the mismatch branch (05-concurrency.md §5: partial runs 5a and 5a-t2), its run 5c
  (distinct uids, gate off) checks the cross-uid A-07 case and its run 5b (three generations of one uid)
  the two-generation collapse, each within its own bounds; the "one uid slot" and "two executions"
  collapses remain justified by prose, their runs having not finished within the time bound (version 4,
  change request CR-F-09).
- **Relaxations of the frozen text's own reuse checks.** T-01's precondition that the previous lease
  satisfied CLOSED ∧ empty (01 T-01; rr L560–565) and T-03's spawner admission checks — uid and lease unused
  in its records, the plan registered with a matching digest, `seq` expected, no active SpawnRecord for the
  workspace, storage budget (01 T-03; conn L112) — are not encoded: `Reserve` requires only `lease = free`,
  `Submit` admits any record. Both relaxations add behaviours (sound for run 1). 01 v9 states the looser
  occupancy reading of T-03 (a record awaiting only its storage release does not occupy uid or lease, conn
  L108–113) and keeps the workspace check's two outcomes open (MM-18); `Submit` admits any record under
  either, so the relaxation still only adds behaviours. Runs 2a–2c therefore show
  what the T-45 membership half covers in a subset where the design's two other reuse checks are absent,
  not that the design would misattribute if only that half were missing (R2 F-04; the reviewer's probe
  with a spawner occupancy check added found no Goal violation in the run-2b configuration, R2 record,
  header). G1 examines both checks; G4 their relation to T-45.
- **Receive.** One skb = one fragment = one frame (AA-07 collapse, for Stream Q); the first acceptance in
  STARTING is the hello (T-12). The stamp is the sender's real uid (T-20 (a) only; branches (b)–(f) are G2
  and G5 inputs). The G2 check logic is not modeled, only its input relation: which skbs can be on which
  row's queue, and the equality of stamp and `expected_uid`.
- **Time.** J_r is a ghost field `inJ` evaluated at the send instant (`holder = f ∧ epochOf[f] = epoch`):
  open from `Reserve` to `Release`, or to `NewEpoch`, which is the retirement event of 02 §1 in the model;
  deadlines, grace periods and the quarantine wait are nondeterministic events (AA-05).
- **Parameters** (each an 01 item that enters by name, none silently resolved): `A07` — a task may hold
  the peer end of another execution's channel (01 A-07, stipulated input; TRUE is the adversary-favourable
  setting); `MembershipGate` — the membership half of the E-04 double gate (the candidate under test);
  `MM09_ReleaseNeedsFdShut` — whether T-45 waits for T-40 step 2 (01 MM-09; FALSE lets release precede the
  fd close, the adversary-favourable reading; 01 v9 resolves MM-09 with release only after close step 2,
  T-45, conn L870–873, so the design is the TRUE setting and the FALSE runs, more permissive, carry over); `MM10_SupervisorFactSound` — whether the supervisor's fact
  implies every old task is dead (01 MM-10; TRUE in every run; FALSE not run).
- **Over-approximations** (sound for a safety property; each may only add behaviours): `Fork` after PID 1
  died (the kernel refuses new tasks in a zapped namespace; not relied on); `Launch` regardless of the
  row's state and of control loss (the spawner may not have seen the stop or the EOF yet, K-04); `Handoff`
  folds COMMIT and `execve` (a COMMIT failure would end the child without an adversary) and sets `execd`
  even when no member of P_X is alive (no action is enabled for an empty P_X).
- **Restrictions** (behaviours the model drops; a preservation file must give a reason before relying on
  one): a stop for a record the spawner never received yields no empty fact in the model, so the lease
  quarantines (the conservative reading of conn L322–323, which the design now states as a control fault,
  01 v9 T-41; a never_created answer, which the design does not state for this case, would allow release
  and reuse, histories the model does not explore); the pre-drop
  member of T-05 … T-07 (the trusted bootstrap at the spawner-side credential) is not a state of the model —
  `Launch` is the post-drop abstraction boundary, and no byte of that member reaches the engine (the spawner
  reads its SEALED bytes, AA-09 and 01 T-08; a pre-drop FAIL ends in record failure, T-07 and T-13), so I_acc
  is unaffected and IG-10's uid clause is stated for the post-drop state (addendum F-01); a wait
  error after a spontaneous PID 1 exit, with no stop and no failed record, has no quarantine path in the
  model (addendum F-03 covers the stop and failed-record cases).
- **Not modeled.** The execution slot and `runtime_copy_view` (MM-12: the branch "no transition reads the
  old slot when binding the new row" is taken by omission; G1 and G4 confirm it from T-01's reads, and 01 v9
  states it, conn L101–102); DRAINING
  as a distinct state (abstracted to ACTIVE, §5.1);
  request state; consumers.

### 5.3 Toolchain and commands

TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802) from the official `tla2tools.jar` at
`<tlaplus-dir>\tla2tools.jar` (outside the repository), Java 21.0.6; the smoke check of
2026-10-12 is in the tooling folder (`tlc-smoke/HOWTO.md`). Run from the `03-tlc` folder; `-deadlock`
disables deadlock reporting because terminal states are expected (both executions retired); `-metadir`
keeps TLC's state files out of the repository; `-coverage 1` prints action coverage.

```
java -cp <tlaplus-dir>\tla2tools.jar tlc2.TLC -config Invariant03-run1.cfg -deadlock -coverage 1 -workers 4 -metadir <scratch> Invariant03.tla
java -cp <tlaplus-dir>\tla2tools.jar tlc2.TLC -config Invariant03-run2.cfg -deadlock -workers 4 -metadir <scratch> Invariant03.tla
java -cp <tlaplus-dir>\tla2tools.jar tlc2.TLC -config Invariant03-run2-goal.cfg -deadlock -workers 4 -metadir <scratch> Invariant03.tla
java -cp <tlaplus-dir>\tla2tools.jar tlc2.TLC -config Invariant03-run2c-noA07.cfg -deadlock -workers 4 -metadir <scratch> Invariant03.tla
```

Full TLC output of each run is kept beside its configuration (`Invariant03-run1.log`, `Invariant03-run2.log`,
`Invariant03-run2-goal.log`, `Invariant03-run2c-noA07.log`); the counts below are copied from them.

### 5.4 Outcomes (2026-10-14)

| run | configuration | gate | A07 | invariants checked | result | states generated / distinct / search depth | time |
|---|---|---|---|---|---|---|---|
| 1 | `Invariant03-run1.cfg` | frozen double gate (`MembershipGate = TRUE`) | TRUE | TypeOK, Goal, IG01 … IG11 | **no violation**: "Model checking completed. No error has been found." | 1,187,676 / 152,054 / 27 | 3 s |
| 2a | `Invariant03-run2.cfg` | membership half removed (`MembershipGate = FALSE`) | TRUE | TypeOK, Goal, IG01 … IG11 | **counterexample**: "Invariant IG02 is violated", four actions after Init | 238 / 183 / 7 at the time of the violation | < 1 s |
| 2b | `Invariant03-run2-goal.cfg` | membership half removed | TRUE | TypeOK, Goal | **counterexample**: "Invariant Goal is violated", twelve actions after Init, ending in a D-ACC whose origin is the other execution | 92,902 / 28,373 / 13 at the time of the violation | < 1 s |
| 2c (supplementary, beyond the two planned runs) | `Invariant03-run2c-noA07.cfg` | membership half removed | FALSE | TypeOK, Goal | **no goal violation** within the bounds | 8,775,538 / 910,932 / 28 | 10 s |

Earlier versions of the spec: version 1 (`Handoff` with a liveness condition on PID 1, R2 F-02) gave
1,053,028 / 138,522 / 27 for run 1 and 8,626,942 / 900,780 / 28 for run 2c; version 2 (that guard dropped)
gave 1,177,356 / 150,362 / 27 and 8,677,006 / 900,780 / 28; version 3 (the kill/wait-error alternative of
`Quarantine`, addendum F-03) gives the figures above. Outcomes are unchanged across the three versions. The
run-2b trace's step 11 is `Send` or `SendExit` depending on the run (the same send by the same task, with or
without its exit); the other eleven actions are the same in every version.

`MM09_ReleaseNeedsFdShut = FALSE` and `MM10_SupervisorFactSound = TRUE` in every run.

**Run 1 action coverage** (TLC `-coverage`, from `Invariant03-run1.log`: distinct successor states :
transitions taken; the transition counts are deterministic, the distinct-successor attribution varies
between runs with four workers). Every action reachable from `Next` fired: Reserve 185:188 · Submit
541:564 · SpawnFailBeforeClone 363:2,068 · Launch 486:940 · SpawnFailAfterClone 5,101:73,284 · Handoff
5,741:19,004 · SpawnFailedNotice 422:1,316 · Withdraw 372:1,776 · Accept 2,277:16,016 · Send 14,854:201,600 ·
Fork 19,761:144,144 · Exit 3,847:166,740 · SendExit 15,255:201,600 · CloseRow 833:26,280 · CloseFd
4,303:88,908 · SendStop 5,060:31,556 · Kill 4,226:32,912 · Reap 9,059:26,708 · ExecutionEmpty
4,721:11,184 · Quarantine 5,724:23,160 · Release 4,961:11,320 · ControlLoss 43,096:99,807 · NewEpoch
865:6,600. The stamp-mismatch branch of `Accept` has no coverage in this run (§5.2, one-uid bound; Stream Q's
two-uid runs reach it, 05-concurrency.md §5).

Counts at a violation vary between runs with four workers; the traces did not between reruns of the same
version (the R2 reviewer reproduced the version-1 traces and the recheck the version-2 traces action by
action, R2 record).

**Run 2a trace** (IG-02): `Reserve(1)` → `Submit(1)` takes its second branch: an indeterminate send whose
record reached the spawner, so the row is CLOSED at once and waits for the empty fact → `Launch(1)` (P_X1 =
{PID 1} at uid U) → `Release(1)` (the row is CLOSED and the lease held; with the membership half removed
nothing else is required) → the lease is free while P_X1 has a live member. In this subset the membership
half is what keeps IG-02 on the indeterminate-submission path of T-02.

**Run 2b trace** (Goal): `Reserve(1)` → `Submit(1)` whole send → `Launch(1)` → `Handoff(1)` (row 1 STARTING,
the adversary of execution 1 begins) → `CloseRow(1)` (any trigger) → `Release(1)` (gate removed; PID 1 of
execution 1 is alive) → `Reserve(2)` (the same uid U, a new execution id) → `Submit(2)` → `Launch(2)`
(socketpair 2 exists) → `Send(1, PID 1 → channel 2)` or `SendExit` (A-07: the surviving member of
execution 1 writes into execution 2's channel, with or without exiting at once; the kernel stamps U; `inJ`
is true because row 2 holds the lease) → `Handoff(2)` (row 2 STARTING) → `Accept(2)` (stamp U equals row 2's `expected_uid`; the bytes are accepted as row 2's hello and
labelled execution 2; their origin is execution 1). This is the history R-G4-01 describes (D_62 q24: a
task of the prior allocation survives into J_2 and sends inside it), realised inside the subset once the
membership half is absent, T-01's and T-03's reuse checks are not encoded (§5.2) and descriptor possession
is stipulated. It is not R-GX-01, whose bytes are queued before J_r.

**Run 2c** (no A-07, gate removed): no false acceptance is reachable in the subset, because without a
foreign descriptor the surviving member of execution 1 can write only into its own channel, whose row is
CLOSED (IG-13), while execution 2's channel receives only execution 2's bytes. IG-02 is still violated in
this configuration (the run 2a trace does not use A-07). So, with the membership half removed and the two
other reuse checks not encoded, a Goal violation is reachable in the subset only with `A07 = TRUE`; IG-02
is violated either way. 02 §4.1 item 1 states the same dependence at the ledger level: descriptor possession
alone is not a failure predicate, it needs a C-06 (or C-02/C-03/C-04) failure beside it.

### 5.5 What the runs do and do not show

They show: on every reachable state of the bounded lifecycle subset, I holds under the frozen E-04 double
gate with the adversary-favourable settings `A07 = TRUE` and `MM09_ReleaseNeedsFdShut = FALSE`; the model is
not vacuous — in a subset without T-01's and T-03's reuse checks, removing the membership half yields a
uid-exclusivity violation within four actions and, with descriptor possession stipulated, a false
attribution within twelve; the initial state satisfies every checked predicate; every action of the subset
is reachable (at action level; the one-uid bound leaves T-23's failure branch unexercised, §5.2). They also show that I holds when release precedes the fd close (MM-09's
adversary-favourable branch), because nothing is read from a CLOSED row (IG-13) and a new execution gets a
new socketpair (IG-12). 01 v9 states the other ordering — release only after close step 2 (T-45; MM-09
resolved) — so the design's release is stricter than the subset's and these results carry over to it.

They do not show: inductiveness (I ∧ T ⇒ I′ is the preservation files' work, including for the transitions
the subset folds or omits); correspondence of the real system to M (01 §7 missing mappings, 01 §10); any of
the check facts C-01, C-03, C-04 or the launch facts of C-05 (inputs here), nor C-02, which the model gives
by construction (`Send` stamps the sender's own `uidOf`); anything about uid changes
after T-07 (G5); the production policy (AA-11); the MM-10 unsound branch (not run; R-GX-04); the real
`receiver_generation` event (MM-15, stated in 01 v9 with the one-per-Channel reading, is not encoded); the behaviour of fragments spanning skbs (AA-07
collapse, Stream Q). No counterexample arose under the frozen gate, so no strengthening of I and no missing
transition is returned to Step 1 or Step 2; no change request is raised by this step.

## 6 What Step 3 hands on

- **To G1 (launch and admission):** IG-07, IG-10, IG-11, IG-12 — the three launch facts of 02 §1 (X_r
  launched with A_r.uid; row r's engine end from X_r's T-04 socketpair; the peer end to X_r's clone alone)
  are IG-10 and IG-12; the indeterminate-submission branch of T-02 (run 2a) and the "stop seals clone first"
  rule (`SpawnFailBeforeClone`) are the G1 transitions IG-03/IG-04 depend on; T-01's previous-lease check
  and T-03's spawner occupancy check, which the subset does not encode (§5.2), are G1's to examine against
  IG-02 and IG-06.
- **To G4 (close and reclaim):** IG-01 … IG-06, IG-08, IG-13 and the MM-09/MM-11 reading of §5.2; the MM-10
  unsound branch (not run) for T-49; the post-CLOSED processing guard (IG-13, former p72); the D4 three-way
  sort of the PLAN's G4 row is answered against this guard list with the E-04 text as the candidate.
- **To G2 (receive and check):** IG-08's form (no stale skb on an open row's channel) and IG-13; that the
  entailment of §4 does not use descriptor possession, so under A-07 the stamp comparison carries
  membership only through IG-02 (R-G4-01; the stale-byte case R-GX-01 is IG-08's subject); the
  one-skb-one-frame collapse.
- **To G5 (boundary):** I keeps the uid fixed after T-07; every departure (T-61, T-62, T-67) is a G5 route's
  precondition against IG-02, not a counterexample to I inside the subset.
- **To Stream Q:** the collapses to justify or reopen — one skb = one frame; three tasks; queue of two; one
  uid; DRAINING abstracted to ACTIVE (T-47) with `bye` a `CloseRow` trigger (T-48); slots omitted (MM-12);
  `Fork` after PID 1's death. Stream Q's answer (2026-10-15, 05-concurrency.md §2 and §5): 24 collapses
  justified, none reopened; the two-generation collapse checked within bounds (run 5b) and the cross-uid
  A-07 case within bounds (run 5c); "one uid slot" and "two executions" justified by prose only, their runs
  5a and 5a-t2 having stopped at the time bound without a violation; no change request to I.
- **To Stream E and reconcile:** the kernel facts the model takes as given are registered — stamping on
  every write path (T-20 (a), kub §2.4) as EV-10 and EV-11, the zap ordering behind `pid1_reaped` (IG-05,
  kub §2.6) as EV-17; for the queued skb outliving its sender (K-06) the registry holds the datagram
  measurement EV-58 and no `SOCK_STREAM` source location yet, an append for reconcile.
- **To R2:** the PLAN R2 row's criteria for this file — I entails the accepted-attribution goal (§4); the
  initial-state argument (§3); the run record states bounds and outcome (§5.2, §5.4); the TLA+ encoding
  matches the lifecycle subset of 01 (§5.1 action table; `check-step3.py` in the tooling folder checks the
  ID correspondence mechanically).
