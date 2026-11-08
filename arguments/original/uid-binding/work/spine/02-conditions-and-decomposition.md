---
title: Step 2 — Sufficient conditions and false-attribution decomposition
date: 2026-10-13
step: 2 of the spine (COV-2)
owner: main Codex session (versions 1–2); main Fable session (version 3, adjudication of the cross-family addendum)
status: R1 and cross-family addendum adjudicated candidate (version 3); version 12 (2026-10-23, M1 repair): wording only — U-02 and the sixth ledger column of R-G2-11 record that its closing property's memory half is a stated requirement not established (conditional on unbuilt requirements), no ID, cell or predicate changed; version 11 (2026-10-23): one relative link re-pointed; version 10 (2026-10-19, follow-up step 4): wording only — U-02 and the sixth ledger column of R-G2-11/12/13 record that the three slots rest on their closing properties (G2 step-4 change request 1), no ID, cell or predicate changed; versions 5 and 6 (2026-10-16) adjust U-01, U-02 and the R-G2-05 ledger row text only (CR-G2-01/02); version 7 (2026-10-18): the four slot entries R-G5-06, R-G5-08, R-G3-05 and R-GX-06 re-marked after the second design freeze, no route added or retired; version 9 (2026-10-18): U-06 names the grant_ref redesign as part of the third freeze; version 8 (2026-10-18): wording of the two deployment-precondition entries aligned with the user's ruling (stated premises, no separate disposition value); no route disposition or preservation result
model: M-UID-2026-10-12, evidence-only kernel addition 2026-10-13; version 7's re-marked entries cite 01 version 9, which models the 2026-10-18 freeze
inventory: 01-model-inventory.md version 9 (blob 1461a0f9feb23817; versions recorded in VERSIONS.md)
vocabulary_note: CLOSED denotes the design state, not a coverage conclusion.
---

# 02 — Conditions and decomposition

This is a scratch derivation, not the final vector table or a deployed-security result. It derives
conditions and candidate causal routes; it does not assign defences, EV IDs, or dispositions. A route
describes what would have to go wrong for an adversary's action to be misattributed, not an observed
vulnerability. Failed predicates are not sufficient for an attack. The preservation worksheets must
decide which transitions can reach them under which premises.

Inputs read: [01](01-model-inventory.md), [group-cut input](00-group-cut-inputs.md), and the ten frozen
files named in PLAN. All ten working-tree blobs matched the
freeze, including kernel blob 131fce72d01a5df8. Source abbreviations follow 01. The load-bearing design
locations are conn E-01 objects/control/launch; E-02 receive; E-03 executor/dispatch; E-04 close/reclaim;
rr E-06/E-07; si E-09/E-10; mech Identity lifecycle; kub §§2.4–2.6, 3–8; scope Boundary Defence.
Design line numbers in this file stay on the 2026-10-12 blobs, translated by the maps in
design-revision-2026-10-18; the version-7 text (U-02, U-03, U-05,
q30, X-08 and the four re-marked ledger rows) cites 01 version 9 IDs, which model the 2026-10-18 freeze.

## 0 Property, time, principal and premises

### 0.1 Ground truth is independent of the lookup

Let X denote the spawner's execution-creation event and P_X its newly created pid namespace. For a
normal-flow byte occurrence b, origin(b) = (task_b, send_b) records the task and instant of the actual
send that queued it. Exec(b) is the unique execution whose P_X contains that task at send_b, including
membership through descendant pid namespaces; an unrelated host task has Exec(b) = outside. This is
ghost history for reasoning, not a proposed runtime /proc lookup. Neither a uid nor a session lookup
defines Exec. Separate send events remain separate even when their bytes are merged into a recvmsg.

At D-ACC (01 T-24), receive_step returns a ValidatedMessage with label L(a), read from engine objects.
Let Bytes(a) include the length header and body that caused that event. Define:

    P_acc(a) := Bytes(a) is nonempty and has actual send origins
                AND for every b in Bytes(a), Exec(b) = L(a).execution.

False attribution is an actual accepted-subject event with no such origin, or at least one contributing
byte whose Exec differs from its label. A rejected fragment's unlabelled diagnostic is not D-ACC.
The D-ACC event precedes business authorization: request_received may exist for a correctly attributed
but unauthorized request. Conversely, a correctly labelled malformed/non-admitted request says nothing
about useful task completion. The successful sequence in 01 §9 remains admitted by these conditions.

**Receive fragment is not send syscall.** A recvmsg return may contain multiple origin segments with
equal credentials (including different threads with one tgid). It is not generally one sending task at
one time. The predicate quantifies over every origin segment/byte, not a diagnostic pid or last fragment.
This refines 01 D-GT/AA-07 without changing the engine interface. Existing source conn L397–403 points
to the pinned AF_UNIX receive loop and credential comparison; the targeted source recheck on 2026-10-13
confirmed that equality governs merging, not a syscall boundary
([pinned source](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/net/unix/af_unix.c#L2618)).

### 0.2 What time and granularity do not claim

Same-execution sibling processes/threads are one principal. Two unrelated executions with the same
numeric uid are **not** made one principal: that is precisely a lifecycle/allocation failure to examine.
A task may send, die, and have its message accepted before the engine processes exit. That does not
violate P_acc if the label remains the sending execution. No live-at-accept or live-at-action guarantee
is added. Nor does P_acc identify a prompt's author or the principal on whose behalf a sender acts.

The PLAN phrase “the row's uid is held by exactly its execution when accepted” is not used as a
nonempty-current-process premise. It would reject the permitted dead-sender history, and current
ownership alone would still fail to distinguish a previous uid holder's queued bytes. C-06/C-07 below
make the required historical relation explicit. This is analysis, not an amendment to frozen design.

### 0.3 Premises and their treatment

- Adversary: arbitrary code at the assigned uid inside the constructed envelope, from T-11 onward;
  language-model capability is irrelevant (scope Boundary Defence). A-07 deliberately grants possession
  of a foreign data endpoint without claiming the deployment permits its acquisition.
- The intended configuration is the exclusive uid pool, engine in initial user namespace, C1–C4 of kub
  §6, and relevant S1–S14. Their **realization is not assumed established**: legitimate privileges,
  missing checks, and mapping/lifecycle errors are candidate configuration or implementation failures.
  The diagnostic policy is not the production policy.
- Intact kernel and no cross-domain hardware memory read/write are declared boundaries. N1 and N9
  remain visible routes. The exclusion covers arbitrary read/write/execute, not just cred edits.
  Malicious hypervisor, a deliberately malicious trusted engine/spawner, and arbitrary replacement of
  the sandbox are outside the declared actor model. Ordinary receiver/bookkeeping mistakes and
  configuration shortfalls are not erased by calling those components trusted.
- C-LS/C-LP/C-R share only the local interface abstraction of 01 AA-06, conditional on its unbuilt
  production policy, connector and no-business-fd-pass premises. Stream Q must challenge that use.
- Kernel semantics in this draft are source readings at the pinned WSL tag, not new experiments.
  Engine checks in conn are specifications, not evidence that their implementation exists.

## 1 Decision inputs and historical state

The specified decision is: obtain one nonblocking recvmsg result on the original Channel; validate
ancillary and each positive-length fragment; compare its decoded uid to that row's immutable expected
uid; assemble only validated bytes; parse the permitted message; construct the label from that same
row. Later consumers retain its object references (conn L409–439, L508–523).

| input ID | named value / state | 01 landing |
|---|---|---|
| I-01 | actual Bytes(a), origin segments, frame/header ownership and receiver path | T-20–T-24, A-01/A-02/A-05, MM-02–04/14 |
| I-02 | per-origin kernel stamp k(b), sender's real/effective/saved kernel uids and capabilities at send | T-07/T-20/T-60–T-62/T-66–T-67, A-04 |
| I-03 | receiver namespace translation r(k), decoded value v(f), actual stored comparand e_r, flags/control length/sentinel status | T-04/T-09/T-21–T-23, MM-07/08 |
| I-04 | channel object, owned fd, generation, frame buffer and selected row r | T-09/T-21–T-25/T-40/T-51, A-07, MM-05/15 |
| I-05 | the row's allocation record A_r = (exec_r, X_r, u_r, lease_r, epoch_r, session_r, channel_r, name_r) as defined below, the row's stored expected_uid field, and the launch records of this engine's spawner (which clone was launched with which uid and which socketpair end) | T-01–T-14/T-43/T-45/T-49/T-52; MM-16 |
| I-06 | actual task membership/uid sets, allocation interval J_r, control facts and lease state | T-01/T-05/T-07/T-40–T-45/T-49/T-60–T-67, K-01–K-10 |
| I-07 | comparison, D-ACC constructor, original context and consumer references at each handoff | T-23–T-25/T-30–T-39/T-51 |
| I-08 | kernel/platform producing these observations and protecting the state; policy actually loaded | T-66/T-67, scope Boundary Defence/S1–S14 |

u(task,t) means the real kernel uid at the send event. It is not a namespace-local number. f(b) is
the receive fragment containing b. k(b) is its actual queued kernel uid stamp, or absent/invalid.
r(k) renders a kernel uid in the receiving namespace; v(f) is the value the engine actually decodes.
e_r is the actual numeric comparand used by the equality decision; it is not defined to equal r(u_r).
For a row r, the allocation record A_r = (exec_r, X_r, u_r, lease_r, epoch_r, session_r, channel_r,
name_r) is fixed at reservation (T-01): the execution_id, the clone event launched for it, the lease's
uid, the lease, the engine epoch, the session, the channel and the local_agent_id; the fields are written
A_r.execution, A_r.uid, A_r.local_agent_id and so on. u_r := A_r.uid is the uid of the lease the
reservation took, and it is the only meaning of u_r in this file. The row's stored expected_uid field is
a separate named input (I-05); 01 T-23 reads the comparand e_r from that field, so a field that differs
from r(u_r) fails p33 (e_r = r(u_r)) whenever the field is the comparand's source. X_r := the T-05
clone event performed for the SpawnRecord whose execution_id equals A_r.execution (01 T-03/T-05).
Whether some other clone of this engine's spawner was launched with A_r.uid against its own record is
the launch-correspondence predicate p53, not part of X_r's definition. Three further launch facts are
G1 preservation guards (T-04, T-07, T-09), not components: that X_r itself was launched with A_r.uid;
that row r's installed engine end belongs to the socketpair created at T-04 for X_r's SpawnRecord; and
that the peer end of that socketpair went to X_r's clone and to no other. Their failure alone puts no
accepted byte at row r (a holder of the peer end with a uid other than u_r fails C-04, as §4.1 item 1
states), so making them components would assign histories caused elsewhere to D_53 (recheck 2, N-03;
recheck 3, N-05). Clones of another engine's spawner are not p53's subject; their allocations are p61's
(recheck 2, N-04). J_r is the interval from that reservation to its release/retirement, open-ended while
not released. When evaluating an event, quantify over the history prefix through that event, not future
processes or allocations. It is not recomputed from the current uid owner. Host tasks and other engines' tasks are
included when asking who can possess u_r, not silently removed from that question.

## 2 Sufficient conditions (predicates, not defences)

For C-01…C-07, quantification is over accepted event a and its contributing bytes, unless explicitly
over the allocation interval. C-08 quantifies over consumer events in the history prefix h. A conjunction's components are ordered as printed for the split in §4.

| ID | predicate over named inputs | purpose / source correspondence |
|---|---|---|
| C-01 origin and frame association | (p11) Bytes(a) is a nonempty ordered normal-stream byte sequence from actual send events; (p12) every byte has a current recvmsg fragment witness; (p13) each witness's data/control belongs to the same read and original channel/generation/frame as a, with no unchecked insertion or substitution. | I-01/I-04; conn E-02; MM-02–04/14. A total provenance relation, not an assumption that every recv has one sender. |
| C-02 stamp equality | (p21) every contributing origin has a populated valid kernel uid stamp; (p22) k(b) = u(task_b,send_b). | I-02; kub §§2.4, 3–6. The equality needs the selected credential slot and capability/mapping premises; intact kernel alone is insufficient if lawful privilege permits another uid. |
| C-03 faithful observation | (p31) r is defined and injective on all kernel uids relevant to this decision, including u_r, with no sentinel alias; (p32) v(f(b)) = r(k(b)) with the correct ABI and intact ancillary, for every byte in f; (p33) the actual stored comparand e_r = r(u_r), in the same number domain. | I-03; kub §§2.5, 6 C3/C4; conn L413–424. It states the needed relation, not that every non-initial namespace necessarily violates it. |
| C-04 actual comparison | (p41) every contributing header/body fragment underwent the equality decision; (p42) every such decision required v(f) = e_r, with the same original comparand and no observe-and-rebind or fallback identity source. | I-03/I-05/I-07; conn L422–435; mech Identity lifecycle. |
| C-05 row/label anchor and launch correspondence | (p51) the row read at a has the immutable reservation A_r corresponding to its original Channel; (p52) L(a).execution = A_r.execution and L(a).local_agent_id = A_r.local_agent_id, with session/channel/lease/epoch fields from the same record (the stored expected_uid field's agreement with r(u_r) is p33 whenever the field is the comparand's source, and is not repeated here); (p53) during J_r, no clone event of this engine's spawner other than X_r is launched with A_r.uid as its T-07 uid while its own SpawnRecord assigns a different uid; a second allocation whose own record assigns u_r is p61's case, and clones of another engine's spawner are C-06's. | I-04/I-05/I-07; conn E-01 objects/handoff/spawn record; E-02 VerifiedContext; optb spawn sequence. p53 states the launch correspondence as a predicate over this spawner's records; it is a deliberately stronger component, not one the implication's last step uses (that step uses X_r's definition and p62): its role is to place a launch that applies a uid against the records in the C-05 cell D_53 (G1) ahead of C-06. That X_r was launched with A_r.uid, that row r holds the engine end of X_r's socketpair, and that its peer end went to X_r's clone alone are G1 preservation guards, not components (§1; addendum F-03, rechecks 1–3). |
| C-06 spatial uid exclusivity | (p61) at each time t in J_r, no other allocation interval for another execution assigns u_r; (p62) every actual task having real kernel uid u_r at t belongs to P_Xr (including descendant namespaces). An empty set satisfies p62; existence is not required. | I-02/I-06; exclusive pool, launch drop, membership semantics; mech lifecycle; D4. p61 is allocator bookkeeping; p62 independently checks that reality corresponds, including foreign host tasks/legitimate uid changes. |
| C-07 time association | (p71) for every b, send_b belongs to J_r. A former second component p72 (same unreleased generation for reads and buffers; receive phase admits the message type) was withdrawn in version 3: its generation half is p13 and its phase half does not bear on attribution (note below), so no first-failure history could reach it (addendum F-01); the phase and generation rules remain Step 3 guards for G4. | I-04/I-06/I-07; conn E-02/E-04; MM-09–12/15. Historical association, not “the uid exists now”; not an assertion that the double gate establishes it. |
| C-08 consumer continuity | (p81) every attributed consumer event carries, for each of its actual D-ACC causal origins, that origin's context/reference unchanged, and the execution label and local_agent_id it emits for the action equal those of the origin whose message requested the action (an event with several origins is not a single-sender event and emits each origin's label with its own reference; addendum F-12); (p82) an event without a D-ACC origin does not gain a verified_subject; lifecycle control_binding is not retyped as a message sender. | I-07; conn E-03, rr E-06/E-07, si E-09. A separate carry obligation, not business-policy correctness. |

C-06/C-07 are deliberately stronger sufficient conditions, not necessary characterizations: e.g. a
post-retirement old callback may still name the right past sender. Likewise a phase error with the right
label is not, by itself, false attribution, which is why the former p72 is not a component of C-07 and
no ledger route is reached through it. Every route below therefore needs both its predicate failure
and the wrong/no-origin labelled event. These distinctions prevent counting DoS, stale authorization or
same-execution task-call mistakes as binding attacks.

## 3 Sufficiency argument and explicit limit

Take any b in Bytes(a). C-01 gives its actual sender and current-read association. C-02 gives
k(b) = u(task_b,send_b). C-03 and C-04 give r(k(b)) = v(f(b)) = e_r = r(u_r); injectivity yields
u(task_b,send_b) = u_r. C-05 identifies the label's execution and agent name with A_r, independently of
the message. C-07 places send_b in J_r. C-06 then puts task_b in P_Xr at that time, X_r being the
named clone event of §1. Thus Exec(b) = X_r = L(a).execution, where the middle term is a trace fact,
not a bookkeeping value. p53 is not used in this step; like C-06/C-07 it is a stronger component whose
job is the cell assignment of §4. This holds for each byte, including all origin segments in a merged
read and the header; C-01 supplies nonempty origins. Therefore C-01 ∧ ... ∧ C-07 ⇒ P_acc.

C-08 additionally gives P_carry: each consumer's claimed sender equals its originating D-ACC label,
and no originless verified subject is introduced. P_acc ∧ C-08 ⇒ the same sender statement at those
consumers. C-08 does not strengthen uid stamping and P_carry does not imply authorization, truthful
model output, or remote-operation integrity. A consumer-only defect leaves P_acc intact and is marked
as such in its ledger row.

The contrapositive gives ¬P_acc ⇒ at least one failed C-01…C-07. This logical implication is only as
useful as its independent definitions and input correspondence. It is **not** transition preservation,
proof of deployability, or an enumeration of all possible software bugs. Step 3 must establish whether
the frozen design can maintain these conditions; an invariant may expose missing conditions or an
overstrong premise. No exclusion/requirement is inferred merely because a table cell exists.

## 4 P / not-P decomposition and route selectors

First partition a causal history by boundary predicate H: did it obtain a forbidden kernel-defect or
cross-domain hardware access? If yes, split by N1 first (software kernel defect) / not N1 (N9 hardware);
histories using both list the second as a dependency. These are R-G5-01/02, capable of violating any
C-01…C-08. A read-only effect does not itself change a uid; it needs a further attribution-changing
step. Remaining histories keep the normal/configuration shortfall distinction in scope.

For any history prefix h, define Bad_acc(h) := there exists an accepted event a in h with
NOT P_acc(a). If Bad_acc holds, select its first such event a* in the executor's event order. Define:

    F_i(h) = Bad_acc(h) AND C-01(a*) AND ... AND C-(i-1)(a*) AND NOT C-i(a*), i=1…7
    F_8(h) = NOT Bad_acc(h) AND NOT C-08(h)

F_1…F_7 classify the selected actual false-attribution event, not every sufficient-condition failure
in otherwise correctly attributed traffic. F_8 is disjoint: all D-ACC events in that history satisfy
P_acc, including histories where a stronger condition such as C-07 fails without wrong attribution.
Within F_8, p81 ranges only over consumers with an actual D-ACC causal origin; p82 owns originless
verified-subject events. This causal origin is a fact of the trace, not the pointer/label being tested.
An originless event therefore need not fail p81 first and hide the D_82 leaf. F_8 remains a condition-
failure candidate, not by itself proof of a false consumer label. The masks are disjoint; a history can
still violate several conditions and have several causal routes beyond its selected partition cell.

For C-i's ordered components, define D_ij = (all earlier p_i components) AND NOT p_ij.
Thus D_11 = NOT p11, D_12 = p11 AND NOT p12, etc. C-03 has three components after R1; C-05 has three
after version 3 (p53 added); C-07 has one (p72 withdrawn).
For a selector list [qA→rA, qB→rB, else→rZ], the exact branch expressions are:

    D_ij AND qA
    D_ij AND NOT qA AND qB
    D_ij AND NOT(qA OR qB)     [explicit remainder, not an omitted branch]

Define B(route) as the OR of all expressions assigned to that route in the table below. A ledger's
branch column cites B(route); conjoining with F_i gives the first-failed-condition partition cell.
The selectors identify observed causal events/data flow in the trace, not an inferred adversary intent.
A selector is true exactly when the trace (I-01…I-08 and the ghost history) contains its named fact; the
explicit remainder owns the histories in which none of the cell's named facts occurs. Whether an analyst
can tell which branch a concrete history falls in is a statement about the analysis, recorded as an open
question in the route file, never a reason to move the history (addendum F-04). These
remainder entries are **unresolved causal refinement slots**, not claimed known mechanisms or finished
final-table rows. They must not gain a supported disposition simply because their predicates are total.
Since version 7, four slot entries carry a stated property that empties their remainder once it holds
(U-02); they stay the explicit remainders of their cells.

### Selector vocabulary (predicates over I-01…I-08 and the event history)

| selector | true exactly when the trace contains this fact |
|---|---|
| q01 | the accepted context is constructed outside the original receive_step/T-24 path (I-07). |
| q02 | the original T-24 path creates the subject while the trace holds no normal-stream byte origin for it (I-01/I-07). |
| q03 | a byte lacking a current recvmsg witness was consumed by read/recv/stdio or an alternate credential-dropping API (I-01). |
| q04 | the unvalidated insertion is a header/body byte, OOB byte or a second reader's data (I-01). |
| q05 | the substituted data/control/buffer belongs to an allocation generation before A_r (I-01/I-04/I-06). |
| q06 | the data and ancillary used together come from different read events in the current generation (I-01/I-03). |
| q07 | the contributing buffer belongs to another current frame or channel (I-01/I-04). |
| q08 | no credential-producing option/path was armed when the relevant bytes were queued (I-02/I-08). |
| q09 | explicit SCM_CREDENTIALS selected a uid from the sender's effective/saved set different from its real uid (I-02). |
| q10 | explicit SCM_CREDENTIALS selected a foreign mapped uid outside that set and the actual capability/map predicates permitted it (I-02). |
| q11 | translation uses an unmapped/invalid/sentinel alias for at least one relevant kernel uid (I-03). |
| q12 | the current ancillary is absent, truncated, duplicated or has invalid structure/length (I-03). |
| q13 | available ancillary was decoded with a wrong ABI/representation, replaced by pid lookup, or read from stale decoded storage (I-03). |
| q14 | a single earlier fragment's credential is reused for subsequent fragments instead of checking them (I-07). |
| q15 | another identified header/body/OOB fragment reaches acceptance without the required check (I-01/I-07). |
| q16 | the received uid or payload identity selects/rewrites the expected row (I-04/I-05/I-07). |
| q17 | the decision uses a connection snapshot, payload/pid identity, or an equality result that differs from the comparison of v(f) with e_r, instead of the current comparison (I-07). |
| q18 | the original row/channel/lease association was inconsistent when installed (I-04/I-05). |
| q19 | a prepared/empty/duplicate control event later changes association or reactivates a retired row (I-05/I-06). |
| q20 | a later association change follows a numeric fd/uid/generation lookup or object alias (I-04/I-05). |
| q21 | retired in version 3 (addendum F-02): a stored expected_uid field that differs from r(u_r) fails p33 whenever the field is the comparand's source (01 T-23) and is routed by D_33; the selector stays declared so that its number is never reused. |
| q22 | the emitted label/tuple (execution, local_agent_id, session, channel, lease, epoch) differs from the compared A_r record (I-05/I-07); this is p52 failing. |
| q23 | the two overlapping allocations were made by the same engine process in the same engine_epoch (I-05/I-06); two engines whose epoch values coincide are not q23. |
| q24 | the offending task belongs to a PRIOR allocation for this uid and survives into J_r (I-06); tested before q25, regardless of when its message arrives. |
| q25 | a non-predecessor task already has the real uid at J_r's reservation (I-06). |
| q26 | a non-predecessor task becomes a holder later through a documented lawful uid change, namespace map, or credential-bearing task creation (I-02/I-06). |
| q27 | send_b is earlier than J_r.start; under NOT p71 the alternative is at/after J_r.end (I-06). |
| q28 | retired in version 3 (addendum F-01): a buffer or read from a different or released allocation generation is q05 under p13; the number is never reused. |
| q29 | retired in version 3 (addendum F-01): acceptance while the original row's receive phase does not admit the event is a Step 3 guard for G4, not an attribution fact; the number is never reused. |
| q30 | the consumer relooks up an old callback by numeric uid/fd/request number or by a recurring local_agent_id after retirement/reuse (I-07); since version 7 such a lookup names a departure from stated design text, not a design gap (01 MM-16 resolved, T-45, T-51). |
| q31 | a current request/cancel/task/grant/binding association joins another session/context (I-07, including T-39). |
| q32 | the original request/context reference is retained but the emitted execution label or `local_agent_id` changes (I-07; p81 requires both to equal the origin's — version 4, change request CR-F-03). |
| q33 | the other overlapping allocation belongs to an earlier engine epoch of the same cell that r's epoch succeeded after that engine's control loss (T-49, MM-10) (I-05/I-06). |

### Total branch assignment

The order inside each cell is semantic. “else” is the exact negation of every preceding selector in
that cell. In the explicitly total two-conjunct cases, the last branch is written as NOT the first
selector; the named other selector explains it rather than leaving a hidden remainder.

| failed component | ordered selectors → ledger routes |
|---|---|
| D_11 | q01 → R-G3-01; NOT q01 AND q02 → R-G2-01; else → R-G2-11 |
| D_12 | q03 → R-G2-01; NOT q03 AND q04 → R-G2-02; else → R-G2-11 |
| D_13 | q05 → R-GX-01; NOT q05 AND q06 → R-G2-03; NOT(q05 OR q06) AND q07 → R-G2-04; else → R-G2-11 |
| D_21 | q08 → R-G1-01; else → R-G2-05 |
| D_22 | q09 → R-G5-03; NOT q09 AND q10 → R-G5-04; else → R-G2-05 |
| D_31 | q11 → R-G5-05; else → R-G2-12 |
| D_32 | q12 → R-G2-03; NOT q12 AND q13 → R-G2-06; else → R-G2-12 |
| D_33 | true → R-G1-02 (expected-representation predicate itself fails) |
| D_41 | q14 → R-G2-07; NOT q14 AND q15 → R-G2-02; else → R-G2-13 |
| D_42 | q16 → R-G2-08; NOT q16 AND q17 → R-G2-09; else → R-G2-13 |
| D_51 | q18 → R-G1-03; NOT q18 AND q19 → R-GX-02; NOT(q18 OR q19) AND q20 → R-GX-03; else → R-GX-06 |
| D_52 | true → R-G2-10 (q22 by the definition of p52) |
| D_53 | true → R-G1-06 (launch-correspondence predicate itself fails) |
| D_61 | q23 → R-G1-05; NOT q23 AND q33 → R-GX-04; else → R-G5-06 (an allocation of a concurrently running engine, U-05) |
| D_62 | q24 → R-G4-01; NOT q24 AND q25 → R-G5-06; NOT(q24 OR q25) AND q26 → R-G5-07; else → R-G5-08 |
| D_71 | q27 → R-GX-01; NOT q27 → R-GX-03 (send at/after retirement; time and interval are typed under the earlier conditions) |
| D_81 | q30 → R-GX-05; NOT q30 AND q31 → R-G3-02; NOT(q30 OR q31) AND q32 → R-G3-03; else → R-G3-05 |
| D_82 | true → R-G3-04 (originless verified-subject event) |

For H, B(R-G5-01) = H AND N1 AND (Bad_acc OR NOT C-08); B(R-G5-02) = H AND NOT N1 (N9) AND (Bad_acc OR
NOT C-08), so the boundary cells, like every other cell, contain no correctly attributed history
(addendum F-10). All remaining B expressions include NOT H. Remainders may later split into appended IDs, but never disappear from the matrix by
being called “unknown.” The logical component/selector partition is total; reachability, mechanism
refinement and real-system correspondence remain open. One witness byte (two uid values for a
translation collision) suffices to demonstrate a predicate failure, not to bound process counts or histories.

### 4.1 Pre-registered hypotheses, independently reconsidered

1. **Foreign endpoint:** A-07 plus T-20 selects a genuine sender uid independently of the endpoint's
   row. A false attribution additionally needs C-04 failure, C-02/C-03 failure, or an actual shared/reused
   uid (C-06/C-07). Thus descriptor possession alone is not a failure predicate. The d2 spawn leak
   and staged arm3 collaboration are different acquisition histories (kub §7.2); neither is a coverage
   argument or a new run. R-G2-09 is the endpoint/snapshot variant; compound histories use GX.
2. **Capability restoration:** under the existing §3 mapping rule, absent S1 can restore capabilities
   inside a newly created user namespace without permitting a foreign kernel uid. That relaxation alone
   need not falsify C-02 or C-06. R-G5-04/07 require foreign-map or relevant-parent/initial capability
   reach as well; R-G5-03 separately handles unequal real/effective/saved credentials. The hypothesis
   “unshare allowed ⇒ forged uid” is rejected, not copied. This does not declare the relaxed configuration
   acceptable or settle its exposure to N1.
3. **Queued dead sender:** membership emptiness does not erase already queued bytes or a FrameReader
   buffer. Conversely, physical queue drain is not logically necessary if no stale byte can obtain a
   new-generation label. R-GX-01/03 test that missing relation; processing after CLOSED is a G4
   preservation guard for Step 3 (the former p72), not a ledger route, because a post-CLOSED acceptance
   with the original row's label is not false attribution (addendum F-01).
   T-40 order and original-object rules are candidate transition semantics to analyze, not a result that
   the double gate either succeeds or fails. A same-generation late read before exit notification is a
   permitted, correctly attributed history.
4. **Foreign explicit SCM_CREDENTIALS probe:** own uid, unmapped uid, mapped own uid after namespace
   creation, and foreign uid are different input cases. Derived outcomes under the intact posture, from
   01 T-20 (b)–(e) and kub §5, not from the probe's expected values: own uid → accepted, stamped with the
   sender's own uid; unmapped number → the send fails and no skb exists; own uid renamed 0 inside a
   self-made namespace → accepted, stamped with the sender's own kernel uid; foreign uid → the send
   fails and no skb exists unless the capability and map predicates of T-20 (c) permit it. One
   disagreement with the PLAN's Stream P row is recorded for the reconcile step: that row expects an
   error for the self-mapped sub-arm, while the derivation gives acceptance under the sender's own uid;
   the probe's observation decides and the derivation is not amended beforehand (addendum F-08). Error
   numbers are not copied as measurements; own-uid success is the positive control, not a
   false-attribution row. Where the PLAN places "the explicit foreign-uid route" in G2 and makes it
   Stream P's trigger: after this cut that route is R-G5-04 (lawful map or privilege) with the R-G2-05
   remainder for the intact posture; under the intact posture T-20 (c) produces no accepted event, so
   no G2 ledger entry carries it. Stream P's trigger is the existence of R-G5-04 and R-G2-05, and the
   ledger's cut supersedes the PLAN's provisional placement (§7; addendum F-09).

### 4.2 Observation-only channels

Reading a uid, channel number, request id or other public label does not change k, r, row association or
membership. A guessed current task_call_id spoken by another process **inside the same execution** is
not a P_acc violation. If leaked information enables reaching a foreign endpoint, its extra step is
A-07 and the conditions above still apply. If it enables authority-bearing memory/control alteration,
record that reachability as an unresolved premise U-04, not “read is harmless.” N1/N9 memory reads are
outside the declared actor envelope even without a demonstrated second step; cache timing observation
alone is not automatically N9's cross-domain memory-read primitive. No claim about outbound response
confidentiality or all leakage channels is made here.

### 4.3 Coverage warrant (written as a check, not an exhaustiveness proof)

Why the split above covers the negation of P_acc, stated in one place (PLAN Context (3); addendum F-13).
(0) Histories are first split by the boundary predicate H: H ∧ (Bad_acc ∨ NOT C-08) is assigned by N1 /
NOT N1 to R-G5-01 / R-G5-02; everything below concerns NOT H histories. (i) The negation is: some
accepted event a has NOT P_acc(a), or some consumer event violates C-08 (a p81 carry failure or a p82
originless verified subject). (ii) §3 gives C-01 ∧ … ∧ C-07 ⇒ P_acc, so a history with Bad_acc has at least one
failed condition at its first false event a*; the masks F_1…F_7 pick the first failed one and F_8 holds the
carry case; the eight masks are pairwise disjoint and together equal Bad_acc ∨ NOT C-08. (iii) Each C-i is
a conjunction of components p_ij over named inputs, so NOT C-i is the disjoint union of the cells D_ij
(earlier components hold, p_ij fails). (iv) Each D_ij row's selector list ends in an explicit remainder, so
every history in a cell reaches exactly one ledger entry (checked mechanically for every selector
valuation by the structural script). Therefore every history that violates P_acc or C-08 reaches exactly
one ledger entry, and every (condition, group) matrix cell either lists entries or states why none is
allocated there. What this does not warrant: that I-01…I-08 are all the inputs the frozen text supplies
(model correspondence, 01 §7 and §10); that a selector's causal meaning matches any implementation; that a
remainder entry is empty or nonempty; that any route is reachable under the design's transitions (Step 3
and the preservation files).

## 5 Traceability check, exclusions and uncertainties

### 5.1 Per-input and interface check (not an exhaustiveness test)

| input / admitted actions | failure components / ledger landing | positive or non-attribution case retained |
|---|---|---|
| I-01, A-01/A-02/A-05: arbitrary framing/ancillary, short I/O, OOB, alternate reads | p11–p13/p32/p41; G2-01…07, G2-11, GX-01 | arbitrary content with correct uid is not misattribution; reject/EOF remains T-40/T-46 |
| I-02, A-03/A-04: process, credential and namespace calls | p21/p22/p62; G1-01, G2-05, G5-03/04/07/08 | same-execution forks, own explicit stamp and own-uid renaming retained |
| I-03: translation/control/ABI/expectation domain | p31/p32/p33; G1-02, G5-05, G2-03/06/12 | an invalid credential rejected without a subject is no D-ACC |
| I-04/I-05, A-07: endpoint, row, immutable association, launch correspondence | p13/p42/p51/p52/p53; G1-03/06, G2-08…10, GX-01…03, GX-06 | foreign fd with distinct uid needs another failed predicate; label equality does not follow from fd possession |
| I-06, K-01…K-10, A-06: death, delay, pool/slot reuse, crashes, deadlines | p61/p62/p71; G1-05, G4-01, G5-06/07/08, GX-01…05 | send then exit before receive can remain correctly labelled; resource stalls alone are availability |
| I-07, A-02/A-06: protocol identifiers, prepare/dispatch/callback/log | p41/p42/p52/p81/p82; G2-07…10, G2-13, G3-01…05, GX-05 | task/grant policy mismatch within one execution is not a different sender |
| I-08, A-08/A-09: trust/policy departure, reachability premises | G5-01…08; U-04 | legitimate privilege is not labelled kernel breach; deliberate malicious trusted actor is outside the actor definition |

Entry check: the frozen data path has one socketpair class per execution; control/file-worker paths are
trusted-only, E-10 changes launch configuration, E-07 is outbound, E-09 is a consumer. Pending MCP
compartment/inter-agent entry designs are **not yet modeled**, not asserted to be identical forever.
A future agent-reachable listener requires a new inventory/freeze. Borrowed state outside the modeled
interfaces would falsify correspondence, not be retroactively “covered” by a nonempty ledger row.

### 5.2 Coverage uncertainties carried to R1 / Step 3 / Q

- **U-01 kernel-origin correspondence:** receiver credential uniformity is not unique syscall/task
  provenance. Revised D-GT tracks all origins. At the pinned tag, the 2026-10-16 reading (04 EV-142–EV-146)
  finds every skb on a connected stream socketpair's receive queue enqueued by the peer's send after
  maybe_add_creds; the one credential-less delivery path, the BPF sockmap ingress list, needs CAP_NET_ADMIN
  in the initial user namespace and a descriptor to the engine's end. Within intact kernel semantics and
  under step 11's capability posture, R-G2-05 therefore holds no history; its remainder is kernel defects
  (R-G5-01), and the reading's two stated bounds (out-of-family receive-queue writers sorted by directory,
  the remaining sockfd_lookup callers sorted by protocol, neither read line by line) travel with this
  statement (version 5, CR-G2-01). Alternate asynchronous submission, if a future production ABI admits it, needs
  its own correspondence check; do not assume the current deny is realized everywhere.
- **U-02 causal-leaf refinement:** p62 and reference-association failures identify a finite relation but
  not every implementation corruption mechanism. Seven explicitly assigned remainder slots
  (R-G2-05/11/12/13, R-G3-05, R-G5-08, R-GX-06) retain their branch predicates and work owners;
  R-G2-05's disposition (version 5) rests on a positive property of the slot's producers (U-01), not on
  the totality of its predicates; version 10 (2026-10-19, follow-up step 4) records the same for R-G2-11, R-G2-12
  and R-G2-13, whose closing properties the engine build's checks establish within the route files' stated limits — for R-G2-12 and R-G2-13; version 12 (2026-10-23, M1 repair) records that R-G2-11's closing property has a memory half, the memory safety of the C reader, which is a stated requirement not established (engine-requirements row 175, assigned to prove 2.2), so that route is conditional on unbuilt requirements and the fuzz run is supplementary evidence. Version 7 (2026-10-18, second design freeze) re-marks four slot
  entries without changing their routes, branch predicates or cells. R-G5-06 (the D_61 remainder and the
  D_62 q25 branch) and R-G5-08 (the D_62 remainder) come to rest on deployment preconditions: the design
  writes the pool-exclusivity premise and its limit — the reservation reads only the engine's own lease
  state, and the local model instance runs under no pool uid (01 T-01, T-67) — and the deployment entries
  (the pool reserved on the host to the engine alone, one engine per range, the deployer's uid inventory
  naming every holder) are the first entry of
  engine-requirements §8.
  R-G3-05 and R-GX-06 become ordinary implementation obligations, discharged by the code at follow-up
  step 4, because the property that empties each remainder is now design text: every consumer step
  reaches the verified context by object reference, with no lookup or keying by name, uid, fd or
  local_agent_id (01 MM-16 resolved); the row–channel–lease association is created at row creation,
  installed at the prepared-fd install with one receiver_generation per Channel, and cleared only by close
  step 2, by object (01 T-01, T-09, T-40, T-45, MM-15 resolved, AA-13).
  An unmodeled way to change a relation requires refinement into appended route/model versions. Only the predicate
  split, not the causal catalogue or real system, has the coverage warrant of §4.3.
- **U-03 lifecycle preservation:** C-06/C-07 are obligations to test. Empty facts, control epochs,
  local withdrawal vs uncertain submission, reader deregistration, buffers and receiver_generation
  need explicit Step 3 guards. MM-10 remains unresolved; MM-09, MM-11 and MM-15 are resolved by the
  design text and MM-12 is stated (01 version 9: close steps 1–4 are one executor decision, lease release
  also requires close step 2, receiver_generation is one per Channel and void after step 2, and a new row
  binds no object of the old execution's slot). That states the transitions Step 3 argues over; whether
  they preserve the guards is still Step 3's question. Pid-namespace membership emptiness must not be
  equated with destruction of all namespace or socket references. No draining requirement is invented.
- **U-04 mutable-state reachability:** AA-04 and A-09 do not prove that a permitted parser or shared
  storage path cannot alter binding state. Those effects are represented by C-01/C-05/C-08; their
  realization and any required leakage-to-write chain remain evidence obligations. Honest-but-buggy
  receiver errors stay visible rather than being dismissed as a fully malicious engine.
- **U-05 deployment / abstraction:** initial namespace, exclusive host-wide pool, S1/S2, trusted
  supervisor and three locality branches require final evidence. No whole W2 or hardware catalogue
  is demanded as a prerequisite to this draft; missing individual relations are named here. A second
  engine running at the same time on an overlapping pool is a failure of this premise and is routed to
  R-G5-06 by D_61 (addendum F-11). Since version 7 the design writes this premise and its limit (01 T-01,
  T-67) and the deployment entries are stated (engine-requirements §8), so R-G5-06 and R-G5-08 rest
  on those deployment preconditions as stated premises the engine does not check (no separate disposition
  value, user 2026-10-18); their realization on a host remains the deployer's
  evidence.
- **U-06 scope of consumers:** C-08 only carries attribution. The grant_ref redesign is in the third freeze
  (01 v10 MM-06: no agent-facing grant_ref; the grant comes from the matched call's TaskBinding); MCP server
  and forwarded inter-agent message designs are not retroactively analyzed by this freeze.
- **U-07 language/source hygiene:** 01 originally used some pre-addition kub line numbers and stale
  MM-04/T-42 wording after MM-01/MM-14 were resolved. Use section anchors at the accepted evidence-only
  blob and repair the scratch inventory without editing the frozen source. Historical “unbuilt” prose
  in kub must not override the later P2a transport evidence or assert a product implementation.

## 6 Route ledger

The primary condition locates a logical failure component; additional conditions record causal
interaction. “Cross” concerns dependence on other groups' **preservation results**, not just citing a
transition as a fact. Every row traverses T-20…T-24 when it concerns a real received frame, unless it
explicitly names an alternate/missing D-ACC path. H rows retain the declared-boundary destination;
all other dispositions and all stop mechanisms are intentionally deferred.

| route ID | one-sentence causal route (attempt plus necessary failure) | branch predicate | violated condition(s) | group | cross-group flag / principal transitions |
|---|---|---|---|---|---|
| R-G1-01 | A sends opening bytes which lack a valid stamp because credential passing was not established at production, and those bytes reach a labelled acceptance. | B(R-G1-01) | C-02; C-03/C-04 if admitted | G1 | no; T-04/T-08/T-09/T-20 |
| R-G1-02 | A's rendered uid is compared to a stored expectation not equal to that allocation uid's receiver-domain representation, allowing a distinct principal to match. | B(R-G1-02) | C-03 | G1 | no; T-01/T-09 |
| R-G1-03 | A's correctly stamped frame is installed/read through a row or endpoint whose initial lease/execution correspondence is wrong. | B(R-G1-03) | C-05 | G1 | no; T-01…T-12/T-26 (whole welcome send) |
| R-G1-05 | A and B simultaneously receive the same uid from distinct allocations made by one engine process in one epoch, and A's bytes are accepted as B. | B(R-G1-05) | C-06 | G1 | no; T-01/T-03/T-05/T-07 |
| R-G1-06 | This engine's spawner launches A's clone with another row's allocation uid against A's own record, and A's bytes reach that row's endpoint and are accepted under its label. | B(R-G1-06) | C-05; C-06 as affected | G1 | no; T-02/T-03/T-04/T-05/T-07/T-09/T-20…T-24; a trusted-actor correspondence error, not an adversary privilege; a second allocation of the same uid is R-G1-05, another engine's clone is R-G5-06 / R-GX-04, and a same-spawner clone launched with u_r before r's reservation is a pre-existing holder (D_62, q25 → R-G5-06) |
| R-G2-01 | A feeds a read path without a current normal-stream credential witness and it produces a sender label anyway. | B(R-G2-01) | C-01 | G2 | no; T-21/T-24/T-64 |
| R-G2-02 | A contributes unchecked header/body or OOB bytes to a frame accepted using the checked remainder's identity. | B(R-G2-02) | C-01/C-04 | G2 | no; T-20…T-25 |
| R-G2-03 | A causes missing/truncated or mismatched current ancillary to be paired with bytes and interpreted as a usable sender. | B(R-G2-03) | C-01/C-03 | G2 | no; T-21/T-22/T-24 |
| R-G2-04 | A's current-frame bytes are mixed with another channel/frame's checked buffer and inherit its label. | B(R-G2-04) | C-01/C-05 | G2 | no; T-21…T-25 |
| R-G2-05 | A labelled acceptance violates stamp population/equality through an as-yet unrefined cause outside the identified production/selected-slot/privilege cases. | B(R-G2-05) | C-02 | G2 | no; T-20/T-64, T-67 (step 11 absent on the deployed host is a configuration failure, not an adversary action; the route holds under its premise — version 6, CR-G2-02); remainder argued from the pinned-tag queue reading (EV-142–EV-146), kernel defects to R-G5-01 |
| R-G2-06 | A's ancillary is present but ABI conversion, stale decoded storage or a substituted pid lookup turns it into another principal. | B(R-G2-06) | C-03 | G2 | no; T-21…T-24 |
| R-G2-07 | A appends another sender's bytes after a first credential check and a cached frame credential admits them. | B(R-G2-07) | C-04 | G2 | no; T-20…T-24/T-60 (same-execution writers retained) |
| R-G2-08 | A's observed uid or identity field chooses/rewrites the expected row instead of being compared to the original expectation. | B(R-G2-08) | C-04/C-05 | G2 | no; T-23/T-24 |
| R-G2-09 | A writes through a held foreign endpoint and a snapshot, payload/pid identity or incorrect equality decision admits it as the endpoint's execution. | B(R-G2-09) | C-04 | G2 | no; T-20/T-23/T-63; possession stipulated as A-07 |
| R-G2-10 | A's checked frame receives context fields naming a different execution than the row used for comparison. | B(R-G2-10) | C-05 | G2 | no; T-23…T-25 |
| R-G3-01 | A's protocol data reaches an internal constructor which fabricates a validated sender without an originating frame. | B(R-G3-01) | C-01/C-05 | G3 | no; T-24/T-30/T-38 alternate-constructor obligation |
| R-G3-02 | A's correctly attributed request/cancel/task result is joined by request id or task/grant reference to B's context during admission/dispatch. | B(R-G3-02) | C-08 | G3 | no; T-25/T-30…T-39; consumer-only |
| R-G3-03 | A's correctly attributed work is recorded or sent onward with another execution label or local_agent_id despite retaining its original request reference. | B(R-G3-03) | C-08 | G3 | no; T-33/T-34/T-38; consumer-only; sentence widened in version 4 (CR-F-03) |
| R-G3-04 | A's rejected input or an originless/control callback gains a verified_subject at a consumer. | B(R-G3-04) | C-08 | G3 | no; T-22/T-25/T-34/T-38; consumer-only |
| R-G4-01 | A's old task survives a reported-empty/release cycle and speaks under a uid now assigned to B. | B(R-G4-01) | C-06 | G4 | no; T-13/T-14/T-40…T-45/T-47…T-50/T-52/T-65; receive semantics cited as facts |
| R-G5-01 | A uses a software kernel defect to alter observations/protected state, or reads through it then takes an additional attribution-changing step. | B(R-G5-01) | C-01…C-08 as affected | G5 | no; T-66; declared N1 destination; read alone is not a stamp mutation |
| R-G5-02 | A uses cross-domain hardware memory access to alter observations/state, or uses a hardware read plus an attribution-changing step. | B(R-G5-02) | C-01…C-08 as affected | G5 | no; T-66; declared N9 destination; S14 is only its checkable half |
| R-G5-03 | A lawfully selects an effective/saved uid different from its real uid and an execution label relies on the unjustified single-uid interpretation. | B(R-G5-03) | C-02 | G5 | no; T-07/T-20/T-61/T-67 |
| R-G5-04 | A attaches another mapped kernel uid using relevant namespace privilege and it is accepted as another execution. | B(R-G5-04) | C-02 | G5 | no; T-07/T-20/T-62/T-67; nested capability alone insufficient |
| R-G5-05 | Distinct senders render to a sentinel/overflow value in the receiving namespace and a labelled decision treats the alias as a principal. | B(R-G5-05) | C-03; C-04 if admitted | G5 | no; T-21/T-23/T-67 |
| R-G5-06 | A nonmember host/other-compartment task already possesses an allocated uid, or a concurrently running engine's allocation assigns it, and bytes under it are accepted as that execution. | B(R-G5-06) | C-06 | G5 | no; T-01/T-05/T-20/T-49/T-67; U-05 deployment exclusivity (p61 for the concurrent-engine case, p62 for the pre-existing holder); resting on deployment preconditions since version 7, stated premises the engine does not check (no separate disposition value, user 2026-10-18): the design writes the pool-exclusivity premise and its limit (01 T-01, T-67), and the pool reserved to the engine alone, one engine per range, is the first deployment entry of engine-requirements §8 |
| R-G5-07 | A later obtains, or lawfully creates a task with, another allocation's real kernel uid and its genuine stamp passes as that execution. | B(R-G5-07) | C-06 | G5 | no; T-07/T-61/T-62/T-67 |
| R-GX-01 | A's old queued or buffered bytes are attributed through a new allocation even after every old task has died. | B(R-GX-01) | C-01/C-07 | GX | yes G2+G4; T-20…T-24/T-40/T-42/T-43/T-45 |
| R-GX-02 | A times failure, late prepared/empty or duplicate control events so the wrong original lease/session is installed or reactivated. | B(R-GX-02) | C-05; C-06/C-07 if reused | GX | yes G1+G4; T-02/T-09/T-13/T-14/T-43/T-49/T-52 |
| R-GX-03 | A sends to a stale endpoint or races numeric fd/generation reuse and its bytes/readiness callback is attached to a different row. | B(R-GX-03) | C-05/C-07 | GX | yes G2+G4; T-09/T-21…T-24/T-40/T-45/T-46/T-51/T-63 |
| R-GX-04 | A survives an old engine/spawner epoch while a replacement engine treats the same uid pool as empty and attributes its messages to new allocations. | B(R-GX-04) | C-06/C-07 | GX | yes G1+G4; T-01/T-03/T-44/T-49; supervisor method MM-10 |
| R-GX-05 | A delays a worker/result until uid/fd/request-number or local_agent_id reuse and a consumer relooks it up under a new execution. | B(R-GX-05) | C-08 | GX | yes G3+G4; T-32…T-38/T-40/T-45/T-50/T-51; consumer-only |
| R-G2-11 | An adversarially triggered accepted byte-origin/witness association fails C-01 outside the identified insertion/read/buffer cases; its concrete cause remains unresolved. | B(R-G2-11) | C-01 | G2 | no; T-20…T-25/T-64; origin-refinement slot; its disposition rests on the slot's closing property (PLAN §Follow-up plan after U), not on the totality of its predicates — since version 10 (follow-up step 4, 2026-10-19) the property's path half is established by the engine build's checks within the route file's stated limits; since version 12 (M1 repair, 2026-10-23) its memory half, the memory safety of the C reader, is recorded as a stated requirement not established (engine-requirements row 175, prove 2.2), so the route is conditional on unbuilt requirements |
| R-G2-12 | An accepted observation violates translation/decoding fidelity outside the identified alias/ancillary/ABI cases; its concrete cause remains unresolved. | B(R-G2-12) | C-03 | G2 | no; T-21…T-24/T-67; observation-refinement slot; its disposition since version 10 (follow-up step 4, 2026-10-19) rests on the slot's closing property (PLAN §Follow-up plan after U), established by the engine build's checks within the route file's stated limits, not on the totality of its predicates |
| R-G2-13 | A labelled acceptance lacks the required current comparison through an unrefined decision path outside the named cache/fallback cases. | B(R-G2-13) | C-04 | G2 | no; T-23…T-25; comparison-refinement slot; its disposition since version 10 (follow-up step 4, 2026-10-19) rests on the slot's closing property (PLAN §Follow-up plan after U), established by the engine build's checks within the route file's stated limits, not on the totality of its predicates |
| R-G3-05 | An attributed consumer changes or loses the original context in a way not yet reduced to numeric reuse, current join or label-only mutation. | B(R-G3-05) | C-08 | G3 | no; T-30…T-39; consumer-only refinement slot, an ordinary implementation obligation since version 7: every consumer step reaching the verified context by object reference, with no lookup or keying by name, uid, fd or local_agent_id, is design text (01 MM-16 resolved), discharged by the code at follow-up step 4 |
| R-G5-08 | A foreign task holds the row uid during its allocation by a cause not yet classified as a prior survivor, pre-existing holder or lawful later acquisition. | B(R-G5-08) | C-06 | G5 | no; T-01/T-05/T-61/T-62/T-67; holder-refinement slot, resting on deployment preconditions since version 7, stated premises the engine does not check (no separate disposition value, user 2026-10-18): the design writes the pool-exclusivity premise and its limit (01 T-01, T-67), and the deployer's uid inventory naming every holder of the range is the first deployment entry of engine-requirements §8 |
| R-GX-06 | A row/channel/allocation association is wrong for an unrefined reason outside installation, control correlation or numeric/object alias. | B(R-GX-06) | C-05 | GX | yes G1+G2+G4; T-01/T-09/T-23/T-24/T-40/T-45/T-52; association-refinement slot, an ordinary implementation obligation since version 7: the association created at row creation, installed at the prepared-fd install with one receiver_generation per Channel and cleared only by close step 2, by object, is design text (01 T-01, T-09, T-40, T-45, MM-15 resolved, AA-13), discharged by the code at follow-up step 4 |

Withdrawn in version 3 (IDs reserved, never reused): **R-G1-04** — its branch D_52 ∧ q21 selected no
history once u_r := A_r.uid, and the stored-field mismatch it described is D_33 → R-G1-02 (addendum
F-02); **R-G4-02** — reached only through the withdrawn p72, whose first-failure cell is empty because a
post-CLOSED acceptance with the original row's label is not false attribution (addendum F-01); its subject,
processing after session teardown, is a G4 preservation guard for Step 3. The live ledger holds 38 entries
(G1 5, G2 13, G3 5, G4 1, G5 8, GX 6); the seven refinement slots of U-02 keep their cells, and version
7 re-marks the standing of R-G5-06, R-G5-08, R-G3-05 and R-GX-06 as U-02 states.

## 7 Group cut (preservation ownership, not a condition partition)

Every 01 transition has exactly one preservation owner below; GX owns routes but no transition.
Calling T-40 from a group's rejection outcome does not move T-40 into that group. All success/refusal,
timeout and error outcomes of an assigned transition travel with it. T-66 is a boundary disturbance row,
not a transition assumed admitted by the normal invariant. T-67 tests configured premise departures.

| group | transition IDs owned | overlap ruling |
|---|---|---|
| G1 launch/admission | T-01, T-02, T-03, T-04, T-05, T-06, T-07, T-08, T-09, T-10, T-11, T-12, T-13, T-14 | hello's row activation belongs here; its bytes/check belong to G2. Local withdrawal remains a launch submission-ownership action even when called from close. RuntimeCopy is only an input to launch, not independent identity. |
| G2 receive/check | T-20, T-21, T-22, T-23, T-24, T-25, T-26, T-60, T-63, T-64 | owns send/read/framing and same-execution writers/endpoint movement; read-error outcome references G4's T-46. Outbound T-26 is retained because its whole-send facts drive T-12/T-31; not an outbound-confidentiality proof. |
| G3 request/dispatch | T-30, T-31, T-32, T-33, T-34, T-35, T-36, T-37, T-38, T-39 | try_dispatch's phase recheck is a consumer decision; lifecycle transitions can precede it. Current callbacks stay here, callbacks after release are T-51 in G4 and their interacting route is GX-05. |
| G4 close/reclaim | T-40, T-41, T-42, T-43, T-44, T-45, T-46, T-47, T-48, T-49, T-50, T-51, T-52, T-65 | owns execution_empty even when it precedes hello; all control sequence/tombstone handling; accepting_new latch on cleanup; supervisor epoch input; exit/queue timing. No global atomicity is inferred. |
| G5 boundary/configuration | T-61, T-62, T-66, T-67 | owns lawful credential/namespace state changes, policy departures and N1/N9 disturbance. G1 owns construction of the initial posture, whose preservation conclusions these routes do not pre-assume. |

Attribution-irrelevant exclusions retained from 01, with their relevant hook shown so they are not lost:

| exclusion | reason and modeled hook |
|---|---|
| X-01 | RuntimeCopy/storage state is not namespace-empty or uid-free; T-03 failure/T-40/T-45 retain its hooks. |
| X-02 | Capacity/backpressure changes ordering/availability; T-21/T-26/T-50 retained, Stream Q may reopen. |
| X-03 | Effect/retry classification is downstream of origin; T-33/T-34 keep context. |
| X-04 | HTTP/SSE mechanics do not determine local sender; T-34 carries the callback association. |
| X-05 | Export/receipt internals do not define message sender; T-38 keeps subject and failure-latch hooks. |
| X-06 | Adapter/LaunchPlan static inputs enter T-03, arbitrary adapter code enters T-11/T-20; a new entry requires a new freeze. |
| X-07 | Catalog selects resource, not sender; T-33 association remains. |
| X-08 | Provider/workspace internals excluded except static uid, workspace lease and reference-release hooks T-01/T-45, and, since 01 version 9, the local-instance deployment precondition (T-67) and the open supervisor method (MM-10). |
| X-09 | Grant rule/argument semantics authorize action, not identity; original-context joins and their producers/updates remain T-30/T-32/T-33/T-39. |
| X-10 | Outbound reads have no sender stamp; no outbound-confidentiality conclusion follows. |
| X-11 | Supervisor implementation outside frozen text, but its epoch-empty assertion is T-49/MM-10, not an established fact. |
| X-12 | Historical demos are evidence, not extra design transitions; Stream E assigns their tags. |

## 8 Condition × route-owner matrix

Cells list route suffixes; G2-03 means R-G2-03. A blank is never silently interpreted as coverage.
“No route” below means no direct route allocated to that family under this cut, not proof of immunity.
Boundary rows can affect every condition but are partitioned by H before the normal component split.

| condition | G1 | G2 | G3 | G4 | G5 | GX |
|---|---|---|---|---|---|---|
| C-01 | no route: launch does not assemble accepted bytes | G2-01,02,03,04,11 | G3-01 | no route: stale read/close interaction allocated GX | G5-01,02 | GX-01 |
| C-02 | G1-01 | G2-05 | no route: consumer does not stamp sends | no route: exit does not retroactively restamp bytes | G5-01,02,03,04 | no route: generation errors retain the old real stamp |
| C-03 | G1-01 (secondary),02 | G2-03,06,12 | no route: decode is G2 | no route: retirement does not render uid | G5-01,02,05 | no route: translation/capture component stays with its local owner |
| C-04 | G1-01 (secondary) | G2-02,07,08,09,13 | no route: D-ACC bypass is C-01, not an actual comparison | no route: a phase failure with the original row's label is not false attribution (former p72, now a G4 preservation guard); the comparison itself is G2's | G5-01,02,05 | no route: cross-generation identity is C-05/C-07; comparison may pass |
| C-05 | G1-03,06 | G2-04,08,10 | G3-01 | no route: cross-generation relabel allocated GX | G5-01,02 | GX-02,03,06 |
| C-06 | G1-05,06 (secondary) | no route: correct stamp does not itself allocate a uid | no route: consumer creates no process/lease | G4-01 | G5-01,02,06,07,08 | GX-02 (secondary),04 |
| C-07 | no route: admission/retirement interaction allocated GX | no route: old queue/buffer interaction allocated GX | no route: post-D-ACC callback continuity is C-08 | no route: a phase or generation error with the original row's label is not false attribution; post-CLOSED processing is a G4 preservation guard (former p72) | G5-01,02 | GX-01,02 (secondary),03,04 |
| C-08 | no route: launch is not a D-ACC consumer | no route: wrong original label is C-05 | G3-02,03,04,05 | no route: late callback interaction allocated GX | G5-01,02 | GX-05 |

[R1](../reviews/R1-2026-10-13.md) reviewed 01 and this file against the frozen text; all findings were
accepted, repaired and confirmed by targeted recheck. The [cross-family addendum](../reviews/R1-addendum-2026-10-13-crossfamily.md)
(Claude Opus, cold context) added sixteen findings; all were accepted and repaired in version 3 (p53
added, p72 withdrawn, R-G1-06 added, R-G1-04 and R-G4-02 withdrawn, q33 added, q21/q28/q29 retired,
§4.3 written, 01 version 7 for F-06/F-07); the targeted recheck sections of the addendum state whether
the version-3 candidate passes the Step 2 candidate gate, and this file does not assert it. At most the
candidate gate is at stake here: not transition preservation, not correspondence of the real system to
M, and not deployment security. No fan-out gate is opened.
Next: optional user ledger scan, then Step 3 and Stream E; the seven causal-refinement slots
remain explicit, four of them with the version-7 standing of U-02. [Change requests](../convergence/change-requests.md) identify the changed spine IDs.
