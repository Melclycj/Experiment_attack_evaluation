---
title: Stream Q — Concurrency challenge of the local uid binding (yield points, collapses, the D7 abstraction, bounded follow-up)
date: 2026-10-14 (the TLC runs of §5 ended on 2026-10-15)
group: Q
owner: Stream Q subagent (cold-context Claude Fable 5.1), dispatched by the main session
status: ready-for-reconcile
based_on:
  model_blob: "1461a0f9feb23817"
  decomposition_blob: "8627a717b631d01b"
  invariant_blob: "6868389a2182c161"
  registry_blob: "52e0625ffeebf23a"
frozen_revision: 2026-10-12 — the ten files and blob ids in PLAN.md §Frozen design revision; kernel-uid-binding.md at the 2026-10-13 evidence-only blob 131fce72d01a5df8
reading_rule: this file judges interleavings and abstractions, not routes. It assigns no disposition, names no defence for a ledger route, and does not weaken I. "Decided by the frozen text" means the text states the ordering or rule that fixes the outcome; it is not a claim about the deployed system. Evidence is cited by EV ID only.
vocabulary_note: CLOSED is the design's state name (01 vocabulary_note) and is not used as a coverage word; "the engine closes the fd" is the T-40 step 2 action.
---

# 05 — Concurrency challenge (COV-4)

Scope: PLAN §Execution flow, Stream Q. (1) The yield points of the frozen text and the interleavings it
permits there, sorted by attribution relevance under the 02 condition list; (2) a justification row for
every collapse of states, inputs or histories that 01 and 03's model make; (3) a re-examination of the D7
common abstraction under interleaving; (4) numbered challenges; (5) a bounded tool-assisted follow-up,
specified before it was run; (6) unresolved relations for the reconcile role; (7) change requests. Source
abbreviations follow 01 (`conn`, `rr`, `si`, `sbx`, `iv`, `mech`, `optb`, `kub`, `scope`, `tm`). Transition,
condition, guard and evidence IDs are cited, never restated; nothing here is a preservation conclusion of
any group, and no group's preservation conclusions are cited.

## 0 The yield points of the frozen text

The model of 01 and 03 interleaves at executor-turn granularity plus the kernel and spawner events of 01
§3.5 (AA-01). The frozen text has five places where another actor may run; every row of §1 names one of
them.

| yield point | where the text states it | who runs in the gap |
|---|---|---|
| executor turn boundary | conn L574–579: one state executor serializes every local decision; "one decision" = no `await`; it gives no atomicity with kernel exits, spawner notifications or worker I/O; conn L725–728: one scheduling round = at most 8 control events, expired timers, one `recvmsg` per ready channel, one event per runnable request, one `sendmsg` per writable channel, round-robin | timers, control records, other channels' reads and writes, worker returns, nothing inside a decision |
| socket syscall boundary | conn L413–418: one non-blocking `recvmsg` per step for the remaining header or body length; conn L443–449: one `sendmsg` per step, partial writes allowed | between two fragments of one frame: everything the executor-turn boundary admits, including the close of this row (hence the "not CLOSED" check before each read) |
| spawner loop turn | conn L314–316, L162–163, L279–280: a bounded event loop serving many `SpawnRecord`s; file jobs do not block control/stop/reap; a `stop` arriving during copy creation seals clone first; `socketpair` and `clone` are consecutive syscalls of one turn | other records' events, control records from the engine, SIGCHLD reaping (the single reaper, K-05), file-worker results |
| kernel event | 01 K-01 … K-10: exits at any instant, the zap of P_X on PID 1's death, asynchronous namespace teardown, arbitrary scheduling delay before the engine or spawner processes an event, skbs that outlive their sender | the kernel, at any instant, independently of both processes |
| worker return | conn L574, L608, L619–620, L634–641; si L111–112, L184–189: prepare, connector, file and log workers return facts to the executor by object reference and never write `Session` or `RequestEntry` | the result lands in a later executor turn, after any number of other decisions |

Two readings fix what "decided by the frozen text" can mean below. A yield point inside a sequence the
text calls "one decision" (T-01, T-09 install, T-33, T-40 step 1, the T-38 reservation) is excluded by the
text; the exclusion is a design statement about an unbuilt executor (EV-78 for the receive path; the
executor itself is design text), so every "decided" verdict below is design-level and inherits that
`[S]`. A yield point the text neither excludes nor orders (T-40 steps 2–4, MM-09; admission after the
parse, §1 row 20) is unstated; where both orders keep I within the bounds of 03 §5, the row says so and the
relation still goes to §6. Both examples are stated in 01 v9 (T-40: steps 1–4 one executor decision, MM-09
resolved; T-24 and T-30: the parse, T-25 and admission one decision, conn L484–485); the verdicts below are
those of the 2026-10-12 freeze this file judged; where the second-freeze design text (01 v9) decides a relation that freeze left open (§1 rows 20, 26 and 35; challenges 2 and 14), the cell adds that verdict, marked "decided by the second-freeze design text". That verdict is design-level `[S]` like every other here; the TLC runs of §5 used the 2026-10-12 freeze and were not re-run.

## 1 Yield points and permitted interleavings

One row per interleaving examined. "Relevance" names the 02 condition or 03 guard the interleaving could
disturb, or says attribution-irrelevant with the reason. "Decided" says whether the frozen text fixes the
outcome; the citation is the deciding sentence. No row says what a group's preservation file concludes.

| # | transition (01) | yield point | interleaving the text permits | relevance | decided by the frozen text? |
|---|---|---|---|---|---|
| 1 | T-01 | executor turn boundary (T-01 is one decision) | T-45 of the previous lease of the same workspace uid in an earlier turn, then T-01 for a new execution of the same workspace while the old execution's slot is still held (`runtime_copy_view ≠ released`) | C-05 p51, C-06 p61 (IG-06, IG-07): the new row must take the lease, not the old slot's state | yes — T-01 reads the pool, the slots and `WorkspaceRecord`; the previous lease must be `free` and have satisfied CLOSED ∧ empty (rr L560–565); the slot gate is independent (conn L167–169); nothing is read from the old slot (MM-12 records that this is design text, not an invariant) |
| 2 | T-02 | control writer's ownership domain | withdrawal (T-14) racing a whole send of the same record; EAGAIN/EINTR with nothing sent | IG-03, IG-04 (C-06): `local_never_submitted` may be written only if nothing was ever sent | yes — the writer withdraws "in its own ownership domain" and confirms irreversibility before the empty fact; an indeterminate result is `uncertain`, never `local` (conn L797–798, L322–323) |
| 3 | T-02 → T-03 → T-05 | spawner loop turn vs executor turn (K-04) | the engine has CLOSED the row (`uncertain` branch, or any T-40 trigger) while the spawner, which does not read row state, admits and clones | IG-02, C-06 p62: a live task at u for a CLOSED row | yes — the lease stays held until the spawner's empty fact (conn L322–323, L805–808); the row waits, the stop follows (T-40 step 4); within the bounds of 03 §5 run 2a shows what the membership half does on this path |
| 4 | T-03 | spawner loop turn | `stop` arriving during the asynchronous copy job; `stop` arriving after clone but before SEALED | IG-04: `never_created` only for a record that never cloned | yes — "stop seals clone first" (conn L162–163); after clone the record is killed and reaped (T-41/T-42); EV-98 `[M]` under the diagnostic policy |
| 5 | T-04, T-05 | spawner loop turn | none involving X: `socketpair`, `setsockopt(SO_PASSCRED)` and `clone` are consecutive syscalls of one turn; no task of P_X exists before `clone` | C-05 (IG-12): the socketpair created for X's record is the one X's clone inherits | yes, by construction (conn L277–281; optb step 0); the peer identity has no kernel query (MM-05) and is carried as AA-04 |
| 6 | T-06, T-07 | kernel event (the child runs concurrently with the spawner loop) | the pre-drop child, at the spawner-side credential, runs while the spawner serves other records; the engine holds no fd | C-02 p22, IG-10: a byte stamped with the pre-drop credential | yes — the engine receives nothing before T-09; the spawner reads only SEALED (conn L293–295); a pre-drop FAIL is record failure, never an authorization fact (conn L287–288); 03 §5.2 restriction |
| 7 | T-08 | socket syscall boundary at the spawner (per fragment) | the spawner serves other records between SEALED fragments; a FAIL, mismatch, EOF or deadline arrives mid-record | C-05 (IG-09, IG-12): the fd handed to the engine belongs to the child that sealed | yes — per-fragment ancillary, `uid == allocated u`, `pid == child_pid`; failure → `spawn_failed`, the spawner drops its engine-end copy (conn L293–295); EV-76 `[M]` diagnostic |
| 8 | T-09 vs T-43 | executor turn boundary (two control records on one fd, but empty may precede prepared) | `execution_empty` processed before `spawn_prepared` | C-05 p51/p52, C-07 (IG-01, IG-09): a late fd must not enable or re-key a row | yes — empty first → row CLOSED; a later prepared closes the received fd and the message does not enable the row (conn L334–336, L324); matching is by `engine_epoch`, `execution_id` and `lease_id`, never uid or fd (conn L138); EV-97 `[M]` diagnostic |
| 9 | T-09 vs T-40 | executor turn boundary | the row reaches CLOSED (deadline, record failure) between the spawner's `sendmsg` and the engine's `recvmsg` of prepared | as row 8 | yes — the late-prepared branch of T-09 (conn L324) |
| 10 | T-09 vs T-52 | executor turn boundary | a consumed `spawn_prepared` arrives again, byte-identical or not | C-05 p51 (IG-09): no re-install into an old `Channel` | yes — the engine closes every fd of the repeated record first, then raises a control fault (conn L135–137) |
| 11 | T-10 | socket syscall boundary (partial COMMIT writes) | the startup deadline, EOF, or other data reaching the child during the partial send | attribution-irrelevant: no adversary exists before `execve` (AA-09) | yes — the child exits on anything but a full COMMIT; the engine's whole-send gate (conn L297, L302–304) |
| 12 | T-11 vs T-21 | kernel event (`execve`) vs executor turn | the engine's reader is installed (STARTING) before the adversary exists; the adversary's first byte follows the whole COMMIT | C-01 p11 (every accepted origin is a task of P_X after T-11) | yes — the child `execve`s only after receiving the full COMMIT (conn L297, L302–303); the phase move to `hello` is read as the whole COMMIT send (MM-17, recorded not resolved) |
| 13 | T-12 | executor turn boundary (welcome queued) | a `request` arrives while the row is STARTING with `welcome` not yet fully sent | attribution-irrelevant: phase (the former p72, 02 §2 note); the frame still passes T-21 … T-24 with the row's own label | yes — refused, and the row goes to CLOSED (conn L305) |
| 14 | T-20, T-60 | kernel event (concurrent sends by several tasks of P_X) | two or more same-uid tasks of one execution write concurrently; one frame is assembled from skbs of several tasks | attribution-irrelevant by D-GT: same-execution origins are one principal (W2.1) | yes — bytes are delimited per skb and the frame is attributed to the execution, not a pid (conn L403, L1161); EV-77 `[M]` diagnostic (different same-uid children sent jointly) |
| 15 | T-20 vs T-65 (K-01, K-06) | kernel event | the sender exits, or PID 1 exits and the zap kills it, after the send and before the engine's read; `execution_empty` arrives before the read | C-07 p71 (IG-08 `inJ`): send_b lies in J_r because the send preceded release | yes — live-at-send (mech CRA-F12; EV-44); the skb outlives the sender (K-06; EV-58 `[M]` on a datagram socket — no `SOCK_STREAM` source location is registered, 03 §6) |
| 16 | T-21 | socket syscall boundary (between fragments of one frame) | timers, control events, other channels' reads, the close of this row by any T-40 trigger | C-01 p13, IG-13: a fragment read after the close would be read from a CLOSED row | yes — "check before each read that the original object is not CLOSED" (conn L413 step 1); the partial frame is discarded at T-40 step 2 (conn L791–792) |
| 17 | T-21 → T-43 → T-40 → T-45 → T-01 | socket syscall boundary, then several executor turns | between two fragments of X's frame: X's empty fact, close, release, and a new execution Y of the same workspace reserved with the same uid | C-01 p13 (q05/q07), C-05 p51, C-07: X's partial frame or X's queue must not become Y's | yes at the design level — Y receives a new socketpair (T-04, one per execution; IG-12); X's `FrameReader` is per `Channel` and is cleared at close, never reused across `Channel`/`TaskCall` (conn L409–410, L438–439, L791–792); realization `[S]` (EV-78) |
| 18 | T-21 … T-23 under A-07 | socket syscall boundary | a task of execution Y (uid u_Y ≠ u_X) holding X's peer end writes a segment between two of X's fragments | C-04 p41/p42 (R-G2-07's cached-credential shape; R-G2-09's endpoint shape) | yes — the kernel ends a receive return where the stamped credential changes (EV-88 `[R]`); every positive-length fragment is compared against the immutable `expected_uid` and any failing fragment discards the whole frame (conn L422–424); EV-77 `[M]` diagnostic, transport library; product receiver `[S]` (EV-78); skb-level check within bounds: §5 run 5c |
| 19 | T-24 | executor turn boundary (the parse is in the same `receive_step` as the last fragment) | a close trigger lands in the next turn; the D-ACC finishes on a row that is then CLOSED | attribution-irrelevant for P_acc: the label is the row's own (IG-13; 02 §4.1 item 3) | yes — `receive_step` returns `ValidatedMessage` from the row read through the `Channel` (conn L508–518) |
| 20 | T-24/T-25 → T-30 | executor turn boundary (unstated in the 2026-10-12 freeze whether admission shares the parse's turn; 01 v9 T-30: it does) | any executor work between the parse and `admit_request`, including close of the row or RESOLVED of the call | C-08 p81 only: the label is fixed at D-ACC and travels by object reference; admission is a consumer decision | yes for P_acc (conn L515–516); for C-08 by the object-reference rule (conn L523, L617–618); the turn structure itself is unstated in the 2026-10-12 freeze and is decided by the second-freeze design text: the parse, T-25 and `admit_request` are one executor decision with no yield (01 v9 T-24, T-30; conn L484–485), so no executor work runs between them — §6 |
| 21 | T-26 | socket syscall boundary (partial writes) | reader, timers, other sessions and the spawner run while the writer waits; a frame is half-sent when a close or cancel lands | attribution-irrelevant: outbound carries no credential (X-10; EV-43); the whole-send facts drive T-12/T-31, which are phase and call state | yes — the current frame finishes or the channel closes; no frame switch mid-frame (conn L443–449, L656–658) |
| 22 | T-32 | worker return | close, revoke, deadline or `task_result` lands before the prepare result returns | C-08 p81: the result must still name the original `RequestEntry`/context | yes — the result carries no permission and is re-checked in T-33's one decision; a terminal entry, or one whose row is CLOSED, only releases (rr L261–283; conn L608, L614) |
| 23 | T-33, T-39 | executor turn boundary (T-33 is one decision with no `await`) | `GrantState.revoke`, `close_session`, rebind, before or after the dispatch decision | authorization content (X-09); C-08 p81 unaffected (the context reference is the original) | yes — revoke and the final decision are ordered by the same executor; rebind only with no active call or request (rr L280–281; 01 T-39) |
| 24 | T-34 → T-51 | worker return | a handler callback (chunk, terminal, released) arrives after the row is CLOSED, after T-45, or after T-01 reused the uid | C-08 p81/p82 (R-GX-05's subject) | yes at the design level — the callback holds the original object; no lookup by uid, fd or request id (conn L523, L835–837; rr L528–529); realization `[S]` |
| 25 | T-38 | executor turn boundary (the record reservation shares T-33's decision; the latch is read once per round) | the record latch fails after the reservation and before or after `handler.start` | C-08 p82: no originless subject may be created by the failure path | yes — `verified_subject` is copied from the `VerifiedContext`; a failed latch sets `accepting_new = false` and closes sessions; stop/reap proceed regardless (si L93, L184–189); the lost record is `evidence_incomplete`, not a relabel (X-05) |
| 26 | T-40 steps 1 → 2 | executor turn boundary (MM-09: whether steps 2–4 share step 1's decision is not stated in the 2026-10-12 freeze; 01 v9 resolves it, steps 1–4 one decision) | queued skbs persist on the socket between the two steps (K-06); T-45 may run before step 2 if the text's order allows it | C-07, C-01 p13, IG-08/IG-13 (R-GX-01, R-GX-03 subjects) | ordering unstated in the 2026-10-12 freeze (MM-09; 01 v9 T-40 and T-45 now state steps 1–4 as one decision and release only after close step 2, conn L870–873); both orders keep I within the bounds of 03 §5 (run 1 uses the adversary-favourable `MM09_ReleaseNeedsFdShut = FALSE`), because no read occurs on a CLOSED row (conn L413) and a new execution gets a new socketpair (T-04). **Yes, decided by the second-freeze design text**: steps 1–4 are one executor decision with no yield and the release at step 6 requires close step 2 done, registration removed and the fd's close performed (01 v9 T-40, T-45; MM-09 and MM-11 resolved; conn L870–872), which excludes T-45 before step 2; the run's FALSE branch over-approximates this text and was not re-run — §6 |
| 27 | T-40 step 4 | control writer / control queue | the stop intent merges into the record's boolean; the control queue is unwritable for 5,000 ms; T-49 fires meanwhile | C-06 p61 (IG-06): the lease must not be freed on a stop that never reached the spawner | yes — a stop intent is one boolean per record; persistent unwritability is a control fault (conn L801–803, L869–873); 5,000 ms empty-wait only after a whole send (conn L813–814) |
| 28 | T-41 vs T-42 vs K-10 | spawner loop turn (single reaper) | PID 1 exits on its own just before the spawner's SIGKILL; the numeric pid is reused on the host after the reap | C-06 p62 (IG-05, IG-11): a missed or wrong kill must not free the lease | yes — the spawner signals only the unreaped direct child and never a numeric pid after reaping it (conn L802; EV-79 `[M]` diagnostic); kill success, ESRCH, ECHILD are not empty facts (conn L834–835) |
| 29 | T-42 vs T-21 | kernel event | the engine reads skbs from senders the zap has already killed; `execution_empty` arrives before or after that read | C-07 p71: those sends preceded release; attribution is correct (live-at-send) | yes — EV-17 `[R]` (`zap_pid_ns_processes` ordering), EV-67 `[M]`; mech CRA-F12 |
| 30 | T-43 vs T-44 vs T-45 | executor turn boundary | the 5,000 ms wait expires (quarantine), then a matching real empty arrives; a duplicate empty with equal terminal fields arrives after release | C-06 p61 (IG-06): one release per lease | yes — a matching real empty in the same healthy epoch lifts the quarantine, then T-45's gate applies once; duplicates are ignored, no second release (conn L328, L813–814, L831–832) |
| 31 | T-45 vs the slot and `runtime_status` | executor turn boundary | the uid is freed while the execution slot and the runtime copy of the old execution are still held; `runtime_status` arrives before or after `execution_empty` | C-05/C-06 (MM-12): a new row must not read the old slot | yes by design text — the two gates are independent and T-01 reads neither the old slot nor the copy view (conn L167–169, L172–176); not by an invariant (MM-12) |
| 32 | T-47 | executor turn boundary (the 5,000 ms grace is a timer) | reads continue in DRAINING; `bye`, EOF or empty arrives; the grace expires | attribution-irrelevant for P_acc: the lease is held until CLOSED, so a D-ACC in DRAINING carries the row's own label; the admitted type set is phase | yes — DRAINING keeps the channel and checks every credential (conn L486–487, L818–819) |
| 33 | T-49 → NewEpoch | kernel event (SIGKILL/OOM of the spawner) and supervisor | the old engine's rows are CLOSED and its lease quarantined; the spawner's sweep is interrupted; a new engine epoch starts on the supervisor's fact while an old task survives | C-06 p61/p62 (IG-02 at the new epoch's initial state; R-GX-04's subject) | **no** — the supervisor's method is outside the frozen text (MM-10; X-11); 03 §3 records the soundness of its fact as a premise; the `MM10_SupervisorFactSound = FALSE` branch was not run |
| 34 | two engines on one pool | outside the model (one engine per model) | a second engine process allocates a uid that this engine's lease also holds | C-06 p61 (R-G5-06's subject; U-05) | **no** — a deployment precondition, not a mechanism (EV-81 `[S]`); no text orders two engines |
| 35 | T-01 `local_agent_id` vs a consumer keyed by the name | worker return after reuse | a worker result or record for execution X is resolved by the recurring `local_agent_id` after Y took the same name | C-08 p81 (q30) | **partly** in the 2026-10-12 freeze — the text states a new execution under a recurring name inherits nothing (conn L79, L343) but states no assignment event and no keying rule for consumers (MM-16). **Yes, decided by the second-freeze design text**: the executor writes `local_agent_id` once at row creation (conn L95–97), a recurring name brings no state (conn L101), and every consumer step reaches the `VerifiedContext` by object reference and neither looks it up nor keys state by name, uid, fd or `local_agent_id` (conn L581–583; for the two keyed consumers it names, rr L245–247 and L386–387) — 01 v9 MM-16 resolved; a consumer keyed by the name (q30) is now a departure from that text (02 v7); §6 |
| 36 | T-64 | kernel event (alternate write syscalls into fd 3) | `splice`, `sendfile`, `sendmmsg`, `write`, `MSG_OOB` interleaved with `sendmsg` by tasks of P_X | C-01 p12, C-02 p21: every path must stamp per skb | yes at the kernel level — all stream write paths reach `unix_stream_sendmsg`/`queue_oob`, which stamp each skb (EV-10, EV-11 `[R]`); OOB/POLLPRI closes the row (T-46); whether the production allow-set admits these calls is S2 `[S]` (EV-93 diagnostic) |

Counts over the 36 rows: attribution-relevant under C-01 … C-08 or a 03 guard: 30 (rows 1–10, 12, 15–18,
20, 22–31, 33–36; row 20 counts under C-08 only); attribution-irrelevant with a stated reason: 6 (rows 11,
13, 14, 19, 21, 32). Decided by the 2026-10-12 frozen text: 32; ordering unstated but I-preserving in both orders
within the bounds of 03 §5: 1 (row 26); not decided: 3 (rows 33, 34, 35). Under the second-freeze design
text (01 v9): decided 34 — the 32 (row 20's turn structure now stated as well), row 26 and row 35; not
decided: 2 (rows 33, 34).

## 2 Justification table — every collapse of states, inputs or histories

One row per collapse in 01 and 03's model (03 §5.2, §6 "to Stream Q", AA-01 … AA-12). Columns as PLAN
§Execution flow requires. "Justified" means the attribution-relevant distinctions (the inputs of C-01 …
C-08 and the guards of I) survive the collapse within the stated limit; "not justified" means a
distinction is lost and the row says which. Over-approximations are sound for a safety property by
construction (they add behaviours) and are listed because the group files must not rely on the behaviour
they add; restrictions drop behaviours and need a reason.

| what was collapsed | why attribution-relevant distinctions are preserved | limit |
|---|---|---|
| **Executor-turn granularity (AA-01).** All intra-decision interleavings of the engine are erased; the model interleaves only at turn boundaries and kernel/spawner events. | The text names which sequences are one decision (T-01; T-09 validation and install; T-33 checks through `handler.start`; T-40 step 1; the T-38 reservation) and says a decision contains no `await` (conn L574–579). Every attribution-relevant write of a label or lease happens inside one such decision, so no half-written row or label is observable by another engine decision. Kernel exits, spawner notifications and worker I/O are kept concurrent, as the text says. **Justified.** | The single-writer executor is design text; the receive path is unbuilt (EV-78 `[S]`), the engine and spawner were never run as two processes (EV-72 `[S]`). An implementation that yields inside a "one decision" sequence voids every "decided" verdict of §1. |
| **Two executions, each reserved at most once (`Execs = {1, 2}`).** | With one uid slot the two ids express exactly the reuse relation (generation n → n+1) that C-06/C-07 and IG-01/02/08 are about; every other pair of executions in the design has distinct uids and interacts only through the per-fragment comparison (T-23) or through A-07, which is a parameter. **Justified**, with the concurrent-rows case checked separately. | At most one row is open at a time in the model (03 §5.2), so no interleaving between two *open* rows is explored. §5 runs 5a and 5a-t2 (three executions, two uids) explored it to depth 23 and 25 without a violation but did not finish within the time bound, so the row stands on this prose, not on a run. |
| **One uid slot (`U`; one lease).** | In the frozen text a uid is statically one-to-one with a workspace and a workspace runs one execution at a time (rr L560–565), so two executions share a uid only sequentially through T-45 → T-01 — the one-uid model — or through a failed check (R-G1-05, R-G1-06) or a second engine (R-G5-06), which are routes, not interleavings. Distinct uids never equal `expected_uid` of the other row, so the cross-uid interleavings reduce to the T-23 mismatch outcome. **Justified**, with the mismatch branch checked separately. | The `Accept` mismatch branch has no coverage in 03's runs (03 §5.2); a cross-uid A-07 send is therefore not exercised there. §5 run 5c exercises it to the end of its bounds (no false acceptance); runs 5a and 5a-t2 give the branch coverage but did not finish. |
| **At most three tasks per execution (`Tasks = {1, 2, 3}`, task 1 = PID 1).** | The attribution-relevant distinctions among tasks are membership of P_X (all tasks), the PID 1 / non-PID 1 split (K-02, IG-05, IG-11), and "a survivor that forks" (T-60). Two non-PID 1 tasks let one exit while another sends and one fork while PID 1 is dead. **Justified.** | Thread groups and tgid-level merging (D-GT, MM-03) are not in the lifecycle subset; the 16-slot and per-session bounds of conn L713–720 are not represented (X-02). |
| **Receive queue ≤ 2 skbs per channel (`MaxQ = 2`).** | IG-08 is a per-element predicate and `Accept` reads one head skb; the only ordering fact needed is that a stale skb and an in-interval skb can coexist, which two slots express. **Justified.** | Frame assembly across skbs and head-of-line effects are outside the subset (next row); capacity-driven ordering is X-02. |
| **At most two allocation generations.** | After T-45 the state of the retired execution is CLOSED, its socket may be open in the subset's `MM09_ReleaseNeedsFdShut = FALSE` branch (01 v9 T-45 releases only after close step 2) but is never read (IG-13), and no live task of it exists (IG-02 across the release). That is the same shape as the initial state plus a dead row, so a third generation repeats the n → n+1 relation. **Justified by this prose**; not shown by 03's runs. | 03's bound does not reach a third generation; §5 run 5b (three executions on one uid) checked it within bounds with no violation. The 1,024-entry tombstone window (T-52) is not modeled (AA-08). |
| **At most two engine epochs.** | One `ControlLoss` → `NewEpoch` expresses the only epoch-crossing relation (old leases never recovered; the pool restarts free). **Justified.** | The FALSE branch of `MM10_SupervisorFactSound` is not run (03 §5.2); §1 row 33. |
| **DRAINING abstracted to ACTIVE (T-47); `bye` as a `CloseRow` trigger (T-48).** | In DRAINING the lease is still held (release needs CLOSED), the channel is kept, every credential is checked and reads continue (conn L486–487, L818–819); the admitted message set and the cleared admission flags are phase, which does not bear on attribution (02 §2 note after the table). The grace expiry is a close trigger, which `CloseRow` already fires nondeterministically. **Justified.** | The outbound `shutdown` frame is not modeled (T-26 outside the subset); `TaskCall.DRAINING` is a different object (conn L821) and is G3's. |
| **`Fork` after PID 1's death (over-approximation).** | Adds behaviours only; the kernel forbids new pids in a zapped namespace (EV-17 `disable_pid_allocation`). The invariant held with the extra behaviours (03 §5.4 run 1), so nothing rests on the kernel refusing. **Justified (sound).** | A group file must not cite the model as showing that a post-zap fork is harmless; it shows that I does not need the kernel's refusal within bounds. |
| **`Launch` regardless of the row state and of control loss (over-approximation).** | Models K-04: the spawner may not have seen the stop or EOF yet. Adds behaviours; §1 row 3. **Justified (sound).** | — |
| **`Handoff` folds T-10 and T-11, sets `execd` for an empty P_X (over-approximation).** | A COMMIT failure ends the child without an adversary (AA-09); an empty P_X enables no action; a channel installed for a dead PID 1 is a STARTING row that only the deadline closes. Adds behaviours. **Justified (sound).** | — |
| **T-01's previous-lease check (CLOSED ∧ empty) not encoded (relaxation).** | `Reserve` needs only `lease = free`; the model admits every history the check would refuse, so a violation hidden by the check cannot be hidden by its absence. Sound for run 1. **Justified (sound).** | Runs 2a–2c therefore measure the membership half in a subset where this check is absent (03 §5.2, R2 F-04); G1 examines the check itself. |
| **T-03's spawner admission checks not encoded (relaxation).** | `Submit` admits every record; same argument. **Justified (sound).** | G1 examines the checks; the occupancy check's relation to T-45 is G4's. |
| **One skb = one fragment = one frame (AA-07 collapse; receive abstracted).** | The per-fragment comparison compares each positive-length fragment with the same immutable comparand `e_r` (conn L422–424; C-04 p42), a failing fragment discards the whole frame, the `FrameReader` is per `Channel` and is cleared at close (conn L409–410, L791–792), and no read occurs on a CLOSED row (conn L413). So for the lifecycle questions I asks — which skbs can sit on which row's queue and whether their stamp equals `expected_uid` — a frame of n fragments behaves like n independent skbs whose acceptance is conjoined, and the cross-fragment interleavings of §1 rows 16–18 are decided by the same sentences that decide the one-skb case. **Justified at the design level.** | The G2 check logic (framing, length, deadline, parse) is not modeled, so the model exhibits no R-G2 route; the product receiver is `[S]` (EV-78) and the measured per-fragment behaviour is the transport library under the diagnostic policy (EV-77); the 5,000 ms frame deadline's interaction with fragment timing is an availability property (X-02). |
| **T-20 (a) only; the stamp is the sender's `uidOf` (C-02 by construction).** | Branches (b)–(f) of T-20 are G2 and G5 inputs that change *which* uid is stamped, not *when* a stamp can reach a row; the lifecycle subset asks the latter. **Justified as a scope split.** | The model cannot refute C-02; the stamping facts are EV-07, EV-08, EV-10, EV-11 (`[R]`); the explicit-foreign-uid probe is Stream P's. |
| **The uid never changes after T-07 (T-61, T-62, T-67 excluded).** | Departures are preconditions of G5 routes against IG-02, not interleavings of the lifecycle. **Justified as a scope split.** | — |
| **Execution slot and `runtime_copy_view` omitted (MM-12).** | T-45 frees the uid independently of the slot; T-01 reads the pool and lease state, not the old slot (conn L167–169); so the slot carries no attribution state and its omission removes no distinction the guards use. **Justified.** | By design text, stated in 01 v9 (MM-12; conn L101–102), not by an invariant; G1/G4 confirm from T-01's reads. |
| **Time as events (AA-05): deadlines, grace periods, the quarantine wait and the frame deadline are nondeterministic events.** | No numeric value enters any label or lease decision; every deadline-driven transition is a trigger the model already fires at any instant (`CloseRow`, `Quarantine`). **Justified.** | A timing *distribution* can be adversary-influenced across executions (§3, §4 challenge 13); the model's nondeterminism covers every instant, so no distinction is lost. |
| **Control channel atomic and `seq`-ordered; T-50, T-51, T-52 omitted (AA-08).** | Records are whole or absent (conn L131–133); the tombstone window matters only for idempotence and faults (T-52), which never revive an execution; T-50/T-51 are consumer bookkeeping with no label write. **Justified.** | A late event beyond the window is a control fault (T-49), which the model fires nondeterministically; T-51 is R-GX-05's subject. |
| **The pre-drop member (T-05 … T-07) is not a state (restriction).** | No byte of that member reaches the engine: the spawner reads SEALED and nothing further (conn L293–295), a pre-drop FAIL is record failure (conn L287–288), and the engine holds no fd before T-09. I_acc is unaffected; IG-10's uid clause is stated post-drop. **Justified.** | MM-05 (the peer's identity has no kernel query) is carried as AA-04; a spawner that handed the engine a different socket would be a trusted-actor fault (R-G1-06's shape), not an interleaving. |
| **A stop for a record the spawner never received yields no empty fact (restriction).** | The text does not state a `never_created` answer for this case; it states that an unknown execution in a control record is a control fault (conn L136–138), which the model fires as `ControlLoss` at any instant, and otherwise the 5,000 ms wait quarantines the lease. The dropped behaviour is one the text does not admit. **Justified.** | — |
| **A wait error after a spontaneous PID 1 exit with no stop and no failed record has no quarantine path (restriction, 03 §5.2).** | In the text a spontaneous exit reaches the engine as EOF (T-46) → T-40 → stop intent (step 4) → whole send → the 5,000 ms wait → quarantine; the model has that path (`CloseRow` → `SendStop` → `Quarantine`). The case "no stop" does not arise for a submitted record. **Justified.** | 01 v9 T-41 names the carriers: a kill error is `spawn_failed(stage = reap)`, a wait error is that record sent best effort followed by control loss (T-49), each ending in quarantine and never in an empty fact (conn L121–126) — §6. |
| **Request state and consumers not modeled (N requests → none).** | C-08 is outside I by construction (03 §1.3); P_carry is G3's. **Justified as a scope split.** | R-GX-05 and the C-08 interleavings of §1 rows 20, 22–25 are decided by text, not by the model. |
| **Descriptor possession as a parameter (`A07`), not a transition.** | The frozen text produces no state in which a task holds a foreign peer end (01 A-07); stipulating it as a constant lets the model explore the adversary-favourable histories without inventing an acquisition transition. **Justified.** | Acquisition histories are Stream E's evidence (EV-42, EV-48, EV-63) and G2/G5 routes; the model says nothing about them. |

Collapses justified: 24 of 24 rows; not justified: 0. Two rows are justified by prose that 03's runs do
not reach (two generations; one uid slot with the mismatch branch unexercised) and are the subject of the
follow-up in §5; three rows are justified only at the design level and inherit the `[S]` of the unbuilt
executor and receiver (executor-turn granularity; the receive collapse; the pre-drop restriction).

## 3 The D7 common abstraction under interleaving

PLAN §Frozen design revision states one model for {C-LS · C-LP · C-R} because the agent ↔ engine leg is
identical in all three, resting on three `[S]` items (production S2 allow-set; the E-07 plaintext rule; no
business fd-pass in the first version). The question here is whether the leg stays identical when the three
configurations are interleaved with the lifecycle, and which `[S]` items that rests on.

**Which transitions can see the configuration.** Of the 01 transitions, only T-32 (prepare), T-34 (handler
and callbacks), T-35 (slot return) and T-38 (record emission) touch a worker or connector whose behaviour
depends on where the model runs; all four are consumers after D-ACC (X-03, X-04, X-05). Every transition
that writes a label or a lease — T-01, T-09, T-21 … T-24, T-40, T-43, T-45 — reads only engine objects,
the data socketpair and control records, none of which carries a configuration-dependent field: the
`ProviderConfig` endpoint is per resource descriptor (rr L96–99), and `credential_partition_id` is per
provider configuration, not per execution. So the inputs I-01 … I-06 of 02 §1 are configuration-independent
by the text; only I-07 (consumer references) can differ.

**What differs under interleaving.** The configuration changes the timing distribution of worker returns:
C-R adds network latency and remote failure; C-LS adds queueing behind other agents' requests on one
server; C-LP removes the shared queue but keeps the shared host CPU (tm D7 cites the CCT README's §B/§E
rows). This moves *when* T-34 callbacks and T-51 late callbacks land relative to T-40, T-45 and a T-01
reuse, and it lets one execution influence *when* another execution's row closes (an output stall of
5,000 ms or a deadline forced by a saturated server, conn L731–733, L713–739). Two facts make these timing
differences attribution-irrelevant for P_acc and reduce them to one rule for P_carry: `CloseRow` in the
model fires from any trigger at any instant, so every adversary-chosen close instant is already a modeled
history (§2 "time as events"); and every callback is bound to its original `RequestEntry`/`Channel` by
object reference with no relookup by uid, fd, request id or name (conn L523, L835–837; rr L528–529), which
is the same sentence in all three configurations. The leg is therefore identical under interleaving for
P_acc; for P_carry it is identical given the object-reference rule.

**Which `[S]` items the abstraction rests on, read against the condition list.**

| `[S]` item | what it carries in the abstraction | which condition it bears on |
|---|---|---|
| production S2 allow-set denies `bind`, `connect` and `io_uring` for every enabled ABI (si L278–289; `[M]` only under the diagnostic policy, EV-75, EV-93) | that the agent cannot reach a local model server or any other local listener except through fd 3 | not a condition of P_acc: an agent that reached the server directly would produce no D-ACC and no label, so no false attribution — an unmediated action (property ②, W2's and CCT's domain). It bears on the reconcile preface's "always invoked" criterion and on the entry check of 01 §5 (a second agent-reachable entry would belong to the server, not the engine) |
| E-07 plaintext HTTP only for a trusted loopback-only local instance (rr L114–118) | the engine → server leg's integrity in C-LS/C-LP | not a condition of P_acc or P_carry: the label never leaves the engine (X-04); it is a consumer-side integrity premise |
| no business fd-pass in the first version (rr L535–537; E-08-R3) | that no agent holds an engine-side descriptor beyond fd 3 | bears on C-01 p12/p13 and on the entry check: a passed resource fd would be a write path the channel's stamp does not cover and would create new descriptor-lifetime relations across T-45; correctly carried as `[S]`, and the PLAN's re-examination rule applies if it is enabled |

Two further `[S]` items the abstraction rests on, which PLAN's list does not name:

- **C-LP: the per-agent model instance's uid and process domain.** The 2026-10-12 freeze does not state under
  which uid, in which pid namespace, or by whom a local per-agent instance is started (rr L116–118 defers
  "provider deployment conditions" to E-08, whose text states the loopback and credential rules but not the
  instance's credential). If an instance ran under a pool uid outside P_X, C-06 p62 (IG-02) would fail at
  the next reservation of that uid (a pre-existing non-member holder, D_62 q25 → R-G5-06), and across reuse
  the instance would be a holder of u_X during J_Y. No accepted byte follows from it alone — the instance
  holds no channel end — but the sufficient condition fails and the model's "every task at u is in P_X"
  reading does not hold. The abstraction needs the statement "a local model instance never runs under a
  pool uid and never joins an execution's pid namespace"; mech L137–143 states this shape for the
  credential-bearing MCP server, not for model instances. Since 2026-10-18 the design writes it, as a
  deployment precondition the engine does not check: the local model instance is an external process that
  runs under no pool uid and belongs to no execution's process domain (01 v9 T-67; rr L387–389, L885–886).
  Carried to §6 and §7.
- **C-LP: per-execution provider selection by object reference.** The frozen E-05/E-07 text selects a
  `ProviderConfig` per resource descriptor, not per execution; a C-LP deployment that routes execution X
  to "X's instance" needs a selection keyed by `execution_id` (object reference). If that key were the uid
  or the recurring `local_agent_id`, a late selection after reuse would be q30 (R-GX-05's class; MM-16).
  Not a P_acc condition; a P_carry (C-08 p81) premise. Since 2026-10-18 the design keys provider selection by
  `execution_id` (01 v9 MM-16; rr L386–387). Carried to §6.

**Verdict.** The agent ↔ engine leg is identical under interleaving in the three configurations for P_acc
by the text; the common abstraction stands with its disposition unchanged — conditional on unbuilt
requirements — and with two `[S]` items added to the three PLAN names. No configuration needs a separate
lifecycle case; C-LP needs two consumer-side statements before its P_carry case equals the others' (both written since
2026-10-18: 01 v9 T-67 and MM-16; the instance statement as a deployment precondition).

## 4 Challenges

Each entry: the interleaving, the transitions, the yield point, the condition of I or the 02 sufficient
condition it targets, whether the frozen text decides it, and the evidence by EV ID. Plain numbers; no
new ID class. "Within bounds" refers to the 03 §5 runs or the §5 runs below and never generalizes.

1. **The reuse-window write.** X's row CLOSED (any trigger) → T-45 → T-01 for Y with the same uid → T-04/T-05
   for Y → a surviving task of X writes into Y's channel (A-07) → T-09 → T-24 accepts it as Y's hello.
   Yield points: executor turns between T-40 step 1 and T-45; the spawner turn between Y's T-04 and T-09.
   Targets IG-02 / C-06 p62 (D_62 q24, R-G4-01's history; the 03 run 2b trace). Decided by the text: T-45
   requires the empty fact (conn L805–808) and the empty fact's basis `pid1_reaped` implies no survivor
   (EV-17, EV-18 `[R]`; EV-67 `[M]`); within bounds, run 1 reaches no such acceptance under the gate. The
   gate itself is `[S]` (EV-16); EV-68 `[M]` is the measured shape of the history without a namespace gate.
2. **Release before the fd close.** T-40 step 1 → T-45 → T-01(Y) while X's socket still holds skbs, then
   T-40 step 2. Yield point: executor turns (MM-09). Targets IG-08 / C-07 p71 (R-GX-01's subject). Decided
   by the text for the outcome — no read on a CLOSED row (conn L413), a new socketpair per execution (T-04)
   — and within bounds by run 1 (`MM09_ReleaseNeedsFdShut = FALSE`); the *ordering* of steps 2–4 relative
   to the release is unstated in the 2026-10-12 freeze (MM-09, §6); the ordering is decided by the second-freeze design text:
   steps 1–4 are one executor decision and the release requires close step 2 done (01 v9 T-40, T-45;
   MM-09 and MM-11 resolved; conn L870–872), which excludes this interleaving; run 1 was not re-run. EV-66 `[M]` (close drops one reference; shutdown acts on the
   object).
3. **A stale skb through numeric fd reuse.** T-40 step 2 closes X's fd number n; a later T-09 for Y receives
   n; a readiness notification for the old n, queued in the event loop before deregistration, is delivered to
   Y's `Channel`. Yield point: executor turn boundary. Targets C-05 p51 / C-01 p13 (R-GX-03's subject).
   Decided by the text at the design level: the reader is deregistered before the close and callbacks are
   bound by object and generation (conn L81, L523, L791); a spurious readiness on n reads Y's own socket,
   whose queue holds only bytes from Y's peer end (IG-12), so the label is Y's own. The 2026-10-12 text does not
   state that the event library delivers no readiness after deregistration; 01 v9 AA-13 now states it and
   requires the chosen library to be checked for it (conn L483–484) — an implementation obligation, §6. EV-91 `[R]` (cookie check not atomic with I/O), EV-77 `[M]` (the transport reader freezes
   fd and cookie; a replaced fd cannot continue a frame — diagnostic policy, transport library).
4. **Cross-uid mid-frame injection.** Execution Y (uid u_Y ≠ u_X) holding X's peer end writes a segment
   between X's header and body fragments; the engine's reader takes it as X's next fragment. Yield point:
   socket syscall boundary. Targets C-04 p41/p42 (R-G2-07's cached-credential shape). Decided by the text:
   the kernel ends the receive return at the credential change (EV-88 `[R]`), the fragment is compared with
   the immutable `expected_uid` and its failure discards the whole frame (conn L422–424); EV-77 `[M]` under
   the diagnostic policy in the transport library; the product receiver is `[S]` (EV-78). At skb level
   within bounds: §5 run 5c (expected and observed: no false acceptance with distinct uids even without the
   gate).
5. **Two open rows with one uid.** Can the frozen text have two open rows whose `expected_uid` coincide?
   Yield point: executor turns around T-01. Targets C-06 p61 (IG-06). Decided by the text: a uid maps
   one-to-one to a workspace and a workspace runs one execution at a time (rr L560–565); the only ways are a
   failed T-01/T-03 check (R-G1-05, R-G1-06) or a second engine (R-G5-06), which are routes. The model's
   one-uid bound makes the state unreachable by construction; §5 runs 5a and 5a-t2 explored two
   concurrently open rows with *distinct* uids to depth 23 and 25 without a violation but did not finish
   within the time bound, so this challenge rests on the text alone.
6. **A third generation.** X1 → X2 → X3 on one uid: does anything of generation 1 (a queued skb, a live
   task, a quarantined lease) reach generation 3? Yield points: the same as challenges 1–2 twice over.
   Targets IG-02, IG-08 across two releases. Decided by the prose induction of §2 (the post-release state has
   the initial state's shape plus a dead row); §5 run 5b checked three generations within bounds with no
   violation.
7. **Withdrawal racing an uncertain send.** T-14 writes `local_never_submitted` while the spawner in fact
   holds the record (T-02 indeterminate result). Yield point: the control writer's ownership domain. Targets
   IG-03 / IG-04 (C-06). Decided by the text: an indeterminate result is `uncertain` and the row waits for the
   spawner's fact; `local` is written only after the writer confirms nothing was ever sent (conn L322–323,
   L797–798; within bounds, run 2a is the history in which this basis would be wrong without the gate).
8. **Empty before prepared, then the late fd for X meeting Y's reuse of the uid.** T-43(X) → T-40 → T-45 →
   T-01(Y, same uid) → the late `spawn_prepared` for X arrives. Yield point: executor turns. Targets C-05 p51
   (R-GX-02's subject). Decided by the text: the record is matched by `engine_epoch / execution_id /
   lease_id` and `seq`, never by uid or fd; a prepared for a CLOSED row closes the fd and registers a stop
   (conn L138, L324, L334–336); EV-97 `[M]` diagnostic (post-handoff FAIL/empty processed in order with the
   original execution and lease).
9. **A quarantine lifted by the wrong empty fact.** X quarantined (stop sent, no empty within 5,000 ms); later
   an empty fact arrives — could it belong to another record with the same uid? Yield point: executor turns.
   Targets IG-06 / C-06 p61. Decided by the text: `execution_id = engine_epoch:allocation_seq` never
   recycles (conn L71–73) and the match is by execution and lease id (conn L138); one release per lease
   (conn L328).
10. **Control loss with an unswept survivor and a new epoch.** T-49 with the spawner SIGKILLed before its
    sweep (conn L868); the supervisor asserts the isolation domain empty; `NewEpoch` restarts the pool free
    while a task of the old epoch holds a pool uid. Yield point: kernel event plus the supervisor. Targets
    IG-02 at the new epoch's initial state / C-06 p62 (R-GX-04's subject). **Not decided** by the frozen
    text: the supervisor's method is outside it (MM-10; X-11); EV-81 `[S]`.
11. **A pre-drop byte in the engine's queue.** The trusted bootstrap at the spawner-side credential writes
    something other than SEALED before step 11, or a FAIL with the root uid, and the engine later reads it.
    Yield point: kernel event (the child runs concurrently). Targets C-02 p22 / IG-10. Decided by the text:
    the engine holds no fd before T-09, the spawner reads only SEALED and drops its engine-end copy on any
    record failure, and a pre-drop FAIL ends the record (conn L287–295; EV-76 `[M]` diagnostic). Residual:
    MM-05 (AA-04).
12. **Acceptance after the sender's death.** X's hello skb is read after PID 1 exited and even after
    `execution_empty` was processed (K-06, §1 row 29). Targets C-07 p71 — satisfied, since the send preceded
    release; the challenge is whether the model's `inJ` ghost is evaluated at the send instant (it is,
    `InJ(f)` inside `Send`/`SendExit`). Decided by the text (mech CRA-F12; EV-44 `[R]`). The queued-skb
    survival is measured only on a datagram socket (EV-58 `[M]`); no `SOCK_STREAM` source location or
    measurement is registered — §6.
13. **Adversary-chosen close instants across executions.** A saturates the shared server (C-LS) or the host
    CPU (all three) so that B's output stall or deadline fires at an instant A chooses, for example between
    two of B's fragments or just before B's `task_result`. Yield point: executor turns and timers. Targets
    nothing in I: every close instant is a `CloseRow` history of the model (§2 "time as events"), and a close
    with the row's own label is not false attribution. Decided (X-02; conn L731–733).
14. **A consumer keyed by the recurring name after reuse.** A worker result for X is matched to Y because
    both carry `local_agent_id = "a"` and Y took the name after X's reclaim. Yield point: worker return.
    Targets C-08 p81 (q30, R-GX-05's class). **Partly decided** in the 2026-10-12 freeze: the text says a new
    execution under a recurring name inherits nothing (conn L79, L343) and callbacks hold objects (conn
    L523), but states no assignment event and no consumer keying rule (MM-16). **Decided by the
    second-freeze design text**: the executor writes the name once at row creation and no consumer step
    looks up the `VerifiedContext` or keys state by `local_agent_id` (01 v9 MM-16 resolved; conn L95–97,
    L581–583); a consumer keyed by the name is a departure from that text (q30, 02 v7) — §6.
15. **A channel installed for a dead PID 1.** PID 1 dies between SEALED and the engine's install; T-09
    succeeds; the row is STARTING with an empty P_X. Yield point: kernel event vs executor turn. Targets
    IG-09, IG-11 — no label is produced (nothing can send) and the startup deadline closes the row; the empty
    fact follows through T-42/T-43. Decided by the text (T-09 states no liveness condition; R2 F-02 in 03
    §5.1).

Counts: 15 challenges; decided by the 2026-10-12 frozen text: 13 (1–9, 11–13, 15 — of which 2 and 3 carry an
unstated ordering or an implementation obligation recorded in §6); not decided: 1 (10); partly decided: 1
(14). Under the second-freeze design text (01 v9): decided 14 (1–9, 11–15; challenge 2's ordering and
challenge 14's keying rule now stated, challenge 3 keeping its implementation obligation, AA-13); not
decided: 1 (10, MM-10).
Two of the decided ones (4 and 6) are additionally checked at skb level within bounds by the follow-up of
§5 (runs 5c and 5b), and 1 has its negative control there (run 5d); the run meant for 5 did not finish
within the time bound and decides nothing.

## 5 Tool-assisted follow-up (specified before it was run)

### 5.1 Why a follow-up is warranted

Two justification rows of §2 rest on prose that 03's runs do not reach: "one uid slot" (the `Accept`
mismatch branch, which every cross-uid interleaving lands in, has no coverage in 03's runs) and "two
generations" (03's bound reaches one reuse). Challenges 4, 5 and 6 are decided by the text but their
skb-level interleavings with the lifecycle were never explored by TLC. A bounded check that adds
concurrent rows with distinct uids and a third generation of one uid, without adding any action, decides
those three challenges within bounds and either confirms or refutes the two justification rows. It also
gives the mismatch branch coverage, which 03 §5.2 lists as missing.

### 5.2 Specification (written before any run)

**Module.** [Concurrency05.tla](05-concurrency-tlc/Concurrency05.tla), a copy of `Invariant03.tla`
version 3 (blob `204f383dcc147004`) with one structural change and no new action: the one `UidLease`
becomes one lease per pool uid, and each execution's uid is fixed by a static map `UidOfExec` (the
workspace → uid one-to-one map of rr L560–565). Concretely: `lease` and `holder` are functions over
`Uids`; `Reserve(e)` takes the lease of `UidOfExec[e]`; `Launch(e)` applies that uid; `InJ(f)` reads the
holder of `UidOfExec[f]`; `Quarantine`, `Release`, `ExecutionEmpty`, `ControlLoss` and `NewEpoch` act on
the execution's own lease; the skb stamp ranges over `Uids`; IG-01, IG-02, IG-06, IG-07 and IG-10 are
restated per uid with the same meaning. `Invariant03.tla` is not modified. Every action, parameter,
over-approximation, relaxation and restriction of 03 §5.1–§5.2 is unchanged, so the runs below inherit
03's limits: a bounded reachability check, not an inductiveness proof, not a result about the real system.

**Runs** (four configurations; all with `MM09_ReleaseNeedsFdShut = FALSE`, `MM10_SupervisorFactSound =
TRUE`, `Tasks = {1, 2, 3}`, `MaxQ = 2`, as in 03):

| run | `Execs` | `Uids` and `UidOfExec` | `A07` | gate | invariants | expected outcome, stated before the run | what it decides within bounds |
|---|---|---|---|---|---|---|---|
| 5a | {1, 2, 3} | {U1, U2}; 1 → U1, 2 → U2, 3 → U1 | TRUE | TRUE | TypeOK, Goal, IG01 … IG11 | no violation; the `Accept` mismatch branch (the ELSE lines of `Accept`) has non-zero coverage | justification rows "one uid slot" and "two executions" (two concurrently open rows with distinct uids, cross-uid A-07 sends, plus one reuse); challenge 5 |
| 5b | {1, 2, 3} | {U1}; all → U1 | TRUE | TRUE | TypeOK, Goal, IG01 … IG11 | no violation | justification row "two generations" (three generations of one uid); challenge 6 |
| 5c | {1, 2} | {U1, U2}; 1 → U1, 2 → U2 (no reuse) | TRUE | FALSE | TypeOK, Goal | no Goal violation (IG-02 is expected to fail in this configuration, as in 03 run 2a, and is deliberately not checked) | challenge 4: with distinct uids a cross-uid A-07 write never reaches a labelled acceptance, even with the membership half removed |
| 5d | {1, 2, 3} | as 5a | TRUE | FALSE | TypeOK, Goal | a counterexample ending in `Accept` with `orig ≠ r`, reached through a same-uid reuse (U1 between executions 1 and 3) and not through a cross-uid acceptance | non-vacuity of 5a; the negative control for challenge 1 in the two-uid model |

**Bounds and their reason.** Three executions are the smallest set that contains both a concurrent pair with
distinct uids and a reuse pair with one uid (5a) or three generations (5b). Tasks, queue, epochs and the
remaining parameters are 03's, so any difference in outcome is attributable to the lease structure. If 5a or
5b exceeds ten minutes of wall time on this machine, the run is repeated with `Tasks = {1, 2}` and the
reduction is recorded as a further limit.

**Toolchain.** TLC2 2.19 from `tla2tools.jar` at <tlaplus-dir> (outside the repository),
Java 21.0.6, as in 03 §5.3; `-deadlock` because terminal states are expected; `-metadir` in the session
scratch folder; `-coverage 1` on 5a for the branch counts; four workers. Commands, configurations and the
full logs are kept in the 05-concurrency-tlc folder beside the module.

**What the runs cannot show.** The same as 03 §5.5: no inductiveness; no correspondence of the real
system to M; nothing about the G2 check logic, fragments, consumers, uid changes after T-07, the production
policy or the MM-10 unsound branch. A bounded result stays bounded (PLAN COV-4).

### 5.3 Outcomes (runs of 2026-10-14 23:53 to 2026-10-15, this session)

Order of events: §5.2, the module and the four configurations were written first (module
`Concurrency05.tla` blob `84afb36066883dc0`; configurations 5a `208a3af96b00ed3e`, 5b `4b8cd4839752c40b`,
5c `49793bf3ea193fc9`, 5d `c82dabcfe954e550`); the runs followed in the order 5c, 5d, 5a, 5b, then the
reduced 5a-t2. Logs are kept beside the configurations; the counts below are copied from them.

| run | result | states generated / distinct / depth | time | against the expected outcome |
|---|---|---|---|---|
| 5c | **no violation** of TypeOK and Goal ("No error has been found") | 66,507,189 / 4,875,608 / 29 | 1 min 22 s | as expected: with distinct uids a cross-uid A-07 write never reaches a labelled acceptance, even with the membership half removed (log blob `908e184f4d4a134a`) |
| 5d | **counterexample**: "Invariant Goal is violated", twelve actions after Init | 516,433 / 158,820 / 13 at the violation | 1 s | as expected: `Reserve(1)` → `Submit(1)` → `Launch(1)` → `Handoff(1)` → `CloseRow(1)` → `Release(1)` → `Reserve(3)` (the holder of U1 becomes execution 3) → `Submit(3)` → `Launch(3)` → `SendExit(1, PID 1 → channel 3)` → `Handoff(3)` → `Accept(3)` with origin 1; execution 2 on U2 takes no step; the false acceptance goes through the same-uid reuse, not through a cross-uid acceptance (log blob `47f702136897dc0e`) |
| 5a (full bounds, `Tasks = {1, 2, 3}`) | **stopped by the ten-minute rule of §5.2**; no violation in the states explored | 161,159,988 / 20,104,891 / BFS depth 23 at the stop, 7,178,177 states still queued | 10 min 3 s, stopped | partial: a breadth-first exploration to depth 23 of the stated bounds, not a result over them. The last per-minute coverage block (the run used `-coverage 1`) shows every action fired and the `Accept` mismatch branch (module lines 246–247) fired 970,308 times of 3,008,397 `Accept` steps, so the branch 03 §5.2 reports as unexercised has coverage here (log blob `a71f5ece133ef4bf`) |
| 5b (full bounds) | **no violation** of TypeOK, Goal, IG01 … IG11 ("No error has been found") | 184,062,205 / 19,067,888 / 39 | 7 min 12 s | as expected: three generations of one uid keep I within the stated bounds (log blob `e4bf1e9960bcc37d`) |
| 5a-t2 (the pre-registered reduction, `Tasks = {1, 2}`; configuration `Concurrency05-run5a-t2.cfg`, blob `1e6d59a0df9c6214`) | **did not finish within the time bound**; no violation in the states explored | 175,854,443 / 25,808,445 / BFS depth 25 at the last progress line, 7,925,663 states still queued | 12 min, ended without a TLC termination message (the process stopped at 00:34:30 inside the coordinator's ten-minute extension; shell status 127; the log ends at the last progress line and is kept as it is) | partial, like 5a: a breadth-first exploration to depth 25 of the reduced bounds. Its last coverage block shows every action fired and the `Accept` mismatch branch fired 1,327,565 times of 3,965,917 `Accept` steps (log blob `cc05f926a696375b`). No further run was started (coordinator's instruction) |

Incidents, recorded because they changed how the runs were executed: (i) the first attempt at the reduced
run wrote TLC's disk state queue to the session scratch folder on drive C:, which filled the drive and
aborted the run with "There is not enough space on the disk" at 16,556,029 distinct states and depth 23
without a violation; the spill folders were deleted (that log was not kept, since the repeat supersedes it)
and the run repeated with the `-metadir` on drive D:, in a temporary subfolder of the 05-concurrency-tlc
folder that was deleted after the run and is not part of the artefact; (ii) the coordinator set a time
bound during the repeat (ten further minutes, no widening of bounds, no further run); the repeat ended
before that bound without a termination message, as the 5a-t2 row records. A 5b reduction was never
needed, since the full 5b run ended inside the rule's limit. The 5a configuration's full-bounds space is
larger than this session could explore on this machine; a longer-running or symmetry-reduced run is
possible later and would be a new run record, not an edit of these.

What the outcomes decide, within the stated bounds and only there:

- justification row "two generations" — decided by 5b: three generations of one uid preserve I;
  challenge 6 likewise;
- challenge 4 — decided by 5c: with distinct uids, no A-07 write by the other execution reaches a labelled
  acceptance, with or without the membership half; the comparison alone carries it;
- non-vacuity of the two-uid model — 5d: removing the membership half yields a false acceptance in twelve
  actions, through the same-uid reuse only;
- justification rows "one uid slot" and "two executions", and challenge 5 — **not decided by the runs**:
  neither 5a (full bounds, depth 23, 20.1M distinct states) nor 5a-t2 (reduced bounds, depth 25, 25.8M
  distinct states) finished within the time bound; both found no violation in the states they explored and
  both gave the `Accept` mismatch branch coverage. That is evidence of the expected shape, not a result over
  the bounds; the two justification rows stand on their prose in §2, and challenge 5 on the text alone.

The `-coverage` successor counts vary between worker runs; the transition counts quoted are the ones the
logs carry (Step 3 executor's note).

## 6 Unresolved relations (for the coverage-uncertainty list)

One line each; the reconcile role aggregates them. None is a route and none changes I.

- MM-09: the frozen text orders T-40 steps 1 → 6 but does not say whether steps 2–4 share step 1's decision or whether T-45 may precede step 2; both orders keep I within the bounds of 03 §5 and §5 here, and the text should still state the order (§1 row 26; challenge 2). 01 v9 states it: steps 1–4 are one decision and T-45 follows close step 2 (MM-09 resolved; conn L870–873).
- MM-10: the soundness of the supervisor's "isolation domain empty" fact at a new epoch is a premise with no mechanism in the frozen text; the `MM10_SupervisorFactSound = FALSE` branch is not run (§1 row 33; challenge 10).
- U-05: a second engine on an overlapping pool has no mechanism in the text, only a deployment precondition (EV-81 `[S]`) (§1 row 34).
- MM-16: the event that assigns `local_agent_id` and the rule that no consumer keys state by it are not stated; q30 remains a consumer relation to decide at the next freeze (§1 row 35; challenge 14). 01 v9 states both (MM-16 resolved; conn L95–97, L581–583), and q30 now names a departure from that text (02 v7).
- The turn structure between the parse (T-24) and admission (T-30) is unstated; attribution is unaffected by the text's object-reference rule, but the "one decision" boundary there should be written (§1 row 20). 01 v9 T-24 and T-30 write it (conn L484–485).
- The event library must deliver no readiness notification for a deregistered fd number after T-40 step 2 (challenge 3); the text binds callbacks by object and generation but does not state this library property. 01 v9 AA-13 states it as a requirement checked against the chosen library (conn L483–484).
- K-06 for `SOCK_STREAM`: the survival of a queued skb and its stamp after the sender's death is measured on a datagram socket only (EV-58) and no kernel source location is registered (03 §6 append) (challenge 12).
- The control-record carrier for a spawner kill/wait error (T-44's "kill/wait error" precondition) is not named in the control table; `spawn_failed{stage = reap}` is the only candidate (§2, restriction row). 01 v9 T-41 and T-44 name the carriers: `spawn_failed(stage = reap)` for a kill error, the same record best effort and then control loss (T-49) for a wait error (conn L121–126).
- C-LP: the uid and process domain of a local per-agent model instance are not stated; the common abstraction needs "never a pool uid, never a member of any P_X" (§3). The design writes this as a deployment precondition since 2026-10-18 (01 v9 T-67; rr L387–389, L885–886).
- C-LP: per-execution provider selection, if any, must be keyed by `execution_id` (object reference), not by uid or `local_agent_id` (§3). The design keys it by `execution_id` since 2026-10-18 (01 v9 MM-16; rr L386–387).
- The `[S]` status of the executor's "one decision" sequences: every "decided by the frozen text" verdict of §1 and §4 is a design-level verdict that an implementation yielding inside such a sequence would void (§0).

## 7 Change requests proposed

None to I, 01 or 02 from the interleaving analysis: no challenge produced a history that reaches a labelled
acceptance with a foreign origin under the frozen text, and no collapse was found unjustified. Two
requests to shared text outside the spine are recorded for the reconcile role to route (they add premises;
they do not change a condition, transition or guard):

| request | IDs touched | what and why |
|---|---|---|
| CR-Q-01 | PLAN §Frozen design revision, "Supported configurations" (no spine ID) | add two `[S]` items to the D7 abstraction's list: (a) a local per-agent model instance (C-LP) never runs under a pool uid and never joins an execution's pid namespace — otherwise C-06 p62 (IG-02) fails at the next reservation of that uid; (b) any per-execution provider selection in C-LP is keyed by `execution_id`, never by uid or `local_agent_id` (C-08 p81, q30). §3 |
| CR-Q-02 | 03 §5.2 ("Not modeled") and §6 "to Stream Q" (wording only; no guard) | record that the collapse "two generations" was checked within the bounds of §5 here (run 5b: three generations of one uid, no violation), that the cross-uid A-07 case was checked within bounds (run 5c), and that the `Accept` mismatch branch has coverage in the partial runs 5a and 5a-t2, so the sentence "the stamp-mismatch branch has no coverage" is scoped to 03's own runs; the collapses "one uid slot" and "two executions" remain justified by prose only (their runs did not finish within the time bound, §5.3) |
