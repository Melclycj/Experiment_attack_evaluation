# UID spine change requests

This is the append-only change-request record required by PLAN. Its first entries are pre-fan-out
R1 repairs, **not** a claim that group reconciliation or convergence has run. Downstream group files
do not yet exist. No change to the frozen design or to the sealed draft is authorized here.

## 2026-10-13 — R1 repairs

Source: [R1 review and adjudication](../reviews/R1-2026-10-13.md). All six original findings and two supplemental findings accepted.
Base: inventory v4 / Step 2 v1 at commit `907fd0b`. Repair: inventory v5 / Step 2 v2, final hashes
registered in [VERSIONS](../spine/VERSIONS.md); the targeted recheck passed the R1 candidate gate only.

| request | changed IDs / surface | decision | execution status |
|---|---|---|---|
| CR-R1-01 | D_ij/B(route), q01…q32; R-G2-05/11/12/13, R-G3-05, R-G5-08, R-GX-06; U-02 and matrix | Accept R1-01: total local splits with explicit unresolved remainders | Applied; independently confirmed |
| CR-R1-02 | C-06 p62, q24…q26; R-G4-01, R-G5-06/07/08 | Accept R1-02: predecessor survival precedes unrelated-holder classification | Applied; independently confirmed |
| CR-R1-03 | T-20/T-61/T-62, guarded outcomes under T-67 | Accept R1-03: include lawful configuration-departure semantics without calling them kernel breach | Applied; independently confirmed |
| CR-R1-04 | new T-39; X-09; G3 cut; R-G3-02/05 | Accept R1-04: model original-session association producers/updates; leave grant-policy content outside scope | Applied; independently confirmed |
| CR-R1-05 | I-03; e_r; C-03 p33, C-04 p42; sufficiency; D_33/R-G1-02 | Accept R1-05: distinguish kernel uid, rendered observation and stored comparand | Applied; independently confirmed |
| CR-R1-06 | T-26/T-60 traces; R-G1-01 matrix incidence; structural checker | Accept R1-06: repair mechanical correspondence without upgrading it to a proof | Applied; independently confirmed |
| CR-R1-07 | Bad_acc(h), a*, F1…F8; C-07 / consumer-only separation | Accept supplemental R1-07: partition actual incorrect accepts, not sufficient-condition failures of correct traffic | Applied; independently confirmed |
| CR-R1-08 | C-08 p81/p82 and D81/D82 | Accept supplemental R1-08: restrict p81 to independent D-ACC causal origins, retaining the originless p82 leaf | Applied; independently confirmed |

No existing transition, condition or route ID was deleted or renumbered. New remainder IDs do not
prejudge a concrete mechanism or final disposition. Subsequent Step 3 refinements must append a new
spine version and name affected IDs; the frozen E-04 double gate remains the candidate under test.

## 2026-10-13 — Step 1 owner acceptance of inventory versions 4 and 5

The Step 2 session (Codex) changed `01-model-inventory.md` twice: version 4 before R1 as a Step 2
input refinement, without a change request; version 5 as the R1 repairs above. The Step 1 owner (the
main Fable session) checked every change against the ten frozen files on 2026-10-13 and accepts all of
them; no change is returned. The record below restores the trail for version 4.

| request | changed IDs / surface | decision | execution status |
|---|---|---|---|
| CR-OWN-01 | version 4: D-GT (per-origin send history, descendant pid-namespace membership, unrelated host task outside), property wording (allocation generation; no live-at-accept premise), AA-07, AA-09, AA-10, A-08, MM-03, MM-04, T-42 outcome, entry-check answer, kub cites at section level | Accept retroactively. D-GT and AA-07 follow conn L397–403; AA-09 corrects a version-3 error (exec and hello were conflated); AA-10 removes a title that would have made premise (c) hold by definition; the entry-check answer no longer presumes the pending consumers' construction; stale kub line numbers (pre-addition blob) are replaced by section cites, Stream E carries file:line | Applied in version 4; accepted by the owner |
| CR-OWN-02 | 01 §0 property paragraph | Add one sentence stating the departure from PLAN Context (1)'s accept-time wording and its reason, so the two texts are seen to differ deliberately; PLAN Context (1) is unchanged until its next edit | Applied as version 6 |

Version 5 (CR-R1-03 T-20/T-61/T-62 guarded outcomes, CR-R1-04 T-39 and X-09) is accepted as recorded
above. Two remarks, neither a blocker: version 4 should have carried a change request before R1; the
owner's own version 2 marked MM-14 resolved while leaving MM-04 open, an inconsistency version 4 repaired.

## 2026-10-13 — adjudication of the cross-family R1 addendum (sixteen findings)

Source: [R1 addendum](../reviews/R1-addendum-2026-10-13-crossfamily.md) (cold-context Claude Opus read of
01 v6 / 02 v2, commit 6e56539). Executor for this adjudication: the main Fable session (execution of the
spine passed from the Codex session at the user's direction, 2026-10-13). Every finding was accepted; none
was applied mechanically — each row states the repair chosen. Repair candidate: 01 version 7, 02 version 3,
hashes registered in VERSIONS after the targeted recheck.

| request | finding | changed IDs / surface | decision and repair |
|---|---|---|---|
| CR-A-01 | F-01 (P2) | C-07 (p72 withdrawn), D_72 removed, R-G4-02 withdrawn, q28/q29 retired, matrix C-07 × G4, §4.1 item 3 | Accept: p72's generation half duplicates p13 and its phase half does not bear on attribution, so F_7 ∧ D_72 selects no history; R-G4-02 had no other entry point. The phase and generation rules move to Step 3 guards for G4. IDs reserved, not reused. |
| CR-A-02 | F-02 (P2) | §1 (u_r := A_r.uid; expected_uid field a separate input), I-05, p52, D_52, q21 retired, R-G1-04 withdrawn | Accept: with one meaning of u_r the stored-field mismatch is p33 → D_33 → R-G1-02, which already describes it; p52 keeps the execution/agent-name/tuple conjuncts. |
| CR-A-03 | F-03 (P2) | §1 (X_r defined as the T-05 clone event of the SpawnRecord with execution_id = A_r.execution), p53 added to C-05, D_53 → new R-G1-06, matrix C-05/C-06 × G1, §3 | Accept: the execution_id ↔ clone map becomes a named predicate (p53); a launch that applies another allocation's uid or endpoint now fails C-05 in G1 before C-06 is evaluated, instead of falling through q26 or the R-G5-08 remainder. |
| CR-A-04 | F-04 (P2) | §4 selector semantics paragraph | Accept: selectors are trace-only predicates; the remainder owns histories in which none of the cell's named facts occurs; analyst uncertainty is recorded in the route file, never used to move a history. |
| CR-A-05 | F-05 (P2) | §5.1 table rows for I-01…I-08 | Accept: the six remainder slots, R-G1-06 and the withdrawals are now in the input rows. |
| CR-A-06 | F-06 (P2) | 01: Execution row, D-ACC label tuple, T-01 writes, new MM-16; 02: I-05, p52, p81, q30, R-GX-05 | Accept: `local_agent_id` is a label field with a stated reuse rule and no landing; landed as a field written once at T-01 and carried by reference, with the assignment event and consumer keying recorded as MM-16; a lookup by the name after reuse is q30 → R-GX-05. |
| CR-A-07 | F-07 (P3) | 01: new MM-17 | Accept: the bootstrap-handoff → hello phase move has no stated trigger; recorded like MM-15, read as the COMMIT whole send (T-10). |
| CR-A-08 | F-08 (P3) | §4.1 item 4 | Accept: the four probe cases now carry their derived outcomes by reference to 01 T-20 (b)–(e) and kub §5; the disagreement with the PLAN's Stream P row on the self-mapped sub-arm is recorded for reconcile; the derivation is not amended before the probe. |
| CR-A-09 | F-09 (P3) | §4.1 item 4 | Accept: the PLAN's "explicit foreign-uid route" is named as R-G5-04 plus the R-G2-05 remainder; under the intact posture T-20 (c) yields no accepted event; Stream P's trigger is stated; the ledger's cut supersedes the provisional G2 placement. |
| CR-A-10 | F-10 (P3) | §4 H expressions | Accept: B(R-G5-01/02) gain the conjunct (Bad_acc OR NOT C-08). |
| CR-A-11 | F-11 (P3) | q33 added, D_61 re-split, R-G5-06 sentence and transitions, U-05 | Accept: epoch succession (q33) keeps R-GX-04; a concurrently running engine's allocation goes to R-G5-06 as a failure of the U-05 exclusivity premise. |
| CR-A-12 | F-12 (P3) | p81 | Accept: p81 quantifies over each D-ACC causal origin; a multi-origin event emits each origin's label with its own reference. |
| CR-A-13 | F-13 (P3) | new §4.3; U-02 pointer | Accept: the coverage warrant is one labelled subsection, written as a check with its non-warranties listed. |
| CR-A-14 | F-14 (P3) | R-G4-02 sentence | Accept, moot after CR-A-01 (the row is withdrawn); the withdrawal note uses "session teardown". |
| CR-A-15 | F-15 (P3) | U-05, closing paragraph | Accept: the two negated uses of the unqualified adjective are reworded. |
| CR-A-16 | F-16 (P3) | VERSIONS rows for 01 v4 and 02 v1 | Accept: the two ids are trimmed to the header's 16-digit form (a format correction of a malformed id, not a change of a version). |

Structural checker after repair: exit 0; 52 transitions; 38 live ledger entries (G1 5, G2 13, G3 5, G4 1,
G5 8, GX 6); 18 components; 33 selectors; 71 local valuations; no errors. Vocabulary scan of 02: none of
the unqualified words of PLAN Context (2) and no rate wording. The seven unresolved refinement slots of
U-02 are unchanged. Step 3, Stream E, fan-out and convergence remain unstarted.

### Second round (same day): targeted recheck of the sixteen repairs

The targeted recheck (addendum section "Targeted recheck (2026-10-13)") found one repair that did not
hold (F-03), two new defects (N-01, N-02) and seven remarks. All ten were accepted and repaired in the
same version-3 candidate; 01 version 7 is unchanged by this round.

| request | item | changed surface | decision and repair |
|---|---|---|---|
| CR-A-17 | F-03 recheck (does not hold) | p53 third clause; §1 A_r definition; C-05 purpose cell; §3 | Accept: p53 now also requires that during J_r no clone event other than X_r is launched with A_r.uid or inherits the peer end of row r's socketpair, so the cross-record launch history fails C-05 at D_53 → R-G1-06 before C-06; §3 and the purpose cell no longer attribute the implication's last step to p53 (it uses X_r's definition and p62). |
| CR-A-18 | N-01 | matrix C-04 × G4 reason | Accept: the reason no longer cites the withdrawn p72. |
| CR-A-19 | N-02 | closing paragraph | Accept: the file no longer asserts that the candidate gate passes; the recheck sections decide that. |
| CR-A-20 | F-02 remark | §1, q21 retired text | Accept: the field mismatch fails p33 "whenever the field is the comparand's source (01 T-23)". |
| CR-A-21 | F-04 remark | q02, q17 | Accept: knowledge wording replaced by trace facts. |
| CR-A-22 | F-06 remark | §1 A_r definition | Accept: A_r is now the full record (execution_id, X_r, uid, lease, epoch, session, channel, local_agent_id) with named fields. |
| CR-A-23 | F-10 remark | §4 Bad_acc definition | Accept: Bad_acc is defined for any history prefix, so its use in the H cells is well-formed. |
| CR-A-24 | F-11 remark | q23, R-G1-05 sentence | Accept: q23 requires the same engine process in the same epoch; coinciding epoch values of two engines are not q23 and route to R-G5-06. |
| CR-A-25 | F-13 remark | §4.3 items (0) and (i) | Accept: the H pre-partition is stated first and item (i) names both C-08 cases. |
| CR-A-26 | F-16 remark | VERSIONS note | Accept: the format correction is now stated inside VERSIONS itself. |

Structural checker after the second round: exit 0, counts unchanged (52 / 38 / 18 / 33 / 71). Vocabulary
scan of 02: none of the unqualified words of PLAN Context (2) and no rate wording.

### Third round (same day): recheck 2 findings N-03 / N-04 and two remarks

| request | item | changed surface | decision and repair |
|---|---|---|---|
| CR-A-27 | N-03 | p53 (clauses 1–2 removed), §1, C-05 purpose cell, R-G1-06 sentence | Accept: p53 keeps only the clause whose failure can put an accepted byte at row r (another clone of this spawner launched with A_r.uid against its own record, or holding row r's peer end); "X_r launched with its own uid" and "row r holds X_r's engine end" become G1 preservation guards, so D_53 no longer captures histories caused by a survivor or a pre-existing holder. |
| CR-A-28 | N-04 | p53 scope, §1, R-G1-06 transitions note | Accept: p53 is scoped to this engine's spawner and excludes clones backed by their own allocation of u_r; same-engine double allocations are p61 → R-G1-05 whatever their timing, another engine's clone is p61 → R-G5-06 (concurrent) or R-GX-04 (succession). |
| CR-A-29 | CR-A-20 remark | p52 parenthetical | Accept: carries the "whenever the field is the comparand's source" qualifier. |
| CR-A-30 | CR-A-22 remark | I-05 | Accept: I-05 restates A_r with the execution_id and the field names of §1. |

Structural checker after the third round: exit 0, counts unchanged. Vocabulary scan of 02: none.

### Fourth round (same day): recheck 3 finding N-05 and two remarks

| request | item | changed surface | decision and repair |
|---|---|---|---|
| CR-A-31 | N-05 (and the CR-A-28 remark) | p53 (endpoint half removed), §1 guard sentence, C-05 purpose cell, R-G1-06 sentence | Accept: p53 is now the single clause "no other clone of this spawner is launched with A_r.uid against its own record during J_r"; the endpoint facts (row r's engine end from X_r's socketpair, the peer end to X_r's clone alone) are G1 preservation guards, since a peer-end holder with another uid fails C-04 (§4.1 item 1) and the half could only select D_53 histories whose accepted bytes came from a C-06 holder. "Row r's socketpair" is defined as the pair created at T-04 for X_r's SpawnRecord. |
| CR-A-32 | CR-A-29 remark | p52 parenthetical | Accept: the field's agreement is with r(u_r), as in §1 and p33. |

Structural checker after the fourth round: exit 0, counts unchanged. Vocabulary scan of 02: none.

### Close-out: recheck 4 result and the stopping rule

Recheck 4 (addendum section "Targeted recheck 4"): CR-A-31 holds with one carried remark, CR-A-32 holds,
no new defect, checker exit 0, gate line "may pass". Stopping rule applied (proposed by the executor to the user on 2026-10-13; the "may pass" branch needed no decision): no
further recheck; remark-level items are adjudicated here.

| request | item | changed surface | decision and repair |
|---|---|---|---|
| CR-A-33 | recheck 4 remark | R-G1-06 transitions note | Accept: the note now states that a same-spawner clone launched with u_r before r's reservation is a pre-existing holder (D_62, q25 → R-G5-06); no predicate changed. |

Final registered blobs are in VERSIONS (01 version 7, 02 version 3). The review record for this node is the
addendum with its four recheck sections; CR-A-01…CR-A-33 are the adjudications. Step 3, Stream E, fan-out and
convergence remain unstarted; the fan-out gate is not opened by this node.

## 2026-10-14 — adjudication of R2 (twenty-two findings)

Source: [R2 review](../reviews/R2-2026-10-14.md) (cold-context Claude Opus read of 03 v1, the TLA+ spec with
its run record, and 04 v1 at commit a9bae30; the reviewer reproduced all four TLC outcomes). Executor: the
main Fable session. Every finding is accepted; none is applied mechanically — each row states the repair
chosen. Repair candidate: 03 version 2, `Invariant03.tla` version 2 (all four configurations rerun), 04
version 2; hashes registered in VERSIONS after the targeted recheck.

| request | finding | changed surface | decision and repair |
|---|---|---|---|
| CR-R2-01 | F-01 (P1) | 03 §1.1 (i) and closing paragraph; §4 claim and step 3 | Accept: the claim is two parts — I_state ∧ C-01 … C-05 ⇒ I_acc(a), and I_acc(a) ∧ C-01 p11 ∧ C-05 ⇒ P_acc(a); C-02 is a listed premise; (i) is described as the joint consequence of C-02 with C-03 and C-04, not as C-02's reading. |
| CR-R2-02 | F-02 (P1) | `Invariant03.tla` `Handoff`; 03 §5.1 row, §5.2 over-approximations, §5.4 numbers | Accept: the liveness condition `1 \in alive[e]` is dropped from both branches, as T-09 states none; `execd` is set regardless (an over-approximation: an empty P_X enables no action); all four runs rerun and the record updated. |
| CR-R2-03 | F-03 (P2) | 03 §4 claim | Accept: I is assumed in every state of the history prefix through a (Init ⇒ I and I ∧ T ⇒ I′), and each step names the instant at which it uses a guard. |
| CR-R2-04 | F-04 (P2) | 03 §5.2 (relaxations bullet), §4 closing paragraph, §5.4 runs 2a–2c, §5.5, §6 G1 line | Accept: T-01's previous-lease check and T-03's spawner occupancy check are listed as relaxations the subset does not encode; every sentence on the membership half is qualified to that subset; the reviewer's probe is cited from the R2 record, not adopted as a result. |
| CR-R2-05 | F-05 (P2) | 03 §2 IG-13 row and the paragraph after the table; §4 step 1 | Accept: IG-13 is restated at read time (conn L413, T-21 precondition re-read before each step); T-25 is dropped as a basis; a D-ACC completing on a CLOSED row with bytes read while open carries the row's own label (02 §4.1 item 3). |
| CR-R2-06 | F-06 (P2) | 03 §2 "must be preserved by" of IG-02, IG-06, IG-08, IG-09, IG-10, IG-13 | Accept: T-65; T-43; T-21, T-24, T-65; T-08; T-60; T-09 added respectively. |
| CR-R2-07 | F-07 (P2) | 03 §5.4 run 2b and 2c paragraphs; §6 G2 line | Accept: run 2b is cited as R-G4-01 alone (D_62 q24); R-GX-01 is named only as IG-08's subject; R-G2-09 is removed from sentences where the comparison is correct. |
| CR-R2-08 | F-08 (P2) | 03 §5.4 run 2c paragraph | Accept: "protects the attribution" is replaced by the observed outcome. |
| CR-R2-09 | F-09 (P2) | 04 §0 `[R]` bullet; §4 new row | Accept: external kernel records (commit, CVE, list or bug) are a stated class carrying the record's own identifier, not a pinned-tree file:line; the four rows are counted in §4. |
| CR-R2-10 | F-10 (P2) | 04 EV-63, EV-86 | Accept: EV-63's excerpt is taken from the measured naive-arm table and listing (L82, L89–92) and the generalisation sentence is noted at L102–104; EV-86's source adds §1 L20, where the excerpt is verbatim. |
| CR-R2-11 | F-11 (P2) | 04 EV-97, EV-98 appended; §3 iv row; §4 counts | Accept: the SC-fault ordering fact (iv L49) and the same-round close race (iv L51) are registered as `[M]` rows under the diagnostic policy. |
| CR-R2-12 | F-12 (P3) | `Invariant03-run2c-noA07.cfg` header comment; 03 §5.4 run 2a sentence | Accept: the comment states run 2c and its expectation; the narrative says which branch `Submit(1)` takes. |
| CR-R2-13 | F-13 (P3) | 03 §5.4 | Accept: one sentence — counts at a violation vary between four-worker runs; the traces did not. |
| CR-R2-14 | F-14 (P3) | 03 §5.2 bounds bullet; §5.5 | Accept: the one-uid bound's two consequences (T-23 failure branch unexercised; at most one open row) are stated; "every action reachable" is qualified to action level. |
| CR-R2-15 | F-15 (P3) | 03 §5.2 | Accept: the unknown-record stop moves from over-approximations to a restrictions bullet with its reason. |
| CR-R2-16 | F-16 (P3) | 03 §5.2 time bullet | Accept: retirement is named as the new-epoch event in the model. |
| CR-R2-17 | F-17 (P3) | 03 §1.2; §2 IG-09 prose | Accept: IG-06's last clause, IG-12 and IG-13 are marked as action or construction guards; IG-09's prose admits a row that has since become CLOSED. |
| CR-R2-18 | F-18 (P3) | 03 §3 | Accept: the two start values are marked as readings with their basis; the new-epoch paragraph names IG-01, IG-06, IG-08, IG-09 and IG-03 … IG-05. |
| CR-R2-19 | F-19 (P3) | 03 §5.1 intro; VERSIONS row; PLAN pointer; two `.tla` comments | Accept: the planned file name is written without backticks; the two comments are reworded. |
| CR-R2-20 | F-20 (P3) | 03 §2 IG-13 row | Accept: one sentence names which halves of the former p72 are carried (post-CLOSED → IG-13; generation → p13 with IG-08 and IG-12) and why the phase half is not. |
| CR-R2-21 | F-21 (P3) | 03 §6 Stream E line | Accept: cites EV-10, EV-11 and EV-17; states that K-06 has only the datagram measurement EV-58 and no `SOCK_STREAM` source location yet. |
| CR-R2-22 | F-22 (P3) | 04 §0 rules 4–5 | Accept: the rules state the values the table carries. |

Checks after repair: `check-step3.py` exit 0 (its q-ID comparison was corrected in the same round: it compared
`q24` with `24`); TLC rerun of all four configurations with the version-2 spec — run 1 no violation 1,177,356 /
150,362 / depth 27, run 2a IG02 violated in four actions, run 2b Goal violated in twelve, run 2c no goal
violation 8,677,006 / 900,780 / 28; vocabulary scan of 03 and 04: none of the unqualified words of PLAN Context
(2) and no rate wording.

### Targeted recheck (same day) and close-out

The recheck (R2 record, section "Targeted recheck (2026-10-14)", cold-context Claude Opus) found every repair
holding (16 hold, 6 hold with remark, 0 do not hold), five new P3 defects (N-01 … N-05), reproduced all four
TLC outcomes and the version-2 traces, recounted 04 (98 rows, 34 `[M]`, 49 `[R]`, 15 `[S]`), and gave the gate
line "may pass". Stopping rule (recorded above under CR-A): no further recheck; the remark-level items are
adjudicated here.

| request | item | changed surface | decision and repair |
|---|---|---|---|
| CR-R2-23 | N-01 | 03 §5.4 version-1 note and counts sentence | Accept: outcomes unchanged but the run-2b trace differs at step 11 (`Send` → `SendExit`); the trace-stability sentence names which version each reviewer reproduced. |
| CR-R2-24 | N-02 | 03 §5.5 | Accept: "a CLOSED row accepts nothing" → "nothing is read from a CLOSED row", consistent with the restated IG-13. |
| CR-R2-25 | N-03 | 04 §3 fdsurvey row | Accept: §1 is listed with the note that its L20 sentence is EV-86's excerpt. |
| CR-R2-26 | N-04 | 04 §0 external-kernel-record sentence | Accept: states that the identifier sits in the fact or note column and the date in the date column where the source gives one. |
| CR-R2-27 | N-05 | 03 §5.5 "do not show" list | Accept: C-02 added, with the reason (the model gives the stamp by construction). |
| CR-R2-28 | F-02 remark | 03 §5.1 `Handoff` row; `.tla` comment | Accept: "empty or dying P_X" → "empty P_X" (before handoff P_X holds at most PID 1); comment-only change to the spec, no rerun. |
| CR-R2-29 | F-10 remark | 04 EV-63 source cell | Accept: the naive row is L84. |
| CR-R2-30 | F-15 remark | 03 §5.2 restrictions bullet | Accept: conn L322–323 (the separator line dropped). |
| CR-R2-31 | F-22 remark | 04 §0 rule 5 | Accept: names the EV-15/EV-32 substrate value. |

Structural checker after the close-out: exit 0; vocabulary scan of 03 and 04: none. Registered blobs at commit
58cfe43: 03 version 2, `Invariant03.tla` version 2, 04 version 2; CR-R2-01 … CR-R2-31 are the adjudications of
the first R2 record and its recheck.

### Cross-family addendum (same day): Codex CLI read of 03 v2, the spec and 04 v2 at 58cfe43

At the user's direction the R2 node gained a cross-family addendum, as R1 had: a cold-context Codex CLI
session (the user's default Codex model; dispatched through the official codex plugin, model and effort left
at the user's configuration) reviewed the committed version-2 files with a two-pass rule (own findings first,
the first R2 record opened afterwards) and reproduced the four TLC outcomes. Record:
[R2 cross-family addendum](../reviews/R2-addendum-2026-10-14-crossfamily.md) — six findings, all P1 by the
reviewer's grading, five NEW and one OVERLAP (first record F-09); gate line "may not pass". The Codex job's
final stdout summary was blocked by the provider's cybersecurity safeguard after the record file had been
written in full; the record itself is written in full (Header, TLC table, Findings, Settled, Checked, Not checked,
Gate). Every finding is accepted; the repair chosen is stated per row. Repair candidate: 03 version 3,
`Invariant03.tla` version 3 (all four configurations rerun), 04 version 3.

| request | finding | changed surface | decision and repair |
|---|---|---|---|
| CR-R2-32 | addendum F-01 (P1) | 03 §2 IG-10 prose; §5.2 restrictions | Accept: IG-10's uid clause is stated for the post-drop state (after T-07); the pre-drop member of T-05 … T-07 is named as a state the model does not carry, with the reason it cannot affect I_acc (AA-09: only the spawner reads its bytes); `Launch` is named as the post-drop abstraction boundary. The model is unchanged. |
| CR-R2-33 | addendum F-02 (P1) | 03 §2 IG-13 (prose, model column, derived-from, preserved-by), §4 step 1, §5.1 "Not modeled" | Accept: IG-13 now reads "not CLOSED — STARTING, ACTIVE or DRAINING", citing T-47 (the channel is kept) and T-25 (`bye`, old terminals, `cancel` admitted in DRAINING); the model's abstraction of DRAINING to ACTIVE is stated once in the model column and once in §5.1, replacing the inconsistent "folded into `CloseRow`'s triggers"; T-47 and T-48 join IG-13's preservation list. The spec already encoded the abstraction (its comment on `exState`). |
| CR-R2-34 | addendum F-03 (P1) | `Invariant03.tla` `Quarantine`; 03 §5.1 row, §5.2 restrictions, §5.4 figures | Accept: `Quarantine` gains the kill/wait-error alternative (`stopSent ∨ failed_after_clone`, the two cases in which the spawner attempts kill/wait and can report an error); the effect of a failed kill or wait is stated to be already in the model (`Kill` / `Reap` not taken); the one dropped case (a wait error after a spontaneous PID 1 exit with no stop and no failed record) is listed as a restriction; all four runs rerun, outcomes unchanged (run 1: 1,187,676 / 152,054 / 27). |
| CR-R2-35 | addendum F-04 (P1) | 04 EV-65 fact, source, excerpt, note | Accept: the measured fact is restricted to the dated root-configuration observations (baseline and unmapped arms read 60001; the mapped arm inconclusive); the mapped-arm statement from an undated unprivileged run is noted as the report's statement, not a measurement registered here. |
| CR-R2-36 | addendum F-05 (P1; overlap with first-record F-09) | 04 EV-28 and EV-87 notes; §0 class list; §4 count | Accept: EV-28 (lore.kernel.org cover letter, no message id in kub — identifier unresolved) and EV-87 (`CVE-2026-46333`, Qualys advisory 2026-05-20) join the external-kernel-record class; the class counts six rows and one unresolved identifier. |
| CR-R2-37 | addendum F-06 (P1) | 03 §5.1 `Submit` and `Handoff` rows, §5.1 "Not modeled"; two `.tla` comments | Accept: the successful T-03 admission is named as folded into `Submit` (its checks being the §5.2 relaxation) and the successful T-08 as `Handoff`'s folded precondition (a trusted-bootstrap fact, AA-04/AA-09; failure branch `SpawnFailAfterClone`). |

Checks after repair: `check-step3.py` exit 0; vocabulary scan of 03 and 04: none; 04 recount 98 rows (34 `[M]`,
49 `[R]`, 15 `[S]`).

### Targeted recheck of the addendum repairs (same day)

Two Codex CLI recheck runs were blocked by the provider's cybersecurity safeguard at their first turn (no
output); the recheck was then run by a cold-context Claude Opus agent (addendum record, section "Targeted
recheck (2026-10-14)"): F-03 holds; F-01, F-04, F-05, F-06 hold with remarks; **F-02 does not hold** because the
repair left the replaced DRAINING reading at two places and did not extend IG-01's open-row set (N-01 P2,
N-02 P1); TLC's four outcomes reproduced; checker exit 0; gate line "may not pass". Stopping rule: a
"does not hold" stops the round and goes to the user; the remark-level and the two new items are repaired
below as targeted edits, and whether another recheck runs is the user's call.

| request | item | changed surface | decision and repair |
|---|---|---|---|
| CR-R2-38 | N-02 (P1) | 03 §2 IG-01 prose | Accept: the open-row set is "RESERVED, PREPARING, STARTING, ACTIVE or DRAINING — the row states other than NONE and CLOSED", with the note that DRAINING is abstracted to ACTIVE in the model's `OpenRow`; IG-01, IG-08, IG-13 and §4 step 2 now use one open-row set. |
| CR-R2-39 | N-01 (P2) | 03 §5.2 "Not modeled" entry; §6 Stream Q line | Accept: "DRAINING as a distinct state (abstracted to ACTIVE, §5.1)"; "DRAINING abstracted to ACTIVE (T-47) with `bye` a `CloseRow` trigger (T-48)". No third wording remains (grep). |
| CR-R2-40 | F-01 remarks | 03 §2 IG-10 prose, §5.2 restrictions, IG-02 derived-from cell | Accept: the AA-09 gloss now reads as 01 states it (the spawner reads the SEALED bytes), and the "no byte reaches the engine" claim rests on T-08 and the pre-drop FAIL outcome (T-07, T-13); IG-02's cell says members hold the record's uid from T-07 on. |
| CR-R2-41 | F-04 remark | 04 EV-65 source cell | Accept: the mapped-arm paragraph is dprime L144–149. |
| CR-R2-42 | F-05 remark | 04 EV-87 note | Accept: the advisory link stands at fdsurvey L60 and additional-cases L48. |
| CR-R2-43 | F-06 remark | 03 §5.2 relaxations bullet, §5.1 `Submit` row; one `.tla` comment | Accept: T-03's admission checks are listed in full (uid/lease occupancy, plan digest, `seq`, no active SpawnRecord for the workspace, storage budget); the row and the comment say "admission checks". |

Checks after these edits: `check-step3.py` exit 0; vocabulary scan of 03 and 04: none; the `.tla` change is
comment-only (no rerun). The user ruled on 2026-10-14 to accept the candidate without a further recheck;
registered blobs: 03 version 3 `af8662ca14b83598`, `Invariant03.tla` version 3 `204f383dcc147004`, 04 version 3
`b868512116d812f0` (VERSIONS). CR-R2-01 … CR-R2-43 are the adjudications of the R2 node (Opus record, its
recheck, the Codex cross-family addendum, its Opus recheck). With both model families' reviews adjudicated the
fan-out gate's conditions are met; fan-out is not started by this node.

## 2026-10-15 — fan-out change requests (seven from the group streams, two from Stream Q)

Adjudicated by the reconcile role (main session) after wave 1, wave 2 and Stream Q were committed. Every
request was accepted; none adds, removes or renumbers an ID, and none weakens a guard. Applied as
01 version 8 `9efb243354a4e9d6`, 02 version 4 `31ddfc5daba58f13`, 03 version 4 `6868389a2182c161`
(TLA+ spec and configurations unchanged: the one-uid subset is unaffected by every change). The group
files' own request tables are kept as submitted (one `change-requests.md` per folder); the record numbers
below are this file's. Downstream re-run per the versioning rule — only files citing a changed ID, by their
owners — had **not** been dispatched when this section was written (the user stopped the session at the
token budget; see PLAN resume pointer); every downstream header therefore still carries the version-7/3/3
ids, which is the staleness the headers are meant to show.

| record | from | file and IDs changed | decision and what was applied |
|---|---|---|---|
| CR-F-01 | G1 CR-G1-01 | 03 IG-10 (guard list) | Accept: the uid clause split into (a) `SpawnRecord.uid` = the uid of the lease its `lease_id` names (T-03, si L271–272) and (b) every member's real uid = `SpawnRecord.uid` after T-07 (SEALED, conn L292–293); trivial in the one-uid model, load-bearing for a pool of more than one uid (R-G1-06, cell D_53). Files citing IG-10 (R-G1-03, three preservation files, R-GX-01…06) are to be re-read by their owners. |
| CR-F-02 | G1 CR-G1-02 | 01 T-14 precondition | Accept: RESERVED, or CLOSED before any send, with `submission = local`; PREPARING ∧ local is unreachable (conn L322). Wording only. Citing files: R-G1-05, R-G4-01, R-GX-02, G1/G4 preservation. |
| CR-F-03 | G3 request 1 | 02 q32; ledger sentence of R-G3-03 | Accept: q32 and the R-G3-03 sentence name `local_agent_id` beside the execution label (p81 requires both); D_81's structure unchanged; R-G3-05's remainder narrows. R-G3-03 §1 must copy the new sentence; R-G3-03/R-G3-05 §2/§6 and R-GX-02/05/06 re-read by their owners. |
| CR-F-04 | G4 request 1 | 03 IG-13 (MM-09 entry; note only, guard unchanged) | Accept: the pre-read check of conn L413 reads the original Session's state (CLOSED from T-40 step 1); the other reading leaves P_acc unaffected. Note only — no re-run. |
| CR-F-05 | G4 request 2 | 01 T-41, T-44 preconditions | Accept: a `stop` naming a record the spawner never received is a control fault (conn L131–142) → T-49 → T-44; both quarantine paths now visible in the inventory (03 §5.2's conservative reading). Citing files: R-G1-05/06, R-G4-01, R-GX-02/04, G1/G4 preservation. |
| CR-F-06 | G5 CR-G5-01 | 01 T-67 precondition | Accept: the exclusive-uid-pool deployment premise (02 §0.3, U-05, conn L87, iv L93–95, EV-81) joins S1–S14 and C1–C4 as a premise whose absence T-67 models; R-G5-06 gains its transition home. Citing files: fourteen (G5 all, R-G1-02, R-G2-07, R-G2-12, preservation files) — additive; owners confirm. |
| CR-F-07 | GX CR-GX-01 | 03 §1.1 (iii) (time fact of I_acc; no guard) | Accept: one rule for the end of an unreleased lease's interval at control loss — in the model it ends at T-49 (`NewEpoch`, sound under MM-10); for 02 §4's cell assignment it stays open, so the epoch-survivor history is R-GX-04's. R-GX-04 §2 and R-G4-01 §3 need no text change (GX). |
| CR-F-08 | Q CR-Q-01 | PLAN §Frozen design revision "Supported configurations" (not a spine file) | Accept for the plan text: two `[S]` items for C-LP — the per-agent model instance never runs under a pool uid or in an execution's pid namespace; per-execution provider selection keyed by `execution_id`, never by uid or `local_agent_id`. To be written into PLAN with the next pointer update; the D7 disposition stays conditional on unbuilt requirements. |
| CR-F-09 | Q CR-Q-02 | 03 §5.2 bounds paragraph, §5.4 run-record sentence, §6 "To Stream Q" (wording; no guard) | Accept: the "no coverage" sentence is scoped to 03's own runs; Stream Q's runs 5b (two generations) and 5c (cross-uid A-07) are recorded as within-bounds checks, 5a/5a-t2 as partial under the time bound; "one uid slot" and "two executions" stay prose-justified. |

Check-step scripts after the edits: `check-step2.py` and `check-step3.py` both exit 0; `reconcile-checks.py`
exit 0 (38 route files ↔ 38 ledger routes; partition and matrix checks pass; three soft findings on
R-G5-03/04/07 traversing the premise-departure row T-67, to be judged in reconcile.md).

## 2026-10-16 — adjudication of R3, Claude Opus record (thirteen findings)

Record: [R3-2026-10-16](../reviews/R3-2026-10-16.md), cold-context Claude Opus review of the convergence at
commit 6ed23699 (brief: R3-brief-codex-2026-10-16.md, shared with the Codex reviewer). 0 P1 · 7 P2 · 6 P3;
gate line "may pass". Every finding is accepted; the repair is the smallest edit by the owning file's rule
(convergence files and the checker: the reconcile role; route and preservation files: their group owners,
resumed with their own context; no spine file changed). The Codex cross-family record is adjudicated in its
own section when the user's dispatch returns it.

| record | finding | file(s) | decision and repair |
|---|---|---|---|
| CR-R3-01 | F-01 P2 | R-G1-01/02/03/05/06, R-G2-07/08 `stops:` vs §3 | Accept: the seven fields and §3 openings made identical by the G1 and G2 owners (G1: field := §3's first sentence; G2: §3's first sentence := the field, continuation moved to a second sentence). Checker check 9 added: the field equals §3's first sentence or is its opening phrase (the template calls the field "one phrase"; 31 files already used the phrase form). reconcile.md §1 row corrected. |
| CR-R3-02 | F-02 P2 | reconcile.md §1 C1–C4 / #1–#6 row; §2 (vi) | Accept: counts re-derived by checker check 12 with the method stated in the row (explicit mentions in §6, ranges counted for their endpoints): C1 23 · C2 7 · C3 8 · C4 28 · #1 5 · #2 25 · #3 2 · #4 12 · #5 2 · #6 29; (vi) names R-GX-05 beside R-G3-02 for #5. The row's conclusion (each maps to ≥ 1 route) was right; the figures were from an earlier grep over pre-re-read files. |
| CR-R3-03 | F-03 P2 | reconcile.md §3 (a); table §Residual line | Accept the record repair: §3 (a) and the residual line now name the premise R-G5-04 / R-G5-07 rest on that is outside S1–S14 and unmodelled by T-67 (no privileged map writer or other privileged actor for the agent's namespace); a 01 change to T-67's precondition is deferred to the next freeze (it re-opens fourteen files for a wording that changes no disposition). |
| CR-R3-04 | F-04 P2 | reconcile.md §3 (new h) | Accept: the `[S]`-dependence judgement for the three supported routes is now recorded in reconcile.md — no necessary component is `[S]`; EV-04's tag classifies the kub paragraph, the as-built drop is EV-74 `[M]`; a registry note is a Stream E matter listed for the next 04 version, not applied. |
| CR-R3-05 | F-05 P2 | G2 preservation.md row T-20 | Accept: EV-29 retagged `[M]` by the G2 owner; checker check 10 added (every `EV-nn [tag]` pair in route, preservation and convergence files against 04) — it reported this one live mismatch and no other. |
| CR-R3-06 | F-06 P2 | obligations-for-engine.md, coverage-uncertainties.md headers; three bullets | Accept the second resolution: each header states that the aggregate was taken at the gate ids before the re-reads and why it stands; the three superseded bullets (stamp-mismatch coverage → CR-F-09; interval-end reading → CR-F-07; IG-10 split → CR-F-01) are marked "superseded" in place with the applied version. Re-aggregation not done: the spine versions changed no obligation or uncertainty beyond those three. |
| CR-R3-07 | F-07 P2 | R-GX-01…05 §4 | Accept for GX: the GX owner replaces the "no registry row" sentences by EV citations and moves the registered rows into the §4 tables. R-G3-01/02/04's "not yet in the registry" tables are allowed by the append rule (those files cite no changed ID) and are left; noted here. |
| CR-R3-08 | F-08 P3 | reconcile.md §1 header row | Accept: "every header carries one of the two id sets in full (29 current, 14 gate)". |
| CR-R3-09 | F-09 P3 | table §Disposition and coverage statement | Accept: "is assigned by that decomposition to one of the 38 ledger routes, seven of which are remainder slots"; the sentence about the two stronger terms now simply says they are not used (the PLAN condition is not restated). |
| CR-R3-10 | F-10 P3 | change-requests.md (R2 section); table L40, L122; checker | Accept: "the record itself is written in full"; "exhaustiveness" twice reworded ("leaves nothing out"); checker check 11 extends the vocabulary scan to convergence/ (allowing "complete relative to M") and the group change-request files. |
| CR-R3-11 | F-11 P3 | R-G4-01 §5; G4 preservation §D4 (two places); R-GX-04 §5 | Accept: "C1 and the first half of C2" replaces the S1 mentions (G4 owner done; GX owner in the same round). |
| CR-R3-12 | F-12 P3 | R-G5-04 §3 | Accept: "read in kub §6 C2, EV-32 `[R]`" (G5 owner). |
| CR-R3-13 | F-13 P3 | table §Disposition and coverage statement | Accept: one clause names R-GX-04 as the conditional row whose requirement (MM-10) has no stated mechanism and is conditional only under AA-04. |

Out-of-scope items recorded by the reviewer: the checker gaps are now checks 9–12 (first item); EV-04's
limit sentence and 01 T-62 → T-67's missing premise are listed for the next registry / inventory version
(reconcile.md §6 does not change; they are Stream E and R1-scope matters by the review-point rule).

Stopping rule: P2 findings were accepted, so one cold targeted recheck per family follows (Claude Opus on
this round's repairs; the Codex record's repairs on their own round).

### Targeted recheck (same day, Claude Opus, cold context) and close-out

The recheck (appended to the R3 record) found 5 holds, 6 holds with remark, 2 do not hold (F-01, F-08) and
three new findings, all side effects of the F-01 repair; gate "may not pass". Adjudication:

| record | finding | file(s) | decision and repair |
|---|---|---|---|
| CR-R3-14 | N-01 P2 (F-01 does not hold) | uid-binding-vector-table.md, seven rows | Accept: the table was re-extracted with `reconcile-checks.py --table-out` after the seven `stops:` fields changed; the seven cells now equal the fields (script diff empty); the extraction comment names the re-extraction. |
| CR-R3-15 | N-02 P2 (F-08 does not hold) | reconcile.md §1 and §5; PLAN pointer; R-G2-08 header | Accept: R-G2-08 cites no changed ID, so its header is returned to the gate ids by the G2 owner (the versioning rule); R-G2-07 stays on the current ids (it cites T-67); the counts read 30 current / 13 gate in reconcile.md §1 and §5 and in the PLAN pointer, with the reason stated in §5. |
| CR-R3-16 | N-03 P3 | reconcile.md §3 (h) | Accept: the sentence no longer claims the EV-04 note is listed in §6; it is noted in (h) for the next registry version and not applied. |

The six "holds with remark" items (F-02, F-04, F-05, F-06, F-07, F-10) are remark-level and are adjudicated
without another recheck per the stopping rule; the remarks stand in the record. One narrow recheck of
CR-R3-14…16 by the same cold reviewer follows; if it returns "may pass" the Opus family of R3 is done.

## 2026-10-16 — adjudication of the R3 cross-family addendum (Codex, eight findings)

Record: [R3-addendum-2026-10-16-crossfamily](../reviews/R3-addendum-2026-10-16-crossfamily.md), dispatched
by the user; the reviewer read commit cedb6917 (the state before the Opus recheck repairs CR-R3-14…16) and
says so. 1 P1 · 4 P2 · 3 P3; 3 NEW, 5 OVERLAP; gate "may not pass" for cedb6917. Every finding is accepted;
three were already repaired at 92210167 / 62f120f3 before the addendum was written and are recorded as
resolved by those repairs; the five others are repaired here by the owning file's rule.

| record | finding | file(s) | decision and repair |
|---|---|---|---|
| CR-R3-17 | F-01 P1 (overlap F-08) | reconcile.md §1, §5 header counts | Accept; resolved before this record by CR-R3-15 (counts 30 / 13 with the reason; R-G2-08 back on the gate ids). The addendum's 31 / 12 is cedb6917's state. |
| CR-R3-18 | F-02 P2 (overlap F-01) | uid-binding-vector-table.md seven stops cells | Accept; resolved before this record by CR-R3-14 (table re-extracted; a fresh `--table-out` diffs empty against the file). |
| CR-R3-19 | F-03 P2 (overlap F-11, new substance) | R-G5-04 §6; coverage-uncertainties.md C-02 bullet | Accept: §6 now says the production allow-set (EV-129 `[S]`) is an optional surface reduction for sub-branch B, not a component the identity defence needs — the map rule and the initial-namespace posture stop the route (G5 owner); the aggregate bullet reworded the same way (reconcile role). Disposition unchanged; the necessary-component statement for the three supported routes stands (reconcile §3 (h)). |
| CR-R3-20 | F-04 P2 (overlap F-06, three further bullets) | coverage-uncertainties.md C-05, C-06, C-08 bullets; header note | Accept: the IG-10-split, T-67-premise and q32 bullets are marked superseded in place by CR-F-01 / CR-F-06 / CR-F-03 with the genuinely open part kept; the header now says six bullets. |
| CR-R3-21 | F-05 P2 NEW | G4 preservation.md §D4, alias row | Accept: the numeric-fd / receiver_generation alias row's selector reference corrected to 02 v4's assignment (D_51 ∧ ¬(q18 ∨ q19) ∧ q20), the reason clause adjusted (G4 owner); the 7 / 6 / 3 labels unchanged. |
| CR-R3-22 | F-06 P3 NEW | obligations-for-engine.md T-07 bullet | Accept: SEALED (conn L289–293) detects a wrong stamped real uid, not an unequal effective or saved uid; a post-drop three-value verification stays an obligation (reconcile role). |
| CR-R3-23 | F-07 P3 NEW | R-GX-03 L58–60 | Accept: the statement is limited to new reads or sends after release; the buffered parse finishing on a CLOSED row with the original label is kept as IG-13 allows (GX owner). |
| CR-R3-24 | F-08 P3 (overlap F-04) | reconcile.md §3 (h) | Accept; resolved before this record by CR-R3-16 (the sentence no longer points to §6). |

Stopping rule: P2 findings with new substance were accepted (CR-R3-19, -20, -21), so one cold targeted
recheck follows, by Claude Opus on the Codex-round repairs (the precedent of R2: the first family rechecks
the second family's repairs); the three findings resolved before the record need no recheck beyond the
Opus narrow recheck already recorded.

### Close-out of R3 (both families)

Targeted recheck of the Codex-round repairs (Claude Opus, cold context, appended to the addendum record):
CR-R3-19 … CR-R3-23 all hold, no remark, no new finding; checker exit 0 (headers 30 current / 13 gate); a
fresh table extraction is byte-identical to the table file; gate "may pass". With the Opus family's narrow
recheck "may pass" (CR-R3-14 … 16), R3 is adjudicated for both families (24 records, CR-R3-01 … CR-R3-24);
the user gate U opens on the table at this state.

## 2026-10-16 — follow-up step 1 (a): the R-G2-05 re-run (two requests from G2)

Source: [G2 change-requests](../groups/G2-receive-and-check/change-requests.md), written by the fresh R-G2-05
owner (cold-context Claude Fable 5.1) on 01 v8 / 02 v4 / 03 v4 / 04 v5. Adjudicated by the executor.

| id | request | decision | applied |
|---|---|---|---|
| CR-G2-01 | 02 §5.2 U-01 / U-02 and the R-G2-05 ledger row's last column: state what the 2026-10-16 queue reading narrows, with its two bounds | Accept: without it the spine still calls the slot an unestablished gap while the route file argues a disposition from a positive property of the producers (02 L218 forbids a disposition from totality alone, which the re-run does not use) | 02 v5 |
| CR-G2-02 | landing of the configuration departure "agent holds CAP_NET_ADMIN in the initial user namespace and a descriptor to the engine's end" (credential-less sockmap bytes, D_21 ∧ ¬q08): (a) a new D_21 selector to a G5 route, or (b) keep it in R-G2-05 and add T-67 | Accept option (b): it matches the existing treatment of premise departures in R-G5-03 / 04 / 07 (supported only on the branches where the premise holds, checker SOFT line); a new selector and route would change the ledger's route count for a history the stated premise already excludes. Step 11 absent on the host is a T-67 configuration failure (01: a deployment or trusted-actor error, not the adversary), so it takes no adversary route; the route file's §6 (iv) states this reading (wording corrected to it the same day, 02 v6) | 02 v5 (ledger row principal transitions gain T-67) |

Executor format repair: R-G2-05's `stops:` field set to the opening phrase of its §3 first sentence (check 9;
punctuation only, the content unchanged).

## 2026-10-19 — follow-up step 4: re-run of 30 routes on the engine build's checks

Source: the step-4 sections of the six group change-request files, written by the route re-run owners
(cold-context Claude Opus) on 01 v10 / 02 v9 / 03 v5 / 04 v7 under [step4-brief](step4-brief.md); G1, G4 and G5
raised none. Adjudicated by the executor. Requests that target the engine's validation record are not applied
here — that record belongs to the engine build — and are forwarded (last table).

| id | request | decision | applied |
|---|---|---|---|
| CR-S4-01 | G3 request 2 (2026-10-18): EV-116 / EV-121 quote text the fourth revision rewrote | Accept as superseding rows plus a §2 paragraph (append-only) | 04 v7: EV-243, EV-244, §2 |
| CR-S4-02 | G3 request 3 (2026-10-18): coverage-uncertainties.md MM-06 item and obligations-for-engine.md stale R-G3-02 cites | Accept for coverage-uncertainties (refreshed whole for step 4); obligations-for-engine is marked superseded as the requirement list by engine-requirements.md, kept as the 2026-10-15 record, so its line cites are not re-pointed | coverage-uncertainties.md, obligations-for-engine.md header |
| CR-S4-03 | G2 4a-1: register val rows 167 / 168 (unsigned uid crossing; sender_pid None) | Accept | 04 v8: EV-247…EV-250 |
| CR-S4-04 | G2 4a-2: EV-174's split positions (bytes 2, 4, 9, one inside the header) | Accept as a new row (no note edits) | 04 v8: EV-251 |
| CR-S4-05 | G2 4a-3: validation.md moved to commit c834ebbd (rows 145 / 146 / 151 / 170 / 191 / 193 / 209 reworded; credential-option scan test) | Accept: §0 names both blobs, §2 paragraph, the scan run registered | 04 v8: EV-252 |
| CR-S4-06 | G2 step-4-b request 1: 02 U-02 and the ledger's sixth column still call R-G2-11 / 12 / 13 unresolved | Accept, wording only | 02 v10 |
| CR-S4-07 | G2 step-4-b request 2: jansson (called by the C reader after the comparison) and CPython's json (on the Python copy) treated in R-G2-11 as premises like the intact kernel; if rejected, R-G2-11 is conditional until an ASan-instrumented jansson fuzz entry runs | **Referred to the user** — the disposition turns on it; R-G2-11 carries the classification visibly in §5 meanwhile | — |
| CR-S4-08 | G3 request 4: seven `[R]` readings proposed by the G3 routes | Accept (each confirmed against the code by the registry agent) | 04 v8: EV-253…EV-259 |
| CR-S4-09 | G3 request 6 and GX CR-GX-03: `[S]` rows cited by route files missing from the step-4 map; stale "cited by no route file" line | Accept | step4-evidence-map.md |
| CR-S4-10 | G3 request 7: the prototype's receive_rejected record carries the row's execution_id in its reject group, which si L68 does not list (not a subject) | Forward to the user as a design / record-schema question; no route disposition depends on it (R-G3-04 argues the record carries no verified_subject) | — |
| CR-S4-11 | R-G5-05 owner: check 7's premise pattern does not admit C3 | Accept: a route traversing T-67 on a C3 departure names C3 | reconcile-checks.py check 7 |

Forwarded to the engine's validation record (not applied by this line):

| from | validation row / section | what the re-run found |
|---|---|---|
| registry agent | row 129 | the cited test refuses at the 16-slot limit, not on uid exhaustion; the exhaustion clause rests on code reading only (R-G1-05 §5 says so) |
| registry agent | row 220 | holds for its own sentence; the engine sets PR_SPEC_DISABLE, scope S14 names FORCE_DISABLE (map: EV-128 partly) |
| G2 step-4-b request 3 | row 175, §R-G2-11 limits | the fuzz covers transport.c only; the Python json half of row 175 is not exercised and its limits list does not say so |
| G3 request 5 | row 172 | the remark "E-09 hook 首版不存在" contradicts requests.py:114 and :229–230 (an observe-only pre_egress hook point exists, empty in the product); the row's result holds |
| GX CR-GX-02 | §R-GX-06 | the result should read 满足（测试加代码阅读） as its row 149 does, and the limit should name the integration normal case that reuses fd numbers through the real spawner (EV-189) |

Executor repairs during reconcile: reconcile.md §7: the lower-case state name in "row-… gate" written as CLOSED (vocabulary scan);
the two G2 step-4 request files merged into the group's change-requests.md (the checker admits only that name);
header set step4 / step4b added to reconcile-checks.py.

## 2026-10-19 — adjudication of the S4 review, Claude Opus record (eight findings)

Source: [S4-2026-10-19](../reviews/S4-2026-10-19.md) (cold-context Claude Opus, at b7c3167d; gate "may not pass" on
F-01). Adjudicated by the executor; the user ruled on F-01's remedy. Repairs by the owning route agents (resumed),
the reconcile role for the table and this file.

| id | finding | decision | applied |
|---|---|---|---|
| CR-S4-12 | F-01 (P1): R-G2-11 counted supported while jansson's memory safety — a parser running inside the C FrameReader after the comparison, on a buffer in the same heap object as the reader's binding fields — was unchecked and carried as a premise | Accept. Verified at transport.c:238 and transport.h:16, and that conn E-02 L487–492 leaves the body parse to Python json, so the C-side parse was an implementation step the design does not have. User ruling 2026-10-19: remove it. Engine commit 7b4ab727 removed it (malformed bodies still rejected, now by the Python parse; regression, integration and fuzz rerun); registry v9; R-G2-11 re-judged on the new evidence — jansson is off the data path, CPython's json a platform premise. CR-S4-07 is resolved by this | engine 7b4ab727; 04 v9 (EV-265–EV-272); R-G2-11 |
| CR-S4-13 | F-02 (P2): R-G2-11's stops said "the C code on that path showed no memory error", more than the fuzz showed | Accept | R-G2-11 stops and §3 (table row re-extracted) |
| CR-S4-14 | F-03 (P2): R-G2-13 inherited the same parser premise, not shown in CR-S4-07 | Accept; moot after CR-S4-12 — R-G2-13 now names no jansson premise; R-G2-01 checked by its owner: its defence never depended on the C-side parse | R-G2-13, R-G2-01 |
| CR-S4-15 | F-04 (P2): the table's residual line listed C1–C4 as unchecked deployment preconditions and omitted the parser premise | Accept | residual line names the engine-requirements §8 entries and the CPython premise |
| CR-S4-16 | F-05 (P3): stale pointers in R-G2-11/12/13 §6 and coverage-uncertainties | Accept | three slot files; coverage-uncertainties.md |
| CR-S4-17 | F-06 (P3): table preface and front matter named 04 v6 / 02 v9 | Accept | table front matter and preface (02 v10, 04 v9) |
| CR-S4-18 | F-07 (P3): R-G2-13 repeated val row 172's wrong remark on the E-09 hook | Accept | R-G2-13 §6 (EV-255) |
| CR-S4-19 | F-08 (P3): premises lines of R-G2-08, R-G3-02, R-G3-03 carried engine-side items | Accept | moved into the compositions, tagged "(realized: EV-…)"; R-G2-10 tagged likewise |

Also in this round: the route files that cite rows describing the pre-7b4ab727 reader (EV-166–EV-168, EV-171's parse
clause, EV-169 / EV-236 line numbers) were checked by their owners — R-G1-02, R-G1-03 and R-G5-05 needed no change;
R-G2-01…10, R-G3-01…04, R-GX-01/02 cite the successors. The evidence-limit clause "engine code … unchanged by later
commits except one test-build line" in nine route files was extended by the reconcile role with "and, at 7b4ab727, the
removal of the C-side body parse (EV-265)" (raised by the R-G5-05 owner).

**Recheck (2026-10-19, the record's §4, at e92cf838): "may pass".** F-01…F-08 hold (F-01 with a remark); stopping
rule applied, no further recheck.

| id | item | decision | applied |
|---|---|---|---|
| CR-S4-20 | F-01 remark: CPython's json is carried as a platform premise that is not an engine-requirements §8 entry; did the user rule on it? | Recorded: the executor's report that proposed the removal named this as the one premise left after it, and the user approved the removal on that basis (2026-10-19, "同意删除jasson") without objection | this row |
| CR-S4-21 | F-09 (P3, new): R-G2-06 and R-G2-07 gave transport.c line ranges of 3ec67985 only | Accept | both files, by their owner |
| CR-S4-22 | F-10 (P3, new): an R-G2-11 support row listed content checks the C reader no longer does | Accept | R-G2-11 §4, by its owner (stops and disposition unchanged) |

Executor repair: the recheck heading of the review record renumbered §4 (the record had two sections numbered 3).

## 2026-10-19 — adjudication of the S4 cross-family addendum (Codex, three findings)

Source: [S4-addendum-2026-10-19-crossfamily](../reviews/S4-addendum-2026-10-19-crossfamily.md) (Codex, user-dispatched, at
562d6ed2; P1 0 · P2 0 · P3 3; gate "may pass"). No disposition change; remark-level only, so adjudicated without a
further recheck (stopping rule).

| id | finding | decision | applied |
|---|---|---|---|
| CR-S4-23 | F-01: the clause the reconcile role inserted into nine evidence-limit sentences attached "of spawner.c" to the body-parse removal | Accept (the executor's own insertion) | nine route files: "one test-build line of spawner.c … and, at 7b4ab727, the removal of the C-side body parse from transport.c, EV-265" |
| CR-S4-24 | F-02: R-G5-05's EV-178 cell read "setsockopt SO_PASSCRED = 0" | Accept | "SO_PASSCRED set to 1 (setsockopt returned 0)" |
| CR-S4-25 | F-03: R-G2-06 and R-G2-02 still pointed to the merged step-4 request file and to unregistered rows | Accept | point to CR-G2-4a-1 / 4a-2 and EV-247–EV-251 |

S4 is adjudicated for both families.

## 2026-10-20 — the forwarded engine findings, resolved

The user asked what the engine side had to change and ruled to do it in this session. Engine commit 9981dd7b: the S14
opt-in now sets `PR_SPEC_FORCE_DISABLE` as S14 names (the registry agent's "not confirmed" row 220); the receive_rejected
reject group no longer carries the row's execution_id (CR-S4-10, user ruling: remove the field); validation.md rows
129, 172 and the R-GX-06 entry reworded to what the code and tests show (the remaining forwarded findings; row 175 was
already repaired at 7b4ab727). Line side: 04 v11 (EV-283–EV-288); R-G3-04 §6, R-G5-02 §4–§6, G4 preservation T-49 / §D4
(D4 sort 9 · 6 · 1 → 9 · 7 · 0: the supervisor's method is stated, its cut belongs to the supervisor and deployment, not
E-04) and coverage-uncertainties updated by their owners. No disposition changed; the table rows are unchanged.
