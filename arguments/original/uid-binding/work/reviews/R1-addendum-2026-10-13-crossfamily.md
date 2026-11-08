# R1 addendum — cross-family cold-context read of Steps 1–2

Date: 2026-10-13. Plan-local addendum to [R1](R1-2026-10-13.md); not a document-harness round, not a
landing approval, not an adjudication. Findings are for the executor to adjudicate under PLAN §Review points.

## Header

- Reviewer: cold-context agent, Claude Opus (Anthropic model family; no access to the executor's or the
  first R1 reviewer's conversation). Read-only except for this file. Sealed draft not read; no experiment run;
  no git state changed.
- Subject blobs, verified with `git hash-object` from the repository root:
  - 02-conditions-and-decomposition.md (version 2): `dfcba2c3255b431d` — match.
  - 01-model-inventory.md (version 6): `0f7b6e5f7167709b` — match. The v5 → v6 diff (commit cf28848)
    was read: one six-line paragraph in §0 and the status line, as VERSIONS states.
- Structural checker `python -I Thesis/Work/Submission/prove/uid-binding/work/tooling/check-step2.py`: exit code 0.
  Counts: 52 transitions; 39 ledger routes (G1 5, G2 13, G3 5, G4 2, G5 8, GX 6); 18 components;
  32 selectors; 74 local split valuations; no missing / extra / duplicate transition owner, no transition
  without ledger trace, no matrix error, no unknown ledger transition, no split error.
- Frozen-file blob checks (first 16 hex digits):

| file | expected | result |
|---|---|---|
| conn (connections.md) | 74b136585c4064e1 | match |
| rr (resources-routing.md) | abfe61158ca9ddfe | match |
| si (supporting-interfaces.md) | 595e1471fbecfa5e | match |
| sbx (sandbox-design.md) | 90766bd3602a1de9 | match |
| iv (implementation-validation.md) | de1e36678014470c | match |
| mech (mechanism.md) | 3a205e6e10e31fdd | match |
| optb (option-b-workload-per-engine.md) | a1764239a580f40d | match |
| kub (kernel-uid-binding.md) | 131fce72d01a5df8 | match |
| scope (scope-and-boundary.md) | 029a51193e92d38f | match |
| tm (threat-model-derivation-map.md) | c8e60929f74a3429 | match |

Line numbers below refer to the verified blobs. "02 Lnn" and "01 Lnn" are lines of the two spine files.
R1-01…R1-08 are not repeated; where a finding touches a repaired element it says what the repair left.

## Findings

**F-01 — P2 — criteria 3 and 4.** 02 L130 (C-07 p72), L141–146 (§3), L171 (F_7), L258 (D_72), L382
(R-G4-02), L448 (C-07 × G4 cell).
*Text:* D_72 = p71 AND NOT p72 routes q28 → R-GX-03 and NOT q28 → R-G4-02; R-G4-02 is reached only
through D_72; the matrix lists G4-02 as the C-07 route of G4.
*Why it fails:* the §3 argument uses C-07 only as "C-07 places send_b in J_r", that is p71; p72 is never used.
So C-01…C-06 ∧ p71 already gives P_acc(a*), and F_7 ∧ D_72 = Bad_acc ∧ C-01…C-06 ∧ p71 ∧ NOT p72 is
unsatisfiable. In addition D_72 ∧ q28 contradicts p13 (same read / generation as a), which holds under F_7.
R-G4-02 therefore has no history in its partition cell, the C-07 × G4 cell lists a route that the masks
leave empty, and the D_72 entry of R-GX-03 is empty. 02 L133–135 already concedes that a phase error with
the right label is not false attribution, which is the same fact. Either §3 omits a use of p72, or D_72 and
R-G4-02 need a "no route, because …" reading.

**F-02 — P2 — criteria 3 and 4 (also 2).** 02 L102 (I-05), L111 (A_r), L126 (p33), L128 (p52), L250
(D_33), L254 (D_52), L363 (R-G1-02), L365 (R-G1-04).
*Text:* I-05 names "row's expected uid u_r"; L111 defines A_r = (X_r, u_r, lease_r, epoch_r); p52's first
conjunct is expected_uid(r) = A_r.uid; D_52 ∧ q21 → R-G1-04 ("expected uid assigned or overwritten
inconsistently with its reservation").
*Why it fails:* u_r has two definitions. If both hold, A_r.uid ≡ u_r ≡ expected_uid(r) and q21 is false by
definition, so R-G1-04's cell is empty. If u_r means A_r's uid, the T-23 comparand e_r is read from the
row's expected_uid field (01 L133), so an overwritten field already violates p33 and the history is routed
D_33 → R-G1-02, whose sentence (L363) describes the same story; D_52 ∧ q21 is then reachable only when
the comparand does not come from the field, where the field mismatch is not the cause of the wrong label
and the history has to fail C-06 or C-07 as well. Under either reading, the R-G1-04 ledger sentence does not
describe the histories its branch predicate selects.

**F-03 — P2 — criteria 2 and (d).** 02 L30–33 (X, Exec), L37 (L(a) read from engine objects), L111–112
(A_r "fixed by reservation and clone correspondence"), L145 ("Exec(b) = X_r = L(a).execution").
*Text:* Exec(b) is a spawner clone event; L(a).execution and A_r.execution are engine execution_id values;
the two are equated through "clone correspondence".
*Why it fails:* the map from an engine execution_id to the clone event that the property's ground truth
uses is neither defined nor stated as a predicate over named inputs, although the last step of the
implication depends on it. The facts that fix it in the inventory (SpawnRecord{execution_id, …, child_pid}
at 01 L75, T-03/T-05/T-09) are not named in 02. A launch correspondence error (a clone made for one
execution_id whose descriptor or uid ends up with another row) therefore has no component of its own: it
either changes the definition of X_r — making the property hold by the bookkeeping that PLAN Context (1)
keeps apart from ground truth — or it falls to p62 and is routed through q26 / the R-G5-08 remainder into
G5 rather than to the G1 transitions that produce it. p51 covers row ↔ channel, not execution_id ↔ clone.

**F-04 — P2 — criterion 3.** 02 L193–196; selectors q02 (L203, "can be associated"), q17 (L218,
"demonstrably wrong"), q26 (L227, "documented lawful").
*Text:* "If attribution of a cause is unknown, its selector is false and the explicit remainder owns it."
*Why it fails:* this makes each selector a predicate over the analyst's present knowledge rather than over
I-01…I-08 and the ghost history that L193 says they read. Totality and pairwise exclusion still hold at each
evaluation, but B(route) stops being a fixed set of histories: the same history moves from a named route to
a remainder slot (or back) as knowledge changes, so a route file or a Step 3 guard cannot cite B(route) as a
stable branch predicate. A trace-only definition with the remainder owning the histories in which none of
the named trace facts occurs keeps the same totality.

**F-05 — P2 — criteria 4 and (c).** 02 L308–314 (§5.1 table) against L395–400 (ledger).
*Text:* the input rows list "G2-01…07, GX-01"; "G1-02, G5-05, G2-03/06"; "G1-05, G4-01/02, G5-06/07,
GX-01…05"; "G2-07…10, G3-01…04, GX-05"; "G5-01…07"; "G1-03/04, G2-08…10, GX-01…03".
*Why it fails:* six of the seven remainder slots added in version 2 appear in no input row: R-G2-11,
R-G2-12, R-G2-13, R-G3-05, R-G5-08, R-GX-06 (only R-G2-05 is listed). The input ↔ route traceability
check therefore fails in the route → input direction for those IDs, and §5.1 was not brought up to the
version-2 ledger. The structural checker does not read §5.1, so its exit 0 does not cover this.

**F-06 — P2 — criterion 1.** conn L79 (local_agent_id is a logical name; a new execution does not inherit
permissions from the same name), conn L343 (E-01-R1: same-name local_agent, new execution, no old grant),
conn L515 (VerifiedContext field), si L93 (verified_subject copies local_agent_id), optb L38; against 01 L45
(D-ACC label), 01 L69 (Execution row), 01 §8 L336–365; 02 L128 (p52), L131 (p81), L231 (q30).
*Text:* 01's label is (execution_id, session_id, channel_id, receiver_generation, expected_uid); the
Execution row omits local_agent_id; no X-entry excludes it; T-24 lists it only as a written field.
*Why it fails:* the frozen text carries a label field that it explicitly marks as reusable across
executions, with a stated rule for that reuse — the same shape as numeric uid reuse. It has neither a model
landing (state and assignment at T-01) nor an exclusion argument in 01. In 02, p52 constrains only the
session/channel/lease/epoch fields and p81 only the execution label, and q30 names relookup by numeric
uid/fd/request number; a consumer keyed on local_agent_id would reach only the R-G3-05 remainder.

**F-07 — P3 — criterion 1.** conn L81 (Channel.phase has four values, from bootstrap-handoff through hello and data to the teardown value),
conn L302 and L391 (FAIL bytes handled "in the hello phase"); 01 L71 (Channel row), L119 (T-09 sets
bootstrap-handoff), L122 (T-12 sets data), §7 L282–334.
*Text:* no 01 transition writes the hello value of Channel.phase.
*Why it fails:* the bootstrap-handoff → hello phase update is a state update the receive path's phase
parse (T-24) and the FAIL-byte rule depend on. The frozen text does not state its triggering event either,
so it belongs in §7 as a missing mapping, like MM-15 for receiver_generation; it is neither landed nor listed.

**F-08 — P3 — criterion 5.** 02 L287–289 (§4.1 item 4); PLAN L518 (Stream P sub-arms); 01 L130
(T-20 branches b–e); kub §5.
*Text:* item 4 lists four input cases and says error numbers are not copied, without stating the derived
outcome of any case.
*Why it fails:* the pre-registered hypothesis is the set of expected outcomes, and it is neither re-derived
nor refuted. The derivation already exists in 01 T-20 (b) own-set slot accepted, (c) foreign uid EPERM
without CAP_SETUID, (d) unmappable EINVAL, (e) self-mapped 0 resolving to the sender's kernel uid. Branch (e)
and kub §5 give a delivered message stamped with the sender's own uid, while PLAN L518 expects
EINVAL / EPERM for the self-mapped sub-arm; 02 does not record that disagreement for the reconcile step.

**F-09 — P3 — criterion 4.** PLAN L470, L513 (the explicit foreign-uid route placed in G2) and L518
(Stream P starts once the ledger contains that route); 02 L246–247 (D_21 / D_22), L371 (R-G2-05),
L386 (R-G5-04), L415 (G5 owns T-61/T-62).
*Text:* the derived foreign-uid cases land in R-G5-04 (lawful map/privilege) or the R-G2-05 remainder;
under the intended posture T-20 (c) produces no skb and hence no route.
*Why it fails:* re-cutting the provisional groups is allowed, but 02 does not state which ledger entry
is the route that PLAN places in G2 and that Stream P waits for, nor record that the intact-posture
foreign attach yields no route. A downstream consumer of the ledger cannot resolve its trigger from 02.

**F-10 — P3 — criterion 3.** 02 L135–136, L162–166, L262.
*Text:* "Every route below therefore needs both its predicate failure and the wrong/no-origin labelled
event"; B(R-G5-01) = H AND N1; B(R-G5-02) = H AND NOT N1.
*Why it fails:* the two H expressions carry no Bad_acc or NOT C-08 conjunct, so their cells contain
correctly attributed histories, contrary to L135–136. Every non-H cell is restricted by F_1…F_8; the H cells
are not.

**F-11 — P3 — criterion 3.** 02 L255 (D_61 NOT q23 → R-GX-04), L393 (R-GX-04 sentence); 02 L342–343 (U-05).
*Text:* the route sentence describes an old-epoch survivor while a replacement engine treats the pool as empty.
*Why it fails:* B(R-GX-04) = D_61 ∧ NOT q23 selects every overlapping allocation with a different
engine_epoch, including two engines running at once on overlapping pools (the U-05 host-wide exclusivity
premise). Those histories are assigned to R-GX-04, whose sentence and transition list (T-49, MM-10) cover
only epoch succession.

**F-12 — P3 — criterion 2.** 02 L131 (p81), L148–149, L177–178.
*Text:* "every attributed consumer event with an actual D-ACC causal origin carries that original context".
*Why it fails:* "that" presumes a unique D-ACC causal origin. A consumer decision with more than one D-ACC
causal origin (for example a T-33 decision over a request and a TaskCall state last changed by a T-36 or
T-37 message) has no defined comparand, so p81 is not a predicate over named inputs for that case and the
P_acc ∧ C-08 step at L148–149 is not defined there either.

**F-13 — P3 — criterion (c).** 02 L154–158, L168–196, L262–266, L333 (U-02).
*Text:* U-02 refers to "the stated logical coverage warrant".
*Why it fails:* no paragraph is labelled or locatable as the coverage warrant PLAN L176–178 requires;
its parts (contrapositive, first-failure masks, component splits, explicit remainders) are spread over §3
and §4. Downstream files and the landing step need one citable statement of why the split covers the
negation of P_acc, written as a check.

**F-14 — P3 — criterion (b).** 02 L382 (R-G4-02 sentence).
*Text:* the sentence uses the bare noun formed from "close" that PLAN Context (2) (PLAN L161–168) lists
among the unqualified words never used, to mean session teardown.
*Why it fails:* the vocabulary note at 02 L9 exempts only the design state name; this noun is not
exempted and has no allowed qualified form here. "Session teardown" or "the T-40 decision" carries the meaning.

**F-15 — P3 — criterion (b).** 02 L343 (U-05) and L453 (closing paragraph).
*Text:* both lines use, in negated form, the unqualified adjective whose only allowed form in PLAN
Context (2) is "… relative to M" with M's version.
*Why it fails:* the discipline is literal ("never used"); the negation does not supply the qualifier.

**F-16 — P3 — criterion 4 (spine records).** VERSIONS.md L32 (01 version 4) and L33 (02 version 1).
*Text:* the blob ids `73a06fb040c417fdc` and `5691956ff40461ddf` carry 17 hex digits.
*Why it fails:* the file header (VERSIONS L3–4) fixes the id as the first 16 hex digits; downstream files
that copy ids by that rule will not match these two rows by string.

## Checked and consistent

- Criterion 2, ground truth apart from lookup: Exec(b) is pid-namespace membership at send_b, with "Neither a
  uid nor a session lookup defines Exec" (02 L30–35); consistent with 01 D-GT (01 L30–40).
- Criterion 2, per-byte chain: C-02 → C-03 (p31 injectivity, p32, p33) → C-04 → u(task_b, send_b) = u_r,
  then p71 and p62 give task_b ∈ P_Xr (02 L141–146); no step reads the label to define the sender (the
  step that depends on the correspondence map is F-03).
- Criterion 2, contrapositive stated: "¬P_acc ⇒ at least one failed C-01…C-07" (02 L154); C-08 kept as a
  separate carry obligation (02 L148–152).
- Criterion 2, R1-07 / R1-08 repairs hold: F_1…F_7 restricted to a* under Bad_acc, F_8 = NOT Bad_acc AND
  NOT C-08 (02 L168–181); p81 limited to actual D-ACC causal origins, p82 owns originless events (02 L131,
  L177–179).
- Criterion 3, local splits: every D_ij row ends in "else", "NOT q…" or "true" (02 L243–260); the checker's
  74 valuations report exactly one hit each; D_ij definition (02 L183–189); H precedes the normal split (02
  L162–166, L262).
- Criterion 3, R1-02 repair holds: D_62 orders q24 (prior survivor) → q25 → q26 → remainder (02 L256).
- Criterion 3, R1-05 repair holds as a predicate: e_r defined apart from r(u_r) (02 L110) and p33 added
  (02 L126); the remaining issue is the u_r symbol (F-02).
- Criterion 4, group cut: every 01 T-ID (T-01…T-14, T-20…T-26, T-30…T-39, T-40…T-52, T-60…T-67) has
  exactly one owner (02 L411–415; checker); GX owns routes only (02 L404).
- Criterion 4, group-cut inputs re-derived: the eight dual-group items of 00-group-cut-inputs.md (L32–40)
  each receive a ruling in 02's overlap column (hello → G1/G2 split; deadline/EOF → T-46 in G4; empty before
  hello → G4; control idempotence → G4; cleanup_stalled latch → G4; late callback → T-51 in G4 with GX-05;
  try_dispatch recheck → G3; configuration-failure route → G5 with G1 owning initial posture) (02 L411–415);
  the four unplaced families land at T-49/X-11, X-01, X-02, X-03 (02 L414, L421–431).
- Criterion 4, ledger columns: all 39 rows carry B(route), violated condition(s), group and cross flag with
  transitions (02 L362–400); ledger condition sets equal matrix incidence (checker); each "no route" cell
  carries a reason (02 L442–449).
- Criterion 4, R1-06 repair holds: T-26 traced by R-G1-03, T-60 by R-G2-07, T-39 by R-G3-02 and R-G3-05
  (02 L364, L373, L378, L398).
- Criterion 5, items 1–3 re-derived rather than copied: descriptor possession alone is not a failure
  predicate (02 L270–274); "unshare allowed ⇒ forged uid" rejected under the §3 mapping rule (02 L275–280);
  physical drain not logically necessary, stale queue routed to GX-01/03 and post-teardown processing to
  G4-02 (02 L281–286; see F-01 on G4-02); observation-only channels answered per Context (2) with U-04
  (02 L291–300).
- Criterion 1, sampled landings: conn E-02 steps 1–7 (L407–435) ↔ T-21–T-24; conn VerifiedContext table
  (L505–523) ↔ T-24 except F-06; conn E-01 state table (L318–336) ↔ T-02, T-09, T-12, T-14, T-40, T-43;
  conn E-04 close steps 1–6 and empty-basis table (L784–848) ↔ T-40–T-45, T-14, MM-09; rr TaskBinding /
  Grant lifecycle ↔ T-39 (R1-04 repair holds); kub §2.6 two conditions (outside-parent fork, parent-namespace
  ptrace) ↔ MM-01 and the S5 premise.
- (a) No defence sentence: a search of 02 for stop / cut / prevent / defend / block / guard / mitigate /
  protect / deny / immune finds only "protected state" in R-G5-01 (02 L383), which names a target.
- (b) No frequency or proportion wording of the kind PLAN Context (2) forbids appears in 02; the two
  uses of "success" (02 L289, L405) name an outcome, not a measure.
- (c) §5.1 is headed as a check, not a coverage proof (02 L304); U-01…U-07 exist (02 L324–350).
- (d) The departure from PLAN Context (1)'s accept-time wording is stated identically in 02 L65–68 and
  01 L55–60 (CR-OWN-02); per-origin merging is consistent with 01 AA-07 (01 L266–268).

## Not checked

- Kernel source at the pinned WSL tag (af_unix.c L2618 and L1745, kernel/pid_namespace.c, kernel/exit.c):
  not fetched; the kub readings were taken as recorded.
- Criterion 1 is a sample, not a full read: rr (1253 lines), si (1017 lines), optb, scope and tm were read
  only at the locations cited above; mech only §Identity lifecycle.
- The intermediate R1 blobs (`288cc59d…`, `3bf08176…`, `932eb481…`) were not reconstructed; only the
  current working-tree blobs and the cf28848 diff were checked.
- Whether the selectors' causal meanings match any implementation: the checker treats them as independent
  booleans, and no implementation exists to compare against.
- Model-family independence of the first R1 pass (executor and reviewer both on OpenAI models per the R1
  record) is outside these criteria and was not assessed.

## Targeted recheck (2026-10-13)

Cold-context recheck of the CR-A-01…CR-A-16 repairs (change-requests, section "adjudication of the
cross-family R1 addendum"), read against the version-3 / version-7 candidates and `git diff 6e56539` of the
spine folder. Read-only except for this section; sealed draft not read; no git state changed.

- Candidate blobs reviewed (`git hash-object`, first 16 hex digits): 02-conditions-and-decomposition.md
  (version 3 candidate) `d66561a2ec97a3b1`; 01-model-inventory.md (version 7 candidate) `7345e9c5d8face07`.
- Structural checker: exit code 0. Counts: 52 transitions; 38 ledger routes (G1 5, G2 13, G3 5, G4 1, G5 8,
  GX 6); 18 components; 33 declared selectors; 71 local split valuations; no missing / extra / duplicate
  transition owner, no transition without ledger trace, no matrix error, no unknown ledger transition, no
  split error (so no undeclared selector in the split table and ledger condition sets equal matrix incidence).
- Frozen-file blobs: all ten match the expected first-16 digits (conn, rr, si, sbx, iv, mech, optb, kub,
  scope, tm).

"02 Lnn" and "01 Lnn" refer to the candidate blobs above.

| finding | verdict | remark or residual defect (file and line) |
|---|---|---|
| F-01 | holds with remark | §3 (02 L147–154) uses C-07 only as p71 and D_71 (02 L271) is the only C-07 cell, assigned to R-GX-01 / R-GX-03; one stale use of the withdrawn p72 remains in the C-04 × G4 matrix reason (02 L498), recorded as N-01. |
| F-02 | holds with remark | u_r is single-valued (02 L111–113) and the field mismatch reaches D_33 → R-G1-02; 02 L113 calls the stored field's agreement with r(u_r) "p33", but p33 (02 L131) constrains the comparand e_r, which equals the field only when T-23 reads it from there (01 T-23). |
| F-03 | does not hold | X_r is now a named trace fact (02 L114–117) and the §3 chain stays non-circular, but p53 (02 L133) constrains only X_r's own T-07 uid and row r's T-09 engine end, so the cross-record case F-03 named — another record's clone given A_r.uid and the peer of row r's socketpair while X_r and row r's engine end are correct — still fails p62 first at the accepting row and routes D_62 → q26 → R-G5-07 or the R-G5-08 remainder (02 L239, L270), while R-G1-06's sentence (02 L413) and CR-A-03 describe exactly that history as a C-05 failure in G1; in addition 02 L133 and L150 attribute the last step of §3 to p53, whereas that step uses the definition of X_r and p62 only. One-sentence repair: add to p53 that no clone event other than X_r is launched with A_r.uid or inherits the peer end of row r's socketpair during J_r. |
| F-04 | holds with remark | 02 L203–206 makes selectors trace-only with the remainder owning histories where no named fact occurs, and the branch set is fixed; two selector texts keep knowledge wording that the new rule must override — "can be associated" in q02 (02 L215) and "demonstrably wrong" in q17 (02 L230). |
| F-05 | holds | Every one of the 38 live entries appears in at least one §5.1 input row (02 L353–359), including R-G1-06 and the seven remainder slots; R-G1-04 and R-G4-02 appear in none. |
| F-06 | holds with remark | 01 lands local_agent_id in the Execution row (01 L70), the label tuple (01 L45), T-01 (01 L112) and MM-16, and 02 carries it in I-05, p52, p81, q22, q30 and R-GX-05; 02 L111 still defines A_r as the four-tuple (X_r, u_r, lease_r, epoch_r), while I-05 (02 L102) and p52 (02 L133) use A_r.local_agent_id and A_r.execution. |
| F-07 | holds | MM-17 records the missing bootstrap-handoff → hello trigger beside MM-15, read as T-10 and not resolved. |
| F-08 | holds | 02 L303–311 states the four derived outcomes, which match 01 T-20 (b)–(e) and kub §5, and records the self-mapped sub-arm disagreement with the PLAN's Stream P row for reconcile. |
| F-09 | holds | 02 L313–317 names R-G5-04 plus the R-G2-05 remainder as the PLAN's foreign-uid route, records that the intact posture yields no accepted event, and states Stream P's trigger. |
| F-10 | holds with remark | B(R-G5-01/02) carry (Bad_acc OR NOT C-08) (02 L275–277); Bad_acc is introduced "for a normal history prefix h" (02 L176), so its use on H histories needs that qualifier dropped. |
| F-11 | holds with remark | q33 and the re-split of D_61 (02 L246, L269) send the concurrent-engine history to R-G5-06, whose sentence and U-05 cover it; q23 (02 L236) compares engine_epoch values without naming the cell (01 L82 makes engine_epoch a per-engine global), so concurrent engines whose epoch values coincide still reach R-G1-05 ("one engine epoch", 02 L412). |
| F-12 | holds | p81 (02 L136) quantifies over each D-ACC causal origin and gives the multi-origin event one label per origin. |
| F-13 | holds with remark | §4.3 (02 L330–345) is one labelled warrant written as a check with its non-warranties; it omits the H pre-partition (02 L170–174, L275–277) on which the "exactly one ledger entry" step depends, and its item (i) names only the originless C-08 case although F_8 also holds p81 failures. |
| F-14 | holds | Moot after the R-G4-02 withdrawal; the withdrawal note uses "session teardown" (02 L452). |
| F-15 | holds | U-05 (02 L389) and the closing paragraph (02 L509) no longer use the negated adjective. |
| F-16 | holds with remark | The two ids in VERSIONS L32–33 are now the correct 16-digit prefixes of the commit 907fd0b blobs; the change edits two existing rows of a file whose header (VERSIONS L3–7) says append-only, which change-requests records as a format correction. |

New defects:

- **N-01** — 02 L498, C-04 × G4 cell: the reason "phase failure is C-07" cites a component that version 3
  withdrew (02 L135), so the cell's "no route" reason now points at nothing; the C-07 × G4 reason (02 L501)
  already carries the right wording.
- **N-02** — 02 L505–510, closing paragraph: it states that version 3 "passes the Step 2 candidate gate",
  which is the decision of this recheck and is not yet true.

Vocabulary and defence checks on the changed text: none of the unqualified words of PLAN Context (2) is
used (CLOSED appears only as the design state; "exhaustiveness proof" at 02 L330 is the PLAN Step 2 row's
own negated phrase); no rate or proportion wording; the new "Step 3 guard for G4" sentences (02 L135, L242,
L298, L452, L501) assign a preservation question and state that no route exists, and do not say that
anything stops a route.

Gate: may not pass, because the F-03 repair does not route the cross-record launch history to R-G1-06 (p53
constrains only X_r and row r's engine end), and N-01 leaves a matrix reason citing the withdrawn p72.

## Targeted recheck 2 (2026-10-13)

Cold-context recheck of the second-round repairs CR-A-17…CR-A-26 (change-requests, subsection "Second
round"), read against the working-tree candidates. Read-only except for this section; sealed draft not read;
no experiment run; no git state changed.

- Blobs reviewed (`git hash-object`, first 16 hex digits): 02-conditions-and-decomposition.md (version 3
  candidate, second round) `80dbc7234c76ee65` — matches the expected id; 01-model-inventory.md (version 7
  candidate, unchanged) `7345e9c5d8face07` — matches.
- Structural checker: exit code 0. Counts: 52 transitions; 38 ledger routes (G1 5, G2 13, G3 5, G4 1, G5 8,
  GX 6); 18 components; 33 selectors; 71 local split valuations; no missing / extra / duplicate transition
  owner, no transition without ledger trace, no matrix error, no unknown ledger transition, no split error.

"02 Lnn" and "01 Lnn" refer to the blobs above.

| item | verdict | remark or residual defect (file and line) |
|---|---|---|
| CR-A-17 (F-03) | holds with remark | With C-01…C-04, p51 and p52 holding, the cross-record history fails p53's third clause (02 L137) and reaches D_53 → R-G1-06 (02 L272) before C-06; p53 reads the SpawnRecord, the T-04 socketpair, the T-07 uid and the T-09 install (01 L114–120); §3 (02 L155–157) and the C-05 purpose cell (02 L137) now give the last step to X_r's definition and p62; R-G1-06's sentence (02 L419) describes the cross-record and endpoint histories, but not those D_53 selects through p53's first or second clause alone (N-03). |
| CR-A-18 (N-01) | holds | The C-04 × G4 reason (02 L504) cites the former p72 only as a G4 preservation guard and gives the comparison to G2. |
| CR-A-19 (N-02) | holds | The closing paragraph (02 L510–517) leaves the gate decision to the recheck sections and does not assert it. |
| CR-A-20 (F-02 remark) | holds with remark | §1 (02 L115–117) and q21 (02 L238) carry the "whenever the field is the comparand's source" qualifier, but p52's parenthetical (02 L137) still calls the field's agreement with u_r "p33" without it. |
| CR-A-21 (F-04 remark) | holds | q02 (02 L219) and q17 (02 L234) now name trace facts only. |
| CR-A-22 (F-06 remark) | holds with remark | §1 (02 L111–114) defines A_r with named fields including the execution_id, but I-05 (02 L102) still restates A_r as a seven-field tuple without the execution_id that p52 uses. |
| CR-A-23 (F-10 remark) | holds | Bad_acc is defined for any history prefix (02 L180), so its use in the H cells (02 L279–281) is well-formed. |
| CR-A-24 (F-11 remark) | holds | q23 (02 L240) requires one engine process in one engine_epoch and excludes coinciding epoch values; R-G1-05 (02 L418) matches. |
| CR-A-25 (F-13 remark) | holds | §4.3 item (0) (02 L337–338) states the H pre-partition first, and item (i) (02 L338–340) names both the p81 and the p82 case. |
| CR-A-26 (F-16 remark) | holds | The format-correction note sits in VERSIONS (L38–39) above the fan-out-gate paragraph. |

New defects:

- **N-03** — 02 L137 (p53, first and second clauses) with 02 L272 (D_53) and L419 (R-G1-06 sentence): a
  history in which p53 fails only because X_r was launched with a uid other than A_r.uid, or only because row
  r's installed engine end is not from X_r's socketpair, while the accepted bytes come from a task that no
  launch during J_r produced (a prior survivor, a pre-existing holder or a lawful later holder) reaches
  D_53 → R-G1-06, whose sentence names a clone launched for another record; the first clause is never the
  necessary failure at row r, since a wrong uid on X_r gives no other task u_r, and without these clauses the
  same histories reach D_62 (q24 / q25 / q26). Either the R-G1-06 sentence states the own-record case or the
  two clauses are moved after C-06.
- **N-04** — 02 L137 (p53, third clause): the clause does not state whether clone events of another engine's
  spawner count as "clone event other than X_r". If they do, a concurrently running engine whose clone is
  launched with u_r during J_r fails C-05 before C-06 and reaches R-G1-06, contrary to the D_61 else-branch
  (02 L273), R-G5-06's sentence (02 L440) and U-05 (02 L395–397); in either reading, same-engine double
  allocations are now split between R-G1-05 (other clone launched before r's reservation) and R-G1-06
  (launched during J_r), which neither route sentence (02 L418, L419) records.

Vocabulary and defence checks on the changed text: none of the unqualified words of PLAN Context (2) is used
(CLOSED appears only as the design state; "exhaustiveness proof" at 02 L334 and "exhaustiveness test" at 02
L355 are negated headings already present); no rate or proportion wording; the "G4 preservation guard"
sentences (02 L139, L246, L301–302, L458, L504, L507) assign a Step 3 preservation question and do not say
that anything stops a route. The checker passes (above).

Gate: may not pass, because N-03 leaves D_53 selecting histories that R-G1-06's sentence does not describe,
and N-04 leaves the routing that U-05 and the D_61 else-branch state dependent on an unstated scope of p53's
third clause; each is a one-sentence repair.

## Targeted recheck 3 (2026-10-13)

Cold-context recheck of the third-round repairs CR-A-27…CR-A-30 (change-requests, subsection "Third
round"), read against the working-tree candidates. Read-only except for this section; sealed draft not read;
no experiment run; no git state changed.

- Blobs reviewed (`git hash-object`, first 16 hex digits): 02-conditions-and-decomposition.md (version 3
  candidate, third round) `d977e62d4e6980aa` — matches the expected id; 01-model-inventory.md (version 7
  candidate, unchanged) `7345e9c5d8face07` — matches.
- Structural checker: exit code 0. Counts: 52 transitions; 38 ledger routes (G1 5, G2 13, G3 5, G4 1, G5 8,
  GX 6); 18 components; 33 selectors; 71 local split valuations; no missing / extra / duplicate transition
  owner, no transition without ledger trace, no matrix error, no unknown ledger transition, no split error.

"02 Lnn" and "01 Lnn" refer to the blobs above.

| item | verdict | remark or residual defect (file and line) |
|---|---|---|
| CR-A-27 (N-03) | does not hold | With p53 reduced to one clause (02 L140), history (a) holds p53 (X_r is excluded) and reaches D_62 → q24 → R-G4-01, and history (c), launched during J_r, fails p53 and reaches D_53 → R-G1-06 (02 L275), whose uid alternative (02 L422) describes it; history (b) reaches D_62 → q25 → R-G5-06 only when no other clone of this spawner holds the peer of row r's installed end, while in its swapped-endpoint form the endpoint half of p53 fails first and sends it to D_53 → R-G1-06, whose sentence ("A's bytes ... accepted") describes a byte that cannot pass C-01…C-04 at row r (N-05). |
| CR-A-28 (N-04) | holds with remark | p53 now names "this engine's spawner" and its uid half excludes a clone whose own SpawnRecord (01 L76 carries the uid) assigns u_r; (d) holds p53, fails p61 and reaches q23 → R-G1-05 (02 L276, L421), and (e) holds p53, fails p61 and reaches NOT q23 AND NOT q33 → R-G5-06 (02 L443), in agreement with R-GX-04 (02 L448), the R-G1-06 transitions note (02 L422) and U-05 (02 L398–400); whether the proviso "a second allocation whose own record assigns u_r is p61's case" also covers the endpoint half is unstated, so a same-engine second allocation whose clone holds row r's peer end may reach R-G1-06 instead of R-G1-05 — removed with N-05's repair. |
| CR-A-29 (CR-A-20 remark) | holds with remark | p52's parenthetical (02 L140) carries "whenever the field is the comparand's source"; it speaks of the field's agreement "with u_r", where §1 (02 L117) and p33 (02 L138) compare with r(u_r). |
| CR-A-30 (CR-A-22 remark) | holds | I-05 (02 L102) restates A_r as (exec_r, X_r, u_r, lease_r, epoch_r, session_r, channel_r, name_r), the tuple and field order of §1 (02 L111–114), including the execution_id, with "as defined below" pointing to the dotted field names. |

New defects:

- **N-05** — 02 L140 (p53, endpoint half "no such clone is made to hold the peer end of row r's
  socketpair") with 02 L275 (D_53), L422 (R-G1-06 sentence) and L291–294 (§4.1 item 1): with C-01…C-04
  holding, every byte accepted at row r has a sender with real uid u_r; a clone of this spawner holding row
  r's peer end has u_r only if the uid half also fails or its own record assigns u_r (p61's case by the
  proviso), so the endpoint half alone is never the necessary failure at row r and selects only histories
  whose accepted bytes come from a prior survivor, a pre-existing holder, a lawful later holder or another
  engine's allocation — the N-03 pattern, and descriptor possession made a component against §4.1 item 1.
  "Row r's socketpair" is also not defined as X_r's T-04 pair or the pair of row r's installed Channel,
  which decides whether recheck 2's history (b) reaches D_53 or D_62. One-sentence repair: move "no other
  clone of this spawner holds the peer end of row r's channel" to the G1 preservation guards of §1 and drop
  the endpoint alternative from p53, the C-05 cell, §1 L119–120 and R-G1-06's sentence.

Remark, not a defect: a clone of this spawner launched with u_r against its own record before r's
reservation holds p53 (which reads "during J_r") and reaches D_62 → q25 → R-G5-06, whose sentence ("other-
compartment task already possesses an allocated uid") describes it; the R-G1-06 transitions note (02 L422)
does not mention this case. A p53 failure that co-occurs with an accepted byte from another u_r holder also
lands in D_53, the same first-failure property D_61 / R-G1-05 have and §4 (02 L195–196) states.

Vocabulary and defence checks on the changed text (02 L102, L111–124, L140, L422): none of the unqualified
words of PLAN Context (2) is used (CLOSED appears only as the design state); no rate or proportion wording;
no sentence says that anything stops a route — "G1 preservation guards" (02 L121–123, L140) assigns a Step 3
question. The checker passes (above).

Gate: may not pass, because N-05 leaves the endpoint half of p53 selecting, at D_53, histories whose accepted
bytes come from a C-06 holder that R-G1-06's sentence does not describe; the repair is one sentence.

## Targeted recheck 4 (2026-10-13)

Cold-context recheck of the fourth-round repairs CR-A-31 and CR-A-32 (change-requests, subsection "Fourth
round"), read against the working-tree candidates. Read-only except for this section; sealed draft not read;
no experiment run; no git state changed.

- Blobs reviewed (`git hash-object`, first 16 hex digits): 02-conditions-and-decomposition.md (version 3
  candidate, fourth round) `ef3691fe209425a8` — matches the expected id; 01-model-inventory.md (version 7
  candidate, unchanged) `7345e9c5d8face07` — matches.
- Structural checker: exit code 0. Counts: 52 transitions; 38 ledger routes (G1 5, G2 13, G3 5, G4 1, G5 8,
  GX 6); 18 components; 33 selectors; 71 local split valuations; no missing / extra / duplicate transition
  owner, no transition without ledger trace, no matrix error, no unknown ledger transition, no split error.

"02 Lnn" refers to the blob above.

| item | verdict | remark or residual defect (file and line) |
|---|---|---|
| CR-A-31 (N-05) | holds with remark | With p53 reduced to its single launch clause (02 L143): (b') holds C-01…C-05 (the holder was not launched during J_r) and fails p62, reaching D_62 → NOT q24 AND q25 → R-G5-06 (02 L280, L446), whose sentence describes it; (b'') gives the other record's clone a stamp u_Y that fails C-04 at row r, so no accepted byte, no Bad_acc event and no route; (c) fails p53 and reaches D_53 → R-G1-06 (02 L278) ahead of C-06; the phrase "row r's socketpair" no longer occurs and its replacement is defined as the socketpair created at T-04 for X_r's SpawnRecord (02 L122), which the C-05 cell abbreviates as "X_r's socketpair"; R-G1-06's sentence (02 L425) now names only the launch against A's own record and a data path to the row, no endpoint hand-over, and describes the D_53 histories up to the first-failure co-occurrence that recheck 3 recorded; the three launch facts are G1 preservation guards in §1 (02 L120–126) and in the C-05 purpose cell (02 L143) in the same order and sense, consistent with §4.1 item 1 (02 L294); recheck 3's remark on a same-spawner clone launched with u_r before r's reservation (D_62 → q25 → R-G5-06) is still absent from the R-G1-06 transitions note, which remains a remark. |
| CR-A-32 (CR-A-29 remark) | holds | p52's parenthetical (02 L143) states the stored field's agreement with r(u_r), as §1 (02 L117) and p33 do. |

The CR-A-28 remark is removed: a same-engine second allocation whose clone holds row r's peer end now holds
p53 (its own record assigns u_r), fails p61 and reaches q23 → R-G1-05 (02 L279, L424).

New defects: none.

Vocabulary and defence checks on the changed text (02 L102, L111–131, L143, L425): none of the unqualified
words of PLAN Context (2) is used ("fixed at reservation" is not the fixed-point wording); no rate or
proportion wording; no sentence says that anything stops a route — "G1 preservation guards" assigns a
Step 3 question. The checker passes (above).

Gate: may pass
