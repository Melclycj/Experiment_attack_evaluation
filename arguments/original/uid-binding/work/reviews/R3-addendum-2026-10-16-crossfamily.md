# R3 cross-family addendum — uid-binding security argument

## Review header

- **Reviewer:** Codex, independent cold-context cross-family reviewer; no executor conversation consulted.
- **Model:** Codex / OpenAI; the exact runtime model identifier is not exposed in this session.
- **Date:** 2026-10-16 (Australia/Sydney).
- **Reviewed revision:** `cedb69177066081aee7e0b31364fbdfb05996a95` (`cedb6917`), as requested, not the brief's `6ed23699`.
- **Checkout discrepancy:** the checkout was on `main` at `bec2d02657c4585d4ad931e56010343250c7eb63`, with pre-existing modifications. Reviewed contents and line numbers below are from `git show cedb6917:<path>`; no checkout, reset, stash, source edit, or repair was performed. This gate verdict is for `cedb6917`, not a verdict on the later checkout.
- **Order:** brief first, specified method rules second; eight independent findings were written into an in-memory draft before opening the first R3 record and its adjudication. Those two records were then used for overlap classification and to narrow F-08 to its inaccurate cross-reference, rather than claiming that no follow-up exists anywhere.
- **Writes:** this new addendum only. No sealed draft, other prewritten vector table, PDF, or earlier conversation was opened. The convergence table explicitly assigned for review was read.
- **Findings:** 8 — P1: 1; P2: 4; P3: 3. NEW: 3; OVERLAP: 5. Prior finding numbers below always refer to the Claude Opus R3 record.

## What was read and run

### Reading record

1. R3 brief; PLAN.md Context to resume cold (2), Frozen design revision, and Execution flow's Convergence, Review points and Reading format.
2. The five convergence deliverables: reconcile.md, change-requests.md (CR-F-01 through CR-F-09 first; R3 adjudication only after the independent draft), obligations-for-engine.md, coverage-uncertainties.md, and uid-binding-vector-table.md.
3. Required route sample, read whole:
   - R-G5-03, R-G5-04, R-G5-07.
   - R-GX-01, R-GX-02, R-GX-03, R-GX-04, R-GX-05, R-GX-06.
   - G1: R-G1-03; G2: R-G2-08; G3: R-G3-03; G4: R-G4-01.
   - Additionally, R-G3-05 §§2, 5–6 for the aggregation check; all 38 route headers and table-source fields were inspected mechanically.
4. All five preservation conclusion blocks, G5's preservation argument and G4 preservation §D4 in full. Relevant spine sentences and records in 01 v8, 02 v4, 03 v4, 04 v4, and VERSIONS.md: changed T/IG/q rows, branch assignments, partition/matrix, entailment and bounded-run record, cited EV rows, reclassifications and totals. These were used to test convergence claims, not to redo R1/R2.
5. All ten frozen design files, at the requested revision, with targeted reading of the sections named by the reviewed claims; all ten blob prefixes match PLAN's freeze, including the evidence-only kernel addition:
   - connections.md — objects, launch/SEALED, receive, close/reclaim and epoch restart.
   - resources-routing.md — dispatch/connector and workspace/uid selection.
   - supporting-interfaces.md — event context and launch-directory cross-check.
   - sandbox-design.md — construction/drop and policy split.
   - implementation-validation.md — dated acceptance rows and stated limits.
   - mechanism.md — identity lifecycle and obligation discharge status.
   - option-b-workload-per-engine.md — six obligations, target configuration, spawner and spawn sequence.
   - kernel-uid-binding.md — credential/map semantics, C1–C4, descriptor-acquisition footing and limits.
   - scope-and-boundary.md — adversary, exclusion width, five surfaces and substrate requirements.
   - threat-model-derivation-map.md — D4, D6 and D7.
6. 05-concurrency.md relevant configuration judgement, outcomes and unresolved relations; terminal/progress records in its 5a, 5a-t2, 5b, 5c and 5d logs. No TLC run was launched.
7. Report headers and relevant result/limit sections, not new experiments: arm3, dprime-build, capability-posture, rendezvous, and foreign-uid probe.
8. Only after the independent findings draft: first R3 record and its adjudication lines 274–304.

### Execution record and baseline isolation

The requested command was run without `-I`, with UTF-8 output and bytecode writes disabled:

```powershell
$env:PYTHONIOENCODING='utf-8'
$env:PYTHONDONTWRITEBYTECODE='1'
python Thesis/Work/Submission/prove/uid-binding/work/tooling/reconcile-checks.py
```

It exited 0 on the later checkout, reporting 30 current / 13 gate headers; that is **not** the requested revision's result. The checker source is unchanged between the target and checkout, so it was also executed without `-I` in memory with `__file__` pointing to its normal location and `Path.read_text` redirected to `git show cedb6917:<repository-relative-path>`; the target and working-tree route filename sets were checked equal. No `--table-out` write was requested.

The target-backed execution exited 0: 38 ledger routes / 38 route files; 48 matrix cells; 141 registry rows; **31 current / 12 gate** headers; dispositions **3 / 25 / 8 / 2**; preservation rows **14 / 10 / 10 / 14 / 4**, with only T-66 and T-67 marked does-not-preserve. It emitted three soft premise-departure notices for R-G5-03/04/07 and no hard findings.

Independent in-memory checks compared all 38 table rows with the route §1 and front matter, counted registry tags and aggregation bullets, and checked evidence-table tags as well as inline EV/tag pairs. The checker does not compare the saved table to its extraction; its clean exit therefore does not settle F-02.

## Findings

### F-01 — P1 — Recorded header-version counts do not reproduce at the requested commit

**Comparison:** OVERLAP — prior F-08 / CR-R3-08 (the all-gate wording was repaired; the retained split is now stale)  
**Location:** convergence/reconcile.md:32, 84–85  


**Defect:** At cedb6917, the unchanged checker run over that commit's inputs reports 31 front-matter files on the current IDs and 12 on the gate IDs, not the 29 / 14 recorded here. The total remains 43, but both recorded category counts are wrong for the revision under review.

**what would resolve it:** Recount the target revision's headers, reconcile any intentional header changes with the re-read record, and update both recorded totals.

### F-02 — P2 — The table was not re-extracted after the stops-field repairs

**Comparison:** OVERLAP — prior F-01 / CR-R3-01 (route-field repairs succeeded; their table projection was not refreshed)  
**Location:** convergence/uid-binding-vector-table.md:56–66, 73–74, 101  
Related: reconcile.md:32; the affected route fields are line 7.

**Defect:** Seven stops cells differ from the corresponding route front matter: R-G1-01/02/03/05/06 retain the earlier paraphrases and R-G2-07/08 retain different initial capitalization. Thus the table is not a mechanical projection of the repaired route files at cedb6917, contrary to its extraction statement and reconcile.md line 32.

**what would resolve it:** Re-extract all five columns from the target route files after the field repairs, and check row-for-row equality rather than only validating each route's stops field.

### F-03 — P2 — The supported route gives incompatible accounts of its S1 / production-policy dependence

**Comparison:** OVERLAP — prior F-11 / CR-R3-11 (the four previously cited locations were repaired; this additional S1-dependence statement remains)  
**Location:** groups/G5-boundary/R-G5-04.md:121–126  
Related: coverage-uncertainties.md:55–56; the same route §§3–5, especially 60–62, 87–100 and 111–115.

**Defect:** Section 6 says sub-branch B additionally relies on the production allow-set excluding what S1 denies, citing EV-129 [S], and coverage-uncertainties.md lines 55–56 repeat that dependence. Sections 3–5 instead say the map rule and initial-namespace capability posture stop the route even when namespace creation is allowed, classify the filter as surface-only, and explicitly exclude S1 from the premises, so the route does not give one consistent account of whether an unbuilt component is necessary.

**what would resolve it:** Make section 6 and its aggregate distinguish optional surface reduction from the required identity defence; if EV-129 is actually necessary, explain that dependence and revisit the supported disposition.

### F-04 — P2 — Additional superseded uncertainty claims survive the stated reconciliation

**Comparison:** OVERLAP — prior F-06 / CR-R3-06 (additional affected bullets, not the three already marked superseded)  
**Location:** convergence/coverage-uncertainties.md:4–6, 101–104, 127–131, 180–183  
Related: 03-invariant.md:100; 02-conditions-and-decomposition.md:255; R-G3-05.md:33–44, 100–108; CR-F-01/03/06.

**Defect:** The header says the three marked supersessions account for the spine changes, but the C-05 bullet still calls the IG-10 split proposed, C-06 still asks T-67 to name the pool premise, and C-08 still treats the local_agent_id-only case as an unresolved q32 selector gap. At cedb6917, 03 v4 IG-10, 01 v8 T-67, 02 v4 q32 and R-G3-05 sections 2 and 6 already contain those changes, although the implementation and remainder uncertainties remain.

**what would resolve it:** Reconcile every affected bullet with the applied versions, preserving the genuinely open parts and making any retained historical count explicit.

### F-05 — P2 — D4 assigns the alias half to the other GX-03 branch

**Comparison:** NEW  
**Location:** groups/G4-close-and-reclaim/preservation.md:91  
Related: R-GX-03.md:40–43; 02-conditions-and-decomposition.md:243, 250, 276, 281.

**Defect:** The numeric-fd / receiver-generation alias row is labelled D_71 ∧ ¬q27, even though R-GX-03 section 2 lines 40–43 and 02's branch table assign that half to D_51 ∧ ¬(q18 ∨ q19) ∧ q20. D_71 ∧ ¬q27 is the member-after-release half already listed at D4 line 82, so D4's claim to reproduce the existing branch conditions is inaccurate even though its 7 / 6 / 3 labels still count correctly.

**what would resolve it:** Correct the alias row's existing condition/selector reference and its reason for inclusion without introducing a route or re-deriving the decomposition.

### F-06 — P3 — SEALED is described as detecting a C1 departure it does not generally test

**Comparison:** NEW  
**Location:** convergence/obligations-for-engine.md:50–52  
Related: connections.md:289–293; R-G5-03.md:91–98; 03-invariant.md:100 (IG-10(b) concerns real uid).

**Defect:** The obligation says a step-11 departure is detected only by T-08's SEALED comparison, but conn lines 289–293 compare the stamped uid and child pid, not all three real/effective/saved uid values. A C1 inequality with the expected real-uid stamp can pass that comparison; R-G5-03 lines 91–98 correctly retains the unchecked-equality limitation.

**what would resolve it:** Say that SEALED detects a stamped-uid mismatch, not arbitrary C1 inequality, and retain equal-argument or post-drop three-value verification as an outstanding obligation.

### F-07 — P3 — No read after CLOSED is overstated as no acceptance

**Comparison:** NEW  
**Location:** groups/GX-cross-group/R-GX-03.md:58–60  
Related: 03-invariant.md:103–108 (IG-13).

**Defect:** The inference that a released CLOSED row cannot accept anything is stronger than the IG-13 rule it cites. In 03 v4 line 103, a D-ACC whose last read preceded the close may finish on a CLOSED row with its original label; that is not a false attribution and does not invalidate the route's stop.

**what would resolve it:** Limit the statement to new reads or sends after release, and preserve the allowed buffered parse/acceptance case with the original row's label.

### F-08 — P3 — The EV-04 follow-up points to the wrong record

**Comparison:** OVERLAP — prior F-04 / CR-R3-04 (the judgement was added; its new follow-up cross-reference is inaccurate)  
**Location:** convergence/reconcile.md:58, 99–111  
Related: change-requests.md:288, 299–301; 04-evidence-registry.md:94, 164, 242.

**Defect:** Judgement (h) says an EV-04 clarification is listed in reconcile section 6 for the next registry version, but that section contains only the eleven Stream Q relations and no EV-04 follow-up. The deferral is actually recorded at change-requests.md lines 299–301, which explicitly says reconcile section 6 does not change, so the two records disagree about the action's location.

**what would resolve it:** Point judgement (h) to the actual deferred-action record, retaining EV-04's [S] tag and the distinction between the unbuilt step-order specification and EV-74's measured P2a drop.

## Checks with no finding

These are bounded checks, not a second unconditional pass for the areas with findings above.

- **Ledger, matrix and partition:** 38 route IDs map one-to-one to files; 48 condition/group cells are populated or explained; all 52 owned transitions occur in the designated preservation partition and are touched by routes; the twelve exclusions remain listed. No new route is proposed.
- **Disposition syntax and route-field format:** one allowed disposition per route, repeated in §5; the repaired `stops:` fields match their §3 first sentence or opening phrase. The seven defects in the first R3's F-01 are repaired in the route files themselves; this addendum F-02 is the separate stale table projection.
- **Vocabulary and evidence tags:** no forbidden rate wording or coverage-word breach was found in the assigned route/preservation/convergence outputs; the qualified coverage phrase occurs once in the table and `CLOSED` is used as a state. Checked EV/tag pairs, including pipe-separated support-table cells, agree with registry v4; the former G2 T-20 EV-29 mismatch is repaired. Explicitly historical EV-29 [R] descriptions are not treated as live misclassifications.
- **Required numeric totals:** 3 supported / 25 conditional / 8 open / 2 declared out of scope; 52 preservation rows, 50 preserve; D4 sorts 7 / 6 / 3; 75 obligations, split 15 design-unstated / 50 stated-but-unbuilt / 10 deployment preconditions; registry 141, split 35 [M] / 48 [R] / 58 [S]. Coverage has 60 aggregation bullets plus eleven Q relations, but F-04 limits treating every retained statement as a current uncertainty. Header-version counts are the exception, F-01.
- **C1–C4 / obligation mentions:** the check's explicit-token convention reproduces C1 23, C2 7, C3 8, C4 28; #1 5, #2 25, #3 2, #4 12, #5 2, #6 29. The two `#1–#6` range citations are distinguished from individual mentions; these are coverage-of-citations counts, not evidence that obligations #5/#6 are discharged.
- **Table's other columns:** for every one of the 38 rows, the route ID, adversary-action sentence, violated-condition field and disposition agree with the route source. The mismatches are confined to the seven stops cells listed in F-02; no disposition-count change follows from that comparison.
- **Reconstructibility sample:** all thirteen required samples supply an action, condition/branch, stop or explicit unresolved slot, support/composition, premise and remaining limitation without requiring another route's prose as a substitute. F-03 is the inconsistent necessary-premise account inside R-G5-04; F-07 is the narrower overstatement in R-GX-03. GX's cited preservation rows are legitimate dependencies, not missing route content.
- **Supported-route evidence:** reading §§3–5 of R-G5-03/04/07, their local kernel-semantics arguments use the own-set/map rules and measured drop posture, not an assertion that the product engine or production policy has been built. EV-74 [M] supports the P2a post-drop equality/capability posture; EV-70 [M] is the earlier probe; EV-04/30/31 remain [S] requirement/specification rows, not silently retagged measurements. No disposition is shown false merely by the presence of those [S] citations, but F-03 must be resolved before making an unqualified necessary-component check-pass statement.
- **Premise departures:** T-66/T-67 are not admitted invariant-preserving normal-flow transitions. The supported routes name their C1 / initial-namespace C2 posture, and the extra no-privileged-helper premise is now expressly carried outside S1–S14 in reconcile §3(a), the table residual line and the obligation list; the first R3 F-03 record gap is repaired. Its absence from T-67's current precondition is acknowledged, not reported again as an unacknowledged defect.
- **Known source pitfalls and boundaries:** spawner privilege separation remains [S]; arm3's staged acquisition is distinguished from the d2 spawn leak; queued-sender evidence is kept to its datagram measurement and does not establish STREAM draining; forge-map / forge-setuid use 2026-09-01; [S] ≡ [U] is stated; #5 and the overall #6 claim remain residuals. The fourth pool exclusion is present in the repaired G1 record. The table quotes the adversary and distinguishes same-uid, live-at-send and outbound-confidentiality limits.
- **Reconcile judgements and fan-out changes:** CR-F-01…09 have their stated landings in 01 v8, 02 v4, 03 v4 and PLAN's C-LP configuration clause; the D7 abstraction remains conditional, not promoted to a measured deployment claim. The open refinement slots remain open. D4's numerical sort is right, with F-05 concerning its branch label rather than its totals.
- **Bounded-run and probe records:** Q logs support the stated outcomes: 5b/5c no violation within their bounds, 5d the expected gate-off counterexample, 5a/5a-t2 stopped with states still queued. The convergence record does not inherit a result over the unfinished bounds; EV-29's upgrade is limited to the WSL2 probe, with the native-Linux arm pending. Dates and substrates in the table preface match the cited report headers.
- **Other first-round repairs:** the GX support tables now use registered EV IDs, the table names its remainder slots and R-GX-04's mechanism-free conditional requirement, EV-32 is described as source-read, and the specific vocabulary/S1 locations cited by the first review are repaired. Those resolved findings are not reissued here.

## Gate line

**may not pass** — for user gate U on **cedb6917**. The review record has a wrong count (F-01), the saved table is not the required mechanical projection of the repaired companions (F-02), and a supported companion still gives contradictory answers to the necessary-[S]-component question (F-03); the remaining findings are bounded consistency/precision repairs, not new routes or a demonstrated deployed-system exploit. This verdict neither downgrades a route automatically nor judges repairs in later commits.

## out of scope for R3, recorded

- No new method objection is proposed, and no decomposition, kernel derivation, TLA+ encoding, or registry classification is re-derived here.
- A future 01 change for the privileged-helper premise and any EV-04 registry clarification remain their already-recorded R1/Stream E matters. F-08 concerns only the location claimed for that follow-up, not an instruction to change evidence tags in this review.
- Production S2/P2b realization, a native-Linux probe, broader runtime verification and the unbuilt engine remain stated evidence limits, not experiments undertaken by this reviewer.


## Targeted recheck (2026-10-16, Claude Opus, cold context)

Reviewer: Claude Opus 5.5, cold context. This round rechecks the five repairs CR-R3-19…23 at commit
`169116e5`; CR-R3-17, -18 and -24 were cleared by the Opus narrow recheck in R3-2026-10-16.md. I read the repair
diff `bec2d026..169116e5` and each named file at the cited places. This section is the only write. Paths are
relative to `work/`.

- **CR-R3-19 (F-03): holds.** `groups/G5-boundary/R-G5-04.md` L125–129 now classes EV-129 `[S]` as an optional
  surface reduction for sub-branch B: it only decides whether the agent can create the namespace. What stops
  the route is the map rule plus the initial-namespace posture. This agrees with §3 L60–62 (S1 does not stop
  the route), §4 L91–93 (EV-129 "bearing only on sub-branch B's surface") and §5 L114 ("S1 is not a premise").
  `convergence/coverage-uncertainties.md` L55–57 says the same. The registry tags EV-129 `[S]` (04 L219).
- **CR-R3-20 (F-04): holds.** `convergence/coverage-uncertainties.md` has three new in-place markers. The
  C-05 bullet (L104–105) cites CR-F-01 and 03 v4 IG-10 (a), and keeps open that the subset cannot express the
  case. The C-06 bullet (L131) cites CR-F-06 and 01 v8 T-67, and keeps open that the method is unstated. The
  C-08 bullet (L184) cites CR-F-03 and 02 v4 q32 (sub-case (i) moved to R-G3-03), and keeps sub-cases (ii) and
  (iii) open. The header (L4–6) says six bullets, and the file has six "[superseded" markers.
- **CR-R3-21 (F-05): holds.** `groups/G4-close-and-reclaim/preservation.md` L91 now reads D_51 ∧ ¬(q18 ∨ q19) ∧
  q20. This matches 02 v4's D_51 row (L276), q20 (L243), the D_71 / q27 assignment (L250, L281) and R-GX-03 §2
  (L41–43). The row names its D_71 ∧ ¬q27 half as the member-after-release line, which is L82. The sort counts
  7 / 6 / 3 are unchanged (L93).
- **CR-R3-22 (F-06): holds.** `convergence/obligations-for-engine.md` L50–53 now says SEALED checks the stamped
  uid and the child pid. That matches conn L292 ("uid 等于分配值、pid 等于直接 child_pid", i.e. uid equal to the
  allocated value, pid equal to the direct child_pid) and 03 v4 IG-10 (b), which concerns the real uid. So
  SEALED detects a wrong real uid but not an unequal effective or saved uid, and the three-value verification
  stays an obligation.
- **CR-R3-23 (F-07): holds.** `groups/GX-cross-group/R-GX-03.md` L58–63 now limits the claim to new reads, and
  so to bytes sent at or after release. It keeps the IG-13 allowance in 03 v4 §2's terms (03 L103): a D-ACC
  whose last read preceded the close may finish on the CLOSED row with that row's own label, which is not
  false attribution.

**Checker and table.** `PYTHONIOENCODING=utf-8 python tooling/reconcile-checks.py`: exit 0, no hard findings.
It reports the three expected T-67 soft findings, headers 30 current / 13 gate, and dispositions
3 · 25 · 8 · 2. A fresh `--table-out` to scratch, diffed against `convergence/uid-binding-vector-table.md`,
gives all 38 rows byte-identical; none of the five repairs touches a front-matter field or §1. My wider
EV-tag scan (list and backtick forms) finds only coverage-uncertainties L49 "EV-29 `[R]`", which is the
historical sentence already noted in the R3 recheck.

**New findings introduced by these repairs:** none.

**Gate line: may pass.** All five repairs hold, no new finding has been introduced, and the checker and the
table extraction are clean.
