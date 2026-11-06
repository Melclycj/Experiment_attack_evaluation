---
role: reconcile
status: ready-for-R3          # owners' re-reads committed and registry version 4 registered, 2026-10-16
date: 2026-10-16
based_on:
  model_blob: "9efb243354a4e9d6"          # 01 v8
  decomposition_blob: "31ddfc5daba58f13"  # 02 v4
  invariant_blob: "6868389a2182c161"      # 03 v4
  registry_blob: "f36170e09dd4c2a9"       # 04 v4
---

# reconcile — checks performed, findings, counts

The reconcile role (PLAN §Convergence) read the designated sections of every fan-out file, wrote only in
this folder, edited no route file, and returned every needed change to a shared file through
[change-requests](change-requests.md). Mechanical checks are `reconcile-checks.py` in the tooling folder
(run from any directory with `PYTHONIOENCODING=utf-8`, without `-I`); the judgement checks are recorded
here with their reasons. The fan-out ran 2026-10-14/15 (wave 1: G1–G5, Q, P; wave 2: GX), one agent per
folder under the fixed [brief](../_templates/fanout-brief.md); every folder was committed by its own
commit after the candidate path check. The user stopped the session at the token budget on 2026-10-15
between the spine versions and the owners' re-reads; this file records the state as resumed on
2026-10-16.

## 1 Checks of the PLAN §Convergence table

| reconcile reads | check | method | finding |
|---|---|---|---|
| the route ledger (02 §6, version 4) | one route file per ledger route and one ledger route per file; a route discovered during fan-out entered the ledger as an appended version first | script, check 1 | 38 ledger routes ↔ 38 route files; no route was discovered during fan-out (the seven unresolved refinement slots stayed slots); R-G1-04 and R-G4-02 remain withdrawn with no file; every file's group and violated-condition IDs agree with its ledger row |
| the condition × group matrix (02 §8) | every cell lists routes or states "no route, because …"; listed routes exist | script, check 2 | 48 cells, all well-formed; every listed route is in the ledger and carries the cell's condition; every condition has at least one route in some group (C-07 only in G5 and GX, as the matrix explains) |
| transition IDs (01, 02 §7, every preservation.md) | partition: each T-ID in exactly one group's preservation file; X-01…X-12 listed; every remaining transition touched by ≥ 1 route | script, check 3 | 52 owned transitions, each in exactly one file (G1 14 · G2 10 · G3 10 · G4 14 · G5 4); the twelve exclusions listed in 02 §7; no owned transition uncited by a route (section 2 or ledger column) |
| the goal-entailment argument and the TLC run record (03) | I entails the accepted-attribution goal; bounds and outcome stated; a counterexample after fan-out would be a Step 3 version, not an edit | read (03 §4, §5.4; R2 record); Stream Q §5 | the argument and the record stand as R2 left them; Stream Q's five bounded runs produced no counterexample (its 5d counterexample is the expected gate-off case); its runs 5b and 5c are recorded in 03 version 4 as within-bounds checks of two collapses, 5a / 5a-t2 as partial under the time bound (CR-F-09) |
| header, sections 1, 5, 6 of every route file; whole file on sample | vocabulary and disposition format; aggregate counts; assemble the five table columns from the front-matter fields and section 1 | script, checks 4–5 and 8; the executor's per-folder checks at each commit (`check_group.py`, session scratch) | every header carries one of the two id sets in full (30 files on the current ids, 13 on the gate ids; section 5) and `ready-for-reconcile`; the `stops:` field is section 3's first sentence or its opening phrase (script check 9, added after R3 F-01; seven fields were paraphrases and were made identical by their owners, CR-R3-01); no forbidden word, no rate wording; dispositions a 3 · b 25 · c 8 · d 2 (section 4); the table is extracted by `reconcile-checks.py --table-out` into [uid-binding-vector-table](uid-binding-vector-table.md) after the owners' re-reads (R-G3-03 §1 copies the widened ledger sentence first) |
| conclusion lines of each preservation.md | no route whose transitions "do not preserve" I is marked supported under stated premises; aggregate the engine obligations | script, check 7; judgement in section 3 (a) | G1–G4: every transition preserves; G5: T-61, T-62 preserve, T-66 and T-67 do not — by construction, as 02 §7 defines them (boundary disturbance; premise departure); the three a-routes R-G5-03/04/07 traverse T-67 and are judged in section 3 (a); obligations aggregated in [obligations-for-engine](obligations-for-engine.md) (75: 15 design unstated · 50 stated but unbuilt · 10 deployment precondition) |
| section 6 of every route file | aggregate the obligation list and the coverage-uncertainty list | the aggregation draft of 2026-10-15 (one cold-context agent reading all 38 §6 and the five preservation files) | obligations as above; uncertainties in [coverage-uncertainties](coverage-uncertainties.md) (60 from the route and preservation files, grouped by condition; plus Stream Q's eleven unresolved relations, section 6 here) |
| "proposed evidence" rows | append to the registry, deduplicated; appends add IDs only and invalidate no header | [registry-appends](registry-appends.md) → 04 version 4 | 86 proposed entries → 46 merged candidates (45 `[S]`, 1 `[R]`); P-04 and P-31 restate registered facts and become notes on existing rows; P-32 (SOCK_STREAM skb survival) has no pinned-tree file:line and is not appended; 28 proposals are runs, readings or checks, listed in 04 §5 as not evidence. Version 4 applied and registered 2026-10-16 (`f36170e09dd4c2a9`; 141 rows: 35 `[M]`, 48 `[R]`, 58 `[S]`) |
| unresolved relations (Q) | aggregate into the uncertainty list; a change to I would be a change request | read (05-concurrency.md §6, §7) | eleven relations, none a route, none changing I; the two Q requests concern plan text and 03 wording (CR-F-08, CR-F-09, accepted); folded into section 6 |
| the three observations (P) | upgrade that one evidence item from `[R]` to `[M]`; nothing else | read (REPORT-scm-creds-foreign-uid-probe.md) → 04 version 4 | EV-29 replaced by the measured row for the WSL2 substrate (arms 0–3 of 2026-10-14: own uid accepted; foreign uid `EPERM` at `sendmsg`, nothing delivered; user-namespace route accepted with the receiver reading the sender's own uid); the native-Linux VM arm is pending; no other row changed |
| C1–C4 and obligations #1–#6 (kub §6, mechanism.md) | each maps to ≥ 1 route or the residual line; no route's sections 3–5 contradict them; write the residual line for #5 / #6 | script check 12 (added after R3 F-02): explicit mentions of the token in section 6, a range such as C1–C4 or #1–#6 counted for its endpoints (R-G5-01 and R-G5-02 cite #1–#6 as affected); `--mapping` lists the routes | C1 cited by 23 routes, C2 by 7, C3 by 8, C4 by 28; #1 by 5 (R-G1-03, R-G2-09, R-GX-03, and the two range citations), #2 by 25, #3 by 2 (R-G2-07, R-G2-09), #4 by 12, #5 by 2 (R-G3-02; R-GX-05 as adjacent), #6 by 29; no contradiction found in the sampled sections 3–5 (one file per group plus all GX); the residual line is in the table file's preface (section 3 (e) here) |
| substrate and run dates | write the preface | frozen revision; the lab reports; the probe report | written in [uid-binding-vector-table](uid-binding-vector-table.md) §Preface |

## 2 Known source pitfalls (PLAN §Convergence, items (i)–(vi))

- (i) The pre-forked spawner "holds nothing" is a design property (`REPORT-capability-posture.md` L131–133): no route file tags it `[M]`; the phrase does not occur in any route or preservation file; the registry keeps it `[S]`. Passes.
- (ii) arm3 m1 was staged with A able to reach B; under the adopted configuration the acquisition footing is the d2 spawn leak (kub §7.2): R-G2-09's evidence limit states exactly this ("EV-48 … where A could reach B by construction"), and 02 §4.1 item 1 re-derived descriptor possession as not a failure predicate; the route is conditional, not supported. Agrees.
- (iii) The rendezvous qmsg arm shows a queued message carries the dead sender's uid; whether the reclamation gate implies channel-shut-and-drained is unstated: G4 §D4 sorts it **design unstated** (R-GX-01's condition; obligation at T-40 / T-45, MM-09 / MM-11), and R-GX-01 is conditional on the fresh-socketpair-per-execution statements. The result is the G4 result the pitfall anticipated, not "open".
- (iv) forge-map / forge-setuid cite the report's run date 2026-09-01: R-G5-04 and R-G5-07 cite EV-59 / EV-60 with that date. Passes.
- (v) `[S]` here ≡ `[U]` in option-b / scope-and-boundary: stated in the preface in one clause.
- (vi) Obligations #5 and #6 are claims, not routes: kept as the residual line; #6's local-binding requirements are mapped by the 29 routes citing #6 in section 6, #5 by R-G3-02 and, as adjacent, R-GX-05 (the grant model is a consumer of attribution, outside this table's property).

## 3 Judgements

- **(a) The three routes supported under stated premises traverse T-67.** 02 §7 defines T-67 as the transition that "tests configured premise departures" and T-66 as "a boundary disturbance row, not a transition assumed admitted by the normal invariant"; G5's preservation row for T-67 says which branches do not preserve (a: C1 absent; b: `CAP_SETUID` held in the initial user namespace; f: exclusive pool absent) and that the other branches preserve. R-G5-03, R-G5-04 and R-G5-07 are stopped by C1 and the first half of C2 at T-07 / T-20 / T-61 / T-62 (transitions that preserve), and traverse T-67 only as the departure the adversary would need; each names C1, C2 or the pool premise under "Premises that must hold" in section 5 (script check 7, premise-row rule). R-G5-04 and R-G5-07 name one further premise — no privileged map writer, and no privileged actor, acting for the agent's namespace — which is outside S1–S14 and C1–C4 and which no T-67 branch models (01 T-62 refers the writer to T-67, whose precondition does not list it; R3 F-03). The disposition form stays valid because the premise is named; this record and the table's residual line name it as a deployment premise outside S1–S14, and obligations-for-engine.md carries it as "a condition not named in S1–S14". Adding it to T-67's precondition is a 01 change deferred to the next freeze (it would re-open the fourteen files citing T-67 for a wording that changes no disposition). The check's literal form therefore fires on a modelling artefact; the disposition "supported under stated premises" is exactly the form the vocabulary reserves for a kernel-semantics conclusion whose premise is named. Accepted as supported; R3 is asked to read all three.
- **(b) Wording of the pool exclusion (conn L78).** R-G1-02 §5 says the pool "excludes 0, the overflow uid and invalid values"; R-G5-05 §3 and candidate P-35 say "… and host identities". The frozen text (conn L78: 排除 0、当前 overflowuid、无效 uid 值及宿主使用中的身份) lists identities in use on the host as a fourth exclusion. R-G5-05 is the faithful reading; R-G1-02's list is a subset and not wrong. The G1 owner adds the fourth item during the re-read (no change request: no ID is touched).
- **(c) The four G2 refinement slots, R-G3-05, R-G5-08 and R-GX-06** stay open: each file states the slot's nature and what the frozen text excludes without inventing a mechanism, as the brief required; the 28 proposed runs in 04 §5 are where several of them would be narrowed. No judgement overrides a slot.
- **(d) D4 (threat-model-derivation-map.md).** Answered in G4 §D4 with the E-04 design as the candidate under test: of the sixteen conditions that break uid ↔ execution 1:1, seven are stopped by E-04, six are not stopped by E-04 (they are deployment premises or G1 / G5 routes — the exclusive pool, a concurrent engine, lawful later acquisition, the unclassified holder slot, a T-03 miscopy, kernel or hardware alteration), three are design unstated (the fd-shut / release ordering at T-40 / T-45, the supervisor's domain-empty method at T-49, the `receiver_generation` increment at T-40 / T-09). The not-stopped and unstated lines are the obligation list's first entries.
- **(e) D7 (the common abstraction).** Stream Q re-examined the three configurations under interleaving: the agent ↔ engine leg is identical for the accepted-attribution property in C-LS, C-LP and C-R; two `[S]` items were added for C-LP (CR-F-08, now in PLAN §Frozen design revision). The disposition stays conditional on unbuilt requirements.
- **(f) The Stream P upgrade is one row.** EV-29 becomes `[M]` for the WSL2 substrate only; R-G5-04's section 4 had anticipated the measurement as a proposed row and its disposition does not change (its support already rested on the kernel map rule and the posture measurements). The native-Linux arm, when run, is appended to the same report and the EV-29 note is widened; nothing else moves.
- **(h) The `[S]` dependence of the three supported routes (R3 F-04).** R-G5-03 §3 and R-G5-07 §4 cite EV-04 — spawn step 11's `setresuid` of three equal values — which the registry tags `[S]` ("design text; not built or exercised", §2: the step order is a specification of the unbuilt spawner). The reconcile judgement, on the files: no *necessary* component of the three defences is `[S]`. C1's equality and the first half of C2 are measured on the as-built P2a drop (EV-74 `[M]`, iv SC-drop, `w2_drop` under the diagnostic policy) and on EV-70 `[M]`; the kernel rules are `[R]` / `[M]` (EV-08, EV-21, EV-59, EV-60); EV-30 and EV-31 are requirement statements whose measured counterparts are cited. EV-04's `[S]` is a classification of the kub paragraph's status, not a statement that the drop is unexercised; a registry note to that effect is a Stream E matter (R2's scope), noted here for the next registry version and not applied.
- **(g) Residual line (#5 / #6).** Obligation #5 (delegation leakage — grant model, WPE-F08) and #6 (full reference-monitor correctness) remain overall residual status lines: this table establishes neither; what it establishes for #6 is the local-binding part — the 38 routes and their dispositions — under the stated premises and the evidence limits per row.

## 4 Counts

| measure | value |
|---|---|
| ledger routes / route files | 38 / 38 (G1 5 · G2 13 · G3 5 · G4 1 · G5 8 · GX 6) |
| supported under stated premises (a) | 4 — R-G2-05, R-G5-03, R-G5-04, R-G5-07 |
| conditional on unbuilt requirements (b) | 25 |
| open (c) | 7 — R-G2-11, R-G2-12, R-G2-13, R-G3-05, R-G5-06, R-G5-08, R-GX-06 |
| declared out of scope (d) | 2 — R-G5-01 (N1), R-G5-02 (N9) |
| preservation rows | 52; preserves 50; does not preserve 2 (T-66, T-67, by construction); design unstated 0 as row results |
| G4 §D4 sort | stopped by E-04 7 · not stopped by E-04 6 · design unstated 3 |
| obligations for the engine | 75 (15 design unstated · 50 stated but unbuilt · 10 deployment precondition) |
| registry version 4 appends | see VERSIONS (EV-99 onward; EV-29 upgraded; 28 proposed runs listed as not evidence) |
| coverage uncertainties | 60 from the route and preservation files + 11 from Stream Q |
| change requests from the fan-out | 9, all accepted (CR-F-01 … CR-F-09); applied as 01 v8, 02 v4, 03 v4 on 2026-10-15 |
| Stream Q TLC runs | 5 (5b, 5c decided within bounds; 5d the expected gate-off counterexample; 5a, 5a-t2 partial under the time bound, no violation) |

## 5 Versions and re-reads after the spine changes

The nine accepted requests changed 01 (T-14, T-41, T-44, T-67 text), 02 (q32; the R-G3-03 ledger sentence)
and 03 (IG-10 split into record = lease uid and member = record uid; IG-13 note; §1.1 (iii) epoch-end
clause; §5.2 / §5.4 / §6 wording); 04 version 4 appended the fan-out evidence. Per the versioning rule only
files citing a changed ID were re-read, each by the owner agent that wrote it (resumed with its own context
on 2026-10-16), and those files copy the four current ids; files citing none keep the gate ids. Result: 30 of
the 43 front-matter files are on the current ids and 13 on the gate ids (`reconcile-checks.py` counts them;
R-G2-07 joined the current set during the R3 F-01 repair because it cites T-67, and R-G2-08, which cites no
changed ID, was returned to the gate ids after the recheck);
no disposition, `stops:` phrase or section-1 sentence changed except R-G3-03's section 1, which copies the
widened ledger sentence. Edits made during the re-reads, by group: G1 — IG-10 citations name the half per
row, the T-14 precondition text, the T-02 control-fault clause, the fourth conn L78 exclusion in R-G1-02 §5,
registered EV rows cited; G2 — IG-10 halves in the T-24 / T-60 rows, the IG-13 note cited, EV-29 retagged
`[M]` in R-G2-05 / 09 / 13 (dispositions unchanged); G3 — R-G3-03 title and §1 on the widened sentence, its
§2 / §3 / §6 carry the `local_agent_id` emission, R-G3-05's sub-case (i) moved; G4 — the control-fault
quarantine path and the IG-13 note cited, T-49 / D4 lines cite EV-139 / EV-140, three "no row exists"
statements replaced by the registered rows; G5 — T-67's premise text quoted, IG-10 half (b) named, EV-29
`[M]` in R-G5-03 / 04 (dispositions unchanged), proposed rows replaced by EV-128 / 129 / 130; GX — R-GX-04's
tension paragraph replaced by the settled 03 §1.1 (iii) clause, IG-10 and q32 sentences updated, registered
rows cited. Commits: ef604918 (G1), 768fc5dc (G2), f88f79a9 (G3), 607ebe49 (G4), 53523bda (G5), df996b9b
(GX); the registry 9504dd98; the spine versions 3abf4c2.

**Follow-up step 1 (a), 2026-10-16.** The R-G2-05 kernel reading entered kub §2.4 as evidence-only (blob
`c9c1c75f158eb600`) and the registry as version 5 (EV-142–EV-146); a fresh owner re-ran R-G2-05 on 01 v8 /
02 v4 / 03 v4 / 04 v5 (disposition open → supported under stated premises); its two change requests became
02 v5 (CR-G2-01 / 02, text only). The executor aligned the file's `stops` field with its §3 opening phrase
(check 9). No other file cites a changed ID; checker exit 0; the re-extracted table differs from the
previous one in the R-G2-05 row only.

**Follow-up step 3, 2026-10-18 (second design freeze).** The three design revisions of 2026-10-18 were
frozen anew and 01 re-run as version 9 by a fresh owner (34 IDs changed in content; AA-13, MM-18, X-13 added).
Every route and preservation file cites at least one changed ID, so the re-run set was chosen by what the
change does to the reasoning, not by citation: most changes write into the design a reading the model
already used or add a stricter check, and the looser spawner-admission reading of the third revision is the
process reading G1's T-03 row had argued; MM-18's two outcomes are that reading or a refusal. Re-run by
fresh owners: 02 (v7, the four pre-announced slot entries re-marked; v8 aligned with the user's ruling that
deployment preconditions are stated premises, no separate disposition value, CR-G5-05), R-G5-06, R-G5-08
(open → supported under stated premises, on the exclusive-pool deployment preconditions), R-G3-05 and R-GX-06
(open → conditional on unbuilt requirements), R-G5-03 and R-G5-07 (dispositions unchanged; the `getresuid`
re-read and its measured failure exit enter their stops). A wording-only pass corrected stale "design unstated"
sentences in 17 group files, Stream Q and 03 (v5, no guard changed; TLC not re-run, the subset's release being
more permissive than the design's); the result cells it left alone were re-judged by a further owner — G4's
D4 sort 7 / 6 / 3 → 9 / 6 / 1 (only MM-10 stays design unstated), G5's T-67 branch (a) split by sub-case (the
re-read preserves I for unequal effective or saved values; a window with the trusted bootstrap at another
execution's real uid remains when C1 fails, with no agent code and no acceptance), Stream Q 34 decided and 2
undecided under 01 v9 — with no route disposition affected. CR-G5-04 was answered by a kernel reading of every
writer of a task's uid at the pinned tag (kub §6, evidence-only, blob `4a7384b7727abe37`; two added
conditions, carried by R-G5-04 / R-G5-07 and by S2). 04 version 6 appended EV-147–EV-162. Checker exit 0; the
re-extracted table differs from the previous one in six rows (R-G3-05, R-G5-03, R-G5-06, R-G5-07, R-G5-08,
R-GX-06); counts 6 · 27 · 3 · 2. Outside the line: the C1 entry of engine-requirements §8 still calls the
post-drop check unstated (reported to the user before any write).

**Third freeze, 2026-10-18 (agent-facing grant_ref removed, fff5b409).** 01 v10 by a fresh owner (MM-06
resolved by design text; T-24, T-30, T-33, A-02 updated; nothing weakened); the G3 owner re-ran R-G3-02
(disposition unchanged, conditional on unbuilt requirements; its grant sub-case keeps no agent-chosen input) and
the G3 preservation rows T-30 / T-31 / T-33 (all preserve, as before), and reworded R-G3-01, R-G3-05 and R-GX-05;
02 v9 rewords U-06. Checker exit 0; the re-extracted table differs in the R-G3-02 stops field only. The two G3
change requests (EV-116 / EV-121 supersession notes; the MM-06 entry of coverage-uncertainties.md and stale
R-G3-02 line cites in obligations-for-engine.md) are left for the step-4 pass with the other two convergence files.

**Follow-up step 4, 2026-10-19 (engine build's checks).** No design file and no model file changed. The
engine prototype (ExperimentLab/engine, commit 3ec67985; validation record at blobs 3d35d8704cd79b5e and, after
c834ebbd, 0ec579941699c576) realizes the engine-side requirements and records a check for each must. A registry
agent appended its evidence as 04 v7 (EV-163–EV-244, with a map of every cited `[S]` row to its realization) and,
after the re-runs, v8 (EV-245–EV-264). The user ruled the disposition rule (step4-brief §1): a route is supported
when every necessary item is backed by `[M]` or `[R]`, deployment preconditions are premises, the realization's
limits go in section 5. Six fresh owners re-ran the 30 conditional or open routes; 29 moved to supported under
stated premises, R-GX-04 stays conditional (the trusted supervisor is outside the build). 02 v10 rewords U-02 and
the three slots' ledger cells. Checker exit 0 (check 7 now admits C3, CR-S4-11); the re-extracted table differs in
29 rows (dispositions, and eleven stops fields); counts 35 · 1 · 0 · 2. Change requests CR-S4-01…11; one referred
to the user (CR-S4-07, third-party parsers in R-G2-11), one design question forwarded (CR-S4-10), five findings on
the engine's validation record forwarded. Review: one cold Opus record and one Codex addendum (user-dispatched)
on the changed rows, records under work/reviews (S4-*).

**S4 review repair, 2026-10-19.** The Opus record (gate "may not pass") found R-G2-11 counted supported while a
third-party parser inside the C reader was carried as a premise (CR-S4-12). The user ruled the C-side parse removed;
engine commit 7b4ab727 did so and reran the regression, integration and fuzz; 04 v9 registers it. R-G2-11 was re-judged
(still supported, on the project's C code and the post-change fuzz, with the CPython runtime as platform premise) and
the other seven findings repaired (CR-S4-13…19). Checker exit 0; the re-extracted table differs in the R-G2-11 stops
field only; counts unchanged at 35 · 1 · 0 · 2. Recheck "may pass" (F-01 remark recorded as CR-S4-20; two P3
repaired, CR-S4-21/22). The Codex cross-family addendum (user-dispatched at 562d6ed2): P3 3, "may pass", repaired as
CR-S4-23…25. S4 adjudicated for both families; next is the user's read of the 29 changed rows.

**Fifth design revision, 2026-10-19 (the supervisor's domain-empty method).** Asked what the trusted supervisor is,
the user observed that a supervisor holding state only moves the regress up a layer; ruled that the fact must be
kernel-held. A dev-host probe (ExperimentLab/engine/runs/20261019T142200Z-cgroup-domain-empty-rerun) showed the
kernel behaviour; the design was revised (59ba7e4a), then amended to the cgroup form only after the 01 owner found
that a restarted releaser cannot re-read a pid-namespace reap (user ruling). 01 v11, 04 v10; R-GX-04 re-run by its
owner: conditional → supported under stated premises (the cell's cgroup and the gate are deployment preconditions).
Checker exit 0; the table differs in the R-GX-04 row only; counts 36 · 0 · 0 · 2. No review round was set for this
revision (as for the third and fourth); the changed row goes to the user's read.

**Forwarded engine findings, 2026-10-20.** Engine commit 9981dd7b (S14 FORCE_DISABLE; no execution_id on a rejection;
three validation rows reworded); 04 v11; owners updated R-G3-04, R-G5-02, the G4 preservation T-49 row and §D4 (sort
9 · 7 · 0) and coverage-uncertainties. Checker exit 0; table rows unchanged; counts 36 · 0 · 0 · 2.

**Extra evidence, 2026-10-21 (user-approved 2026-10-20).** Engine commit b262e80e (tests and the integration runner
only): four root receive cases for R-G2-06 to R-G2-09, each with a control and a negative control, and the two-epoch
run of 04 §5 item 27 under a test stand-in cgroup release gate (run 20261020T154357Z-engine-extra-evidence-rerun; the
first attempt failed on the runner's own reap assertion and is kept, not cited). 04 v12 (EV-289–EV-299); R-G2-06,
R-G2-07, R-G2-08 and R-G2-09 re-run by one cold agent, R-GX-04 by another; coverage-uncertainties and the step 4
evidence map marked in place. Dispositions unchanged; R-GX-04 does not claim end-to-end measurement (stand-in gate, A
silent after its hello, one run). Checker exit 0; the re-extracted table equals the one before; counts 36 · 0 · 0 · 2.

**M1 repair, 2026-10-23 (user-approved plan M1-repair-plan.md; Codex method review M1, work/reviews).** No design
change and no re-run of the model, decomposition or invariant. R-G2-11 was re-judged by the repair executor
(M1 item 1): its closing property has a path half, established by code reading and static tests, and a memory half —
the memory safety of the project's C code on the receive path — which is a stated requirement not established
(engine-requirements row 175); a one-hour ASan/UBSan fuzz run on which no error appeared bounds what was tried, not
what exists, so it is supplementary evidence and not the requirement's discharge. Disposition supported → conditional
on unbuilt requirements; the requirement's proof is assigned to prove 2.2, after which the route is re-run. Header ids
unchanged (no spine content the file cites changed). 02 v12 records the same in U-02 and the ledger row's sixth
column (wording only). Semantic check of the files that cite R-G2-11 (the rule-4 check the plan adds): R-G2-01, R-G2-04,
R-G2-05 and R-GX-06 name it only as the cell that owns memory-error histories or as a cross-reference — their stops
and premises are untouched, no re-run; R-G2-13 names the memory safety of the C code as a premise owned by R-G2-11 —
the premise stands as a premise, the owning route now carries the condition, R-G2-13's own composition items are
unchanged, so its disposition stands and the Counts classification in security-argument.md records the dependence;
the preservation files cite no R-G2-11 property; engine-requirements row 175 already says "unstated"; the engine's
validation record keeps its fuzz entry as the engine's check, the judgement of what it establishes being this line's.
coverage-uncertainties U-02 gains one clause. Checker exit 0; the re-extracted table differs from the 2026-10-21 one
in the R-G2-11 row only; counts 35 · 1 · 0 · 2. security-argument.md additionally classes the 35 supported rows by
premise (M1 item 3) and marks the five consumer-side rows (M1 item 5); PLAN rule 4 carries the semantic check (M1
item 4). M1 item 2 (an impact summary at each reading cut-off, R-G2-05 and 01 §8) is deferred until prove 1.1 fixes its
conservative-summary stopping rule. Review: the Codex recheck could not run — the service refused the request twice
on 2026-10-23 (content filter), once as written and once rephrased; a cold Claude Opus recheck returned may pass with
nine remarks, adjudicated in work/reviews/M1-recheck-2026-10-23.md (ten changes applied the same day, one deferred
with M1 item 2); the user then dispatched Codex directly the same day: may pass, four non-blocking remarks (two
wording changes in the Counts section, one correction of the review record, one recorded — the pre-existing X-13 soft
finding), so both families of rule 6 have passed the repair. Deviation recorded: R-G2-11
was re-judged by the repair executor, not by a fresh or owning agent (the plan assigned it so); the cold recheck read
the file in full.

## 6 Stream Q's unresolved relations (folded here; the per-condition list is in coverage-uncertainties.md)

- MM-09: the text orders T-40 steps 1 → 6 but does not say whether steps 2–4 share step 1's decision or whether T-45 may precede step 2; both orders keep I within the bounds checked.
- MM-10: the soundness of the supervisor's domain-empty fact at a new epoch is a premise with no mechanism in the frozen text; the FALSE branch is not run (R-GX-04).
- U-05: a second engine on an overlapping pool has no mechanism in the text, only a deployment precondition (EV-81 `[S]`; R-G5-06).
- MM-16: the event that assigns `local_agent_id` and the rule that no consumer keys state by it are not stated (R-GX-05; q30).
- The turn structure between the parse (T-24) and admission (T-30) is unstated; attribution is unaffected by the object-reference rule, but the "one decision" boundary should be written.
- The event library must deliver no readiness notification for a deregistered fd number after T-40 step 2; the text binds callbacks by object and generation but does not state the library property (R-GX-03).
- K-06 for `SOCK_STREAM`: queued-skb survival after the sender's death is measured on a datagram socket only (EV-58); no kernel source location is registered (candidate P-32 pending).
- The control-record carrier for a spawner kill / wait error (T-44) is not named in the control table.
- C-LP: the uid and process domain of a local per-agent model instance (CR-F-08 first item).
- C-LP: per-execution provider selection keyed by `execution_id` only (CR-F-08 second item).
- Every "decided by the frozen text" verdict of Stream Q is a design-level verdict that an implementation yielding inside a one-decision sequence would void.

## 7 Sealed main-thread draft compared at L (2026-10-19)

The sealed draft (.goals/plans/uid-binding-security-argument.draft-table.md, 2026-09-13, eight rows) was opened
only after the table landed. Every draft row has a counterpart: forged explicit credentials and becoming another
uid → R-G5-03 / R-G5-04 / R-G5-07; wrong uid read by the engine → R-G1-02, R-G2-03, R-G2-06, R-G5-05; setup race →
R-G1-01, R-G1-06; recycled-uid survivor → R-G4-01, R-GX-01, R-GX-03; kernel exploit → R-G5-01 (the table adds the
hardware path R-G5-02). Differences: (1) the draft counts channel-fd theft prevention (pidfd_getfd denial, no
/proc reopen) as a defence; the table does not rest attribution on it — a held foreign endpoint is stopped by the
per-fragment stamp comparison (R-G2-09), so fd theft is not an attribution route; (2) the draft tags the engine-side
halves (row-CLOSED gate, sentinel rejection) `[M]` or leaves them untagged; the table carries them as `[S]`,
conditional on unbuilt requirements; (3) the draft has no consumer-side (C-08), control-correlation (R-GX-02),
epoch-survivor (R-GX-04), pool-exclusivity (R-G5-06 / R-G5-08) or remainder-slot routes, and no deployment
preconditions. None is a source-checkable error in the table; the table stands. The landed section in mechanism.md
equals this table text apart from heading levels, one superseding sentence and relative links (checked by diff).
