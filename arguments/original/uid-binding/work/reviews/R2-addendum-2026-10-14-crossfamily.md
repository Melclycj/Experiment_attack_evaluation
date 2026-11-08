# R2 cross-family addendum — uid-binding security argument

## Header

- Reviewer: Codex CLI, independent of the Claude conversation. Exact model identifier and reasoning-effort setting are not exposed by this session's runtime metadata; neither is inferred from the instruction-layer persona. The optional CODEX_MODEL, OPENAI_MODEL and CODEX_REASONING_EFFORT environment variables were unset.
- Date: 2026-10-14 (Australia/Sydney).
- Subject: commit `58cfe43d51bd8abc7bef4a50ed0d9a497e090495`, verified with `git log -1`: “docs(uid-binding): adjudicate R2 on Step 3 and Stream E, register 03 v2, Invariant03 v2 and 04 v2”.
- Observed with `git hash-object`:
  - `work/spine/03-invariant.md`: `0544cb63d740682d1abccb6fef19437b1a1a6b44`.
  - `work/spine/03-tlc/Invariant03.tla`: `d2b42224e3ac8a1e7f61a4fac8dde693a7df34e7`.
  - `work/spine/04-evidence-registry.md`: `e3b2ec9ec5a1f2da1b0202b20d200321cf2b62be`.
- Paths beginning with `work/` below are relative to `Thesis/Work/Submission/prove/uid-binding/`; all other paths are repository-relative. In checks and the sample table, 01, 02, 03 and 04 denote their numbered files in `work/spine/`, and Spec denotes `work/spine/03-tlc/Invariant03.tla`. Source aliases are defined below.
- Criteria: A goal entailment and historical definitions; B initial state and new epoch; C run record and traces; D lifecycle correspondence and abstraction direction; E independent TLC execution; F evidence provenance, tags, samples and counts; G vocabulary/path restrictions; H IDs, group cut and prior rulings.
- Read before forming findings: PLAN's specified context, frozen revision, execution/review and resume sections; 01 v7; 02 v3; VERSIONS; the CR-R1, CR-OWN, CR-A and CR-R2 rulings; 03 and 04; Spec; all four configurations and committed logs. The R1 cross-family addendum was consulted for structure. TASKS §0 and the SUB-12 scope/dependencies were consulted for repository navigation.
- All ten frozen blobs matched PLAN. Unlike the first review's hash-only treatment of five sources, passages of each were read: conn E-01/E-02/E-04; rr:546–571; si:89–122,184–195,242–289; sbx SB-01/SB-04/SB-07 and SC-catalog/start/drop/fault/reclaim; iv's build, observation and limit sections; mech:125–147,257–301; optb:166–214,243–281; kub §2.4–§2.6 and the registry locations below; scope:149–187; tm:113–130,156–190. This was a passage-based check, not a reading of every line of every source.
- Registry sources read: all eight source documents at the relevant passages; the fd survey's historical-cases, additional-cases and local-semantics working notes, plus its plan introduction. The sample below contains 32 rows across all eight sources, including 21 rows absent from the first review's sample table.
- Two passes: the independent candidate findings and sample list were recorded in session memory before opening the first R2 record. The first opening of `work/reviews/R2-2026-10-14.md` was at 2026-10-14 06:53:04 UTC (17:53:04 Sydney), after the independent pass and all four TLC reruns. Its original findings, sample table, adjudication pointer and targeted recheck were then read. Required change-request rulings had already been read as context. NEW below means a substantive issue absent from that record's findings, not merely a newly inspected line.
- Structural checker: `python -I work/tooling/check-step3.py`, from the line folder, returned exit **0**, `errors: []`; 23 action rows, IG01–IG11 and 13 prose guards were recognized.
- Repository handling: only this new record was written. No git-writing command was run. The reviewed files matched the subject commit; unrelated pre-existing changes in adjacent design documents were left untouched. No sealed material was opened. All text-file reads used UTF-8.

Source aliases used for citations:

| Alias | Repository-relative file |
|---|---|
| conn | `ExperimentLab/lab/experiments/w2/implementation/engine-design/connections.md` |
| rr | `ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md` |
| si | `ExperimentLab/lab/experiments/w2/implementation/engine-design/supporting-interfaces.md` |
| sbx | `ExperimentLab/lab/experiments/w2/implementation/sandbox-design.md` |
| iv | `ExperimentLab/lab/experiments/w2/implementation-validation.md` |
| mech | `Thesis/Work/Design/sandbox-mediated-agent-execution/mechanism.md` |
| optb | `Thesis/Work/Design/sandbox-mediated-agent-execution/option-b-workload-per-engine.md` |
| kub | `Thesis/Work/Design/sandbox-mediated-agent-execution/kernel/kernel-uid-binding.md` |
| scope | `Thesis/Work/Design/sandbox-mediated-agent-execution/scope-and-boundary.md` |
| tm | `Thesis/Work/Design/sandbox-mediated-agent-execution/threat-model-derivation-map.md` |
| arm3 | `ExperimentLab/lab/experiments/REPORT-binding-arm3-workload-per-engine.md` |
| rendezvous | `ExperimentLab/lab/experiments/REPORT-netns-userns-rendezvous.md` |
| dprime | `ExperimentLab/lab/experiments/REPORT-dprime-build.md` |
| cappost | `ExperimentLab/lab/experiments/REPORT-capability-posture.md` |
| fdsurvey | `Thesis/Work/Design/sandbox-mediated-agent-execution/kernel/kernel-fd-reference-survey.md` |
| additional | `Thesis/Work/Submission/prove/uid-binding/fd-reference-survey/additional-cases.md` |
| local | `Thesis/Work/Submission/prove/uid-binding/fd-reference-survey/local-semantics.md` |
| desc9 | `Thesis/Work/Design/sandbox-mediated-agent-execution/kernel/kernel-descriptor-security.md`, §9 |

### TLC observed in this session

TLC2 2.19, revision 5a47802, Oracle Java 21.0.6, Windows 11 amd64. Each command ran from `work/spine/03-tlc/`:

```text
java -cp <tlaplus-dir>/tla2tools.jar tlc2.TLC -config <cfg> -deadlock -workers 4 -metadir <external-scratch> Invariant03.tla
```

The four cfg names were Invariant03-run1.cfg, Invariant03-run2.cfg, Invariant03-run2-goal.cfg and Invariant03-run2c-noA07.cfg. Separate external metadirs were used. No spec variant was written or run.

| Run | Exit | Observed outcome | Generated / distinct / depth |
|---|---:|---|---|
| 1 | 0 | No error | 1,177,356 / 150,362 / 27 |
| 2a | 1 | “Invariant IG02 is violated” | 199 / 153 / 6 |
| 2b | 1 | “Invariant Goal is violated” | 71,684 / 22,480 / 13 |
| 2c | 0 | No error | 8,677,006 / 900,780 / 28 |

Both counterexample action sequences reproduced the committed version-2 sequences. In 2b, State 11 follows SendExit, not Send; its queued entry has origin 1 and inJ TRUE, while execution 1's PID 1 has exited. The independent runs did not request action coverage; all 23 coverage pairs were separately compared with the committed run-1 log and matched.

## Findings

### F-01 — P1 — NEW — criteria D, H: IG-10 extends the post-drop uid fact into bootstrap states

**File and line:** `work/spine/03-invariant.md:16–19,96,186`; `work/spine/03-tlc/Invariant03.tla:173–183,484–485`; 01:116–119; 02:118–123.

**Text:** IG-10 says tasks exist “at the record's uid”; Launch creates the task and assigns U in one action.

**Why it fails:** I is stated over the 01 state, not only over post-bootstrap abstract observations. In 01, T-05 already creates P_X and its child; T-06 explicitly runs that child as root, and T-07 subsequently changes its real uid to the allocated non-root uid. Thus a normal T-05 → T-06 prefix has a live member of P_X whose uid is not the record's uid. The model's collapse of T-04 through T-07 erases precisely that state, so the checked predicate is not a justification for handing this unqualified guard to G1 for the individual transitions. The G1 launch fact in 02:121 points to T-07; it does not change when X_r or its task membership begins. This is distinct from the first record's Handoff-liveness finding.

**Smallest repair:** Qualify the uid clause of IG-10 by successful T-07, retain pre-drop task membership in the full-model statement, and identify the post-drop abstraction boundary of Launch explicitly.

### F-02 — P1 — NEW — criteria A, D, H: the read-time guard excludes admitted DRAINING reads

**File and line:** `work/spine/03-invariant.md:87,94,99,143–147,207–209,253–255`; `work/spine/03-tlc/Invariant03.tla:38,242`; 01:136,165–166; conn:413,486–487,508–516,816–821.

**Text:** IG-13 requires every contributing byte to have been read while the row was “STARTING or ACTIVE”; the prose says DRAINING is folded into CloseRow triggers, whereas Spec:38 says “DRAINING folded into ACTIVE”.

**Why it fails:** T-47 enters DRAINING without immediately discarding the channel. During its grace interval the frozen receiver still validates each credential and accepts bye and the permitted old terminal/cancel messages. T-48 itself requires a validated bye in ACTIVE or DRAINING. These messages pass the common receive/label path; they are not outside D-ACC merely because new task admission is disabled. The source check is “not CLOSED”, not the two-state test in IG-13. A valid DRAINING bye therefore refutes the literal full-model guard used in §4 step 1. Mapping DRAINING to abstract ACTIVE can be a suitable abstraction, but that interpretation is neither the prose guard nor the stated CloseRow fold. The read-versus-accept-time repair of first-record F-05 holds; this is a separate omission of a permitted read phase, not a request to restore the former p72.

**Smallest repair:** Include DRAINING among the full-model open/read states and consistently state its abstraction to ACTIVE, preserving the ban on reads after CLOSED.

### F-03 — P1 — NEW — criterion D: error quarantine is incorrectly dependent on a sent stop

**File and line:** `work/spine/03-tlc/Invariant03.tla:187–193,338–354,373–378`; `work/spine/03-invariant.md:187,199–202,249–252`; 01:119,159–162; conn:831–834.

**Text:** Quarantine requires `stopSent[e]`, although its table row says it represents “timeouts and kill/wait errors”.

**Why it fails:** T-44's stop-sent requirement belongs to its 5,000-ms timeout alternative; kill/wait errors are a separate alternative. For example, a T-08 record failure can initiate the spawner's own cleanup before any engine stop arrives. The model itself admits Kill for failed_after_clone with stopSent FALSE. The frozen error outcome then quarantines the lease, but this model cannot represent that outcome: Kill always removes PID 1, Reap always sets reaped, and Quarantine is disabled until an extra stop is delivered. A wait error following spontaneous child exit supplies another stop-independent case. ControlLoss is not an equivalent substitute: it also changes every row and admission state. The sole restriction listed in §5.2 concerns unknown records, not these known-record errors.

**Smallest repair:** Add a kill/wait-error quarantine alternative independent of stopSent while retaining the stop-sent guard for the timeout alternative and stating how failed kill/reap effects are represented.

### F-04 — P1 — NEW — criterion F: EV-65 attaches the mapped-arm result to the wrong run configuration

**File and line:** `work/spine/04-evidence-registry.md:146`; dprime:129–149.

**Text:** The measured fact says that “with the engine as root” it read 60001 in the “baseline, unmapped … and mapped arms”, with date 2026-08-15 / 2026-08-16 and the EV-62 root substrate.

**Why it fails:** The report expressly says the mapped arm is inconclusive in that root configuration because writing setgroups failed. Its mapped-arm answer comes from an earlier unprivileged run, whose date the report does not supply. EV-65's note does preserve that caveat, but the primary fact and shared provenance still attribute all three outcomes to the root configuration. This is not merely an absent caveat: the fact and the note contradict each other, and the mapped part does not meet the row's measured-run/date/substrate contract. The first review sampled dprime:138 for the excerpt; it did not raise this provenance conflict.

**Smallest repair:** Restrict EV-65's measured fact to the dated root baseline/unmapped observations and retain the earlier mapped-arm claim separately as source-read with its unknown run provenance.

### F-05 — P1 — OVERLAP(F-09) — criterion F: the external-record repair does not cover all qualifying rows

**File and line:** `work/spine/04-evidence-registry.md:45–49,109,168,247`; kub:489–507; additional:46–50; `work/convergence/change-requests.md:150,184`.

**Text:** The external-kernel-record rule requires the record's identifier and counts four rows; EV-28 gives only a 2023 lore discussion, and EV-87 gives only Qualys and an advisory date.

**Why it fails:** CR-R2-09 and CR-R2-26 repaired the class definition and the four originally named rows. The resulting universal rule also applies to EV-28's kernel mailing-list record and EV-87's kernel vulnerability advisory, neither of which has a pinned-tree location. Neither row supplies its record identifier in its fact or note: EV-28 has no message reference; EV-87 omits CVE-2026-46333 and the advisory reference available at additional:46–48. The existing four-row count is therefore not an inventory of that class. There are at least six qualifying rows under the stated split: the four listed plus EV-28 and EV-87. This does not require pretending either is a pinned-tree reading; the accepted class split should be applied consistently. For EV-28 the cited note itself supplies no precise list identifier, so that gap must remain explicit until verified.

**Smallest repair:** Apply the external-record rule to EV-28 and EV-87, supply the available advisory identifier, mark the unresolved mailing-list identifier honestly, and recount the class and any unresolved identifier entries.

### F-06 — P1 — NEW — criterion D: successful T-03 and T-08 branches lack an explicit fold or omission account

**File and line:** `work/spine/03-invariant.md:178–188,207–213`; `work/spine/03-tlc/Invariant03.tla:150–160,176–183,201–213`; 01:114,119; conn:289–296.

**Text:** Submit “stands for” T-02 only; the only T-03 entry names its failure branch, the only T-08 entry names its failure branch, and Handoff starts at T-09.

**Why it fails:** Submit writes an admitted SpawnRecord, which is the successful T-03 effect, not a T-02 send-side write. Successful T-08 consumes and validates SEALED before T-09, but neither Launch's T-04–T-07 fold nor Handoff's listed T-09–T-11 fold accounts for it. The Not modeled paragraph names neither success branch or its abstraction reason. §5.2's declaration that T-03's occupancy check is relaxed is useful but does not identify the successful admission fold or the SEALED-success premise. The action count and presence of the bare T-03/T-08 IDs therefore do not satisfy criterion D's branch-sensitive correspondence check. This is a mapping-account defect; it is not evidence of a false accepted label in the runs.

**Smallest repair:** Map successful T-03 explicitly into Submit and successful T-08 into the chosen abstract action or input premise, naming the suppressed checks/intermediate interleavings and their abstraction rationale.

## Settled

- F-01
- F-02
- F-03
- F-04
- F-05
- F-06
- F-07
- F-08
- F-10
- F-11
- F-12
- F-13
- F-14
- F-15
- F-16
- F-17
- F-18
- F-19
- F-20
- F-21
- F-22
- N-01
- N-02
- N-03
- N-04
- N-05

## Checked and consistent

- **A — logical sufficiency, conditional on the stated guards.** 03:136–162 now states two implications and lists C-02. The prefix quantification at 139–141 permits historical use of IG-02 and IG-08. The conclusion uses 02:111–129's allocation and clone identity, not a definition through the observed uid or label. Spec:261–265,291–300 records origin from the sending membership index. No new circularity was found. F-02 concerns whether an asserted guard covers all admitted reads, not the algebra of the two implications.
- **A — interval.** Spec's InJ, Reserve, Release and NewEpoch match 02:127–129's reservation-to-release/retirement interval under the stated finite-id abstraction; 03:235–236 now names NewEpoch as retirement. ControlLoss alone does not change holder, and it permits no subsequent read. This holds even though sender exit can precede acceptance.
- **B.** 03:108–132 names I_acc and all IG-01–IG-13 before T-01, distinguishes the free-pool/accepting_new readings from quoted facts, and uses U-05 to exclude a pre-existing pool-uid task. The new-epoch argument retains MM-10 as a premise and gives the other guards' state effects; Spec:409–422 implements that reading. This check is about the initial-state argument, not a preservation result.
- **C.** 03:217–269 records bounds, parameters, toolchain and commands. Its table at 279–282 matches the committed result/count/depth lines: run1.log:14,489–490; run2.log:14,136–137; run2-goal.log:14,328–329; run2c-noA07.log:15,20–21. All 23 pairs at 03:293–299 match run1.log:22–353. The original log's zero mismatch-branch coverage is at 134–135, consistent with the one-uid explanation.
- **C.** Run 2a is Init → Reserve → Submit → Launch → Release (log:16,40,64,88,112); Submit is the indeterminate, admitted-record branch. Run 2b is Init → Reserve → Submit → Launch → Handoff → CloseRow → Release → Reserve → Submit → Launch → SendExit → Handoff → Accept (log:16–304). The prose at 305–320 matches. Counts at violation vary as acknowledged. R-G4-01, not R-GX-01, names the live old task's send inside J_2.
- **C/D.** 03:223–230 now identifies both omitted reuse checks as relaxations and qualifies the counterexamples accordingly. The unknown-record stop case is called a restriction at 249–252. Fork after PID 1 death adds behavior; Handoff no longer requires a live PID 1 and its pre-handoff empty-P_X description is consistent with Fork's execd precondition. These specific repairs hold; F-01–F-03 and F-06 identify other correspondence problems.
- **D — coverage boundary.** T-40 steps 1/2/4 and T-41–T-45 have distinct actions; T-46 is a CloseRow trigger. The text explicitly accounts for the T-47/T-48 choice (but inconsistently, F-02), T-50–T-52 bookkeeping, and K-01–K-10 through its action rows or omission paragraph (03:194–213). The IG01–IG11 operators agree with the stated abstract predicates, including IG09 admitting a formerly STARTING row now in CLOSED. IG06's once-per-lease clause and IG12/IG13 are correctly distinguished from TLC state predicates at 03:57–59. Agreement inside the abstraction does not cure F-01's full-model wording.
- **E.** All four specified TLC outcomes reproduced; the run table is in the header. No modified-spec experiment was used to support a finding.
- **F — format/counts.** 04:82–179 has exactly 98 contiguous EV IDs and eight nonempty cells per row: 34 [M], 49 [R], 15 [S]. Per-source counts are kub 46, arm3 9, rendezvous 6, dprime 7, cappost 4, iv 11, fdsurvey 12, desc9 3. §2 has 15 reclassifications. Nine measured rows explicitly use the P2a diagnostic policy: EV-73–77, EV-79, EV-80, EV-97–98; EV-54 expressly says its earlier arm3 profile is not that policy. The 15 numbered pinned-kernel rows lacking source-note line numbers are accounted for by the permitted marker. The four entries printed in the external-record count were verified, but F-05 prevents endorsing that as the class total.
- **F — three no-row spot checks.** 04:216 against dprime:111–125 concerns passed-socket reachability rather than a new sender-attribution observation; 04:217 against cappost:80–86 concerns the spawner's pivot_root gate; 04:220 against desc9:673–689 is the owner/interface argument rather than a distinct measured or pinned-source attribution observation. Those exclusions are consistent with the registry's stated extraction scope.
- **F/G — row role.** No registry row newly assigns a route or a disposition in this research line. EV-30/33/34/40 report existing source rulings, EV-36 quotes a source-local route name, and EV-49's historical hardening language/EV-54–55's source heading are source evidence, not a new assignment by this registry. They were not treated as new findings.
- **G.** The specified vocabulary scan found no prohibited occurrence in the bodies of 03 or 04. The planned module filename is no longer backtick-quoted (03:176–178); actual local artifact references name committed files, and kernel paths are source locations rather than planned local deliverables. No sealed-material reference occurs in either reviewed body.
- **H.** The checker returned 0 with no errors. The IDs retain the meanings inspected in 01/02; the preservation-owner labels in 03's guard table agree with 02:467–480's group cut. The repaired ownership additions are present. 03:352–375 keeps the G1 launch obligations, the former p72's distinct parts, and R-G4-01 versus R-GX-01 separate. F-01 and F-02 concern guard scope, not a request to reverse those rulings.

### Registry sample

“Verbatim” compares displayed text: Markdown emphasis/code delimiters and line wrapping are ignored, explicit ellipses are permitted. It does not certify the underlying kernel or external publication. A star marks a row absent from the first R2 sample table. All listed locations exist.

| EV id | Location checked | Verbatim? | Tag by meaning? |
|---|---|---|---|
| EV-04 * | kub:70–100, §2.3 | Yes | Yes [S], order requirement distinct from the probe |
| EV-05 * | kub:75–83 | Yes | Yes [R], source semantics; line-not-given marker |
| EV-06 * | kub:84–90,461–463 | Yes | Yes [R], source/man-page semantics |
| EV-08 * | kub:136–165 | Yes | Yes [R], explicit-credential check |
| EV-12 * | kub:194–198 | Yes | Yes [R], connection snapshot |
| EV-13 * | kub:202–220 | Yes | Yes [R], receiver translation |
| EV-14 * | kub:605–608 | Yes | Yes [R], missing control buffer |
| EV-15 * | kub:222–225 | Yes | Yes [R], secondary statement of d7, not a registered measured run |
| EV-20 * | kub:284–298 | Yes | Yes [R], namespace-local capability set |
| EV-21 * | kub:300–329,340–342 | Yes | Yes [R], map-write rule |
| EV-23 * | kub:420–426 | Yes | Yes [R], CVE-2019-19241 external record |
| EV-25 * | kub:465–468 | Yes | Yes [R], synchronous capture |
| EV-26 * | kub:473–478 | Yes | Yes [R], historical case plus pinned-source observation |
| EV-27 * | kub:480–487 | Yes | Yes [R], historical CVE/fix record |
| EV-28 * | kub:489–507 | Yes | [R] yes; external identifier/count defect F-05 |
| EV-30 * | kub:535–544 | Yes | Yes [S], equal-value requirement |
| EV-31 * | kub:546–557 | Yes | Yes [S], two-part stated configuration |
| EV-33 * | kub:590–604 | Yes | Yes [S], engine namespace requirement |
| EV-34 * | kub:605–622,662–668,749,752–755 | Yes | Yes [S], PASSCRED/receive requirements |
| EV-51 | arm3:41–43,109–112; date:41; substrate:7 | Yes | Yes [M], dated added cell |
| EV-57 * | rendezvous:60–62,72–78,85–86; date/substrate:4–6,32 | Yes | Yes [M], uid-1001 rendezvous arm |
| EV-64 | dprime:82–85,106–109; date/substrate:4–5 | Yes | Yes [M], hygienic arm and inherited stdio |
| EV-65 | dprime:129–149; date/substrate:4–5 | Yes | Not for the combined fact: F-04 |
| EV-67 | dprime:169–176,205–206; date/substrate:4–5 | Yes | Yes [M], fork-only EOF observation |
| EV-69 | cappost:37–52; date/substrate:4–5 | Yes | Yes [M], single-probe capability experiment |
| EV-71 | cappost:88–92,103–112; date/substrate:4–5 | Yes | Yes [M], targeted unshare filter |
| EV-72 | cappost:131–133 | Yes | Yes [S], separate-process design not exercised |
| EV-76 * | iv:47; substrate:17,22–31; run:12 | Yes | Yes [M], diagnostic handoff observation |
| EV-87 | additional:46–50; fdsurvey:40,58–60 | Yes | [R] yes; external identifier/count defect F-05 |
| EV-92 | local:100–108; fdsurvey:68–69 | Yes | Yes [R], diagnostic-policy source read |
| EV-94 | desc9:622–642 | Yes | Yes [R], conditional fd-lookup argument |
| EV-96 | desc9:652–655 | Yes | Yes [S], location of engine-side associations |

## Not checked

- No inductive preservation proof for all transitions, no extension beyond the stated TLC bounds, and no run of the unsound-supervisor parameter branch or alternative fd-shut parameter setting.
- No kernel tree was fetched or re-audited, no public advisory/list source was independently re-verified, and no original lab experiment or production engine was executed. Registry checks end at the cited source notes/reports. EV-28's precise mailing-list identifier remains unverified.
- The 66 registry rows outside the displayed sample received format/count and relevant repair checks, not a fresh row-by-row provenance audit. Only the three no-row exclusions identified above were independently spot-checked in this addendum.
- No action-coverage-enabled TLC rerun; coverage verification used the committed log. No modified model was executed for F-01–F-03; those findings follow from direct transition/guard comparison.
- External scratch removal was attempted with native PowerShell Remove-Item after checking the absolute targets, but the sandbox rejected it. The four metadirs under `<scratch>/` named `uid-r2-crossfamily-run1`, `uid-r2-crossfamily-run2a`, `uid-r2-crossfamily-run2b` and `uid-r2-crossfamily-run2c` were therefore not confirmed removed. No repository TLC scratch directory was created, and no permission bypass was attempted.
- Exact runtime model identity and reasoning effort could not be independently obtained; the header reports that limitation rather than a guessed model name.

## Gate

may not pass, because F-01–F-06 are P1 candidate-review defects in guard scope, lifecycle correspondence or registry provenance/format; this is only the R2 candidate gate and makes no statement about security or the real system.

## Executor adjudication (2026-10-14)

Dispatch note: this record was written by a Codex CLI session started through the official codex plugin at the
user's direction (model and reasoning effort left at the user's Codex configuration); the session's final
stdout summary was blocked by the provider's cybersecurity safeguard after the file above had been written in
full, so the job is marked failed in the plugin's log while the record is complete.

All six findings accepted by the main session; the repairs chosen are recorded one row each as CR-R2-32 …
CR-R2-37 in [change requests](../convergence/change-requests.md). Repair candidate: 03 version 3,
`Invariant03.tla` version 3 (all four configurations rerun; outcomes unchanged), 04 version 3. The targeted
recheck of the repairs is appended below by a cold-context reviewer (two Codex attempts were blocked by the
provider's safeguard at the first turn; the recheck ran on Claude Opus). Its gate line was "may not pass" (F-02's
repair short at two places, N-01/N-02); those items and the four remarks were repaired as CR-R2-38 … 43, and
the user accepted the candidate on 2026-10-14 without a further recheck.

## Targeted recheck (2026-10-14)

**Reviewer and subject.** Cold-context Claude Opus (Claude family), no access to the executor's conversation; a recheck of the CR-R2-32 … CR-R2-37 repairs of the six findings above, on the uncommitted working-tree candidate against `58cfe43`. The executor tried twice to have Codex run this recheck; the provider's safeguard blocked both runs at the first turn, so this is a Claude-family recheck of Codex-family findings. Blobs observed with `git hash-object`: 03 `4d8c1121…`, spec `dc6dd407…`, 04 `1563495b…`. Read: this record, CR-R2-32 … 37, `git diff 58cfe43` of the line folder, 03 v3, spec v3, 04 v3 in full at the edited places; 01 v7 rows T-03, T-05 … T-08, T-25, T-44, T-47, T-48, AA-04, AA-09 and the `Execution.state` row; 02 v3 §1; conn L413, L481–487, L813–821, L831–834; dprime L127–149; kub L487–507; additional L46–52; fdsurvey L38–40, L56–60. Only this section was written; no git-writing command was run.

### Verdicts

| finding / CR | verdict | evidence (file:line, brief quote) |
|---|---|---|
| F-01 / CR-R2-32 | holds with remark | 03:96 IG-10 now reads "after T-07 succeeded every member's real uid is the record's uid … Between T-05 and T-07 the single member is the trusted bootstrap … `Launch` is the post-drop abstraction boundary"; 03:256–259 lists the pre-drop member as a restriction; task existence before T-07 stays in the first clause. Remarks: (1) the AA-09 gloss "the spawner alone reads SEALED" inverts 01:274 "The spawner reads only SEALED"; the claim "no byte of it reaches the engine" rests on AA-04 with T-07/T-08 (01:118–119: a pre-drop FAIL ends in record failure, SEALED is sent after step 11), not on that sentence. (2) The sibling phrase in IG-02's derived-from cell, 03:88 "01 T-05/T-07 (members are created at the record's uid)", is untouched and now reads against IG-10's new prose (pre-existing, not introduced). |
| F-02 / CR-R2-33 | does not hold | IG-13 itself is repaired (03:99 "not CLOSED — STARTING, ACTIVE or DRAINING", model column "abstracts DRAINING to ACTIVE"; §4 step 1 at 03:145; §5.1 at 03:209–211), and it matches T-25/T-47/T-48 (01:136,165–166; conn L486–487, L818–819) and the spec comment tla:38 "DRAINING folded into ACTIVE". But the inconsistent phrase the CR says was replaced survives at 03:379 (§6, to Stream Q) "DRAINING folded into CloseRow's triggers", and 03:263 still lists "DRAINING" under Not modeled; and the full-model open-row set of IG-01 (03:87), which §4 step 2 uses through IG-08, still excludes DRAINING. See N-01, N-02. |
| F-03 / CR-R2-34 | holds | tla:381 `(stopSent[e] \/ spawnRec[e] = "failed_after_clone")`; comment tla:375–379 and 03:203 name the two alternatives and state that a failed kill/wait is represented by `Kill` / `Reap` not being taken, which the model admits (tla:342–354). This matches T-44's separate alternatives (01:162; conn L813–814, L831). The remaining stop-independent case is listed as a restriction (03:259–261). The control-loss sweep's kill error is covered by `ControlLoss`'s own quarantine (03:205), so its omission from the alternative list is not a gap. |
| F-04 / CR-R2-35 | holds with remark | 04:147 fact now "baseline and unmapped … arms, `engine_ever_misled` was false, and the mapped arm was inconclusive in this configuration"; note: the earlier unprivileged run's statement is "the report's, not a measurement registered here". Matches dprime:132–138, 144–149. Remark: the locator "mapped-arm paragraph L143–147" is off by one to two lines; the paragraph is dprime L144–149 (L143 is blank). |
| F-05 / CR-R2-36 | holds with remark | 04:48–50 class list now includes EV-28 and EV-87; 04:248 "6 (EV-22, EV-23, EV-27, EV-28, EV-36, EV-87); identifier unresolved in the source: 1 (EV-28)"; EV-87 note (04:169) names `CVE-2026-46333` and the Qualys oss-security advisory of 2026-05-20, which additional:48 and fdsurvey:40, 60 give; EV-28 note (04:110) marks the identifier unresolved. Remarks: EV-87's "openwall link at fdsurvey L58" points at the R5 heading; the link stands at fdsurvey L60 (and additional L48). EV-28's "lore.kernel.org" expands kub L490 "lore"; harmless but not the source's wording. |
| F-06 / CR-R2-37 | holds with remark | 03:185 `Submit` "T-02, with the successful T-03 admission folded"; 03:189 `Handoff` "with the successful T-08 as its folded precondition (SEALED consumed: `uid == allocated u`, `pid == child_pid` …)"; 03:211–212; tla:147–148, 199–200. Consistent with 01:114, 119 and with the spec's guards (Handoff requires `spawnRec = launched`; SpawnFailAfterClone is the failure branch). Remark: 03:185 and tla:148 say "T-03's occupancy and budget checks are the relaxation of §5.2", but §5.2 (03:227–229) names only the uid/lease occupancy check; the storage-budget, plan-digest, `seq` and workspace checks of T-03 (01:114) are not named there. Dropping them only adds behaviours, so this is a naming gap, not a soundness one. |

### New defects

**N-01 — P2 — 03:379 and 03:263: the DRAINING abstraction is still stated three ways.**
Text: §6, to Stream Q, "DRAINING folded into CloseRow's triggers"; §5.2 Not modeled, "…; DRAINING; request state; consumers."
Why it fails: CR-R2-33 states that the abstraction of DRAINING to ACTIVE now replaces "the inconsistent 'folded into `CloseRow`'s triggers'", and 03:99, 03:209–211 and tla:38 say "abstracted to ACTIVE". The §6 handoff to Stream Q still carries the replaced reading, so the collapse Stream Q is asked to justify is the one the repair withdrew. §5.2 calls DRAINING "not modeled" while §5.1 says it is abstracted to ACTIVE. This is the inconsistency F-02 named, left at a third place.
Smallest repair: at 03:379 write "DRAINING abstracted to ACTIVE (T-47), `bye` a `CloseRow` trigger (T-48)", and at 03:263 qualify the entry as "DRAINING as a distinct state (abstracted to ACTIVE, §5.1)".

**N-02 — P1 — 03:87 with 03:99 and 03:147: the full-model "open row" excludes DRAINING, so §4 step 2 no longer covers every read IG-13 admits.**
Text: IG-01, "An open row (RESERVED, PREPARING, STARTING or ACTIVE) holds its lease …"; IG-13, "Acceptance reads only from an open row: … not CLOSED — STARTING, ACTIVE or DRAINING"; §4 step 2, "By IG-08 at the read instant, every skb on an open row's channel was sent while that row's interval was open … (IG-01 gives the same at the read instant …)".
Why it fails: after the F-02 repair a D-ACC byte may be read in DRAINING (01:136, 165–166). IG-08 and IG-01 are stated over open rows, and the only enumeration of open rows in 03 is IG-01's, which omits DRAINING (01:70 lists DRAINING as a state). For a DRAINING read, step 2's appeal to IG-08 and IG-01 therefore has no guard behind it in the full-model statement, and IG-13's own first clause ("reads only from an open row") contradicts its second. Inside the model the gap is invisible because DRAINING maps to ACTIVE and `OpenRow` (tla:73) contains ACTIVE; the defect is in the 01-level wording the preservation files receive (criteria A, D). Before the repair IG-13's two states matched IG-01's set; the repair introduced the mismatch.
Smallest repair: add DRAINING to IG-01's open-row list at 03:87 with the note "(DRAINING abstracted to ACTIVE in `OpenRow`, §5.1)", so IG-01, IG-08, IG-13 and §4 step 2 use one open-row set.

No other new defect was found. IDs keep their meanings (IG-10's first clause and IG-13's post-CLOSED role are unchanged in kind); the `exState` comment (tla:38) agrees with 03:99 and 03:209; EV-65, EV-28 and EV-87 quote and locate their sources apart from the remarks above.

### TLC rerun

TLC2 2.19 (rev 5a47802), Java 21 on PATH, from `03-tlc`, `-deadlock -workers 4`, metadir under this session's temp scratchpad (outside the repository); no repository file was written or changed by the runs (`git status` of `03-tlc` showed only the executor's pre-existing modifications).

| run | outcome | generated / distinct / depth | trace |
|---|---|---|---|
| 1 | "Model checking completed. No error has been found." | 1,187,676 / 152,054 / 27 | — |
| 2a | "Invariant IG02 is violated" | 200 / 153 / 6 | Init → Reserve → Submit → Launch → Release |
| 2b | "Invariant Goal is violated" | 80,759 / 24,915 / 13 | Init → Reserve → Submit → Launch → Handoff → CloseRow → Release → Reserve → Submit → Launch → SendExit → Handoff → Accept (twelve actions; the eleventh action, State 11, is SendExit) |
| 2c | "Model checking completed. No error has been found." | 8,775,538 / 910,932 / 28 | — |

Runs 1 and 2c match 03:288, 291 exactly; 2a and 2b reproduce the recorded traces, with violation-time counts differing as 03:312 states.

### Vocabulary and checker

Body scan of 03 and 04 (front matter excluded) for *closure*, *closed* (any case other than the state name CLOSED), *complete*, *exhaustive*, *proven*, *fixed-point*, rate/percentage wording, and "stops" / "defends against" / "protects against": no prohibited occurrence. Hits inspected and allowed: "Model checking completed" (03, TLC quotation); "exhausted" / "exhaustion" (04 EV-02, pool exhaustion, source wording, not *exhaustive*); "memory protection" (04 EV-94, a source premise); "stop" as the protocol record name (03). `python -I work/tooling/check-step3.py` from the line folder: exit **0**, `errors: []`, 23 action rows, IG01–IG11 operators, 13 guard rows, four cfg files. 04 recount from the table: 98 contiguous rows of eight cells; [M] 34, [R] 49, [S] 15; 15 reclassification rows in §2; 9 [M] rows under the diagnostic policy (EV-73–77, EV-79, EV-80, EV-97, EV-98; EV-54 excluded as its note states); 6 external kernel records, 1 unresolved identifier — all as §0 and §4 state.

Gate: may not pass, because F-02's repair does not hold: the replaced DRAINING reading survives at 03:379 and 03:263 (N-01, P2), and IG-01's open-row set at 03:87 omits DRAINING, so §4 step 2 does not cover the DRAINING reads IG-13 now admits (N-02, P1). This is only the R2 candidate gate; it says nothing about security or the real system.
