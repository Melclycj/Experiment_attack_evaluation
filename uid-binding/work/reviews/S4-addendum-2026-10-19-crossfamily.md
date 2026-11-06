# S4 cross-family review addendum — 2026-10-19

Reviewer: Codex, independent cross-family review under the S4 brief.

## 1 Scope and pins

- Review input: commit `562d6ed286687c8f6acf0bc3606e7c0fbb9ceda3`, including `Thesis/Work/Submission/prove/uid-binding/work/reviews/S4-brief-2026-10-19.md` and the initial Opus review and its recheck in `Thesis/Work/Submission/prove/uid-binding/work/reviews/S4-2026-10-19.md`.
- Engine change inspected: `7b4ab727fc780990485a794f5275d63742c4c729`, its diff, source, tests and archived observations. The engine tree has no difference between that commit and the review pin. Registry v9, including EV-265–EV-272 and its supersession paragraph, is the applicable registry; the brief's v8 instruction predates these repairs.
- Read the 30 rerun routes' compositions and disposition limits. Full-file readings included R-G1-01/02/05, R-G2-01/11/12/13, R-G3-01/03/05, R-G4-01, R-G5-05 and R-GX-01/02/04/06; R-G5-06 was the additional G5 sample, although it was not rerun at step 4. G4 has no second route file.
- Read the step-4 brief, evidence map, reconcile follow-up, change requests, vector table, refreshed uncertainties, PLAN's follow-up properties, the relevant engine requirements and validation passages. Source readings and archive checks below were limited to the route evidence, not a general engine audit.
- The sealed draft was not opened. No route, source, evidence registry, index, checkpoint or other review record was changed. This addendum is the only output file.

The conclusions below concern the pinned prototype and the disposition rule supplied by the user, not deployment assurance. Archived Linux tests and fuzzing were inspected, not rerun on this Windows review host; only the reconciliation checker and read-only consistency checks were executed here.

## 2 Independent checks and prior repairs

### Mechanics

| Check | Result |
|---|---|
| Reconciliation checker | Exit 0, no hard findings; 38 ledger routes, 38 route files, 48 matrix cells, 272 registry rows |
| Dispositions | 35 supported under stated premises; 1 conditional on unbuilt requirements; 0 open; 2 declared out of scope |
| Route-to-table extraction | All 38 five-column rows agree with route IDs, section 1 and front-matter violates/stops/disposition fields after whitespace and Markdown pipe normalization |
| Required spot checks | R-G1-02, R-G2-11, R-G2-12, R-G2-13, R-G3-03, R-G3-05, R-G4-01, R-G5-05, R-GX-04 and R-GX-06 agree |
| Step-4 row delta | Exactly 29 route rows differ from the pre-step-4 table at `c834ebbd28af95838d46b55cd88ce49787d9a971` (`b7c3167d^`); R-GX-04 remains conditional |
| Evidence tags | No mismatched tag in the explicit single-EV support-table rows of the 30 rerun files |
| Vocabulary | No prohibited lowercase whole-word occurrence in those routes or the vector table, except the permitted table phrase; no rate claim found |

The checker was run with UTF-8 output and bytecode writing disabled, without its table-output option: `python Thesis/Work/Submission/prove/uid-binding/work/tooling/reconcile-checks.py`. The relevant working files matched the review pin before execution. Comparing only the immediate parent of `562d6ed2` would measure the last repair, not the step-4 change; the 29-row check therefore uses the pre-step-4 baseline above.

### Remainder properties

| Route | Evidence checked independently | Judgment within the brief's rule |
|---|---|---|
| R-G2-11 | EV-169/170/236 and EV-265–272; the FFI copy boundary, sole data receive call, reader binding and reset, Python parse, source-scan test and its archived negative control; raw fuzz logs, environment and replay coverage | The current reader performs framing and credential comparison without a C-side body parse. Its stop reports the bounded observation for project C code, not a general memory-safety theorem; the untested CPython runtime remains explicitly named. |
| R-G2-12 | EV-163–165/262; startup check before catalogs/control use, native identity-map parser, 31 archived startup fields and the non-identity-map refusal | The startup property is realized and checked. The initial-user-namespace identity remains a separate deployment premise rather than a claimed consequence of reading an identity map. |
| R-G2-13 | EV-171/172/173/239/253/265; per-return ancillary validation, counting only checked bytes, parsing and phase decision before the sole VerifiedContext construction | The one-path/one-comparison argument is reconstructible. A CLOSED session takes the pre-read refusal, not a comparison on nonexistent input; non-STARTING negative phase coverage is correctly limited to the stand-in row. |
| R-G3-05 | EV-196–198/227/229/241/253–259; request admission, authorization, Sink, response writer and recorder object paths, plus the archived by-reference test result | The property reaches the present handlers and stub connector only. The decoy covers execution-ID lookup; absence of other identity-keyed consumer lookups rests on source reading, not on that test. |
| R-GX-06 | EV-187/191–195/205/264; reservation/install/retirement assignments, callback-identity check, reclamation gate and AA-13 record | The property is supported for the pinned object lifecycle and epoll backend. Test-created same-round fd reuse and spawner-mediated sequential reuse remain distinct observations; no composed adversarial history is claimed. |

Key inspected source locations are `ExperimentLab/engine/native/sandbox/transport.c:90–121,150–161,212–239`, `ExperimentLab/engine/engine/ffi.py:92–106`, `ExperimentLab/engine/engine/receive.py:107–123,273–300`, `ExperimentLab/engine/engine/startup.py:61–93,167–185`, `ExperimentLab/engine/native/sandbox/support.c:218–226`, `ExperimentLab/engine/engine/lifecycle.py:121–167,197–349,423–502`, `ExperimentLab/engine/engine/loop.py:58–85,104–126`, `ExperimentLab/engine/engine/requests.py:81–99,144–292`, `ExperimentLab/engine/engine/writer.py:46–80,139–193` and `ExperimentLab/engine/engine/records.py:206–226`.

### Measured evidence and its boundaries

- The current transport source's SHA-256 is `32ef6fc600d0330c0ac6b9ce81d0a47c20da7a8d8408ce3330cb26557ec12c6c`, matching `ExperimentLab/engine/runs/20261019T025332Z-fuzz-no-c-parse/environment.txt:10`. The frame/ancillary/control log totals are respectively 81,700,084 / 139,403,813 / 390,030,460 executions. The archive reports one 3,600-second run per entry, no finding and successful replay; the gcov record shows 239 executions of copy-out at source line 238 and no execution of the EOF ancillary line 158. Line execution is not all-branch coverage or a guarantee of future behavior.
- `ExperimentLab/engine/runs/20261019T025203Z-engine-no-c-parse-rerun/nocparse.json` records 364 unprivileged unit passes, 32 skips, 32 root unit passes, 32 integration cases and five true cleanup fields. `ExperimentLab/engine/runs/20261019T024756Z-sandbox-no-c-parse/nocparse.json` records 171 sandbox cases and three true cleanup fields. The earlier failed attempt is not substituted for successful evidence.
- `ExperimentLab/engine/runs/20261019T025203Z-engine-no-c-parse-rerun/negative_control.txt:1–8` distinguishes the earlier body-parsing reader from the current reader. The malformed-body expectation changes agree with the source: Python rejects the body before context construction; the record kind and stop reason are not confused with the row's changed close_reason.
- `ExperimentLab/engine/runs/20261019T011226Z-engine-pool-70000/pool70000.json` supplies the positive identity-map observations, exit-3 namespace refusal, normal same-uid reuse, and kill-error/kill-no-fact quarantine observations cited by the routes. They do not establish host-wide uid exclusivity or a restart supervisor.
- `ExperimentLab/engine/runs/20261018T152246Z-aa13-deregistration/README.md:13–27` distinguishes the two positive stale-event cases from their failing negative controls and limits the observation to epoll with test-created fd reuse. The cited loop and retirement code matches that account.

### Premises and partly realized items

1. **CPython/jansson:** Opus F-01's extra C-side body parser was removed, not silently retagged as measured. Jansson still exists on other native paths, but not in the data reader's body path; the Python parse is still uninstrumented by these fuzz runs. R-G2-11, R-G2-13 and the vector table expose the remaining CPython premise. CR-S4-20 records the executor's account of the user's approval on that basis; this reviewer has the record, not the underlying conversation, and does not independently invent or expand that ruling. This meets the brief's instruction to assess the premise's honest statement rather than decide it anew.
2. **Initial namespace and pool:** R-G1-02, R-G2-12 and R-G5-05 separate the measured startup-map check from the initial-namespace requirement in `Thesis/Work/Design/sandbox-mediated-agent-execution/engine-requirements.md` §8. Host allocator configuration, other holders and privileged actors are not replaced by the NSS account check. No new deployment fact is inferred from the WSL measurements.
3. **EV-81 and EV-139:** R-G1-05's within-engine allocation rule and R-GX-02's matching of control records do not require a second-epoch supervisor to establish their local cuts. The previous-epoch case stays in R-GX-04, still conditional; source inspection of control loss and process exit does not turn test-runner cleanup into the missing supervisor.
4. **EV-125:** The incomplete queued-byte/FIFO requirement does not supply R-G3-03's identity-carry argument. Each Channel owns its writer; queued build functions retain the original RequestEntry, and the wire frames carry no execution label or local_agent_id. EV-242/257 and the checked object paths support that narrower attribution statement despite deferred encoding.
5. **EV-72, EV-128 and EV-129:** The engine/spawner separation measurement does not establish every spawner capability or holdings condition; the latter is not treated as a measured within-epoch cut. PR_SPEC_DISABLE is not silently described as PR_SPEC_FORCE_DISABLE, and the hardware class remains outside scope. A production seccomp allow-list is still absent; the receive/consumer cuts do not depend on it, while the compiler's unconditional restrictions are separately readable at `ExperimentLab/engine/native/sandbox/policy.c:16,30–51`.
6. **Spawner termination:** R-G4-01 names CAP_KILL as a deployment requirement, not a test-established universal capability fact. The checked safety cut is no uid release without the appropriate empty fact and retirement gate; error or lack of such a fact quarantines rather than proving emptiness, consistent with `ExperimentLab/engine/native/sandbox/spawner.c:365–393` and the lifecycle source.

No change to a disposition is warranted by these checks. Opus F-01–F-08's substantive repairs hold within the supplied rule; the two recheck repairs are visible at the review pin, including the earlier-library qualification in R-G2-11 and the line-number qualifications in R-G2-06/07. The findings below are additional precision repairs, not a revival of the removed-parser issue or of the recorded parser-classification decision.

## 3 Findings

Finding IDs below are local to this addendum, not the Opus record. Counts: P1 **0** · P2 **0** · P3 **3**.

### F-01 — P3 — The inserted engine-change qualification attaches the parse removal to the wrong file

**Locations:**
- `Thesis/Work/Submission/prove/uid-binding/work/groups/G1-launch-admission/R-G1-01.md:56`
- `Thesis/Work/Submission/prove/uid-binding/work/groups/G1-launch-admission/R-G1-02.md:59`
- `Thesis/Work/Submission/prove/uid-binding/work/groups/G1-launch-admission/R-G1-03.md:65`
- `Thesis/Work/Submission/prove/uid-binding/work/groups/G1-launch-admission/R-G1-05.md:64`
- `Thesis/Work/Submission/prove/uid-binding/work/groups/G1-launch-admission/R-G1-06.md:62`
- `Thesis/Work/Submission/prove/uid-binding/work/groups/G4-close-and-reclaim/R-G4-01.md:156`
- `Thesis/Work/Submission/prove/uid-binding/work/groups/G5-boundary/R-G5-05.md:169`

**Defect:** These evidence-limit sentences now read as a removal of the C-side body parse “of spawner.c,” because the inserted qualification separates that filename from the original “one test-build line” phrase. Commit 7b4ab727 removes the parse from `ExperimentLab/engine/native/sandbox/transport.c`, whereas the earlier test-only uid edit belongs to `ExperimentLab/engine/native/sandbox/spawner.c`; EV-265 remains correct and no route's cut changes.

**What would resolve it:** Attach the test-build qualification explicitly to spawner.c and the body-parse removal explicitly to transport.c in these seven sentences.

### F-02 — P3 — The SO_PASSCRED trace abbreviation conflates the option value with the syscall result

**Location:** `Thesis/Work/Submission/prove/uid-binding/work/groups/G5-boundary/R-G5-05.md:126`.

**Defect:** The EV-178 support cell abbreviates the observation as “setsockopt SO_PASSCRED = 0,” omitting that the option value was 1 and that zero was the successful syscall return. EV-178 and `ExperimentLab/engine/runs/20261019T010923Z-sandbox-pool-70000/pool70000-busy-process.trace:7` show `setsockopt(11, SOL_SOCKET, SO_PASSCRED, [1], 4) = 0`, so the shorthand can be read as disabling the option immediately before cloning despite the actual enabling observation.

**What would resolve it:** Write “SO_PASSCRED set to 1, setsockopt returned 0, before clone,” or retain the exact trace call.

### F-03 — P3 — Two route passages retain a removed request-file pointer and a superseded registration todo

**Locations:** `Thesis/Work/Submission/prove/uid-binding/work/groups/G2-receive-and-check/R-G2-06.md:109–110`; `Thesis/Work/Submission/prove/uid-binding/work/groups/G2-receive-and-check/R-G2-02.md:82–85`.

**Defect:** R-G2-06 still says validation rows 167 and 168 are not registered and directs the reader to change-requests-step4-a.md, which R-G2-02 also cites although that file is absent from the reviewed tree. Registry v9 already contains EV-247–EV-250 for the former gap and EV-251 for the split positions, with the requests merged into `Thesis/Work/Submission/prove/uid-binding/work/groups/G2-receive-and-check/change-requests.md:32–43`, so these passages describe stale follow-up work rather than the current evidence state without changing either disposition.

**What would resolve it:** Replace the removed-file pointers with CR-G2-4a-1/2 in the merged request file, mark the R-G2-06 registration gap superseded by EV-247–EV-250 and point R-G2-02 to EV-251 while retaining EV-174 as the run evidence.

## 4 out of scope for step 4, recorded

No new method finding is raised. The checker retains seven soft notices: the X-13/02 §7 inventory notice and six T-67 premise-departure notices for R-G5-03–R-G5-08; these are not new route evidence or grounds for changing the step-4 count. The decomposition was not re-derived, and no proposed run was promoted to an observation. The remaining supervisor, deployment, connector and CPython limits stay with their existing owners and records.

**Gate: may pass — no new P1 or P2 defect found under the supplied disposition rule; the three P3 findings are non-blocking precision repairs, and the judgment remains limited to the pinned prototype, its recorded premises and its checked evidence.**
