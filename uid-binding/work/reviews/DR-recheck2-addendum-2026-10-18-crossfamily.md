# Targeted recheck 2 — Codex cross-family addendum

Date: 2026-10-18  
Reviewer: Codex, cold context; read-only review, not a fix  
Brief: `DR-recheck2-brief-2026-10-18.md`  
Revision checked: `c0aef66b00db1c5b47a442aef38f431755a109c3` (HEAD).  
Recheck counts: **resolved 12 / partly 0 / not resolved 0**.  
New findings introduced by this commit: **P1 0 / P2 1 / P3 0**.

Read the actual `git show c0aef66b` diff, including the newly committed earlier recheck records and brief; reread separately where combined output was truncated. Checked the current changed files and the surrounding ownership, control, initialization, receive, provider-mapping, registry and storage contracts. The five reviewed design/build/revision files match the commit: `git diff c0aef66b -- <these paths>` is empty, and their working-tree blob hashes are below. The three current design hashes also match BUILD:32 and REV:109–111.

No C code, excluded `implementation/engine-design.md`, uid-binding route/spine files, or R1–R3 sufficiency argument was reviewed. No engine, provider, workload, native build or fault-injection test was run. One in-memory JSON size calculation checks the budget repair; it is not implementation or workload evidence. Only this record is written; no fixes or commit are made.

All line numbers below refer to the current files at the reviewed commit.

| Alias | File | Git blob, first 16 hex |
|---|---|---|
| CONN | `ExperimentLab/lab/experiments/w2/implementation/engine-design/connections.md` | `a18c27dd820cb902` |
| RR | `ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md` | `b92ccda479c95eb8` |
| SI | `ExperimentLab/lab/experiments/w2/implementation/engine-design/supporting-interfaces.md` | `b5e189c19d399d6e` |
| BUILD | `ExperimentLab/engine/BUILD-PLAN.md` | `e155b846de4ea4fb` |
| REV | `Thesis/Work/Submission/prove/uid-binding/design-revision-2026-10-18.md` | `67416c84479cc188` |

## 1. Requested items

The three decisions are accepted as the specified choices, not reconsidered. Counts cover twelve checklist rows: the brief separately lists N-09's uncertain-submission qualification and its retained-copy clause, so they have separate rows; coincident Opus/Codex findings are counted once. “Resolved” closes the specified earlier defect, not a different defect introduced by its remedy or an outstanding implementation check.

| Item | Where c0aef66b addresses it; relevant surrounding contract | Verdict | Reason |
|---|---|---|---|
| Opus N-03 = Codex N-02 — reused spawner kill/wait-error behavior | CONN:121–126,151; BUILD:34; CONN:876–877,894,922–936 | resolved | E-01 now explicitly states the silent kill error after an earlier spawn_failed and its stop-plus-5,000 ms quarantine fallback, and the wait-error control-link loss affecting all executions; BUILD defers to that contract and neither outcome establishes empty. |
| Opus N-02 — first-build sender_pid / received_at sources | CONN:467,491–493,570; SI:93 | resolved | The first-build exception fixes sender_pid to null and received_at to whole-frame handover to Python, retains C's first-byte assembly bound, and is referenced from VerifiedContext; no additional C metadata return is promised. |
| Opus N-09, uncertain-submission clause — qualify the unknown-stop rationale | CONN:114–120; unchanged CONN:359–360,854–857 | resolved | The supplement explicitly admits a correct engine's uncertain-send stop, restricts local send errors to known-zero-send cases, and leaves the submitted/uncertain close path and global fault consequence intact. |
| Opus O-F04 partly = Codex N-01 — budget the provider-mapped form | RR:378; SI:557–558; RR:95,245–250,407–413 | resolved | Both adapter descriptions now measure mapped messages, including argument-string escaping, and the tool set including function wrappers, plus the stated overheads; prepare independently enforces the frozen-body cap. |
| Opus N-01 — distinguish storage/control-live from uid/lease occupancy | CONN:108–113; CONN:179,203–218 | resolved | The added clause explicitly keeps the empty-but-storage-pending record live for control, capacity and storage while exempting it only from uid/lease occupancy at spawn admission. |
| Opus N-04 — numeric limits on model-generated tool arguments | RR:380,457–459; CONN:513; SI:460–477 | resolved | The connector must reject out-of-range integers and nonfinite numbers as upstream_error before returning tool_calls, rather than emitting a value the Node receiver rejects as a frame fault. |
| Opus N-05 — startup_deadline writer and write-once time | CONN:100,335–338 | resolved | startup_deadline is explicitly written once by the executor at spawn enqueue; the existing calculation before enqueue and nonresetting absolute deadline remain compatible. |
| Opus N-06 — absent terminal-value chunk_index | SI:106,120 | resolved | terminal_value post_read now omits chunk_index, agreeing with the absent-field rule instead of prescribing null. |
| Opus N-07 — runtime-copy digest and connector's declared-tool-set reference | SI:417,425–430; RR:380 | resolved | The runtime-tree file must match tool_definitions_digest at combination checking, and the connector receives the same declared set used by freeze_operation through CandidateOperation references. |
| Opus N-08 — five-check count and reread injection mechanism | BUILD:70–83,11–15 | resolved | The five named checks remain five, the extra reread check is separate, and uid.reread is specified under W2_TESTING rather than as another production change; the newly added worker-case oracle has a separate defect, M-01. |
| Opus N-10 — residual text-bridge/local-instance wording | RR:478,899,1001,1179; RR:811–818 | resolved | The current sentence says complete generation result, and all three historical-record notes now also supersede the supervisor-instance-admission judgments in favor of the deployment-precondition ruling. |
| Opus N-09, retained-copy clause — remove the incorrect comparison | CONN:110–111; RR:638–639,673–677 | resolved | The retained-copy/workspace claim is removed from the strict-versus-loose comparison without removing the store-wide retained/fault admission restriction that applies under either reading. |

**Budget spot-check.** Compact UTF-8 JSON with one 18,000-byte user text and two historical write calls, each containing a 6,000-backslash content string, gives 42,219 bytes of args-form messages, individual calls of 12,077 bytes, and 24,157 bytes for their call array. With a 109-byte mapped tool set, the former preflight total is 43,352 bytes, while the mapped body is 66,572 bytes and exceeds 65,536; applying the revised mapped-message accounting plus 64 bytes per message and the 1 KiB allowance gives 67,565 bytes and therefore rejects locally as intended. This checks the earlier escaping failure mode only, not all configurations or a real provider.

## 2. New findings introduced by c0aef66b only

### M-01 — The new storage-worker injection inherits an agent-bootstrap result oracle — P2

- **File and line:** `ExperimentLab/engine/BUILD-PLAN.md:80–83`, especially the newly added file-worker case at lines 81–82.
- **Related contract:** CONN:220–230,245–247; RR:700–713.
- **Defect:** The revised check applies the same `FAIL(stage=uid)`, no SEALED/prepared, and spawner `spawn_failed` plus `execution_empty` expectations to both the runner-bootstrap injection and the newly added file-worker privilege-drop injection. But the single storage worker initializes before control_ready permits any spawn (CONN:220–230), and its exit expressly is not an agent's execution_empty (RR:711–713), so the worker-startup case has no corresponding execution/agent-bootstrap exchange and an implementer must choose between the new test oracle and the existing initialization-failure contract.
- **What would resolve it:** Split the observations by injection target: retain the per-execution FAIL/spawn_failed/empty sequence for runner bootstrap, but require worker initialization failure/EOF, no control_ready or spawn admission, and the prescribed cleanup for the worker case, without inventing a per-execution empty notification.

This is a new verification-contract inconsistency from adding the worker case, not a reopening of the chosen uid-reread change or an inference about unread C implementation. The original N-08 count/mechanism omissions are fixed; the new worker-specific expected result is not.

## 3. Gate

may pass — engine build step 1 now has an authoritative kill/wait-error contract, explicit storage-live versus uid-occupancy semantics, and the unchanged uncertain-submission path with its consequence stated; M-01 is a mismatch in the additional negative-check oracle, not an unresolved step-1 runtime choice, and must be corrected before that reread check is accepted.
