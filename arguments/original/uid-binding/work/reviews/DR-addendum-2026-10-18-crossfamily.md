# Design-revision review — Codex cross-family addendum

Date: 2026-10-18  
Reviewer: Codex, cold context; design review, not a fix  
Brief: `DR-brief-2026-10-18.md`  
Findings: **P1: 3 · P2: 2 · P3: 0**

## Review basis

Read the current design files, the requirements header and §0–§8, all seven approved workload definitions, the revision record, and BUILD-PLAN §1. Inspected both actual commit diffs with `git show 7bc77b82` and `git show 600d212a`, including a separate reread of the first commit's adapter diff. Actual checkout HEAD is `4d781a2d`, not the brief's `1fd71759`; the four design-file hashes match the revision record. The scoped working-tree diff changes only the workload document's navigation link, not its workload definitions.

Current-file abbreviations below, with current line numbers throughout:

| Abbreviation | File | Git blob, first 16 hex |
|---|---|---|
| CONN | `ExperimentLab/lab/experiments/w2/implementation/engine-design/connections.md` | `976a842da4be5c33` |
| RR | `ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md` | `b91408f27402d2d7` |
| SI | `ExperimentLab/lab/experiments/w2/implementation/engine-design/supporting-interfaces.md` | `fb57e5d4873abf1e` |
| OPT | `Thesis/Work/Design/sandbox-mediated-agent-execution/option-b-workload-per-engine.md` | `934f93e984a2d60c` |
| REQ | `Thesis/Work/Design/sandbox-mediated-agent-execution/engine-requirements.md` | `c7d3dad97f04b00dd` |
| LW | `ExperimentLab/lab/experiments/w2/workload-validation.md` | current working file |

No native implementation inspection, execution tests, identity-proof re-review, or route/preservation/spine rerun was performed. This record changes no design, task state, or implementation and makes no utility-pass claim.

## Findings

### F-01 — The Node receiver rejects the newly legal model result

- **File and line:** `ExperimentLab/lab/experiments/w2/implementation/engine-design/supporting-interfaces.md:468–471`.
- **Questions:** Q2, Q3, Q4.
- **Severity:** P1.
- **Defect:** The unchanged Node receive rule requires `result.value` to be exactly `{}` for both business actions, whereas RR:357,379–381 and the revised Pi conversion at SI:556–563 require accepting `{tool_calls:[...]}` for `model.generate`. A successful native tool turn therefore fails the shared response decoder before reaching the Pi bridge, preventing the required tool-driven files, exec, resource, followup and parallel paths from completing under the combined written rules.
- **What would resolve it:** Specify action-specific terminal-value validation in the Node receiver: retain the empty document result and admit the bounded native-tool model result before passing it to the Pi bridge.

### F-02 — The transport-release barrier still specifies an empty success value

- **File and line:** `ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md:480–487`.
- **Questions:** Q2, Q3, Q4.
- **Severity:** P1.
- **Defect:** Although RR:467–469 now promises a completion carrying validated tool calls, the subsequent mandatory release procedure preserves only completion evidence in `pending_completion`, clears the parser, and explicitly submits `Complete({})` while retaining an evidence-only small handle. That procedure neither preserves ownership of the validated call array across cleanup nor delivers the required nonempty success value, contradicting the native-result contract even if F-01 is resolved.
- **What would resolve it:** Define bounded immutable result-value ownership alongside completion evidence through the real I/O-release barrier, and publish that original value exactly once afterward, including the cancellation/late-result disposal case.

### F-03 — Terminal tool-call output has no inbound observation or output-evidence mapping

- **File and line:** `ExperimentLab/lab/experiments/w2/implementation/engine-design/supporting-interfaces.md:120–131,153–155`.
- **Related location:** RR:379–381,455–478; SI:98,150–165.
- **Questions:** Q2, Q4.
- **Severity:** P1.
- **Defect:** Native tool calls are deliberately not emitted as chunks and instead travel in `Complete.value`, but E-09 defines `post_read` and its payload borrow only for `Chunk`/`read_chunk`, while E-07's specified output hash and byte count cover generated text only. A tool-call-only success can consequently deliver generated data without the required inbound observation and with empty-text output evidence, weakening the existing no-observation-bypass rule rather than merely changing its wire encoding.
- **What would resolve it:** Define the bounded representation, digest/length accounting, original-execution flow event and observation-before-queue step for structured terminal output, without adding semantic interpretation of tool arguments.

### F-04 — Trusted tool definitions have no unambiguous catalog schema

- **File and line:** `ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md:372–379`.
- **Related location:** SI:254–257,412–425,504,613–617.
- **Questions:** Q2, Q4.
- **Severity:** P2.
- **Defect:** E-07 requires full `name`/description/`input_schema` definitions from the execution's trusted RuntimeDescriptor/LaunchPlan, but E-10 specifies neither their precise catalog field/reference nor its closed schema, and its adapter configuration describes a tool list while the registry rejects unknown fields. An implementer must therefore choose both where the connector's definitions live and how they are checked against the SDK-generated schemas used by Pi, rather than merely supply the remaining deployment values.
- **What would resolve it:** Specify one catalog-owned definition format/reference, its digest coverage and load-time validation, and the compatibility check tying it to the adapter's enabled tool names and schemas.

### F-05 — Tool-call IDs are conflated with two different wire-ID rules

- **File and line:** `ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md:377–378`.
- **Related location:** CONN:481–485; RR:357,405–407; SI:543–544,561–563.
- **Questions:** Q4.
- **Severity:** P2.
- **Defect:** The instruction that returned tool-call `id` obey the “wire ID rules” does not distinguish E-02's general bounded ASCII IDs from its additional positive-decimal restriction for the field named `id`, although the Pi bridge preserves the provider's tool-call ID unchanged. Thus an opaque ID such as `call_example` is accepted under one reading and rejected under the other, leaving the connector, result decoder and subsequent `tool_call_id` history mapping without one agreed format contract.
- **What would resolve it:** Define a separate tool-call ID type and use its explicit syntax consistently in returned calls, assistant history and tool results, keeping it distinct from engine request IDs.

## Q1 — Faithful transcription checked

Read all fourteen §0 requirements and traced every item claimed by REQ:28–42 to its underlying must and revised sentence. The following is transcription coverage, not a finding that the requirements have been implemented or that the uid-binding argument has been re-proved.

| Absorbed item | Source must, current REQ line | Revised design sentence / disposition |
|---|---|---|
| Pre-read check uses Session state | §3, 159 | CONN:459–460 explicitly forbids `recvmsg` after close step 1 sets CLOSED. |
| Process-terminal record retains uid/lease occupancy while storage is unreleased | §4, 186 | CONN:104 explicitly includes that record at spawner admission and names the availability cost. |
| Stop for a never-received record is a control fault | §4, 191 | CONN:105 selects fault, not timeout or a fabricated `never_created` fact; E-04 control-loss quarantine remains applicable. |
| Close steps 1–4 are one decision | §5, 200 | CONN:838 forbids yielding between the four steps; CONN:606–607 defines the local decision boundary. |
| Lease release waits for close step 2 | §5, 201 | CONN:838–840 explicitly adds deregistration and fd closure to the release gate. |
| Parse and admission are one decision | §7, 225 | CONN:462–463 joins parsing and `admit_request` without yielding; later asynchronous prepare is not included. |
| Post-drop uid reread before SEALED | §8, 251 | CONN:108–109 requires `getresuid`, equality of all three values to the recorded uid, and FAIL/no SEALED on mismatch; original per-step failure handling remains at CONN:303–307. |
| Receiver-generation construction and retirement | §2, 145 | CONN:99–101 specifies a per-install, epoch-monotonic value, retirement at step 2 and subsequent fd reuse. |
| Parser/FrameReader memory-safety implementation method | §3, 172 | CONN:459–464 specifies receiver-exclusive access, Python `json`, and sanitized/fuzzed FFI transport; this is the chosen approach, not evidence that the memory-safety obligation is already met. |
| Kill/wait error notification | §4, 192 | CONN:106–107 names `spawn_failed(stage=reap,error_code=os_error)` and quarantine, not empty; the control enums already admit these values at CONN:137–140. |
| Write-once reservation fields in one decision | §2, 136 | CONN:95–96 states the field set and T-01 decision; expected uid still comes from the lease, not an observed sender. |
| No inheritance across executions, including an old occupied runtime slot | §2, 139 | CONN:97–98 states both recurring-name and slot/object cases. |
| Channel-to-Session link installation/clearing | §2, 146 | CONN:99 says write once at T-09, clear by object only at close step 2. |
| Limits of local lease checks / exclusive-pool premise | §1, 129 | CONN:102–103 explicitly excludes detection of previous-epoch survivors and external pool-uid holders. |
| Event-library deregistration property | §3, 160 | CONN:461–462 requires the property and refuses a library that does not satisfy it. |
| FrameReader receiver-exclusive access | §3, 171 | CONN:460–461 excludes workers, hooks and other Channels; the original reset/discard rules remain at CONN:427–457. |
| All consumers carry the original context by reference | §7, 223 | CONN:549–551 names admission, prepare/authorize, dispatch, handler and recording, and forbids reusable-key lookup; CONN:633–635 retains `ValidatedRequest` admission. |
| Per-execution provider selection | §7, 240 | RR:384–385 explicitly selects `execution_id`/object reference, never uid or local agent name. |
| Local model as external deployment process | §7, 239 | RR:385–387 excludes pool uids, execution process domains and engine lifecycle management; RR:807–814 retains deployment-owned instance/state isolation. |

The seven stricter choices have a stated reason/authority: the explicit user ruling in REQ:28–35 and the revision supplements, rather than an unexplained strengthening. No additional lost absorption choice was identified. Memory safety, event-library behavior and the post-drop check still need implementation evidence; naming Python, sanitizers or fuzzing does not establish the result. Production S2 and the supervisor's domain-empty method remain deployment/implementation inputs, not silently completed checks; BUILD-PLAN:10–18 expressly defers production S2 and restart recovery.

## Q2 — Conflicts with retained text checked

Checked E-01 control matching and failure enums, E-02 parsing/admission, E-03's single writer and request/TaskCall barriers, E-04 close/release, E-08 runtime/workspace ownership and E-09 event ownership. The substantive retained-text conflicts are F-01–F-03; F-04 is an incomplete cross-file interface.

The engine allocator becoming free before the spawner releases a storage-held record is not by itself a contradictory identity rule: the spawner can refuse an early new spawn, and normal re-admission can wait for `runtime_status=released` (CONN:104,184–199,832–840; RR:634–651,677–681). No old callback is thereby permitted to address the new execution. Likewise, one-decision parsing/admission does not prohibit asynchronous prepare, and one-decision close steps 1–4 do not wait for reap or file cleanup. The new reap-error message remains non-empty evidence and does not release a quarantined lease.

Applied the explicit October 4 internal-grant override instead of treating retained agent-facing `grant_ref` examples as current requirements (OPT:69–72; CONN:3–4,479; RR:132–133). Applied OPT:348–357's supersession of the older text-only rationale. Historical acceptance records and explicitly superseded passages were not used to invent current conflicts.

## Q3 — All seven normal workload paths checked

These are design walks, not executions; the native tool-result blockers are separated from the stricter lifecycle choices and from missing deployment inputs.

| Workload | Normal path checked | Can it complete under the written design? |
|---|---|---|
| W2-LW-start (LW:34) | Reserve workspace/uid → independent runtime copy → SEALED/prepared/COMMIT → Pi initialization and hello/welcome → TaskCall → authorized real model request → response. | A first text-only final response has a completion path, given valid deployment inputs; a first response requesting a tool hits F-01/F-02. Startup/identity choices themselves introduce no impossible wait. |
| W2-LW-files (LW:35) | Model tool selection → Pi read/ls/grep/find/edit/write in `/work` → tool results in history → next model turn → independently checked artifacts. | **No consistent native-tool path as written:** F-01/F-02 stop the tool-selection handoff. Workspace operations otherwise use the pre-granted mount capability, not invented engine handlers. |
| W2-LW-exec (LW:36) | Pi writes Node program → `w2_shell` spawns the program/assertions → stdout/stderr/exit and file-I/O cleanup → model continuation → artifact checks. | **Blocked by F-01/F-02** before the required tools run; the specified shell/Tini cleanup path itself can finish under the deployed policy and budgets (SI:580–611,622–669). |
| W2-LW-resource (LW:37) | Model selects `w2_read_document` → fresh `document.read` through the original current call and grant → chunks/empty document result → bounded file save → model continuation. | **Blocked by F-01/F-02** on model tool selection; the subsequent document handler and its legitimately empty result are coherent. |
| W2-LW-followup (LW:38) | First TaskCall reaches its terminal/release barriers → Session remains ACTIVE → new TaskCall with the same valid TaskBinding/grant → Pi retains history and `/work` → artifact adjustment. | Lifecycle continuation **can complete**; the actual tool-using task remains blocked by F-01/F-02. No-inheritance applies between executions, not between calls in one execution (CONN:697–738; RR:176–183; SI:501,553–555,690–691). |
| W2-LW-parallel (LW:39) | Separate workspaces/static uids/leases, runtime copies and Pi instances → concurrent model and local-tool work → responses to original Channels. | The required files/exec work is **blocked by F-01/F-02**, not by serialization of state decisions. Otherwise it needs at least two configured workspace/uid mappings, sufficient runtime capacity and suitable provider partitions; the 16-execution and 16-global-model-slot limits allow several executions (CONN:745–756; RR:575–585,664–681,825). |
| W2-LW-finish (LW:40) | Finish resolved TaskCall → DRAINING/shutdown → bye/EOF → close steps 1–4 → actual reap/empty → reference and runtime-storage release → fresh execution/new copy/new Session/Channel/grant → remount persistent `/work`. | The teardown/remount path **can complete** once the preceding task has completed; that task's tool path has the blockers above. Wait for storage-held spawner occupancy to clear before restarting with the workspace's fixed uid: slower reuse, not permanent failure (CONN:104,838–853; RR:541–590,677–681; SI:703). |

The persistent files are engine-managed workspace contents, explicitly reauthorized/remounted under a new WorkspaceLease; they are not inherited old Session, Channel, Grant, callback, runtime-copy or Pi-memory objects. Thus CONN:97–98 does not require deleting those files or make W2-LW-finish impossible. Pool exhaustion, retained storage, insufficient context budgets and an unselected production configuration must be reported as their actual availability/deployment conditions, not as proof that the healthy normal path is impossible. No fixed model response was counted as real-model utility.

## Q4 — Native tool calling checked end to end

Followed model arguments/history and launch-tool definitions → frozen E-06 outbound body → fixed provider mapping → bounded SSE `delta.tool_calls` assembly → format checks → completion/release → E-02/Node result decoding → Pi `toolCall`/`toolResult` history → the next model request. Findings F-01–F-05 identify the missing or contradictory links; the new surface is not yet an internally complete end-to-end contract.

The intended semantic boundary is otherwise consistent: RR:377–383 checks bounded structure and declared names, explicitly not argument-schema semantics; SI:556–575 performs tool-schema interpretation inside the untrusted adapter. The connector does not acquire authority from a generated resource/grant or call an engine handler merely because the model named a tool. A protected document action must be a new validated, admitted and authorized request through CONN:633–646 and RR:261–278, while local workspace tools use an already-granted sandbox capability. No authorization-bypass path was established by this review; the observation gap in F-03 must not be misreported as a grant bypass.

SSE finish/error/DONE handling, late-result suppression, no automatic retry, frozen provider/credential selection, stateless completion and exclusion of logprobs remain compatible in intent. A pinned provider's actual streaming behavior and Pi/Node compatibility are still acceptance inputs, not verified by this document review. BUILD-PLAN §1 stubs the real connector and defers Pi, but includes real request/result handling and E-09 and permits a tool-call-producing stub; that does not supply the missing native-result ownership/recording contract.

may not pass — the design still contradicts native tool-result delivery and omits its required inbound observation/output-evidence mapping (F-01–F-03); resolve those contracts before treating it as the engine-build specification, rather than relying on the stub/deferred-Pi scope to hide them.
