# Design-revision recheck — Codex cross-family addendum

Date: 2026-10-18  
Reviewer: Codex, cold context; read-only design review, not a fix  
Brief: `DR-recheck-brief-2026-10-18.md`  
Revision checked: `820d4529`, with the count correction in `7f49fee7` (checkout HEAD).  
Recheck counts: **resolved 23 / partly 1 / not resolved 0**.  
New findings: **P1 0 / P2 2 / P3 0**.

Read both actual `git show` diffs, rereading the changed-file diffs separately where the combined output was truncated; both earlier review records; the current changed passages and surrounding control, lifecycle, resource, adapter and observation contracts; the seven workload definitions; and BUILD-PLAN. The current design/build files match the revision blobs below; the revision record matches the subsequent count-correction commit. The workload document's working-tree change is a navigation link, not a changed workload. No native C inspection, engine/provider execution, identity-argument re-review, or route/preservation/spine rerun was performed. One in-memory JSON byte-accounting calculation checks N-01; it is not a workload or implementation test. Only this review record is written.

All line references below are to the current files, not the earlier reviewers' line numbers.

| Alias | File | Current git blob, first 16 hex |
|---|---|---|
| CONN | `ExperimentLab/lab/experiments/w2/implementation/engine-design/connections.md` | `e0d231a3265bc775` |
| RR | `ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md` | `aa1d81a0278e4ba5` |
| SI | `ExperimentLab/lab/experiments/w2/implementation/engine-design/supporting-interfaces.md` | `530d165a2fafb05d` |
| OPT | `Thesis/Work/Design/sandbox-mediated-agent-execution/option-b-workload-per-engine.md` | `564173bf552b8417` |
| REQ | `Thesis/Work/Design/sandbox-mediated-agent-execution/engine-requirements.md` | `66806a07d271778a` |
| BUILD | `ExperimentLab/engine/BUILD-PLAN.md` | `adf503cc2f91e846` |
| REV | `Thesis/Work/Submission/prove/uid-binding/design-revision-2026-10-18.md` | `e15b79a37bc547cf` |

## 1. Recheck of the 24 distinct findings

O-Fxx refers to the Opus record; C-Fxx refers to the earlier Codex addendum. The two coincident pairs each occupy one row. The three user rulings are accepted as the specified resolution, not reopened as defects. A resolved row closes the original defect, not an implementation acceptance obligation or a different new defect.

| Finding | Where the revision addresses it: current file and line | Verdict | Reason |
|---|---|---|---|
| O-F01 — successor refused while old storage remains | CONN:108–112; RR:543–554,583–591,652–680 | resolved | The user-selected looser admission rule removes the old record's uid/lease occupancy after empty; storage, workspace references and global capacity remain separate gates, without inventing an engine wait. |
| O-F02 = C-F04 — tool definitions have no catalog home | SI:412–430; RR:375–381 | resolved | RuntimeDescriptor now references a digested, closed-format tool-definition artifact loaded read-only by the engine, with startup comparison against the adapter's actual definitions. |
| O-F03 — connector attachment versus single freeze point | RR:243–250,377–378; SI:548–552 | resolved | The original request's object-reference chain supplies the tool set to freeze_operation; tools enter body_bytes/body_hash and the connector sends those bytes unchanged. |
| O-F04 — input limits do not add up | RR:95,378; SI:414,556–562 | partly | max_input_bytes and tool-set accounting are now named, but the new adapter formula does not account for the provider mapping's history-argument string escaping; N-01 leaves a passing local budget check followed by prepare rejection. |
| O-F05 = C-F03 — tool output absent from completion/flow evidence | RR:474–487; SI:98,120,129–159 | resolved | Tool-call digest/length, one terminal_value post_read before queueing, and a bounded synchronous payload borrow now cover the structured output without treating it as a text chunk. |
| O-F06 — current acceptance rows still use the text bridge | SI:707–708 | resolved | The rows now trace frozen catalog tools, native Complete values, adapter schema validation and role-tool results. |
| O-F07 — undefined event labels and fields | CONN:95–105,472–475; BUILD:79 | resolved | RESERVED row creation and prepared-fd installation replace T-01/T-09, epoch comes from execution_id, mutable fields are enumerated, and the pre-read check names Session.admission. |
| O-F08 — competing Channel writers | CONN:81,103–105,840–842 | resolved | Installation/phase/closure belong to the state executor, frame_reader to the receiver, and frame_writer to its single writer. |
| O-F09 — memory-safety activity mistaken for the property | CONN:478–482; BUILD:76 | resolved | The design locates FrameReader in C, states the bounded FFI/no-internal-pointer obligation, distinguishes sanitizer/fuzz evidence from the property, and requires production flags/source identity; implementation evidence remains outstanding. |
| O-F10 — unspecified Python JSON configuration | CONN:456–459,482–485 | resolved | Strict UTF-8/BOM handling, duplicate-key and constant rejection, and surrogate/depth/element/integer checks now accompany the stdlib parser choice. |
| O-F11 — second reap-stage spawn_failed has undefined treatment | CONN:118–120,145,162–168 | resolved | The specific receive rule admits a reap error after an earlier startup failure and quarantines rather than treating that second message as a conflicting terminal; the newly documented producer exception is separately N-02. |
| O-F12 — unknown-stop fault carrier/blast radius | CONN:113–117,914–928 | resolved | The ruling now explicitly faults/closes the control link, stops all records, closes engine rows and quarantines unconfirmed leases, and states the first-build restart cost and rationale. |
| O-F13 — missing supervisor-method deployment pointer | REQ:43–45; RR:887–888 | resolved | The header now points to a real deployment-input entry that names the method as unresolved and excludes restart recovery from the first build. |
| O-F14 — reuse plan contradicts the selected admission/bootstrap readings | BUILD:10–14,31–35,80; CONN:108–122 | resolved | The looser admission ruling removes the proposed admission-code change, while BUILD now explicitly plans the uid reread, the nonidentical native version, a fresh regression run and positive/negative checks; N-02 is a different new reuse-note inconsistency. |
| O-F15 — local-instance lifecycle/cache ownership | RR:387–389,811–818,885–886 | resolved | Shared-instance no-cross-request-cache and exclusive-instance clearing/nonreuse are explicit deployment preconditions, not engine checks; deployer ownership and fixed-version startup evidence are stated. |
| O-F16 — empty tools and stop-with-tool-fragments | RR:410–411,460–462 | resolved | Empty sets omit tools/tool_choice, and stop after assembled tool-call fragments is upstream_error rather than silently dropping or executing them. |
| O-F17 — serialized result size and assembly buffer | RR:359,380–381,483,832 | resolved | Returned-call limits are measured on serialized JSON and a distinct bounded SSE assembly buffer is included in the capacity table and pending-completion lifetime. |
| O-F18 — frozen-tag statement versus revised local-instance row | REQ:28–30,242–243,293–295 | resolved | The header explicitly identifies the single revised requirement/tag exception; the other tags/locations remain the freeze index, not an assertion of current implementation status. |
| O-F19 — reread placement and stale Option B wording | CONN:121–122; OPT:246–257; BUILD:12–13 | resolved | All three place getresuid after setresuid and before seccomp/SEALED, with FAIL on unequal values; no new S2 allowance is assumed. |
| O-F20 — close step 2 when no Channel existed | CONN:859–863 | resolved | The step-2 condition is explicitly vacuous for never-installed Channels, late prepared fds are closed, and dropping unsent bytes is distinguished from peer consumption. |
| O-F21 — stale bridge labels and historical verdicts | RR:354,899,1001,1179; SI:509,722,837,948; CONN:1498,1732 | resolved | The current heading/API alias are renamed and the historical text-bridge judgments are explicitly superseded; the excluded engine-design.md is not used as a contrary current input. |
| C-F01 — Node rejects a legal nonempty model result | SI:473–477,563–570 | resolved | The receiver now validates action-specific terminal values, preserving {} for document.read and admitting the bounded model tool-call value before Pi conversion. |
| C-F02 — release barrier discards the tool-call value | RR:482–501 | resolved | The immutable bounded value survives parser/I/O cleanup in pending_completion, is submitted once after ProviderLease release, and is discarded rather than delivered when cancellation/deadline/closure has already won. |
| C-F05 — tool-call ID conflated with engine request ID | RR:379,407–409; SI:568–570 | resolved | A separate bounded ASCII tool-call ID is explicitly shared by returned calls, assistant history and tool_call_id, without E-02's decimal request-ID restriction. |

### Additional question: W2-LW-finish and the looser reading

**The normal finish/restart path can now complete, subject to the already-written capacity and deployment conditions.** After finish/drain, close and actual empty, the uid can be re-leased; the workspace additionally waits for its old engine I/O/references to finish (CONN:838–869; RR:543–554). A new execution gets new identity objects, a new copy_id and different runtime inodes while remounting the retained workspace files (RR:583–598,617–628). CONN:108–112 no longer makes ordinary outstanding deletion a reason to refuse that same numeric uid.

The remaining restrictions are not a hidden reintroduction of uid occupancy:

- **Execution slot:** the old slot stays occupied until CLOSED, empty, request/TaskCall/workspace-reference cleanup and runtime view released (CONN:197–202,766; RR:652–654).
- **Spawner record:** an empty-but-storage-live record still consumes one of the 16 live records, becoming a tombstone only after empty and released have been sent and its outstanding ownership has cleared (CONN:173,204–212). Live-for-capacity does not mean uid-held-for-admission under the new explicit exception.
- **Storage:** both copies remain fully charged until their own release, with at most 16 copies and the configured byte/node/physical-space gates (RR:666–683; SI:303–305). The configuration admits at least two maximum-sized copies, not an unbounded restart backlog.
- **Storage failure:** retained storage still blocks new admission globally (RR:638–639,673–677), and a full engine/record/store budget still permits bounded refusal. The ruling does not promise immediate restart under saturation or a storage fault, and it adds no automatic wait/retry.

SI:710 describes a valid serialized path that waits for the old slot's complete release before starting the next execution; it does not impose a same-uid storage-release gate on every otherwise-admissible spawn. No remaining current CONN/RR/SI sentence was found that requires the stricter same-uid admission reading. This is a design walk, not a measured W2-LW-finish pass or a new identity-proof conclusion.

### Additional question: catalog → model → adapter, evidence and semantics

The repaired ownership/delivery path is coherent: SI:412–430 supplies the checked tool artifact; RR:243–250 freezes it with messages through the original request's references; RR:407–416 defines the provider mapping; RR:453–471 assembles and format-checks bounded calls; RR:474–501 preserves their value/evidence through actual I/O release; SI:120,129–159 requires the original-execution terminal-value observation before queueing; CONN:687–705 supplies demand credit, original sink, late-result suppression and writer ownership; SI:476–477,563–575 decodes, validates arguments against the tool schema and returns tool results into history.

The connector checks declared-name membership, syntax and bounds, not argument-schema semantics or generated instructions. Local tools use the pre-granted sandbox workspace capability; the protected-document tool issues a fresh document.read through the original verified session/current call and E-06 authorization (RR:263–279,379–385; SI:510–511,580–582). Neither a generated resource name nor an observer result grants authority. No new connector-side semantic execution or bypass was found. The unresolved qualification is the new preflight **size calculation** in N-01, not the previously missing catalog/value/evidence links; in-budget native tool turns now have the written return path.

### Additional question: BUILD-PLAN alignment and reused spawner behavior

- **Sections 1/2/5:** BUILD:10–14 and 80 now carry precisely the planned getresuid change and its checks, including failure before SEALED/prepared and a fresh sandbox regression. The no-longer-required strict admission change is correctly absent. BUILD:31–32's explicitly third-revision blob values all match git hash-object and the actual commit; the older values at 27–29 are followed by that dated update, not silently used as the new baseline. The C change is planned, not claimed implemented.
- **Wait error:** BUILD:33–34 is compatible with E-01/E-04. Receiving a valid second reap failure need not itself be a protocol conflict; the spawner can then end the control epoch, at which point CONN:914–928 closes all rows/quarantines unconfirmed leases. Failure to deliver the best-effort record does not manufacture an empty fact. CONN:886's same-healthy-epoch late-empty release option is unavailable once that epoch is lost.
- **Kill error after an earlier failure:** the 5,000 ms fallback in BUILD:34–35 exists at CONN:868–869 and safely preserves occupancy until real empty, but the plan's explicit suppression of the reap-error report is not reconciled with CONN:118–120/145's reporting contract. This is N-02; documenting the timeout does not by itself document an exception to that contract. The issue is what the first build must implement/test, not a claim that timeout is being used as empty.

## 2. New findings introduced by this revision

### N-01 — The new adapter budget measures messages before a size-changing provider mapping

- **File and line:** `ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md:378`; `ExperimentLab/lab/experiments/w2/implementation/engine-design/supporting-interfaces.md:556–558`.
- **Related contract:** RR:95,245–250,407–413; SI:414.
- **Severity:** P2.
- **Defect:** The new `64KiB - tool_set_bytes - 1KiB` rule budgets the adapter's serialized E-07 messages, but the provider mapping adds function wrappers and converts each historical arguments object into a JSON string that must itself be escaped, so this is not a bound on the frozen outbound body even if tool_set_bytes is already measured in its provider form. An in-memory compact-JSON calculation using two bounded historical write calls gives 44,277 bytes of input messages, individual calls of 14,054 bytes and 28,111 bytes in total, and a 44,454-byte request, all within the relevant input limits and the new 64,365-byte budget with a 147-byte mapped tool set, yet the mapped provider body is 72,657 bytes and must be rejected by prepare.
- **What would resolve it:** Define the preflight budget over the provider-mapped serialized messages, including argument-string escaping, define tool_set_bytes in the same outbound representation, and bound the remaining fixed fields consistently with the descriptor/grant limits and the 64KiB body cap.

This is the newly introduced attempted remedy for O-F04, not a new report of the old missing tool-set budget. The calculation uses only ordinary JSON serialization in memory, with no engine, provider, native code or repository fixture modification; it demonstrates a contract-sizing inconsistency, not an authorization bypass or a measured failure of the approved small workload fixtures.

### N-02 — The new reuse note suppresses the reap-error report still specified by the design

- **File and line:** `ExperimentLab/engine/BUILD-PLAN.md:33–35`.
- **Related contract:** BUILD:3–4,11–14; CONN:118–120,145,868–886; REQ:38–39,195.
- **Severity:** P2.
- **Defect:** The newly added reuse note says that a kill error after an earlier spawn_failed sends no further record and the engine instead waits for the empty deadline, whereas the revised E-01 supplement/control table still describe kill/wait errors as spawn_failed(stage=reap) reports and expressly support one following the earlier failure. BUILD says the design remains authoritative and permits only the uid-reread C change, leaving an implementer to choose between the documented reused producer/timeout behavior and the design's error-notification behavior without an explicit exception or precedence rule.
- **What would resolve it:** Reconcile the producer contract in E-01 and BUILD by explicitly adopting and testing the silent-duplicate-kill/timeout exception, or by planning the reporting change and updating the one-C-change scope; retain E-04's requirement for real empty before release in either case.

The original O-F11 consumer-side ambiguity is resolved: if a second reap failure arrives, its treatment is explicit. N-02 concerns the separate new BUILD promise about whether the producer sends it; the timeout remains fail-closed, and no premature uid release is established by this finding. The wait-error/control-loss note is not itself a new finding.

## 3. Gate

may not pass — starting engine build step 1 still requires one authoritative kill-error reporting/timeout contract (N-02), because that step implements the real control and lifecycle path rather than a model stub; the normal finish/restart and planned uid-reread blockers are resolved, while N-01 remains a separate native-model budget issue to settle before that path's acceptance.
