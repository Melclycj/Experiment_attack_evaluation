---
role: design-revision recheck record (cold context, Claude Opus)
date: 2026-10-18
brief: DR-recheck-brief-2026-10-18.md
repo_head: 7f49fee7 (revision 820d4529, count fix 7f49fee7)
blobs_checked: conn e0d231a3265bc775 · rr aa1d81a0278e4ba5 · si 530d165a2fafb05d · optb 564173bf552b8417 · ereq 66806a07d271778a · BUILD-PLAN adf503cc2f91e846 (git hash-object = git rev-parse HEAD:<path> for all six; working tree equals HEAD for these files)
---

# Design-revision recheck — third revision of 2026-10-18

Reviewer: Claude Opus, cold context. Read: `git show 820d4529` (all design-file hunks) and `git show 7f49fee7`;
the two earlier review records; the revision record § Third revision; and in the current files conn 70–230,
300–365, 425–576, 835–935; rr 90–100, 225–285, 353–497, 535–710, 795–895; si 80–170, 225–345, 396–580, 700–716;
ereq 20–50, 160–260, 290–305; optb 246–260; BUILD-PLAN in full. For the BUILD-PLAN question I read (did not
review) `native/sandbox/transport.c` 90–260 and `transport.h` 16–25, only to check the plan's "one C change"
claim against the receive design.

File abbreviations: `conn`, `rr`, `si` = connections.md, resources-routing.md, supporting-interfaces.md under
`ExperimentLab/lab/experiments/w2/implementation/engine-design/`; `optb` = option-b-workload-per-engine.md;
`ereq` = engine-requirements.md (both under `Thesis/Work/Design/sandbox-mediated-agent-execution/`);
`BP` = `ExperimentLab/engine/BUILD-PLAN.md`. Line numbers are of the current files.

Counts: resolved 23 · partly 1 · not resolved 0. New findings: P1 0 · P2 4 · P3 6.

## 1 Findings checked

| finding | where the revision addresses it | verdict | reason |
|---|---|---|---|
| O-F01 W2-LW-finish successor refused (ruling: looser reading) | conn 108–112; ereq 34–36 | resolved | The spawner no longer counts a terminal record awaiting storage release as holding its uid, so the engine's re-lease on CLOSED + empty (rr 583–585) and the spawner's admission agree; the successor proceeds. One leftover wording conflict in ereq is N-01. |
| O-F02 = C-F04 tool definitions have no catalog home | si 412–419; rr 375 | resolved | `tool_definitions_ref/digest` added to RuntimeDescriptor with a closed artefact schema, parse-time checks, and an adapter start-up comparison. The link between the runtime-tree copy and the catalog digest is left open (N-07, P3). |
| O-F03 connector attaches vs single freeze point | rr 245–247, 377–378, 359 | resolved | freeze_operation now serializes the tool set into body_bytes and body_hash, reached by object reference; the connector sends only the frozen bytes. |
| O-F04 input limits do not add up | rr 95, 378; si 557–558 | partly | max_input_bytes is now defined and the adapter knows tool_set_bytes, but the budget "64KiB − tool_set_bytes − 1KiB" is measured on the args form, while the frozen body uses the mapped form (rr 408–410: `type:"function"` wrappers, `parameters` renames, arguments re-encoded as a JSON string with escaping). A request that passes the adapter's check can still exceed 64KiB at prepare. Resolve by defining tool_set_bytes and the messages budget on the outbound mapped serialization, or by giving a fixed per-message and per-tool overhead allowance. |
| O-F05 = C-F03 tool calls missing from evidence and post_read | rr 474–475; si 98, 120, 153–154 | resolved | CompletionEvidence carries tool_calls_digest and tool_calls_bytes; post_read fires once for the terminal value with part=terminal_value; PayloadBorrow covers the pending_completion value. One schema wording nit is N-06. |
| O-F06 E-10 acceptance table describes the text bridge | si 707–708 | resolved | Both rows now give the native path: frozen tool set → tool_calls in Complete → adapter schema check → toolResult as role tool. |
| O-F07 undefined labels and fields | conn 95–105, 472 | resolved | Design events named (row creation at RESERVED; prepared-fd install at PREPARING→STARTING), epoch fixed by the execution_id prefix, mutable fields listed, `Session.admission` named. Execution.startup_deadline fits neither list (N-05, P3). |
| O-F08 writer of Channel fields answered two ways | conn 81 | resolved | Writer given per field: the executor for install, phase and close; the receiver for frame_reader; the single writer for frame_writer. |
| O-F09 memory safety stated as an activity | conn 478–482; ereq 40–41 | resolved | The FrameReader is placed in C (`transport.c`), fuzzing is called evidence, production flags and source identity are recorded, and the FFI buffer contract is stated. Placing it in C exposes a field gap (N-02). |
| O-F10 stdlib json without configuration | conn 482–485 | resolved | Strict UTF-8 decode first, duplicate-key hook, NaN/Infinity rejection, surrogate, depth, node and integer post-checks. |
| O-F11 reap spawn_failed after an earlier spawn_failed | conn 118–120, 145 | resolved | Allowed explicitly and consumed as a quarantine trigger, not a conflicting terminal. BP's note that the reused C does not send it after a kill error is N-03. |
| O-F12 stop for unknown record (ruling: control fault) | conn 113–117 | resolved | The text now says "control-protocol fault, handled as E-04 control loss", gives the carrier (none, none added) and the blast radius (every parallel execution ends; engine restart). The stated reason has a factual gap (N-09, P3). |
| O-F13 supervisor method pointer lands nowhere | rr 887–888; ereq 43–45 | resolved | Listed in the rr E-08 deployment-input list and marked open; the header points there. |
| O-F14 BUILD-PLAN reuses code with rejected readings | BP 11–14, 80; conn 108–112 | resolved | The looser admission reading now matches the reused spawner, and the getresuid re-read is the named C change with a positive and a negative check. |
| O-F15 local instance: deployer vs supervisor (ruling: deployment preconditions) | rr 811–818, 885–886 | resolved | Two cache-isolation requirements stated as deployment preconditions the engine does not check; the supervisor wording is replaced; precondition and start options are in the input list. |
| O-F16 SSE stop + assembled calls; empty tool set | rr 461, 411 | resolved | Stop with assembled tool_calls → upstream_error; an empty tool set omits `tools` and `tool_choice`. |
| O-F17 tool_calls size measure and buffer budget | rr 359, 381, 832 | resolved | Measured on the serialized result-frame JSON; the assembly buffer has its own capacity row. |
| O-F18 header "tags still describe the freeze" broken | ereq 28–30 | resolved | The header names the one revised row (§7 local model instance, line 242); every other row keeps the freeze text, which the header declares. |
| O-F19 getresuid re-read placement | conn 121–122; optb 252–257 | resolved | Placed between setresuid and the seccomp install, so S2 needs no getresuid; Option B now says "Required, and checked". |
| O-F20 step-2 condition for rows with no Channel | conn 859–863 | resolved | Met vacuously; the late-prepared fd is closed on receipt; step 2 does not imply drained. |
| O-F21 stale text-bridge names | rr 354; si 509; superseded notes at conn 1498, 1732, rr 899, 1001, 1179, si 722, 837, 948 | resolved | Heading and api alias renamed; every record set marked superseded. One residual phrase in current text is in N-10. |
| C-F01 Node receiver rejects the tool-call result | si 476–477 | resolved | The receiver now validates by action: `{}` for document.read, `{}` or `{tool_calls:[...]}` for model.generate. The number-range gap this exposes is N-04. |
| C-F02 release barrier delivers only `Complete({})` | rr 482–490, 469–471 | resolved | The validated, immutable tool_calls value rides in pending_completion across the release barrier. It is committed exactly once and dropped on cancel, deadline or close. |
| C-F05 tool-call id vs E-02 id rules | rr 379 | resolved | A separate tool-call ID type (1–96 ASCII, `[A-Za-z0-9._:-]+`) is applied to returned calls, history tool_calls and tool_call_id, and is stated to be exempt from E-02's positive-integer `id` rule. |

## 2 New findings introduced by the revision

### N-01 — ereq's spawn-admission must uses "live", which conn now defines to include the record that no longer holds its uid — P2

- **Where:** ereq 188 (and its sibling 189) against conn 108–112, 173, 206, 1606.
- **Defect:** ereq 188 requires the spawner to refuse a spawn "whose uid or lease is in a live SpawnRecord", and conn calls a record that still has a storage budget or an unsent storage terminal a "live" object (173, "16 个 live 记录" at 206). Under the looser reading that live record no longer holds its uid. An implementer reading the must with conn's vocabulary builds the strict reading the ruling rejected.
- **What would resolve it:** in ereq 188 write "a SpawnRecord whose process has not been reported empty" (or cite the looser reading at row 189), or add one clause at conn 108 saying such a record stays live for control and storage but not for uid admission.

### N-02 — the C FrameReader returns only bytes, so VerifiedContext's sender_pid and received_at have no source — P2

- **Where:** conn 478–480 (FrameReader in C, "Python 只取得…整帧 bytes") against conn 440–441 (FrameReader holds frame_started_at and a pid summary), 460–462 (step 6), 562 (VerifiedContext); BP 11 ("C 部分只改一处"); native `transport.c` 212–240 (read only).
- **Defect:** step 6 and VerifiedContext require sender_pid (when every fragment's pid matches) and received_at (time of the first verified header byte), and E-09 copies sender_pid into verified_subject (si 93). The reused `w2_frame_receive` returns only the body and its length; it keeps neither pid nor first-byte time, and it returns 0 both for EAGAIN and for partial progress, so Python cannot reconstruct either value. With "only one C change", build step 2 cannot meet step 6 as written.
- **What would resolve it:** either add the second C change (return the common pid or a mismatch flag, and the first-header-byte time) to BP §1 and its checks, or relax step 6 and VerifiedContext to values Python can observe (sender_pid always null; received_at = completion time) and say so in conn.

### N-03 — BUILD-PLAN's two notes on reused spawner behaviour depart from conn E-01 without conn recording the exceptions — P2

- **Where:** BP 33–35 against conn 118–120 and 145; conn 866–869 (stop deadline), 914–916 (control loss).
- **Defect:** conn says, without exception, that a reap-stage kill or wait error "由 `spawn_failed` 报告", and that it may follow an earlier startup spawn_failed. BP says the reused C sends nothing on a kill error after an earlier spawn_failed (quarantine then comes from the 5,000 ms empty deadline), and that a wait error also faults the whole control link. The outcomes are safe and do match E-04 (stop is sent because no empty arrived; the deadline quarantines; control loss closes every row). But the design promises a report the build will not send, and the wait-error blast radius (every parallel execution, engine restart) appears only in the plan, unlike the stop-for-unknown case, where conn states it.
- **What would resolve it:** add both exceptions to the conn E-01 supplement: no report after an earlier spawn_failed, quarantine by the stop deadline; and a wait error is a control-link fault, with its blast radius. Or change the C and list that change in BP §1.

### N-04 — numbers in model-generated tool arguments are not bounded by the engine, but the Node receiver closes the channel on them — P2

- **Where:** rr 380–381 and 453 (format check: strict JSON, duplicate keys, depth and nodes only) against conn 505 (all JSON integers within ±(2^53−1)) and si 460–463 (Node rejects unsafe integers; an invalid frame closes the channel).
- **Defect:** a model call such as `{"offset": 18446744073709551615}`, or a float that overflows to infinity, passes the engine's format check. The engine then either emits a result frame that breaks the E-02 number rule or rejects the frame, and the text says neither. The new action-specific Node receiver then treats the frame as a protocol fault and closes the whole execution instead of returning a tool error.
- **What would resolve it:** add the E-02 number limits (integers within ±(2^53−1); finite numbers) to the connector's format check, with a violation giving upstream_error.

### N-05 — Execution.startup_deadline is neither a reservation field nor in the mutable list — P3

- **Where:** conn 95–100 against conn 79 and 328–329.
- **Defect:** the supplement lists the reservation fields and states "此后可改的只有" a closed set; startup_deadline is in neither list, although conn 328 computes it "在 spawn 入队前", which can come after row creation.
- **What would resolve it:** add startup_deadline to the write-once fields (set at spawn enqueue) or to the mutable list.

### N-06 — the terminal-value post_read sets chunk_index to null, against the event rule that absent fields are omitted — P3

- **Where:** si 120 against si 106.
- **Defect:** si 106 says every absent field is omitted and null never stands in for a value; the new post_read sets "chunk_index 为 null". An implementer can emit null or omit the field.
- **What would resolve it:** "chunk_index 省略" for part=terminal_value (or list chunk_index as nullable beside sender_pid).

### N-07 — two ends of the tool-definition path are implicit — P3

- **Where:** si 415–419; rr 379–380.
- **Defect:** the artefact is "同时作为 runtime 树内只读文件提供给 adapter", but nothing requires that file's bytes to match tool_definitions_digest (it is covered only by the component manifest). The connector's "name 属于声明集合" check names no route to the set, while freeze_operation does (rr 246). Both gaps are utility-only, since the model sees the engine's frozen copy.
- **What would resolve it:** one registry check that the runtime-tree copy equals the catalog artefact by digest, and "the declared set is the one freeze_operation used, carried on the CandidateOperation".

### N-08 — BUILD-PLAN check table: count and the injection point — P3

- **Where:** BP 71, 80, 11.
- **Defect:** the heading still says "五项检查" over six rows. The negative re-read check needs an injection point that makes getresuid disagree, which is a second C change (or a preload or seccomp-trap harness), but §1 says the C changes in one place only.
- **What would resolve it:** "六项检查", and name how the mismatch is injected (a test-only build flag counted in §1, or an external harness).

### N-09 — the stated reason and cost in two rulings are imprecise (rulings stand) — P3

- **Where:** conn 116–117 against conn 351 and ereq 187; conn 111 against rr 638 and 673.
- **Defect:** the stop-for-unknown reason says an invalid stop means the engine's own state is wrong. But conn's own uncertain-submission path sends a stop by design, and if that spawn never reached the spawner, a correct engine triggers the fault. The looser-reading note names "副本被保留时工作区一直不可用" as a cost of the strict reading only, but a retained copy closes admission store-wide under both readings.
- **What would resolve it:** add "including a stop after an uncertain spawn send" to the blast-radius sentence, and drop the retained-copy clause from the comparison.

### N-10 — residual superseded wording in current text and unmarked records — P3

- **Where:** rr 478 ("不能给出完整工具文本"); rr 953 and 1082 (records still requiring supervisor instance mapping and clearing evidence, "无证据不准入").
- **Defect:** rr 478 is current E-07 text that keeps the text-bridge phrase. The two record rows contradict the third revision's ruling that instance isolation is a deployment precondition the engine does not check, and their sections carry only the text-bridge superseded note.
- **What would resolve it:** "不能给出完整生成结果" at rr 478, and extend the superseded note at rr 899/1001/1179 to the local-instance rule.

## 3 Questions besides the table

**Looser reading and W2-LW-finish.** The successor now completes on the written path: finish → DRAINING →
bye → close steps 1–4 → stop → reap → execution_empty → uid lease freed (conn 853–861, rr 583–585) →
WorkspaceLease re-granted after the engine-side workspace I/O ends (rr 543–545) → spawn admitted, because the
old record no longer holds the uid (conn 108) → new copy. The other capacities still hold:
- the old row keeps one of the 16 engine execution slots until runtime_status released (conn 766, 199);
- the old record stays one of the 16 live spawner records and copies (conn 173, 206);
- the old copy keeps its B/N charge (rr 666).

A single restart fits these limits, since `max_reserved_bytes ≥ 2*max(B)` (si 304). Restarting during
W2-LW-parallel can hit a one-off storage-budget refusal, which is a bounded availability case (rr 671, 676), not
a uid refusal. Only ereq 188's "live" (N-01) still reads as the strict rule. si 710 describes the old slot
returning before the new execution, which is one valid order, not a requirement.

**One path for tool definitions.** The path holds:
1. Catalog artefact (si 412–416).
2. Engine read-only copy.
3. freeze_operation by object reference into body_bytes and body_hash (rr 245–247).
4. pre_egress, then the connector sends the frozen bytes (rr 378).
5. Bounded SSE assembly (rr 457–461, 832).
6. Format check only: count, ID type, declared name, strict JSON, sizes (rr 379–381).
7. pending_completion across the release barrier, committed once (rr 483, 487).
8. post_read terminal_value (si 120).
9. Action-specific Node receiver (si 476–477).
10. Adapter schema validation (si 563–567).
11. toolCall/toolResult history in the next request (si 549–550).

At no step does the connector read argument semantics. The gaps are N-04 (number range), N-07 (two implicit
links) and the budget measure under O-F04.

**BUILD-PLAN.** §1 names the one C change in the same words and placement as conn 121–122 and optb 252–257.
§2 lists the new blobs, which match HEAD. §5 adds the re-read check. The C-change claim does not cover N-02
(FrameReader fields) or the N-08 injection point. On the two notes: both outcomes match E-04's mechanisms
(stop deadline → quarantine; control EOF → all rows closed). But conn E-01 still promises a report in the
kill-after-spawn_failed case and does not state the wait-error blast radius (N-03).

## 4 Gate

**May pass** for starting engine build step 1 on this design. No finding of the revision is unresolved, and
no new finding loses or contradicts a requirement or blocks a workload. Build step 1 (control client and
lifecycle) is affected only by N-03, where BUILD-PLAN already fixes the engine's behaviour and the outcome is
quarantine either way. Correct the conn text before the step-1 review. Settle N-02 before build step 2
(receive), and N-04 and the O-F04 budget measure before a real connector replaces the stub.
