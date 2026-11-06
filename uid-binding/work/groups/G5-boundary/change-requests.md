---
group: G5
owner: G5-boundary stream (cold-context Fable subagent), 2026-10-14
status: ready-for-reconcile
based_on:
  model_blob: "9efb243354a4e9d6"
  decomposition_blob: "31ddfc5daba58f13"
  invariant_blob: "6868389a2182c161"
  registry_blob: "f36170e09dd4c2a9"
---

# change requests from the G5 boundary stream

Requests for changes to shared files, for the reconcile role to merge into the convergence folder's
change-requests.md. This stream edits no spine file and no template.

| id | file and ID | requested change | why |
|---|---|---|---|
| CR-G5-01 | 01-model-inventory.md, T-67 (text only; no new ID) | Add the exclusive-uid-pool deployment premise — "the exclusive uid pool" of 02 §0.3, U-05 of 02 §5.2, conn L87 ("可信部署在启动前提供 uid/gid 池独占约束；一次 /proc 扫描不能证明池独占"), iv L93–95 (EV-81) — to the list of configured premises whose absence T-67 models, beside S1–S14 and C1–C4. | 02 §6 routes the premise's failure (a pre-existing host or other-compartment holder, or a concurrently running engine on an overlapping pool) to R-G5-06 through T-67 and U-05, but T-67's text names only "a required item of S1–S14 or C1–C4". The premise is neither an S-row nor a C-condition, so R-G5-06's departure has no transition home by the letter of T-67. The G5 preservation row for T-67 already reads the premise in (branch f); this request makes the inventory say so. |

Adjudication (convergence change-requests.md §2026-10-15): CR-G5-01 accepted as CR-F-06 — 01 version 8
(blob 9efb243354a4e9d6) names the exclusive-uid-pool deployment premise in T-67's precondition and assigns
its failure to R-G5-06; this folder's files were re-read against 01 v8, 02 v4, 03 v4 and 04 v4 on 2026-10-16
and their headers carry those ids. No further request is raised.

No disagreement with 02 §4.1 arose: the re-derivation of R-G5-03, R-G5-04 and R-G5-07 agrees with 02 §4.1
item 2 (the capability clause of a self-made namespace is not a barrier; the map is; S1 is surface
reduction). The PLAN's pre-registered hypothesis "C2 and spawn step 11 stop it" is adjudicated in those
route files' §6 (its second half, the `unshare` deny, is not what stops the routes); PLAN.md is not a spine
file, so no request is raised against it.

## Re-run of 2026-10-18 (R-G5-03, R-G5-06, R-G5-07, R-G5-08 under 01 v9, 02 v7, 03 v4, 04 v5)

| id | file and ID | requested change | why |
|---|---|---|---|
| CR-G5-02 | 04-evidence-registry.md (append; no existing ID changes) | Append the proposed-evidence rows of the four re-run files (seven distinct rows: the re-read regression `[M]`, diagnostic policy; the `w2_drop` code reading; the design text of the re-read `[S]`; the kub §6 source reading of the uid writers at blob 4a7384b7727abe37 `[R]`, which replaces the credentials(7) row an earlier pass of this re-run proposed; conn E-01 L106–107 `[S]`; rr L387–389 and L885–886 `[S]`; engine-requirements §8 first entry `[S]`), and add to EV-30's note column that its "no runtime check added" is superseded by the 2026-10-18 design text and the re-read run. Confirm the tag of the `w2_drop` reading: the `[R]` definition names kernel source, man pages, external records and design text, not product C code. | R-G5-03 and R-G5-07 rest on the re-read, which has no registry ID yet; R-G5-06 and R-G5-08 rest on design text of the second freeze and on the deployment entry, which no row registers; EV-30 now states the opposite of the current design. |
| CR-G5-03 | preservation.md of this folder (not re-run in this pass): rows T-61 and T-67 branches (a) and (f); the "does not preserve" and "design unstated" conclusion lines | Re-read the wording against 01 v9: T-07's outcome now includes the `getresuid` re-read (an unequal value gives FAIL, no SEALED), so branch (a)'s offending state needs the re-read absent or defective, and "C1's required-but-unchecked call" no longer describes the design; the pool premise now has its limit (conn L106–107) and its deployment entries (engine-requirements §8), so "stated as a precondition without a mechanism" should name the configuration-level entries. No preservation result is expected to change. | The four route files cite these rows; their text predates 01 v9 and contradicts the current T-07 and T-67. |
| CR-G5-04 | 02-conditions-and-decomposition.md: ledger row R-G5-08, U-02, U-05 (text only; no new ID) | State that the deployer's inventory empties R-G5-08's remainder for holders outside the engine's executions only, and that holders inside them are emptied by the documented credential semantics (fork inherits, `execve` keeps the real uid, the real uid changes through `setuid` / `setreuid` / `setresuid`), which route every such change to q26 (R-G5-07). Add, as a follow-up item of 04 §5, a source reading of the real-uid write sites at the pinned tag, the analogue of item 9 for R-G2-05. | Re-derivation in R-G5-08 §3: the inventory is checkable by reading configuration (engine-requirements §8 notes) and does not reach a runtime credential change by a task of one of the engine's own executions; the disposition holds, but on two properties, one of which 02 does not name. |
| CR-G5-05 | 02-conditions-and-decomposition.md (ledger rows R-G5-06, R-G5-08; U-05) or route-record.md (disposition values) | "conditional on deployment preconditions" is not one of the template's four values. The two re-run files take "supported under stated premises", by the brief's rule that a deployment precondition the engine does not check is a premise and since no unbuilt engine component enters either stop. Either reword 02 to that value, or, if the user wants deployment-premised routes kept apart in the five-column table, add a value to the template (the reconcile checks' disposition list would follow). | The reconcile checks accept only the four values; the spine phrase and the file disposition should name the same standing. |

Adjudication (2026-10-18):
- CR-G5-05 resolved by the user: the template keeps its four values; a route whose premise is a deployment
  precondition the engine does not check takes "supported under stated premises", with the precondition
  named among the section-5 premises. R-G5-06 and R-G5-08 stand as written; the reconcile role aligns 02's
  wording.
- CR-G5-04 answered by the kernel source reading merged into kub §6 (passage L633–700, blob
  4a7384b7727abe37): the real uid is written only inside the setuid family and by a copy of the task's own
  values, so the inside-engine half of R-G5-08 now rests on source, with two conditions — no reachable user
  namespace mapping another kernel uid (q26, R-G5-07 and R-G5-04, premises AA-04 and the §8 entry) and
  io_uring unreachable on the stamp side (S2, no business fd-pass; R-G2-05, not R-G5-08's cell). R-G5-08
  and R-G5-07 cite the reading; the 04 §5 follow-up item this request proposed is no longer needed. The
  request's text change to 02 (the inventory empties only the outside-engine half) still stands for the
  reconcile role.

No disagreement with 02 §4.1 arose in this re-run: the re-read strengthens C1 inside step 11 and leaves item 2's
separation of the C1 and C2 routes as it was.
