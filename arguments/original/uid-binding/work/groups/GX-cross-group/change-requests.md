# change-requests — GX cross-group routes (2026-10-15)

Requests for changes to shared files, for the reconcile role to merge into the convergence folder's
change-requests file. Nothing here is applied by this stream; the spine is read-only during fan-out.
Based on 01 v7 7345e9c5d8face07, 02 v3 558f035982198c7c, 03 v3 af8662ca14b83598, 04 v3 b868512116d812f0.
Status (2026-10-16): CR-GX-01 accepted and applied as CR-F-07 in 03 v4 6868389a2182c161 (convergence
change-requests.md §2026-10-15); the six route files were re-read against 01 v8, 02 v4, 03 v4 and 04 v4
and their headers bumped the same day.

| ID | file and IDs it would change | request | reason |
|---|---|---|---|
| CR-GX-01 | 03-invariant.md §1.1 clause (iii) (the time fact of I_acc) and, if reconcile prefers, 02-conditions-and-decomposition.md §1 (the definition of J_r); no route, condition, transition or evidence ID changes | state one rule for the end of an unreleased lease's interval at control loss: 02 §1 says J_r is "open-ended while not released", 03 §1.1 (iii) says J_r ends at "the release or retirement of its lease (T-45, or the end of its engine epoch at T-49)". Smallest repair: 03 §1.1 (iii) gains the clause "in the model; for the cell assignment of 02 §4 an unreleased lease of a lost epoch keeps its interval open (02 §1), and the model's NewEpoch retirement is the modelling device whose soundness is the MM-10 premise" | the epoch-survivor history is assigned to R-GX-04 by D_61 ∧ ¬q23 ∧ q33 (02 §4; CR-A-11), which needs p61 to fail — two allocation intervals assigning u overlap — and so needs the old lease's interval to stay open after T-49. Under 03's reading the old interval ended at T-49, p61 holds, and the same history falls to D_62 ∧ q24 → R-G4-01, whose file states that the new-epoch variant is R-GX-04 and not its own. The two spine files are consistent only under the first reading; R-GX-04 §2 follows the ledger and records the tension. Downstream files: R-GX-04 §2 and R-G4-01 §3 (last bullet) — no text change needed in either once the clause is added. |

No request concerns 01, 04 or the templates. The evidence gaps the six route files surface — the K-06 fact
for SOCK_STREAM, the `[S]` design statements of E-01 control handling, E-02 FrameReader rules, E-03/E-04
callback and release rules — are proposed-evidence rows inside the route files (section 4), which reconcile
appends under the append-only rule; they are appends, not change requests. The two pending wave-1 requests
that could touch GX — the IG-10 split (CR-G1-01) and the q32 widening (G3) — are examined in section 6 of
each route file; none of the six arguments changes under either.

## Requests of 2026-10-19 (step 4)

Based on 01 v10 d27d65d7874bbf6c, 02 v9 5d2a0b9438f37302, 03 v5 ae58d7db31c95c82, 04 v7 97b869a738a79b0e.
The six route files were re-run on the engine build's checks (step4-brief §4). No request concerns a spine
file or a template; neither request below changes a disposition.

| ID | file and IDs it would change | request | reason |
|---|---|---|---|
| CR-GX-02 | ExperimentLab/engine validation.md, section "R-GX-06 关联只按对象建立与清除" (its result line); no route, condition, transition or evidence ID changes | for the engine record's owner: give the section's result as 满足（测试加代码阅读）, as row 149 already does, and add to its limit that the integration normal case (run 20261019T011226Z-engine-pool-70000; EV-189) shows fd-number reuse through the real spawner in sequence, as the AA-13 section already says | the section's test (test_association_made_installed_and_cleared_by_object) shows the link made, installed and cleared; the "only" — no other writer of channel.session — rests on code reading (lifecycle.py:276, :471; EV-194), so the section's 满足（测试） understates its method; its limit sentence "fd 号复用由测试自己制造…不是经真实 spawner 的自然复用" omits the integration case that does exercise real-spawner reuse across rounds. R-GX-06 §5 and §6 state both points, so nothing downstream waits on this |
| CR-GX-03 | convergence/step4-evidence-map.md table 1 (rows only; no ID changes) | add rows for EV-151, EV-152, EV-153, EV-155, EV-157 and EV-158, now cited by R-GX-06 §4 beside their realization (EV-194/EV-193/EV-187/EV-190; EV-187/EV-186; EV-195; EV-191/EV-192; EV-231; EV-205), and drop the sentence that EV-155 is cited by no route file | R-GX-06 previously carried these statements as proposed rows without IDs; the step-4 re-run cites them by ID, so the map's "cited by" coverage and its counts lag the route files |
