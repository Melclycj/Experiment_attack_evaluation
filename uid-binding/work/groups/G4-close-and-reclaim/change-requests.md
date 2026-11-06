# G4 change requests (2026-10-14) — for the reconcile role to merge into the convergence folder

Two clarifications; neither strengthens I, neither adds an ID, neither changes a disposition. The spine is
not edited here.

Adjudicated 2026-10-15 (convergence change-requests.md §2026-10-15): request 1 accepted as CR-F-04 (03
version 4, note only), request 2 accepted as CR-F-05 (01 version 8). Spine ids after the re-read of
2026-10-16: 01 9efb243354a4e9d6 · 02 31ddfc5daba58f13 · 03 6868389a2182c161 · 04 f36170e09dd4c2a9.

| # | shared file and ID it would change | what to change | why |
|---|---|---|---|
| 1 | 03-invariant.md, IG-13 row, MM entry ("MM-09: the window between steps 1 and 2 is modeled; no read occurs in it") | add the reading on which "no read occurs in it" rests: the pre-read check of conn L413 consults the original Session held by the FrameReader (conn L409–410), whose state is set CLOSED at T-40 step 1; note that under the other reading (the Channel's phase, set at step 2) a read in the window would carry the row's own label while the row still holds its lease (IG-02 at the send instant), so P_acc is unaffected but IG-13's letter would need the first reading | the G4 preservation row for T-40 (and J-07) rests on this reading; the frozen text names "the original object" without naming the field, so the reading should be visible in the spine rather than only in a group file |
| 2 | 01-model-inventory.md, T-41 precondition and T-44 precondition | add the path for a stop that names a record the spawner never received (T-02 `uncertain` with no record at the spawner): the spawner treats an unknown execution id as a control fault (conn L131–142) → T-49 → T-44, beside the 5,000 ms empty-wait path of conn L813–814; both end in quarantine | 03 §5.2 records the conservative reading (no empty fact, the lease quarantines) as a restriction of the model; 01's T-41 row lists only the unreaped-record and control-loss-sweep preconditions, so the control-fault path by which that reading is reached in the frozen text is not visible in the inventory (G4 J-05) |
