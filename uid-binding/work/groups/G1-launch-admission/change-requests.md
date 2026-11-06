# change-requests — G1 launch and admission (2026-10-14)

Requests for changes to shared files, to be merged by the reconcile role into the convergence folder's
change-requests file. Nothing here is applied by this stream; the spine is read-only during fan-out.
Submitted against 01 v7 7345e9c5d8face07, 02 v3 558f035982198c7c, 03 v3 af8662ca14b83598, 04 v3 b868512116d812f0; re-read 2026-10-16 against 01 v8 9efb243354a4e9d6, 02 v4 31ddfc5daba58f13, 03 v4 6868389a2182c161, 04 v4 f36170e09dd4c2a9.

| ID | file and IDs it would change | request | reason |
|---|---|---|---|
| CR-G1-01 | 03-invariant.md IG-10 (§2 guard list; §5.2 bounds note); Stream Q's bound list if it adopts more than one pool uid | split IG-10's uid clause into two: (a) for every live SpawnRecord, SpawnRecord.uid equals the uid of the UidLease its lease_id names, written at T-03 from the T-02 record and never changed; (b) after T-07 succeeded, every member's real uid equals SpawnRecord.uid | with one pool uid the subset cannot express a record that carries another lease's uid (R-G1-06's cell D_53 and the T-03 miscopy named in R-G1-06 §6). The design's two checks map one-to-one onto the halves: the spawner's cross-check of the spawn's uid against the workspace's registered static uid before clone (si L271–272) preserves (a); the spawner's SEALED check (conn L292–293) preserves (b). Without (a), the entailment of 03 §4 step 4 uses IG-02 only, which is stated over "the pool uid" and silently identifies the record's uid with the lease's. No guard is weakened; one is refined. |
| CR-G1-02 | 01-model-inventory.md T-01 … T-14 table, row T-14, precondition cell | replace "RESERVED/PREPARING with submission = local (nothing ever sent)" by "RESERVED, or a row CLOSED before any send, with submission = local (nothing ever sent)" | conn L322 moves a row to PREPARING only on a whole send (submission = submitted), so PREPARING ∧ local is not a reachable state of the frozen text; conn L323 and L797–798 name RESERVED and the close path; the TLA+ Withdraw action already encodes RESERVED or CLOSED. Wording only; no transition, outcome or interleaving changes. |

Status 2026-10-16: both accepted on 2026-10-15 — CR-G1-01 as CR-F-01 (03 v4 IG-10, halves (a) and (b)), CR-G1-02 as CR-F-02 (01 v8 T-14). The G1 files cite the new text.
