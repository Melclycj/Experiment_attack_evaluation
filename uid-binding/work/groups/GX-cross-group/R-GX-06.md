---
route_id: R-GX-06
group: GX
owner: GX re-run subagent (Claude Opus 5.5, cold context), dispatched by the main session on 2026-10-18; re-run 2026-10-19 for follow-up step 4 (Claude Opus 5.5, cold context); wording compacted 2026-10-21 (shared evidence boundary cited; no content change)
status: ready-for-reconcile
date: 2026-10-19
violates: C-05
stops: "the association is created at T-01, installed at T-09 and cleared at T-40 step 2 only, by object — realized in the engine prototype and established by the validation record's R-GX-06 check and its AA-13 check"
disposition: supported under stated premises
based_on:
  model_blob: "d27d65d7874bbf6c"
  decomposition_blob: "5d2a0b9438f37302"
  invariant_blob: "ae58d7db31c95c82"
  registry_blob: "97b869a738a79b0e"
---

# R-GX-06 — A row/channel/allocation association is wrong for an unrefined reason outside installation, control correlation or numeric/object alias.

## 1 What the adversary does
A row/channel/allocation association is wrong for an unrefined reason outside installation, control correlation or numeric/object alias.

## 2 How it would produce false attribution
- **Preconditions:** C-05 p51 fails — the row read at a D-ACC does not carry the immutable reservation A_r
  of its original Channel — by a cause that is not q18 (inconsistent at install: R-G1-03), not q19 (a
  prepared, empty or duplicate control event changes it or reactivates a retired row: R-GX-02) and not q20
  (a later change follows a numeric fd, uid or generation lookup or an object alias: R-GX-03). No adversary
  capability beyond A-01 … A-06 is stated, because the slot names no cause. Configuration: all three
  (C-LS, C-LP, C-R) under the common abstraction of the frozen revision; nothing here depends on one.
- **Transitions traversed:** T-01 (row creation), T-09 (install), T-23 and T-24 (the row read for the
  comparison and the label at D-ACC), T-40 (close steps 1–4), T-45 (lease release and uid reuse), T-52
  (control idempotence). The slot is the remainder of cell D_51 (02 §4: "else → R-GX-06").
- **Sufficient condition violated:** C-05 p51; B(R-GX-06) = ¬H ∧ D_51 ∧ ¬(q18 ∨ q19 ∨ q20). With the
  association consistent at install, p51 can fail only if, after install, (i) a reservation field of the
  row changes, (ii) the Channel → Session link changes, (iii) the D-ACC reads its row through an object
  other than the Channel the fragment arrived on, or (iv) a new row binds an object of an earlier
  execution. The label read at a then names a reservation other than the one the bytes' channel was
  created for, so L(a).execution ≠ Exec(b).

## 3 What stops it
The association is created at T-01, installed at T-09 and cleared at T-40 step 2 only, by object — realized
in the engine prototype and established by the validation record's R-GX-06 check and its AA-13 check. This
is the remainder slot's closing property (PLAN §Follow-up plan, the seven-slot table); since the second
freeze it is design text (02 v7 U-02 and ledger row; 01 v9 T-01, T-09, T-40, T-45, MM-15 resolved, MM-12
stated, AA-13), and the disposition rests on that positive property, not on the totality of the cell's
predicates (02 §4.3). Each sub-case of section 2, against the design text and the code:

- **(i) reservation fields.** The executor writes Execution's execution_id, lease_id, local_agent_id,
  launch_plan_id, launch_plan_digest and Session's session_id, execution_id, expected_uid once, at row
  creation, in the decision that acquires the lease; the fields that may change afterwards are listed, and
  none is a label field (conn L95–100; 01 T-01). expected_uid is never set from an observed value (conn L80;
  IG-07). The executor is the sole writer of Session; workers return facts (conn L634; si L111–112). In the
  build these fields are write-once by type — a second assignment raises (EV-187) — and set in the one
  reservation function, expected_uid from the lease (EV-186); handlers post their results to the executor's
  loop (EV-231).
- **(ii) the link.** The Channel → Session link and Session.channel_id are written once, at the
  prepared-fd install, in the PREPARING→STARTING decision, on a new Channel object; the link is cleared only
  at close step 2, by object (conn L103–104; 01 T-09). In the build the link is made only by constructing a
  new Channel at install, and the package's only other assignment to it sets it to None at step 2 (EV-194;
  "write once" holds by code structure, val row 149); Session.channel_id and the Channel's channel_id,
  owned_fd and receiver_generation are write-once by type (EV-187); a second prepared for the same row is
  refused with its fd shut (EV-219); the test of made-installed-cleared passed (EV-193). CLOSED is terminal
  (EV-222, EV-239).
- **(iii) the object read at D-ACC.** The label is read from the row referenced by the Channel object the
  fragment arrived on, never from the message (conn L572; 01 D-ACC). In the build the VerifiedContext has
  one constructor, in receive_step, which takes every identity field from the Channel it was invoked on and
  that Channel's Session (EV-172, EV-183), and returns no label once the link is cleared or admission is
  CLOSED (EV-172, EV-239). After step 2 deregisters an fd, a selected event is dispatched only if its
  snapshotted callback is still the fd's current registration (AA-13: EV-191, EV-192), so a reused number
  reaches the new Channel only; old callbacks hold their own Channel and act only while it is current
  (EV-190, EV-192). receiver_generation is one per Channel from an epoch counter and void after step 2
  (conn L104–105); the build's cut does not rest on its value (val row 148).
- **(iv) cross-execution binding.** A new execution inherits no object of an earlier one; a recurring
  local_agent_id brings no state; the new row binds neither the old execution's still-occupied slot nor any
  object in it (conn L101–102; MM-12 stated). Identifiers derive from execution_id and are never reused
  (conn L71–74). Lease release also requires close step 2 done (conn L870–873; MM-11 resolved). In the
  build: new lease, Session, view and workspace-lease objects for a new execution while the old slot is
  still held (EV-195); identifiers from a fresh epoch and a non-wrapping counter (EV-240); no table keyed
  by local_agent_id, and the uid- and fd-keyed tables used only as EV-196 states; release gated on step 2
  (EV-205).

Preservation conclusions cited (GX may cite them): G1 lists T-01 and T-09 as preserving; G2 lists T-23 and
T-24; G4 lists T-40, T-45 and T-52. The disposition rests on the 01 v9 transition facts, the design lines
above and their realization, not on those rows.

## 4 Support
| evidence id | tag | what it shows | file and section | date / substrate / version |
|---|---|---|---|---|
| EV-152 | [S] | the reserved fields of Execution and Session are written once by the executor at row creation, in the lease-acquiring decision; only the enumerated fields change afterwards | conn E-01 identity supplements (L95–100) | design text; realized by EV-187, EV-186 |
| EV-187 | [M] | a second assignment to Execution.lease_id, execution_id, startup_deadline_ns and lease, to Session.expected_uid and channel_id, to UidLease.uid and to Channel.receiver_generation each raised AttributeError | int (unit suite), test_reservation_fields_write_once (val rows 139, 148) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; unprivileged unit suite |
| EV-186 | [R] | expected_uid is written once, when the Session is constructed in the reservation decision with expected_uid = lease.uid; the C reader returns no observed uid | eng lifecycle.py:139, :149–150; objects.py:14–22, :149–157; receive.py:284, :297–299; ffi.py:92–106 (val rows 139, 140, 165, 169) | commit 3ec67985; code reading |
| EV-157 | [S] | the engine state executor is the only writer of Session and RequestEntry; workers do not modify them | conn E-03 (L634) | design text; realized by EV-231 |
| EV-231 | [R] | handlers deliver results by posting a callback to the state executor's loop; the record log thread writes only its own queue | eng handlers.py:33–43; records.py:254–283 (val row 246) | commit 3ec67985; code reading |
| EV-151 | [S] | Channel fields and receiver_generation written once at install; the Channel → Session link written once at the prepared-fd install and cleared only at close step 2, by object; receiver_generation one per Channel, epoch-monotonic | conn E-01 (L81, L103–105) | design text; realized by EV-194, EV-193, EV-187, EV-190 |
| EV-194 | [R] | the link is made only by constructing a new Channel with the row's Session at install, Session.channel_id being write-once; the only other assignment sets it to None at close step 2 | eng lifecycle.py:147–158, :273–283, :460–475 (L471); objects.py:128–157 (val §关联只按对象建立与清除; row 149) | commit 3ec67985; code reading |
| EV-193 | [M] | before the handoff the Session points to its Execution and there is no Channel; after spawn_prepared the Channel's session is the row's Session and the fd is registered; after close the link is None, the phase CLOSED, the fd in no loop registration, reader and writer discarded | int (unit suite), test_association_made_installed_and_cleared_by_object (val §关联只按对象建立与清除; rows 149, 202) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-219 | [M] | a consumed spawn_prepared arriving again, or a mismatched one, has its fd shut and faults | int (unit suite) (val row 185) | 2026-10-19 |
| EV-133 | [S] | the fd is owned by the Channel; close step 2 deregisters, then closes the fd once by object and generation | conn E-01, E-04 close | design text; realized by EV-192, EV-193 |
| EV-192 | [R] | close step 2 unregisters the fd before shutdown and close, sets the phase CLOSED and drops the link; the loop dispatches a selected event only if its snapshotted callback is still the current registration; receive and send callbacks act only while their Channel is current | eng lifecycle.py:460–475; loop.py:58–85, :104–126; phases.py:45–63 (val §AA-13; rows 161, 163, 202) | commit 3ec67985; code reading |
| EV-155 | [S] | the event library delivers no readiness for an fd number after close step 2 deregistered it; checked against the chosen library, which is otherwise not admitted | conn E-02 receive-side supplements (L481–484) | design text; realized by EV-191, EV-192 |
| EV-191 | [M] | AA-13 check: an old Channel's fd selected in a round was retired and its number at once reused by a new socket; the old receive callback was not called, the new registration got no stale event; with the identity check removed both new tests failed | aa13 README §结果; output.txt; negative_control.py (val §AA-13; row 163) | 2026-10-18; WSL2 6.6.87.2-microsoft-standard-WSL2; CPython 3.12.3, EpollSelector; epoll backend only; reuse made by os.dup2 |
| EV-190 | [M] | with a new row on the same uid and fd number, the old row's callbacks, deadlines and late facts did not reach the new row, and an event selected for the old registration was not dispatched to the new one; the new Channel's generation is larger | int (unit suite) (val rows 141, 147, 148, 161) | 2026-10-19; fd reuse made by the test (low fds held or dup2) |
| EV-189 | [M] | integration normal case: a second execution on the same workspace and uid got a new lease and the same fd number in a new Channel object; the first execution's stale callbacks had no effect; the second Hello was attributed to the second row | int pool70000.json, cases normal (test and production build) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy; real spawner, reuse in sequence |
| EV-110 | [S] | receive_step(Channel) is the only constructor of VerifiedContext; identity fields come from the original objects | conn E-02 VerifiedContext | design text; realized by EV-172, EV-183 |
| EV-172 | [R] | receive_step checks Session.admission before reading, constructs the VerifiedContext only after a whole frame, the parse and the phase rule, and is the package's one construction of it | eng receive.py:273–300; phases.py:61–87 (val rows 162, 171, 172) | commit 3ec67985; code reading |
| EV-183 | [M] | VerifiedContext( occurs once, in receive.py; every verified-kind record's subject carries the row's uid, execution_id and channel_id | int (unit suite) (val rows 172, 173) | 2026-10-19 |
| EV-239 | [M] | once the session's admission is CLOSED the receiver makes no call into the C reader | int (unit suite) (val row 162) | 2026-10-19 |
| EV-136 | [S] | CLOSED is terminal; accepting_new reopens no row | conn E-01 state table, E-03 | design text; realized by EV-222, EV-239 |
| EV-222 | [M] | a prepared for a CLOSED row stops once and installs nothing; tombstones do not revive a row | int (unit suite) (val rows 143, 201) | 2026-10-19 |
| EV-153 | [S] | when an old execution's slot is still occupied after its uid was released, the new row binds neither that slot nor any object in it | conn E-01 identity supplements (L101–102) | design text; realized by EV-195 |
| EV-195 | [M] | with the old row's uid and workspace returned but its slot still held, a new execution on the same workspace and uid started with new lease, Session, view and workspace-lease objects; the old runtime status released only the old slot | int (unit suite) (val row 142) | 2026-10-19 |
| EV-102 | [S] | session, channel and lease identifiers derive from execution_id, one per execution | conn E-01 §对象、字段和所有权 | design text; realized by EV-240 |
| EV-240 | [R] | engine_epoch from secrets.token_hex(16) at start-up; allocation_seq refuses to pass 2^64 − 1; lease, Session and Channel ids are execution_id + :u, :s, :c | eng startup.py:96–98; lifecycle.py:145–150, :276; main.py:47 (val row 141) | commit 3ec67985; code reading |
| EV-103 | [S] | no structure supports finding an execution by numeric fd or uid | conn E-01 control, E-04 | design text; realized by EV-196, EV-220 |
| EV-196 | [R] | the only uid-keyed table is the allocator's holders (reservation and release); the only fd-keyed table is the loop's handlers, checked by identity before dispatch; no table keyed by local_agent_id | eng lifecycle.py:100, :140, :150–157, :500–501; receive.py:297; records.py:74; loop.py:50, :112, :122 | commit 3ec67985; code reading |
| EV-220 | [R] | a control record is matched by execution_id with lease_id compared, after the engine_epoch check | eng lifecycle.py:197–235; control.py:204–207 (val row 184) | commit 3ec67985; code reading |
| EV-158 | [S] | close steps 1–4 run in one executor decision; lease release at step 6 also requires step 2 to have run | conn E-04 (L870–873) | design text; release half realized by EV-205 |
| EV-205 | [R] | the uid lease is released only when the row is CLOSED and membership_empty, close step 2 has run and the lease is HELD, and once | eng lifecycle.py:328–349, :443–449, :491–502 (val rows 204–206) | commit 3ec67985; code reading |
| EV-96 | [S] | the expected uid and the execution/session associations live in engine userspace | desc9 §9.2 | design text; realized by EV-186, EV-194, EV-196 |
| EV-78 | [S] | the product receive path and its E-02 integration were unbuilt at the P2a run | implementation-validation.md SC-frames limit; §尚未由本次证明 | 2026-09-11; realized by EV-169–EV-175 |

**Composition:** a conjunction of sub-cases (i)–(iv) and the AA-13 library property; every necessary item
is now backed by `[R]` or `[M]`. (i) Write-once reservation fields and sole writer (EV-152, EV-157 `[S]`):
EV-187 `[M]`, EV-186, EV-231 `[R]`. (ii) The link made once at install and cleared only at step 2 (EV-151,
EV-133 `[S]`): EV-194, EV-192 `[R]` and EV-193, EV-219, EV-222 `[M]`. (iii) The label read through the
arrival Channel and nothing after the link is cleared (EV-110, EV-136 `[S]`): EV-172 `[R]` with EV-183,
EV-239 `[M]`; the AA-13 property (EV-155 `[S]`) checked by EV-191 `[M]` and EV-192 `[R]`; uid and fd-number
reuse by EV-190 `[M]` (made by the test) and EV-189 `[M]` (through the real spawner, in sequence). (iv) No
cross-execution binding and never-reused identifiers (EV-153, EV-102, EV-103 `[S]`): EV-195 `[M]`, EV-240,
EV-196, EV-220 `[R]`; release gated on step 2 (EV-158 `[S]`, release half): EV-205 `[R]`. The one-decision
half of EV-158 is not needed by the cut: the pre-read check (EV-172, EV-239) stops any read after step 1
whatever runs between the steps. No single recorded run exercised every sub-case together; the slot's
closing property is established by the code readings and the named checks, not measured end to end.

**Proposed evidence (not yet in the registry):** none; the five design statements this file proposed on
2026-10-18 are EV-151, EV-152, EV-153, EV-155 and EV-158, cited above beside their realization.

## 5 Disposition
**supported under stated premises** — the same value as the `disposition:` field. The slot's closing
property is established by the validation record's R-GX-06 check (test_association_made_installed_and_cleared_by_object
with the uid and fd reuse tests) and its AA-13 check, with the code readings of section 4; no necessary item
is `[S]` only.
- Premises that must hold: the event library in use is the one the AA-13 check ran on (CPython selectors,
  epoll backend) or another that passes the same check; the single executor (AA-01); the spawner trusted as
  AA-04 states; the common abstraction of the frozen revision for C-LS, C-LP and C-R. This rests on the
  frozen design and the prototype's checked realization; it is not a claim about a deployed system.
- Evidence limit (configuration, substrate, run dates): runs of 2026-10-18/19; the unit tests drive the engine against the test harness's
  stand-in spawner. Check limits as validation.md states them: in the R-GX-06 check the fd-number reuse is made
  by the test (low fds held or dup2), not by the real spawner; the AA-13 check covers the epoll backend only,
  with the reuse made by os.dup2 (EV-191). The integration normal case (EV-189) adds reuse through the real
  spawner, across rounds; "written once" for the Channel → Session link holds by code structure, not by type
  (EV-194; val row 149).
  Shared limits: [coverage-uncertainties § Shared evidence boundary](../../convergence/coverage-uncertainties.md#shared-evidence-boundary-every-route-not-repeated-below).

## 6 What remains
- Residual: the slot stays the explicit remainder of D_51 (02 U-02); its closing property is now
  established for the prototype at commit 3ec67985, and a later build keeps it only by keeping the
  obligations below. Whether an analyst can tell that a history falls here rather than in R-G1-03, R-GX-02
  or R-GX-03 is a statement about the analysis (02 §4; addendum F-04). Memory corruption of engine state
  through the C FrameReader is R-G2-11's subject. Re-arguing the G1, G2 and G4 preservation rows on 01 v9
  belongs to Step 3, not to this file.
- No disagreement with 02 v7: its ledger row and this derivation agree. On the validation record: its
  R-GX-06 section gives the result as 满足（测试）, while the "only" in "cleared only at step 2" rests on
  code reading (row 149 gives 满足（测试加代码阅读）), and its limit sentence omits the integration normal
  case, which shows reuse through the real spawner; neither changes this disposition (change request in
  this folder, 2026-10-19).
- Design obligations (engine; each realized at commit 3ec67985 and to be kept by any later build): T-01 —
  the reserved fields immutable in code, not by convention (EV-187); T-09 — refuse any second install on a
  row (EV-219); T-40 — clear the link only in step 2 (EV-194); T-45 — gate release on step 2 (EV-205); T-21
  — admit an event library only after the AA-13 check (EV-191).
- Cross-references: R-G1-03, R-GX-02, R-GX-03 (the named causes of D_51); R-G2-10 (p52); R-G3-05 (the
  consumer-side slot under the same standing); R-GX-04 (epoch survivors, MM-10 still open). Obligations: #6
  (reference-monitor correctness) is the one a cause of this shape would breach; #2 and #4 adjacent.
  Conditions C1–C4: none.
