---
route_id: R-GX-02
group: GX
owner: GX stream subagent (Claude Fable 5.1, cold context), dispatched by the main session on 2026-10-15; re-run 2026-10-19 for follow-up step 4 (Claude Opus 5.5, cold context); wording compacted 2026-10-21 (shared evidence boundary cited; no content change)
status: ready-for-reconcile
date: 2026-10-19
violates: C-05; C-06/C-07 if reused
stops: "every control record is matched to the original row by engine_epoch, execution_id and lease_id and never by uid or fd — a late prepared on a CLOSED row has its fd shut and installs nothing, a consumed prepared arriving again has its fds shut and faults, a duplicate empty is ignored with no second release, and CLOSED is terminal"
disposition: supported under stated premises
based_on:
  model_blob: "d27d65d7874bbf6c"
  decomposition_blob: "5d2a0b9438f37302"
  invariant_blob: "ae58d7db31c95c82"
  registry_blob: "751aa7d69983c406"
---

# R-GX-02 — A times failure, late prepared/empty or duplicate control events so the wrong original lease/session is installed or reactivated.

## 1 What the adversary does
A times failure, late prepared/empty or duplicate control events so the wrong original lease/session is installed or reactivated.

## 2 How it would produce false attribution
- **Preconditions:** two rows of one engine epoch for the same workspace uid u in succession (A, then B
  after A's release) or two concurrent rows (A and C on distinct uids); a control record meant for one row
  acts on another, or revives a row that was CLOSED. The adversary of A controls only timing after T-11:
  when its tasks exit (K-01, T-65) and hence when the spawner produces execution_empty, when hello, bye or
  EOF arrive, and how long it stalls (A-06). It cannot write a control record (A-09; conn L98, L347), and
  it does not exist before T-11, so the order of spawn_prepared against the row's startup deadline or empty
  fact is trusted-actor timing (K-04) — admitted here as the honest-but-buggy case of 02 §0.3. The
  histories: (a) a prepared for A arriving after A's row is CLOSED (deadline, or empty-first) while B is
  RESERVED or PREPARING on the same u; (b) a spawn_prepared already consumed arriving again (a
  byte-identical old seq, or a spawner defect) while A's Channel exists or after its fd was shut; (c) an
  execution_empty for A duplicated, or arriving late after B took u, so that B's membership_empty is
  written; (d) a spawn_failed treated as an empty fact; (e) a local_never_submitted basis written for a
  record that did reach the spawner; (f) after T-49, a record of the old epoch arriving at the new engine;
  (g) any of these reactivating A's CLOSED row so that bytes still queued on A's socket are accepted at a
  row whose reservation no longer corresponds to its Channel. "If reused": where (c) or (e) frees A's
  lease while A's tasks live, u is reused while alive — the C-06/C-07 shape of R-G4-01, reached through a
  control event. Configuration: all three under the common abstraction of the frozen revision.
- **Transitions traversed:** T-02 (submission state), T-09 (prepared; its late branch), T-13, T-14, T-43,
  T-52, T-49; T-40 (step 1 CLOSED; step 4 stop or withdrawal), T-45; then T-20 … T-24 at the misassociated
  or revived row (G2 facts).
- **Sufficient condition violated:** C-05 p51 — the row read at acceptance no longer holds the immutable
  reservation A_r corresponding to its original Channel — cell D_51 with selector q19 (a prepared, empty
  or duplicate control event later changes the association or reactivates a retired row); B(R-GX-02) =
  ¬H ∧ D_51 ∧ ¬q18 ∧ q19. Secondary: C-06 p61/p62 or C-07 p71 where a lease is re-associated or freed. Why
  it is a wrong attribution: A's clone's bytes installed into B's row are labelled B; bytes accepted at a
  revived A row are accepted after A_r's interval ended, with a label whose reservation the Channel no
  longer corresponds to.

## 3 What stops it
Every control record is matched to the original row by engine_epoch, execution_id and lease_id and never by
uid or fd — a late prepared on a CLOSED row has its fd shut and installs nothing, a consumed prepared
arriving again has its fds shut and faults, a duplicate empty is ignored with no second release, and CLOSED
is terminal. Per history:

- **(a) Late prepared.** T-09's late branch: a prepared for a CLOSED row shuts the received fd and registers
  a stop (conn L324); empty-first ordering closes the row first, the late fd is shut and the message does
  not enable the row (conn L334–335). The prepared record names execution_id, lease_id and engine_epoch
  and is matched to the original object (conn L231), never to "the row currently holding u"; B's row has a
  different execution_id (engine_epoch:allocation_seq, never reused, conn L71–73) and lease_id
  (execution_id + ":u"), so A's prepared cannot match B. G1 preservation, row T-09 (install only on the
  success branch, into the named row, in one decision); G4 preservation, row T-43 (empty-first ordering).
- **(b) Duplicate prepared.** A consumed spawn_prepared arriving again, whatever its seq, has every fd it
  carried shut first and then raises a control fault; no descriptor is installed back into an old Channel;
  the idempotent-ignore branch exists only for fd-less, byte-identical old records (conn L135–138). G4
  row T-52 (IG-09).
- **(c) Late or duplicate empty.** execution_empty is matched by engine_epoch, execution_id and lease_id,
  never by uid (conn L116, L830); a record carrying the same terminal is ignored by comparing its terminal
  fields, with no second reclamation (conn L133–134); an event beyond the tombstone window is a protocol
  fault that revives nothing (conn L138–141); a late empty for A names A's ids and cannot land on B; one
  release per lease (conn L328). G4 rows T-43, T-45, T-52.
- **(d) spawn_failed.** It closes the row it names and is stated not to be an empty fact (conn L114, L828);
  no basis is written. G1 row T-13.
- **(e) Local withdrawal.** local_never_submitted is written only while submission = local, after the
  writer confirms in its own ownership domain that nothing was sent; an uncertain submission sends a stop
  and waits for the spawner's fact (conn L322–323, L797–800). G1 rows T-02 and T-14; G4 row T-40 (step 4).
- **(f) New epoch.** No reconnect or replay (conn L131); the new engine's epoch value differs and an unknown
  execution or lease is a control fault (conn L133); the old epoch's leases are never recovered (conn
  L866–867); a new spawner's self-report lifts no old quarantine (conn L832). G4 rows T-49 and T-44.
- **(g) Reactivation.** CLOSED is terminal (conn L327); accepting_new reopens no CLOSED or DRAINING session
  (conn L577); a hello after empty cannot revive (conn L334–335); tombstones serve idempotence only and no
  execution is revived from one (conn L138–141, L837). G4 row T-40; G1 row T-12.

G4 preservation §D4 sorts this route's G4 half "stopped by E-04" (T-43, T-52 · IG-03, IG-06, IG-09). The G1
half — install only into the named original row while it is PREPARING, never on a CLOSED row — is G1's rows
T-09, T-13 and T-14. On the adversary's reach: the only control events it can time are downstream of its
own exit or protocol behaviour (empty via T-42/T-43, EOF, bye, a deadline met by silence), each matched by
ids, and the spawner emits an empty fact only from its own waitpid return or its own seal (G4 rows T-41,
T-42; G1 row T-03), so no timing by A makes an empty fact appear for a row other than A's. Preservation
rows relied on: G1 T-02, T-03, T-09, T-12, T-13, T-14; G4 T-40, T-41, T-42, T-43, T-44, T-45, T-49, T-52.
The engine prototype realizes each per-history rule; section 4 maps them to code readings and tests. In the
build, history (f) cannot arise inside one engine process: the engine exits on control loss and has no
path that accepts a new spawner (EV-217), and a new engine process draws a fresh epoch (EV-240).

## 4 Support
| evidence id | tag | what it shows | file and section | date / substrate / version |
|---|---|---|---|---|
| EV-76 | [M] | the P2a receiver rejected missing, multiple or unexpected fds, a wrong socket, a named endpoint, truncation, extra fields and control credentials on prepared; the fd arrived with CLOEXEC | implementation-validation.md SC-handoff (L47) | 2026-09-11; WSL2 6.6.87.2; diagnostic policy |
| EV-97 | [M] | a FAIL or empty arriving after handoff is processed in order with the original execution and lease and the actual wait recorded; a preparation failure leaves no exec marker | implementation-validation.md SC-fault (L49) | 2026-09-11; diagnostic policy; 129 injected fault cases |
| EV-98 | [M] | same-round close race: a retry of an earlier READY slot after a later slot's child was reported lost must seal clone | implementation-validation.md 同轮关闭竞争 (L51) | 2026-09-11; diagnostic policy; READY object is a fixture |
| EV-79 | [M] | the P2a spawner accepted only a unique waitpid terminal state across a repeated stop, orphans, EOF, ineffective kill, ESRCH/EIO, ECHILD and two-execution faults | implementation-validation.md SC-reclaim (L50) | 2026-09-11; diagnostic policy |
| EV-17 | [R] | PID 1's exit zaps the namespace before PID 1 becomes reapable — the basis every pid1_reaped rests on | kub §2.6 | 2026-10-13; pinned tag |
| EV-66 | [M] | a close drops one reference; the open file description stays with other holders — a shut late fd keeps no engine reference | REPORT-dprime-build.md §d5 | 2026-08-15/16; WSL2; real root |
| EV-94 | [R] | fd numbers and other identifiers create no reference; operations resolve in the caller's own table | desc9 §9.1 | pinned commit 427645e3db3a |
| EV-102 | [S] | session, channel and lease identifiers derive from execution_id, one of each per execution, execution_id = 128-bit random engine_epoch joined to a non-wrapping allocation_seq | conn E-01 objects (L71–73) | design text; realized by EV-240 |
| EV-240 | [R] | engine_epoch is 32 hex digits from secrets.token_hex(16) at start-up; allocation_seq refuses to pass 2^64 − 1; lease, Session and Channel ids are execution_id + :u, :s, :c | eng startup.py:96–98; lifecycle.py:145–150, :276; main.py:47 (val row 141) | commit 3ec67985; code reading |
| EV-103 | [S] | a control record is validated in full, its association must match the original object, an unknown execution or an inconsistent lease is a control fault, and no lookup of an execution by numeric fd or uid exists | conn E-01 control (L116, L133); C17 (L226, L231); E-04 (L830) | design text; realized by EV-218, EV-220, EV-196, EV-269 |
| EV-220 | [R] | a control record is matched by execution_id with lease_id compared; an unknown execution faults unless it repeats the tombstone's terminal; a fact for a never-submitted row faults; any record with another engine_epoch faults before that | eng lifecycle.py:197–235; control.py:204–207 (val row 184) | commit 3ec67985; code reading |
| EV-218 | [M] | records with another engine_epoch, for an unknown execution, with a changed lease_id, or for a never-submitted row each faulted | int (unit suite) (val row 184) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; unprivileged unit suite |
| EV-196 | [R] | the only uid-keyed table is the allocator's holders (reservation and release); the only fd-keyed table is the loop's handlers, checked by identity before dispatch | eng lifecycle.py:100, :140, :150–157, :500–501; loop.py:50, :112, :122 | commit 3ec67985; code reading |
| EV-269 | [M] | the control-record parser fuzzed again after 7b4ab727 with no finding; same oracle as EV-168 (every accepted record a v=1 object of a known type) | fuzz-no-c-parse README §结果; fuzz-control.log | 2026-10-19, 3600 s, one run, no repetition; the parser uses jansson, uninstrumented, whose input is the trusted spawner's control records |
| EV-168 | [M] | the earlier control-parser fuzz run with no finding | fuzz README §结果; fuzz-control.log | 2026-10-18/19, 3600 s; superseded by EV-269 (registry §2) |
| EV-134 | [S] | seq discipline; a consumed spawn_prepared arriving again has all fds shut first and then faults; a same-terminal duplicate is ignored with no second reclamation; tombstones serve idempotence only | conn E-01 control (L131–142) | design text; realized by EV-219, EV-222, EV-203 |
| EV-219 | [M] | prepared again or mismatched closes its fd and faults; a duplicate equal terminal is ignored and a conflicting one faults; seq rules; an old seq carrying an fd closes it and faults | int (unit suite) (val row 185) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-135 | [S] | a late spawn_prepared on a CLOSED row has its fd shut and a stop registered; after empty-first ordering a later prepared or hello cannot enable the row | conn E-01 state table (L324, L334–335) | design text; realized by EV-222, EV-185 |
| EV-185 | [R] | the install compares digests and copy_id with the row and installs the fd only while the row is PREPARING within its deadline | eng spawner.c:189–193, :214–220; lifecycle.py:244–271 (val rows 143, 184) | commit 3ec67985; code reading |
| EV-222 | [M] | a prepared for a CLOSED row stops once; a late prepared after the deadline stops once with timeout; the tombstone window test passed | int (unit suite) (val rows 143, 201) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-136 | [S] | CLOSED is terminal and accepting_new reopens no CLOSED or DRAINING session | conn E-01 state table (L327); E-03 (L577) | design text; realized by EV-222, EV-239 |
| EV-239 | [M] | once the session's admission is CLOSED the receiver makes no call into the C reader | int (unit suite) (val row 162) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-16 | [S] | the reclamation gate is engine behaviour | kub §2.6 | design text; realized by EV-205, EV-203 |
| EV-205 | [R] | membership_empty is set at exactly two places (spawner empty fact, local withdrawal); the uid lease is released only when CLOSED, empty, close step 2 run and HELD, once | eng lifecycle.py:328–349, :443–449, :491–502 (val rows 204–206) | commit 3ec67985; code reading |
| EV-203 | [M] | empty wait quarantines and a real empty lifts it; control fault closes all and quarantines; never_created after prepared faults; normal round trip; duplicate terminal ignored, conflict faults | int (unit suite) (val rows 205, 206) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-206 | [R] | the spawner marks a record empty only after its waitpid on the record's PID 1 returns an exit or signal, or when the record was never cloned; a wait error is a reap failure plus control loss, never empty | eng spawner.c:53–58, :158–163, :221–227, :365–393, :400–401 (val rows 209, 210) | commit 3ec67985; code reading |
| EV-211 | [M] | startup faults at validate, clone, uid.reread, policy and handoff each gave spawn_failed with that stage, no Channel, and the row CLOSED, empty, lease FREE | int pool70000.json, cases startup-fault | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy; real spawner, test build |
| EV-107 | [S] | the control writer withdraws a never-sent spawn in its own ownership domain and only then records membership_empty with basis local_never_submitted | conn E-01 (L103–104, L323); E-04 (L797–798) | design text; realized by EV-221 |
| EV-221 | [M] | local withdrawal and "an uncertain send is never local" passed; the integration close-preparing case ended with stop sent, basis never_created, lease FREE | int (unit suite; case close-preparing) (val rows 186, 187) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy for the integration case |
| EV-190 | [M] | with a new row on the same uid and fd number, the old row's callbacks, deadlines and late facts did not reach the new row | int (unit suite) (val rows 141, 147, 148, 161) | 2026-10-19; fd reuse made by the test |
| EV-216 | [M] | on control loss the spawner stopped, reaped and exited, and the engine set each row CLOSED, lease QUARANTINED, admission off | sbr control-loss; int control-loss cases and unit suite (val rows 216, 217) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy |
| EV-217 | [R] | on a control fault the engine closes every row and quarantines each lease without an empty fact; the main loop ends when the control link is dead; no path accepts a new spawner | eng lifecycle.py:526–533; main.py:67–80 (val row 217) | commit 3ec67985; code reading |
| EV-78 | [S] | the product receive path and E-02 integration were unbuilt at the P2a run | implementation-validation.md SC-frames limit column | 2026-09-11; realized by EV-169–EV-175 |
| EV-96 | [S] | expected uid and the execution/session associations live in engine userspace | desc9 §9.2 | design text; realized by EV-186, EV-194, EV-196 |
| EV-81 | [S] | exclusive deployment uids, frozen sources and full process-domain tracking by a trusted supervisor are stated preconditions of use | implementation-validation.md §尚未由本次证明 | 2026-09-11; design text; not a necessary item of this cut (composition) |

**Composition:** a conjunction of per-history rules, each now realized and checked. Matching by the three
ids and never by uid or fd (EV-103 `[S]`): EV-220 `[R]`, EV-218 `[M]`, EV-196 `[R]`, with the control
parser fuzzed (EV-269 `[M]`, EV-168 before 7b4ab727) and the never-reused identifiers EV-240 `[R]` (EV-102 `[S]`). (a) Late
prepared (EV-135 `[S]`): EV-185 `[R]`, EV-222 `[M]`. (b) Duplicate prepared and seq rules (EV-134 `[S]`):
EV-219 `[M]`. (c) Duplicate or late empty, one release: EV-219, EV-203, EV-190 `[M]`, EV-205 `[R]`. (d)
spawn_failed is not an empty fact: EV-205 `[R]` (membership_empty has two writers only), EV-211 `[M]`.
(e) Local withdrawal (EV-107 `[S]`): EV-221 `[M]`. (f) New epoch: EV-220 `[R]` and EV-218 `[M]` for a
record of another epoch, EV-217 `[R]` and EV-216 `[M]` for no reconnect and no recovery. (g) CLOSED
terminal (EV-136 `[S]`): EV-222, EV-239 `[M]`. The spawner side — the empty fact only from its own
waitpid or seal — is EV-206 `[R]` beside the earlier P2a observations EV-79, EV-97, EV-98 `[M]`, with
EV-17 `[R]` for the kernel half. EV-81 `[S]` stays in the table but is not a necessary item: its
exclusive-pool half is the premise named in section 5, and its supervisor half concerns survivors of an
old epoch (R-GX-04), not the matching of records. No recorded run exercised the composed history of
04 §5 item 25 (two rows holding u in succession under every event order against the real spawner); the
unit tests drive the engine against the harness's stand-in spawner, so the defence is not measured end to
end.

**Proposed evidence (not yet in the registry):** none new; 04 §5 item 25 (the two-row run against the real
spawner) remains unrun.

## 5 Disposition
**supported under stated premises** — the same value as the `disposition:` field. Every necessary item of
section 4's composition is backed by a code reading or a run of the prototype.
- Premises that must hold: the spawner is trusted and emits a record only for an execution it admitted,
  sealed or reaped, under its own seq discipline (AA-04; the code read in EV-206, EV-209); control records
  are atomic and seq-ordered, one epoch, no reconnect or replay (AA-08; EV-217); the single executor
  (AA-01); engine_epoch is a fresh 128-bit value per engine process (EV-240); the pool is exclusive to one
  engine at a time (U-05; engine-requirements §8 first entry, a deployment precondition — a concurrently
  running engine is R-G5-06, not this route); the common abstraction of the frozen revision for C-LS, C-LP
  and C-R. This rests on the frozen design, kernel semantics where cited and the prototype's checked
  realization; it is not a claim about a deployed system.
- Evidence limit (configuration, substrate, run dates): runs of 2026-10-18/19. Check limits: the per-history unit tests use the test
  harness's stand-in spawner, and the integration cases with the real spawner cover the startup faults,
  close-preparing and control loss but not every prepared/empty order on two rows of one uid; the control fuzz
  entry ran one hour with no repetition (EV-269); jansson, which since commit 7b4ab727 parses only the trusted
  spawner's control records and no agent bytes, is not instrumented; fd reuse in EV-190 is made by the test. The
  P2a observations are of 2026-09-11. The bounded TLC check models the late-prepared branch and ExecutionEmpty
  but not T-52's idempotence or tombstones (AA-08).
  Shared limits: [coverage-uncertainties § Shared evidence boundary](../../convergence/coverage-uncertainties.md#shared-evidence-boundary-every-route-not-repeated-below).

## 6 What remains
- Residual and open questions: a stop naming a record the spawner never received (T-02 uncertain) is not
  adversary-timed; the design answers it with a control fault and quarantine (01 v9 T-41; G4 J-05), and the
  build faults the whole control link on an indeterminate send (val row 186, stricter); history (b)
  presupposes a trusted-side defect or a byte-identical replay that AA-08 excludes — kept as the admitted
  honest-but-buggy case and realized as a fault (EV-219). The IG-10 split of 03 v4 and 02 v4's q32 have no
  bearing here. Coverage uncertainty left: the composed two-row run (04 §5 item 25) is not done; a later
  build that indexed control records by uid, by the received descriptor's number or by workspace alone
  would leave every cut above.
- Design obligations surfaced for the engine (one sentence each; each is realized at commit 3ec67985 and
  must be kept by any later build):
  - T-09: install only when the record's execution_id, lease_id and engine_epoch match a row in PREPARING;
    on a CLOSED row shut the fd, install nothing, register a stop (EV-185, EV-222).
  - T-43 / T-52: match by the three ids; ignore an equal-terminal duplicate without a second release;
    fault on an unknown id or an event beyond the window; never revive an execution from a tombstone
    (EV-219, EV-220, EV-222).
  - T-40: CLOSED is terminal and no later control event, hello or flag re-enters an open state (EV-222,
    EV-239).
  - T-14: write local_never_submitted only after the writer's irreversible withdrawal; an uncertain
    submission waits for the spawner's fact (EV-221).
- Cross-references: R-G1-03 (association inconsistent at install, q18), R-GX-03 (numeric or object alias
  after install, q20), R-GX-06 (the remainder of cell D_51), R-G4-01 (release while a task lives), R-GX-04
  (a record or survivor of an earlier epoch), R-G1-05 (a double allocation in one epoch). Obligations: #4
  (no agent-ID confusion) and #6 (reference-monitor correctness of the session-table lifecycle) are
  instantiated; #2 is touched. Conditions C1–C4: none is touched.
