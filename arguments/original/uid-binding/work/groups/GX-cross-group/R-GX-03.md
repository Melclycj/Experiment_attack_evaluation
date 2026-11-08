---
route_id: R-GX-03
group: GX
owner: GX stream subagent (Claude Fable 5.1, cold context), dispatched by the main session on 2026-10-15; re-run 2026-10-19 for follow-up step 4 (Claude Opus 5.5, cold context); wording compacted 2026-10-21 (shared evidence boundary cited; no content change)
status: ready-for-reconcile
date: 2026-10-19
violates: C-05/C-07
stops: "no member of A is alive once A's lease is released and no CLOSED row is ever read, while the engine's reader and callbacks are bound to the Channel object and its generation — deregistered, then the fd shut and its close performed once at T-40 step 2 before the number can be reused — so neither a late send nor a stale readiness event reaches another row"
disposition: supported under stated premises
based_on:
  model_blob: "d27d65d7874bbf6c"
  decomposition_blob: "5d2a0b9438f37302"
  invariant_blob: "ae58d7db31c95c82"
  registry_blob: "97b869a738a79b0e"
---

# R-GX-03 — A sends to a stale endpoint or races numeric fd/generation reuse and its bytes/readiness callback is attached to a different row.

## 1 What the adversary does
A sends to a stale endpoint or races numeric fd/generation reuse and its bytes/readiness callback is attached to a different row.

## 2 How it would produce false attribution
- **Preconditions:** two halves. **(i) Member-after-release:** a byte is accepted at a row after that row's
  interval ended — after T-45 released its uid, or after T-49 retired its epoch — either because a task of
  A still sends into A's channel and the engine still accepts there, or because a task at u that is not the
  accepting row's member sends after that row's interval ended. **(ii) Alias:** A's row is CLOSED; T-40
  step 2 frees A's owned_fd number N; the kernel assigns N to the next descriptor the engine receives — B's
  engine end at B's T-09 (MSG_CMSG_CLOEXEC, lowest free number) — while a readiness callback, reader
  registration or FrameReader still associated with A fires on N, or a consumer finds a row by uid or fd
  number, or A's receiver_generation value recurs for B's Channel; B's bytes are then read through A's
  object and labelled A, or A's bytes, still on A's socket, are read through a number-keyed path into B's
  reader. The adversary's levers are timing (A-06): send then exit at once (T-65), bye or EOF right after
  a send (T-48, T-46), a flood that keeps A's socket readable while A's row closes, and rapid launch/exit
  cycles that churn fd numbers; and endpoint actions (T-63): copies of fd 3 in same-execution descendants
  (they die with PID 1) and shutdown or close of fd 3 to place EOF at a chosen instant. Configuration: all
  three under the common abstraction of the frozen revision.
- **Transitions traversed:** T-20, T-65, T-63 (A's sends and endpoint actions); T-46 (EOF or deadline into
  T-40); T-40 (step 1 CLOSED; step 2 deregistration, shut, close once by object/generation; steps 1–4 one
  decision, 01 v9 MM-09 resolved); T-43;
  T-45 (J_A ends); T-49 (epoch end); T-01, T-04, T-09 for B (G1 facts: a new fd received with CLOEXEC, a
  new Channel object and generation); T-21 … T-24 at either row; T-51 (a late callback).
- **Sufficient condition violated:** half (i) is C-07 p71 — send_b at or after J_r's end — cell D_71 ∧
  ¬q27; half (ii) is C-05 p51 — the row read at a does not correspond to the Channel the bytes arrived on
  — cell D_51 with selector q20 (a later association change follows a numeric fd, uid or generation lookup
  or an object alias); B(R-GX-03) is the OR of D_51 ∧ ¬(q18 ∨ q19) ∧ q20 and D_71 ∧ ¬q27. Why it is a
  wrong attribution: in (ii), B's bytes read through A's object carry A's label while Exec(b) = B, or A's
  stale bytes gain B's label; in (i), a row whose interval ended still produces a label for bytes it no
  longer corresponds to. A member of A sending into a *foreign* endpoint is C-06's and not this route
  (R-G4-01 in the same epoch, R-GX-04 across epochs, R-G5-06 and R-G5-07 for other holders).

## 3 What stops it
No member of A is alive once A's lease is released and no CLOSED row is ever read, while the engine's
reader and callbacks are bound to the Channel object and its generation — deregistered, then the fd shut
and its close performed once at T-40 step 2 before the number can be reused — so neither a late send nor a
stale readiness event reaches another row.

**Half (i).** T-45 requires row CLOSED ∧ membership_empty (conn L805–806; since 01 v9 also close step 2
done), and a sound empty fact (IG-03,
IG-05; G4 preservation, rows T-42 and T-43) means no member of A is alive at release, so no send by A
follows J_A's end ("no member is alive at release, so no send by X_r can follow it" — G4 row T-45; G4
preservation §D4 sorts this half "stopped by E-04"). No new read is made from a CLOSED row (conn L413; IG-13; G4
row T-40) and a CLOSED row never returns to ACTIVE (conn L327), so no byte sent at or after release — the
row being CLOSED by T-45's precondition — is read at the released row. What IG-13 does allow (03 v4 §2): a
D-ACC whose last read preceded the close may finish on the CLOSED row, and it carries that row's own label,
which is not false attribution and not this route's history, since every byte of it was read while the row
was open. At T-49 every row is CLOSED and the old epoch's leases are quarantined and never
recovered (G4 row T-49); a survivor's bytes land on the old socket and are unread; the new epoch's
executions have new socketpairs (IG-12; G1 row T-04). What is left for a non-member at u after a row's
interval ended is reaching that row's socket, which needs a foreign endpoint (A-07) and is C-06's.

**Half (ii).** The frozen text binds the reader and every callback to the Channel object, not to the
number: the fd is owned by the object and callbacks hold the object and its generation (conn L81); at T-40
step 2 the reader and writer registrations are removed and the fd is shut and then its close performed
exactly once by object and generation (conn L791) — the number N is free only after that step, when no
registration for A's object remains; a response callback that later sees the same fd number or request id
is not re-addressed (conn L523); after a uid is released no table is consulted by uid (conn L835–837); T-23
never looks up another row by the observed uid (conn L424; IG-07); T-43 matches by ids (conn L116, L830);
T-51 performs release only (G4 row T-51). The second line: every read is preceded by the check that the
object the reader holds is not CLOSED (conn L413); a stale readiness event delivered for A's object after
step 1 finds A's row CLOSED and performs no recvmsg on whatever N now names (G2 row T-21; G4 row T-40 and
J-07). The field that check consults is stated as Session.admission (01 v9 T-21, conn L481–482; G4 change
request 1), and steps 1 and 2 share one executor decision (01 v9 MM-09 resolved), so no event is
dispatched between them; under the other reading too, both the Session state and the Channel phase are
terminal once step 2 has run, and only after step 2 can N be reused.
B's install at T-09 creates a new Channel object with its own channel_id, owned_fd (received with CLOEXEC)
and receiver_generation (G1 row T-09; EV-76), and B's FrameReader starts empty (R-GX-01 §3). The design
also states that after deregistration the event library delivers no readiness for that fd number (AA-13,
conn L483–484) and how receiver_generation is set (01 v9 MM-15 resolved). This route's cut does not use the
generation value: it uses object identity, the step-1 CLOSED check and the order deregister → shut → close
at step 2 before the number is free. An implementation that keyed a registration, a readiness dispatch or
a lookup by fd number, uid or a generation counter rather than by object would have no cut — that is the
obligation, restated in §6. Preservation rows relied on: G4 T-40, T-42, T-43, T-45, T-46, T-49, T-51 and
§D4's two R-GX-03 lines; G2 T-21, T-23, T-24, T-63; G1 T-04, T-09.

In the prototype both halves are realized, and the alias half has two layers: the event loop dispatches a
selected event only if the callback object it snapshotted at selection is still the fd's current
registration (the AA-13 check, EV-191 and EV-192), and a receive callback acts only while its own Channel
object is the row's current Channel in an open phase (EV-192 note, phases.py:56–63). Section 4 maps both.

## 4 Support
| evidence id | tag | what it shows | file and section | date / substrate / version |
|---|---|---|---|---|
| EV-17 | [R] | PID 1's exit disables pid allocation, kills every remaining pid and waits until every other pid is freed before PID 1 is reapable | kub §2.6 | 2026-10-13; pinned tag |
| EV-18 | [R] | the same wait covers outside-parent and parent-ptraced tasks | kub §2.6 | 2026-10-13; pinned tag |
| EV-67 | [M] | d6 D′: after PID 1 exited, the forked survivor was silent | REPORT-dprime-build.md §d6 | 2026-08-15/16; WSL2; real root; no seccomp; lab engine |
| EV-68 | [M] | d6 D′−ns: without a pid namespace the survivor spoke at the recycled uid and the lab engine's session table resolved it to execution 2 — the consequence this route needs, measured where the gate is absent | REPORT-dprime-build.md §d6 | as EV-67 |
| EV-79 | [M] | the P2a spawner accepted only a unique waitpid terminal state; after losing ownership no numeric PID is signalled again | implementation-validation.md SC-reclaim (L50) | 2026-09-11; diagnostic policy |
| EV-206 | [R] | the spawner marks a record empty only after its waitpid on the record's PID 1 returns an exit or signal, or for a never-cloned record; a wait error is a reap failure plus control loss, never empty; SIGCHLD stays SIG_DFL | eng spawner.c:53–58, :158–163, :221–227, :365–393, :400–401 (val rows 209, 210) | commit 3ec67985; code reading |
| EV-16 | [S] | the reclamation gate is engine behaviour | kub §2.6 | design text; realized by EV-205, EV-203, EV-204 |
| EV-205 | [R] | membership_empty is set only from the spawner's empty fact or the local withdrawal; the uid lease is released only when CLOSED, empty, close step 2 run and HELD, once | eng lifecycle.py:328–349, :443–449, :491–502 (val rows 204–206) | commit 3ec67985; code reading |
| EV-203 | [M] | unit tests of the empty wait, quarantine, never_created after prepared, the normal round trip and duplicate terminals passed | int (unit suite) (val rows 205, 206) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-204 | [M] | a failing kill and a kill with no effect each left the lease quarantined and the uid not reused | int pool70000.json, cases kill-error and kill-no-fact | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy; real spawner, test build |
| EV-172 | [R] | receive_step checks Session.admission before reading and calls the C reader only on an OPEN session | eng receive.py:273–300; phases.py:61–87 (val rows 162, 171, 172) | commit 3ec67985; code reading |
| EV-239 | [M] | once the session's admission is CLOSED the receiver makes no call into the C reader | int (unit suite) (val row 162) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-217 | [R] | on a control fault every row is set CLOSED and each lease quarantined without an empty fact; the engine exits when the control link is dead | eng lifecycle.py:526–533; main.py:67–80 (val row 217) | commit 3ec67985; code reading |
| EV-44 | [R] | provenance is live-at-send; the sender need not exist when the engine acts | kub §8 | read 2026-10-14 |
| EV-94 | [R] | fd numbers are table-local and create no reference to another endpoint | desc9 §9.1 | pinned commit 427645e3db3a |
| EV-66 | [M] | a close drops one reference; shutdown acts on the shared open file description — after step 2's shutdown the peer's sends fail | REPORT-dprime-build.md §d5 | 2026-08-15/16 |
| EV-76 | [M] | the prepared fd arrived with CLOEXEC and PASSCRED kept; one unnamed STREAM fd | implementation-validation.md SC-handoff (L47) | 2026-09-11; diagnostic policy |
| EV-133 | [S] | the fd is owned by the Channel object and callbacks hold object and generation; at close step 2 registrations are removed, then the fd is shut and its close performed once by object and generation; unsent frames dropped | conn E-01 objects (L81); E-04 close (L791–793) | design text; realized by EV-192, EV-193 |
| EV-192 | [R] | close step 2 removes every registration of the fd through loop.forget before shutdown and close, then sets the Channel phase CLOSED, drops its Session link and frees reader and writer; the loop dispatches a selected event only if the callback snapshotted at selection is still the current registration | eng lifecycle.py:460–475; loop.py:58–85, :104–126; phases.py:45–53 (val §AA-13; rows 161, 163, 202) | commit 3ec67985; code reading |
| EV-193 | [M] | after close the link is None, the phase CLOSED, the fd in no loop registration, reader and writer discarded | int (unit suite) (val §关联只按对象建立与清除; rows 149, 202) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-191 | [M] | AA-13 check: on the real close_session path an old Channel's fd selected in a round was retired and its number at once reused by a new socket; the old receive callback was not called, the new registration got no stale event, the new socket's data was reported only by the next select; with the identity check removed both new tests failed | aa13 README §结果; output.txt; negative_control.py (val §AA-13; row 163) | 2026-10-18; WSL2 6.6.87.2-microsoft-standard-WSL2; CPython 3.12.3, EpollSelector; epoll backend only; reuse made by os.dup2 |
| EV-124 | [S] | the response callback holds the original RequestEntry and Channel and is never re-addressed when the same fd number or request id appears later | conn E-01 (L84); E-02 (L523); E-03 (L641); rr E-07 (L339–340) | design text; realized by EV-197, EV-198, EV-190 |
| EV-198 | [R] | admission builds a RequestEntry holding its Session, Channel, Execution, TaskCall, TaskBinding and GrantState; the Sink holds only its entry and manager | eng requests.py:81–99, :144–182; handlers.py:147–150 (val rows 226, 227, 234) | commit 3ec67985; code reading |
| EV-197 | [M] | with the row for the execution_id replaced by a decoy before the request frame, the request path ran on the original objects; each of four stages changed to look up by execution_id hit the decoy | int (unit suite) (val §consumer 按引用携带; row 226) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; up to the stub handler |
| EV-138 | [S] | acceptance criteria name forced reuse of uid and numeric fd: old callbacks and late notices cannot reach a new session | conn E-01 checks (L343); E-02 checks (L533) | acceptance criteria; realized by EV-189, EV-190, EV-191 |
| EV-189 | [M] | integration normal case: a second execution on the same workspace and uid got a new lease and the same fd number in a new Channel object; the first execution's stale callbacks had no effect; the second Hello was attributed to the second row | int pool70000.json, cases normal (test and production build) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy; real spawner, reuse in sequence |
| EV-190 | [M] | with a new row on the same uid and fd number, the old row's callbacks, deadlines and late facts did not reach the new row, and an event selected for the old registration was not dispatched to the new one | int (unit suite) (val rows 141, 147, 148, 161) | 2026-10-19; fd reuse made by the test (low fds held or dup2) |
| EV-194 | [R] | the Channel → Session link is made only by constructing a new Channel at install; the only other assignment sets it to None at close step 2 | eng lifecycle.py:147–158, :273–283, :460–475 (val row 149) | commit 3ec67985; code reading |
| EV-196 | [R] | the only uid-keyed table is the allocator's holders; the only fd-keyed table is the loop's handlers, used to fetch the callback registered on that fd and checked by identity before dispatch | eng lifecycle.py:100, :140, :150–157, :500–501; loop.py:50, :112, :122 (val row 142) | commit 3ec67985; code reading |
| EV-78 | [S] | the product receive path and E-02 integration were unbuilt at the P2a run | implementation-validation.md SC-frames limit column | 2026-09-11; realized by EV-169–EV-175, EV-239 |
| EV-96 | [S] | the execution/session associations live in engine userspace, not in the fd table | desc9 §9.2 | design text; realized by EV-186, EV-194, EV-196 |
| EV-77 | [M] | the transport reader froze the uid and SO_COOKIE so an fd replaced between calls could not continue a frame | implementation-validation.md SC-frames (L48) | 2026-09-11; diagnostic policy; transport library |
| EV-89 | [R] | the reader binds expected uid, overflow value, fd and cookie on first use and goes dead on any change | fdsurvey/local-semantics §2 | 2026-09-28 |
| EV-91 | [R] | the cookie check and the following I/O are separate syscalls; exclusive ownership and a single reader are design requirements | fdsurvey §4; local-semantics §5 | 2026-09-28 |

**Composition:** two sub-routes, each a conjunction, every necessary item now backed by `[R]` or `[M]`.
Half (i): kernel zap ordering (EV-17 ∧ EV-18 `[R]`) ∧ the spawner's empty basis only from its own reap
(EV-206 `[R]`, beside the P2a observation EV-79 `[M]`) ∧ the engine's gate and no read after CLOSED — the
design row EV-16 `[S]` realized by EV-205 `[R]` with EV-203 and EV-204 `[M]`, and the pre-read check by
EV-172 `[R]` and EV-239 `[M]`; at an epoch end, EV-217 `[R]`. Half (ii): object-keyed registration,
deregistration before the close, and callbacks bound to objects — the design rows EV-133, EV-124 and
EV-138 `[S]` realized by EV-192, EV-194, EV-196, EV-198 `[R]` and EV-193, EV-197 `[M]`; the library
property AA-13 checked by EV-191 `[M]` with EV-192 `[R]`; fd-number and uid reuse checked by EV-190 `[M]`
(reuse made by the test) and EV-189 `[M]` (reuse through the real spawner, in sequence); the kernel's
table-local numbering EV-94 `[R]`. EV-67 and EV-68 are the lab engine's consequence measurements and
EV-77, EV-89, EV-91 the earlier transport library — isolated components. No recorded run exercised the
composed alias history of 04 §5 item 26 — a stale readiness event injected after B's prepared fd lands on
A's old number through the real spawner's handoff — so half (ii) is not measured end to end; the AA-13 run
and the normal case each check one part.

**Proposed evidence (not yet in the registry):** none new; 04 §5 item 26 stays "in part" (EV-191 and EV-189
cover its two parts separately).

## 5 Disposition
**supported under stated premises** — the same value as the `disposition:` field. Every necessary item of
section 4's composition is backed by a code reading or a run of the prototype.
- Premises that must hold: the empty fact is sound (IG-03 … IG-05; the spawner trusted and running the code
  read in EV-206, AA-04; kub §2.6 at the pinned tag, AA-02); the event library in use is the one the AA-13
  check ran on — CPython selectors with the epoll backend — or another that passes the same check; the
  single executor (AA-01); the common abstraction of the frozen revision for C-LS, C-LP and C-R. This rests
  on the frozen design, kernel semantics where cited and the prototype's checked realization; it is not a
  claim about a deployed system.
- Evidence limit (configuration, substrate, run dates): runs of 2026-10-18/19. Check limits as validation.md states them: the AA-13 check
  covers the epoll backend only and makes the fd-number reuse with os.dup2, not by the spawner's handoff
  (EV-191; it ran on commit 73f86021 plus the test file, with loop.py, lifecycle.py and phases.py identical to
  74833c58); the unit reuse tests make the reuse themselves (EV-190); reuse through the real spawner is observed
  only in sequence, across rounds (EV-189). The gate's kernel evidence is kub's reading at
  linux-msft-wsl-6.6.87.2 and the lab engine's d6 of 2026-08-15/16. The bounded TLC check does not model fd
  numbers or K-10 (03 §5.1).
  Shared limits: [coverage-uncertainties § Shared evidence boundary](../../convergence/coverage-uncertainties.md#shared-evidence-boundary-every-route-not-repeated-below).

## 6 What remains
- Residual and open questions: the receiver_generation value is set as 01 v9 MM-15 states and is
  write-once (EV-187) but is not what the cut uses (val row 148 records the same: old callbacks lose effect
  by object identity, not by the generation number); outbound frames of A's request after N is reused go to
  A's original Channel object and are dropped at step 2 (conn L792; EV-192) — a different property (X-10)
  and R-G3-03's consumer domain; host pid reuse (K-10) is not an alias of this route, since the spawner
  signals no reaped pid and the engine signals none (G4 J-08). The IG-10 split of 03 v4 is not used.
  Coverage uncertainty left: the composed alias run through the real spawner (04 §5 item 26) is not done;
  another selectors backend or event library needs the AA-13 check again before it is admitted.
- Design obligations surfaced for the engine (one sentence each; each is realized at commit 3ec67985 and
  must be kept by any later build):
  - T-40 step 2: remove every registration for the Channel object before the fd's close and perform the
    close once (EV-192, EV-193).
  - T-21: map a readiness event to the callback object registered when it was selected, never number →
    object, and run the pre-read check on that object before any recvmsg (EV-191, EV-192, EV-172).
  - T-09: every install creates a new Channel object; no old object or generation value is reused for a
    new fd (EV-194, EV-187).
  - T-43 / T-51: match and apply by ids and object references, never by uid or fd number (EV-196, EV-220).
- Cross-references: R-GX-01 (A's stale bytes into B's label through the socket or buffer), R-G2-04 (two
  current generations mixed), R-G2-09 (a foreign endpoint with a different uid), R-G4-01 (a surviving
  member sends inside J_B), R-GX-04 (across epochs), R-GX-02 (a control event re-associates a row), R-GX-06
  (the remainder of cell D_51), R-GX-05 and R-G3-03 (consumer-side relookup by fd or request number).
  Obligations: #1 (channel/FD unforgeability — the one-shot channel), #2 (channel-to-agent binding), #4
  (no agent-ID confusion) and #6 (reference-monitor correctness) are touched. Conditions C1–C4: none.
