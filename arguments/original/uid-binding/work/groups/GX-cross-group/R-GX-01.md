---
route_id: R-GX-01
group: GX
owner: GX stream subagent (Claude Fable 5.1, cold context), dispatched by the main session on 2026-10-15; re-run 2026-10-19 for follow-up step 4 (Claude Opus 5.5, cold context); wording compacted 2026-10-21 (shared evidence boundary cited; no content change)
status: ready-for-reconcile
date: 2026-10-19
violates: C-01/C-07
stops: "A's queue dies with A's socket and A's buffer with A's Channel object: B reads only the fresh socketpair T-04 created for B's own record, installed as a new Channel at T-09, and nothing is read from A's row after CLOSED"
disposition: supported under stated premises
based_on:
  model_blob: "d27d65d7874bbf6c"
  decomposition_blob: "5d2a0b9438f37302"
  invariant_blob: "ae58d7db31c95c82"
  registry_blob: "751aa7d69983c406"
---

# R-GX-01 — A's old queued or buffered bytes are attributed through a new allocation even after every old task has died.

## 1 What the adversary does
A's old queued or buffered bytes are attributed through a new allocation even after every old task has died.

## 2 How it would produce false attribution
- **Preconditions:** execution A at pool uid u sent bytes that were not consumed before A's last task died:
  skbs still queued on the engine end of A's socketpair (K-06: an skb outlives its sender until it is read
  or the socket is released; EV-58 is the datagram measurement of that fact), or a partial frame — header
  or body bytes that already passed T-23 — sitting in A's FrameReader. A's row is CLOSED (T-40 step 1),
  the empty fact arrives (T-43) and the lease is released (T-45). B is reserved for the same workspace
  under the same numeric u (T-01, a G1 fact) with a new execution_id, session_id, channel_id and lease_id
  (conn L71–74; rr L566–568). The adversary's part is only what it sends and when it exits (A-01, A-03,
  A-06; T-65): a whole frame followed by an immediate exit, or a frame left half-sent when PID 1 exits.
  A third shape, a stale decoded credential (control buffer) from an A fragment paired with a B fragment,
  is admitted under the same selector. Configuration: all three (C-LS, C-LP, C-R) under the common
  abstraction of the frozen revision; the agent ↔ engine leg is identical in each.
- **Transitions traversed:** T-20 (a) by a member of A (skbs stamped u on A's engine end); T-65 or T-42
  (send then exit; PID 1's exit empties P_XA while the engine-end queue, not part of P_XA, persists);
  T-40 steps 1–2 for A (step 2 precedes step 6: 01 v9 T-45 releases only after close step 2, MM-09 resolved); T-43; T-45; T-01, T-04, T-09 for B
  (G1 facts); T-21 … T-24 at B's row ending in a D-ACC labelled B whose Bytes(a) contain a byte whose
  ghost origin is a task of A.
- **Sufficient condition violated:** C-01 p13 — the witness fragment's data, control or buffer belongs to
  an allocation generation before A_B — with selector q05 (D_13 ∧ q05); or, where the witness relation
  holds and C-01 … C-06 hold at the event, C-07 p71 with q27: send_b is earlier than J_B's start (D_71 ∧
  q27). B(R-GX-01) is the OR of the two. Why it is a wrong attribution: the stamp is u, B's expected_uid
  is u, so the per-fragment comparison passes (C-02 … C-04 hold at the fragment) and the label is A_B's
  (C-05 holds), but Exec(b) = A, whose P_XA held the sender at send_b ∉ J_B. The uid reuse makes the
  stamp useless for separation here; separation must come from where the bytes sit. Not this route: a
  send inside J_B by a surviving task of A (R-G4-01) and a mix of two current generations (R-G2-04).

## 3 What stops it
A's queue dies with A's socket and A's buffer with A's Channel object: B reads only the fresh socketpair
T-04 created for B's own record, installed as a new Channel at T-09, and nothing is read from A's row after
CLOSED. The stale bytes can sit in three places; none is reachable from B's reader.

1. **A's socket receive queue.** The kernel holds an skb on the socket object it was queued to, and a
   descriptor-based receive resolves in the caller's own table to the open file description that fd names
   (EV-94). B's Channel reads only its owned_fd, the engine end of the socketpair the spawner created at
   T-04 for B's SpawnRecord and handed over at T-09 as the single SCM_RIGHTS fd of B's spawn_prepared,
   matched to B's row by execution_id, lease_id and engine_epoch (G1 preservation, rows T-04 and T-09;
   IG-12). A socketpair is created empty ("the new queue is empty and no row has installed it", G1 row
   T-04), and B's pair exists only after B's reservation, which T-01 grants only after A's lease is
   CLOSED ∧ empty (G1 row T-01) — so no byte A ever sent can be queued on B's socket. A's skbs stay on A's
   socket until T-40 step 2 shuts the fd and closes it once by object and generation, after which the
   kernel frees the queue with the engine's last reference — the spawner dropped its copy at T-09's whole
   send and no other holder exists (G4 preservation, row T-40; IG-12; EV-66: a close drops one
   reference). Until step 2, which shares step 1's executor decision (01 v9 T-40; MM-09 resolved), A's queue
   could be read only through A's Channel object, whose pre-read check finds the row CLOSED from step 1 on
   (conn L413, stated in 01 v9 T-21 as Session.admission; IG-13; G4 row T-40; G2 row T-21); no read falls
   between the two steps under either reading of that check (G4 change request 1), and such a read would
   carry A's own label, which is not false attribution (02 §4.1 item 3; 03 IG-13 prose). So the order of
   step 2 against step 6, which 01 v9 now states (release requires close step 2 done, T-45; MM-09, MM-11
   resolved; G4 preservation §D4 sorts this condition "design unstated"), is not what cuts the route: in either order A's skbs are on A's socket and B's
   reader never holds that socket — the point 03 §5.5 states for the subset (I holds when release precedes
   the fd shut, because nothing is read from a CLOSED row and a new execution gets a new socketpair).
2. **A's FrameReader buffer.** A Channel has exactly one receiver and one FrameReader, holding the original
   Session and generation, at most 4 header bytes and one bounded body (conn L409–410); after a frame it
   is emptied before the next header (conn L435); an old partial frame is never reused across Channel or
   TaskCall (conn L438); on close, EOF or deadline the unfinished frame is discarded (conn L434–435; G4 row
   T-46). B's install at T-09 creates a new Channel object with its own FrameReader (channel_id =
   execution_id + ":c", conn L73; G1 row T-09), so B's reader starts empty, and a byte enters B's label
   only through B's own FrameReader with a witness in B's channel and frame (G2 preservation, rows T-21
   and T-24).
3. **A stale control buffer.** Every receive step re-initialises msghdr, iovec and the control buffer and
   never reuses the previous return's length, flags or credential (conn L414–415; G2 row T-21), so a ucred
   decoded for an A fragment cannot be paired with a B fragment.

Hence every byte B accepts has its witness on B's socket, which was created after B's reservation, so
send_b ∈ J_B (p71) and p13 holds — the IG-08 argument of G2 row T-20 and G4 row T-45, read for the new
holder. Preservation rows relied on: G1 T-01, T-04, T-09; G2 T-20, T-21, T-24; G4 T-40, T-42, T-45, T-46,
T-65; G4 preservation §D4, R-GX-01 line. The engine prototype realizes each of the three cuts; section 4
gives the code readings and runs.

## 4 Support
| evidence id | tag | what it shows | file and section | date / substrate / version |
|---|---|---|---|---|
| EV-58 | [M] | qmsg: a datagram sent by a uid-1001 sender that exited and was reaped before the read still carried uid 1001 — the premise that old bytes exist after their sender's death | REPORT-netns-userns-rendezvous.md §qmsg | 2026-09-01; WSL2 kernel 6.6.87.2; datagram socket; nothing about the gate or draining |
| EV-44 | [R] | provenance is live-at-send; the kernel certifies the sender's uid at the send instant | kub §8 | source undated; read 2026-10-14 |
| EV-13 | [R] | at receive the credential is rendered from the skb's stored kuid — stamped at send, not re-derived | kub §2.5 | source reading; pinned tag |
| EV-94 | [R] | a fd-based socket operation resolves in the calling task's own descriptor table; numbers, inodes, cookies create no reference to another endpoint | desc9 §9.1 | pinned commit 427645e3db3a |
| EV-66 | [M] | after the engine closes its copy of a passed socket the other copy stays usable; shutdown acts on the shared open file description | REPORT-dprime-build.md §d5 | 2026-08-15/16; WSL2 6.6.87.2; real root; no seccomp |
| EV-34 | [S] | C4: the spawner creates the socketpair before the agent exists, with SO_PASSCRED on the engine end — one pair per launch | kub §6 C4, §6.1, §7.3 | design text; realized by EV-179, EV-178 |
| EV-179 | [R] | per record the spawner creates the socketpair, sets SO_PASSCRED on the engine end, then clones; the child gets the other end and shuts the engine end; the spawner shuts its copy of the engine end after the whole spawn_prepared send | eng spawner.c:49–51, :101–135, :244–251; child.c:100–103 (val rows 145, 150, 151) | commit 3ec67985; code reading |
| EV-178 | [M] | trace order socketpair → setsockopt SO_PASSCRED on the engine end → clone with CLONE_NEWPID | pco README §结果; sbr README §结果 (val row 145) | 2026-10-18, repeated 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy; busy case of the diagnostic fixture only |
| EV-200 | [R] | the reservation refuses a workspace whose previous row is not CLOSED with membership_empty, and takes the uid only from the workspace record | eng lifecycle.py:121–167 (val rows 128–130) | commit 3ec67985; code reading |
| EV-185 | [R] | the install compares the prepared record's digests and copy_id with the row and installs the fd only while the row is PREPARING within its deadline | eng spawner.c:189–193, :214–220; lifecycle.py:244–271 (val rows 143, 184) | commit 3ec67985; code reading |
| EV-194 | [R] | the Channel → Session link is made only by constructing a new Channel at install; the only other assignment sets it to None at close step 2 | eng lifecycle.py:147–158, :273–283, :460–475 (val row 149) | commit 3ec67985; code reading |
| EV-189 | [M] | integration normal case: after the first execution was stopped, emptied and its lease freed, a second execution on the same workspace and uid got a new lease and the same fd number in a new Channel object; the first execution's stale callbacks had no effect and the second Hello was attributed to the second row | int pool70000.json, cases normal (test and production build) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy; real spawner; native agent fixture |
| EV-78 | [S] | the product receive path, FrameReader integration and VerifiedContext were unbuilt at the P2a acceptance run | implementation-validation.md SC-frames limit column; §尚未由本次证明 | 2026-09-11; design text; realized by EV-169–EV-175 (EV-171 less its body-parse clause), EV-265, EV-239 |
| EV-96 | [S] | expected uid and execution/session associations live in engine userspace | desc9 §9.2 | design text; realized by EV-186, EV-194, EV-196 |
| EV-131 | [S] | one receiver and one FrameReader per Channel, holding the original Session and generation; emptied per frame, never reused across Channel or TaskCall; an unfinished frame is discarded on close, EOF or deadline | conn E-02 receive pipeline (L409–410, L434–435, L438) | design text; realized by EV-236, EV-238 |
| EV-236 | [R] | a FrameReader is created with its Channel at install and freed at close step 2; the C reader binds fd, socket cookie, expected uid and overflow uid on first use, dies on any change, and is reset after each whole frame | eng lifecycle.py:276–277; phases.py:45–50; transport.c:216–218, :239 (val row 174) | commit 3ec67985; code reading; at 7b4ab727 the per-frame reset is one line earlier (L238, EV-265), registry §2 |
| EV-238 | [M] | two frames in one send, a frame timer per frame and a byte-by-byte hello passed; in the integration partial case a half frame ended its row after 5.0 s with frame_timeout | int (unit suite; case agent-fault partial) (val rows 164, 174) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy for the integration case |
| EV-132 | [S] | every receive step re-initialises msghdr, iovec and the control buffer and never reuses the previous return's length, flags or credential | conn E-02 receive pipeline (L414–415) | design text; realized by EV-237, EV-267 |
| EV-237 | [R] | every data-channel recvmsg builds a new msghdr, iovec and control buffer on the stack; the ancillary parse state is reset on each call | eng transport.c:90–93, :150–154 (val row 157) | commit 3ec67985; code reading |
| EV-265 | [R] | at commit 7b4ab727 w2_frame_receive calls no JSON function between the per-fragment comparison and the copy-out; it copies out the whole body and resets the reader (L237–238); the body is parsed only in Python (receive.py:107–123, :291) | eng transport.c:211–239 at 7b4ab727; receive.py (registry `nocparse`) | commit 7b4ab727; code reading |
| EV-267 | [M] | frame fuzz entry rerun after 7b4ab727 over a real socketpair with kernel-stamped credentials: no sanitizer report, crash, timeout or oracle failure; the replay executed every line of w2_frame_receive | fuzz-no-c-parse README §结果; fuzz-frame.log; gcov-frame-transport.c.gcov | 2026-10-19, 3600 s, one run, no repetition; WSL2 6.6.87.2-microsoft-standard-WSL2; ASan/UBSan; same harness and oracles as EV-166 |
| EV-166 | [M] | the earlier frame fuzz run, on the reader of 3ec67985 that still parsed the body in C: no sanitizer report, crash or oracle failure | fuzz README §结果; fuzz-frame.log (val rows 157, 160, 164, 175) | 2026-10-18/19, 3600 s; superseded by EV-267 for the current reader (registry §2) |
| EV-172 | [R] | receive_step checks Session.admission before reading and calls the C reader only on an OPEN session | eng receive.py:273–300; phases.py:61–87 (val rows 162, 171, 172) | commit 3ec67985; code reading |
| EV-239 | [M] | once the session's admission is CLOSED the receiver makes no call into the C reader | int (unit suite), test_pre_read_check_reads_nothing_on_closed_session (val row 162) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; unprivileged unit suite |
| EV-133 | [S] | the fd is owned by the Channel object; at close step 2 registrations are removed, then the fd is shut and its close performed once by object and generation; unsent frames dropped | conn E-01 objects (L81); E-04 close (L791–793) | design text; realized by EV-192, EV-193 |
| EV-192 | [R] | close step 2 unregisters the fd before shutdown and close, sets the Channel phase CLOSED, drops its Session link and frees reader and writer | eng lifecycle.py:460–475; loop.py:58–85, :104–126; phases.py:45–53 (val rows 161, 163, 202) | commit 3ec67985; code reading |
| EV-193 | [M] | the association is made, installed and cleared by object: after close the link is None, the phase CLOSED, the fd in no loop registration, reader and writer discarded | int (unit suite) (val §关联只按对象建立与清除; rows 149, 202) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; unprivileged unit suite |
| EV-16 | [S] | the reclamation gate (membership empty and no live row) is engine behaviour | kub §2.6 | design text; realized by EV-205, EV-203 |
| EV-205 | [R] | membership_empty is set only from the spawner's empty fact or the local never-submitted withdrawal; the uid lease is released only when the row is CLOSED and membership_empty, close step 2 has run and the lease is HELD, and once | eng lifecycle.py:328–349, :443–449, :491–502 (val rows 204, 205, 206) | commit 3ec67985; code reading |
| EV-203 | [M] | unit tests of the empty wait, quarantine, never_created after prepared, the normal round trip and duplicate terminals passed | int (unit suite) (val rows 205, 206) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-77 | [M] | the transport reader froze the uid and SO_COOKIE so an fd replaced between calls could not continue a frame | implementation-validation.md SC-frames (L48) | 2026-09-11; diagnostic policy; transport library, not the product receiver |
| EV-89 | [R] | the transport reader binds expected uid, overflow value, fd and cookie on first use and goes dead on any change | fdsurvey/local-semantics §2 | 2026-09-28; source read of transport.c |
| EV-91 | [R] | the SO_COOKIE check and the following I/O are separate syscalls; exclusive fd ownership and a single reader are design requirements | fdsurvey §4; local-semantics §5 | 2026-09-28 |

**Composition:** a conjunction, every necessary item now backed by `[R]` or `[M]`. (1) The kernel's
per-socket queue: EV-94 `[R]`. (2) One fresh socketpair per execution, created after the reservation and
held only by the engine after the handoff: the design row EV-34 `[S]` is realized by the spawner code
EV-179 `[R]` and observed in order on one diagnostic-fixture case (EV-178 `[M]`); the reservation's
previous-row gate EV-200 `[R]`; install only into a PREPARING row EV-185 `[R]`; a new Channel object per
install EV-194 `[R]`, with EV-189 `[M]` as the integration case in which a second execution on the same uid
got the same fd number in a new Channel and its own attribution. (3) No read from a CLOSED row: EV-172 `[R]`
and EV-239 `[M]` realize the pre-read check that EV-78 `[S]` named as unbuilt. (4) One FrameReader per
Channel, emptied per frame and freed at step 2: EV-131 `[S]` realized by EV-236, EV-265 `[R]` and EV-238 `[M]` (a
half frame ends its own row). (5) A fresh control buffer per receive: EV-132 `[S]` realized by EV-237 `[R]`
and the frame fuzz rerun EV-267 `[M]` (EV-166 the run before 7b4ab727). (6) The fd shut once at step 2 and release gated on it: EV-133 and
EV-16 `[S]` realized by EV-192, EV-205 `[R]` and EV-193, EV-203 `[M]`; EV-66 `[M]` for the kernel half.
EV-58, EV-44 and EV-13 establish the premise that stale stamped bytes exist, not the cut. EV-77, EV-89 and
EV-91 concern the earlier transport library. The `[S]` rows stay in the table as the design text the
realization implements. No recorded run exercised this route's composed history — A's queued or half frame
left behind and B reading on the same uid — so the defence is not measured end to end; each component is
checked separately.

**Proposed evidence (not yet in the registry):** none new. Still open: the K-06 candidate P-32 (SOCK_STREAM
skb survival at the pinned tag; the route's precondition, not its cut) and 04 §5 item 24, the composed run,
which version 7 does not mark as begun.

## 5 Disposition
**supported under stated premises** — the same value as the `disposition:` field. Every necessary item of
section 4's composition is backed by a code reading or a run of the prototype; no necessary item is `[S]`
only.
- Premises that must hold: the spawner is trusted and runs the code read in EV-179 (AA-04; MM-05 carried as
  spawner trust); the single executor (AA-01); the kernel at the pinned tag behaves as kub reads it (AA-02),
  with K-06 taken from 01 as the route's precondition; the common abstraction of the frozen revision for
  C-LS, C-LP and C-R. Not needed: a drained queue (MM-11; 03 §1.3) or any order of T-40 step 2 against
  step 6 (MM-09; 03 §5.5), although the design and the code (EV-205) put step 2 first. This rests on the
  frozen design, kernel semantics where cited and the prototype's checked realization; it is not a claim
  about a deployed system.
- Evidence limit (configuration, substrate, run dates): runs of 2026-10-18/19; unit tests drive the engine against the test harness's stand-in
  spawner, the integration cases against the real spawner. Check limits: the SO_PASSCRED-before-clone order is
  observed on the busy case of the diagnostic fixture only, not in an engine integration run (EV-178); the fuzz
  rerun is one hour per entry with no repetition (EV-267); fd-number reuse inside one round is made by the
  tests, reuse through the real spawner happens in sequence (EV-189, EV-190). EV-58 is a datagram measurement of
  2026-09-01; the bounded TLC check (03 §5.4 run 1) is a reachability check over a subset with one skb per
  frame.
  Shared limits: [coverage-uncertainties § Shared evidence boundary](../../convergence/coverage-uncertainties.md#shared-evidence-boundary-every-route-not-repeated-below).

## 6 What remains
- Residual and open questions: the K-06 source gap for SOCK_STREAM (P-32) bears on whether the route's
  precondition arises, not on the cut; the one-skb-one-frame collapse of 03 §5.2 is Stream Q's and is not
  used; the composed run (04 §5 item 24) is not done. The IG-10 split of 03 v4 is not used. Coverage
  uncertainty left: the cut is spatial (which socket, which buffer); it says nothing about bytes a surviving
  task of A queues on B's own socket (R-G4-01) or about a different-uid holder of B's endpoint (R-G2-09).
- Design obligations surfaced for the engine (one sentence each; each is realized at commit 3ec67985 and
  must be kept by any later build):
  - T-40 / T-45: the fd shut of close step 2 is a condition of the lease release at step 6 (EV-205).
  - T-21: the pre-read check on Session.admission runs before every read, so no read follows step 1
    (EV-172, EV-239).
  - T-21 / T-24: the FrameReader belongs to one Channel object, is freed with it at step 2 and is never
    handed to another Channel or TaskCall (EV-236).
  - T-09: an install always creates a new Channel object, once per row (EV-185, EV-194).
- Cross-references: R-GX-03 (the reverse direction — B's bytes into A's object through a numeric alias),
  R-G4-01 (a surviving task sends inside J_B), R-G2-04 (two current generations mixed), R-G2-07 (a cached
  first credential within one frame), R-G2-09 (foreign endpoint, different uid), R-GX-02 (a control event
  reviving A's row). Obligations: #4 (no agent-ID confusion — "uid-reuse races against stale session
  entries") is the one this route instantiates; #2 (channel-to-agent binding) and #6 (reference-monitor
  correctness of the session-table lifecycle) are touched. Conditions C1–C4: none is the cut; C4 (a)
  enters only as the premise that A's skbs carry a stamp. Threat-model D4 premise (c).
