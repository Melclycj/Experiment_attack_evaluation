# Coverage uncertainties — archive (2026-10-21)

Archived 2026-10-21: the whole of coverage-uncertainties.md as of commit c77e4dc1, moved here verbatim when the live
file was compacted to the uncertainties open now. Nothing below the rule was edited; its "superseded" markers, dates and
"Still open" sentences describe the moment they were written. Live file: [coverage-uncertainties.md](coverage-uncertainties.md).

---

---
role: reconcile-draft
status: refreshed 2026-10-19 for step 4   # was ready-for-R3 (promoted 2026-10-16 by the reconcile role; Stream Q section appended)
# header ids: re-read 2026-10-19 against section 5 and 6 of all 38 route files and the conclusion lines of the
# five preservation files, at 01 v10, 02 v9, 03 v5 and 04 v8. 30 route files were re-run that day on the engine
# prototype's checks (step4-brief.md); bullets they now answer with engine evidence carry an in-place
# "superseded 2026-10-19 (step 4)" marker naming the EV IDs, and each keeps its genuinely open remainder as a
# sentence of its own. A few bullets were also answered by the 2026-10-18 text of route files not re-run in
# step 4 (R-G5-03, R-G5-06, R-G5-07, R-G5-08) or by the current preservation conclusion lines; their marker says
# so. No bullet is deleted. 22 bullets are added for uncertainties the re-run files name that the draft lacked,
# chiefly the realization limits of the prototype. The earlier in-place supersessions (R3 F-06; cross-family
# F-04) are kept as written. Targeted update the same day (S4 review F-05; CR-S4-06, CR-S4-07): after the user
# approved removing the C-side jansson body parse, engine commit 7b4ab727 and 04 v9 (EV-265 … EV-272), the
# bullets on the third-party parsers, the pre-change fuzz and the 02 slot text carry a "superseded 2026-10-19
# (engine 7b4ab727)" or 02 v10 marker in place; ids now 02 v10 and 04 v9. No bullet added or removed.
# Targeted update 2026-10-20: engine commit 9981dd7b (user-approved; reject group without execution_id,
# EV-285 / EV-286; S14 opt-in with PR_SPEC_FORCE_DISABLE, EV-283 / EV-284) and the fifth design revision (01
# v11 MM-10, the supervisor's method as the old cell cgroup's populated 0; EV-273 … EV-282; R-GX-04 now
# supported) are marked "superseded 2026-10-20" in place on the bullets they answer; ids now 01 v11 and 04
# v11. No bullet added or removed.
# Targeted update 2026-10-21: engine commit b262e80e (tests and the integration runner only; user-approved
# extra evidence) made the four G2 root unit cases and the two-epoch run of 04 §5 item 27 (04 v12, EV-289 …
# EV-299); the bullets that named them as not made carry a "superseded 2026-10-21 (extra evidence)" marker in
# place; registry id now 04 v12. No bullet added or removed.
date: 2026-10-21
based_on:
  model_blob: "8e5d9e5d21330b6a"
  decomposition_blob: "eceee4b4c7426e3a"
  invariant_blob: "ae58d7db31c95c82"
  registry_blob: "046b0449a22e687c"
---

# Coverage uncertainties — reconcile draft

Aggregated from section 6 of every route file ("Residual and open questions; the coverage uncertainty
this route leaves"), from section 5's premises and evidence limits where the step 4 re-run placed the
realization's limits, and from the open columns and conclusion lines of the five preservation files. One
bullet per distinct uncertainty, with the route and preservation IDs that raise it; grouped under the
sufficient condition (C-01 … C-08) it concerns, then a final group for uncertainties about the
abstraction and the method. Nothing here is a disposition or a new route; a route raising an item under
more than one condition is listed once, where its `violates:` field places it. Nothing below is stated
that is not in those files. "Prototype" means the engine prototype at commit 3ec67985 (engine code at
74833c58) as the re-run route files cite it.

## C-01 — byte origin and witness

- An alternate read API or asynchronous submission path admitted by a future production ABI would need its
  own witness check; 02 U-01's note applies to reads as well as sends, and io_uring is outside the fill
  list only by S2. (R-G2-01, R-G1-01) [2026-10-19 (step 4), not a supersession: R-G1-01 adds that the
  policy compiler refuses an allow list naming io_uring calls (EV-215), while the production allow-set
  itself stays `[S]` (EV-129); R-G2-01 §6 keeps the item open.]
- Whether the implementation has exactly one VerifiedContext constructor is a code-level fact for P2b;
  each pending consumer (engine-forwarded inter-agent messages at mech L316, the MCP compartment) adds a
  candidate constructor and re-runs R-G3-01 at the next freeze; an unlisted shape of alternate constructor
  (beyond retry, replay, reject-fill, trusted-message typing) is still q01, but its stopping statement
  would have to be found again. (R-G3-01) [superseded 2026-10-19 (step 4): the prototype has one
  construction, receive.py:297, found once by a text search run as a test (EV-172, EV-183), and the
  message types that carry a context are built only by receive_step's helper (EV-253); R-G3-01 is now
  supported under stated premises.] Still open: the text search holds for this commit only and is repeated
  at each code change; each pending consumer, a real E-10 adapter or a configured E-09 observer adds a
  candidate constructor and re-runs R-G3-01; an unlisted shape of an alternate constructor is still q01.
- The C-01 remainder slot R-G2-11 stays open until a cause is named or the product receiver's paths are
  enumerated and each shown to be a named neighbour; the frozen text makes no statement about the memory
  safety of the parser or FrameReader beyond the boundaries EV-77 exercised in the transport library, and
  02 U-04 is the standing uncertainty behind it. (R-G2-11) [superseded 2026-10-19 (step 4): the slot's
  closing property is established by code reading, a static test and the fuzz run — one FrameReader path
  per Channel (EV-169, EV-170, EV-236, EV-237) and no memory error in the ASan/UBSan fuzz run (EV-166 …
  EV-168); R-G2-11 is now supported under stated premises.] [superseded 2026-10-19 (engine 7b4ab727): the
  C reader no longer parses the body, calling no third-party parser on the path (EV-265, EV-266), and the
  fuzz was rerun on the changed reader with no finding (EV-267, EV-268), which replaces EV-166 and EV-167
  for the current reader.] Still open: the memory half rests on one hour per entry for the project's C code
  (transport.c, support.c); the body parse rests on the CPython platform premise (the added bullet below);
  02 U-04 is answered for the project's own code within these limits, not for the interpreter.
- R-GX-01's cut is spatial (which socket, which buffer); it says nothing about bytes a surviving task of A
  queues on B's own socket (R-G4-01) or about a different-uid holder of B's endpoint (R-G2-09). (R-GX-01)
- Added 2026-10-19 (step 4). The two third-party parsers on the receive path — jansson 2.14, which the C
  reader calls on the counted body after the comparison, and CPython 3.12's json on the Python-owned copy —
  are taken as premises of the same kind as the intact kernel, which the named check does not establish;
  jansson was not instrumented in the fuzz run (checked only as far as ASan intercepts its allocations) and
  the Python parse was not fuzzed; an instrumented jansson entry is proposed and not run. [superseded
  2026-10-19 (engine 7b4ab727): the classification was referred to the user (CR-S4-07), who approved
  removing the C-side body parse; at 7b4ab727 the C reader hands the credential-checked body over
  unchanged and the body is parsed only in Python (EV-265, EV-266, EV-270), a malformed body ending the row
  with protocol_error (EV-272), so jansson is neither an item nor a premise on the data path and the
  instrumented jansson entry is no longer needed.] Still open: CPython's json, now the only body parse, is
  a platform premise and is not fuzzed (R-G2-11 §5); jansson remains in the trusted spawner's
  control-record parser only, where the control fuzz entry ran with it uninstrumented (EV-269; R-GX-02).
  (R-G2-11, R-G2-13, R-G2-01, R-GX-02)

## C-02 — stamp population and equality

- The C-02 remainder slot R-G2-05 is argued since 2026-10-16 from the pinned-tag queue reading (EV-142 …
  EV-146; supported under stated premises — intact kernel, step 11's initial-namespace capability posture).
  What remains: kernel defects (R-G5-01); the reading's two stated bounds (out-of-family receive-queue
  writers sorted by directory, the remaining sockfd_lookup callers sorted by protocol); the io_uring
  execution context, unread at the pin and relevant only if the production S2 `[S]` item (AA-11) admits
  asynchronous submission. Step 11 absent on the deployed host is a premise failure (T-67, a configuration
  failure, not an adversary action), carried by the step 11 requirement and a deployment check; the
  engine's rejection of a message without a credential at T-22 is a second layer, unbuilt `[S]` (02 v6,
  CR-G2-02). (R-G2-05; G2 preservation
  T-20 open, T-64 open) [superseded in part 2026-10-19 (step 4): the T-22 second layer is now realized and
  checked in the prototype — exactly one credential required per return, truncated, missing, duplicate and
  mis-sized ancillary rejected over a fresh control buffer (EV-171, EV-176, EV-181, EV-237; R-G2-03, now
  supported under stated premises); R-G2-05 itself was not re-run and its §6 still calls that layer an
  `[S]` engine check.] Still open: the kernel defects, the reading's two bounds and the io_uring execution
  context, as above.
- The explicit foreign-uid send was derived, not measured, in the registry at the time the routes were
  written (EV-29 `[R]`); Stream P's WSL2 arm now measures it (registry-appends.md §3), and the native-Linux
  arm is pending. (R-G5-04, R-G2-05)
- With C1 absent, R-G5-03's route still needs an endpoint of the row whose uid was selected (A-07) or a G1
  installation error, so a C1 failure alone yields a discarded frame, not a wrong label — a bound on the
  consequence, not a defence; and C1 has no runtime check, so a refactor of step 11 would not be caught.
  (R-G5-03; G5 preservation T-61 open) [superseded 2026-10-19 (step 4 refresh, from the 2026-10-18 text of
  R-G5-03 and the step 4 rows): C1 now has a runtime check — the shared drop's getresuid re-read before the
  seccomp install, whose failure exit was exercised by test-build fault injection (EV-148, EV-149), with
  the drop order read at EV-212 — and keeping the re-read and its two injection cases in the regression is
  the obligation that catches a refactor of step 11.] Still open: the re-read's unequal-value branch is
  read in the code, not exercised; the consequence bound is kept and not relied on; the G5 preservation rows
  T-61 and T-67 (a) still call C1 unchecked (CR-G5-03).
- R-G5-04's sub-branch B is additionally narrowed by the production allow-set not admitting what S1 denies —
  the separate `[S]` item EV-129, an optional surface reduction, not a component the identity defence needs
  (the map rule and the initial-namespace posture stop the route; CR-R3-19). (R-G5-04)
- The "if admitted" half of R-G1-01 (a sentinel or absent credential passing the comparison) is not argued
  there; it belongs to R-G2-03 and R-G5-05. (R-G1-01) [superseded 2026-10-19 (step 4): both are now
  supported under stated premises on the prototype's checks — the T-22 / T-23 rejections (EV-171, EV-175,
  EV-176, EV-237) and the start-up identity-map check with the record path's refusal of a sentinel subject
  (EV-165, EV-225); R-G1-01 §6 keeps the pointer.]
- Added 2026-10-19 (step 4). The C4 (a) half — SO_PASSCRED armed on the engine end before any task of P_X
  exists — is realized, with check limits: the PASSCRED-before-clone order was observed on the busy case of
  the diagnostic fixture only, not in an engine integration run (EV-178); the T-09 refusal of an fd without
  the option was exercised with sockets the test made, not with a spawner that omitted it (EV-177); "never
  cleared" rests on a text search (EV-180). An integration run recording the spawner's order and a negative
  case in which the real spawner omits the option are named and not made. (R-G1-01, R-G2-03, R-G5-05,
  R-GX-01)

## C-03 — translation and decoding fidelity

- The C-03 remainder slot R-G2-12 stays open until the rendering path at the pin is read for any producer
  of a control-message uid other than __scm_recv_common's rendering of the skb's stamp, or a cause is
  named. (R-G2-12) [superseded 2026-10-19 (step 4): the slot's closing property — the engine runs under the
  identity map, checked at every start, refusing service otherwise — is established on the development
  host by the integration run's positive and refusal cases and a code reading of the check (EV-163, EV-164,
  EV-165), with no unshare or setns call in the package (EV-262); R-G2-12 is now supported under stated
  premises, the slot holding only kernel-side causes (R-G5-01).] Still open: the initial user namespace as
  a deployment premise (the added bullet below); one refusal case on one substrate.
- The C3 start-up self-check (MM-07) is stated and unbuilt, and by the acceptance run's own limit an
  identity-map precheck cannot show that an arbitrary deployment's engine is in the initial namespace
  (EV-80). (R-G2-06, R-G5-05, R-G1-02, R-G2-12; G5 preservation T-67 open) [superseded 2026-10-19 (step 4):
  the self-check is realized and checked — it accepts only the single map line 0 0 4294967295 and runs
  before any catalog load or control-link use (EV-165), and refused service under a non-identity map
  (EV-164).] Still open: EV-80's limit stands in the same form for the prototype — the check confirms the
  identity map, not that the namespace is the initial one (val row 256), and the G5 preservation
  conclusion line still names the check unbuilt.
- Under an injective non-identity map (S13 absent) every own-execution frame fails T-23 and a foreign kernel
  uid can match only if the map carries it to a pool number; whether a task at such a uid is reachable is
  R-G5-05's and R-G5-06's subject and is not argued. (R-G1-02) [superseded in part 2026-10-19 (step 4):
  the prototype's self-check refuses service under any non-identity map (EV-164, EV-165), so case (iii)
  leaves only the premise that the identity-mapped namespace is the initial one.] Still open: a foreign
  kernel uid matching only through such a map stays R-G5-05's and R-G5-06's subject.
- D4 on the record path: receive_rejected carries no verified_subject, but the audit stream must also never
  write a sentinel as a principal, and D4 is unbuilt (EV-40 `[S]`); kub §6.1's own exposure statement —
  before D4 the compare-path rejection of the alias was incidental and the record paths would have written
  65534 as a principal — is the reason D4 exists. (R-G2-03, R-G5-05) [superseded 2026-10-19 (step 4): D4
  is realized in the prototype's recorder — verified kinds only with a VerifiedSubject, a sentinel or
  mismatched sender uid refused, no subject on other kinds — and checked (EV-225, EV-224), the reject event
  built without a subject (EV-172; R-G3-04, R-G5-05).] Still open: no E-09 export consumer exists, so the
  absence of a subject is checked at the recorder, not at any reader of the export (R-G3-04).
- An engine bookkeeping defect at T-01 (a wrong expected_uid written) is the honest-but-buggy case of 02
  §0.3; the write-once rule localises it to one transition and one field but does not exclude it.
  (R-G1-02) [2026-10-19 (step 4), not a supersession: the prototype has one such write (EV-186), its "no
  other write" resting on a text search; the case is still not excluded.]
- Added 2026-10-19 (step 4). The engine's namespace being the initial user namespace (C3 / S13) is a
  deployment premise of engine-requirements §8 that the engine does not check: on the development host the
  identity map holds and the initial-namespace identity is inferred from the WSL2 distribution's init and
  from the agents' namespace link (EV-213), not separately shown for the engine (val row 256). The proposed
  readings that would narrow this — map_write's extent rule and the PROC_USER_INIT_INO value at the pinned
  tag, and the engine's own namespace link in its startup posture — are not made. (R-G1-01, R-G1-02,
  R-G2-06, R-G2-09, R-G2-12, R-G5-05)
- Added 2026-10-19 (step 4). The start-up pool check excludes identities in use on the host only as far as
  NSS reports host accounts (EV-201, EV-202; val row 131). (R-G1-02, R-G5-05)
- Added 2026-10-19 (step 4). The sentinel, pid 0, MSG_CTRUNC, duplicated and short-credential buffers of the
  sandbox regression are synthetic, not kernel-generated (EV-176); a kernel-truncated rights message is
  covered only by the ancillary fuzz entry's constructed headers; a kernel-generated MSG_CTRUNC or pid 0
  against the product reader, and a root unit case with pool uids above 2^31 (today a type reading only,
  EV-247), are named and not made. (R-G2-03, R-G2-06, R-G5-05) [superseded in part 2026-10-21 (extra
  evidence): the root unit case with pool uids above 2^31 is made — accepted from their own uid, sign-bit
  pairs rejected (EV-289, EV-290; receive side only).] Still open: a kernel-generated MSG_CTRUNC or pid 0
  against the product reader.

## C-04 — current comparison

- The C-04 remainder slot R-G2-13 stays open until the product receiver exists and its decision paths are
  enumerated against the single-comparison rule; the frozen text enumerates rules, not code paths.
  (R-G2-13) [superseded 2026-10-19 (step 4): the slot's closing property — one comparison point on the only
  path from recvmsg to the buffer, every phase passing through it — is established by a structural reading
  of the C reader and of receive_step (EV-171, EV-172, EV-253) with root unit tests across STARTING, ACTIVE
  and DRAINING and a pre-read test for a CLOSED session (EV-173, EV-174, EV-239); R-G2-13 is now supported
  under stated premises.] Still open: the phase coverage outside STARTING rests on a stand-in row; a
  wrong-uid case through the full lifecycle in ACTIVE and DRAINING is named and not run.
- Whether the production allow-set permits an MSG_OOB send at all is part of the S2 `[S]` item; the
  OOB-path memory-safety item (EV-27) belongs to R-G5-01's declared exclusion. (R-G2-02) [superseded in
  part 2026-10-19 (step 4): R-G2-02 no longer needs the S2 answer, since the engine ends the row on any OOB
  byte (EV-182).] Still open: the S2 item itself and EV-27's reachability, as stated.
- Same-uid joint writers remain one principal by W2.1: no route separates members of P_X, and the design
  does not claim to. (R-G2-07; G2 preservation justification row 1)
- Outbound confidentiality under A-07 is not protected by this mechanism — a holder reads what the engine
  writes to the endpoint (kub §7.4; X-10) — a different property; the acquisition footing of A-07 (the d2
  naive-spawn leak against the hygienic spawn; the pidfd_getfd exit window of CVE-2026-46333 whose fix is
  absent at the pin, where the uid/gid first-layer match still confines theft to same-uid tasks) is
  Stream E and G5 material and does not enter I. (R-G2-09, R-G3-03; G2 preservation T-63 open)
- Added 2026-10-19 (step 4). The comparison tests' own limits: in the negative cases the frames share one
  code path and differ only in the failure position; the phase rule ran on a stand-in row object; a
  wrong-uid case through the full lifecycle exists only in STARTING; the senders of the root unit suite are
  at test-catalog uids. Cases named and not run: a sender change at the frame's last byte; two rows whose
  expected uids are swapped relative to the sending channels. (R-G2-02, R-G2-07, R-G2-08, R-G2-13)
  [superseded in part 2026-10-21 (extra evidence): both cases are made — the last-byte change rejected
  (EV-291) and the swapped rows each rejected with no row taking either frame (EV-292, in the unit harness
  with a scripted spawner).] Still open: the other limits as stated.
- Added 2026-10-19 (step 4). The different-uid holder is exercised as a writer at another pool uid in a root
  unit test, not as a task holding a copy of the agent end obtained through a spawn defect; a case in which
  a different-uid task holds a duplicate of the agent end and sends with a pid of X is named and not run;
  the absence of SO_PEERCRED and of a pid lookup is by text search. (R-G2-09) [superseded in part 2026-10-21
  (extra evidence): a task at another uid holding a copy of the agent end, handed over by SCM_RIGHTS from a
  live task of X, and sending with that task's pid is rejected (EV-293; control EV-294).] Still open: the copy
  is handed over by the test, not obtained through a spawn defect; the sender held CAP_SYS_ADMIN to name the
  pid; the product's absence of SO_PEERCRED and of a pid lookup is by text search.

## C-05 — row, channel and allocation association

- MM-05: the engine cannot establish that the delivered fd's peer is the child's fd 3; the design carries
  it as spawner trust plus the spawner's own SEALED pid check. (R-G1-03; G1 preservation T-09 open)
  [2026-10-19 (step 4), not a supersession: the spawner's SEALED pid check is realized and read (EV-210),
  and the inherited descriptor set is observed in the sandbox regression (EV-245); the engine still cannot
  verify the peer, and the endpoint half rests on code reading (EV-179).]
- MM-15: the event that increments receiver_generation is not stated; the routes read it as one generation
  per Channel object, and R-GX-03's cut does not use the generation value. (R-G1-03, R-G2-04, R-G2-10,
  R-GX-03; G1 preservation T-09 open; G2 preservation T-24 open; G4 preservation §D4) [superseded
  2026-10-19 (step 4): MM-15 is resolved in 01 v9 as one receiver_generation per Channel, set at install;
  the prototype sets it from a counter, one per Channel, write-once (EV-187), and stale callbacks fail by
  object identity, not by the generation value (val row 148); the G4 preservation conclusion line now sorts
  the T-40 step 2 with T-09 condition stopped.]
- The T-03 miscopy case — the record itself carrying another lease's uid — is outside p53's wording and is
  not expressible in the one-uid TLA+ subset; the T-03 directory cross-check is its stated cut, and a guard
  for it is proposed as the IG-10 split (CR-G1-01) [superseded: applied as CR-F-01, 03 v4 IG-10 (a); the
  subset's inexpressibility remains]; a miscopy that passes the directory check would need
  two workspaces registered to one uid (the U-05 premise). (R-G1-06; G1 preservation conclusion lines)
  [superseded 2026-10-19 (step 4): the directory cross-check is realized as the spawner's registered-uid
  check, refused before any clone in the bad-uid and bad-gid cases (EV-209, EV-208), the bootstrap drops to
  its own record's plan (EV-246), and two workspaces registered to one uid are refused at engine start-up
  (EV-202).] Still open: the subset's inexpressibility; the U-05 premise across engines.
- R-GX-02's per-record rules are argued from text: an implementation that indexed control records by uid, by
  the fd number of the received descriptor, or by workspace alone would be outside every cut; histories (b),
  (c) and (f) have no bounded-check coverage (T-52's idempotence and tombstones are not modeled, AA-08);
  history (b) presupposes a trusted-side defect or a byte-identical replay that AA-08 excludes. (R-GX-02)
  [superseded 2026-10-19 (step 4): the per-record rules are realized and checked — matching by
  engine_epoch, execution_id and lease_id (EV-185, EV-220), a late prepared on a CLOSED row shut and stopped
  once (EV-222), a repeated prepared faulting and a duplicate terminal ignored (EV-219), the uncertain-send
  withdrawal (EV-221); history (b) is realized as a fault (EV-219); R-GX-02 is now supported under stated
  premises.] Still open: a later build that indexed control records by uid, by the received descriptor's
  number or by workspace alone would leave every cut; the per-history unit tests use a stand-in spawner and
  the integration cases do not cover every prepared / empty order on two rows of one uid; the composed
  two-row run (04 §5 item 25) is not done; the bounded check still does not model T-52's idempotence or
  tombstones.
- R-GX-03's alias half is argued from object-identity statements only, with nothing measured on the
  product's event loop, and the bounded check does not model fd numbers or K-10. (R-GX-03) [superseded
  2026-10-19 (step 4): the AA-13 check measured it on the real close path — an old Channel's fd retired and
  its number reused at once, no old callback reaching the new socket (EV-191) — with close step 2's
  deregistration before the close read (EV-192) and the unit reuse tests (EV-190); R-GX-03 is now
  supported under stated premises.] Still open: the check covers the epoll backend only with the reuse made
  by os.dup2, and the composed alias run through the real spawner (04 §5 item 26) is done only in part; the
  bounded check still does not model fd numbers or K-10.
- The C-05 remainder slot R-GX-06 holds sub-cases (i) a later write to a reservation field, (ii) a lifecycle
  rebind of the Channel → Session link, (iii) a stale derived record across a uid reuse while the old slot
  is held (MM-12); each is a refinement candidate for an appended selector, and whether an analyst can tell
  a concrete history falls here rather than in R-G1-03, R-GX-02 or R-GX-03 is a statement about the
  analysis (02 §4, addendum F-04); the slot waits on MM-09, MM-12, MM-15, MM-16 and U-06. (R-GX-06)
  [superseded 2026-10-19 (step 4): the slot's closing property — the association created at T-01,
  installed at T-09 and cleared at T-40 step 2 only, by object — is established for the prototype by the
  validation record's R-GX-06 check and its AA-13 check (EV-193, EV-194, EV-187, EV-219, EV-205, EV-195,
  EV-191), MM-12 and MM-15 now being stated design text; R-GX-06 is now supported under stated premises.]
  Still open: the analyst statement, unchanged; a later build keeps the property only by keeping the five
  obligations R-GX-06 §6 lists; the reuse limits in the added bullet below.
- Added 2026-10-19 (step 4). fd-number reuse inside one round is made by the tests (low fds held, or
  os.dup2), not by the real spawner, which reuses numbers only in sequence, across rounds (EV-189, EV-190,
  EV-191); the AA-13 check covers CPython selectors with the epoll backend only, so another backend or
  event library needs the same check again before it is admitted; an integration case with two channels
  whose partial frames interleave between executor turns is named and not run. (R-G1-03, R-G2-04, R-GX-01,
  R-GX-02, R-GX-03, R-GX-05, R-GX-06)
- Added 2026-10-19 (step 4). The write-once properties hold by code structure, not by type: the guard is a
  Python-level check on attribute assignment that admits a first assignment to a field still holding None
  (EV-187), and the Channel → Session link's "written once" holds by code structure (EV-194; val row 149).
  (R-G1-02, R-G2-08, R-GX-06)

## C-06 — uid exclusivity

- The uid ↔ execution 1:1 premise (tm D4 (c)) rests on lifecycle bookkeeping the design states and the
  engine does not implement (obligation #4, PARTIAL — NOT BUILT); the allocator cut and the spawner
  occupancy cut are independent specifications, so one defect does not open the route, but neither is
  measured. (R-G1-05) [superseded 2026-10-19 (step 4): both cuts are realized and checked for one engine
  and one epoch — the reservation's uid only from the workspace record, a held uid and a workspace whose
  previous row is not CLOSED and empty refused (EV-200, EV-199), the spawner's live-record refusal before
  any clone (EV-207, EV-209); R-G1-05 is now supported under stated premises.] Still open: across engine
  instances the premise rests on the trusted supervisor (outside the build; R-GX-04) [superseded in part
  2026-10-20 (fifth design revision): the supervisor's release rule is now the cell cgroup's populated 0
  (01 v11 MM-10; EV-273 … EV-277), a deployment precondition under which R-GX-04 is supported]; the holders refusal
  and the previous-row refusal rest on code reading, the held-uid test being refused earlier at the
  workspace check; uid-pool exhaustion is exercised by no test (the cited test refuses at the
  execution-slot limit; EV-199 note); mech obligation #4's "PARTIAL — NOT BUILT" predates the prototype.
- Whether "uid and lease unused" at T-03 counts a process-terminal record awaiting its storage release is
  not stated; both readings preserve I. (R-G1-05; G1 preservation T-03 open) [superseded 2026-10-19 (step
  4): the prototype realizes the occupancy notion as "a live record that is not empty" (spawner.c:89–91;
  EV-209; val row 189), the permissive reading the user ruled on 2026-10-18, which is MM-18's admission
  outcome.] Still open: the G1 preservation conclusion line still records it as the one unstated reading.
- Nothing verifies after clone that a namespace is fresh (optb L211–212); carried as AA-04. (G1
  preservation T-05 open)
- U-05 is carried unchanged: the exclusive-pool premise is a deployment fact the binding inherits by
  reference (tm D10), the method of establishing and maintaining it is not stated (CR-G5-01 asks 01 T-67 to
  name the premise [superseded: applied as CR-F-06, 01 v8 T-67 names it; the method stays unstated]), and the route's reachability is the conjunction of that premise failure with a
  descriptor acquisition (A-07), neither resolved. (R-G5-06; G5 preservation T-67 open, conclusion lines;
  G4 preservation §D4) [superseded in part 2026-10-19 (step 4 refresh, from the 2026-10-18 text of R-G5-06
  and the current G5 preservation conclusion line): the method is now stated as engine-requirements §8's
  first entry — the pool reserved on the host to the engine alone, one engine per range, a uid inventory
  naming every holder — and R-G5-06 is supported under stated premises with it as a premise; the
  engine-side start-up check refuses a shared uid or gid (EV-202; R-G1-05).] Still open: the deployment
  entries are realized on no host and are the deployer's evidence; no run measures a pre-existing holder,
  a concurrent engine or an inventory; when the premise fails the route is reachable given A-07 and the
  engine cannot see it.
- The premise "no privileged actor acts for the agent" (AA-04) has no stated deployment control: a
  deployer's user-namespace tooling such as a set-user-ID map-writing helper whose subordinate-uid range
  covered the pool would be exactly the privileged map writer, and the frozen text does not forbid such a
  helper; recorded as an open deployment condition, not a route. (R-G5-07, R-G5-04) [superseded in part
  2026-10-19 (step 4 refresh, from the 2026-10-18 text of R-G5-07): for configured helpers the control is
  now engine-requirements §8's first entry (no subordinate-uid entry, container remap or other allocator
  overlapping the pool).] Still open: a privileged actor outside every configured allocator stays AA-04,
  unchecked by the engine; R-G5-04 §6 still records the helper statement as not stated as a requirement.
- The C-06 remainder slot R-G5-08: a history in which a holder of u_r acquired it by an undocumented path
  would be placed in this cell by default and must then be investigated, not dismissed as unreachable;
  EV-24's silence is search-bounded. (R-G5-08) [superseded in part 2026-10-19 (step 4 refresh, from the
  2026-10-18 text of R-G5-08): the slot is argued empty under stated premises — the uid inventory for tasks
  outside the engine's executions, the kernel's writers of a task's uid at the pin for tasks inside them —
  and R-G5-08 is supported under stated premises.] Still open: the kernel reading's bounds (a whole-struct
  copy or an unusually named variable would escape the sweep, override callees not traced); a history
  reaching u_r by an unlisted path lands here and must be investigated; no run measured any history in or
  near the cell.
- Of R-G4-01's two necessary legs only survival past release is cut there; the endpoint leg (A-07, a
  stipulated input, not a shown acquisition) is G1's construction and G2's check facts, so a history that
  defeats both is not argued in one file; the engine side of every cut is `[S]`. (R-G4-01) [superseded in
  part 2026-10-19 (step 4): the engine and spawner side of the survival cut is realized and checked — the
  release gate on CLOSED, empty and close step 2 (EV-205), the empty fact only after the spawner's waitpid
  or for a never-cloned record (EV-206, EV-263), quarantine on errors and timeouts (EV-203, EV-204); R-G4-01
  is now supported under stated premises.] Still open: a history that defeats both legs is not argued in
  one file; no run placed a live survivor at release, and an integration case with a live descendant at
  stop is named and not run.
- A stop for a record the spawner never received (T-02 uncertain): both readings quarantine and neither
  releases, but a never_created answer, if a later design adds one, needs its own "never cloned" guarantee
  (IG-04). (R-G4-01, R-GX-02; G4 preservation J-05, T-41 open, T-44 open) [superseded 2026-10-19 (step 4):
  the design answers it with a control fault and quarantine (01 v9 T-41; CR-F-05) and the build faults the
  whole control link on an indeterminate send (val row 186, stricter; EV-221); the never_created seal
  against clone is read at spawner.c:101–102 (EV-263).] Still open: the seal rests on code reading plus
  regression cases that end before clone (val row 209).
- R-GX-04: the supervisor's method (MM-10) — what it enumerates (every PID 1 of the old epoch, by what
  record, since spawner 1's SpawnRecords may be gone with it) and what "empty" is checked against — is not
  stated; the design's own alternative membership set (a cgroup populated flag, mech §Identity lifecycle)
  is not stated for the supervisor; engine and spawner have never run as two processes (EV-72); this is
  the one lifecycle route on which neither the frozen text nor the bounded check says anything beyond the
  precondition sentence, and the MM-10 FALSE branch was not run. (R-GX-04; G4 preservation T-49 open, J-09,
  §D4) [superseded in part 2026-10-19 (step 4): engine and spawner now run as two processes, the engine
  with every capability set empty while the spawner runs separately (EV-234), which checks EV-72 only in
  part.] [superseded 2026-10-20 (fifth design revision): 01 v11 MM-10 states the method — the old cell runs
  in one cgroup of its own, which is killed with cgroup.kill, and a new engine starts only once
  cgroup.events reports populated 0, a kernel-held fact, never a self-report (EV-273 … EV-277); the kernel
  half is measured on the development host (EV-278 … EV-281) and the sandbox mounts no /sys or cgroup file
  system (EV-282); R-GX-04 is now supported under stated premises.] Still open: the MM-10 FALSE branch was
  not run in the bounded check; the no-leave premise was observed for an unprivileged member under one
  cgroup ownership layout (EV-279); the remainder in the added supervisor bullet below.
- Where spawner 1 survives control loss, its sweep needs CAP_KILL in the agent's user namespace; its absence
  leaves survivors for the supervisor (conn L842–854). (R-GX-04) [2026-10-19 (step 4), not a supersession:
  CAP_KILL is now a deployment premise of engine-requirements §8 (val row 257) whose development-host
  reading holds; the control-loss cases cover a spawner that survives and sweeps (EV-216), not a spawner
  killed before its sweep.]
- Added 2026-10-19 (step 4). The trusted supervisor is not built: R-GX-04 is the one route still
  conditional on unbuilt requirements, its remaining `[S]` item the supervisor's termination of every
  execution of the old epoch and its own domain-empty confirmation (EV-139; the supervisor half of EV-81;
  engine-requirements line 218, outside the build's scope). The build performs no restart recovery and
  starts no second epoch (EV-217); on the development host the stand-in is a restart of WSL after an engine
  crash, an operating procedure, not a checked mechanism; the two-epoch run (04 §5 item 27) is possible
  only once the method is stated. (R-GX-04, R-G1-05, R-G4-01) [superseded in part 2026-10-20 (fifth design
  revision): the method is stated (01 v11 MM-10; EV-273 … EV-277) and R-GX-04 is no longer conditional;
  under step4-brief §1 the cell's cgroup and the release gate are deployment preconditions
  (engine-requirements row 218), so the unbuilt supervisor is a premise, not an `[S]` item.] Still open: no
  supervisor has been built and no deployment has placed a cell in such a cgroup — that is the deployer's
  evidence; the cgroup behaviour is one probe run with sleep processes and a script standing in for the
  engine, spawner, executions and release gate (EV-278 … EV-280); whether the gate is a host-init unit, a
  wrapper or an operator procedure is not fixed by the design; the two-epoch run (04 §5 item 27) is not
  done. [superseded in part 2026-10-21 (extra evidence): the two-epoch run is made with the real engine,
  spawner and agent — A still running in the cell's cgroup after spawner 1's SIGKILL, gone before engine 2
  leased the same uid, released by a test stand-in gate on populated 0 (EV-295 … EV-298).] Still open: no
  supervisor built and no deployment; the gate in that run is a stand-in; A was silent after its hello and
  made no attempt on engine 2's rows; one run on the development host.
- Added 2026-10-19 (step 4). The C1 and launch-correspondence branches that a fault would take are read,
  not exercised: the spawner's SEALED uid-mismatch branch (EV-210) and the re-read's unequal-value
  comparison (EV-148, EV-149) — the fault points exercised precede the comparison; a regression case in
  which the bootstrap sends SEALED from a foreign uid is named and not made. (R-G1-06, R-G5-03, R-G5-07)
- Added 2026-10-19 (step 4 refresh, from the 2026-10-18 text of R-G5-07). The explicit ambient and permitted
  clear of step 11 is still marked unexercised as a step in its own right (01 MM-13); its outcome —
  capability sets zero — is observed (EV-74). (R-G5-07)

## C-07 — send inside the allocation interval

- MM-09 / MM-11: whether the fd shut of T-40 step 2 is a condition of the release at step 6, and whether the
  gate implies a shut-and-drained channel, are not stated; I does not need either (03 §5.5), but the
  ordering is an unstated design fact, and an implementation that released before shutting and keyed a
  reader by fd number would join R-GX-01 to R-GX-03's alias half; which field the pre-read check consults
  is G4 change request 1. (R-GX-01, R-G4-01, R-GX-03; G4 preservation T-40 open, T-45 open, J-07, §D4; G2
  preservation T-21 open) [superseded 2026-10-19 (step 4): 01 v9 states the fd shut before release, the
  prototype gates the release on close step 2 having run (EV-205), and the pre-read check on the Session's
  admission runs before every read (EV-172, EV-239; CR-F-04); the G4 preservation conclusion line now
  sorts the T-40 with T-45 condition stopped.] Still open: a later build keeps the order only by keeping
  the obligation R-GX-01 §6 lists; I needs neither the order nor a drained channel.
- K-06 for SOCK_STREAM — that a queued skb survives its sender's exit until read or socket release — has no
  registered source location; only the datagram measurement EV-58 exists, and the routes use 01's kernel
  reading. (R-GX-01, R-G4-01; G4 preservation T-42 open, T-65 open; G2 preservation T-20 open)
  [2026-10-19 (step 4), not a supersession: the P-32 reading proposed again by R-G4-01 was not registered,
  because the pinned tree is not in this workspace; it bears on whether R-GX-01's precondition arises, not
  on its cut.]
- MM-12: the uid is reusable while the old execution slot may still be held; the branch "no transition
  reads the old slot when binding the new row" is design text, not an invariant. (G4 preservation T-45
  open, J-06; R-GX-06) [superseded in part 2026-10-19 (step 4): MM-12 is now stated design text, and the
  prototype's test shows a new execution binding nothing of an old row whose slot is still held (EV-195;
  R-GX-05, R-GX-06).] Still open: it remains design text and a test, not an invariant of I.
- R-GX-03's member-after-release half is covered in the bounded check only through the gate (release before
  the fd shut allowed, no violation). (R-GX-03) [superseded in part 2026-10-19 (step 4): the gate is
  realized in the prototype (EV-205) and checked in the unit suite and two fault-injected integration cases
  (EV-203, EV-204).] Still open: no run placed a live survivor at release (R-G4-01).

## C-08 — carry to consumers

- MM-16: the frozen text forbids a relookup by uid, fd number or request id in words (conn L523, L835–837)
  but names local_agent_id only in the no-inheritance rule (conn L79), so the name leg rests on the
  by-reference rule plus the absence of any stated name-keyed consumer; the pending consumers (the
  engine-internal grant lookup MM-06, the MCP compartment, engine-forwarded inter-agent messages at mech
  L316) must each state that they key by object, not by name (U-06). (R-GX-05, R-G2-10, R-G3-05; G2
  preservation T-24 open; G3 preservation conclusion lines) [superseded 2026-10-19 (step 4): MM-16 is
  resolved in 01 v9 — local_agent_id written once at row creation, no consumer keying by it — and the
  prototype has no table keyed by it (EV-196); the engine-internal grant lookup adds no constructor and
  keys by object (EV-243, EV-227).] Still open: the MCP compartment, engine-forwarded inter-agent messages
  and any real connector must each key by object and be re-checked when built (U-06); the text search
  holds for this commit only.
- The C-08 remainder slot R-G3-05: sub-case (i), a local_agent_id-only mutation with the reference and the
  execution label retained, is a selector gap (G3's change request asks q32 to name local_agent_id)
  [superseded: applied as CR-F-03, 02 v4 q32; sub-case (i) moved to R-G3-03]; sub-cases (ii) lost context and (iii) a stale copy remain refinement candidates; whether an analyst can
  tell a history falls here rather than in R-G3-02 or R-G3-03 is a statement about the analysis. (R-G3-05)
  [superseded 2026-10-19 (step 4): the slot's closing property — every consumer step carries the verified
  context by object reference, with no construction and no lookup or state key by name, uid, fd or
  local_agent_id — is established by the validation record's R-G3-05 check up to the stub handlers
  (EV-196, EV-197, EV-259); R-G3-05 is now supported under stated premises, without claiming the remainder
  empty in a real system.] Still open: the stub-handler limit (the added bullet below); the analyst
  statement, unchanged.
- The inputs to admission change at the next freeze (MM-06; U-06), so the T-30 / T-33 statements of R-G3-02
  re-run then; the retained wire schema still carries an agent-supplied grant_ref until the pending
  revision; whether the request slots and the TaskBinding store can be made to alias across sessions by
  filling their bounds is an implementation question the design answers with refusal, not reuse. (R-G3-02;
  G3 preservation justification row 5, T-30 open) [superseded 2026-10-19 (step 4): 01 v10 removes the
  agent-facing grant_ref; in the prototype every message type carrying an identity-like field, grant_ref
  among them, is invalid (EV-184), the grant is taken only from the matched call's TaskBinding (EV-198,
  EV-227), and a binding leaves its Session only when inactive and unreferenced (EV-256); R-G3-02 is now
  supported under stated premises.] Still open: the cross-session cases rest on code reading, the unit
  layer having one sending uid, and a test with two sending uids is named and not run; the build has no
  rebind entry, so the design's rebind guard is unexercised and a later rebind entry re-runs the T-39
  sub-case; MM-06's two leftover points do not reopen the route (R-G3-02 §6).
- A same-uid process in P_X that learns the current call id is the same subject (W2.1), so a join inside one
  execution is outside the C-08 routes and outside P_carry. (R-G3-02; G3 preservation T-36 open)
- The E-09 export carries the label to a run-evidence directory, and any future consumer of that export
  (MPI-F05, inter-agent forwarding at mech L316) inherits whatever T-38 emitted (U-06); whether the
  "clearly distinguished unverified information" allowed on a reject (si L68, E-09-R1) can be mistaken for
  a subject by such a consumer is a schema question for that consumer's design. (R-G3-03, R-G3-04)
- The whole R-GX-05 cut is design text about unbuilt consumers, and the bounded check does not model
  consumers; a request's deadline bounded by its TaskCall's (conn L704) limits how late "late" can be, an
  availability fact not relied on. (R-GX-05) [superseded 2026-10-19 (step 4): the cut is realized for the
  build's consumers and checked up to the stub handler — a late fact applied only to the object it holds
  and release-only after CLOSED (EV-198, EV-223), labels and keys copied from the carried context (EV-183,
  EV-229), a slot returned only to its own TaskCall (EV-195), no state keyed by local_agent_id (EV-196);
  R-GX-05 is now supported under stated premises.] Still open: the case of two sessions ACTIVE at once rests
  on code reading only (val row 236); the composed run (04 §5 item 28) is done only in part; the bounded
  check still does not model consumers; the deadline remark is unchanged and not relied on.
- Obligation #5 (no delegation leakage between agents, NOT DONE) is adjacent: the subagent chain is outside
  the frozen text, and a join to another execution's grant is the local shape of that leakage. (R-G3-02,
  R-GX-05)
- Added 2026-10-19 (step 4). The model chain and the resources are stub connectors, so every consumer-side
  disposition is checked up to the stub handlers only; BUILD-PLAN asks for the validation record's R-G3-05
  check to be repeated each time a real connector replaces a stub (the chat-tools-sse model connector, a
  real document handler), and a real E-07 connector replaces the stub's callback with network-side
  identifiers, whose attachment of results to the sink is re-checked then; until then a real connector's
  handling of the sink and of its own callbacks is outside the evidence. (R-G3-01, R-G3-02, R-G3-03,
  R-G3-04, R-G3-05, R-GX-05, R-G2-10)
- Added 2026-10-19 (step 4). The pre_egress hook point is observe-only because no observer is configured and
  the return is discarded (EV-255), not because the type forbids a write: an observer receives the
  CandidateOperation and through it the mutable RequestEntry, so a configured observer is a consumer in its
  own right and re-runs R-G3-01 and R-G3-03. The validation record's row 172 states that the hook does not
  exist in the first version, which does not match the code (G3 change request 5); its result, one
  constructor, is unaffected. (R-G3-01, R-G3-03, R-G3-05)
- Added 2026-10-19 (step 4). The prototype's receive_rejected record carries the row's own execution_id
  inside its reject group (EV-258). It is not a verified_subject and connection_ref already identifies the
  row, so R-G3-04 is not affected; but si L68 lists connection_ref, the reason and length/flags only, and a
  later consumer of the E-09 export could read the field as "who sent this". Diagnostic records carry
  session_id in a detail group under the same caution. Whether the field is wanted is a schema question put
  to the reconcile role (G3 change request 7). (R-G3-04) [superseded 2026-10-20 (engine 9981dd7b,
  user-approved): the reject group now holds the cause and the detail only, with no execution_id and no
  verified_subject, as si L68 lists, and a test asserts the group's two keys and fails on the earlier code
  (EV-285, EV-286; EV-258's clause superseded).] Still open: diagnostic records carry session_id in a detail
  group, never a subject, under the same consumer caution (R-G3-04 §6).
- Added 2026-10-19 (step 4). The decoy check replaces the execution_id key only, the uid, fd and
  local_agent_id keys being excluded by code reading (EV-196, EV-197); the single-constructor and
  no-name-keyed-table facts are text searches of this commit's package, and a Python dataclass can be
  constructed by any later code, so each is repeated at every code change. (R-G3-01, R-G3-02, R-G3-03,
  R-G3-05, R-GX-05, R-G2-10)

## Model and method

- **U-01 (kernel-origin correspondence)** re-raised for alternate asynchronous submission and alternate
  read APIs under a future production ABI. (R-G2-01, R-G2-05, R-G1-01)
- **U-02 (causal-leaf refinement)**: the seven refinement slots — R-G2-05 (C-02; since 2026-10-16 argued
  from a positive property of its producers, U-01, and no longer open), R-G2-11
  (C-01), R-G2-12 (C-03), R-G2-13 (C-04), R-G3-05 (C-08), R-G5-08 (C-06), R-GX-06 (C-05) — each stays open
  until a cause is named (a new route by a spine version) or the slot is narrowed by a change request;
  none is claimed empty or nonempty and none gains a disposition from the totality of its predicates (02
  §4.3). (the seven slot files) [superseded 2026-10-19 (step 4): no slot is open — R-G2-11, R-G2-12,
  R-G2-13, R-G3-05 and R-GX-06 now rest on closing properties established by the engine-build checks
  (the EV IDs are in their bullets above), R-G5-08 on the inventory and the kernel reading since
  2026-10-18, R-G2-05 on the queue reading since 2026-10-16; each disposition rests on stated positive
  properties, not on the totality of the cell's predicate; 02 v10 rewrote U-02 and the three G2 slots'
  ledger cells to match (CR-S4-06).] Still open: each slot stays the explicit remainder of its cell, and a
  mechanism named later is an appended route.
- **U-03 (lifecycle preservation)**: MM-09, MM-10, MM-11, MM-12 and MM-15 remain unresolved; the G4
  preservation file sorts three D4 conditions "design unstated" on exactly these (T-40 with T-45; T-49;
  T-40 step 2 with T-09). (G4 preservation §D4, conclusion lines; R-GX-01, R-GX-03, R-GX-04, R-GX-06)
  [superseded in part 2026-10-19 (step 4): MM-09, MM-11, MM-12 and MM-15 are stated design text since 01 v9
  and realized in the prototype (EV-205, EV-195, EV-187); the G4 preservation conclusion line now sorts
  only the T-49 condition design unstated.] Still open: MM-10, the supervisor's domain-empty fact (C-06
  above). [superseded 2026-10-20 (fifth design revision): 01 v11 MM-10 states it as the old cell cgroup's
  populated 0 after cgroup.kill (EV-273 … EV-282; R-GX-04 supported under stated premises); the G4
  preservation file was not re-run and still sorts T-49 design unstated.]
- **U-04 (mutable-state reachability)**: whether a permitted parser or storage path can alter binding state
  is not shown by AA-04; and the read-then-act refinement for N1 / N9 — whether a permitted leak can reach
  a write of binding state — stays open, the read form having no named in-model second step (02 §4.2).
  (R-G2-11, R-G5-01, R-G5-02) [superseded in part 2026-10-19 (step 4): for the project's own C code on the
  receive path the parser half is answered within the fuzz run's limits (EV-166 … EV-168; R-G2-11), and the
  spawner's bootstrap read and the record-writer thread were read as producers outside the engine package
  (EV-260, EV-261).] [superseded 2026-10-19 (engine 7b4ab727): no third-party parser runs in the C reader
  any more (EV-265), and the fuzz rerun on the changed code (EV-267 … EV-269) replaces EV-166 … EV-168.]
  Still open: the parser half for the interpreter, CPython's json being a platform premise; the
  read-then-act refinement, unchanged.
- **U-05 (deployment / abstraction)**: the initial namespace (C3 / S13), the exclusive host-wide pool, S1 /
  S2 and the trusted supervisor require final evidence; no measurement in the registry covers a
  pre-existing holder, a concurrent engine or a supervisor. (R-G5-05, R-G5-06, R-GX-04, R-G2-05, R-G5-04)
  [2026-10-19 (step 4), not a supersession: the engine-side half of C3 is now realized (EV-165) and the pool
  premise is stated as engine-requirements §8 entries; the namespace identity, the pool's realization on a
  host, the production allow-set S2 and the supervisor all still lack final evidence (C-03 and C-06
  above).] [2026-10-20, not a supersession: the supervisor's method is now stated (01 v11 MM-10) and its
  kernel half measured on the development host (EV-278 … EV-281); its realization in a deployment still
  lacks final evidence.]
- **U-06 (scope of consumers)**: the pending grant_ref redesign, the MCP compartment and forwarded
  inter-agent messages are not analysed by this freeze; every C-08 route and R-G3-01 re-runs when they are
  stated. (R-G3-01, R-G3-02, R-G3-03, R-G3-04, R-G3-05, R-GX-05, R-GX-06) [superseded in part 2026-10-19
  (step 4): the grant_ref redesign is in 01 v10 and realized (EV-243, EV-184, EV-227).] Still open: the MCP
  compartment, forwarded inter-agent messages, a real E-10 adapter and a configured E-09 observer.
- **U-07 (language / source hygiene)**: not re-raised by any route or preservation file.
- **The kernel-intact premise and the declared exclusions**: the exclusion is an assumption whose cost is
  owed as evidence (W2's kernel-TCB residuals, SUB-14's read paths, SUB-07 for Rowhammer under ECC / DDR5 /
  KSM-off); the two exposure items at the pin (EV-27, EV-86) have no reachability assessment under the
  channel's socket type and the deployed policy, and whether EV-27's OOB path is reachable when the receiver
  treats OOB as fatal (EV-90) is open; S14 is unchecked on any production host and what it leaves inside
  the non-goal (engine-code gadgets, store-bypass) stays declared; nothing certifies another build (tm D8).
  (R-G5-01, R-G5-02; G5 preservation T-66 open) [2026-10-19 (step 4), not a supersession: R-G5-01 and
  R-G5-02 were not re-run; R-G5-02 §6 still calls the S14 per-task opt-in unbuilt, while the registry now
  carries the engine's indirect-branch opt-in (EV-232, EV-233), which R-G5-02's next re-run would weigh.]
  [superseded 2026-10-20 (engine 9981dd7b, user-approved): the engine half of S14 is realized — the opt-in
  uses PR_SPEC_FORCE_DISABLE, start-up refuses unless the read-back state has the FORCE bit, and a later
  PR_SPEC_ENABLE failed with EPERM on the development host (EV-283, EV-284; EV-233 superseded) — and
  R-G5-02's S14 sentences say so.] Still open: S14's host half, the production host's sysfs vulnerability
  readings, is unchecked on any production host (val row 259 is a deployment premise, not a registry
  observation); what S14 leaves inside the non-goal stays declared.
- **The TLA+ subset's bounds** (03 §5.2): two executions sharing one pool uid, at most three tasks per
  execution, a receive queue of two skbs, two allocation generations, two engine epochs; the stamp-mismatch
  branch of Accept has no coverage [superseded in part by CR-F-09: Stream Q's two-uid runs reach it, 05-concurrency.md §5] and at most one row is open at a time; T-01's and T-03's reuse checks
  are not encoded, so runs 2a–2c are a reachability check over a subset lacking the design's two other reuse
  checks, not an inductiveness result; consumers, request state, fd numbers and K-10, T-52's idempotence and
  tombstones, DRAINING (abstracted to ACTIVE) and the execution slot are not modeled; the MM-10 FALSE branch
  was not run; the one-skb-one-frame collapse is Stream Q's and the preservation rows argue per fragment
  instead; Stream Q may reopen the request-interleaving question (X-02). (R-G2-09, R-G4-01, R-GX-01,
  R-GX-02, R-GX-03, R-GX-04, R-GX-05; G1 preservation justification row 1; G2 preservation T-24 open, T-25
  open, justification row 5; G4 preservation J-04; G3 preservation justification row 2)
- **The interval-end reading**: 03 §1.1 (iii) models J_r as ending at the epoch's end (NewEpoch as the
  retirement event), under which R-GX-04's history would fall to D_62 ∧ q24 rather than D_61 ∧ q33; the
  ledger's assignment by q33 is followed and the wording tension is raised as CR-GX-01 [superseded: applied as CR-F-07 in 03 v4 §1.1 (iii); R-GX-04 §2 now cites the settled clause]. (R-GX-04)
- **The one-uid pool of the subset against a multi-uid pool**: the IG-10 split proposed in CR-G1-01 [superseded: applied as CR-F-01 in 03 v4] is
  needed as soon as the pool has more than one uid, where the subset cannot express a record carrying
  another lease's uid; the TLA+ one-uid, two-execution bound is not inherited by any G1 row. (G1
  preservation conclusion lines, justification row 1; R-G1-06)
- **Trusted-actor premises carried without a check**: AA-09 (the bootstrap sends exactly SEALED and then
  waits for COMMIT; a bootstrap that sent other bytes would be a trusted-actor departure) and AA-04 for the
  spawner's record discipline and the T-04-before-T-05 ordering. (G1 preservation justification row 2,
  T-04 open, T-07 open; R-G1-01, R-G1-03, R-G1-06) [superseded in part 2026-10-19 (step 4): the spawner's
  record discipline and order are now realized and read at the commit — socketpair, SO_PASSCRED on the
  engine end, then clone (EV-179), the registered-uid admission (EV-209), the per-fragment SEALED check
  (EV-210), the drop to the record's plan (EV-246) — and the order was observed on the diagnostic fixture
  (EV-178).] Still open: AA-04 and AA-09 remain premises (the trusted code runs as read), not checks
  against a departure; the negative cases named under C-02 and C-06 are not made.
- **Diagnostic against production policy**: every `[M]` on the P2a path (EV-73 … EV-77, EV-79, EV-80,
  EV-97, EV-98) was taken under the 2026-09-11 diagnostic seccomp policy; the production allow-set is a
  separate `[S]` (AA-11), so no composed defence on that path is measured end to end. (every G1, G2, G4 and
  GX route's section 5; G2 preservation T-20 open, T-64 open) [2026-10-19 (step 4), not a supersession: the
  prototype's integration and sandbox cases also ran under the diagnostic policy; the production allow-set
  S2 stays `[S]` (EV-129) and outside the build's scope (val row 177); R-G2-09, R-G2-11 and R-G2-13 state
  that their cut does not rest on it; no re-run route claims a composed defence measured end to end.]
- **Pre-registered hypotheses, as adjudicated**: no route records a disagreement with 02 §4.1; the PLAN's
  expected errno values for the self-mapped sub-arm remained the hypotheses the probe decides, and the
  PLAN's placement of the explicit foreign-uid route in G2 is superseded by the ledger's cut (R-G5-04 plus
  the R-G2-05 remainder); the "unshare allowed ⇒ forged uid" reading is rejected, not copied. (R-G2-05,
  R-G5-04, R-G5-07)
- **Statements about the analysis itself**: whether an analyst can tell that a concrete history falls in a
  remainder slot rather than a named neighbour is recorded by 02 §4 (addendum F-04) as a statement about
  the analysis, not a reason to move histories. (R-G3-05, R-GX-06, R-G5-08)
- **Added 2026-10-19 (step 4) — the realization's substrate.** Every re-run disposition rests on the
  prototype at commit 3ec67985 (engine code at 74833c58, unchanged by later commits except one test-build
  line of spawner.c; the C frame reader as changed by engine commit 7b4ab727, which removed its body parse,
  EV-265, with the integration, sandbox and fuzz reruns EV-267 … EV-271) on the WSL2 development host only (kernel 6.6.87.2-microsoft-standard-WSL2; no
  native-Linux substrate), runs of 2026-10-18 and 2026-10-19, the agent as the native fixture; kernel facts
  are source readings at linux-msft-wsl-6.6.87.2, and nothing certifies another build. No row is a claim
  about a deployed system. (all 30 re-run route files, section 5)
- **Added 2026-10-19 (step 4) — fuzz limits.** The fuzz run is one run of one hour per entry with no
  repetition, so its result is that this run found no memory error or oracle violation, not that none
  exists; the fuzzed build is clang 18 at -O1 while the product library is a gcc -O2 build of the same
  source, checked only by the gcc ASan/UBSan replay of the final corpora; the frame entry's EOF, deadline
  and reader-rebinding branches are left to unit tests and code reading; one line of w2_recv_credential is
  not executed; the negative control demonstrates one defect class only; the control fuzz entry ran with
  jansson uninstrumented (EV-168). R-G2-11 asks that the product library's build identity be recorded
  beside the fuzzed source identity. (R-G2-01, R-G2-02, R-G2-03, R-G2-11, R-GX-01, R-GX-02) [superseded in
  part 2026-10-19 (engine 7b4ab727): the three entries were rerun on the changed reader (run
  20261019T025332Z-fuzz-no-c-parse; EV-267, EV-268, EV-269), which replace EV-166 … EV-168 for the current
  code, and the replay executed every line of w2_frame_receive (EV-267).] Still open: the rerun has the
  same one-run, one-hour, no-repetition limit; the clang-against-gcc build difference and the build-identity
  obligation stand; the frame entry's EOF, deadline and reader-rebinding branches and line 158 of
  w2_recv_credential stay outside it; the negative control is from the earlier run; the Python json parse
  is not fuzzed; the control entry still runs jansson uninstrumented, on the trusted spawner's records only
  (EV-269).
- **Added 2026-10-19 (step 4) — runs and cases named and not made.** Composed runs of 04 §5: item 24
  (R-GX-01), item 25 (R-GX-02) and item 27 (R-GX-04) not done, items 26 (R-GX-03) and 28 (R-GX-05) done in
  part. Cases proposed by the re-run files and not registered because no observation exists: the bootstrap
  FAIL record read in the hello phase (R-G2-01); interleaved partial frames on two channels (R-G2-04); pool
  uids above 2^31 (R-G2-06); a sender change at the last byte (R-G2-07); swapped expected uids (R-G2-08); a
  different-uid holder of a duplicate agent end (R-G2-09); two live executions under one recurring
  local_agent_id (R-G2-10); an instrumented jansson fuzz entry (R-G2-11; no longer needed since engine
  7b4ab727 removed the C-side body parse, EV-265); a wrong-uid case through the full
  lifecycle in ACTIVE and DRAINING (R-G2-13); a live descendant at stop (R-G4-01); the engine's own
  namespace link (R-G5-05) [superseded in part 2026-10-21 (extra evidence): item 27 (R-GX-04) done,
  EV-295 … EV-298; the cases of R-G2-06, R-G2-07, R-G2-08 and R-G2-09 made and registered, EV-289 …
  EV-294]; and, named in section 6 only, the spawner-order integration run and the
  omitted-option case (R-G1-01), a uid-pool exhaustion test and a direct holders refusal (R-G1-05), a
  foreign-uid SEALED case (R-G1-06), a cross-session test with two sending uids (R-G3-02).
- **Added 2026-10-19 (step 4) — readings at the pinned tag not checkable here.** Three proposed kernel
  readings were not registered because the pinned tree is not in this workspace: whether a sender can
  produce MSG_CTRUNC against the data channel's control buffer (R-G2-03), K-06 for SOCK_STREAM, P-32
  (R-G4-01, R-GX-01), and map_write's extent rule with the PROC_USER_INIT_INO value (R-G5-05).
- **Added 2026-10-19 (step 4) — statements of the validation record that the route files did not find in
  the code.** Row 172 says the E-09 hook does not exist in the first version, while the code has an
  observe-only hook point (R-G3-01; G3 change request 5); the R-GX-06 section gives its result as
  satisfied by test, while the "only" rests on code reading, and its limit omits the integration normal
  case (R-GX-06; CR-GX-02); row 175 names the Python json parse as covered by fuzzing, which ran on
  transport.c only (R-G2-11; G2 change request 3 of the slot re-run); row 129's cited test refuses at the
  execution-slot limit, not by a uid shortage (R-G1-05); validation.md at HEAD differs from the blob 04 v7
  cites in rows 145, 146 and 170 (CR-G2-4a-3, registered as EV-252). None changes a disposition.
- **Added 2026-10-19 (step 4) — status text that predates the build.** mech's obligation #4 status line
  still reads "PARTIAL — NOT BUILT" (R-G1-05, R-G4-01); 02's U-02 text and ledger rows called the three
  G2 slots unresolved (R-G2-11, R-G2-12, R-G2-13) [superseded 2026-10-19: 02 v10 rewrote them, CR-S4-06];
  the G5 preservation rows T-61 and T-67 (a) still call
  C1 unchecked and its conclusion line names the C3 self-check unbuilt (R-G5-03, R-G5-07; CR-G5-03); the
  G1 preservation conclusion line still records the T-03 reading as unstated (R-G1-05); within the route
  files, the section 6 of R-G1-03 and of R-G2-06 still lists as unregistered rows that their own section 4
  records as registered (EV-245; EV-247 … EV-250). Reconcile maps each; none changes a disposition.

## Counts

- C-01: 5 · C-02: 6 · C-03: 8 · C-04: 6 · C-05: 8 · C-06: 13 · C-07: 4 · C-08: 11 · model and method: 21
  (82 bullets: the 60 of 2026-10-16 plus 22 added 2026-10-19; 36 of the 60 carry a step 4 superseded
  marker, in full or in part — 32 from the re-run route files, 4 from the 2026-10-18 text of R-G5-03,
  R-G5-06, R-G5-07 and R-G5-08 — and each keeps its open remainder as its own sentence; 8 more carry a
  dated note that is not a supersession)

## Stream Q — unresolved relations (05-concurrency.md §6, folded 2026-10-16)

Eleven relations, none a route and none changing I; they are listed in full in reconcile.md §6 and are
counted beside the 82 items above. In short: MM-09 (T-40 step order), MM-10 (supervisor domain-empty fact,
no mechanism), U-05 (second engine on an overlapping pool), MM-16 (`local_agent_id` assignment and keying),
the parse → admission turn boundary, the event library's no-stale-readiness property, K-06 for
`SOCK_STREAM` (candidate P-32), the control-record carrier for a kill / wait error, the two C-LP items of
CR-F-08, and the design-level status of every "decided by the frozen text" verdict. Since step 4 the route
files bear on three of them: MM-09's order and MM-16's keying are realized in the prototype (EV-205;
EV-196; C-07 and C-08 above), and the no-stale-readiness property is checked for the epoll backend only by
the AA-13 check (EV-191; C-05 above); MM-10 and K-06 stay as stated; the others are not addressed by the
route files. [superseded in part 2026-10-20 (fifth design revision): MM-10 now has a mechanism, the old
cell cgroup's populated 0 after cgroup.kill (01 v11; EV-273 … EV-282; C-06 above); K-06 stays as stated.]
