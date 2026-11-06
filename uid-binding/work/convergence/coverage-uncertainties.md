---
role: reconcile-draft — the coverage uncertainties open now
status: compacted 2026-10-21   # current state only; history in coverage-uncertainties-archive-2026-10-21.md
# Compacted 2026-10-21 (user request): every bullet states only what is open at 01 v11, 02 v10, 03 v5 and 04 v12.
# Bullets whose uncertainty is resolved are not carried; resolved halves, "superseded" markers and dates are in the
# archive, verbatim. Limits shared by every route are stated once in "Shared evidence boundary"; overlapping bullets
# of the earlier file are merged (the archive's 82 bullets → 56 here, plus the 5 shared-boundary bullets). Status sentences of the archive that no
# longer hold were checked against their files on 2026-10-21 and dropped (mechanism.md's obligation #4 status, the
# G4 preservation sort of T-49, the §6 of R-G1-03 and R-G2-06, the validation-record statements now reworded).
date: 2026-10-21
based_on:
  model_blob: "8e5d9e5d21330b6a"
  decomposition_blob: "eceee4b4c7426e3a"
  invariant_blob: "ae58d7db31c95c82"
  registry_blob: "046b0449a22e687c"
---

# Coverage uncertainties — reconcile draft

The uncertainties the 38 route files and the five preservation files leave open, one bullet per distinct
uncertainty with the IDs that raise it, grouped under the sufficient condition (C-01 … C-08) it concerns, then
the model and method. Nothing here is a disposition or a new route, and nothing is stated that is not in those
files. A case named and not made is stated in the bullet of the property it bears on. Earlier text, including
every resolved item: [coverage-uncertainties-archive-2026-10-21.md](coverage-uncertainties-archive-2026-10-21.md).

## Shared evidence boundary (every route; not repeated below)

- **Prototype and substrate.** Every disposition rests on the engine prototype (code at commit 3ec67985, whose
  engine code equals 74833c58 apart from one test-build line of spawner.c; the C reader as changed by 7b4ab727, which
  removed its body parse, EV-265; the fixes of 9981dd7b; the tests of b262e80e) on the WSL2 development host only
  (kernel 6.6.87.2-microsoft-standard-WSL2; no native-Linux substrate), with the native fixture as agent and the
  model chain and resources as stub connectors. Kernel facts are source readings at linux-msft-wsl-6.6.87.2.
  Nothing certifies another build, and no row is a claim about a deployed system.
- **Diagnostic policy.** Every `[M]` on the engine path ran under the diagnostic seccomp policy; the production
  allow-set S2 stays `[S]` (EV-129) and outside the build (val row 177), so no composed defence is measured end to
  end. R-G2-09, R-G2-11 and R-G2-13 state that their cut does not rest on S2.
- **Deployment premises realized on no host.** The engine in the initial user namespace (C3 / S13), the exclusive
  host-wide uid pool, the cell's own cgroup under host init with release on populated 0, the spawner's CAP_KILL and
  S14's host half are engine-requirements §8 entries the engine does not check; each is the deployer's evidence.
- **Per-commit facts.** Text searches and code readings — one VerifiedContext constructor, no name-, uid- or
  fd-keyed table, one write of expected_uid, no SO_PEERCRED, no pid lookup or /proc scan — hold for the commit read
  and are repeated at each code change.
- **One run each.** Every run is a single run with no repetition; the fuzz is one hour per entry.

## C-01 — byte origin and witness

- An alternate read API or asynchronous submission path admitted by a future production ABI needs its own witness
  check (U-01 re-raised); io_uring is outside the fill list only by S2, the policy compiler refusing an allow list
  that names it (EV-215). (R-G1-01, R-G2-01, R-G2-05)
- Each pending consumer — the MCP compartment, engine-forwarded inter-agent messages, a real E-10 adapter, a
  configured E-09 observer — adds a candidate VerifiedContext constructor and re-runs R-G3-01; an unlisted shape of
  alternate constructor is still q01. (R-G3-01)
- R-GX-01's cut is spatial (which socket, which buffer); it says nothing about bytes a surviving task of A queues
  on B's own socket (R-G4-01) or about a different-uid holder of B's endpoint (R-G2-09); its composed run (04 §5
  item 24) is not done. (R-GX-01)
- Parsing and memory safety: the C reader rests on one fuzz run of one hour per entry over transport.c and
  support.c, with the frame entry's EOF, deadline and reader-rebinding branches and line 158 of w2_recv_credential
  outside it, the clang-against-gcc build difference and the build-identity obligation open, and the negative
  control from the earlier run; CPython's json, the only body parse, is a platform premise and is not fuzzed;
  jansson remains in the trusted spawner's control-record parser only, fuzzed uninstrumented (EV-269). U-04's
  parser half is answered for the project's own code within these limits, not for the interpreter. (R-G2-01,
  R-G2-02, R-G2-03, R-G2-11, R-G2-13, R-GX-01, R-GX-02)
- A bootstrap FAIL record arriving on the agent's channel in the hello phase is read, by the code, as an oversize
  length that closes the channel; an integration case recording it is named and not made. (R-G2-01)

## C-02 — stamp population and equality

- The R-G2-05 slot leaves kernel defects (R-G5-01), the queue reading's two stated bounds (out-of-family
  receive-queue writers sorted by directory, the remaining sockfd_lookup callers sorted by protocol) and the
  io_uring execution context, unread at the pin and relevant only if S2 admits asynchronous submission. Step 11
  absent on the deployed host is a T-67 premise failure. R-G2-05 was not re-run, and its §6 still calls the T-22
  second layer an `[S]` engine check although the prototype realizes it (EV-171, EV-176, EV-181, EV-237). (R-G2-05,
  R-G5-01; G2 preservation T-20 open, T-64 open)
- The explicit foreign-uid send is measured on the WSL2 arm only (EV-29); the native-Linux arm is pending.
  (R-G2-05, R-G5-04)
- The fault branches of C1 and the launch correspondence are read, not exercised: the spawner's SEALED
  uid-mismatch branch (EV-210) and the re-read's unequal-value comparison (EV-148, EV-149), the fault points
  exercised preceding the comparison; a regression case in which the bootstrap sends SEALED from a foreign uid is
  named and not made; the consequence bound is kept and not relied on. (R-G1-06, R-G5-03, R-G5-07)
- R-G5-04's sub-branch B is further narrowed by S2 not admitting what S1 denies — an optional surface reduction,
  not a component the defence needs (CR-R3-19). (R-G5-04)
- C4 (a), SO_PASSCRED armed before any task of P_X exists: the order was observed on the busy case of the
  diagnostic fixture only, not in an engine integration run (EV-178); the T-09 refusal was exercised with sockets
  the test made, not with a spawner that omitted the option (EV-177); "never cleared" rests on a text search
  (EV-180). An integration run recording the spawner's order and a case in which the real spawner omits the option
  are named and not made. (R-G1-01, R-G2-03, R-G5-05, R-GX-01)

## C-03 — translation and decoding fidelity

- The engine's namespace being the initial one (C3 / S13): the start-up check confirms the identity map, not the
  namespace's identity (EV-80; val row 256); on the development host the identity is inferred from the WSL2
  distribution's init and the agents' namespace link (EV-213), not shown for the engine. The readings that would
  narrow it — map_write's extent rule and the PROC_USER_INIT_INO value at the pinned tag (tree not in this
  workspace), and the engine's own namespace link in its startup posture — are not made. The R-G2-12 slot adds one
  refusal case on one substrate. (R-G1-01, R-G1-02, R-G2-06, R-G2-09, R-G2-12, R-G5-01, R-G5-05)
- Under a non-identity map a foreign kernel uid could match only through the map; whether a task at such a uid is
  reachable is R-G5-05's and R-G5-06's subject and is not argued in R-G1-02. (R-G1-02, R-G5-05, R-G5-06)
- No E-09 export consumer exists, so the absence of a subject and of a sentinel principal is checked at the
  recorder, not at any reader of the export. (R-G2-03, R-G3-04, R-G5-05)
- An engine bookkeeping defect at T-01 (a wrong expected_uid written) is the honest-but-buggy case of 02 §0.3: the
  write-once rule localises it to one transition and one field but does not exclude it. (R-G1-02)
- The start-up pool check excludes identities in use on the host only as far as NSS reports host accounts
  (EV-201, EV-202; val row 131). (R-G1-02, R-G5-05)
- Receiver inputs not produced by the kernel in any run: the sentinel, pid 0, MSG_CTRUNC, duplicated and short
  credential buffers are synthetic (EV-176); a kernel-truncated rights message appears only as constructed
  headers in the ancillary fuzz entry; whether a sender can produce MSG_CTRUNC against this control buffer is a
  pinned-tag reading not checkable here. Pool uids above 2^31 are exercised on the receive side only (EV-289,
  EV-290), not through the catalog and the spawner. (R-G2-03, R-G2-06, R-G5-05)

## C-04 — current comparison

- The comparison tests' own limits: the phase rule ran on a stand-in row object, so phase coverage outside
  STARTING rests on it, and a wrong-uid case through the full lifecycle in ACTIVE and DRAINING is named and not
  run; the negative frames share one code path and differ only in the failure position; the swapped-rows case runs
  in the unit harness with a scripted spawner (EV-292). (R-G2-02, R-G2-07, R-G2-08, R-G2-13)
- Whether S2 permits an MSG_OOB send at all is part of the S2 `[S]` item; the OOB-path memory-safety item (EV-27)
  is R-G5-01's declared exclusion. (R-G2-02, R-G5-01)
- Same-uid joint writers are one principal by W2.1: no route separates members of P_X, and the design does not
  claim to. (R-G2-07; G2 preservation justification row 1)
- Outbound confidentiality under A-07 is not protected by this mechanism — a holder reads what the engine writes
  to the endpoint (kub §7.4; X-10); the acquisition footing of A-07 (the d2 naive-spawn leak; the pidfd_getfd exit
  window of CVE-2026-46333, unfixed at the pin, confined by the uid/gid match to same-uid tasks) does not enter I.
  (R-G2-09, R-G3-03; G2 preservation T-63 open)
- The different-uid holder of the agent end received its copy from the test over SCM_RIGHTS, not through a spawn
  defect, and held CAP_SYS_ADMIN to name another task's pid (EV-293, EV-294). (R-G2-09)

## C-05 — row, channel and allocation association

- MM-05: the engine cannot establish that the delivered fd's peer is the child's fd 3; the design carries it as
  spawner trust plus the spawner's SEALED pid check (EV-210), and the endpoint half rests on code reading (EV-179).
  (R-G1-03; G1 preservation T-09 open)
- The T-03 miscopy case — a record carrying another lease's uid — is not expressible in the one-uid TLA+ subset,
  and that bound is inherited by no G1 row; a miscopy passing the directory check needs two workspaces on one uid,
  refused at one engine's start-up (EV-202) and across engines resting on the pool premise (U-05). (R-G1-06; G1
  preservation conclusion lines)
- R-GX-02's per-record rules: a later build that indexed control records by uid, by the received descriptor's
  number or by workspace alone would leave every cut; the per-history unit tests use a stand-in spawner, the
  integration cases do not cover every prepared / empty order on two rows of one uid, the composed two-row run
  (04 §5 item 25) is not done, and the bounded check does not model T-52's idempotence or tombstones. (R-GX-02)
- fd-number reuse: reuse inside one round is made by the tests (low fds held, os.dup2), not by the real spawner,
  which reuses numbers in sequence across rounds (EV-189 … EV-191); the AA-13 check covers CPython selectors with
  the epoll backend only, so another backend or event library needs the same check before it is admitted; the
  composed alias run through the real spawner (04 §5 item 26) is done in part; the bounded check does not model fd
  numbers or K-10; an integration case with two channels whose partial frames interleave between executor turns
  is named and not run. (R-G1-03, R-G2-04, R-GX-01, R-GX-02, R-GX-03, R-GX-05, R-GX-06)
- Two live executions under one recurring local_agent_id are covered by code reading and by a recurring name
  across a release (EV-189, EV-195), not by an integration case with both live; that case is named and not made.
  (R-G2-10)
- A later build keeps R-GX-06's property only by keeping the five obligations its §6 lists. (R-G1-03, R-GX-02,
  R-GX-03, R-GX-06)
- The write-once properties hold by code structure, not by type: the guard is a Python-level check on attribute
  assignment that admits a first assignment to a field still holding None (EV-187), and the Channel → Session
  link's "written once" holds by code structure (EV-194; val row 149). (R-G1-02, R-G2-08, R-GX-06)

## C-06 — uid exclusivity

- The uid ↔ execution 1:1 premise across engine instances rests on the deployment's cell cgroup and release gate
  (R-GX-04); within one engine the holders refusal and the previous-row refusal rest on code reading, the held-uid
  test being refused earlier at the workspace check, and uid-pool exhaustion is exercised by no test (the cited
  test refuses at the execution-slot limit; EV-199 note); a direct holders-refusal test is named and not made.
  (R-G1-05, R-GX-04)
- Whether "uid and lease unused" at T-03 counts a process-terminal record awaiting its storage release: the
  prototype realizes the permissive reading the user ruled (EV-209), while the G1 preservation conclusion line
  still records it as the one unstated reading; both readings preserve I. (R-G1-05; G1 preservation T-03 open)
- Nothing verifies after clone that a namespace is fresh (optb L211–212); carried as AA-04. (G1 preservation
  T-05 open)
- The exclusive-pool premise: no run measures a pre-existing holder, a concurrent engine or an inventory; when the
  premise fails the route is reachable given A-07 and the engine cannot see it. (R-G1-05, R-G5-06)
- A privileged actor outside every configured allocator stays AA-04, unchecked by the engine; R-G5-04 §6 still
  records the helper statement as not stated as a requirement. (R-G5-04, R-G5-07)
- R-G5-08: the kernel reading's bounds (a whole-struct copy or an unusually named variable would escape the
  sweep; override callees not traced); a history reaching u_r by an unlisted path lands here and must be
  investigated; no run measured any history in or near the cell. (R-G5-08)
- Survivors within one engine: a history that defeats both legs of R-G4-01 is not argued in one file; no run
  placed a live survivor at release, and an integration case with a live descendant at stop is named and not run;
  the seal rests on code reading plus regression cases that end before clone (val row 209). (R-G4-01, R-GX-02,
  R-GX-03)
- The epoch boundary: no supervisor is built and no deployment has placed a cell in its own cgroup; whether the
  gate is a host-init unit, a wrapper or an operator procedure is not fixed by the design. The two-epoch run
  (EV-295 … EV-298) is one run on the development host with a stand-in gate and an agent silent after its hello —
  no surviving task tried to leave the cgroup or reach engine 2's rows; the no-leave premise was observed for an
  unprivileged member under one cgroup ownership layout (EV-279); the MM-10 FALSE branch was not run in the
  bounded check. (R-G1-05, R-G4-01, R-GX-04)
- The explicit ambient and permitted clear of step 11 is unexercised as a step in its own right (01 MM-13); its
  outcome, capability sets zero, is observed (EV-74). (R-G5-07)

## C-07 — send inside the allocation interval

- A later build keeps the order of T-40 step 2 before release only by keeping the obligation R-GX-01 §6 lists; I
  needs neither the order nor a drained channel. (R-G4-01, R-GX-01, R-GX-03)
- K-06 for SOCK_STREAM — that a queued skb survives its sender's exit until read or socket release — has no
  registered source location: only the datagram measurement EV-58 exists, and the P-32 reading is not checkable
  here (pinned tree absent); it bears on whether R-GX-01's precondition arises, not on its cut. (R-GX-01, R-G4-01;
  G4 preservation T-42 open, T-65 open; G2 preservation T-20 open)
- MM-12 (no transition reads the old slot when binding the new row) is design text and a test (EV-195), not an
  invariant of I. (R-GX-05, R-GX-06; G4 preservation T-45 open, J-06)

## C-08 — carry to consumers

- Consumers not yet built — the MCP compartment, engine-forwarded inter-agent messages, a real E-10 adapter, a
  configured E-09 observer and every real connector — must each key by object and re-run R-G3-01 and the C-08
  routes when built (U-06). The decoy check replaces the execution_id key only, the uid, fd and local_agent_id
  keys being excluded by code reading (EV-196, EV-197). (R-G2-10, R-G3-01, R-G3-02, R-G3-03, R-G3-04, R-G3-05,
  R-GX-05, R-GX-06)
- With the model chain and the resources as stubs, every consumer-side disposition is checked up to the stub
  handlers; the validation record's R-G3-05 check is repeated each time a real connector replaces a stub, and a
  real E-07 connector's network-side callbacks and their attachment of results to the sink are re-checked then.
  (R-G2-10, R-G3-01, R-G3-02, R-G3-03, R-G3-04, R-G3-05, R-GX-05)
- The pre_egress hook point is observe-only because no observer is configured and the return is discarded
  (EV-255), not because the type forbids a write; a configured observer receives the mutable RequestEntry and is a
  consumer in its own right. (R-G3-01, R-G3-03, R-G3-05)
- The cross-session cases of R-G3-02 rest on code reading, the unit layer having one sending uid; a test with two
  sending uids is named and not run; the build has no rebind entry, so the design's rebind guard is unexercised
  and a later rebind entry re-runs the T-39 sub-case. (R-G3-02)
- A same-uid process in P_X that learns the current call id is the same subject (W2.1), so a join inside one
  execution is outside the C-08 routes. (R-G3-02; G3 preservation T-36 open)
- Future consumers of the E-09 export inherit whatever T-38 emitted (U-06); whether the "clearly distinguished
  unverified information" allowed on a reject (si L68) or the session_id in a diagnostic record's detail group can
  be mistaken for a subject is a schema question for that consumer's design. (R-G3-03, R-G3-04)
- R-GX-05: two sessions ACTIVE at once rest on code reading only (val row 236); the composed run (04 §5 item 28)
  is done in part; the bounded check does not model consumers. (R-GX-05)
- Obligation #5 (no delegation leakage between agents) remains open and is adjacent: the subagent chain is outside
  the frozen text, and a join to another execution's grant is the local shape of that leakage. (R-G3-02, R-GX-05)

## Model and method

- **U-02 (refinement slots).** No slot is open; each stays the explicit remainder of its cell, and a mechanism
  named later is an appended route. Whether an analyst can tell that a concrete history falls in a slot rather than
  a named neighbour is a statement about the analysis (02 §4, addendum F-04), not a reason to move histories.
  Since 2026-10-23 (M1 repair) R-G2-11 is conditional on unbuilt requirements: the memory half of its closing
  property, the memory safety of the C reader, is a stated requirement for prove 2.2 to establish, the fuzz run being
  supplementary evidence. (R-G2-05, R-G2-11, R-G2-12, R-G2-13, R-G3-05, R-G5-08, R-GX-06)
- **U-04 (mutable-state reachability).** The read-then-act refinement for N1 / N9 — whether a permitted leak can
  reach a write of binding state — stays open, the read form having no named in-model second step (02 §4.2).
  (R-G5-01, R-G5-02)
- **U-07 (language / source hygiene).** Not re-raised by any route or preservation file.
- **The kernel-intact premise and the declared exclusions.** The exclusion is an assumption whose cost is owed as
  evidence (W2's kernel-TCB residuals, SUB-14's read paths, SUB-07 for Rowhammer); the two exposure items at the pin
  (EV-27, EV-86) have no reachability assessment under the channel's socket type and the deployed policy, and
  whether EV-27's OOB path is reachable when the receiver treats OOB as fatal (EV-90) is open; what S14 leaves
  inside the non-goal (engine-code gadgets, store-bypass) stays declared. (R-G5-01, R-G5-02; G5 preservation
  T-66 open)
- **The TLA+ subset's bounds** (03 §5.2): two executions sharing one pool uid, at most three tasks per execution,
  a receive queue of two skbs, two allocation generations, two engine epochs; the stamp-mismatch branch of Accept
  is reached only in Stream Q's two-uid runs (05-concurrency.md §5), and at most one row is open at a time; T-01's
  and T-03's reuse checks are not encoded, so runs 2a–2c are a reachability check, not an inductiveness result;
  consumers, request state, fd numbers and K-10, T-52's idempotence and tombstones, DRAINING (abstracted to
  ACTIVE) and the execution slot are not modeled; the MM-10 FALSE branch was not run; the one-skb-one-frame
  collapse is Stream Q's, and the preservation rows argue per fragment instead. (R-G2-09, R-G4-01, R-GX-01,
  R-GX-02, R-GX-03, R-GX-04, R-GX-05; G1 preservation justification row 1; G2 preservation T-24 open, T-25 open,
  justification row 5; G4 preservation J-04; G3 preservation justification row 2)
- **Trusted-actor premises.** AA-04 (the spawner's record discipline and order) and AA-09 (the bootstrap sends
  exactly SEALED, then waits for COMMIT) are premises — the trusted code runs as read — not checks against a
  departure. (R-G1-01, R-G1-03, R-G1-06; G1 preservation justification row 2, T-04 open, T-07 open)
- **Pre-registered hypotheses, as adjudicated.** No route records a disagreement with 02 §4.1; the PLAN's placement
  of the explicit foreign-uid route in G2 is superseded by the ledger's cut (R-G5-04 plus the R-G2-05 remainder);
  the "unshare allowed ⇒ forged uid" reading is rejected, not copied. (R-G2-05, R-G5-04, R-G5-07)
- **Files whose text predates the build.** The G5 preservation rows T-61 and T-67 (a) and its conclusion line,
  which still names the C3 self-check unbuilt (CR-G5-03, open), and R-G2-05 §6 (C-02 above); neither changes a
  disposition. (R-G2-05, R-G5-03, R-G5-07)

## Counts

Shared evidence boundary: 5 · C-01: 5 · C-02: 5 · C-03: 6 · C-04: 5 · C-05: 7 · C-06: 9 · C-07: 3 · C-08: 8 ·
model and method: 8 — 61 bullets. They carry what is still open of the archive's 82 bullets: 5 archive bullets were
resolved in full and are not carried (the "if admitted" half of R-G1-01, MM-15, the interval-end reading, U-03's
lifecycle items, the validation-record statements), the archive's index of runs and cases not made is not carried
because each open case now sits in the bullet it bears on, and the rest are merged where they overlapped.

## Stream Q — unresolved relations (05-concurrency.md §6)

Eleven relations, none a route and none changing I, listed in full in reconcile.md §6. Their state now: MM-09's
order and MM-16's keying are realized in the prototype (EV-205; EV-196); MM-10 has a mechanism, the old cell
cgroup's populated 0 after cgroup.kill (01 v11; EV-273 … EV-282), realized on no deployment (C-06 above); the
no-stale-readiness property is checked for the epoll backend only (EV-191; C-05 above); K-06 for SOCK_STREAM stays
as stated (C-07 above); U-05 (a second engine on an overlapping pool), the parse → admission turn boundary, the
control-record carrier for a kill / wait error, the two C-LP items of CR-F-08 and the design-level status of every
"decided by the frozen text" verdict are not addressed by the route files.
