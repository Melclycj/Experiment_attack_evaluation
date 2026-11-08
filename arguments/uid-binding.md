# Security argument for the local uid binding (2026-10-18)

Moved here on 2026-10-23 from mechanism.md, which keeps a pointer at the old anchor. Content unchanged except heading levels and relative links.

This section supersedes the arm3-era "Proof-obligation discharge status (after arm3, 2026-07-03)" (user ruling 2026-10-18: those statuses rested on a demonstration, not on an argument of this rigour). It is the adversary-vector table of the uid-binding line, approved by the user at U on 2026-10-18; the route, preservation and spine files it is extracted from live under [`work/`](original/uid-binding/work).

**Updated 2026-10-19** with the engine build's checks (uid-binding follow-up step 4, approved by the user): every
route whose defence the engine prototype realizes and checks moved to supported under stated premises, under the
disposition rule the preface states; the engine's C frame reader stopped parsing message bodies on the way
(engine commit 7b4ab727). Reviews: Claude Opus and Codex, both "may pass" after one repair round. The same day the fifth design
revision stated the supervisor's domain-empty method as a kernel-held fact (the old cell's own cgroup reports
`populated 0`), and R-GX-04 moved to supported under stated premises.

**Updated 2026-10-23** (M1 repair, the user-approved M1-repair-plan.md, after the Codex method
review [M1](original/uid-binding/work/reviews/M1-codex-method-2026-10-23.md)): R-G2-11 is re-judged *conditional on unbuilt requirements* —
the memory safety of the C frame reader is a stated requirement whose proof is assigned to prove 2.2, and the one-hour
ASan/UBSan fuzz run is supplementary evidence, not its discharge; counts 35 · 1 · 0 · 2. The Counts section classes the
supported rows by the premises they rest on, and the Preface marks which rows concern the label at accept and which the
label the consumers carry.

## Preface

**Adversary.** The declaration of scope-and-boundary.md §Boundary Defence, verbatim: *"Adversary =
arbitrary code running at the agent's uid within the envelope the engine constructs. The capability of the
language model is **not** a load-bearing assumption."* — with the kernel inside the TCB (the section's
non-goals: compromised host kernel · malicious hypervisor · broken sandbox implementation · fully-malicious
engine · cross-domain hardware read/write).

**Position of this table.** It fills the **mediated face** row of that section's five-surface table: what Leg 1
of the two-leg trust model (mechanism.md) withstands, enumerated as routes to false attribution. The property
is 02 §0: the label the engine reads at accept names the execution of the kernel task that executed
`sendmsg`, with time semantics live-at-send; same-uid siblings are one execution class by construction (W2.1)
and are outside the property. The property has two parts (02 §3), and each row belongs to one, the two boundary
rows excepted (they can violate any condition of either part). The part just stated holds *at accept* (P_acc, conditions C-01…C-07): 31 rows, plus the two boundary rows R-G5-01 and R-G5-02,
which can violate any condition. The second part holds *at the consumers* (P_carry, condition C-08): every
consumer's claimed sender equals the label the accept produced, and no originless verified subject is introduced
— the five rows R-G3-02, R-G3-03, R-G3-04, R-G3-05 and R-GX-05, whose stop is the object-reference discipline,
checked up to the stub handlers. A consumer-only defect leaves the accept-time label intact (02 §3), and P_carry
does not imply authorization or the correctness of what a consumer does with the label.

**Judging criteria.** Always invoked and tamper resistance for the local binding; correctness of the engine's
own decision logic is a separate obligation (#6) and is not established here.

**Tags.** `[M]` measured · `[R]` source-read · `[S]` stated requirement not built — `[S]` here is the same
thing as `[U]` in option-b-workload-per-engine.md and scope-and-boundary.md. From step 4 (2026-10-19) an engine-side
item realized in the engine prototype carries `[M]` (a recorded run under ExperimentLab/engine/runs) or `[R]` (a code
reading of the project's own engine or sandbox code); the design statement it realizes keeps its `[S]` row.

**Dispositions (exactly one per route).** supported under stated premises · conditional on unbuilt
requirements · open · declared out of scope. A "supported" row rests on the frozen design, kernel semantics
where cited and — since step 4 (user ruling 2026-10-19) — the engine prototype's checked realization: a route is
supported when every necessary item of its defence is backed by `[M]` or `[R]` evidence, under the premises its
route file names, with the realization's limits stated in its section 5 (prototype at commit 3ec67985, WSL2
development host, diagnostic seccomp policy, model chain and resources as stub connectors, each check's own
limits). Deployment preconditions the engine cannot check are premises. A route is *conditional on unbuilt
requirements* when a necessary item of its defence is a stated requirement not yet established, whatever evidence
short of establishing it exists; R-G2-11 is such a row since 2026-10-23 (the memory safety of the C frame reader,
a requirement for prove 2.2 to establish, with the fuzz run as supplementary evidence). A requirement whose failure
could be the first failed condition in more than one cell — the memory safety of the C reader: C-01 in R-G2-11's cell,
C-04 in R-G2-13's, C-05 in R-GX-06's — is carried by one row, the remainder slot of the cell its own code path belongs
to (R-G2-11); the other rows name it as a premise owned there, and their dispositions are read together with
R-G2-11's. No row is a claim about the deployed
system, which would additionally need the P2b configuration evidence, and no row is measured end to end.

**What the table does not claim.** W2.1 same-uid indistinguishability; the live-at-send time guarantee beyond
what kub §8 states; outbound confidentiality (kub §7.4); that the route list leaves nothing out — the list is a
structured coverage argument under the 02 decomposition (its coverage warrant, 02 §4.3) with the
uncertainties listed in [coverage-uncertainties](original/uid-binding/work/convergence/coverage-uncertainties.md) and [reconcile.md](original/uid-binding/work/convergence/reconcile.md) §6;
that every mechanism has been derived — what the decomposition supports is that the classification of bad
histories has total coverage relative to the listed model and predicates (every history that violates P_acc or
C-08 reaches exactly one route, 02 §4.3), not that the 38 mechanisms are all the mechanisms there are.

**Substrate of every `[M]` row.** Kernel `6.6.87.2-microsoft-standard-WSL2` under WSL2 (Ubuntu); Docker
Desktop containers for arm3 (docker-seccomp T1) and the capability-posture cell; the 2026-09-11 sandbox
acceptance run under the diagnostic seccomp policy (the production allow-set is P2b's and is `[S]`). Run
dates from the reports: arm3 2026-07-02, added cells 2026-07-03 · dprime-build 2026-08-15/16 ·
capability-posture 2026-08-18 · rendezvous 2026-09-01 · sandbox acceptance 2026-09-11 · foreign-uid attach
probe 2026-10-14 (WSL2 arm; native-Linux VM arm pending) · getresuid re-read regression 2026-10-18 (diagnostic policy) ·
engine prototype runs 2026-10-18/19 (ExperimentLab/engine/runs: integration and root unit runs, sandbox regression
under the diagnostic policy, transport fuzz, AA-13; the engine's validation record names each).

**Frozen design revision.** The second freeze of 2026-10-18 (PLAN §Frozen design revision; VERSIONS): conn,
rr, si and optb at their post-revision blobs, the other six files unchanged, kernel-uid-binding.md at the 2026-10-18
evidence-only blob; the third freeze of the same day (agent-facing grant_ref removed) changes no line count. Spine: 01 v11 · 02 v10 (v11 path only; v12 wording, R-G2-11's re-judgement) · 03 v5 · 04 v12 (v13 path only) (01 v11 models the fifth design revision of 2026-10-19, the supervisor's domain-empty method; 02 v10 rewords the three slot cells; 04 v7–v9 append the engine-build evidence, v9 the removal of the C-side body parse at engine commit 7b4ab727, v10 the fifth revision's evidence, v11 the engine fixes of 9981dd7b, v12 the extra evidence of 2026-10-21). Files whose reasoning uses no content-changed ID keep
the 2026-10-12 freeze and their header ids. Step 4 (2026-10-19) changed no design file and no model file of the
spine; it appended engine-build evidence (04 v7, v8) and re-ran the 30 route files that were conditional or open.

## Table

Five columns, extracted mechanically from each route file's front matter (`violates:`, `stops:`,
`disposition:`) and section 1 by `reconcile-checks.py --table-out`; nothing in it is hand-written. A reader
opens the route file named in column 1 to reconstruct the row from one file.

| route | adversary action (route file §1) | condition violated | what stops it | disposition |
|---|---|---|---|---|
| R-G1-01 | A sends opening bytes which lack a valid stamp because credential passing was not established at production, and those bytes reach a labelled acceptance. | C-02; C-03/C-04 if admitted | SO_PASSCRED is set on the engine end at T-04, before any task of P_X exists, and the engine verifies at T-09 that the delivered fd carries SO_PASSCRED = 1 — so the kernel stamps every skb that is ever queued on this engine end, and an fd without the option is never installed as a channel. | supported under stated premises |
| R-G1-02 | A's rendered uid is compared to a stored expectation not equal to that allocation uid's receiver-domain representation, allowing a distinct principal to match. | C-03 | expected_uid is written once at T-01 from the lease's pool uid, is never overwritten, and is compared in the engine's initial user namespace (C3), so e_r = u_r = r(u_r). | supported under stated premises |
| R-G1-03 | A's correctly stamped frame is installed/read through a row or endpoint whose initial lease/execution correspondence is wrong. | C-05 | The row, its lease and its channel are one object graph created at T-01 and bound at T-09 by matching the prepared record's execution_id and lease_id to the original row in one decision, by object and never by number. | supported under stated premises |
| R-G1-05 | A and B simultaneously receive the same uid from distinct allocations made by one engine process in one epoch, and A's bytes are accepted as B. | C-06 | T-01 refuses a reservation while the workspace uid's lease is held or quarantined — one lease, one holder; one workspace, one uid, one execution — and T-03 refuses a spawn whose uid or lease is in a live SpawnRecord. | supported under stated premises |
| R-G1-06 | This engine's spawner launches A's clone with another row's allocation uid against A's own record, and A's bytes reach that row's endpoint and are accepted under its label. | C-05; C-06 as affected | The spawner's per-fragment SEALED check at T-08 — the kernel-stamped uid of the bootstrap's bytes must equal the record's uid and the pid the record's child_pid — fails the record before COMMIT, so a clone launched at another row's uid never reaches execve. | supported under stated premises |
| R-G2-01 | A feeds a read path without a current normal-stream credential witness and it produces a sender label anyway. | C-01 | T-21's single recvmsg read path and T-24's constructor, which labels only bytes that passed T-23 | supported under stated premises |
| R-G2-02 | A contributes unchecked header/body or OOB bytes to a frame accepted using the checked remainder's identity. | C-01/C-04 | T-23's comparison of every positive-length return, the four header bytes included, and T-21's close on any OOB/POLLPRI byte | supported under stated premises |
| R-G2-03 | A causes missing/truncated or mismatched current ancillary to be paired with bytes and interpreted as a usable sender. | C-01/C-03 | T-22's rejection of truncated, missing, duplicate or mis-sized ancillary over a fresh control buffer per read, with SO_PASSCRED armed at T-04 before any sender exists | supported under stated premises |
| R-G2-04 | A's current-frame bytes are mixed with another channel/frame's checked buffer and inherit its label. | C-01/C-05 | one FrameReader per Channel, emptied per frame, with the label read through that Channel's own objects | supported under stated premises |
| R-G2-05 | A labelled acceptance violates stamp population/equality through an as-yet unrefined cause outside the identified production/selected-slot/privilege cases. | C-02 | the per-skb stamp at the only two enqueue sites of a connected stream socketpair — unix_stream_sendmsg and queue_oob, each after maybe_add_creds — with step 11's initial-namespace capability posture gating the one credential-less delivery path, the BPF sockmap ingress list | supported under stated premises |
| R-G2-06 | A's ancillary is present but ABI conversion, stale decoded storage or a substituted pid lookup turns it into another principal. | C-03 | T-23's decode with the ABI types from the current read's control buffer, the pid diagnostic only, and no identity lookup | supported under stated premises |
| R-G2-07 | A appends another sender's bytes after a first credential check and a cached frame credential admits them. | C-04 | The per-fragment comparison: every positive-length return is compared to expected_uid, and no first-fragment credential is cached for later fragments | supported under stated premises |
| R-G2-08 | A's observed uid or identity field chooses/rewrites the expected row instead of being compared to the original expectation. | C-04/C-05 | The immutable expected_uid is compared against and never written from an observation; no row is selected by the observed uid or by a payload identity field | supported under stated premises |
| R-G2-09 | A writes through a held foreign endpoint and a snapshot, payload/pid identity or incorrect equality decision admits it as the endpoint's execution. | C-04 | T-23's per-fragment comparison of the kernel stamp against the endpoint row's expected_uid — no connect-time snapshot, no payload or pid identity | supported under stated premises |
| R-G2-10 | A's checked frame receives context fields naming a different execution than the row used for comparison. | C-05 | VerifiedContext is built only by receive_step from the Channel's own Session and Execution objects — the same objects the comparand was read through | supported under stated premises |
| R-G2-11 | An adversarially triggered accepted byte-origin/witness association fails C-01 outside the identified insertion/read/buffer cases; its concrete cause remains unresolved. | C-01 | Bytes reach the comparison only through the one FrameReader path of the Channel that owns it and the C reader on that path calls no third-party parser, established by code reading and static tests; the remaining branch — a memory error of the project's C code on that path (transport.c, support.c) — is stopped only if that code is memory-safe, a stated requirement (engine-requirements row 175) whose proof this route does not have: it is assigned to prove 2.2, and the one-hour ASan/UBSan fuzz run that found no error is supplementary evidence for it within the limits section 5 states, with the body parse resting on the CPython runtime as a platform premise. | conditional on unbuilt requirements |
| R-G2-12 | An accepted observation violates translation/decoding fidelity outside the identified alias/ancillary/ABI cases; its concrete cause remains unresolved. | C-03 | The engine runs under the identity map, checked at every start by the product entry's self-check, which refuses service otherwise, and this is the closing property of R-G2-12 in PLAN §Follow-up plan after U, established on the development host by the integration run's positive and refusal cases and a code reading of the check. | supported under stated premises |
| R-G2-13 | A labelled acceptance lacks the required current comparison through an unrefined decision path outside the named cache/fallback cases. | C-04 | One comparison point lies on the only path from recvmsg to the buffer and every phase passes through it, which is the closing property of R-G2-13 in PLAN §Follow-up plan after U, established by a structural reading of the C reader and of receive_step, with root unit tests across STARTING, ACTIVE and DRAINING and a pre-read test for a CLOSED session, within the limits section 5 states. | supported under stated premises |
| R-G3-01 | A's protocol data reaches an internal constructor which fabricates a validated sender without an originating frame. | C-01/C-05 | one VerifiedContext constructor, at the receive entry; every consumer takes the label by object reference and constructs none, and no retry or replay path re-creates a request — realized in the prototype engine and checked by test and code reading up to the stub handlers | supported under stated premises |
| R-G3-02 | A's correctly attributed request/cancel/task result is joined by request id or task/grant reference to B's context during admission/dispatch. | C-08 | admission, cancel, task_result and dispatch resolve only inside the original Session's objects: request and call keys carry session_id and direction, the TaskBinding and the Grant it names are the ones reachable from the original Session's current call, and no agent-facing message carries a grant selector — realized in the prototype engine and checked by test and code reading | supported under stated premises |
| R-G3-03 | A's correctly attributed work is recorded or sent onward with another execution label or local_agent_id despite retaining its original request reference. | C-08 | the label and the response destination travel by object reference from the original RequestEntry: the sink is fixed to that entry, verified_subject is copied only from its carried VerifiedContext, and the per-channel writer is owned by the original Channel — realized in the prototype engine and checked by test and code reading up to the stub handlers | supported under stated premises |
| R-G3-04 | A's rejected input or an originless/control callback gains a verified_subject at a consumer. | C-08 | verified_subject exists only as a copy of the VerifiedContext that the receive entry produced for a validated message; a receive_rejected event carries none and is never filled from the connection's expected subject, and lifecycle events carry control_binding, a different field — realized in the prototype's recorder and checked by test and code reading | supported under stated premises |
| R-G3-05 | An attributed consumer changes or loses the original context in a way not yet reduced to numeric reuse, current join or label-only mutation. | C-08 | every consumer step carries the verified context by object reference, with no construction and no lookup or state key by name, uid, fd or local_agent_id (conn E-02 L581–583) — established in the prototype by the R-G3-05 check of the validation record (test and code reading, up to the stub handlers) | supported under stated premises |
| R-G4-01 | A's old task survives a reported-empty/release cycle and speaks under a uid now assigned to B. | C-06 | T-45 releases the lease only after T-43's empty fact, whose pid1_reaped basis follows the kernel's namespace zap (T-41/T-42) and whose never_created basis follows the spawner's seal against clone; errors and timeouts quarantine (T-44) and never free — realized in the prototype engine and spawner and checked | supported under stated premises |
| R-G5-01 | A uses a software kernel defect to alter observations/protected state, or reads through it then takes an additional attribution-changing step. | C-01…C-08 as affected | declared exclusion: the kernel-breach paragraph of scope-and-boundary.md §Boundary Defence (N1, the software path) | declared out of scope |
| R-G5-02 | A uses cross-domain hardware memory access to alter observations/state, or uses a hardware read plus an attribution-changing step. | C-01…C-08 as affected | declared exclusion: the kernel-breach paragraph of scope-and-boundary.md §Boundary Defence (N9, the hardware path), with S14 its checkable deployment half | declared out of scope |
| R-G5-03 | A lawfully selects an effective/saved uid different from its real uid and an execution label relies on the unjustified single-uid interpretation. | C-02 | C1 — spawn step 11's setresuid with three equal values, re-read by getresuid before the seccomp install so that an unequal value fails the spawn with no SEALED, leaves the task's own set {u}, and the kernel's own-set rule admits no other explicit value (T-07 outcome; preservation row T-61) | supported under stated premises |
| R-G5-04 | A attaches another mapped kernel uid using relevant namespace privilege and it is accepted as another execution. | C-02 | first half of C2 — no CAP_SETUID in the initial user namespace (step 11's cleared bounding set and no_new_privs) — with the kernel's write-time map rule, under which a sender can name only its own kernel uid (T-07 outcome; preservation rows T-61, T-62) | supported under stated premises |
| R-G5-05 | Distinct senders render to a sentinel/overflow value in the receiving namespace and a labelled decision treats the alias as a principal. | C-03; C-04 if admitted | C3 — the engine in the initial user namespace (S13) keeps the rendering injective, and the engine refuses service unless its namespace has the single full identity map; if an alias still arrives, T-23's sentinel rejection, T-01's pool exclusion of sentinel values and D4 on the record paths keep it from being a comparand or a principal — realized in the prototype and checked | supported under stated premises |
| R-G5-06 | A nonmember host/other-compartment task already possesses an allocated uid, or a concurrently running engine's allocation assigns it, and bytes under it are accepted as that execution. | C-06 | the exclusive-pool premise as the design now writes it — the pool reserved on the host to the engine alone, at most one engine per range, a uid inventory naming every holder, the local model instance under no pool uid — under which no task outside the engine's own executions holds a pool uid, so the route's precondition does not arise (03 §3, IG-02; T-67 branch f is the departure) | supported under stated premises |
| R-G5-07 | A later obtains, or lawfully creates a task with, another allocation's real kernel uid and its genuine stamp passes as that execution. | C-06 | C1, checked by the getresuid re-read before the seccomp install, and the first half of C2 — three equal values at step 11, no CAP_SETUID in the initial user namespace — with the kernel's own-set and write-time map rules, so no task of P_X can come to hold another allocation's real kernel uid (preservation rows T-61, T-62) | supported under stated premises |
| R-G5-08 | A foreign task holds the row uid during its allocation by a cause not yet classified as a prior survivor, pre-existing holder or lawful later acquisition. | C-06 | the deployer's uid inventory of engine-requirements §8 for tasks outside the engine's own executions, and, for tasks inside them, the kernel's writers of a task's uid at the pinned tag — a real uid copied at fork, never written by execve, moved by the setuid family only within the own set unless a reachable user namespace maps another kernel uid, all q26 paths — so that with an intact kernel no history is left in this cell | supported under stated premises |
| R-GX-01 | A's old queued or buffered bytes are attributed through a new allocation even after every old task has died. | C-01/C-07 | A's queue dies with A's socket and A's buffer with A's Channel object: B reads only the fresh socketpair T-04 created for B's own record, installed as a new Channel at T-09, and nothing is read from A's row after CLOSED | supported under stated premises |
| R-GX-02 | A times failure, late prepared/empty or duplicate control events so the wrong original lease/session is installed or reactivated. | C-05; C-06/C-07 if reused | every control record is matched to the original row by engine_epoch, execution_id and lease_id and never by uid or fd — a late prepared on a CLOSED row has its fd shut and installs nothing, a consumed prepared arriving again has its fds shut and faults, a duplicate empty is ignored with no second release, and CLOSED is terminal | supported under stated premises |
| R-GX-03 | A sends to a stale endpoint or races numeric fd/generation reuse and its bytes/readiness callback is attached to a different row. | C-05/C-07 | no member of A is alive once A's lease is released and no CLOSED row is ever read, while the engine's reader and callbacks are bound to the Channel object and its generation — deregistered, then the fd shut and its close performed once at T-40 step 2 before the number can be reused — so neither a late send nor a stale readiness event reaches another row | supported under stated premises |
| R-GX-04 | A survives an old engine/spawner epoch while a replacement engine treats the same uid pool as empty and attributes its messages to new allocations. | C-06/C-07 | before a replacement engine in the same cell restarts its pool, the old cell's own cgroup is killed and must report populated 0 in cgroup.events — a kernel-held fact on which the trusted supervisor releases, keeping no safety-relevant state — under the deployment precondition that every member of the cell sits in that cgroup and no agent can leave it | supported under stated premises |
| R-GX-05 | A delays a worker/result until uid/fd/request-number or local_agent_id reuse and a consumer relooks it up under a new execution. | C-08 | a late worker fact or connector result is applied only to the RequestEntry it was issued for, reached by object reference — never found again by uid, fd number, request number or local_agent_id — and after the row is CLOSED or the uid released it is release-only, carrying the old session and epoch | supported under stated premises |
| R-GX-06 | A row/channel/allocation association is wrong for an unrefined reason outside installation, control correlation or numeric/object alias. | C-05 | the association is created at T-01, installed at T-09 and cleared at T-40 step 2 only, by object — realized in the engine prototype and established by the validation record's R-GX-06 check and its AA-13 check | supported under stated premises |

<!-- extracted 2026-10-16 by reconcile-checks.py --table-out; re-extracted after the R3 F-01 repair of seven stops fields (CR-R3-01); re-extracted 2026-10-16 after the R-G2-05 re-run (follow-up step 1 (a)), one row changed; re-extracted 2026-10-18 after the step-3 re-run on the second design freeze, six rows changed (R-G3-05, R-G5-03, R-G5-06, R-G5-07, R-G5-08, R-GX-06 by re-run; reconcile.md §5); re-extracted 2026-10-18 after the third freeze (grant_ref), the R-G3-02 stops field changed; re-extracted 2026-10-19 after the step-4 re-run on the engine build's checks, 29 rows changed (29 dispositions; stops of R-G2-11, R-G2-12, R-G2-13, R-G3-01…05, R-G4-01, R-G5-05, R-GX-06; reconcile.md §5); re-extracted 2026-10-19 after the S4 repair round (C-side body parse removed), the R-G2-11 stops field changed; re-extracted 2026-10-19 after the fifth design revision (supervisor's method, cgroup only), the R-GX-04 row changed; re-extracted 2026-10-23 after the M1 repair (R-G2-11 re-judged conditional on unbuilt requirements), the R-G2-11 stops and disposition changed -->

## Counts

supported under stated premises **35** · conditional on unbuilt requirements **1** · open **0** · declared out
of scope **2** (38 routes; before 2026-10-23 the counts were 36 · 0 · 0 · 2, R-G2-11 then counted supported on the
fuzz run).

The 35 supported rows, classed by the premises their route files name in section 5 (the kernel at the pinned tag,
the single executor, the honest spawner and the three-configuration abstraction are common to all and not repeated).
The classes sort rows by what their own stop rests on; no class is a count of rows free of assumptions — the shared
dependence on the engine's code running as written is stated after the table:

| premise class | rows | what the class means |
|---|---|---|
| kernel semantics and the checked prototype, no deployment premise | 22 — R-G1-03, R-G1-06, R-G2-01, R-G2-02, R-G2-03, R-G2-04, R-G2-05, R-G2-07, R-G2-08, R-G2-10, R-G2-13, R-G3-01, R-G3-02, R-G3-03, R-G3-04, R-G3-05, R-G5-03, R-GX-01, R-GX-02, R-GX-03, R-GX-05, R-GX-06 | the stop is design text realized in the prototype and checked, or a kernel reading at the pinned tag. The consumer-side rows and R-G3-01 hold up to the stub handlers and are re-checked for each real connector; R-G2-05, R-G2-07 and R-GX-02 take C1, C2 and the pool premise as stated pre-state conditions whose departures are other routes' cells (R-G5-03, R-G5-04, R-G5-06, R-G5-07), not as premises of their own stop; R-G2-13 (and R-GX-06, R-G2-01) name the memory safety of the C reader as a premise owned by R-G2-11 (Preface) |
| a deployment precondition the engine cannot check (engine-requirements §8) | 12 — R-G1-01, R-G1-02, R-G1-05, R-G2-06, R-G2-09, R-G2-12, R-G4-01, R-G5-04, R-G5-05, R-G5-06, R-G5-07, R-G5-08 | the engine in the initial user namespace (C3 / S13: R-G1-01, R-G1-02, R-G2-06, R-G2-09, R-G2-12, R-G5-04, R-G5-05); the exclusive uid pool, the deployer's one-to-one directory and uid inventory (R-G1-05, R-G4-01, R-G5-06, R-G5-07, R-G5-08); the spawner's CAP_KILL (R-G4-01); no privileged actor writing a map or a uid for the agent's namespace (R-G5-04, R-G5-07, R-G5-08). Two kinds of row: for R-G5-06, and for the outside-engine half of R-G5-08, the stop *is* the deployment precondition (nothing in the engine stops the history; the premise makes it not arise — R-G5-08's inside-engine half is a kernel-source reading of every writer of a task's uid), for the other ten the stop is realized in the prototype and additionally needs the precondition. Each precondition is the deployer's evidence; the development host realizes none of them as a deployment |
| a deployment mechanism not yet built, listed as a precondition since the fifth design revision | 1 — R-GX-04 | the cell's own cgroup under host init and a releaser that acts only on `populated 0` (engine-requirements row 218); the kernel fact was measured once on the development host, the mechanism exists on no host |

Every engine-side row also assumes that the engine's code runs as written. Two things are bundled in that: AA-04,
that the engine and spawner are honest and run the code that was read — a TCB premise, proved by no unit; and the
memory safety of the C reader on the receive path — carried once, by R-G2-11 as the one conditional row (Preface),
with its proof assigned to prove 2.2.

Preservation: 50 of 52 owned transitions preserve I; T-66 and T-67 do not, by
construction (boundary disturbance; premise departure); the preservation files were not re-run at step 4
(no design change). Obligations for the engine: the 75 of [obligations-for-engine](original/uid-binding/work/convergence/obligations-for-engine.md)
(2026-10-15) were superseded as the requirement list by engine-requirements.md (97 musts),
whose realization is recorded must by must in the engine's validation record.

## Residual line

Obligations #5 (delegation leakage — grant model, WPE-F08) and #6 (full reference-monitor correctness) remain
overall residual status lines. This table establishes neither. For #6 it establishes the local-binding part:
each of the 38 routes has a disposition under named premises and an evidence limit; of the 35 supported, the
engine-side items of 34 are realized in the prototype and checked (the 35th, R-GX-04, rests on a kernel-held fact
and deployment preconditions); the one conditional route, R-G2-11, waits on the memory safety of the C frame
reader (prove 2.2); the prototype's checks cover the attribution-relevant musts, not the whole reference monitor.
What remains: the memory safety of the project's C code on the receive path (engine-requirements row 175;
R-G2-11, conditional; its proof assigned to prove 2.2), the deployment preconditions the engine cannot check
(engine-requirements §8: the exclusive uid pool, the engine in the initial user namespace (C3 / S13), the
deployment halves of C1 and C2 that the engine's own checks do not reach, the deployment rows of S1–S14, and —
named by R-G5-04 and R-G5-07, outside S1–S14 — no privileged map writer or other privileged actor acting for
the agent's namespace), the CPython runtime under the engine's strict json parse (R-G2-11), the
production seccomp allow-set (P2b), the cell's own cgroup under host init with the release gate on `populated 0` (R-GX-04,
engine-requirements row 218), each real connector's re-check of the
consumer chain (R-G3-05), and the prototype's realization limits that the route files state.

## Disposition and coverage statement

Under the 02 decomposition of the property's negation into eight sufficient conditions, every admitted
adversary action that could produce a false attribution is assigned by that decomposition to one of the 38
ledger routes, seven of which are remainder slots (the coverage warrant, 02 §4.3, is a check, not a proof
that nothing is left out). By the part of the property they concern (Preface): 31 routes and the two boundary
rows concern the label at accept (P_acc), and five — R-G3-02, R-G3-03, R-G3-04, R-G3-05 and R-GX-05 — concern the
label the consumers carry (P_carry, C-08), where the stop is the object-reference discipline checked up to the stub
handlers. Thirty-five routes are supported under stated premises. Six were so before step 4:
three on C1 and the first half of C2 — three equal uids at spawn step 11, re-read by `getresuid` before the
seccomp install, and no `CAP_SETUID` in the initial user namespace — with the kernel map rule (R-G5-03,
R-G5-04, R-G5-07); the C-02 remainder slot R-G2-05 on the pinned-tag reading that every skb on the channel's
queue is stamped by the peer's send, with step 11's initial-namespace capability posture gating the one
credential-less delivery path (within the reading's stated bounds); and the two pool routes R-G5-06 and
R-G5-08 on the exclusive-pool deployment preconditions (engine-requirements §8), premises the engine does not
check. Twenty-eight moved at step 4 (2026-10-19) and stand, when every necessary item of their defence was
realized in the engine prototype and checked — by recorded tests and code reading of the project's engine code —
under the premises and limits each route file states. Among them are the remainder slots R-G2-12 and R-G2-13,
each on its closing property (PLAN §Follow-up plan after U), R-G2-12 and R-G5-05 with the initial user namespace
as a deployment premise; and R-G3-05 and R-GX-06 on theirs, R-G3-05 up to the stub handlers. The thirty-fifth,
R-GX-04, moved with the fifth design revision (2026-10-19, user ruling): the old cell is shown empty at a new
epoch by a kernel-held fact — its own cgroup, killed, reports `populated 0` — on which a stateless releaser acts;
the cell's cgroup and the gate are deployment preconditions and the kernel behaviour was measured once on the
development host. One route is conditional on an unbuilt requirement: the third remainder slot, R-G2-11, moved
at step 4 as well and was re-judged on 2026-10-23 (M1 item 1). The path half of its closing property is
established by code reading and static tests, after the engine stopped parsing the body in the C reader (commit
7b4ab727, S4 F-01); its memory half — the memory safety of the project's C code on the receive path — is a stated
requirement (engine-requirements row 175) whose proof is prove 2.2's, the one-hour ASan/UBSan fuzz run being
supplementary evidence; the CPython runtime under the strict json parse is its platform premise. Two are
declared out of scope by the kernel-breach paragraph (N1 software, N9 hardware; S14 is N9's checkable half). No
row is measured end to end: each rests on a composition of design text, kernel semantics and isolated checks.
What the result is: relative to the listed model and predicates — the 01 version-11 inventory, the 02 version-10
ledger (version 12 wording) and the 03 version-5 invariant — the classification of bad histories has total
coverage, every history that violates P_acc or C-08 reaching exactly one route (02 §4.3), with the uncertainties
listed. It is a statement about the classification, not that the 38 mechanisms are all the mechanisms there are;
the phrase *complete relative to M* (PLAN rule 5) names this and nothing more, and the two stronger coverage
terms of PLAN Context (2) are not used.
