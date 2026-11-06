---
route_id: R-GX-05
group: GX
owner: GX stream subagent (Claude Fable 5.1, cold context), dispatched by the main session on 2026-10-15; re-run 2026-10-19 for follow-up step 4 (Claude Opus 5.5, cold context); wording compacted 2026-10-21 (shared evidence boundary cited; no content change)
status: ready-for-reconcile
date: 2026-10-19
violates: C-08
stops: "a late worker fact or connector result is applied only to the RequestEntry it was issued for, reached by object reference — never found again by uid, fd number, request number or local_agent_id — and after the row is CLOSED or the uid released it is release-only, carrying the old session and epoch"
disposition: supported under stated premises
based_on:
  model_blob: "d27d65d7874bbf6c"
  decomposition_blob: "5d2a0b9438f37302"
  invariant_blob: "ae58d7db31c95c82"
  registry_blob: "97b869a738a79b0e"
---

# R-GX-05 — A delays a worker/result until uid/fd/request-number or local_agent_id reuse and a consumer relooks it up under a new execution.

## 1 What the adversary does
A delays a worker/result until uid/fd/request-number or local_agent_id reuse and a consumer relooks it up under a new execution.

## 2 How it would produce false attribution
- **Preconditions:** A's request is correctly attributed (label A, P_acc holds) and dispatched (T-33): a
  connector transfer or document read is in flight (T-34), or a prepare worker (T-32) has not returned. A
  makes the result or the request's end late: it stalls its reads, withholds task_result, or exits right
  after sending (T-65), so that A's row closes (T-40 step 3 issues cancel and release without waiting for
  workers), the empty fact and release follow (T-43, T-45), and the same workspace is re-launched as B
  (T-01) with the same u, the same recurring local_agent_id (conn L79), request ids restarting at 1 in
  B's session (conn L478–479), and possibly A's old fd number (T-09). Then the delayed fact arrives: a
  late callback (T-51), the late-result event (si L72), the worker's released notice (T-35), or nothing
  within 5,000 ms (T-50). A consumer that found its target again — the RequestEntry by uid, fd number or
  request number, or the Execution by local_agent_id — would attach A's result, terminal, record or
  returned slot to B's context. The adversary's inputs are protocol content and timing (A-02, A-06); a
  connector's delay is not under A's control beyond what its request asks, and the model's capability is
  not an input (AA-12). Configuration: all three — the connector leg differs (X-04) but the callback
  boundary into the executor is the same in C-LS, C-LP and C-R.
- **Transitions traversed:** T-20 → T-21 … T-24 (label A) → T-25 → T-30 → T-32 → T-33 → T-34 (in flight)
  → T-40 (A's close, step 3) → T-43 → T-45 → T-01 … T-12 for B (G1 facts) → T-51, T-35, T-38 or T-50 for
  A's late fact.
- **Sufficient condition violated:** C-08 p81 (D_81) with selector q30 — the consumer relooks up an old
  callback by numeric uid, fd or request number, or by a recurring local_agent_id, after retirement or
  reuse; B(R-GX-05) = ¬H ∧ D_81 ∧ q30. Consumer-only: every D-ACC keeps P_acc; the carry fails — B's
  verified_subject on A's work, A's connector evidence credited to B's request, A's slot returned to B's
  TaskCall, a late terminal written into B's entry. P_carry of 02 §3 fails at that consumer; no inbound
  byte is mislabelled.

## 3 What stops it
A late worker fact or connector result is applied only to the RequestEntry it was issued for, reached by
object reference — never found again by uid, fd number, request number or local_agent_id — and after the
row is CLOSED or the uid released it is release-only, carrying the old session and epoch.

- **By reference, at every consumer.** The response callback holds the original RequestEntry and Channel and
  is not re-addressed even if the same fd number or request id appears later (conn L523); the sink
  delivers only to the original RequestEntry and cannot name a session, fd or seq (conn L641); router and
  connector results must carry the original object (conn L84); request_key = (session_id, direction, id),
  so a request number alone is no key, and session_id derives from a never-reused execution_id (conn L73,
  L84); E-03-R1 and E-03-R2: responses keep their original execution, session and request and are never
  found by an agent-chosen id, and an old execution's results do not enter a new execution (conn L558–559).
  G3 preservation, rows T-32, T-34, T-35, T-38 (facts return holding the object; the executor applies them
  to that object).
- **After close and release.** A late event is release-only or the late-result event of the original
  request, never a second terminal (conn L621–625; si L72; G3 row T-34); after a uid is released the old
  RequestEntry and its callbacks keep their old session, epoch and close gate, and no table is consulted by
  uid (conn L835–837; G4 preservation, row T-45); T-51 performs release only — no lookup by uid, fd or
  request id, no dispatch, no label (G4 row T-51); cleanup_stalled retains the slot and references rather
  than freeing (conn L875–879; G4 row T-50); an old callback obtains no new workspace lease and is not
  re-addressed by uid (rr L528–529); T-40 step 3 commits the session-close terminal value of E-03 into the
  original entry and issues cancel and release there (G4 row T-40).
- **The recurring name.** A new execution under a recurring local_agent_id inherits nothing (conn L79;
  E-01-R1, conn L343); verified_subject and the event correlation keys are value copies of the carried
  VerifiedContext and of the original objects' ids (si L90, L93); the design states that every consumer
  step reaches the VerifiedContext by object reference and neither looks it up nor keys state by name,
  uid, fd or local_agent_id, and keys provider selection by execution_id (01 v9 MM-16 resolved; conn
  L581–583; rr L386–387).
- **Slots.** T-35 returns the request slot of the original entry (conn L718); the execution slot is a
  separate gate (conn L166–169; MM-12), and B's T-01 creates new objects without reading A's slot (G1
  preservation, row T-01: MM-12, now stated design text, agrees with T-01's reads; conn L101–102).

A task_result or request citing a previous call's id is refused at T-30 and T-36 (conn L699–700) — same
execution, not this route. The by-reference statements are the same text R-G3-02 and R-G3-03 argue for the
current-association and label-only cases; this route adds the retirement-and-reuse leg from G4 rows T-40,
T-45, T-50, T-51 and G1 row T-01. Preservation rows relied on: G3 T-32, T-34, T-35, T-38; G4 T-40, T-45,
T-50, T-51; G1 T-01. The engine prototype realizes each rule for its consumers — the request manager, the
stub handlers behind the Sink, and the record path; section 4 maps them to code readings and tests.

## 4 Support
| evidence id | tag | what it shows | file and section | date / substrate / version |
|---|---|---|---|---|
| EV-124 | [S] | the response callback holds the original RequestEntry and Channel and is never re-addressed when the same fd number or request id appears later; the sink delivers only to the original entry; results carry the original object | conn E-01 (L84); E-02 (L523); E-03 (L641); rr E-07 (L339–340) | design text; realized by EV-198, EV-197, EV-190 |
| EV-198 | [R] | admission starts from context.session_ref and context.channel_ref and builds a RequestEntry holding message, subject, Session, Channel, Execution, TaskCall, TaskBinding and GrantState; the Sink holds only its entry and manager (__slots__); handlers start only an AuthorizedOperation | eng requests.py:81–99, :144–182; handlers.py:147–150 (val rows 226, 227, 234) | commit 3ec67985; code reading |
| EV-197 | [M] | with the row for the execution_id replaced by a decoy before the request frame was sent, admission, prepare, final decision, dispatch, result driving and release ran on the original objects; each of four stages changed to look the row up by execution_id hit the decoy and failed | int (unit suite) (val §consumer 按引用携带; row 226) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; up to the stub handler; the decoy replaces only the execution_id key |
| EV-117 | [S] | E-03-R1 / R2: responses keep their original execution, session and request, the receiver is never found by an agent-chosen request id, and an old execution's results do not enter a new execution | conn E-03 requirements (L558–559) | design text; realized by EV-198, EV-197, EV-223 |
| EV-137 | [S] | late events are release-only or the late-result event of the original request; after a uid is released old entries keep their session, epoch and close gate and no table is consulted by uid; cleanup_stalled retains the slot and references | conn E-03 (L621–625); E-04 (L835–837, L875–879); si E-09 (L72) | design text; realized by EV-223, EV-196 |
| EV-223 | [M] | a stale Sink after close reaches nothing new; a late completion does not rewrite the terminal; a late reply after resolution does not overwrite; cleanup_stalled holds the slot and closes admission | int (unit suite) (val rows 207, 208) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-196 | [R] | local_agent_id is only copied into Session, Execution, the VerifiedContext and records, with no table keyed by it; the only uid-keyed table is the allocator's holders (reservation and release); the only fd-keyed table is the loop's handlers, checked by identity before dispatch | eng lifecycle.py:100, :140, :150–157, :500–501; receive.py:297; records.py:74; loop.py:50, :112, :122 (val §consumer 按引用携带 limits; row 142) | commit 3ec67985; code reading |
| EV-115 | [S] | request_key and call_key carry session_id and direction; active ids are per-direction counters whose namespace is session + direction | conn E-01 objects (L82–84); E-02 messages (L478–479) | design text; realized by EV-229, EV-228 |
| EV-229 | [R] | a request key is session_id, direction letter a and the request id, a call key session_id, letter e and the call id; correlation fields are copied from the entry's own objects; reply_to is resolved only in the original session's tables | eng requests.py:120–132, :156, :526–534; tasks.py:112–114, :358–365 (val rows 236, 240) | commit 3ec67985; code reading |
| EV-228 | [M] | agent cancel of in-flight and unknown ids, a stale task_result reply dropped and a future one closing, and an old or repeated request id closing passed; integration task-protocol and task-read cases | int (unit suite; cases task-protocol, task-read) (val rows 236, 244) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy for the integration cases; two sessions ACTIVE at once by code reading only (val row 236) |
| EV-122 | [S] | event correlation fields are value copies of original object ids; the post_read flow's destination is the original request's execution_id; asynchronous workers cannot choose a session or write the log | si E-09 schema (L90); emission (L111–112, L120) | design text; realized by EV-229, EV-230, EV-231 |
| EV-230 | [M] | a document read ran through request_received, authorization_decided and dispatch_started to success with three post-read records; the full-path unit test passed | int pool70000.json, cases task-read (test and production build); unit suite (val rows 231, 241) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2; diagnostic policy; document handler and model connector are stubs |
| EV-231 | [R] | handlers deliver results by posting a callback to the state executor's loop; the record log thread writes only its own queue to its own descriptor | eng handlers.py:33–43; records.py:254–283 (val row 246) | commit 3ec67985; code reading |
| EV-141 | [S] | an old request callback obtains no new workspace lease and is not re-addressed by uid; a new execution under a recurring local_agent_id inherits nothing | rr E-08 (L528–529); conn E-01 (L79, L343) | design text; realized by EV-195, EV-196, EV-190 |
| EV-195 | [M] | with the old row's uid and workspace returned but its slot still held, a new execution on the same workspace and uid started with new lease, Session, runtime-copy view and workspace-lease objects and a larger workspace generation; the old row's runtime status released only the old slot | int (unit suite) (val row 142) | 2026-10-19; WSL2 6.6.87.2-microsoft-standard-WSL2 |
| EV-190 | [M] | with a new row on the same uid and fd number, the old row's callbacks, deadlines and late facts did not reach the new row | int (unit suite) (val rows 141, 147, 148, 161) | 2026-10-19; fd reuse made by the test |
| EV-241 | [R] | CandidateOperation holds its RequestEntry with operation_id = session_id + :r: + request id; AuthorizedOperation is built only by authorize(), called once in the final decision, then passed only to handlers.start | eng operations.py:156–235; requests.py:273–290 (val rows 226, 231) | commit 3ec67985; code reading |
| EV-16 | [S] | the reclamation gate; a uid is reclaimable only when the membership set is empty and no row is live | kub §2.6 | design text; realized by EV-205, EV-203 |
| EV-205 | [R] | membership_empty only from the spawner's empty fact or the local withdrawal; the uid lease released only when CLOSED, empty, close step 2 run and HELD, once | eng lifecycle.py:328–349, :443–449, :491–502 (val rows 204–206) | commit 3ec67985; code reading |
| EV-203 | [M] | unit tests of the empty wait, quarantine, the normal round trip and duplicate terminals passed | int (unit suite) (val rows 205, 206) | 2026-10-19 |
| EV-78 | [S] | dispatch and the VerifiedContext hand-over were stated E-02/E-03 integration obligations, unbuilt at the P2a run | implementation-validation.md SC-frames limit column; §尚未由本次证明 | 2026-09-11; realized by EV-172, EV-183, EV-197 |
| EV-183 | [M] | VerifiedContext has one constructor; every verified-kind record's subject is a copy of it, every other kind carries none | int (unit suite) (val rows 172, 173) | 2026-10-19 |
| EV-96 | [S] | the execution/session associations live in engine userspace, not in the fd table | desc9 §9.2 | design text; realized by EV-186, EV-194, EV-196 |
| EV-44 | [R] | the send→act window is named: the label is fixed at send, the principal need not exist when the engine acts | kub §8 | read 2026-10-14 |
| EV-94 | [R] | fd numbers are table-local; an identifier creates no reference | desc9 §9.1 | pinned commit 427645e3db3a |
| EV-47 | [M] | the lab engine authorized A's request on A's channel as agent-A and B's on B's as agent-B — row-keyed, in a different engine | REPORT-binding-arm3-workload-per-engine.md §Per-cell detail | 2026-07-02; docker-seccomp T1; staged |
| EV-51 | [M] | two same-uid executions on two channels got distinct identities in the lab engine | REPORT-binding-arm3-workload-per-engine.md §Added cells | 2026-07-03; as EV-47 |
| EV-50 | [M] | a same-uid holder inside one execution is the same subject (W2.1) — bounds what any consumer key separates | REPORT-binding-arm3-workload-per-engine.md §m4 | 2026-07-02; as EV-47 |
| EV-15 | [R] | the lab engine read the correct uid for both agents on every message (d7) | kub §2.5 | source reading of kub |

**Composition:** a conjunction of by-reference rules at T-34, T-35 and T-38 with the release-only rule at
T-51 and T-50, every necessary item now backed by `[R]` or `[M]`. By reference at every consumer (EV-124,
EV-117 `[S]`): EV-198, EV-241 `[R]` and the decoy test EV-197 `[M]`, with EV-190 `[M]` for uid and fd reuse.
Release-only after close or release and no table by uid (EV-137 `[S]`): EV-223 `[M]`, EV-196 `[R]`, with
the gate EV-205 `[R]` and EV-203 `[M]` (EV-16 `[S]`). Keys carrying session and direction (EV-115 `[S]`):
EV-229 `[R]`, EV-228 `[M]`. Value copies and worker posting (EV-122 `[S]`): EV-229, EV-231 `[R]`, EV-230
and EV-183 `[M]`. The recurring name and new objects per execution (EV-141 `[S]`): EV-196 `[R]` (no table
keyed by local_agent_id), EV-195 `[M]`. The arm3 items are of the lab binding engine and measure nothing
about these paths. No recorded run exercised the composed history of 04 §5 item 28 — a slow connector, A's
release, B on the same uid with the same local_agent_id and request id 1, then A's late result — so the
defence is not measured end to end; the late-result unit tests (EV-223) and the decoy test (EV-197) each
check one part, up to the stub handlers.

**Proposed evidence (not yet in the registry):** none new; 04 §5 item 28 stays "in part" (EV-223).

## 5 Disposition
**supported under stated premises** — the same value as the `disposition:` field. Every necessary item of
section 4's composition is backed by a code reading or a run of the prototype.
- Premises that must hold: the consumers are the build's — the request manager, the handlers behind the
  Sink (stubs here) and the record path; a consumer added later (a real connector, the MCP compartment,
  engine-forwarded inter-agent messages) is outside this disposition until it is re-checked for keying by
  object (BUILD-PLAN asks for a re-check for each real connector; U-06); workers return facts that hold the
  object and never write Session or RequestEntry, the single executor being their only writer (AA-01;
  EV-231); provider selection is not keyed per execution in the build (val row 243, by construction); the
  three configurations share the callback boundary (AA-06; X-04). This rests on the frozen design and the
  prototype's checked realization; it is not a claim about a deployed system.
- Evidence limit (configuration, substrate, run dates): runs of 2026-10-19. Check limits as validation.md states them: checked up to
  the stub handler; the decoy replaces only the execution_id key (EV-197); the case of two sessions ACTIVE at
  once needs two sender uids and rests on code reading only (val row 236); fd reuse in EV-190 is made by the
  test. The lab engine items are of 2026-07-02/03 on a staged docker substrate; the bounded TLC check does not
  model consumers (03 §5.1).
  Shared limits: [coverage-uncertainties § Shared evidence boundary](../../convergence/coverage-uncertainties.md#shared-evidence-boundary-every-route-not-repeated-below).

## 6 What remains
- Residual and open questions: the pending consumers (a real connector, the MCP compartment,
  engine-forwarded inter-agent messages at mech L316) must each key by object, not by name (U-06), and be
  re-checked when built; the composed run (04 §5 item 28) is not done. 02 v4's q32 (CR-F-03) concerns cell
  D_81's q32 branch and moves no q30 history. The IG-10 split of 03 v4 has no bearing. A request's deadline
  is bounded by its TaskCall's (conn L704) and T-34 re-checks it before applying each callback (conn L621)
  — an availability fact this route does not rely on.
- Design obligations surfaced for the engine (one sentence each; each is realized at commit 3ec67985 and
  must be kept by any later build):
  - T-51 / T-34: apply a late fact only to the object it holds; after the row is CLOSED or the uid
    released, release-only (EV-198, EV-223).
  - T-38: populate verified_subject, local_agent_id and the correlation keys only from the carried
    VerifiedContext and the original objects (EV-183, EV-229).
  - T-35: return only the original entry's request slot; never return a slot to another TaskCall (val
    row 235; EV-195).
  - T-01: local_agent_id is written once and no consumer keys state by it (EV-196).
  - T-50: retain the stalled entry and its references; never free or re-address them (EV-223).
- Cross-references: R-G3-02 (a current association joins another session), R-G3-03 (reference kept, label
  changed), R-G3-05 (the remainder of cell D_81), R-G3-04 (an originless subject), R-GX-03 (an fd alias on
  the receive side), R-G2-10 (the constructor's source), R-G4-01. Obligations: #6 (reference-monitor
  correctness — session-table lifecycle) is instantiated; #4 is touched; #5 (no delegation leakage) is
  adjacent through the forwarding consumer. Conditions C1–C4: none.
