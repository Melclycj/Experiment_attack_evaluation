---
group: G2
owner: Stream G2 re-run owner (cold-context Claude Fable 5.1), dispatched by the main session 2026-10-16
status: ready-for-reconcile
based_on:
  model_blob: "9efb243354a4e9d6"
  decomposition_blob: "31ddfc5daba58f13"
  invariant_blob: "6868389a2182c161"
  registry_blob: "52e0625ffeebf23a"
---

# change requests from the G2 receive-and-check stream (R-G2-05 re-run, 2026-10-16)

Requests for changes to shared files, for the reconcile role to merge into the convergence folder's
change-requests.md. This stream edits no spine file and no template. Both requests arise from the re-run of
R-G2-05 against registry version 5 (EV-142 … EV-146); no other G2 file was changed, and no new ID is created
here — a selector or route ID, if one is wanted, is the spine owner's to assign.

| id | file and ID | requested change | why |
|---|---|---|---|
| CR-G2-01 | 02-conditions-and-decomposition.md: §5.2 U-01 and U-02 (text); §6 ledger row R-G2-05, sixth column (text, now "unresolved mechanism, not a demonstrated path"); no ID changes | Record what the 2026-10-16 kernel reading narrows. U-01's sentence "An intact-kernel foreign-real-uid result outside the explicit-slot/capability/mapping cases is not established; R-G2-05 is a named source/model gap" should cite EV-142 … EV-146 and state the result: at the pin every skb on a connected stream socketpair's receive queue is enqueued at unix_stream_sendmsg or queue_oob after maybe_add_creds, so the credential-read branch D_22 ∧ ¬(q09 ∨ q10) holds no history within intact kernel semantics (its remainder is the kernel-defect exclusion, R-G5-01), and the producer branch D_21 ∧ ¬q08 reduces to the BPF sockmap ingress list — a credential-less delivery path behind CAP_NET_ADMIN in the initial user namespace and a descriptor to the engine's end (EV-145) — plus kernel defects; the reading's two stated bounds (out-of-family queue writers sorted by directory; the remaining sockfd_lookup callers sorted by protocol, neither read line by line) travel with the statement. U-02's count of seven slots is unchanged; its sentence may note that one slot now has a disposition other than open. The ledger row's sixth column may read "remainder argued from the pinned-tag queue reading (EV-142 … EV-146); kernel defects to R-G5-01". | 02 §4 says a remainder entry "must not gain a supported disposition simply because its predicates are total", and §5.2 U-01 names this slot as the open source/model gap. The re-run gives it *supported under stated premises* on a positive property of the producers (PLAN §Follow-up plan after U, closing property of R-G2-05), not on totality. If 02 keeps the gap wording, the spine and the route file disagree about whether the slot is open; the text change keeps them aligned without touching any predicate, selector or ID. |
| CR-G2-02 | 02-conditions-and-decomposition.md: §4 total branch assignment, D_21 row (selector list [q08 → R-G1-01, else → R-G2-05]); §6 ledger row R-G2-05, last column (principal transitions T-20/T-64) | Decide the landing of one configuration-departure history. If the agent holds CAP_NET_ADMIN in the initial user namespace (S4 / step 11's bounding-set clear absent — a T-67 departure) and a descriptor to the engine's end, it can place the engine's end in a SOCKMAP and deliver credential-less bytes to the engine's reader through the psock ingress list (EV-145). Such bytes are D_21 ∧ ¬q08 (SO_PASSCRED armed, no stamp), and D_21's selector list has no privilege branch, so the history stays in R-G2-05 — while every other privilege departure of C-02 is routed to G5 (D_22 ∧ q10 → R-G5-04). Either (a) D_21 gains a selector for "the credential-less delivery was enabled by a capability the agent holds in the initial user namespace or by a held descriptor to the engine's end (T-67)" routing it to a G5 route — the selector number and route ID are the spine owner's — or (b) 02 states that R-G2-05 keeps the departure and adds T-67 to the row's principal transitions, so the route file's section 6 (iv) is the agreed reading. | Under the stated premises the sockmap path is cut by the posture (R-G2-05 §3), but the departure case is cut only by the engine's missing-credential check at T-22 (C4 (b), an `[S]` item). A G5 route would carry it with the right disposition family (configuration failure, like R-G5-04); left in G2 it sits inside a route whose disposition is *supported under stated premises*, which is accurate only because the premise excludes the departure. The spine should say which it intends; the route file records the question in its section 6 and does not move the history (02 §4, addendum F-04). |

No disagreement with 02 §4.1 arose: the re-run's derivation of the four probe cases agrees with 02 §4.1
item 4 and with the WSL2 measurement (EV-29). PLAN.md is not a spine file; its expected disposition for this
re-run was a hypothesis and no request is raised against it. Registry version 5's five rows were checked
against kub §2.4 L194–235: every excerpt matches its passage; EV-142's note describes the search method
("a search of net/unix for writes to sk_receive_queue") in words the passage does not itself use, and cites
garbage.c L333 where the passage gives L330–334 — neither is an excerpt mismatch, and no request is raised
against 04.

## Requests of 2026-10-19 (step 4), re-run of R-G2-01–04 and R-G2-06–10

Requests for changes to shared files, for the reconcile role to merge into the convergence folder's
change-requests.md. This re-run edits no spine file and no template and creates no ID. None of the three
requests changes a disposition: each route's necessary items are backed by registered `[M]` / `[R]` rows
without them; they make the citations more direct.

| id | file and ID | requested change | why |
|---|---|---|---|
| CR-G2-4a-1 | 04-evidence-registry.md: new rows (IDs for the registry step to assign) | Register val row 167 and val row 168 as their own rows. Row 167: the comparand crosses from Python to C as ctypes.c_uint32 (ffi.py:52) and frame_receive refuses an expected uid outside 0 < uid < 0xFFFFFFFF (ffi.py:97); the unit test test_ffi_uid_bounds (test_receive.py:114–122) passes 0, 2^32 − 1, 2^32 and −1 and expects ValueError for each. Row 168: the VerifiedContext's sender_pid is None in the first version (receive.py:298) and the C reader returns no pid. | R-G2-06 and R-G2-09 argue the unsigned decode and the pid-as-diagnostic rule from EV-171, EV-169, EV-186 and EV-235; no 04 v7 row states the c_uint32 crossing or the absent sender_pid, though val rows 167 and 168 record both (results 满足（测试加代码阅读） and 满足（测试）, first version stricter). |
| CR-G2-4a-2 | 04-evidence-registry.md: EV-174, note column (append-only: a new row if notes may not change) | Record the split positions of test_uid_change_inside_one_frame_rejected_before_completion: it is parametrised at bytes 2, 4 and 9 of a wire frame that includes its four-byte header (test_receive_root.py:100–106), so one case changes the sender inside the header, one at the header/body boundary, one inside the body. | R-G2-02 and R-G2-07 cite the header-internal case; EV-174's text says only "a uid change between fragments of one frame". |
| CR-G2-4a-3 | 04-evidence-registry.md: §0 `val` source line; EV-178 note; EV-180 | Note that validation.md at HEAD (commit c834ebbd, blob 0ec579941699c576) differs from the blob 04 v7 cites (3d35d8704cd79b5e): row 145's result now reads 满足（测试加代码阅读） where EV-178's note copies 满足（代码阅读加回归）; rows 146 and 170 now cite a new unit test, test_no_credential_option_written_or_peer_credential_read (source scan for setsockopt, SO_PASSCRED and SO_PEERCRED), run 20261019T014433Z-engine-credential-scan. The engine package and sandbox code are unchanged by c834ebbd (it adds a test and a run). Optionally register the scan as an `[M]` row beside EV-180. | Keeps the registry's copied val wording traceable to the blob it names; EV-180 (absence by text search) is cited by R-G2-03, R-G2-07 and R-G2-09 and would gain a recorded test. |

No disagreement with 02 §4.1 arose. Validation rows read against the code for these routes (rows 140, 145,
157, 158, 164, 165, 167, 169, 174): each
cited file:line says what the row says; row 164's form "recvmsg writes the bytes before the comparison, only
counted bytes are read afterwards" is as EV-171 records it.

## Requests of 2026-10-19 (step 4), re-run of the remainder slots R-G2-11, R-G2-12, R-G2-13

Requests for the reconcile role to merge into the convergence folder's change-requests.md. They arise from
the re-runs of R-G2-11, R-G2-12 and R-G2-13 against registry version 7 and the engine build at commit
3ec67985. No spine file, template or other route file was edited, and no ID is created here; the three
requests are numbered only within this file.

| request | file and ID | requested change | why |
|---|---|---|---|
| 1 | 02-conditions-and-decomposition.md: §5.2 U-02 (text); §6 ledger rows R-G2-11, R-G2-12, R-G2-13, sixth column (text); no ID changes | Record that the three C-01 / C-03 / C-04 remainder slots now rest on the closing properties of PLAN §Follow-up plan after U, established by the engine-build checks (R-G2-11: EV-169, EV-170, EV-236 with EV-166 … EV-168; R-G2-12: EV-163 … EV-165; R-G2-13: EV-171 … EV-174, EV-239), with kernel defects to R-G5-01 and the stated premises (R-G2-11: jansson and CPython's json; R-G2-12: the initial user namespace as a deployment premise). U-02's count of seven slots is unchanged; the sentence may note that, with R-G2-05, four slots now carry a disposition other than open. | The route files now give *supported under stated premises* on a positive property of each input's producers, which is how PLAN says a slot leaves open, not on totality of the predicates (02 §4). If 02 keeps the "unresolved" wording, the spine and the route files disagree about the three slots. |
| 2 | R-G2-11 (route file, section 5 premises); PLAN §Follow-up plan after U, closing property of R-G2-11 ("the parser has no memory error") | Confirm or reject the classification used in R-G2-11: the two third-party parsers on the path — jansson, which w2_frame_receive calls on the counted body after the comparison (transport.c:238), and CPython's json, which parses the Python-owned copy (receive.py:107–123) — are premises of the same kind as the intact kernel, and the named fuzz check establishes the property for the project's own C code only. If the classification is rejected, R-G2-11 becomes *conditional on unbuilt requirements* with one remaining item: a fuzz entry that links an ASan-instrumented jansson and drives the body parse (CPython's json would then still be a platform premise). | The closing property's wording does not separate the project's code from linked third-party code. The fuzz run executed jansson without instrumentation (EV-168 note) and did not exercise the Python parse (EV-169 note); the design places parser memory safety on the C side and on the standard library (conn E-02 receive-side supplement). The disposition turns on this classification, so it should be the reconcile role's or the user's decision, not one re-run agent's. |
| 3 | ExperimentLab engine validation.md, §R-G2-11 limits and row 175 (not a spine file; for forwarding) | Add to the limits of §R-G2-11 that the Python half of row 175 (receive.py:107–123, the standard-library json parse of the copied body) is not exercised by the fuzz run and that its memory safety rests on the CPython runtime, as EV-169's note already says. | Row 175 ("parser 与 FrameReader 内存安全") is marked 满足（fuzz 加代码阅读） and names receive.py:107–123 as implementation, while the fuzz targets only transport.c. The section's limit list names jansson but not the Python parse, so the row reads as covering a parser the check did not run. |
