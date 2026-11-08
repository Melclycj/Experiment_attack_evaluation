# No-bypass: method, system-call rows and branch table

This document is proof unit 1.1, no-bypass. The property it argues is this: under the listed premises and configuration, what the engine does not hand to an execution, the execution cannot obtain without the engine. The configuration is engine baseline v1 (engine aa3f2803, kernel linux-msft-wsl-6.6.87.2; the engine source is in this repository at `arguments/original/engine-v1/`), the 74 system calls of the diagnostic allow list, and the host readings of the development machine (NB-EV-018, NB-EV-019).

Status, as the sources state it. The enumeration exists: the system-call rows (version 8, 2026-10-29) and the backbone with its branch table (version 12, 2026-10-29) have both closed review one. The backbone assigns each of the 306 branches to the chapter that is to write its cell in block two, and it ends with the list of items it hands to block two; the cells of NB-K-01 and NB-K-02 are to be added to the backbone before block two starts. In the initial-state tables of the backbone every item is recorded as holding except one, the effects of other subjects on the child during the construction window, which is recorded as undetermined and handed to the PS and LC chapters. The strength statement of the method is marked as a draft, and the scale and cost of the reverse tests and of TLC are given as inferences.

## Method

### Names used in this document

The rules of the argument are in SPEC (the argument specification), TESTING (reverse tests and TLC) and PLAN (execution and stopping points). Where they differ from this description, they prevail. The method rules shared by all proof units are in METHOD. "01 §x" refers to 01, the model inventory. "SPEC §4.1", "SPEC §4.2" and so on refer to SPEC.

### The logic of the argument

1. **The conclusion to be proved.** Under the listed premises and configuration, what the engine does not hand to an execution, the execution cannot obtain without the engine.
   - The "configuration" consists of baseline v1 (engine code and kernel source at fixed versions), the 74 system calls of the diagnostic allow list, and the host readings of the development machine (NB-EV-018, NB-EV-019).
   - The "premises" are these. Trusted parties are not controlled by the attacker and do not act maliciously. Of them, only the correct behaviour of the hypervisor and firmware, the supervisor and the offline deployer is a premise. The behaviour of code that affects reachability, such as the engine and the spawner, is to be proved and is not taken as a premise. The deployment preconditions are also premises. One of them covers privileged processes on the host: host processes whose credentials can pass the ptrace access check on an execution's tasks, or that hold a privileged fanotify group, do not take, read or write the private part of an execution (NB-AA-08). It is written as a conservative upper bound by credential, and the deployer must list these processes and check them one by one.
2. **What counts as "obtaining".** Each consequence that each action of an execution can cause is examined one by one. There are only four kinds of legitimate consequence:
   - it is completed through the engine's mediation;
   - it falls within the rights the delivery list gives;
   - it acts only on the execution's own private objects. This is judged by the full criterion of SPEC §4.1, which includes local environment instances "created by construction for this execution alone". The part the host can see without privilege does not count as private. A part whose visibility is not yet settled is treated as visible, and the two are marked separately (01 §2.6);
   - it touches only global aggregate quantities that nobody owns, for example load counters. Of these, one used only to infer other parties' activity is recorded as a side channel, priced or recorded as unpriced. One that makes other parties' operations slower or fail is recorded as an availability effect. The same kind also contains the **host-observable**: the consequence acts only on the part of the execution's own state that the host can see, such as the argument area, comm and task state, and the content that the kernel writes into host logs on its behalf, taken from its own state (for example comm). It obtains no undelivered object, so it is not a route. But this content can be chosen by the execution, and ordinary host processes can read it. It is an outbound channel to host readers that does not pass through the engine, and it is written into the conclusion as a limit.

   A consequence outside these four kinds is a **route**: one consequence of one action that goes beyond what was handed to the execution. The local environment is only a source of objects, not a fifth kind.
3. **How completeness is sought.** An agent affects anything outside itself only through five families of events: system calls, user-mode instructions and memory accesses, actions the kernel completes on its behalf, deferred actions, and process state changes (the basis is in [Why these five families](#why-these-five-families)).
   - System calls are listed one per row from the allow list. A call that performs several kinds of operation is split at the kernel's dispatch location, and one further row covers the remaining values.
   - The rows of the other four families are derived by a tracing rule. The rule starts from every event already in the model and from the state the sandbox construction sets up, plus a few extra entry points: the exception vectors user mode can trigger, the common paths for kernel return to user mode and for scheduling, and background threads. From there it follows the mappings, registrations, queues, dirty state and references each event leaves behind, until they are fully handled or handed to a column or row that is responsible for them. Newly derived rows are traced further in the same way. When one event can be triggered from several entry points, it gets one main row; each entry point is recorded in the main row, and the main row's analysis covers all of them. An entry point that changes the state used, the execution point or the follow-on actions gets a main row of its own.
   - Columns are derived mechanically, not listed by hand. They come from the semantics of the parameters (fields in structures, nested pointers and fds, and sub-operations are all sources of names), from the implicit subjects when there is no parameter (process group and session, parent process, keyring, resources counted per uid and so on), from the inherited attributes that copy_process and execve keep, and from the state that trusted parties later dereference (one column for each such trusted party) (SPEC §4.2 steps 2 and 4).
   - Every cell is either analysed or carries a written reason why it does not apply.

   So "nothing left out" has a definite meaning: complete relative to this table. Whether the table itself is missing rows or columns is checked by review one, which is dedicated to that question. The known namespace-bypass cases are first assigned to branches at the start of block two. After the matrix is filled, they are checked again item by item, together with the resource and check seeds of the CCT (SPEC §3.4, SPEC §4.2 step 5).
4. **One invariant ties the whole argument together.** It has three clauses:
   - I1: every reference the execution holds comes from what the code actually handed it at start and from the local environment the sandbox constructed, or from its own actions that are recorded in the table;
   - I2: the part of its private objects that the host can reach only with privilege can be taken, read or written only by the execution itself and by the trusted parties on the list. That privileged processes on the host do not take, read or write it is the premise NB-AA-08;
   - I3: every consequence it produces is within the four kinds (private is judged by the full criterion, of which I2 is only the holder condition). Otherwise it is a route that is stopped by a specific mechanism, or that can only be realised through an exclusion.
5. **The proof has three steps:**
   - Initial state (block one): prove that all three clauses hold at the moment of execve. Check item by item what the code actually hands over, each step of the sandbox construction, and the inherited attributes.
   - Preservation (block two): each cell of the table corresponds to one class of action. The action is cut into one or more steps at the transition granularity the backbone sets (one system call can be several steps). Prove that after each step the three clauses still hold. This step has two kinds of work:
     - **Single-cell facts**: what this action reaches through this name, and whether it is stopped. Backbone v9 yields 306 branches, which is the bulk of the work. For cells that can be tested, the judge is the **reverse test** ([Reverse tests](#reverse-tests)). The test is added on top of the conservative summary and the source citation. All three are needed, and they count only when they agree. When they disagree, a route is recorded as open and other cells as undetermined until it is resolved. Cells that cannot be tested rest on the conservative summary and the source citation alone.
     - **Composition logic**: whether the three clauses still hold when all single-cell conclusions are put together with the actions of the spawner, the worker, the engine and the supervisor, under every ordering, concurrency and lifecycle. The judge is **TLC** ([TLC](#tlc), run in block three). Within a bounded instance it replaces hand-written induction. Scale beyond the instance, and transitions that TLC's model does not contain, are argued through each cell's interference obligations and the composition chapter.
   - Implication (block three): from the three clauses always holding, derive the conclusion of item 1.
6. **Each route has one of four outcomes** (common to all proof units):
   - stopped (the mechanism's code cited line by line; for testable routes also measured by a reverse test; if the two disagree, recorded as open until resolved; at the composition level, checked by TLC within the bounds);
   - holds conditionally, pending a requirement not yet built;
   - insufficient evidence, recorded as open;
   - declared out of scope.
7. **How the conclusion is reported:**
   - All routes stopped or declared out of scope, and no "undetermined" cell: report "no-bypass under the listed premises and configuration, complete relative to M", and state each version, the TLC bounds and the coverage of the reverse tests.
   - Any open item or "undetermined" cell (even one): do not report the property as holding. Report only the supported part, plus the list of open items.
   - No open or "undetermined" items, but some conditional routes: report only the conditional conclusion, with each condition listed.
   - Counterexamples found are marked separately and are not mixed with open items that lack evidence.

   A list of "conditions the production allow list must meet" is attached as well. The host-observable kind is listed as a limit, with items verified as visible kept apart from items treated as visible. The results of the author's spot checks (sample size and number of errors found) are written into the conclusion.
8. **What this proof does not claim:** the production allow list (the conclusion holds only for the diagnostic allow list); confidentiality against ordinary host processes (the host-observable kind, and its outbound channel to host readers); real connectors; a compromised kernel; cross-domain hardware reads and writes, and contention on hardware the host already shares; subagents inside the same execution; host-level denial of service (shared writes the engine itself introduces are written as limits and are not in this exclusion); non-Intel processors.

### Objects

| Name | What it is | Where |
|---|---|---|
| execution | the group of processes the agent runs in the sandbox; the attacker's code is here | — |
| engine | the intermediary that acts for the agent, and also the party that hands things to the execution | the engine snapshot of baseline v1 |
| delivery list | the four things the engine hands to the execution: /work, the read-only copy of the runtime, the engine channel fd 3, and the channel between executions (not designed) | 01 §2.1 (the only definition) |
| local environment | what the sandbox builds itself: /, /tmp, /dev/shm, four devices, proc, loopback and so on, each marked "exclusive" or "shared with the host" | 01 §2.2 |
| matrix | row = action; column = the "name" the action uses to designate an object (including implicit subjects, inherited attributes, and state that trusted parties later dereference); cell = what this action can reach through this name | the backbone sets the branch table; the chapters fill the cells |

### The matrix

#### What a cell does (example: openat × path)

| What openat opens | What it reaches | Classification |
|---|---|---|
| a file under /work, read-write | workspace file | delivered, within the rights |
| an existing file under /runtime, for writing | the runtime copy | beyond the delivered rights → route; both file permissions and the read-only mount stop it: without O_TRUNC the file permissions give EACCES first, with O_TRUNC the read-only mount gives EROFS first |
| host /etc/shadow | host file | not handed to it → route; the mount namespace, pivot_root and unmounting the old root stop it (the path does not exist) |
| reopening /proc/self/fd/0 | host /dev/null | item shared with the host: operations with an external effect are judged as a shared aggregate (kind 4) or as a route |
| /tmp/x | a temporary file in its own sandbox | private; it must be proved that other executions cannot reach it |

This table is the content of the preservation step in the openat cell. "Classify and decide the outcome" and "prove that this step preserves the three clauses" are the same piece of work, with no order between them. The routes of 1.1 are not multi-step attack chains like those of the uid-binding line. Multi-step compositions (for example, leaving a symbolic link in /work for a trusted party to follow later) are handled in the "trusted-party dereference" columns and in the cross-chapter composition.

**Splitting.** Calls that do different things depending on an operation code (fcntl, prctl, futex, clone, unshare, getsockopt, madvise, arch_prctl) get one row per operation code, because the objects they reach differ (for example, F_GETFL only reads the process's own fd flags, while F_SETLEASE makes other parties block when they open the file).

#### Why these five families

The basis has three layers. The sources are in hardware-premise-sources and unprivileged-instructions.

1. **The processor.** It is a premise that the processor carries out the x86-64 privilege and memory-protection rules as the Intel 64 and IA-32 Architectures Software Developer's Manual (325462-093US) describes them (SPEC §4.2). The manual lists every means of program control transfer (Vol. 3A §6.8). Of these, the ones that can raise user mode to kernel privilege are the system-call instructions (SYSCALL, SYSENTER), software-interrupt instructions, exceptions, external interrupts, and far calls through call gates (Vol. 3A §6.8.4, §7.12.1.2). The manual has no single sentence that enumerates these; this item is assembled from several sections (evidence record §2.2), and for one part of it, that IRET cannot return to a higher privilege, the evidence record cites no source. User-mode memory access is constrained by paging permissions, and touching a kernel page triggers a page fault (Vol. 3A §5.6.1, §5.7; evidence record §2.1 marks this item as partly supported and lists the exceptions there). Privileged instructions and I/O instructions without permission trigger an exception in user mode (Vol. 3A §6.9; Vol. 1 §20.5).
2. **The configuration of the baseline kernel.** Every escalation path passes through structures the kernel configures itself. On baseline v1: the system-call entry registers point only to the 64-bit entry and two 32-bit compatibility entries, and the latter are killed by the filter for an architecture mismatch; the GDT and LDT contain no call gates; every exception vector has a destination; there is no FRED, no LASS, no user interrupts, and no system call that opens I/O permissions.
3. **Instructions that do not enter the kernel.** The 822 instruction pages of the manual's Vol. 2 and the 43 in Vol. 3 are placed one page at a time. Most touch only the program's own registers and its own mapped memory, or trigger an exception in user mode. The few that read the clock, the CPU number and the processor's static configuration read only machine-wide shared values, and belong to the observation channels (01 NB-E-M-04, NB-E-M-08). Those that exit directly to the hypervisor inside a virtual machine are carried by the premise "correct behaviour of the hypervisor and firmware". Those that only cause cache, timing or bus contention belong to METHOD rule 2's exclusion of cross-domain hardware reads and writes and contention on shared hardware.

From this, apart from the one PTWRITE case below, user-mode code has only two ways to affect anything beyond itself: user-mode instructions reading and writing mapped memory or reading machine-wide shared processor state; or entering the kernel (a deliberate trap is a system call; an exception triggered by an instruction is something the kernel completes on its behalf). The PTWRITE case is this: when the host enables processor tracing and allows PTWRITE, a user-mode instruction writes data into the host's trace record. In the model it belongs to 01 NB-E-K-14. Deferred actions and process state changes are caused within the first three families or by the constructed initial state (for example, an inherited RLIMIT_CPU), and their consequences happen later. They are listed separately because they are the easiest to miss when looking at system calls one by one. They are derived by the tracing rule over the kernel source (item 3 of [The logic of the argument](#the-logic-of-the-argument)). The only exclusions are the four classes of METHOD rule 2. These three layers only read the manual and the source; nothing was measured on a machine. The conclusion is written only for Intel processors.

The five families are a classification, not sources. The same event can be triggered from several kernel entry points (for example, a parent process can be notified either by a normal exit or by a kill), and the follow-on actions of one entry point can fall in another family. So "nothing left out" does not rely on "one entry per family". It relies on the tracing rule in item 3 of [The logic of the argument](#the-logic-of-the-argument). The basis is a structural check of where the five families come from (recorded).

#### Scale (backbone v9, 2026-10-27)

System calls: 45 rows (74 calls). Of these, 8 multiplexed calls are split into 87 sub-operation rows (including 8 rows for "remaining values"). The other four families have 39 main rows; construction and lifecycle have 16 rows. There are 13 columns (8 named-domain columns, plus 5 trusted-party columns). The branch table has 306 branches in all, plus 97 not-applicable items and 13 column not-applicable rules ([02 §3.3–§3.6](#33-sub-operation-table)).

### Reverse tests

- **What it is.** Actually carrying out an action in the sandbox and observing the kernel's real response. The judge is the kernel's actual behaviour, not an inference from reading the source. It is verification, not attack: the object is a sandbox on this machine, built by this run from fixed versions; the tests only confirm that attempts to exceed rights are stopped; the targets are decoys this run creates itself, and no real sensitive object is touched; no bypass method is researched or recorded.
- **What it can prove.** For a specific input: "cannot reach" (it is stopped), or "what it reaches is exactly what was handed to it". It turns a single-cell conclusion from an inference into a measurement. Generalising to a whole class (for example, a few host paths standing for "all host paths") needs an argument grounded in the source; what cannot be generalised is recorded as open.
- **What it cannot prove.** That the columns are complete; parameters not tested; composition and races (handed to TLC and the lifecycle chapter); privacy with respect to the host (two sandboxes looking at each other check only whether another execution can reach something; they do not check host processes and do not verify the premise NB-AA-08).
- **Which cells are tested:**

  | Nature of the consequence | Example | Tested or not |
  |---|---|---|
  | touches only itself | getting its own pid, changing its own memory protection | not tested, judged from the source; one whose conservative summary has a deferred or external effect cannot be exempted |
  | route (claimed unreachable) | opening a decoy file on the host, writing /runtime, sending a signal to a decoy process | reverse test: do it and observe that it is stopped; routes declared out of scope and routes that hold conditionally are not claimed to be stopped and are not tested |
  | class boundary (claimed to reach exactly what was handed to it, and only that far) | writing /work succeeds; another sandbox cannot see /tmp | do it once, then check the object's identity (device number and inode from fstat, mount information); for the private class, two sandboxes look at each other |
  | only through a shared aggregate (claimed not to act on a specific object, for example on a device shared with the host) | /proc/self/fd/0 really is host /dev/null | an object-identity test, supporting classification as kind 4 |
  | host-observable (claimed to act only on its own state, or on content the kernel writes into a log on its behalf, taken from its own state) | the host reads its argument area | an object-identity test, checking that what the host reads is this execution's own entry |

  The full obligation table, row by row by recorded value, is in TESTING.
- **What each test writes down in advance:**
  - Criteria: the observation that defines each of three outcomes. Stopped by the expected mechanism; success; any other outcome (stopped by another mechanism, set-up or observation failure) is recorded as uncertain until resolved.
  - Target: the target exists, and its identity is checked.
  - Controls: a route test has a positive control (the same probe touches a counterpart that is reachable by design, and must succeed). A boundary test has a negative control (the side beyond the rights must fail).
  - After-the-fact check: for a route test, after the window in which the effect could happen, check from outside the sandbox that the forbidden effect did not happen. For a boundary test, check that the change landed only on the delivered object.
  - A control that does not hold, a set-up failure, a timeout or insufficient observation does not count as measured evidence.
- **Why there is no single-mechanism ablation.** One way to check whether a test can detect errors is to remove one mechanism and see whether the test result changes with it. In the instances 1.1 has analysed, removing one mechanism either leaves the route stopped by another mechanism, or makes the construction fail so that the sandbox does not start. For routes where only one mechanism has been confirmed so far, this document does not predict what happens when it is removed. So there is no uniform "remove it and the result flips" criterion.
  - Stopped by another mechanism: the same route is often stopped by more than one mechanism. Opening an existing file in /runtime for writing is stopped by both the file permissions (the copy belongs to root, files are 0444 or 0555) and the read-only mount: without O_TRUNC the file permissions give EACCES first, with O_TRUNC the read-only mount gives EROFS first. For privileged calls outside the allow list, both the seccomp default action and the capability check return EPERM. For networking and SysV IPC, the diagnostic allow list contains no socket or SysV calls, bind and connect are fixed as forbidden, and the net and ipc namespaces are a second layer. Removing one of these leaves the route stopped. If the one removed is the one that fires first on the kernel path, the observation changes to the later one (for example EACCES becomes EROFS), and under TESTING's criteria it is recorded as uncertain. In this case ablation only shows that there is a fallback; it cannot show whether the test itself is valid.
  - Construction fails, the sandbox does not start: if any step of construction fails, the sandbox does not start and not one line of agent code runs (each step aborts on failure, and the engine regression injects a failure at each step). Two pairs depend on each other: without unmounting the old root, the next step, removing the old root directory, fails; without setting no_new_privs, the seccomp filter cannot be installed after privileges are dropped. The other steps (for example the read-only remount, keeping only process directories in proc, closing surplus fds) can be removed and the sandbox still starts. The initial-state analysis checks the state after each failure step by step.
  - Only one mechanism confirmed so far: for example, the CLONE_NEWUSER flag of clone and unshare is stopped by seccomp. Privileged operations inside the allow list (setuid(0), unshare without CLONE_NEWUSER creating other namespaces) are stopped first by the capability check, and it has not yet been ruled out whether the checks after it form a separate layer (for example, setuid has a security hook after the capability check). How many routes are of this kind will be given by the depth statistics of block three.

  So whether a test is valid rests on each test's controls and criteria, not on ablation. Where the error code is the same (for example the EPERM above), the observation alone cannot tell which layer fired; [R] states which one fires first on the kernel path, and the measurement proves that the action was stopped. Which routes are stopped by how many mechanisms is summarised in block three as the distribution of defence in depth (PLAN §1.1). The source locations of the instances above in the baseline snapshot are listed in reconcile, in the section "targeted re-review changes written back on 2026-10-27".
- **How the tests are organised.** In groups by "the mechanism that stops it", each group with a list of attempts (table-driven). This is **how the tests are organised (an after-the-fact classification), not a derivation of completeness**. What to test is decided by the matrix. Each route the matrix finds is put into the group of the mechanism that stops it; one that fits no group starts a new group. So the grouping does not limit coverage.

  | Mechanism | What it stops | One test group |
  |---|---|---|
  | file view (mount namespace, pivot_root, mount flags) | host paths, writes to read-only areas | host path table × every call that takes a path |
  | pid namespace | other processes | host pid table × kill, wait4, prlimit64, F_SETOWN and so on |
  | net namespace + seccomp forbidding network calls | the network | each network call |
  | ipc namespace | shared memory, message queues | the related calls |
  | seccomp filter | calls outside the allow list and forbidden flags | table of calls and flags |
  | no capabilities, no_new_privs | privileged operations | table of privileged operations |
  | file permissions | other parties' files | permission table |

  Three groups of boundary tests are added: the two sides of the delivered rights, privacy between two sandboxes, and the identity of devices shared with the host.
- **How they are run.** As the engine's existing regression does: build the sandbox program from the baseline v1 snapshot, and run it as root in a private mount namespace in WSL. Create two new 256 MiB images, run mkfs.btrfs on them and loop-mount them as the deployment root and the workspace storage (the engine requires them to be on btrfs). Each run first checks the kernel version and the registered host readings. Test targets are always decoys this run creates itself. Routes that could only be tested with real sensitive objects are not tested and are judged from the source. Time, memory, process count and output all have limits. At the end, or on error, cleanup runs in a fixed order and is checked. Each batch starts only when the author says "start". Tests that would affect the host (memory exhaustion, machine-wide writeback pressure) are not run. The full rules are in TESTING. A trial run (NB-EV-020) confirmed that this approach works.
- **Scale and cost (we infer).** About 200–400 test cases in 20–40 groups, of the same shape as the engine's existing 172 regression cases; about 3–6 work sessions plus review.

### TLC

- **Three names.** TLA+ is a specification language (it writes the state, how each step changes it, and what always holds). TLC is its model checker: it instantiates the model at a finite size, walks every reachable state from the initial state, and checks the invariant in each state. TLAPS is a proof system: backend provers check each step, and the result holds for any size (not done for now).
- **Bounds.** Any number of models can be written. TLC checks one concrete instance at a time: two executions, one of which has a successor (a successor execution on the same workspace and the engine's epoch change are both included), and a finite number of objects and references. Within this instance it checks every ordering of all actions (all interleavings). TLC's result says nothing about sizes beyond the instance; those are argued by the composition chapter. Run limits: at most 10 minutes, 2 GiB heap, 1 GiB state directory. Hitting a limit is recorded as uncertain.
- **What the model contains.** Only the state relevant to 1.1: which references each execution holds; who each object belongs to (delivered, local exclusive, shared with the host, another execution, the host); which deferred actions are registered; epoch and uid allocation. Actions are abstracted by class. Each action rule is written from the conservative summaries of the corresponding cells, not from the cells' conclusions (for example: "open" only adds a reference to an object in the execution's own view; "pass an fd over the channel" moves the reference to the engine, which closes it; "exit" triggers the registered deferred writes; "reap"; "construct a successor" may reuse a uid). The action granularity follows the transition granularity the backbone sets. Of the trusted parties' actions, the few that move references are written. Each of the other relevant transitions (for example a symlink a trusted party later dereferences, locks and leases) gets a stated destination: written into the model, omitted after proving it has no effect, or handed to a named residual argument. Each kind of object is represented by one instance, and the reason they are interchangeable is written into the run-spec, so the state space is small.
- **Granularity.** Fine in the dimensions of references, ownership, registration and lifecycle; coarse in the others. When two actions combine into a new result, TLC finds it among the interleavings as long as the relevant actions are in the model, the result can be expressed as a state change in these dimensions, and it falls within the instance being run. Compositions that depend on finer kernel semantics (file contents, timing channels) are not in the model; they are handed to the single cells and tests, or to the argument of the composition chapter. "Not in the model" does not mean out of scope; the only exclusions are the four classes of METHOD rule 2.
- **How a counterexample is handled.** It is corrected as a model error only if reading the source shows that the step cannot happen under any input; what is corrected is then only behaviour the abstraction added. Tests serve only as supporting evidence. Otherwise the counterexample becomes a route and is recorded as open until resolved.
- **What it can find.** Missed orderings, chains of reference passing (clone, exec, passing fds over the channel), the order of reaping and of deleting copies, leftover references across epochs, and uid reuse.
- **What it cannot check.** Whether each abstract rule is faithful to the kernel and the engine (that rests on tests and reading the source); whether the columns are complete (that rests on the table and review one); whether the invariant in the model is enough to derive the property of SPEC §4.1 (that rests on human review and the implication argument, checked by review three). TLC only checks that I1–I3 hold on the reachable states within the bounds. It gives no general argument that "I implies the property". Nor is I3 required to equal the property; I may be stronger than the property. The model has only the dimensions of references, ownership, registration and lifecycle, so in the model I carries at most the part of SPEC §4.1 in these dimensions. The other parts (for example the two conditions of the private criterion "cannot be acted on during its lifetime" and "no effect on external objects", file contents and timing) are carried by the cells, and the implication argument combines the two.
- **Cost (we infer).** The model is about 300–600 lines, 1–3 sessions to write and debug, plus review. TLAPS would take weeks and has few AI-assisted precedents, so it is not done for now.

### What the two judges contribute

| Layer | With text reasoning only | After adding tests | After adding TLC | Still resting on argument |
|---|---|---|---|---|
| single-cell facts (reachable or not) | AI reads the source, AIs review each other | the kernel's actual behaviour; catches misread kernel semantics and interactions between configurations | unchanged | the argument for generalising to a whole class (grounded in the source) |
| composition logic | hand-written induction, AIs review each other | unchanged | the tool checks all interleavings within the bounds; catches missed orderings, chains of reference passing, and problems in reaping order | sizes beyond the bounds; transitions not in the model; effects outside the model's dimensions (file contents, timing) |
| whether the columns are complete | the table, check scripts, review one | unchanged | unchanged | yes |
| whether the TLC model is faithful to the code | — | tests cover part of it | — | the remaining part |

**Why do it (precedents).** The precedents found in this search, of top-venue work that uses AI for security analysis or proofs, all have a judge that "is not a large language model": a prover, a verifier, real execution, or human confirmation. No precedent was found where both the judge and the judged are large language models (within the scope of 10 searches), and a paper at IEEE S&P 2024 points out that the security reasoning of large language models is often unfaithful. Precedents whose venue and year have been verified: Baldur (ESEC/FSE 2023), Lemur (ICLR 2024), Selene (ACL 2024, seL4 lemmas), AutoVerus (OOPSLA 2025), PropertyGPT (NDSS 2025), KernelGPT (ASPLOS 2025), LLift (OOPSLA 2024), IRIS (ICLR 2025); the counter-example: Ullah et al. (IEEE S&P 2024, DOI 10.1109/sp54263.2024.00210). Before being written into the thesis, each is to be checked again against the original under the research rules.

Method details have two further sources:
- **Comparison with known cases** (SPEC §3.4) learns from two precedents. Provos, Friedl and Honeyman (USENIX Security 2003) §5 used previously reported security problems to analyse what effect privilege separation would have. Hyperkernel by Nelson et al. (SOSP 2017) §6.1, Figure 7, judged by hand, one by one, whether the defects fixed in xv6 from January 2016 to July 2017 (8 in all, after excluding two lock defects that did not apply) would be prevented; this is a comparison, not a replayed execution. Both papers use historical cases to show "would be stopped". 1.1 uses them instead as a coverage check: it only looks at whether a case falls into a cell, and does not treat this as evidence that a route is stopped. Some conclusions of N1–N10 have already entered the design text and, through S1, been transcribed into 01; for these entries the comparison finds less than an independent source would.
- **"The invariant implies the property; the two need not be equal"** ([TLC](#tlc)) matches how Hyperkernel §2.2 and §2.4 are written: a declarative property is written separately from the state-machine specification, and a verifier checks that the former satisfies the latter. In 1.1 this step is carried by human review and the implication argument (if the property formula P is adopted, TLC also checks it only within the bounds).

**Strength statement (draft).** What this document gives is a structured safety argument, not a machine-checked proof. Its scope is the versioned model M. Completeness is claimed only relative to M. The premises are stated, including the deployment precondition that privileged host processes do not take, read or write the private part of an execution (NB-AA-08). The cell-by-cell analysis is drafted by an LLM under a fixed method. Single-cell facts that can be tested take the reverse test as judge; those that cannot be tested rest on source citations; the conclusion reports the number of cells of each kind. Composition logic is checked by TLC within a bounded instance. This statement applies only to 1.1: uid-binding has no reverse tests, and its TLC ran only a bounded subset of the lifecycle, so this is not a rule shared by all proof units. The five-family classification takes as a premise that the processor enforces privilege and memory protection as the Intel architecture manual (325462-093US) describes, and the conclusion is written only for Intel x86-64.

**Dependencies and limits.** The conclusion depends on these tools working correctly within their own duties: the baseline snapshot and version check (baseline.py, including the export of kernel files); the build and run apparatus of the reverse tests, including the compiler that builds the test sandbox and libseccomp (the policy is compiled into BPF by libseccomp at run time); the tests' targets and effect observation; the encoding of the TLA+ model and invariant, and TLC; the coverage and evidence check scripts. The text reports separately the measured coverage, the scope of the bounded checks, and the semantic correspondence that still rests on human work. Passing the check scripts does not prove the source summaries correct. Passing TLC does not prove the model faithful to the implementation. Neither proves that these tools are free of errors. This document does not claim a machine-checked proof of the correctness of this tool chain.

## The 74 system calls

These are the system-call rows: the 74 calls of L, split by sub-operation, with the name-source columns of the parameters and the implicit subjects. L is the diagnostic allow list ([3.1](#31-entries-of-l-and-abi-entries)). The table is step S1 of the spine (the appendix table to 01 §3.1), dated 2026-10-24. Status: version 8, 2026-10-29; review one has closed.

- **Frozen revision.** NB-P3-2026-10-24. L is taken from checks L117–130 (blob 20b0959a). The fixed clauses are taken from policy L16, L34–36, L46–49 (blob 57012b55).
- **Reading rule.** Each row states only which objects this call can find through which names, which parameters must be expanded by their semantics, and which implicit subjects it has. It does not state defences and does not classify. The column IDs are in 01 §4: NB-N-01 path · 02 fd · 03 pid · 04 network · 05 IPC · 06 unisolated names · 07 implicit subjects · 08 inherited attributes.

**Stopping criterion (SPEC §4.2 step 3).** The conservative summary of each cell is written in S2. This table gives each row its "parameter expansion list". S2 must not leave out any expansion item.

**User buffers (added 2026-10-26, review one).** For every call with a user buffer (an input or output buffer, an iov, a structure and the pointers nested in it), the kernel reads and writes the buffer through copy_from_user and copy_to_user (include/linux/uaccess.h). The buffer can lie on any mapping of the execution: a shared mapping of a /work file, shmem, private memory, the read-only /runtime, and the vdso. This read or write is itself one trigger source of the NB-E-M rows of 01 §3.2 (including page faults, partial completion and EFAULT). The table below does not repeat this row by row. The conservative summary of each cell states where the call's output buffer lands, and where the part already written stays on partial completion. The "facts" column records only kernel semantics or code facts. The source locations behind `[R]` are pinned in S3 to the tag of §5.

### A Files and paths

| Row | Call | Name-source columns | Sub-operations / parameter expansion | Implicit subjects and inherited items | Fixed conditions and facts |
|---|---|---|---|---|---|
| NB-E-S-openat | openat | N-01 path (dirfd-relative → N-02) | flags bit by bit: O_CREAT (new inode, subject to umask), O_EXCL, O_TRUNC, O_APPEND, O_PATH, O_NOFOLLOW, O_DIRECTORY, O_TMPFILE, O_DIRECT, O_SYNC/O_DSYNC, O_NOATIME (needs owner), O_CLOEXEC; mode; path classes: /work (rw), /runtime (ro; O_WRONLY → EROFS/EACCES [M] checks L205), /tmp, /dev/shm, the four /dev nodes, /proc/self/* (including magic links: exe, cwd, root, fd/N, map_files/*, ns/*; for the writable entries see 01 NB-DI-25), / and /dev (root 0755: creation fails) | umask; RLIMIT_NOFILE; per-uid files count | protected_symlinks/hardlinks/fifos/regular take effect in 1777 directories (/tmp, /dev/shm); reopening fd/N of a socket gives ENXIO; opening ns/* gives an nsfd; /proc/self/mem can write the process itself |
| NB-E-S-read | read / readv | N-02 | target fd classes: /work, /runtime, tmpfs, /dev/zero, /dev/random, /dev/urandom (shared CRNG), /proc/self/*, fd 3 (protocol responses; the protocol belongs to 2.2), directory (EISDIR) | — | /dev/random has not blocked since 5.6 |
| NB-E-S-write | write / writev | N-02 | targets: /work (dirty pages → writeback; btrfs transactions and free space are shared), tmpfs (uses host memory), /dev/null, /dev/zero, /dev/random and /dev/urandom (mixed into the input pool, NB-DI-22), writable /proc/self entries (oom_score_adj, comm, timerslack_ns, coredump_filter, clear_refs, mem, attr/*, sched), fd 3 (requests, kind 1/2) | RLIMIT_FSIZE (inherited) | sync/syncfs are fixed as forbidden; fsync has its own row |
| NB-E-S-close | close | N-02 | closing the last reference triggers: release of locks and leases, dnotify, socket shutdown semantics (fd 3 fully closed → the engine reads EOF), release of memory when a tmpfs file is already unlinked | — | — |
| NB-E-S-fstat | fstat / newfstatat / statx | N-02; N-01 | st_ino (/proc entries and anonymous inodes take the global get_next_ino counter [M] OBS-04), st_dev (the anonymous dev number of the /work subvolume, the dev of /runtime), st_nlink, timestamps; statx's STATX_MNT_ID, STATX_ATTR_*; AT_EMPTY_PATH | — | each stat of a /proc/self/* path allocates a new inode number (the way OBS-04 is read) |
| NB-E-S-lseek | lseek | N-02 | SEEK_DATA/SEEK_HOLE read the layout of a /work file | — | — |
| NB-E-S-access | access / faccessat2 | N-01; N-02 (the directory fd of faccessat2) | existence probing (/var/lib not visible [M] checks L199); AT_EACCESS; the dirfd of faccessat2: a relative path is resolved from this directory fd (fs/open.c::do_faccessat via user_path_at(dfd), as with openat's dirfd) | — | — |
| NB-E-S-getdents64 | getdents64 | N-02 | directory fd: /proc (lists only pid directories and self/thread-self), /work, /runtime, /dev, /tmp, /dev/shm | — | — |
| NB-E-S-readlink | readlink / readlinkat | N-01; N-02 (the directory fd of readlinkat) | the dirfd of readlinkat: a relative path is resolved from this directory fd; with an empty path it reads the symbolic link the dirfd itself points to (fs/stat.c::do_readlinkat); /proc/self/exe, cwd, root, fd/N ("socket:[ino]", "/dev/null"), ns/* ("pid:[4026…]": the inode number of this ns), map_files/*, the symbolic links bin/lib/lib64/usr; symbolic links inside /work and /runtime | — | ns inode numbers are global nsfs numbers |
| NB-E-S-chdir | chdir | N-01 | changes cwd to any searchable directory; /work, /tmp, /proc/self/* directories | cwd is inherited by child processes | fchdir ∉ L |
| NB-E-S-getcwd | getcwd | — | reads its own cwd path (relative to its own root) | — | — |
| NB-E-S-fsync | fsync / fdatasync | N-02 | /work files (btrfs log tree/transaction commit: shared with the other subvolumes and the store on the same file system; host block-device I/O), directory fd, tmpfs (no-op), read-only /runtime fd (no dirty pages), fd 3 (EINVAL) | — | a pending item of CCT gap 6; sync/syncfs are fixed as forbidden |
| NB-E-S-execve | execve | N-01; N-02 (fd inheritance); N-06 (binfmt_misc registrations) | path: any executable file under /runtime and /work (/work allows exec [M] checks L211); interpreter: ELF PT_INTERP resolved in this mount ns; scripts `#!`; binfmt_misc: global registrations matched by magic, the interpreter path resolved in the caller's ns (three on the development machine: /init, /usr/bin/python3.12, /usr/bin/lli-18 → /init does not exist inside the sandbox, /usr → /runtime/usr); argv/envp free; AT_SECURE; setuid/setgid bits and file capabilities have no effect because of nosuid and NNP | kept: fd 3, credentials, NNP, seccomp, rlimit, SIG_IGN, cwd/root, cgroup, keyring, affinity; cleared: O_CLOEXEC fds, robust list, altstack, POSIX and CPU timers, mm; pdeathsig is cleared only on secureexec, an ordinary exec keeps it (corrected 2026-10-25) | the ia32/x32 entries are KILL_PROCESS [M]; comm is set to the file name |

### B Memory

| Row | Call | Name-source columns | Sub-operations / parameter expansion | Implicit subjects and inherited items | Fixed conditions and facts |
|---|---|---|---|---|---|
| NB-E-S-mmap | mmap | N-02; N-06 (pools) | fd class × prot × flags: writable MAP_SHARED (/work: dirty-page writeback; tmpfs; /dev/zero anonymous shared), MAP_PRIVATE, PROT_EXEC (allowed on /work), MAP_HUGETLB (hugetlb pool, 0 pages on the development machine), MAP_LOCKED (RLIMIT_MEMLOCK), MAP_POPULATE, MAP_FIXED, MAP_NORESERVE (overcommit_memory=0 heuristic), MAP_SYNC; anonymous mappings use host memory (no memcg) | RLIMIT_AS, DATA, MEMLOCK (inherited); vm.max_map_count | — |
| NB-E-S-mprotect | mprotect | — | its own mappings; PROT_EXEC transitions (MDWE inherited as off) | — | — |
| NB-E-S-munmap | munmap | — | release; dirty pages of shared mappings are left for writeback | — | — |
| NB-E-S-brk | brk | — | anonymous memory | RLIMIT_DATA | — |
| NB-E-S-madvise | madvise | N-06 (THP, reclaim) | MADV_DONTNEED/FREE, MADV_HUGEPAGE/NOHUGEPAGE (khugepaged), MADV_COLLAPSE (synchronous collapse), MADV_REMOVE (punching a hole in a /work shared mapping = changing the file), MADV_COLD/PAGEOUT (file pages need write permission), MADV_WIPEONFORK, MADV_DONTFORK, MADV_POPULATE_*, MADV_HWPOISON/SOFT_OFFLINE (need CAP), MADV_DODUMP/DONTDUMP (core is already off) | — | PR_SET_MEMORY_MERGE (registers the whole mm with KSM) does not check capabilities, see the prctl row; host ksm/run=0 |

### C Processes, signals, threads

| Row | Call | Name-source columns | Sub-operations / parameter expansion | Implicit subjects and inherited items | Fixed conditions and facts |
|---|---|---|---|---|---|
| NB-E-S-clone | clone | N-03 (new task); N-02 (CLONE_PIDFD returns a pidfd); N-06 (consumption of the host pid number space) | flags bit by bit: CLONE_VM/FILES/FS/SIGHAND/THREAD/SYSVSEM/SETTLS/PARENT_SETTID/CHILD_SETTID/CHILD_CLEARTID (deferred write address)/VFORK/PIDFD/IO; CLONE_PARENT (called by the ns init → EINVAL); CLONE_NEWNS/NEWPID/NEWNET/NEWIPC/NEWUTS/NEWCGROUP/NEWTIME (need CAP_SYS_ADMIN → EPERM); CLONE_NEWUSER refused by the filter; CLONE_PTRACE/UNTRACED; exit_signal | the new task inherits all of §4 NB-N-08; process group/session unchanged (still the spawner's); RLIMIT_NPROC (per uid u); threads-max, pid_max global | filter: A0 contains CLONE_NEWUSER → EPERM; clone3 → ENOSYS (libc falls back to clone [M] pthread=0) |
| NB-E-S-unshare | unshare | — | CLONE_FILES/FS/SYSVSEM/NEWNS… (NEWNS and the like need CAP → EPERM); CLONE_NEWUSER refused | — | as above |
| NB-E-S-exit | exit / exit_group | N-07 (parent process, ns members) | on exit: robust list and clear_child_tid writes; fds closed (locks/leases released); PID 1 exits → SIGKILL to everything in the ns → spawner SIGCHLD + waitpid; a non-init exits → the parent process in this ns | — | 01 NB-E-P-02 (exit chain), NB-E-A-01, NB-E-A-03, NB-E-A-04, NB-E-A-05, NB-E-K-07 (parent notification); tracing in 01-trace-events |
| NB-E-S-wait4 | wait4 / waitid | N-03; N-02 (P_PIDFD) | can wait only for its own children in this ns; WUNTRACED/WCONTINUED; rusage reads the resource statistics of its own children | — | — |
| NB-E-S-kill | kill | N-03; N-07 | pid>0 (this ns); pid=0 (the current process group = the spawner's process group: its members include the engine, the spawner, the worker and other executions; permission by uid, with the exception that SIGCONT is allowed within the same session); pid=-1 (every process visible in this ns); pid<-1 (the process-group number is resolved in this ns); signal 0 as an existence probe | process group, session | SIGKILL/SIGSTOP sent to this ns's init are ignored; kernel/signal.c check_kill_permission [R] to be pinned |
| NB-E-S-tgkill | tgkill | N-03 | tgid/tid in this ns | — | — |
| NB-E-S-setsid | setsid | N-07 | creates a new session and process group: leaves the spawner's session (EPERM if PID 1 is a process-group leader? the leader is the spawner, PID 1 is not a leader → allowed) | — | afterwards kill(0) reaches only its own group |
| NB-E-S-rt_sigaction | rt_sigaction / rt_sigprocmask / rt_sigreturn / sigaltstack / pause / restart_syscall | — | its own dispositions, mask, alternate stack; SA_NOCLDWAIT for its own children | dispositions inherited from the spawner (NB-DI-16) | — |
| NB-E-S-getpid | getpid / getppid / gettid | — | numbers within the ns; getppid()=0 | — | — |
| NB-E-S-getuid | getuid / geteuid / getgid / getegid / getresuid / getresgid / getgroups | — | reads u, g, an empty set of supplementary groups | — | — |
| NB-E-S-setuid | setuid | — | no CAP_SETUID: can only set u (a no-op); setuid(0) → EPERM [M] | — | — |
| NB-E-S-prlimit64 | prlimit64 | N-03 | pid=0 or its own task in this ns; reads every rlimit (including the inherited values NB-MM-01); lowers soft/hard limits; raising a hard limit needs CAP_SYS_RESOURCE | inherited rlimits | the RLIMIT_CORE hard limit 1 cannot be raised back [M] OBS-06 |
| NB-E-S-prctl | prctl | N-03 (the pid of PR_SET_PTRACER and PR_SCHED_CORE); N-06 (comm goes into the kernel log and host ps; the addresses of the argument and environment areas and the auxv that PR_SET_MM_MAP changes, with the host reading cmdline and environ through /proc; the KSM registration of PR_SET_MEMORY_MERGE) | one row per sub-operation: PR_SET_NAME (comm), PR_SET_PDEATHSIG, PR_SET_CHILD_SUBREAPER, PR_SET_DUMPABLE, PR_SET_PTRACER, PR_SET_TIMERSLACK, PR_SET_THP_DISABLE, PR_SET_SPECULATION_CTRL (itself), PR_SET_SYSCALL_USER_DISPATCH, PR_SET_VMA, PR_SET_MDWE, PR_SET_SECCOMP (adding further filters), PR_SET_NO_NEW_PRIVS, PR_SET_KEEPCAPS, PR_SET_TSC, PR_MCE_KILL, PR_SET_FP_MODE, PR_GET_*; those that do not check capabilities: PR_SET_MM_MAP and PR_SET_MM_MAP_SIZE of PR_SET_MM (CONFIG_CHECKPOINT_RESTORE=y; kernel/sys.c::prctl_set_mm goes to kernel/sys.c::prctl_set_mm_map before the capability check; PR_SET_MM_MAP_SIZE only writes the size of the structure back to the address the caller gives and does not change the mm; PR_SET_MM_MAP changes the addresses of this mm's code segment, data segment, brk, stack start, argument area and environment area, and the auxv; the exe_fd in the structure needs the checkpoint-restore capability, otherwise EPERM), PR_SET_MEMORY_MERGE and PR_GET_MEMORY_MERGE (register the whole mm with ksmd, mm/ksm.c::ksm_enable_merge_any; not scanned while host ksm run=0); those that need CAP: the other values of PR_SET_MM, PR_SET_IO_FLUSHER and PR_GET_IO_FLUSHER (CAP_SYS_RESOURCE), PR_SET_SECUREBITS, PR_CAPBSET_DROP (CAP_SETPCAP); PR_SCHED_CORE_CREATE/SHARE (core scheduling cookie: affects co-scheduling on the host's SMT sibling cores — CONFIG_SCHED_CORE is not enabled on the development machine, NB-EV-018; for the production host see NB-MM-07) | — | — |
| NB-E-S-arch_prctl | arch_prctl | — | ARCH_SET_FS/GS, ARCH_SET_CPUID (CPUID trap), ARCH_REQ_XCOMP_PERM (AMX: a larger XSAVE buffer = memory), ARCH_MAP_VDSO_* | — | — |
| NB-E-S-set_tid_address | set_tid_address / set_robust_list / rseq | — | registers addresses the kernel will write at exit/preemption (they can lie on a /work shared mapping) | — | 01 NB-E-A-01 (clear_child_tid, robust list), NB-E-A-10 (rseq); tracing in 01-trace-events |
| NB-E-S-futex | futex | N-02 indirectly (the inode key of a shared mapping); N-03 (PI operations: the owner tid in the futex word) | FUTEX_WAIT/WAKE/REQUEUE/CMP_REQUEUE/WAKE_OP/LOCK_PI/UNLOCK_PI/WAIT_BITSET/WAKE_BITSET; the PI operations (FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_TRYLOCK_PI, FUTEX_WAIT_REQUEUE_PI, FUTEX_CMP_REQUEUE_PI) resolve the tid in the futex word into the owner task in the caller's pid namespace (kernel/futex/pi.c::attach_to_pi_owner via find_get_task_by_vpid); private vs shared keys (a futex on a /work file mapping: the successor X′ can have the same key; concurrent executions share no file) | — | — |

### D Sockets (fd 3 only; socket() ∉ L)

| Row | Call | Name-source columns | Sub-operations / parameter expansion | Implicit subjects and inherited items | Fixed conditions and facts |
|---|---|---|---|---|---|
| NB-E-S-sendmsg | sendmsg / sendto | N-02 (fd 3; msg_name on a connected STREAM → EISCONN); N-02 (the fds carried by SCM_RIGHTS); N-03 (the pid in SCM_CREDENTIALS); N-06 (the uid and gid in SCM_CREDENTIALS, resolved in the initial user namespace) | iov bytes (protocol); cmsg: SCM_RIGHTS (any fd held: /work files, /runtime files, nsfd, pidfd, /proc entries, directories), SCM_CREDENTIALS (uid line T-20; the pid in ucred must equal the caller's tgid, and the uid and gid must be the caller's own, otherwise a capability is needed, net/core/scm.c::scm_check_creds; once accepted, the pid is resolved into a reference in the caller's pid namespace, net/core/scm.c::__scm_send via find_get_pid); MSG_OOB, MSG_NOSIGNAL, MSG_DONTWAIT, MSG_EOR; the SO_SNDBUF limit | fds the engine receives occupy the engine's fd table and RLIMIT_NOFILE until closed; in-flight fds keep their objects alive | the protocol content belongs to 2.2/3.1; the engine closes every fd it receives (conn L459–461) |
| NB-E-S-recvmsg | recvmsg / recvfrom | N-02 | MSG_PEEK, MSG_TRUNC, MSG_CMSG_CLOEXEC; the engine sends no fds | — | — |
| NB-E-S-getsockopt | getsockopt | N-02; N-06 | SO_PEERCRED (the credentials when the spawner created the socketpair: uid 0, gid 0, the pid rendered as 0 in the caller's ns; corrected 2026-10-25), SO_PEERSEC (LSM label), SO_PEERGROUPS, SO_PEERNAME (peer address: both ends unnamed), SO_PEERPIDFD (installs in the caller's fd table a pidfd pointing to the process recorded in the peer credentials, that is the spawner; derived in [02 §3.3](#33-sub-operation-table), added to this table 2026-10-26), SO_COOKIE (global cookie counter, allocated once), SO_NETNS_COOKIE (the cookie of the host net namespace the socket belongs to), SO_MEMINFO, SO_SNDBUF/RCVBUF, SO_INCOMING_CPU, SO_PASSCRED (its own end), SO_ERROR, SO_TYPE, SO_DOMAIN, SO_PROTOCOL; the other 47 SOL_SOCKET options are listed in the /OTHER row of [02 §3.3](#33-sub-operation-table) | — | setsockopt ∉ L |
| NB-E-S-getsockname | getsockname / getpeername | N-04 | both ends unnamed: returns sun_family, length 2 [M] checks L212 | — | — |
| NB-E-S-shutdown | shutdown | N-02 | SHUT_RD/WR/RDWR: the engine end reads EOF/EPIPE (an operation on the delivered channel) | — | — |
| NB-E-S-poll | poll / ppoll | N-02 | readiness of any fd; POLLPRI | — | — |

### E Time, randomness, identity readings

| Row | Call | Name-source columns | Sub-operations / parameter expansion | Implicit subjects and inherited items | Fixed conditions and facts |
|---|---|---|---|---|---|
| NB-E-S-clock_gettime | clock_gettime | N-06 (host clocks); N-03 (the pid encoded in a CPU clock id); N-02 (the fd encoded in a dynamic clock id) | CLOCK_REALTIME, MONOTONIC, BOOTTIME (host uptime [M] OBS-05), PROCESS/THREAD_CPUTIME, TAI; the vdso path; negative clock ids are expanded by their semantics: a CPU clock id encodes a pid, resolved in the caller's pid namespace (kernel/time/posix-cpu-timers.c::pid_for_clock: a thread clock is limited to this thread group, a process clock can be any process in this namespace); CLOCKFD encodes an fd (kernel/time/posix-timers.c::clockid_to_kclock goes to kernel/time/posix-clock.c::get_clock_desc, which after fget requires a posix clock device, otherwise EINVAL) | no time ns | — |
| NB-E-S-nanosleep | nanosleep / clock_nanosleep | N-03 (the pid encoded in the CPU clock id of clock_nanosleep) | relative or absolute (TIMER_ABSTIME on CLOCK_REALTIME: host time); timerslack inherited; the CPU clock id of clock_nanosleep is as in the clock_gettime row: the pid of a process clock is resolved in the caller's pid namespace, and a temporary CPU timer is attached to that process until it expires (kernel/time/posix-cpu-timers.c::do_cpu_nanosleep); a thread clock can only name another thread in the same thread group (naming this thread returns EINVAL); the dynamic clock of CLOCKFD has no nsleep method, returns EOPNOTSUPP and does not resolve the fd (clock_posix_dynamic in kernel/time/posix-clock.c) | — | — |
| NB-E-S-getrandom | getrandom | N-06 (CRNG) | GRND_RANDOM, GRND_NONBLOCK, GRND_INSECURE | — | does not deplete, does not block (5.6+) |
| NB-E-S-uname | uname | N-06 (UTS) | sysname, nodename (host hostname), release, version, machine, domainname | no uts ns | — |
| NB-E-S-fcntl | fcntl | N-02; N-03 (the pid of F_SETOWN); N-07 | one row per sub-operation: F_DUPFD/F_DUPFD_CLOEXEC (fd duplication, subject to RLIMIT_NOFILE), F_GETFD/F_SETFD, F_GETFL/F_SETFL (O_NONBLOCK, O_APPEND, O_ASYNC → SIGIO, O_DIRECT, O_NOATIME), F_GETLK/F_SETLK/F_SETLKW and F_OFD_* (record locks on /work files: visible to the successor X′ and to trusted observers; they die with the process/OFD), F_GETOWN/F_SETOWN/F_*_EX (the pid is resolved in this ns; signal delivery checks the uid through sigio_perm), F_GETSIG/F_SETSIG, F_SETLEASE/F_GETLEASE (leases on /work files: need owner; when a lease is broken the kernel blocks the opener for up to 45 s — the example of "control" in SPEC §4.1), F_NOTIFY (dnotify; directory events are delivered to itself as signals), F_GETPIPE_SZ/F_SETPIPE_SZ (no pipe), F_ADD_SEALS/F_GET_SEALS (memfd only), F_GET_RW_HINT/F_SET_RW_HINT | — | leases-enable=1, dir-notify-enable=1 (development machine) |

### F Row-count check

| Group | Calls | Notes |
|---|---|---|
| A Files and paths | 13 rows, 20 calls | openat, read, readv, write, writev, close, fstat, newfstatat, statx, lseek, access, faccessat2, getdents64, readlink, readlinkat, chdir, getcwd, fsync, fdatasync, execve |
| B Memory | 5 rows, 5 | mmap, mprotect, munmap, brk, madvise |
| C Processes | 16 rows, 33 | clone, unshare, exit, exit_group, wait4, waitid, kill, tgkill, setsid, rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack, pause, restart_syscall, getpid, getppid, gettid, getuid, geteuid, getgid, getegid, getresuid, getresgid, getgroups, setuid, prlimit64, prctl, arch_prctl, set_tid_address, set_robust_list, rseq, futex |
| D Sockets | 6 rows, 10 | sendmsg, sendto, recvmsg, recvfrom, getsockopt, getsockname, getpeername, shutdown, poll, ppoll |
| E Time, randomness, identity readings | 5 rows, 6 | clock_gettime, nanosleep, clock_nanosleep, getrandom, uname, fcntl |

20 + 5 + 33 + 10 + 6 = 74, which matches the 74 calls of L. Rows: 13 + 5 + 16 + 6 + 5 = 45 (the row counts of groups A, C and E were corrected on 2026-10-26). When S2 builds the matrix, each call gets one row, and sub-operations are split as in the table above. The grouping of this table is only a reading order.

## The backbone and the 306 branches

This is the backbone (02): the grounding of the invariant and the initial state, with the branch table in the second half. It is step "block one, backbone upper half" (PLAN §1.1); the lower half is the second half of the same file. Dated 2026-10-25. Status: version 12, 2026-10-29; review one has closed.

- **Baseline.** Baseline v1 (engine aa3f2803, kernel linux-msft-wsl-6.6.87.2).
- **Baseline check.** At the start of work on 2026-10-25, `python baseline.py check v1` → OK (the engine's 82 blobs match one by one; kernel 116/116; the working tree equals the baseline). On 2026-10-26, during the changes of review one, it was run again after fetching 5 kernel files → OK (kernel 121/121).
- **Inputs.** 01-model-inventory v15, 01-rows-syscalls v7, 01-trace-events v4 (blobs in VERSIONS). PLAN, SPEC, TESTING and METHOD are used at the blobs registered when block one started.
- **Reading rule.** The initial-state tables follow the format of SPEC §4.2. Every file and ID in a basis also appears in the dependencies. Kernel files are written as in-tree paths. Engine files are written as 01's abbreviation plus line numbers (the file name where 01 has no abbreviation).

**Purpose.** This file grounds the "shape of the proof" of SPEC §4.2 on this system: which code objects each of the three clauses of the invariant corresponds to, at what granularity transitions are cut, and which chapter each trusted-party transition belongs to (§1); and the initial state, that is, that I1–I3 hold at the execve that construction issues for each execution (§2). The second half is the decomposition of bad events: the sub-operation table, the branch table, and the column not-applicable rules (backbone lower half). The definitions of the invariant I1–I3 are in SPEC §4.2; this file does not rewrite them.

### 1 Grounding the invariant

#### 1.1 Model state and the corresponding code objects

The TLC model and the conservative summaries of the chapters all use the model state in the table below. Each item states what object it is in the kernel and in the engine. When a conservative summary says "acts on some state", it means the objects given here.

| Model state | Clause | Object in the kernel | Object in the engine |
|---|---|---|---|
| the set of executions, each with its epoch, uid, workspace and lease | all | a pid namespace (kernel/pid_namespace.c) and the tasks in it; the tasks' credentials, struct cred | the spawner's spawn_record (spawner L18–29); the workspace and uid registered in the catalog (catalog L311–334); the engine's sessions and leases |
| fd references the execution holds | I1 | the struct file in each task's files_struct and fdtable (fs/file.c) | — |
| paths and mounts | I1 | the mnt_namespace the task's nsproxy points to, and the struct mount tree in it; the root and pwd of fs_struct (fs/namespace.c, fs/fs_struct.c) | the mount steps of construction (child L39–82) |
| memory mappings | I1 | the vm_area_structs of mm_struct, each with the vm_file it holds (mm/mmap.c) | — |
| visible processes | I1 | the struct pids in this pid namespace (kernel/pid.c); fd references can also include the struct pid a pidfd points to, and the one getsockopt's SO_PEERPIDFD gives points to the spawner, outside this pid namespace (01-trace-events §8; review one, Claude's comment 11) | — |
| inherited attributes and implicit subjects | I1 | cred (credentials, keyring), signal_struct (rlimit, process group, session, CPU time accounting), sighand (dispositions), css_set (cgroup membership), the four namespaces in nsproxy carried over from the host | values set by the launcher and the spawner (cell L13–55; spawner L396–404; child L103–105) |
| objects and ownership: delivered, local exclusive, shared with the host, another execution, the host | I2, I3 | delivered: the inode tree of the workspace subvolume, the inode tree of the runtime copy, the channel's socket; local exclusive: the tmpfs and proc superblocks in this mount ns, this net ns and ipc ns, its own tasks and mm; shared with the host: the inodes of the four devices | the entries of the delivery list (01 §2.1); the local objects construction provides (01 §2.2) |
| registered deferred actions | I3 | clear_child_tid, robust_list, rseq and pdeath_signal in the task; the f_owner and fasync entries of a file; the file_lock_context of an inode (locks, leases); dnotify marks; skbs and in-flight fds in socket queues; dirty pages of an address_space; pending signals; the CPU time limit in signal_struct | — |
| references held by trusted parties | I2 | the fd tables and mm of the trusted parties' processes (the same objects as above) | spawner: child_pid, the channel end before hand-over, the fds of the store and the catalog (spawner L18–52); engine: the channel end and the fds it receives and then closes (transport.c L90–123, L212–240); file worker: the fds of the store and the seed; supervisor: the cell cgroup |
| epoch and uid allocation | I1, I2 | cgroup.kill and populated (kernel/cgroup/cgroup.c) | at admission, live records with the same uid, the same gid or the same workspace exclude each other (spawner L87–92); epoch change (spawner L405–439; recover L7–16) |

I2 covers only the part of a private candidate that the host can reach only with privilege (SPEC §4.2). The model records ownership and references per whole object. In the reference dimension, checking that no other execution holds a reference to the whole object is stronger than what I2 requires. The other requirements of I2 are still carried elsewhere: that the listed trusted parties do not pass references on is carried by the trusted-party transitions, and that privileged host processes do not take, read or change the object is carried by the premise NB-AA-08. Host processes that are not trusted parties are not in the model. The part they can reach without privilege is recorded as host-observable in each cell (SPEC §4.1 kind 4).

#### 1.2 Transition granularity

The rule of SPEC §4.2: a system call or sub-operation counts as one transition only when its cell states an atomicity basis (the location of the lock, or an equivalent mechanism, in the kernel that prevents interleaving). Where no basis can be stated, it is cut at every position where another task can interleave, or conservatively treated as "the intermediate state is visible to other tasks". This rule applies to all transitions alike (review one, Claude's comment 10, Codex's comment R7): the execution's system calls and user-mode accesses, actions the kernel completes on its behalf and deferred asynchronous actions, process state transitions, and each step of the trusted parties. Threads of the same execution belong to the same subject (NB-X-03). This only says that their effects on each other do not count as interference. It is not an atomicity basis: when they act on objects shared with other subjects, their interleavings with other subjects' actions are still handled at cut points. The default granularity of each class of transition is as follows. A cell may merge the default cuts on the strength of a basis. A merge must state its basis; without a basis there is no merge.

**Failure returns and partial completion.** A call or trusted-party action, once cut, is a sequence of transitions. A failure return is this sequence reaching some cut point and turning onto the error path. The transitions already completed still act on the state, and the last transition gives the error return value. So the conservative summary of a failure path states "the completed prefix is visible". Partial completion (read copied only part, writev wrote the first few segments, a copy deletion was cancelled half-way) is the same sequence stopping midway. Each possible stopping point counts as one candidate effect (SPEC §4.2). The conservative summary states what the state is when it stops there, and who takes over afterwards.

| Class of transition | Default granularity | Cut points (positions where other tasks can interleave) |
|---|---|---|
| system calls and sub-operations (the appendix table to 01 §3.1) | one call is several transitions, cut at every cut point | sleeping and waiting (locks, I/O, page cache), copying user memory (may fault), releasing locks, positions where the RCU read lock is taken again; where a cell cannot state the cut points, its conservative summary is written as "the intermediate state is visible to other tasks" |
| user-mode instructions and memory accesses (NB-E-M-01…08) | one read or write instruction is one transition, and each instruction that reads processor state is one transition (NB-E-M-04, NB-E-M-08); page-fault handling counts as a separate transition | between instructions; an access that crosses a cache line or is unaligned is not guaranteed to be single-copy atomic and is handled as "the intermediate state is visible to other subjects"; threads of the same mm do not count as interfering with each other (NB-X-03), but when they act on a shared mapping their interleavings with other subjects are still cut |
| actions the kernel completes on its behalf, and deferred and asynchronous actions (NB-E-K-*, NB-E-A-*) | one unit of work is one transition: one signal delivery, one inode in one writeback pass, one rseq handling, one asynchronous notification, one release of a last reference | as in the system-call row |
| process state transitions (NB-E-P-*) | cut by the steps at the actual execution point: exec is cut into de_thread, exec_mmap, closing the close-on-exec fds, resetting dispositions and so on; exit is cut by the steps of do_exit | between the steps |
| construction (NB-K-01…10) | for this execution: transitions not subject to a preservation argument; their result is its initial state, checked step by step in §2; for other executions running concurrently with it: a trusted-party transition (construction for another execution), cut as in the next row and belonging to LC (§1.3) | as in the next row |
| run-time trusted-party transitions (NB-K-11…16 and the engine's run-time actions, including construction for another execution) | several steps are merged into one transition only with an atomicity basis (a lock in the trusted party's code, or the atomicity basis of a single system call); otherwise the cut is between each two system calls of the trusted party's code, and the system calls themselves are cut as in the first row. Example: the file worker deletes a copy one unlinkat at a time (catalog L431–493), with a cut between each two; the engine's handling of one message is not atomic either | between and inside the system calls of the trusted party's code; each cut point is treated as "the intermediate state is visible to the execution", with an interference obligation for each cell |

#### 1.3 Owning chapters of trusted-party transitions

Each trusted-party transition has one chapter responsible for its preservation argument (SPEC §4.2 "preservation") and its interference obligations. The same construction action has two cases (review one, Codex's comment R6). For this execution X, the result of construction is X's initial state, checked step by step in §2 of this file. A construction that the spawner performs for another execution Y while X runs is a trusted-party transition concurrent with X's actions. Its preservation and interference obligations belong to LC, and the branches of NB-K-03…10 in §3.4 carry exactly this case. NB-K-01 and 02 happen only once, at cell start, when there is no execution yet; their branches stay in this file.

| Trusted-party transition | Row of 01 | Owner | Reason |
|---|---|---|---|
| w2-cell start, spawner initialisation | NB-K-01, 02 | backbone §2 (initial state); the branches stay in this file | happens once at cell start, before any execution |
| admission, copy creation, before clone, the child's construction (closing fds, mounts, lo and stdio, dropping privileges and the filter, SEALED and execve), for this execution X | NB-K-03…10 | backbone §2 (initial state) | completed before X's code runs; the result is X's initial state |
| the spawner performing the same construction for another execution Y, concurrent with X's actions | NB-K-03…10 (for Y) | LC (the branches of these rows in §3.4) | PLAN §1.2: construction by a trusted party for another execution belongs to the lifecycle chapter |
| the spawner checks SEALED and hands the channel to the engine | NB-K-11 | NI | it passes an fd and belongs to the engine channel |
| the engine processes channel input and the fds it receives, and closes them | NB-K-12 | NI | PLAN §1.2 |
| the engine writes record files and stdout, stderr | NB-K-12 | PF | engine files (PLAN §1.2) |
| the spawner stops, reaps, clears | NB-K-13 | PS | signals and reaping |
| the file worker deletes the copy | NB-K-14 | LC | the file worker creates and deletes copies (PLAN §1.2) |
| a successor reuses the workspace | NB-K-15 | LC | successors and leases |
| control loss, epoch change, w2-recover | NB-K-16 | LC | reaping and epochs |
| trusted parties later dereferencing state the execution shaped: the successor's construction and run read /work, host cleanup and backup read /work, host trusted parties meet locks and leases when opening /work files, the supervisor reads populated | the four step-4 items of 01-trace-events §7 | the three items that read /work belong to PF, the supervisor item to LC | PF is responsible for the workspace state that trusted parties will later read (SPEC §4.2 step 4); populated is the reaping decision |
| core dump handler | NB-S-09 | PF | not invoked when RLIMIT_CORE is 1 (NB-E-K-01); PF still writes this cell |

### 2 Initial state

**What is to be proved.** I1–I3 hold at each execve (SPEC §4.2 "shape of the proof"). The execve here is the one that construction issues for each execution (NB-K-10), that is, the moment the execution starts (review one, Codex's comment R4). An execve that the execution itself does later is the transition NB-E-P-01. It keeps existing state such as fds without close-on-exec, SIG_IGN, rlimit, cwd and root (the follow-on actions of NB-E-P-01 in 01 §3.2), and does not reset the state to what this section describes. So preservation is proved from the state before it, which already satisfies I (the cells of NB-E-P-01 and NB-E-S-execve), and the tables of this section are not applied to it. At the moment of the execve that construction issues, the execution has not yet done any action. So I1 is "every reference held comes from D_impl or from the construction of the local environment". I2 is "for the part of each private candidate that the host can reach only with privilege (cut as the private criterion of §4.1 cuts it), the only holders of references that can take, read out or change it are this execution's tasks and the trusted holders 01 lists (privileged host processes outside the baseline snapshot are taken up by the premise NB-AA-08), and the trusted holders do not pass it on" (SPEC §4.2). I3 has no candidate effects to classify in the initial state: the effects produced through these references and implicit subjects are judged by each cell. The tables below check item by item: D_impl against the delivery list and the local environment (§2.1), the eight differences of 01 §2.4 (§2.2), each step of construction (§2.3), prior state the attacker has shaped (§2.4), and references held by trusted parties (§2.5). The inherited attributes are checked item by item at the end of §2.1. The allocation of NB-AA is in §2.6.

**Table header.** Initial-state item, record (holds, undetermined, or a route ID), basis, dependencies, test (SPEC §4.2). The test column gives the evidence number of an engine regression run, or "not tested" with a reason. The runs registered before 2026-10-25 (NB-EV-014…016) are the engine's own regression and support only the items they assert (the applicability boundary of 04).

#### 2.1 D_impl against the delivery list and the local environment

| Initial-state item | Record | Basis | Dependencies | Test |
|---|---|---|---|---|
| fd table: at execve only 0, 1, 2, 3 | holds | [R] spawner L50 first closes the engine end, the control fd, the worker fd and the store lock; child L88–103 dup2s 0–2 to /dev/null, moves the channel to 3 and clears CLOEXEC, and close_range(4,~0) closes the rest (fs/file.c::__close_range); [M] NB-EV-015 | spawner; child; fs/file.c; NB-DI-01; NB-EV-015 | NB-EV-015 (still has fds 0–3) |
| fds 0–2: opened with root credentials, the same file, pointing to host /dev/null | holds | [R] child L88 opens /dev/null in the sandbox with O_RDWR before dropping privileges (child L104); it is a bind of the same host device (child L66–75); the file records the opener's credentials, but the read and write methods of /dev/null do not look at them (drivers/char/mem.c::read_null, drivers/char/mem.c::write_null); reopening through /proc/self/fd/0 is a new open, with the execution's own credentials | child; drivers/char/mem.c; NB-L-04; NB-L-08 | not tested: source reading only; the identity test after reopening is in the GS chapter (the group for the identity of devices shared with the host) |
| fd 3: the agent end of the channel | holds | [R] spawner L113–124 creates an AF_UNIX SOCK_STREAM socketpair before clone (it belongs to the host net ns) and checks the buffers of both ends; child L100–102 puts the agent end at fd 3 without CLOEXEC; the spawner holds the peer end until it closes it after hand-over (spawner L251); the peer credentials of both ends are taken from the spawner when the socketpair is created (net/unix/af_unix.c::unix_socketpair → net/unix/af_unix.c::init_peercred), so the agent end reads uid 0 from SO_PEERCRED (corrected in v5 of the system-call table) | spawner; child; net/unix/af_unix.c; NB-D-03; NB-DI-02 | NB-EV-015 (fd 3 exists); peer credentials not tested: source reading only |
| mount table: only the mounts construction provides, with private propagation | holds | [R] child L44 first sets the whole tree to private; child L45, L64–65, L76–78 create the tmpfs root, proc, /dev, /tmp, /dev/shm; child L58, L62 mount /runtime and /work by recursive bind, then remount only the top level (child L31–32; recursive bind goes through fs/namespace.c::copy_tree, remount goes through fs/namespace.c::do_reconfigure_mnt, which changes only the top level); child L79–82 pivot_root and then detach the old root with MNT_DETACH (fs/namespace.c::do_umount); that the recursive bind brings in no submounts depends on the premise NB-AA-02; [M] NB-EV-015 | child; fs/namespace.c; NB-DI-03; NB-AA-02; NB-EV-015 | NB-EV-015 (mountinfo has no shared and no master) |
| /work is the workspace subvolume the catalog registers | holds | [R] when the catalog is loaded, it checks btrfs, the subvolume root (inode 256, a device number different from the parent directory's), owner u:g, 0700, and records dev and ino (catalog L311–334); in child the workspace is opened under the deployment fd through w2_workspace_open, every ancestor along the way must be root-owned and not group- or other-writable (support L172–190), and the same items and the recorded dev and ino are checked again (catalog L366–376); before the bind, mount_fd re-resolves the absolute path with an openat2 that does not follow symbolic links and compares the identity (child L19–31); between the comparison and the bind, only someone with write permission on a root-owned ancestor can replace the path, which depends on the premise NB-AA-01 | catalog; support; child; NB-D-01; NB-DI-04; NB-DI-19; NB-AA-01 | not tested: source reading only; the boundary test on both sides of the delivered rights is in the PF chapter |
| /runtime is the copy the worker built for this execution | holds | [R] child L39–43 opens copy_id under the objects fd with RESOLVE_BENEATH, not following symbolic links and not crossing mounts, and compares it with the dev and ino the worker recorded; mount_fd compares again before the bind (child L19–31) and remounts ro, nosuid, nodev, noatime (child L32); the copy is owned by 0:0, has read-only permission bits, and shares no inode with the seed (catalog L399–429); depends on the premises NB-AA-01, NB-AA-02; [M] NB-EV-015 | child; catalog; NB-D-02; NB-DI-18; NB-AA-01; NB-AA-02; NB-EV-015 | NB-EV-015 (writing /runtime fails) |
| /proc is the proc of this pid namespace, with only pid entries | holds | [R] child L64: mounted by PID 1 of the new pid ns; proc takes the mounter's active pid ns (fs/proc/root.c::proc_init_fs_context); subset=pid keeps only the pid directories and self, thread-self; [M] NB-EV-015 | child; fs/proc/root.c; NB-L-06; NB-DI-05; NB-EV-015 | NB-EV-015 (/proc/meminfo ENOENT, mountinfo has subset=pid) |
| the four nodes in /dev are the same host devices | holds | [R] child L66–75 first creates 0600 placeholder files on tmpfs, then binds the host /dev nodes of the same names onto them non-recursively (fs/namespace.c::do_loopback without MS_REC clones only the top level), and remounts them nosuid, noexec; the host nodes are 0666 (NB-EV-019); they are local environment shared with the host, and operations on them with an external effect are judged in each cell as kind 4 or as a route | child; fs/namespace.c; NB-L-04; NB-EV-019 | not tested: the identity test is in the GS chapter |
| the tmpfs root, /dev, /tmp, /dev/shm are new instances | holds | [R] child L45, L65, L76–78 each create a new tmpfs superblock, mounted in the mount namespace that clone created (spawner L128–129), with the whole tree first set to private (child L44); other executions and trusted parties hold no references to these instances (§2.5) | child; spawner; NB-L-01; NB-L-02; NB-L-03; NB-L-05; NB-PV-08 | not tested: the privacy test of two sandboxes looking at each other is in the PF chapter |
| network: this net namespace has only lo | holds | [R] spawner L128–129 with CLONE_NEWNET; child L83–87 brings only lo UP; [M] NB-EV-015 | spawner; child; NB-L-07; NB-EV-015 | NB-EV-015 (net has only lo) |
| cwd and root | holds | [R] child L79–82 pivot_root to the tmpfs root and detach the old root, so host paths have no name in this namespace; child L111 chdirs to /work | child; NB-L-09; NB-PV-08 | not tested: source reading only |
| credentials | holds | [R] support L237–261: first sets no_new_privs, drops the bounding set bit by bit, setgroups(0), setresgid and setresuid, then getresuid rechecks the three values, clears ambient, cap_set_proc(empty); when euid changes the kernel clears pdeath_signal and sets dumpable according to suid_dumpable (kernel/cred.c::commit_creds), and an execve that is not setuid sets dumpable back to 1 (fs/exec.c::begin_new_exec); [M] NB-EV-015 | support; kernel/cred.c; fs/exec.c; NB-DI-07; NB-EV-015 | NB-EV-015 (CapBnd 0, NNP 1) |
| seccomp filter | holds | [R] child L105 installs the filter compiled by the catalog after dropping privileges (no_new_privs is already set; kernel/seccomp.c::seccomp_prepare_filter requires no_new_privs or CAP_SYS_ADMIN); the filter's content is in policy L13–67; [M] NB-EV-014, NB-EV-015 | child; policy; kernel/seccomp.c; NB-DI-08; NB-EV-014; NB-EV-015 | NB-EV-014 (the three fixed forbidden items give EPERM); NB-EV-015 (Seccomp 2; the ia32 and x32 entries get SIGSYS) |
| namespaces | holds | [R] spawner L128–129 create new mount, pid, net and ipc namespaces; user, uts, cgroup and time are carried over from the host; nowhere in spawner.c is there code that opens /proc/\<pid\>/ns; the engine sends only with send without ancillary data (transport.c L247–260) and hands no nsfd to anyone | spawner; transport.c; NB-DI-09 | not tested: source reading only |
| the address space after execve: no writable mapping shared with other subjects, and no mapping whose backing object can be written by a subject other than a trusted party (the initial-state assertion handed over from 01's destination table; review one narrowed it to this wording following Codex's comment R9) | holds | [R] exec creates a new mm and switches to it, and all mappings of the old mm are dropped (fs/exec.c::bprm_mm_init, fs/exec.c::exec_mmap); the segments the ELF loader maps are all MAP_PRIVATE (fs/binfmt_elf.c::elf_map, fs/binfmt_elf.c::load_elf_binary), backed by the executable and interpreter in this execution's /runtime copy: the copy's inodes are not shared with the seed or with other copies, are owned by 0:0, have read-only permission bits, and are mounted ro (NB-DI-17, NB-DI-18); before copy-on-write, what is read is the page-cache pages of these inodes; the page cache is separate per inode, only this execution's tasks map these inodes, and host trusted parties can read them; the stack is a new anonymous mapping (fs/exec.c::setup_arg_pages); the vdso code page and vvar are mapped by arch/x86/entry/vdso/vma.c::arch_setup_additional_pages; they are read-only pages shared across the machine, and vvar is written by the kernel (NB-E-M-04). So there is no writable mapping shared with the engine, the spawner, the file worker or other executions, and only trusted parties can write the backing objects (NB-AA-03 checked against the code). No claim is made at the level of physical pages: the page cache and later KSM merging are managed by the kernel, and the latter is a run-time event (NB-E-A-07) | fs/exec.c; fs/binfmt_elf.c; arch/x86/entry/vdso/vma.c; NB-AA-03; NB-E-M-04; NB-DI-17; NB-DI-18; NB-E-A-07 | not tested: source reading only |
| process group, session and controlling terminal | holds | [R] clone without setsid or setpgid (spawner L128–129): PID 1 stays in the spawner's process group and session; the same group also contains the engine (from fork then exec in cell L36–54), the spawner, the file worker and the other executions; the controlling terminal depends on how the cell is started (cell does not call setsid). This is an inherited implicit subject, a source that I1 allows; the candidate effects through it are judged in the cells of column N-07 | spawner; cell; NB-DI-10; NB-MM-02 | not tested: the effects are tested in the PS chapter |
| parent process and exit_signal | holds | [R] the exit_signal of the clone at spawner L128–129 is SIGCHLD, and PID 1's parent is the spawner (kernel/fork.c::copy_process); only the spawner calls waitpid on it (spawner L372) | spawner; kernel/fork.c; NB-DI-11 | not tested: source reading only |
| cgroup membership | holds | [R] the new task enters the spawner's css_set (kernel/cgroup/cgroup.c::cgroup_post_fork); there is no cgroupfs in the sandbox, mount is not in L, and there are no capabilities, so it cannot migrate out (the code half of NB-AA-06); that the cell is placed in an exclusive cgroup is the supervisor's deployment precondition (the premise half of NB-AA-06) | kernel/cgroup/cgroup.c; NB-DI-14; NB-AA-06; L (whole table) | not tested: source reading only |
| keyring | holds | [R] fork inherits the session keyring reference in the credentials (kernel/cred.c::copy_creds); keyctl, add_key and request_key are not in L; this is an inherited attribute, and the candidate effects through it are judged in the cells of column N-07 | kernel/cred.c; NB-DI-15; NB-MM-03; L (whole table) | not tested: source reading only |
| rlimit | holds | [R] child L103 sets both the soft and the hard RLIMIT_CORE to 1 (raising the hard limit needs CAP_SYS_RESOURCE, kernel/sys.c::do_prlimit); the others are inherited from the launcher's parent process, neither cell nor spawner sets them, and their values are a deployment condition (NB-MM-01); they only limit this execution's resources and give no references | child; kernel/sys.c; NB-DI-06; NB-MM-01 | NB-EV-016 (/proc/self/limits shows core 1 1) |
| signal dispositions and mask | holds | [R] spawner L400–402 sets SIGCHLD to SIG_DFL and clears the mask; other dispositions are inherited; SIG_IGN is kept across exec, and handler functions are reset at exec (kernel/signal.c::flush_signal_handlers); this only affects how this execution handles the signals it receives | spawner; kernel/signal.c; NB-DI-16; NB-MM-04 | not tested: touches only itself |
| umask | holds | [R] child does not set umask (child L38–119); the value is inherited from the launcher's parent process (NB-MM-05); it decides the permission bits of new files on /work, while the workspace subvolume root is 0700, owner u (catalog L323–324), so on the host only root and u can enter it | child; catalog; NB-MM-05; NB-DI-19 | not tested: source reading only |
| pdeath_signal | holds | [R] cleared at clone (kernel/fork.c::copy_process), and cleared again by the kernel when child drops privileges and euid changes (kernel/cred.c::commit_creds), so it is 0 at execve; an ordinary exec does not clear it (fs/exec.c::begin_new_exec clears it only on secureexec): 01 §4 NB-N-08 and the execve row of the system-call table originally said "cleared at exec"; this is corrected (01 v8, the system-call table v5) | kernel/fork.c; kernel/cred.c; fs/exec.c; NB-N-08 | not tested: source reading only |
| robust list, alternate stack, POSIX timers and itimer | holds | [R] at clone the robust list is cleared (kernel/fork.c::copy_process calls futex_init_task), and the ITIMER_REAL in the new signal structure is newly created (kernel/fork.c::copy_signal); at exec the POSIX and CPU timers and the alternate stack are cleared (fs/exec.c::begin_new_exec), and the robust list is cleared (kernel/futex/core.c::futex_exec_release) | kernel/fork.c; fs/exec.c; kernel/futex/core.c; NB-N-08 | not tested: source reading only |
| loginuid and sessionid | holds | [R] inherited from the launcher; if the inherited value is unset, the execution can set it once without privilege, which also allocates a new sessionid (kernel/audit.c::audit_set_loginuid); they appear only in this execution's audit records (NB-E-K-13); 01 NB-DI-25 has been extended with them (01 v8); the inherited value must be read on the host (01-trace-events §7) | kernel/audit.c; NB-DI-25; NB-E-K-13 | not tested: the effect is in the GS chapter |
| comm, dumpable, oom_score_adj, affinity, ioprio, nice, personality, securebits, timerslack, mempolicy, THP disable, speculation control, MDWE, TSC disable, CPUID trapping, syscall user dispatch, dynamic XSAVE permissions | holds | [R] comm is set to the executable's file name at exec (fs/exec.c::__set_task_comm); for dumpable see the credentials item; the others are inherited by fork (kernel/fork.c::copy_process), and child does not change them (child L38–119 has no call that sets them); they all act only on this execution's own tasks and mm, and the candidate effects through them (for example oom_score_adj changing the OOM choice) are judged in each cell. The last four items (added by the targeted re-review): at the execve construction issues, syscall user dispatch and CPUID trapping are both off (the former is cleared at fork and exec: kernel/fork.c::dup_task_struct, fs/exec.c::begin_new_exec; the latter is cleared at exec: arch/x86/kernel/process.c::arch_setup_new_exec); the TSC-disable flag is copied at fork (arch/x86/kernel/process.c::arch_dup_task_struct) and kept at exec; its value comes from the launcher's parent process, it is a deployment condition, and it only affects this execution's own reads of the TSC; dynamic XSAVE permissions are inherited at fork and reset to the default at exec (arch/x86/kernel/fpu/core.c::fpu_inherit_perms, arch/x86/kernel/fpu/core.c::fpstate_reset), so after the execve construction issues the execution has no AMX permission (pinned 2026-10-27) | fs/exec.c; kernel/fork.c; arch/x86/kernel/process.c; arch/x86/kernel/fpu/core.c; child; NB-N-08; NB-MM-05 | not tested: source reading only |

#### 2.2 The eight differences of 01 §2.4

| Initial-state item | Record | Basis | Dependencies | Test |
|---|---|---|---|---|
| NB-DI-21 recursive bind and non-recursive remount | holds | [R] see the mount-table item; submounts under the source directory can only be added by a subject that can mount in the host mount namespace (root): the copy directory under objects is newly created by the worker (catalog L402), and the workspace subvolume is created by the deployer; so it depends on the premise NB-AA-02 | catalog; NB-DI-21; NB-AA-02 | not tested: premise |
| NB-DI-22 /dev/random and /dev/urandom are writable | holds | [R] the host nodes are 0666 (NB-EV-019), and the bind's remount adds only nosuid, noexec (child L74); writes are mixed into the global input pool (drivers/char/random.c::random_write_iter); this is a candidate effect for column N-06, not a new reference | child; drivers/char/random.c; NB-DI-22; NB-EV-019 | not tested: the effect is in the GS chapter |
| NB-DI-23 /dev has no nodev | holds | [R] /dev is a root-owned 0755 tmpfs (child L65), and u cannot create entries in it; mknod is not in L, and there is no CAP_MKNOD; so /dev contains only the four nodes construction put there | child; NB-DI-23; L (whole table) | not tested: source reading only |
| NB-DI-24 O_NONBLOCK on fd 3 | holds | [R] spawner L113 creates the socketpair with SOCK_NONBLOCK; it only affects how this end reads and writes | spawner; NB-DI-24 | not tested: touches only itself |
| NB-DI-25 writable entries under /proc/self | holds | [R] after execve dumpable is 1, and the entries' owner is u (fs/proc/base.c::task_dump_owner); the list of writable entries is in 01 NB-DI-25 (v8 added loginuid); the effects of writing them are judged in each cell (the write row of 01-trace-events §1.1) | fs/proc/base.c; NB-DI-25 | not tested: the effects are in the chapters |
| NB-DI-26 inherited attributes | holds | [R] item by item, see the items of §2.1 from "process group, session and controlling terminal" to the last row | NB-DI-26 | not tested: see each item |
| NB-DI-27 the same btrfs file system | holds | [R] catalog loading checks only the workspace subvolume root (catalog L311–334), not whether the file system is exclusive; the workspace of the diagnostic catalog is on the same file system as the store and the seed; what is shared is aggregate state such as free space, transactions and metadata trees, which gives no new references; the candidate effects are judged in the cells of column N-06 | catalog; NB-DI-27; NB-MM-11 | not tested: the effect is in the GS chapter |
| NB-DI-28 the channel belongs to the host net namespace | holds | [R] the spawner creates the socketpair in the host net ns before clone (spawner L113, L128); both ends are unnamed; the host side can list it; from the agent side it can only read and write this one connection | spawner; NB-DI-28 | not tested: source reading only |

#### 2.3 Each step of construction

Each step checks four things: host sources, recursive submounts, name resolution between checking and use, and the state after failure. The basis of each step states each of these four things; one that is not involved is written "not involved", with a reason (review one, Claude's comment 7). The construction window (clone to execve) is split into two items. One item, that only trusted code runs, is checked against the code. The effects other subjects can exert during the window are another item, handed as an interference obligation to the PS and LC chapters (Codex's comment R5).

| Initial-state item | Record | Basis | Dependencies | Test |
|---|---|---|---|---|
| NB-K-01 w2-cell start | holds | [R] Host sources: the start parameters (deployment root, catalog, the engine's uid and gid, the engine executable path) are given by the launcher's parent process (cell L14–16); the catalog is read from the deployment root under /var/lib, and every ancestor along the way must be root-owned and not group- or other-writable (catalog L42–59, L263–363); inherited fds are first removed with close_range(3) (cell L19), the environment bytes are wiped and clearenv is called (cell L28–29), capabilities are limited to six (cell L29, L31), and an engine uid or gid equal to overflow or to any workspace's is refused (cell L32–33). Recursive submounts: not involved, this step does not mount. Between checking and use: the catalog is read into memory once before fork (cell L31); the spawner uses the copy from fork and does not reread the catalog by name afterwards, and the paths in the catalog are checked by identity separately when they are used (NB-K-04, NB-K-07); the engine executable is resolved by host path at execv (cell L54), and this path is given by the offline deployer (NB-AA-07). Failure: if any step before fork fails, it returns and does not fork the spawner (cell L14–35); if the parent side fails after fork (cell L49–54), the engine does not start, and the spawner, after reading EOF on the control end (spawner L139–142), marks control as lost (spawner L408, L451–452) and finishes as in NB-K-16 | cell; catalog; spawner; NB-K-01; NB-K-04; NB-K-07; NB-K-16; NB-AA-07 | not tested: source reading only |
| NB-K-02 spawner initialisation and the file worker | holds | [R] spawner L396–404: SIGCHLD is set to SIG_DFL, the mask is cleared, no signal handlers are installed; the worker is forked before sensitive state appears, drops to 0:0 with no capabilities (storage L194–210, L264–270), and does not hold the engine's control end (storage L269). Host sources: the store's lock file, the root and objects directories, and the seed trees are all accessed through fds opened when the catalog was loaded; the spawner holds store.lock exclusively with flock (storage L266); at init the worker checks the store's dev, ino, owner, permissions and file-system identity (storage L185–191, L205) and that objects is empty (storage L205), and checks the seed tree by tree (storage L206). Recursive submounts: not involved, this step does not mount; afterwards the worker always opens paths through tree_open, with RESOLVE_BENEATH and RESOLVE_NO_XDEV, not crossing mounts (catalog L132–140). Between checking and use: the worker rechecks the store's identity before each job (storage L242) and resolves by fd, not by absolute host path. Failure: if flock, socketpair or fork fails, the spawner marks the store as dead and marks control as lost (spawner L403); admission requires the store to be ready (spawner L93), so no spawn is accepted; if the worker's checks fail, it reports ok=false and exits (storage L209–210) | spawner; storage; catalog; NB-K-02; NB-S-06 | not tested: source reading only |
| NB-K-03 admission: at any one time only one live execution with the same uid, the same gid or the same workspace | holds | [R] spawner L83–92: the uid and gid equal the values of the workspace in the plan and are not overflow; the request is refused if it shares the uid, the gid or the workspace with any record not yet cleared; clearing requires PID 1 to have been reaped (spawner L373–382); leftovers across epochs are excluded by the cgroup.kill and populated 0 of NB-K-16, which depends on the premises NB-AA-05, NB-AA-06. Host sources: the spawn request comes from the engine's control message (the engine is a trusted party, NB-AA-07); the plan is looked up by id and digest in the catalog read at start (spawner L81; catalog L395–398). Recursive submounts: not involved. Between checking and use: the spawner is a single-threaded polling loop (spawner L405–458); the check and the registration complete within the same spawn call, with no other message handled in between; the slot is marked as used before the check (spawner L75), and later requests can see it. Failure: fail_record marks the record as failed and stopped, closes the channel, and clears it when there is no pid (spawner L53–58); no space is reserved and no clone happens (spawner L85, L90, L96) | spawner; catalog; NB-K-03; NB-K-16; NB-AA-05; NB-AA-06; NB-AA-07 | not tested: source reading only; the cases of successors and epochs are in the LC chapter |
| NB-K-04 copy creation | holds | [R] catalog L399–429: mkdirat a new directory under objects (it fails if the directory exists), create each file with O_CREAT and O_EXCL, FICLONE, check the digest, fchmod, and finally tree_check verifies that no inode is shared with the seed; the worker runs as 0:0 with umask 0 (storage L194–199). Host sources: the objects directory and the seed trees are accessed through fds opened when the catalog was loaded; before each job the store's identity is rechecked and the free space is checked (storage L241–245). Recursive submounts: tree_open uses RESOLVE_BENEATH and RESOLVE_NO_XDEV and does not cross mounts (catalog L132–140); the copy directory is newly created by the worker (catalog L402), and there are no mounts under it. Between checking and use: as soon as the new directory is created, its dev and ino are recorded (catalog L402–406), and child compares this identity before mounting (NB-K-07); file contents are checked against the manifest digest after the reflink (catalog L420); the objects directory is root-owned, 0700 (storage L189), so between recording the identity and mounting only root can replace the copy, which depends on the premise NB-AA-01. Failure: the worker reports failed (the root directory was already created) or not_materialized (storage L251–255); the spawner fails this spawn, and what was already created is left to be deleted and is cleaned up by the deletion job (spawner L295–298, L319–337; NB-K-14) | catalog; storage; spawner; NB-K-04; NB-K-07; NB-K-14; NB-DI-18; NB-AA-01 | not tested: source reading only |
| NB-K-05 before clone | holds | [R] spawner L112–132: socketpair, SO_PASSCRED only on the engine end, a check of the buffer limits, clone creating four new namespaces; if any step fails, both ends are closed and no half-made record is left (spawner L133–135). Host sources: the socketpair is created in the host net namespace where the spawner is (spawner L113); the new mount namespace is a copy of the host mount tree, and the host mounts in it are set to private in NB-K-07 and detached after pivot; the two source paths used for mounting are assembled from the catalog root and copy_id (spawner L108–111); here they are only assembled as strings, not resolved, and child uses them only after comparing by identity (NB-K-07). Recursive submounts: not involved, this step does not mount. Between checking and use: not involved, this step opens no object by name. Failure: see above | spawner; NB-K-05; NB-K-07 | not tested: source reading only |
| NB-K-06 child closes the fds that do not belong to it | holds | [R] spawner L50 closes the engine end, the control fd, the worker fd and the store lock fd; the catalog and objects fds are kept for construction and are closed together in the close_range(4,~0) of NB-K-08 (child L103). Host sources: not involved, this step opens no object. Recursive submounts: not involved. Between checking and use: not involved, it closes by fd number and resolves no names. Failure: these few closes do not check their return values; any that is missed is caught by the close_range at child L103 (whose failure goes to FAIL) | spawner; child; NB-K-06; NB-K-08 | not tested: source reading only |
| NB-K-07 construction mounts | holds | [R] Host sources: the runtime is opened under the objects fd and compared with the identity the worker recorded (child L39–43); the workspace is opened through w2_workspace_open and compared (catalog L366–376); the four device nodes are bound by host path /dev/\<name\> (child L66–75); at this point the mount namespace is still a copy of the host mount tree, and host /dev is maintained by host init (NB-S-08); proc and the four tmpfs are new instances (child L45, L64–65, L76–78). Recursive submounts: a recursive bind would bring them in, which depends on the premise NB-AA-02. Between checking and use: mount_fd compares the identity and then binds by path (child L19–31); in the window only someone with write permission on a root-owned ancestor can replace the path (support L172–190), which depends on the premise NB-AA-01. Failure: TRY jumps to FAIL when any step fails or times out; after FAIL is sent, _exit(125), and no exec (child L18, L113–119); half-made mounts are destroyed together with the mount namespace | child; catalog; support; NB-K-07; NB-S-08; NB-AA-01; NB-AA-02 | not tested: source reading only; the result of a successful construction is in the mount-table item |
| NB-K-08 lo, stdio, fd 3, the core limit | holds | [R] child L83–103. Host sources: /dev/null is opened by sandbox path after pivot; it is the same host device bound in by NB-K-07 (child L88, L66–75); a temporary AF_INET socket is created in this net namespace and closed after use (child L83–87). Recursive submounts: not involved. Between checking and use: /dev/null is resolved by sandbox path; at this point only root can change /dev in the sandbox tree (the tmpfs /dev is root-owned, 0755, child L65), and child is still root and runs only trusted code. Failure: if any TRY step fails, it goes to FAIL, _exit(125), and no exec (child L18, L113–119); [M] NB-EV-015, NB-EV-016 | child; NB-K-07; NB-K-08; NB-EV-015; NB-EV-016 | NB-EV-015; NB-EV-016 |
| NB-K-09 the order of dropping privileges and the filter | holds | [R] child L104–105 first drops privileges (support L237–261), then installs the filter; from installation the filter is in force for every later system call, including execve. Host sources: the filter program is compiled by the catalog, sealed through memfd and read into the spawner's memory (NB-DI-08); child uses the copy from fork (child L105). Recursive submounts: not involved. Between checking and use: not involved, this step resolves no names. Failure: if dropping privileges or installing the filter fails, it goes to FAIL, and no exec (child L104–105, L113–119); [M] NB-EV-015 | child; support; NB-K-09; NB-DI-08; NB-EV-015 | NB-EV-015 |
| NB-K-10 SEALED, COMMIT and execve | holds | [R] child L106–112: SEALED is sent over fd 3; only after receiving COMMIT in full does child chdir to /work and execve the executable the catalog registers; failure goes to FAIL (child L113–119); at catalog load the executable and interpreter were checked for ELF64 x86_64 and for the position of PT_INTERP (catalog L224–256). Host sources: the executable, argv and env are taken from the catalog's runtime description (child L112); COMMIT is sent by the spawner over fd 3 after it checks SEALED and the peer credentials (NB-K-11). Recursive submounts: not involved. Between checking and use: the ELF check at catalog load is done on the seed; at execve the executable is resolved by sandbox path from the /runtime copy; at creation the copy's bytes were checked against the manifest digest to be the same as the seed's (catalog L420); /runtime is an ro mount, the copy is 0:0 with read-only permission bits, child has already dropped privileges at this point, and on the host only root can change the copy, which depends on the premise NB-AA-01. Failure: a failure to send SEALED, to receive COMMIT or of execve all go to FAIL, _exit(125) (child L108–119) | child; catalog; NB-K-10; NB-K-11; NB-DI-17; NB-AA-01 | not tested: source reading only |
| the construction window runs only trusted code (NB-AA-04 checked against the code) | holds | [R] between clone and execve only the spawner's child_entry and w2_child_launch run (spawner L49–52; child L38–119); if any step fails it goes to FAIL and then _exit(125), and no exec (child L113–119); NB-AA-04 claims only this (review one, Codex's comment R5); the effects other subjects can exert in the window are the next item | spawner; child; NB-AA-04 | not tested: source reading only |
| effects of other subjects on child during the construction window (interference obligation, handed to PS and LC) | undetermined | [R] Effect paths found so far (review one, Claude's comment 8, Codex's comment R5): signals sent by pid cannot reach child, which is in a new pid namespace, and the namespaces of other executions have no number for it; signals sent by process group can reach it: child stays in the spawner's process group and session (NB-DI-10), and kill(0) walks the whole process group regardless of pid namespace (kernel/signal.c::__kill_pgrp_info); permission is judged by uid; before dropping privileges child is uid 0 and after it is u, and there is no other live execution with the same uid (spawner L87–92, premise NB-AA-05), but SIGCONT within the same session is not judged by uid (kernel/signal.c::check_kill_permission; the kill row of the system-call table), so other executions can deliver SIGCONT to child; when SIGCONT arrives it clears pending stop signals and wakes stopped threads (kernel/signal.c::prepare_signal); child is the init of a new pid namespace and has SIGNAL_UNKILLABLE (kernel/fork.c::copy_process); signals whose disposition is the default are not queued for it (kernel/signal.c::sig_task_ignored), and neither cell nor the spawner installs signal handlers (cell L13–55; spawner L400–402), so child's dispositions are only default and ignore; the SIGHUP and SIGCONT the kernel sends to orphaned process groups (NB-E-P-03) reach this process group too; when machine-wide aggregate state (memory, pid numbers, shared btrfs space) is used up, construction can fail, and failure goes to FAIL, with no execve. Whether these effects can change the state at execve is decided, as interference obligations, by the PS chapter in the cells NB-E-S-kill × NB-N-07 and NB-E-P-03 × NB-N-07, and by the LC chapter in the cells of NB-K-03…10 (construction for another execution, §1.3); after the decision, this item is filled in | kernel/signal.c; kernel/fork.c; spawner; cell; NB-DI-10; NB-AA-05; NB-E-P-03; NB-E-S-kill; NB-N-07; NB-K-03; NB-K-10 | not tested: decided in the PS and LC chapters |

#### 2.4 Prior state the attacker has shaped

| Initial-state item | Record | Basis | Dependencies | Test |
|---|---|---|---|---|
| /work as written by a predecessor execution | holds | [R] the successor's construction checks only the workspace subvolume root (catalog L366–376: btrfs, dev, ino, owner, 0700) and does not read its contents; L has no calls for mkdir, symlink, link, rename, mknod, chmod, chown or changing xattrs, so in /work the predecessor can only create and write regular files and give permission bits at creation (subject to umask), and cannot change the owner and permissions of the subvolume root; a setuid bit given at creation has no effect on a nosuid mount (child L32); the successor reading the contents is the expected behaviour of the delivered object (NB-X-08) | catalog; child; NB-K-15; NB-X-08; L (whole table) | not tested: the successor's tests are in the LC chapter |
| concurrent executions occupying the shared btrfs | holds | [R] before creating a copy, the worker checks with fstatvfs that the free space is at least the copy's size plus a minimum margin (storage L240–246), and fails this spawn if not; space and transactions are aggregate state and give no new references; the availability side is classed as host-level denial of service under README §6 (NB-X-04) | storage; NB-X-04; NB-DI-27 | not tested: availability is not tested (TESTING run rule 4) |
| same-uid tasks left by a predecessor or an old epoch | holds | [R] admission requires the previous record of the same workspace to be cleared (spawner L87–92); clearing requires PID 1 to have been reaped, and after PID 1 dies everything in the ns is killed (kernel/pid_namespace.c::zap_pid_ns_processes); at an epoch change the supervisor writes cgroup.kill and waits for populated 0 (NB-K-16); that the uid is not reused on the host is the premise NB-AA-05 | spawner; kernel/pid_namespace.c; NB-K-16; NB-AA-05; NB-AA-06 | not tested: in the LC chapter |

#### 2.5 References held by trusted parties

| Initial-state item | Record | Basis | Dependencies | Test |
|---|---|---|---|---|
| spawner | holds | [R] the spawner holds child_pid and uses it only for kill and waitpid (spawner L344–395); this number is not reused before PID 1 is reaped; before hand-over it holds the engine end of the channel, and it closes it after hand-over (spawner L251); nowhere in spawner.c is there code that opens /proc/\<pid\>; child's mounts, tmpfs and namespaces leave no fd in the spawner | spawner; NB-S-05; NB-PV-01; NB-PV-08 | not tested: source reading only |
| engine | holds | [R] the engine holds the peer end of the channel; receiving on the channel goes w2_frame_receive → w2_recv_credential (transport.c L212–240, L151–161), which calls w2_ancillary with credentials=true (L158, L160), and this path closes every SCM_RIGHTS fd received (L119–120); the branch in w2_ancillary that hands the single fd to the caller (L121) is taken only when credentials=false; its callers are w2_recv_control on the control channel (L135–146; the engine uses it through ffi.py L62 to receive spawn_prepared, and the channel end in it, from the spawner, and spawner.c L139 uses it too) and w2_recv_fixed (L193–208, which closes any fd it receives and reports an error); the latter is what child uses to receive COMMIT on fd 3 during the construction handshake (child.c L109). The three places must be kept apart (corrected by the targeted re-review): w2_recv_control on the control channel can hand over one fd; w2_recv_fixed in the construction handshake and w2_frame_receive, with which the engine receives agent data at run time, both close the fds they receive; the engine sends without ancillary data (transport.c L247–260) and passes no fd on to anyone | transport.c; ffi.py; spawner; child; NB-S-04; NB-PV-04; NB-PV-08 | not tested: tested in the NI chapter |
| file worker | holds | [R] the worker holds only the fds of the store, the seed and copy jobs (storage L194–270), and closes them after the copy is deleted (catalog L431–493); it holds no fd, mount or process reference of the execution | storage; catalog; NB-S-06 | not tested: source reading only |
| launcher and supervisor | holds | [R] once the launcher has exec'd into the engine, it no longer exists (cell L54); the supervisor holds only the cell cgroup, and its correct behaviour is a premise (NB-AA-07) | cell; NB-S-07; NB-S-08; NB-AA-07 | not tested: premise |
| w2-recover (NB-S-16) | holds | [R] w2-recover and the spawner both take store.lock with LOCK_EX and LOCK_NB (storage L266, L308): while any execution is being constructed or is running, the spawner holds this lock, and if w2-recover cannot take it, it returns failure (recover L12–14); it is run by the deployer after an epoch change, and "the supervisor has confirmed that the old domain is empty" is a premise (NB-AA-07): recover L8–9 only checks whether this flag is on the command line, and L15 states that this is provided by the supervisor and that the program does not infer it (corrected by the targeted re-review); it opens only the catalog, the store, and the copy roots under objects (storage L307–340), and holds no fd, mount or process reference of any execution (review one, Claude's comment 9) | recover; storage; NB-S-16; NB-K-16; NB-AA-07 | not tested: source reading only |
| core dump handler (NB-S-09) | holds | [R] the kernel starts it, and it receives the core through a pipe, only when the kernel takes a pipe-style core_pattern; this execution's RLIMIT_CORE is 1, soft and hard, and the kernel gives up before calling it (fs/coredump.c::do_coredump; child L103; NB-E-K-01), so in the initial state it holds no reference of this execution; what it would read is judged by the cells of column NB-N-12 (review one, Claude's comment 9) | fs/coredump.c; child; NB-S-09; NB-E-K-01; NB-N-12 | NB-EV-016 (core limit 1 1) |
| host cleanup and backup (NB-S-15): construction hands it no references | holds | [R] it is not in the baseline snapshot and is arranged by the deployer (NB-S-10); the spawner and child contain no code that interacts with it, and construction hands it no fd, mount or process reference; the state shaped by the execution that it reads later is judged by the cells of column NB-N-10, and its own behaviour is a deployment precondition (NB-AA-07; review one, Claude's comment 9) | spawner; child; NB-S-15; NB-S-10; NB-N-10; NB-AA-07 | not tested: source reading only |
| host observation component (NB-S-17): construction hands it no references | holds | [R] it is not in the baseline snapshot; the spawner and child contain no code that interacts with it, and construction hands it no fd, mount or process reference. What it receives from the kernel at run time is handed to cells such as NB-E-K-09 × N-13; only two checked facts are recorded here (rewritten by the third targeted re-review). A file event is dispatched to every group that has set a mark on the file's inode, its directory, its mount or its file system (fs/notify/fsnotify.c::fsnotify); which events a group receives is decided by the effective coverage of its marks, and an inode mark set on a directory also receives events for the children in the directory; dispatch carries the path of the accessor's file (include/linux/fsnotify.h::fsnotify_file), and when fanotify reads an event, it opens an fd by the path in the event with the reader's credentials (fs/notify/fanotify/fanotify_user.c::create_fd). Only for path-type events (the group is not in FID mode, and the object is a regular file or a directory: fs/notify/fanotify/fanotify.c::fanotify_group_event_mask, which filters before the event is allocated) does fanotify store this path and take a reference (fs/notify/fanotify/fanotify.c::fanotify_alloc_path_event); so while such an event is in the queue it pins the execution mount the event went through, and the fd opened after it is read pins it too; in this configuration these are the binds of /work and /runtime (this scope is derived by combining construction and the premises; its conditions are written in 01 NB-E-K-09, and it is not the basis of this item); the four character devices under /dev produce no events of this type. FID-mode events take another branch, and their reference kind is checked in the cell NB-E-K-09 × N-13; the pidfd attached to an event keeps only an identity reference to the struct pid, and keeps neither the task nor the address space alive (corrected by the fourth targeted re-review). Who can set which marks, and who can receive events with fds, is written in the premises of 01 §6.1 and not expanded here; the fields in the records that the execution sets are judged by the cells of column NB-N-13, and what the components do after reading them is a deployment precondition (NB-AA-07) | spawner; child; fs/notify/fsnotify.c; include/linux/fsnotify.h; fs/notify/fanotify/fanotify_user.c; fs/notify/fanotify/fanotify.c; NB-S-17; NB-E-K-09; NB-N-13; NB-AA-07 | not tested: source reading only |

#### 2.6 Allocation of NB-AA

| NB-AA | Assigned to | Where it lands |
|---|---|---|
| NB-AA-01 no replacement in the source trees | premise list (the deployer prepares them offline and does not change them at run time; the code narrows the window by identity comparison to the interval between comparison and bind, and in the window only root can replace) | §2.1 the /work and /runtime items; §2.3 NB-K-07 |
| NB-AA-02 no submounts in the source trees | premise list (deployer) | §2.1 the mount-table and /runtime items; §2.2 NB-DI-21; §2.3 NB-K-07 |
| NB-AA-03 no shared writable mapping | initial state, checked against the code | §2.1 the item on the address space after execve |
| NB-AA-04 trusted code segment | initial state, checked against the code (it claims only that this segment runs only trusted code) | §2.3 the item that the construction window runs only trusted code; the effects of other subjects in the window are another item, recorded as undetermined and handed as an interference obligation to PS and LC |
| NB-AA-05 exclusive pool, and the uid not reused on the host | premise list (deployer; a premise of T-67 of the uid line, carried over by 1.1) | §2.3 the NB-K-03 and construction-window items; §2.4 the same-uid leftovers item |
| NB-AA-06 cell cgroup | split into two halves: that host init places the cell in an exclusive cgroup is in the premise list (supervisor); that the agent cannot migrate out is checked against the code | §2.1 the cgroup-membership item; §2.3 NB-K-03; §2.4 the same-uid leftovers item |
| NB-AA-07 trusted parties are not controlled by the attacker and do not act maliciously | the premise list contains only the hypervisor and firmware, the supervisor and the offline deployer; the code of the engine, spawner, file worker, launcher and w2-recover is checked with [R] against the baseline snapshot (the items of this section and the chapters) | §2.5 the items for the launcher and supervisor, w2-recover, host cleanup and backup, and the host observation component |
| NB-AA-08 privileged host processes do not take, read or write private candidates | premise list (deployer; the constrained objects are written as a conservative upper bound, see 01 §6.1): host processes outside the baseline snapshot whose credentials can pass, or can be exchanged for credentials that pass, the ptrace access check on an execution's tasks, and processes that hold a privileged fanotify group, do not take or read the execution's private candidates by any path; the deployer lists these processes and checks them one by one | not in the initial-state tables: the initial state only proves what construction handed over (§2.5). It lands on the judgement of privacy: the part of 01 §2.6 that the host can reach only with privilege, and NB-PV-02; the cells of the block-two chapters that record "private" write NB-AA-08 in their dependencies (§3.7). The part the host can see without privilege does not rely on it and counts as host-observable under the rule of 01 §2.6 |
| NB-AA-09 the host does not enable user-mode reading of performance counters | premise list (deployer; the author, 2026-10-27): the sysfs value of rdpmc is not set to 2 (see 01 §6.1) | not in the initial-state tables: it lands on the destination of RDPMC (01-trace-events §3.4); with the default value, an execution that executes RDPMC triggers #GP |

**Deployment conditions (not premises; their values must be read).** The rlimit, umask, signal dispositions, loginuid and controlling terminal inherited from the launcher's parent process (NB-MM-01, 02, 04, 05), and the TSC-disable flag (§2.1, added by the second targeted re-review), do not affect I1–I3 of the initial state, but they affect the candidate effects of the cells. Their production values, and the pending items for host readings (01-trace-events §7), are written in the GS chapter and in the deployment limits of the summary.

**Items handed over by the S1 supplement.** The initial-state assertion handed over from the destination table: §2.1, the address-space item. Two factual corrections: §2.1, the pdeath_signal and loginuid items (01 v8, the system-call table v5). NB-AA-01, NB-AA-02: §2.6.

### 3 Decomposition of bad events (backbone lower half)

**Purpose.** Each row × each column of 01 is split into branches, and each branch is assigned to one chapter, which writes its cell (the rule of PLAN §1.2). A (row, column) pair that forms no branch is covered by a not-applicable item or by a column not-applicable rule. `check_coverage.py --stage backbone` checks the coverage mechanically; whether the rules and reasons hold is checked by review one. Multiplexed calls are split into sub-operation rows, with the sub-operations taken from the dispatch locations of the baseline kernel (§3.3). The values newly derived beyond the system-call table, and the /OTHER rows, have been traced further under the tracing rule (01-trace-events §8); there are no new events of the four families.

#### 3.1 Entries of L and ABI entries

**The 74 allowed entries of L.** They are taken from the diagnostic allow list at lines 117–130 of run_sandbox_checks.py in the baseline snapshot, and match the list of 01 §3.1 one by one. Each entry falls in exactly one row of [the system-call table](#the-74-system-calls) (checked by script on 2026-10-25: 74 entries, 45 rows, none missing, none duplicated).

| Row of 01 | Entries of L |
|---|---|
| NB-E-S-openat | openat |
| NB-E-S-read | read, readv |
| NB-E-S-write | write, writev |
| NB-E-S-close | close |
| NB-E-S-fstat | fstat, newfstatat, statx |
| NB-E-S-lseek | lseek |
| NB-E-S-access | access, faccessat2 |
| NB-E-S-getdents64 | getdents64 |
| NB-E-S-readlink | readlink, readlinkat |
| NB-E-S-chdir | chdir |
| NB-E-S-getcwd | getcwd |
| NB-E-S-fsync | fsync, fdatasync |
| NB-E-S-execve | execve |
| NB-E-S-mmap | mmap |
| NB-E-S-mprotect | mprotect |
| NB-E-S-munmap | munmap |
| NB-E-S-brk | brk |
| NB-E-S-madvise | madvise |
| NB-E-S-clone | clone |
| NB-E-S-unshare | unshare |
| NB-E-S-exit | exit, exit_group |
| NB-E-S-wait4 | wait4, waitid |
| NB-E-S-kill | kill |
| NB-E-S-tgkill | tgkill |
| NB-E-S-setsid | setsid |
| NB-E-S-rt_sigaction | rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack, pause, restart_syscall |
| NB-E-S-getpid | getpid, getppid, gettid |
| NB-E-S-getuid | getuid, geteuid, getgid, getegid, getresuid, getresgid, getgroups |
| NB-E-S-setuid | setuid |
| NB-E-S-prlimit64 | prlimit64 |
| NB-E-S-prctl | prctl |
| NB-E-S-arch_prctl | arch_prctl |
| NB-E-S-set_tid_address | set_tid_address, set_robust_list, rseq |
| NB-E-S-futex | futex |
| NB-E-S-sendmsg | sendmsg, sendto |
| NB-E-S-recvmsg | recvmsg, recvfrom |
| NB-E-S-getsockopt | getsockopt |
| NB-E-S-getsockname | getsockname, getpeername |
| NB-E-S-shutdown | shutdown |
| NB-E-S-poll | poll, ppoll |
| NB-E-S-clock_gettime | clock_gettime |
| NB-E-S-nanosleep | nanosleep, clock_nanosleep |
| NB-E-S-getrandom | getrandom |
| NB-E-S-uname | uname |
| NB-E-S-fcntl | fcntl |

**ABI entries.** Besides the x86_64 syscall instruction, user mode can enter the kernel through the following entries. The destination of each is given.

| Entry | Destination | Basis |
|---|---|---|
| the x86_64 syscall instruction | the rows of the table above; the filter judges by call number | policy L13–67; kernel/seccomp.c::__seccomp_filter |
| int 0x80, syscall in 32-bit mode, and sysenter (from whichever mode it is executed, it enters the 32-bit compatibility entry: arch/x86/kernel/cpu/common.c::syscall_init, arch/x86/entry/common.c::do_SYSENTER_32; added 2026-10-27) | the filter kills the process for an architecture mismatch (SCMP_ACT_KILL_PROCESS), going to NB-E-K-01 | policy L35; arch/x86/kernel/idt.c::def_idts; NB-EV-015 |
| x32 call numbers (with __X32_SYSCALL_BIT) | as above, killed | policy L35; NB-EV-015 |
| the vsyscall page (vsyscall=none) | not an entry: the access faults, is logged, and SIGSEGV is sent as for an invalid access (01-trace-events §3.1) | arch/x86/entry/vsyscall/vsyscall_64.c::emulate_vsyscall |
| exception vectors | not a system-call entry: vector by vector in 01-trace-events §3.1 | arch/x86/kernel/idt.c::def_idts |

#### 3.2 Trusted-party columns of step 4

SPEC §4.2 step 4: state that the execution shapes in delivered objects and that a trusted party other than the engine later reads or operates on gets one column per trusted party. NB-N-09…11 are taken from the items handed over by 01-trace-events §7, and NB-N-12 is the core dump handler. NB-N-13 was added by review one (2026-10-26): the components on the host that read the records and events the kernel sends out. METHOD rule 2 counts them as trusted parties that later act on state the execution shaped, and their own behaviour is written as a deployment precondition under SPEC §5.1 (01 NB-S-17, NB-AA-07).

| Column ID | Trusted party | The state shaped by the execution that it later dereferences | Source |
|---|---|---|---|
| NB-N-09 | the construction and run (NB-K-15) of a successor execution (NB-S-03) | the content and metadata the previous execution left in the workspace: files, permission bits, timestamps; the successor's construction checks only the subvolume root | 01-trace-events §7; SPEC §4.2 step 4 |
| NB-N-10 | host cleanup and backup (NB-S-15) | the content and metadata in the workspace; record locks and leases met when opening workspace files | as above |
| NB-N-11 | supervisor (NB-S-08) | the populated of the cell cgroup (decided by the creation and exit of tasks in the cell) and the objects cgroup.kill acts on | as above; NB-K-16 |
| NB-N-12 | the host core dump handler (NB-S-09) | the core content sent to it under a pipe-style core_pattern; when RLIMIT_CORE is 1 the kernel gives up before calling it (NB-E-K-01) | SPEC §4.2 step 4 |
| NB-N-13 | the host observation component (NB-S-17), defined as in 01 §1 NB-S-17: a component the deployer installs, that reads the records and events the kernel sends out or reads the execution's /proc entries, and whose handling is a deployment precondition; host processes and users that the deployer did not install belong to NB-S-14 and are judged in the cells of N-06 (corrected by two targeted re-reviews) | the fields set by the execution in the records and events the kernel sends them: comm, exe path, exit code, loginuid and sessionid, file names and event types; for fanotify permission events, the operation continues only after the component answers | review one (Claude's comment 5); METHOD rule 2; 01-trace-events §5 NB-E-K-09…14 |

#### 3.3 Sub-operation table

| Call row | Sub-operation row | Dispatch location | Values included |
|---|---|---|---|
| NB-E-S-fcntl | NB-E-S-fcntl/F_DUPFD | fs/fcntl.c::do_fcntl: case F_DUPFD, F_DUPFD_CLOEXEC → fs/file.c::f_dupfd | F_DUPFD_CLOEXEC |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETFD | fs/fcntl.c::do_fcntl: case F_GETFD, F_SETFD | F_GETFD |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETFL | fs/fcntl.c::do_fcntl: case F_GETFL, F_SETFL → fs/fcntl.c::setfl | F_GETFL |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETLK | fs/fcntl.c::do_fcntl: case F_GETLK, F_SETLK, F_SETLKW, F_OFD_* → fs/locks.c::fcntl_getlk, fs/locks.c::fcntl_setlk | F_GETLK, F_SETLKW, F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETOWN | fs/fcntl.c::do_fcntl: case F_GETOWN, F_SETOWN, F_GETOWN_EX, F_SETOWN_EX, F_GETOWNER_UIDS → fs/fcntl.c::f_setown, fs/fcntl.c::f_setown_ex | F_GETOWN, F_GETOWN_EX, F_SETOWN_EX, F_GETOWNER_UIDS |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETSIG | fs/fcntl.c::do_fcntl: case F_GETSIG, F_SETSIG | F_GETSIG |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETLEASE | fs/fcntl.c::do_fcntl: case F_GETLEASE, F_SETLEASE → fs/locks.c::fcntl_setlease | F_GETLEASE |
| NB-E-S-fcntl | NB-E-S-fcntl/F_NOTIFY | fs/fcntl.c::do_fcntl: case F_NOTIFY → fs/notify/dnotify/dnotify.c::fcntl_dirnotify | — |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETPIPE_SZ | fs/fcntl.c::do_fcntl: case F_SETPIPE_SZ, F_GETPIPE_SZ (returns an error for anything that is not a pipe) | F_GETPIPE_SZ |
| NB-E-S-fcntl | NB-E-S-fcntl/F_ADD_SEALS | fs/fcntl.c::do_fcntl: case F_ADD_SEALS, F_GET_SEALS (valid only for memfd) | F_GET_SEALS |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SET_RW_HINT | fs/fcntl.c::do_fcntl: case F_GET_RW_HINT, F_SET_RW_HINT → fs/fcntl.c::fcntl_rw_hint | F_GET_RW_HINT |
| NB-E-S-fcntl | NB-E-S-fcntl/OTHER | fs/fcntl.c::do_fcntl: default: returns EINVAL | the remaining cmd values |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_NAME | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_NAME, PR_GET_NAME | PR_GET_NAME |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_PDEATHSIG | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_PDEATHSIG, PR_GET_PDEATHSIG | PR_GET_PDEATHSIG |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_CHILD_SUBREAPER | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER | PR_GET_CHILD_SUBREAPER |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_DUMPABLE | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_DUMPABLE, PR_GET_DUMPABLE | PR_GET_DUMPABLE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_PTRACER | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: Yama: security/yama/yama_lsm.c::yama_task_prctl | PR_SET_PTRACER_ANY |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_TIMERSLACK | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_TIMERSLACK, PR_GET_TIMERSLACK | PR_GET_TIMERSLACK |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_THP_DISABLE | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_THP_DISABLE, PR_GET_THP_DISABLE | PR_GET_THP_DISABLE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_SPECULATION_CTRL | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_SPECULATION_CTRL, PR_GET_SPECULATION_CTRL → arch/x86/kernel/cpu/bugs.c::arch_prctl_spec_ctrl_set | PR_GET_SPECULATION_CTRL |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_SYSCALL_USER_DISPATCH | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_SYSCALL_USER_DISPATCH → kernel/entry/syscall_user_dispatch.c::set_syscall_user_dispatch | — |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_VMA | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_VMA (CONFIG_ANON_VMA_NAME is not enabled; returns EINVAL) | — |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_MDWE | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_MDWE, PR_GET_MDWE | PR_GET_MDWE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_SECCOMP | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_SECCOMP, PR_GET_SECCOMP → kernel/seccomp.c::prctl_set_seccomp | PR_GET_SECCOMP |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_NO_NEW_PRIVS | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS | PR_GET_NO_NEW_PRIVS |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_KEEPCAPS | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: commoncap: PR_SET_KEEPCAPS, PR_GET_KEEPCAPS of security/commoncap.c::cap_task_prctl | PR_GET_KEEPCAPS |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_TSC | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_TSC, PR_GET_TSC → arch/x86/kernel/process.c::set_tsc_mode | PR_GET_TSC |
| NB-E-S-prctl | NB-E-S-prctl/PR_MCE_KILL | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_MCE_KILL, PR_MCE_KILL_GET | PR_MCE_KILL_GET, PR_MCE_KILL_CLEAR, PR_MCE_KILL_SET |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_FP_MODE | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: architecture-specific values that return EINVAL on x86 (each with its own default macro in sys.c) | PR_GET_FP_MODE, PR_SET_UNALIGN, PR_GET_UNALIGN, PR_SET_FPEMU, PR_GET_FPEMU, PR_SET_FPEXC, PR_GET_FPEXC, PR_SET_ENDIAN, PR_GET_ENDIAN, PR_MPX_ENABLE_MANAGEMENT, PR_MPX_DISABLE_MANAGEMENT, PR_SVE_SET_VL, PR_SVE_GET_VL, PR_SME_SET_VL, PR_SME_GET_VL, PR_PAC_RESET_KEYS, PR_PAC_SET_ENABLED_KEYS, PR_PAC_GET_ENABLED_KEYS, PR_SET_TAGGED_ADDR_CTRL, PR_GET_TAGGED_ADDR_CTRL, PR_RISCV_V_SET_CONTROL, PR_RISCV_V_GET_CONTROL |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_MM | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: values that need CAP_SYS_RESOURCE: case PR_SET_MM → the arg2 values of kernel/sys.c::prctl_set_mm other than PR_SET_MM_MAP and PR_SET_MM_MAP_SIZE (a failed capability check returns EPERM); case PR_SET_IO_FLUSHER, PR_GET_IO_FLUSHER | PR_SET_IO_FLUSHER, PR_GET_IO_FLUSHER |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_MM_MAP | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_MM → kernel/sys.c::prctl_set_mm: when arg2 is PR_SET_MM_MAP or PR_SET_MM_MAP_SIZE, it goes to kernel/sys.c::prctl_set_mm_map before the capability check (CONFIG_CHECKPOINT_RESTORE=y) | PR_SET_MM_MAP_SIZE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_MEMORY_MERGE | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_MEMORY_MERGE → mm/ksm.c::ksm_enable_merge_any, mm/ksm.c::ksm_disable_merge_any (no capability check); case PR_GET_MEMORY_MERGE | PR_GET_MEMORY_MERGE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_SECUREBITS | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: commoncap: PR_SET_SECUREBITS and PR_CAPBSET_DROP need CAP_SETPCAP; the RAISE of PR_CAP_AMBIENT needs the capability to be already in permitted and inheritable | PR_GET_SECUREBITS, PR_CAPBSET_DROP, PR_CAPBSET_READ, PR_CAP_AMBIENT |
| NB-E-S-prctl | NB-E-S-prctl/PR_SCHED_CORE | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SCHED_CORE (CONFIG_SCHED_CORE is not enabled; returns EINVAL) | PR_SCHED_CORE_CREATE, PR_SCHED_CORE_SHARE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_TIMING | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_SET_TIMING, PR_GET_TIMING (accepts only PR_TIMING_STATISTICAL) | PR_GET_TIMING |
| NB-E-S-prctl | NB-E-S-prctl/PR_TASK_PERF_EVENTS_DISABLE | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: case PR_TASK_PERF_EVENTS_DISABLE, PR_TASK_PERF_EVENTS_ENABLE (acting on the perf events this task created itself) | PR_TASK_PERF_EVENTS_ENABLE |
| NB-E-S-prctl | NB-E-S-prctl/PR_GET_AUXV | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: values that only read this task or this mm: case PR_GET_AUXV, PR_GET_TID_ADDRESS | PR_GET_TID_ADDRESS |
| NB-E-S-prctl | NB-E-S-prctl/OTHER | kernel/sys.c::SYSCALL_DEFINE5(prctl), first through the LSM hooks security/commoncap.c::cap_task_prctl and security/yama/yama_lsm.c::yama_task_prctl: default: returns EINVAL | the remaining option values |
| NB-E-S-futex | NB-E-S-futex/FUTEX_WAIT | kernel/futex/syscalls.c::do_futex (FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME are modifier bits): case FUTEX_WAIT, FUTEX_WAIT_BITSET → kernel/futex/waitwake.c::futex_wait | FUTEX_WAIT_BITSET |
| NB-E-S-futex | NB-E-S-futex/FUTEX_WAKE | kernel/futex/syscalls.c::do_futex (FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME are modifier bits): case FUTEX_WAKE, FUTEX_WAKE_BITSET → kernel/futex/waitwake.c::futex_wake | FUTEX_WAKE_BITSET |
| NB-E-S-futex | NB-E-S-futex/FUTEX_REQUEUE | kernel/futex/syscalls.c::do_futex (FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME are modifier bits): case FUTEX_REQUEUE, FUTEX_CMP_REQUEUE → kernel/futex/requeue.c::futex_requeue | FUTEX_CMP_REQUEUE |
| NB-E-S-futex | NB-E-S-futex/FUTEX_WAKE_OP | kernel/futex/syscalls.c::do_futex (FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME are modifier bits): case FUTEX_WAKE_OP → kernel/futex/waitwake.c::futex_wake_op | — |
| NB-E-S-futex | NB-E-S-futex/FUTEX_LOCK_PI | kernel/futex/syscalls.c::do_futex (FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME are modifier bits): case FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI → kernel/futex/pi.c::futex_lock_pi, kernel/futex/pi.c::futex_unlock_pi | FUTEX_LOCK_PI2, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI |
| NB-E-S-futex | NB-E-S-futex/FUTEX_WAIT_REQUEUE_PI | kernel/futex/syscalls.c::do_futex (FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME are modifier bits): case FUTEX_WAIT_REQUEUE_PI, FUTEX_CMP_REQUEUE_PI → kernel/futex/requeue.c::futex_wait_requeue_pi | FUTEX_CMP_REQUEUE_PI |
| NB-E-S-futex | NB-E-S-futex/OTHER | kernel/futex/syscalls.c::do_futex (FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME are modifier bits): the remaining ops: return ENOSYS | the remaining op values |
| NB-E-S-clone | NB-E-S-clone/CSIGNAL | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): the common part of every creation, whichever flags are set (allocating the pid at each level, counting toward the per-uid and cell cgroup counts, the records of the connector and tracing facilities, the child task's first run; the row "clone common part" of 01-trace-events §1.3), and the exit_signal in the low 8 bits; the extra effects of each flag bit are in the rows below | exit_signal |
| NB-E-S-clone | NB-E-S-clone/CLONE_VM | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): sharing and TLS flag bits | CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_THREAD, CLONE_SYSVSEM, CLONE_IO, CLONE_SETTLS |
| NB-E-S-clone | NB-E-S-clone/CLONE_PARENT_SETTID | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): flag bits that write a tid: kernel_clone writes parent_tid, schedule_tail writes child_tid | CLONE_CHILD_SETTID |
| NB-E-S-clone | NB-E-S-clone/CLONE_CHILD_CLEARTID | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): registers clear_child_tid | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_VFORK | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): the parent task waits for the child task to exec or exit | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_PIDFD | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): installs a pidfd in the caller's fd table | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_PARENT | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): the parent becomes the caller's parent; a call by the ns init returns EINVAL | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_NEWNS | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): flag bits that create namespaces: kernel/nsproxy.c::copy_namespaces requires CAP_SYS_ADMIN | CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP, CLONE_NEWTIME |
| NB-E-S-clone | NB-E-S-clone/CLONE_NEWUSER | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): refused by the filter at entry (policy L46–49) | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_PTRACE | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): tracing-related bits: no effect when the caller is not being traced | CLONE_UNTRACED |
| NB-E-S-clone | NB-E-S-clone/OTHER | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process (branching by flag bit): the remaining bits: CLONE_DETACHED is ignored; illegal combinations return EINVAL at the start of copy_process | the remaining bits |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_FILES | kernel/fork.c::ksys_unshare (kernel/fork.c::check_unshare_flags accepts only the bits below): kernel/fork.c::unshare_fd, kernel/fork.c::unshare_fs | CLONE_FS |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_SYSVSEM | kernel/fork.c::ksys_unshare (kernel/fork.c::check_unshare_flags accepts only the bits below): performs this task's SysV semaphore undo | — |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_NEWNS | kernel/fork.c::ksys_unshare (kernel/fork.c::check_unshare_flags accepts only the bits below): bits that create namespaces: need CAP_SYS_ADMIN | CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP, CLONE_NEWTIME |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_NEWUSER | kernel/fork.c::ksys_unshare (kernel/fork.c::check_unshare_flags accepts only the bits below): refused by the filter at entry (policy L46–49) | — |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_THREAD | kernel/fork.c::ksys_unshare (kernel/fork.c::check_unshare_flags accepts only the bits below): accepted only when nothing is shared (single-threaded, mm and sighand not shared), otherwise EINVAL | CLONE_SIGHAND, CLONE_VM |
| NB-E-S-unshare | NB-E-S-unshare/OTHER | kernel/fork.c::ksys_unshare (kernel/fork.c::check_unshare_flags accepts only the bits below): the remaining bits: return EINVAL | the remaining bits |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_PEERCRED | net/socket.c::__sys_getsockopt: for level SOL_SOCKET, net/core/sock.c::sk_getsockopt; other levels return EOPNOTSUPP for AF_UNIX: peer identity: case SO_PEERCRED, SO_PEERGROUPS, SO_PEERSEC, SO_PEERNAME | SO_PEERGROUPS, SO_PEERSEC, SO_PEERNAME |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_PEERPIDFD | net/socket.c::__sys_getsockopt: for level SOL_SOCKET, net/core/sock.c::sk_getsockopt; other levels return EOPNOTSUPP for AF_UNIX: case SO_PEERPIDFD: installs a pidfd for sk_peer_pid in the caller's fd table (kernel/fork.c::pidfd_prepare) | — |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_COOKIE | net/socket.c::__sys_getsockopt: for level SOL_SOCKET, net/core/sock.c::sk_getsockopt; other levels return EOPNOTSUPP for AF_UNIX: global numbers: case SO_COOKIE (allocated on first read), SO_NETNS_COOKIE | SO_NETNS_COOKIE |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_ERROR | net/socket.c::__sys_getsockopt: for level SOL_SOCKET, net/core/sock.c::sk_getsockopt; other levels return EOPNOTSUPP for AF_UNIX: case SO_ERROR: reads and clears this end's error | — |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_TYPE | net/socket.c::__sys_getsockopt: for level SOL_SOCKET, net/core/sock.c::sk_getsockopt; other levels return EOPNOTSUPP for AF_UNIX: read only this end's attributes | SO_DOMAIN, SO_PROTOCOL, SO_SNDBUF, SO_RCVBUF, SO_INCOMING_CPU, SO_PASSCRED, SO_MEMINFO |
| NB-E-S-getsockopt | NB-E-S-getsockopt/OTHER | net/socket.c::__sys_getsockopt: for level SOL_SOCKET, net/core/sock.c::sk_getsockopt; other levels return EOPNOTSUPP for AF_UNIX: the remaining SOL_SOCKET options and the remaining levels | the remaining 47 SOL_SOCKET options (taken from the case labels of sk_getsockopt, listed by review one on 2026-10-26): SO_DEBUG, SO_DONTROUTE, SO_BROADCAST, SO_REUSEADDR, SO_REUSEPORT, SO_KEEPALIVE, SO_OOBINLINE, SO_NO_CHECK, SO_PRIORITY, SO_LINGER, SO_BSDCOMPAT, SO_TIMESTAMP_OLD, SO_TIMESTAMPNS_OLD, SO_TIMESTAMP_NEW, SO_TIMESTAMPNS_NEW, SO_TIMESTAMPING_OLD, SO_TIMESTAMPING_NEW, SO_RCVTIMEO_OLD, SO_RCVTIMEO_NEW, SO_SNDTIMEO_OLD, SO_SNDTIMEO_NEW, SO_RCVLOWAT, SO_SNDLOWAT, SO_PASSPIDFD, SO_ACCEPTCONN, SO_PASSSEC, SO_MARK, SO_RCVMARK, SO_RXQ_OVFL, SO_WIFI_STATUS, SO_PEEK_OFF, SO_NOFCS, SO_BINDTODEVICE, SO_GET_FILTER, SO_LOCK_FILTER, SO_BPF_EXTENSIONS, SO_SELECT_ERR_QUEUE, SO_BUSY_POLL, SO_PREFER_BUSY_POLL, SO_MAX_PACING_RATE, SO_INCOMING_NAPI_ID, SO_ZEROCOPY, SO_TXTIME, SO_BINDTOIFINDEX, SO_BUF_LOCK, SO_RESERVE_MEM, SO_TXREHASH; the remaining levels |
| NB-E-S-madvise | NB-E-S-madvise/MADV_DONTNEED | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/madvise.c::madvise_dontneed_free | MADV_FREE, MADV_DONTNEED_LOCKED |
| NB-E-S-madvise | NB-E-S-madvise/MADV_HUGEPAGE | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/madvise.c::madvise_vma_behavior → mm/khugepaged.c::khugepaged_enter_vma | MADV_NOHUGEPAGE |
| NB-E-S-madvise | NB-E-S-madvise/MADV_COLLAPSE | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/khugepaged.c::madvise_collapse | — |
| NB-E-S-madvise | NB-E-S-madvise/MADV_REMOVE | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/madvise.c::madvise_remove | — |
| NB-E-S-madvise | NB-E-S-madvise/MADV_COLD | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/madvise.c::madvise_cold, mm/madvise.c::madvise_pageout | MADV_PAGEOUT |
| NB-E-S-madvise | NB-E-S-madvise/MADV_WIPEONFORK | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/madvise.c::madvise_vma_behavior changes VMA flags | MADV_KEEPONFORK, MADV_DONTFORK, MADV_DOFORK |
| NB-E-S-madvise | NB-E-S-madvise/MADV_POPULATE_READ | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/madvise.c::madvise_populate | MADV_POPULATE_WRITE |
| NB-E-S-madvise | NB-E-S-madvise/MADV_HWPOISON | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/madvise.c::madvise_inject_error (needs CAP_SYS_ADMIN) | MADV_SOFT_OFFLINE |
| NB-E-S-madvise | NB-E-S-madvise/MADV_DODUMP | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): mm/madvise.c::madvise_vma_behavior changes VMA flags | MADV_DONTDUMP |
| NB-E-S-madvise | NB-E-S-madvise/MADV_WILLNEED | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): read-ahead hints: mm/madvise.c::madvise_willneed and VMA flags | MADV_NORMAL, MADV_SEQUENTIAL, MADV_RANDOM |
| NB-E-S-madvise | NB-E-S-madvise/MADV_MERGEABLE | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): KSM registration: mm/ksm.c::ksm_madvise | MADV_UNMERGEABLE |
| NB-E-S-madvise | NB-E-S-madvise/OTHER | mm/madvise.c::do_madvise (mm/madvise.c::madvise_behavior_valid accepts only the values below): the remaining values: return EINVAL | the remaining values |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_SET_FS | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl): first arch/x86/kernel/process_64.c::do_arch_prctl_64, and when that returns EINVAL, arch/x86/kernel/process.c::do_arch_prctl_common: do_arch_prctl_64 | ARCH_SET_GS, ARCH_GET_FS, ARCH_GET_GS |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_SET_CPUID | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl): first arch/x86/kernel/process_64.c::do_arch_prctl_64, and when that returns EINVAL, arch/x86/kernel/process.c::do_arch_prctl_common: do_arch_prctl_common → arch/x86/kernel/process.c::set_cpuid_mode | ARCH_GET_CPUID |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_REQ_XCOMP_PERM | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl): first arch/x86/kernel/process_64.c::do_arch_prctl_64, and when that returns EINVAL, arch/x86/kernel/process.c::do_arch_prctl_common: do_arch_prctl_common → arch/x86/kernel/fpu/xstate.c::fpu_xstate_prctl | ARCH_GET_XCOMP_SUPP, ARCH_GET_XCOMP_PERM |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_REQ_XCOMP_GUEST_PERM | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl): first arch/x86/kernel/process_64.c::do_arch_prctl_64, and when that returns EINVAL, arch/x86/kernel/process.c::do_arch_prctl_common: as above, for guest permissions | ARCH_GET_XCOMP_GUEST_PERM |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_MAP_VDSO_64 | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl): first arch/x86/kernel/process_64.c::do_arch_prctl_64, and when that returns EINVAL, arch/x86/kernel/process.c::do_arch_prctl_common: do_arch_prctl_64 → arch/x86/entry/vdso/vma.c::map_vdso_once | ARCH_MAP_VDSO_32, ARCH_MAP_VDSO_X32 |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_SHSTK_ENABLE | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl): first arch/x86/kernel/process_64.c::do_arch_prctl_64, and when that returns EINVAL, arch/x86/kernel/process.c::do_arch_prctl_common: do_arch_prctl_64 → shstk_prctl (CONFIG_X86_USER_SHADOW_STACK is not enabled; returns EINVAL) | ARCH_SHSTK_DISABLE, ARCH_SHSTK_LOCK, ARCH_SHSTK_UNLOCK, ARCH_SHSTK_STATUS |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/OTHER | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl): first arch/x86/kernel/process_64.c::do_arch_prctl_64, and when that returns EINVAL, arch/x86/kernel/process.c::do_arch_prctl_common: the remaining values return EINVAL (CONFIG_ADDRESS_MASKING is not enabled, so the LAM values are not compiled in) | ARCH_GET_UNTAG_MASK, ARCH_ENABLE_TAGGED_ADDR, ARCH_FORCE_TAGGED_SVA, ARCH_GET_MAX_TAG_BITS |

#### 3.4 Branch table

Owning chapters: PF paths and files · NI network, IPC and the engine channel · PS processes and signals · GS unisolated names and machine-wide state · LC lifecycle and successors · 02 this file (only NB-K-01 and 02: construction at cell start; their cells are added to this file from the initial-state items of §2 before block two starts). The branches of NB-K-03…10 belong to LC; they carry the preservation and interference obligations of the spawner constructing another execution while this execution runs (§1.3).
A (row, column) pair belongs to exactly one chapter. The generic fd calls (read, write, close, fstat, lseek, fsync, mmap, and the sub-operations of futex) × NB-N-02 belong to PF. Their cells must include non-file targets such as fd 3 and pidfd in the conservative summary, and must put cross-chapter marks on the related cells of NI and PS. poll × NB-N-02 belongs to NI, because the pidfd is produced by getsockopt's SO_PEERPIDFD, which is also in NI.

| Row ID | Column ID | Owning chapter |
|---|---|---|
| NB-E-A-01 | NB-N-02 | PF |
| NB-E-A-01 | NB-N-08 | PS |
| NB-E-A-01 | NB-N-09 | LC |
| NB-E-A-01 | NB-N-10 | PF |
| NB-E-A-02 | NB-N-02 | NI |
| NB-E-A-03 | NB-N-02 | PF |
| NB-E-A-03 | NB-N-06 | GS |
| NB-E-A-03 | NB-N-09 | LC |
| NB-E-A-03 | NB-N-10 | PF |
| NB-E-A-04 | NB-N-02 | PF |
| NB-E-A-04 | NB-N-10 | PF |
| NB-E-A-05 | NB-N-01 | LC |
| NB-E-A-05 | NB-N-06 | GS |
| NB-E-A-06 | NB-N-02 | NI |
| NB-E-A-07 | NB-N-06 | GS |
| NB-E-A-08 | NB-N-08 | PS |
| NB-E-A-09 | NB-N-03 | PS |
| NB-E-A-10 | NB-N-02 | PF |
| NB-E-A-10 | NB-N-09 | LC |
| NB-E-A-10 | NB-N-10 | PF |
| NB-E-A-11 | NB-N-06 | GS |
| NB-E-K-01 | NB-N-06 | GS |
| NB-E-K-01 | NB-N-12 | PF |
| NB-E-K-02 | NB-N-06 | GS |
| NB-E-K-02 | NB-N-13 | GS |
| NB-E-K-03 | NB-N-02 | PF |
| NB-E-K-03 | NB-N-06 | GS |
| NB-E-K-04 | NB-N-06 | GS |
| NB-E-K-05 | NB-N-02 | PF |
| NB-E-K-05 | NB-N-10 | PF |
| NB-E-K-06 | NB-N-06 | GS |
| NB-E-K-07 | NB-N-07 | PS |
| NB-E-K-08 | NB-N-02 | PF |
| NB-E-K-08 | NB-N-08 | PS |
| NB-E-K-08 | NB-N-09 | LC |
| NB-E-K-08 | NB-N-10 | PF |
| NB-E-K-09 | NB-N-01 | PF |
| NB-E-K-09 | NB-N-02 | PF |
| NB-E-K-09 | NB-N-13 | GS |
| NB-E-K-10 | NB-N-06 | GS |
| NB-E-K-10 | NB-N-13 | GS |
| NB-E-K-11 | NB-N-06 | GS |
| NB-E-K-11 | NB-N-13 | GS |
| NB-E-K-12 | NB-N-06 | GS |
| NB-E-K-12 | NB-N-13 | GS |
| NB-E-K-13 | NB-N-06 | GS |
| NB-E-K-13 | NB-N-13 | GS |
| NB-E-K-14 | NB-N-06 | GS |
| NB-E-K-14 | NB-N-13 | GS |
| NB-E-M-01 | NB-N-02 | PF |
| NB-E-M-01 | NB-N-06 | GS |
| NB-E-M-01 | NB-N-09 | LC |
| NB-E-M-01 | NB-N-10 | PF |
| NB-E-M-02 | NB-N-02 | PF |
| NB-E-M-02 | NB-N-06 | GS |
| NB-E-M-03 | NB-N-02 | PF |
| NB-E-M-03 | NB-N-06 | GS |
| NB-E-M-04 | NB-N-06 | GS |
| NB-E-M-05 | NB-N-06 | GS |
| NB-E-M-07 | NB-N-02 | PF |
| NB-E-M-07 | NB-N-06 | GS |
| NB-E-M-08 | NB-N-06 | GS |
| NB-E-P-01 | NB-N-02 | PF |
| NB-E-P-01 | NB-N-08 | PS |
| NB-E-P-02 | NB-N-06 | GS |
| NB-E-P-02 | NB-N-07 | PS |
| NB-E-P-02 | NB-N-11 | LC |
| NB-E-P-03 | NB-N-07 | PS |
| NB-E-P-04 | NB-N-03 | PS |
| NB-E-P-04 | NB-N-07 | PS |
| NB-E-P-05 | NB-N-07 | PS |
| NB-E-P-06 | NB-N-07 | PS |
| NB-E-P-07 | NB-N-02 | PF |
| NB-E-P-07 | NB-N-03 | PS |
| NB-E-P-07 | NB-N-06 | GS |
| NB-E-P-07 | NB-N-07 | PS |
| NB-E-P-07 | NB-N-08 | PS |
| NB-E-P-07 | NB-N-09 | LC |
| NB-E-P-07 | NB-N-10 | PF |
| NB-E-P-07 | NB-N-11 | LC |
| NB-E-S-access | NB-N-01 | PF |
| NB-E-S-access | NB-N-02 | PF |
| NB-E-S-access | NB-N-06 | GS |
| NB-E-S-arch_prctl/ARCH_MAP_VDSO_64 | NB-N-06 | GS |
| NB-E-S-arch_prctl/ARCH_REQ_XCOMP_GUEST_PERM | NB-N-08 | PS |
| NB-E-S-arch_prctl/ARCH_REQ_XCOMP_PERM | NB-N-08 | PS |
| NB-E-S-arch_prctl/ARCH_SET_CPUID | NB-N-08 | PS |
| NB-E-S-arch_prctl/ARCH_SET_FS | NB-N-08 | PS |
| NB-E-S-arch_prctl/ARCH_SHSTK_ENABLE | NB-N-08 | PS |
| NB-E-S-arch_prctl/OTHER | NB-N-08 | PS |
| NB-E-S-brk | NB-N-06 | GS |
| NB-E-S-chdir | NB-N-01 | PF |
| NB-E-S-clock_gettime | NB-N-02 | PF |
| NB-E-S-clock_gettime | NB-N-03 | PS |
| NB-E-S-clock_gettime | NB-N-06 | GS |
| NB-E-S-clone/CLONE_CHILD_CLEARTID | NB-N-08 | PS |
| NB-E-S-clone/CLONE_NEWNS | NB-N-06 | GS |
| NB-E-S-clone/CLONE_NEWUSER | NB-N-06 | GS |
| NB-E-S-clone/CLONE_PARENT | NB-N-03 | PS |
| NB-E-S-clone/CLONE_PARENT | NB-N-07 | PS |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-02 | PF |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-03 | PS |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-09 | LC |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-10 | PF |
| NB-E-S-clone/CLONE_PIDFD | NB-N-02 | PS |
| NB-E-S-clone/CLONE_PIDFD | NB-N-03 | PS |
| NB-E-S-clone/CLONE_PTRACE | NB-N-03 | PS |
| NB-E-S-clone/CLONE_VFORK | NB-N-03 | PS |
| NB-E-S-clone/CLONE_VM | NB-N-03 | PS |
| NB-E-S-clone/CLONE_VM | NB-N-05 | NI |
| NB-E-S-clone/CSIGNAL | NB-N-03 | PS |
| NB-E-S-clone/CSIGNAL | NB-N-06 | GS |
| NB-E-S-clone/CSIGNAL | NB-N-07 | PS |
| NB-E-S-clone/CSIGNAL | NB-N-11 | LC |
| NB-E-S-clone/OTHER | NB-N-03 | PS |
| NB-E-S-close | NB-N-02 | PF |
| NB-E-S-close | NB-N-10 | PF |
| NB-E-S-execve | NB-N-01 | PF |
| NB-E-S-execve | NB-N-02 | PF |
| NB-E-S-execve | NB-N-06 | GS |
| NB-E-S-execve | NB-N-08 | PS |
| NB-E-S-execve | NB-N-09 | LC |
| NB-E-S-execve | NB-N-10 | PF |
| NB-E-S-exit | NB-N-07 | PS |
| NB-E-S-fcntl/F_ADD_SEALS | NB-N-02 | PF |
| NB-E-S-fcntl/F_DUPFD | NB-N-02 | PF |
| NB-E-S-fcntl/F_NOTIFY | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETFD | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETFL | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETLEASE | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETLEASE | NB-N-10 | PF |
| NB-E-S-fcntl/F_SETLK | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETLK | NB-N-03 | PF |
| NB-E-S-fcntl/F_SETLK | NB-N-10 | PF |
| NB-E-S-fcntl/F_SETOWN | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETOWN | NB-N-03 | PS |
| NB-E-S-fcntl/F_SETOWN | NB-N-07 | PS |
| NB-E-S-fcntl/F_SETPIPE_SZ | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETSIG | NB-N-02 | PF |
| NB-E-S-fcntl/F_SET_RW_HINT | NB-N-02 | PF |
| NB-E-S-fcntl/F_SET_RW_HINT | NB-N-06 | GS |
| NB-E-S-fcntl/OTHER | NB-N-02 | PF |
| NB-E-S-fstat | NB-N-01 | PF |
| NB-E-S-fstat | NB-N-02 | PF |
| NB-E-S-fstat | NB-N-06 | GS |
| NB-E-S-fsync | NB-N-02 | PF |
| NB-E-S-fsync | NB-N-06 | GS |
| NB-E-S-futex/FUTEX_LOCK_PI | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_LOCK_PI | NB-N-03 | PS |
| NB-E-S-futex/FUTEX_LOCK_PI | NB-N-06 | GS |
| NB-E-S-futex/FUTEX_REQUEUE | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAIT | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAIT | NB-N-06 | GS |
| NB-E-S-futex/FUTEX_WAIT_REQUEUE_PI | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAIT_REQUEUE_PI | NB-N-03 | PS |
| NB-E-S-futex/FUTEX_WAIT_REQUEUE_PI | NB-N-06 | GS |
| NB-E-S-futex/FUTEX_WAKE | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAKE_OP | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAKE_OP | NB-N-09 | LC |
| NB-E-S-futex/FUTEX_WAKE_OP | NB-N-10 | PF |
| NB-E-S-futex/OTHER | NB-N-02 | PF |
| NB-E-S-getcwd | NB-N-01 | PF |
| NB-E-S-getdents64 | NB-N-02 | PF |
| NB-E-S-getdents64 | NB-N-06 | GS |
| NB-E-S-getdents64 | NB-N-09 | LC |
| NB-E-S-getdents64 | NB-N-10 | PF |
| NB-E-S-getpid | NB-N-03 | PS |
| NB-E-S-getrandom | NB-N-06 | GS |
| NB-E-S-getsockname | NB-N-04 | NI |
| NB-E-S-getsockopt/OTHER | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_COOKIE | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_COOKIE | NB-N-06 | GS |
| NB-E-S-getsockopt/SO_ERROR | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_PEERCRED | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_PEERPIDFD | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_PEERPIDFD | NB-N-03 | NI |
| NB-E-S-getsockopt/SO_TYPE | NB-N-02 | NI |
| NB-E-S-getuid | NB-N-08 | PS |
| NB-E-S-kill | NB-N-03 | PS |
| NB-E-S-kill | NB-N-07 | PS |
| NB-E-S-lseek | NB-N-02 | PF |
| NB-E-S-madvise/MADV_COLD | NB-N-02 | PF |
| NB-E-S-madvise/MADV_COLD | NB-N-06 | GS |
| NB-E-S-madvise/MADV_COLLAPSE | NB-N-06 | GS |
| NB-E-S-madvise/MADV_DODUMP | NB-N-12 | PF |
| NB-E-S-madvise/MADV_DONTNEED | NB-N-06 | GS |
| NB-E-S-madvise/MADV_HUGEPAGE | NB-N-06 | GS |
| NB-E-S-madvise/MADV_HWPOISON | NB-N-06 | GS |
| NB-E-S-madvise/MADV_MERGEABLE | NB-N-06 | GS |
| NB-E-S-madvise/MADV_POPULATE_READ | NB-N-02 | PF |
| NB-E-S-madvise/MADV_POPULATE_READ | NB-N-06 | GS |
| NB-E-S-madvise/MADV_REMOVE | NB-N-02 | PF |
| NB-E-S-madvise/MADV_REMOVE | NB-N-06 | GS |
| NB-E-S-madvise/MADV_REMOVE | NB-N-09 | LC |
| NB-E-S-madvise/MADV_REMOVE | NB-N-10 | PF |
| NB-E-S-madvise/MADV_WILLNEED | NB-N-02 | PF |
| NB-E-S-madvise/MADV_WILLNEED | NB-N-06 | GS |
| NB-E-S-madvise/MADV_WIPEONFORK | NB-N-08 | PS |
| NB-E-S-madvise/OTHER | NB-N-06 | GS |
| NB-E-S-mmap | NB-N-02 | PF |
| NB-E-S-mmap | NB-N-06 | GS |
| NB-E-S-mmap | NB-N-09 | LC |
| NB-E-S-mmap | NB-N-10 | PF |
| NB-E-S-mprotect | NB-N-02 | PF |
| NB-E-S-munmap | NB-N-02 | PF |
| NB-E-S-nanosleep | NB-N-03 | PS |
| NB-E-S-nanosleep | NB-N-06 | GS |
| NB-E-S-openat | NB-N-01 | PF |
| NB-E-S-openat | NB-N-02 | PF |
| NB-E-S-openat | NB-N-06 | GS |
| NB-E-S-openat | NB-N-09 | LC |
| NB-E-S-openat | NB-N-10 | PF |
| NB-E-S-poll | NB-N-02 | NI |
| NB-E-S-prctl/OTHER | NB-N-08 | PS |
| NB-E-S-prctl/PR_GET_AUXV | NB-N-08 | PS |
| NB-E-S-prctl/PR_MCE_KILL | NB-N-08 | PS |
| NB-E-S-prctl/PR_SCHED_CORE | NB-N-03 | PS |
| NB-E-S-prctl/PR_SET_CHILD_SUBREAPER | NB-N-07 | PS |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-01 | PF |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-12 | PF |
| NB-E-S-prctl/PR_SET_FP_MODE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_KEEPCAPS | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_MDWE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_MEMORY_MERGE | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_MEMORY_MERGE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_MM | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_MM_MAP | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_MM_MAP | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_NAME | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_NAME | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_NO_NEW_PRIVS | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_PDEATHSIG | NB-N-07 | PS |
| NB-E-S-prctl/PR_SET_PDEATHSIG | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_PTRACER | NB-N-03 | PS |
| NB-E-S-prctl/PR_SET_PTRACER | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_SECCOMP | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_SECCOMP | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_SECUREBITS | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_SPECULATION_CTRL | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_SPECULATION_CTRL | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_SYSCALL_USER_DISPATCH | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_THP_DISABLE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_TIMERSLACK | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_TIMING | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_TSC | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_VMA | NB-N-08 | PS |
| NB-E-S-prctl/PR_TASK_PERF_EVENTS_DISABLE | NB-N-08 | PS |
| NB-E-S-prlimit64 | NB-N-03 | PS |
| NB-E-S-prlimit64 | NB-N-08 | PS |
| NB-E-S-read | NB-N-02 | PF |
| NB-E-S-read | NB-N-06 | GS |
| NB-E-S-read | NB-N-09 | LC |
| NB-E-S-read | NB-N-10 | PF |
| NB-E-S-readlink | NB-N-01 | PF |
| NB-E-S-readlink | NB-N-02 | PF |
| NB-E-S-readlink | NB-N-06 | GS |
| NB-E-S-readlink | NB-N-09 | LC |
| NB-E-S-readlink | NB-N-10 | PF |
| NB-E-S-recvmsg | NB-N-02 | NI |
| NB-E-S-rt_sigaction | NB-N-08 | PS |
| NB-E-S-sendmsg | NB-N-02 | NI |
| NB-E-S-sendmsg | NB-N-03 | NI |
| NB-E-S-sendmsg | NB-N-06 | NI |
| NB-E-S-set_tid_address | NB-N-08 | PS |
| NB-E-S-setsid | NB-N-07 | PS |
| NB-E-S-setuid | NB-N-08 | PS |
| NB-E-S-shutdown | NB-N-02 | NI |
| NB-E-S-tgkill | NB-N-03 | PS |
| NB-E-S-uname | NB-N-06 | GS |
| NB-E-S-unshare/CLONE_FILES | NB-N-02 | PF |
| NB-E-S-unshare/CLONE_NEWNS | NB-N-06 | GS |
| NB-E-S-unshare/CLONE_NEWUSER | NB-N-06 | GS |
| NB-E-S-unshare/CLONE_SYSVSEM | NB-N-05 | NI |
| NB-E-S-unshare/CLONE_THREAD | NB-N-07 | PS |
| NB-E-S-unshare/OTHER | NB-N-07 | PS |
| NB-E-S-wait4 | NB-N-02 | PS |
| NB-E-S-wait4 | NB-N-03 | PS |
| NB-E-S-wait4 | NB-N-06 | GS |
| NB-E-S-write | NB-N-02 | PF |
| NB-E-S-write | NB-N-06 | GS |
| NB-E-S-write | NB-N-08 | PS |
| NB-E-S-write | NB-N-09 | LC |
| NB-E-S-write | NB-N-10 | PF |
| NB-E-S-write | NB-N-12 | PF |
| NB-K-01 | NB-N-08 | 02 |
| NB-K-02 | NB-N-08 | 02 |
| NB-K-03 | NB-N-07 | LC |
| NB-K-04 | NB-N-01 | LC |
| NB-K-04 | NB-N-06 | LC |
| NB-K-05 | NB-N-02 | LC |
| NB-K-06 | NB-N-02 | LC |
| NB-K-07 | NB-N-01 | LC |
| NB-K-08 | NB-N-02 | LC |
| NB-K-09 | NB-N-08 | LC |
| NB-K-10 | NB-N-01 | LC |
| NB-K-11 | NB-N-02 | NI |
| NB-K-12 | NB-N-01 | PF |
| NB-K-12 | NB-N-02 | NI |
| NB-K-13 | NB-N-03 | PS |
| NB-K-13 | NB-N-07 | PS |
| NB-K-14 | NB-N-01 | LC |
| NB-K-14 | NB-N-06 | LC |
| NB-K-15 | NB-N-09 | LC |
| NB-K-16 | NB-N-07 | LC |
| NB-K-16 | NB-N-11 | LC |

#### 3.5 Not-applicable items

Each (row, column) pair that the "name-source columns" of [the system-call table](#the-74-system-calls) point to, but that forms no branch, has one reason written for it.

| Row ID | Column ID | Reason |
|---|---|---|
| NB-E-S-clone/CLONE_CHILD_CLEARTID | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/CLONE_CHILD_CLEARTID | NB-N-03 | it only registers an address; the new task itself is judged by the N-03 cell of the CSIGNAL row |
| NB-E-S-clone/CLONE_CHILD_CLEARTID | NB-N-06 | every creation goes through the CSIGNAL row; the use of the host pid number space is judged by its N-06 cell |
| NB-E-S-clone/CLONE_NEWNS | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/CLONE_NEWNS | NB-N-03 | it lacks the capability or is refused by the filter, and creates no new task |
| NB-E-S-clone/CLONE_NEWUSER | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/CLONE_NEWUSER | NB-N-03 | it lacks the capability or is refused by the filter, and creates no new task |
| NB-E-S-clone/CLONE_PARENT | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/CLONE_PARENT | NB-N-06 | every creation goes through the CSIGNAL row; the use of the host pid number space is judged by its N-06 cell |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-06 | every creation goes through the CSIGNAL row; the use of the host pid number space is judged by its N-06 cell |
| NB-E-S-clone/CLONE_PIDFD | NB-N-06 | every creation goes through the CSIGNAL row; the use of the host pid number space is judged by its N-06 cell |
| NB-E-S-clone/CLONE_PTRACE | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/CLONE_PTRACE | NB-N-06 | every creation goes through the CSIGNAL row; the use of the host pid number space is judged by its N-06 cell |
| NB-E-S-clone/CLONE_VFORK | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/CLONE_VFORK | NB-N-06 | every creation goes through the CSIGNAL row; the use of the host pid number space is judged by its N-06 cell |
| NB-E-S-clone/CLONE_VM | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/CLONE_VM | NB-N-06 | every creation goes through the CSIGNAL row; the use of the host pid number space is judged by its N-06 cell |
| NB-E-S-clone/CSIGNAL | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/OTHER | NB-N-02 | this class of flags puts no new reference in the fd table; the fd table the new task shares or copies belongs to the cell of NB-E-P-07 |
| NB-E-S-clone/OTHER | NB-N-06 | every creation goes through the CSIGNAL row; the use of the host pid number space is judged by its N-06 cell |
| NB-E-S-fcntl/F_ADD_SEALS | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_ADD_SEALS | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_DUPFD | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_DUPFD | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_NOTIFY | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_NOTIFY | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_SETFD | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_SETFD | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_SETFL | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_SETFL | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_SETLEASE | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_SETLEASE | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_SETLK | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_SETPIPE_SZ | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_SETPIPE_SZ | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_SETSIG | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_SETSIG | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/F_SET_RW_HINT | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/F_SET_RW_HINT | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-fcntl/OTHER | NB-N-03 | this sub-operation neither takes a pid argument nor outputs a pid |
| NB-E-S-fcntl/OTHER | NB-N-07 | it does not act on implicit subjects such as the process group, the session or the parent process; signal targets are judged by the cells of the F_SETOWN row |
| NB-E-S-futex/FUTEX_REQUEUE | NB-N-03 | not a PI operation: waiters are found by futex key, and the value in the futex word is not resolved as a tid |
| NB-E-S-futex/FUTEX_WAIT | NB-N-03 | not a PI operation: waiters are found by futex key, and the value in the futex word is not resolved as a tid |
| NB-E-S-futex/FUTEX_WAKE | NB-N-03 | not a PI operation: waiters are found by futex key, and the value in the futex word is not resolved as a tid |
| NB-E-S-futex/FUTEX_WAKE_OP | NB-N-03 | not a PI operation: waiters are found by futex key, and the value in the futex word is not resolved as a tid |
| NB-E-S-futex/OTHER | NB-N-03 | returns ENOSYS and resolves no name |
| NB-E-S-getsockopt/OTHER | NB-N-06 | it only reads attributes of this end, or of the peer as recorded at set-up, and reads no global counter |
| NB-E-S-getsockopt/SO_ERROR | NB-N-06 | it only reads attributes of this end, or of the peer as recorded at set-up, and reads no global counter |
| NB-E-S-getsockopt/SO_PEERCRED | NB-N-06 | it only reads attributes of this end, or of the peer as recorded at set-up, and reads no global counter |
| NB-E-S-getsockopt/SO_PEERPIDFD | NB-N-06 | creating the pidfd reads no global name; the process the pidfd points to is judged by the N-02 and N-03 cells of this row |
| NB-E-S-getsockopt/SO_TYPE | NB-N-06 | it only reads attributes of this end, or of the peer as recorded at set-up, and reads no global counter |
| NB-E-S-madvise/MADV_DODUMP | NB-N-06 | it only changes VMA flags; what it affects is the content of the core dump, judged by the N-12 cell of this row |
| NB-E-S-madvise/MADV_WIPEONFORK | NB-N-06 | it only changes VMA flags; what it affects is the mappings a child task gets at a later clone, judged by the N-08 cell of this row |
| NB-E-S-prctl/OTHER | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/OTHER | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_GET_AUXV | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_GET_AUXV | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_MCE_KILL | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_MCE_KILL | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SCHED_CORE | NB-N-06 | CONFIG_SCHED_CORE is not enabled (NB-EV-018); it returns EINVAL and creates no core scheduling cookie |
| NB-E-S-prctl/PR_SET_CHILD_SUBREAPER | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_CHILD_SUBREAPER | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_FP_MODE | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_FP_MODE | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_KEEPCAPS | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_KEEPCAPS | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_MDWE | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_MDWE | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_MEMORY_MERGE | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_MM | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_MM | NB-N-06 | it lacks CAP_SYS_RESOURCE, returns EPERM and changes no state |
| NB-E-S-prctl/PR_SET_MM_MAP | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_NAME | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_NO_NEW_PRIVS | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_NO_NEW_PRIVS | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_PDEATHSIG | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_PDEATHSIG | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_SECCOMP | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_SECUREBITS | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_SECUREBITS | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_SPECULATION_CTRL | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_SYSCALL_USER_DISPATCH | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_SYSCALL_USER_DISPATCH | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_THP_DISABLE | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_THP_DISABLE | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_TIMERSLACK | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_TIMERSLACK | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_TIMING | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_TIMING | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_TSC | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_TSC | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_SET_VMA | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_SET_VMA | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |
| NB-E-S-prctl/PR_TASK_PERF_EVENTS_DISABLE | NB-N-03 | this value takes no pid argument |
| NB-E-S-prctl/PR_TASK_PERF_EVENTS_DISABLE | NB-N-06 | it only changes or reads attributes of this task or this mm, or returns an error; it goes through no unisolated name |

#### 3.6 Column not-applicable rules

| Column ID | Where it applies | Why it does not apply elsewhere |
|---|---|---|
| NB-N-01 | rows that take a path as a parameter or resolve a path (openat, access, newfstatat and statx, readlink, chdir, getcwd, execve); rows that construct and destroy mounts (NB-K-04, NB-K-07, NB-K-10, NB-K-14, NB-E-A-05); files the engine writes by host path (NB-K-12); prctl's PR_SET_DUMPABLE, which changes the owner of the /proc/self entries (when dumpable is 0 the entries become root-owned); and the fsnotify events produced when acting on objects by path or fd (NB-E-K-09) | the parameters of the other rows are fds, addresses, pids or numbers, or there are no parameters; they do not resolve paths; every object that can be found by path is covered by the cells of the rows above |
| NB-N-02 | rows that take an fd as a parameter, or that act through mappings and file objects: file I/O and metadata, memory mappings, socket calls, duplication and closing of fds, the directory fds of faccessat2 and readlinkat, the CLOCKFD clock id of clock_gettime (which encodes an fd), and the events in which the kernel writes user memory through a mapping (NB-E-M-01, 02, 03, 07, NB-E-K-03, 05, 08, 09, NB-E-A-01, 02, 03, 04, 06, 10, NB-E-P-01, 07) | the other rows neither take an fd nor act on objects through an existing file or mapping: they act on tasks, signals, credentials and global state, which are covered by the columns that apply to them. There are two places where an fd is nested in a parameter but not resolved: the exe_fd in the structure of prctl PR_SET_MM_MAP must first pass the checkpoint-restore capability check, and without the capability the call returns EPERM (kernel/sys.c::prctl_set_mm_map); the CLOCKFD clock id of clock_nanosleep has no nsleep method and returns EOPNOTSUPP (clock_posix_dynamic in kernel/time/posix-clock.c). Which mapping the user buffers that system calls read and write land on is carried by the NB-E-M rows ([the header of the system-call table](#the-74-system-calls), 01-rows-syscalls) |
| NB-N-03 | rows that take a pid, tid or process-group number as a parameter (including one nested in a parameter), or that create, reap or notify tasks: kill, tgkill, wait4 and waitid, prlimit64, getpid, the sub-operations of clone, fcntl's F_SETOWN and F_SETLK (F_GETLK outputs the lock holder's pid), prctl's PR_SET_PTRACER and PR_SCHED_CORE, getsockopt's SO_PEERPIDFD, the CPU clock ids of clock_gettime and clock_nanosleep (which encode a pid), the PI sub-operations of futex (the owner tid in the futex word), sendmsg's SCM_CREDENTIALS (the pid in ucred), and NB-E-A-09, NB-E-P-04, NB-E-P-07, NB-K-13 | the other rows do not find objects by pid or tid names; tasks outside this pid namespace have no number, and tasks reached through implicit relations are covered by N-07 |
| NB-N-04 | only the getsockname row (both ends of fd 3 are unnamed) | socket and socketpair are not in L, bind and connect are fixed as forbidden (NB-DI-08), and the only socket in the execution's hands is the connected fd 3; no other call in L takes a network address as a parameter, and the msg_name of sendmsg on a connected STREAM returns EISCONN |
| NB-N-05 | unshare's CLONE_SYSVSEM (performs this task's SysV semaphore undo) and clone's CLONE_SYSVSEM (in the CLONE_VM sub-operation row: the new task shares the undo list with the caller) | the SysV IPC and POSIX message-queue calls are not in L, and no mqueue file system is mounted (NB-N-05); no other call in L takes an IPC key or ID as a parameter |
| NB-N-06 | rows that read or write unisolated names or machine-wide state: clocks, the CPU number and the processor's static configuration (NB-E-M-04, NB-E-M-08, added 2026-10-27), UTS, random numbers, global counters (inode numbers, cookies, allocation and return of pid numbers, including wait4 and waitid), the kernel log and host observation facilities, the shared btrfs and block devices (including the trusted parties' NB-K-04, NB-K-14), host memory and swap, hugetlb, THP and KSM (including prctl's PR_SET_MEMORY_MERGE), binfmt_misc, the Yama exception table, the global hash buckets of futex (including PI waits), sendmsg's SCM_CREDENTIALS (uid and gid resolved in the initial user namespace), the comm, cmdline and environ the host reads through /proc (prctl's PR_SET_NAME and PR_SET_MM_MAP, write, execve, NB-E-M-07), speculative execution and split lock (NB-E-K-06, NB-E-A-11) | the other rows act only on this execution's own objects or on delivered objects, not through unisolated names; their use of machine-wide aggregate state (memory, CPU) is judged together in the cells of the rows above. Host-observable execution state (the host visibility rule of 01 §2.6: what the host can see without privilege, and what has undetermined visibility and is treated as visible) does not form separate branches: the appearance and exit of tasks, and their states and counts, are judged in the cells of clone's CSIGNAL, NB-E-P-07 and NB-E-P-02; attributes set at construction and not changed by any later row (uid, gid, the initial signal dispositions and mask) are also judged in these cells; the cell of NB-E-P-02 lists separately the reaping effect of the host's process_mrelease on a task that is exiting, and the state readings; the argument area and comm are judged in the cells of execve, prctl's PR_SET_NAME and PR_SET_MM_MAP, write, and NB-E-M-07; counts and states that other rows change and that the host can read through /proc (CPU time, memory use, signal masks and so on) are judged together in these cells as one and the same observation channel; the record of such a cell takes the value "host-observable · verified" or "host-observable · treated as visible" (SPEC §4.1 kind 4; added after the third targeted re-review, changed to record values after the R0d full review) |
| NB-N-07 | rows that act on implicit subjects such as the process group, the session, the parent process, cgroup membership and per-uid counts: kill, exit, setsid, clone's CSIGNAL and CLONE_PARENT, unshare's CLONE_THREAD and the remaining bits, fcntl's F_SETOWN, prctl's PR_SET_PDEATHSIG and PR_SET_CHILD_SUBREAPER, and NB-E-K-07, NB-E-P-02…07, NB-K-03, NB-K-13, NB-K-16 | the other rows do not act on other tasks or counts through implicit subjects |
| NB-N-08 | rows that read or change inherited task attributes: credentials, rlimit, signal dispositions and mask, registered addresses, the sub-operations of prctl and arch_prctl, the writable /proc/self entries (the write row), and NB-E-K-08, NB-E-A-01, NB-E-A-08, NB-E-P-01, NB-E-P-07 (new tasks inherit these attributes), NB-K-01, NB-K-02, NB-K-09 | the other rows neither read nor change the attributes that 01 §4 NB-N-08 lists |
| NB-N-09 | rows that change the content or metadata of /work: openat (creating files, truncating), write, read and getdents64 and readlink (relatime updates atime), mmap and execve (btrfs's mmap method and exec's reading of the executable update atime in the same way: fs/btrfs/file.c::btrfs_file_mmap, mm/filemap.c::filemap_read), madvise's MADV_REMOVE, futex's FUTEX_WAKE_OP and clone's tid writes (writes to user memory, which can land on a /work shared mapping), and NB-E-M-01, NB-E-K-08, NB-E-A-01, NB-E-A-03, NB-E-A-10, NB-E-P-07 and NB-K-15 | the other rows do not change the content and metadata of /work; when the output buffers they write for the caller land on a /work shared mapping, this is judged by the cell of NB-E-M-01; record locks and leases are released when the process dies and no longer exist before the successor starts (NB-K-15 requires the previous execution to be cleared) |
| NB-N-10 | the same group of rows as N-09 that change the content or metadata of /work (without NB-K-15, which only represents the successor's reading), plus the rows that make host trusted parties meet locks and leases when opening workspace files (fcntl's F_SETLK and F_SETLEASE, close, NB-E-K-05, NB-E-A-04) | the other rows neither change /work nor leave locks or leases on files in /work |
| NB-N-11 | rows that change the number of tasks in the cell cgroup: clone's CSIGNAL (the common part of every creation), NB-E-P-02, NB-E-P-07, NB-K-16 | the other rows neither create nor end tasks and do not change populated |
| NB-N-12 | NB-E-K-01 (the core dump path), and the rows that decide the content of the core: madvise's MADV_DODUMP, prctl's PR_SET_DUMPABLE, write (/proc/self/coredump_filter) | the core dump handler is invoked only on the pipe path of fs/coredump.c::do_coredump, and when RLIMIT_CORE is 1 the kernel gives up before the call (NB-E-K-01); the execution cannot raise the hard limit of RLIMIT_CORE back; the other rows do not go through it. The rows listed above are the ones that decide whether a core is produced and which segments it contains; every row that writes memory or changes comm or auxv changes the content of the core, and these are judged together in the cell NB-E-K-01 × N-12 (corrected by the targeted re-review) |
| NB-N-13 | rows in which the kernel sends records or events to host observation components: NB-E-K-02 (kernel log), NB-E-K-09 (fsnotify events and fanotify permission events), NB-E-K-10 (process event connector), NB-E-K-11 (BSD accounting), NB-E-K-12 (taskstats), NB-E-K-13 (audit), NB-E-K-14 (tracing facilities) | the other rows produce no records sent to host components: the records they trigger are all sent through the rows above (each row's follow-on actions are handed to them); host processes that read the execution's comm, cmdline and environ through the host's /proc do not receive them from the kernel, and this is judged by N-06 in the cells of the rows that shape this content: prctl's PR_SET_NAME and PR_SET_MM_MAP, write (/proc/self/comm), execve (argv, envp and comm), NB-E-M-07 (writing the argument and environment areas on the stack); host processes and users the deployer did not install (NB-S-14) are the objects of the effect when they read the kernel log or /proc, and this is likewise judged in the cells of N-06; what the /proc readers the deployer installs (that half of NB-S-17) read is also judged in the cells of N-06; the pressure readings of PSI are machine-wide aggregate state, judged by N-06 in the cell of NB-E-K-04 |

#### 3.7 Items handed to block two

- **SO_PEERPIDFD** (NB-E-S-getsockopt/SO_PEERPIDFD, NI): the execution can get, in its own fd table, a pidfd pointing to the spawner (01-trace-events §8).
  This is a value the system-call table did not list; it appeared only when the values were derived from the dispatch locations. It gives a reference to a trusted process on the host, and through it the execution can read whether the spawner is still alive. The NI chapter judges its candidate effects under SPEC §4.1, and the PS chapter puts a cross-chapter mark on the information of the same kind that parent notification and pdeathsig can already read.
- **Cells of the construction rows**: the branches of NB-K-01 and 02 belong to 02; their cells are added to this file from the initial-state items of §2 before block two starts, and the chapter code those cells cite is BB. The branches of NB-K-03…10 belong to LC (§1.3); their cells state the preservation and interference obligations of constructing another execution at run time, while this execution's own initial state is still carried by §2.
- **Interference obligations of the construction window**: the item "effects of other subjects on child during the construction window" of §2.3 is recorded as undetermined. The PS chapter judges, in the cells NB-E-S-kill × NB-N-07 and NB-E-P-03 × NB-N-07, the effect of same-session SIGCONT and of orphaned-process-group signals on the child under construction. The LC chapter judges the other concurrent effects in the cells of NB-K-03…10. After the decision, that item is filled in (review one, Codex's comment R5).
- **Host observation components**: the seven branches of NB-N-13 belong to GS (§3.2). What the components do after reading the records is a deployment precondition, which the GS chapter writes into the deployment limits under SPEC §5.1. The cell NB-E-K-09 × N-13 must state that path-type fanotify events and event fds pin the execution mount the event went through (in this configuration the binds of /work and /runtime; for the conditions of this scope see 01 NB-E-K-09; the reference is already taken while the event is in the queue), must check the reference kind of FID-mode events, and must state that the pidfd attached to an event is only an identity reference to the struct pid (§2.5).
- **Host-observable cells**: under the host visibility rule of 01 §2.6, the part the host can see without privilege and the part whose visibility is undetermined are not recorded as "private". In the cells of N-06 they are recorded as "host-observable · verified" or "host-observable · treated as visible" (SPEC §4.1 kind 4: an outbound content channel to host readers, written into the conclusion as a limit). Block three's summary counts the two separately. Where deployment conditions (host /proc mounted with hidepid, the cell on an exclusive virtual machine) can make them invisible to ordinary host processes, they will later be changed back to private, as a deployment condition.
- **Private cells**: the I2 of SPEC §4.2 covers only the part of a private candidate that the host can reach only with privilege (01 §2.6). A cell that records "private" writes in its dependencies, besides "subject (whole table)", also NB-AA-08 (privileged host processes do not take, read or write private objects). check_coverage.py currently checks only the former; the latter is added to the check when the sample chapter fixes the format.
- **Classification of the records host observation components receive (to be decided)**: the audit, accounting, taskstats, process-event and tracing records the kernel sends to host observation components also contain content taken from the execution's own state (comm and so on), written into host objects. The host-observable exception of SPEC §4.1 covers only the part visible through /proc and the kernel log, so for now these writes can only be judged by the priority rule. Before the GS chapter is written, their classification is to be decided, written into SPEC §4.1 or into this section, and handed to the author (R0d second targeted re-review, Claude's item 7 of that round).
- **TLC and reverse tests**: for transition granularity see §1.2. The branch table decides which cells are to be tested (the test-obligation table of TESTING); test numbers are set when the chapters write their cells.
