# The two structured arguments (Section 6.1)

Section 6.1 of the thesis reports two attempts at a structured security argument, both on an earlier version of the engine than the one Chapters 3 and 4 evaluate. Neither is a machine-checked proof, and neither was redone on that later version.

| The thesis says | Here |
|---|---|
| "on an earlier version that allowed 74 system calls, listing the actions gave 306 cases, each to be argued from the kernel source" | [no-bypass.md](no-bypass.md) |
| "Of the 38 ways a label could go wrong … we judged 35 stopped under stated premises" | [uid-binding.md](uid-binding.md) |

Under [original/](original/) are the records as they were written: the Chinese originals of the no-bypass enumeration, the working records of the uid-binding argument and the source of the earlier engine. As the thesis says, AI coding agents drafted this work under the author's direction, and `original/uid-binding/work/` keeps the briefs they were given and the author's dated rulings. Links in these records that led outside this repository are plain text. Section numbers inside them follow the thesis drafts of their time.

## Which version they analyse

Both analyse the directory `ExperimentLab/engine` of the author's working repository, with the kernel `microsoft/WSL2-Linux-Kernel` at tag `linux-msft-wsl-6.6.87.2`.

- **No-bypass** analyses baseline v1, the directory at commit `aa3f2803` (2026-10-24). Its 82 files are in [original/engine-v1/](original/engine-v1/), byte for byte as exported.
- **Uid binding** cites the same directory at commits up to `b262e80e` (2026-10-21). Between that commit and `aa3f2803`, nine files of the directory changed: `BUILD-PLAN.md`, `native/README.md`, `native/checks/agent_fixture.c`, `native/checks/check_catalogs.py`, `native/checks/run_sandbox_checks.py`, `native/sandbox/child.c`, `native/sandbox/policy.c`, `native/sandbox/support.h` and `validation.md`. The route records name the commit each piece of evidence rests on.

## No-bypass

The property is that what the engine does not hand to an execution, the execution cannot obtain without the engine. The method lists every action an execution can take, so that coverage is complete relative to the model, and each action's consequences become branches to be argued from the kernel source. On baseline v1, with its allow list of 74 system calls, this gave 306 branches. [no-bypass.md](no-bypass.md) holds the method, the 74 calls and the branch table. The branches were not argued one by one.

## Uid binding

### The property

The label the engine reads when it accepts a message names the execution of the kernel task that executed `sendmsg`, with live-at-send time semantics. Each accepted message labelled X was preceded by a send from a task of X that still held the allocated uid when it sent. Same-uid siblings are one execution class by construction, and they lie outside the property. The full statement is §0 of [original/uid-binding/work/spine/02-conditions-and-decomposition.md](original/uid-binding/work/spine/02-conditions-and-decomposition.md).

### The eight conditions

Sufficient conditions on decision inputs, defined in §2 of the same file. C-06 and C-07 are deliberately stronger than necessary.

| Condition | What it requires |
|---|---|
| C-01 origin and frame association | The bytes of an accepted message come from actual send events and from one read, one channel, one generation and one frame, with nothing inserted or substituted |
| C-02 stamp equality | Every contributing origin carries a valid kernel uid stamp, equal to the sending task's uid at the send |
| C-03 faithful observation | The uid mapping is defined and injective on the uids involved, the engine reads the stamp faithfully, and the stored comparand is in the same number domain |
| C-04 actual comparison | Every contributing fragment underwent the equality decision against the same original comparand, with no fallback identity source |
| C-05 row and label anchor | The row read at accept has the immutable reservation of its original channel, and the label's fields come from that record |
| C-06 spatial uid exclusivity | During the allocation interval no other execution holds the uid, and every task with that real uid belongs to this execution's process set |
| C-07 time association | Every send falls inside the allocation interval |
| C-08 consumer continuity | Every consumer's claimed sender equals the label produced at accept, and no originless verified subject is introduced |

Taking the contrapositive, histories that violate the property split by first failed condition into disjoint cells, with a remainder slot in each cell. A mechanical check confirms that each history reaches exactly one route, which is what the route table enumerates. Coverage is relative to the listed model and predicates, not a claim that these are all the mechanisms there are.

### The result

Of 38 routes, 35 are supported under stated premises, 1 is conditional on unbuilt requirements, 0 are open and 2 are declared out of scope. The conditional route is R-G2-11, the memory safety of the C frame reader, a requirement that this argument does not establish. A fuzz run is supplementary evidence only. That requirement is a premise of every engine-side route, and it is counted once. The two routes out of scope need a kernel or hardware flaw. The route table is in [uid-binding.md](uid-binding.md).

### Premise classes of the 35 supported routes

Details are under "Counts" in [uid-binding.md](uid-binding.md). All of them also assume the kernel at the pinned tag, the single executor, the honest spawner and that the engine's code runs as written.

| Class | Routes | What it means |
|---|---|---|
| Kernel semantics and the checked prototype, no deployment premise | 22 | The stop is design text realized in the prototype and checked, or a kernel reading at the pinned tag |
| A deployment precondition the engine cannot check | 12 | For example the engine in the initial user namespace, or an exclusive uid pool |
| A deployment mechanism not yet built | 1 | R-GX-04: the kernel fact was measured once on the development host, and the mechanism exists on no host |

### Model checking with TLC

TLC checks only a bounded lifecycle subset: that the invariants hold on all reachable states of that subset. It does not check that every step preserves them, and the preservation arguments are written by hand.

- **First group.** Two executions sharing one pool uid, at most three tasks per execution, a receive queue of two skbs per channel, two allocation generations and two engine epochs ([original/uid-binding/work/spine/03-invariant.md](original/uid-binding/work/spine/03-invariant.md) §5.2). The double gate gives no violation over 152,054 distinct states.
- **Negative controls, same file.** With the membership half of the gate removed, TLC reports a violation of uid exclusivity four actions after Init, and a false attribution twelve actions after Init. This shows that the model is not vacuous.
- **Second group** ([original/uid-binding/work/05-concurrency.md](original/uid-binding/work/05-concurrency.md) §5.3, with models and logs in [original/uid-binding/work/05-concurrency-tlc/](original/uid-binding/work/05-concurrency-tlc/)). Runs 5b and 5c found no violation. Run 5d found the expected counterexample, through same-uid reuse.
- **Two runs of the second group did not finish.** Run 5a was stopped at its ten-minute limit at breadth-first depth 23, with about 7.2 million states queued. Its reduction 5a-t2 ended without a termination message at about 12 minutes, at depth 25, with about 7.9 million states queued. Neither found a violation in the states it explored, and neither is a result over its bounds.

### Prototype checks

A route counts as supported when every necessary item of its defence is backed by a measurement or a source reading. The prototype was checked at commit `3ec67985` on a WSL 2 development host, under a diagnostic seccomp policy, with the model chain and resources as stub connectors. Each check's own limits are in its route record under [original/uid-binding/work/](original/uid-binding/work/). No row is a claim about a deployed system, and no row is measured end to end.

Files in Chinese under `original/`: the no-bypass originals, `original/uid-binding/ARGUMENT.md`, `original/uid-binding/method-review.md` and some files under `original/uid-binding/work/`.
