# The argument for the identification link

Section 5.2 of the thesis reports a structured argument for one property of an earlier version of the engine. This folder holds its full method and the table of all 38 cases. It is a structured security argument relative to versioned models. It is not a machine-checked proof, and it was not redone on the engine as finally built.

**Start with** [security-argument.md](security-argument.md), which holds the table and the counts. Files in Chinese: [ARGUMENT.md](ARGUMENT.md), the method summary, and parts of [work/](work/). `work/` holds the records as they were written, including the briefs given to AI drafters and reviewers and dated decisions by the author (Section 5.3 of the thesis describes that process).

## The property

The label the engine reads when it accepts a message names the execution of the kernel task that executed `sendmsg`, with live-at-send time semantics. Each accepted message labelled X was preceded by a send from a task of X that still held the allocated uid when it sent. Same-uid siblings are one execution class by construction, and they lie outside the property. The full statement is §0 of [work/spine/02-conditions-and-decomposition.md](work/spine/02-conditions-and-decomposition.md).

## The eight conditions

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

## The result

Of 38 routes, 35 are supported under stated premises, 1 is conditional on unbuilt requirements, 0 are open and 2 are declared out of scope. The conditional route is R-G2-11, the memory safety of the C frame reader, a requirement that this argument does not establish. A fuzz run is supplementary evidence only. That requirement is a premise of every engine-side route, and it is counted once. The two routes out of scope need a kernel or hardware flaw.

## Premise classes of the 35 supported routes

Details are under "Counts" in [security-argument.md](security-argument.md). All of them also assume the kernel at the pinned tag, the single executor, the honest spawner and that the engine's code runs as written.

| Class | Routes | What it means |
|---|---|---|
| Kernel semantics and the checked prototype, no deployment premise | 22 | The stop is design text realized in the prototype and checked, or a kernel reading at the pinned tag |
| A deployment precondition the engine cannot check | 12 | For example the engine in the initial user namespace, or an exclusive uid pool |
| A deployment mechanism not yet built | 1 | R-GX-04: the kernel fact was measured once on the development host, and the mechanism exists on no host |

## Model checking with TLC

TLC checks only a bounded lifecycle subset: that the invariants hold on all reachable states of that subset. It does not check that every step preserves them, and the preservation arguments are written by hand.

- **First group.** Two executions sharing one pool uid, at most three tasks per execution, a receive queue of two skbs per channel, two allocation generations and two engine epochs ([work/spine/03-invariant.md](work/spine/03-invariant.md) §5.2). The double gate gives no violation over 152,054 distinct states.
- **Negative controls, same file.** With the membership half of the gate removed, TLC reports a violation of uid exclusivity four actions after Init, and a false attribution twelve actions after Init. This shows that the model is not vacuous.
- **Second group** ([work/05-concurrency.md](work/05-concurrency.md) §5.3, with models and logs in [work/05-concurrency-tlc/](work/05-concurrency-tlc/)). Runs 5b and 5c found no violation. Run 5d found the expected counterexample, through same-uid reuse.
- **Two runs of the second group did not finish.** Run 5a was stopped at its ten-minute limit at breadth-first depth 23, with about 7.2 million states queued. Its reduction 5a-t2 ended without a termination message at about 12 minutes, at depth 25, with about 7.9 million states queued. Neither found a violation in the states it explored, and neither is a result over its bounds.

## Prototype checks

A route counts as supported when every necessary item of its defence is backed by a measurement or a source reading. The prototype was checked at commit 3ec67985 on a WSL 2 development host, under a diagnostic seccomp policy, with the model chain and resources as stub connectors. Each check's own limits are in its route record under [work/](work/). No row is a claim about a deployed system, and no row is measured end to end.

Links in these working files that lead outside this repository have been turned into plain text.
