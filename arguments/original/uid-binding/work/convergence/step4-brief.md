---
role: brief for follow-up step 4 (PLAN §Follow-up plan after U, step 4) — read by the registry agent and every route re-run agent
date: 2026-10-19
supersedes: nothing; it adds to [fanout-brief](../_templates/fanout-brief.md), which still applies except where this file says otherwise
---

# Step 4 brief — re-judging routes on the engine build's checks

## 0 What changed and what this step does

The engine prototype has been built (ExperimentLab/engine, BUILD-PLAN steps 1–4) and every must of
engine-requirements.md §1–§8 has a recorded check in the engine's validation record
(validation.md, blob `3d35d8704cd79b5e`, commit 3ec67985).
The design did not change: the spine (01 v10, 02 v9, 03 v5) stays as it is. What changes is the evidence:
design statements that were `[S]` (stated, not built) now have implementation evidence — tests observed in
recorded runs, fuzzing, and code reading of the project's own engine code. Step 4 registers that evidence
(04 v7) and re-judges the 27 routes conditional on unbuilt requirements and the 3 open remainder slots
(R-G2-11, R-G2-12, R-G2-13) on it.

## 1 Disposition rule for this step (user ruling 2026-10-19)

A route moves from *conditional on unbuilt requirements* to *supported under stated premises* when **every
necessary item** of its section-4 composition is backed by `[M]` or `[R]` evidence — the `[S]` design
statement now realized in the prototype and checked (test, fuzz or code reading). The section-5 evidence
limit must then name the realization's limits: the prototype engine at commit 3ec67985 (engine code at
74833c58, unchanged by later commits except one test-build line), the WSL2 development host (kernel
6.6.87.2-microsoft-standard-WSL2), the diagnostic seccomp policy (the production allow-set S2 is P2b's and
stays `[S]`), the model chain and resources as stub connectors, and the check's own stated limits as
validation.md gives them (for example: fuzz one hour per entry, no repetition; fd reuse made by the test,
not by the real spawner).

A route stays *conditional on unbuilt requirements* if any necessary item is still `[S]` — not built,
outside the build's scope (validation.md "超出范围": the production seccomp allow-set, row 177; the trusted
supervisor, row 218), or only partly checked. Name the remaining `[S]` item(s) in section 5. A deployment
precondition the engine does not check (engine-requirements §8) is a **premise**, not an `[S]` item, as the
2026-10-18 rulings already treat R-G5-06 and R-G5-08: it goes in the premises line and does not by itself
bar *supported*.

An open remainder slot (R-G2-11 / 12 / 13) leaves *open* when its closing property (PLAN §Follow-up plan,
the seven-slot table) is established by the named check; its `stops:` then names that property and the
check, not "none in the frozen design".

What stays true: no row is a claim about the deployed system. "Supported" now rests on the frozen design,
kernel semantics where cited, and the prototype's checked realization, under the premises and limits stated.
Do not write that a route is "measured end to end" unless one recorded run exercised the whole composed
defence; an isolated measured component still never makes a composed defence measured end to end (template
§4).

## 2 Current ids (copy into every header you write)

| file | version | blob id |
|---|---|---|
| 01-model-inventory.md | v10 | `d27d65d7874bbf6c` |
| 02-conditions-and-decomposition.md | v9 | `5d2a0b9438f37302` |
| 03-invariant.md | v5 | `ae58d7db31c95c82` |
| 04-evidence-registry.md | v7 | `97b869a738a79b0e` |

Design files at the fourth revision: connections.md `0c16e567a34aa441`, resources-routing.md
`1a8ea18374b07431`, supporting-interfaces.md `c8aff1a37d73561b` (all under
ExperimentLab/lab/experiments/w2/implementation/engine-design/); engine-requirements.md `20acd533e99dd35c`.

## 3 Registry step (one agent; writes 04 and one map file)

- Append rows EV-163 onward to 04 §1, in the existing column format; update the front-matter status, §0's
  source-abbreviation table (add the engine sources: the validation record, the engine code at commit
  3ec67985, and each run directory cited), §4 counts. Append-only: no existing row changes.
- Tags. `[M]` = observed in a recorded run under ExperimentLab/engine/runs (unit, root unit, integration,
  sandbox regression, fuzz); the row carries the run directory, its date and the substrate string from the
  run's README, and "diagnostic policy" where the sandbox ran under it. `[R]` = code reading of the
  project's own engine or sandbox code (as EV-149 does for support.c), with file:line at the commit named
  in the source column. Fuzzing is `[M]` with the run's duration and limits in the note.
- One fact per row; primary source = the run directory or the code file; name validation.md's row (its
  "行号" = the engine-requirements line) in the note column so a reader can find the mapping.
- Register only facts that bear on an existing `[S]` row cited by a route file, plus the closing properties
  of R-G2-11 / 12 / 13 and the AA-13 check. Do not register checks unrelated to attribution (business stubs,
  availability).
- Write [step4-evidence-map.md](step4-evidence-map.md) beside this brief: one row per `[S]` EV row cited by
  any route file under work/groups (find them by grep), with columns: `[S]` EV · engine-requirements line(s)
  · validation result (copied words: 满足（测试）, 超出范围, 部署前提, …) · new EV ID(s) that back it · still
  `[S]`? (yes / no / partly, with the reason). Then a second short table for the three remainder slots:
  slot · closing property · new EV IDs · established? (yes / partly, reason).
- Never state a disposition or name a route as stopped in 04 (registry rule 2); the map file may name routes
  only in a "cited by" column.

## 4 Route re-run (one agent per group folder)

- Re-run only the route files named in the prompt. Keep section 1 verbatim. Rewrite sections 3–6 as
  needed: section 4 cites the new EV rows (keep the `[S]` rows the design text still supplies, now next to
  their realization evidence), the composition paragraph says which items are realized and checked and
  which stay `[S]`, section 5 applies §1 above, section 6 lists what remains.
- Update the front matter: `based_on` (§2 ids), `stops:` (first sentence of section 3), `disposition:`,
  `status: ready-for-reconcile`, and the date. Preservation files are not re-run (the design did not change).
- Read the code when a validation row is "满足（代码阅读）" and the route depends on it: confirm the cited
  file:line says what the row says. A disagreement goes to section 6 and to your folder's change-requests.md.
- The fanout-brief §5 forbidden list applies in full, including the vocabulary ban.
- Return message: at most 15 lines — files rewritten, dispositions before → after per route (route ID and
  the two values only), change requests, and any validation row you found not to support what it claims.
