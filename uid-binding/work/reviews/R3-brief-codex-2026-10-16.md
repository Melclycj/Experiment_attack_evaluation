# R3 review brief — Codex (cross-family), uid-binding security argument

Written 2026-10-16 by the executor for the user to dispatch (PLAN §Review points: at R3 the user dispatches
the Codex review; the executor supplies this brief and adjudicates the findings). Repository root
`<repository root>`, branch main at commit `6ed23699` (the convergence commit). You are a cold-context reviewer: you
have no access to the executor's conversation, you edit nothing, and you write exactly one file.

## What you write

A new file named R3-addendum-2026-10-16-crossfamily.md in the same folder as this brief (the reviews folder
of the uid-binding line's work directory) — numbered findings
`F-01`, `F-02`, … each with: the file and line, severity (P1 = a disposition, count or check claim that is
wrong; P2 = a route file not reconstructible from itself, a vocabulary or format breach, or a check whose
recorded finding does not match the files; P3 = wording, precision), the defect in two sentences, and one
line "what would resolve it". End with a gate line: "may pass" / "may not pass" for the user gate U, with
the reason. Keep the stdout summary to counts and file names only (the provider's safeguard has blocked
narrative summaries of this material before; the record file is what counts).

## Files under review (read-only)

- `Thesis/Work/Submission/prove/uid-binding/work/convergence/reconcile.md` — the twelve checks, the pitfalls, the
  judgements (a)–(g), the counts, the re-read record.
- `Thesis/Work/Submission/prove/uid-binding/work/convergence/change-requests.md` — section "2026-10-15 — fan-out
  change requests" (CR-F-01 … CR-F-09) and their application as 01 v8 / 02 v4 / 03 v4.
- `Thesis/Work/Submission/prove/uid-binding/work/convergence/obligations-for-engine.md` (75 obligations in three
  classes) and `coverage-uncertainties.md`.
- `Thesis/Work/Submission/prove/uid-binding/work/convergence/uid-binding-vector-table.md` — the preface, the
  five-column table (38 rows, extracted mechanically), counts, residual line, disposition and coverage
  statement.
- Route files, under `Thesis/Work/Submission/prove/uid-binding/work/groups/`: **all three routes marked
  "supported under stated premises"** (`G5-boundary/R-G5-03.md`, `R-G5-04.md`, `R-G5-07.md`), **all six GX
  routes** (`GX-cross-group/R-GX-01.md` … `R-GX-06.md`), and **one route of your choice from each of G1, G2,
  G3, G4**; the conclusion lines of the five `preservation.md` files; `G4-close-and-reclaim/preservation.md`
  §D4.
- The spine, read-only: `work/spine/01-model-inventory.md` (v8), `02-conditions-and-decomposition.md` (v4),
  `03-invariant.md` (v4), `04-evidence-registry.md` (v4), `VERSIONS.md`; the ten frozen design files listed
  in `Thesis/Work/Submission/prove/uid-binding/PLAN.md` §Frozen design revision; the method rules in PLAN §Execution
  flow (Convergence, Review points, Reading format) and §Context to resume cold (2).
- Never read `.goals/plans/uid-binding-security-argument.draft-table.md` (the sealed draft) or any other
  prewritten vector table.

## What you check (PLAN §Review points, R3 row)

1. **The reconcile checks were actually performed and their findings match the files.** Re-run the
   mechanical half yourself: `PYTHONIOENCODING=utf-8 python Thesis/Work/Submission/prove/uid-binding/work/tooling/reconcile-checks.py`
   (without `-I`); compare its output with reconcile.md §1 and §4. For the judgement half (§1 rows marked
   "read"/"judgement", §2 pitfalls, §3 judgements) check each claim against the files it names.
2. **Disposition and vocabulary rules.** Exactly one of four dispositions per route; `stops:` equals section
   3's first sentence; section 5 states the disposition; no rate or percentage wording; none of the words
   *closure, closed, complete, exhaustive, proven, fixed-point* except the one allowed qualified form
   "complete relative to M" in the table file and `CLOSED` as the state name; evidence only by EV ID and the
   tag as the registry (v4) has it.
3. **A sampled route file is reconstructible from itself.** For each sampled route: can a reader, from that
   one file plus the IDs it cites, state what the adversary does, which condition is violated, what stops
   it, on which evidence, and what remains — without opening another route file?
4. **No `[S]`-dependent route is "supported under stated premises".** For R-G5-03, R-G5-04, R-G5-07: is any
   *necessary* component of the defence tagged `[S]` in the registry? Is the premise each names in section 5
   the premise whose departure T-67's branches (a), (b), (f) model (reconcile.md §3 (a))? Is the "supported"
   conclusion a kernel-semantics conclusion with its evidence limit stated?
5. **The table is mechanical.** Spot-check five rows of the table against the route files' front matter and
   section 1.
6. **The counts.** 3 / 25 / 8 / 2; 52 preservation rows, 50 preserve; D4 7 / 6 / 3; 75 obligations; registry
   141 rows (35 / 48 / 58).

Do not propose new routes, do not re-derive the decomposition (that was R1's scope), do not review Steps
1–3 (R2's scope) except where a convergence claim depends on a specific spine sentence. Findings on the
method itself go in a separate final section "out of scope for R3, recorded".
