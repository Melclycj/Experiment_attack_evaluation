# Fan-out brief — fixed for every wave-1 and wave-2 agent (2026-10-14)

This brief is identical for every fan-out stream (PLAN §Execution flow, management rule 6). The per-stream
part — your folder, your transition IDs, your route IDs — is given in the task prompt. Where the prompt and
this brief disagree, this brief wins. Repository root: `<repository root>`. All paths below are relative to it.

## 0 Your role

You own exactly one folder (or, for Stream Q, one file; for Stream P, one lab report with its script and
results). Nobody else writes there; you write nowhere else. The spine is read-only for everyone during
fan-out. You do not run `git`; the reconcile role commits your folder after its own checks.

## 1 Read-only context

**The four spine files** (their blob ids go into every header you write; `git hash-object <path>`, first
16 hex digits):

| file | version | blob id |
|---|---|---|
| Thesis/Work/Submission/prove/uid-binding/work/spine/01-model-inventory.md | v7 | `7345e9c5d8face07` |
| Thesis/Work/Submission/prove/uid-binding/work/spine/02-conditions-and-decomposition.md | v3 | `558f035982198c7c` |
| Thesis/Work/Submission/prove/uid-binding/work/spine/03-invariant.md | v3 | `af8662ca14b83598` |
| Thesis/Work/Submission/prove/uid-binding/work/spine/04-evidence-registry.md | v3 | `b868512116d812f0` |

The table above is the **fan-out gate set** (2026-10-14). A file written or re-run after a later spine version
copies the **current** set instead: the latest numbered row per file in VERSIONS (on 2026-10-16: 01 v8
`9efb243354a4e9d6`, 02 v4 `31ddfc5daba58f13`, 03 v4 `6868389a2182c161`, 04 v4 `f36170e09dd4c2a9`); the
dispatcher's prompt states which set applies. Also read-only in the spine folder: `03-tlc/Invariant03.tla` (v3) with its `.cfg` and `.log` files,
`00-group-cut-inputs.md`, `VERSIONS.md`.

**The ten frozen design files** (the text the model describes; blob ids in PLAN §Frozen design revision;
verified identical in the working tree on 2026-10-14):

1. ExperimentLab/lab/experiments/w2/implementation/engine-design/connections.md (E-01 launch and admission,
   E-02 receive pipeline, E-03 request/response, E-04 close/stop/reap and the uid reclamation double gate)
2. ExperimentLab/lab/experiments/w2/implementation/engine-design/resources-routing.md (E-06, E-07)
3. ExperimentLab/lab/experiments/w2/implementation/engine-design/supporting-interfaces.md (E-09, E-10)
4. ExperimentLab/lab/experiments/w2/implementation/sandbox-design.md
5. ExperimentLab/lab/experiments/w2/implementation-validation.md (acceptance run 2026-09-11)
6. Thesis/Work/Design/sandbox-mediated-agent-execution/mechanism.md (§Identity lifecycle, §Proof-obligation
   discharge status — obligations #1–#6)
7. Thesis/Work/Design/sandbox-mediated-agent-execution/option-b-workload-per-engine.md (spawn sequence,
   configuration premises C1–C4 as designed)
8. Thesis/Work/Design/sandbox-mediated-agent-execution/kernel/kernel-uid-binding.md (§2–§8; "kub" in the
   spine's citations)
9. Thesis/Work/Design/sandbox-mediated-agent-execution/scope-and-boundary.md (§Boundary Defence: adversary
   declaration, non-goals, kernel-breach paragraph, five-surface table, S1–S14)
10. Thesis/Work/Design/sandbox-mediated-agent-execution/threat-model-derivation-map.md (D1–D10)

**Also allowed, read-only:** the lab reports and other sources the evidence registry cites (to check an
excerpt before relying on it); the two templates in this folder (`route-record.md`,
`preservation-row.md`); the review records under `work/reviews/` and `work/convergence/change-requests.md`
(to see why a spine sentence reads as it does); PLAN.md §Context to resume cold, §Frozen design revision
and §Execution flow (rules and vocabulary; the plan's pre-registered hypotheses are *not* givens — see §4).

**Never read:** the sealed draft `.goals/plans/uid-binding-security-argument.draft-table.md`, or any other
prewritten vector table. If a file you open turns out to be a prewritten table of routes and defences,
close it and say so in your return message.

## 2 What you write

- `preservation.md` from `preservation-row.md`: one row per transition ID that 02 §7 (group cut) assigns to
  your group, nothing more and nothing less; the justification rows; the four conclusion lines in the exact
  form of the template (they are what the reconcile role reads).
- One `R-<route-id>.md` per route the 02 §6 ledger assigns to your group, from `route-record.md`, file name
  exactly the route ID plus `.md`. Withdrawn ledger entries (their IDs are reserved) get no file.
- Optionally `change-requests.md` **inside your folder**: a request for a change to a shared file (a spine
  file, a template), naming the IDs it would change and why. The reconcile role merges it into the
  convergence folder's `change-requests.md`; you never edit that file or the spine.
- Delete the template's instruction comment in every real record. Fill every front-matter field.

## 3 Header and field rules

- `based_on`: the four blob ids above, copied exactly.
- `status: ready-for-reconcile` when you are done; `draft` while working.
- `violates:` = the condition ID(s) from the ledger's third column, copied.
- `stops:` = one phrase; section 3's first sentence must say the same thing. For *open* write
  `none in the frozen design`; for *declared out of scope* write `declared exclusion: <paragraph cited>`.
- `disposition:` = exactly one of `supported under stated premises` · `conditional on unbuilt requirements`
  · `open` · `declared out of scope`; section 5 states the same value.
- Section 1 copies the ledger's one-sentence adversary action verbatim and names no defence.

## 4 Content rules

- **Property.** Ground truth = the kernel task that executed `sendmsg`, identified by the pid namespace the
  spawner created for one execution; label = the session row the engine reads at accept. The property is
  "the label's execution is the ground-truth task's execution"; time semantics are live-at-send (02 §0.1,
  §0.2). Never define the ground truth as "whoever holds the uid".
- **Configuration.** State which configuration the route assumes: C-LS, C-LP, C-R, or all three under the
  common abstraction of the frozen revision (PLAN §Frozen design revision, "Supported configurations").
- **Transitions.** Any T-nn from 01 may be cited as a Step 1 fact, whichever group owns it. Another group's
  preservation *conclusions* may not be cited; a route whose defence rests on them is cross-group (GX) and
  is not yours — say so in section 6 and stop.
- **Invariant.** The guards are IG-01…IG-13 in 03 §2. 03 §5.2 lists what the TLA+ subset does *not* encode
  (among them T-01's "previous lease CLOSED and empty" check and T-03's spawner admission check); your
  preservation rows argue those in prose from the frozen text, they do not inherit the TLC result.
- **Evidence.** Only by registry ID (EV-nn, tag as the registry has it). Composition rules (template §4): a
  necessary `[S]` item bars *supported under stated premises*; an isolated `[M]` component never makes a
  composed, partly unbuilt defence measured end to end; an `[M]` taken under the diagnostic policy is
  tagged so, with the production policy a separate `[S]`; `[S]` here ≡ `[U]` in option-b /
  scope-and-boundary. New evidence goes in the "Proposed evidence" rows without an ID.
- **Design-level vs realized.** A *supported under stated premises* disposition is a design-layer or
  kernel-semantics conclusion; say so in section 5's premises. Nothing you write is a claim about the
  deployed system.
- **Pre-registered hypotheses.** PLAN names defences for some routes (C2 / spawn step 11 for the
  configuration-failure route; the qmsg case; the probe's expected errno values). They are hypotheses. Use
  02 §4.1's independent re-derivation; if your derivation disagrees with 02 §4.1, write the disagreement in
  section 6 and in a change request, never silently.
- **Obligations and conditions.** Where a route touches kub §6 C1–C4 or mechanism obligations #1–#6, name
  them in section 6 (reconcile maps them).
- **Counterexamples.** A transition that does not preserve I is recorded as `does not preserve` with the
  offending state; the transition is never removed from the model and I is never weakened in your file; a
  proposed strengthening goes to the conclusion lines and a change request.
- **Collapses.** Every collapse of states, inputs or histories (two executions → one, N requests → one,
  one recycle) has a justification row.

## 5 Forbidden list (identical for every stream)

- Do not read the sealed draft (§1).
- No rate, percentage or success-rate wording anywhere.
- Do not write the words *closure*, *closed*, *complete*, *exhaustive*, *proven* or *fixed-point* — not
  even qualified. Say "stopped", "not reachable within the stated premises", "all 38 ledger routes",
  "argued", "within the bounds stated". The lifecycle state is written `CLOSED` in capitals exactly as 01
  names it, and only as that state name.
- Do not edit the four spine files, the templates, or another stream's folder; do not create files outside
  your folder.
- Cite files by Markdown link or bare file name. Never write a backtick-quoted path that contains a slash
  (the pre-commit path guard rejects it). IDs (T-, C-, IG-, EV-, R-) are plain text.
- No new ID of any kind: routes, conditions, transitions and evidence IDs are created only by a spine
  version. A route you believe is missing is a change request.

## 6 Size and return message

- A route file is normally 60–150 lines; a preservation row is terse but says why I holds after the
  transition from any I-state, with the guard IDs touched.
- Your return message is at most 15 lines and contains only: files written (names), routes by disposition
  (counts for a / b / c / d), preservation results (counts of preserves / does not preserve / design
  unstated), number of proposed-evidence rows, number of change requests, and the four conclusion lines
  verbatim. Do not narrate attack routes in the return message; the files carry the content.
