---
route_id: R-G?-??            # from the route ledger at the end of 02-conditions-and-decomposition
group: G?                    # G1 launch-admission · G2 receive-and-check · G3 request-and-dispatch · G4 close-and-reclaim · G5 boundary · GX cross-group
owner:
status: draft                # draft · ready-for-reconcile · returned · accepted
violates: C-??               # sufficient condition ID(s) from 02, copied from the ledger (table column 3)
stops: ""                    # one phrase, what cuts the route (table column 4); for open write "none in the frozen design", for declared out of scope write "declared exclusion: <paragraph>"
disposition: ""              # exactly one of: supported under stated premises · conditional on unbuilt requirements · open · declared out of scope (table column 5)
based_on:                    # git blob id prefix of each spine file at fan-out (git hash-object <path>); staleness is visible here
  model_blob: ""             # 01-model-inventory
  decomposition_blob: ""     # 02-conditions-and-decomposition
  invariant_blob: ""         # 03-invariant
  registry_blob: ""          # 04-evidence-registry
---

# R-G?-?? — <one-line adversary action, copied verbatim from the route ledger>

<!-- Template (2026-10-12). One route = one file; everything about the route lives here. Outward
references are only evidence IDs (EV-nn), transition IDs (T-nn) and condition IDs (C-nn). Transition
IDs from any group may be cited (they are Step 1 facts); another group's preservation CONCLUSIONS may
not — a route whose defence rests on them is a cross-group route (GX). Forbidden: reading the sealed
draft; rates, percentages, success-rate wording; the unqualified words closure / closed / complete /
exhaustive / proven / fixed-point;
editing the spine files or another group's folder. Cite planned or untracked files by bare file name
or Markdown link, never as a backtick-quoted path with a slash (the pre-commit path guard blocks
those). Delete this comment in a real record. -->

## 1 What the adversary does
One sentence: the causal route to false attribution, as the ledger states it. Name no defence here.

## 2 How it would produce false attribution
- **Preconditions:** what the adversary must already hold or do; configuration assumed (C-LS / C-LP /
  C-R, or all three under the common abstraction of the frozen revision).
- **Transitions traversed:** T-nn IDs from 01-model-inventory, in order.
- **Sufficient condition violated:** C-nn from 02-conditions-and-decomposition, its branch predicate
  (which ¬P this route realises), and why the violation yields a wrong attribution (the engine's label
  vs the ground-truth sending task).

## 3 What stops it
The mechanism, named at the transition where the route is cut, and the preservation row(s) in this
group's preservation file it relies on (T-nn → row). If nothing in the frozen design cuts the route, say
so here and give disposition *open* in section 5. For a route that lands in the declared exclusion, cite
the exact boundary paragraph here and give *declared out of scope* in section 5. The first sentence of
this section must match the `stops:` field.

## 4 Support
| evidence id | tag | what it shows | file and section | date / substrate / version |
|---|---|---|---|---|
| EV-nn | [M] / [R] / [S] | | | |

**Composition:** how the items join (conjunction, alternatives). Rules: a necessary `[S]` item means the
disposition cannot be *supported under stated premises*; an isolated measured component never makes a
composed, partly unbuilt defence measured end to end; `[S]` here ≡ `[U]` in option-b / scope-and-boundary;
an `[M]` taken under the diagnostic policy is tagged so, with the production policy as a separate `[S]`.

**Proposed evidence (not yet in the registry):** rows without an ID; reconcile appends them to the
registry (append-only; existing IDs never change).

## 5 Disposition
**Exactly one of:** supported under stated premises · conditional on unbuilt requirements · open · declared out of scope — and the same value in the `disposition:` field.
- Premises that must hold:
- Evidence limit (configuration, substrate, run dates):

## 6 What remains
- Residual and open questions; the coverage uncertainty this route leaves.
- Design obligations surfaced for the engine (one sentence each, with the transition it concerns).
- Cross-references: other routes; obligations #1–#6 and conditions C1–C4 touched.
