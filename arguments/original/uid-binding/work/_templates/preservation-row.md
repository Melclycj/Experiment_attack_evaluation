---
group: G?                    # one preservation file per group folder
owner:
status: draft                # draft · ready-for-reconcile · returned · accepted
based_on:                    # same four spine blob ids as the route records
  model_blob: ""
  decomposition_blob: ""
  invariant_blob: ""
  registry_blob: ""
---

# preservation — <group name>

<!-- Template (2026-10-12). One row per transition assigned to this group by the Step 2 group-cut
table (T-id → group); transitions come from 01-model-inventory, conditions from 02, the invariant I
from 03. Rules: a refusal or close path must land in a state that still satisfies the guarded I, not
merely be labelled rejected; do not collapse two executions, one pending request or one recycle into
arbitrary counts without a justification row; a counterexample is recorded as "does not preserve" with
the offending state, never by removing the transition from the model; a needed strengthening of I is
proposed in the conclusion lines and sent to change-requests, not applied here. Transition IDs of other
groups may be cited as facts; their preservation conclusions may not. Delete this comment in a real
record. -->

## Rows

| transition id | precondition | actor | atomicity / interruption points | conditions of I touched | preservation argument | result | evidence ids | open |
|---|---|---|---|---|---|---|---|---|
| T-nn | | engine · spawner · kernel · adversary | | | why I holds after this transition from any I-state | preserves · does not preserve · design unstated | EV-nn | |

## Justification rows (collapses and abstractions used above)

| what was collapsed | why attribution-relevant distinctions are preserved | limit |
|---|---|---|
| | | |

## Conclusion lines (what reconcile reads)

- preserves: T-nn, T-nn
- does not preserve: T-nn (state; obligation handed to the engine)
- design unstated: T-nn (what the design must say)
- proposed strengthening of I: … (to change-requests; not applied here)
