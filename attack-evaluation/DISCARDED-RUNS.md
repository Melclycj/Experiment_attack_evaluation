# Attempts that produced no results

These attempts are not in this repository and count toward no result. Every result reported comes from a completed batch.

| Attempt | What happened | Then |
|---|---|---|
| no-bypass `20261106T002757Z-v4-nb-engine-a` | A test of ours still expected an earlier format of the workspace mirror, so NB-21's control step exited before its synchronization and the controller aborted the batch. No row after it started. The fault was in the test, not the engine | Corrected in `harness/cell/nb_engine_actions.py` and `harness/engine_observe.py`, then rerun as `20261106T003331Z-v4-nb-engine-a` |
| credential-binding `20261105T181601Z-v4-cb-b4` | The controller and the outer launcher were killed together, with no marker in the archive. The Windows event log recorded a planned host restart at that moment | Rerun |
| credential-binding `20261105T182841Z-v4-cb-b4` | The first batch after that restart took about twice as long as usual and hit the 600-second batch limit. We attribute the delay to cold file caches; that is an inference, not a measurement of this batch | Rerun as `20261105T230126Z-v4-cb-b4` |
| NB-30 `20261105T165854Z-nb30-v4`, `20261105T170049Z-nb30-v4` | Faults in the wrapper script: a wrong run directory, then a name clash. Neither arm started | Rerun as `20261105T170329Z-nb30-v4` |

Because of the correction above, the harness digest recorded in `run.json` differs between batches: `96aae084…` for the credential-binding batches and for no-bypass `files-a` to `files-d` and `connect`; `653667ef…` for no-bypass `engine-a`, `engine-b` and `boundary`. The two changed functions are used only by NB-21. The engine digest `c049638f…` is the same in all of them. The copy of `harness/` here is the later one.
