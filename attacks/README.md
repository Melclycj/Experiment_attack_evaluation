# Attacks and their results (Section 4.2, Table 4.1)

| The thesis says | Here |
|---|---|
| "the full list, with the cases we set aside and why, is in our public repository" | [ATTACKS.md](ATTACKS.md) and [cases/set-aside.md](cases/set-aside.md) |
| "publicly disclosed cases from three collections that we compiled" | [cases/](cases/): [sandbox-escape-cases.md](cases/sandbox-escape-cases.md), [credential-cases.md](cases/credential-cases.md), [namespace-attack-survey.md](cases/namespace-attack-survey.md) |
| The numbers of Table 4.1 | Recompute with `python3 -X utf8 tally-table-4.1.py`. It covers every row but NB-30, whose row is read from [original/nb30/run/](original/nb30/run/). It reports each legitimate operation's newest run; the batch-by-batch count is in [ATTACKS.md](ATTACKS.md) |

Everything under [original/](original/) is kept as it ran: the harnesses, the attack scripts, the run archives and the per-unit test specifications. Most of it is written in Chinese, including the code comments and the reports the harness generates. [ATTACKS.md](ATTACKS.md) gives every attack and its result in English, and this file says how to read the rest.

## How a result is judged

An attack runs as arbitrary code under the agent's uid. It is judged by external facts, not by what the engine replied: a decoy on the host changed, a marker file appeared, a test server received a request, or a test credential's real value appeared at a scanned outlet. A stop under the engine counts only if the same sub-goal reached its goal unprotected in the same batch, unless it has no counterpart there. Each batch of the harnesses also runs legitimate operations, which the engine must allow; the NB-30 run, on the other deployment, carried none.

All targets are decoys that each run builds for itself, on an isolated test network. Every credential is a random test string with no production rights. Decoy names such as `nb-decoy-…` and the sentinel values in the archives are test material, not secrets.

## What was tested

The engine is baseline v4, the files in [../engine/](../engine/). A batch is marked `formal=true` only when the source it compiled matches the registered export file by file, the baseline check passes and the host readings in [original/baseline/host-readings-v4.json](original/baseline/host-readings-v4.json) agree. All batches ran on one host under WSL 2, kernel `6.6.87.2-microsoft-standard-WSL2`, once per sub-goal per configuration. The self-check batches (`…-selfchk`, `…-selfcheck-…`) ran on deliberately weakened copies of the engine, to show that the judging reports a success when one happens; their run records carry the weakening patch.

## Reading a run archive

Each batch is one directory, `original/<unit>/runs/<UTC start>-<label>/`, where the unit is `no-bypass`, `decision-faithfulness` or `credential-binding`.

| File | What it holds |
|---|---|
| `results.md`, `results.jsonl` | One row per attack, configuration and sub-goal: the expected outcome written before the run, the observed outcome and the evidence files. `results.md` is the same table for reading, in Chinese |
| `README.md` | The batch's purpose and the same results, in Chinese |
| `run.json` | The configuration: the sha256 of every engine and harness file, the test specification's digest, the host readings, the commands and whether the batch is formal |
| `raw-*` | The raw evidence: requests sent, what the test servers received, decoy snapshots, credential scans, the engine processes' output |
| `COMPLETE.json` | The sha256 of every file in the directory, written when the archive closed |

`original/<unit>/runs/history.md` sums up each attack across batches, in Chinese. Paths inside the archives name the original machine, and some of their links lead outside this repository.

`python3 verify.py` at the repository root checks the archives against their `COMPLETE.json`, and the engine, harness, scripts and test specifications against each `run.json`. Two notes on what it finds:

- **Test specifications.** Each unit's `tests.md` is the version its batches cite. The decision-faithfulness batches cite two versions: the last batch the current `tests.md`, the five before it `tests.b79edf25.md`.
- **Harness revisions.** The no-bypass batches `files-a` to `files-d` and `connect`, and all credential-binding batches, ran an earlier revision of two harness files, `cell/nb_engine_actions.py` and `engine_observe.py`; NB-21 alone uses them. Those revisions are in [original/harness-earlier/](original/harness-earlier/). The engine is the same in all batches.

## Attempts that produced no results

These attempts are not in this repository and count toward no result. Every result reported comes from a completed batch.

| Attempt | What happened | Then |
|---|---|---|
| no-bypass `20261106T002757Z-v4-nb-engine-a` | A test of ours still expected an earlier format of the workspace mirror, so NB-21's control step exited before its synchronization and the controller aborted the batch. No row after it started. The fault was in the test, not the engine | Corrected in `harness/cell/nb_engine_actions.py` and `harness/engine_observe.py`, then rerun as `20261106T003331Z-v4-nb-engine-a` |
| credential-binding `20261105T181601Z-v4-cb-b4` | The controller and the outer launcher were killed together, with no marker in the archive. The Windows event log recorded a planned host restart at that moment | Rerun |
| credential-binding `20261105T182841Z-v4-cb-b4` | The first batch after that restart took about twice as long as usual and hit the 600-second batch limit. We attribute the delay to cold file caches; that is an inference, not a measurement of this batch | Rerun as `20261105T230126Z-v4-cb-b4` |
| NB-30 `20261105T165854Z-nb30-v4`, `20261105T170049Z-nb30-v4` | Faults in the wrapper script: a wrong run directory, then a name clash. Neither arm started | Rerun as `20261105T170329Z-nb30-v4` |

## What else is in original/

| Path | What it is |
|---|---|
| `METHOD.md`, `TESTING.md` | The shared method and run rules, in Chinese |
| `<unit>/attacks.md`, `<unit>/tests.md` | Per-unit attack lists and test specifications, in Chinese: judging criteria, controls and validity conditions for every sub-goal |
| `<unit>/scripts/` | The attack scripts |
| `harness/`, `decision-faithfulness/harness/` | The harnesses. The first serves no-bypass and credential binding, the second decision faithfulness |
| `nb30/` | NB-30, which needs an export step and so ran on the deployment of the end-to-end checks |
| `nb29/` | The NB-29 probe, which is not a formal result and is not in Table 4.1 (see [cases/set-aside.md](cases/set-aside.md)) |
| `baseline/` | What the engine version changed, in Chinese, and the host readings the formal runs were checked against |
| `case-collections/` | The Chinese originals of two of the case collections |

The batches cannot be rerun from this repository alone: the harnesses need root under WSL 2, and they were written for the author's original layout.
