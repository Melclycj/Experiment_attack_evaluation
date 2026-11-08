# Source and evaluation records: a reference monitor for AI agents on a shared kernel

This repository holds what the thesis points to: the source of the monitor it builds (the engine), the attacks and their run records, the records behind the utility and cost measurements, and two structured security arguments.

## Where the thesis points

| The thesis says | Here |
|---|---|
| Abstract: "The attacks, their run records and the full argument are available at …" | [attacks/](attacks/README.md) for the attacks and their runs; [arguments/](arguments/README.md) for the arguments |
| Section 3.8: "The source code and the list of attacks are in our public repository" | [engine/](engine/) for the source, with Table 3.6 recounted [below](#the-engine); [attacks/ATTACKS.md](attacks/ATTACKS.md) for the list |
| Section 4.2: "the full list, with the cases we set aside and why, is in our public repository" | [attacks/ATTACKS.md](attacks/ATTACKS.md) and [attacks/cases/set-aside.md](attacks/cases/set-aside.md) |
| Sections 4.3 and 4.4: three agents through the engine; memory per agent and time per request | [utility-and-cost/](utility-and-cost/README.md) |
| Section 6.1: "74 system calls … 306 cases (see our public repository)" | [arguments/no-bypass.md](arguments/no-bypass.md) |
| Section 6.1: "Of the 38 ways a label could go wrong (see our public repository)" | [arguments/uid-binding.md](arguments/uid-binding.md) |

## Layout

| Folder | For |
|---|---|
| [engine/](engine/) | The engine's source, exactly as evaluated |
| [attacks/](attacks/README.md) | The attacks of Section 4.2 and their run records |
| [utility-and-cost/](utility-and-cost/README.md) | Sections 4.3 and 4.4 |
| [arguments/](arguments/README.md) | The two structured arguments of Section 6.1 |

In each folder, the files at the top are in English and written to be read; start with its `README.md`. Each `original/` subfolder, and `engine/` as a whole, holds files exactly as they ran or were written. Many of those are in Chinese, including the engine's own documentation and some code comments. They are kept unchanged because the run records hold their digests, so a changed byte would no longer match what ran.

## The engine

[engine/](engine/) is baseline v4 of the engine: the directory `ExperimentLab/engine-v3` at commit `a9eff999` of the author's working repository, 188 files, without its `runs/` directory. Chapters 3 and 4 describe and evaluate this version. Its documentation (`README.md`, `SPEC-canonical-form.md`, `deployment.md`, `validation.md`) is in Chinese.

Table 3.6 counts lines with `wc -l` over the top-level source files of each directory, blank lines and comments included. Each row below is `cat <files> | wc -l` run in `engine/`.

| Component | Files in engine/ | Files | Lines |
|---|---|---|---|
| Spawner, child and supporting code | `native/sandbox/*.c native/sandbox/*.h` | 17 | 3,273 |
| Core | `engine/*.py` | 21 | 6,175 |
| Connector | `connector/*.py` | 8 | 2,302 |
| File worker | `fileworker/*.py` | 4 | 550 |
| Management client, transfer part | `client/workspace.py client/link.py client/__init__.py` | 3 | 712 |
| Management client, approval and attach parts | `client/admin.py client/attach.py client/main.py client/render.py` | 4 | 835 |
| Simple PDP | `pdp/*.py` | 2 | 64 |
| In-compartment front end | `frontend-go/*.go` | 6 | 935 |
| MCP server, without tests | `mcp-go/*.go` except `*_test.go` | 4 | 796 |
| Relay | `relay/*.c` | 1 | 111 |

The first five rows are the engine trusted computing base: 53 files and 13,012 lines.

## Checking the records

```
python3 verify.py
```

It checks, with the standard library only, every file kept as an original against the digests the run records hold: [engine/](engine/) against every attack batch and every memory and latency run, each batch's harness, scripts and test specification against its `run.json`, and every run archive against its `COMPLETE.json`. `.gitattributes` turns off line-ending conversion, because the digests cover these bytes. The longest path in the repository is 155 characters, so on Windows a clone into a deep folder needs `git -c core.longpaths=true clone …`.

## What is not claimed

The batches cannot be rerun from this repository alone. The harnesses need root under WSL 2 and were written for the author's original layout, and the memory runs used a rented server. Nothing here claims reproduction; the records show what ran and what it produced.

Decoys, placeholder credentials such as `sk-ant-api03-…-placeholder-…`, and the sentinel values in the archives are test material. Every credential in the records is a random test string or a placeholder, with no production rights.
