# Utility and cost (Sections 4.3 and 4.4)

The records behind Section 4.3 (whether existing agents work through the engine) and Section 4.4 (memory per agent and time per request). Every run directory under [original/](original/) is a byte-for-byte copy of the run as written, apart from the built deployment tarballs, which are left out. The run notes inside them are in Chinese. The engine in all of them, except the one host-file run noted below, is baseline v4, the files in [../engine/](../engine/); `python3 verify.py` at the repository root checks the memory and latency runs' file digests against it.

## Utility: three agents through the engine

[original/utility/20261105T154520Z-gate-v4-derive-wrapped/](original/utility/20261105T154520Z-gate-v4-derive-wrapped/) ran a fixed set of operations with Claude Code, OpenCode and Pi, each changed only in configuration. The runner is the engine's own `checks/run_gate.py --suite derive`, through the wrapper `gate_derive_v4.py` in the run directory, which changes two things in the running process only: it empties the workspace's fixed subdirectory rather than the workspace, and it judges each operation on a copy of that subdirectory owned by the host user. Each operation ran once, so these records show that the operations work, not a success rate. The model was Claude Haiku.

| Operation | What the agent was asked to do |
|---|---|
| (a) model only | Answer a question without tools |
| (b) files | Write two files with its file tool, then edit them |
| (c) shell | Run seven shell commands and show their output |
| (d) tests | Run the test suite with pytest |
| (e) git | Commit in the workspace, clone two public repositories, and commit and push to a test repository |
| (f) packages | Install packages with pip, uv and npm, and import each |
| (g) web page | Fetch `https://example.com/` with its web fetch tool |
| (h) MCP | Call a tool on a remote MCP server (DeepWiki) |
| interactive (a) | Answer in the interactive interface |

The exact prompts and pass criteria are in `allowlist-derivation.md` of [../engine/](../engine/), in Chinese with the prompts in English. Pi has no web fetch tool, so (g) does not apply to it.

| Agent | Version | Operations | Passed | Requests | Released | With a credential written by the engine |
|---|---|---|---|---|---|---|
| Pi | 1.4.0 | 8 | 8 | 51 | 51 | 33 |
| OpenCode | 1.19.5 | 9 | 9 | 68 | 68 | 41 |
| Claude Code | 2.1.312 | 9 | 9 | 76 | 76 | 54 |
| Total | | 26 | 26 | 195 | 195 | 128 |

No request was refused, and the sentinel scan found no credential outside where it belongs. The per-agent records are `v4-derive-<agent>.json`, the engine's decisions are in `v4-derive-<agent>-events.jsonl`, and the terminal sessions are in the `.cast` and `-terminal.txt` files.

**Reading a registered host file.** [original/utility/20261103T234437Z-gate-files-fix/](original/utility/20261103T234437Z-gate-files-fix/) is the run in which Claude Code read a file that the user registered, through the MCP server and the file worker. It ran before the engine was frozen as baseline v4, on an earlier state of the same directory: commit `64da1d30` of the author's working repository plus uncommitted fixes to the core, the file worker, the MCP server and the management client. Its engine files are therefore not exactly those in [../engine/](../engine/). The read returned the file's 43 bytes; the engine refused a path through `..` and a symbolic link, each with its reason word, and a file outside the registered directory never appeared in the output.

## Memory per agent

[original/memory/20261105T141542Z-formal-server-memory-engine-v4/](original/memory/20261105T141542Z-formal-server-memory-engine-v4/) is the measurement, on one rented AWS server with 16 vCPU and 61 GiB, with one to sixteen Claude Code agents idle at their prompts and three repetitions at each count. It measured the engine with the default shared runtime image and with a private copy for each execution, and in the same run the same agent without the engine, allowed to reach only the model API. The driver that ran it is in `driver-snapshot/`; each engine deployment's `deployment.json` under `engine/` records the sha256 of the 188 engine files. The method is in [original/memory/protocol.md](original/memory/protocol.md), in Chinese.

[original/memory/20261105-memory-analysis-engine-v4/](original/memory/20261105-memory-analysis-engine-v4/) is the analysis. [table-4.2.py](table-4.2.py) recomputes Table 4.2 of the thesis from its `memory-analysis.json`:

```
python3 -X utf8 table-4.2.py
```

Each cell is the range over the three repetitions of the agent's own part, the proportional set size (PSS) of its processes beyond the same agent without the engine, plus the mean growth of the engine's shared parts per added agent. At sixteen agents the two parts sum to 36.8–37.1 MiB with the shared image and 132.9–133.2 MiB with a private copy. The shared parts take about 30 MiB at one agent. The script drops the one reading that the protocol flags, at four agents with a private copy.

## Time per request

[original/latency/20261106T023157Z-formal-latency-engine-v4/](original/latency/20261106T023157Z-formal-latency-engine-v4/) compares requests through the engine with the same requests sent directly, on the same server, with one request in flight (k6 with one virtual user), an nginx upstream with TLS 1.3 and a PDP that allows every request without reading it. Seven groups vary the credential, connection reuse and request size, three passes each. The figure in Section 4.4, about 8 ms at the median, is the group with a credential and a reused connection: 7.85, 7.80 and 8.19 ms in the three passes. `latency-analysis.md` in the directory has every group.

The two controls repeat that group with the engine's records on a memory disk ([original/latency/20261106T031320Z-formal-latency-control-tmpfs/](original/latency/20261106T031320Z-formal-latency-control-tmpfs/), 0.96–1.03 ms) and on the server's network disk ([original/latency/20261106T031547Z-formal-latency-control-disk/](original/latency/20261106T031547Z-formal-latency-control-disk/), 7.63–8.06 ms). Most of the added time is the wait for the allow record to reach the disk.

No statistical test was made on any of these numbers. Sustained load, concurrent requests and start-up time were not measured.
