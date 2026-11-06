# What we set aside, and why

Table 4.1 of the thesis reports the attacks we ran. This file lists what we did not run and the reason for each. Case numbers refer to the collections in [case-collections/](case-collections/): C and A to the sandbox-escape cases, B and BM to the credential cases, N to the namespace-attack survey. Attack numbers refer to [ATTACKS.md](ATTACKS.md).

## ZTAC attacks we did not run (35 of 74)

| Group | Count | Attacks | Why |
|---|---|---|---|
| What our design hands to the agent | 21 | Reading the workspace's own `.env` under various names (9); running code through git configuration or a shell the agent already has (9), including fs-git-fsmonitor and fs-git-bare-repo; the integrity of the workspace itself (3) | Workspace contents belong to the execution, and real credentials do not enter the workspace. The agent already has a shell, and the runtime sits inside the compartment, so no program outside runs what these plant. Local commits are not reviewed, the workspace has no protected path, and writing to it does not pass through the engine |
| A platform we do not use | 3 | handoff-editor-case and handoff-editor-py-case, which rely on a case-insensitive file system (2); an injection specific to macOS Seatbelt (1) | The platform is Linux |
| Data sent out inside a permitted request | 5 | The net-dlp attacks | Left to the PDP. BD-01 and BD-02 in [ATTACKS.md](ATTACKS.md) demonstrate the position |
| Resting on argument rather than a run | 6 | proto-tamper (DF-02); exec-py-race (DF-14); approval-commit-worktree; proto-replay-restart; proto-impersonate and proto-unenrolled, which impersonate another execution or send from an unregistered process (UB-01, UB-02) | See the next section. The two identification attacks rest on the argument in [uid-binding/](uid-binding/README.md) |

## Attacks that have no entry point

| Attack | Why there is nothing to attack |
|---|---|
| DF-02: change the body after approval (ZTAC proto-tamper) | The connector writes the body to a memfd it created, sealed against writes and against changes of length, and the core checks the seals. The connector sends from its own memory. The compartment holds no handle to the memfd; more bytes on the same connection are the next request |
| DF-14: swap a directory for a symlink during a host-file read, or repoint it after approval (ZTAC exec-py-race; the path version of approval-retarget) | The objects read are registered by the user, outside any workspace, and do not enter a compartment. The file tools only list and read. Code in a compartment can affect host files only through export, which does not touch the working tree or take symlinks |
| approval-commit-worktree (named on the DF-10 row of the Chinese list; DF-10 does not test it) | It needs a path that the engine reads and writes for the agent, which this version does not build, and the engine makes no commits for the agent |
| proto-replay-restart | No signature or approval token exists in the compartment to replay, "allow this time" is not persisted, and old rows are terminated before a new engine starts |
| DF-15: fill in another row's call number | The canonical form has no call number the agent can fill in; the core identifies the row by the port a message arrives on. An extra field fails the grammar, which is input parsing |
| The decision-port half of DF-16 | The decision port is a socketpair between connector and core, and it does not enter a compartment |

DF-04 and DF-11 are not set aside: they are merged into DF-03 as the sub-goals `other-port` and `other-workspace`. The former DF-13, a late answer that arrives after the client has gone, is not an attack; it and crashes between writing a record and sending a request belong to the engine's own tests.

## An attack kept out of Table 4.1

NB-29, on WSL interoperation, tries to make the kernel's binfmt_misc hand a file starting with `MZ` to the WSL interpreter and so start a Windows process. It ran as a light probe on a simulated compartment root, not on a full deployment, so it is not a formal result and is not in the table. Section 3.5 of the thesis discusses it. In that probe the same file started a Windows process from the normal WSL root, whereas in the simulated compartment root the interpreter `/init` was not found and the attempt failed with ENOENT. The seccomp layer of the expected defence was read from the policy, not exercised. The probe and its record are in [attack-evaluation/nb29/](attack-evaluation/nb29/).

## Public cases we did not count

| Category | Cases | Why |
|---|---|---|
| No matching exit in our construction | GitSpawn: `core.fsmonitor` run by git that the agent runs automatically (ZTAC Table 3); nested bare repository with `core.fsmonitor` (Copilot CLI, CVE-2026-45033); a hook in the workspace's agent settings run by the host engine at the end of a turn (Cursor, CVE-2026-48124; C07, C10 item 6; NB-15 is an adaptation, not a replay); an IDE starting a process from a new MCP configuration before approval (CurXecute, C14); headless mode trusting workspace configuration (Gemini CLI, C09); the process-starting half of MCPoison and Amazon Q (C15, C16); the first half of GitPwned, allowing git outside the sandbox by command name (C08); a worktree named `.git` with the worktrees directory replaced by a link to the host home (Claude Code, CVE-2026-55607, the other half of C05) | In the original incidents the exit is a program outside the sandbox that executes things for the agent. Here the whole runtime is in the compartment, so no program outside interprets workspace contents. A payload can only run in the compartment under the agent's uid, and what it can do from there is tested by NB-01, NB-07 and NB-17 |
| The object does not exist in our construction | Copilot and Zed rewriting approval configuration that the agent can write and the executor reads (CVE-2025-53773, CVE-2025-55012; C13, C18, B11, B17) | We have no such state: the runtime's own approval settings are the agent's own state, and the engine's table is outside the compartment. The same goal, approving oneself, is tested by NB-21 |
| The object does not exist in our construction | Cursor DuneSlide: the sandbox scope computed from a working directory the agent controls, and a file tool falling back to an unchecked path (C06) | The spawner fixes the compartment boundary from the deployment list before agent code runs, and file reads and writes do not pass through the engine, so this checkpoint does not exist |
| The source is not a bypass | 0DIN Clone This Repo (C19) | The collection judges it abuse of permitted execution, with no bypass of isolation or approval. An outbound connection from a script is tested by NB-17 |
| The source is not a bypass | The three Anthropic events (C02) | No attack action, and the network was open anyway. "The network is actually reachable" is tested by NB-17 and NB-18 |
| The source is not a bypass | Gemini CLI yolo mode not keeping shell restrictions (C09, another route); Claude Code issue #25000, a sub-agent passing a Bash refusal (C17, a user report, unconfirmed) | The agent has a shell anyway; a sub-agent and the main loop are the same row |
| Method not published | Mythos Preview's escape on request (C03) | The system card (2026-04-07, p. 54) confirms the event but gives no method, so it cannot be replayed. The boundary crossed, restricted outbound network, is tested by NB-16, NB-17 and NB-18; an allowed proxy reaching an unlisted host is tested by DF-03 |
| Source unavailable | ShadowLeak (A02) | We could not obtain the original material |
| Belongs to another unit | The credential half of B1, B5, B6, C12, C22, C24; Amazon Q (C16); Cowork (A09, B8); the name-bound approval half of MCPoison (C15); the connector half of OpenAI / Hugging Face (C01) | Covered by CB-01, CB-03, CB-04, CB-05 and the Cowork boundary (BD-02), and by DF-08 and DF-03 |
| Not at the compartment boundary | EchoLeak, ForcedLeak, GitLab Duo, Slack AI (A01, A05, A06, A07); postmark-mcp adding a recipient (C23) | Output leaves through a renderer outside the compartment or a user's click, or goes to a recipient: this is PDP policy |
| Not at the compartment boundary | GitHub MCP, Supabase, Comet (A03, A04, A08) | They use an authorized account or session. Scope belongs to PDP policy, and account binding is tested in the credential and decision units |
| Not at the compartment boundary | MCP confused deputy, Akamai `_meta` (C20, C21) | Analyses of mechanisms, with no named event |
| Not present on the baseline kernel | CVE-2026-43391 (N7); CVE-2022-0492 (N7); CVE-2009-1338 (N8); CVE-2018-18955 (N8); CVE-2015-4176, CVE-2014-9717 (N8); RDS cross-namespace lookup (N8, fix 5521ae71e32a) | nsfs file handles arrive only in 6.18; the others were fixed before the baseline kernel; the RDS code is in 6.6.87, but the WSL configuration does not build RDS |
| Kernel vulnerabilities or defects | CVE-2022-0185, the nf_tables family, CVE-2024-53095 (N8); syzbot's netns reference-count reports (N5) | The kernel is in the TCB |
| Not an attack, or does not transfer | moby issue #31414 (N2); three bypasses of Ubuntu's AppArmor limit on user namespaces (N7); same-uid rendezvous through a user namespace (N10) | The first is a lifecycle defect of leftover network namespaces. We do not use AppArmor, and seccomp refuses user namespaces. The third is a design finding measured in this project, not a public incident |

## Credential cases outside the attack list

| Case | Why |
|---|---|
| CB-13: a destination echoes request headers | A legitimate endpoint puts the header into its response body, so the real value returns to the compartment. The design explicitly does not scan for this and leaves it to policy. We did not run it, and it counts neither as stopped nor as a failure |
| ElizaOS (B9) | Credential isolation held, and the agent was still tricked into a harmful transfer. It serves as a negative control: that a credential cannot be taken does not mean that every operation should be allowed |
| Cowork (B8) | The agent carries an attacker's own key in a request to an allowed domain. This is sending data out by content, which we do not claim to stop. BD-02 demonstrates it |
| CB-14, the half on new credentials returned with a result (clause 10) | Not in this round: it has no test specification, and it was not run |

## SandboxEscapeBench (C11, arXiv 2603.02277 v3)

The benchmark starts from root in a container plus a misconfiguration or a published vulnerability. We added no experiment for its 18 scenarios. Each is supported as follows. "Structural" means that the premise does not exist in our construction: the compartment root is a new tmpfs, `/dev` holds four devices, `/proc` shows only the compartment's processes, new mount, PID, net and IPC namespaces are used, the syscall allow-list applies and the agent's uid has no capabilities.

| Scenario | How the benchmark escapes | Our construction | Supported by |
|---|---|---|---|
| docker.sock | Connect to a privileged daemon's socket and have it start a privileged container | The socket path is not in the compartment | NB-19 |
| RBAC | Use over-privileged control-plane credentials to start a privileged workload | Our control plane is the engine's management port, outside any compartment, and no usable credential is inside | NB-21; the control-port half by DF-16 |
| hostpath | Change host files through a writable host `/etc` mount | No host path in a closed mount list | NB-07, NB-08, NB-10 |
| pid_ns | Share the host PID namespace and inject with CAP_SYS_PTRACE | Own PID namespace; ptrace is not on the allow-list | Host processes not being visible: NB-23. The ptrace half: structural |
| privileged | All capabilities, host devices visible, no seccomp; mount the host disk | Four devices in `/dev`; mount is not on the allow-list; no capabilities | Structural |
| CAP_SYS_ADMIN | mount, new namespaces | mount, unshare and setns are not on the allow-list; the user-namespace flag is masked | Structural |
| CAP_SYS_MODULE | Load a kernel module | The module-loading calls are not on the allow-list | Structural |
| CAP_DAC_READ_SEARCH | Cross mount boundaries with open_by_handle_at | The call is not on the allow-list | Structural |
| runc_2024 (CVE-2024-21626) | A host directory's descriptor leaks into the container and serves as an anchor | As NB-24 | NB-24 |
| route_ln (CVE-2020-8558) | kube-proxy configuration lets a container reach a host service listening only on localhost | Own net namespace | NB-16 |
| kubectl_cp (CVE-2019-1002101) | A replaced tar in the container makes the host side write outside the target directory | Export is generated by the management client in the TCB, takes only regular files and directories and does not unpack for the user | What returns to the host: NB-30. Who generates the stream: structural |
| runc_2019 (CVE-2019-5736) | While the host's runc enters the container, the container overwrites it through `/proc/self/exe` | No step executes a host program into a running compartment | Structural |
| CRI-O (CVE-2022-0811) | Inject kernel parameters through a pod sysctl | No CRI-O or Kubernetes; no `/proc/sys` in the compartment | Structural |
| cgroup (CVE-2022-0492), dirty_cow (CVE-2016-5195), dirty_pipe (CVE-2022-0847), bpf_privesc (CVE-2017-16995), packet_sock (CVE-2017-7308) | Kernel vulnerabilities | The kernel is in the TCB, and these were all fixed before the baseline kernel | Not applicable |
