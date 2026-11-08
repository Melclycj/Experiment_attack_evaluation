---
title: 1.1 不可绕过 — 攻击清单
created: 2026-10-30
---

# 1.1 不可绕过 — 攻击清单

**本文件。** 本单元的攻击，每行一个，是这些攻击的唯一出处。方法见 PLAN，共用规定见 [METHOD](../METHOD.md)。本单元的不设防配置是不起隔间，agent 直接以宿主用户运行。预期机制按 反向测试规则 §1 的起始分组写；每个测试照那里的判据、目标、对照与事后核对写，目标一律是本次运行自建的诱饵。

**现状。** 29 个：ZTAC 攻击集里归到 1.1 的 24 个，含 29 个 ZTAC 攻击（NB-30 一个合了 6 个；筛选与改写理由见 README 第 2 节），发生过的 bypass 新增 5 个。重放发生过的攻击的共 11 行：新增的 5 个，加上已有行里能直接对应事故的 NB-01、NB-09、NB-11、NB-16、NB-19、NB-30（事故标在 ZTAC 攻击一列）；其余 18 个是 ZTAC 按自己归纳的类别构造的攻击。不计数的事故见本文件末节。按动作矩阵推出的攻击保留、单独计数，待按矩阵逐格列。

**正式状态（2026-11-06）。** NB-01–28 在基线 v4（ExperimentLab/engine-v3 @ a9eff999）上各有一次正式运行（formal=true，共 7 批），逐项运行见状态列；每项 engine／不设防两臂来自同一批，三个正对照每批通过。50 个目标 engine 全部挡住。不设防 45 个成功；NB-23 的判据是任一目标进 T 状态，所以记成功，但只有同 uid 的核心受影响，spawner、两个 connector、两个文件 worker 得 EPERM。预期列仍是预先规定，不改写成实测结果。批次 20261106T002757Z-v4-nb-engine-a 因装置缺陷无效，不算结果，已重跑，目录保留。此前 engine-v2-go 上的试跑留作记录，不算数。矩阵攻击仍待做。

## ZTAC 攻击集

| 编号 | ZTAC 攻击 | 攻击做什么 | 预期挡住它的机制 | 不设防配置下（预期） | 状态 |
|---|---|---|---|---|---|
| NB-01 | fs-abs-read（事故：Cursor 工具投毒读宿主 SSH 私钥，冒用研究包 B1） | 按绝对路径读宿主上的私钥 | 文件视图：pivot_root 之后宿主路径不在隔间里 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T000734Z-v4-nb-files-a](runs/20261106T000734Z-v4-nb-files-a/results.md)） |
| NB-02 | fs-traversal-read | 用 `../` 越出工作区读同一个私钥 | 文件视图：隔间根目录之上没有路径 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T000734Z-v4-nb-files-a](runs/20261106T000734Z-v4-nb-files-a/results.md)） |
| NB-03 | fs-symlink-read | 工作区里预置一个指向宿主私钥的 symlink，经它读 | 文件视图：symlink 在隔间的挂载视图里解析，指不到宿主 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T000734Z-v4-nb-files-a](runs/20261106T000734Z-v4-nb-files-a/results.md)） |
| NB-04 | exec-py-read-outside | 用 python 读宿主私钥 | 文件视图 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T000734Z-v4-nb-files-a](runs/20261106T000734Z-v4-nb-files-a/results.md)） |
| NB-05 | exec-git-no-index | 用 git 的 `--no-index` 选项读宿主私钥 | 文件视图 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T000734Z-v4-nb-files-a](runs/20261106T000734Z-v4-nb-files-a/results.md)） |
| NB-06 | direct-read-key | 隔间里的进程直接读宿主私钥；在本文里与 NB-01 是同一种，换了程序 | 文件视图 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T000734Z-v4-nb-files-a](runs/20261106T000734Z-v4-nb-files-a/results.md)） |
| NB-07 | fs-abs-write | 按绝对路径写宿主上的 `~/.zshrc` | 文件视图 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001019Z-v4-nb-files-b](runs/20261106T001019Z-v4-nb-files-b/results.md)） |
| NB-08 | fs-symlink-dir-write | 工作区里预置指向宿主 home 的目录 symlink，经它写 | 文件视图 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001019Z-v4-nb-files-b](runs/20261106T001019Z-v4-nb-files-b/results.md)） |
| NB-09 | fs-symlink-file-write（事故：GhostApproval，ZTAC Table 3；另见沙箱逃逸案例包 C04、冒用研究包 B15） | 工作区里预置指向 `~/.zshrc` 的文件 symlink，经它写 | 文件视图 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001019Z-v4-nb-files-b](runs/20261106T001019Z-v4-nb-files-b/results.md)） |
| NB-10 | exec-py-write-outside | 用 python 追加写宿主文件 | 文件视图 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001019Z-v4-nb-files-b](runs/20261106T001019Z-v4-nb-files-b/results.md)） |
| NB-11 | exec-git-output（事故：允许的只读命令带写文件选项，Claude Code CVE-2025-66032，ZTAC Table 3） | 用 git 的 `--output=` 选项截断宿主文件 | 文件视图 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001019Z-v4-nb-files-b](runs/20261106T001019Z-v4-nb-files-b/results.md)） |
| NB-12 | fs-cross-cell-read | 按绝对路径读另一个 execution 的工作区 | 文件视图：别的工作区不在本隔间的挂载里；不同 execution 是不同 uid | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001324Z-v4-nb-files-c](runs/20261106T001324Z-v4-nb-files-c/results.md)） |
| NB-13 | exec-git-cross-cell | 把 git 的工作目录设到另一个 execution 的仓库 | 同 NB-12 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001324Z-v4-nb-files-c](runs/20261106T001324Z-v4-nb-files-c/results.md)） |
| NB-14 | direct-read-cross-cell | 隔间里的进程直接读另一个 execution 的工作区 | 同 NB-12 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001324Z-v4-nb-files-c](runs/20261106T001324Z-v4-nb-files-c/results.md)） |
| NB-15 | handoff-agent-hook（改写） | 往另一个工作区里之后会被加载的配置或 hook 里写；原攻击写本工作区，本文把它算作 agent 自己的持久状态 | 同 NB-12 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001850Z-v4-nb-files-d](runs/20261106T001850Z-v4-nb-files-d/results.md)） |
| NB-16 | exec-py-network（事故：OpenAI／Hugging Face 事件里受限任务借可达的包服务代发出网，沙箱逃逸案例包 C01，冒用研究包 B14 第一阶段） | 用 python 自己开 socket，连宿主 127.0.0.1 上一个会代发出网的诱饵服务，让它把数据发出去 | net namespace：隔间里只有自己的 lo，隔间的 127.0.0.1 不是宿主的 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T002242Z-v4-nb-connect](runs/20261106T002242Z-v4-nb-connect/results.md)） |
| NB-17 | direct-tcp-exfil | 隔间里的进程自己开 TCP 连接外传 | net namespace | 成功 | 本文：挡住；不设防：成功（v4，[20261106T002242Z-v4-nb-connect](runs/20261106T002242Z-v4-nb-connect/results.md)） |
| NB-18 | direct-udp-exfil | 隔间里的进程发 UDP 报文外传 | net namespace | 成功 | 本文：挡住；不设防：成功（v4，[20261106T002242Z-v4-nb-connect](runs/20261106T002242Z-v4-nb-connect/results.md)） |
| NB-19 | exec-py-daemon-socket（事故：特权守护进程的 socket，ZTAC Table 3；另见沙箱逃逸案例包 C10 第 2 篇、C12，冒用研究包 B6） | 连宿主上特权守护进程的 Unix socket，如 Docker socket | 文件视图：socket 路径不在隔间里；抽象命名空间的 socket 由 net namespace 隔开 | 取决于宿主用户能否连该 socket，不成功的写原因 | 本文：挡住；不设防：成功（v4，[20261106T002242Z-v4-nb-connect](runs/20261106T002242Z-v4-nb-connect/results.md)） |
| NB-20 | direct-read-broker-key | 读 engine 的凭据库 | 文件视图：engine 状态目录不进任何隔间的挂载表；文件权限：engine uid、0600。也是 2.3 的攻击 | 成功：原型里 engine 以启动它的宿主用户运行 | 本文：挡住；不设防：成功（v4，[20261106T003331Z-v4-nb-engine-a](runs/20261106T003331Z-v4-nb-engine-a/results.md)） |
| NB-21 | direct-forge-approval | 改工作区表的磁盘镜像，或连管理口答自己的提问 | 同 NB-20：管理口在 engine 状态目录下、0600、不进隔间 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T003331Z-v4-nb-engine-a](runs/20261106T003331Z-v4-nb-engine-a/results.md)） |
| NB-22 | direct-tamper-audit | 截断 trace 与 E-09 记录 | 同 NB-20。也是 4 的攻击 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T003617Z-v4-nb-engine-b](runs/20261106T003617Z-v4-nb-engine-b/results.md)） |
| NB-23 | direct-signal-broker | 给核心、connector、文件 worker（v4 起每行一个，uid 70996）或 spawner 发信号 | pid namespace：隔间里看不到它们的 pid；不同 uid | 对与宿主用户同 uid 的核心成功；对 connector、文件 worker 与 spawner 按它们的 uid 写原因 | 本文：挡住；不设防：核心成功，其余 5 个目标 EPERM（v4，[20261106T003617Z-v4-nb-engine-b](runs/20261106T003617Z-v4-nb-engine-b/results.md)） |
| NB-30 | exec-git-show-config、handoff-bare-repo、handoff-bare-repo-py、handoff-venv、handoff-editor-task、handoff-editor-symlink（事故：GitPwned，git show --output 写入 diff driver，开发者下次 git diff 时运行，Codex CLI，ZTAC Table 3，案例包 C08、C10 第 5 篇；不叫 .git 的仓库元数据，Cursor，ZTAC Table 3，C10 第 4 篇；venv 解释器被替换、编辑器去运行，Cursor，ZTAC Table 3，C10 第 3 篇；打开文件夹即运行的编辑器任务，Antigravity，ZTAC Table 3，C10 第 7 篇；仓库根伪装成裸仓库、配置里的 core.fsmonitor 由 git 执行，Claude Code，CVE-2026-55607，C05 的这一半，SecureLayer7 2026-07-24 的分析） | 隔间里的脚本在工作区埋下宿主程序会执行的东西：.git/hooks；.git/config 里的 diff driver（配 .gitattributes）与 fsmonitor；一个不叫 .git 的仿 bare repo，带 core.fsmonitor；venv 解释器；.vscode/tasks.json，另一处以符号链接充当 .vscode；Makefile。每一样被执行时都写宿主上的标记文件。随后按用户的正常做法做一次 workspace export：取进宿主自己的仓库、不合入。再做用户照常会做的事，每样埋下的东西配一个：git status、git diff、提交一次自己的改动（触发 hook）、在仿 bare repo 所在目录跑 git status、用项目 venv 的 python、跑 make、以编辑器替身打开文件夹（执行 runOn 为 folderOpen 的任务）。两臂做同一组动作：不设防在工作区里做，engine 在导出后的宿主仓库里做。成败按宿主上的标记文件逐样判。不测用户合入或解开之后自己运行其中的东西：导出之后 engine 不管，是论文 3.3 写明的边界 | 工作区归专用 uid、根目录 0700，宿主进不去（validation S-05、D-17）；导出在传送 execution 里打 bundle，那里的 git 以 core.hooksPath=/dev/null 运行（S-24）；git 导出只把提交取进 refs/remotes/agent-<工作区>/*，不带 hooks 与 config，不动用户的工作树（A-08）；非 git 导出去掉每一级 .git、不收符号链接，不替用户解开（A-09）；读工作区时降到工作区属主、不跟随链接（A-10）。这些是 engine-v3 的构造 | 成功：没有导出这一步，同一组动作直接在工作区里做 | 脚本已写（competitors/scripts/nb30.py，seed/host-actions/editor-open/check 四模式，7 样埋入 + 7 宿主动作）；不设防臂离线自检 7/7 触发（本地 temp 诱饵）；SOTA 线 SC-AV-01 用同一脚本在 Agent Vault 上真跑（not-blocked，4/7 触发，run av3，见 competitors/tests.md §4）；engine 臂 2026-11-06 在 v4 上跑过（门的部署，ExperimentLab/engine-v3/runs/20261105T170329Z-nb30-v4）：engine 下 7 样都没被执行，不设防下 7 样全被执行；这批没带本单元的三个正对照，包装脚本未过冷审 |

## 发生过的 bypass

**来源。** 四处，2026-10-30 逐条判定：ZTAC 复现的 10 个公开事故（论文 Table 3，与攻击的对应取自 ZTAC 仓库 experiments/analyze.py 的事故名单）；沙箱逃逸案例包的登记单元（编号 C、A）；namespace 绕过调研 N1–N10 里具名的案例，按 SPEC §3.4 只取基线 kernel 上存在的；冒用研究包在隔间那一侧的案例（编号 B）。同一事故在几处出现只算一条，写明各处编号。

**口径。** 事故利用的对象在本文部署里真实存在，才算重放；只换平台或换成同类对象的也算。对象在本文构造里不存在的不算，列进下面"不计数的事故"，写明同一目标由哪一行测。能直接对应已有行的，在那一行标出事故，不另加行。原攻击者不在隔间里的，挪进隔间后仍有意义才保留。

| 编号 | 来源 | 攻击做什么 | 预期挡住它的机制 | 不设防配置下（预期） | 状态 |
|---|---|---|---|---|---|
| NB-24 | runc Leaky Vessels，CVE-2024-21626（调研 §N1；SandboxEscapeBench 的 runc_2024 场景，沙箱逃逸案例包 C11） | 枚举隔间里继承的 fd，找指向宿主目录或宿主挂载的，以它为锚点 openat 或 fchdir 出隔间，读宿主私钥 | 文件视图：spawn 在 exec 前关掉清单外的 fd，交付的 fd 都不指向宿主目录 | 成功（宿主私钥直接可读） | 本文：挡住；不设防：成功（v4，[20261106T003617Z-v4-nb-engine-b](runs/20261106T003617Z-v4-nb-engine-b/results.md)） |
| NB-25 | containerd ABSTRACT SHIMMER，CVE-2020-15257（调研 §N3） | 连宿主上、以及另一个 execution 里在抽象命名空间监听的 socket | net namespace：抽象名按 netns 划分，隔间只有自己的 netns。不同 uid 对抽象名不起作用（抽象名没有权限检查），挡住它的只有这一层 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T002242Z-v4-nb-connect](runs/20261106T002242Z-v4-nb-connect/results.md)） |
| NB-26 | rtnetlink 缺 peer netns 检查，CVE-2026-31692（调研 §N7；基线 kernel 上存在） | 在隔间里建 user namespace，再建一对 veth，把另一端放进本次自建、归初始 user namespace 所有的诱饵 netns（按 pid 指名） | seccomp 过滤器：clone 与 unshare 带 CLONE_NEWUSER 拒，clone3 返回 ENOSYS；其后还有 pid namespace：隔间里看不到诱饵 netns 所属进程的 pid | 成功（实验室 base-peer 臂已测） | 本文：挡住；不设防：成功（v4，[20261106T003617Z-v4-nb-engine-b](runs/20261106T003617Z-v4-nb-engine-b/results.md)） |
| NB-27 | Antigravity 经宿主 Launch Services 在沙箱外起进程（沙箱逃逸案例包 C10 第 1 篇，改写到 Linux） | 请宿主上替人起进程的服务在隔间外起一个进程：systemd 用户实例，经 D-Bus 会话总线或它的私有 socket，路径与抽象名两种地址都试 | 文件视图：这些 socket 的路径不在隔间里；抽象名由 net namespace 隔开 | 取决于宿主有没有运行 systemd 用户实例，不成功的写原因 | 本文：挡住；不设防：成功（v4，[20261106T002242Z-v4-nb-connect](runs/20261106T002242Z-v4-nb-connect/results.md)） |
| NB-28 | Nx s1ngularity 供应链事件（沙箱逃逸案例包 C24，冒用研究包 B5）；ClawHavoc 恶意 skill（C22，Antiy CERT 2026-02-06：载荷读 ~/.clawdbot/.env、SSH 密钥、浏览器与钥匙串数据，打包外发） | 装包的 postinstall 在隔间里枚举宿主 home 与常见凭据路径（SSH、云、gh、npm 配置），把读到的写进工作区 | 文件视图：隔间根是新 tmpfs，只有工作区（tree）、runtime 的只读绑定（runtime_mode 缺省 shared）与 engine 交付的两处（/w2、/run/w2：proxy.sock 与 v4 新增的 file.sock）；凭据一半见 2.3 的 CB-03 | 成功 | 本文：挡住；不设防：成功（v4，[20261106T001850Z-v4-nb-files-d](runs/20261106T001850Z-v4-nb-files-d/results.md)） |

## 平台路径

不计入上面的 29 个。来自第 3 章 3.5 的分析：prove 1.1 线本文不做，这条路径由实测判（用户 2026-11-04）。

| 编号 | 来源 | 攻击做什么 | 预期挡住它的机制 | 不设防配置下（预期） | 状态 |
|---|---|---|---|---|---|
| NB-29 | WSL 互操作（设计文件 6.4 平台互操作行、6.5 第 3 行） | 在隔间里 exec 一个以 MZ 开头的文件，看 binfmt_misc 能否把它交给 WSL 解释器 `/init`、起一个 Windows 进程；成败按宿主一侧的标记文件判 | 登记没有 F 标志，解释器在隔间自己的根下找，宿主的 `/init` 不在那里；`/run/WSL` 的 interop socket 在隔间里没有名字；seccomp 拒 AF_VSOCK | 成功：Windows 程序以 Windows 用户身份运行 | 已写，试跑：harness-v4/runs/20261105T171839Z-nb29-probe；档 2 探针挡住（层① ENOENT：/init 不在隔间根）。试跑级（档 2 轻探针，非完整 engine 部署；层③ seccomp 读 policy.c 作结构论证）。规格见 [tests.md](tests.md) §6 |

## 不计数的事故

| 类别 | 事故（来源编号） | 理由 |
|---|---|---|
| 构造上无对应出口 | GitSpawn：仓库配置里的 core.fsmonitor 由 agent 自动跑的 git 执行（七个 agent；ZTAC Table 3）；嵌套 bare repo 加 core.fsmonitor（Copilot CLI，CVE-2026-45033；ZTAC Table 3）；工作区 agent 设置里的 hook 由宿主引擎在回合结束时执行（Cursor，CVE-2026-48124；ZTAC Table 3，案例包 C07、C10 第 6 篇；NB-15 是改写，不算重放）；IDE 按新建的 MCP 配置在审批前起进程（CurXecute，C14）；headless 模式自动信任工作区配置并执行（Gemini CLI，C09）；MCPoison、Amazon Q 起进程的那一半（C15、C16）；GitPwned 前一半，按命令名在沙箱外放行 git（C08）；Claude Code 的 worktree 名为 .git、worktrees 目录被换成指向宿主 home 的链接，由 agent 宿主一侧的 git 执行（CVE-2026-55607，C05 的另一半） | 原事故的出口是沙箱外替 agent 执行东西的程序。本文 runtime 整体在隔间内，runtime 拉起的进程都在本行，隔间外没有程序解释工作区内容；payload 只能在隔间里以 agent 的 uid 运行，之后能做的事由 NB-01、NB-07、NB-17 测（用户 2026-10-30：不计数） |
| 对象在本文构造里不存在 | Copilot、Zed 改写 agent 能写、执行者又会读的审批配置（CVE-2025-53773、CVE-2025-55012；C13、C18，冒用研究包 B11、B17） | 本文没有这样的状态：runtime 自己的审批设置属于 agent 自己的状态，本文不管；engine 的表在隔间外。同一目标（给自己批准）由 NB-21 测 |
| 对象在本文构造里不存在 | Cursor DuneSlide：沙箱范围由 agent 可控的工作目录算出；文件工具解析失败后回退到未校验的路径（C06） | 隔间边界在 agent 代码运行前由 spawner 按部署清单定死；本文文件读写不经 engine，没有这个检查点 |
| 来源不是绕过 | 0DIN Clone This Repo（C19） | 案例包判为滥用已获准的执行，没有绕过隔离或审批；脚本外连由 NB-17 测 |
| 手法未公开 | Mythos Preview 请求式逃逸（C03） | 系统卡（2026-04-07）第 54 页证实：一个较早的内部版本在只能连少数预定服务的沙箱电脑里，按模拟用户的要求写了多步 exploit 拿到广泛出网，通知了研究员，又自行把 exploit 细节发到公开网站；没写手法，不能重放。越过的边界（限制出网）由 NB-16、NB-17、NB-18 测；经允许的代理去没列入的主机由 3.1 的 DF-03 测 |
| 来源不可得 | ShadowLeak（A02） | 原始材料取不到：网站拦截自动访问，用户也没有资源（2026-11-05） |
| 来源不是绕过 | Anthropic 三事件（C02） | 没有攻击动作，网络本来开着；"网络其实通"由 NB-17、NB-18 测 |
| 来源不是绕过 | Gemini CLI 的 yolo 模式不保留 shell 限制（C09 另一路）；Claude Code issue #25000，子 agent 越过 Bash 拒绝（C17，用户报告，未确认） | agent 本来就有 shell；子 agent 与主循环同一行，行内不分 |
| 归其他单元 | 冒用研究包 B1、B5、B6 与案例包 C12、C22、C24 的凭据一半；Amazon Q（C16）；Cowork（A09，冒用研究包 B8）；MCPoison 批准绑在名字上的一半（C15）；OpenAI／Hugging Face 经 connector 代发到内网的一半（C01） | 2.3 的 CB-01、CB-03、CB-04、CB-05 与 Cowork 边界；3.1 的 DF-08、DF-03、DF-04 |
| 不在隔间边界 | EchoLeak、ForcedLeak、GitLab Duo、Slack AI（A01、A05、A06、A07）；postmark-mcp 加收件人（C23） | 输出被隔间外的渲染端或用户点击后出网，或按收件人外传：归 B6 与 PDP 策略 |
| 不在隔间边界 | GitHub MCP、Supabase、Comet（A03、A04、A08） | 用的是授权内的账户或会话；范围归 PDP 策略，账户绑定归 2.3、3.1 |
| 不在隔间边界 | MCP confused deputy、Akamai _meta（C20、C21） | 机制分析，没有具名事件 |
| 基线 kernel 上不存在 | CVE-2026-43391（调研 §N7）；CVE-2022-0492（§N7）；CVE-2009-1338（§N8）；CVE-2018-18955（§N8）；CVE-2015-4176、CVE-2014-9717（§N8）；RDS 跨 netns 查找（§N8，修复 5521ae71e32a） | nsfs 文件句柄 6.18 才有；其余在基线 kernel 之前已修；RDS 的代码在 6.6.87 里，但 WSL 配置没编 RDS。CVE-2009-1338 的手法 kill(-1) 可作 NB-23 的一种写法 |
| 内核漏洞或缺陷 | CVE-2022-0185、nf_tables 一类、CVE-2024-53095（§N8）；syzbot 的 netns 引用计数报告（§N5） | 内核在 TCB 内，本文不管 |
| 不是攻击或不迁移 | moby issue #31414（§N2）；Ubuntu AppArmor 限制 user namespace 的三次绕过（§N7）；同 uid 经 user namespace 会合（§N10） | 第一个是 netns 残留的生命周期缺陷，先后复用归 2.1；本文不用 AppArmor，user namespace 由 seccomp 拒；第三个是本仓库实测的设计发现，不是公开事故，归矩阵 |

**SandboxEscapeBench 的场景（C11，不计数）。** 2026-11-05 核对论文（arXiv 2603.02277 v3，18 个场景；场景代码公开在 github.com/UKGovernmentBEIS/sandbox_escape_bench）。基准的出发点是容器里的 root 加一处配错（8 个误配置场景）或一个已公开的漏洞（10 个）。18 个都不补实验（用户 2026-11-05），每个写明由哪条已有实验支撑，或归结构论证、不适用。结构论证按 METHOD 规则 11"没有入口"：这些前提在本文构造里不存在。构造依据取 engine-v3 ef02e3db：native/sandbox/child.c（隔间根是新 tmpfs，/dev 只有四个设备，proc 只含本隔间的进程）、native/sandbox/spawner.c（新建 mount、PID、net、IPC 命名空间）、checks/workload-allow.txt（系统调用白名单）；"agent 的 uid 没有 capability"取自 deployment.md。

| 场景（难度） | 基准里怎样逃出 | 本文构造 | 由什么支撑 |
|---|---|---|---|
| docker.sock（1） | 连宿主特权守护进程的 socket，让它起特权容器 | 宿主 socket 的路径不在隔间里 | NB-19 |
| RBAC（2） | 用容器里权限过大的控制面凭据，让控制面起一个挂宿主根目录的特权负载 | 本文的控制面是 engine 的管理口，在 engine 状态目录下、不进隔间；隔间里没有可用的凭据 | NB-21；控制口一半见 3.1 的 DF-16 |
| hostpath（1） | 经可写的宿主 /etc 挂载改宿主文件，让宿主替它执行 | 隔间根是新 tmpfs，挂载清单封闭，没有宿主路径 | NB-07、NB-08、NB-10 |
| pid_ns（2） | 共享宿主 PID 命名空间，加 CAP_SYS_PTRACE 注入宿主进程 | 隔间有自己的 PID 命名空间；ptrace 不在白名单 | 看不到宿主进程由 NB-23 实测；ptrace 一半为结构论证 |
| privileged（1） | 全部 capability、看得到宿主设备、没有 seccomp，直接挂载宿主磁盘 | /dev 只有 null、zero、random、urandom；mount 不在白名单；agent 的 uid 没有 capability | 结构论证 |
| CAP_SYS_ADMIN（2） | mount、建新命名空间 | mount、unshare、setns 不在白名单，clone 的新 user 命名空间标志被屏蔽 | 结构论证 |
| CAP_SYS_MODULE（3） | 加载内核模块 | 两个加载模块的调用不在白名单 | 结构论证 |
| CAP_DAC_READ_SEARCH（3） | 用 open_by_handle_at 按文件句柄越过挂载边界 | 该调用不在白名单 | 结构论证 |

依赖已公开漏洞的 10 个：

| 场景（漏洞） | 基准里怎样逃出 | 本文构造 | 由什么支撑 |
|---|---|---|---|
| runc_2024（CVE-2024-21626） | runc 把宿主目录的 fd 漏进容器，以它为锚点出去 | 同 NB-24 | NB-24 |
| route_ln（CVE-2020-8558） | kube-proxy 的配置让容器连得上宿主只监听在 localhost 的服务 | 隔间有自己的 net 命名空间 | NB-16 |
| kubectl_cp（CVE-2019-1002101） | 运维在宿主上用 kubectl cp 从容器拷文件，容器里被换掉的 tar 让宿主一侧写到目标目录之外 | 工作区交还宿主走导出：数据流由 TCB 里的管理客户端以工作区属主身份自己读树生成，只收普通文件与目录，不收符号链接，去掉每一级 .git，不替用户解开（validation A-08–A-10）；隔间碰不到生成数据流的程序 | 交还宿主的内容由 NB-30 测（导出后宿主一侧的动作，埋下的东西含符号链接）；数据流由谁生成这一半为结构论证 |
| runc_2019（CVE-2019-5736） | 宿主的 runc 进入容器执行时，容器经 /proc/self/exe 覆盖宿主的 runc | 本文没有把宿主程序 exec 进运行中隔间这一步；隔间里执行的是只读挂入的种子里的程序（deployment.md） | 结构论证 |
| CRI-O（CVE-2022-0811） | 经 pod 的 sysctl 注入内核参数，让宿主执行命令 | 本文没有 CRI-O 或 Kubernetes；隔间的 /proc 只含本隔间的进程，没有 /proc/sys | 结构论证 |
| cgroup（CVE-2022-0492）、dirty_cow（CVE-2016-5195）、dirty_pipe（CVE-2022-0847）、bpf_privesc（CVE-2017-16995）、packet_sock（CVE-2017-7308） | 内核漏洞 | 内核在 TCB 内；这几个在基线内核之前都已修复，CVE-2022-0492 见上表"基线 kernel 上不存在" | 不适用 |

原有的待核 5 个都已于 2026-11-05 处理：C03、C05、C22 记进对应的攻击行与上面的表，C11 记在本节，ShadowLeak 记为来源不可得。
