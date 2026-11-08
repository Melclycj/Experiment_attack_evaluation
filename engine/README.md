# engine v3 — 隔间内 HTTP 前端、每行一个 connector、execution

## 这一版与 engine-v2-go 的关系

本目录是 engine 的主线（用户 2026-11-02："我要开 V3，因为 V2 跑过实验了，留个档"）：工作区改造在这里做，计划在仓库根的 .goals/plans/engine-v2-workspace-owner.plan.md。ExperimentLab/engine-v2-go 冻结、不再改代码，作为第二阶段各次运行与已跑实验的出处。

- 起点：本目录是 engine-v2-go 在 commit ea8c77ff 的已提交内容（不含 runs/）。
- 证据的出处：validation.md 里改造之前的证据写作"engine-v2-go 的 runs/<编号>"，指 ExperimentLab/engine-v2-go/runs 下的目录；本目录自己的运行写在本目录的 runs/ 下。
- 下面"engine-v2-go 与 engine-v2 的关系"与"原 engine-v2 说明"两节是 engine-v2-go 冻结时的原文，其中"本目录"指 engine-v2-go，run 编号指 engine-v2-go 的 runs/ 下的目录。

## engine-v2-go 与 engine-v2 的关系（engine-v2-go 冻结时的原文）

本目录是 engine 的主线（用户 2026-11-01）：第二阶段在这里做，实现设计文件 agent-rm-model.md 在 648d60f2 的改动，计划在仓库根的 .goals/plans/engine-v2-phase2.plan.md。ExperimentLab/engine-v2 冻结、不再改代码，作为建造计划 7.1–7.3 与内存测量记录的出处。

- 起点：本目录是 engine-v2 在 commit 7c3ee57a 的已提交内容（不含 runs/），隔间内前端换成 Go 版（计划 .goals/plans/engine-v2-go-frontend.plan.md）。
- 第二阶段开工时两边的差别（读码 2026-11-01，engine-v2 在 ce77cf20）：engine 核心、connector、relay/、native/、client/、bin/ 逐字节相同（运行时放法开关在 ce77cf20 提交进 engine-v2 后 native/ 两边也相同）；不同的只在前端、种子打包（checks/gate_seed.py）、门的运行器（checks/run_gate.py）、白名单推导（checks/derive_host.py、checks/workload-allow.txt，名字相同、来源注释不同）、检查范围与前端测试（checks/run_engine_checks.py、tests/test_frontend.py）与文档。Go 前端版改了哪些文件、每项检查的结果与 run 目录、已知差异，见 [validation.md](validation.md) 文末「Go 前端版记录」。
- 两个前端都在。frontend-go/ 是 Go 版（只用 Go 标准库，静态二进制），是本目录的默认；frontend/engine_frontend.py 是 Python（mitmproxy）版，留着对照与回退。两者对外约定相同，行为对照与已知差异见 [frontend-go/README.md](frontend-go/README.md)。
- 换前端为什么不重开可信基的证明：前端不在 TCB，它产生的规范形式帧由 connector 当不可信输入逐字段校验（SPEC-canonical-form.md §1、§3.1）。
- 为什么换：同一启动形式下空闲时的私有内存，Go 版约 6.7 MiB，Python 版约 61.5 MiB（各实测一次，见 frontend-go/README.md「内存对照」）。
- 选前端：门 checks/run_gate.py 与白名单推导 checks/derive_host.py 用 --frontend go|python，前端测试 tests/test_frontend.py 用环境变量 W2_FRONTEND_IMPL=go|python，默认都是 go。

当前状态（2026-11-02）：第二阶段第 1–6 步做完，经两份冷审阅（Opus、Codex）与修复后的冷复核，按审阅改过的代码在后续运行里全过；第 8 步的回归与实测、第 9 步的实验用种子与推导集跑完。最近一次 engine 检查 runs/20261101T192445Z-engine-p2-records（非特权单元 694 passed、root 单元 42 passed、集成 23 例全过）；最近一次沙箱回归 runs/20261101T192145Z-sandbox-p2-channels（208 例全过）；门与推导集在实验用种子上的最近一次是 runs/20261101T194631Z-gate-p2-seed（7.1、7.2 都过；推导集三个 agent 共 26 项在隔间里走完并判过，(g) 按 2026-11-02 改后的预期结果判，见 allowlist-derivation.md"结果"）。逐条 must 的证据与结果在 [validation.md](validation.md)，三个 agent 的 runtime 说明在 runtimes/。待办：Go 工具链 1.27.3 满两周（2026-11-02）后升级、重编、重跑前端测试与门；Go 前端在真隔间里运行中的内存在服务器 VM 上测（.goals/plans/sota-engine-memory-row.plan.md）。

## 原 engine-v2 说明

第二版原型，与 v1（`ExperimentLab/engine/`，基线 aa3f2803）平级，v1 目录原样不动。设计来源只有一份：
`Thesis/Work/Intake/2026-10-08-confused-deputy-authority-models/agent-rm-model.md`；第一阶段按它在 commit 260a3e50 的版本，第二阶段按 648d60f2 及其后的改定。部署说明（execution 开始时拿到什么、部署方提供什么、spawner 的检查）在 [deployment.md](deployment.md)。
建造计划在 .goals/plans/engine-v2-build.plan.md；验收层（must 表、覆盖核对、审阅门记录）在 [validation.md](validation.md)，
写代码之前建，每条 must 的后四列随各块填齐。

## 目录

| 目录 | 内容 | 来源 |
|---|---|---|
| native/ | spawner、child、policy、storage、transport 等 C 源，C 检查与 fuzz | v1 整体带走；按计划第 1 块改 spawner.c、child.c、policy.c、cell.c、storage.c、transport.c |
| engine/ | 核心（Python 标准库加 ctypes）：事件循环、生命周期、控制通道、记录、启动自检、agent 侧控制口的读取与阶段驱动 | v1 带走，删去 requests、tasks、operations、handlers、business 五个模块；第 3 块加工作区表、判定口、hook、管理口 |
| connector/ | 每行一个的 HTTP(S) connector（专用 uid；核章、规范形式校验、交核心、凭据替换、上游 TLS、响应剥除） | 第 4 块新写 |
| fileworker/ | 每行一个的文件 worker（宿主文件只读）：自己的专用 uid，不持特权；在文件口（SPEC 链路 G）逐片核章、只核帧、原样交核心（链路 H），用核心交来的 fd 读（pread）与列（scandir），用完即关；入口 bin/file-worker | 2026-11-04 文件读（计划 engine-v3-n16-file-read 2.3b）；tests/test_fileworker.py、tests/test_fileworker_root.py |
| frontend-go/ | 隔间内 HTTP 前端的 Go 版（本目录默认）：只用 Go 标准库，静态二进制，对外约定与 frontend/engine_frontend.py 相同；以 uid_i 运行，不在 TCB | engine-v2-go；做法与行为对照见 frontend-go/README.md，宿主侧集成测试 tests/test_frontend.py |
| mcp-go/ | 隔间内的 MCP server（宿主文件只读）：只用 Go 标准库，静态二进制，种子里 /runtime/mcp/engine-mcp；child 在前端之后、agent 之前以 uid_i 拉起，监听 127.0.0.1:mcp_port 的 /mcp，三个工具经本行的文件口（SPEC 链路 G）向文件 worker 请求；不在 TCB | 2026-11-04 文件读（计划 engine-v3-n16-file-read 2.3c）；做法与构建见 mcp-go/README.md，Go 测试在该目录，隔间里的端到端在 checks/run_engine_checks.py 的 mcp 一例 |
| frontend/ | 隔间内 HTTP 前端的 Python 版（本目录可选）engine_frontend.py（mitmproxy 以编程方式起在 lo:port、addon 改向、同进程 translator 把 HTTP/1.1 翻成规范形式帧送代理路径），以 uid_i 运行，不在 TCB；另有 make_ca_pool.py（部署方离线生成 CA 池）、git-credential-placeholder 与 npmrc.template（5.3 客户端适配） | 第 5 块；方案实测见 runs/20261028T151248Z-frontend-mitmproxy-trial，宿主侧集成测试 tests/test_frontend.py |
| relay/ | 隔间内 pty 转发进程 relay.c（静态 C，/runtime/bin/w2-relay；附接协议 SPEC §3.5），以 uid_i 运行，不在 TCB | 第 5 块；tests/test_relay.py |
| client/ | 管理客户端，两个入口，`--root` 都指部署根。bin/engine-client 以 engine uid 运行，在可信决策通道内，不在 TCB。bin/engine-workspace 以 root 运行导入、推进、导出，只载入 link.py 与 workspace.py，这两个在 TCB 内（下面的 TCB 模块清单；validation.md A-10、K-41）。`admin questions` 逐条画提问（不可打印字节一律转义）、收四词答复，"并记录"先确认范围再发；`admin entry/cred/ws/row/object …` 各发一帧（`admin object put <工作区> <别名> <宿主路径> --type file|dir [--list] [--mode allow|ask|deny]` 登记宿主文件对象，绝对路径原样发、相对路径只在前面接上当前目录，不折叠任何段，链接与 .. 交核心解析；`admin object del` 按别名删，validation.md H-01）（真值只从文件、环境变量或不回显提示读；`row start … --account host:port=account` 指定本次 execution 在该目的地用的那一个账户）；`attach <execution>` 连该行附接 socket，原始模式、窗口大小与 Ctrl-C 经转发，Ctrl-] 断开，`--record` 写 asciinema v2 记录；`admin row start … --policy-context FILE` 附这一行的策略上下文（至多 16 KiB，原样带给 PDP）；`bin/engine-workspace push|export`（以 root 运行，见 deployment.md 第 4、5 节）在 hold 下导入、推进、导出：推进到工作区的 refs/remotes/user/*，导出到用户仓库的 refs/remotes/agent-<工作区>/*，非 git 工作区推进到新目录、导出成归档文件 | 第 6 块；工作区改造加 workspace.py；tests/test_client_admin.py、tests/test_client_attach.py、tests/test_client_workspace.py |
| checks/ | 集成运行器；run_gate.py 是第 7 块的门：真部署（种子里放真实 agent、前端（默认 Go 二进制，--frontend python 换回 Python + mitmproxy）、ldd 闭包库，部署方的 workload seccomp 策略），只经管理客户端操作；--seed experiment 换成实验用种子（gate_seed.py，deployment.md 第 8 节），--suite derive 在隔间里跑推导集（derive_cell.py） | v1 带走，去掉 task 场景与业务目录；run_gate.py 第 7 块 |
| runtimes/ | 三个 agent（Claude Code、Pi、OpenCode）的 runtime 说明：种子、登记、条目各至少要什么，按推导集的操作注明依据（建造计划 7.4 第 7 条） | 第二阶段第 9 步 |
| tests/ | pytest 单测（非特权与 root 两套） | v1 带走，删去测已删模块的六个文件 |
| bin/ | engine 与 engine-scenario 入口（LIBW2SANDBOX ROOT CATALOG EVIDENCE，不再有 BUSINESS）；connector（第 4 块）、engine-client（第 6 块）与 file-worker（文件读）入口 | v1 带走，后三个新写 |
| runs/ | 每次运行一个独立目录（配置、命令、时间、原始输出） | — |

## 第一版做什么、不做什么

做：隔间本身；网络目的地一个列族（精确、模式、兜底三种键）；HTTP(S) 一种 connector，3.9 条款 1–9 全做、条款 10 做拒绝与剥除；
规范形式与线上编码；工作区表与磁盘镜像；行的登记、uid 按 execution 从保留区间分配、idmapped 工作区、pty 对；原型 PDP 即审批模式
标记；每行一个 connector；隔间内前端与转发进程；管理口与管理客户端；凭据记录；E-09 记录与 trace；关闭与回收。
只留接口：agent 侧控制 socketpair（身份规则照核，动词集合为空，任何请求答 `unsupported_kind`）；OAuth 账户的三端点（只登记）。
宿主文件只读（设计 3.3"经 engine 读的路径"，2026-11-05 落盘）：用户登记的文件与目录经隔间内的 MCP server 与每行一个文件 worker 只读，validation.md 的 H 组；写宿主文件不做。
不做：本机模型、入站端点两列；execution 之间的通信列与表本身列；次数与租约（归 PDP）；3.9 协议覆盖的
不支持清单；OAuth 轮换、cookie 库、WebSocket、HTTP/2、非 HTTP 协议、流式上传正文；行间隔离。每一项在 validation.md 的 N 组
里各有一行，写法只有失能不泄漏、声明不做、部署前提三种。

## TCB 模块清单（只许标准库 import；import 检查按本清单扫描，每块重跑）

- native/sandbox/：contract.c、support.c（文件读加 w2_open_beneath：核心打开宿主文件的唯一途径，validation.md H-10–H-12）、policy.c、catalog.c、transport.c、child.c、storage.c、spawner.c、cell.c、recover.c、catalog_tool.c 及各自头文件。
- engine/：__init__.py、admin.py、control.py、credentials.py、ffi.py、fileobjects.py（宿主文件对象：登记与锚、重启核对、文件请求的第一个检查点、打开目标、理由词，文件读加）、fileport.py（文件判定口的核心一端，SPEC 链路 H，文件读加）、hook.py、judgment.py、lifecycle.py、loop.py、main.py、matching.py、objects.py、pdp.py（hook 口，第二阶段加）、phases.py、receive.py、records.py、startup.py、workspaces.py、writer.py。
- connector/：__init__.py、canonical.py（第 2 块的规范形式）、reader.py（代理口读取：C 判定口读取器经 ctypes，核章、拒 fd、早查种类与预算）、channel.py（判定口：序号、JUDGE/WITHDRAW/REPORT 发出、答复按序号派回、REVOKE、迟到 ALLOW 清零）、upstream.py（地址过滤、TLS、凭据替换、http.client 发送、响应帧与剥除、连接登记表）、token_response.py（条款 10 的 token 响应按正文认：候选、读不出、是否 token 响应，三个纯函数，由 upstream.py 调用）、session.py（每条 fd 一个线程：读帧、校验、封印、交核心、等答复、拒绝或发出、回报）、main.py（入口：fd 3/4 继承、PASSCRED 核验、连接上限、线程）。
- fileworker/：__init__.py、channel.py（文件判定口的 worker 一端：序号、FILE_ASK/FILE_WITHDRAW 发出、答复按序号派回、FILE_ALLOW 恰带一个 fd，违约即退出）、session.py（每条文件口连接一个线程：核章读帧、只核结构、等核心、按 fd 读与列、关 fd）、main.py（入口：先设不可 dump，再 fd 3/4 继承、PASSCRED 核验、16 条连接上限、线程）。只 import 标准库与 connector/ 下的模块；不按路径打开、stat 或列任何东西（validation.md H-15）。
- client/：__init__.py、link.py（管理口连接）、workspace.py（导入、推进、导出）。以 root 运行的入口 bin/engine-workspace 只载入客户端的这三个模块（validation.md A-10、K-41；判别测试在 tests 的 test_canonical 里）。
- 不在 TCB：frontend-go/、mcp-go/、frontend/、relay/、pdp/（简易 PDP，engine 外的程序，P-01）、engine/testing/、tests/、checks/、native/checks/、native/fuzz/；client/ 的 admin.py、attach.py、main.py、render.py（入口 bin/engine-client，以 engine uid 运行，在决策通道可信的前提内）。

## 内存量级（工程默认，建造计划工程项 4）

每行同时连接 64 条，每条 fd 同时一个请求，正文上限 64 MiB，每行在途正文总量上限 256 MiB（按帧的声明长度记账）。
核心按需 mmap 只读、不复制。connector 一侧，正文在交换期间只住在密封的 memfd 里（发送时从它 pread）；解析那一刻有短暂的
多份副本（C 读取器的线缓冲、mmap 输出缓冲、帧字节、字段），上界约为正文的 4 倍，解析完即释放，所以一行的瞬时峰值可达
在途总量的数倍，稳态占用等于在途 memfd 之和。每行排队请求 32 条（含正在等人的那一个）。

## 运行时放法开关

目录可选键 `runtime_mode`：缺省或 `shared` 让每个隔间直接只读绑定 spawner 启动时核过的那一份种子，不建副本；`copy` 是每次
execution 一份核过的 reflink 副本（storage.c 的 worker、spawner.c、child.c）。缺省在工作区改造里由 copy 改为 shared（用户
2026-11-02："就是默认改成共享"；设计 7bb0b717 的理由表；validation.md S-23）：每行一份副本换来的只是不与别的行共用 inode，即页缓存、
锁与 inotify 这类侧信道的防御，侧信道不在本文范围。三个运行器都把这个键显式写进目录：门（checks/run_gate.py）与 engine 集成
（checks/run_engine_checks.py）缺省 shared、可用 `--runtime-mode copy`，engine 集成另有 `--runtime-mode default`，故意不写这个键、
测目录自己的缺省（S-23），每个用例都断言隔间里的 runtime 是种子本身还是副本；沙箱回归（native/checks/run_sandbox_checks.py）写 copy，
因为它的存储用例考的是副本的建与删。这一开关是 2026-10-31 从 engine-v2 工作区原样搬来的，engine-v2 在 ce77cf20 提交了同一开关。

## 完成记录开关（测量用）

设计规定 engine 不记完成（agent-rm-model 648d60f2 4.3：trace 是放行与尝试的账本，connector 的完成回报只作核心的内部记账）。门要拿远端状态码作"替换生效、上游 2xx"的证据，而 connector 的输出由 spawner 接到 /dev/null，所以 bin/engine 另收一个可选参数 `--measure-completion`：打开时核心把每个完成回报另写一条诊断 `request_completed`（measurement_only=true，序号、结果类别、状态码），只此而已，不改变任何判定，不是审计记录。缺省不开；门（checks/run_gate.py）与集成场景（engine/testing/scenario.py）打开它。

## 每次 execution 的 CA（S-16，第 5 块）

部署根下有一个 CA 池目录（catalog 的 `ca_pool_ref`），每个条目一个目录（`ca.pem`、`ca.key`），由部署方离线用 frontend/make_ca_pool.py（或 openssl）生成。spawner 为每行从池里取一个条目（rename 进行目录，池空即 spawn 失败），child 把它只读 bind 到隔间的 /w2/ca；前端用它签叶证书，agent 经 NODE_EXTRA_CA_CERTS、SSL_CERT_FILE、GIT_SSL_CAINFO、PIP_CERT、REQUESTS_CA_BUNDLE、CURL_CA_BUNDLE（都指 /w2/ca/ca.pem）信任它；行回收时条目随行目录删除。私钥在隔间内可读是设计所定（骗得了的只有 agent 自己），这张证书永不装进别处的信任库（D-08）。

隔间里的 HOME 不论 runtime 登记写什么，一律由 child 设为隔间自己的 /tmp（S-16，构建计划 7.4 第 4b 条）：HOME 里写的缓存、程序状态、会话记录与隔间里做的登录，行结束即丢。

## 边界声明（validation.md N 组与 C-31）

不支持的协议与客户端失能不泄漏；正文与 Location 里的其他凭据、非标准发 token 端点、公开目的地的 Set-Cookie 不剥；
token 响应按正文认（POST 的 JSON 或表单编码响应、不超过 64 KiB、顶层或 JSON 顶层对象值的直接键里有 access_token），
只对这两种标准格式作保证，认不出的不扣：别的格式或字段名，包括 agent 借 Accept 让授权服务器换格式（如 GitHub 的 XML）、
access_token 在第三层或更深或在数组里、token 在跳转地址里、正文超过 64 KiB 或 JSON 解析失败、方法不是 POST；
已登记的 token 端点在请求一侧照样被拒（与登记端点相等的检查）（N-16，用户 2026-11-05 定）；模型 API
请求体里的服务端工具归 PDP，engine 只保证 hook 看得到完整请求体；行间不隔离，上游响应与 TLS 这一输入面的缺陷能及全部行的凭据
（3.8 TCB 的输入行）；答复已出、尚未发出时撤销的残余是每条 fd 至多一个请求。
