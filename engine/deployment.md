# engine 的部署说明

本文件说明 engine-v2-go 怎样部署：一次 execution 开始时拿到什么，部署方提供什么，spawner 对部署方给的内容做哪些检查。

论文（Thesis/Work/Intake/2026-10-08-confused-deputy-authority-models/agent-rm-model.md）对部署方提供的内容只作假设：它们可信，写在论文 6.2 uid 一行的部署前提里。本文件第 6 节的检查是 engine 自己防部署失误的保险，不进论文的安全论证（用户 2026-11-02）。内容来自 2026-10-31 种子讨论的结论（建造计划 .goals/plans/engine-v2-build.plan.md"种子讨论"一项，用户认可），按 2026-11-01、11-02 的改定写成现在的样子。

## 1. 论文管到哪里，部署方管什么

论文从 execution 开始运行的那一刻管起，管两件事：execution 开始时手里有什么，也就是启动状态的形状；以及之后它的每个请求怎样经过 engine。

setup 归部署方：谁装种子、从哪里取、用什么工具部署。setup 在论文里只出现两处：部署前提里一句"种子与 /w2 由可信的部署方离线写好、归 root，其中没有 FIFO、socket 这类特殊文件"；评测的实验配置里一张版本表。

agent 要用的解释器和库，例如 python、node，是种子内容，归部署方。engine 部件（隔间内前端、pty 转发进程）由 engine 交付，但不在 TCB 里，不进安全论证。

## 2. execution 开始时拿到什么

| 内容 | 在隔间里的位置 | 谁定内容 |
|---|---|---|
| agent 本身与依赖 | /runtime，只读 | 部署方，每个 agent 一份 |
| 工作工具：shell、coreutils、git、python 等 | /runtime，只读 | 部署方；实验里三个 agent 同一份 |
| engine 部件：前端、pty 转发进程、MCP server（宿主文件只读） | /runtime，只读 | engine |
| 工作区 | /work，可写 | 用户 |
| 工具的占位配置：git 凭据助手与占位值、gitconfig、.npmrc | /w2，只读 | 部署方，所有 runtime 共用 |
| 本次 execution 专用的 CA | /w2/ca，只读 | engine：事先生成一池，每次起行取一张 |
| 环境变量与启动参数 | 进程环境 | 部署方写在登记里；HOME、HTTPS_PROXY、CA 路径等受管变量由 engine 覆盖 |
| 代理路径；pty 的 slave 端作 stdio；控制 socketpair 作 fd 3 | 隔间内 | engine |
| 根 tmpfs、/tmp、/dev/shm、proc、四个设备节点 | 隔间内 | engine |
| uid、无 capability、seccomp 名单、只有 lo 的网络 | 进程属性 | engine；seccomp 名单三个基础 runtime 共用一份 |

不进隔间、但起这一行必须有的：工作区的条目、凭据记录（真值只在 engine 一侧）、本行的 connector 进程（engine 起）。

## 3. engine 兑现什么，对部署方假设什么

engine 兑现两类：

- agent 改不了这些文件：由只读挂载、文件归 root、agent 的 uid 没有 capability 兑现。
- engine 自己搭的那部分形状正确：挂载清单封闭；agent 进程只有 fd 0–3，行内另有 pty 转发进程持有 pty 的 master 端与附接监听口；uid 按 execution 分配；seccomp 底线；对外只经代理口。由证明线 1.1 证。

"对外只经代理口"不只靠 network namespace 里只有 lo：有的套接字族可能不受 network namespace 约束。固定禁止的那组调用里有协议族过滤，socket 与 socketpair 只许 AF_UNIX、AF_INET、AF_INET6 三族与 AF_NETLINK 里的 NETLINK_ROUTE，其余一律 EPERM（validation.md S-19）。

engine 的保证不依赖种子里的程序做什么、是哪个版本。种子只读挂入，agent 改不了；nosuid，种子里就算有 setuid 程序或带文件 capability 的程序，执行时也不生效；nodev，设备节点打不开。engine 还有几条不信部署方配置的底线：一组系统调用固定禁止，名单怎么写都放不开；受管的环境变量由 engine 覆盖，登记里写什么都不算。

对部署方的假设：

- 种子与 /w2 由可信的部署方离线写好、归 root，其中没有 FIFO、socket 这类特殊文件。只读挂载挡不住连接一个 Unix socket 文件或写一个 FIFO（Linux 6.6 的只读检查只管普通文件、目录与符号链接；依据源码，2026-11-02 实测：只读 bind mount 下无关的无特权 uid 照样连上、写进），所有隔间共用的目录里若有这类文件，就是隔间之间的显式通道，所以论文把"没有"写成部署前提。
- 部署方不把不该给 agent 看的东西放进种子或 /w2，这和他往环境变量里放什么是同一类选择。部署方给的内容对不对，只影响 agent 能不能干活。
- 种子在一个 engine 运行周期内不变，升级种子就是新版本，要重新核验（第 6 节）。trace 与论文的 Methods 据此说清跑的是哪个版本。
- 工作区的存储归一个专用 uid（工作区属主），所有工作区共用它；它不是 engine、connector、PDP 的 uid（S-22，engine 与 spawner 启动时都核），宿主上除管理客户端外没有进程以它运行。每个工作区是一个 btrfs 子卷：根目录 0700，engine 按它的 device 加 inode 认工作区，它不进任何隔间；内容放在根目录下固定的子目录 tree 里，隔间挂的是这个子目录（S-25）。存储的各级上级目录宿主用户不可写，对 engine uid 可搜索（engine 按路径 stat 工作区根）。宿主用户因此进不去工作区，在里面建不了文件、Unix socket、FIFO 与硬链接；agent 能改的只有子目录，把它改成 0777 也不打开根目录这道门（D-17）。改造前工作区归宿主用户，宿主进程放进工作区的 socket 与 FIFO 隔间连得上、写得进（engine-v2-go 的 runs/20261101T192145Z-sandbox-p2-channels），那条前提已被取代。
- 文件 worker 的专用 uid（宿主文件只读，2026-11-04 起；validation.md D-19、H-14）：部署时建或保留一个 uid 与组，只给这个 engine 的文件 worker 用，所有行的 worker 共用它；没有服务或账户配在其上，宿主上没有别的进程以它运行。它不在保留区间里，不是 engine、connector、PDP 或工作区属主的 uid，组同样不是（spawner 读目录时、cell 起 engine 前、engine 启动时三处都核，不符即拒绝启动）。目录里写成 `file_worker`：uid、gid、可执行文件与 argv（`python3 -I -B bin/file-worker --library <部署根>/libw2sandbox.so`，spawner 在末尾补本行 uid 与 execution 标识）；测试与门用 70996。
- 隔间内的 MCP server（宿主文件只读，2026-11-04 起；validation.md H-23）：engine 部件，与前端同一待遇，不在 TCB。种子里放 mcp-go/ 编出的静态程序 /runtime/mcp/engine-mcp（checks/gate_seed.py 的 mcp_build：CGO_ENABLED=0、-trimpath、-buildvcs=false、-ldflags='-s -w'，约 6.4 MiB）。目录里写成 `mcp_server`（可执行文件与 argv，同 `frontend` 的形状；child 在 argv 末尾补 /run/w2/file.sock、端口与 ready 文件 /tmp/.w2-mcp-ready）与 `mcp_port`（1–65535，不得等于 `proxy_port`，spawner 读目录时核；测试与门用 3129）。每个隔间有自己的网络 namespace，各行用同一个端口号；agent 的 MCP 配置写 http://127.0.0.1:<mcp_port>/mcp。它在 agent 的 seccomp 名单下运行，名单要容得下它（checks/workload-allow.txt）。
- 宿主上以 root 运行的进程属于部署方，按可信处理；导入工作区的内容来自用户，按可信处理。
- connector 的拒绝清单（目录里 `connector` 的 argv 带的 --deny-address，可重复；validation.md D-05、C-19）：清单里的地址，格子点名了也不连。装实例公网 IP，与链路本地段以外的云元数据地址（按所在云厂商的文档给出）；部署在 WSL2 的 NAT 网络模式时，另装 Windows 一侧的全部接口地址，不只默认网关：runs/20261104T221233Z-wsl-windows-side-reach 实测默认网关与 Windows 的每个局域网地址从 WSL 都连得上，终点都是 Windows 自己。链路本地段、回环段与宿主接口地址由 connector 自己处理（内置段，启动时枚举接口地址加逐连接探测），不用进清单。
- 其余部署前提（保留 uid 区间、云元数据地址清单等）见论文 6.2。

## 4. 谁提供什么

原型里用户与部署方是同一个人。

部署时，engine 启动前做一次：

- 每个 agent 一份：种子里的 agent 本身与依赖；登记，即环境变量与启动参数。
- 所有 agent 共用：工作工具；git、npm 等工具的占位配置。
- 启动计划：哪个 runtime 配哪个工作区，怎样配论文不管。
- 宿主前提：保留 uid 区间、btrfs 部署根、工作区属主这个专用 uid、文件 worker 的专用 uid 等，论文里只列为部署前提。
- 每个工作区：子卷归工作区属主、0700，里面建好子目录 tree（归属主、0700）；推进与导出两个传送计划，名字是"<工作区>.push"与"<工作区>.export"，runtime 是保留的 w2-transfer-push 与 w2-transfer-export，命令是 checks/transfer_runtimes.py 里的固定脚本，种子里要有 bash 与 git。
- CA 池按起行次数备：传送 execution 也是一行，照样从池里取一个 CA 条目、占一个保留 uid。

用 engine 时，经管理客户端：

- 建工作区，再导入：以 root 运行 bin/engine-workspace push，git 仓库给 --repo 与 --branch（只带点名的分支，第一次推进顺带检出第一个分支），普通目录给 --dir。
- 登记凭据记录：目的地、账户、放置位、认证词（Bearer 或 token）与真值，Basic 的真值是用户名与密码；OAuth 种类的账户另登记 token 端点。
- 条目：agent 要访问的目的地都要事先放好条目；没有条目的请求当场拒（论文 3.2）。
- 每次起行：选工作区与启动计划；某个目的地列了多个账户时，指定这次用哪一个；可以附一个至多 16 KiB 的策略上下文文件，engine 原样带给 PDP（--policy-context）。
- 之后把改动交给 agent：engine-workspace push，取到工作区里的 refs/remotes/user/*；普通目录落在工作区里一个新建的 from-user-<时间> 目录。
- 取回 agent 的产出：engine-workspace export --repo，取到用户仓库的 refs/remotes/agent-<工作区>/*，合入由用户自己做；非 git 工作区用 --archive-to，得到一个归档文件，什么时候解开由用户定。

不用用户提供的：engine 部件、seccomp 名单、CA，以及 fd、uid、namespace 与挂载的形状。seccomp 名单覆盖三个基础 runtime；第四种 agent 若用到名单外的系统调用，名单要扩。

每个 agent 一份 runtime 说明，三节：种子（只写 agent 本身与依赖）、登记、条目。seccomp 名单与工作工具都是三个 runtime 共用一份，单独写一次，不进每个 agent 的说明。

## 5. 工作区与每次起行

工作区挂哪个目录，在创建时定下，之后不变；工作区按根目录的 device 加 inode 认。工作区是 engine 存的那份 clone，不是用户的仓库：每导入一次就是一个新的工作区，同一个用户仓库可以导入几次，用来并行。内容跨 execution 保留，只有这个工作区的 execution 与经管理客户端的推进能改它；宿主用户进不去（第 3 节）。

每次起行，从部署时给这个工作区登记的启动计划里选一个。一份启动计划把一个 runtime、一个工作区与那份 seccomp 名单配在一起。怎样选论文不管。

身份不变：uid 按 execution 分配，持久名字是工作区。条目挂在工作区上，所以同一个工作区里起哪个 agent，读的都是同一份条目；要分开，就用不同的工作区。

推进与导出：管理客户端以 root 运行，先为这个工作区取 hold（管理口 WS_HOLD，K-55）：工作区上还有活着、关闭中或隔离中的行就拒；hold 期间别的连接起不了行，持有者自己也只能起传送计划；连接一断 hold 就放。git 的推进与导出由传送 execution 在隔间里做（不挂条目、不带账户、网络请求一律拒、git 的钩子不跑，S-24）；客户端只把一个 bundle 文件放进 .engine/incoming，或从 .engine/outgoing 取出一个，等这一行的进程都结束再读 .engine/result。碰工作区的那部分降到工作区属主做，碰用户一侧的那部分（含 git 的两次取回）降到发起用户做；在工作区里逐级不跟随符号链接地打开、排他新建、按类型收（A-10）。

runtime 的放法：缺省所有隔间只读挂同一份核过的种子，不建副本；目录写 runtime_mode 为 copy 时，每次 execution 一份核过的 reflink 副本（README"运行时放法开关"，S-23）。各运行器都把这个键显式写进目录。

## 6. spawner 的检查

这些检查都不进论文的安全论证：论文假设部署方提供的内容可信（第 3 节）。它们是 engine 自己防部署失误的保险，以及版本对应与副本隔离的手段。

engine 启动时，spawner 对每个种子全量核对一次：清单外没有多余项，属主是 root，权限只许 0755、0444、0555，单一硬链接，没有特殊属性，只有目录、普通文件与符号链接，链接不出种子，ELF 为 x86-64，sha256 相等。sha256 这一遍把实际在跑的字节和目录登记的摘要对上，trace 与 Methods 据此说清跑的是哪个版本。

复制放法下，每次起行对副本只做结构检查：属主、权限、文件类型、硬链接数、与种子不共用 inode、没有多余条目，不再重算 sha256（validation.md S-21）；共享放法（缺省）不建副本，起行时没有这一步。理由：检查发生在 agent 运行之前；种子与副本归 root，只读挂入；能改字节的只有可信的部署方；隔间里来自 runtime 的程序都在降权、装上 seccomp 之后才运行。每次起行之前，spawner 对 /w2 做与种子相同的文件类型检查（validation.md S-20）。

按作用分三类：

- 防部署失误的：文件类型（只有目录、普通文件与符号链接）、属主、权限、多余条目、没有特殊属性、链接不出种子、ELF 架构。链接一项只防失误：复制种子时符号链接按清单原样重建、文件不跟随链接打开（读码），隔间里的符号链接按隔间的根解析，指向的都是 agent 本来够得着的东西。
- 隔离副本的：单一硬链接与不与种子共用 inode，保证每次复制的放法下副本不与种子、不与别的副本共用 inode，也是页缓存侧信道的防御。
- 对版本的：sha256。

清单检查里的查重与查上级目录按路径查表，判定条件与逐项扫描相同（validation.md U-03）；原先的写法是平方级，带上 Pi 的种子单次约 30 秒，到启动期限。

## 7. 跨行共享 inode

/w2 是部署目录的 bind mount，四个设备节点是宿主设备节点的 bind mount，所有隔间共用同一批 inode；seccomp 名单放开了 flock、fcntl 与 inotify 一组调用。由此有两种信道，只读挂载与单一硬链接都挡不住（推断，未实测；flock(2) 允许在只读打开的文件上加排他锁，inotify 按 inode 报事件）：两个合谋的隔间经锁状态或 inotify 事件传比特；一个隔间不需合谋，监视共用文件就能看到别的隔间何时打开、读取它们，例如从 /w2 的 git 凭据助手看出另一行何时推送。

两种都不是交流通道：没有一方能把内容写进对方读的对象，只能借锁与事件这类信号合流来编码，属于隐蔽信道与侧信道，和计时、页缓存是同一类。论文不考虑隐蔽信道与侧信道（论文 3.4"声明不控"）。缺省的共享放法下，种子的文件也在这批共用 inode 里，还能看出别的隔间跑了哪些程序；同属侧信道，声明不控（validation.md N-17）。

## 8. 实验用的种子

| 部分 | 内容 | 三个 runtime 是否相同 |
|---|---|---|
| engine 部件 | pty 转发进程（静态 C，一个文件）；前端：缺省 Go 版，一个静态程序；Python 版（Python 3.12 加 mitmproxy 12.3.1，约 2,860 个条目、79 MB）留作对照；MCP server（宿主文件只读，2026-11-04 起）：Go 静态程序一个，约 6.4 MiB，sha256 记在 dependency-lock.json 的 mcp_sha256 | 相同 |
| 工作工具 | bash；coreutils、grep、findutils、sed、diffutils 按 dpkg 列出的程序；python3.12（另有 python3 链接）加 pytest 9.1.1 及其依赖与 pip；git 加 https 传输；curl、uv、gh；node v22.23.4 加 npm（另有 npm、npx 链接）；ripgrep 15.2.0、fd 10.5.0（GitHub 发布页的静态 musl 版）；ldd 补的共享库 | 相同，实验设计 |
| agent | Claude Code 2.1.312：一个文件，294 MB；Pi 1.4.0：npm 装出的 node_modules，16,588 个条目、112 MB，要 node ≥22.19，其中 linux-arm64 的一个预编译 .node 不放（目录检查只收 x86-64 的 ELF）；OpenCode 1.19.5：npm 包里 postinstall 放好的那一个程序，214 MB，包里别的条目不放 | 各一个 |

组种子的是 checks/gate_seed.py（--seed experiment）。它写一份版本锁定文件，即种子里的 dependency-lock.json，逐项记版本、来源与 sha256，供 Methods 取版本号。不做正式的部署工具。实测：这份种子 20,955 个条目、932 MB；spawner 启动时的全量核对（含对全部字节算 sha256）2.5–7.5 秒，每次起行 0.5–0.8 秒（engine-v2-go 的 runs/20261101T194631Z-gate-p2-seed，validation.md U-03）。

ripgrep 与 fd 放进种子后，Pi 不再自己下载（实测，同一运行目录：Pi 十五行里没有去 GitHub 发布页的请求；宿主上没有这两样时，Pi 首次进交互界面会下载）。每个 agent 至少要什么，见 runtimes/ 下三份 runtime 说明。

## 9. 依据

| 结论 | 依据 |
|---|---|
| setup 与 spawner 的检查不进安全论证 | 论文只假设部署方提供的内容可信（用户 2026-11-02）；安全论证只依赖启动状态的形状 |
| 种子与 /w2 里没有特殊文件写成部署前提 | 只读挂载挡不住连接 Unix socket 文件、写 FIFO（Linux 6.6 源码；2026-11-02 实测）；共用目录里的这类文件是隔间之间的显式通道；论文不留显式交流通道，engine 关不掉、或论文不靠 engine 关的，写成部署前提 |
| 起行时不重算 sha256 | 见第 6 节的理由；证明线 1.1 记的副本性质是属主、权限、硬链接、inode，不是 sha256；7.2 种子上每次起行约省 3.0 秒（sha256 速度实测 400–426 MB/s，拆分按速度乘字节推算，与 trace 的总耗时相符） |
| 清单检查改查表 | 实测（照抄循环的小程序，非 engine 本身）：查重加查上级一遍，5,754 个条目 1.5 秒，22,347 个条目 30.4 秒 |
| 工作工具与 seccomp 名单三个 runtime 共用 | 实验设计：三个 agent 的比较要在同一组工具与同一份名单下做 |
| 锁与 inotify 归隐蔽信道，不考虑；显式交流通道不留 | 用户 2026-11-01："本文可以不考虑这些用信号合流的 channel，但是不能留显式的交流通道" |
| 套接字族过滤：AF_UNIX、AF_INET、AF_INET6 与 NETLINK_ROUTE | vsock 可能不受 network namespace 约束，属显式通道；7.4 推导的宿主 strace 里三个 agent 只用到 AF_UNIX、AF_INET、AF_INET6、AF_NETLINK 四族，AF_VSOCK 只出现在经 WSL interop 调 Windows 程序的路径上；整族放开 netlink 时隔间能读到宿主的设备事件（本机实测），所以 netlink 只放 NETLINK_ROUTE（用户 2026-11-01） |
