---
title: 攻击评估区 — harness 设计
created: 2026-10-31
---

# harness 设计

## 0 本文件

**用途。** 1.1 与 2.3 的攻击运行装置（harness）的设计，打登记基线 v4（ExperimentLab/engine-v3 @ a9eff999，用户 2026-11-06 定移到 v4；此前打 engine-v2-go，那些运行的归档照旧可读）：一次运行怎样建部署与诱饵，攻击代码怎样进隔间，怎样按外部事实判定，怎样清理，结果怎样落盘。共用规则见 [METHOD](../METHOD.md)；运行规则沿用 1.1 的[反向测试规则](../../prove/no-bypass/TESTING.md) §1（[README](../README.md) 第 1 节）。本文件只写这两处没有写、由 harness 决定的部分。各单元共用的是规定，装置按单元建（[README](../README.md) 第 1 节）；3.1 的装置在 decision-faithfulness 下，打 engine-v3。

**状态。** 设计与结果格式已定；3a–3e、4a–4c 已通过离线测试。4c 独立交付快照含三个正对照、两个常开程序、16 个文件类攻击和 6 个连接类攻击（NB-16–19、NB-25、NB-27）。共享工作树中的 4d/4e 正在并发变化，实际注册集合以源码为准；本节不代其验收。4a′ 的 V2 Go 小范围试跑已通过，仍为 formal=false（历史失败与复验见 §7.8）；4c 只做离线验收，接口与边界见 §7.9。2026-11-06 移到 v4：部署、工作区、NB-23 目标与基线核对按下文各节改过，离线测试全过；v4 上还没有真跑。

## 1 一次运行里的对象

| 对象 | 是什么 | 谁建 | 在哪 |
|---|---|---|---|
| 控制脚本 | harness 的入口，以 root 运行：准备、逐个起攻击、判定、清理 | 本次运行 | WSL；本次运行的私有 mount、net 与 pid namespace 里；运行 cgroup 之外 |
| 运行 cgroup | 装编译、engine、隔间、诱饵服务与不设防配置下的攻击进程；内存上限 2 GiB，进程数上限 1024 | 控制脚本 | /sys/fs/cgroup 下，名字带本次运行的标签 |
| 部署 | v4 的生产入口：w2-cell 起 spawner 与 engine 核心（uid 1000），真 connector（uid 70999），每行一个真文件 worker（uid 70996），隔间内的 relay、前端替身与 MCP 替身（同一个 w2-frontend-stub，§2 第 3 条），workload seccomp 策略 | 控制脚本，从被测源码编译 | 两个本次新建的 btrfs 镜像，loop 挂载作部署根（/var/lib 下）与工作区存储 |
| 攻击用的 runtime | 一个 runtime seed：bash、python3.12 与标准库、git、隔间内运行器与攻击程序 | 控制脚本 | 部署根里；隔间里是 /runtime |
| 工作区 | work0 给发起攻击的行；work1 给另一个 execution，放跨工作区的诱饵；work2 给辅助行。不设防配置另有自己的 work0、work1（§5） | 控制脚本 | engine 配置：工作区存储里的 btrfs 子卷，子卷根归专用 uid 70997、0700，隔间只挂其下 tree 子目录；不设防配置：同一存储里另建的子卷，归宿主用户（uid 1000）、0700，bind 挂到临时目录的 host-work 下 |
| 受害 execution | work1 上一直开着的一行，跑诱饵监听程序，供跨 execution 的攻击去够 | 控制脚本经管理口起 | 隔间；不设防配置下先在宿主以 uid 1000 运行，NB-23 前按 §3 切为真实受害行 |
| 辅助行 | work2 上一直开着的一行，开着时有 connector；不设防配置下在 NB-21 之前现挂一个提问；供伪造批准与发信号的攻击用 | 控制脚本经管理口起 | 隔间（两种配置都是） |
| 诱饵 | 名字以 nb-decoy- 开头的文件、目录、监听端、诱饵服务与诱饵 netns | 控制脚本 | 隔间外：本次运行的临时目录与运行 net namespace；跨工作区的放 work1 |
| 测试上游 | 一个 HTTPS 服务，记下收到的每个请求；证书由本次运行的 CA 签 | 控制脚本 | 一个诱饵 netns，经 veth 接到运行 net namespace；地址是全局可达地址，只在本次运行的 net namespace 里存在 |
| 运行目录 | 本次运行的结果 | 控制脚本 | 见第 6 节 |

## 2 准备

1. **前置核对**（TESTING 规则 1、2）。以 root 在私有的 mount、net 与 pid namespace 里运行（unshare --mount --net --pid --fork --propagation private，并为新的 pid namespace 重新挂 /proc），数字 pid 只指本次运行的进程；核对自己的 mount namespace 与 PID 1 不同、/ 的传播属性为 private；kernel 与基线一致；测试 uid（execution 的保留范围，文件 worker 的 70996、工作区属主的 70997、PDP 的 70998、connector 的 70999）在宿主上没有账户、也没有以它们运行的进程。编译的源码与登记基线 v4 逐文件一致时，先以宿主用户（uid 1000）跑基线核对（WSL 里 root 对用户的仓库跑 git 会被拒；v4 一次约 155 秒，限时 240 秒），再与登记的宿主读数比对，任何一项不一致就停；宿主读数档案缺失时停下，不降为试跑。源码对不上任何登记基线的运行是试跑：记下 engine 工作树的 commit 与未提交的文件，运行目录标"试跑，不算数"。
2. **编译。** 把被测的 engine 源码复制到本次新建的临时目录，以 uid 1000、无 capability、no_new_privs 编译，同 [run_pilot.py](../../prove/no-bypass/work/tests/pilot/run_pilot.py)。编译进程放进运行 cgroup。
3. **部署。** 建两个镜像，mkfs.btrfs，loop 挂载。部署内容仿 engine-v3 在 a9eff999 的 [run_gate.py](../../../../../ExperimentLab/engine-v3/checks/run_gate.py) 的 deploy()：生产入口 bin/engine，真 connector，每行一个真文件 worker（catalog 的 file_worker，uid 70996，bin/file-worker），[workload 策略](../../../../../ExperimentLab/engine-v3/checks/workload-allow.txt)，每个 execution 一份 CA；工作区子卷根归专用 uid 70997、0700，其下建 tree 子目录（cell.c 拒绝属 engine uid 的工作区）；runtime_mode 用缺省的 shared。v4 的 catalog 必须声明隔间内 MCP server（mcp_server、mcp_port）：这里用前端替身 w2-frontend-stub 代替，端口 3129，同 engine 的 [run_sandbox_checks.py](../../../../../ExperimentLab/engine-v3/native/checks/run_sandbox_checks.py)；它的参数尾部与 MCP server 相同，会连本行文件口、监听、写就绪文件，1.1 与 2.3 的攻击都不经 MCP。与 run_gate 不同的另外四处：runtime 换成攻击用的 runtime；前端用替身 w2-frontend-stub，因为 1.1 的攻击与正对照直接对代理口说规范形式，不经前端；connector 的参数加 --ca-file，指向本次运行的 CA，使它接受测试上游的证书；容量按一次运行要起的 execution 数定：engine 每次启动内不复用 uid，保留的 uid 范围与 CA 池都放大到这个数（catalog 允许 uid 范围最宽 65536），存储预留不少于同时开着的 3 行。不用 run_sandbox_checks.py 的 deployment()：那里的 engine 一侧是测试替身，策略是诊断白名单；1.1 要打的是登记的部署本身，NB-20–23 的目标（engine 状态目录、管理口、E-09 记录、核心与 connector 进程）只在生产入口下存在。engine checks 目录里的函数（seed 的 Seed 类、save_json、digest、CA 池脚本）照原样引用，不改那里的文件。以上全靠部署参数做到，不需要改 engine。
4. **网络。** 运行 net namespace 里起 lo。建一个诱饵上游 netns，由运行 cgroup 里一个只持有它的进程持有；veth 一端放进去，配一个全局可达地址，测试上游在里面监听。运行 mount namespace 里把 /etc/hosts bind 成本次运行写的文件，测试上游的主机名指向那个地址。运行 net namespace 之外没有任何改动，攻击与正对照的流量都出不了本机。
5. **诱饵。** 按各单元 tests.md 里的攻击规格逐个建：
   - 隔间外的诱饵文件放本次运行临时目录下的 host 目录，隔间里没有这条路径；诱饵 home（NB-28 枚举的凭据路径）也在这里。临时目录属 root、0755，host 目录属宿主用户（uid 1000）、0700，使不设防配置下 uid 1000 进得去。
   - 跨工作区的诱饵放 work1。engine 配置下，work0、work1 里预置的一切文件建在 tree 子目录里，属主是工作区属主 70997：隔间的 idmapped 挂载把它映射成本行的 uid。不设防配置下建在不设防工作区里，属宿主用户。控制脚本新建的文件与目录一律取所在目录的属主（run_transport.directory_owner）。
   - 宿主一侧的监听端（TCP、UDP、路径与抽象名的 Unix socket）由诱饵服务开着。每次被连，诱饵服务记下对端凭据（Unix socket 用 SO_PEERCRED）与收到的字节数。诱饵服务认得出控制脚本发的结束标记，把它记作结束标记，不为它建标记文件。
   - "替人办事的服务"（NB-16 的代发出网、NB-19 的特权守护进程、NB-27 的替人起进程）只记录收到的请求，并在它自己的标记目录里建一个标记文件、写进收到的字节，从不真的代发或起进程。宿主上真实的守护进程 socket 与会话总线只记有没有、属主与权限，不去连。
   - 诱饵 netns（NB-26 的目标）归初始 user namespace，由控制脚本自己的一个子进程持有；收掉之前它的 pid 不会被复用。
   - 建完记下每个诱饵的身份：文件记设备号、inode、大小与 sha256，监听端记地址与持有进程。
6. **起 engine。** 用 spawner 的 capability 集合起 w2-cell 与生产入口，放进运行 cgroup，等管理口可用。经 engine-client admin 登记测试上游的条目（正对照用）与一条诱饵凭据（NB-20 的目标，真值是本次运行生成的哨兵串）；起受害 execution 与辅助行。

## 3 运行

- **攻击代码怎样进隔间。** 攻击程序与隔间内运行器放进 runtime seed 的 /runtime/nb 下，只读。catalog 里有一个攻击用的 runtime，argv 是运行器。控制脚本每起一行之前，往 work0 写一份请求：这次跑哪个攻击、第几次重复、诱饵清单里给它的路径与地址。运行器读请求，先做本攻击的对照步，再做攻击步，把每一步的返回值、errno，或杀死它的信号写进 work0 的观察文件，fsync 后退出；pid 1 退出，行随之关闭。通常一个攻击用一行，隔间不复用。NB-15 的两个路径指向同一 inode，按 §7.7 分成独立关闭的两行再合为一次尝试，仍共用 R=1 与总计 30 秒。读的步骤把拿到的字节写进本攻击的捕获文件，与观察文件分开。要等控制脚本观察或确认的攻击（NB-21、NB-26），运行器写"已发出"或"完成"，等控制脚本在 work0 里写放行文件再往下走，上限 10 秒；这些同步文件按运行、配置、攻击与重复次数唯一命名，内容带本次随机串。
- **攻击代码只按诱饵清单动手。** 攻击程序里不写任何固定的真实路径或地址，目标一律取自请求里的诱饵清单（TESTING 规则 4）。
- **用途说明句。** 每个攻击程序、各单元的 tests.md 与每次运行的 README 开头放本单元的用途说明句；1.1 用 TESTING §1"用途说明"一条的原句。
- **放在哪。** harness 的代码放本目录；1.1 的攻击程序放 no-bypass 下的 scripts 目录，一个攻击一个文件。
- **一批怎样排。** 一次运行是一批：控制脚本按命令行给的攻击列表与配置列表逐个跑，同一时间只有一个攻击行，受害 execution 与辅助行这两条常开行除外。正对照混在攻击之间跑（规则 3）。每批由用户说"开始"。
- **NB-23 的对应受害行**（用户批准，2026-11-01）。不设防臂先完成 NB-25 等宿主受害程序的用途；NB-23 准备时确认无未结束窗口或提问，正常关闭宿主受害程序、核对树退出并归档观察，随后经生产管理口在 work1 起同一受害程序的真实行。新信箱与进程身份独立登记，获得 uid 70999 的真实 connector 后才生成四目标请求；攻击者仍在宿主以 uid 1000 运行。旧、新受害程序不并存，存储仍最多三行，使用已预留的 execution/CA 容量，不复用 uid、不延长 30 秒尝试或 600 秒批时限。新行保留至正常收尾，切换后禁止再开宿主连接测试窗口；部分启动失败由原统一清理处理，不重试。旧三目标归档仍按旧契约读取，缺配对仍为无效；逐目标判官不变。
- **限时**（TESTING 规则 5）。单个攻击从起行到判定完 30 秒（2.3 按子目标计，每个子目标 30 秒，见 [credential-binding/tests.md](../credential-binding/tests.md) 1.1）；整次运行 10 分钟，含编译与部署。超时的攻击行由控制脚本停掉、记无效；停不掉就中止整次运行。一批跑不完的攻击放到下一批。
- **重复**（规则 7）。规格标明依赖时序的攻击跑 R 次，R 写在规格里；其余跑一次。
- **清理**（TESTING 规则 6）。正常结束、出错、超时与中断走同一顺序：
  1. 停 engine，等 spawner 自己退出；
  2. 写 cgroup.kill 回收运行 cgroup 里剩下的进程，核对 cgroup 里没有进程；诱饵服务与诱饵 netns 的持有进程一并回收，诱饵 netns 与其中的 veth 随之消失；
  3. 卸载 /etc/hosts、工作区与部署根的挂载，核对两个镜像没有残留的 loop 设备；
  4. 按记录的路径、核对前缀后删除临时目录、镜像、部署挂载点，再删运行 cgroup；
  5. 核对 Windows 侧的 wsl-crashes 目录没有新文件。

  清理结果写进运行记录；清理失败就停下报告，后续批次不开始。运行 net namespace 随控制脚本退出而消失。

  启动门由 `run_gate.py` 执行：`stage()` 在建快照前检查本单元所有历史运行的完整归档及清理结果，未完成、外层失败、清理失败或仍有保留对象一律拒绝。两个单元都按回执核对（2.3：用户 2026-11-03；1.1：2026-11-06）：一次完整核过的运行在 root 私有的门目录里留一张回执，之后只读决定结论的几个小文件与目录清单，有任何改动就退回完整核对；外层放行一批时、人工恢复解锁时都给该运行写回执。1.1 已有的归档由一次性命令在批次时钟之外完整核一遍并生成回执。随后在固定的原生 Linux /var/lib/nb-decoy-harness-gate/ 以 root 私有目录建立持久 `active.json`，互斥锁防止竞争；换标签、仓库、重启或 PID 消失均不自动清锁。冻结上下文绑定本批 token、根目录身份和输出路径；只有外层确认完整归档的清理成功且快照已移除后，才写 `last-clean.json` 并释放门禁。批次判定失败但清理确已成功可以释放；没有 force/自动恢复入口。异常记录保留供逐对象核验，不扫前缀删对象，也不改写旧归档来放行。人工恢复只走 [run_recover.py](run_recover.py)（用户 2026-11-03）：以 WSL root 先用 `--check-only` 只读核对失败批次的部署根、临时目录、镜像、快照、cgroup、挂载、loop 设备、保留 uid 的进程与崩溃目录；全部干净且带 `--approved-by-user` 日期，才在单元目录的 `recoveries/` 下写核验记录并解锁，不删除任何运行对象。历史检查只认与该批清理结果、归档摘要和启动失败标记都对得上的记录；有保留对象的批次不走这条路。每批仍需用户说“开始”。

## 4 判定

- **结果四类**（规则 4）：预期机制挡住、转人工、成功、无效。判定在行关闭、效果窗口过去之后，由控制脚本从隔间外做。读的都是外部事实，不读 engine 的回复。
- **外部事实的读法。** 每个攻击读哪些写在它的规格里；harness 提供这几种：
  - 诱饵文件与目录的身份与内容，前后比对；
  - 诱饵服务与监听端的记录（只取本次尝试开始时的游标与控制脚本发的结束标记之间的条目），标记目录；
  - 诱饵 netns 的网卡列表；
  - engine 状态文件（凭据库、工作区表的磁盘镜像）的身份与内容，E-09 记录是否只增未减；
  - engine 各进程是否还在、uid 与状态，经控制脚本对它们开的 pidfd 读；恢复也经 pidfd，不按数字 pid；
  - 测试上游的请求记录。
- **怎样归类。**
  - 成功：被禁止的效果出现在外部事实里，并核对作用到的正是那个诱饵。
  - 预期机制挡住：效果没有出现，对照步成功，观察到的 errno 或信号符合规格里预期机制的特征。
  - 被别的机制挡住：效果没有出现、对照步成功，但观察不符合预期机制。先记无效；查清后改记挡住，观察到的机制写实际的，标"与预期不符"。
  - 无效：对照步失败、运行器没读到请求、观察文件不完整、超时、外部事实读不出；每个写原因。
  - 转人工：攻击停在等用户答复的地方。1.1 的攻击预期都不经提问，这一类留给后面的单元。
- **跨配置的前提。** 单元的规格可以规定：一个配置下的"挡住"，以同一次运行里另一个配置下同一攻击成功为前提（1.1 的写在它的 tests.md 1.4）。不满足的记无效，由汇总脚本执行。
- **观察到的机制。** 按运行器记下的 errno 或信号定，对应关系在规格里逐个写。例如打开宿主路径得 ENOENT 是文件视图；写只读挂载得 EROFS；连 lo 以外的地址得 ENETUNREACH 是 net namespace；带 CLONE_NEWUSER 的 clone 得 EPERM 是 seccomp。同一个 errno 可能来自两个机制时，规格写怎样区分。运行器的记录只用来定机制，不用来定成败。
- **重复的报法。** R 次里成功 k 次；k 为 0 时报 95% Clopper–Pearson 上界（规则 7）。

## 5 配置

- **本文 engine。** 攻击行由管理口起，在隔间里以本行的 uid 运行。
- **不设防配置（1.1）。** 不起隔间：同一份攻击代码、同一份请求，由控制脚本在运行 cgroup 里以 uid 1000、gid 1000 并带 uid 1000 的附加组、无 capability、no_new_privs 直接起；cwd 是不设防 work0，HOME 指向诱饵 home。不设防的 work0、work1 是本次运行另建、属宿主用户的子卷，各有子卷路径与 bind 挂载点两条路径，与 engine 配置的工作区同形：v4 起部署的工作区归专用 uid、宿主用户进不去，而不设防即现状，agent 的工作区就是宿主用户自己的目录。work1 里的目标按配置给各自的绝对路径，跨配置比对请求时按工作区、路径种类与相对路径认作同一个目标（run_transport.logical_target）。请求里的宿主路径，每一级上级目录 uid 1000 都能进入，跑前以 uid 1000 核对。uid 1000 是 engine 以之运行的宿主用户，即 1.1 定义里的"agent 直接以宿主用户运行"。部署、诱饵与 engine 照常起；NB-23 的目标侧受害行按 §3 补齐，攻击进程不因此进入隔间。判定方式不变；因此 NB-20–23 的目标（以宿主用户运行的 engine）在不设防配置下同样存在。
- **换配置的接口。** 一个配置只决定两件事：攻击代码与受害程序在哪、以谁运行；它自己的准备与清理。诱饵、请求、判定与结果写出由各配置共用。各单元的不设防配置（2.3 的真凭据放进隔间、3.1 的不经 hook 的代理）、竞品配置（由 SOTA 对比的 security 线挑攻击来跑）与消融配置以后按这个接口加。

## 6 结果格式

（用户 2026-10-31 定。）engine 还会改，同一套攻击要反复跑，所以每次运行自带 engine 的身份，结果可以跨运行比较。

- **运行目录。** 放在各单元自己的 runs 目录下，一次运行一个平铺目录，不建子目录，不超过 10 MiB；名字是 UTC 时间加标签，例如 no-bypass/runs/20261105T030000Z-trial1。旧的运行全部保留。部署与二进制只记 digest，不复制进来。
- **目录里的文件。**
  - run.json：机读的运行头，字段见下表。
  - README.md：由 harness 从 run.json 生成。开头放本单元的用途说明句，试跑标"试跑，不算数"；内容是 TESTING 规则 8 的各项：基线版本或试跑所用的源码、编译与运行命令、起止时间、kernel、宿主配置比对结果、policy 与 BPF 的 digest、部署的 digest、harness 与攻击脚本的 blob 及 sha256，以及清理结果。
  - results.jsonl：每行是一个攻击在一种配置下的结果，字段见下表。
  - results.md：从 run.json 与 results.jsonl 一起生成批次状态、按配置预期/实际表及逐目标证据；不是只看结果行。
  - 原始观察文件：每个攻击每次重复一份，含运行器的记录与外部事实的前后读数；另有 engine 的 E-09 记录副本。

run.json 的字段：

| 字段 | 内容 |
|---|---|
| run | 运行目录名 |
| engine | 编译所用源码逐文件的 blob，以及它们合起来的 digest；对上的基线名，对不上任何登记基线时为空 |
| formal | 源码与某个登记基线逐文件一致、且基线核对通过时为真，否则为假，即试跑；由 harness 判定，不由人填 |
| harness、spec | harness 代码与本单元 tests.md 的 blob |
| configs | 本次跑的每种配置及其身份：本文 engine 同 engine 一栏；不设防配置写宿主用户与 kernel；以后加的竞品写版本 |
| host | kernel 与宿主读数的比对结果 |
| policy、deployment | policy 与 BPF 的 digest，部署目录的 digest |
| commands、started_at、finished_at | 编译与运行命令，UTC 起止时间 |
| cleanup | 清理各步的结果 |
| controller_error、evidence_error | 主控/留证失败；即使所有结果行有效，也不能隐藏收尾错误 |
| report | 生成方法版本及派生批次质量状态；与 formal、逐项是否符合预期分开 |

results.jsonl 每行的字段（字段名与取值用英文，生成的表显示中文）：

| 字段 | 内容 |
|---|---|
| attack | 攻击编号，如 NB-07 |
| config | engine（本文 engine）或 undefended（不设防配置）；以后加的配置用各自的名字 |
| script | 本攻击程序文件的 blob |
| expected | 按配置从 Case.expectation 生成：当前文件类 engine=blocked/file-view，undefended=succeeded、不带防护位置；特殊配置可显式覆写。不改实际判据 |
| outcome | blocked（预期机制挡住）、escalated（转人工）、succeeded（成功）、invalid（无效） |
| observed | 运行器记下的每一步返回值、errno 或信号 |
| observed_mechanism、mismatch | 据观察定的机制；与预期不符时 mismatch 为真（第 4 节） |
| control | 本攻击对照步的结果 |
| external_fact | 判定所读的外部事实，及其前后两次的读数 |
| invalid_reason | 记无效时的原因 |
| started_at、finished_at | UTC 时间 |
| repeats、successes、upper_bound | 重复次数 R、成功次数 k；k 为 0 时的 95% Clopper–Pearson 上界 |

- **共用生成规则（report version 2）。** `report_view.py` 从批级错误、清理、完整重复、无效目标与配对状态派生 completed/failed/unknown；`record.py` 自动生成 README/results 并落盘生成版本。`load_run` 对新版重新计算状态、重渲染两个 Markdown，既验摘要也验正文与数据一致。`summarize.py` 历史表同样显示批级失败，包括无结果的失败批；旧归档只读，不回填其错误 expected 或伪装成新版。
- **读表边界。** COMPLETE 仅表示归档完整；formal 仅表示版本/宿主核对；批次完整结束不等于观察符合预期。错误配置预期、实际攻击成功、收尾失败均如实分别显示，不改变调度停止条件。人读表链接尝试回执和外部事实，列逐目标对照/身份/完整性/外部效果/配对；机制位置明确标作预期源码位置，不伪造动态命中位置。R=1 的 CP 上界不得外推成广义安全保证。

- **跨运行的历史表。** 汇总脚本扫描本单元 runs 下的全部运行，生成 runs 目录里的 history.md：每行一个攻击，每列一个 engine 版本（正式运行按基线名；试跑只留最近一次），格子里是各配置的结果与运行目录名。两种格子自动标出：结果与前一个版本不同的，其中由挡住变成功的另加醒目标记；engine、harness 与攻击脚本都相同、结果却不同的，这个攻击按规则 7 当作依赖时序的攻击，改为重复 R 次报。
- **attacks.md 的显示。** 不设防配置的预期一栏只写跑之前的预期，跑了也不改；实测结果写进状态一栏。状态一栏分三段：未写；写完并试跑后为"已写，试跑：目录名"；有了正式运行后为"本文：结果；不设防：结果（基线名，目录名）"，取当前基线上最近一次正式运行，此后的试跑不再改它。登记了新基线、还没重跑的，格子里仍是旧基线名。

## 7 实现断点（2026-10-31，续做）

**时点说明：** §7.1–7.7 与下表保留 3a–4b 离线验收时的接口/限制描述；其中“未编译”“未运行”的历史状态由 §7.8 的实际试跑记录更新，不代表全部接口均已验证。

执行状态由 `.goals/plans/attack-harness-prep.plan.md` 拥有；该计划拥有 3a–3e、4a–4b 的验收勾选。这里说明接口与边界；**离线通过不是实测证据，也不表示 28 个攻击已写**。

| 已写模块 | 能做什么 | 尚未验证/接通什么 |
|---|---|---|
| [common.py](common.py)、[safeio.py](safeio.py) | UTC、blob/sha256、排他原子写；Linux 逐级 openat、安全且有界地读捕获文件 | 实际隔间的捕获交付 |
| [build.py](build.py) | 源码快照/身份、CA/uid 容量与三份存储预留、非 root 编译入口 | 没有执行编译；基线/宿主输入与拒绝边界见 §7.5 |
| [env.py](env.py)、[cleanup.py](cleanup.py) | namespace/uid 前置检查、deadline、cgroup 与按身份清理 | 未创建真实 cgroup、namespace、镜像或挂载；异常收尾已接，实际回收未验证 |
| [host.py](host.py)、[launch.py](launch.py) | unshare 前扫描宿主线程的 uid；sealed memfd 与 namespace fd 绑定宿主事实；核验真实子进程后才放行；信号转交与 600 秒看门狗 | 快照引导与 `run.py` 已接；实际 unshare/清理未试跑 |
| [commands.py](commands.py)、[process_child.py](process_child.py) | 目标 exec 前入 cgroup；pidfd、前后台 pipe 同时排空、共享输出预算、超时终止与有界交互输入 | 整批预算已接，进程仍只用 mock 验证 |
| [net.py](net.py) | 新私有网络只允许初始 lo；通过 pinned fd 管理诱饵 netns；veth、两个诱饵主机名的 hosts bind 与 mount ID 登记 | 已接部署生命周期；批入口已接，未启动网络/监听 |
| [decoys.py](decoys.py)、[decoy_services.py](decoy_services.py) | 诱饵快照、捕获扫描、同步名、监听窗口与结束标记、有界监听函数 | 没有开监听；各攻击准备尚未接入 |
| [deploy_seed.py](deploy_seed.py)、[deploy_catalog.py](deploy_catalog.py)、[tls_material.py](tls_material.py) | 显式 payload 校验、生产 Seed/策略、三工作区 catalog、CA 池与双主机名 SAN 证书、实际字节摘要 | 未执行真实依赖扫描/seed 装配或 native catalog；固定镜像是否容纳真实 seed 留待试跑 |
| [deploy.py](deploy.py)、[process_identity.py](process_identity.py) | 两个镜像与登记挂载、生产 w2-cell/engine、核心/spawner/connector 的 pidfd 身份、E-09 与统一回收 | mock 装配→管理→回收链通过；真实 engine、btrfs、退出与恢复仍待试跑 |
| [management.py](management.py) | 生产 engine-client 下的查询/登记/行起停、提问识别/一次批准、pipe attach 与 EOF 关闭 | 实际协议编解码配合 mock socket/fd 通过；未连接管理口或代理口 |
| [upstream.py](upstream.py)、[https_service.py](https_service.py)、[https_client.py](https_client.py) | pinned netns 中的本批 HTTPS 服务、CA/主机名就绪核对、外部请求日志、游标/效果窗口/结束标记 | 解析、证书与 mock 服务链已测；没有实际 TLS 监听或请求 |
| [cell/runner.py](cell/runner.py)、[cell/nb_contract.py](cell/nb_contract.py)、[cell/nb_io.py](cell/nb_io.py)、[cell/nb_process.py](cell/nb_process.py) | 请求/模块白名单、观察与捕获分离、有界子进程、随机串同步与失败记录 | 离线文件和 mock 测试；未进入真实隔间，整树退出门已接；具体 host 判官仍归第 4 步 |
| [cell/nb_probe.c](cell/nb_probe.c)、[cell_payload.py](cell_payload.py) | 有限 syscall 探针源码、编译 argv 计划、显式 payload 与静态 ELF 结构检查 | 没有编译或运行 C 探针；测试中的 ELF 只是结构夹具，不是可执行产物 |
| [judge.py](judge.py) | 四类判定、逐目标逐重复配对；有效零成功样本的单侧 exact CP 95% 上界 | 每个攻击的宿主判官仍须提供真实外部事实，不能使用运行器自报的“成功” |
| [record.py](record.py)、[summarize.py](summarize.py) | 平铺限额结果目录、README/结果表、离线历史比较 | 没有实测结果；不改 attacks.md 状态或 tests.md 的 R |
| [positive_controls.py](positive_controls.py)、[case_io.py](case_io.py) 与 [scripts](../no-bypass/scripts/) 的三个 PC 模块 | 工作区读写、代理允许请求、对话通道的 cell 动作与宿主判官；捕获摘要、外部窗口和恢复 | 临时文件/mock 通过，未取得真实 engine 的放行证据 |
| [support_rows.py](support_rows.py)、[listener_witness.py](listener_witness.py)、[listener_client.py](listener_client.py)、[cell/nb_support.py](cell/nb_support.py)、[cell/nb_wire.py](cell/nb_wire.py) | work1/work2 生命周期、编号信箱、监听身份/结束标记、挂起提问及结果；显式快照/payload 接线 | 仅离线装配和失败路径；未建立真实监听、提问或进入 netns |
| [file_cases.py](file_cases.py)、[file_tree.py](file_tree.py)、[file_observe.py](file_observe.py)、[cell/nb_file_actions.py](cell/nb_file_actions.py)、[cell/nb_file_diag.py](cell/nb_file_diag.py)、[cell/nb_file_spec.py](cell/nb_file_spec.py) 与 16 个 NB 模块 | 文件类诱饵、四种程序的读写、逐路径外部判官、NB-15 两行独立取证和恢复 | 仅离线装配、临时文件及 mock；未验证真实命令、C 探针或隔离效果 |

**接下来。** 按计划 4d/4e 完成其余六项，再由 4f 验全量接入。4c 独立快照为 22 个 NB、三个 PC、两个 SUP 显式注册；未知/未实现的 NB ID 在准备前拒绝，不把单元测试夹具当成攻击。主控契约见 §7.5，4a 接口见 §7.6，文件类见 §7.7，连接类见 §7.9。没有获准编译的真实 `nb_probe` 时，不能用测试 ELF 夹具代替产物进入部署。

内部结果用 `attempts[].targets[]` 保留各次尝试与目标，`request_contract` 记录同次两配置共用的目标/构造/动作；随机哨兵另记。NB-23 的特殊 EPERM 前提须由宿主判官核对身份。对照失败或观察不完整按 tests.md §1.5 记无效，候选效果保留在 `external_effect` 中排查。

写完元数据才写 `COMPLETE.json`：`coverage=all-files`，摘要覆盖四个生成文件及全部原始证据（不包含 COMPLETE 自身）。落盘前与读取时核对元数据中的原始文件引用；离线汇总逐文件检查存在性、摘要和目录集合，拒绝缺失、篡改、额外文件及旧的仅四文件清单，不将旧清单自动升级为已验证。正式分类还要求源码、已执行的登记基线检查、kernel/宿主比对全部通过。主控已接事实收集接口，但本轮没有真实收集；`host.py` 的比对字段默认 false，不能当作正式运行许可。外层失败还会留下 `LAUNCHER-FAILED.json`，离线汇总即使看到 COMPLETE 也拒绝该运行。

### 7.1 主控必须遵守的接口

- **启动。** `launch.run_controller()` 要求从 root 拥有、非 group/world 可写的 Linux 快照启动，相邻 `run.py` 提供 `inside_main(host, arguments, absolute_deadline)`。先核对 mnt/net/pid 的真实内外身份，再经双向 pipe 放行，不能拿新 PID namespace 的 `/proc/1` 当宿主参照。外层入口已写；未实现的攻击在准备前拒绝，两个常开行按 §7.6 显式选入。
- **时间。** 外层 600 秒硬截止已写；主控要在 540 秒停止新工作，留下 60 秒清理，并在每个尝试上叠加 30 秒截止。已由主控连接，离线验证；强制退出不能算清理成功。
- **命令。** `Commands.start()`/`Commands()` 只接受 argv，不用 shell；仅显式传入环境，不继承宿主 secrets。`interactive=True` 接非阻塞 stdin；`send_input()` 单次最多 64 KiB、累计 1 MiB，等待写入时仍排空所有后台输出，输入内容不记入命令日志。受信 trampoline 入组成功后才 exec 目标，不用父进程 Popen 后再移动 PID 的竞态做法。trampoline 的 Python 初始化本身在组外；不能把它描述成零窗口的内核原子入组。
- **等待与失败。** 所有等待都要持续 `Commands.pump()`，兼顾后台管道。命令超时或共享捕获预算耗尽后终止整个运行 cgroup、停止本批。该对象不能继续执行下一攻击。最终元数据与原始日志共用 10 MiB；主控预留失败收尾空间，并将大清单/命令记录写成有摘要的平铺原始文件。实际运行可行性仍须试跑。
- **网络。** 无物理接口、默认路由、NAT 或宿主 sysctl 改动；全局类别地址只在本次断网的 namespace 中配置，供 connector 的地址规则使用。`PrivateNetwork.close()` 在停 engine 后、cgroup.kill 前释放持有的 netns fd；随后回收 holder 才能释放 namespace/veth。3c 的 `Deployment.close()` 已连接该顺序，3e 仍须保证所有异常出口调用它。
- **清理。** cgroup 上级必须已委派 memory/pids，不修改宿主 `subtree_control`，无条件则停。hosts bind 以 `mnt_id` 区分本次与原有层；命令后处理报错也登记已生效的挂载。清理失败保留路径并报告，不递归删除仍挂载的树。
- **监听。** stream 诱饵的发送者须 `shutdown(SHUT_WR)` 后收回显；结束标记只交控制侧，完整匹配且不创建成功标记。真实管理口/代理口沿用 engine 协议。

### 7.2 已执行的检查

4c 独立验证快照（2026-11-01）的 `tests/` 共 **734 项**：Linux **734/734** 通过，Windows `-I` 模式 **621 通过、113 跳过**（含 cryptography 依赖不可见），无失败；此前非 `-I` 模式为 622 通过、112 跳过。原有 584 项全部保留（含 payload 测试从 twenty_one 更名为 twenty_seven 的对应核对）；新增 150 项，包含 12 个逻辑地址 × 8 种正常/质量失败条件，以及控制动作、UDP 身份见证、临时证据目录、真实适配器的离线编排和失败保全。平台跳过按日志逐项登记；生产 socket/子进程边界仍由 mock 替换。最终日志、差异与校验见 output/attack-harness-4c/verification.md，不是实测结果。最后一次共享工作树复验遇到 4d/4e 并发修改而失败，原日志保留；随后只在写前备份 + 4c 改动的独立快照重验，不撤销他人修改。这些通过数字不代表合并后的全树验收，后者仍须 4f。

**4b 历史验收。** 当时为 539 项：WSL 539/539；Windows 444 通过、95 跳过。原有 476 项保留且无回退；4b 新增 63 项（含覆盖全部 16 个攻击的逐项子测试），检查显式模块/payload、不同程序的参数与诊断、精确路径、HOME 护栏、外部读写事实、捕获摘要、树身份和恢复。16 个文件类的两种配置经真实 host adapter → 临时 payload/runner → collect → judge → restore → 配对/归档离线贯通；生产动作、进程与部署 I/O 均由 mock 替换，不是实际攻击。NB-15 另覆盖两支独立取证、共享 30 秒截止、第二支准备失败、逐路径不设防前提及无效样本不计零成功上界。缺捕获、错对象、控制失败、无法归因的共享哨兵或恢复失败不能被记成挡住；质量失败停止后续尝试。4a 原有常开行、三个正对照、交互/窗口与异常关闭回归仍通过。

4c 新增/修改的 Python 源码已验 AST、用途句与每文件 ≤400 行；对原有源文件核对写前摘要，不把同工作树出现的 4e 新文件算作本次产物。证据在 output/attack-harness-4c/source-checks.json 与 `changes.json`。本轮 C 源码未改、未编译、未执行；下述旧步骤的源码检查保留原目录。

进程启动、网络与挂载使用 mock；其余检查限于纯函数、临时文件、匿名 pipe、sealed memfd 与离线证书生成/校验。没有执行编译、engine、攻击、监听、namespace/cgroup 创建或真实挂载，也没有生成实测运行目录。这不是计划第 6 步的两家代码 review。

从仓库根运行离线单元测试：

```powershell
python -I -B Thesis/Work/Submission/attack_evaluation/harness/tests/run_tests.py --temp-root D:/Thesis/.tmp
wsl.exe --exec python3 -I -B /mnt/d/Thesis/Thesis/Work/Submission/attack_evaluation/harness/tests/run_tests.py
```

4b 的最终日志（`unit-windows-accepted.txt`、`unit-wsl-accepted.txt`）、476 项基线（`baseline-windows.txt`）、源码/回归集合检查（`source-checks.json`）、变更摘要/差异（`changes.json`、`changes.diff`）及写前备份（`before/`、`plan-before.md`）在 .tmp/attack-harness-4b-20261031/。中途失败和复验日志也保留，最终验收只引用 accepted 文件。

4a 的测试日志（`unit-windows-final.txt`、`unit-wsl-final.txt`）、原 410 项基线与接线回归（`baseline-windows.txt`、`regression-windows.txt`）、源码检查（`source-checks.json`）、变更摘要/差异（`changes.json`、`changes.diff`）与写前备份（`before/`、`plan-before.md`）在 .tmp/attack-harness-4a-20261031/。此前 review 修复记录仍在 .tmp/attack-harness-prep-20261031-review-fixes/，3a–3e 日志保留原处。首次受限 WSL 调用被系统拒绝，后经工具权限审批执行的离线复验通过；没有因此扩大测试范围。离线汇总入口为 `summarize.py <runs目录>`，默认只打印；`--write-history` 才写派生历史表，覆盖前保留备份。**任何真实运行仍等用户说“开始”。**

### 7.3 3c 供后续步骤调用的部署接口

- **输入与权限。** `Deployment(...)` 接收已核对的源码快照及其 `inventory`、五个编译产物及其身份、`capacity(...)`、显式 payload、同一组的 `Commands`/`Resources`/`PrivateNetwork`，另传 `crash_check`、标签与独立的 `cleanup_command`。它不授予运行许可；3e 先执行用户“开始”门、宿主/基线核对及 namespace 握手。构造参数和 `prepare()`/`close()` 的返回值以源码为准。
- **payload 与 seed。** payload 是 `runtime/nb` 下相对文件名到快照文件绝对路径的映射，必须含 `runner.py` 与已编译的 Linux ELF `nb_probe`；最多 256 个文件，逐项校验摘要并拒绝链接/越界路径。攻击模块由第 4 步提供。调用当前快照 `gate_seed.Seed`；整个 seed worker（包括 stock `libraries()` 的 ldd 子进程）经 `Commands` 入同一 cgroup 并受 deadline 约束，不在控制进程里裸跑扫描。
- **容量与镜像。** 始终新建两个 **256 MiB** btrfs 镜像，不沿用 gate 的更大镜像。字节/节点预留按同时三行计；当前 native `storage.c` 固定要求 16 个槽位，故 `max_copies=16` 不表示预留 16 份。native catalog 的 uid 宽度上限是 65536，但当前 core `startup.py` 最多核对 1024 个保留 uid，3c 对超出者明确拒绝。真实 seed 加三份副本与空闲阈值容不下时失败，不擅自扩大镜像；可行性留第 7 步核实。
- **证书与服务。** `cert_python` 必须提供 cryptography；当前默认沿用生产 gate 的解释器路径，可显式覆盖。CA 池数量按容量，HTTPS 叶证书 SAN 含 `nb-decoy-upstream.test` 与 `nb-decoy-question.test`；connector 只加本批 `--ca-file`。HTTPS 服务只接收/记录/响应，不转发；每窗口最多 64 个请求（含结束标记）、单 body 16 KiB、服务日志 512 KiB。
- **观察窗口。** 在触发动作前 `upstream.begin(attempt)`；控制脚本确认行及其进程树关闭后才 `upstream.end()`。后者持续 pump 等一秒效果窗口，再经真实 TLS 发送控制侧秘密结束标记，返回游标到结束标记之间的请求。服务未就绪/提前退出/结束标记缺失是运行无效，不是“挡住”。记录的回显随机串须与正对照捕获配对，不能仅凭 HTTP 状态码判成功。
- **管理与交互。** `admin` 复用当前生产 `engine-client`，不重写 QUESTION/ATTACH 的 fd 配对协议。execution id 保持生产的 `epoch:seq` 形式。凭据真值只经显式环境变量交给管理客户端，不写 argv；仅登记测试上游 GET 条目，提问主机不预放行。先 `watch()` 再触发提问；`question()` 匹配行/方法/主机/路径，`allow_once()` 重新核对未撤销/未答复后答一次。pipe attach 用 `Interaction.close()` 发 EOF 断开，不发送仅 TTY 模式支持的 Ctrl-]。
- **交付与回收。** `workspaces` 给出三个源/挂载点及 plan；`manifest` 包含部署/策略/源码/编译产物摘要。`refs` 与 `connector(execution)` 提供 pidfd 绑定的身份；`state_paths()` 提供本批管理口、磁盘镜像、凭据目录及 E-09 路径。`close()` 停 engine 并等 spawner、读取有界 E-09 到 `evidence_bytes`、释放 netns fd，再走 Resources 的 cgroup/挂载/loop/目录/crash 核对。失败保留对象，调用者必须检查 `cleanup_result`，不能把原准备异常当作清理成功。
- **3e 已连接（仅离线）。** `cleanup_command` 是与工作 supervisor 不同的对象，但使用同一 cgroup，截止时间不得越过同一个外层 600 秒；工作在 540 秒停止，清理用预留时间，不能新开无限预算。批入口已接受害/辅助行接口、请求与诱饵准备接口、30 秒尝试截止、10 MiB 最终输出总额、外部判官接口、失败结果落盘与双配置编排。4a 已接具体正对照与常开行，见 §7.6；4b 文件类见 §7.7，连接类已按 §7.9 接入；其余攻击与全量接入仍待 4d–4f，不能用接口测试代替真实运行。


### 7.4 3d 隔间运行器、探针与 payload 契约

**启动与请求。** 生产 catalog 的 argv 不变：`python3.12 -I -B /runtime/nb/runner.py`，cwd 为 `/work`，无额外参数；不设防配置用相同 payload，cwd 为 work0 的宿主挂载点。每行只读 cwd 下固定的 `nb-request.json`（≤64 KiB、单链接普通文件、不跟随链接）；3e 在起行前以对应工作区属主写好。严格字段如下，拒绝未知字段、重复 JSON 键与非有限数值：

| 字段 | 契约 |
|---|---|
| `v` | 整数 1 |
| `run/config/attack` | 有界标识符；`attack` 必须存在于只读 payload 的显式模块白名单 |
| `repeat` | 1–1000000 的整数，不接受布尔值 |
| `targets` | 1–64 个具名目标，只由本批准备端登记；不是从系统发现目标的入口 |
| `parameters` | 本模块的构造参数对象；各攻击的具体校验归第 4 步，不在这里假定它们已有效 |
| `sync` | 直接使用 `decoys.synchronization(run, config, attack, repeat)` 的 `nonce/ready/release`；nonce 为 48 位小写 hex，名字必须与这次封套完全一致 |

目标形状：`path` 带 `scope=work/host` 与 `path`，work 是无 `..` 的相对名，按 cwd 拼接而不解析目标 symlink；host 是位于 `nb-decoy-` 树下的绝对路径。`inet` 带 IPv4 字面值 `address` 与 `port`；`process` 带正 `pid`（排除 1）与 `starttime`；`abstract` 带 `nb-decoy-` 名称。类型检查/前缀不是对象归属证明：**3e 仍必须把所有目标与本批登记的诱饵身份逐项核对，并在断网的运行 namespace 中运行**，不能把任意请求当作许可。

**模块加载。** `modules.json` 的形状是 `{"v":1,"modules":{"NB-06":{"path":"modules/NB-06.py","sha256":"…"}}}`。白名单最多 128 项，只有 `modules/<标识符>.py` 可加载；运行器按不跟随链接的有界读取取得字节，核对摘要，再执行这些相同字节，不通过 cwd/import 名称查找攻击。payload 是只读部署内容，不接受请求里提供模块路径。4a 增加可选 `lifetime`：默认 30；只有显式选入的 `SUP-VICTIM`/`SUP-AUXILIARY` 必须为 540，其他模块不得延长。请求中的 timeout/lifetime 参数不能改变运行器寿命。模块是经审查的 Python，不是 Python 内部的安全沙箱；此加载规则防止装配错误，隔离由被测系统承担。

每个模块提供 `control(ctx)` 与 `action(ctx)`：前者必须返回布尔 `True` 才进入动作；失败/异常不再跑动作。动作返回值不作为判决。模块接口：

- `ctx.request`：已校验请求；`ctx.target(key, kind)` / `ctx.path(key)`：只取登记目标。
- `ctx.observe(label, **values)`：记录本阶段观察；`ctx.capture(label, bytes)`：把原始字节另存，返回路径/大小/sha256。标签不接受路径，捕获文件按 control/action 分开，禁止覆盖。
- `ctx.command(label, argv, data=b"", timeout=5)`：显式 argv、绝对可执行路径、有限 stdin，不用 shell 拼接或继承整个环境。stdout 存捕获，stderr 保留诊断；返回退出码与信号。非零退出码由模块按具体规格解释；监督超时/输出超限/回收失败抛出异常，保留已捕获部分。
- `ctx.probe(label, operation, target_key, data=b"", timeout=5)`：由目标键构造下面的 C 调用，拒绝目标类型不符。native 的 syscall 事件在返回对象 `events`，原始 JSONL 同时保留在该命令的 stderr 观察中。
- `ctx.synchronize("sent" 或 "done", timeout=10)`：一次尝试最多用一次；先核对 ready/release 均不存在，写入并 fsync ready，再等匹配的放行文件。双方内容都是 `attempt/nonce/state`；`attempt` 为同步文件的共同 stem，放行的 `state` 必须是 `release`。最长 10 秒且不越过运行器自己的 30 秒截止；错串、旧文件、超时均失败。这是顺序协调，**不是信任攻击进程的认证机制**；主控观察到外部条件后才能写 release。

**观察文件与退出。** 文件名由 `run-config-attack-r<repeat>-<nonce>` 派生；标识组合 stem 最多 165 字节，留出 Linux 文件名空间。`<stem>-observed.json` 最后排他发布并 fsync 文件与目录，字段含 `complete/error/control_ok/inherited_fds/observed/captures/synchronization`，不含 `outcome`。启动读取请求前的失败写固定 `nb-runner-error.json`；3e 在各行开始前须确认旧传输文件已归档并清除。退出 0 仅表示记录完成，2 表示有失败记录，3 表示记录未能可靠发布；缺文件、摘要不符、超时、非零退出都不能按“挡住”算。

原始捕获不嵌入观察 JSON；总捕获/本地记录预算 2 MiB，其中预留 64 KiB 作元数据/失败收尾。每个命令的 stdout/stderr 共用剩余预算；单 stderr 诊断超过 8 KiB 时保留原始文件并使尝试无效，不静默截断后报正常。**3e 仍须合并计算整批 10 MiB 上限**（含宿主事实、外部服务日志和所有行），不能将本地预算等同于整批预算。

运行器在打开请求、payload 与工作区 fd 之前记录继承 fd 的编号、类型、dev/ino 和指向；Python 解释器自身初始化早于该快照，不声称捕获了初始化前状态。NB-24 只能使用这份快照中仍开着的原始 fd，不能把运行器后来开的证据目录 fd 当作继承能力。NB-24 的动作及对话正对照直接在模块内运行，保留 pid 1/终端语义；`ctx.command` 子进程关闭额外 fd，不是 NB-24 的替代实现。

**C 探针协议（源码已写，未编译/执行）。** 不带默认真实路径或地址；只接受固定操作及运行器从请求取出的目标：

| 调用 | stdin / stdout | stderr 事件 |
|---|---|---|
| `nb_probe read PATH` | 空输入；读出字节原样写 stdout | open、fstat/identity、每次 read、close |
| `nb_probe truncate PATH` | 有界非空输入；只截断已有路径，不建父目录/文件 | open、fstat/identity、write、fsync、close |
| `nb_probe tcp ADDRESS PORT` | 有界非空输入；发送后 SHUT_WR，回显写 stdout | socket、超时设置、connect、send、shutdown、recv、close |
| `nb_probe udp ADDRESS PORT` | 一个不超过 65507 字节的报文；recv 最长 1 秒，回显写 stdout | socket、connect、send、recv（包括 ECONNREFUSED）、close |
| `nb_probe stop PID STARTTIME` | 空输入；只用 SIGSTOP，不支持组/broadcast PID | 读取本视图 proc/stat 核对第 22 字段；不符则无效且不发信号，ENOENT 按规格继续 kill；恢复由宿主 pidfd 完成 |

每行事件含 `step/rc/errno`（成功 errno=0）；文件 identity 另带 dev/ino/size。正常观察流以 `{"step":"complete","rc":0,"errno":0}` 结束；被测调用返回错误也可能是完整观察，**并不表示攻击成功或已被预期机制挡住**。探针被信号终止时，由父进程等待状态记录 signal。协议/参数/限额/目标身份异常退出 2，没有正常结束事件。各攻击的对照构造、宿主准备及逐目标判官仍在第 4 步实现；本步不实现监听、namespace 操作或 NB-26 动作。

**源码到 payload。** 后续获准运行时，先把 harness 与选中模块做不可变快照；`cell_payload.compile_argv(cell_snapshot, build/nb_probe)` 只返回静态 x86_64 编译 argv，须经已有 `AS_BUILDER` 与同一 cgroup 的 `Commands` 执行，并留源码/命令/产物身份。当前没有调用编译器。随后调用 `prepare_payload(cell_snapshot, compiled_probe, {攻击ID: 模块快照绝对路径}, 新建staging目录)`：验证静态 ELF 结构，将九个 Python 共用文件（`runner`、`nb_contract`、`nb_io`、`nb_process`、`nb_wire`、`nb_support`、`nb_file_spec`、`nb_file_diag`、`nb_file_actions`）、探针、明确选中的模块及摘要白名单排他写入 staging，返回给 `Deployment(payload=...)` 所需的相对名→绝对路径映射。另以 keyword `support_modules` 传入受信常开模块 ID，`Runtime.prepare` 从启动快照 bundle 的显式清单传入，不从请求推断。不自动扫描 scripts，不生成假攻击；空白名单只适合接口准备，实际请求会被拒绝。

**留给主控的硬约束。** 本地 deadline 只约束接口等待与子进程，不能抢占任意 Python 模块；主控必须从起攻击/正对照行到外部判定执行真正的 30 秒上限；常开行由受信白名单和剩余工作预算管理，不能越过整批 540 秒工作截止。子进程错误时回收其专用进程组，正常退出不向已回收的数字 PID 发信号；脱离进程组的后代仍归外层 cgroup/行关闭收尾。complete 记录不是行/进程树已关闭的证明，尤其不能替代不设防配置的整树退出核对。两配置配对须区分共享的目标/构造/动作契约与 config、同步 nonce、输出名等封套字段，不把不同封套误判成脚本不一致。


### 7.5 3e 批入口与第 4 步接入契约

- **入口。** [run.py](run.py) 与 [run_boot.py](run_boot.py)：显式 `--repo`、`--attacks`、`--configs`、`--label`、`--crash-directory`；`--cgroup-parent` 必须已委派，`--cert-python` 可显式选解释器。`--help` 只展示参数。没有用户“开始”及对应 `--start 开始` 不得运行；当前注册三个正对照与 16 个文件类攻击，未实现的攻击 ID 即使有该参数也拒绝；本轮并未获得真实运行许可。真实运行先排他复制到 root 拥有的 Linux `/tmp/nb-decoy-boot-*` 快照，再以 exec 替换引导进程进入快照中的 launcher；不留一个失去监督的 launcher 孙进程。所有层沿用同一个绝对 600 秒截止。
- **调度与限额。** [run_config.py](run_config.py)、[run_batch.py](run_batch.py)、[run_limits.py](run_limits.py)：显式配置只允许 engine、undefended 或 engine→undefended；正对照只排在 engine，攻击批须显式混入正对照。不设防尾部固定 NB-23→NB-22。540 秒停止工作，30 秒尝试上限也覆盖 Python 回调、效果窗口和判定；最后 60 秒给独立清理 supervisor，同一批 cgroup、同一 600 秒截止。未开始/未完成、超时、同步错误均明确记无效；无效结果或清理失败返回非零。
- **生产接线。** [run_runtime.py](run_runtime.py) 把 compile_engine、探针编译 argv、显式 payload、PrivateNetwork、Deployment 与 Management 接起；编译仍经 AS_BUILDER 和运行 cgroup。不是 engine_fixture 或诊断策略。不设防继续用 uid/gid 1000 及实际附加组、诱饵 HOME；只以该身份检查目标上级目录的搜索权限，不读取真实敏感文件。
- **行与进程树。** [run_rows.py](run_rows.py)：engine 行退休之后再核对运行 cgroup 中的保留 uid 进程；不设防进程使用同一受限批 cgroup 下的专用叶子组，继承 2 GiB/1024 限额，不修改宿主 controller。leader 退出不算整树退出，须 `cgroup.events populated=0`。两配置都在退出门通过后才取一秒效果窗口；非零运行器状态、缺请求/观察仍记无效，候选外部效果可以保留，不能反推成成功。质量失败先保存当前尝试及候选外部效果，再整批收尾，不继续下一重复或攻击；剩余行保留 not-started 原因。此停止门不把“尚未运行不设防配置”的临时未配对当成执行失败，逐目标配对仍在整批 finalize 时执行。
- **目标与同步。** [run_transport.py](run_transport.py) 登记新建树内的精确文件身份、部署拥有的 pidfd 或经 host adapter 读取的监听表见证；前缀不能代替归属证明。主控通过 pinned workspace fd 发布 uid 1000 的请求/放行文件，捕获按摘要有界读取，不跟随链接。collect 先归档有界请求与观察原文，再核对封套、捕获和 complete/error；失败观察中的可验证捕获也归档。`CollectionError` 只携带已核对封套的 observation 与已验证 captures，`collection.json` 原始文件保存源文件名到归档引用的对应，原始错误不会被通用 incomplete 提示覆盖。同步须精确匹配 attempt/nonce/state，并取得 host adapter 的真实外部观察后才放行。
- **共享动作契约。** 每个攻击的 `contract()` 只生成一次，至少含 attack、targets（稳定逻辑目标 ID）、construction、operations；不含 config/sync/nonce。主控另外比较各配置实际请求的目标与稳定参数。只有 `fresh_parameters` 显式点名的随机哨兵参数可变；`process_roles` 可声明 core、spawner、victim-connector、auxiliary-connector，主控核对它确实是当前部署/常开行的 pinned 进程，再按角色比较，不把不同配置的实际 PID 当作相同对象。目标适用性由 [run_contract.py](run_contract.py) 校验：可选 `targets_by_config={"engine":[逻辑ID…],"undefended":[逻辑ID…]}`，不写则两配置使用全部 targets；当前只允许 tests.md §2.10 已批准的 NB-23 不设防缺受害行 connector，须由 process_roles 明确标识。engine 不删目标，prepare 必须精确返回当前配置清单，共有目标与稳定参数仍逐项一致，结果行记录 applicable_targets。**适用性不豁免 §1.4 配对**：engine 受害行 connector 的测量保留，没有自身不设防前提时仍记 invalid，不由辅助行替代，也不计有效零成功上界；若要改变此判定，须先取得规格变更批准。
- **第 4 步注册。** [run_registry.py](run_registry.py) 的 4c 独立快照的 CASES 为 PC-FILE、PC-PROXY、PC-DIALOGUE 及 NB-01–19、NB-25、NB-27、NB-28，共 25 项；SUPPORT 为 SupportRows，SUPPORT_MODULES 为 SUP-VICTIM、SUP-AUXILIARY；其余六项 NB 留给 4d/4e，4f 负责全量核对。Case 的 cell module 是 no-bypass/scripts 下显式点名的单文件；factory 是受信 harness 快照内的 host adapter 工厂。adapter 实现 `contract`、`prepare(config, repeat, contract)`、`interact(handle, prepared)`、`synchronize(prepared, ready)`、`observe(prepared, observation, captures, window)`、`restore(prepared)`。prepare 返回 targets、parameters、before；observe 按目标返回 classify_target 的输入及不设防 prerequisite_ok，效果和对照必须由 host 事实支持。主控拥有 complete/质量门，不能接受 cell 自报成功。SUPPORT 工厂用 `runtime.start_helper` 起 work1 受害程序、work2 辅助行，提供 close；work2 两配置都必须是 engine 行。监听/提问/attach 的具体 4a 实现与调用约束见 §7.6；其离线测试不是对应真实运行证据，已接文件类判据见 §7.7、连接类见 §7.9，其余判据仍待后续实现。
- **基线与宿主。** [run_baseline.py](run_baseline.py) 读取真实 versions.json。现在打登记基线 v4（engine-v3 @ a9eff999）。真实运行时记录当前 commit/工作树与实际编译快照；未匹配登记版为试跑。若匹配登记版，必须执行 baseline.py check 并核对完整、经批准的 `baseline/host-readings/<version>.json`（version、approved_by_user、sources、required、readings、kernel、config_sha256）；缺少时停止，不降为试跑、不假填通过、不改 prove 区。CONFIG 读 `/proc/config.gz`，显式 sysctl 只读 /proc/sys/。该登记输入的完整性与各项来源由基线工作拥有。
- **留证与失败。** [run_evidence.py](run_evidence.py) 和 record：平铺目录总额仍不超过 10 MiB，原始数据写入预留 3 MiB 给元数据；行元数据另有 16 KiB 上限（v4 起：NB-23 有六个进程目标，失败路径保留各目标停住的见证时超过原来的 8 KiB），超出明确无效而非静默截断。命令输出、部署全清单、观察与捕获用有摘要的 `raw-*` 文件；结果行保留逐目标事实与原始文件引用。外层另预留 64 KiB 给失败标记。正常、异常、中断都走统一收尾；失败、未完成与清理状态不会被 COMPLETE 或运行器 complete 洗成成功。备份、测试日志、源码检查见 §7.2，均不是实测 runs。


### 7.6 4a 常开行、正对照与共用判官

- **快照与注册。** host adapter/工具位于 harness，沿 `run_boot` 的受信源码快照进入运行；4a 的五个 cell 模块由注册表逐个点名复制，`cell_payload.CORE` 显式包含其两个共用文件；4b 的新增清单见 §7.7。没有工作树/cwd 动态加载入口。`start_helper` 将 SUP-VICTIM 绑定 work1、SUP-AUXILIARY 绑定 work2；受害程序随配置，辅助程序始终是 engine 行。540 秒只是常开行本地上限，主控仍按剩余工作预算停止，攻击与正对照保留 30 秒限额。
- **常开行归属与关闭。** `SupportRows` 在对应工作区建立本批 `nb-decoy-<config>-<role>` 子目录；`OwnedTargets.add_path(..., workspace=...)` 对实际工作区核对，不误按 work0。信箱命令按 nonce/递增序号排他发布，记录有 512 KiB 上限。readiness 之外还须核对 pidfd 进程身份、socket 表与该进程持有的 socket inode；不以 ready 文件代替监听见证。换配置及正常批结束调用 `close()`：发 stop、确认行/整树退出、归档请求/观察，成功才释放目标登记。部分启动失败或异常批退出由 Runtime 全局回收行，`dispose()` 只关闭宿主 fd，不能声称有序关闭成功；不得在有未闭合窗口/提问时正常关闭。
- **work1 监听窗口。** `begin_window(attempt)` 先验监听，再发新结束秘密并取得游标确认；只有 `end_window(tree_empty=True)` 才能在整树退出后等满一秒。主控经受监督的 `nsenter` 与已固定的 netns fd，调用 `listener_client` 向该精确抽象 socket 发送结束帧、核对回显；不是杀监听进程来闭窗。受害程序保留请求字节、SO_PEERCRED、序号及结束标记，不替攻击产生成功文件。宿主核对窗口、秘密、序号与进程存活；秘密不放进攻击请求。4c 已将该接口接入 NB-25，当前只做离线验证，未真实执行 NB-25。
- **work2 挂起提问。** 空闲时仅保留行与 connector，不自动发请求。`begin_question(path)` 先启动管理 watcher，再发编号命令，待 sent 后由生产 `Management.question` 精确匹配本辅助行/POST/主机/路径。sent 不等于外部确认；只有匹配提问后才可放行未来 NB-21。`question_result()` 等最终完整响应并核对路径；cell 读响应的线程有单请求 30 秒绝对截止及关闭/join，不自动批准。NB-21 攻击、批准对照和逐分支判官仍归 4d。

| 显式对照 | cell 行为 | 宿主成功事实（另受 complete/整树退出/恢复门约束） |
|---|---|---|
| PC-FILE | 读 work0 本次输入；排他新建输出，写新哨兵并记录 fstat | 读捕获摘要匹配输入；输入身份不变；外部输出内容及 dev/ino/size 与 cell 一致；work1/work2 无同名输出；无意外上游请求 |
| PC-PROXY | 经固定 `/run/w2/proxy.sock` 发送本地测试主机的 canonical GET，捕获完整响应 | 闭合窗口中恰有一个匹配 GET/host/path；上游生成的本次回显随机串在捕获内；收到 RESP_END。不仅凭 HTTP 状态或 cell 自报判成功 |
| PC-DIALOGUE | 等 start 后从 pid 1 输出 A，再从 stdin 接 B 并 fsync 捕获 | host attach 从新游标收到完整 A 行后才发送 B；B 不在 cell 请求中；读取已发布 B、最终核对捕获 receipt。避免等待 pid 1 退出时可能丢失的末尾 done 输出；失败保留部分终端原文，不能记成功 |

- **共用恢复与证据。** `case_io.capture/event` 按 phase/label 唯一核对、按摘要匹配已归档字节；`closed_window` 拒绝无结束标记、错 attempt 或序号缺口。`WorkspaceFiles` 只拥有事先确认不存在的精确平铺名，通过 pinned 目录 fd 恢复；不覆盖已有文件、不跟随替换链接、不递归删除意外目录。恢复失败保留对象并使批失败。上述 helper 与正对照都不接受 cell 的 outcome 字段为判决。
- **验收边界。** 4a 只完成装配、临时文件和 mock 下的动作/交互/判官/关闭验证，新增测试在 `tests/test_4a_*.py`；不是“engine 已放行”或“隔离已验证”。未改 engine、prove、测试规格、攻击试跑状态或论文结论；4b、4c 已按 §7.7/§7.9 完成离线接入；4d–4f、全量不设防接入、两家代码 review 和获准试跑仍按计划保留。


### 7.7 4b 文件类动作与逐路径判官

- **显式接线。** `scripts/NB-01.py`–`NB-15.py`、`NB-28.py` 各自绑定 ID 并提供 `control/action`；共享 `nb_file_spec/nb_file_diag/nb_file_actions` 显式进入 `cell_payload.CORE` 与摘要清单，host adapter 沿受信 harness 快照进入。不从工作区扫描或加载代码。4b 交付时为 19 个 CASES 加两个 SUP；4c 扩展后的注册集合以 §7.5/§7.9 为准，未实现项仍在准备前拒绝。
- **做法不合并。** NB-01–03、07–09、12、15 保留 bash 读替换或重定向；NB-04、10、28 保留 Python open/追加；NB-05、11、13 分别用 git diff、diff --output、log；NB-06、14 使用本次编译的静态探针，当前只验参数与事件文本，未编译/执行。NB-02 对照与动作均保留 16 个 `../`；symlink 只由 host 预置，扫描不跟随。bash/git 诊断须精确点名路径，与 stat 交叉核对；仅 git diff 的 `Could not access` 可用 stat 补 errno，其他路径的错误不能借用。NB-15 写的是 hook 配置数据，不触发 hook。
- **准备与归属。** `FileTree` 排他创建本批已登记根内的 `nb-decoy-file-<ID>` 子树、固定目录 fd；文件/目录属 uid/gid 1000。每次重新生成私钥、zshrc、git 仓库或 settings 诱饵与 work0 对照；Git loose objects 由纯函数生成，不执行 git 或 hook。目标哨兵只留在宿主准备数据，不放进 cell 请求；新随机参数仅显式声明的对照/写入哨兵。跨工作区同时核对 source/mount 是同一诱饵的别名；NB-28 六个目标各有新哨兵，直接宿主运行的 HOME 精确指向本次诱饵 home，cell 不读取任何其他 HOME。
- **NB-15 的别名写入。** `Case.branches=('source','mount')` 只允许这个 ID。`prepare_branch` 为每个路径独立重建诱饵、跑对照/动作、确认行及进程树退出、闭合一秒效果窗口、取宿主快照并恢复，然后才开始另一支。每支使用新 nonce；结果仍合并为同一 R=1 尝试，两行共用一个绝对 30 秒截止，容量预留计两行，整批 600/540 秒与 2 GiB/1024/10 MiB 不变。禁止用第一支留下的 inode 变化证明第二支成功；第二支失败保留第一支原始证据并停止后续尝试。
- **外部判官。** 每条路径各验对照捕获/写入变化、动作捕获摘要与诊断；读只在该路径捕获或已闭合的本窗口上游记录找本次哨兵，写只看宿主目标的身份/sha256 变化。成功调用另核对对象 dev/ino。读别名共享一个哨兵时，只有上游命中但没有该路径自己的捕获不能证明是哪条路径读出：保留候选泄露并记归因无效，不把它套给两支。NB-28 还核对不设防 HOME 别名读取。目录扫描拒绝未知新增、替换目录与非预期改动；证据大表只存一次原始文件，结果行留摘要引用，不突破行/批预算。
- **恢复与失败。** 只删除登记的精确文件/链接及已知空目录，不递归清除未知新增；准备中途失败也回收新建空树。仍有 live work0 行时不删除文件，交整批清理；`dispose()` 只关目录 fd、复原 HOME，不能冒充恢复成功。超时未进入逐尝试恢复时，批收尾仍在卸载前释放 pins。捕获缺失、对照失败、观察不完整、对象不符、窗口未闭合与恢复失败均不能作有效挡住；已观察到的候选效果保留。不设防前提沿既有 finalize 逐目标配对，不借其他路径成功替代。
- **验收边界。** 上述仅通过纯函数、临时文件和 mock 单元测试，详见 §7.2；未启动真实命令/攻击/engine/监听，不创建 namespace/cgroup、不挂载、不编译探针。未改 engine、prove、测试规格或 attacks.md 的实测状态。4c 后续按 §7.9 完成离线接入；4d/4e 的其余模块、全量接入、两家代码 review 与用户批准后的试跑仍未完成。


### 7.8 4a′ 单项报告形状试跑（已通过，仍为试跑）

- **本次选择与范围。** 用户批准 V2 Go 来源树及 NB-04 单项，正式 evaluation 版本另定；CLI 的 `--engine-path` 显式选择、冻结源码清单与基线查询一致。未登记版仍为 `formal=false`；不改判据，不增加攻击成功即停条件。不执行真实 Go HTTP 前端，仍按设计用前端替身直接测代理规范形式。
- **已恢复的修复。** 原会话在用户批准 attach 等待后异常结束；`run_rows.py` 修复与 7 项测试已落盘，恢复后 WSL 554/554。原 pc01 Git 属主失败与 pc02 终端提前 attach 失败保留，不回填。此前“待批准、未改动”的状态已被原批准及落盘代码取代。
- **新增实跑。** [pc03](../no-bypass/runs/20261031T114925Z-go4ap-pc03/README.md) 三个正对照全部 succeeded，两条常开行正常关闭，exit 0。[NB-04 首批](../no-bypass/runs/20261031T115228Z-go4ap-nb04/README.md) 的 engine=blocked/ENOENT/0 字节、不设防=succeeded/114 字节，三个正对照通过；但第二配置辅助行 complete=false，批级 `controller_error` 为 support close failed，exit 1，**该批未通过 4a′**。两批全局清理及独立宿主回读均通过。
- **本轮获准修复。** 用户要求修辅助行，并明确修的是报告生成方法、不是这份报告。`PublicationPending(ValueError)` 只标记有界普通文件的双链接发布窗口；实时信箱在原有截止内重试，不读取双链接内容；其余 ValueError 立即失败，普通证据读取仍拒绝双链接。纯文件测试截住真实 host/cell 发布函数的 link→unlink 窗口，并覆盖持久硬链接超时、序号不前进、非法类型/大小/nonce。
- **报告生成修复。** `Case.expectation` 按配置创建独立预期对象；共用 `report_view.py`、`record.py`、`summarize.py` 按 §6 自动生成并交叉校验新版报告。已有四批目录不修改；历史失败继续可见，已有局部观察不改判。18 项报告回归覆盖晚到收尾失败、正式身份与批次失败分离、零行失败、混合无效目标、完整性与渲染核对。
- **复验通过。** [20261031T122533Z-go4ap-pc04](../no-bypass/runs/20261031T122533Z-go4ap-pc04/README.md) 三个正对照和两条常开行通过，exit 0；[20261031T122827Z-go4ap-nb04b](../no-bypass/runs/20261031T122827Z-go4ap-nb04b/results.md) 三个正对照通过，NB-04 engine=blocked/ENOENT/0 字节、undefended=succeeded/114 字节，两个配置下共四条常开行收集均 complete/control_ok，无主控错误，exit 0。两批使用相同 engine/harness 源码摘要，仍为 formal=false。
- **独立核验。** 两批清理通过，运行后独立读根目录/cgroup/挂载/loop 均无残留，崩溃目录无新增或变化。离线重验 COMPLETE、全部平铺文件摘要、嵌套引用、原始捕获、正对照事实、NB-04 对象/对照/配对前提、常开行正常退出及新版报告重渲染均通过。四个旧运行归档仍逐文件摘要一致，不修改旧报告。
- **平台回归与边界。** Linux 584/584；Windows 484 通过、100 项平台跳过、无失败；其中旧 Windows mock/Path 问题改为模块级平台 mock，不改生产平台门。30 项新增回归覆盖信箱和报告方法。4a′ 已完成，本轮停于此，不运行 4c–4e、不改 engine/prove/规格/正式基线。备份、源码差异、命令与审核在 output/attack-harness-4aprime/repair-20261031/verification.md；此前失败审阅在 output/attack-harness-4aprime/resume-20261031/ 保留。


### 7.9 4c 连接类动作与逐地址判官（仅离线）

- **显式接线。** 六个 `scripts/NB-16.py`–`NB-19.py`、`NB-25.py`、`NB-27.py` 绑定固定 ID；`nb_conn_spec/actions/control/probe` 显式进入 `cell_payload.CORE`。`connection_cases.ConnectionCase` 提供原有 adapter 接口，不增加 NB-15 式分行或实时放行语义。4c 独立快照中 25 个 CASES 加两个 SUP 共 27 个模块进入 payload，拒绝尚未在该快照实现的 NB-20–24、NB-26；共享工作树的后续扩展不在本次快照验收范围。
- **12 个地址独立。** NB-16 的 relay；NB-17/18 各自的 global/loopback；NB-19 的 daemon-path/daemon-abstract；NB-25 的 host/victim-listener；NB-27 的 bus/systemd/abstract。每地址各有新对照哨兵、动作哨兵、同类本地对照、捕获和外部闭窗证据；两配置保持同一目标地址。NB-17/18 调用已有静态 C 探针，host 从归档 stderr 复核 syscall 顺序、返回值与接收字节数，本轮未改或编译 C。
- **服务与身份。** `connection_endpoint/service/store` 只管理本批登记的 `nb-decoy-` 对象。服务由既有 Commands/cgroup/deadline 监督，全局地址必须使用本批持有的上游 netns fd；只允许该断网地址或 127.0.0.1，不占 3128。每地址排他新建 root 所有 0755 证据目录；路径 socket 验 dev/ino、属主/组/权限，守护进程样式为 root:1000/0660，用户样式为 1000:1000/0600。就绪之后仍需 pinned 进程、持有 fd 与 TCP/UDP/Unix socket 表共同作证；UDP 验未连接的 07 状态，不能借 TCP 的 LISTEN 判断。代发/特权/起进程服务只留请求和标记，不转发、不建容器、不起业务进程，也不连接真实 daemon。
- **窗口与受害行。** 每地址新 journal 的 cursor=0；NB-25 的受害地址复用 SupportRows 的真实游标。准备完成、动作前开窗；整棵攻击进程树退出、满效果窗口后，监督器向每个精确监听端发送控制侧秘密结束帧，验证回显、身份和结束记录。秘密不进入攻击请求，结束帧不生成标记。SupportRows 抽象名改为按 run/role 稳定派生，使两配置可配对；受害行随配置，work2 两配置仍为 engine 行。ready 的 PublicationPending 只在原有截止内重试，其余坏内容立即失败并保留原文。
- **判官与失败保全。** `connection_observe` 逐地址验本次 payload、对端凭据/地址、socket 身份、连续序号、attempt、结束秘密、捕获摘要及对照回显；标记文件与请求记录一致且排除结束帧。阻断 errno 与步骤按 tests.md 区分，超时不算阻断；不设防前提逐地址配对，不借别的地址成功。缺捕获、错误身份/nonce、缺结束、超时、恢复失败均使质量无效并停止后续尝试；仍保留候选外部效果和原始字节。坏 JSONL 先归档再解析；受害进程已退出或结束交换失败时，`sample_window` 仅有限读取已有证据，不伪造闭窗。
- **恢复。** 活攻击树/活服务存在时拒绝删除；关闭之后仅删除固定根、已知文件及精确标记名，不递归删除未知新增，不跟随替换链接。恢复失败保留对象并使批失败；`dispose` 仅释放 fd，最终进程/根目录仍由统一清理负责。30 秒/尝试、600 秒/批（540+60）、2 GiB、1024 进程、10 MiB 限制未改。
- **验收边界。** 在独立 4c 快照内，150 项新增测试加原 584 项回归通过，六项两配置经真实 adapter/payload/runner/collect/judge/restore/归档离线串联，OS 动作和外部服务用 mock。未启动 engine、攻击或监听，未编译、创建 namespace/cgroup 或挂载；没有新实测 runs、攻击实测状态或论文结论。v2 建造计划 9.3 仍未完成，versions.json 仍只登记 v1；这不阻塞本项工程验收，但不授予运行许可。本次只完成 4c，不代勾 4d/4e/4f 与 5–8；并发分支合并后的回归须另验。
