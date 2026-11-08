---
title: 02 — 主干（不变量的落地、初态；分支表在后半）
date: 2026-10-25
step: 第一块 主干·上（PLAN §1.1）；主干·下在本文件后半
owner: 执行者（Claude Code 会话）
baseline: 基线 v1（engine aa3f2803，kernel linux-msft-wsl-6.6.87.2）
baseline_check: 2026-10-25 开工时 `python baseline.py check v1` → OK（engine 82 个 blob 逐个一致；kernel 116/116；工作树等于基线）；2026-10-26 审核一修改时取回 5 个 kernel 文件后再跑 → OK（kernel 121/121）
inputs: 01-model-inventory v15、01-rows-syscalls v7、01-trace-events v4（v6 时是 v13、v7、v4，v5 时是 v12、v7、v4，v4 时是 v11、v7、v4，v3 时是 v10、v6、v3，v2 时是 v9、v5、v2；blob 见 VERSIONS）；PLAN、SPEC、TESTING、METHOD 用第一块开工时登记的 blob
status: version 12，2026-10-29；R0d 第二次定向复核的修改（审核一已收口）。版本历史：v1 是前半（主干·上），v2 加后半（主干·下：L 与 ABI 入口、第 4 步的四列、子操作表、分支表、不适用项、列的不适用规则）；v3（审核一的修改）：§1.2 统一转换粒度、补失败与部分完成；§1.3 区分对本 execution 的构造与为另一个 execution 的构造，NB-K-03…10 的分支改归 LC；§2 写明初态指构造发出的 execve，§2.1 地址空间一项收窄，§2.3 每步写出四件事、构造窗口拆成两项（其他主体的作用一项记未定，交 PS、LC），§2.5 补四个可信方；§3.2 新增 NB-N-13；§3.3 拆出 PR_SET_MM_MAP、PR_SET_MEMORY_MERGE，CSIGNAL 改成每次创建的共同部分，getsockopt/OTHER 列出 47 个取值；§3.4 共 303 个分支；§3.5 共 97 个不适用项；§3.6 13 条列规则；v4（定向复核的修改，2026-10-26）：§2.1 继承属性一项补四项；§2.5 engine 一行分开写三处接收、w2-recover 一行把前提标为前提、宿主清理与备份与宿主观测组件各拆成两项并依赖新前提 NB-AA-08、supervisor 与 core dump 处理程序两项补 NB-AA-08；§2.6 加 NB-AA-08；§3.2 NB-N-13 按角色定义；§3.4 加 FUTEX_LOCK_PI × N-06（304 个分支）；§3.6 N-12、N-13 的理由；初态 59 项（1 项未定）；v5（第二次定向复核的修改，2026-10-26）：§2.5 去掉两个"运行期不取用"项与 supervisor、core dump 两项里的 NB-AA-08 句，宿主观测组件一项按源码改写事件范围与 fd；§2.6 NB-AA-08 改成按凭据、写明落在哪里，部署条件补 TSC；§3.2 NB-N-13 与 01 取同一定义；§3.6 N-06 括注补齐；§3.7 补两条；初态 57 项（1 项未定）；v6（第三次定向复核的修改，2026-10-26）：§2.5 宿主观测组件一项只留构造交出了什么与已核的事件分派、事件存路径并取引用，权限判定移到 01 NB-AA-08（登记并取回 fs/notify/fanotify/fanotify.c）；§2.6 NB-AA-08 一行改写；§3.4 加 NB-E-P-02 × N-06（305 个分支）；§3.6 N-06 写入宿主可观察的状态与默认规则，N-13 写明部署的 /proc 读者；§3.7 补两条；v7（第四次定向复核的修改，2026-10-26）：§2.5 宿主观测组件一项把被钉住的挂载限到路径型事件的 /work 与 /runtime、pidfd 写成身份引用、依赖栏去掉 NB-AA-08；§3.6 N-06 规则补构造时设定的属性与退出时的回收作用；§3.7 同步；v8（审核一收口，2026-10-26）：§2.5 与 §3.7 写明"本配置下 /work 与 /runtime"这一范围的条件在 01 NB-E-K-09；v9（五族依据，2026-10-27）：§1.2 用户态指令与内存访问一族（改名）补 NB-E-M-08；§2.1 继承属性一项钉定动态 XSAVE 权限；§2.6 加 NB-AA-09；§3.1 ABI 入口的 sysenter 一行补"不论从哪种模式执行"；§3.4 加 NB-E-M-08 × N-06（306 个分支）；§3.6 N-06 规则补 CPU 号与静态配置；v10（R0d 全量审核的修改，2026-10-29）：§3.6 N-06 规则与 §3.7 宿主可观察的格改用 SPEC §4.1 第 4 类的两个记录取值；§2 开头与 §3.7 私有的格写明 I2 只管宿主要特权才碰得到的部分，§3.7 构造行的格写明章代号；v11（R0d 定向复核的修改，2026-10-29）：§1.1 表下写明 I2 的私有部分在模型里怎样对应；§2 开头的 I2 照抄 SPEC；v12（R0d 第二次定向复核，2026-10-29）：§1.1 表下一句改准（只在引用这一维比 I2 强，不是可信方的宿主进程不在模型里，宿主特权进程归 NB-AA-08）；§2 开头的 I2 照新文本补全；§3.7 加宿主观测组件所收记录的归类待定一条
reading_rule: 初态表按 SPEC §4.2 的格式；依据里的每个文件与 ID 都在依赖里；kernel 文件写树内路径，engine 文件写 01 的缩写加行号（01 没有缩写的写文件名）。
---

# 02 — 主干

**用途。** 把 SPEC §4.2"证明的形状"落到这个系统上：不变量的三条子句各对应哪些代码对象，转换按什么粒度切，每个可信方转换归哪一章
（§1）；初态，即每个 execution 由构造发出的那次 execve 时 I1–I3 成立（§2）。后半是坏事件的分解：子操作表、分支表、列的不适用规则（主干·下）。
不变量 I1–I3 的定义在 SPEC §4.2，本文件不重写。

## 1 不变量的落地

### 1.1 模型状态与代码对象的对应

TLC 模型与各章的保守摘要都用下表的模型状态；每一项写它在 kernel 与 engine 里是什么对象，保守摘要说"作用到某状态"时指的就是这里的对象。

| 模型状态 | 子句 | kernel 里的对象 | engine 里的对象 |
|---|---|---|---|
| execution 的集合，各自的 epoch、uid、工作区、租约 | 全部 | 一个 pid namespace（kernel/pid_namespace.c）及其中的任务；任务的凭据 struct cred | spawner 的 spawn_record（spawner L18–29）；目录登记的工作区与 uid（catalog L311–334）；engine 的会话与租约 |
| execution 持有的 fd 引用 | I1 | 每个任务的 files_struct 与 fdtable 里的 struct file（fs/file.c） | — |
| 路径与挂载 | I1 | 任务的 nsproxy 指向的 mnt_namespace 与其中的 struct mount 树；fs_struct 的 root 与 pwd（fs/namespace.c、fs/fs_struct.c） | 构造的挂载步骤（child L39–82） |
| 内存映射 | I1 | mm_struct 的 vm_area_struct，各自持有的 vm_file（mm/mmap.c） | — |
| 可见的进程 | I1 | 本 pid namespace 里的 struct pid（kernel/pid.c）；fd 引用里还可以有 pidfd 指向的 struct pid，其中 getsockopt 的 SO_PEERPIDFD 给出的那个指向本 pid namespace 之外的 spawner（01-trace-events §8；审核一，Claude 意见 11） | — |
| 继承的属性与隐式主体 | I1 | cred（凭据、keyring）、signal_struct（rlimit、进程组、会话、CPU 时间计时）、sighand（处置）、css_set（cgroup 成员）、nsproxy 里沿用宿主的四个 namespace | 启动器与 spawner 设下的值（cell L13–55；spawner L396–404；child L103–105） |
| 对象与归属：交付、本地独占、宿主共享、别的 execution、宿主 | I2、I3 | 交付：工作区子卷的 inode 树、runtime 副本的 inode 树、channel 的 socket；本地独占：本 mount ns 里的 tmpfs 与 proc 超级块、本 net ns 与 ipc ns、自己的任务与 mm；宿主共享：四个设备的 inode | 交付清单的条目（01 §2.1）；构造给出的本地对象（01 §2.2） |
| 登记的延迟动作 | I3 | 任务里的 clear_child_tid、robust_list、rseq、pdeath_signal；file 的 f_owner 与 fasync 项；inode 的 file_lock_context（锁、租约）；dnotify 标记；socket 队列里的 skb 与在途 fd；address_space 的脏页；挂起信号；signal_struct 的 CPU 时间上限 | — |
| 可信方持有的引用 | I2 | 可信方进程的 fd 表与 mm（同上各对象） | spawner：child_pid、交接前的 channel 端、store 与目录的 fd（spawner L18–52）；engine：channel 端与收到又关闭的 fd（transport.c L90–123、L212–240）；文件 worker：store 与 seed 的 fd；supervisor：cell cgroup |
| epoch 与 uid 分配 | I1、I2 | cgroup.kill 与 populated（kernel/cgroup/cgroup.c） | 准入时同 uid、同 gid、同工作区的活记录互斥（spawner L87–92）；epoch 更换（spawner L405–439；recover L7–16） |

I2 只管私有候选里宿主要特权才碰得到的部分（SPEC §4.2）。模型按整个对象记归属与引用：在引用这一维，查别的 execution 不持有整个
对象的引用比 I2 的要求强；I2 的其余要求照旧由别处承担，列出的可信方不转交由可信方转换承担，宿主特权进程不取用、不读、不改由前提
NB-AA-08 承担。不是可信方的宿主进程不在模型里，它们不要特权就碰得到的部分由各格记宿主可观察（SPEC §4.1 第 4 类）。

### 1.2 转换粒度

SPEC §4.2 的规则：一个系统调用或子操作，只有在格里写出原子性依据（kernel 里使它不可被插入的锁或等价机制的位置）时才算一个转换；
写不出的，在别的任务能插入的每个位置切开，或保守地按"中间状态对其他任务可见"处理。这条规则对所有转换一样适用（审核一，Claude 意见 10、
Codex 意见 R7）：execution 的系统调用与用户态访问、kernel 代为完成与延迟异步的动作、进程状态转换、可信方的每一步。同一 execution 的线程
属于同一主体（NB-X-03），这只说明它们之间的作用不算干扰，不是原子性依据：作用到与其他主体共享的对象时，它们与其他主体动作的交错
照样按切点处理。各类转换的默认粒度如下；格里可以按依据把默认切法合并，合并要写出依据，写不出依据的就不合并。

**失败返回与部分完成。** 一个调用或可信方动作切开之后是一串转换。失败返回是这串转换走到某个切点之后转向错误路径：之前已完成的
转换照样作用到状态，最后一个转换给出错误返回值，所以失败路径在保守摘要里写"已完成的前缀可见"。部分完成（read 只拷了一部分、writev
写了前几段、副本删到一半时被取消）是同一串转换在中途停下；每个可能的停点各算一个候选效果（SPEC §4.2），保守摘要写停在那里时
状态是什么、之后由谁接手。

| 转换的类 | 默认粒度 | 切点（别的任务能插入的位置） |
|---|---|---|
| 系统调用与子操作（01 §3.1 附表） | 一次调用是若干转换，在每个切点切开 | 睡眠与等待（锁、I/O、页缓存）、用户内存拷贝（可能缺页）、放锁、重新取 RCU 读锁的位置；格里写不出切点的，按"中间状态对其他任务可见"写保守摘要 |
| 用户态指令与内存访问（NB-E-M-01…08） | 一次读写指令一个转换，读处理器状态的指令一条一个转换（NB-E-M-04、NB-E-M-08）；缺页处理另算一个转换 | 指令之间；跨缓存行或不对齐的访问不保证单拷贝原子，按"中间状态对其他主体可见"处理；同一 mm 的线程之间不算干扰（NB-X-03），作用到共享映射时与其他主体的交错照样切 |
| kernel 代为完成与延迟、异步动作（NB-E-K-*、NB-E-A-*） | 一个工作单元一个转换：一次信号交付、一次回写遍历里的一个 inode、一次 rseq 处理、一次异步通知、一次最后引用的释放 | 同系统调用一行 |
| 进程状态转换（NB-E-P-*） | 按实际执行点里的步骤切：exec 切成 de_thread、exec_mmap、关闭 close-on-exec 的 fd、重置处置等步；退出按 do_exit 的步骤切 | 各步之间 |
| 构造（NB-K-01…10） | 对本 execution：不作保持论证的转换，结果是它的初态，在 §2 逐步核对；对与之并发运行的其他 execution：是可信方转换（为另一个 execution 构造），按下一行切分，归 LC（§1.3） | 同下一行 |
| 运行期的可信方转换（NB-K-11…16 与 engine 的运行期动作，含为另一个 execution 做的构造） | 有原子性依据（可信方代码里的锁，或单个系统调用的原子性依据）才把几步合并成一个转换；否则在可信方代码的每个系统调用之间切开，系统调用本身按第一行切。例：文件 worker 删除副本是逐个 unlinkat（catalog L431–493），每两次之间切开；engine 处理一条消息也不是原子的 | 可信方代码的系统调用之间与系统调用内部的切点；每个切点按"中间状态对 execution 可见"处理，对每个格作干扰义务 |

### 1.3 可信方转换的归属章

每个可信方转换由一章负责保持论证（SPEC §4.2"保持"）与干扰义务。同一个构造动作分两种情形（审核一，Codex 意见 R6）：对本 execution X，
构造的结果是 X 的初态，在本文件 §2 逐步核对；X 运行期间 spawner 为另一个 execution Y 做的构造是一个可信方转换，它与 X 的动作并发，
保持与干扰义务归 LC，§3.4 里 NB-K-03…10 的分支承载的就是这种情形。NB-K-01、02 只在 cell 启动时发生一次，那时还没有任何 execution，
它们的分支留在本文件。

| 可信方转换 | 01 的行 | 归属 | 理由 |
|---|---|---|---|
| w2-cell 启动、spawner 初始化 | NB-K-01、02 | 主干 §2（初态）；分支留在本文件 | cell 启动时发生一次，在任何 execution 之前 |
| 准入、副本创建、clone 前、child 的构造（关 fd、挂载、lo 与 stdio、降权与过滤器、SEALED 与 execve），对本 execution X | NB-K-03…10 | 主干 §2（初态） | 在 X 的代码运行之前完成，结果是 X 的初态 |
| spawner 为另一个 execution Y 做同样的构造，与 X 的动作并发 | NB-K-03…10（对 Y） | LC（§3.4 里这些行的分支） | PLAN §1.2：可信方为另一 execution 构造归生命周期章 |
| spawner 校验 SEALED 并把 channel 交给 engine | NB-K-11 | NI | 转交 fd，属于 engine 通道 |
| engine 处理通道输入、收到的 fd 并关闭 | NB-K-12 | NI | PLAN §1.2 |
| engine 写记录文件与 stdout、stderr | NB-K-12 | PF | engine 文件（PLAN §1.2） |
| spawner 停止、回收、置空 | NB-K-13 | PS | 信号与回收 |
| 文件 worker 删除副本 | NB-K-14 | LC | 文件 worker 建删副本（PLAN §1.2） |
| 后继复用工作区 | NB-K-15 | LC | 后继与租约 |
| 控制失联、epoch 更换、w2-recover | NB-K-16 | LC | 回收与 epoch |
| 可信方后来解引用 execution 塑造的状态：后继的构造与运行读 /work、宿主清理与备份读 /work、宿主可信方打开 /work 文件时遇到锁与租约、supervisor 读 populated | 01-trace-events §7 的第 4 步四项 | 读 /work 的三项归 PF，supervisor 一项归 LC | PF 负责可信方之后会读的工作区状态（SPEC §4.2 第 4 步）；populated 是回收判定 |
| core dump 处理程序 | NB-S-09 | PF | RLIMIT_CORE 为 1 时不被调用（NB-E-K-01），仍由 PF 写这一格 |

## 2 初态

**要证的。** 每次 execve 时 I1–I3 成立（SPEC §4.2"证明的形状"）。这里的 execve 指每个 execution 由构造发出的那一次（NB-K-10），即
execution 开始的时刻（审核一，Codex 意见 R4）。execution 自己之后再做的 execve 是转换 NB-E-P-01：它保留不带 close-on-exec 的 fd、SIG_IGN、
rlimit、cwd 与 root 等既有状态（01 §3.2 NB-E-P-01 的后续动作），不把状态重置成本节的样子，所以从它之前已满足 I 的状态证保持（NB-E-P-01
与 NB-E-S-execve 的格），不套本节的表。在构造发出的 execve 那一刻 execution 还没有做过任何动作，所以 I1 是"持有的每个
引用都来自 D_impl 或局部环境的构造"，I2 是"每个私有候选里宿主要特权才碰得到的部分（按 §4.1 私有判据的切法），持有能取用、读出或改变它的引用的，只有本 execution 的任务和 01 列出的可信持有者（基线快照之外的宿主特权进程由前提 NB-AA-08 承接），可信持有者不把它转交出去"（SPEC §4.2），I3 在初态没有候选效果可归类：
经这些引用与隐式主体产生的效果由各格判。下表逐项核对：D_impl 对照交付清单与局部环境（§2.1）、01 §2.4 的八处差异（§2.2）、构造的
每一步（§2.3）、攻击者塑造过的先前状态（§2.4）、可信方持有的引用（§2.5）；继承属性逐项在 §2.1 末尾。NB-AA 的分配在 §2.6。

**表头。** 初态项、记录（成立、未定，或路线 ID）、依据、依赖、测试（SPEC §4.2）。测试一栏写 engine 回归运行的证据编号，或"不测"加
理由；2026-10-25 之前登记的运行（NB-EV-014…016）是 engine 自己的回归，只支撑它断言到的那几项（04 的适用边界）。

### 2.1 D_impl 对照交付清单与局部环境

| 初态项 | 记录 | 依据 | 依赖 | 测试 |
|---|---|---|---|---|
| fd 表：execve 时只有 0、1、2、3 | 成立 | [R] spawner L50 先关掉 engine 端、控制 fd、worker fd 与 store 锁；child L88–103 把 0–2 dup2 到 /dev/null，channel 移到 3 并清 CLOEXEC，close_range(4,~0) 关掉其余（fs/file.c::__close_range）；[M] NB-EV-015 | spawner；child；fs/file.c；NB-DI-01；NB-EV-015 | NB-EV-015（仍有 fd 0–3） |
| fd 0–2：以 root 凭据打开、指向宿主 /dev/null 的同一个 file | 成立 | [R] child L88 在降权（child L104）之前以 O_RDWR 打开沙箱里的 /dev/null，它是宿主同一设备的 bind（child L66–75）；file 记下打开者的凭据，而 /dev/null 的读写方法不看它（drivers/char/mem.c::read_null、drivers/char/mem.c::write_null）；经 /proc/self/fd/0 重开是一次新的打开，用 execution 自己的凭据 | child；drivers/char/mem.c；NB-L-04；NB-L-08 | 不测：只读源码；重开后的身份测试在 GS 章（宿主共享设备的身份组） |
| fd 3：channel 的 agent 端 | 成立 | [R] spawner L113–124 在 clone 之前建 AF_UNIX SOCK_STREAM 的 socketpair（属于宿主 net ns）并核对两端缓冲；child L100–102 把 agent 端放到 fd 3 且不带 CLOEXEC；对端由 spawner 持有到交接后关闭（spawner L251）；两端的对端凭据在建 socketpair 时取自 spawner（net/unix/af_unix.c::unix_socketpair → net/unix/af_unix.c::init_peercred），所以 agent 端读 SO_PEERCRED 得到 uid 0（附表 v5 已改正） | spawner；child；net/unix/af_unix.c；NB-D-03；NB-DI-02 | NB-EV-015（fd 3 存在）；对端凭据不测：只读源码 |
| 挂载表：只有构造给出的挂载，传播私有 | 成立 | [R] child L44 先把整棵树设为私有；child L45、L64–65、L76–78 建 tmpfs 根、proc、/dev、/tmp、/dev/shm；child L58、L62 以递归 bind 挂 /runtime 与 /work，再只对顶层 remount（child L31–32；递归 bind 走 fs/namespace.c::copy_tree，remount 走 fs/namespace.c::do_reconfigure_mnt 只改顶层）；child L79–82 pivot_root 后以 MNT_DETACH 摘掉旧根（fs/namespace.c::do_umount）；递归 bind 不带入子挂载依赖前提 NB-AA-02；[M] NB-EV-015 | child；fs/namespace.c；NB-DI-03；NB-AA-02；NB-EV-015 | NB-EV-015（mountinfo 没有 shared 与 master） |
| /work 是目录登记的那个工作区子卷 | 成立 | [R] 目录加载时核 btrfs、子卷根（inode 256、设备号与父目录不同）、owner u:g、0700，并记下 dev 与 ino（catalog L311–334）；child 里经 w2_workspace_open 在部署 fd 下打开，沿途祖先须 root 所有且不可组写他写（support L172–190），再核同样各项与记下的 dev、ino（catalog L366–376）；mount_fd 以不跟随符号链接的 openat2 重新解析绝对路径并比对身份后才 bind（child L19–31）；比对与 bind 之间能替换路径的只有对 root 所有的祖先有写权限者，依赖前提 NB-AA-01 | catalog；support；child；NB-D-01；NB-DI-04；NB-DI-19；NB-AA-01 | 不测：只读源码；交付权利两侧的边界测试在 PF 章 |
| /runtime 是 worker 为本 execution 建的副本 | 成立 | [R] child L39–43 在 objects fd 下以 RESOLVE_BENEATH、不跟随符号链接、不跨挂载打开 copy_id，并与 worker 记下的 dev、ino 比对；mount_fd 再比对后 bind（child L19–31），remount 为 ro、nosuid、nodev、noatime（child L32）；副本 0:0 所有、只读权限位、与 seed 不共享 inode（catalog L399–429）；依赖前提 NB-AA-01、NB-AA-02；[M] NB-EV-015 | child；catalog；NB-D-02；NB-DI-18；NB-AA-01；NB-AA-02；NB-EV-015 | NB-EV-015（写 /runtime 失败） |
| /proc 是本 pid namespace 的 proc，只有 pid 条目 | 成立 | [R] child L64 由新 pid ns 的 PID 1 挂载，proc 取挂载者的活动 pid ns（fs/proc/root.c::proc_init_fs_context），subset=pid 只留 pid 目录与 self、thread-self；[M] NB-EV-015 | child；fs/proc/root.c；NB-L-06；NB-DI-05；NB-EV-015 | NB-EV-015（/proc/meminfo ENOENT，mountinfo 有 subset=pid） |
| /dev 的四个节点是宿主的同一设备 | 成立 | [R] child L66–75 先在 tmpfs 上建 0600 占位文件，再把宿主 /dev 下同名节点非递归 bind 上去（fs/namespace.c::do_loopback 不带 MS_REC 只克隆顶层），remount 为 nosuid、noexec；宿主节点 0666（NB-EV-019）；它们是宿主共享的局部环境，其上有外部效果的操作在各格按第 4 类或路线判 | child；fs/namespace.c；NB-L-04；NB-EV-019 | 不测：身份测试在 GS 章 |
| tmpfs 根、/dev、/tmp、/dev/shm 是新建的实例 | 成立 | [R] child L45、L65、L76–78 各自新建 tmpfs 超级块，挂在 clone 新建的 mount namespace 里（spawner L128–129），整棵树先设为私有（child L44）；其他 execution 与可信方没有指向这些实例的引用（§2.5） | child；spawner；NB-L-01；NB-L-02；NB-L-03；NB-L-05；NB-PV-08 | 不测：两个沙箱互看的私有性测试在 PF 章 |
| 网络：本 net namespace 只有 lo | 成立 | [R] spawner L128–129 带 CLONE_NEWNET；child L83–87 只把 lo 置 UP；[M] NB-EV-015 | spawner；child；NB-L-07；NB-EV-015 | NB-EV-015（net 只有 lo） |
| cwd 与 root | 成立 | [R] child L79–82 pivot_root 到 tmpfs 根并摘掉旧根，宿主路径在本 namespace 里没有名字；child L111 chdir 到 /work | child；NB-L-09；NB-PV-08 | 不测：只读源码 |
| 凭据 | 成立 | [R] support L237–261：先置 no_new_privs，逐位丢 bounding，setgroups(0)，setresgid、setresuid 后 getresuid 复核三值，清 ambient，cap_set_proc(空)；euid 变化时 kernel 清 pdeath_signal 并按 suid_dumpable 设 dumpable（kernel/cred.c::commit_creds），非 setuid 的 execve 把 dumpable 设回 1（fs/exec.c::begin_new_exec）；[M] NB-EV-015 | support；kernel/cred.c；fs/exec.c；NB-DI-07；NB-EV-015 | NB-EV-015（CapBnd 0、NNP 1） |
| seccomp 过滤器 | 成立 | [R] child L105 在降权之后装目录编译的过滤器（no_new_privs 已置；kernel/seccomp.c::seccomp_prepare_filter 要求 no_new_privs 或 CAP_SYS_ADMIN）；过滤器的内容见 policy L13–67；[M] NB-EV-014、NB-EV-015 | child；policy；kernel/seccomp.c；NB-DI-08；NB-EV-014；NB-EV-015 | NB-EV-014（三个固定禁止项 EPERM）；NB-EV-015（Seccomp 2，ia32 与 x32 入口 SIGSYS） |
| namespace | 成立 | [R] spawner L128–129 新建 mount、pid、net、ipc，user、uts、cgroup、time 沿用宿主；spawner.c 全文没有打开 /proc/\<pid\>/ns 的代码；engine 的发送只用不带辅助数据的 send（transport.c L247–260），不把 nsfd 交给任何人 | spawner；transport.c；NB-DI-09 | 不测：只读源码 |
| execve 之后的地址空间：没有与其他主体共享的可写映射，也没有后备对象可被可信方以外的主体写的映射（接 01 去向表移交的初态断言；审核一按 Codex 意见 R9 收窄成这一说法） | 成立 | [R] exec 新建 mm 并换上，旧 mm 的映射全部放掉（fs/exec.c::bprm_mm_init、fs/exec.c::exec_mmap）；ELF 装入的段都是 MAP_PRIVATE（fs/binfmt_elf.c::elf_map、fs/binfmt_elf.c::load_elf_binary），后备是本 execution 的 /runtime 副本里的可执行文件与解释器：副本 inode 不与 seed 或其他副本共享，0:0 所有、只读权限位，挂载为 ro（NB-DI-17、NB-DI-18）；写时复制之前读到的是这些 inode 的页缓存页，页缓存按 inode 分开，映射这些 inode 的只有本 execution 的任务，宿主可信方可以读；栈是新的匿名映射（fs/exec.c::setup_arg_pages）；vdso 代码页与 vvar 由 arch/x86/entry/vdso/vma.c::arch_setup_additional_pages 映射，是全机共享的只读页，vvar 由 kernel 写（NB-E-M-04）。所以没有与 engine、spawner、文件 worker 或其他 execution 共享的可写映射，后备对象只有可信方能写（NB-AA-03 对代码核）。物理页层面不作主张：页缓存与之后的 KSM 合并由 kernel 管理，后者是运行期的事件（NB-E-A-07） | fs/exec.c；fs/binfmt_elf.c；arch/x86/entry/vdso/vma.c；NB-AA-03；NB-E-M-04；NB-DI-17；NB-DI-18；NB-E-A-07 | 不测：只读源码 |
| 进程组、会话与控制终端 | 成立 | [R] clone 不带 setsid、setpgid（spawner L128–129）：PID 1 留在 spawner 的进程组与会话里，同组的还有 engine（cell L36–54 fork 后 exec 而来）、spawner、文件 worker 与其他 execution；控制终端取决于启动方式（cell 不调 setsid）。这是继承的隐式主体，是 I1 允许的来源；经它的候选效果在 N-07 列的格判 | spawner；cell；NB-DI-10；NB-MM-02 | 不测：效果在 PS 章测 |
| 父进程与 exit_signal | 成立 | [R] spawner L128–129 clone 的 exit_signal 是 SIGCHLD，PID 1 的父进程是 spawner（kernel/fork.c::copy_process）；只有 spawner 对它 waitpid（spawner L372） | spawner；kernel/fork.c；NB-DI-11 | 不测：只读源码 |
| cgroup 成员 | 成立 | [R] 新任务进 spawner 的 css_set（kernel/cgroup/cgroup.c::cgroup_post_fork）；沙箱里没有 cgroupfs，mount 不在 L，也没有 capability，所以迁不出（NB-AA-06 的代码一半）；cell 放进独占 cgroup 是 supervisor 的部署前提（NB-AA-06 的前提一半） | kernel/cgroup/cgroup.c；NB-DI-14；NB-AA-06；L（整表） | 不测：只读源码 |
| keyring | 成立 | [R] fork 继承凭据里的 session keyring 引用（kernel/cred.c::copy_creds）；keyctl、add_key、request_key 不在 L；这是继承属性，经它的候选效果在 N-07 列的格判 | kernel/cred.c；NB-DI-15；NB-MM-03；L（整表） | 不测：只读源码 |
| rlimit | 成立 | [R] child L103 把 RLIMIT_CORE 软硬都设为 1（提高硬限需要 CAP_SYS_RESOURCE，kernel/sys.c::do_prlimit）；其余继承自启动器的父进程，cell 与 spawner 都不设，取值是部署条件（NB-MM-01）；它们只限制本 execution 的资源，不给出引用 | child；kernel/sys.c；NB-DI-06；NB-MM-01 | NB-EV-016（/proc/self/limits 显示 core 1 1） |
| 信号处置与掩码 | 成立 | [R] spawner L400–402 把 SIGCHLD 置 SIG_DFL、掩码清空；其余处置继承，SIG_IGN 跨 exec 保留、处理函数在 exec 时重置（kernel/signal.c::flush_signal_handlers）；只影响本 execution 收到信号时的处理 | spawner；kernel/signal.c；NB-DI-16；NB-MM-04 | 不测：只碰自己 |
| umask | 成立 | [R] child 不设 umask（child L38–119），值继承自启动器的父进程（NB-MM-05）；它决定 /work 上新建文件的权限位，而工作区子卷根是 0700、owner u（catalog L323–324），宿主上只有 root 与 u 能进入 | child；catalog；NB-MM-05；NB-DI-19 | 不测：只读源码 |
| pdeath_signal | 成立 | [R] clone 时清零（kernel/fork.c::copy_process），child 降权使 euid 变化时 kernel 再清零（kernel/cred.c::commit_creds），所以 execve 时为 0；普通 exec 不清（fs/exec.c::begin_new_exec 只在 secureexec 时清）：01 §4 NB-N-08 与附表 execve 一行原先写"exec 时清除"，已改正（01 v8、附表 v5） | kernel/fork.c；kernel/cred.c；fs/exec.c；NB-N-08 | 不测：只读源码 |
| robust list、备用栈、POSIX 定时器与 itimer | 成立 | [R] clone 时清 robust list（kernel/fork.c::copy_process 调 futex_init_task），新信号结构里的 ITIMER_REAL 是新建的（kernel/fork.c::copy_signal）；exec 时清 POSIX 与 CPU 定时器与备用栈（fs/exec.c::begin_new_exec），清 robust list（kernel/futex/core.c::futex_exec_release） | kernel/fork.c；fs/exec.c；kernel/futex/core.c；NB-N-08 | 不测：只读源码 |
| loginuid 与 sessionid | 成立 | [R] 继承自启动器；继承值未设时 execution 可以不经特权设一次，同时分配新的 sessionid（kernel/audit.c::audit_set_loginuid）；它们只出现在本 execution 的审计记录里（NB-E-K-13），01 NB-DI-25 已补上（01 v8）；继承值要读宿主（01-trace-events §7） | kernel/audit.c；NB-DI-25；NB-E-K-13 | 不测：效果在 GS 章 |
| comm、dumpable、oom_score_adj、亲和性、ioprio、nice、personality、securebits、timerslack、mempolicy、THP 禁用、推测执行控制、MDWE、TSC 禁用、CPUID 陷入、syscall user dispatch、动态 XSAVE 权限 | 成立 | [R] comm 在 exec 时设为可执行文件名（fs/exec.c::__set_task_comm）；dumpable 见凭据一项；其余由 fork 继承（kernel/fork.c::copy_process），child 不改（child L38–119 没有设它们的调用）；都只作用于本 execution 自己的任务与 mm，经它们的候选效果（例如 oom_score_adj 改变 OOM 的选择）在各格判。后四项（定向复核补）：构造发出的 execve 时 syscall user dispatch 与 CPUID 陷入都是关的（前者在 fork 与 exec 时清除：kernel/fork.c::dup_task_struct、fs/exec.c::begin_new_exec；后者在 exec 时清除：arch/x86/kernel/process.c::arch_setup_new_exec）；TSC 禁用标志随 fork 复制（arch/x86/kernel/process.c::arch_dup_task_struct）、exec 时保留，取值来自启动器的父进程，是部署条件，只影响本 execution 自己读 TSC；动态 XSAVE 权限 fork 时继承、exec 时复位为默认（arch/x86/kernel/fpu/core.c::fpu_inherit_perms、arch/x86/kernel/fpu/core.c::fpstate_reset），所以构造发出的 execve 之后 execution 没有 AMX 权限（2026-10-27 钉定） | fs/exec.c；kernel/fork.c；arch/x86/kernel/process.c；arch/x86/kernel/fpu/core.c；child；NB-N-08；NB-MM-05 | 不测：只读源码 |

### 2.2 01 §2.4 的八处差异

| 初态项 | 记录 | 依据 | 依赖 | 测试 |
|---|---|---|---|---|
| NB-DI-21 递归 bind 与非递归 remount | 成立 | [R] 见挂载表一项；源目录下的子挂载只能由能在宿主 mount namespace 里挂载的主体（root）加上：objects 下的副本目录由 worker 新建（catalog L402），工作区子卷由部署方建；所以依赖前提 NB-AA-02 | catalog；NB-DI-21；NB-AA-02 | 不测：前提 |
| NB-DI-22 /dev/random、/dev/urandom 可写 | 成立 | [R] 宿主节点 0666（NB-EV-019），bind 的 remount 只加 nosuid、noexec（child L74）；写入混进全局输入池（drivers/char/random.c::random_write_iter），是 N-06 列的候选效果，不是新的引用 | child；drivers/char/random.c；NB-DI-22；NB-EV-019 | 不测：效果在 GS 章 |
| NB-DI-23 /dev 没有 nodev | 成立 | [R] /dev 是 root 所有、0755 的 tmpfs（child L65），u 不能在其中建条目；mknod 不在 L，也没有 CAP_MKNOD；所以 /dev 里只有构造放的四个节点 | child；NB-DI-23；L（整表） | 不测：只读源码 |
| NB-DI-24 fd 3 的 O_NONBLOCK | 成立 | [R] spawner L113 建 socketpair 时带 SOCK_NONBLOCK；只影响本端的读写方式 | spawner；NB-DI-24 | 不测：只碰自己 |
| NB-DI-25 /proc/self 下的可写条目 | 成立 | [R] execve 后 dumpable 为 1，条目 owner 为 u（fs/proc/base.c::task_dump_owner）；可写条目的清单见 01 NB-DI-25（v8 补了 loginuid），写它们的效果在各格判（01-trace-events §1.1 write 一行） | fs/proc/base.c；NB-DI-25 | 不测：效果在各章 |
| NB-DI-26 继承属性 | 成立 | [R] 逐项见 §2.1 从"进程组、会话与控制终端"到末行的各项 | NB-DI-26 | 不测：见各项 |
| NB-DI-27 同一 btrfs 文件系统 | 成立 | [R] 目录加载只核工作区子卷根（catalog L311–334），不核文件系统是否独占，诊断目录的工作区与 store、seed 同在一个文件系统；共享的是空闲空间、事务与元数据树这类汇总状态，不给出新的引用，候选效果在 N-06 列的格判 | catalog；NB-DI-27；NB-MM-11 | 不测：效果在 GS 章 |
| NB-DI-28 channel 属于宿主 net namespace | 成立 | [R] socketpair 在 clone 之前由 spawner 在宿主 net ns 里建（spawner L113、L128）；两端无名；宿主侧能列出它，agent 一侧经它只能读写这一条连接 | spawner；NB-DI-28 | 不测：只读源码 |

### 2.3 构造的每一步

每一步查四件事：宿主来源、递归子挂载、核对与使用之间的名字解析、失败后的状态；每一步的依据逐项写出这四件事，不涉及的写"不涉及"并给理由（审核一，Claude 意见 7）。
构造窗口（clone 到 execve）分两项：只跑可信代码一项对代码核；其他主体在窗口里能施加的作用是另一项，作为干扰义务交给 PS、LC 两章（Codex 意见 R5）。

| 初态项 | 记录 | 依据 | 依赖 | 测试 |
|---|---|---|---|---|
| NB-K-01 w2-cell 启动 | 成立 | [R] 宿主来源：启动参数（部署根、目录、engine 的 uid 与 gid、engine 可执行文件路径）由启动器的父进程给出（cell L14–16）；目录从 /var/lib 下的部署根读，沿途祖先须 root 所有、不可组写他写（catalog L42–59、L263–363）；继承的 fd 先以 close_range(3) 去掉（cell L19），环境字节抹掉并 clearenv（cell L28–29），capability 限到六项（cell L29、L31），拒绝 engine 的 uid 或 gid 等于 overflow 或任一工作区（cell L32–33）。递归子挂载：不涉及，这一步不挂载。核对与使用之间：目录在 fork 之前一次读进内存（cell L31），spawner 用 fork 出的副本，之后不再按名字重读目录，目录里的路径在用到时另行按身份核对（NB-K-04、NB-K-07）；engine 可执行文件在 execv 时按宿主路径解析（cell L54），这个路径由离线部署方给出（NB-AA-07）。失败：fork 之前任一步失败即返回，不 fork spawner（cell L14–35）；fork 之后父进程一侧失败（cell L49–54）则 engine 不启动，spawner 在控制端读到 EOF（spawner L139–142）后置控制失联（spawner L408、L451–452），按 NB-K-16 收尾 | cell；catalog；spawner；NB-K-01；NB-K-04；NB-K-07；NB-K-16；NB-AA-07 | 不测：只读源码 |
| NB-K-02 spawner 初始化与文件 worker | 成立 | [R] spawner L396–404：SIGCHLD 置 SIG_DFL、掩码清空，不装信号处理函数；worker 在敏感状态出现前 fork，降到 0:0 且无 capability（storage L194–210、L264–270），不持 engine 的控制端（storage L269）。宿主来源：store 的锁文件、root 与 objects 目录、seed 树都经目录加载时打开的 fd 访问；spawner 以 flock 独占 store.lock（storage L266）；worker 在 init 时核 store 的 dev、ino、owner、权限与文件系统身份（storage L185–191、L205）、objects 为空（storage L205），逐树核 seed（storage L206）。递归子挂载：不涉及，这一步不挂载；worker 之后打开路径一律经 tree_open，带 RESOLVE_BENEATH 与 RESOLVE_NO_XDEV，不跨挂载（catalog L132–140）。核对与使用之间：worker 在每个作业之前重核 store 身份（storage L242），按 fd 解析，不按宿主绝对路径。失败：flock、socketpair 或 fork 失败时 spawner 把 store 记为 dead 并置控制失联（spawner L403），admission 要求 store 已就绪（spawner L93），所以不接受 spawn；worker 核对失败时报 ok=false 后退出（storage L209–210） | spawner；storage；catalog；NB-K-02；NB-S-06 | 不测：只读源码 |
| NB-K-03 准入：同一时刻同 uid、同 gid、同工作区只有一个活的 execution | 成立 | [R] spawner L83–92：uid、gid 等于计划里工作区的值且不等于 overflow；与任何未置空的记录同 uid、同 gid 或同工作区就拒绝；置空要求 PID 1 已回收（spawner L373–382）；跨 epoch 的残留由 NB-K-16 的 cgroup.kill 与 populated 0 排除，依赖前提 NB-AA-05、NB-AA-06。宿主来源：spawn 请求来自 engine 的控制消息（engine 是可信方，NB-AA-07），计划按 id 与 digest 在启动时读入的目录里查（spawner L81；catalog L395–398）。递归子挂载：不涉及。核对与使用之间：spawner 是单线程的轮询循环（spawner L405–458），检查与登记在同一次 spawn 调用里完成，中间不处理别的消息；槽位在检查之前已标为已用（spawner L75），之后的请求能看到它。失败：fail_record 把记录标为失败与停止、关掉 channel，没有 pid 时置空（spawner L53–58），不预留空间、不 clone（spawner L85、L90、L96） | spawner；catalog；NB-K-03；NB-K-16；NB-AA-05；NB-AA-06；NB-AA-07 | 不测：只读源码；后继与 epoch 的情形在 LC 章 |
| NB-K-04 副本创建 | 成立 | [R] catalog L399–429：在 objects 下 mkdirat 新目录（已存在就失败），逐个以 O_CREAT 与 O_EXCL 建文件、FICLONE、核 digest、fchmod，最后 tree_check 核不与 seed 共享 inode；worker 以 0:0、umask 0 运行（storage L194–199）。宿主来源：objects 目录与 seed 树经目录加载时打开的 fd 访问，每个作业前重核 store 身份并查可用空间（storage L241–245）。递归子挂载：tree_open 带 RESOLVE_BENEATH 与 RESOLVE_NO_XDEV，不跨挂载（catalog L132–140）；副本目录由 worker 新建（catalog L402），它下面没有挂载。核对与使用之间：新目录建好随即记下 dev 与 ino（catalog L402–406），child 挂载前按这对身份比对（NB-K-07）；文件内容在 reflink 之后按清单核 digest（catalog L420）；objects 目录 root 所有、0700（storage L189），记下身份到挂载之间能替换副本的只有 root，依赖前提 NB-AA-01。失败：worker 报 failed（已建了根目录）或 not_materialized（storage L251–255），spawner 让这次 spawn 失败，已建的部分留作待删，由删除作业清掉（spawner L295–298、L319–337；NB-K-14） | catalog；storage；spawner；NB-K-04；NB-K-07；NB-K-14；NB-DI-18；NB-AA-01 | 不测：只读源码 |
| NB-K-05 clone 前 | 成立 | [R] spawner L112–132：socketpair、SO_PASSCRED 只在 engine 端、缓冲上限核对、clone 新建四个 namespace；任一步失败都关掉两端，不留半成的记录（spawner L133–135）。宿主来源：socketpair 建在 spawner 所在的宿主 net namespace 里（spawner L113）；新 mount namespace 是宿主挂载树的副本，其中的宿主挂载在 NB-K-07 设为私有、pivot 后摘掉；挂载用的两个源路径由目录根与 copy_id 拼成（spawner L108–111），这里只拼字符串、不解析，在 child 里按身份比对后才用（NB-K-07）。递归子挂载：不涉及，这一步不挂载。核对与使用之间：不涉及，这一步不按名字打开对象。失败：见上 | spawner；NB-K-05；NB-K-07 | 不测：只读源码 |
| NB-K-06 child 关掉不属于它的 fd | 成立 | [R] spawner L50 关 engine 端、控制 fd、worker fd 与 store 锁 fd；目录与 objects 的 fd 留给构造用，在 NB-K-08 的 close_range(4,~0) 里一并关掉（child L103）。宿主来源：不涉及，这一步不打开对象。递归子挂载：不涉及。核对与使用之间：不涉及，按 fd 号关闭、不解析名字。失败：这几次 close 不检查返回值，漏关的由 child L103 的 close_range 兜底（它的失败走 FAIL） | spawner；child；NB-K-06；NB-K-08 | 不测：只读源码 |
| NB-K-07 构造挂载 | 成立 | [R] 宿主来源：runtime 在 objects fd 下打开并比对 worker 记下的身份（child L39–43），工作区经 w2_workspace_open 打开并比对（catalog L366–376），四个设备节点按宿主路径 /dev/<名> bind（child L66–75），这时 mount namespace 还是宿主挂载树的副本，宿主 /dev 由宿主 init（NB-S-08）维护，proc 与四个 tmpfs 是新建的实例（child L45、L64–65、L76–78）；递归子挂载：递归 bind 会带入，依赖前提 NB-AA-02；核对与使用之间：mount_fd 比对身份后按路径 bind（child L19–31），窗口里能替换路径的只有对 root 所有的祖先有写权限者（support L172–190），依赖前提 NB-AA-01；失败：TRY 在任一步失败或超时就跳到 FAIL，发出 FAIL 后 _exit(125)，不 exec（child L18、L113–119），半成的挂载随 mount namespace 一起销毁 | child；catalog；support；NB-K-07；NB-S-08；NB-AA-01；NB-AA-02 | 不测：只读源码；成功构造的结果见挂载表一项 |
| NB-K-08 lo、stdio、fd 3、core 上限 | 成立 | [R] child L83–103。宿主来源：/dev/null 在 pivot 之后按沙箱路径打开，它是 NB-K-07 bind 上来的宿主同一设备（child L88、L66–75）；临时 AF_INET socket 建在本 net namespace 里，用完关闭（child L83–87）。递归子挂载：不涉及。核对与使用之间：/dev/null 按沙箱路径解析，这时沙箱树里能改 /dev 的只有 root（tmpfs /dev 是 root 所有、0755，child L65），child 自己还是 root、只跑可信代码。失败：TRY 任一步失败走 FAIL、_exit(125)，不 exec（child L18、L113–119）；[M] NB-EV-015、NB-EV-016 | child；NB-K-07；NB-K-08；NB-EV-015；NB-EV-016 | NB-EV-015；NB-EV-016 |
| NB-K-09 降权与过滤器的顺序 | 成立 | [R] child L104–105 先降权（support L237–261）再装过滤器；过滤器从装上起对之后的每个系统调用生效，含 execve。宿主来源：过滤器程序是目录编译、经 memfd 封印后读进 spawner 内存的（NB-DI-08），child 用 fork 来的副本（child L105）。递归子挂载：不涉及。核对与使用之间：不涉及，这一步不解析名字。失败：降权或装过滤器失败走 FAIL，不 exec（child L104–105、L113–119）；[M] NB-EV-015 | child；support；NB-K-09；NB-DI-08；NB-EV-015 | NB-EV-015 |
| NB-K-10 SEALED、COMMIT 与 execve | 成立 | [R] child L106–112：SEALED 经 fd 3 发出，收满 COMMIT 才 chdir 到 /work 并 execve 目录登记的可执行文件，失败走 FAIL（child L113–119）；可执行文件与解释器在目录加载时核过 ELF64 x86_64 与 PT_INTERP 的位置（catalog L224–256）。宿主来源：可执行文件、argv 与 env 取自目录的 runtime 描述（child L112）；COMMIT 由 spawner 在核对 SEALED 与对端凭据之后经 fd 3 发来（NB-K-11）。递归子挂载：不涉及。核对与使用之间：目录加载时的 ELF 检查是对 seed 做的，可执行文件在 execve 时按沙箱路径从 /runtime 副本解析；副本的字节在创建时按清单 digest 核过与 seed 相同（catalog L420），/runtime 是 ro 挂载、副本 0:0 只读权限位，这时 child 已降权，宿主侧能改副本的只有 root，依赖前提 NB-AA-01。失败：SEALED 发送、COMMIT 接收或 execve 失败都走 FAIL、_exit(125)（child L108–119） | child；catalog；NB-K-10；NB-K-11；NB-DI-17；NB-AA-01 | 不测：只读源码 |
| 构造窗口只跑可信代码（NB-AA-04 对代码核） | 成立 | [R] clone 到 execve 之间只跑 spawner 的 child_entry 与 w2_child_launch（spawner L49–52；child L38–119），任一步失败走 FAIL 后 _exit(125)、不 exec（child L113–119）；NB-AA-04 只主张这一点（审核一，Codex 意见 R5），窗口里其他主体能施加的作用是下一项 | spawner；child；NB-AA-04 | 不测：只读源码 |
| 构造窗口里其他主体对 child 的作用（干扰义务，交 PS 与 LC） | 未定 | [R] 已找到的作用路径（审核一，Claude 意见 8、Codex 意见 R5）：按 pid 发信号够不到 child，它在新 pid namespace 里，其他 execution 的 namespace 里没有它的号；按进程组发信号够得到：child 留在 spawner 的进程组与会话里（NB-DI-10），kill(0) 遍历整个进程组、不分 pid namespace（kernel/signal.c::__kill_pgrp_info）；权限按 uid 判，降权前 child 是 uid 0、降权后是 u，同 uid 没有别的活 execution（spawner L87–92，前提 NB-AA-05），但同一会话里的 SIGCONT 不按 uid 判（kernel/signal.c::check_kill_permission；01 附表 kill 一行），所以其他 execution 能把 SIGCONT 送到 child；SIGCONT 到达时清掉挂起的停止信号、唤醒已停止的线程（kernel/signal.c::prepare_signal）；child 是新 pid namespace 的 init，带 SIGNAL_UNKILLABLE（kernel/fork.c::copy_process），处置为默认的信号对它不排队（kernel/signal.c::sig_task_ignored），而 cell 与 spawner 都不装信号处理函数（cell L13–55；spawner L400–402），child 的处置只有默认与忽略两种；kernel 发给孤儿进程组的 SIGHUP 与 SIGCONT（NB-E-P-03）同样到达这个进程组；全机汇总状态（内存、pid 号、共享 btrfs 空间）被占用时构造可以失败，失败走 FAIL、不 execve。这些作用会不会改变 execve 时的状态，作为干扰义务由 PS 章在 NB-E-S-kill × NB-N-07 与 NB-E-P-03 × NB-N-07 的格、LC 章在 NB-K-03…10 的格（为另一个 execution 构造，§1.3）判定，判定后回填本项 | kernel/signal.c；kernel/fork.c；spawner；cell；NB-DI-10；NB-AA-05；NB-E-P-03；NB-E-S-kill；NB-N-07；NB-K-03；NB-K-10 | 不测：判定在 PS、LC 章 |

### 2.4 攻击者塑造过的先前状态

| 初态项 | 记录 | 依据 | 依赖 | 测试 |
|---|---|---|---|---|
| 前任 execution 写下的 /work | 成立 | [R] 后继的构造只核工作区子卷根（catalog L366–376：btrfs、dev、ino、owner、0700），不读其中内容；L 里没有 mkdir、symlink、link、rename、mknod、chmod、chown 与改 xattr 的调用，前任在 /work 里只能建与写普通文件、给出创建时的权限位（受 umask），改不了子卷根的 owner 与权限；创建时给的 setuid 位在 nosuid 挂载上无效（child L32）；内容被后继读到是交付物的预期行为（NB-X-08） | catalog；child；NB-K-15；NB-X-08；L（整表） | 不测：后继的测试在 LC 章 |
| 并发 execution 占用共享 btrfs | 成立 | [R] 副本创建前 worker 核 fstatvfs 的可用空间不少于副本大小加最小余量（storage L240–246），不够就让这次 spawn 失败；空间与事务是汇总状态，不给出新的引用；可用性一面按 README §6 归宿主层面的拒绝服务（NB-X-04） | storage；NB-X-04；NB-DI-27 | 不测：可用性不测（TESTING 运行规则 4） |
| 前任或旧 epoch 留下的同 uid 任务 | 成立 | [R] 准入要求同工作区的前一个记录已置空（spawner L87–92），置空要求 PID 1 已回收，而 PID 1 死后 ns 内全部被杀（kernel/pid_namespace.c::zap_pid_ns_processes）；epoch 更换时 supervisor 写 cgroup.kill 并等 populated 0（NB-K-16）；uid 不复用于宿主是前提 NB-AA-05 | spawner；kernel/pid_namespace.c；NB-K-16；NB-AA-05；NB-AA-06 | 不测：在 LC 章 |

### 2.5 可信方持有的引用

| 初态项 | 记录 | 依据 | 依赖 | 测试 |
|---|---|---|---|---|
| spawner | 成立 | [R] spawner 持 child_pid，只用于 kill 与 waitpid（spawner L344–395），PID 1 回收之前这个号不会被复用；交接前持 channel 的 engine 端，交接后关闭（spawner L251）；spawner.c 全文没有打开 /proc/\<pid\> 的代码，child 的挂载、tmpfs 与 namespace 没有 fd 留在 spawner | spawner；NB-S-05；NB-PV-01；NB-PV-08 | 不测：只读源码 |
| engine | 成立 | [R] engine 持 channel 的对端；channel 上的接收走 w2_frame_receive → w2_recv_credential（transport.c L212–240、L151–161），以 credentials=true 调 w2_ancillary（L158、L160），这条路径把收到的 SCM_RIGHTS 全部关闭（L119–120）；w2_ancillary 里把唯一一个 fd 交给调用者的分支（L121）只在 credentials=false 时走，调用方是控制通道上的 w2_recv_control（L135–146；engine 经 ffi.py L62 用它从 spawner 收 spawn_prepared 与其中的 channel 端，spawner.c L139 也用它）以及 w2_recv_fixed（L193–208，收到 fd 即关闭并报错），后者是构造握手时 child 在 fd 3 上收 COMMIT 用的（child.c L109）。三处要分开（定向复核改正）：控制通道上的 w2_recv_control 可以交出一个 fd；构造握手的 w2_recv_fixed 与运行期 engine 接收 agent 数据的 w2_frame_receive 都把收到的 fd 关闭；engine 发送不带辅助数据（transport.c L247–260），不把任何 fd 转交出去 | transport.c；ffi.py；spawner；child；NB-S-04；NB-PV-04；NB-PV-08 | 不测：在 NI 章测 |
| 文件 worker | 成立 | [R] worker 只持 store、seed 与副本作业的 fd（storage L194–270），副本删除后关闭（catalog L431–493）；不持 execution 的 fd、挂载与进程引用 | storage；catalog；NB-S-06 | 不测：只读源码 |
| 启动器与 supervisor | 成立 | [R] 启动器 exec 成 engine 后不再存在（cell L54）；supervisor 只持 cell cgroup，它的正确行为是前提（NB-AA-07） | cell；NB-S-07；NB-S-08；NB-AA-07 | 不测：前提 |
| w2-recover（NB-S-16） | 成立 | [R] w2-recover 与 spawner 对 store.lock 都取 LOCK_EX 与 LOCK_NB（storage L266、L308）：任一 execution 构造与运行期间 spawner 持着这把锁，w2-recover 取不到就返回失败（recover L12–14）；它在 epoch 更换之后由部署方运行，"supervisor 已确认旧域为空"是前提（NB-AA-07）：recover L8–9 只检查命令行里有没有这个标志，L15 写明这一点由 supervisor 提供、程序不推断（定向复核改正）；它打开的只有目录、store 与 objects 下的副本根（storage L307–340），不持任何 execution 的 fd、挂载或进程引用（审核一，Claude 意见 9） | recover；storage；NB-S-16；NB-K-16；NB-AA-07 | 不测：只读源码 |
| core dump 处理程序（NB-S-09） | 成立 | [R] 只在 kernel 走管道式 core_pattern 时由 kernel 启动并经管道收到 core；本 execution 的 RLIMIT_CORE 软硬都是 1，kernel 在调用它之前放弃（fs/coredump.c::do_coredump；child L103；NB-E-K-01），所以初态时它不持本 execution 的任何引用；它会读到什么由 NB-N-12 列的格判（审核一，Claude 意见 9） | fs/coredump.c；child；NB-S-09；NB-E-K-01；NB-N-12 | NB-EV-016（core 上限 1 1） |
| 宿主清理与备份（NB-S-15）：构造不交给它引用 | 成立 | [R] 不在基线快照内，由部署方安排（NB-S-10）；spawner 与 child 里没有与它交互的代码，构造不把任何 fd、挂载或进程引用交给它；它之后读到的、由 execution 塑造的状态由 NB-N-10 列的格判，它自己的行为是部署前提（NB-AA-07；审核一，Claude 意见 9） | spawner；child；NB-S-15；NB-S-10；NB-N-10；NB-AA-07 | 不测：只读源码 |
| 宿主观测组件（NB-S-17）：构造不交给它引用 | 成立 | [R] 不在基线快照内，spawner 与 child 里没有与它交互的代码，构造不把任何 fd、挂载或进程引用交给它。它运行期从 kernel 收到什么交 NB-E-K-09 × N-13 等格判，这里只记已核的两件事（第三次定向复核改写）：一个文件事件分派给在这个文件的 inode、所在目录、所在挂载或所在文件系统上设了标记的每个组（fs/notify/fsnotify.c::fsnotify），收到哪些事件由标记的有效覆盖范围决定，对目录设的 inode 标记也收目录里子项的事件；分派时带的是访问者那个 file 的路径（include/linux/fsnotify.h::fsnotify_file），fanotify 读事件时以读者的凭据按事件里的路径开 fd（fs/notify/fanotify/fanotify_user.c::create_fd）。fanotify 只对路径型事件（组不是 FID 模式、对象是普通文件或目录：fs/notify/fanotify/fanotify.c::fanotify_group_event_mask，筛选在分配事件之前）存下这个路径并取引用（fs/notify/fanotify/fanotify.c::fanotify_alloc_path_event），所以这类事件在队列里时就钉住事件所经的 execution 挂载，读出后开的 fd 同样钉住它；在本配置下是 /work 与 /runtime 的 bind（这个范围是结合构造与前提得出的，条件写在 01 NB-E-K-09，不是本项的依据），/dev 下四个字符设备不产生这类事件。FID 模式的事件走另一分支，引用种类在 NB-E-K-09 × N-13 的格里核；事件附带的 pidfd 只保留 struct pid 的身份引用，不保活任务或地址空间（第四次定向复核改正）。谁能设什么标记、谁能收到带 fd 的事件，写在 01 §6.1 的前提里，这里不展开；记录里由 execution 设定的字段由 NB-N-13 列的格判，它们读到之后怎样做是部署前提（NB-AA-07） | spawner；child；fs/notify/fsnotify.c；include/linux/fsnotify.h；fs/notify/fanotify/fanotify_user.c；fs/notify/fanotify/fanotify.c；NB-S-17；NB-E-K-09；NB-N-13；NB-AA-07 | 不测：只读源码 |

### 2.6 NB-AA 的分配

| NB-AA | 分到 | 落在哪里 |
|---|---|---|
| NB-AA-01 源树无替换 | 前提清单（部署方离线准备、运行期不改；代码用身份比对把窗口缩到比对与 bind 之间，窗口里只有 root 能替换） | §2.1 /work 与 /runtime 两项；§2.3 NB-K-07 |
| NB-AA-02 源树无子挂载 | 前提清单（部署方） | §2.1 挂载表与 /runtime 两项；§2.2 NB-DI-21；§2.3 NB-K-07 |
| NB-AA-03 无共享的可写映射 | 初态对代码核 | §2.1 execve 之后的地址空间一项 |
| NB-AA-04 可信代码段 | 初态对代码核（只主张这一段只跑可信代码） | §2.3 构造窗口只跑可信代码一项；窗口里其他主体的作用是另一项，记未定，作为干扰义务交 PS、LC |
| NB-AA-05 池独占与 uid 不复用于宿主 | 前提清单（部署方；uid 线 T-67 的前提，1.1 沿用） | §2.3 NB-K-03 与构造窗口两项；§2.4 同 uid 残留一项 |
| NB-AA-06 cell cgroup | 拆成两半：cell 由宿主 init 放进独占 cgroup 是前提清单（supervisor）；agent 迁不出对代码核 | §2.1 cgroup 成员一项；§2.3 NB-K-03；§2.4 同 uid 残留一项 |
| NB-AA-07 可信方不受攻击者控制、不作恶 | 前提清单只含 hypervisor 与固件、supervisor、离线部署方；engine、spawner、文件 worker、启动器、w2-recover 的代码由基线快照以 [R] 核（本节各项与各章） | §2.5 启动器与 supervisor、w2-recover、宿主清理与备份、宿主观测组件各项 |
| NB-AA-08 宿主特权进程不取用、不读写私有候选 | 前提清单（部署方；约束对象写成保守上界，见 01 §6.1）：基线快照之外、凭据能通过或能换到通过对 execution 任务的 ptrace 访问检查的宿主进程，以及持有特权 fanotify 组的进程，不经任何途径取用或读取 execution 的私有候选；部署方列出这些进程逐个核 | 不在初态表里：初态只证构造交出了什么（§2.5）。它落在私有的判断上：01 §2.6 里宿主要特权才碰得到的部分与 NB-PV-02；第二块各章记"私有"的格在依赖里写 NB-AA-08（§3.7）。宿主不要特权就看得到的部分不靠它，按 01 §2.6 的规则算宿主可观察 |
| NB-AA-09 宿主不打开用户态读性能计数器 | 前提清单（部署方，用户 2026-10-27）：rdpmc 的 sysfs 值不设为 2（见 01 §6.1） | 不在初态表里：落在 RDPMC 的去向上（01-trace-events §3.4）；默认值下 execution 执行 RDPMC 触发 #GP |

**部署条件（不是前提，取值要读）。** 继承自启动器父进程的 rlimit、umask、信号处置、loginuid 与控制终端（NB-MM-01、02、04、05），以及 TSC 禁用标志（§2.1，第二次定向复核补），不影响初态的
I1–I3，但影响各格的候选效果；它们的生产取值与宿主读数的待查项（01-trace-events §7）在 GS 章与汇总的部署限制里写。

**S1 补充交来的项。** 去向表移交的初态断言：§2.1 地址空间一项；两处事实改正：§2.1 pdeath_signal 与 loginuid 两项（01 v8、附表 v5）；
NB-AA-01、NB-AA-02：§2.6。

## 3 坏事件的分解（主干·下）

**用途。** 把 01 的每一行 × 每一列分成分支，每个分支归一章写格（PLAN §1.2 的规则）；不成分支的（行，列）由不适用项或列的不适用规则覆盖。
`check_coverage.py --stage backbone` 机械核对覆盖；规则与理由是否成立由审核一核。多路复用的调用拆成子操作行，子操作取自基线 kernel 的分派
位置（§3.3）；附表之外新导出的取值与 /OTHER 行已按追踪规则补追（01-trace-events §8），没有新的四族事件。

### 3.1 L 的入口与 ABI 入口

**L 的 74 个允许入口。** 取自基线快照 run_sandbox_checks.py 第 117–130 行的诊断白名单，与 01 §3.1 的名单逐个一致；每个入口落在附表的
恰好一行（2026-10-25 用脚本核对：74 个入口、45 行，没有缺的、没有重复的）。

| 01 的行 | L 的入口 |
|---|---|
| NB-E-S-openat | openat |
| NB-E-S-read | read、readv |
| NB-E-S-write | write、writev |
| NB-E-S-close | close |
| NB-E-S-fstat | fstat、newfstatat、statx |
| NB-E-S-lseek | lseek |
| NB-E-S-access | access、faccessat2 |
| NB-E-S-getdents64 | getdents64 |
| NB-E-S-readlink | readlink、readlinkat |
| NB-E-S-chdir | chdir |
| NB-E-S-getcwd | getcwd |
| NB-E-S-fsync | fsync、fdatasync |
| NB-E-S-execve | execve |
| NB-E-S-mmap | mmap |
| NB-E-S-mprotect | mprotect |
| NB-E-S-munmap | munmap |
| NB-E-S-brk | brk |
| NB-E-S-madvise | madvise |
| NB-E-S-clone | clone |
| NB-E-S-unshare | unshare |
| NB-E-S-exit | exit、exit_group |
| NB-E-S-wait4 | wait4、waitid |
| NB-E-S-kill | kill |
| NB-E-S-tgkill | tgkill |
| NB-E-S-setsid | setsid |
| NB-E-S-rt_sigaction | rt_sigaction、rt_sigprocmask、rt_sigreturn、sigaltstack、pause、restart_syscall |
| NB-E-S-getpid | getpid、getppid、gettid |
| NB-E-S-getuid | getuid、geteuid、getgid、getegid、getresuid、getresgid、getgroups |
| NB-E-S-setuid | setuid |
| NB-E-S-prlimit64 | prlimit64 |
| NB-E-S-prctl | prctl |
| NB-E-S-arch_prctl | arch_prctl |
| NB-E-S-set_tid_address | set_tid_address、set_robust_list、rseq |
| NB-E-S-futex | futex |
| NB-E-S-sendmsg | sendmsg、sendto |
| NB-E-S-recvmsg | recvmsg、recvfrom |
| NB-E-S-getsockopt | getsockopt |
| NB-E-S-getsockname | getsockname、getpeername |
| NB-E-S-shutdown | shutdown |
| NB-E-S-poll | poll、ppoll |
| NB-E-S-clock_gettime | clock_gettime |
| NB-E-S-nanosleep | nanosleep、clock_nanosleep |
| NB-E-S-getrandom | getrandom |
| NB-E-S-uname | uname |
| NB-E-S-fcntl | fcntl |

**ABI 入口。** 用户态进入 kernel 的入口除 x86_64 的 syscall 指令外还有以下几条，逐条写去向。

| 入口 | 去向 | 依据 |
|---|---|---|
| x86_64 的 syscall 指令 | 上表的各行，过滤器按调用号判 | policy L13–67；kernel/seccomp.c::__seccomp_filter |
| int 0x80、32 位模式下的 syscall，以及 sysenter（不论从哪种模式执行，都进 32 位兼容入口：arch/x86/kernel/cpu/common.c::syscall_init、arch/x86/entry/common.c::do_SYSENTER_32；2026-10-27 补） | 过滤器按架构不符杀进程（SCMP_ACT_KILL_PROCESS），走 NB-E-K-01 | policy L35；arch/x86/kernel/idt.c::def_idts；NB-EV-015 |
| x32 调用号（带 __X32_SYSCALL_BIT） | 同上，被杀 | policy L35；NB-EV-015 |
| vsyscall 页（vsyscall=none） | 不是入口：访问缺页，打日志后按无效访问发 SIGSEGV（01-trace-events §3.1） | arch/x86/entry/vsyscall/vsyscall_64.c::emulate_vsyscall |
| 异常向量 | 不是系统调用入口：逐个向量在 01-trace-events §3.1 | arch/x86/kernel/idt.c::def_idts |

### 3.2 第 4 步的可信方列

SPEC §4.2 第 4 步：execution 在交付对象里塑造、由非 engine 的可信方之后读取或操作的状态，每个可信方一列。NB-N-09…11 取自 01-trace-events §7
交来的项，NB-N-12 是 core dump 处理程序；NB-N-13 是审核一加的（2026-10-26）：宿主上读 kernel 送出的记录与事件的组件，METHOD 规则 2
把它们算作之后作用于 execution 塑造的状态的可信方，它们自己的行为按 SPEC §5.1 写成部署前提（01 NB-S-17、NB-AA-07）。

| 列 ID | 可信方 | 它之后解引用的、由 execution 塑造的状态 | 来源 |
|---|---|---|---|
| NB-N-09 | 后继 execution（NB-S-03）的构造与运行（NB-K-15） | 前一个 execution 留在工作区里的内容与元数据：文件、权限位、时间戳；后继的构造只核子卷根 | 01-trace-events §7；SPEC §4.2 第 4 步 |
| NB-N-10 | 宿主清理与备份（NB-S-15） | 工作区里的内容与元数据；打开工作区文件时遇到的记录锁与租约 | 同上 |
| NB-N-11 | supervisor（NB-S-08） | cell cgroup 的 populated（由 cell 里任务的创建与退出决定）与 cgroup.kill 的作用对象 | 同上；NB-K-16 |
| NB-N-12 | 宿主 core dump 处理程序（NB-S-09） | 管道式 core_pattern 下送给它的 core 内容；RLIMIT_CORE 为 1 时 kernel 在调用它之前放弃（NB-E-K-01） | SPEC §4.2 第 4 步 |
| NB-N-13 | 宿主观测组件（NB-S-17），定义与 01 §1 NB-S-17 相同：部署方安装、读 kernel 送出的记录与事件或读 execution 的 /proc 条目、其处理方式作为部署前提的组件；不是部署方安装的宿主进程与用户属 NB-S-14，在 N-06 的格判（两次定向复核改正） | kernel 送给它们的记录与事件里由 execution 设定的字段：comm、exe 路径、退出码、loginuid 与 sessionid、文件名与事件种类；fanotify 权限事件要它答复后操作才继续 | 审核一（Claude 意见 5）；METHOD 规则 2；01-trace-events §5 NB-E-K-09…14 |

### 3.3 子操作表

| 调用行 | 子操作行 | 分派位置 | 包含的取值 |
|---|---|---|---|
| NB-E-S-fcntl | NB-E-S-fcntl/F_DUPFD | fs/fcntl.c::do_fcntl：case F_DUPFD、F_DUPFD_CLOEXEC → fs/file.c::f_dupfd | F_DUPFD_CLOEXEC |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETFD | fs/fcntl.c::do_fcntl：case F_GETFD、F_SETFD | F_GETFD |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETFL | fs/fcntl.c::do_fcntl：case F_GETFL、F_SETFL → fs/fcntl.c::setfl | F_GETFL |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETLK | fs/fcntl.c::do_fcntl：case F_GETLK、F_SETLK、F_SETLKW、F_OFD_* → fs/locks.c::fcntl_getlk、fs/locks.c::fcntl_setlk | F_GETLK、F_SETLKW、F_OFD_GETLK、F_OFD_SETLK、F_OFD_SETLKW |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETOWN | fs/fcntl.c::do_fcntl：case F_GETOWN、F_SETOWN、F_GETOWN_EX、F_SETOWN_EX、F_GETOWNER_UIDS → fs/fcntl.c::f_setown、fs/fcntl.c::f_setown_ex | F_GETOWN、F_GETOWN_EX、F_SETOWN_EX、F_GETOWNER_UIDS |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETSIG | fs/fcntl.c::do_fcntl：case F_GETSIG、F_SETSIG | F_GETSIG |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETLEASE | fs/fcntl.c::do_fcntl：case F_GETLEASE、F_SETLEASE → fs/locks.c::fcntl_setlease | F_GETLEASE |
| NB-E-S-fcntl | NB-E-S-fcntl/F_NOTIFY | fs/fcntl.c::do_fcntl：case F_NOTIFY → fs/notify/dnotify/dnotify.c::fcntl_dirnotify | — |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SETPIPE_SZ | fs/fcntl.c::do_fcntl：case F_SETPIPE_SZ、F_GETPIPE_SZ（对非 pipe 返回错误） | F_GETPIPE_SZ |
| NB-E-S-fcntl | NB-E-S-fcntl/F_ADD_SEALS | fs/fcntl.c::do_fcntl：case F_ADD_SEALS、F_GET_SEALS（只对 memfd 有效） | F_GET_SEALS |
| NB-E-S-fcntl | NB-E-S-fcntl/F_SET_RW_HINT | fs/fcntl.c::do_fcntl：case F_GET_RW_HINT、F_SET_RW_HINT → fs/fcntl.c::fcntl_rw_hint | F_GET_RW_HINT |
| NB-E-S-fcntl | NB-E-S-fcntl/OTHER | fs/fcntl.c::do_fcntl：default：返回 EINVAL | 其余 cmd |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_NAME | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_NAME、PR_GET_NAME | PR_GET_NAME |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_PDEATHSIG | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_PDEATHSIG、PR_GET_PDEATHSIG | PR_GET_PDEATHSIG |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_CHILD_SUBREAPER | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_CHILD_SUBREAPER、PR_GET_CHILD_SUBREAPER | PR_GET_CHILD_SUBREAPER |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_DUMPABLE | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_DUMPABLE、PR_GET_DUMPABLE | PR_GET_DUMPABLE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_PTRACER | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：Yama：security/yama/yama_lsm.c::yama_task_prctl | PR_SET_PTRACER_ANY |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_TIMERSLACK | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_TIMERSLACK、PR_GET_TIMERSLACK | PR_GET_TIMERSLACK |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_THP_DISABLE | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_THP_DISABLE、PR_GET_THP_DISABLE | PR_GET_THP_DISABLE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_SPECULATION_CTRL | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_SPECULATION_CTRL、PR_GET_SPECULATION_CTRL → arch/x86/kernel/cpu/bugs.c::arch_prctl_spec_ctrl_set | PR_GET_SPECULATION_CTRL |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_SYSCALL_USER_DISPATCH | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_SYSCALL_USER_DISPATCH → kernel/entry/syscall_user_dispatch.c::set_syscall_user_dispatch | — |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_VMA | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_VMA（CONFIG_ANON_VMA_NAME 未开，返回 EINVAL） | — |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_MDWE | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_MDWE、PR_GET_MDWE | PR_GET_MDWE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_SECCOMP | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_SECCOMP、PR_GET_SECCOMP → kernel/seccomp.c::prctl_set_seccomp | PR_GET_SECCOMP |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_NO_NEW_PRIVS | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_NO_NEW_PRIVS、PR_GET_NO_NEW_PRIVS | PR_GET_NO_NEW_PRIVS |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_KEEPCAPS | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：commoncap：security/commoncap.c::cap_task_prctl 的 PR_SET_KEEPCAPS、PR_GET_KEEPCAPS | PR_GET_KEEPCAPS |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_TSC | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_TSC、PR_GET_TSC → arch/x86/kernel/process.c::set_tsc_mode | PR_GET_TSC |
| NB-E-S-prctl | NB-E-S-prctl/PR_MCE_KILL | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_MCE_KILL、PR_MCE_KILL_GET | PR_MCE_KILL_GET、PR_MCE_KILL_CLEAR、PR_MCE_KILL_SET |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_FP_MODE | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：x86 上返回 EINVAL 的架构专用取值（sys.c 里各自的默认宏） | PR_GET_FP_MODE、PR_SET_UNALIGN、PR_GET_UNALIGN、PR_SET_FPEMU、PR_GET_FPEMU、PR_SET_FPEXC、PR_GET_FPEXC、PR_SET_ENDIAN、PR_GET_ENDIAN、PR_MPX_ENABLE_MANAGEMENT、PR_MPX_DISABLE_MANAGEMENT、PR_SVE_SET_VL、PR_SVE_GET_VL、PR_SME_SET_VL、PR_SME_GET_VL、PR_PAC_RESET_KEYS、PR_PAC_SET_ENABLED_KEYS、PR_PAC_GET_ENABLED_KEYS、PR_SET_TAGGED_ADDR_CTRL、PR_GET_TAGGED_ADDR_CTRL、PR_RISCV_V_SET_CONTROL、PR_RISCV_V_GET_CONTROL |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_MM | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：需要 CAP_SYS_RESOURCE 的取值：case PR_SET_MM → kernel/sys.c::prctl_set_mm 里 PR_SET_MM_MAP、PR_SET_MM_MAP_SIZE 之外的 arg2（能力检查失败返回 EPERM）；case PR_SET_IO_FLUSHER、PR_GET_IO_FLUSHER | PR_SET_IO_FLUSHER、PR_GET_IO_FLUSHER |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_MM_MAP | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_MM → kernel/sys.c::prctl_set_mm：arg2 为 PR_SET_MM_MAP、PR_SET_MM_MAP_SIZE 时在能力检查之前转到 kernel/sys.c::prctl_set_mm_map（CONFIG_CHECKPOINT_RESTORE=y） | PR_SET_MM_MAP_SIZE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_MEMORY_MERGE | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_MEMORY_MERGE → mm/ksm.c::ksm_enable_merge_any、mm/ksm.c::ksm_disable_merge_any（不检查能力）；case PR_GET_MEMORY_MERGE | PR_GET_MEMORY_MERGE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_SECUREBITS | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：commoncap：PR_SET_SECUREBITS、PR_CAPBSET_DROP 需要 CAP_SETPCAP；PR_CAP_AMBIENT 的 RAISE 需要该能力已在 permitted 与 inheritable 里 | PR_GET_SECUREBITS、PR_CAPBSET_DROP、PR_CAPBSET_READ、PR_CAP_AMBIENT |
| NB-E-S-prctl | NB-E-S-prctl/PR_SCHED_CORE | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SCHED_CORE（CONFIG_SCHED_CORE 未开，返回 EINVAL） | PR_SCHED_CORE_CREATE、PR_SCHED_CORE_SHARE |
| NB-E-S-prctl | NB-E-S-prctl/PR_SET_TIMING | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_SET_TIMING、PR_GET_TIMING（只接受 PR_TIMING_STATISTICAL） | PR_GET_TIMING |
| NB-E-S-prctl | NB-E-S-prctl/PR_TASK_PERF_EVENTS_DISABLE | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：case PR_TASK_PERF_EVENTS_DISABLE、PR_TASK_PERF_EVENTS_ENABLE（作用于本任务自己建的 perf 事件） | PR_TASK_PERF_EVENTS_ENABLE |
| NB-E-S-prctl | NB-E-S-prctl/PR_GET_AUXV | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：只读本任务或本 mm 的取值：case PR_GET_AUXV、PR_GET_TID_ADDRESS | PR_GET_TID_ADDRESS |
| NB-E-S-prctl | NB-E-S-prctl/OTHER | kernel/sys.c::SYSCALL_DEFINE5(prctl)，先经 LSM 钩子 security/commoncap.c::cap_task_prctl 与 security/yama/yama_lsm.c::yama_task_prctl：default：返回 EINVAL | 其余 option |
| NB-E-S-futex | NB-E-S-futex/FUTEX_WAIT | kernel/futex/syscalls.c::do_futex（FUTEX_PRIVATE_FLAG、FUTEX_CLOCK_REALTIME 是修饰位）：case FUTEX_WAIT、FUTEX_WAIT_BITSET → kernel/futex/waitwake.c::futex_wait | FUTEX_WAIT_BITSET |
| NB-E-S-futex | NB-E-S-futex/FUTEX_WAKE | kernel/futex/syscalls.c::do_futex（FUTEX_PRIVATE_FLAG、FUTEX_CLOCK_REALTIME 是修饰位）：case FUTEX_WAKE、FUTEX_WAKE_BITSET → kernel/futex/waitwake.c::futex_wake | FUTEX_WAKE_BITSET |
| NB-E-S-futex | NB-E-S-futex/FUTEX_REQUEUE | kernel/futex/syscalls.c::do_futex（FUTEX_PRIVATE_FLAG、FUTEX_CLOCK_REALTIME 是修饰位）：case FUTEX_REQUEUE、FUTEX_CMP_REQUEUE → kernel/futex/requeue.c::futex_requeue | FUTEX_CMP_REQUEUE |
| NB-E-S-futex | NB-E-S-futex/FUTEX_WAKE_OP | kernel/futex/syscalls.c::do_futex（FUTEX_PRIVATE_FLAG、FUTEX_CLOCK_REALTIME 是修饰位）：case FUTEX_WAKE_OP → kernel/futex/waitwake.c::futex_wake_op | — |
| NB-E-S-futex | NB-E-S-futex/FUTEX_LOCK_PI | kernel/futex/syscalls.c::do_futex（FUTEX_PRIVATE_FLAG、FUTEX_CLOCK_REALTIME 是修饰位）：case FUTEX_LOCK_PI、FUTEX_LOCK_PI2、FUTEX_TRYLOCK_PI、FUTEX_UNLOCK_PI → kernel/futex/pi.c::futex_lock_pi、kernel/futex/pi.c::futex_unlock_pi | FUTEX_LOCK_PI2、FUTEX_TRYLOCK_PI、FUTEX_UNLOCK_PI |
| NB-E-S-futex | NB-E-S-futex/FUTEX_WAIT_REQUEUE_PI | kernel/futex/syscalls.c::do_futex（FUTEX_PRIVATE_FLAG、FUTEX_CLOCK_REALTIME 是修饰位）：case FUTEX_WAIT_REQUEUE_PI、FUTEX_CMP_REQUEUE_PI → kernel/futex/requeue.c::futex_wait_requeue_pi | FUTEX_CMP_REQUEUE_PI |
| NB-E-S-futex | NB-E-S-futex/OTHER | kernel/futex/syscalls.c::do_futex（FUTEX_PRIVATE_FLAG、FUTEX_CLOCK_REALTIME 是修饰位）：其余 op：返回 ENOSYS | 其余 op |
| NB-E-S-clone | NB-E-S-clone/CSIGNAL | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：每次创建的共同部分，不论带哪些标志（分配各层 pid、计入 per-uid 与 cell cgroup 的计数、连接器与跟踪设施的记录、子任务的首次运行；01-trace-events §1.3"clone 共同部分"一行），以及低 8 位的 exit_signal；各标志位另加的作用在下面各行 | exit_signal |
| NB-E-S-clone | NB-E-S-clone/CLONE_VM | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：共享与 TLS 类标志位 | CLONE_FILES、CLONE_FS、CLONE_SIGHAND、CLONE_THREAD、CLONE_SYSVSEM、CLONE_IO、CLONE_SETTLS |
| NB-E-S-clone | NB-E-S-clone/CLONE_PARENT_SETTID | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：写 tid 的标志位：kernel_clone 写 parent_tid，schedule_tail 写 child_tid | CLONE_CHILD_SETTID |
| NB-E-S-clone | NB-E-S-clone/CLONE_CHILD_CLEARTID | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：登记 clear_child_tid | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_VFORK | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：父任务等待子任务 exec 或退出 | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_PIDFD | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：在调用者 fd 表里装 pidfd | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_PARENT | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：父进程取调用者的父进程；ns init 调用返回 EINVAL | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_NEWNS | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：新建 namespace 的标志位：kernel/nsproxy.c::copy_namespaces 要求 CAP_SYS_ADMIN | CLONE_NEWPID、CLONE_NEWNET、CLONE_NEWIPC、CLONE_NEWUTS、CLONE_NEWCGROUP、CLONE_NEWTIME |
| NB-E-S-clone | NB-E-S-clone/CLONE_NEWUSER | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：过滤器在入口拒绝（policy L46–49） | — |
| NB-E-S-clone | NB-E-S-clone/CLONE_PTRACE | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：跟踪相关位：调用者没有被跟踪时无效果 | CLONE_UNTRACED |
| NB-E-S-clone | NB-E-S-clone/OTHER | kernel/fork.c::SYSCALL_DEFINE5(clone) → kernel/fork.c::kernel_clone → kernel/fork.c::copy_process（按标志位分支）：其余位：CLONE_DETACHED 被忽略；非法组合在 copy_process 开头返回 EINVAL | 其余位 |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_FILES | kernel/fork.c::ksys_unshare（kernel/fork.c::check_unshare_flags 只接受下列位）：kernel/fork.c::unshare_fd、kernel/fork.c::unshare_fs | CLONE_FS |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_SYSVSEM | kernel/fork.c::ksys_unshare（kernel/fork.c::check_unshare_flags 只接受下列位）：执行本任务的 SysV 信号量撤销 | — |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_NEWNS | kernel/fork.c::ksys_unshare（kernel/fork.c::check_unshare_flags 只接受下列位）：新建 namespace 的位：需要 CAP_SYS_ADMIN | CLONE_NEWPID、CLONE_NEWNET、CLONE_NEWIPC、CLONE_NEWUTS、CLONE_NEWCGROUP、CLONE_NEWTIME |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_NEWUSER | kernel/fork.c::ksys_unshare（kernel/fork.c::check_unshare_flags 只接受下列位）：过滤器在入口拒绝（policy L46–49） | — |
| NB-E-S-unshare | NB-E-S-unshare/CLONE_THREAD | kernel/fork.c::ksys_unshare（kernel/fork.c::check_unshare_flags 只接受下列位）：只在不共享时接受（单线程、mm 与 sighand 不共享），否则 EINVAL | CLONE_SIGHAND、CLONE_VM |
| NB-E-S-unshare | NB-E-S-unshare/OTHER | kernel/fork.c::ksys_unshare（kernel/fork.c::check_unshare_flags 只接受下列位）：其余位：返回 EINVAL | 其余位 |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_PEERCRED | net/socket.c::__sys_getsockopt：level 为 SOL_SOCKET 时 net/core/sock.c::sk_getsockopt，其余 level 对 AF_UNIX 返回 EOPNOTSUPP：对端身份：case SO_PEERCRED、SO_PEERGROUPS、SO_PEERSEC、SO_PEERNAME | SO_PEERGROUPS、SO_PEERSEC、SO_PEERNAME |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_PEERPIDFD | net/socket.c::__sys_getsockopt：level 为 SOL_SOCKET 时 net/core/sock.c::sk_getsockopt，其余 level 对 AF_UNIX 返回 EOPNOTSUPP：case SO_PEERPIDFD：为 sk_peer_pid 装一个 pidfd 到调用者的 fd 表（kernel/fork.c::pidfd_prepare） | — |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_COOKIE | net/socket.c::__sys_getsockopt：level 为 SOL_SOCKET 时 net/core/sock.c::sk_getsockopt，其余 level 对 AF_UNIX 返回 EOPNOTSUPP：全局编号：case SO_COOKIE（首次读时分配）、SO_NETNS_COOKIE | SO_NETNS_COOKIE |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_ERROR | net/socket.c::__sys_getsockopt：level 为 SOL_SOCKET 时 net/core/sock.c::sk_getsockopt，其余 level 对 AF_UNIX 返回 EOPNOTSUPP：case SO_ERROR：读出并清零本端错误 | — |
| NB-E-S-getsockopt | NB-E-S-getsockopt/SO_TYPE | net/socket.c::__sys_getsockopt：level 为 SOL_SOCKET 时 net/core/sock.c::sk_getsockopt，其余 level 对 AF_UNIX 返回 EOPNOTSUPP：只读本端属性 | SO_DOMAIN、SO_PROTOCOL、SO_SNDBUF、SO_RCVBUF、SO_INCOMING_CPU、SO_PASSCRED、SO_MEMINFO |
| NB-E-S-getsockopt | NB-E-S-getsockopt/OTHER | net/socket.c::__sys_getsockopt：level 为 SOL_SOCKET 时 net/core/sock.c::sk_getsockopt，其余 level 对 AF_UNIX 返回 EOPNOTSUPP：SOL_SOCKET 的其余选项与其余 level | SOL_SOCKET 的其余 47 个选项（取自 sk_getsockopt 的 case 标签，审核一 2026-10-26 列出）：SO_DEBUG、SO_DONTROUTE、SO_BROADCAST、SO_REUSEADDR、SO_REUSEPORT、SO_KEEPALIVE、SO_OOBINLINE、SO_NO_CHECK、SO_PRIORITY、SO_LINGER、SO_BSDCOMPAT、SO_TIMESTAMP_OLD、SO_TIMESTAMPNS_OLD、SO_TIMESTAMP_NEW、SO_TIMESTAMPNS_NEW、SO_TIMESTAMPING_OLD、SO_TIMESTAMPING_NEW、SO_RCVTIMEO_OLD、SO_RCVTIMEO_NEW、SO_SNDTIMEO_OLD、SO_SNDTIMEO_NEW、SO_RCVLOWAT、SO_SNDLOWAT、SO_PASSPIDFD、SO_ACCEPTCONN、SO_PASSSEC、SO_MARK、SO_RCVMARK、SO_RXQ_OVFL、SO_WIFI_STATUS、SO_PEEK_OFF、SO_NOFCS、SO_BINDTODEVICE、SO_GET_FILTER、SO_LOCK_FILTER、SO_BPF_EXTENSIONS、SO_SELECT_ERR_QUEUE、SO_BUSY_POLL、SO_PREFER_BUSY_POLL、SO_MAX_PACING_RATE、SO_INCOMING_NAPI_ID、SO_ZEROCOPY、SO_TXTIME、SO_BINDTOIFINDEX、SO_BUF_LOCK、SO_RESERVE_MEM、SO_TXREHASH；其余 level |
| NB-E-S-madvise | NB-E-S-madvise/MADV_DONTNEED | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/madvise.c::madvise_dontneed_free | MADV_FREE、MADV_DONTNEED_LOCKED |
| NB-E-S-madvise | NB-E-S-madvise/MADV_HUGEPAGE | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/madvise.c::madvise_vma_behavior → mm/khugepaged.c::khugepaged_enter_vma | MADV_NOHUGEPAGE |
| NB-E-S-madvise | NB-E-S-madvise/MADV_COLLAPSE | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/khugepaged.c::madvise_collapse | — |
| NB-E-S-madvise | NB-E-S-madvise/MADV_REMOVE | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/madvise.c::madvise_remove | — |
| NB-E-S-madvise | NB-E-S-madvise/MADV_COLD | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/madvise.c::madvise_cold、mm/madvise.c::madvise_pageout | MADV_PAGEOUT |
| NB-E-S-madvise | NB-E-S-madvise/MADV_WIPEONFORK | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/madvise.c::madvise_vma_behavior 改 VMA 标志 | MADV_KEEPONFORK、MADV_DONTFORK、MADV_DOFORK |
| NB-E-S-madvise | NB-E-S-madvise/MADV_POPULATE_READ | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/madvise.c::madvise_populate | MADV_POPULATE_WRITE |
| NB-E-S-madvise | NB-E-S-madvise/MADV_HWPOISON | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/madvise.c::madvise_inject_error（需要 CAP_SYS_ADMIN） | MADV_SOFT_OFFLINE |
| NB-E-S-madvise | NB-E-S-madvise/MADV_DODUMP | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：mm/madvise.c::madvise_vma_behavior 改 VMA 标志 | MADV_DONTDUMP |
| NB-E-S-madvise | NB-E-S-madvise/MADV_WILLNEED | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：预读提示：mm/madvise.c::madvise_willneed 与 VMA 标志 | MADV_NORMAL、MADV_SEQUENTIAL、MADV_RANDOM |
| NB-E-S-madvise | NB-E-S-madvise/MADV_MERGEABLE | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：KSM 登记：mm/ksm.c::ksm_madvise | MADV_UNMERGEABLE |
| NB-E-S-madvise | NB-E-S-madvise/OTHER | mm/madvise.c::do_madvise（mm/madvise.c::madvise_behavior_valid 只接受下列取值）：其余取值：返回 EINVAL | 其余取值 |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_SET_FS | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl)：先 arch/x86/kernel/process_64.c::do_arch_prctl_64，返回 EINVAL 时再 arch/x86/kernel/process.c::do_arch_prctl_common：do_arch_prctl_64 | ARCH_SET_GS、ARCH_GET_FS、ARCH_GET_GS |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_SET_CPUID | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl)：先 arch/x86/kernel/process_64.c::do_arch_prctl_64，返回 EINVAL 时再 arch/x86/kernel/process.c::do_arch_prctl_common：do_arch_prctl_common → arch/x86/kernel/process.c::set_cpuid_mode | ARCH_GET_CPUID |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_REQ_XCOMP_PERM | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl)：先 arch/x86/kernel/process_64.c::do_arch_prctl_64，返回 EINVAL 时再 arch/x86/kernel/process.c::do_arch_prctl_common：do_arch_prctl_common → arch/x86/kernel/fpu/xstate.c::fpu_xstate_prctl | ARCH_GET_XCOMP_SUPP、ARCH_GET_XCOMP_PERM |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_REQ_XCOMP_GUEST_PERM | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl)：先 arch/x86/kernel/process_64.c::do_arch_prctl_64，返回 EINVAL 时再 arch/x86/kernel/process.c::do_arch_prctl_common：同上，客户机权限 | ARCH_GET_XCOMP_GUEST_PERM |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_MAP_VDSO_64 | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl)：先 arch/x86/kernel/process_64.c::do_arch_prctl_64，返回 EINVAL 时再 arch/x86/kernel/process.c::do_arch_prctl_common：do_arch_prctl_64 → arch/x86/entry/vdso/vma.c::map_vdso_once | ARCH_MAP_VDSO_32、ARCH_MAP_VDSO_X32 |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/ARCH_SHSTK_ENABLE | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl)：先 arch/x86/kernel/process_64.c::do_arch_prctl_64，返回 EINVAL 时再 arch/x86/kernel/process.c::do_arch_prctl_common：do_arch_prctl_64 → shstk_prctl（CONFIG_X86_USER_SHADOW_STACK 未开，返回 EINVAL） | ARCH_SHSTK_DISABLE、ARCH_SHSTK_LOCK、ARCH_SHSTK_UNLOCK、ARCH_SHSTK_STATUS |
| NB-E-S-arch_prctl | NB-E-S-arch_prctl/OTHER | arch/x86/kernel/process_64.c::SYSCALL_DEFINE2(arch_prctl)：先 arch/x86/kernel/process_64.c::do_arch_prctl_64，返回 EINVAL 时再 arch/x86/kernel/process.c::do_arch_prctl_common：其余取值返回 EINVAL（CONFIG_ADDRESS_MASKING 未开，LAM 的取值不编进去） | ARCH_GET_UNTAG_MASK、ARCH_ENABLE_TAGGED_ADDR、ARCH_FORCE_TAGGED_SVA、ARCH_GET_MAX_TAG_BITS |

### 3.4 分支表

归属章：PF 路径与文件 · NI 网络、IPC 与 engine 通道 · PS 进程与信号 · GS 未隔离的名字与全机状态 · LC 生命周期与后继 · 02 本文件（只有 NB-K-01、02：cell 启动时的构造，格在第二块开工前按 §2 的初态项补进本文件）。NB-K-03…10 的分支归 LC，
承载 spawner 在本 execution 运行期间为另一个 execution 做构造的保持与干扰义务（§1.3）。
一个（行，列）只归一章。泛用的 fd 调用（read、write、close、fstat、lseek、fsync、mmap 与 futex 的各子操作）× NB-N-02 归 PF，它们的格要
把 fd 3 与 pidfd 这类非文件目标一并写进保守摘要，并对 NI、PS 的相关格作跨章标记；poll × NB-N-02 归 NI，因为 pidfd 由 getsockopt 的
SO_PEERPIDFD 产生，也在 NI。

| 行 ID | 列 ID | 归属章 |
|---|---|---|
| NB-E-A-01 | NB-N-02 | PF |
| NB-E-A-01 | NB-N-08 | PS |
| NB-E-A-01 | NB-N-09 | LC |
| NB-E-A-01 | NB-N-10 | PF |
| NB-E-A-02 | NB-N-02 | NI |
| NB-E-A-03 | NB-N-02 | PF |
| NB-E-A-03 | NB-N-06 | GS |
| NB-E-A-03 | NB-N-09 | LC |
| NB-E-A-03 | NB-N-10 | PF |
| NB-E-A-04 | NB-N-02 | PF |
| NB-E-A-04 | NB-N-10 | PF |
| NB-E-A-05 | NB-N-01 | LC |
| NB-E-A-05 | NB-N-06 | GS |
| NB-E-A-06 | NB-N-02 | NI |
| NB-E-A-07 | NB-N-06 | GS |
| NB-E-A-08 | NB-N-08 | PS |
| NB-E-A-09 | NB-N-03 | PS |
| NB-E-A-10 | NB-N-02 | PF |
| NB-E-A-10 | NB-N-09 | LC |
| NB-E-A-10 | NB-N-10 | PF |
| NB-E-A-11 | NB-N-06 | GS |
| NB-E-K-01 | NB-N-06 | GS |
| NB-E-K-01 | NB-N-12 | PF |
| NB-E-K-02 | NB-N-06 | GS |
| NB-E-K-02 | NB-N-13 | GS |
| NB-E-K-03 | NB-N-02 | PF |
| NB-E-K-03 | NB-N-06 | GS |
| NB-E-K-04 | NB-N-06 | GS |
| NB-E-K-05 | NB-N-02 | PF |
| NB-E-K-05 | NB-N-10 | PF |
| NB-E-K-06 | NB-N-06 | GS |
| NB-E-K-07 | NB-N-07 | PS |
| NB-E-K-08 | NB-N-02 | PF |
| NB-E-K-08 | NB-N-08 | PS |
| NB-E-K-08 | NB-N-09 | LC |
| NB-E-K-08 | NB-N-10 | PF |
| NB-E-K-09 | NB-N-01 | PF |
| NB-E-K-09 | NB-N-02 | PF |
| NB-E-K-09 | NB-N-13 | GS |
| NB-E-K-10 | NB-N-06 | GS |
| NB-E-K-10 | NB-N-13 | GS |
| NB-E-K-11 | NB-N-06 | GS |
| NB-E-K-11 | NB-N-13 | GS |
| NB-E-K-12 | NB-N-06 | GS |
| NB-E-K-12 | NB-N-13 | GS |
| NB-E-K-13 | NB-N-06 | GS |
| NB-E-K-13 | NB-N-13 | GS |
| NB-E-K-14 | NB-N-06 | GS |
| NB-E-K-14 | NB-N-13 | GS |
| NB-E-M-01 | NB-N-02 | PF |
| NB-E-M-01 | NB-N-06 | GS |
| NB-E-M-01 | NB-N-09 | LC |
| NB-E-M-01 | NB-N-10 | PF |
| NB-E-M-02 | NB-N-02 | PF |
| NB-E-M-02 | NB-N-06 | GS |
| NB-E-M-03 | NB-N-02 | PF |
| NB-E-M-03 | NB-N-06 | GS |
| NB-E-M-04 | NB-N-06 | GS |
| NB-E-M-05 | NB-N-06 | GS |
| NB-E-M-07 | NB-N-02 | PF |
| NB-E-M-07 | NB-N-06 | GS |
| NB-E-M-08 | NB-N-06 | GS |
| NB-E-P-01 | NB-N-02 | PF |
| NB-E-P-01 | NB-N-08 | PS |
| NB-E-P-02 | NB-N-06 | GS |
| NB-E-P-02 | NB-N-07 | PS |
| NB-E-P-02 | NB-N-11 | LC |
| NB-E-P-03 | NB-N-07 | PS |
| NB-E-P-04 | NB-N-03 | PS |
| NB-E-P-04 | NB-N-07 | PS |
| NB-E-P-05 | NB-N-07 | PS |
| NB-E-P-06 | NB-N-07 | PS |
| NB-E-P-07 | NB-N-02 | PF |
| NB-E-P-07 | NB-N-03 | PS |
| NB-E-P-07 | NB-N-06 | GS |
| NB-E-P-07 | NB-N-07 | PS |
| NB-E-P-07 | NB-N-08 | PS |
| NB-E-P-07 | NB-N-09 | LC |
| NB-E-P-07 | NB-N-10 | PF |
| NB-E-P-07 | NB-N-11 | LC |
| NB-E-S-access | NB-N-01 | PF |
| NB-E-S-access | NB-N-02 | PF |
| NB-E-S-access | NB-N-06 | GS |
| NB-E-S-arch_prctl/ARCH_MAP_VDSO_64 | NB-N-06 | GS |
| NB-E-S-arch_prctl/ARCH_REQ_XCOMP_GUEST_PERM | NB-N-08 | PS |
| NB-E-S-arch_prctl/ARCH_REQ_XCOMP_PERM | NB-N-08 | PS |
| NB-E-S-arch_prctl/ARCH_SET_CPUID | NB-N-08 | PS |
| NB-E-S-arch_prctl/ARCH_SET_FS | NB-N-08 | PS |
| NB-E-S-arch_prctl/ARCH_SHSTK_ENABLE | NB-N-08 | PS |
| NB-E-S-arch_prctl/OTHER | NB-N-08 | PS |
| NB-E-S-brk | NB-N-06 | GS |
| NB-E-S-chdir | NB-N-01 | PF |
| NB-E-S-clock_gettime | NB-N-02 | PF |
| NB-E-S-clock_gettime | NB-N-03 | PS |
| NB-E-S-clock_gettime | NB-N-06 | GS |
| NB-E-S-clone/CLONE_CHILD_CLEARTID | NB-N-08 | PS |
| NB-E-S-clone/CLONE_NEWNS | NB-N-06 | GS |
| NB-E-S-clone/CLONE_NEWUSER | NB-N-06 | GS |
| NB-E-S-clone/CLONE_PARENT | NB-N-03 | PS |
| NB-E-S-clone/CLONE_PARENT | NB-N-07 | PS |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-02 | PF |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-03 | PS |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-09 | LC |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-10 | PF |
| NB-E-S-clone/CLONE_PIDFD | NB-N-02 | PS |
| NB-E-S-clone/CLONE_PIDFD | NB-N-03 | PS |
| NB-E-S-clone/CLONE_PTRACE | NB-N-03 | PS |
| NB-E-S-clone/CLONE_VFORK | NB-N-03 | PS |
| NB-E-S-clone/CLONE_VM | NB-N-03 | PS |
| NB-E-S-clone/CLONE_VM | NB-N-05 | NI |
| NB-E-S-clone/CSIGNAL | NB-N-03 | PS |
| NB-E-S-clone/CSIGNAL | NB-N-06 | GS |
| NB-E-S-clone/CSIGNAL | NB-N-07 | PS |
| NB-E-S-clone/CSIGNAL | NB-N-11 | LC |
| NB-E-S-clone/OTHER | NB-N-03 | PS |
| NB-E-S-close | NB-N-02 | PF |
| NB-E-S-close | NB-N-10 | PF |
| NB-E-S-execve | NB-N-01 | PF |
| NB-E-S-execve | NB-N-02 | PF |
| NB-E-S-execve | NB-N-06 | GS |
| NB-E-S-execve | NB-N-08 | PS |
| NB-E-S-execve | NB-N-09 | LC |
| NB-E-S-execve | NB-N-10 | PF |
| NB-E-S-exit | NB-N-07 | PS |
| NB-E-S-fcntl/F_ADD_SEALS | NB-N-02 | PF |
| NB-E-S-fcntl/F_DUPFD | NB-N-02 | PF |
| NB-E-S-fcntl/F_NOTIFY | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETFD | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETFL | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETLEASE | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETLEASE | NB-N-10 | PF |
| NB-E-S-fcntl/F_SETLK | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETLK | NB-N-03 | PF |
| NB-E-S-fcntl/F_SETLK | NB-N-10 | PF |
| NB-E-S-fcntl/F_SETOWN | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETOWN | NB-N-03 | PS |
| NB-E-S-fcntl/F_SETOWN | NB-N-07 | PS |
| NB-E-S-fcntl/F_SETPIPE_SZ | NB-N-02 | PF |
| NB-E-S-fcntl/F_SETSIG | NB-N-02 | PF |
| NB-E-S-fcntl/F_SET_RW_HINT | NB-N-02 | PF |
| NB-E-S-fcntl/F_SET_RW_HINT | NB-N-06 | GS |
| NB-E-S-fcntl/OTHER | NB-N-02 | PF |
| NB-E-S-fstat | NB-N-01 | PF |
| NB-E-S-fstat | NB-N-02 | PF |
| NB-E-S-fstat | NB-N-06 | GS |
| NB-E-S-fsync | NB-N-02 | PF |
| NB-E-S-fsync | NB-N-06 | GS |
| NB-E-S-futex/FUTEX_LOCK_PI | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_LOCK_PI | NB-N-03 | PS |
| NB-E-S-futex/FUTEX_LOCK_PI | NB-N-06 | GS |
| NB-E-S-futex/FUTEX_REQUEUE | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAIT | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAIT | NB-N-06 | GS |
| NB-E-S-futex/FUTEX_WAIT_REQUEUE_PI | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAIT_REQUEUE_PI | NB-N-03 | PS |
| NB-E-S-futex/FUTEX_WAIT_REQUEUE_PI | NB-N-06 | GS |
| NB-E-S-futex/FUTEX_WAKE | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAKE_OP | NB-N-02 | PF |
| NB-E-S-futex/FUTEX_WAKE_OP | NB-N-09 | LC |
| NB-E-S-futex/FUTEX_WAKE_OP | NB-N-10 | PF |
| NB-E-S-futex/OTHER | NB-N-02 | PF |
| NB-E-S-getcwd | NB-N-01 | PF |
| NB-E-S-getdents64 | NB-N-02 | PF |
| NB-E-S-getdents64 | NB-N-06 | GS |
| NB-E-S-getdents64 | NB-N-09 | LC |
| NB-E-S-getdents64 | NB-N-10 | PF |
| NB-E-S-getpid | NB-N-03 | PS |
| NB-E-S-getrandom | NB-N-06 | GS |
| NB-E-S-getsockname | NB-N-04 | NI |
| NB-E-S-getsockopt/OTHER | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_COOKIE | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_COOKIE | NB-N-06 | GS |
| NB-E-S-getsockopt/SO_ERROR | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_PEERCRED | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_PEERPIDFD | NB-N-02 | NI |
| NB-E-S-getsockopt/SO_PEERPIDFD | NB-N-03 | NI |
| NB-E-S-getsockopt/SO_TYPE | NB-N-02 | NI |
| NB-E-S-getuid | NB-N-08 | PS |
| NB-E-S-kill | NB-N-03 | PS |
| NB-E-S-kill | NB-N-07 | PS |
| NB-E-S-lseek | NB-N-02 | PF |
| NB-E-S-madvise/MADV_COLD | NB-N-02 | PF |
| NB-E-S-madvise/MADV_COLD | NB-N-06 | GS |
| NB-E-S-madvise/MADV_COLLAPSE | NB-N-06 | GS |
| NB-E-S-madvise/MADV_DODUMP | NB-N-12 | PF |
| NB-E-S-madvise/MADV_DONTNEED | NB-N-06 | GS |
| NB-E-S-madvise/MADV_HUGEPAGE | NB-N-06 | GS |
| NB-E-S-madvise/MADV_HWPOISON | NB-N-06 | GS |
| NB-E-S-madvise/MADV_MERGEABLE | NB-N-06 | GS |
| NB-E-S-madvise/MADV_POPULATE_READ | NB-N-02 | PF |
| NB-E-S-madvise/MADV_POPULATE_READ | NB-N-06 | GS |
| NB-E-S-madvise/MADV_REMOVE | NB-N-02 | PF |
| NB-E-S-madvise/MADV_REMOVE | NB-N-06 | GS |
| NB-E-S-madvise/MADV_REMOVE | NB-N-09 | LC |
| NB-E-S-madvise/MADV_REMOVE | NB-N-10 | PF |
| NB-E-S-madvise/MADV_WILLNEED | NB-N-02 | PF |
| NB-E-S-madvise/MADV_WILLNEED | NB-N-06 | GS |
| NB-E-S-madvise/MADV_WIPEONFORK | NB-N-08 | PS |
| NB-E-S-madvise/OTHER | NB-N-06 | GS |
| NB-E-S-mmap | NB-N-02 | PF |
| NB-E-S-mmap | NB-N-06 | GS |
| NB-E-S-mmap | NB-N-09 | LC |
| NB-E-S-mmap | NB-N-10 | PF |
| NB-E-S-mprotect | NB-N-02 | PF |
| NB-E-S-munmap | NB-N-02 | PF |
| NB-E-S-nanosleep | NB-N-03 | PS |
| NB-E-S-nanosleep | NB-N-06 | GS |
| NB-E-S-openat | NB-N-01 | PF |
| NB-E-S-openat | NB-N-02 | PF |
| NB-E-S-openat | NB-N-06 | GS |
| NB-E-S-openat | NB-N-09 | LC |
| NB-E-S-openat | NB-N-10 | PF |
| NB-E-S-poll | NB-N-02 | NI |
| NB-E-S-prctl/OTHER | NB-N-08 | PS |
| NB-E-S-prctl/PR_GET_AUXV | NB-N-08 | PS |
| NB-E-S-prctl/PR_MCE_KILL | NB-N-08 | PS |
| NB-E-S-prctl/PR_SCHED_CORE | NB-N-03 | PS |
| NB-E-S-prctl/PR_SET_CHILD_SUBREAPER | NB-N-07 | PS |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-01 | PF |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-12 | PF |
| NB-E-S-prctl/PR_SET_FP_MODE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_KEEPCAPS | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_MDWE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_MEMORY_MERGE | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_MEMORY_MERGE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_MM | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_MM_MAP | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_MM_MAP | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_NAME | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_NAME | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_NO_NEW_PRIVS | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_PDEATHSIG | NB-N-07 | PS |
| NB-E-S-prctl/PR_SET_PDEATHSIG | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_PTRACER | NB-N-03 | PS |
| NB-E-S-prctl/PR_SET_PTRACER | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_SECCOMP | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_SECCOMP | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_SECUREBITS | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_SPECULATION_CTRL | NB-N-06 | GS |
| NB-E-S-prctl/PR_SET_SPECULATION_CTRL | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_SYSCALL_USER_DISPATCH | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_THP_DISABLE | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_TIMERSLACK | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_TIMING | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_TSC | NB-N-08 | PS |
| NB-E-S-prctl/PR_SET_VMA | NB-N-08 | PS |
| NB-E-S-prctl/PR_TASK_PERF_EVENTS_DISABLE | NB-N-08 | PS |
| NB-E-S-prlimit64 | NB-N-03 | PS |
| NB-E-S-prlimit64 | NB-N-08 | PS |
| NB-E-S-read | NB-N-02 | PF |
| NB-E-S-read | NB-N-06 | GS |
| NB-E-S-read | NB-N-09 | LC |
| NB-E-S-read | NB-N-10 | PF |
| NB-E-S-readlink | NB-N-01 | PF |
| NB-E-S-readlink | NB-N-02 | PF |
| NB-E-S-readlink | NB-N-06 | GS |
| NB-E-S-readlink | NB-N-09 | LC |
| NB-E-S-readlink | NB-N-10 | PF |
| NB-E-S-recvmsg | NB-N-02 | NI |
| NB-E-S-rt_sigaction | NB-N-08 | PS |
| NB-E-S-sendmsg | NB-N-02 | NI |
| NB-E-S-sendmsg | NB-N-03 | NI |
| NB-E-S-sendmsg | NB-N-06 | NI |
| NB-E-S-set_tid_address | NB-N-08 | PS |
| NB-E-S-setsid | NB-N-07 | PS |
| NB-E-S-setuid | NB-N-08 | PS |
| NB-E-S-shutdown | NB-N-02 | NI |
| NB-E-S-tgkill | NB-N-03 | PS |
| NB-E-S-uname | NB-N-06 | GS |
| NB-E-S-unshare/CLONE_FILES | NB-N-02 | PF |
| NB-E-S-unshare/CLONE_NEWNS | NB-N-06 | GS |
| NB-E-S-unshare/CLONE_NEWUSER | NB-N-06 | GS |
| NB-E-S-unshare/CLONE_SYSVSEM | NB-N-05 | NI |
| NB-E-S-unshare/CLONE_THREAD | NB-N-07 | PS |
| NB-E-S-unshare/OTHER | NB-N-07 | PS |
| NB-E-S-wait4 | NB-N-02 | PS |
| NB-E-S-wait4 | NB-N-03 | PS |
| NB-E-S-wait4 | NB-N-06 | GS |
| NB-E-S-write | NB-N-02 | PF |
| NB-E-S-write | NB-N-06 | GS |
| NB-E-S-write | NB-N-08 | PS |
| NB-E-S-write | NB-N-09 | LC |
| NB-E-S-write | NB-N-10 | PF |
| NB-E-S-write | NB-N-12 | PF |
| NB-K-01 | NB-N-08 | 02 |
| NB-K-02 | NB-N-08 | 02 |
| NB-K-03 | NB-N-07 | LC |
| NB-K-04 | NB-N-01 | LC |
| NB-K-04 | NB-N-06 | LC |
| NB-K-05 | NB-N-02 | LC |
| NB-K-06 | NB-N-02 | LC |
| NB-K-07 | NB-N-01 | LC |
| NB-K-08 | NB-N-02 | LC |
| NB-K-09 | NB-N-08 | LC |
| NB-K-10 | NB-N-01 | LC |
| NB-K-11 | NB-N-02 | NI |
| NB-K-12 | NB-N-01 | PF |
| NB-K-12 | NB-N-02 | NI |
| NB-K-13 | NB-N-03 | PS |
| NB-K-13 | NB-N-07 | PS |
| NB-K-14 | NB-N-01 | LC |
| NB-K-14 | NB-N-06 | LC |
| NB-K-15 | NB-N-09 | LC |
| NB-K-16 | NB-N-07 | LC |
| NB-K-16 | NB-N-11 | LC |

### 3.5 不适用项

附表"名字来源列"点到、但不成分支的（行，列），各写一条理由。

| 行 ID | 列 ID | 理由 |
|---|---|---|
| NB-E-S-clone/CLONE_CHILD_CLEARTID | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/CLONE_CHILD_CLEARTID | NB-N-03 | 只登记地址；新任务本身由 CSIGNAL 一行的 N-03 格判 |
| NB-E-S-clone/CLONE_CHILD_CLEARTID | NB-N-06 | 每次创建都经过 CSIGNAL 一行，宿主 pid 号空间的占用由它的 N-06 格判 |
| NB-E-S-clone/CLONE_NEWNS | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/CLONE_NEWNS | NB-N-03 | 缺能力或被过滤器拒绝，不建新任务 |
| NB-E-S-clone/CLONE_NEWUSER | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/CLONE_NEWUSER | NB-N-03 | 缺能力或被过滤器拒绝，不建新任务 |
| NB-E-S-clone/CLONE_PARENT | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/CLONE_PARENT | NB-N-06 | 每次创建都经过 CSIGNAL 一行，宿主 pid 号空间的占用由它的 N-06 格判 |
| NB-E-S-clone/CLONE_PARENT_SETTID | NB-N-06 | 每次创建都经过 CSIGNAL 一行，宿主 pid 号空间的占用由它的 N-06 格判 |
| NB-E-S-clone/CLONE_PIDFD | NB-N-06 | 每次创建都经过 CSIGNAL 一行，宿主 pid 号空间的占用由它的 N-06 格判 |
| NB-E-S-clone/CLONE_PTRACE | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/CLONE_PTRACE | NB-N-06 | 每次创建都经过 CSIGNAL 一行，宿主 pid 号空间的占用由它的 N-06 格判 |
| NB-E-S-clone/CLONE_VFORK | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/CLONE_VFORK | NB-N-06 | 每次创建都经过 CSIGNAL 一行，宿主 pid 号空间的占用由它的 N-06 格判 |
| NB-E-S-clone/CLONE_VM | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/CLONE_VM | NB-N-06 | 每次创建都经过 CSIGNAL 一行，宿主 pid 号空间的占用由它的 N-06 格判 |
| NB-E-S-clone/CSIGNAL | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/OTHER | NB-N-02 | 这一类标志不在 fd 表里放新引用；新任务共享或复制的 fd 表归 NB-E-P-07 的格 |
| NB-E-S-clone/OTHER | NB-N-06 | 每次创建都经过 CSIGNAL 一行，宿主 pid 号空间的占用由它的 N-06 格判 |
| NB-E-S-fcntl/F_ADD_SEALS | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_ADD_SEALS | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_DUPFD | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_DUPFD | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_NOTIFY | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_NOTIFY | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_SETFD | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_SETFD | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_SETFL | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_SETFL | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_SETLEASE | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_SETLEASE | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_SETLK | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_SETPIPE_SZ | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_SETPIPE_SZ | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_SETSIG | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_SETSIG | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/F_SET_RW_HINT | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/F_SET_RW_HINT | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-fcntl/OTHER | NB-N-03 | 这一子操作既不取 pid 参数，也不输出 pid |
| NB-E-S-fcntl/OTHER | NB-N-07 | 不作用到进程组、会话、父进程这类隐式主体；信号目标由 F_SETOWN 一行的格判 |
| NB-E-S-futex/FUTEX_REQUEUE | NB-N-03 | 不是 PI 操作：等待者按 futex 键找，不把 futex 字里的值当 tid 解析 |
| NB-E-S-futex/FUTEX_WAIT | NB-N-03 | 不是 PI 操作：等待者按 futex 键找，不把 futex 字里的值当 tid 解析 |
| NB-E-S-futex/FUTEX_WAKE | NB-N-03 | 不是 PI 操作：等待者按 futex 键找，不把 futex 字里的值当 tid 解析 |
| NB-E-S-futex/FUTEX_WAKE_OP | NB-N-03 | 不是 PI 操作：等待者按 futex 键找，不把 futex 字里的值当 tid 解析 |
| NB-E-S-futex/OTHER | NB-N-03 | 返回 ENOSYS，不解析任何名字 |
| NB-E-S-getsockopt/OTHER | NB-N-06 | 只读本端或对端在建立时记下的属性，不读全局计数 |
| NB-E-S-getsockopt/SO_ERROR | NB-N-06 | 只读本端或对端在建立时记下的属性，不读全局计数 |
| NB-E-S-getsockopt/SO_PEERCRED | NB-N-06 | 只读本端或对端在建立时记下的属性，不读全局计数 |
| NB-E-S-getsockopt/SO_PEERPIDFD | NB-N-06 | 建 pidfd 不读全局名字；pidfd 指向的进程由本行 N-02、N-03 两格判 |
| NB-E-S-getsockopt/SO_TYPE | NB-N-06 | 只读本端或对端在建立时记下的属性，不读全局计数 |
| NB-E-S-madvise/MADV_DODUMP | NB-N-06 | 只改 VMA 标志，影响的是 core dump 的内容，由本行 N-12 格判 |
| NB-E-S-madvise/MADV_WIPEONFORK | NB-N-06 | 只改 VMA 标志，影响的是以后 clone 时子任务得到的映射，由本行 N-08 格判 |
| NB-E-S-prctl/OTHER | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/OTHER | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_GET_AUXV | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_GET_AUXV | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_MCE_KILL | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_MCE_KILL | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SCHED_CORE | NB-N-06 | CONFIG_SCHED_CORE 未开（NB-EV-018），返回 EINVAL，不建 core 调度 cookie |
| NB-E-S-prctl/PR_SET_CHILD_SUBREAPER | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_CHILD_SUBREAPER | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_DUMPABLE | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_FP_MODE | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_FP_MODE | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_KEEPCAPS | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_KEEPCAPS | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_MDWE | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_MDWE | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_MEMORY_MERGE | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_MM | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_MM | NB-N-06 | 缺 CAP_SYS_RESOURCE，返回 EPERM，不改任何状态 |
| NB-E-S-prctl/PR_SET_MM_MAP | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_NAME | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_NO_NEW_PRIVS | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_NO_NEW_PRIVS | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_PDEATHSIG | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_PDEATHSIG | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_SECCOMP | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_SECUREBITS | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_SECUREBITS | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_SPECULATION_CTRL | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_SYSCALL_USER_DISPATCH | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_SYSCALL_USER_DISPATCH | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_THP_DISABLE | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_THP_DISABLE | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_TIMERSLACK | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_TIMERSLACK | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_TIMING | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_TIMING | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_TSC | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_TSC | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_SET_VMA | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_SET_VMA | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |
| NB-E-S-prctl/PR_TASK_PERF_EVENTS_DISABLE | NB-N-03 | 这一取值不取 pid 参数 |
| NB-E-S-prctl/PR_TASK_PERF_EVENTS_DISABLE | NB-N-06 | 只改或只读本任务、本 mm 的属性，或返回错误；不经未隔离的名字 |

### 3.6 列的不适用规则

| 列 ID | 适用规则 | 不适用的理由 |
|---|---|---|
| NB-N-01 | 以路径为参数或解析路径的行（openat、access、newfstatat 与 statx、readlink、chdir、getcwd、execve），构造与销毁挂载的行（NB-K-04、NB-K-07、NB-K-10、NB-K-14、NB-E-A-05），engine 经宿主路径写的文件（NB-K-12），改变 /proc/self 条目属主的 prctl PR_SET_DUMPABLE（dumpable 为 0 时条目变为 root 所有），以及经路径或 fd 作用到对象时产生的 fsnotify 事件（NB-E-K-09） | 其余行的参数是 fd、地址、pid、数值或没有参数，不解析路径；经路径能找到的每个对象都由上面这些行的格覆盖 |
| NB-N-02 | 以 fd 为参数、或经映射与 file 对象作用的行：文件 I/O 与元数据、内存映射、socket 调用、fd 的复制与关闭、faccessat2 与 readlinkat 的目录 fd、clock_gettime 的 CLOCKFD 时钟号（编码一个 fd），以及 kernel 经映射写用户内存的事件（NB-E-M-01、02、03、07，NB-E-K-03、05、08、09，NB-E-A-01、02、03、04、06、10，NB-E-P-01、07） | 其余行既不取 fd，也不经已有的 file 或映射作用到对象：它们的作用对象是任务、信号、凭据与全局状态，由各自适用的列覆盖。参数里嵌套 fd 但不解析的两处：prctl PR_SET_MM_MAP 结构里的 exe_fd 要先过 checkpoint-restore 能力检查，没有能力返回 EPERM（kernel/sys.c::prctl_set_mm_map）；clock_nanosleep 的 CLOCKFD 时钟号没有 nsleep 方法，返回 EOPNOTSUPP（kernel/time/posix-clock.c 的 clock_posix_dynamic）。系统调用读写的用户缓冲区落在哪个映射上由 NB-E-M 各行承担（01-rows-syscalls 文件头） |
| NB-N-03 | 取 pid、tid 或进程组号作参数（含参数里嵌套的），或创建、回收、通知任务的行：kill、tgkill、wait4 与 waitid、prlimit64、getpid、clone 的子操作、fcntl 的 F_SETOWN 与 F_SETLK（F_GETLK 输出持锁者的 pid）、prctl 的 PR_SET_PTRACER 与 PR_SCHED_CORE、getsockopt 的 SO_PEERPIDFD、clock_gettime 与 clock_nanosleep 的 CPU 时钟号（编码一个 pid）、futex 的 PI 子操作（futex 字里的持有者 tid）、sendmsg 的 SCM_CREDENTIALS（ucred 的 pid），以及 NB-E-A-09、NB-E-P-04、NB-E-P-07、NB-K-13 | 其余行不以 pid 或 tid 名字找对象；本 pid namespace 之外的任务没有号，经隐式关系作用到的任务由 N-07 覆盖 |
| NB-N-04 | 只有 getsockname 一行（fd 3 两端无名） | socket、socketpair 不在 L，bind 与 connect 固定禁止（NB-DI-08），execution 手里唯一的 socket 是已连接的 fd 3；L 里没有别的调用以网络地址为参数，sendmsg 的 msg_name 对已连接的 STREAM 返回 EISCONN |
| NB-N-05 | unshare 的 CLONE_SYSVSEM（执行本任务的 SysV 信号量撤销）与 clone 的 CLONE_SYSVSEM（在 CLONE_VM 子操作行里：新任务与调用者共享撤销表） | SysV IPC 与 POSIX 消息队列的调用都不在 L，mqueue 文件系统没有挂载（NB-N-05）；L 里没有别的调用以 IPC 键或 ID 为参数 |
| NB-N-06 | 读写未隔离的名字或全机状态的行：时钟、CPU 号与处理器的静态配置（NB-E-M-04、NB-E-M-08，2026-10-27 补）、UTS、随机数、全局计数（inode 号、cookie、pid 号的分配与归还，含 wait4 与 waitid）、kernel 日志与宿主观测设施、共享 btrfs 与块设备（含可信方的 NB-K-04、NB-K-14）、宿主内存与 swap、hugetlb、THP 与 KSM（含 prctl 的 PR_SET_MEMORY_MERGE）、binfmt_misc、Yama 例外表、futex 的全局哈希桶（含 PI 等待）、sendmsg 的 SCM_CREDENTIALS（uid 与 gid 按初始 user namespace 解析）、宿主经 /proc 读到的 comm、cmdline 与 environ（prctl 的 PR_SET_NAME 与 PR_SET_MM_MAP、write、execve、NB-E-M-07）、推测执行与 split lock（NB-E-K-06、NB-E-A-11） | 其余行只作用到本 execution 自己的对象或交付对象，不经未隔离的名字；它们对全机汇总状态的占用（内存、CPU）在上面这些行的格里一并判。宿主可观察的 execution 状态（01 §2.6 的宿主可见性规则：宿主不要特权就看得到的，以及可见性未定、按可见处理的）不另成分支：任务的出现与退出、状态与计数在 clone 的 CSIGNAL、NB-E-P-07 与 NB-E-P-02 的格判，构造时设定、之后没有行再改的属性（uid、gid、初始的信号处置与掩码）也在这几格判，NB-E-P-02 的格把宿主对正在退出的任务做的 process_mrelease 回收作用与状态读数分开列，参数区与 comm 在 execve、prctl 的 PR_SET_NAME 与 PR_SET_MM_MAP、write、NB-E-M-07 的格判，其余行改变、宿主经 /proc 读得到的计数与状态（CPU 时间、内存用量、信号掩码等）作为同一条观察信道在这些格里一并判；格的记录取"宿主可观察·已核实"或"宿主可观察·按可见"（SPEC §4.1 第 4 类；第三次定向复核后加，R0d 全量审核后改为记录取值） |
| NB-N-07 | 作用到进程组、会话、父进程、cgroup 成员与按 uid 计数这类隐式主体的行：kill、exit、setsid、clone 的 CSIGNAL 与 CLONE_PARENT、unshare 的 CLONE_THREAD 与其余位、fcntl 的 F_SETOWN、prctl 的 PR_SET_PDEATHSIG 与 PR_SET_CHILD_SUBREAPER，以及 NB-E-K-07、NB-E-P-02…07、NB-K-03、NB-K-13、NB-K-16 | 其余行不经隐式主体作用到别的任务或计数 |
| NB-N-08 | 读或改继承的 task 属性的行：凭据、rlimit、信号处置与掩码、登记的地址、prctl 与 arch_prctl 的各子操作、/proc/self 的可写条目（write 一行），以及 NB-E-K-08、NB-E-A-01、NB-E-A-08、NB-E-P-01、NB-E-P-07（新任务继承这些属性）、NB-K-01、NB-K-02、NB-K-09 | 其余行不读也不改 01 §4 NB-N-08 列出的属性 |
| NB-N-09 | 改变 /work 内容或元数据的行：openat（建文件、截断）、write、read 与 getdents64 与 readlink（relatime 更新 atime）、mmap 与 execve（btrfs 的 mmap 方法与 exec 读可执行文件同样更新 atime：fs/btrfs/file.c::btrfs_file_mmap、mm/filemap.c::filemap_read）、madvise 的 MADV_REMOVE、futex 的 FUTEX_WAKE_OP 与 clone 的 tid 写入（写用户内存，可落在 /work 共享映射上），以及 NB-E-M-01、NB-E-K-08、NB-E-A-01、NB-E-A-03、NB-E-A-10、NB-E-P-07 与 NB-K-15 | 其余行不改 /work 的内容与元数据；它们为调用者写的输出缓冲区落在 /work 共享映射上时，由 NB-E-M-01 的格判；记录锁与租约随进程消亡释放，后继开始之前已不存在（NB-K-15 要求前一个 execution 已置空） |
| NB-N-10 | 与 N-09 同一组改变 /work 内容或元数据的行（不含只代表后继读取的 NB-K-15），加上会让宿主可信方打开工作区文件时遇到锁与租约的行（fcntl 的 F_SETLK 与 F_SETLEASE、close、NB-E-K-05、NB-E-A-04） | 其余行既不改 /work，也不在 /work 的文件上留下锁或租约 |
| NB-N-11 | 改变 cell cgroup 里任务数的行：clone 的 CSIGNAL（每次创建的共同部分）、NB-E-P-02、NB-E-P-07、NB-K-16 | 其余行不建也不结束任务，不改变 populated |
| NB-N-12 | NB-E-K-01（core dump 路径），以及决定 core 内容的行：madvise 的 MADV_DODUMP、prctl 的 PR_SET_DUMPABLE、write（/proc/self/coredump_filter） | core dump 处理程序只在 fs/coredump.c::do_coredump 的管道路径上被调用，RLIMIT_CORE 为 1 时在调用前放弃（NB-E-K-01），RLIMIT_CORE 的硬限 execution 提不回去；其余行不经它。上面列的是决定 core 是否产生、包含哪些段的行；任何写内存、改 comm 或 auxv 的行都改 core 的内容，这些在 NB-E-K-01 × N-12 的格里一并判（定向复核改正） |
| NB-N-13 | kernel 向宿主观测组件送出记录或事件的行：NB-E-K-02（kernel 日志）、NB-E-K-09（fsnotify 事件与 fanotify 权限事件）、NB-E-K-10（进程事件连接器）、NB-E-K-11（BSD 记账）、NB-E-K-12（taskstats）、NB-E-K-13（审计）、NB-E-K-14（跟踪设施） | 其余行不产生送给宿主组件的记录：它们触发的记录都经上面这些行送出（各行的后续动作交给它们）；宿主进程经宿主的 /proc 读 execution 的 comm、cmdline 与 environ 不经 kernel 送出，由 N-06 在塑造这些内容的行的格判：prctl 的 PR_SET_NAME 与 PR_SET_MM_MAP、write（/proc/self/comm）、execve（argv、envp 与 comm）、NB-E-M-07（写栈上的参数区与环境区）；不是部署方安装的宿主进程与用户（NB-S-14）读 kernel 日志或 /proc 时是效果的对象，同样在 N-06 的格判；部署方安装的 /proc 读者（NB-S-17 的那一半）读到的内容也在 N-06 的格判；PSI 的压力读数是全机汇总状态，由 N-06 在 NB-E-K-04 的格判 |

### 3.7 交给第二块的事项

- **SO_PEERPIDFD**（NB-E-S-getsockopt/SO_PEERPIDFD，NI）：execution 能在自己的 fd 表里得到一个指向 spawner 的 pidfd（01-trace-events §8）。
  这是附表没有列、从分派位置导出时才出现的取值；它给出一个指向宿主上可信进程的引用，经它能读出 spawner 是否还活着。NI 章按 SPEC §4.1
  判它的候选效果，PS 章对父进程通知与 pdeathsig 已能读出的同类信息作跨章标记。
- **构造行的格**：NB-K-01、02 的分支归 02，格在第二块开工前按 §2 的初态项补进本文件，格引用的章代号用 BB；NB-K-03…10 的分支归 LC（§1.3），格写运行期为另一个
  execution 构造时的保持与干扰义务，本 execution 自己的初态仍由 §2 承担。
- **构造窗口的干扰义务**：§2.3"构造窗口里其他主体对 child 的作用"一项记未定。PS 章在 NB-E-S-kill × NB-N-07、NB-E-P-03 × NB-N-07 的格判同会话
  SIGCONT 与孤儿进程组信号对构造中的 child 的作用，LC 章在 NB-K-03…10 的格判其余并发作用；判定后回填那一项（审核一，Codex 意见 R5）。
- **宿主观测组件**：NB-N-13 的七个分支归 GS（§3.2）；它们读到记录之后怎样做是部署前提，GS 章按 SPEC §5.1 写进部署限制。NB-E-K-09 × N-13 的格要写路径型 fanotify 事件与事件 fd 钉住事件所经的 execution 挂载（本配置下 /work 与 /runtime 的 bind，范围的条件见 01 NB-E-K-09；事件在队列里时就已取了引用），核 FID 模式事件的引用种类，并写明事件附带的 pidfd 只是 struct pid 的身份引用（§2.5）。
- **宿主可观察的格**：按 01 §2.6 的宿主可见性规则，宿主不要特权就看得到的部分与可见性未定的部分不记"私有"，在 N-06 的格里记"宿主可观察·已核实"或"宿主可观察·按可见"（SPEC §4.1 第 4 类：通向宿主读者的出向内容通道，作为局限写进结论）；第三块汇总时两类分开计数。部署条件（宿主 /proc 以 hidepid 挂载、cell 独占虚拟机）能让它们对宿主普通进程不可见的，以后作为部署条件改回私有。
- **私有的格**：SPEC §4.2 的 I2 只管私有候选里宿主要特权才碰得到的部分（01 §2.6）。记"私有"的格除了"主体（整表）"，在依赖里还写 NB-AA-08（宿主特权进程不取用、不读写私有对象）；check_coverage.py 目前只核前者，后者在样板章定格式时一并加进检查。
- **宿主观测组件所收记录的归类（待定）**：kernel 送给宿主观测组件的审计、记账、taskstats、进程事件与跟踪记录里，也有取自 execution
  自身状态的内容（comm 等），写进的是宿主对象。SPEC §4.1 宿主可观察的例外只含 /proc 可见的部分与 kernel 日志，这些写入现在只能按
  优先规则判；GS 章动笔前定下它们的归类，写进 SPEC §4.1 或本节，交用户（R0d 第二次定向复核，Claude 本轮 7）。
- **TLC 与反向测试**：转换粒度见 §1.2；分支表决定要测的格（TESTING 测试义务表），测试编号在各章写格时定。
