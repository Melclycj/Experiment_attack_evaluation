---
title: S1 — 系统调用行：L 的 74 个调用按子操作拆分，参数的名字来源列与隐式主体
date: 2026-10-24
step: S1 of the spine（01 §3.1 的附表）
status: version 8，2026-10-29；审核一已收口。版本历史：v1 首版；v2 只改 prctl 行一处过时的读数说明（SCHED_CORE 已读）；v3 只改指向（PLAN 拆分）；v4 只改 exit 与 set_tid_address 两行指向 01 §3.2 的编号（S1 补充）；v5（主干·上）改正 execve 一行的 pdeathsig 与 getsockopt 一行的 SO_PEERCRED；v6（审核一的修改）：文件头补用户缓冲区一段；prctl 一行改正 PR_SET_MM_MAP 与 PR_SET_MEMORY_MERGE 的能力事实（madvise 一行同步）；access、readlink、futex、sendmsg、clock_gettime、nanosleep 六行补参数里嵌套的名字；getsockopt 一行补 SO_PEERNAME、SO_PEERPIDFD、SO_NETNS_COOKIE；§F 改正三类的行数；v7（定向复核的修改，2026-10-26）：prctl 一行把 PR_SET_MM_MAP_SIZE 与 PR_SET_MM_MAP 分开写；v8（2026-10-29）：只改文件头的状态句
frozen_revision: NB-P3-2026-10-24；L 取自 checks L117–130（blob 20b0959a）；固定条款取自 policy L16、L34–36、L46–49（blob 57012b55）
reading_rule: 每行只写这个调用经哪些名字能找到什么对象、哪些参数要按语义展开、有什么隐式主体；不写防御、不判归类。列 ID 见 01 §4（NB-N-01 路径 · 02 fd · 03 pid · 04 网络 · 05 IPC · 06 未隔离名字 · 07 隐式主体 · 08 继承属性）。
---

# 01 附表 — 系统调用行

**停止准则（SPEC §4.2 第 3 步）。** 每格的保守摘要在 S2 写；本表给每行的"参数展开清单"，S2 不得漏掉任何一个展开项。

**用户缓冲区（2026-10-26 补，审核一）。** 每个带用户缓冲区的调用（输入或输出缓冲区、iov、结构体与其中嵌套的指针）由 kernel 经
copy_from_user、copy_to_user 读写（include/linux/uaccess.h），缓冲区可以落在 execution 的任何映射上：/work 文件的共享映射、shmem、
私有内存、只读的 /runtime 与 vdso。这次读写本身是 01 §3.2 的 NB-E-M 行的一个触发来源（含缺页、部分完成与 EFAULT），下表不逐行重复；
各格的保守摘要写这个调用的输出缓冲区落在哪里、部分完成时已写的部分留在哪里。
"事实"列只记 kernel 语义或代码事实，`[R]` 的源码位置在 S3 钉到 §5 的 tag。

## A 文件与路径

| 行 | 调用 | 名字来源列 | 子操作 / 参数展开 | 隐式主体与继承项 | 固定条件与事实 |
|---|---|---|---|---|---|
| NB-E-S-openat | openat | N-01 路径（dirfd 相对 → N-02） | flags 逐位：O_CREAT（新 inode，受 umask）、O_EXCL、O_TRUNC、O_APPEND、O_PATH、O_NOFOLLOW、O_DIRECTORY、O_TMPFILE、O_DIRECT、O_SYNC/O_DSYNC、O_NOATIME（需 owner）、O_CLOEXEC；mode；路径类别：/work（rw）、/runtime（ro；O_WRONLY → EROFS/EACCES [M] checks L205）、/tmp、/dev/shm、/dev 四节点、/proc/self/*（含 magic link：exe、cwd、root、fd/N、map_files/*、ns/*；写入条目见 01 NB-DI-25）、/ 与 /dev（root 0755：创建失败） | umask；RLIMIT_NOFILE；per-uid files 计数 | protected_symlinks/hardlinks/fifos/regular 在 1777 目录（/tmp、/dev/shm）生效；fd/N 对 socket 重开 ENXIO；ns/* 打开得 nsfd；/proc/self/mem 可写自身 |
| NB-E-S-read | read / readv | N-02 | 目标 fd 类别：/work、/runtime、tmpfs、/dev/zero、/dev/random、/dev/urandom（共享 CRNG）、/proc/self/*、fd 3（协议响应；协议归 2.2）、目录（EISDIR） | — | /dev/random 自 5.6 不阻塞 |
| NB-E-S-write | write / writev | N-02 | 目标：/work（脏页→回写，btrfs 事务与空闲空间共享）、tmpfs（占宿主内存）、/dev/null、/dev/zero、/dev/random 与 /dev/urandom（混入输入池，NB-DI-22）、/proc/self 可写条目（oom_score_adj、comm、timerslack_ns、coredump_filter、clear_refs、mem、attr/*、sched）、fd 3（请求，第 1/2 类） | RLIMIT_FSIZE（继承） | sync/syncfs 固定禁止；fsync 单列 |
| NB-E-S-close | close | N-02 | 最后引用关闭触发：锁与租约释放、dnotify、socket 的 shutdown 语义（fd 3 全关 → engine 读到 EOF）、tmpfs 文件已 unlink 时释放内存 | — | — |
| NB-E-S-fstat | fstat / newfstatat / statx | N-02；N-01 | st_ino（/proc 条目与匿名 inode 是 get_next_ino 全局计数 [M] OBS-04）、st_dev（/work 子卷匿名 dev 号、/runtime 的 dev）、st_nlink、时间戳；statx 的 STATX_MNT_ID、STATX_ATTR_*；AT_EMPTY_PATH | — | 路径 /proc/self/* 每次 stat 分配新 inode 号（OBS-04 的读数途径） |
| NB-E-S-lseek | lseek | N-02 | SEEK_DATA/SEEK_HOLE 读 /work 文件布局 | — | — |
| NB-E-S-access | access / faccessat2 | N-01；N-02（faccessat2 的目录 fd） | 存在性探测（/var/lib 不可见 [M] checks L199）；AT_EACCESS；faccessat2 的 dirfd：相对路径从这个目录 fd 解析（fs/open.c::do_faccessat 经 user_path_at(dfd)，同 openat 的 dirfd） | — | — |
| NB-E-S-getdents64 | getdents64 | N-02 | 目录 fd：/proc（只列 pid 目录与 self/thread-self）、/work、/runtime、/dev、/tmp、/dev/shm | — | — |
| NB-E-S-readlink | readlink / readlinkat | N-01；N-02（readlinkat 的目录 fd） | readlinkat 的 dirfd：相对路径从这个目录 fd 解析，空路径时读 dirfd 本身指向的符号链接（fs/stat.c::do_readlinkat）；/proc/self/exe、cwd、root、fd/N（"socket:[ino]"、"/dev/null"）、ns/*（"pid:[4026…]"：本 ns 的 inode 号）、map_files/*、符号链接 bin/lib/lib64/usr；/work、/runtime 内符号链接 | — | ns inode 号是全局 nsfs 号 |
| NB-E-S-chdir | chdir | N-01 | 把 cwd 换到任何可 search 的目录；/work、/tmp、/proc/self/* 目录 | cwd 继承给子进程 | fchdir ∉ L |
| NB-E-S-getcwd | getcwd | — | 读自己的 cwd 路径（相对本 root） | — | — |
| NB-E-S-fsync | fsync / fdatasync | N-02 | /work 文件（btrfs log tree/事务提交：与同文件系统的其他子卷、store 共享；宿主块设备 I/O）、目录 fd、tmpfs（无操作）、/runtime 只读 fd（无脏页）、fd 3（EINVAL） | — | CCT 缺口 6 的待查项；sync/syncfs 固定禁止 |
| NB-E-S-execve | execve | N-01；N-02（fd 继承）；N-06（binfmt_misc 登记） | 路径：/runtime 与 /work 下任何可执行文件（/work 允许 exec [M] checks L211）；解释器：ELF PT_INTERP 在本 mount ns 解析；脚本 `#!`；binfmt_misc：全局登记按 magic 匹配，解释器路径在调用方 ns 解析（开发机三条：/init、/usr/bin/python3.12、/usr/bin/lli-18 → 沙箱内 /init 不存在，/usr → /runtime/usr）；argv/envp 自由；AT_SECURE；setuid/setgid 位与 file capability 因 nosuid 与 NNP 无效 | 保留：fd 3、凭据、NNP、seccomp、rlimit、SIG_IGN、cwd/root、cgroup、keyring、亲和性；清除：O_CLOEXEC fd、robust list、altstack、POSIX 与 CPU 定时器、mm；pdeathsig 只在 secureexec 时清除，普通 exec 保留（2026-10-25 改正） | ia32/x32 入口被 KILL_PROCESS [M]；comm 置为文件名 |

## B 内存

| 行 | 调用 | 名字来源列 | 子操作 / 参数展开 | 隐式主体与继承项 | 固定条件与事实 |
|---|---|---|---|---|---|
| NB-E-S-mmap | mmap | N-02；N-06（池） | fd 类别 × prot × flags：MAP_SHARED 可写（/work：脏页回写；tmpfs；/dev/zero 匿名共享）、MAP_PRIVATE、PROT_EXEC（/work 允许）、MAP_HUGETLB（hugetlb 池，开发机 0 页）、MAP_LOCKED（RLIMIT_MEMLOCK）、MAP_POPULATE、MAP_FIXED、MAP_NORESERVE（overcommit_memory=0 启发式）、MAP_SYNC；匿名映射占宿主内存（无 memcg） | RLIMIT_AS、DATA、MEMLOCK（继承）；vm.max_map_count | — |
| NB-E-S-mprotect | mprotect | — | 自己映射；PROT_EXEC 转换（MDWE 继承为关） | — | — |
| NB-E-S-munmap | munmap | — | 释放；共享映射的脏页留待回写 | — | — |
| NB-E-S-brk | brk | — | 匿名内存 | RLIMIT_DATA | — |
| NB-E-S-madvise | madvise | N-06（THP、回收） | MADV_DONTNEED/FREE、MADV_HUGEPAGE/NOHUGEPAGE（khugepaged）、MADV_COLLAPSE（同步合并）、MADV_REMOVE（在 /work 共享映射上打洞 = 改文件）、MADV_COLD/PAGEOUT（文件页需可写权限）、MADV_WIPEONFORK、MADV_DONTFORK、MADV_POPULATE_*、MADV_HWPOISON/SOFT_OFFLINE（需 CAP）、MADV_DODUMP/DONTDUMP（core 已关） | — | PR_SET_MEMORY_MERGE（整个 mm 登记给 KSM）不检查能力，见 prctl 一行；宿主 ksm/run=0 |

## C 进程、信号、线程

| 行 | 调用 | 名字来源列 | 子操作 / 参数展开 | 隐式主体与继承项 | 固定条件与事实 |
|---|---|---|---|---|---|
| NB-E-S-clone | clone | N-03（新任务）；N-02（CLONE_PIDFD 返回 pidfd）；N-06（宿主 pid 号空间消耗） | flags 逐位：CLONE_VM/FILES/FS/SIGHAND/THREAD/SYSVSEM/SETTLS/PARENT_SETTID/CHILD_SETTID/CHILD_CLEARTID（延迟写地址）/VFORK/PIDFD/IO；CLONE_PARENT（ns init 调用 → EINVAL）；CLONE_NEWNS/NEWPID/NEWNET/NEWIPC/NEWUTS/NEWCGROUP/NEWTIME（需 CAP_SYS_ADMIN → EPERM）；CLONE_NEWUSER 由过滤器拒绝；CLONE_PTRACE/UNTRACED；exit_signal | 新任务继承 §4 NB-N-08 全部；进程组/会话不变（仍是 spawner 的）；RLIMIT_NPROC（per uid u）；threads-max、pid_max 全局 | 过滤器：A0 含 CLONE_NEWUSER → EPERM；clone3 → ENOSYS（libc 回退到 clone [M] pthread=0） |
| NB-E-S-unshare | unshare | — | CLONE_FILES/FS/SYSVSEM/NEWNS…（NEWNS 等需 CAP → EPERM）；CLONE_NEWUSER 拒绝 | — | 同上 |
| NB-E-S-exit | exit / exit_group | N-07（父进程、ns 成员） | 退出时：robust list 与 clear_child_tid 写；fd 关闭（锁/租约释放）；PID 1 退出 → ns 内全部 SIGKILL → spawner SIGCHLD + waitpid；非 init 退出 → 本 ns 父进程 | — | 01 NB-E-P-02（退出链）、NB-E-A-01、NB-E-A-03、NB-E-A-04、NB-E-A-05、NB-E-K-07（父进程通知）；追踪见 01-trace-events |
| NB-E-S-wait4 | wait4 / waitid | N-03；N-02（P_PIDFD） | 只能等本 ns 内自己的子进程；WUNTRACED/WCONTINUED；rusage 读自己子进程的资源统计 | — | — |
| NB-E-S-kill | kill | N-03；N-07 | pid>0（本 ns）；pid=0（当前进程组 = spawner 的进程组：成员含 engine、spawner、worker、其他 execution；权限按 uid，SIGCONT 例外按同会话放行）；pid=-1（本 ns 可见的全部进程）；pid<-1（进程组号在本 ns 解析）；信号 0 作存在性探测 | 进程组、会话 | 向本 ns init 发 SIGKILL/SIGSTOP 被忽略；kernel/signal.c check_kill_permission [R] 待钉 |
| NB-E-S-tgkill | tgkill | N-03 | tgid/tid 在本 ns | — | — |
| NB-E-S-setsid | setsid | N-07 | 建新会话与进程组：离开 spawner 的会话（PID 1 是进程组组长时 EPERM？组长是 spawner，PID 1 不是组长 → 允许） | — | 之后 kill(0) 只到自己的组 |
| NB-E-S-rt_sigaction | rt_sigaction / rt_sigprocmask / rt_sigreturn / sigaltstack / pause / restart_syscall | — | 自己的处置、掩码、备用栈；SA_NOCLDWAIT 对自己的子进程 | 处置继承自 spawner（NB-DI-16） | — |
| NB-E-S-getpid | getpid / getppid / gettid | — | ns 内编号；getppid()=0 | — | — |
| NB-E-S-getuid | getuid / geteuid / getgid / getegid / getresuid / getresgid / getgroups | — | 读 u、g、空补充组 | — | — |
| NB-E-S-setuid | setuid | — | 无 CAP_SETUID：只能设为 u（无操作）；setuid(0) → EPERM [M] | — | — |
| NB-E-S-prlimit64 | prlimit64 | N-03 | pid=0 或本 ns 内自己的任务；读全部 rlimit（含继承值 NB-MM-01）；降低软/硬限制；提高硬限制需 CAP_SYS_RESOURCE | 继承的 rlimit | RLIMIT_CORE 硬限 1 不可提回 [M] OBS-06 |
| NB-E-S-prctl | prctl | N-03（PR_SET_PTRACER、PR_SCHED_CORE 的 pid）；N-06（comm 进 kernel 日志与宿主 ps；PR_SET_MM_MAP 改的参数区与环境区地址、auxv，宿主经 /proc 读 cmdline 与 environ；PR_SET_MEMORY_MERGE 的 KSM 登记） | 子操作各成一行：PR_SET_NAME（comm）、PR_SET_PDEATHSIG、PR_SET_CHILD_SUBREAPER、PR_SET_DUMPABLE、PR_SET_PTRACER、PR_SET_TIMERSLACK、PR_SET_THP_DISABLE、PR_SET_SPECULATION_CTRL（自己）、PR_SET_SYSCALL_USER_DISPATCH、PR_SET_VMA、PR_SET_MDWE、PR_SET_SECCOMP（再加过滤器）、PR_SET_NO_NEW_PRIVS、PR_SET_KEEPCAPS、PR_SET_TSC、PR_MCE_KILL、PR_SET_FP_MODE、PR_GET_*；不检查能力的：PR_SET_MM 的 PR_SET_MM_MAP 与 PR_SET_MM_MAP_SIZE（CONFIG_CHECKPOINT_RESTORE=y，kernel/sys.c::prctl_set_mm 在能力检查之前转到 kernel/sys.c::prctl_set_mm_map；PR_SET_MM_MAP_SIZE 只把结构的大小写回调用者给的地址，不改 mm；PR_SET_MM_MAP 改本 mm 的代码段、数据段、brk、栈起点、参数区、环境区的地址与 auxv，结构里的 exe_fd 要 checkpoint-restore 能力，否则 EPERM），PR_SET_MEMORY_MERGE 与 PR_GET_MEMORY_MERGE（把整个 mm 登记给 ksmd，mm/ksm.c::ksm_enable_merge_any；宿主 ksm run=0 时不扫）；需 CAP 的：PR_SET_MM 的其余取值、PR_SET_IO_FLUSHER 与 PR_GET_IO_FLUSHER（CAP_SYS_RESOURCE）、PR_SET_SECUREBITS、PR_CAPBSET_DROP（CAP_SETPCAP）；PR_SCHED_CORE_CREATE/SHARE（core scheduling cookie：影响宿主 SMT 兄弟核的共调度 — 开发机 CONFIG_SCHED_CORE 未启用，NB-EV-018；生产宿主见 NB-MM-07） | — | — |
| NB-E-S-arch_prctl | arch_prctl | — | ARCH_SET_FS/GS、ARCH_SET_CPUID（CPUID 陷阱）、ARCH_REQ_XCOMP_PERM（AMX：更大 XSAVE 缓冲 = 内存）、ARCH_MAP_VDSO_* | — | — |
| NB-E-S-set_tid_address | set_tid_address / set_robust_list / rseq | — | 登记退出/抢占时 kernel 要写的地址（可落在 /work 共享映射） | — | 01 NB-E-A-01（clear_child_tid、robust 列表）、NB-E-A-10（rseq）；追踪见 01-trace-events |
| NB-E-S-futex | futex | N-02 间接（共享映射的 inode 键）；N-03（PI 操作：futex 字里的持有者 tid） | FUTEX_WAIT/WAKE/REQUEUE/CMP_REQUEUE/WAKE_OP/LOCK_PI/UNLOCK_PI/WAIT_BITSET/WAKE_BITSET；PI 操作（FUTEX_LOCK_PI、FUTEX_LOCK_PI2、FUTEX_TRYLOCK_PI、FUTEX_WAIT_REQUEUE_PI、FUTEX_CMP_REQUEUE_PI）把 futex 字里的 tid 在调用者的 pid namespace 里解析成持有者任务（kernel/futex/pi.c::attach_to_pi_owner 经 find_get_task_by_vpid）；私有 vs 共享键（/work 文件映射上的 futex：后继 X′ 可同键；并发无共享文件） | — | — |

## D socket（只有 fd 3；socket() ∉ L）

| 行 | 调用 | 名字来源列 | 子操作 / 参数展开 | 隐式主体与继承项 | 固定条件与事实 |
|---|---|---|---|---|---|
| NB-E-S-sendmsg | sendmsg / sendto | N-02（fd 3；msg_name 对已连接 STREAM → EISCONN）；N-02（SCM_RIGHTS 携带的 fd）；N-03（SCM_CREDENTIALS 里的 pid）；N-06（SCM_CREDENTIALS 里的 uid、gid，按初始 user namespace 解析） | iov 字节（协议）；cmsg：SCM_RIGHTS（任何持有的 fd：/work 文件、/runtime 文件、nsfd、pidfd、/proc 条目、目录）、SCM_CREDENTIALS（uid 线 T-20；ucred 的 pid 须等于调用者的 tgid、uid 与 gid 须是调用者自己的，否则要能力，net/core/scm.c::scm_check_creds；通过后 pid 在调用者的 pid namespace 里解析成引用，net/core/scm.c::__scm_send 经 find_get_pid）；MSG_OOB、MSG_NOSIGNAL、MSG_DONTWAIT、MSG_EOR；SO_SNDBUF 上限 | engine 收到的 fd 在关闭前占 engine 的 fd 表与 RLIMIT_NOFILE；在途 fd 维持对象存活 | 协议内容归 2.2/3.1；engine 关闭一切收到的 fd（conn L459–461） |
| NB-E-S-recvmsg | recvmsg / recvfrom | N-02 | MSG_PEEK、MSG_TRUNC、MSG_CMSG_CLOEXEC；engine 不发 fd | — | — |
| NB-E-S-getsockopt | getsockopt | N-02；N-06 | SO_PEERCRED（spawner 建 socketpair 时的凭据：uid 0、gid 0，pid 在调用者的 ns 里渲染为 0；2026-10-25 改正）、SO_PEERSEC（LSM 标签）、SO_PEERGROUPS、SO_PEERNAME（对端地址：两端无名）、SO_PEERPIDFD（在调用者 fd 表里装一个指向对端凭据所记进程即 spawner 的 pidfd，02 §3.3 导出，2026-10-26 补进本表）、SO_COOKIE（全局 cookie 计数，一次分配）、SO_NETNS_COOKIE（socket 所属的宿主 net namespace 的 cookie）、SO_MEMINFO、SO_SNDBUF/RCVBUF、SO_INCOMING_CPU、SO_PASSCRED（自己端）、SO_ERROR、SO_TYPE、SO_DOMAIN、SO_PROTOCOL；其余 47 个 SOL_SOCKET 选项列在 02 §3.3 的 /OTHER 行 | — | setsockopt ∉ L |
| NB-E-S-getsockname | getsockname / getpeername | N-04 | 两端无名：返回 sun_family 长度 2 [M] checks L212 | — | — |
| NB-E-S-shutdown | shutdown | N-02 | SHUT_RD/WR/RDWR：engine 端读到 EOF/EPIPE（交付的通道上的操作） | — | — |
| NB-E-S-poll | poll / ppoll | N-02 | 任何 fd 的就绪；POLLPRI | — | — |

## E 时间、随机、身份读数

| 行 | 调用 | 名字来源列 | 子操作 / 参数展开 | 隐式主体与继承项 | 固定条件与事实 |
|---|---|---|---|---|---|
| NB-E-S-clock_gettime | clock_gettime | N-06（宿主时钟）；N-03（CPU 时钟号里编码的 pid）；N-02（动态时钟号里编码的 fd） | CLOCK_REALTIME、MONOTONIC、BOOTTIME（宿主开机时长 [M] OBS-05）、PROCESS/THREAD_CPUTIME、TAI；vdso 路径；负的时钟号按语义展开：CPU 时钟号编码一个 pid，在调用者的 pid namespace 里解析（kernel/time/posix-cpu-timers.c::pid_for_clock：线程时钟限本线程组，进程时钟可以是本 namespace 里任何进程），CLOCKFD 编码一个 fd（kernel/time/posix-timers.c::clockid_to_kclock 转到 kernel/time/posix-clock.c::get_clock_desc，fget 后要求是 posix 时钟设备，否则 EINVAL） | 无 time ns | — |
| NB-E-S-nanosleep | nanosleep / clock_nanosleep | N-03（clock_nanosleep 的 CPU 时钟号里编码的 pid） | 相对或绝对（TIMER_ABSTIME 对 CLOCK_REALTIME：宿主时间）；timerslack 继承；clock_nanosleep 的 CPU 时钟号同 clock_gettime 一行：进程时钟的 pid 在调用者的 pid namespace 里解析，并在那个进程上挂一个临时 CPU 定时器直到到期（kernel/time/posix-cpu-timers.c::do_cpu_nanosleep），线程时钟只能指同一线程组里别的线程（指本线程返回 EINVAL）；CLOCKFD 的动态时钟没有 nsleep 方法，返回 EOPNOTSUPP，不解析 fd（kernel/time/posix-clock.c 的 clock_posix_dynamic） | — | — |
| NB-E-S-getrandom | getrandom | N-06（CRNG） | GRND_RANDOM、GRND_NONBLOCK、GRND_INSECURE | — | 不耗尽、不阻塞（5.6+） |
| NB-E-S-uname | uname | N-06（UTS） | sysname、nodename（宿主 hostname）、release、version、machine、domainname | 无 uts ns | — |
| NB-E-S-fcntl | fcntl | N-02；N-03（F_SETOWN 的 pid）；N-07 | 子操作各成一行：F_DUPFD/F_DUPFD_CLOEXEC（fd 复制，受 RLIMIT_NOFILE）、F_GETFD/F_SETFD、F_GETFL/F_SETFL（O_NONBLOCK、O_APPEND、O_ASYNC → SIGIO、O_DIRECT、O_NOATIME）、F_GETLK/F_SETLK/F_SETLKW 与 F_OFD_*（/work 文件记录锁：对后继 X′ 与可信观察者可见；随进程/OFD 消亡）、F_GETOWN/F_SETOWN/F_*_EX（pid 在本 ns 解析；信号投递按 sigio_perm 核 uid）、F_GETSIG/F_SETSIG、F_SETLEASE/F_GETLEASE（/work 文件租约：需 owner；破坏时 kernel 阻塞打开者至多 45 s —— SPEC §4.1"控制"的例子）、F_NOTIFY（dnotify，目录事件以信号送自己）、F_GETPIPE_SZ/F_SETPIPE_SZ（无 pipe）、F_ADD_SEALS/F_GET_SEALS（仅 memfd）、F_GET_RW_HINT/F_SET_RW_HINT | — | leases-enable=1、dir-notify-enable=1（开发机） |

## F 行数核对

| 类 | 调用数 | 说明 |
|---|---|---|
| A 文件与路径 | 13 行，20 个调用 | openat、read、readv、write、writev、close、fstat、newfstatat、statx、lseek、access、faccessat2、getdents64、readlink、readlinkat、chdir、getcwd、fsync、fdatasync、execve |
| B 内存 | 5 行，5 个 | mmap、mprotect、munmap、brk、madvise |
| C 进程 | 16 行，33 个 | clone、unshare、exit、exit_group、wait4、waitid、kill、tgkill、setsid、rt_sigaction、rt_sigprocmask、rt_sigreturn、sigaltstack、pause、restart_syscall、getpid、getppid、gettid、getuid、geteuid、getgid、getegid、getresuid、getresgid、getgroups、setuid、prlimit64、prctl、arch_prctl、set_tid_address、set_robust_list、rseq、futex |
| D socket | 6 行，10 个 | sendmsg、sendto、recvmsg、recvfrom、getsockopt、getsockname、getpeername、shutdown、poll、ppoll |
| E 时间、随机、身份读数 | 5 行，6 个 | clock_gettime、nanosleep、clock_nanosleep、getrandom、uname、fcntl |

20 + 5 + 33 + 10 + 6 = 74，与 L 的 74 个一致；行数 13 + 5 + 16 + 6 + 5 = 45（2026-10-26 改正 A、C、E 三类的行数）。S2 建矩阵时每个调用一行，子操作按上表拆开；本表的分组只是阅读顺序。
