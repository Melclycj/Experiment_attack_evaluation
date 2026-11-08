# native — C17 sandbox/spawner、接收库与检查

engine 复用的 C 部分：spawner、bootstrap、`transport.c` 接收库、文件 worker、策略编译与全部检查。
由本目录维护；功能与实现说明见 W2 原件的 [sandbox README](../../lab/experiments/w2/implementation/sandbox/README.md)。

## 来源（2026-10-18 复制）

自 W2 [implementation](../../lab/experiments/w2/implementation/README.md) 复制；W2 原件已在 commit `a2404265`
提交并冻结，作为已实测证据对应的版本。复制后用 sha256 逐个核对 2026-09-11 验收运行的输入摘要
（[acceptance-full-7.json](../../lab/experiments/w2/runs/20260911T060920Z-p2a-sandbox-acceptance/acceptance-full-7.json)）：

- **31 个文件逐字节相同**：`Makefile`、`sandbox/` 下全部 `.c` / `.h`、`checks/` 下全部 `.c` 及
  `check_catalogs.py`、`check_wire.py`、`engine_fixture.py`。
- **3 个文件只改了路径**，因为设计与计划文档仍留在 W2：`checks/run_sandbox_checks.py`（仓库根改为
  `parents[2]`，W2 文档经 `W2` 常量读取）、`checks/run_checks.py`（仓库根、run 目录改为本项目的
  runs 目录、设计文档从 W2 读取）、`checks/check_sources.py`（规范文本从 W2 的 engine-design 读取）。

复制后在 WSL（内核 6.6.87.2-microsoft-standard-WSL2，GCC 13.3.0）用全新构建目录执行
`make all sandbox` 成功；不需特权的 `check-contract` 与 `check_sources.py` 均通过（2026-10-18）。
需要 root 与 btrfs loop 镜像的 sandbox 回归已在本目录重跑作为基线：[runs/20261018T025210Z-sandbox-baseline](../runs/20261018T025210Z-sandbox-baseline/README.md)，169 个 case 通过。

## 复制后的改动

- **2026-10-18，`getresuid` 重读**（设计第三次修订，conn E-01 身份补充）：`sandbox/support.c` 的 `w2_drop` 在
  `setresuid` 之后、任何过滤器安装之前重读 real/effective/saved uid，三者不全等于目标 uid 即失败（stage=uid）；
  bootstrap、engine 与文件 worker 降权共用此函数。`checks/run_sandbox_checks.py` 增加测试构建注入点
  `uid.reread` 的两例（bootstrap 与文件 worker）。自此 `support.c` 与 W2 实测版本不再逐字节相同（原 31 个中其余 30 个
  仍相同）；`run_sandbox_checks.py` 原本就只改了路径，此次另加两例；
  改后回归见 [runs/20261018T070548Z-uid-reread](../runs/20261018T070548Z-uid-reread/README.md)。

- **2026-10-19，回归运行器观察 SO_PASSCRED 次序**（engine-requirements §2 第 145 行）：`checks/run_sandbox_checks.py` 的 busy 一例
  strace 过滤加上 socketpair 与 setsockopt，并新增 `passcred_before_clone` 检查 spawner 先设 SO_PASSCRED 再 clone。产品代码未改。
  首次运行见 [runs/20261018T231806Z-sandbox-passcred-order](../runs/20261018T231806Z-sandbox-passcred-order/README.md)。
- **2026-10-19，测试池 uid 改为 70000–70002**（开发机部署前提：原池 60000 落在 login.defs 的登录用户范围内）：`checks/` 下的
  运行器、fixture 与检查程序，以及 `sandbox/spawner.c` 中只在测试构建（`W2_TESTING`）里存在的 reap 注入点（`r->uid==70001`）。
  生产构建 `w2-cell`、`libw2sandbox.so` 改前改后字节相同；自此 `spawner.c` 也与 W2 实测版本不再逐字节相同（只差这一行测试代码）。
  重跑见 [runs/20261019T010923Z-sandbox-pool-70000](../runs/20261019T010923Z-sandbox-pool-70000/README.md)。
- **2026-10-23，procfs 遮蔽与固定禁止项**（prove 1.1 开工前的构造改动）：`sandbox/child.c` 的 proc 挂载加 `subset=pid`；
  `sandbox/policy.c` 的固定禁止列表加 `sysinfo`、`sync`、`syncfs`。`checks/` 下 agent fixture、回归运行器与 catalog 检查加对应探测与断言。
  回归见 [runs/20261023T052552Z-sandbox-procfs-sync](../runs/20261023T052552Z-sandbox-procfs-sync/README.md)。
- **2026-10-23，core dump 上限**：`sandbox/child.c` 在降权前把 RLIMIT_CORE 设为 1:1（注入点 `core.limit`，失败阶段沿用 fd_cleanup）；
  `sandbox/support.h` 加 `#include <sys/resource.h>`。回归见 [runs/20261023T105939Z-sandbox-core-limit](../runs/20261023T105939Z-sandbox-core-limit/README.md)。

## 构建

在 WSL 中：`make BUILD_DIR=<全新的 Linux 本地目录> all sandbox`。产物不写入本仓库。
本项目以 `.gitattributes` 固定 LF 行尾；在 Windows 侧检出时也不会转成 CRLF。

## fuzz（本项目新增，不来自 W2）

`fuzz/` 是 `transport.c` 的三个 libFuzzer 入口（数据通道收帧 `w2_frame_receive`、ancillary 解析 `w2_ancillary`、控制记录
解析 `w2_control_parse`），加 gcc 回放驱动、种子生成与运行脚本，服务 BUILD-PLAN §5 的 R-G2-11 检查。工具为 clang-18 与
libFuzzer（为此新装 `clang-18`、`libclang-rt-18-dev`，用户 2026-10-19 同意）。在 WSL 中以非 root 用户运行：
`bash native/fuzz/run_fuzz.sh <已建好且只含 README.md 的 run 目录> <每个入口的秒数>`。`sandbox/` 不因此改动。
