# engine 实现验证记录

BUILD-PLAN §4 第 5 步所说的 validation 记录，在首次需要记录时创建（2026-10-18），第 4 步（检查）补齐逐条映射
（2026-10-19）。每条按 [verification-plan](../lab/experiments/w2/implementation/verification-plan.md) 的可追溯链记：
条款/源身份 · 设计位置 · 实现位置与构建身份 · 验证方法/判据 · 原始观察/run ID · 结果及限制。

## 构建与证据身份

- **条款源**：[engine-requirements](../../Thesis/Work/Design/sandbox-mediated-agent-execution/engine-requirements.md)
  blob `20acd533e99dd35c`，§1–§8 共 97 条 must；下表"行号"是该文件的行号。第 164、208 行的需求句在 2026-10-19 按用户批准改成
  与设计一致（uid-binding 线判断两条读法都接受），其余行与此前的 blob `4aecaa3176c589d3` 相同，行号不变。该文件的 tag 与设计位置仍描述
  2026-10-12 的冻结版本；设计在 2026-10-18 已吸收其中的 unstated 与"(design chooses)"条目（见该文件第 28–45 行），
  所以下表的设计位置按当前设计给出。
- **设计**：connections.md `0c16e567a34aa441`（下称 conn）、resources-routing.md `1a8ea18374b07431`（rr）、
  supporting-interfaces.md `c8aff1a37d73561b`（si），三份均在 `../lab/experiments/w2/implementation/engine-design/`。
  设计行号指这三个 blob。
- **2026-10-19 C 侧帧体解析删除**（uid-binding 线 step-4 复查 S4 F-01，用户同意）：`transport.c` 的 `w2_frame_receive` 原在逐片比对
  之后用 jansson（`w2_frame_json`）解析帧体再丢弃，设计 conn E-02 第 487–492 行没有这一步（C 侧只分帧与比对，帧体由 Python
  标准库 json 解析）；这一步把一个未插桩的第三方解析器放在比对之后、与读取器绑定字段同一堆对象的缓冲上。删去该行后
  `transport.c` sha256 前缀 `32ef6fc600d0330c`；engine 包未改。内容不合法的帧仍被拒、仍关闭原通道，拒绝从 C 侧移到 Python
  解析：事件仍为 receive_rejected、stop 仍为 protocol_error，行的 close_reason 由 receive_rejected 变为 protocol_error。测试随之：
  `native/checks/check_wire.py` 十个内容例改为断言原样交出，`tests/test_phases.py` 三例与 `tests/test_receive_root.py` 一例改期望，
  新增 `tests/test_receive.py::test_c_reader_parses_no_body`（反向对照存档）。运行：
  [sandbox 回归](runs/20261019T024756Z-sandbox-no-c-parse/README.md)（171 个 case）、
  [集成运行](runs/20261019T025203Z-engine-no-c-parse-rerun/README.md)（单元 364 passed、32 skipped，root 单元 32 passed，32 个 case；
  [首次](runs/20261019T025041Z-engine-no-c-parse/README.md)因 root 单元一例旧期望失败，保留不作证据）、
  [fuzz](runs/20261019T025332Z-fuzz-no-c-parse/README.md)（三入口各 3600 秒）。下文 R-G2-11 条目与第 175 行按此更新；其余条目
  引用的 `transport.c` 行号在第 238 行之后的减一。
- **2026-10-20 两处 engine 修正**（uid-binding 线 step-4 转来的发现，用户 2026-10-19 同意在同一 session 修）：`engine/startup.py`
  按 scope S14 改用 `PR_SPEC_FORCE_DISABLE` 并检查设置后状态含 FORCE 位（sha256 前缀 `a6534759f8d93188`）；`engine/phases.py` 的
  receive_rejected 记录去掉 reject 组里的 execution_id，只留 cause 与 detail，按 si E-09 只以 connection_ref 指连接（`8748205e5fd9d48a`）；
  测试工具 `engine/testing/scenario.py` 随之按 connection_ref 归属拒收事件。运行：[集成运行](runs/20261020T055739Z-engine-force-disable-reject-fields-rerun/README.md)
  （单元 364 passed、32 skipped，root 单元 32 passed，32 个 case；[首次](runs/20261020T055528Z-engine-force-disable-reject-fields/README.md)因测试工具读
  旧字段失败，保留不作证据；反向对照存档）、[sandbox 回归](runs/20261020T055915Z-sandbox-after-engine-fixes/README.md)（171 个 case）。上文与下表引用的 `phases.py` 行号从第 80 行起、`startup.py`
  行号从第 85 行起，在这次修正后各加一。
- **2026-10-20 补充证据运行**（uid-binding 线，用户 2026-10-20 批准）：只加测试与集成运行器，产品代码与 native 代码未改，未重跑
  sandbox 回归。`tests/test_receive_root.py` 新增四组 root 用例（第 164、167、168、169 行下各记一组，含对照与反向对照）；
  `checks/run_engine_checks.py` 与 `engine/testing/scenario.py` 新增两代 engine 运行（见下文"R-GX-04 两代运行"）。运行：
  [集成运行](runs/20261020T154357Z-engine-extra-evidence-rerun/README.md)（单元 364 passed、47 skipped，root 单元 47 passed，33 个 case；
  [首次](runs/20261020T154146Z-engine-extra-evidence/README.md)因运行器自己的一条回收断言写错而失败，保留不作证据）。
- **2026-10-23 procfs 遮蔽与固定禁止项**（prove 1.1 开工前的构造改动，用户 2026-10-23 批准；设计记录见
  [no-bypass 设计修订](../../Thesis/Work/Submission/prove/no-bypass/design-revision-2026-10-23.md)）：`native/sandbox/child.c` 第 64 行
  proc 以 `subset=pid` 挂载，sandbox 内只剩 pid 目录与 self、thread-self，全局计数文件不再可见（sha256 前缀 `0bd12387504ef265`）；
  `native/sandbox/policy.c` 第 16 行固定禁止列表加 `sysinfo`、`sync`、`syncfs`，任何 catalog 策略都不能允许它们（`5e9b7f382eb23c61`）。
  两处都是行内改动，本文件引用的两文件行号不变。测试：`agent_fixture.c` 加四个探测并改读 `/proc/self/net/dev`，
  `run_sandbox_checks.py` 加对应断言（行内改动，行号不变），`check_catalogs.py` 加三个禁止项变体。运行：
  [改产品代码之前](runs/20261023T052321Z-sandbox-procfs-sync-red/README.md)与[只改禁止列表之后](runs/20261023T052442Z-sandbox-procfs-sync-red2/README.md)
  两次按预期失败（反向对照存档）；[sandbox 回归](runs/20261023T052552Z-sandbox-procfs-sync/README.md)（171 个 case）、
  [集成运行](runs/20261023T052901Z-engine-procfs-sync/README.md)（单元 364 passed、47 skipped，root 单元 47 passed，33 条记录）通过。
  局限：`subset=pid` 要求 kernel 5.8 及以上；真实 runtime（Node 与 Pi）读不到 `/proc/cpuinfo`、`/proc/meminfo`、`/proc/sys` 时的行为未测。
- **2026-10-23 core dump 上限**（同一设计修订的第二项，用户 2026-10-23 批准）：`native/sandbox/child.c` 第 103 行在关闭多余 fd 之后、降权之前
  把 RLIMIT_CORE 设为 1:1（sha256 前缀 `95f261a1fd188609`），kernel 遇到上限 1 时放弃 core dump，包括交给宿主处理程序的那一种；
  agent 降权后没有 CAP_SYS_RESOURCE，提不回硬上限。`native/sandbox/support.h` 加 `#include <sys/resource.h>`（`59957a218c82a07d`）。
  child.c 的改动在行内，本文件引用的行号不变。测试：fixture 在已有行内读 `/proc/self/limits`，回归运行器在已有行内断言上限为 1 1，
  故障注入清单加 `core.limit`。运行：[改产品代码之前](runs/20261023T105849Z-sandbox-core-limit-red/README.md)按预期失败，并在宿主
  Windows 临时目录留下 2 个 fixture dump（反向对照存档）；[sandbox 回归](runs/20261023T105939Z-sandbox-core-limit/README.md)（172 个 case，
  宿主无新 dump）、[集成运行](runs/20261023T110208Z-engine-core-limit/README.md)（单元 364 passed、47 skipped，root 单元 47 passed，33 条记录，
  宿主无新 dump）通过。局限：kernel 一侧的依据（fs/coredump.c 对上限 1 的处理）待按固定版本读源码；生产宿主的处理程序未测。
- **实现**：提交 74833c58 的 `engine/` 与 `native/sandbox/`，第 4 步只改了 `spawner.c` 中仅存在于测试构建（`W2_TESTING`）的
  一个 reap 注入点的 uid（测试池改为 70000 起，2026-10-19），生产构建 `w2-cell` 与 `libw2sandbox.so` 改前改后字节相同。sha256 前缀：`engine/control.py`
  `1da49cfebd09c1c6`、`ffi.py` `ebe7ed601f084e44`、`handlers.py` `dbff9c0cd9de0481`、`lifecycle.py` `e43b2a1288c2919c`、
  `loop.py` `a99fd49fcb7e325c`、`main.py` `e1d118f9b9727fc7`、`objects.py` `33122ffd2cc5b0e1`、`operations.py`
  `2c2e115a32e1b5b7`、`phases.py` `050b18aadc9dd172`、`receive.py` `e475696d0ec08a71`、`records.py` `965c35a7d1434f4c`、
  `requests.py` `25ab8ea661ab4fa5`、`startup.py` `69f5a91ec198f680`、`tasks.py` `7b92fe211ef15ef2`、`writer.py`
  `971ba4efad29926e`；`native/sandbox/transport.c` `18d4bb8d90f97829`、`spawner.c` `357185da4306f7fe`（测试池改动前为 `1c7a8d0c387464e5`）、`child.c`
  `ddc51c3caae89d03`、`support.c` `08b64d779d501ed9`、`policy.c` `135b368df034b429`。下表的 `文件:行号` 都指这些文件。
- **第 4 步新增的测试与工具**：`tests/test_by_reference.py`、`tests/test_handoff.py`、`tests/test_receive_root.py` 末尾的
  R-G2-13 两组、`tests/conftest.py` 的 `open_fds`（改为 fcntl 逐号探测）、`native/fuzz/`（三个 harness、回放驱动、种子、
  运行脚本）、`native/checks/run_sandbox_checks.py` 的 `passcred_before_clone`。
- **证据栏所指的运行**（均在 `runs/` 下；都是整体 review 修正之后的运行）：
  - 集成运行 = [20261018T231612Z-engine-step4-review-fixes](runs/20261018T231612Z-engine-step4-review-fixes/README.md)：非特权
    单元 362 passed、32 skipped，root 单元 32 passed，32 个集成 case 通过。"（单元）""（root 单元）"指其中的单元套件。
  - sandbox 回归 = [20261018T231806Z-sandbox-passcred-order](runs/20261018T231806Z-sandbox-passcred-order/README.md)：171 个
    case 通过，含 SO_PASSCRED 次序观察。
  - fuzz 运行 = [20261018T231525Z-fuzz-transport-oracles](runs/20261018T231525Z-fuzz-transport-oracles/README.md)（修正判据后）。
  - 测试池改为 70000–70002 后的重跑（开发机部署前提，§8 第 252 行；结果与上面两次相同）：
    [sandbox 回归](runs/20261019T010923Z-sandbox-pool-70000/README.md)（171 个 case）、
    [集成运行](runs/20261019T011226Z-engine-pool-70000/README.md)（单元 362 passed、32 skipped，root 单元 32 passed，32 个 case）。
  - 必要性分析后的补充（2026-10-19）：第 146、170 行新增源码扫描测试，见文末"必要性分析后的补充"一节的运行。
  - AA-13 运行 = [20261018T152246Z-aa13-deregistration](runs/20261018T152246Z-aa13-deregistration/README.md)。
  - 被取代的第 4 步首次运行（保留，不作证据）：[集成](runs/20261018T220504Z-engine-step4-checks/README.md)、
    [sandbox](runs/20261018T220655Z-sandbox-step4/README.md)、[fuzz](runs/20261018T215700Z-fuzz-transport/README.md)。
    整体 review 发现其中的 fd 泄漏断言与两项 fuzz 附加判据测不出泄漏、诱饵就位太晚，见"整体 review"一节。

**结果用语**：满足（测试）、满足（代码阅读）、满足（测试加代码阅读）、由构造满足、以更严格方式满足、
设计已写明（只要求设计写明的条目；同时核对实现与所写读法一致）、读法待用户确认（实现按所写读法满足，但读法是对条款
文字的解释，按 BUILD-PLAN §7 报用户）、超出范围（写明归属）、部署前提（附开发机读数）、未满足。混合条目按子句分别写。

## 结果总览

（各节统计见文末"计数"。）第 4 步没有发现 engine 或 native 产品代码违反某条 must。整体 review 发现的是检查本身的缺陷
（fd 泄漏断言、两项 fuzz 附加判据、诱饵就位时机、R-G2-13 用例的区分力）与几处理由或措辞，已修正并重跑，见"整体 review"一节。
第 164、208 两行的读法经 uid-binding 线判断接受，需求句于 2026-10-19 按用户批准改成与设计一致。
开发机上 §8 第一条部署前提原先不成立（池 uid 60000 落在 `/etc/login.defs` 的登录用户范围 1000–60000 之内）；测试池已改为
70000–70002 并重跑回归与集成运行，读数见 §8 第 252 行。

## BUILD-PLAN §5 的五项 PLAN 检查

### R-G2-12 启动自检

- **条款**：第 219 行（engine 启动自检须见 `/proc/self/uid_map` 为身份映射、overflow uid 可读，否则拒绝服务；不替代 S13）。
- **设计位置**：conn E-01 对象、字段和所有权，第 87–89 行。
- **实现**：`startup.py:61–72`（读五项环境值，交给与 spawner 同一 C 解析 `w2_environment_values`），`main.py:40–43`
  （在打开控制端点之前）；拒绝时 `main.py:61–64` 输出一行 `startup_refused` 并以 3 退出。
- **验证**：正向——集成运行 production-entry 一例中 `startup_checked` 记下 uid_map `0 0 4294967295`、overflowuid/gid
  65534；反向——同一生产入口在 `unshare --user --map-root-user` 下（uid_map `0 0 1`）拒绝服务，exit 3，理由含 uid_map；
  单元 `test_identity_map_accepted`、`test_non_identity_map_refused`（参数化的多种非身份映射）、`test_unreadable_refused`。
- **结果及限制**：满足（测试）。自检只证明 engine 所在 namespace 的映射是身份映射，不证明它是 initial user namespace
  （第 256 行，部署前提）。

### R-G2-11 字节与凭据的对应（fuzz）

- **条款**：第 175 行（parser 与 FrameReader 内存安全；设计决定方式），连同第 164、174 行。
- **设计位置**：conn E-02 第 487–492 行：FrameReader 在 C 侧 `transport.c`，以 ASan/UBSan 构建 fuzz 作为证据；Python
  只取得已比对、长度已定的整帧 bytes，以严格配置的 `json` 解析。
- **实现**：`transport.c` 全文；FFI 边界 `ffi.py:92–106`（Python 分配 65,536 字节定长缓冲并传入容量，C 只拷入整帧、
  不回传指针）；Python 侧 `receive.py:107–123`。代码阅读：数据通道上 Python 取得字节的路径只有
  `receive.py:284` → `ffi.frame_receive` → `w2_frame_receive`（另见第 158 行）。
- **验证**：fuzz 运行（修正判据后的重跑），clang-18 + libFuzzer，ASan/UBSan（`-fno-sanitize-recover=undefined`），三个入口并行
  各 3600 秒：
  - frame：`w2_frame_receive` 经真实 socketpair，内核盖章的凭据；输入决定分片、附带 SCM_RIGHTS、带外字节与 expected/overflow
    uid。判据另含返回约定（完整帧长度在 1–65,536；reader 死后不复活）与描述符检查：socketpair 仍打开时，处理完全部操作后最低
    空闲 fd 与刚建好 socketpair 时相同（收到的副本会落在这个号上）。7,152,640 次执行，覆盖边 112 → 128。
  - ancillary：原始字节模式（任意控制缓冲字节与 msg_flags，以精确大小的堆块传入）加结构化模式（内核式的合法 header，rights 可
    截短，描述符值各不相同；最后一个 header 不补齐，比内核通常写出的补齐末尾更苛刻，补齐末尾只由原始字节模式覆盖）。判据：拒绝时不交出描述符；带截断或带外标志时从不接受；读凭据时不交出描述符；结构化模式中，
    拒绝或读凭据时缓冲区里每个描述符恰好关闭一次、不关闭其他值，接受时只交出唯一的那个。142,246,729 次执行，覆盖边 86 → 112。
  - control：`w2_control_parse`。判据另含：接受的记录是 v=1、类型已知的对象。392,868,274 次执行，覆盖边 79 → 190。
  - 三个入口都没有崩溃、超时或内存超限；`overall_status=0`；最终语料由 gcc 13 的 ASan/UBSan `--coverage` 构建回放，全部退出 0。
  - 反向对照：拒绝路径不关 rights 的 `transport.c` 副本上，frame 与 ancillary 两个判据都失败（rc=77），未改的文件上通过。
  - 行覆盖（gcc 回放）：`w2_frame_receive`、`w2_control_parse` 每行都执行过，`w2_ancillary` 在 ancillary 入口中每行都执行过；
    `w2_recv_credential` 只有第 158 行（零字节返回时关闭 rights）未执行。
  - 被取代的首次 fuzz 运行（三入口各 3600 秒、无 sanitizer 报告）只支持"未发现内存错误"，其两项描述符判据无效，不作关闭证据。
  - **2026-10-19 重跑（C 侧帧体解析删除后）**：同一 harness、判据与种子，三入口各 3600 秒，`overall_status=0`，无报告：frame
    81,700,084 次执行、覆盖边 82 → 88（jansson 不再在路径上，所以少于上一次），ancillary 139,403,813 次、86 → 113，control
    390,030,460 次、79 → 197；回放全部退出 0；`w2_frame_receive` 每行都执行过，`w2_recv_credential` 仍只有第 158 行未执行。
    此后 R-G2-11 以这次运行为证据；上面的数字记录删除前的版本。
- **结果及限制**：满足（fuzz 加代码阅读）。限制：每个入口一次、一小时，无重复试验，结论是"本次运行未发现内存错误或判据违反"；
  fuzz 用 clang 构建，gcc 构建只经回放检查；2026-10-19 起数据通道的 C 路径上没有第三方解析器（control 入口经过的 jansson
  未插桩，只在 ASan 拦截分配的范围内受检；控制记录来自可信 spawner）；Python 侧的 json 解析（`receive.py:107–123`）不在 fuzz
  范围内，其内存安全依赖 CPython 运行时；frame 入口未经 fuzz 的分支
  （EOF、5 秒期限到期、reader 换绑）由单元测试与代码阅读覆盖；反向对照只演示了一种缺陷。详见 fuzz 运行的 README。

### R-G2-13 唯一比对点

- **条款**：第 171 行（recvmsg 到缓冲之间恰有一个比对点，各阶段与错误路径无旁路；阶段规则在它之后运行）。
- **设计位置**：conn E-02 每条数据消息的接收管线，第 455–466 行。
- **实现与代码阅读**：数据通道唯一的 recvmsg 在 `transport.c:154`（`w2_recv_credential`），返回前在 `transport.c:160`
  经 `w2_ancillary` 与绑定的 expected uid 比较；`w2_frame_receive`（`transport.c:224–231`）只在比较通过后推进 `used`，
  比较失败即 reader 死亡（`240`），之后每次调用都返回 -1。Python 侧 `receive_step`（`receive.py:280–300`）先调用 C reader，
  只有 COMPLETE 才进入解析（291）、schema（291）和阶段规则（294）；REJECT 直接返回 `receive_rejected`（287–288）。没有
  别的函数调用 `frame_receive`（grep）。错误路径：EOF（`transport.c:226`）、截断与意外 ancillary（`w2_ancillary`，`96–118`）、带外字节
  （`219–221`）、超期（`222`、`229`、`237`）都走同一个 `bad` 出口，不旁路比较。
- **测试**：root 单元 `test_wrong_uid_rejected_before_every_phase_rule`（新增，18 例）：三种阶段规则（STARTING、ACTIVE、
  DRAINING）× 三种帧（合法 hello、合法 request、Python schema 才拒绝的未知类型）× 两种错 uid 位置：整帧来自另一个池内 uid
  （在第一个头片失败），或头 4 字节来自 expected uid、body 来自另一个 uid（头片通过，在 body 片失败）。一律 `receive_rejected`，
  阶段规则一次也没被调用。对照 `test_right_uid_reaches_parse_and_phase_after_the_comparison`：同样的帧由 expected uid 发送时
  分别到达 Hello、`hello_repeated`、`request_in_draining`、`invalid/type`，C 拒绝的非 JSON 帧为 `receive_rejected`。既有
  `test_uid_change_inside_one_frame_rejected_before_completion`（帧中途换 uid）。
- **结果及限制**：满足（测试加代码阅读）。错 uid 的帧在比较处就失败，帧内容与阶段规则都到不了，所以"三种帧"在负向例中走同一
  条代码路径，区分只在两种失败位置（头片、body 片）；三种帧的作用是让对照例分别到达不同的阶段结果。阶段规则用
  `DataPlane._phase` 本身，行对象是只带 state 与 adapter_id 的替身；经完整 lifecycle 的错 uid 例只在 STARTING
  （`test_wrong_uid_rejected_at_first_fragment`）。

### R-G3-05 consumer 按引用携带

- **条款**：第 226 行（每个 consumer 按对象引用取得 verified context，不自行构造，不按名称、uid、fd 或 local_agent_id 查找）。
- **设计位置**：conn E-02 engine 内部的 VerifiedContext，第 581–583 行。
- **实现**：admission `requests.py:144–182`（从 `context.session_ref` 与 `context.channel_ref` 出发，RequestEntry 写一次地
  持有 Session、Channel、Execution、TaskCall、TaskBinding、GrantState）；prepare 与最终裁决 `requests.py:201–293`（只读条目
  所持对象）；冻结与授权 `operations.py:206–235`、`201–203`（CandidateOperation 持条目本身）；handler `handlers.py:147–150`
  （只收 AuthorizedOperation 与 Sink），Sink `requests.py:81–99` 只持原条目；结果与释放 `requests.py:325–525`（经
  `entry.channel.frame_writer`）；E-09 记录 `requests.py:120–132`（主体是 `VerifiedSubject.from_context` 的副本）。
- **测试**：`test_request_path_carries_objects_by_reference`（新增）：在 agent 发出请求帧之前，把 lifecycle 中该 execution_id
  对应的行换成一碰即失败的诱饵；随后 admission、prepare、最终裁决、分派、结果驱动与释放全部完成，请求在原通道上收到全部 chunk
  与 result。条目所持对象与帧到达的对象逐一是同一对象（`is`），handler 收到的 operation 与 sink 指回同一条目，该请求的每条
  E-09 记录主体都等于原 VerifiedContext 的副本。对照 `test_decoy_catches_a_lookup_by_execution_id`（4 例）：分别把 admission
  （`on_request`）、prepare、最终裁决与分派（`_final`）、结果驱动（`_drive`）改成按 execution_id 取行，同一流程都撞上诱饵而失败。
- **结果及限制**：满足（测试加代码阅读），覆盖到 stub handler 为止。诱饵只替换了 execution_id 一个键。engine 中以 uid 为键的
  表只有分配器的 `holders`，只在预留与释放时使用（`lifecycle.py:100、140、157、500–501`）；以 fd 号为键的表只有事件循环的
  注册表 `Loop.handlers`（`loop.py:50`、`73–85`），它只用来取回该 fd 当时登记的回调，派发前核对回调身份（`loop.py:112`、`122`），
  不用来找 Session、请求或行。没有以 local_agent_id 为键的表。BUILD-PLAN 要求每接入一个真实 connector 复核一次。

### R-GX-06 关联只按对象建立与清除

- **条款**：第 149 行（Channel → Session 链接安装时写一次、close 第 2 步按对象清除），连同第 148、161 行。
- **设计位置**：conn E-01 身份补充第 103–105 行；E-04 关闭第 2 步（第 851–852 行）。
- **实现**：建行时 `lifecycle.py:150–155`（Session 与 Execution 互指，Channel 尚无）；安装 `lifecycle.py:273–283`（新 Channel
  构造时带 Session，`Session.channel_id` 写一次）；清除 `lifecycle.py:460–475`（先注销、再 shutdown 与 close、再断开
  `channel.session`、再释放 reader 与 writer）。
- **测试**：`test_association_made_installed_and_cleared_by_object`（新增）：RESERVED/PREPARING 时 Session 指回 Execution、
  无 Channel；prepared 后 `channel.session is ex.session`、fd 已注册；close 后链接为 None、phase 为 CLOSED、fd 不在 loop 的
  任何注册中、reader 与 writer 已丢弃。fd 号与 uid 复用：`test_uid_and_fd_reuse_do_not_reach_new_row`（同 uid、同 fd 号的
  新行建立后，旧行的回调、超期与迟到事实都不落到新行）、`test_old_callbacks_do_not_reach_new_channel_on_reused_fd`、
  AA-13 两例。
- **结果及限制**：满足（测试加代码阅读，与第 149 行一致）。上面几例的 fd 号复用由测试自己制造（占住低号 fd 或 dup2）；集成运行的
  normal 例里，真实 spawner 先后交出的 prepared fd 也落在同一号上（`fd_number_reused: true`），旧回调不影响新行。

### bootstrap uid 重读（第三次修订另加的检查）

- **实现**：`support.c:250–255`（`setresuid` 后 `getresuid`，三值须都等于记录 uid，否则失败，在任何 filter 安装之前）。
- **验证**：sandbox 回归中 bootstrap `uid.reread` 注入例与文件 worker `worker.drop.uid.reread` 注入例通过。正向：回归中所有
  到达 SEALED 的启动路径（如 normal、busy）都在重读通过之后才 SEALED；在准入或更早的降权步骤失败的注入例（bad-uid、bad-gid、
  bounding.*、groups 等）不经过重读，不算正向证据。
- **结果**：满足（测试）。注入点只在测试构建（`W2_TESTING`）中存在。

## 逐条 must

### §1 UidLease

| 行号 | must | 设计位置 | 实现位置 | 验证方法与判据 | 证据 | 结果 |
|---|---|---|---|---|---|---|
| 128 | 分配器只把工作区登记的 uid 租给它；不符即拒绝，不建行、不换 uid | rr E-08 工作区租约；conn E-01 第 78 行 | `lifecycle.py:139–141`（uid 只取自 WorkspaceRecord）；`spawner.c:83–88`（spawn 时再核 uid/gid 与目录登记值） | 代码阅读：engine 侧 uid 只有这一个来源；`test_refusals_create_no_row`（计划指向另一工作区：拒绝、不建行） | 集成运行（单元）；sandbox 回归 | 满足（测试加代码阅读） |
| 129 | 一个租约至多一个持有者：持有或隔离中的不再出租，同一工作区并发取得被拒，耗尽时拒绝启动而不换 uid | rr E-08；conn E-01 `UidLease` | `lifecycle.py:135–141`；隔离不移出 `holders`（`483–488`），只有释放时移出（`497–501`） | `test_refusals_create_no_row`、`test_pool_exhaustion_refuses`、`test_empty_wait_quarantines_then_real_empty_lifts`、`test_workspace_reference_holds_workspace_and_slot` | 集成运行（单元） | 满足（测试加代码阅读）：`test_pool_exhaustion_refuses` 测的是执行槽位上限（`lifecycle.py:135–136`）；"uid 被占即拒、不换 uid" 由代码阅读支撑——每个工作区的 uid 固定，`lifecycle.py:139–140` 在该 uid 不在池中或已被持有时拒绝，没有换用其他 uid 的路径 |
| 130 | 预留要求上一租约的行为 CLOSED 且成员已空，不只看空闲标志 | rr E-08 | `lifecycle.py:142–144` | 代码阅读；工作区只在 `_reclaim` 中回到 AVAILABLE（`505–507`，前提 CLOSED 且已空），所以正常路径上 `137–138` 的工作区门槛先拒绝，`142–144` 是第二道检查 | — | 满足（代码阅读） |
| 131 | 池排除 0、overflow uid、无效值与主机身份 | conn E-01 第 78 行；rr E-08 | `startup.py:167–185`；记录侧另拒哨兵 `records.py:217–220` | `test_pool_excludes_sentinels`、`test_pool_accepts_disjoint` | 集成运行（单元） | 满足（测试）。主机身份只按 uid 经 NSS 查（`pwd.getpwuid`） |
| 132 | 设计须写明：预留查不出上一 epoch 的残留、也查不出 engine 之外持池内 uid 的任务，两者都依赖 §8 的池前提 | conn E-01 第 87、105–107 行 | — | 对照设计原文 | — | 设计已写明 |
| 133 | 旧回调取不到新工作区租约，也不能仅凭 workspace_id 或 uid 到达当前租约；每个租约带工作区、execution 与不回卷的 lease_generation | rr E-08 `WorkspaceRecord` | `objects.py:98–104`（冻结的 WorkspaceLease）；`lifecycle.py:151–152`（generation 只增）；改动工作区前都核对 `active_lease is wlease`（`344–346`、`436`、`486`、`505`） | 代码阅读；`test_uid_and_fd_reuse_do_not_reach_new_row` | 集成运行（单元） | 满足（测试加代码阅读） |

### §2 Execution、Session 与 Channel

| 行号 | must | 设计位置 | 实现位置 | 验证方法与判据 | 证据 | 结果 |
|---|---|---|---|---|---|---|
| 139 | Execution 与 Session 的保留字段建行时在一个裁决中写一次；之后只改状态类字段 | conn E-01 第 95–100 行 | `objects.py:14–22`（WriteOnce），`151–152`、`178–180`；`lifecycle.py:121–167`（launch 一次完成） | `test_reservation_fields_write_once` | 集成运行（单元） | 满足（测试加代码阅读） |
| 140 | expected_uid 与租约取得同一裁决、取自租约对象，不取自请求体、观察凭据或 payload | conn E-01 | `lifecycle.py:149–150` | 代码阅读：`expected_uid` 只在此处写入（grep） | — | 满足（代码阅读） |
| 141 | Session、Channel、lease 标识由不复用的 execution_id 一次派生，各一个 | conn E-01 | `lifecycle.py:147–154`、`276` | `test_uid_and_fd_reuse_do_not_reach_new_row`（复用 uid 与 fd 号时 id 不同） | 集成运行（单元） | 满足（测试加代码阅读） |
| 142 | 新 execution 不继承旧 execution 的任何对象：同名 local_agent_id 不带状态；旧行槽位仍占用而 uid 已释放时，新行也不绑定该槽位 | conn E-01 第 101–102 行 | local_agent_id 只被复制进 Session、Execution、VerifiedContext 与记录，无以它为键的表（grep：`lifecycle.py:150、153`，`receive.py:297`，`records.py:74`） | 代码阅读；`test_new_execution_binds_nothing_of_an_old_row_whose_slot_is_still_held`（新增：旧行 uid 与工作区已还、槽位仍等 runtime 副本时，同工作区、同 uid 再启动成功，新行的 lease、Session、runtime copy 视图与工作区租约都是新对象，工作区代次更大；旧行的 runtime_status 只让旧行释放槽位，新行不受影响） | 集成运行（单元） | 满足（测试加代码阅读） |
| 143 | 交接安装在一个裁决中验证 prepared 记录并把 fd 装进所指行的 Channel，仅当该行 PREPARING；CLOSED 行则关 fd、不安装、登记 stop | conn E-01 控制接口、状态转换 | `lifecycle.py:244–271`、`273–283` | `test_prepared_on_closed_row_stops_once`、`test_late_prepared_after_deadline_stops_once_with_timeout`、`test_prepared_again_or_mismatch_closes_fd_and_faults` | 集成运行（单元） | 满足（测试） |
| 144 | 交接时核验 fd 为已连接、两端无名、SO_PASSCRED=1 的 AF_UNIX stream，不合格则交接失败，不自行设置 | conn E-01 控制接口 | `transport.c:124–134`（`w2_validate_channel`），由 `w2_recv_control` 调用（`145`）；engine 无 setsockopt 调用 | 正向 `test_channel_is_unnamed_stream_with_passcred`；反向 `test_wrong_handoff_fd_faults_and_installs_nothing`（新增：无 PASSCRED、datagram、一端有名、AF_INET 四种都判故障、不装 Channel、不遗留描述符） | 集成运行（单元） | 满足（测试）；以更严格方式：不合格 fd 判整条控制链路故障，而不只是本次交接失败 |
| 145 | SO_PASSCRED 在 socketpair 创建时于 engine 端设好，先于 clone；构建验收须观察到 | conn E-01 启动时序 | `spawner.c:113–115`（socketpair 后立即设置），clone 在 `128–129` | 代码阅读（次序）；观察：sandbox 回归 busy 一例的 strace 中，spawner 依次 `socketpair(AF_UNIX, SOCK_STREAM…) = [11, 12]`、`setsockopt(11, SOL_SOCKET, SO_PASSCRED, [1], 4)`、`clone(…CLONE_NEWPID…)`，由运行器的 `passcred_before_clone` 断言次序 | sandbox 回归 | 满足（测试加代码阅读）。回归运行器对次序有专门断言；只在诊断 fixture 的 busy 一例上观察 |
| 146 | engine 在通道生命期内从不清除本端 PASSCRED | conn E-02 | engine 中没有 setsockopt 调用（grep `engine/*.py`） | 代码阅读；`tests/test_receive.py::test_no_credential_option_written_or_peer_credential_read`（2026-10-19 新增：engine 源码中不出现 setsockopt、SO_PASSCRED、SO_PEERCRED；`transport.c` 只读 SO_PASSCRED、从不设置；测试内先确认扫描式能命中一条典型的清除语句） | 集成运行（单元，见文首"必要性分析后的补充"） | 满足（测试加代码阅读） |
| 147 | 每次安装新建一个拥有该 fd 的 Channel 对象 | conn E-01 `Channel` | `lifecycle.py:275–279` | `test_uid_and_fd_reuse_do_not_reach_new_row`（同 fd 号复用时是新对象、更大代次） | 集成运行（单元） | 满足（测试） |
| 148 | 每个 Channel 有自己的 receiver_generation，取值方式由设计定；close 第 2 步作废后 fd 号才可复用，旧代次的回调不作用于新通道 | conn E-01 第 103–105 行（epoch 内单调计数，安装时取） | `lifecycle.py:275–276`；`objects.py:133`（写一次）；回调持对象而非代次（`phases.py:43`、`56–58`） | `test_reservation_fields_write_once`、`test_uid_and_fd_reuse_do_not_reach_new_row`（新代次更大，旧回调不落到新行） | 集成运行（单元） | 满足（测试加代码阅读）。旧回调失效靠对象身份，不靠代次数值（与设计一致） |
| 149 | Channel → Session 链接安装时写一次、close 第 2 步按对象清除 | conn E-01 第 103–104 行 | 见 R-GX-06 条目 | 见 R-GX-06 条目 | 集成运行（单元） | 满足（测试加代码阅读）。"写一次"靠代码结构：`Channel.session` 不在 WriteOnce 字段中，只在构造时（`lifecycle.py:276`）与 close 第 2 步（`471`）赋值（grep） |
| 150 | 每个 execution 在保留之后为其记录建一个 socketpair | conn E-01 启动时序 | `spawner.c:113`（在 spawn 准入之后的 `clone_ready` 内，每条记录一次） | 代码阅读；sandbox 回归 | sandbox 回归 | 满足（代码阅读加回归） |
| 151 | 对端只到达同一记录的 clone：execve 前关掉其他描述符；spawner 整条发送 prepared 后关闭自己的 engine 端副本 | conn E-01 启动时序、控制接口；optb spawn 序列第 10 步 | `spawner.c:49–50`（child 先关 other、control、worker 与锁）；`child.c:100–103`（dup2 到 3、`close_range(4, ~0)`）；`spawner.c:251`（prepared 整条发出后关闭副本） | 代码阅读；sandbox 回归的 agent fixture 在打开任何文件之前探测 fd 0–63，回归断言继承下来的恰好是 0、1、2、3，且 fd 3 不带 close-on-exec（`native/checks/agent_fixture.c:41–50`，`native/checks/run_sandbox_checks.py:192–194`） | sandbox 回归 | 满足（测试加代码阅读）。fd 探测范围为 0–63 |

### §3 接收管线

| 行号 | must | 设计位置 | 实现位置 | 验证方法与判据 | 证据 | 结果 |
|---|---|---|---|---|---|---|
| 157 | 每次接收用新的 msghdr、iovec 与至少 CMSG_SPACE(ucred) 的控制缓冲，不沿用上次的长度、flags 或凭据 | conn E-02 接收管线第 1 步 | `transport.c:151–154`（每次在栈上新建，缓冲为 CMSG_SPACE(ucred)+CMSG_SPACE(256 个 fd)）；`92–93`（解析状态每次重置） | 代码阅读；fuzz 的 frame 入口 | fuzz 运行 | 满足（代码阅读加 fuzz） |
| 158 | 数据通道只由唯一 reader 以 recvmsg 读取，无 read/recv/stdio/MSG_PEEK/MSG_WAITALL/带外入口或第二个 reader | conn E-02 第 2 步 | 唯一路径 `receive.py:284` → `ffi.py:92–106` → `transport.c:224` → `154`，flags 只有 MSG_CMSG_CLOEXEC 与 MSG_DONTWAIT | `test_no_python_reader_on_sockets`；代码阅读 | 集成运行（单元） | 满足（测试加代码阅读） |
| 159 | POLLPRI/带外结果关闭通道，不重同步 | conn E-02 第 2 步 | `transport.c:219–221` → `receive.py:287–288` → `phases.py:86` | `test_out_of_band_byte_closes`（STARTING 与 ACTIVE）；fuzz frame 入口含带外操作 | 集成运行（单元）；fuzz 运行 | 满足（测试） |
| 160 | 截断消息附带的每个 SCM_RIGHTS fd 在处理错误前关闭 | conn E-02 第 3 步 | `transport.c:96–113`（先收集）、`114`（截断判无效）、`119–121`（全部关闭） | `test_rights_closed_and_never_kept`（泄漏断言用修正后的 `open_fds`）；fuzz frame 入口（socketpair 打开时最低空闲 fd 不变）与 ancillary 结构化模式（缓冲区中每个描述符恰好关闭一次）；两项判据的反向对照见 fuzz 运行 README | 集成运行（单元）；fuzz 运行 | 满足（测试加 fuzz）。内核实际截断 rights 的情形只在 ancillary 入口以内核式的合法 header 构造覆盖 |
| 161 | reader 与回调按 Channel 对象注册：就绪事件映射到注册它的对象，不以 fd 号映射对象 | conn E-01 `Channel`；E-02 | `phases.py:43`（回调持 Execution 与 Channel）；`loop.py:112`（选中时快照回调对象）、`122`（派发前要求仍是当前注册） | `test_stale_selected_event_not_dispatched_to_new_registration`、`test_old_callbacks_do_not_reach_new_channel_on_reused_fd`、AA-13 两例 | 集成运行（单元）；AA-13 运行 | 满足（测试加代码阅读）。selectors 与 engine 的 `Loop.handlers` 都以 fd 号为键（epoll 接口如此，`loop.py:50`）；engine 只用它取回该 fd 当时登记的回调并在派发前核对身份，不以它找对象 |
| 162 | 每次 recvmsg 前核对 Channel 未关闭；设计须写明核对哪个字段 | conn E-02 接收侧补充第 481–482 行（`Session.admission`） | `receive.py:280–283` | `test_pre_read_check_reads_nothing_on_closed_session` | 集成运行（单元） | 满足（测试）；设计已写明（严格读法） |
| 163 | event library 在 close 第 2 步注销后不再为该 fd 号投递就绪 | conn E-02 接收侧补充第 483–484 行 | 见下文 AA-13 条目 | 见 AA-13 条目 | AA-13 运行 | 满足（测试加代码阅读） |
| 164 | 每次正长度返回（含 4 个头字节）先过凭据比较，才计入头/body 缓冲、才解码长度；所有片都通过后才构成帧；失败的片使 reader 作废 | conn E-02 第 4–5 步（第 462–466 行） | `transport.c:224–231`（通过才推进 `used`）、`232–235`（头 4 字节齐后才解码）、`238`（整帧后才解析） | `test_wrong_uid_rejected_at_first_fragment`、`test_uid_change_inside_one_frame_rejected_before_completion`、`test_hello_byte_by_byte_then_welcome_and_active`；`test_uid_change_at_last_byte_rejected`（换发送者落在帧的最后一个字节，此前各片都已通过；对照 `test_same_uid_last_byte_completes_the_frame`；反向对照：只在帧头片段比较凭据的缺陷副本上该例失败、对照通过）；fuzz frame 入口 | 集成运行（单元、root 单元；最后一字节一例见 [2026-10-20 补充证据运行](runs/20261020T154357Z-engine-extra-evidence-rerun/README.md)）；fuzz 运行 | 满足（测试加 fuzz）。条款于 2026-10-19 改为"计入头/body 缓冲之前"（用户批准）。recvmsg 同时交付字节与凭据，字节先由内核写进 C reader 的定长数组（`transport.c:224`），比较在 `160`，通过后才计入 `used`（`230`）。两个条件均成立：长度解码只读已计入 `used` 的 4 个头字节（`232–235`，此时 `used == needed == 4`），整帧解析与拷出只读 `wire+4` 到 `used` 之间（`238–239`）；比较失败即走 `bad`，reader 置为死亡（`240`），之后每次调用在 `214` 先返回 -1，不再读 `wire`，Python 只拿到整帧拷出的字节，所以没有任何路径读取 `used` 之外的字节（与 R-G2-13 单一比对点的代码阅读一起确认） |
| 165 | FrameReader 的公共 uid 只是派生检查结果，不作后续片的比较对象 | conn E-02 | `transport.c:217–218`、`224`（每片与绑定时的 expected 比）；`receive.py:297–299`（sender_uid 取行的 expected_uid） | 代码阅读；`test_uid_change_inside_one_frame_rejected_before_completion` | 集成运行（root 单元） | 满足（测试加代码阅读） |
| 166 | 比较先要求 pid>0 与非哨兵 uid，再比相等 | conn E-02 第 4 步 | `transport.c:115–117` | `test_root_sender_rejected`、`test_overflow_uid_sender_rejected_even_when_equal`（expected 等于 overflow 时仍拒）；pid 为 0 与 uid 为 0、overflow：sandbox 回归中 check-transport 的合成 ancillary 例（`native/checks/check_transport.c:52–54`） | 集成运行（root 单元）；sandbox 回归 | 满足（测试） |
| 167 | uid 按无符号 uid_t 从本次控制缓冲解码，不转有符号 | conn E-02 第 4 步 | `transport.c:109`（拷入 `struct ucred`）；`ffi.py:52`（c_uint32）、`97` | `test_ffi_uid_bounds`；`test_pool_uid_above_2_31_accepted`（2^31+60000、2^31+60001、4294967294 由同 uid 的真实发送者发出时接受，上下文的 uid 原值）、`test_pool_uid_above_2_31_other_uid_rejected`（邻值、只在符号位不同的两对、4294967294 与其低 31 位同值者均拒收）；反向对照：比较只看低 31 位的缺陷副本上三个符号位例失败 | 集成运行（单元）；[2026-10-20 补充证据运行](runs/20261020T154357Z-engine-extra-evidence-rerun/README.md)（root 单元） | 满足（测试加代码阅读）。2^31 以上的值此前只有类型阅读，2026-10-20 起有真内核凭据的接受与拒收；只在接收侧，目录与 spawner 对此类 uid 的处理未测 |
| 168 | pid 只作诊断；帧的 sender_pid 只在各片相同时记录 | conn E-02 VerifiedContext；si E-09 | `receive.py:196`、`298`（首版恒为 None） | `test_pool_uid_sender_accepted`、`test_two_same_uid_processes_compose_one_frame`；`test_other_uid_holder_naming_a_task_of_x_rejected`（X 的任务经 SCM_RIGHTS 交出 agent 端副本，另一 uid 的持有者只保留 CAP_SYS_ADMIN、在凭据里写 X 那个仍存活任务的 pid，探针读回内核交付的正是该 pid 与持有者 uid；拒收）、对照 `test_same_uid_holder_naming_a_foreign_pid_accepted`（X 自己的 uid 写 X 之外的 pid，接受，上下文无 pid）；反向对照：按交付 pid 查 /proc 的 uid 代替比较的缺陷副本上两例都失败 | 集成运行（root 单元）；[2026-10-20 补充证据运行](runs/20261020T154357Z-engine-extra-evidence-rerun/README.md) | 满足（测试）；首版不记录 pid，比条款更严 |
| 169 | 观察到的 uid 不选择行、不写入行；与 expected_uid 的比较是数据通道上唯一的身份裁决 | conn E-01；E-02 | `receive.py:284`（传入行的 expected_uid）；`ffi.py:92–106`（C 不回传观察到的 uid） | 代码阅读；`test_other_pool_uid_rejected`；`test_swapped_expected_uids_reject_both_frames_and_select_no_row`（Lifecycle 上两条行，各自 channel 上由对方行的 uid 发 hello：两条拒收记录只按各自连接引用，无 message_received，两行都以 receive_rejected 关闭，预期 uid 不变）、对照 `test_unswapped_senders_each_reach_their_own_row`；反向对照：去掉与预期 uid 比较的缺陷副本上该例失败、对照通过 | 集成运行（root 单元）；[2026-10-20 补充证据运行](runs/20261020T154357Z-engine-extra-evidence-rerun/README.md) | 满足（测试加代码阅读） |
| 170 | 数据通道不以 SO_PEERCRED 读数为身份 | conn E-01；kub §2.4 | engine 与 `transport.c` 都不读 SO_PEERCRED（grep） | 代码阅读；`tests/test_receive.py::test_no_credential_option_written_or_peer_credential_read`（同第 146 行） | 集成运行（单元，见文首"必要性分析后的补充"） | 满足（测试加代码阅读） |
| 171 | recvmsg 到缓冲之间恰有一个比对点，无旁路 | conn E-02 | 见 R-G2-13 条目 | 见 R-G2-13 条目 | 集成运行（root 单元） | 满足（测试加代码阅读） |
| 172 | receive_step 是 VerifiedContext 的唯一构造点 | conn E-02 VerifiedContext；E-03；si E-09 | `receive.py:297` | `test_verified_context_has_one_constructor` | 集成运行（单元） | 满足（测试）。条款点名的 E-10 adapter 首版不存在；E-09 的 pre_egress hook 点存在（`requests.py:114`、`229–230`），只观察、返回值被丢弃，产品中没有挂任何观察者 |
| 173 | VerifiedContext 的标签字段都取自其被调用的 Channel 及经它到达的 Session、Execution | conn E-02 | `receive.py:280`、`297–299` | `test_every_record_subject_is_a_copy_of_the_verified_context`、`test_request_path_carries_objects_by_reference`（新增） | 集成运行（单元） | 满足（测试加代码阅读） |
| 174 | FrameReader 属于一个 Channel、只由其接收器触碰，每帧后清空，随 Channel 丢弃，不交给别的 Channel 或 TaskCall | conn E-02 接收侧补充第 482–483 行 | `lifecycle.py:277`（随 Channel 新建）；`phases.py:48–50`（第 2 步释放）；`transport.c:217–218`（C reader 绑定 fd、socket cookie、expected 与 overflow，任一改变即死亡）、`239`（整帧后清零） | 代码阅读；`test_two_frames_in_one_send`、`test_frame_timer_restarts_per_frame` | 集成运行（单元） | 满足（测试加代码阅读） |
| 175 | parser 与 FrameReader 内存安全（方式由设计定） | conn E-02 第 487–492 行 | `transport.c`；`receive.py:107–123` | 见 R-G2-11 条目 | fuzz 运行（2026-10-19 C 侧帧体解析删除后重跑） | 满足（fuzz 加代码阅读）：C 侧 FrameReader 由 fuzz 检查，路径上已无第三方解析器；Python 侧 json 解析不在 fuzz 范围内，依赖 CPython 运行时 |
| 176 | 未知字段拒绝覆盖每种消息中的身份类字段 | conn E-02 数据消息字段 | `receive.py:146–170`（每种类型字段集合封闭） | `test_identity_like_field_rejects_every_message_type`（新增：5 种类型 × 13 个字段）、`test_request_schema_without_grant_ref` | 集成运行（单元） | 满足（测试） |
| 177 | 生产 agent seccomp allow-set（S2）须为部署的 runtime 写明 | si E-10；scope S2 | — | 首版用诊断政策 | — | 超出范围（P2b；BUILD-PLAN §1"不做"，rr E-08 第 889–890 行列为部署输入） |
| 178 | ancillary 检查遇 MSG_TRUNC、MSG_CTRUNC、缺失或重复凭据、ucred 长度不对时关闭会话，并拒绝其他意外 ancillary | conn E-02 第 3 步 | `transport.c:99`、`102`、`107–110`、`114–118` | sandbox 回归中 check-transport 的合成 ancillary 六例（uid 为 0、overflow uid、pid 为 0、MSG_CTRUNC、重复凭据、ucred 长度差一）；fuzz ancillary 入口只断言其中"带截断或带外标志时从不接受"一项，结构化模式中错误长度的凭据、其他 level 的 header 与重复凭据只作为输入覆盖，不判接受与否；`test_rights_closed_and_never_kept` | sandbox 回归；fuzz 运行；集成运行（单元） | 满足（测试加 fuzz） |

### §4 控制记录与启动准入

| 行号 | must | 设计位置 | 实现位置 | 验证方法与判据 | 证据 | 结果 |
|---|---|---|---|---|---|---|
| 184 | 控制记录按 execution_id、lease_id、engine_epoch 匹配到行，不按 uid 或 fd 号；未知 execution 或 lease 判故障，从未提交的行收到事实被拒 | conn E-01 控制接口；E-04 | `control.py:206–207`（epoch）；`lifecycle.py:220–235` | `test_epoch_mismatch_faults`、`test_unknown_execution_and_lease_mismatch_fault`（未知 execution；同 execution 换 lease_id）、`test_fact_for_live_unsubmitted_row_faults` | 集成运行（单元） | 满足（测试加代码阅读） |
| 185 | 重复控制记录不改变任何东西：已消费的 spawn_prepared 再到时先关其 fd 再判故障；重复的相同终态被忽略 | conn E-01 控制接口 | `lifecycle.py:248–249`、`269–271`（finally 在故障传出前关 fd）；`311–313`、`330–334`、`353–357`；`control.py:212–218` | `test_prepared_again_or_mismatch_closes_fd_and_faults`、`test_duplicate_terminal_ignored_conflict_faults`、`test_seq_rules`、`test_old_seq_with_fd_closes_fd_and_faults` | 集成运行（单元） | 满足（测试） |
| 186 | 控制 writer 把每次 spawn 发送分为整条或不确定；不确定使行 uncertain 并 CLOSED、发 stop | conn E-01；E-04 | 见下文"以更严格方式满足"一节 | 同左 | 集成运行（单元） | 以更严格方式满足 |
| 187 | local_never_submitted 只在控制 writer 确认未发且撤回不可逆后写入；不确定的提交不产生本地依据 | conn E-01；E-04 | `control.py:75–82`（只有仍在队列中的 spawn 可撤回，发送只在 flush 内）；`lifecycle.py:444–449` | `test_local_withdrawal`、`test_uncertain_send_never_local` | 集成运行（单元） | 满足（测试） |
| 188 | spawner 拒绝 uid 或 lease 在活记录中、或工作区有活记录的 spawn | conn E-01 控制接口；rr E-05 | `spawner.c:68–70`（同 execution 或墓碑）、`89–94`（活记录占用 uid、gid 或工作区时 resource_exhausted） | sandbox 回归的 busy 例 | sandbox 回归 | 满足（测试加代码阅读） |
| 189 | 设计须写明：已终结而存储未释放的记录在 spawn 准入时是否仍占 uid 与 lease | conn E-01 第 108–113 行（不再占用，宽松读法，用户 2026-10-18） | `spawner.c:89–91`（`!old->empty` 才算占用） | 对照设计原文与代码 | sandbox 回归 | 设计已写明（宽松读法），实现一致 |
| 190 | spawner 在 clone 前核对 spawn 的 uid/gid 与干净启动目录的登记值 | si E-10；sbx SC-catalog | `spawner.c:83–88` | sandbox 回归的 bad-uid、bad-gid 两例 | sandbox 回归 | 满足（测试） |
| 191 | 第 11 步在每条创建路径上禁止建立 user namespace（S1） | optb 第 11 步；scope S1 | `policy.c:36`（clone3 → ENOSYS）、`46–49`（clone、unshare 只允许不含 CLONE_NEWUSER） | 代码阅读；sandbox 回归的 agent fixture 在 sandbox 内依次调用 `unshare(CLONE_NEWUSER)`、`clone(CLONE_NEWUSER)`、`clone3`，回归断言前两个为 EPERM、`clone3` 为 ENOSYS（`native/checks/agent_fixture.c:61–64`，`native/checks/run_sandbox_checks.py:199–209`） | sandbox 回归 | 满足（测试加代码阅读）。覆盖诊断政策下的三条创建路径 |
| 192 | spawner 按片读 SEALED，要求 uid 等于准入时存下的记录 uid、pid 等于 child_pid；不符、FAIL、EOF 或超期都在 COMMIT 前失败 | conn E-01 启动时序 | `spawner.c:170–188`、`444` | sandbox 回归 | sandbox 回归 | 满足（代码阅读加回归） |
| 193 | drop 之前发出的 FAIL 可能带 root uid，只作失败诊断 | conn E-01 启动时序 | `spawner.c:177`（early_failure 时不比 uid）、`185`（FAIL 只产生 spawn_failed）；`lifecycle.py:309–326`（engine 只把它当关闭理由） | 代码阅读；sandbox 回归在降权之前的各阶段注入故障（`native/checks/run_sandbox_checks.py:229–250` 的故障表），这些 FAIL 带 root uid，用例断言收到的第一条记录是该阶段的 spawn_failed（不是 prepared），随后是 execution_empty（`native/checks/engine_fixture.py:476–482`） | sandbox 回归 | 满足（测试加代码阅读） |
| 194 | 设计须写明 spawner 对指向未收到记录的 stop 如何应答 | conn E-01 第 114–120 行（判控制协议故障） | `spawner.c:158–163`（既非活记录也非墓碑即返回 -1，循环判 lost） | 对照设计原文与代码 | — | 设计已写明（严格读法），实现一致 |
| 195 | 控制表须指明哪条记录把 spawner 的 kill/wait 错误带给 engine | conn E-01 第 121–126 行（spawn_failed，stage=reap） | `spawner.c:362–363`（kill 出错）、`390–391`（wait 出错，随后判控制链路丢失）；`lifecycle.py:322–324`（隔离 lease 并关闭行） | `test_reap_failure_after_startup_failure_quarantines`、`test_reap_failures_bounded` | 集成运行（单元） | 设计已写明；实现满足（测试） |

### §5 关闭与回收

| 行号 | must | 设计位置 | 实现位置 | 验证方法与判据 | 证据 | 结果 |
|---|---|---|---|---|---|---|
| 201 | CLOSED 是终态：后来的控制事件、hello 或标志不能重开，不从墓碑复活，墓碑窗口外的事件判故障 | conn E-01 状态转换、墓碑；E-03 | `lifecycle.py:426–427`、`220–230`；`phases.py:56–58` | `test_tombstone_window`、`test_duplicate_terminal_ignored_conflict_faults`、`test_pre_read_check_reads_nothing_on_closed_session` | 集成运行（单元） | 满足（测试） |
| 202 | close 第 2 步先移除该 Channel 的全部注册，再 shut fd，按对象与代次关闭一次，丢弃未发帧 | conn E-04 关闭第 2 步 | `lifecycle.py:460–475`；`loop.py:82–85`；`writer.py:182–193` | `test_association_made_installed_and_cleared_by_object`（新增）、AA-13 两例、`test_send_failure_closes_before_queued_records_drop` | 集成运行（单元） | 满足（测试） |
| 203 | 设计须写明 close 第 2–4 步是否与第 1 步同一裁决 | conn E-04 第 870 行（1–4 步同一裁决） | `lifecycle.py:423–458`（一个函数内完成，不让出） | 对照设计原文与代码 | — | 设计已写明（严格读法），实现一致 |
| 204 | 设计须写明第 2 步关闭 fd 是否是第 6 步释放 lease 的条件 | conn E-04 第 870–873 行（是） | `lifecycle.py:475`、`497`（`channel_retired`） | 对照设计原文与代码 | — | 设计已写明（严格读法），实现一致 |
| 205 | membership_empty 只来自 spawner 的空集合事实或本地未提交依据；出错或超时隔离，只由同一健康控制 epoch 中匹配的真实空集合事实解除 | conn E-04；E-01 | `lifecycle.py:337–347`、`447–448`、`192–194`、`342` | `test_empty_wait_quarantines_then_real_empty_lifts`、`test_control_fault_closes_all_and_quarantines`、`test_never_created_after_prepared_faults` | 集成运行（单元） | 满足（测试） |
| 206 | lease 只释放一次，且只在行 CLOSED 且 membership_empty 时；重复事实不再释放 | conn E-04 第 6 步 | `lifecycle.py:491–502` | `test_normal_round_trip`、`test_duplicate_terminal_ignored_conflict_faults` | 集成运行（单元） | 满足（测试） |
| 207 | 停滞的清理条目及其引用被保留，不释放、不改址 | conn E-04 | `requests.py:500–507` | `test_cleanup_stalled_holds_the_slot_and_closes_admission` | 集成运行（单元） | 满足（测试） |
| 208 | 迟到事实只到达它所持的对象，只做释放或原请求的迟到结果事件，不产生带新主体或改动主体的事件（迟到事件可带从所持对象取得的原请求主体副本） | conn E-03、E-04；si E-09 | `requests.py:81–99`（Sink 只持原条目）、`325–331`、`396–399`；`lifecycle.py:220–230` | `test_stale_sink_after_close_reaches_nothing_new`、`test_late_completion_does_not_rewrite_the_terminal`、`test_late_reply_after_resolution_does_not_overwrite` | 集成运行（单元） | 满足（测试加代码阅读）。条款于 2026-10-19 改为"不带新的或改动过的主体"（用户批准）。迟到事实只经 Sink 回到原 RequestEntry（`requests.py:81–99`），会带主体的只有 `late_completion`（`396–399`）与会话关闭后才到的释放所发的 `request_released`（`406–416` → `523`）。条件均成立：两者的主体都取自原条目的 `entry.subject`（`requests.py:127`），它在 admission 时由帧到达的 VerifiedContext 拷贝而来（`155`、`172`），且写一次（`44`），从不按 uid、fd 或 request id 重新查找；释放只归还槽位、计数与引用并尝试结束调用（`509–525`、`tasks.py:382–395`），不进入授权或分派 |
| 209 | spawner 在发 never_created 之前把记录封住、不再 clone | conn E-01 `execution_empty`；E-04 | `spawner.c:53–57`、`160–162`（stopping；未 clone 时 empty）、`102`（stopping 或 empty 时不 clone）、`223`（pid 为 0 才报 never_created） | 代码阅读；sandbox 回归中多例在未 clone 时结束（stop 先到、准入失败、worker 丢失），engine fixture 断言收到的空集合依据为 never_created、没有交接 fd（`native/checks/engine_fixture.py:262、281、294、351、359、450、481`） | sandbox 回归 | 满足（测试加代码阅读） |
| 210 | spawner 的唯一 reaper 是 PID 1 的 waitpid 的唯一消费者；不忽略 SIGCHLD、不设 SA_NOCLDWAIT | conn E-01；E-04 | `spawner.c:400–401`（SIGCHLD 为 SIG_DFL）、`372`（唯一 `waitpid(r->pid)`；`304` 是文件 worker） | 代码阅读；sandbox 回归 | sandbox 回归 | 满足（代码阅读加回归） |

### §6 Supervisor、epoch 与 engine 启动

| 行号 | must | 设计位置 | 实现位置 | 验证方法与判据 | 证据 | 结果 |
|---|---|---|---|---|---|---|
| 216 | 控制丢失时存活的 spawner 停止并回收每条 SpawnRecord，然后退出 | conn E-04 控制链路故障 | `spawner.c:409–440` | sandbox 回归的 control-loss 与 reap-control-loss 例；集成运行中 spawner 自然退出（exit 0），监督者未收养进程 | sandbox 回归；集成运行 | 满足（测试加代码阅读） |
| 217 | 控制丢失时 engine 隔离每个未确认的 lease，不恢复旧 epoch 的 lease；新 spawner 的自报不能解除隔离 | conn E-04 | `lifecycle.py:527–533`；`control.py:249–260`；`main.py:77–80`（控制链路死亡后 engine 退出） | `test_control_fault_closes_all_and_quarantines`、`test_launch_refused_after_control_loss` | 集成运行（单元） | 满足（测试）；后半句由构造满足：首版控制丢失即退出，不接新 spawner |
| 218 | 可信 supervisor 跟踪整个进程域，在新 engine 的池重新可用前终止旧域并自行确认域已空，不采信 engine 或 spawner 的自报 | conn E-04；rr E-08 第 887–888 行 | — | 集成运行器以 PR_SET_CHILD_SUBREAPER 收养并记录残留进程，是测试用监督，不是本条的 supervisor | — | 部署前提：方法 2026-10-19 写入设计（conn E-04 控制失联——以内核持有的事实为据：cell 独占 cgroup 的 `populated 0`）；首版不做重启恢复，engine 侧无可测部分；开发机读数：[cgroup 域清空探针](runs/20261019T142200Z-cgroup-domain-empty-rerun/README.md) 的四项内核行为成立；真实 engine、spawner 与 agent 的[两代运行](runs/20261020T154357Z-engine-extra-evidence-rerun/README.md)（放行门为测试替身，见下文"R-GX-04 两代运行"） |
| 219 | 启动自检见 uid_map 为身份映射、overflow uid 可读，否则拒绝服务，不替代 S13 | conn E-01 第 87–89 行 | 见 R-G2-12 条目 | 见 R-G2-12 条目 | 集成运行 | 满足（测试） |
| 220 | engine 在持有秘密之前按任务开启间接分支缓解（prctl） | scope S14 | `startup.py:75–94`（2026-10-20 起用 `PR_SPEC_FORCE_DISABLE`，与 S14 所写一致）；`main.py:40`（在读目录与建 Recorder 之前） | `test_indirect_branch_opt_in`、`test_real_kernel_opt_in`；集成运行 production-entry 记下 `indirect_branch=opted_in` | 集成运行（2026-10-20 重跑） | 满足（测试）：设置后检查 FORCE 位；真实内核上再请求 PR_SPEC_ENABLE 得 EPERM（`test_real_kernel_opt_in`）；2026-10-20 前用的是 PR_SPEC_DISABLE，不符合 S14 所写的调用 |

### §7 Consumers

| 行号 | must | 设计位置 | 实现位置 | 验证方法与判据 | 证据 | 结果 |
|---|---|---|---|---|---|---|
| 226 | 每个 consumer 按对象引用取得 verified context，不构造、不按名称、uid、fd 或 local_agent_id 查找或作状态键 | conn E-02 第 581–583 行 | 见 R-G3-05 条目 | 见 R-G3-05 条目 | 集成运行（单元） | 满足（测试加代码阅读） |
| 227 | admission 只经请求所在 Session 对象到达 TaskCall 与 TaskBinding，不经 engine 范围的 id 表 | conn E-02；E-03 | `requests.py:146–160` | `test_binding_mismatch_is_denied_without_a_slot`、`test_request_with_no_call_is_denied`、`test_request_path_carries_objects_by_reference` | 集成运行（单元） | 满足（测试） |
| 228 | 设计须写明解析与 admission 之间的回合边界 | conn E-02 接收侧补充第 484–485 行（同一裁决） | `phases.py:61–97`、`141–142`（同一回调中直接调用 `on_request`） | 对照设计原文与代码；`test_request_path_carries_objects_by_reference`（条目出现的同一轮内 handler 已启动） | 集成运行（单元） | 设计已写明（严格读法），实现一致 |
| 229 | Grant 只经请求 Session 可达的 TaskBinding 解析，不选别的会话的 Grant | conn E-03；rr E-06 | `requests.py:172`、`248–254`（`binding.session is session`、grant 的 session_id 相符） | `test_final_check_sees_a_closed_binding`、`test_final_check_sees_a_revoked_grant_state`、`test_expired_and_revoked_grants_deny` | 集成运行（单元） | 满足（测试） |
| 230 | TaskBinding 只经可信入口在所述守卫下改绑或移除 | rr E-06；conn E-03 | `tasks.py:83`（grant_state 写一次，首版没有改绑入口）、`191–206`（移除守卫） | `test_grant_capacity_returns_when_executions_close`；下文 TaskBinding 裁定条目 | 集成运行（单元） | 满足（测试加代码阅读）；不提供改绑，比条款更严 |
| 231 | operation_id 与 OperationSummary 取自条目的请求键与携带的上下文，不经会话或 grant 查找 | rr E-06；si E-09 | `operations.py:208`（条目所持 Session 的 id 加请求 id，与 request_key 同源）、`173–182`（grant_ref 取自 `entry.grant_state`） | `test_document_read_full_path_and_records`；代码阅读 | 集成运行（单元） | 满足（测试加代码阅读） |
| 232 | 重试或重放不重新提交已存请求；失败给终态，新请求以自己的标签经过接收管线 | conn E-03、E-04；rr E-07 | `requests.py:287–292`（启动失败即终态，不重试）；handler 无重试路径 | `test_old_or_repeated_request_id_closes`；代码阅读 | 集成运行（单元） | 满足（测试加代码阅读） |
| 233 | 响应 writer 是原 Channel 自己的 writer，由 RequestEntry 的 Channel 对象选定 | conn E-02；E-03 | `requests.py:308`、`327`、`435` | `test_request_path_carries_objects_by_reference` | 集成运行（单元） | 满足（测试） |
| 234 | worker 事实或 connector 结果只作用于它所属的 RequestEntry；sink 无法指名会话、fd 或 seq | conn E-03；rr E-07 | `requests.py:81–99`（Sink 只有 `_entry` 与 `_manager`，`__slots__`） | `test_request_path_carries_objects_by_reference`、`test_stale_sink_after_close_reaches_nothing_new` | 集成运行（单元） | 满足（测试） |
| 235 | 只归还原条目的请求槽 | conn E-03 | `requests.py:509–525`（仅当 `session.requests.get(id) is entry` 时删除） | `test_cancelled_timers_hold_no_request`；代码阅读 | 集成运行（单元） | 满足（测试加代码阅读） |
| 236 | reply_to 只在原会话、原方向的在途表中解析 | conn E-02；E-03 | `requests.py:530`（agent 方向）；`tasks.py:360–363`（engine 方向） | `test_agent_cancel_in_flight_and_unknown`、`test_task_result_reply_to_stale_is_dropped_and_future_closes` | 集成运行（单元） | 满足（测试加代码阅读）。两个会话同时 ACTIVE 的交叉情形需要两个不同 uid 的发送方，单元层只有一个可用 uid，由代码阅读支持 |
| 237 | verified_subject 只作为 VerifiedContext 的副本出现在已验证请求路径的种类上；其余种类（含 receive_rejected）不带 | si E-09 | `records.py:28–31`、`206–222` | `test_every_record_subject_is_a_copy_of_the_verified_context`、`test_phase_refusal_builds_no_subject`、`test_rejection_diagnostic_carries_no_agent_text`、`test_recorder_type_guards_latch` | 集成运行（单元） | 满足（测试） |
| 238 | control_binding 与 verified_subject 是不同类型 | si E-09 | `records.py:59–89`、`214–226` | `test_recorder_type_guards_latch` | 集成运行（单元） | 满足（测试） |
| 239 | 记录路径不把哨兵 uid 写成主体 | si E-09；mech D4 | `records.py:217–220` | `test_recorder_type_guards_latch`（uid 0、overflow uid、非比较结果三例） | 集成运行（单元） | 满足（测试） |
| 240 | 关联键是决策所用对象 id 的值拷贝 | si E-09 | `requests.py:124–129`（request_key、call.key、channel_id 取自条目所持对象，均为字符串） | 代码阅读 | — | 满足（代码阅读） |
| 241 | post-read 流的目的地是原请求的 execution_id | si E-09 | `requests.py:343`、`375` | `test_document_read_full_path_and_records` | 集成运行（单元） | 满足（测试加代码阅读） |
| 242 | 本地模型实例不以池内 uid 运行、不属于任何 execution 的进程域 | rr E-07 第 386–388 行 | 首版没有本地模型实例（model.generate 为 stub） | — | — | 部署前提（首版不涉及） |
| 243 | 若按 execution 选择 provider，以 execution_id 为键 | rr E-07 第 386–387 行 | 首版不按 execution 选择：provider 固定在业务目录的资源上（`operations.py:219–228`） | 代码阅读 | — | 由构造满足（不存在按 execution 的选择） |
| 244 | 旧或重复的活动请求 id 关闭会话，请求 id 不用于新尝试 | conn E-03；E-04 | `requests.py:149–154` | `test_old_or_repeated_request_id_closes` | 集成运行（单元） | 满足（测试） |
| 245 | TaskBinding 由可信任务入口为一个 Session 创建；task 与 grant id 由 engine 分配、不复用 | rr E-06 | `tasks.py:131–161` | `test_task_and_grant_ids_are_engine_assigned_and_unique` | 集成运行（单元） | 满足（测试） |
| 246 | worker 只提供有界事实，不选会话、不写日志；单一状态执行器是 Session 与 RequestEntry 的唯一写入者 | conn E-03；si E-09 | `handlers.py:41–42`（结果经 `loop.soon` 投回执行器）；`records.py:254–283`（日志线程只写自己的队列与文件） | 代码阅读 | — | 满足（代码阅读） |

### §8 部署主机

按用户 2026-10-19 裁定：部署前提归部署方，不算通过；附开发机（WSL）读数，读数不是部署证明。读数取于 2026-10-18
UTC，内核 6.6.87.2-microsoft-standard-WSL2，CPU 13th Gen Intel Core i7-13700KF。

| 行号 | must | 设计位置 | 开发机读数与实现部分 | 结果 |
|---|---|---|---|---|
| 252 | engine 的 uid 池在主机上只属于它：与任何 uid 分配器的范围不重叠，没有服务或账户配在池内 uid 上，同一池同时至多一个 engine，部署方的 uid 清单列出池内每个持有者 | conn E-01 第 87、105–107 行 | 集成与回归用的池 uid 自 2026-10-19 起为 70000–70002（此前 60000–60002，其中 60000 落在登录范围内；用户同意改池）。`/etc/login.defs` UID_MIN–UID_MAX 为 1000–60000、SUB_UID_MIN 为 100000；`/etc/subuid`、`/etc/subgid` 为 100000–165535；无 systemd DynamicUser 单元（默认范围 61184–65519）；overflow uid 65534；docker 已装、WSL 中没有 docker 守护进程配置文件 daemon.json（未配 userns-remap）；passwd 与 group 中无 70000–70002；运行器逐个运行，同时只有一个 engine。单元测试目录里的 60000 起的 uid 未改，它们不是部署池 | 部署前提；开发机读数：成立 |
| 253 | workspace ↔ uid 目录由可信部署方离线准备，一工作区一 uid | rr E-08 | 开发机上由运行器在每次运行前生成；engine 启动时检查一一对应（`startup.py:167–185`） | 部署前提（开发机读数：成立） |
| 254 | C1：降权以三个相同值调用 setresuid；engine 侧须在 SEALED 前知道三值相等 | kub §6；optb 第 11 步；conn E-01 | 实现部分：`support.c:250–255`（三值相同的 setresuid 加 getresuid 重读）；见上文 bootstrap uid 重读条目 | 实现部分满足（测试）；C1 本身随构建进入部署 |
| 255 | C2 前半 / S4：agent 在 initial user namespace 不持任何 capability——第 11 步清 ambient、permitted 与 bounding，设 no_new_privs，runtime 与 /work 以 nosuid 挂载 | kub §6；optb 第 3–4、11 步；scope S4 | 实现部分：`support.c:238–246`（no_new_privs，逐个 drop bounding）、`257–260`（清 ambient，`cap_set_proc` 空集清 permitted 与 effective）；`child.c:33`（runtime 与 /work 以 MS_NOSUID 重挂）；sandbox 回归 | 实现部分满足（代码阅读加回归）；部署部分为部署前提 |
| 256 | C3 / S13：engine 运行在 initial user namespace，身份映射 | kub §6；scope S13 | uid_map `0 0 4294967295`（集成运行 production-entry 与本次读数）；WSL2 发行版的 init 所在 namespace 即本机 initial namespace（推断，未另行证明） | 部署前提（开发机读数：映射成立） |
| 257 | spawner 在 agent 的 user namespace 中持 CAP_KILL | conn E-04 终止权限 | agent 不建 user namespace（`policy.c:46–49`），所以与 spawner 同在 initial user namespace；运行器给 spawner 的 bounding set 含 kill（`checks/run_engine_checks.py:36`） | 部署前提（开发机读数：成立） |
| 258 | S5：取得描述符的面被拒——seccomp 拒绝 pidfd_getfd 与 ptrace，ptrace_scope ≥ 1，DAC | scope S5 | ptrace_scope = 1；诊断政策默认 EPERM，allow 表不含 ptrace 与 pidfd_getfd（`native/checks/run_sandbox_checks.py:98–111`）；池 uid 两两不同 | 部署前提（开发机读数：成立；生产 S2 另定） |
| 259 | 部署写明内核构建、相关暴露项与生产主机的瞬态执行读数（S14 主机半） | tm D8；scope S14 | 内核 6.6.87.2-microsoft-standard-WSL2（`#1 SMP PREEMPT_DYNAMIC Thu Jun 5 18:30:46 UTC 2025`）；`/sys/devices/system/cpu/vulnerabilities`：spectre_v2 "Enhanced / Automatic IBRS; IBPB: conditional; RSB filling; PBRSB-eIBRS: SW sequence; BHI: BHI_DIS_S"，spectre_v1、spec_store_bypass、retbleed、reg_file_data_sampling 有缓解，其余 9 项 Not affected | 部署前提（开发机读数已记录） |

## 外部请求核对的条目

### AA-13：注销后的 fd 号不再投递就绪（uid-binding 线请求，2026-10-18）

- **条款**：[engine-requirements](../../Thesis/Work/Design/sandbox-mediated-agent-execution/engine-requirements.md)
  （blob `4aecaa3176c589d3`）第 163 行："The event library must deliver no readiness notification for an fd number after
  its registration was removed at close step 2"（服务 one channel, one execution）；uid-binding 论证中记为 AA-13（[S]），
  R-GX-06、R-GX-03 依赖它。
- **设计位置**：conn E-02 接收侧补充（connections.md blob `0c16e567a34aa441`，第 483–484 行："所用 event library 在
  close 第 2 步注销某 fd 后，不再为该 fd 号投递就绪通知；实施时对照所选库核实，不满足则不准入"）；E-04 关闭第 2 步。
- **实现**（提交 73f86021；sha256 前缀 `engine/loop.py` `a99fd49fcb7e325c`、`engine/lifecycle.py` `e43b2a1288c2919c`、
  `engine/phases.py` `050b18aadc9dd172`）。所选库：CPython 3.12.3 `selectors.DefaultSelector`，实际后端 `EpollSelector`。
  - 注销在关闭之前：`lifecycle.py:460–472` `_retire_channel` 先 `loop.forget(fd)`（`loop.py:82` → `_apply` →
    `selector.unregister`，`loop.py:66`，读写两个方向的注册一并移除），再 shutdown（失败也继续）、close，最后
    `data.detach`。控制 fd 同序：`control.py:255–256`。
  - 同一轮已返回的就绪事件：`loop.py:112` 把每个事件与它被选中时的回调对象一起快照，`loop.py:122` 派发前要求该对象
    仍是当前注册（`is`）。fd 已注销，或该号已被新对象注册时，旧事件都不派发；新对象的就绪只来自它自己的下一次 select。
  - 绑定在 Channel 上的其他路径：接收与发送回调持原 Execution 与 Channel，先查 `_current`（`phases.py:56`；Channel
    已为 CLOSED 即不动作，`phases.py:62`、`190`、`208`、`216`）；该 Channel 的组帧、停滞、半帧 timer 在 detach 中取消
    （`phases.py:45–47`）；writer 在 detach 中置空，请求与任务只经 `channel.frame_writer` 写，置空后无写出路径。
- **验证方法/判据**：代码阅读（上条）；测试 `tests/test_deregistration.py`：真实 `close_session` 路径上，同一轮内旧
  Channel 已被选中后被关闭、fd 号立即被新 socket 复用，断言旧 Channel 的接收回调不被调用、新注册不收到旧事件、新 socket
  有数据时只在下一次 select 被报告，并断言后端为 epoll；反向对照（去掉 `loop.py:122` 的身份核对）下两例失败。既有
  `test_control.py::test_stale_selected_event_not_dispatched_to_new_registration`、
  `test_phases.py::test_old_callbacks_do_not_reach_new_channel_on_reused_fd` 一并重跑。
- **原始观察/run ID**：[runs/20261018T152246Z-aa13-deregistration](runs/20261018T152246Z-aa13-deregistration/README.md)。
- **结果及限制**：满足。证据为代码阅读加单元测试（含反向对照）。只核对了 epoll 后端；换用其他 selectors 后端或
  其他事件库须重新核对。测试用 `dup2` 制造同号复用，不经 spawner 交接；真实交接下的跨轮复用由上述既有测试与集成运行
  normal 一例覆盖。第二层防护（Channel 已 CLOSED 时回调不动作）独立于库性质存在，但条款要求的是库性质本身，以第一层为准。

### R-GX-04 两代运行（uid-binding 线请求，2026-10-20）

- **条款**：engine-requirements 第 218 行（部署项）；uid-binding 线 registry §5 item 27："spawner 1 is SIGKILLed while A runs;
  engine 2 starts under the supervisor; record whether A is found and terminated before engine 2's pool restarts and that A's
  bytes reach no engine-2 row"。
- **设计位置**：conn E-04 控制失联（第五次修订，cgroup 形式）：新 engine 起之前，旧 cell 的 cgroup 经 `cgroup.kill` 后
  `cgroup.events` 报 populated 0，放行方只据此、不保存影响安全的状态。
- **实现**：engine 侧无新增：控制断开即隔离并退出（第 217 行）。被测的是 cell 的整体行为；放行门 `release_gate`
  （`checks/run_engine_checks.py`）是测试替身，代替部署中由宿主 init 管理的 supervisor，只读 `cgroup.events`。
- **验证方法/判据**：运行器建 cgroup，engine 1 的整个 cell 在其中；agent A 为 linger 夹具（PID 1 加 setsid 后代，uid 70000）；
  A 到 ACTIVE 后 SIGKILL spawner 1；engine 1 退出后记录 A 仍在；门写 `cgroup.kill`、读到 populated 0 才放行；`w2-recover
  --supervisor-confirmed-old-domain-empty` 后在同一 cgroup 起 engine 2，同一 workspace（同一 uid）上的执行 B 正常往返并关闭。
  判据逐条写在运行 README（开跑前）。
- **原始观察/run ID**：[runs/20261020T154357Z-engine-extra-evidence-rerun](runs/20261020T154357Z-engine-extra-evidence-rerun/README.md)，`extra.json` 的 two-epoch case 与两份事件文件。
- **结果及限制**：判据全部满足。engine 1 退出后 cgroup populated 1，A 的两个任务在运行；门的步骤为 seen 1、kill、seen 0、
  release（engine 1 退出到门放行约 6 ms，含写 kill）；放行时 A 的任务无一在运行，engine 2 启动前均已不存在，A 的 PID 1 回到运行器时为
  SIGKILL，后代由内核在其 pid namespace 内回收；engine 2 的执行 B 租到同一 uid 70000，接受的唯一消息是 B 自己的 Hello，
  无拒收记录。限制：A 在 hello 后静默，不主动尝试接触 engine 2 的行，"无 A 的字节"是对 engine 2 全部记录的核对，不是对抗
  尝试；门是测试替身，不是部署的 supervisor；一次运行；WSL2 开发主机；诊断 seccomp 政策。

## 设计未写、用户裁定的条目

### 会话关闭时 TaskBinding 一并关闭，无引用后归还 grant 容量（用户 2026-10-19 同意）

- **设计位置与缺口**：rr E-06（resources-routing.md blob `1a8ea18374b07431`，第 180–181 行）只写"session 关闭则禁止新动作"；
  conn E-03 容量与调用规则（connections.md blob `0c16e567a34aa441`，第 769–770 行）写 TaskBinding "仅当已 closed 且无调用/请求
  引用时可移除"。两处都没写会话关闭时 TaskBinding 是否转为 closed。不转的话，已关闭会话的绑定永远达不到移除条件，
  engine 级 grant 容量（`GRANTS_ENGINE_MAX` = 256）只占不还，第 17 个满额 execution 起无法再授权。
- **裁定**：close 第 3 步把该会话的每个 TaskBinding 一并转为 closed。当前调用与子请求持有的引用全部归还后，绑定被移除；
  其 grant 不再被任何绑定引用时一并移除，归还 engine 级容量。
- **实现**（提交 73f86021；sha256 前缀 `engine/tasks.py` `7b92fe211ef15ef2`、`engine/requests.py` `25ab8ea661ab4fa5`）：
  `tasks.py:402–414` `on_session_closed` 对每个绑定调用 `close_task`（`191–194`），后者进入 `_maybe_remove`（`196–206`）：
  绑定为 closed 且 `refs` 为 0 时才移除，grant 的绑定计数归零时移除 grant 并递减 `grants_live`。`refs` 由 task_start
  （`tasks.py:243`）与请求准入（`requests.py:178`）加一，由调用结束（`tasks.py:394–395`）与请求释放（`requests.py:520–521`）
  减一后再试移除，所以仍在途的调用或请求不会失去它的绑定与 grant。
- **验证方法/判据**：代码阅读（上条）；测试 `tests/test_request_limits.py::test_grant_capacity_returns_when_executions_close`：
  17 个 execution 依次各建满 16 个 grant（共 272 个，超过 256），每个都经关闭与回收；断言最后 `grants_live` 为 0，且新
  execution 仍能建 grant。
- **原始观察/run ID**：[runs/20261018T144745Z-engine-step3-recheck-fixes](runs/20261018T144745Z-engine-step3-recheck-fixes/README.md)
  （非特权单元测试 281 passed，含上条测试）。
- **结果及限制**：按裁定实现并有单元测试。测试只看最终计数，没有单独断言"调用在途时绑定不被移除"，这一点只有代码阅读。
  本条不改变授权判断：会话关闭本已禁止新动作，关闭绑定只决定容量何时归还。设计文字未改；写入设计须走 uid-binding 线的
  修订加记录（BUILD-PLAN §7）。

## 由构造满足、未做注入测试的条目

### E-01 "预排 hello 不能启用行"（用户 2026-10-19 裁定：不加注入点）

- **条款**：conn E-01 施工验收判据（connections.md blob `0c16e567a34aa441`，第 384 行）："预排 hello…COMMIT 前发数据
  均不能启用行"。
- **满足方式**：只有可信 bootstrap 在 COMMIT 前持有通道；它发完 SEALED 后只收 COMMIT 再 execve，中间不写
  （`native/sandbox/child.c:106–112`，代码阅读）。agent 在那之前不存在，造不出预排的 hello。
- **限制**：engine 一侧不区分字节的写入时刻。若可信 bootstrap 有缺陷、在 COMMIT 前写了 hello，engine 会接受它（读代码
  推断，未运行）。后果限于同一 execution、同一 uid：exec 失败时这一行会短暂 ACTIVE，随后被关闭；不产生跨 execution 的
  错误归属。按用户裁定不在测试构建中加注入点，这一条不在 engine 侧以测试覆盖。

## 以更严格方式满足的条目

### 发送结果不确定的 spawn（用户 2026-10-18 裁定：保持现状）

- **条款**：[engine-requirements](../../Thesis/Work/Design/sandbox-mediated-agent-execution/engine-requirements.md)
  §4，第 186 行："an indeterminate send makes the row uncertain and CLOSED and sends a stop"。
- **设计位置**：conn E-01 状态转换与失败裁决（RESERVED 一行）；E-04 关闭第 4 步；E-04 控制链路故障（"控制 EOF/错误"）。
- **实现**：`control.py:124–133`（`flush` 把 EAGAIN/EINTR 以外的发送错误判为 uncertain，先回调
  `Lifecycle._on_uncertain`，再进入控制链路故障）；`lifecycle.py:184–187`（`_on_uncertain` 把行标为 uncertain 并
  CLOSED）、`527–533`（`_on_control_fault` 关闭所有行，隔离所有未确认空集合的 lease）。构建身份见文首；首次记录时
  （第 1 步）的文件 sha256 前缀为 control.py `0d7c3e08d0cc23b3`、lifecycle.py `49a27cd176d43ce5`。
- **与条款文字的差别**：不补发 stop，而是立即判整条控制通道故障。
- **为什么等价**：只有整条发出才推进序号（conn E-01），所以补发的 stop 会沿用那次 spawn 的序号。
  - 若 spawner 已收到 spawn，同序号的另一条记录是冲突，spawner 判控制故障。
  - 若 spawner 未收到，stop 指向它从未收到的记录。按 conn E-01 身份补充（用户 2026-10-18 裁定），这同样是控制故障。
  - 两种情况都以整条通道故障结束。差别只在由谁先关、早晚，以及是否在刚出错的通道上多发一条。
  - 两种做法都不在没有空集合事实时释放 uid。
- **验证**：单元测试 `tests/test_lifecycle.py::test_uncertain_send_never_local` 断言三点：行 CLOSED 且为 uncertain；
  不写 local 依据；lease 隔离、通道关闭。另有 `test_fact_for_live_unsubmitted_row_faults` 一项。
  第 4 步的集成运行（单元）中两项照常通过；首次记录时的证据为
  [runs/20261018T094456Z-engine-step1-recheck-fixes](runs/20261018T094456Z-engine-step1-recheck-fixes/README.md)。
- **结果与限制**：以更严格方式满足，代价只在可用性，需重启 engine。只有单元测试证据，
  因为真实环境中难以制造这种发送错误。设计文字未改。

## 整体 review（BUILD-PLAN §5，第 4 步检查全部跑完之后）

冷上下文 review，两个模型家族各一次：Codex（核对 40 条 must 并复算 97 行）与 Opus（核对约 45 处引用）。两家都判"不能通过"，
都未发现产品代码违反某条 must；发现与处置如下（"两家"指两家都提出）。

| 发现 | 提出 | 处置 | 重跑 |
|---|---|---|---|
| fuzz frame 入口的描述符泄漏判据在 socketpair 之前取基准、结束时先关掉 socketpair，泄漏到更高号查不出；ancillary 入口的替代 close 只计数、从不断言 | 两家（blocking） | frame 改为 socketpair 打开时比较；ancillary 加结构化模式，断言缓冲区中每个描述符恰好关闭一次；反向对照（拒绝路径不关 rights 的 `transport.c` 副本）两入口都失败 | fuzz 运行 |
| `open_fds` 列 /proc/self/fd 时自己占着一个目录 fd，泄漏的描述符可落在已在快照里的号上（影响第 144、160 行的测试） | 两家 | 改为 fcntl 逐号探测，加对照测试；旧做法在同一情形下漏报（本会话中演示过：旧做法报告新 fd 已在快照中、差集为空；输出未存档，属推断级证据） | 集成运行 |
| R-G3-05 的诱饵在 admission、授权与分派之后才就位 | 两家 | 诱饵在请求帧发出之前就位，对照参数化到四个阶段 | 集成运行 |
| fuzz 运行脚本在 fuzz 或回放失败时仍以 0 退出 | Codex | 汇总 `overall_status`，失败时非 0 退出 | fuzz 运行 |
| 第 142 行"由构造满足"的理由与代码不符：uid 与工作区可在旧槽位仍占用时归还 | 两家 | 改写理由，新增旧槽位仍占用时再启动的测试 | 集成运行 |
| `test_handoff.py` 未进入首次运行 | Opus | 已进入集成运行 | 集成运行 |
| 第 145 行要求的次序观察没做 | Opus | 回归运行器在 busy 一例上以 strace 观察并断言 SO_PASSCRED 先于 clone | sandbox 回归 |
| 第 164 行把"进入缓冲"读作"计入 `used`"未经裁定 | Opus | 报用户；读法被接受，需求句改为"计入头/body 缓冲之前"（2026-10-19），记录补写两个条件 | — |
| 第 208 行的读法只说了 `late_completion`，`request_released` 也带原主体副本 | Opus | 报用户；读法被接受，需求句改为"不带新的或改动过的主体"（2026-10-19），记录写明两种事件及条件 | — |
| R-G2-13 的 3×4 用例在负向例中走同一条路径，非 JSON 三例无区分力 | Opus | 改为头片错与 body 片错两种位置 × 三种阶段规则 × 三种帧，写明区分只在失败位置 | 集成运行（root 单元） |
| "按 fd 查找的表不存在"不准确（`Loop.handlers` 以 fd 号为键） | Opus | R-G3-05 条目与第 161 行改写 | — |
| 第 147 行引的新测试没走到安装路径；第 149 行"写一次"不靠类型；第 166 行 pid ≤ 0 无测试引用 | Opus | 147 去掉该测试；149 写明靠代码结构；166 引 check-transport 的 pid 为 0 例 | — |
| 第 195 行只引了 kill 出错 | Opus | 加 wait 出错的 `spawner.c:390–391` | — |
| 计数表的列归类不一致 | Codex | 按新定义的列重算 | — |
| bootstrap uid 重读的正向说法把 169 个 case 都算成 SEALED | 两家 | 改为"所有到达 SEALED 的启动路径"，列出不经过重读的例 | — |
| `native/fuzz/` 下的两个 crash 文件 | Opus | 来自开跑前的反向对照（libFuzzer 默认把产物写进当前目录），已删除，不提交 | — |

修正后按 BUILD-PLAN §5 只重跑受影响的检查，并以冷上下文复查修正部分，复查返回"可以通过"即停。

**复查（2026-10-19，两家各一次，只看修正部分）：两家都返回"可以通过"，无 blocking。** 余下的小项都只改文字，不重跑：
第 178 行把 fuzz 写成三类拒绝的证据，说过头（Opus，should-fix，已改写为 fuzz 只断言标志一项）；"已演示"与 SO_PASSCRED 解析
函数的合成 trace 核对没有存档（Opus，已注明未存档）；首次 sandbox 回归未标被取代（Opus，已标）；第 145 行的归类与其他以回归
为证据的行不一致（Opus，已改，计数随之重算）；ancillary 结构化模式的"内核式"说法不准，末尾未补齐（Opus，推断，已在 R-G2-11
条目写明；harness 注释未改，以免与运行所记的文件哈希不符）；`open_fds` 只探测 65,536 以下的 fd 号（Codex，minor：内核总是分配
最低空闲号，泄漏只有在已开 65,536 个描述符时才会落到更高处，本套测试远不到；未改代码，以免与运行所用版本不符）。

## 计数

| 节 | must | 满足（测试） | 满足（测试加代码阅读、fuzz 或回归） | 满足（无测试：代码阅读、回归或 fuzz） | 设计已写明 | 由构造满足 | 以更严格方式满足 | 读法待用户确认 | 实现部分满足、部署部分为前提 | 部署前提 | 超出范围 | 未满足 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| §1 UidLease | 6 | 1 | 3 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| §2 Execution、Session 与 Channel | 13 | 3 | 8 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| §3 接收管线 | 22 | 6 | 13 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| §4 控制记录与启动准入 | 12 | 3 | 4 | 1 | 3 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| §5 关闭与回收 | 10 | 5 | 2 | 1 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| §6 Supervisor、epoch 与 engine 启动 | 5 | 3 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| §7 Consumers | 21 | 9 | 7 | 2 | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| §8 部署主机 | 8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 6 | 0 | 0 |
| 合计 | 97 | 30 | 38 | 9 | 7 | 1 | 1 | 0 | 2 | 8 | 1 | 0 |

按每行"结果"栏的第一个结论计；回归中对该条有专门断言的算"测试"（2026-10-19 统一）；一行带两个结论的（如第 144、168、217、230 行）只计第一个，第二个写在该行内。
由脚本按本文件的表格复算（2026-10-19，必要性分析后的补充之后）。

## 收尾运行

整体 review 修正之后的运行即文首"证据栏所指的运行"：集成运行（单元 362 passed、32 skipped，root 单元 32 passed，32 个 case）、
sandbox 回归（171 个 case，含 SO_PASSCRED 次序观察）、fuzz 运行（三入口各 3600 秒，修正判据）。三次运行的开跑前判据全部满足，
跑后均无残留部署目录、挂载与 loop 设备。冷上下文复查记录见"整体 review"一节。

## 必要性分析后的补充（2026-10-19）

逐条核对计数表中"无测试"一列的 16 行哪些值得补测试（用户确认）：
- 已有专门测试、只改归类：第 145 行（回归运行器的次序断言）、第 151 行（fixture 的继承 fd 快照与回归断言）、第 191 行（sandbox
  内建 user namespace 的三条路径被拒）、第 193 行（降权前各阶段的故障注入）、第 209 行（never_created 的多例断言）。归类规则随之
  写明：回归中对该条有专门断言的算"测试"。
- 新增测试：第 146、170 行的源码扫描 `test_no_credential_option_written_or_peer_credential_read`。运行
  [20261019T014433Z-engine-credential-scan](runs/20261019T014433Z-engine-credential-scan/README.md)：单元 363 passed、32 skipped，root 单元 32 passed，32 个 case 通过。
- 不补：第 140、240、246 行已由结构保证（写一次的字段与唯一赋值处、字符串值拷贝、单线程执行器），扫描测试表达不了；第 130 行是
  正常流程到不了的第二道检查；第 150、210 行是复用 C 代码中的唯一调用处与信号设置；第 192 行需要测试构建的 child 注入点（同类注入
  此前用户已否），且降权后的 uid 重读已在 SEALED 之前拦住错误 uid；第 157、175 行以 fuzz 检验。
