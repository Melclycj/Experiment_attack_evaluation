# Engine 首版构建计划（身份路径）

本文件是 engine 首版的开工计划：做什么、按什么顺序做、怎样算做完。设计正文仍以三份分组设计为准，
本文件不重复设计，只给模块与设计节的对应、构建顺序、检查与完成条件。范围由 uid-binding 线的
[PLAN 第 4 步实现范围](../../Thesis/Work/Submission/prove/uid-binding/PLAN.md)（§Follow-up plan after U，Step 4）
与用户 2026-10-18 的裁定决定。

## 1 范围

- **做**：engine 用 Python（WSL 内 CPython 3.12.3）实现；复用已实测的 C17 spawner 与接收库
  （[native/](native/README.md)，自 W2 复制、与实测版本逐字节核对；`transport.c` 经 FFI 调用）。C 部分只改一处：
  bootstrap 在第 11 步的 setresuid 之后、安装 seccomp 之前用 `getresuid` 重读三个 uid，不全等于记录 uid 即 FAIL
  （stage=uid）、不写 SEALED（conn E-01 身份补充）。重读写在共用的 `w2_drop` 中，engine 与文件 worker 降权时同样
  执行。改后 native 与 W2 实测版本不再逐字节相同，差异记入
  native/README，sandbox 回归在新 run 目录重跑。身份路径全部真做：控制协议与启动交接、
  生命周期与 uid 租约、接收管线与逐片凭据比对、阶段规则、状态执行器、请求准入与分派、Grant /
  TaskBinding、E-09 记录、关闭与回收双门槛。
- **只留接口**：模型调用链（`model.generate` 的 connector 为 stub，按 E-07 签名返回固定文本或固定
  tool_calls）；资源种类（一个 dummy 资源配 `document.read`）。工具定义（rr E-07、si E-10 的
  `tool_definitions_ref`）：复用的 spawner 目录解析不认该字段，首版生产工具集为空（不发 `tools` / `tool_choice`），
  返回 tool_calls 一路只在单元测试中经同一对象链验证；该字段随 E-10 / Pi 接入与 C 一起改（用户 2026-10-19）。
- **不做**：重启恢复与 supervisor（engine 崩溃即重启 WSL）；生产 S2 allow-set（P2b，开发用诊断
  政策）；Pi adapter 与真实模型（E-10 / P2b）；本地模型实例（外部进程，部署方配置）；provider 的
  具体选择（OpenAI 兼容 profile 的 vLLM / llama.cpp 由用户另定）；Anthropic profile。

## 2 必读输入（按此顺序）

1. [engine-requirements.md](../../Thesis/Work/Design/sandbox-mediated-agent-execution/engine-requirements.md)
   §0 的 14 条 requirement 与其下的 must；这是身份路径的验收清单。
2. 当前设计：[connections.md](../lab/experiments/w2/implementation/engine-design/connections.md)（E-01–E-04，blob `976a842da4be5c33`）、
   [resources-routing.md](../lab/experiments/w2/implementation/engine-design/resources-routing.md)（E-06–E-08，`b91408f27402d2d7`）、
   [supporting-interfaces.md](../lab/experiments/w2/implementation/engine-design/supporting-interfaces.md)（E-09–E-10，`fb57e5d4873abf1e`）。
   开工时用 `git hash-object` 核对这三个 blob；不一致说明设计已再修订，先读修订再动手。
  （2026-10-18 第三次修订及其定向修订后：conn `741bc6be72f806e1`、rr `fa3a0bf20c8bc701`、si `39a3f42043770ff9`；
  同日第四次修订（agent 侧不再携带 grant_ref）后：conn `0c16e567a34aa441`、rr `1a8ea18374b07431`、si `c8aff1a37d73561b`。修订内容见
  [design-revision-2026-10-18.md](../../Thesis/Work/Submission/prove/uid-binding/design-revision-2026-10-18.md)。）
  复用 spawner 在 kill/wait 出错时的两处具体行为已写入 conn E-01 身份补充，engine 按其处理。
3. [sandbox-design.md](../lab/experiments/w2/implementation/sandbox-design.md)、[verification-plan.md](../lab/experiments/w2/implementation/verification-plan.md) 的实现侧一节。

## 3 模块与设计节

| 模块 | 职责 | 设计节 |
|---|---|---|
| 控制客户端 | engine ↔ spawner 的 SEQPACKET JSON v:1 与 SCM_RIGHTS；记录按 execution_id / lease_id / engine_epoch 匹配；重复与未知记录的处理 | conn E-01 engine ↔ spawner 控制接口 |
| 生命周期管理 | Execution / Session / Channel / UidLease / WorkspaceRecord；保留、交接安装、关闭、隔离、释放 | conn E-01 对象、字段和所有权、状态转换与失败裁决；E-04；rr E-08 |
| 接收管线 | Channel 的唯一 reader；`transport.c` FFI 的逐片凭据比对；FrameReader；阶段规则；VerifiedContext 唯一构造点 | conn E-02 |
| 状态执行器 | 单线程事件循环；“同一裁决”内不让出控制权；唯一状态写入者 | conn E-03 具体决策、复用和唯一状态写入者 |
| 请求与分派 | RequestEntry、admit_request、TaskCall / TaskBinding、engine 内部 Grant、prepare / authorize / try_dispatch | conn E-03；rr E-06 |
| handler 与 stub | document.read（dummy 资源）、model.generate stub connector；sink 固定原请求 | rr E-07 |
| 记录 | E-09 事件与 verified_subject / control_binding 的区分 | si E-09 |
| 可信入口 | task_start / finish_execution / close_session | conn E-03 连续任务与调用结束屏障；E-04 |
| 测试用 agent | 讲 `w2-local/2` 的最小 agent fixture（扩展现有 [agent_fixture.c](native/checks/agent_fixture.c)），含异常行为开关 | conn E-02 |

## 4 构建顺序

1. **启动与回收**：控制客户端 + 生命周期管理，与现有 spawner 打通 spawn → prepared → 安装 → close →
   empty → 释放；含隔离与重复记录。
2. **接收**：接收管线经 FFI 接 `transport.c`；hello / 阶段规则；VerifiedContext。
3. **请求**：状态执行器、请求与分派、stub handler、E-09 记录、可信入口。
4. **检查**：第 5 节全部检查跑通并留证。
5. **记录**：实现映射写入本目录的 validation 记录（首次记录时创建），原始观察进本目录 runs 下的独立
   run 目录（带配置、命令、时间），旧结果保留。W2 的 implementation-validation 只保存 W2 的历史证据。

## 5 检查

**按 requirement 验收。** engine-requirements §0 的每条 requirement，其下每条标为本次范围内的 must 都要
有一项检查（测试或代码阅读），按 [verification-plan.md](../lab/experiments/w2/implementation/verification-plan.md) 的可追溯链记入
本目录的 validation 记录：条款/源身份 · 设计位置 · 实现位置与构建身份 ·
验证方法/判据 · 原始观察/run ID · 结果及限制；超出范围的 must（第 1 节“不做”）
标明归属，不算通过。测试优先攻击身份绑定与授权：不同 uid 的发送方、篡改的 hello / payload 身份字段、
旧行与迟到事实、fd 号与 request id 的复用、关闭与释放的交错；授权路径另测默认拒绝。

**PLAN 第 4 步的五项检查**（关闭对应的余量槽）：

| 检查 | 方法 |
|---|---|
| R-G2-12 启动自检 | 在真实 engine 启动中观察 uid_map 与 overflowuid 检查通过；人为制造不符的映射观察拒绝服务 |
| R-G2-11 字节与凭据的对应 | `transport.c` 以 ASan/UBSan 构建并 fuzz（记录时长、语料与结果）；Python 侧只经该路径取得已比对的字节 |
| R-G2-13 唯一比对点 | 代码阅读确认 recvmsg 到缓冲之间只有一个比对点、各阶段与错误路径无旁路；配合各阶段的负向测试 |
| R-G3-05 consumer 按引用携带 | 代码阅读与测试：admission → authorize → dispatch → stub handler → 结果 → E-09 记录全程只经对象引用；每接入一个真实 connector 复核一次 |
| R-GX-06 关联只按对象建立与清除 | 测试建行（RESERVED）时建立、安装 prepared fd 时安装、close 第 2 步清除，以及 fd 号与 uid 复用下旧回调不落到新行 |

**第三次修订另加的检查：bootstrap uid 重读。** 正向：完整回归中每次 SEALED 前重读通过。反向：用测试构建
（`w2-cell-test`，`W2_TESTING`）的现有注入机制，在重读处加注入点 `uid.reread`，分两例观察。bootstrap 一例：
FAIL(stage=uid)、无 SEALED、无 prepared，spawner 发 spawn_failed 与 execution_empty。文件 worker 降权一例
（`worker.drop.uid.reread`）：worker 初始化失败，spawner 不回 control_ready、控制通道关闭、不接受 spawn，不产生
任何 execution 记录（同现有 worker-init 用例）。生产构建不含注入点，不算第二处产品改动。

**E-01 的"预排 hello"一例**（conn E-01 施工验收判据）：不加注入点（用户 2026-10-19）。由可信 bootstrap 的构造满足
（发完 SEALED 后只收 COMMIT 再 exec），记入 [validation](validation.md) 的"由构造满足"一节，engine 侧不以测试覆盖。

**AA-13：注销后的 fd 号不再投递就绪**（conn E-02 接收侧补充；uid-binding 线请求）：代码阅读加单元测试（含反向对照），
已记入 [validation](validation.md)。

**Review（用户 2026-10-18 同意）。** 第 4 节 1–3 步各结束后做一次冷上下文代码 review，Opus 与 Codex 两个
模型家族各一次；第 5 节检查全部跑完后再做一次整体 review。review 复核代码与测试本身，不替代测试与
代码阅读；发现按受影响检查重跑，复查返回“可以通过”即停。

## 6 完成条件

- 第 4 节 1–5 步完成；第 5 节每项检查都有记录，失败与未做的照实标出。
- 结果按实测陈述：stub 覆盖到哪里就写到哪里，不把 stub 下的结果写成真实 connector 的结果。
- 完成后交回 uid-binding 线：第 4 步据此关闭 R-G2-11 / 12 / 13 并核对 R-G3-05 / R-GX-06（新 spine 版本，
  受影响文件重跑）。

## 7 开发约定（用户 2026-10-18）

- **设计走不通时停下。** 编码中发现设计有缺口、自相矛盾或无法实现，停下来向用户报告具体位置与可选做法；
  不擅自改设计，也不在代码里绕过。改设计仍走修订加记录（uid-binding 线 design-revision 文件）。
- **集成运行直接跑。** 本目录需要 WSL root 与 btrfs loop 镜像的集成运行（含
  [native/checks/run_sandbox_checks.py](native/checks/run_sandbox_checks.py) 与第 1 步起新增的 engine 集成检查）不必事先
  报批：每次新建 runs 下的运行目录，跑完核对无残留部署目录、挂载与 loop 设备，结果照实汇报。动到 WSL 以外
  的环境或需要安装新包时先问用户。
- **不引入第三方依赖。** engine 只用 Python 3.12 标准库、ctypes 与本目录的 C 库；pytest 仅用于测试。
