# engine — 可信 engine 原型实现

workload-per-engine 设计的原型实现：engine（Python）加复用的 C17 spawner 与接收库。2026-10-18 起由本目录
承接实现（用户裁定）；W2 工作线已停用，其设计文件与实测证据继续被引用。

| 入口 | 职责 |
|---|---|
| [BUILD-PLAN.md](BUILD-PLAN.md) | 首版（身份路径）的范围、模块与设计节对应、构建顺序、检查、review 安排与完成条件；从这里开始 |
| [native/](native/README.md) | 复用的 C 部分及其来源核对；`native/fuzz/` 是 `transport.c` 的 libFuzzer harness 与运行脚本（R-G2-11） |
| [engine/](engine/) | engine 本体（Python 3.12 标准库 + ctypes）：启动自检与两份目录（启动目录、业务目录）、控制客户端、生命周期与回收、事件循环、数据通道的接收管线、阶段规则与写出端、请求准入/授权/分派、任务与 grant 及可信入口、document.read handler 与 model.generate stub connector、E-09 记录；`engine/testing/` 只供集成运行 |
| [bin/](bin/) | 入口：`bin/engine LIB ROOT CATALOG BUSINESS EVIDENCE`（生产，由 `w2-cell` exec；可信调用方暂无进程外通道）与 `bin/engine-scenario`（集成场景） |
| [tests/](tests/)、[checks/run_engine_checks.py](checks/run_engine_checks.py) | 单元测试（pytest，无需特权）与集成运行器（WSL root、btrfs loop 镜像） |
| [validation.md](validation.md) | 实现验证记录：engine-requirements 97 条 must 的逐条映射与 BUILD-PLAN §5 的五项检查（第 4 步）及用户裁定的条目 |
| [engine-requirements](../../Thesis/Work/Design/sandbox-mediated-agent-execution/engine-requirements.md) | engine 必须满足的需求（§0 的 14 条 requirement 及其 must），即验收清单 |
| [W2 engine 设计](../lab/experiments/w2/implementation/engine-design.md) | 设计正文仍在 W2：连接管理、资源管理与路由、配套接口三份分组文件 |
| [验收方法](../lab/experiments/w2/implementation/verification-plan.md) | 设计侧与实现侧的验收规程（用户 2026-09-10 / 09-11 批准） |

实现映射与原始观察记在本目录：validation 记录在首次记录时创建，每次运行进 runs 下的独立目录，旧结果保留。
