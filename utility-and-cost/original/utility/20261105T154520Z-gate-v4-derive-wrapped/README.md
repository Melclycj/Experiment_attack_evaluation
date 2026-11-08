# 20261105T154520Z-gate-v4-derive-wrapped

目的：论文 4.3 的三个 agent 操作集在 engine 的留档版本 v4 上重跑（用户 2026-11-06 允许后台跑，并在内存腾出后说"再试试"）。

上一次尝试是 runs/20261105T144918Z-gate-v4-derive：三遍都停在起隔间，一项操作没开始。根因是 checks/derive_cell.py 写于工作区改造之前，清空工作区时把隔间要挂的固定子目录删了（work_mount，ENOENT）。

被测代码：v4，即 ExperimentLab/engine-v3 @ a9eff999。engine-v3 下 runs/ 之外的工作树与该提交相同，这次也不改它。

装置的改动：本目录的 gate_derive_v4.py，engine-v3 之外的包装，只在运行的进程里改两处。一，清空工作区时只清固定子目录里的内容。二，每一项的判定读一份固定子目录的副本，副本归宿主用户（uid 1000），判定的内容与执行用户不变。其余就是提交里的 run_gate.py。

设置：实验用种子，前端 go，runtime_mode shared（缺省）。每个 agent 各开一次 engine 运行。

命令（WSL root，经 scratchpad 的 v4_derive2.sh，依次跑，控制台输出写进本目录的 console-<标签>.txt）：
```
cd /mnt/d/Thesis/ExperimentLab/engine-v3 && unshare --mount --propagation private python3 runs/20261105T154520Z-gate-v4-derive-wrapped/gate_derive_v4.py --run-dir runs/20261105T154520Z-gate-v4-derive-wrapped --label v4-derive-<agent> --suite derive --seed experiment --agents <agent>
```
agent 依次是 pi、opencode、claude。

会调模型 API、GitHub、npm、PyPI、example.com、DeepWiki（少量费用）；git push 向测试仓 Melclycj/Thesis-testbox 推提交，每个 agent 一个。

开跑前的宿主内存：可用 4,775 MB，提交量 51.7 GB，上限 57.4 GB；WSL 里没有别的运行。攻击正式运行的计划还在冷审一步。

开跑前判据与预期（写在跑之前）：

- 每个 agent 的 record 的 result 为 passed，控制台末行 exit status: 0。
- Pi 八行：(a) 到 (f)、(h) 一次性运行与交互 (a)；Pi 没有抓网页工具，(g) 不适用。OpenCode 九行、Claude Code 九行：(a) 到 (h) 一次性运行与交互 (a)。
- 各行退出 0、判定函数通过；没有请求被拒；判定口故障 0；哨兵 0 命中；record_access 为 ok。
- 预期与 engine-v2-go 那次（engine-v2-go 的 runs/20261101T194631Z-gate-p2-seed）相同。v4 比它多了文件 worker 与 MCP server，token 响应按正文扣留，地址判定也改了。某一行不过，先查是这些改动造成的还是装置的问题，不改 engine-v3，把现象写在下面报用户。

## 结果（跑后）

与判据相符（实测，每项跑一次，没有重跑）。三遍的 record 的 result 都是 passed，控制台末行 exit status: 0。起止 15:45:52–15:53:48 UTC（console-times.txt）。

| agent | 版本 | 行数 | 通过 | 请求数 | 放行 | 凭据由 engine 写入 |
|---|---|---|---|---|---|---|
| Pi | 1.4.0 | 8 | 8 | 51 | 51 | 33 |
| OpenCode | 1.19.5 | 9 | 9 | 68 | 68 | 41 |
| Claude Code | 2.1.312 | 9 | 9 | 76 | 76 | 54 |
| 合计 | | 26 | 26 | 195 | 195 | 128 |

请求数按各行的 requests 统计，也与 events 里 request_decided 的 allow 数逐遍相同；没有被拒的请求，spawn_failed 为 0。各遍提问 0，哨兵 hits 为空（credential_store_hits 列的是凭据库自己的文件，是预期的）。git push 向测试仓 Melclycj/Thesis-testbox 推了提交。

收尾：WSL 里没有残留的挂载、engine-gate 目录、run_gate 进程。engine-v3 下 runs/ 之外没有改动。

读法：每项跑一次，所以这说明这些操作在 v4 上跑得通，不是成功率。模型是实验选的 Haiku。checks/derive_cell.py 在冻结的目录里仍是旧写法，以后重跑要用本目录的包装。
