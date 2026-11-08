# 20261105T141542Z-formal-server-memory-engine-v4

本论文内存一行按 engine 留档版本 v4 的正式重测（计划 .goals/plans/sota-engine-v4-memory-row.plan.md 第 8 步）：engine-v4-shared（v4，共享放法，v4 的默认）、engine-v4-copy（v4，副本放法）、bare-api-only（本轮基准）、docker-sandboxes（本轮的 VM 型对照，用户 2026-11-05 定每轮都测）。开跑原话"开跑"（用户 2026-11-06）。配置 config/server-memory-engine-v4.json：1、2、4、8、16 档，两遍 2+1 次，时序同 config/server-memory.json（常驻最短 150 秒），seed 20261105，第一遍的次序 docker-sandboxes、engine-v4-shared、bare-api-only、engine-v4-copy，第二遍反过来。服务器同前几轮（AWS us-east-1 m8i.4xlarge，内核 7.0.0-1014-aws）。本目录 driver-snapshot/ 是运行时的驱动原样。

被测的 engine：ExperimentLab/engine-v3 @ a9eff999（prove/baseline 的 v4），服务器 /opt/thesis/ExperimentLab/engine-v3 的 188 个文件与本机导出副本逐个相同；每个部署的 deployment.json 记了这些文件的 sha256（engine_files），随存档在 engine/ 下。开跑前在同一台机器上过了的：v4 自己的检查（engine-v3/runs/20261105T1*-server-*）与驱动 cgroup 放法下的检查（engine-v3/runs/20261105T121*-server-*-placed）；两种放法与 Docker Sandboxes 的冒烟、两种放法各 2 单位的逐进程拆分（runs/20261105T121513Z-v4-chain）；精简试跑 runs/20261105T124603Z-trial-server-engine-v4-mini 、审阅处置与删兜底之后的 runs/20261105T132335Z-trial-server-engine-v4-mini、冷复核处置之后（最终版驱动）的 runs/20261105T134644Z-trial-server-engine-v4-mini。驱动经两家审阅与一次冷复核，处置在 reviews/2026-11-05-engine-v4-disposition.md。

与 10-31 那轮（engine-v2-go）不同的地方：每个单位多两个进程（隔间外的文件 worker、隔间里的 MCP server），全机多一个简易 PDP；核心带测量开关起（v4 只在这个开关下记请求的完成）；每遍登记后删掉 v4 工作区默认的兜底条目（用户 2026-11-06 定，其余主机一律拒绝），每个工作区正好 4 条，驱动核对；engine 在这套登记下不会提问，出现提问判配置错误、停块。

第一次开跑（14:13:28 UTC，目录 20261105T141328Z-formal-server-memory-engine-v4）在开跑前检查停下：Docker 在运行（实例 11-04 重开时开机自启），什么都没测。按驱动自己的停法停掉 docker.socket、docker.service、containerd.service 后，在本目录重新开跑；用户的开跑原话同上。

## 开跑前的预期（推断，2026-11-06 写）

常驻状态，每 agent，非共享 PSS 相对同轮只放行模型 API 的不加系统，MiB。由 10-31 那轮 Go 两行逐档的数（runs/20261031-memory-analysis-engine-go-rerun）加上 2 单位拆分量到的两个新部件推得：文件 worker 私有 12.2、加摊到的 Python 文件页；MCP server 私有约 1.05、加文件页 4.8（副本放法每单位一整份，共享放法按单位数摊）。

| 档 | 共享放法 | 副本放法 |
|---|---|---|
| 1 | 约 54 | 约 53 |
| 2 | 约 43 | 约 94 |
| 4 | 约 37 | 约 114 |
| 8 | 约 34 | 约 124 |
| 16 | 约 33 | 约 129 |

- 副本减共享约为 102.5 ×（1 − 1/N）：N = 2、4、8、16 时约 51、77、90、96（102.5 是副本放法每单位不共享的文件页：Claude Code 91.1、前端 6.0、MCP 4.8、转发 0.6）。10-31 那轮实测比同样的推算高约 5%。
- 共用部件（核心、PDP、spawner 与存储 worker）每多一个 agent 约涨 3 MiB，所以"两项合计"约比上表多 3；PDP 本身固定约 9 MiB。
- 整机已用的斜率：两种放法都约 33–36（10-31 是 20–22，加两个新部件的私有内存约 13）。
- 假设甲（协议第 7 节）：共享放法在每档都低于三家 VM 型对象（Docker Sandboxes、Gondolin、Kairos）最小值的四分之一，满足；副本放法对 Docker Sandboxes、Gondolin 满足，对 Kairos 在 8、16 档会超线（约 124、129 对线 120.0、119.2），4 档约 114 对线 118.3、余量在误差内，所以副本放法很可能不满足。Gondolin 与 Kairos 只在 10-31 晚那轮测过，比较是跨轮的。

## 成功标准（衡量测量本身做成没有，与假设成不成立无关）

- 四个对象两遍都测到 1–16 档，每档 3 次重复，空载与常驻都有读数；出错、停止、缺测都写明原因。
- 计入主结果的读数窗口都没受干扰，或已按规则重跑；每遍收尾核对通过，最后清扫无残留。
- engine 两行：每遍开测前的模型检查是 POST /v1/messages 放行、凭据已放、上游 2xx；每个常驻屏幕在提示符、auto mode；提问 0；每个工作区登记后正好 4 条。
- 分析时从 E-09 逐遍统计被拒的其余主机请求，并逐单位核模型请求。
- 本目录没有真 key 与它的末 20 个字符。

## 结果（跑后）

状态 completed，开跑前检查 18 项全过，最后清扫无残留（sweep_left 为空）；14:15:42–17:44:37 UTC。
- engine-v4-shared、engine-v4-copy、bare-api-only 两遍都测到 1–16 档，每档 3 次；这 45 次重复与 Docker Sandboxes 的 10 次都没受干扰。Docker Sandboxes 第一遍五档各 2 次都在，第二遍起步时 sbx 的登录被服务端吊销（refresh token revoked，"Not authenticated to Docker"），记为 pass_error、一档没测，所以它每档只有 2 次（缺测，原因如上；之后测延迟、并发两列前要用户重新 sbx login）。成功标准的第一条因此对 Docker Sandboxes 没达到，其余三个对象达到。
- 8 次收尾核对都过（各对象每遍一次；Docker Sandboxes 第二遍出错后的收尾也过）。副本放法 4 档有一次读数标为不稳定，按协议不进干净的数。
- engine 两行：每遍的模型检查是 POST /v1/messages 放行、凭据已放、上游 200；每遍登记后 16 个工作区的默认兜底删掉（第一遍 deleted、第二遍 absent），各 4 条；全部常驻屏幕在提示符、auto mode；提问 0；落到其余主机被拒的请求 0。
- 本目录没有真 key：取回前在服务器上、取回后在本机各扫一次（整串与末 20 个字符），0 命中。
- 开跑前的预期与实测每档相差不到 1.5 MiB。分析在 runs/20261105-memory-analysis-engine-v4（含 E-09 逐遍统计、跨轮漂移与假设甲：共享放法每档满足，副本放法对 Kairos 在 8、16 档不满足）。
