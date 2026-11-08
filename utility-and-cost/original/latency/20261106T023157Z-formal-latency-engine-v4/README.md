# 20261106T023157Z-formal-latency-engine-v4

每请求开销的正式测：engine 留档版本 v4（ExperimentLab/engine-v3 @ a9eff999）对直连，只测本论文（用户 2026-11-06）。计划 .goals/plans/engine-v4-request-latency.plan.md，方法在 protocol.md 第 3.3 节的"engine v4 这一轮"。02:31:57–02:42:02 UTC，status completed，收尾没有残留。命令：`python3 -m driver.latency config/latency-engine-v4.json formal`，驱动快照在 driver-snapshot/。

## 条件

- 服务器：AWS m8i.4xlarge（16 vCPU，Xeon 6975P-C），内核 7.0.0-1014-aws，记录所在的盘是 EBS。Docker、containerd 都没有运行。
- 部署：共享放法（v4 缺省），1 个工作区，简易 PDP（对每个请求答允许，不读正文），精确放行条目，删默认兜底，提问 0 次。不开完成记录开关。engine 文件 188 个与 v4 导出副本逐个相同（deployment.json 对 prove/baseline/artifacts/v4/engine，取回后在本机比）。
- 客户端：k6 v2.3.0，1 个 VU，一次迭代一个请求，连续发。两臂是同一个文件：engine 臂种子里的 bin/k6 由 driver/engine_deploy.py 从 /usr/local/bin/k6 拷入，直连臂直接运行它（components.json 的 sha256 前缀 e001bbf3，与 setup/agent-vault.md 记的同一个 k6 相同）。配额都是 2 CPU、4 GiB；42 块节流 0 次。
- 上游：nginx 1.24.0，TLS 1.3，单独的网络命名空间，经 veth 接出，同一台机器。放测试 CA，凭据是随机测试值，没有用到模型 key（本目录按模型 key 扫过，0 命中）。
- CPU：nginx 在 vCPU 0–3，驱动在 vCPU 4，被测的都在 vCPU 5–15。
- 每遍开始前：CPU 校准 0.747、0.781、0.818 秒；同一磁盘 fsync 中位 3.46、3.47、3.43 ms，p99 4.38、4.28、3.99 ms。

## 开跑前的预期（2026-11-06，写在计划里，开跑之前）与结果

| 预期（推断） | 结果 |
|---|---|
| 带凭据 + 复用连接的中位差在 2 到 20 ms 之间 | 符合：7.8–8.2 ms |
| 不带凭据与带凭据相差不到 2 ms | 符合：7.3–8.0 对 7.8–8.2 |
| 客户端新建比复用多几毫秒到十几毫秒 | **不符合**：差几乎不变（7.8–8.0），因为直连也要付一次握手；只看 engine 臂多约 0.7 ms（8.6–8.8 对 7.9–8.3） |
| 大请求的差大于小请求 | 符合：9.1–9.4 ms |

成功标准（7 组 3 遍跑完，逐块核对全过，engine 文件与 v4 相同）达到。

## 结果

latency-analysis.md 是分析脚本 driver/analyze_latency.py 的输出，latency-analysis.json 是它的全部数字；数值表也在 REPORT.md 第 5 节。⟨c⟩ 取带凭据 + 复用连接的中位差：三遍 7.85、7.80、8.19 ms。

## 用这些数之前要先知道的

- **大部分时间在等放行记录落盘。** 放行记录写好、落盘的回执回来，engine 才发放行（engine/hook.py 第 544 行起），写线程每批 fsync 一次（engine/records.py 第 342 行起）。带凭据 + 复用连接的 engine 臂，从放行记录到上游记完中位 6.17、6.22、6.41 ms（实测，每次中位都比接收到判定的 0.3 ms 大一个量级）。同一磁盘一次 fsync 中位约 3.45 ms（实测）；第 1 遍第一块里，这一段在第 111–474 次中位 2.99 ms，第 500 次起 6.08 ms（实测），差正好约一次 fsync。"一个请求通常等两次 fsync"是读码加这些数的推断，没有记录放行帧发出时刻的事件。换磁盘这个数会变，没有测过。
- **第 1 遍第一块有一段停顿。** plain-keepalive-small 的 engine 臂（整个运行的第一块）第 98–110 次连续 13 次 17–257 ms，时间全在放行记录到上游这一段，其中 11 次在测量段，所以这一组 p99 差的上端是 63.97，其余两遍 9.05 与 9.29。这段停顿留在结果里。原因没有查清（推断是磁盘短时变慢；部署刚建好，这条驱动没有像内存测那样等写回稳定）。之后 364 次落在一次 fsync 的那一档，这一块的中位 7.37 因此比另两遍低。⟨c⟩ 那组不受影响：三遍里没有超过本块中位两倍的样本。
- **两档。** 一个请求的记录可能落在一批或两批里，engine 臂因此有约 4.4 与约 8 ms 两档，由线程调度决定。稳态几乎都在 8 ms 那一档（⟨c⟩ 那组 19、42、30 次落在 6 ms 以下，共 3000 次）。试跑只有 50 次，有几块落在 4.4 ms 那一档。
- **连续发。** 每块前 20 次已是约 8 ms，不是累积出来的（实测）。隔很久才发一个请求的情况没有测；按写线程的代码，那样也是两批（推断）。每块第一次迭代 engine 13.5–19.3 ms、直连 1.5–3.8 ms，都含建连，只能当上界。
- **客户端新建时两臂的连接不一样。** engine 臂上游一个新连接都没有（connector 自己复用），直连每次都新连上游。协议第 3.3 节规定各跳不拉平，按实际部署的成本比。
- **其他限制。** 上游在同一台机器，不含真实网络；简易 PDP 要加上真实 PDP 自己的时间；只有一台机器、3 遍，没有统计检验；只测了一个请求在途。

## 冷复核

reviews/2026-11-06-latency-recheck-fable.md（冷启动 Fable，独立复算 42 块，与分析结果逐行一致），裁定可用、带限定。处置：落盘等待与停顿都已写进分析脚本和上面两条；协议第 3.3 节"判定记录在答复帧发出之后才写"与 v4 不符，已改；隔间内外 k6 是否同一文件，读 engine_deploy.py 与 sha256 已核（见"条件"）；快照里多一个 engine_deploy.py.before-uid-range 是服务器上的备份，不被 import，不处理。

## 本目录的文件

config.json、meta.json、summary.json；blocks.jsonl（每块一行）、passes.jsonl（每遍的校准与 fsync）；k6/（k6 原始 JSON，gzip）；upstream/（nginx 访问日志，gzip，按块切开）；nginx.conf（测试值已隐去）；engine/（每遍一次核心运行：记录 events-*.jsonl.gz、日志、部署配置）；k6-direct.log；host-*/（代理的 5 秒采样）；driver-snapshot/。
