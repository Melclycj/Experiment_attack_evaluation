# 每请求开销：分析结果

由 driver/analyze_latency.py 生成。单位 ms。差 = 经 engine − 同遍直连，最近秩法，范围取核对都过的遍，没有统计检验。p99 的差是分位点之差，不是新增耗时的 p99。

| 组 | 遍数 | 中位差（范围） | p99 差（范围） | 逐遍中位：engine / 直连 |
|---|---|---|---|---|
| cred-keepalive-small | 3 | 0.96–1.03 | 1.48–1.76 | 1.04 / 0.08；1.10 / 0.08；1.07 / 0.08 |

## 连接（每块测量段的次数）

| 遍 | 组 | 臂 | 客户端 TLS 握手 | 客户端新连接 | 上游新连接 | 上游会话复用 | 客户端协议 | 上游协议 |
|---|---|---|---|---|---|---|---|---|
| 1 | cred-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | cred-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |

## 核对没过的块

没有。

## 超过本块中位两倍的样本（留在结果里）

- 第 1 遍 cred-keepalive-small direct：19 个，本块中位 0.08、p99 0.22
- 第 2 遍 cred-keepalive-small direct：22 个，本块中位 0.08、p99 0.24
- 第 3 遍 cred-keepalive-small direct：19 个，本块中位 0.08、p99 0.23
- 第 3 遍 cred-keepalive-small engine：2 个，本块中位 1.07、p99 1.78

## 放行记录到上游记完（engine 臂，含等放行记录落盘）

| 遍 | 组 | 中位 | p99 |
|---|---|---|---|
| 1 | cred-keepalive-small | -0.17 | 0.38 |
| 2 | cred-keepalive-small | -0.17 | 0.52 |
| 3 | cred-keepalive-small | -0.14 | 0.43 |

## 核心自己的分段（engine 记录，只看量级，不相加）

| 核心运行 | 组 | 判定 | 放行 | 凭据已放 | 接收到判定 中位 / p99 | PDP 往返 中位 / p99 |
|---|---|---|---|---|---|---|
| engine-v4-latency-20261106T031401 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.26 / 0.34 | 0.15 / 0.21 |
| engine-v4-latency-20261106T031437 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.27 / 0.38 | 0.16 / 0.23 |
| engine-v4-latency-20261106T031512 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.26 / 0.36 | 0.15 / 0.23 |

## 每遍开始前的环境读数

| 遍 | CPU 校准（秒） | fsync 中位 / p99（ms） |
|---|---|---|
| 1 | 0.760 | 0.00 / 0.00 |
| 2 | 0.752 | 0.00 / 0.00 |
| 3 | 0.752 | 0.00 / 0.00 |
