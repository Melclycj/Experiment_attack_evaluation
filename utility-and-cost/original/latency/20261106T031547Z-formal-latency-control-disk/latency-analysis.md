# 每请求开销：分析结果

由 driver/analyze_latency.py 生成。单位 ms。差 = 经 engine − 同遍直连，最近秩法，范围取核对都过的遍，没有统计检验。p99 的差是分位点之差，不是新增耗时的 p99。

| 组 | 遍数 | 中位差（范围） | p99 差（范围） | 逐遍中位：engine / 直连 |
|---|---|---|---|---|
| cred-keepalive-small | 3 | 7.63–8.06 | 8.95–9.14 | 7.71 / 0.08；8.14 / 0.08；7.77 / 0.08 |

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

- 第 1 遍 cred-keepalive-small direct：24 个，本块中位 0.08、p99 0.26
- 第 2 遍 cred-keepalive-small direct：21 个，本块中位 0.08、p99 0.23
- 第 3 遍 cred-keepalive-small direct：25 个，本块中位 0.08、p99 0.27

## 放行记录到上游记完（engine 臂，含等放行记录落盘）

| 遍 | 组 | 中位 | p99 |
|---|---|---|---|
| 1 | cred-keepalive-small | 6.01 | 7.72 |
| 2 | cred-keepalive-small | 6.30 | 7.68 |
| 3 | cred-keepalive-small | 6.11 | 7.58 |

## 核心自己的分段（engine 记录，只看量级，不相加）

| 核心运行 | 组 | 判定 | 放行 | 凭据已放 | 接收到判定 中位 / p99 | PDP 往返 中位 / p99 |
|---|---|---|---|---|---|---|
| engine-v4-latency-20261106T031639 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.29 / 0.56 | 0.17 / 0.43 |
| engine-v4-latency-20261106T031728 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.34 / 0.61 | 0.21 / 0.49 |
| engine-v4-latency-20261106T031818 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.30 / 0.54 | 0.18 / 0.42 |

## 每遍开始前的环境读数

| 遍 | CPU 校准（秒） | fsync 中位 / p99（ms） |
|---|---|---|
| 1 | 0.752 | 3.27 / 4.05 |
| 2 | 0.750 | 3.38 / 4.18 |
| 3 | 0.752 | 3.42 / 4.05 |
