# 每请求开销：分析结果

由 driver/analyze_latency.py 生成。单位 ms。差 = 经 engine − 同遍直连，最近秩法，范围取核对都过的遍，没有统计检验。p99 的差是分位点之差，不是新增耗时的 p99。

| 组 | 遍数 | 中位差（范围） | p99 差（范围） | 逐遍中位：engine / 直连 |
|---|---|---|---|---|
| cred-bothcold-small | 3 | 8.45–8.78 | 9.13–9.60 | 9.15 / 0.70；9.48 / 0.70；9.32 / 0.71 |
| cred-clientcold-small | 3 | 7.83–8.01 | 8.72–9.05 | 8.57 / 0.74；8.75 / 0.74；8.58 / 0.74 |
| cred-keepalive-big | 3 | 9.05–9.36 | 10.04–10.41 | 10.64 / 1.58；10.88 / 1.52；10.74 / 1.50 |
| cred-keepalive-small | 3 | 7.79–8.19 | 9.03–9.36 | 7.93 / 0.08；7.87 / 0.08；8.27 / 0.08 |
| plain-bothcold-small | 3 | 8.50–8.57 | 9.30–9.61 | 9.21 / 0.71；9.29 / 0.72；9.25 / 0.70 |
| plain-clientcold-small | 3 | 7.62–7.85 | 8.42–9.33 | 8.36 / 0.74；8.58 / 0.74；8.44 / 0.74 |
| plain-keepalive-small | 3 | 7.29–7.97 | 9.05–63.97 | 7.37 / 0.08；7.81 / 0.08；8.05 / 0.08 |

## 连接（每块测量段的次数）

| 遍 | 组 | 臂 | 客户端 TLS 握手 | 客户端新连接 | 上游新连接 | 上游会话复用 | 客户端协议 | 上游协议 |
|---|---|---|---|---|---|---|---|---|
| 1 | cred-bothcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | cred-bothcold-small | engine | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | cred-clientcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | cred-clientcold-small | engine | 1000 | 1000 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | cred-keepalive-big | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | cred-keepalive-big | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | cred-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | cred-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | plain-bothcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | plain-bothcold-small | engine | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | plain-clientcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | plain-clientcold-small | engine | 1000 | 1000 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | plain-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 1 | plain-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-bothcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-bothcold-small | engine | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-clientcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-clientcold-small | engine | 1000 | 1000 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-keepalive-big | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-keepalive-big | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | cred-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | plain-bothcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | plain-bothcold-small | engine | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | plain-clientcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | plain-clientcold-small | engine | 1000 | 1000 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | plain-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 2 | plain-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-bothcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-bothcold-small | engine | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-clientcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-clientcold-small | engine | 1000 | 1000 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-keepalive-big | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-keepalive-big | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | cred-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | plain-bothcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | plain-bothcold-small | engine | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | plain-clientcold-small | direct | 1000 | 1000 | 1000 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | plain-clientcold-small | engine | 1000 | 1000 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | plain-keepalive-small | direct | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |
| 3 | plain-keepalive-small | engine | 0 | 0 | 0 | 0 | HTTP/1.1 | TLSv1.3 |

## 核对没过的块

没有。

## 超过本块中位两倍的样本（留在结果里）

- 第 1 遍 cred-bothcold-small direct：4 个，本块中位 0.70、p99 1.35
- 第 1 遍 cred-clientcold-small direct：1 个，本块中位 0.74、p99 1.22
- 第 1 遍 cred-keepalive-small direct：26 个，本块中位 0.08、p99 0.27
- 第 1 遍 plain-bothcold-small direct：2 个，本块中位 0.71、p99 1.22
- 第 1 遍 plain-clientcold-small direct：4 个，本块中位 0.74、p99 1.26
- 第 1 遍 plain-keepalive-small direct：22 个，本块中位 0.08、p99 0.23
- 第 1 遍 plain-keepalive-small engine：11 个，本块中位 7.37、p99 64.20
- 第 2 遍 cred-bothcold-small direct：5 个，本块中位 0.70、p99 1.29
- 第 2 遍 cred-clientcold-small direct：1 个，本块中位 0.74、p99 1.29
- 第 2 遍 cred-keepalive-small direct：26 个，本块中位 0.08、p99 0.26
- 第 2 遍 plain-bothcold-small direct：5 个，本块中位 0.72、p99 1.27
- 第 2 遍 plain-clientcold-small direct：1 个，本块中位 0.74、p99 1.20
- 第 2 遍 plain-keepalive-small direct：18 个，本块中位 0.08、p99 0.22
- 第 3 遍 cred-bothcold-small direct：5 个，本块中位 0.71、p99 1.26
- 第 3 遍 cred-clientcold-small direct：5 个，本块中位 0.74、p99 1.23
- 第 3 遍 cred-keepalive-small direct：22 个，本块中位 0.08、p99 0.21
- 第 3 遍 plain-bothcold-small direct：5 个，本块中位 0.70、p99 1.17
- 第 3 遍 plain-clientcold-small direct：3 个，本块中位 0.74、p99 1.22
- 第 3 遍 plain-keepalive-small direct：23 个，本块中位 0.08、p99 0.23

## 放行记录到上游记完（engine 臂，含等放行记录落盘）

| 遍 | 组 | 中位 | p99 |
|---|---|---|---|
| 1 | cred-bothcold-small | 6.57 | 7.88 |
| 2 | cred-bothcold-small | 6.80 | 8.14 |
| 3 | cred-bothcold-small | 6.68 | 7.75 |
| 1 | cred-clientcold-small | 5.94 | 7.25 |
| 2 | cred-clientcold-small | 6.05 | 7.55 |
| 3 | cred-clientcold-small | 5.94 | 7.33 |
| 1 | cred-keepalive-big | 7.58 | 9.01 |
| 2 | cred-keepalive-big | 7.84 | 9.41 |
| 3 | cred-keepalive-big | 7.68 | 9.09 |
| 1 | cred-keepalive-small | 6.17 | 7.59 |
| 2 | cred-keepalive-small | 6.22 | 7.68 |
| 3 | cred-keepalive-small | 6.41 | 7.82 |
| 1 | plain-bothcold-small | 6.60 | 7.93 |
| 2 | plain-bothcold-small | 6.66 | 8.19 |
| 3 | plain-bothcold-small | 6.62 | 7.91 |
| 1 | plain-clientcold-small | 5.79 | 6.94 |
| 2 | plain-clientcold-small | 5.96 | 7.62 |
| 3 | plain-clientcold-small | 5.84 | 7.59 |
| 1 | plain-keepalive-small | 5.63 | 62.77 |
| 2 | plain-keepalive-small | 6.13 | 7.51 |
| 3 | plain-keepalive-small | 6.29 | 7.61 |

## 核心自己的分段（engine 记录，只看量级，不相加）

| 核心运行 | 组 | 判定 | 放行 | 凭据已放 | 接收到判定 中位 / p99 | PDP 往返 中位 / p99 |
|---|---|---|---|---|---|---|
| engine-v4-latency-20261106T023228 | cred-bothcold-small | 1100 | 1100 | 1100 | 0.31 / 0.49 | 0.18 / 0.36 |
| engine-v4-latency-20261106T023228 | cred-clientcold-small | 1100 | 1100 | 1100 | 0.30 / 0.50 | 0.18 / 0.36 |
| engine-v4-latency-20261106T023228 | cred-keepalive-big | 1100 | 1100 | 1100 | 0.33 / 0.61 | 0.19 / 0.46 |
| engine-v4-latency-20261106T023228 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.30 / 0.54 | 0.18 / 0.43 |
| engine-v4-latency-20261106T023228 | plain-bothcold-small | 1100 | 1100 | 0 | 0.30 / 0.53 | 0.18 / 0.40 |
| engine-v4-latency-20261106T023228 | plain-clientcold-small | 1100 | 1100 | 0 | 0.29 / 0.49 | 0.17 / 0.37 |
| engine-v4-latency-20261106T023228 | plain-keepalive-small | 1100 | 1100 | 0 | 0.27 / 0.52 | 0.16 / 0.40 |
| engine-v4-latency-20261106T023541 | cred-bothcold-small | 1100 | 1100 | 1100 | 0.32 / 0.56 | 0.19 / 0.42 |
| engine-v4-latency-20261106T023541 | cred-clientcold-small | 1100 | 1100 | 1100 | 0.32 / 0.53 | 0.19 / 0.40 |
| engine-v4-latency-20261106T023541 | cred-keepalive-big | 1100 | 1100 | 1100 | 0.33 / 0.56 | 0.19 / 0.40 |
| engine-v4-latency-20261106T023541 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.29 / 0.53 | 0.17 / 0.41 |
| engine-v4-latency-20261106T023541 | plain-bothcold-small | 1100 | 1100 | 0 | 0.30 / 0.49 | 0.18 / 0.37 |
| engine-v4-latency-20261106T023541 | plain-clientcold-small | 1100 | 1100 | 0 | 0.30 / 0.49 | 0.18 / 0.35 |
| engine-v4-latency-20261106T023541 | plain-keepalive-small | 1100 | 1100 | 0 | 0.30 / 0.56 | 0.18 / 0.45 |
| engine-v4-latency-20261106T023855 | cred-bothcold-small | 1100 | 1100 | 1100 | 0.32 / 0.54 | 0.19 / 0.40 |
| engine-v4-latency-20261106T023855 | cred-clientcold-small | 1100 | 1100 | 1100 | 0.31 / 0.48 | 0.18 / 0.34 |
| engine-v4-latency-20261106T023855 | cred-keepalive-big | 1100 | 1100 | 1100 | 0.33 / 0.53 | 0.19 / 0.38 |
| engine-v4-latency-20261106T023855 | cred-keepalive-small | 1100 | 1100 | 1100 | 0.34 / 0.55 | 0.21 / 0.43 |
| engine-v4-latency-20261106T023855 | plain-bothcold-small | 1100 | 1100 | 0 | 0.31 / 0.51 | 0.19 / 0.39 |
| engine-v4-latency-20261106T023855 | plain-clientcold-small | 1100 | 1100 | 0 | 0.30 / 0.46 | 0.18 / 0.33 |
| engine-v4-latency-20261106T023855 | plain-keepalive-small | 1100 | 1100 | 0 | 0.35 / 0.58 | 0.22 / 0.46 |

## 每遍开始前的环境读数

| 遍 | CPU 校准（秒） | fsync 中位 / p99（ms） |
|---|---|---|
| 1 | 0.747 | 3.46 / 4.38 |
| 2 | 0.781 | 3.47 / 4.28 |
| 3 | 0.818 | 3.43 / 3.99 |
