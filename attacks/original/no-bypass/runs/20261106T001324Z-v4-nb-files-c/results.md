这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| NB-12 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0012.file-fact.json](raw-0012.file-fact.json), [raw-0013.file-fact.json](raw-0013.file-fact.json), [raw-0014.json](raw-0014.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0021.json](raw-0021.json) |
| NB-13 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0032.file-fact.json](raw-0032.file-fact.json), [raw-0033.file-fact.json](raw-0033.file-fact.json), [raw-0034.json](raw-0034.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0041.json](raw-0041.json) |
| NB-14 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0052.file-fact.json](raw-0052.file-fact.json), [raw-0053.file-fact.json](raw-0053.file-fact.json), [raw-0054.json](raw-0054.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0056.attach.txt](raw-0056.attach.txt), [raw-0062.json](raw-0062.json) |
| NB-12 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0081.file-fact.json](raw-0081.file-fact.json), [raw-0082.file-fact.json](raw-0082.file-fact.json), [raw-0083.json](raw-0083.json) |
| NB-13 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0094.file-fact.json](raw-0094.file-fact.json), [raw-0095.file-fact.json](raw-0095.file-fact.json), [raw-0096.json](raw-0096.json) |
| NB-14 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0107.file-fact.json](raw-0107.file-fact.json), [raw-0108.file-fact.json](raw-0108.file-fact.json), [raw-0109.json](raw-0109.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## NB-12 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | source | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0012.file-fact.json](raw-0012.file-fact.json), [raw-0014.json](raw-0014.json) |
| 1 | mount | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0013.file-fact.json](raw-0013.file-fact.json), [raw-0014.json](raw-0014.json) |

脚本 sha256：ea724f6ceabb9d71cb265361adda0dd7b7a852351b865f3d8424533f4b770d1e；请求契约：sha256:99a303f3ed08651e47b39979b1b1be588d8a7f1bd4c4a85e6e95841b1d26aeb0。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0021.json](raw-0021.json) |

脚本 sha256：224ff1a8f01e53bad0c90348a02bf0eb27a5bb5bdc7a0512c2d61f9d5e13b79f；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## NB-13 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | source | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0032.file-fact.json](raw-0032.file-fact.json), [raw-0034.json](raw-0034.json) |
| 1 | mount | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0033.file-fact.json](raw-0033.file-fact.json), [raw-0034.json](raw-0034.json) |

脚本 sha256：4dcfecf792a21ca6b450c600140e855ad20813fc4a440bfc708689bff5eee241；请求契约：sha256:875b1666d78b39f76607b5fa8616df52733b29093fa2600b5aecbc9e7bb31763。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0041.json](raw-0041.json) |

脚本 sha256：a0ce34ee27a806a7f302bc1776791c95b3767d0c8a4694f3b02a6ea89a20e6f2；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## NB-14 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | source | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0052.file-fact.json](raw-0052.file-fact.json), [raw-0054.json](raw-0054.json) |
| 1 | mount | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0053.file-fact.json](raw-0053.file-fact.json), [raw-0054.json](raw-0054.json) |

脚本 sha256：fcf5fa3845bd146739a8d534ff7a9281135e98b1f2cf20c687c28a8fc437fe95；请求契约：sha256:0ed3df487c9b6343d5773bb39919330a3d4e85c3e68e0f60ec9ce05b00765435。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0056.attach.txt](raw-0056.attach.txt), [raw-0062.json](raw-0062.json) |

脚本 sha256：9b64571b5ba1131ef3a60706c732017975a4ed1d0a7829f62df5f8efc8c242f1；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## NB-12 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | source | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0081.file-fact.json](raw-0081.file-fact.json), [raw-0083.json](raw-0083.json) |
| 1 | mount | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0082.file-fact.json](raw-0082.file-fact.json), [raw-0083.json](raw-0083.json) |

脚本 sha256：ea724f6ceabb9d71cb265361adda0dd7b7a852351b865f3d8424533f4b770d1e；请求契约：sha256:99a303f3ed08651e47b39979b1b1be588d8a7f1bd4c4a85e6e95841b1d26aeb0。

## NB-13 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | source | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0094.file-fact.json](raw-0094.file-fact.json), [raw-0096.json](raw-0096.json) |
| 1 | mount | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0095.file-fact.json](raw-0095.file-fact.json), [raw-0096.json](raw-0096.json) |

脚本 sha256：4dcfecf792a21ca6b450c600140e855ad20813fc4a440bfc708689bff5eee241；请求契约：sha256:875b1666d78b39f76607b5fa8616df52733b29093fa2600b5aecbc9e7bb31763。

## NB-14 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | source | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0107.file-fact.json](raw-0107.file-fact.json), [raw-0109.json](raw-0109.json) |
| 1 | mount | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0108.file-fact.json](raw-0108.file-fact.json), [raw-0109.json](raw-0109.json) |

脚本 sha256：fcf5fa3845bd146739a8d534ff7a9281135e98b1f2cf20c687c28a8fc437fe95；请求契约：sha256:0ed3df487c9b6343d5773bb39919330a3d4e85c3e68e0f60ec9ce05b00765435。
