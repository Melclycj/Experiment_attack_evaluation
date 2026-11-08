这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| NB-24 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0013.fd-fact.json](raw-0013.fd-fact.json), [raw-0014.json](raw-0014.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0021.json](raw-0021.json) |
| NB-26 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0033.nb26-fact.json](raw-0033.nb26-fact.json), [raw-0034.json](raw-0034.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0041.json](raw-0041.json) |
| NB-22 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0050.audit-after.bin](raw-0050.audit-after.bin), [raw-0052.json](raw-0052.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0054.attach.txt](raw-0054.attach.txt), [raw-0060.json](raw-0060.json) |
| NB-23 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0074.json](raw-0074.json) |
| NB-24 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0093.fd-fact.json](raw-0093.fd-fact.json), [raw-0094.json](raw-0094.json) |
| NB-26 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0106.nb26-fact.json](raw-0106.nb26-fact.json), [raw-0107.json](raw-0107.json) |
| NB-23 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0114.signal-stopped.json](raw-0114.signal-stopped.json), [raw-0127.json](raw-0127.json) |
| NB-22 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0136.audit-after.bin](raw-0136.audit-after.bin), [raw-0138.json](raw-0138.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## NB-24 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:w2_child_launch(pivot_root)；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | key | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0013.fd-fact.json](raw-0013.fd-fact.json), [raw-0014.json](raw-0014.json) |

脚本 sha256：90a95a12002cbfcb66d19f58ebe4124bfad05fd8be7734b2b7c237b51ac6615c；请求契约：sha256:8696579b2af1b574fdefc3537af92e0f9269b6dc70fb8a536483d3d03439a5a2。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0021.json](raw-0021.json) |

脚本 sha256：224ff1a8f01e53bad0c90348a02bf0eb27a5bb5bdc7a0512c2d61f9d5e13b79f；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## NB-26 / engine

预期机制：seccomp + no-cap-net-admin；预期位置（规格/源码，不是动态定位）：native/sandbox/policy.c + child.c:capability-drop；实际观察机制：seccomp + no-cap-net-admin。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | netns | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | seccomp + no-cap-net-admin | — | [raw-0033.nb26-fact.json](raw-0033.nb26-fact.json), [raw-0034.json](raw-0034.json) |

脚本 sha256：3ec133513c462ab0fec92336f623270bc90fa9eec22109d28c285c9833a1ad7f；请求契约：sha256:83f849f5368a13a36abb3214a2980a1fb34119a16285fde73643c9c0958e114b。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0041.json](raw-0041.json) |

脚本 sha256：a0ce34ee27a806a7f302bc1776791c95b3767d0c8a4694f3b02a6ea89a20e6f2；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## NB-22 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:w2_child_launch(pivot_root)；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | audit | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0050.audit-after.bin](raw-0050.audit-after.bin), [raw-0052.json](raw-0052.json) |

脚本 sha256：ae1c4bb1e039dd7aded3f033e622b25e4361ad28b475143a6fbc95fdc1ac6012；请求契约：sha256:5359400d2ed5761920a0e4a8c6cb676cdbead599cf8d1e16cb8bfee954977173。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0054.attach.txt](raw-0054.attach.txt), [raw-0060.json](raw-0060.json) |

脚本 sha256：9b64571b5ba1131ef3a60706c732017975a4ed1d0a7829f62df5f8efc8c242f1；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## NB-23 / engine

预期机制：pid-namespace；预期位置（规格/源码，不是动态定位）：native/sandbox/spawner.c:clone_ready(CLONE_NEWPID)；实际观察机制：pid-namespace。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | core | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | pid-namespace | — | [raw-0074.json](raw-0074.json) |
| 1 | spawner | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | pid-namespace | — | [raw-0074.json](raw-0074.json) |
| 1 | victim | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | pid-namespace | — | [raw-0074.json](raw-0074.json) |
| 1 | auxiliary | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | pid-namespace | — | [raw-0074.json](raw-0074.json) |
| 1 | victim-worker | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | pid-namespace | — | [raw-0074.json](raw-0074.json) |
| 1 | auxiliary-worker | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | pid-namespace | — | [raw-0074.json](raw-0074.json) |

脚本 sha256：2fa12155590f9878901c923a747d3da6bb4e96e899c14b9d090cbb5b7e725170；请求契约：sha256:a893e04736abc39edf4d77b31132db2f0d01cc9eb7de7e3dfb4a9a531816aa2a。

## NB-24 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | key | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0093.fd-fact.json](raw-0093.fd-fact.json), [raw-0094.json](raw-0094.json) |

脚本 sha256：90a95a12002cbfcb66d19f58ebe4124bfad05fd8be7734b2b7c237b51ac6615c；请求契约：sha256:8696579b2af1b574fdefc3537af92e0f9269b6dc70fb8a536483d3d03439a5a2。

## NB-26 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | netns | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0106.nb26-fact.json](raw-0106.nb26-fact.json), [raw-0107.json](raw-0107.json) |

脚本 sha256：3ec133513c462ab0fec92336f623270bc90fa9eec22109d28c285c9833a1ad7f；请求契约：sha256:83f849f5368a13a36abb3214a2980a1fb34119a16285fde73643c9c0958e114b。

## NB-23 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：uid-permission。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | core | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0114.signal-stopped.json](raw-0114.signal-stopped.json), [raw-0127.json](raw-0127.json) |
| 1 | spawner | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | uid-permission | — | [raw-0127.json](raw-0127.json) |
| 1 | victim | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | uid-permission | — | [raw-0127.json](raw-0127.json) |
| 1 | auxiliary | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | uid-permission | — | [raw-0127.json](raw-0127.json) |
| 1 | victim-worker | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | uid-permission | — | [raw-0127.json](raw-0127.json) |
| 1 | auxiliary-worker | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | uid-permission | — | [raw-0127.json](raw-0127.json) |

脚本 sha256：2fa12155590f9878901c923a747d3da6bb4e96e899c14b9d090cbb5b7e725170；请求契约：sha256:a893e04736abc39edf4d77b31132db2f0d01cc9eb7de7e3dfb4a9a531816aa2a。

## NB-22 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | audit | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0136.audit-after.bin](raw-0136.audit-after.bin), [raw-0138.json](raw-0138.json) |

脚本 sha256：ae1c4bb1e039dd7aded3f033e622b25e4361ad28b475143a6fbc95fdc1ac6012；请求契约：sha256:5359400d2ed5761920a0e4a8c6cb676cdbead599cf8d1e16cb8bfee954977173。
