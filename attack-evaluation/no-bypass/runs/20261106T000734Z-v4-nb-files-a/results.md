这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| NB-01 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0010.file-fact.json](raw-0010.file-fact.json), [raw-0011.json](raw-0011.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0018.json](raw-0018.json) |
| NB-02 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0027.file-fact.json](raw-0027.file-fact.json), [raw-0028.json](raw-0028.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0035.json](raw-0035.json) |
| NB-03 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0044.file-fact.json](raw-0044.file-fact.json), [raw-0045.json](raw-0045.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0047.attach.txt](raw-0047.attach.txt), [raw-0053.json](raw-0053.json) |
| NB-04 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0062.file-fact.json](raw-0062.file-fact.json), [raw-0063.json](raw-0063.json) |
| NB-05 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0072.file-fact.json](raw-0072.file-fact.json), [raw-0073.json](raw-0073.json) |
| NB-06 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0082.file-fact.json](raw-0082.file-fact.json), [raw-0083.json](raw-0083.json) |
| NB-01 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0100.file-fact.json](raw-0100.file-fact.json), [raw-0101.json](raw-0101.json) |
| NB-02 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0110.file-fact.json](raw-0110.file-fact.json), [raw-0111.json](raw-0111.json) |
| NB-03 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0120.file-fact.json](raw-0120.file-fact.json), [raw-0121.json](raw-0121.json) |
| NB-04 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0130.file-fact.json](raw-0130.file-fact.json), [raw-0131.json](raw-0131.json) |
| NB-05 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0140.file-fact.json](raw-0140.file-fact.json), [raw-0141.json](raw-0141.json) |
| NB-06 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0150.file-fact.json](raw-0150.file-fact.json), [raw-0151.json](raw-0151.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## NB-01 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0010.file-fact.json](raw-0010.file-fact.json), [raw-0011.json](raw-0011.json) |

脚本 sha256：8574510c3c3218e3e2ceb240494b184d59cecf3b5aab076f14b1e6aed3583bd7；请求契约：sha256:afc6c0c61d0e57fe4c1b1da13af57030c3a0fa1ea67a9ed94112c32a716db8d3。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0018.json](raw-0018.json) |

脚本 sha256：224ff1a8f01e53bad0c90348a02bf0eb27a5bb5bdc7a0512c2d61f9d5e13b79f；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## NB-02 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0027.file-fact.json](raw-0027.file-fact.json), [raw-0028.json](raw-0028.json) |

脚本 sha256：456b7ca3dffe3126b04c81e68c36291e27887d936e58a19410beb3f84b3954d2；请求契约：sha256:340790d0b8bec6817c0c15e1efca006044f1ce308da27377c895e4cc62d69aff。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0035.json](raw-0035.json) |

脚本 sha256：a0ce34ee27a806a7f302bc1776791c95b3767d0c8a4694f3b02a6ea89a20e6f2；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## NB-03 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0044.file-fact.json](raw-0044.file-fact.json), [raw-0045.json](raw-0045.json) |

脚本 sha256：0384992b36b69137e1556c19df8a00fe4f0483216f557961ed90c5dbaf4e5c70；请求契约：sha256:54959201c8eba286683c6e7d0bf3c5c9b247c98fdbf039ecfdb123381ff3feaf。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0047.attach.txt](raw-0047.attach.txt), [raw-0053.json](raw-0053.json) |

脚本 sha256：9b64571b5ba1131ef3a60706c732017975a4ed1d0a7829f62df5f8efc8c242f1；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## NB-04 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0062.file-fact.json](raw-0062.file-fact.json), [raw-0063.json](raw-0063.json) |

脚本 sha256：22a368c6a8ce7887588349142f98c793f4ca282844bda353b09a836e8f74c883；请求契约：sha256:673882c8a2560529cd3e77e687f97b465e7ff9d9861cb33bacd9eb926aa1bef0。

## NB-05 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0072.file-fact.json](raw-0072.file-fact.json), [raw-0073.json](raw-0073.json) |

脚本 sha256：afd9080127527469335c511040e9b24504d8222c52c7f3bb3ac9120357d91858；请求契约：sha256:000f55763fd7fe33f6d0fa808b8762284fc2cecbb7b17393acb32a2dc9d93c98。

## NB-06 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0082.file-fact.json](raw-0082.file-fact.json), [raw-0083.json](raw-0083.json) |

脚本 sha256：55f0786cf09e290bb356d9a82f1d3ba85db87f4b6bdb0237b7bdbfa60f67d375；请求契约：sha256:e0fe48d5edee3e7f3e69361a83ee1b260389eae5afb78087a70881402a229b6e。

## NB-01 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0100.file-fact.json](raw-0100.file-fact.json), [raw-0101.json](raw-0101.json) |

脚本 sha256：8574510c3c3218e3e2ceb240494b184d59cecf3b5aab076f14b1e6aed3583bd7；请求契约：sha256:afc6c0c61d0e57fe4c1b1da13af57030c3a0fa1ea67a9ed94112c32a716db8d3。

## NB-02 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0110.file-fact.json](raw-0110.file-fact.json), [raw-0111.json](raw-0111.json) |

脚本 sha256：456b7ca3dffe3126b04c81e68c36291e27887d936e58a19410beb3f84b3954d2；请求契约：sha256:340790d0b8bec6817c0c15e1efca006044f1ce308da27377c895e4cc62d69aff。

## NB-03 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0120.file-fact.json](raw-0120.file-fact.json), [raw-0121.json](raw-0121.json) |

脚本 sha256：0384992b36b69137e1556c19df8a00fe4f0483216f557961ed90c5dbaf4e5c70；请求契约：sha256:54959201c8eba286683c6e7d0bf3c5c9b247c98fdbf039ecfdb123381ff3feaf。

## NB-04 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0130.file-fact.json](raw-0130.file-fact.json), [raw-0131.json](raw-0131.json) |

脚本 sha256：22a368c6a8ce7887588349142f98c793f4ca282844bda353b09a836e8f74c883；请求契约：sha256:673882c8a2560529cd3e77e687f97b465e7ff9d9861cb33bacd9eb926aa1bef0。

## NB-05 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0140.file-fact.json](raw-0140.file-fact.json), [raw-0141.json](raw-0141.json) |

脚本 sha256：afd9080127527469335c511040e9b24504d8222c52c7f3bb3ac9120357d91858；请求契约：sha256:000f55763fd7fe33f6d0fa808b8762284fc2cecbb7b17393acb32a2dc9d93c98。

## NB-06 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0150.file-fact.json](raw-0150.file-fact.json), [raw-0151.json](raw-0151.json) |

脚本 sha256：55f0786cf09e290bb356d9a82f1d3ba85db87f4b6bdb0237b7bdbfa60f67d375；请求契约：sha256:e0fe48d5edee3e7f3e69361a83ee1b260389eae5afb78087a70881402a229b6e。
