这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| NB-07 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0010.file-fact.json](raw-0010.file-fact.json), [raw-0011.json](raw-0011.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0018.json](raw-0018.json) |
| NB-08 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0027.file-fact.json](raw-0027.file-fact.json), [raw-0028.json](raw-0028.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0035.json](raw-0035.json) |
| NB-09 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0044.file-fact.json](raw-0044.file-fact.json), [raw-0045.json](raw-0045.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0047.attach.txt](raw-0047.attach.txt), [raw-0053.json](raw-0053.json) |
| NB-10 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0062.file-fact.json](raw-0062.file-fact.json), [raw-0063.json](raw-0063.json) |
| NB-11 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0072.file-fact.json](raw-0072.file-fact.json), [raw-0073.json](raw-0073.json) |
| NB-07 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0090.file-fact.json](raw-0090.file-fact.json), [raw-0091.json](raw-0091.json) |
| NB-08 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0100.file-fact.json](raw-0100.file-fact.json), [raw-0101.json](raw-0101.json) |
| NB-09 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0110.file-fact.json](raw-0110.file-fact.json), [raw-0111.json](raw-0111.json) |
| NB-10 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0120.file-fact.json](raw-0120.file-fact.json), [raw-0121.json](raw-0121.json) |
| NB-11 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0130.file-fact.json](raw-0130.file-fact.json), [raw-0131.json](raw-0131.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## NB-07 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0010.file-fact.json](raw-0010.file-fact.json), [raw-0011.json](raw-0011.json) |

脚本 sha256：cbc31c6afa4f1288afcfa00014e863b2d52dfbed6e813c2697e6f83b4be71b63；请求契约：sha256:f38b3eb32c0be4e344616b0f0e6e02a43bf324d4f93abce120f3d250cd658e08。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0018.json](raw-0018.json) |

脚本 sha256：224ff1a8f01e53bad0c90348a02bf0eb27a5bb5bdc7a0512c2d61f9d5e13b79f；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## NB-08 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0027.file-fact.json](raw-0027.file-fact.json), [raw-0028.json](raw-0028.json) |

脚本 sha256：bce36c1b5cde5d4d35098a07880b748bee0dd8aa4081d2fd85c925d018ec8113；请求契约：sha256:d2e9167cb7572392771b4386077912158dfaa439b546114b5c99a14a155bee01。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0035.json](raw-0035.json) |

脚本 sha256：a0ce34ee27a806a7f302bc1776791c95b3767d0c8a4694f3b02a6ea89a20e6f2；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## NB-09 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0044.file-fact.json](raw-0044.file-fact.json), [raw-0045.json](raw-0045.json) |

脚本 sha256：82785409dbb9f166402a5a8e41d2f9f8e652b0ee71a7683a87805fd3ccee0be9；请求契约：sha256:301ac2457301476a3b7ddc300d0c8dccc2a77ad04ed65551b04b23858322001f。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0047.attach.txt](raw-0047.attach.txt), [raw-0053.json](raw-0053.json) |

脚本 sha256：9b64571b5ba1131ef3a60706c732017975a4ed1d0a7829f62df5f8efc8c242f1；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## NB-10 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0062.file-fact.json](raw-0062.file-fact.json), [raw-0063.json](raw-0063.json) |

脚本 sha256：afc94f0c370202aff5430e7ccbc83683705cb087bfb193679bb635aad6f81e70；请求契约：sha256:306aabdacbe7e6ba74b4ecd8c7cc991a22addf9383d171aae23db8d9029ee81a。

## NB-11 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0072.file-fact.json](raw-0072.file-fact.json), [raw-0073.json](raw-0073.json) |

脚本 sha256：61d22be33d6e93870dec8e549fd868655bc609347713154424087faef97f08d6；请求契约：sha256:9d6042fc2fd4d0e8063bfc2815e0b762312687a06012ba07ee2be37dac05e461。

## NB-07 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0090.file-fact.json](raw-0090.file-fact.json), [raw-0091.json](raw-0091.json) |

脚本 sha256：cbc31c6afa4f1288afcfa00014e863b2d52dfbed6e813c2697e6f83b4be71b63；请求契约：sha256:f38b3eb32c0be4e344616b0f0e6e02a43bf324d4f93abce120f3d250cd658e08。

## NB-08 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0100.file-fact.json](raw-0100.file-fact.json), [raw-0101.json](raw-0101.json) |

脚本 sha256：bce36c1b5cde5d4d35098a07880b748bee0dd8aa4081d2fd85c925d018ec8113；请求契约：sha256:d2e9167cb7572392771b4386077912158dfaa439b546114b5c99a14a155bee01。

## NB-09 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0110.file-fact.json](raw-0110.file-fact.json), [raw-0111.json](raw-0111.json) |

脚本 sha256：82785409dbb9f166402a5a8e41d2f9f8e652b0ee71a7683a87805fd3ccee0be9；请求契约：sha256:301ac2457301476a3b7ddc300d0c8dccc2a77ad04ed65551b04b23858322001f。

## NB-10 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0120.file-fact.json](raw-0120.file-fact.json), [raw-0121.json](raw-0121.json) |

脚本 sha256：afc94f0c370202aff5430e7ccbc83683705cb087bfb193679bb635aad6f81e70；请求契约：sha256:306aabdacbe7e6ba74b4ecd8c7cc991a22addf9383d171aae23db8d9029ee81a。

## NB-11 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | file | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0130.file-fact.json](raw-0130.file-fact.json), [raw-0131.json](raw-0131.json) |

脚本 sha256：61d22be33d6e93870dec8e549fd868655bc609347713154424087faef97f08d6；请求契约：sha256:9d6042fc2fd4d0e8063bfc2815e0b762312687a06012ba07ee2be37dac05e461。
