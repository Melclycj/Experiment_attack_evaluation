这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| CB-09 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0078.json](raw-0078.json), [raw-0156.json](raw-0156.json), [raw-0234.json](raw-0234.json), [raw-0312.json](raw-0312.json), [raw-0390.json](raw-0390.json), [raw-0468.json](raw-0468.json), [raw-0546.json](raw-0546.json), [raw-0624.json](raw-0624.json), [raw-0625.json](raw-0625.json) |
| PC-CREDENTIAL | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0688.json](raw-0688.json), [raw-0751.json](raw-0751.json), [raw-0814.json](raw-0814.json), [raw-0877.json](raw-0877.json), [raw-0878.json](raw-0878.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0897.json](raw-0897.json), [raw-0898.json](raw-0898.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0920.json](raw-0920.json), [raw-0921.json](raw-0921.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0942.json](raw-0942.json), [raw-0943.json](raw-0943.json) |
| CB-09 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-1019.json](raw-1019.json), [raw-1094.json](raw-1094.json), [raw-1169.json](raw-1169.json), [raw-1244.json](raw-1244.json), [raw-1319.json](raw-1319.json), [raw-1394.json](raw-1394.json), [raw-1469.json](raw-1469.json), [raw-1544.json](raw-1544.json), [raw-1545.json](raw-1545.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## CB-09 / engine

预期机制：row-account-selection；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：row-account-selection。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-unique | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0078.json](raw-0078.json), [raw-0625.json](raw-0625.json) |
| 1 | api-key-selected | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0156.json](raw-0156.json), [raw-0625.json](raw-0625.json) |
| 1 | bearer-unique | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0234.json](raw-0234.json), [raw-0625.json](raw-0625.json) |
| 1 | bearer-selected | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0312.json](raw-0312.json), [raw-0625.json](raw-0625.json) |
| 1 | token-unique | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0390.json](raw-0390.json), [raw-0625.json](raw-0625.json) |
| 1 | token-selected | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0468.json](raw-0468.json), [raw-0625.json](raw-0625.json) |
| 1 | basic-unique | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0546.json](raw-0546.json), [raw-0625.json](raw-0625.json) |
| 1 | basic-selected | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0624.json](raw-0624.json), [raw-0625.json](raw-0625.json) |

脚本 sha256：3d77cc5bc9909ec366fb297f0a528d610f8ff3d23409c669b3fd032e0fc82375；请求契约：sha256:e84b45f6a6126119d65875ecaac0a8bbf9990db6466d852bee7ad30893878d7e。

## PC-CREDENTIAL / engine

预期机制：allowed；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0688.json](raw-0688.json), [raw-0878.json](raw-0878.json) |
| 1 | bearer-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0751.json](raw-0751.json), [raw-0878.json](raw-0878.json) |
| 1 | token-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0814.json](raw-0814.json), [raw-0878.json](raw-0878.json) |
| 1 | basic-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0877.json](raw-0877.json), [raw-0878.json](raw-0878.json) |

脚本 sha256：ffb97511245b90663d7eba998a462f854c222a816dff4b1b2019e80bd095a3f7；请求契约：sha256:f64619315ffa9e5992d39a9d3088fbb9c096ab81a47562f6c7d9e1ba9d427da4。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0897.json](raw-0897.json), [raw-0898.json](raw-0898.json) |

脚本 sha256：ba5d834fcc879489cb8a013229de039a890c170e8beb71f5d3a804772b069233；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0920.json](raw-0920.json), [raw-0921.json](raw-0921.json) |

脚本 sha256：0be370793ca808072bf3206c2db998c57f01e956240c8d5ac055cca4f9499f73；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0942.json](raw-0942.json), [raw-0943.json](raw-0943.json) |

脚本 sha256：455e2fdd4233bad41f8aa2fd77e1ea5ea7ab14b036c32fbad510d019ba05c879；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## CB-09 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-unique | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1019.json](raw-1019.json), [raw-1545.json](raw-1545.json) |
| 1 | api-key-selected | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1094.json](raw-1094.json), [raw-1545.json](raw-1545.json) |
| 1 | bearer-unique | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1169.json](raw-1169.json), [raw-1545.json](raw-1545.json) |
| 1 | bearer-selected | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1244.json](raw-1244.json), [raw-1545.json](raw-1545.json) |
| 1 | token-unique | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1319.json](raw-1319.json), [raw-1545.json](raw-1545.json) |
| 1 | token-selected | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1394.json](raw-1394.json), [raw-1545.json](raw-1545.json) |
| 1 | basic-unique | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1469.json](raw-1469.json), [raw-1545.json](raw-1545.json) |
| 1 | basic-selected | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1544.json](raw-1544.json), [raw-1545.json](raw-1545.json) |

脚本 sha256：3d77cc5bc9909ec366fb297f0a528d610f8ff3d23409c669b3fd032e0fc82375；请求契约：sha256:e84b45f6a6126119d65875ecaac0a8bbf9990db6466d852bee7ad30893878d7e。
