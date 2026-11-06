这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| CB-07 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0055.json](raw-0055.json), [raw-0110.json](raw-0110.json), [raw-0165.json](raw-0165.json), [raw-0220.json](raw-0220.json), [raw-0275.json](raw-0275.json), [raw-0330.json](raw-0330.json), [raw-0385.json](raw-0385.json), [raw-0440.json](raw-0440.json), [raw-0441.json](raw-0441.json) |
| PC-CREDENTIAL | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0504.json](raw-0504.json), [raw-0567.json](raw-0567.json), [raw-0630.json](raw-0630.json), [raw-0693.json](raw-0693.json), [raw-0694.json](raw-0694.json) |
| CB-08 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0745.json](raw-0745.json), [raw-0796.json](raw-0796.json), [raw-0797.json](raw-0797.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0816.json](raw-0816.json), [raw-0817.json](raw-0817.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0839.json](raw-0839.json), [raw-0840.json](raw-0840.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0861.json](raw-0861.json), [raw-0862.json](raw-0862.json) |
| CB-07 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0915.json](raw-0915.json), [raw-0967.json](raw-0967.json), [raw-1019.json](raw-1019.json), [raw-1071.json](raw-1071.json), [raw-1123.json](raw-1123.json), [raw-1175.json](raw-1175.json), [raw-1227.json](raw-1227.json), [raw-1279.json](raw-1279.json), [raw-1280.json](raw-1280.json) |
| CB-08 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-1328.json](raw-1328.json), [raw-1376.json](raw-1376.json), [raw-1377.json](raw-1377.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## CB-07 / engine

预期机制：registered-placement-only；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：registered-placement-only。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-body | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | registered-placement-only | — | [raw-0055.json](raw-0055.json), [raw-0441.json](raw-0441.json) |
| 1 | api-key-query | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | registered-placement-only | — | [raw-0110.json](raw-0110.json), [raw-0441.json](raw-0441.json) |
| 1 | api-key-other | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | registered-placement-only | — | [raw-0165.json](raw-0165.json), [raw-0441.json](raw-0441.json) |
| 1 | api-key-dual | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | registered-placement-only | — | [raw-0220.json](raw-0220.json), [raw-0441.json](raw-0441.json) |
| 1 | bearer-body | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | registered-placement-only | — | [raw-0275.json](raw-0275.json), [raw-0441.json](raw-0441.json) |
| 1 | bearer-query | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | registered-placement-only | — | [raw-0330.json](raw-0330.json), [raw-0441.json](raw-0441.json) |
| 1 | bearer-other | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | registered-placement-only | — | [raw-0385.json](raw-0385.json), [raw-0441.json](raw-0441.json) |
| 1 | bearer-dual | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | registered-placement-only | — | [raw-0440.json](raw-0440.json), [raw-0441.json](raw-0441.json) |

脚本 sha256：f856bac58dce6e5b4a68e1db5d9f8c46d1d70fcaec9dde902934e3169d9f62a6；请求契约：sha256:f38b3d19a0499e96a866d6e8ff11b4f8245fee90cb16bdd9084410c4978b326c。

## PC-CREDENTIAL / engine

预期机制：allowed；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0504.json](raw-0504.json), [raw-0694.json](raw-0694.json) |
| 1 | bearer-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0567.json](raw-0567.json), [raw-0694.json](raw-0694.json) |
| 1 | token-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0630.json](raw-0630.json), [raw-0694.json](raw-0694.json) |
| 1 | basic-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0693.json](raw-0693.json), [raw-0694.json](raw-0694.json) |

脚本 sha256：ffb97511245b90663d7eba998a462f854c222a816dff4b1b2019e80bd095a3f7；请求契约：sha256:f64619315ffa9e5992d39a9d3088fbb9c096ab81a47562f6c7d9e1ba9d427da4。

## CB-08 / engine

预期机制：row-account-selection；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：row-account-selection。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-sink | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0745.json](raw-0745.json), [raw-0797.json](raw-0797.json) |
| 1 | bearer-sink | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | row-account-selection | — | [raw-0796.json](raw-0796.json), [raw-0797.json](raw-0797.json) |

脚本 sha256：50fe5ad01e0a05b14ae5ee3281a38f4f626ff09cb142aca0653224483a87a749；请求契约：sha256:f9082879772618864c33e08c4134188b3fc47dd26ef77990249055e294a787c9。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0816.json](raw-0816.json), [raw-0817.json](raw-0817.json) |

脚本 sha256：ba5d834fcc879489cb8a013229de039a890c170e8beb71f5d3a804772b069233；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0839.json](raw-0839.json), [raw-0840.json](raw-0840.json) |

脚本 sha256：0be370793ca808072bf3206c2db998c57f01e956240c8d5ac055cca4f9499f73；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0861.json](raw-0861.json), [raw-0862.json](raw-0862.json) |

脚本 sha256：455e2fdd4233bad41f8aa2fd77e1ea5ea7ab14b036c32fbad510d019ba05c879；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## CB-07 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-body | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0915.json](raw-0915.json), [raw-1280.json](raw-1280.json) |
| 1 | api-key-query | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0967.json](raw-0967.json), [raw-1280.json](raw-1280.json) |
| 1 | api-key-other | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1019.json](raw-1019.json), [raw-1280.json](raw-1280.json) |
| 1 | api-key-dual | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1071.json](raw-1071.json), [raw-1280.json](raw-1280.json) |
| 1 | bearer-body | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1123.json](raw-1123.json), [raw-1280.json](raw-1280.json) |
| 1 | bearer-query | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1175.json](raw-1175.json), [raw-1280.json](raw-1280.json) |
| 1 | bearer-other | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1227.json](raw-1227.json), [raw-1280.json](raw-1280.json) |
| 1 | bearer-dual | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1279.json](raw-1279.json), [raw-1280.json](raw-1280.json) |

脚本 sha256：f856bac58dce6e5b4a68e1db5d9f8c46d1d70fcaec9dde902934e3169d9f62a6；请求契约：sha256:f38b3d19a0499e96a866d6e8ff11b4f8245fee90cb16bdd9084410c4978b326c。

## CB-08 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-sink | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1328.json](raw-1328.json), [raw-1377.json](raw-1377.json) |
| 1 | bearer-sink | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1376.json](raw-1376.json), [raw-1377.json](raw-1377.json) |

脚本 sha256：50fe5ad01e0a05b14ae5ee3281a38f4f626ff09cb142aca0653224483a87a749；请求契约：sha256:f9082879772618864c33e08c4134188b3fc47dd26ef77990249055e294a787c9。
