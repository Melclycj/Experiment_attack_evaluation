这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| CB-01 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0055.json](raw-0055.json), [raw-0056.json](raw-0056.json) |
| PC-CREDENTIAL | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0119.json](raw-0119.json), [raw-0182.json](raw-0182.json), [raw-0245.json](raw-0245.json), [raw-0308.json](raw-0308.json), [raw-0309.json](raw-0309.json) |
| CB-02 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0364.json](raw-0364.json), [raw-0419.json](raw-0419.json), [raw-0420.json](raw-0420.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0439.json](raw-0439.json), [raw-0440.json](raw-0440.json) |
| CB-03 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0497.json](raw-0497.json), [raw-0553.json](raw-0553.json), [raw-0609.json](raw-0609.json), [raw-0610.json](raw-0610.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0631.json](raw-0631.json), [raw-0632.json](raw-0632.json) |
| CB-04 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0688.json](raw-0688.json), [raw-0689.json](raw-0689.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0709.json](raw-0709.json), [raw-0710.json](raw-0710.json) |
| CB-05 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0765.json](raw-0765.json), [raw-0766.json](raw-0766.json) |
| CB-12 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0821.json](raw-0821.json), [raw-0876.json](raw-0876.json), [raw-0877.json](raw-0877.json) |
| CB-01 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0929.json](raw-0929.json), [raw-0930.json](raw-0930.json) |
| CB-02 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0982.json](raw-0982.json), [raw-1034.json](raw-1034.json), [raw-1035.json](raw-1035.json) |
| CB-03 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-1088.json](raw-1088.json), [raw-1141.json](raw-1141.json), [raw-1194.json](raw-1194.json), [raw-1195.json](raw-1195.json) |
| CB-04 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-1247.json](raw-1247.json), [raw-1248.json](raw-1248.json) |
| CB-05 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-1299.json](raw-1299.json), [raw-1300.json](raw-1300.json) |
| CB-12 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-1352.json](raw-1352.json), [raw-1404.json](raw-1404.json), [raw-1405.json](raw-1405.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## CB-01 / engine

预期机制：truth-outside-agent；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：truth-outside-agent。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-mcp | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | truth-outside-agent | — | [raw-0055.json](raw-0055.json), [raw-0056.json](raw-0056.json) |

脚本 sha256：77b299c82de0e3f09d94fd8d59c1edbae1131a8813b4e0838c331b6012f21aa7；请求契约：sha256:d511e6593be50375eeeb3b429f7bdeac6423fa1c21752495442291c895651b60。

## PC-CREDENTIAL / engine

预期机制：allowed；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0119.json](raw-0119.json), [raw-0309.json](raw-0309.json) |
| 1 | bearer-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0182.json](raw-0182.json), [raw-0309.json](raw-0309.json) |
| 1 | token-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0245.json](raw-0245.json), [raw-0309.json](raw-0309.json) |
| 1 | basic-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0308.json](raw-0308.json), [raw-0309.json](raw-0309.json) |

脚本 sha256：ffb97511245b90663d7eba998a462f854c222a816dff4b1b2019e80bd095a3f7；请求契约：sha256:f64619315ffa9e5992d39a9d3088fbb9c096ab81a47562f6c7d9e1ba9d427da4。

## CB-02 / engine

预期机制：truth-outside-agent；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：truth-outside-agent。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-gateway | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | truth-outside-agent | — | [raw-0364.json](raw-0364.json), [raw-0420.json](raw-0420.json) |
| 1 | api-key-device | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | truth-outside-agent | — | [raw-0419.json](raw-0419.json), [raw-0420.json](raw-0420.json) |

脚本 sha256：93e5fefbe2352182ebf23d36b8f971f2bb30e19a1b228b6665f4322cb9600dfd；请求契约：sha256:9235cde92275ce0ebd9f4523e7be42405606bf93fb4410c49e71493a2a81961c。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0439.json](raw-0439.json), [raw-0440.json](raw-0440.json) |

脚本 sha256：ba5d834fcc879489cb8a013229de039a890c170e8beb71f5d3a804772b069233；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## CB-03 / engine

预期机制：truth-outside-agent；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：truth-outside-agent。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-github | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | truth-outside-agent | — | [raw-0497.json](raw-0497.json), [raw-0610.json](raw-0610.json) |
| 1 | api-key-npm | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | truth-outside-agent | — | [raw-0553.json](raw-0553.json), [raw-0610.json](raw-0610.json) |
| 1 | api-key-cloud | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | truth-outside-agent | — | [raw-0609.json](raw-0609.json), [raw-0610.json](raw-0610.json) |

脚本 sha256：f8d57b0013f99503a57649a867568d0fa75dcd3774a822af90db8a2238bb4e5f；请求契约：sha256:02ff1891f1ae3bf9189fc0d01f35fd6024b5f17d181ff83d61db0422995fb544。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0631.json](raw-0631.json), [raw-0632.json](raw-0632.json) |

脚本 sha256：0be370793ca808072bf3206c2db998c57f01e956240c8d5ac055cca4f9499f73；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## CB-04 / engine

预期机制：truth-outside-agent；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：truth-outside-agent。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-service | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | truth-outside-agent | — | [raw-0688.json](raw-0688.json), [raw-0689.json](raw-0689.json) |

脚本 sha256：df18c24ef7d14496bb78b78287c8038d2539f1058cff659105bebde5a97f03c2；请求契约：sha256:5f191f17784a52dc954a7be0a7889bb741ae89a13229dc9a1fca5b4d943cac50。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0709.json](raw-0709.json), [raw-0710.json](raw-0710.json) |

脚本 sha256：455e2fdd4233bad41f8aa2fd77e1ea5ea7ab14b036c32fbad510d019ba05c879；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## CB-05 / engine

预期机制：truth-outside-agent；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：truth-outside-agent。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-child | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | truth-outside-agent | — | [raw-0765.json](raw-0765.json), [raw-0766.json](raw-0766.json) |

脚本 sha256：0f0e7bcd8db14777049a20d6ba9f2d2b9cf8b70f34d1bda80271113edd2e8088；请求契约：sha256:ad78e78fa99e2b2acdbec47b3e6dc6226660867e94da0d3c8951ef5ff5fa0209。

## CB-12 / engine

预期机制：canonical-host-rejection；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：canonical-host-rejection。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-host | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | canonical-host-rejection | — | [raw-0821.json](raw-0821.json), [raw-0877.json](raw-0877.json) |
| 1 | bearer-host | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | canonical-host-rejection | — | [raw-0876.json](raw-0876.json), [raw-0877.json](raw-0877.json) |

脚本 sha256：2efa5c162fb5cc2c9aaf0c3ade9e1025480895b981041fa2ac7b513ef89ebc7d；请求契约：sha256:388a3b9df95f4a4bdc1459527fea4ddf62d85461ab7ed8cc63cffa77ea319c83。

## CB-01 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-mcp | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0929.json](raw-0929.json), [raw-0930.json](raw-0930.json) |

脚本 sha256：77b299c82de0e3f09d94fd8d59c1edbae1131a8813b4e0838c331b6012f21aa7；请求契约：sha256:d511e6593be50375eeeb3b429f7bdeac6423fa1c21752495442291c895651b60。

## CB-02 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-gateway | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0982.json](raw-0982.json), [raw-1035.json](raw-1035.json) |
| 1 | api-key-device | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1034.json](raw-1034.json), [raw-1035.json](raw-1035.json) |

脚本 sha256：93e5fefbe2352182ebf23d36b8f971f2bb30e19a1b228b6665f4322cb9600dfd；请求契约：sha256:9235cde92275ce0ebd9f4523e7be42405606bf93fb4410c49e71493a2a81961c。

## CB-03 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-github | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1088.json](raw-1088.json), [raw-1195.json](raw-1195.json) |
| 1 | api-key-npm | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1141.json](raw-1141.json), [raw-1195.json](raw-1195.json) |
| 1 | api-key-cloud | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1194.json](raw-1194.json), [raw-1195.json](raw-1195.json) |

脚本 sha256：f8d57b0013f99503a57649a867568d0fa75dcd3774a822af90db8a2238bb4e5f；请求契约：sha256:02ff1891f1ae3bf9189fc0d01f35fd6024b5f17d181ff83d61db0422995fb544。

## CB-04 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-service | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1247.json](raw-1247.json), [raw-1248.json](raw-1248.json) |

脚本 sha256：df18c24ef7d14496bb78b78287c8038d2539f1058cff659105bebde5a97f03c2；请求契约：sha256:5f191f17784a52dc954a7be0a7889bb741ae89a13229dc9a1fca5b4d943cac50。

## CB-05 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-child | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1299.json](raw-1299.json), [raw-1300.json](raw-1300.json) |

脚本 sha256：0f0e7bcd8db14777049a20d6ba9f2d2b9cf8b70f34d1bda80271113edd2e8088；请求契约：sha256:ad78e78fa99e2b2acdbec47b3e6dc6226660867e94da0d3c8951ef5ff5fa0209。

## CB-12 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-host | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1352.json](raw-1352.json), [raw-1405.json](raw-1405.json) |
| 1 | bearer-host | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-1404.json](raw-1404.json), [raw-1405.json](raw-1405.json) |

脚本 sha256：2efa5c162fb5cc2c9aaf0c3ade9e1025480895b981041fa2ac7b513ef89ebc7d；请求契约：sha256:388a3b9df95f4a4bdc1459527fea4ddf62d85461ab7ed8cc63cffa77ea319c83。
