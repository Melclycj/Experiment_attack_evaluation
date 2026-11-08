这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| CB-10 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0055.json](raw-0055.json), [raw-0110.json](raw-0110.json), [raw-0165.json](raw-0165.json), [raw-0220.json](raw-0220.json), [raw-0275.json](raw-0275.json), [raw-0330.json](raw-0330.json), [raw-0331.json](raw-0331.json) |
| PC-CREDENTIAL | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0394.json](raw-0394.json), [raw-0457.json](raw-0457.json), [raw-0520.json](raw-0520.json), [raw-0583.json](raw-0583.json), [raw-0584.json](raw-0584.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0603.json](raw-0603.json), [raw-0604.json](raw-0604.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0626.json](raw-0626.json), [raw-0627.json](raw-0627.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0648.json](raw-0648.json), [raw-0649.json](raw-0649.json) |
| CB-10 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0702.json](raw-0702.json), [raw-0754.json](raw-0754.json), [raw-0806.json](raw-0806.json), [raw-0858.json](raw-0858.json), [raw-0910.json](raw-0910.json), [raw-0962.json](raw-0962.json), [raw-0963.json](raw-0963.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## CB-10 / engine

预期机制：no-redirect-follow；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：no-redirect-follow。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | token-302 | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | no-redirect-follow | — | [raw-0055.json](raw-0055.json), [raw-0331.json](raw-0331.json) |
| 1 | token-307 | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | no-redirect-follow | — | [raw-0110.json](raw-0110.json), [raw-0331.json](raw-0331.json) |
| 1 | token-308 | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | no-redirect-follow | — | [raw-0165.json](raw-0165.json), [raw-0331.json](raw-0331.json) |
| 1 | basic-302 | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | no-redirect-follow | — | [raw-0220.json](raw-0220.json), [raw-0331.json](raw-0331.json) |
| 1 | basic-307 | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | no-redirect-follow | — | [raw-0275.json](raw-0275.json), [raw-0331.json](raw-0331.json) |
| 1 | basic-308 | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | no-redirect-follow | — | [raw-0330.json](raw-0330.json), [raw-0331.json](raw-0331.json) |

脚本 sha256：3b3edf4933bb9ace139ef4685c23720204562f04e02aff77f2381cdbdb0e4be2；请求契约：sha256:90bf8e68af3f82f9258991eb873e4947b50c09f2892c43fb43a0f50711121548。

## PC-CREDENTIAL / engine

预期机制：allowed；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0394.json](raw-0394.json), [raw-0584.json](raw-0584.json) |
| 1 | bearer-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0457.json](raw-0457.json), [raw-0584.json](raw-0584.json) |
| 1 | token-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0520.json](raw-0520.json), [raw-0584.json](raw-0584.json) |
| 1 | basic-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0583.json](raw-0583.json), [raw-0584.json](raw-0584.json) |

脚本 sha256：ffb97511245b90663d7eba998a462f854c222a816dff4b1b2019e80bd095a3f7；请求契约：sha256:f64619315ffa9e5992d39a9d3088fbb9c096ab81a47562f6c7d9e1ba9d427da4。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0603.json](raw-0603.json), [raw-0604.json](raw-0604.json) |

脚本 sha256：ba5d834fcc879489cb8a013229de039a890c170e8beb71f5d3a804772b069233；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0626.json](raw-0626.json), [raw-0627.json](raw-0627.json) |

脚本 sha256：0be370793ca808072bf3206c2db998c57f01e956240c8d5ac055cca4f9499f73；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0648.json](raw-0648.json), [raw-0649.json](raw-0649.json) |

脚本 sha256：455e2fdd4233bad41f8aa2fd77e1ea5ea7ab14b036c32fbad510d019ba05c879；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## CB-10 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | token-302 | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0702.json](raw-0702.json), [raw-0963.json](raw-0963.json) |
| 1 | token-307 | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0754.json](raw-0754.json), [raw-0963.json](raw-0963.json) |
| 1 | token-308 | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0806.json](raw-0806.json), [raw-0963.json](raw-0963.json) |
| 1 | basic-302 | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0858.json](raw-0858.json), [raw-0963.json](raw-0963.json) |
| 1 | basic-307 | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0910.json](raw-0910.json), [raw-0963.json](raw-0963.json) |
| 1 | basic-308 | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0962.json](raw-0962.json), [raw-0963.json](raw-0963.json) |

脚本 sha256：3b3edf4933bb9ace139ef4685c23720204562f04e02aff77f2381cdbdb0e4be2；请求契约：sha256:90bf8e68af3f82f9258991eb873e4947b50c09f2892c43fb43a0f50711121548。
