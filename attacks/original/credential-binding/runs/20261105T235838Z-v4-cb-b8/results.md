这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| CB-14 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0036.json](raw-0036.json), [raw-0037.json](raw-0037.json) |
| PC-CREDENTIAL | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0100.json](raw-0100.json), [raw-0163.json](raw-0163.json), [raw-0226.json](raw-0226.json), [raw-0289.json](raw-0289.json), [raw-0290.json](raw-0290.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0309.json](raw-0309.json), [raw-0310.json](raw-0310.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0332.json](raw-0332.json), [raw-0333.json](raw-0333.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0354.json](raw-0354.json), [raw-0355.json](raw-0355.json) |
| CB-14 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0389.json](raw-0389.json), [raw-0390.json](raw-0390.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## CB-14 / engine

预期机制：connection-account-isolation；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §2.13；实际观察机制：connection-account-isolation。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-reuse | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | connection-account-isolation | — | [raw-0036.json](raw-0036.json), [raw-0037.json](raw-0037.json) |

脚本 sha256：1d2b05352a7b354fa193aa09eddbbb4ff1e77a00a3f9e37fa5b98f5e110d3744；请求契约：sha256:cfb980aa48d75af67c7ec0ecfc54fef31a1b994115165cbe6f1c8268b94c6b3f。

## PC-CREDENTIAL / engine

预期机制：allowed；预期位置（规格/源码，不是动态定位）：credential-binding/tests.md §3；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0100.json](raw-0100.json), [raw-0290.json](raw-0290.json) |
| 1 | bearer-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0163.json](raw-0163.json), [raw-0290.json](raw-0290.json) |
| 1 | token-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0226.json](raw-0226.json), [raw-0290.json](raw-0290.json) |
| 1 | basic-valid | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0289.json](raw-0289.json), [raw-0290.json](raw-0290.json) |

脚本 sha256：ffb97511245b90663d7eba998a462f854c222a816dff4b1b2019e80bd095a3f7；请求契约：sha256:f64619315ffa9e5992d39a9d3088fbb9c096ab81a47562f6c7d9e1ba9d427da4。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0309.json](raw-0309.json), [raw-0310.json](raw-0310.json) |

脚本 sha256：ba5d834fcc879489cb8a013229de039a890c170e8beb71f5d3a804772b069233；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0332.json](raw-0332.json), [raw-0333.json](raw-0333.json) |

脚本 sha256：0be370793ca808072bf3206c2db998c57f01e956240c8d5ac055cca4f9499f73；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0354.json](raw-0354.json), [raw-0355.json](raw-0355.json) |

脚本 sha256：455e2fdd4233bad41f8aa2fd77e1ea5ea7ab14b036c32fbad510d019ba05c879；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## CB-14 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | api-key-reuse | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0389.json](raw-0389.json), [raw-0390.json](raw-0390.json) |

脚本 sha256：1d2b05352a7b354fa193aa09eddbbb4ff1e77a00a3f9e37fa5b98f5e110d3744；请求契约：sha256:cfb980aa48d75af67c7ec0ecfc54fef31a1b994115165cbe6f1c8268b94c6b3f。
