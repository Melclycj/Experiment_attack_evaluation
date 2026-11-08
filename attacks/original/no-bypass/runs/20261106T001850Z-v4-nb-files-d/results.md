这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| NB-15 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0010.file-fact.json](raw-0010.file-fact.json), [raw-0020.file-fact.json](raw-0020.file-fact.json), [raw-0023.json](raw-0023.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0029.json](raw-0029.json) |
| NB-28 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0048.file-fact.json](raw-0048.file-fact.json), [raw-0049.file-fact.json](raw-0049.file-fact.json), [raw-0050.file-fact.json](raw-0050.file-fact.json), [raw-0051.file-fact.json](raw-0051.file-fact.json), [raw-0052.file-fact.json](raw-0052.file-fact.json), [raw-0053.file-fact.json](raw-0053.file-fact.json), [raw-0054.json](raw-0054.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0061.json](raw-0061.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0063.attach.txt](raw-0063.attach.txt), [raw-0069.json](raw-0069.json) |
| NB-15 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0086.file-fact.json](raw-0086.file-fact.json), [raw-0096.file-fact.json](raw-0096.file-fact.json), [raw-0099.json](raw-0099.json) |
| NB-28 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0123.file-fact.json](raw-0123.file-fact.json), [raw-0124.file-fact.json](raw-0124.file-fact.json), [raw-0125.file-fact.json](raw-0125.file-fact.json), [raw-0126.file-fact.json](raw-0126.file-fact.json), [raw-0127.file-fact.json](raw-0127.file-fact.json), [raw-0128.file-fact.json](raw-0128.file-fact.json), [raw-0129.json](raw-0129.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## NB-15 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | source | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0010.file-fact.json](raw-0010.file-fact.json), [raw-0023.json](raw-0023.json) |
| 1 | mount | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0020.file-fact.json](raw-0020.file-fact.json), [raw-0023.json](raw-0023.json) |

脚本 sha256：0697427fdd8a7a8e11a0d06d942f7966f0746c13f65467b711e4546632a4b84a；请求契约：sha256:189efc5fd7f670aa36479032cb4d6ca9e3e7dc7408692f8762fb7f10d52c611c。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0029.json](raw-0029.json) |

脚本 sha256：224ff1a8f01e53bad0c90348a02bf0eb27a5bb5bdc7a0512c2d61f9d5e13b79f；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## NB-28 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:pivot_root；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | zshrc | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0048.file-fact.json](raw-0048.file-fact.json), [raw-0054.json](raw-0054.json) |
| 1 | ssh | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0049.file-fact.json](raw-0049.file-fact.json), [raw-0054.json](raw-0054.json) |
| 1 | aws | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0050.file-fact.json](raw-0050.file-fact.json), [raw-0054.json](raw-0054.json) |
| 1 | gh | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0051.file-fact.json](raw-0051.file-fact.json), [raw-0054.json](raw-0054.json) |
| 1 | npm | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0052.file-fact.json](raw-0052.file-fact.json), [raw-0054.json](raw-0054.json) |
| 1 | netrc | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0053.file-fact.json](raw-0053.file-fact.json), [raw-0054.json](raw-0054.json) |

脚本 sha256：a213a7ad30d75a073a15b4e308b16ea30115d2c08cb6f3758d83af1e364b6ba8；请求契约：sha256:80c1fc1074a3b0d17981788654c6c4e1559b0dd952af684301ec68fdf9a958f2。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0061.json](raw-0061.json) |

脚本 sha256：a0ce34ee27a806a7f302bc1776791c95b3767d0c8a4694f3b02a6ea89a20e6f2；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0063.attach.txt](raw-0063.attach.txt), [raw-0069.json](raw-0069.json) |

脚本 sha256：9b64571b5ba1131ef3a60706c732017975a4ed1d0a7829f62df5f8efc8c242f1；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## NB-15 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | source | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0086.file-fact.json](raw-0086.file-fact.json), [raw-0099.json](raw-0099.json) |
| 1 | mount | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0096.file-fact.json](raw-0096.file-fact.json), [raw-0099.json](raw-0099.json) |

脚本 sha256：0697427fdd8a7a8e11a0d06d942f7966f0746c13f65467b711e4546632a4b84a；请求契约：sha256:189efc5fd7f670aa36479032cb4d6ca9e3e7dc7408692f8762fb7f10d52c611c。

## NB-28 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | zshrc | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0123.file-fact.json](raw-0123.file-fact.json), [raw-0129.json](raw-0129.json) |
| 1 | ssh | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0124.file-fact.json](raw-0124.file-fact.json), [raw-0129.json](raw-0129.json) |
| 1 | aws | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0125.file-fact.json](raw-0125.file-fact.json), [raw-0129.json](raw-0129.json) |
| 1 | gh | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0126.file-fact.json](raw-0126.file-fact.json), [raw-0129.json](raw-0129.json) |
| 1 | npm | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0127.file-fact.json](raw-0127.file-fact.json), [raw-0129.json](raw-0129.json) |
| 1 | netrc | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0128.file-fact.json](raw-0128.file-fact.json), [raw-0129.json](raw-0129.json) |

脚本 sha256：a213a7ad30d75a073a15b4e308b16ea30115d2c08cb6f3758d83af1e364b6ba8；请求契约：sha256:80c1fc1074a3b0d17981788654c6c4e1559b0dd952af684301ec68fdf9a958f2。
