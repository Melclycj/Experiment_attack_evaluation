这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| NB-20 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0013.truth-after.bin](raw-0013.truth-after.bin), [raw-0014.metadata-after.bin](raw-0014.metadata-after.bin), [raw-0016.json](raw-0016.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0023.json](raw-0023.json) |
| NB-21 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0036.mirror-after.bin](raw-0036.mirror-after.bin), [raw-0038.json](raw-0038.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0045.json](raw-0045.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0047.attach.txt](raw-0047.attach.txt), [raw-0053.json](raw-0053.json) |
| NB-20 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0073.truth-after.bin](raw-0073.truth-after.bin), [raw-0074.metadata-after.bin](raw-0074.metadata-after.bin), [raw-0076.json](raw-0076.json) |
| NB-21 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0092.mirror-after.bin](raw-0092.mirror-after.bin), [raw-0094.json](raw-0094.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## NB-20 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:w2_child_launch(pivot_root)；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | truth | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0013.truth-after.bin](raw-0013.truth-after.bin), [raw-0016.json](raw-0016.json) |
| 1 | metadata | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0014.metadata-after.bin](raw-0014.metadata-after.bin), [raw-0016.json](raw-0016.json) |

脚本 sha256：86169ff2b82eceebc33d18c30a0524da4bf9ea76c6e3e5951896ababb28f2bac；请求契约：sha256:6463a5a9202bb8c192bbe056bbf0ab23c083777272590ac3d08b7514640a3e22。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0023.json](raw-0023.json) |

脚本 sha256：224ff1a8f01e53bad0c90348a02bf0eb27a5bb5bdc7a0512c2d61f9d5e13b79f；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## NB-21 / engine

预期机制：file-view；预期位置（规格/源码，不是动态定位）：native/sandbox/child.c:w2_child_launch(pivot_root)；实际观察机制：file-view。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | mirror | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0036.mirror-after.bin](raw-0036.mirror-after.bin), [raw-0038.json](raw-0038.json) |
| 1 | admin | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0038.json](raw-0038.json) |

脚本 sha256：8600299c0f159498e3e55c85a1f3c4408c312d341c0700156dd5e40d1f946be2；请求契约：sha256:1ecae42012f8619420806f671112039d07a786d298976e84ebe575dfc36cf35c。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0045.json](raw-0045.json) |

脚本 sha256：a0ce34ee27a806a7f302bc1776791c95b3767d0c8a4694f3b02a6ea89a20e6f2；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0047.attach.txt](raw-0047.attach.txt), [raw-0053.json](raw-0053.json) |

脚本 sha256：9b64571b5ba1131ef3a60706c732017975a4ed1d0a7829f62df5f8efc8c242f1；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## NB-20 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | truth | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0073.truth-after.bin](raw-0073.truth-after.bin), [raw-0076.json](raw-0076.json) |
| 1 | metadata | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0074.metadata-after.bin](raw-0074.metadata-after.bin), [raw-0076.json](raw-0076.json) |

脚本 sha256：86169ff2b82eceebc33d18c30a0524da4bf9ea76c6e3e5951896ababb28f2bac；请求契约：sha256:6463a5a9202bb8c192bbe056bbf0ab23c083777272590ac3d08b7514640a3e22。

## NB-21 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | mirror | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0092.mirror-after.bin](raw-0092.mirror-after.bin), [raw-0094.json](raw-0094.json) |
| 1 | admin | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0094.json](raw-0094.json) |

脚本 sha256：8600299c0f159498e3e55c85a1f3c4408c312d341c0700156dd5e40d1f946be2；请求契约：sha256:1ecae42012f8619420806f671112039d07a786d298976e84ebe575dfc36cf35c。
