这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

# 本次结果

**批次状态：完整结束；正式身份已核对（不等于批次通过）。**

COMPLETE.json 只表示归档完整；逐项观测不等于整批通过。

| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |
|---|---|---|---|---|---|---|---|
| NB-16 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0013.connection-window.json](raw-0013.connection-window.json), [raw-0014.json](raw-0014.json) |
| PC-FILE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0023.json](raw-0023.json) |
| NB-17 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0039.connection-window.json](raw-0039.connection-window.json), [raw-0042.connection-window.json](raw-0042.connection-window.json), [raw-0043.json](raw-0043.json) |
| PC-PROXY | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0054.json](raw-0054.json) |
| NB-18 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0070.connection-window.json](raw-0070.connection-window.json), [raw-0073.connection-window.json](raw-0073.connection-window.json), [raw-0074.json](raw-0074.json) |
| PC-DIALOGUE | engine | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0080.attach.txt](raw-0080.attach.txt), [raw-0086.json](raw-0086.json) |
| NB-19 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 预期机制未观察到 | [raw-0102.connection-window.json](raw-0102.connection-window.json), [raw-0105.connection-window.json](raw-0105.connection-window.json), [raw-0106.json](raw-0106.json) |
| NB-25 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 符合记录的预期 | [raw-0126.connection-window.json](raw-0126.connection-window.json), [raw-0128.connection-window.json](raw-0128.connection-window.json), [raw-0129.json](raw-0129.json) |
| NB-27 | engine | 预期机制挡住 | 预期机制挡住 | 0/1 | 0.95 | 预期机制未观察到 | [raw-0151.connection-window.json](raw-0151.connection-window.json), [raw-0154.connection-window.json](raw-0154.connection-window.json), [raw-0157.connection-window.json](raw-0157.connection-window.json), [raw-0158.json](raw-0158.json) |
| NB-16 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0184.connection-window.json](raw-0184.connection-window.json), [raw-0185.json](raw-0185.json) |
| NB-17 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0203.connection-window.json](raw-0203.connection-window.json), [raw-0206.connection-window.json](raw-0206.connection-window.json), [raw-0207.json](raw-0207.json) |
| NB-18 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0227.connection-window.json](raw-0227.connection-window.json), [raw-0230.connection-window.json](raw-0230.connection-window.json), [raw-0231.json](raw-0231.json) |
| NB-19 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0251.connection-window.json](raw-0251.connection-window.json), [raw-0254.connection-window.json](raw-0254.connection-window.json), [raw-0255.json](raw-0255.json) |
| NB-25 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0275.connection-window.json](raw-0275.connection-window.json), [raw-0278.connection-window.json](raw-0278.connection-window.json), [raw-0279.json](raw-0279.json) |
| NB-27 | undefended | 成功 | 成功 | 1/1 | — | 符合记录的预期 | [raw-0301.connection-window.json](raw-0301.connection-window.json), [raw-0304.connection-window.json](raw-0304.connection-window.json), [raw-0307.connection-window.json](raw-0307.connection-window.json), [raw-0308.json](raw-0308.json) |

无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。
上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。
试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。

## NB-16 / engine

预期机制：net-namespace；预期位置（规格/源码，不是动态定位）：native/sandbox/spawner.c:clone_ready(CLONE_NEWNET)；实际观察机制：net-namespace。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | relay | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0013.connection-window.json](raw-0013.connection-window.json), [raw-0014.json](raw-0014.json) |

脚本 sha256：7c192b117cf65823b1f3ab080f5803123fd0767a6142ddafa3bb7835faca78b2；请求契约：sha256:a3e84e895e52d5a5d7b7ab4d18ca13b45dab2df083d2dd3a048bc5bb27057d0a。

## PC-FILE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | workspace | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0023.json](raw-0023.json) |

脚本 sha256：224ff1a8f01e53bad0c90348a02bf0eb27a5bb5bdc7a0512c2d61f9d5e13b79f；请求契约：sha256:f8d01a56e05988125a38ad92f484ebeb05242d03c15143a60783aa65ae6b39bb。

## NB-17 / engine

预期机制：net-namespace；预期位置（规格/源码，不是动态定位）：native/sandbox/spawner.c:clone_ready(CLONE_NEWNET)；实际观察机制：net-namespace。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | global | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0039.connection-window.json](raw-0039.connection-window.json), [raw-0043.json](raw-0043.json) |
| 1 | loopback | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0042.connection-window.json](raw-0042.connection-window.json), [raw-0043.json](raw-0043.json) |

脚本 sha256：aa70b75314f4ab0353535bcd7d610d5a3ab83f38d09f8f583959da1f2a9acfa6；请求契约：sha256:01ba850ff973ed72cef9d7b4b255d042811d0227a173b19c47c6d245c9571167。

## PC-PROXY / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | upstream | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0054.json](raw-0054.json) |

脚本 sha256：a0ce34ee27a806a7f302bc1776791c95b3767d0c8a4694f3b02a6ea89a20e6f2；请求契约：sha256:5580e07bb2b374c5ac102fbe0917269185a3821214304dd89b99b9ee3bd1255f。

## NB-18 / engine

预期机制：net-namespace；预期位置（规格/源码，不是动态定位）：native/sandbox/spawner.c:clone_ready(CLONE_NEWNET)；实际观察机制：net-namespace。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | global | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0070.connection-window.json](raw-0070.connection-window.json), [raw-0074.json](raw-0074.json) |
| 1 | loopback | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0073.connection-window.json](raw-0073.connection-window.json), [raw-0074.json](raw-0074.json) |

脚本 sha256：6ad5c3e97bca80fb2b629d35564307caeb9841f95ed926c3677d9233f48ef50e；请求契约：sha256:6644bdcc7b0d60c49bd878114d8e611a39001496677d871272eec612589a82a9。

## PC-DIALOGUE / engine

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：allowed。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | terminal | 成功 | 是 | 是 | 是 | 是 | 不适用 | allowed | — | [raw-0080.attach.txt](raw-0080.attach.txt), [raw-0086.json](raw-0086.json) |

脚本 sha256：9b64571b5ba1131ef3a60706c732017975a4ed1d0a7829f62df5f8efc8c242f1；请求契约：sha256:8460201787e1e30482d0b77366920537a8304dd3cef27fbbbd8f57fe4852cd74。

## NB-19 / engine

预期机制：file-view + net-namespace；预期位置（规格/源码，不是动态定位）：native/sandbox/spawner.c:clone_ready(CLONE_NEWNET); native/sandbox/child.c:w2_child_launch(pivot_root)；实际观察机制：file-view, net-namespace。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | daemon-path | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0102.connection-window.json](raw-0102.connection-window.json), [raw-0106.json](raw-0106.json) |
| 1 | daemon-abstract | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0105.connection-window.json](raw-0105.connection-window.json), [raw-0106.json](raw-0106.json) |

脚本 sha256：38c0720d6f7a98c429eb5699d1fa1b3466c947f3fe16363dae5314fe5f4de23a；请求契约：sha256:a31960fdba2263ae5543dece9190e6e808408f9b81de30ea6fd729260e4b6109。

## NB-25 / engine

预期机制：net-namespace；预期位置（规格/源码，不是动态定位）：native/sandbox/spawner.c:clone_ready(CLONE_NEWNET)；实际观察机制：net-namespace。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | host | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0126.connection-window.json](raw-0126.connection-window.json), [raw-0129.json](raw-0129.json) |
| 1 | victim-listener | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0128.connection-window.json](raw-0128.connection-window.json), [raw-0129.json](raw-0129.json) |

脚本 sha256：842c0c61be2e7369d83d2cb50c250063328568fc785ea8aaa1363126da8c0229；请求契约：sha256:b31d8139b728e8c56f97de2bc430f43e95015ba9541d7ed49e01e92a403b649a。

## NB-27 / engine

预期机制：file-view + net-namespace；预期位置（规格/源码，不是动态定位）：native/sandbox/spawner.c:clone_ready(CLONE_NEWNET); native/sandbox/child.c:w2_child_launch(pivot_root)；实际观察机制：file-view, net-namespace。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | bus | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0151.connection-window.json](raw-0151.connection-window.json), [raw-0158.json](raw-0158.json) |
| 1 | systemd | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | file-view | — | [raw-0154.connection-window.json](raw-0154.connection-window.json), [raw-0158.json](raw-0158.json) |
| 1 | abstract | 预期机制挡住 | 是 | 是 | 是 | 否 | 是 | net-namespace | — | [raw-0157.connection-window.json](raw-0157.connection-window.json), [raw-0158.json](raw-0158.json) |

脚本 sha256：e0b6067f5f3e66f114f486bf8025c6d4ea4f12cedfef3ba0136c32fc1d97d8b1；请求契约：sha256:13e0da1719ae2c317317317e7820d99f64080d0ac0e1c574484228c8b09912bd。

## NB-16 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | relay | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0184.connection-window.json](raw-0184.connection-window.json), [raw-0185.json](raw-0185.json) |

脚本 sha256：7c192b117cf65823b1f3ab080f5803123fd0767a6142ddafa3bb7835faca78b2；请求契约：sha256:a3e84e895e52d5a5d7b7ab4d18ca13b45dab2df083d2dd3a048bc5bb27057d0a。

## NB-17 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | global | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0203.connection-window.json](raw-0203.connection-window.json), [raw-0207.json](raw-0207.json) |
| 1 | loopback | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0206.connection-window.json](raw-0206.connection-window.json), [raw-0207.json](raw-0207.json) |

脚本 sha256：aa70b75314f4ab0353535bcd7d610d5a3ab83f38d09f8f583959da1f2a9acfa6；请求契约：sha256:01ba850ff973ed72cef9d7b4b255d042811d0227a173b19c47c6d245c9571167。

## NB-18 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | global | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0227.connection-window.json](raw-0227.connection-window.json), [raw-0231.json](raw-0231.json) |
| 1 | loopback | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0230.connection-window.json](raw-0230.connection-window.json), [raw-0231.json](raw-0231.json) |

脚本 sha256：6ad5c3e97bca80fb2b629d35564307caeb9841f95ed926c3677d9233f48ef50e；请求契约：sha256:6644bdcc7b0d60c49bd878114d8e611a39001496677d871272eec612589a82a9。

## NB-19 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | daemon-path | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0251.connection-window.json](raw-0251.connection-window.json), [raw-0255.json](raw-0255.json) |
| 1 | daemon-abstract | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0254.connection-window.json](raw-0254.connection-window.json), [raw-0255.json](raw-0255.json) |

脚本 sha256：38c0720d6f7a98c429eb5699d1fa1b3466c947f3fe16363dae5314fe5f4de23a；请求契约：sha256:a31960fdba2263ae5543dece9190e6e808408f9b81de30ea6fd729260e4b6109。

## NB-25 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | host | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0275.connection-window.json](raw-0275.connection-window.json), [raw-0279.json](raw-0279.json) |
| 1 | victim-listener | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0278.connection-window.json](raw-0278.connection-window.json), [raw-0279.json](raw-0279.json) |

脚本 sha256：842c0c61be2e7369d83d2cb50c250063328568fc785ea8aaa1363126da8c0229；请求契约：sha256:b31d8139b728e8c56f97de2bc430f43e95015ba9541d7ed49e01e92a403b649a。

## NB-27 / undefended

预期机制：不要求防护机制；预期位置（规格/源码，不是动态定位）：不适用；实际观察机制：未观察到防护机制。

| 重复 | 目标 | 结果 | 对照通过 | 身份核对 | 观察完整 | 外部效果 | 配对前提 | 机制 | 问题 | 事实证据 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | bus | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0301.connection-window.json](raw-0301.connection-window.json), [raw-0308.json](raw-0308.json) |
| 1 | systemd | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0304.connection-window.json](raw-0304.connection-window.json), [raw-0308.json](raw-0308.json) |
| 1 | abstract | 成功 | 是 | 是 | 是 | 是 | 是 | — | — | [raw-0307.connection-window.json](raw-0307.connection-window.json), [raw-0308.json](raw-0308.json) |

脚本 sha256：e0b6067f5f3e66f114f486bf8025c6d4ea4f12cedfef3ba0136c32fc1d97d8b1；请求契约：sha256:13e0da1719ae2c317317317e7820d99f64080d0ac0e1c574484228c8b09912bd。
