---
title: 3.1 判定忠实 — 测试规格（草稿）
created: 2026-11-04
---

# 3.1 判定忠实 — 测试规格

这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

## 0 本文件

**用途。** [attacks.md](attacks.md) 里保留实测的 13 个攻击编号怎样测、怎样判：每个子目标的做法、成功看哪个外部事实、挡住时预期看到什么、这次尝试算有效的前提、不设防下的做法；另有正对照与自检。攻击含义以 attacks.md 为准；设计以 agent-rm-model（6fb56f9f）3.2、4.2、4.3、5.3 为准；被测 engine 是登记基线 v4，engine-v3 在 a9eff999。共用的方法规则见 [METHOD](../METHOD.md)，运行规则沿用 1.1 的 [TESTING](../../prove/no-bypass/TESTING.md) §1。

**状态。** 用户 2026-11-04 批准；两轮冷审后的修正用户 2026-11-05 批准。

**范围。** 报的攻击数 N = 13 个编号（用户 2026-11-04 批准由 17 改为 13）；子目标、正对照与自检不另计攻击数。DF-02、DF-15 改写成结构论证，DF-04、DF-11 并入 DF-03，都写在 attacks.md。DF-14 不在本文件：v4 已有经 engine 只读宿主文件的接口，规格未写，本轮不做。差分随机测试不在本文件。本文件不声称覆盖了全部请求序列。

## 1 共用约定

### 1.1 两种配置与安全范围

- **engine 配置。** 每个子目标起一行（必要时两行），攻击脚本在隔间里以本行 uid 运行，直接对本行代理口说规范形式，不经隔间内前端；DF-16 另用 fd 3 上的控制口。PDP 默认用简易 PDP；DF-17 的两个 PDP 期间子目标与正对照 PC-RECHECK 换成能扣住答复的 PDP 替身（1.5）。
- **不设防配置。** 照 METHOD 规则 3：不起隔间，攻击进程以宿主 uid 1000、无 capability、no_new_privs 在本批运行 cgroup 与私有 namespace 里运行，直连测试上游，不经 engine；测试凭据真值放在它的环境变量里。要经 engine 的手法在这里退化成直接做成目标；每个子目标的退化做法写在第 2 节"不设防下"一栏。DF-16、DF-18 在不设防下没有对应物（没有表、没有原因词），按规则 3 写"不成功的原因"，不硬造成功（用户 2026-11-04）。
- **只打自建对象。** 条目、凭据、上游、诱饵、DNS 名字都由本批建立，名字带 nb-decoy- 前缀；测试凭据是无生产权限的随机串，每次尝试重新生成。批次网络与宿主网络隔开，出口只通到本批的测试网络（1.3）。
- **时限与资源。** 每个子目标 30 秒（该子目标全部行，从起行到判定完）；600 秒/批；2 GiB、1024 进程、10 MiB 归档；统一清理顺序。例外：DF-06 no-answer 单独一批，子目标 360 秒、批次 900 秒，因为请求总时限 330 秒写死在 connector（connector/session.py WAIT_TIMEOUT）。子目标跑不完就拆到另一批，不延时、不省略目标。
- **每批开跑前停下问用户 WSL 内是否干净**（没有别的会话在编译或跑测试），用户确认并说"开始"才跑。

### 1.2 跑前建的对象

| 对象 | 内容 |
|---|---|
| 工作区 | work0：攻击行所在；work1：DF-03 other-workspace 的别的工作区、DF-18 的别行。每个子目标需要的条目在起行前经管理口登记，跑完删掉，下一个子目标从空表加兜底开始 |
| 兜底条目 | 每个工作区一条，方法 {GET}、不带账户、不问（匿名默认表） |
| 测试上游 | 断网测试网络里的 HTTPS 服务，证书由本批 CA 签；主机名 nb-decoy-up（精确条目用）与 nb-decoy-open（不列入表，只经兜底），经本批 hosts 文件指向同一全局类别测试地址；另在 8443 端口监听（DF-03 other-port）。端点：/ok（2xx）、/redirect/302、/redirect/307、/redirect/308（Location 指向内网诱饵）、/close-after-read（读完请求即断开、不回响应）、/stream（先发一块，等测试一侧放行后再发带标记的第二块）、/oauth/token（DF-18） |
| 测试上游记录 | 每个请求一行：时间、TCP 连接号、方法、路径、查询、全部头、正文长度与摘要；每个流式响应记每一块的发出时间 |
| 内网诱饵 | 四个记录器：10.x 私网地址、169.254.169.254、127.0.0.1（运行网络的 lo）、运行网络自己的接口地址；每个记下被连的时间与收到的字节 |
| 测试 DNS | 测试网络里的 DNS 服务器，只答名字 nb-decoy-rebind：A 查询第一次答测试上游的全局地址，之后答 10.x 内网诱饵；AAAA 答无记录；记下每次查询。这个名字不在 hosts 文件里 |
| 凭据记录 | 账户 nb-decoy-acct-a，放置位 authorization 加认证词 Bearer，目的地 nb-decoy-up:443；DF-18 另登记 OAuth 账户 nb-decoy-acct-y，token 端点 https://nb-decoy-up/oauth/token |

### 1.3 判定

- **成败只看外部事实。** 外部事实是测试上游记录、内网诱饵记录、测试 DNS 记录、隔间收到的字节（攻击者自己看到的东西，DF-12、DF-18 用）、工作区表在磁盘上的镜像。engine 的回复只在它本身就是攻击目标时作事实（DF-18 的原因词）。
- **请求怎样对上记录。** 每个请求在路径或查询里带本次尝试的随机串；E-09 的 request_admitted 记录查询与头值，测试上游记录全部字段，按随机串对上。
- **机制看记录。** 挡住时观察到的机制取自三处：隔间收到的 x-engine-reason 原因词；E-09 的 request_decided（deny_reason 与 reason_code）、question_*、request_withdrawn、entry_revoked；connector 自己的记录（request_refused、upstream_failure）。与预期不符或推不出时先记无效，查清再改（METHOD 规则 4）。
- **trace 共用判定。** 每批结束后检查：测试上游与内网诱饵收到的每个请求，之前都有同一随机串的 request_decided（allow），主体是发出它的那一行。效果范围按构造封闭：批次网络里出口只通到测试网络，那里的每个监听端都是记录器；连别处在 connector 就连不出去，不产生效果。本文件不声称"所有出口都查过"。
- **结果四类。** 预期机制挡住、转人工、成功、无效（METHOD 规则 4）。有效前提不成立的尝试一律记无效，写原因，不记挡住。

### 1.4 对照、配对与完成条件

- **对照步。** 每个子目标在攻击步之前先做对照步：同一脚本向允许的目标发同形状的请求，必须放行；不放行记无效。
- **配对。** 同一子目标在同一批里 engine 与不设防交替跑；engine 臂记挡住，以同批不设防臂成功为前提，否则记无效（DF-16、DF-18 除外，见 1.1）。批次中途失败只损失正在跑的子目标。
- **完成条件。** 每个子目标有一对有效结果；每批正对照全部放行；每批 trace 判定全部通过；真跑前判据自检先过（第 5 节）。

### 1.5 依赖时序的子目标怎样做成确定的

测试一侧撑住窗口，每次尝试留"确实落进窗口"的证据，跑一次（用户 2026-11-04）：

- **PDP 替身。** 以 PDP 专用 uid 连 hook 口，收到请示后不答，等测试一侧放行再答允许；答复与简易 PDP 相同，只延后。证据：替身记下的收到请示与答复时间。
- **测试 DNS。** 同一名字第一次答全局地址、之后答内网地址。证据：DNS 查询记录。
- **上游控制的流式响应。** 第一块发出后停住，测试一侧完成撤销，E-09 出现 entry_revoked（核心已发出撤销）、connector 自己的记录出现 revoked（connector 处理完了撤销帧）之后，上游才发带标记的第二块。只看 E-09 不够：它不是 connector 已处理的确认。放行不看匹配到几条连接：处理了却没切到连接正是要暴露的缺陷，匹配到的连接数至少 1 写在挡住时预期里（这个数是 connector 匹配到并调用切断的连接数，不是核实过的切断数；挡住还要看隔间那一侧流确实断了）。第二块写进已切断的连接失败也算已发出；上游等放行超时没发的不算。证据：上游每块的发出记录、E-09 撤销记录与 connector 的 revoked 记录。

撑不住窗口的退回 METHOD 规则 7，R = 10。

## 2 逐个攻击

每张表的"挡住时预期"写原因词与 E-09 记录；"有效前提"不成立记无效。

### 2.1 DF-01 一次允许执行两次

出发点：攻击者自己的服务器（经兜底）收下请求后断开，诱 connector 重发。凭证重放那一半没有入口（METHOD 规则 11）。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| close-after-read | 同一条代理口连接上先 GET /ok 读完，再发 /close-after-read（带随机串）；上游读完第二个请求即断开 | 上游记录里第二个请求的随机串出现 2 次 | 1 次；隔间收到"结果未知"（x-engine-reason result_unknown）；connector 记 upstream_failure | 第二个请求的上游连接号与第一个相同 | 脚本收到断开后照样再发一次 |

### 2.2 DF-03 发往没列入的主机（含并入的 DF-04、DF-11）

出发点：请求全由 agent 自己填。没列入的主机发 GET 按设计经兜底放行，是正对照 PC-FALLBACK。NAT64 众所周知前缀与 IPv4 映射的 IP 字面量在文法层拒，归 2.2 的文法测试，不在这里（用户 2026-11-04 删去：本批网络没有 NAT64 转换，不设防下到不了，凑不成配对）。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| post-unlisted | POST https://nb-decoy-open/ok | 上游收到 | not_authorized；request_decided deny，reason_code not_covered（兜底条目在，请求命中兜底而方法不覆盖） | 对照步：GET 同一目标放行 | 直连上游 |
| method-uncovered | 精确条目 nb-decoy-up:443 方法 {GET}；发 POST | 上游收到 | not_authorized，not_covered | 对照：GET 放行 | 同上 |
| path-uncovered | 精确条目方法 {POST}、前缀 /ok；发 POST /other | 上游收到 | not_authorized，not_covered | 对照：POST /ok 放行 | 同上 |
| recorded-deny | 精确条目状态禁止；发 GET | 上游收到 | recorded_deny | 对照：记禁止之前 GET 经兜底放行（同一张只有兜底的表），之后测试一侧记禁止再放行攻击步 | 同上 |
| ip-loopback | GET http://127.0.0.1:端口/ | 诱饵收到 | clause；connector 校验阶段拒（条款 7），E-09 无该随机串的准入；connector 的记录里这条代理口连接以"IP literal refused at validation"关闭 | 对照：GET 允许目标放行 | 直连诱饵 |
| ip-linklocal | 同上，169.254.169.254 诱饵 | 诱饵收到 | 同上 | 同上 | 同上 |
| ip-interface | 同上，运行网络自己的接口地址 | 诱饵收到 | 同上 | 同上 | 同上 |
| ip-private | GET http://10.x 诱饵/ | 诱饵收到 | not_authorized；request_decided deny，reason_code address_not_named（兜底覆盖 GET，但兜底不点名任何非全局地址；核心第一个检查点，K-58）；E-09 有该随机串的准入 | 对照：GET 允许目标放行 | 直连诱饵 |
| name-private | GET https://nb-decoy-inner/（hosts 指向 10.x 诱饵），经兜底 | 诱饵收到 | 有 request_decided allow，之后 connector 连接前拒：解析出的 10.x 不是全局地址、允许它的格子没点名（条款 7 第二道门，C-19）；隔间收到 not_authorized，connector 记 request_refused（address_not_named） | 对照：GET nb-decoy-open 放行 | 直连该名字 |
| other-port | 精确条目 nb-decoy-up:443 允许 POST；POST https://nb-decoy-up:8443/ok | 8443 收到 | not_authorized（8443 只剩兜底，兜底不覆盖 POST） | 对照：POST 443 放行 | 直连 8443 |
| other-workspace | work1 有精确条目 nb-decoy-up:443 允许 POST；work0 没有；work0 的行 POST | 上游收到 | not_authorized，not_covered（work0 只有兜底） | 对照：work1 的行同一 POST 放行 | 直连上游 |

### 2.3 DF-05 重定向到内网

出发点：攻击者的服务器回 3xx 指向内网。在 v4 上自测三种状态码，不借 2.3 在 v2-go 上的结果。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| 302、307、308 | GET /redirect/30x，Location 是 10.x 诱饵的 IP 字面量；脚本像客户端那样跟随 Location 再发一次 | 10.x 诱饵收到 | 隔间收到原样的 30x（远端响应）；跟随的那次 not_authorized：E-09 有准入，request_decided deny、reason_code address_not_named（兜底不点名私网地址，K-58） | 上游记录显示它回了 30x | 脚本直接跟随 |

### 2.4 DF-06 往需要审批的端点上传

出发点：用户把某格标"每次都问"，agent 往里发。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| deny | 精确条目每次都问；POST；测试一侧答"这次拒绝" | 上游收到 | user_denied；question_answered verdict 3 | 管理口收到提问 | 直连上游 |
| no-answer | 同上；不答，等 connector 的 330 秒总时限 | 上游收到 | timeout；request_withdrawn stage asking；管理口收到 QUESTION_WITHDRAWN | 管理口收到提问 | 同上 |

### 2.5 DF-07 "允许一次"用两次

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| once-twice | 每次都问的格；第一个请求答"这次允许"；随即发同一请求 | 第二个请求没有新答复就到了上游 | 转人工：第二次出现新提问；上游只 1 次；测试一侧不答，脚本断开后 request_withdrawn | 第一个请求经 user_allow_once 放行 | 脚本连发两次 |

### 2.6 DF-08 问用户到发出之间换请求

出发点：agent 撤回旧请求、立刻发新的，让用户对旧提问的答复落到新请求上。改正在等的那份请求没有入口（正文密封）。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| withdraw-swap | 每次都问的格；请求 A 起提问后脚本断开；发请求 B（同格、不同正文）；测试一侧对 A 的提问答"这次允许" | B 在 B 的提问得到答复之前到了上游 | 对 A 的答复被拒（ERR）；B 的提问挂着；B 没到上游 | E-09 里 A 的 request_withdrawn 早于对 A 的答复 | 直连发 B |

### 2.7 DF-09 批准后换 DNS 地址

出发点：攻击者拥有一个经兜底可达的域名的 DNS。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| rebind | 新开一条代理口连接（没有可复用的上游连接，connector 必须解析）；GET https://nb-decoy-rebind/ok（经兜底） | 10.x 诱饵收到连接 | 上游收到，诱饵没收到 | 攻击步之前这个名字没被查过，攻击步里至少查过一次（DNS 记录）；对照步用 nb-decoy-open，不消耗这个名字的第一次答复 | 脚本连两次，第二次解析到诱饵 |

### 2.8 DF-10 换账户后复用连接

出发点：带不带凭据头由 agent 决定。换正文那一半没有入口。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| account-then-none | 精确条目 nb-decoy-up:443 带账户 a；同一条代理口连接上先发两个带 authorization 的请求并各自读完，再发不带的 | 不带的与前一个带账户请求的上游连接号相同 | 不同；带账户的 request_decided allow placement 2，不带的 credential none | 第一个请求在上游的头恰为"Bearer 真值"；对照：两个带账户请求同一条上游连接（同键确实复用，换连接才归因于键带账户） | 一条 keep-alive 连接连发三次 |

### 2.9 DF-12 撤销后继续用已开的连接

出发点：攻击者保持一条长的流式响应，用户发现异常去撤销。只收窄方法或路径时不切断是设计，不在此列。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| entry-del、entry-narrow-account、entry-deny、cred-del、cred-put | 带账户 a 的精确条目；GET /stream 带 authorization 占位头（本行以账户 a 发出，不带头则不绑定账户）；收到第一块后，测试一侧分别删条目、把账户从条目收窄掉、把条目改禁止、删凭据记录、覆盖凭据记录 | 隔间收到第二块的标记 | 隔间收到的流在撤销处截断（没有 RESP_END）；E-09 有 entry_revoked；connector 记 revoked，匹配到的连接数至少 1 | 上游收到的 /stream 请求头恰为"Bearer 真值"；隔间收到第一块在撤销之前；上游第二块在 entry_revoked 与 connector 的 revoked 都出现之后才放行（不论匹配到几条） | 撤销对直连没有作用，第二块照到 |

五种都测（用户 2026-11-04）：五种在 engine 里走三条代码路径（删条目与改禁止发切整个键的撤销帧，撤销账户按账户发，凭据删除与覆盖走凭据变动），确定性的子目标每个只多一行。五种撤销方式来自 agent-rm-model 4.3"请求的路径与三个检查点"一段与 must K-31。

### 2.10 DF-16 往控制口送修改类动词

出发点：控制口一端在隔间里（fd 3）。判定口那一半没有入口。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| control-verbs | 向 fd 3 发 type 为 entry_put、answer、cred_put、row_start 的消息；再 POST 一个只有 entry_put 生效才会放行的请求 | 工作区表镜像变了，或那个 POST 放行 | 每条答 unsupported_kind；表镜像前后一致；POST not_authorized | 控制口有回答 | 没有控制口与表，不成功；按规则 3 写原因 |

### 2.11 DF-17 并发改表

出发点：窗口由用户改表与 PDP 时序造成，攻击者撑不开；写成"并发改表时判定仍忠实"的检验。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| ask-then-narrow | 每次都问的格；提问挂着时把这一格的方法收窄到不含该请求，再答"这次允许" | 请求到了上游 | 答复被拒（superseded）；policy_changed；question_answered superseded=true | 改格的 table_changed 早于答复 | 没有表，直连 |
| pdp-narrow | PDP 替身扣住；扣住期间把方法收窄为 {GET}（非空集合，不含该请求的 POST；空集合是不限方法）；放行替身 | 请求到了上游 | policy_changed，reason_code recheck_failed | 替身记下的收到请示早于 table_changed，放行晚于它 | 同上 |
| pdp-deny | 同上，扣住期间把条目改禁止 | 同上 | 同上 | 同上 | 同上 |

### 2.12 DF-18 借拒绝原因探测别行的 token 端点

出发点：agent 自己发请求、读拒绝原因。work1 的行能用 OAuth 账户 y，其凭据记录登记了 https://nb-decoy-up/oauth/token；work0 的行用不了 y。每个子目标在 work0 的行里成对发两个 POST（JSON 正文）：一个到 /oauth/token，一个到没人登记的 /oauth/other。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| uncovered | work0 的表不覆盖 nb-decoy-up 的 POST | 两个请求的回复（类别、原因词）不同 | 都是 not_authorized | 管理口有 y 的端点登记回执 | 没有原因词，不成功；按规则 3 写原因 |
| covered | work0 有精确条目允许 POST、不带账户 | 同上 | 两个都放行到上游，没有 clause | 同上 | 同上 |

### 2.13 DF-19 不符的认证词

出发点：头由 agent 自己填。

| 子目标 | 做法 | 成功 | 挡住时预期 | 有效前提 | 不设防下 |
|---|---|---|---|---|---|
| word-mismatch | 账户 a 登记 Bearer；请求带 authorization: token 占位值 | 上游收到的头里出现 token | 上游的头恰为"Bearer 真值" | 请求确实带了"token 加占位值"（E-09 request_admitted 的头值） | 脚本用环境变量里的真值自填 token 头 |
| word-missing | 请求带 authorization: 占位值（没有认证词） | 上游收到的头不是"Bearer 真值" | 同上 | 请求确实带了不带词的占位值（E-09 request_admitted 的头值） | 同上，自填不带词的头 |

## 3 预期机制在 a9eff999 的位置

| 机制 | 位置 | must |
|---|---|---|
| 查表与默认拒绝 | engine/matching.py match；engine/hook.py Hook.check | K-08、K-12、K-43 |
| 拒绝原因词 | engine/hook.py Hook._deny（核心的拒绝号）；connector/session.py DENY_WORDS、Session._refuse（拒绝号转成公开词）；connector/upstream.py REFUSED_WORDS（connector 自己的拒绝）；从不连的范围与本机地址的 IP 字面量在 connector/session.py Session._request 准入前拒（Policy.never_connect）；其余非全局字面量在 engine/hook.py literal_not_named、Hook.check 拒（K-58） | K-51、K-58 |
| 地址过滤（全局可达、本机接口地址） | connector/upstream.py first_gate、address_refusal、Policy.refusal、Policy.never_connect、is_local_address（第一道门从不连；第二道门非全局且没点名） | C-19、C-35、C-36 |
| 只连检查过的地址、不自行重连 | connector/upstream.py Exchange.run、_connect（auto_open=0；连上之后、发字节之前再判一次对端） | C-19 |
| 不跟随 3xx | connector/upstream.py Exchange._relay | C-18 |
| 一次发出、不重试 | connector/upstream.py Exchange.run | C-22 |
| 上游连接按（host、port、scheme、账户）分，每条代理口连接各自保管 | connector/upstream.py Exchange.run 的 key、Exchange.links | C-21 |
| 凭据头整串生成 | connector/upstream.py header_value、placed_headers | C-16 |
| 提问、答复、答复作废 | engine/hook.py Hook._ask、Hook.answer、Hook._answer_cell | K-13、K-45 |
| 撤回与总时限 | connector/session.py Session._await；engine/hook.py Hook.withdraw | C-15、K-16 |
| 第三个检查点 | engine/hook.py Hook._third_checkpoint | K-46 |
| 撤销切断 | engine/hook.py Hook.table_changed、Hook.credential_changed；connector/upstream.py Registry.revoke | K-31、C-26 |
| 条款 10 端点按行 | engine/hook.py Hook.check；engine/matching.py usable_accounts、endpoint_hit | K-25、K-32 |
| 控制口不支持任何动词 | engine/phases.py DataPlane._unsupported | K-04 |

## 4 正对照

每批都跑 PC-ALLOW 与 PC-FALLBACK，另跑与本批攻击相关的。全部拒绝不算通过（METHOD 规则 3）。

| 编号 | 做法 | 必须看到 |
|---|---|---|
| PC-ALLOW | 精确条目允许 POST；POST /ok | 上游 2xx 一次，隔间收到完整响应 |
| PC-FALLBACK | GET https://nb-decoy-open/ok | 经兜底放行，上游一次 |
| PC-ONCE | 每次都问的格，答"这次允许" | 恰好放行一次 |
| PC-CELL | 每次都问的格，答"允许，这一格以后不再问"；再发一次 | 第二次不提问即放行 |
| PC-CRED | 带账户的请求 | 上游的头恰为"Bearer 真值"，2xx |
| PC-RECHECK | PDP 替身扣住期间，在同一工作区改一条与该请求无关的允许条目（nb-decoy-open:443 的 GET；不覆盖该请求，也不是覆盖它的禁止） | 版本号变了（E-09 的 table_changed 落在请示与答复之间）但这一格不变，照常放行 |
| PC-STREAM | GET /stream，不撤销 | 两块都到，有 RESP_END |

## 5 自检

- **离线（写代码时）。** 给每个判据喂伪造的观察：伪造的成功必须判成功；机制与预期不符必须记无效；有效前提不成立必须记无效。
- **第一批：故意做错的 engine（用户 2026-11-04）。** 在钉住源码的快照副本上打补丁，不改 engine-v3；变体运行永不标正式。每个补丁对应的子目标必须翻成成功，翻不过来先修判据：

| 补丁 | 必须翻成成功 |
|---|---|
| connector 跟随 3xx 一次，且不经地址过滤直接连 Location | DF-05 三个 |
| connector 在结果未知时重发一次 | DF-01 |
| connector 收到撤销帧不切断（仍照常记下 revoked，放行条件不因此卡住） | DF-12 五个 |
| 上游连接的键不含账户 | DF-10 |
| 第三个检查点一律放行 | DF-17 pdp-narrow、pdp-deny |
| "这次允许"当作"这一格以后不再问" | DF-07 |
| connector 连接时按主机名再解析 | DF-09 |
| connector 保留请求里的认证词 | DF-19 两个 |
| 条款 10 端点清单取全部账户 | DF-18 covered |

DF-03、DF-06、DF-08 的判据与上面的诱饵记录、上游记录判据同一种；DF-16 的表镜像判据只做离线自检。

## 6 执行与报告边界

- 每批开跑前停下问用户 WSL 内是否干净，用户说"开始"才跑；一次一批。
- engine 源码与登记基线 v4（a9eff999）逐文件一致、基线核对通过、宿主读数档案 v4 已批准且读数一致，才标正式；否则标"试跑，不算数"。
- 报告按 METHOD 规则 1 的措辞上限："这组攻击全部被挡住"或"挡住几个、放过几个"；不写"无法绕过"。
