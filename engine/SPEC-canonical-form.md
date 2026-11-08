# 规范形式与线上编码（engine v2，第 2 块）

设计来源：agent-rm-model.md（commit 260a3e50）3.9 代理口的形状与身份规则（规范形式字段、派生字段、正文经密封 memfd、响应形状）、条款 1–3（头与路径的拒绝项）、3.7 核心对外三条口；建造计划工程项 3（四条链路、编码）、4（上限）、15（序号）、16（memfd）。本文是 connector 读取器与编码器的唯一依据；validation.md 的 C-05、C-06、C-07、C-08、C-10、C-12、C-13、C-28、K-03、K-24、K-36、K-59 引本文。

## 1. 地位

- 规范形式是 engine 从 runtime 方向接受的唯一输入（3.8 TCB 的输入行）：隔间内的前端把 HTTP/1.1 翻成它，agent 绕过前端直接对代理路径说规范形式是允许且等价的。connector 把它当不可信输入逐字段校验；任一字段读不通，整帧拒。
- 四条链路各有自己的帧种类表，每条链路只认自己表里的种类，收到别的种类或反方向的种类即断开（C-06、K-03）。后来加的链路同样如此：F（hook 口，第二阶段）、H（文件判定口）与 G（文件口，隔间内 MCP server 到文件 worker，不可信输入，宿主文件读 2026-11-04 起）。agent 侧控制 socketpair 沿用 v1 的 JSON 成帧（engine/receive.py），不在本文编码之内；第一版动词集合为空，任何消息答 `error` 帧、`code` 为 `unsupported_kind`。

## 2. 线上编码（链路 A、B、D、F、G、H 共用）

```
frame   := length:u32be  kind:u8  field*          length = 1 + Σ len(field)，即长度字之后的全部字节数
field   := flen:u32be  bytes[flen]                每字段一个长度字，字段顺序由种类表固定，不带键名
```

- 整数值字段：u16、u32、u64 都以大端定长字节放在一个 field 里（flen 分别为 2、4、8）；枚举值 u8（flen 为 1）。
- 字符串字段：ASCII 字节（host、method、路径、查询串、头名）或 latin-1 字节（头值）；不是 UTF-8 文本，不做任何转码。
- 列表字段：一个 field，其 bytes 为 `count:u32be` 后接 count 个 `item`，item 本身是 `ilen:u32be bytes[ilen]`；头列表的 item 是名、值交替（count 为名值对数的两倍）。
- 空字段：flen 为 0；"可缺省"的字段（查询串）以 flen 为 0 表示缺省。
- 读取器先读 length，length 超过该链路的帧上限即断开，不读正文；第五个字节（kind）一到就查它是否在本链路的表里，不在即断开、不缓冲其余字节；再按种类表的字段数与顺序逐个读，少字段、多字段（读到第 n+1 个字段的长度字即停）、flen 越过帧尾都算读不通。列表字段先比 count 与项数上限，再逐项读。
- 没有 JSON、没有键名、没有对齐填充。

## 3. 帧种类表

### 3.1 链路 A：隔间内前端（或 agent）→ connector，代理口（不可信输入）

| kind | 名 | 方向 | 字段（顺序固定） |
|---|---|---|---|
| 0x01 | REQUEST | 前端→connector | method、scheme、host、port(u16)、path、query（可缺省）、headers(list)、body（8 个字段） |
| 0x11 | RESP_HEAD | connector→前端 | category(u8：1 远端响应、2 明确拒绝、3 传输错误、4 结果未知)、status(u16，非远端响应时为 0)、headers(list) |
| 0x12 | RESP_CHUNK | connector→前端 | bytes |
| 0x13 | RESP_END | connector→前端 | （无字段） |

身份核验在传输层、在任何帧被解析之前（3.9 身份规则；validation.md C-01、C-02）：connector 核验每个 accept 出的 fd 上 SO_PASSCRED=1、从不自己设置，不为 1 即关闭该连接；每条消息附的内核章 uid 必须等于该路径登记的 uid_i 且 pid 大于 0，不符即关闭该连接并丢弃已读字节；代理口上附带 SCM_RIGHTS 的消息一律关闭所收 fd 并断开（实施注意 2）。每条 accept 连接同时只有一个 REQUEST 在处理；RESP_END 发出前 connector 不读下一帧（parse_request 不碰 socket，这一层在它之前）。明确拒绝、传输错误、结果未知三类的 RESP_HEAD 之后紧跟 RESP_END，带一个 RESP_CHUNK 作错误体，按固定模板生成（648d60f2 4.3 拒绝回复，connector/upstream.py refusal_body）：被拒请求的方法、scheme、目的地与路径（读不通的请求不回显任何字段），一行原因词，一行这个原因的下一步；不含 query、头值、正文、异常消息与上游字节（C-23）；这三类的 RESP_HEAD 头列表里有一个 `x-engine-reason` 头，值是固定的原因词：核心给的 not_authorized、recorded_deny、user_denied、pdp_denied、policy_changed、clause、credential、unavailable（DENY 的 reason 照表转），connector 自己给的 clause（文法与条款 1–3 的校验、条款 7 的第一关：校验阶段的 IP 字面量与连接时的地址，含连上之后、发出任何字节之前的重判；校验阶段落在部署方配置的 NAT64 前缀里的 IP 字面量；条款 4）、not_authorized（条款 7 的第二关：连接时解析出的非全局地址不在允许帧的点名集合里，见 §3.2"条款 7 的连接判定"）、credential、timeout、response_withheld（条款 10 扣下 token 响应，请求已发出），以及 502 的 transport_error、result_unknown；前端把明确拒绝映射成 403、另两类映射成 502，头与正文原样转发。校验阶段的拒绝（帧完整、字段读不通，或 IP 字面量落在条款 7 的第一关或部署方配置的 NAT64 前缀里）回明确拒绝后断开这条连接；帧的边界都定不出来的（长度不合、超上限、种类不在本链路、带 fd、章不符）直接断开（C-36、C-35）。远端响应的 RESP_HEAD 头列表是上游的头去掉成帧头（transfer-encoding、content-length、connection、keep-alive、te、trailer、upgrade）、proxy-* 与 x-engine-*（后者是 connector 自己的词，上游写的一律剥掉）之后的名值对，名小写、obs-fold 已展开；上游的头读不通（解析器缺陷、名不是 token、值含控制字节）整个响应按结果未知处理、不发 RESP_HEAD；100 以外的 1xx（如 103）同样按结果未知处理并丢弃该连接，因为真正的响应会落到下一个请求上；带账户目的地再去掉 set-cookie 与 set-cookie2（条款 10）。RESP_END 之前 connector 关闭连接，即响应被切断（上游中途失败、Content-Length 未满的 EOF、撤销切断，含以连接关闭定界的正文被撤销切断）：前端把它当截断的响应，不当完整响应（第 4 块定）。TLS 上游的连接以 suppress_ragged_eofs=False 建立：上游不发 close_notify 就关连接时，以连接关闭定界的正文同样算截断（取严：路径上注入的 FIN 与不发 close_notify 的上游分不开；审阅点 B 定）。

条款 10 的 token 响应（读法：用户 2026-11-04 定稿，2026-11-05 裁定多看一层、不扩 XML，计划 engine-v3-n16-file-read；设计文本待批，在提案文件里；validation.md C-25、N-16）。按响应的正文认，不看请求怎么编码，也不看 Cache-Control；只对标准格式（JSON、表单编码）作保证：
- 请求一侧：方法为 POST（不分大小写）的请求，connector 一律发 `Accept-Encoding: identity`，agent 给的 accept-encoding 一个也不发。别的方法照旧不加、不改。
- 候选：POST 请求的响应，有一个 Content-Type 字段的媒体类型是 `application/json` 或 `application/x-www-form-urlencoded`。媒体类型取 `;` 之前的部分，去掉首尾空白，不分大小写比较；多个 Content-Type 字段里有一个对上就算。状态码不论。别的响应（SSE、二进制等）不是候选，不缓存，照旧逐片转发。代价：媒体类型是这两种的 POST 流式响应（不是 SSE），要等到 64 KiB 或读完才转出第一个字节。
- 读不出就扣下：候选带 identity 以外的 Content-Encoding（各字段按逗号分开，空元素不算），扣下，TCB 里不解压。候选带 http.client 解不开的传输编码，同样扣下：Transfer-Encoding 合起来不恰好是一个 chunked，或 http.client 没按 chunked 读（工程选择，同一条"TCB 不解压、失败即关"）。
- 先缓存、后判定：候选的正文读到 64 KiB 加一个字节（65,537 字节）或读完为止，什么都不发。读完、不超过 64 KiB（65,536 字节）、且正文的键里有 `access_token` 的，是 token 响应。JSON（媒体类型是 application/json）看两层：顶层对象的成员名，以及值本身是 JSON 对象的那些顶层成员的直接成员名（用户 2026-11-05 定；Slack 的用户 token 在 authed_user 这一层）；两层都用 `object_pairs_hook` 收全部成员名，重复的名也算；顶层不是对象的不算；数组（顶层的或成员值里的）、字符串值与第三层及更深都不看；正文按 `json.loads` 对字节的规则解码（UTF-8，可带 BOM，或 UTF-16、UTF-32）。表单编码用 `parse_qsl`（保留空值）解出的键，正文按 latin-1 读成文本，只看这一层（`a[access_token]` 这类键不算）。两个媒体类型都出现时两种都试，有一种找到就算。
- 扣下：回明确拒绝、`x-engine-reason: response_withheld`、模板正文，丢弃这条上游连接，记 `token_response_withheld`（带 why：body、content_encoding 或 transfer_encoding），REPORT 照报远端响应与状态码。
- 放行：不是 token 响应的候选，包括超过 64 KiB 的、JSON 解析失败的、access_token 在第三层或更深或在数组里的（N-16 的残余），照常发 RESP_HEAD，缓存的部分连同其余原样转出，字节不变。
- 保证的边界（N-16，用户 2026-11-05 定）：别的媒体类型不是候选，其中的 token 响应原样转出，不另认；agent 能让授权服务器换格式时同样挡不住，例如 GitHub 的 token 端点按请求的 Accept 回 JSON、XML 或表单，带 `Accept: application/xml` 换来的 XML token 响应原样进隔间（connector 不改写 Accept）。已登记的 token 端点在请求一侧照样被拒（与登记端点相等的检查，validation.md K-25），不论响应是什么形状。tests/test_connector_token_response.py 里名字以 test_declared_boundary_ 开头的几例记录这条边界。
- 缓存期间切断：撤销、读失败、Content-Length 未满就 EOF，都照转发中途切断处理：发 RESP_HEAD 后不发 RESP_END 就关连接，缓存的部分一个字节也不交出，不拿读到的一部分去判。读完、还没转出时撤销，同样只发 RESP_HEAD；撤销落在判定期间的，不论判定是不是 token 响应，都按撤销处理（撤销优先，不发扣下的回复）。缓存块转出失败（客户端已走）或连接已被撤销时，不再读上游，直接切断。
- 缓存期间客户端离开：每读一片就看一次客户端 socket 有没有挂断（零等待的 poll，看 POLLRDHUP、POLLHUP、POLLERR，不读下一请求的字节），挂断了就丢上游连接、照报 REPORT，与转发中途写失败发现客户端走了一样处理。上游一个字节也不来时，要等到读超时才发现，与转发时相同。已知代价（2026-11-04 复核发现，裁定为可用性问题，这次不修）：默认的 Go 前端在等 RESP_HEAD 时不把客户端的取消传给 connector（不关这条链路 A 连接），所以真实客户端在候选缓存期间离开，挂断探针看不到，要等候选读完、读满 64 KiB 或单次读超时（600 秒）才收尾。后果只是本行自己的线程、上游连接与请求名额被占：不涉泄漏，撤销与行结束照常生效；同样的占用今天经长流也做得到。修法列为后续工作：前端在客户端取消时关掉这条链路 A 连接，并与归池同步。

### 3.2 链路 B：connector ↔ 核心，判定口（每行一对 socketpair）

| kind | 名 | 方向 | 字段 |
|---|---|---|---|
| 0x21 | JUDGE | connector→核心 | seq(u64)、sender_uid(u32)、method、scheme、host、port(u16)、path（已归一化）、query、headers(list，已剥 override 头)、stripped(list，被剥的头名，供 trace，C-10)、body_kind、form_keys(list)、body_len(u64)，共 13 个字段；正文的密封 memfd 恰一个，随本帧经 SCM_RIGHTS 传递 |
| 0x22 | WITHDRAW | connector→核心 | seq(u64) |
| 0x23 | REPORT | connector→核心 | seq(u64)、result(u8：1 远端响应、2 传输错误、3 结果未知、4 未发出)、status(u16) |
| 0x31 | ALLOW | 核心→connector | seq(u64)、placement(u8：1 x-api-key、2 authorization 加认证词、3 authorization basic)、word(bytes：placement 2 时是凭据记录登记的认证词 `Bearer` 或 `token`，其余为空)、truth_a(bytes：真值；Basic 时是登记的用户名)、truth_b(bytes：Basic 时是登记的密码，其余为空)、account(bytes，选中的账户标识：connector 按（host、port、账户）分上游连接（条款 8、C-21）并按它匹配 REVOKE 帧的 account（C-26）；它是标识，不是真值)、named(list，点名的非全局地址：发帧那一轮过了检查的那一格存的点名集合，不取请求的任何字节，K-59；写法见表后)，共 7 个字段。connector 按 placement 生成整个头值，不取请求里的任何字节（648d60f2 4.3 凭据、5.4，C-16）：1 是 truth_a；2 是 word、一个空格、truth_a；3 是 `Basic ` 加 truth_a、`:`、truth_b 的 base64；只替换请求里该放置位的那个头（x-api-key 或 authorization 的第一个），请求没带就拒、不添加。帧的形状与 placement 不符（placement 2 的 word 不是这两个词、别的 placement 带 word、Basic 缺 truth_b、非 Basic 带 truth_b、truth_a 为空、account 为空）即断开；named 读不通（见表后）同样断开 |
| 0x32 | ALLOW_NOCRED | 核心→connector | seq(u64)、account_destination(u8：1 命中条目带账户，0 不带；第 4 块加：条款 10 "带账户目的地的响应剥 Set-Cookie" 按目的地判，connector 不知道条目，由核心在此告知；ALLOW 一律视为带账户目的地)、named(list，同 ALLOW)，共 3 个字段；named 读不通即断开 |
| 0x33 | DENY | 核心→connector | seq(u64)、reason(u8，648d60f2 4.3 拒绝回复的公开原因词，connector 照表转成词：1 recorded_deny、2 user_denied、3 timeout、4 clause、5 unavailable（行关闭、排队满、记录故障）、6 not_authorized（没有格子或格子不覆盖；目的地是非全局的 IP 字面量、覆盖它的允许格子没点名它，K-58）、7 pdp_denied、8 policy_changed（第二或第三个检查点复核未过）、9 credential（带凭据头而没有可用的凭据记录，或凭据读不出）；细的原因只进核心的 trace) |
| 0x34 | REVOKE | 核心→connector | key_kind(u8：1 精确、2 模式、3 兜底)、key(bytes，host:port 或 后缀:port，兜底为空)、account(bytes)、scope(u8：1 只切这一个账户在该键下的连接；2 切该键下的全部连接，不论账户、含无凭据的，此时 account 为空；第 4 块审阅点 B 加：条目被删、改为禁止或新登记禁止时用 2；允许条目改动后旧的点名集合里有一项不在新集合里（按存的文本比，/8 换成 /24 也算），同样用 2，这一帧也盖住同一次改动失去的账户（K-31，设计 2026-11-05 落盘起）；条目只失去部分账户时按账户各发一帧 1），共 4 个字段 |

- seq 由 connector 分配，从 1 起、在 connector 进程生命周期内严格递增、不复用：JUDGE 帧的 seq 必须大于此前所有 JUDGE 的 seq，否则核心断开该 connector（K-36）；WITHDRAW 与 REPORT 带的是已发出的 JUDGE 的 seq，重复或未知的 seq 丢弃并记录，不断开。
- 判定口每条消息带内核章；核心核 uid 等于 connector 专用 uid 且 pid 大于 0（K-02）。
- memfd：connector 以 `MFD_CLOEXEC | MFD_ALLOW_SEALING` 建，写入正文后加 `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`；核心以 `F_GET_SEALS` 核对三道封都在，缺一即以 DENY（条款拒）答并记录，fd 关闭；memfd 的大小必须等于 body_len（K-24、C-13）。JUDGE 帧不带恰好一个 fd（0 个或多于 1 个）即断开。
- ALLOW 的 truth_a 与 truth_b 在 connector 内只存在于替换缓冲与生成的头值，用后清零（C-29）；找不到等待者的 ALLOW 立即清零并以 REPORT(result=4 未发出) 回报（C-14）。
- named（ALLOW 第 7 个、ALLOW_NOCRED 第 3 个，都是最后一个字段；K-59）：列表的每项是一个地址段的规范文本，即 str(ipaddress.ip_network(项)) 的 ASCII 字节，一律带前缀长，单个地址写成 /32 或 /128（如 `10.0.0.5/32`、`10.0.0.0/8`、`fd12:3456::/48`）。核心照抄那一格存的项（engine/judgment.py named_field）：已去重，按（IP 版本、网络地址、前缀长）排序；空表即没点名，模式与兜底格子总是空表。connector 的读法（connector/canonical.py read_named）：项数超过 64（LIMITS.named_addresses），或某项不是 ASCII、读不成地址段、不恰等于自己的规范文本，即读不通，connector 退出（C-28）；ALLOW 先核与 placement 的形状、再读 named，都过了才拷出真值。次序与重复不核；内置段与拒绝集也不在这里核，交连接时的第一关（下一段），所以核心发错的点名照样连不上那些地址。

**条款 7 的连接判定**（设计 2026-11-05 落盘的 5.3 条款 7；连上之后的重判、重判耗时计入连接时限、配置 NAT64 前缀里的字面量三处按用户 2026-11-05 的裁定，计划 engine-v3-private-net 点名 9；validation.md C-19、C-20、C-35、C-37、K-58、N-15；connector/upstream.py 的 Policy 与 Exchange，connector/session.py 的 Session._request）。connector 在连接的那一刻解析目的地（Exchange._connect；IP 字面量不解析，列表就是它自己），对解析结果里的每个地址判两关。第一关，点名也不连：原地址与判定地址（IPv4 映射地址与 NAT64 地址按内嵌的 IPv4 判，NAT64 前缀是众所周知的 64:ff9b::/96 与 --nat64-prefix 配置的）都不得落在 canonical.NEVER_CONNECT 的内置段里（链路本地 169.254.0.0/16、fe80::/10，回环 127.0.0.0/8、::1，未指定 0.0.0.0/8、::，IPv4 兼容 ::/96，另加工程加严的多播 224.0.0.0/4、ff00::/8 与受限广播 255.255.255.255），也不得落在拒绝集里（--deny-address 给的部署方清单，加 connector 启动时枚举的宿主全部接口地址）；此外逐个地址用一个不发包的 UDP 套接字探测它与它内嵌的地址此刻是不是本机地址，是即同样不过；探测做不成（建不出探测套接字，如描述符耗尽）当作本机地址、同样不过（失败即关，用户 2026-11-05 定，计划 engine-v3-private-net 点名 10），例外是宿主不支持这个地址族（EAFNOSUPPORT）：宿主没有这一族的地址，也建不出这一族的 TCP 套接字，算不是本机；探测套接字的 connect() 失败（没有路由）也算不是本机。第二关：判定地址全局可达（ipaddress 的 is_global，跟两张 IANA 特殊用途地址表）即过；不全局可达的，须落在这个请求的允许帧的 named 里某一段之内。整个列表任一地址不过，整个请求即拒，一个地址也不去连（读法一）。原因词：有地址落在第一关回 clause，不论别的地址是否只差点名；不过的地址都只是没点名回 not_authorized；解析结果为空回 clause；解析本身出错（getaddrinfo 失败）照旧是传输错误。前三种都按 §3.1 的固定模板回明确拒绝，不回显解析出的地址与点名集合，REPORT 报未发出。都过了，才在一个连接时限（C-20，30 s）里按解析的次序逐个去连这同一批地址，用第一个连上的；连的只是判过的地址。每个地址 connect 之前，把这一个地址照上面两关（含本机探测）再判一次，不过即整拒、后面的地址一个也不试：前一个地址连接失败的那段时间里，下一个地址可能已成了本机的。connect() 成功之后、发出任何字节（TLS 握手的 ClientHello 也算）之前，把连上的对端照两关再判一次：内核在 connect() 等待期间每次重发 SYN 都重新查路由，目的地址这期间成了本机的，握手就落在本机的服务上。对 TCP，连上的对端就是交给 connect() 的那个地址，变的是它此刻是不是本机的，所以重判的是这个地址；实际会变的只有本机探测，原因词即 clause。不过即关掉这条连接、整拒，按 §3.1 的固定模板回明确拒绝，REPORT 报未发出，一个字节都不发；握手本身可能到达本机的服务，是声明的残余（N-15）。这两次重判的耗时都从同一个连接时限里扣：先重判，再算剩余时限交给 connect 与 TLS 握手；整列表那一次判定在连接时限起算之前。named 放不开第一关：允许帧点名了内置段或拒绝集里的地址，照样不连。留着的上游连接记下连接时给 connect() 的地址；复用之前，按这个请求的允许帧的 named 把它照上面两关重判一次（含本机探测），不过就丢掉这条连接、在它上面一个字节也不写，照新连接的路走：重新解析、整列表判定（C-37）。IP 字面量另有两处早查：校验阶段查两样，第一关（Policy.never_connect），以及是否落在部署方配置的 NAT64 前缀（Policy.nat64）里，后者与文法拒 64:ff9b::/96 同样处理，断开时的原因提示改写成 IPv4 地址；任一在其中即回 clause、断开这条代理连接，核心收不到（C-35）。所以核心收不到要按内嵌 IPv4 判的字面量；IPv6-only 的部署经主机名（DNS64）访问内嵌 IPv4 的目的地。其余字面量照常交核心，不全局可达的（落在内置段里的也算）由第一个检查点比覆盖它的允许格子的点名集合，按字面判，没点名即以 DENY 的 not_authorized 拒，先于条款 10、不问用户、不交 PDP（K-58，request_decided 的细因为 address_not_named）；放行的到连接时再照上面两关判一次。

### 3.3 链路 C：agent 侧控制 socketpair（runtime → 核心）

成帧照 v1（u32 大端长度前缀，正文是严格的 UTF-8 JSON：无 BOM、无重复键、无浮点、整数在 ±2^53−1 内、嵌套至多 16 层、成员与元素合计至多 4096 个），身份规则照 v1（PASSCRED、每片的章等于本行 uid，在解析之前比较）。没有握手：COMMIT 整条发出，行即活跃。

消息只有一种定义：带字符串 `type` 字段的 JSON 对象。第一版动词集合为空：不论 `type` 是什么，都答 `{"v":2,"type":"error","reply_to":…,"code":"unsupported_kind"}`，行状态不变（K-04）。答复的 `reply_to` 原样回消息的 `id`，`id` 不可回时回消息的 `reply_to`，都不可回时为 `null`；可回的只有不超过 64 个字符的字符串或整数，保证答复装得进一个 1,024 字节的控制帧。除这两个回显字段外，消息的字段一概不读。读不通的帧（JSON 不严格、不是对象、没有字符串 `type`）关行，原因 protocol_error。

### 3.4 链路 D：管理客户端 ↔ 核心，管理口（state 目录下的 admin.sock）

| kind | 名 | 方向 | 字段（第 3.5 步定稿字段细节，种类与方向在此冻结） |
|---|---|---|---|
| 0x41 | QUESTION | 核心→客户端 | question_id(u64，核心分配、全局唯一、不复用；核心自己保存 question_id 到（行、JUDGE seq）的映射，客户端看不到 connector 的 seq）、execution_id、workspace_id、matched_key_kind(u8)、matched_key、request 的全部字段（同 JUDGE 的 method 到 form_keys，含 stripped，共 10 个）、body_len(u64)、binding(list：engine 在第一个检查点算出的凭据绑定，三项 host_port、account、placement(u8)，不附凭据时为空；不含真值，按格子与起行时的指定算出，不读请求里的头值，648d60f2 3.2、4.3，K-28)、cell(list：命中的那一格，六项 state(u8)、methods(list)、prefixes(list)、accounts(list)、approval(u8)、addresses(list：那一格点名的地址，存的规范文本与次序，同 §3.2 的 named，没点名为空表；K-57，设计 2026-11-05 落盘起)；与 PDP_REQUEST 的 cell 同形（engine/pdp.py entry_fields）；持久答复作用于这一整格，648d60f2 3.2，A-01)，以上 18 个字段；宿主文件读（2026-11-04 起，validation.md H-09）在其后追加 6 个：file_op(u8：0 网络请求，2 列目录，3 读)、alias、path（相对路径，原样）、start(u64：读的起始位置或列的起始序号)、length(u64：读的长度，列为 0)、object(list：用户登记的 host_path、type(u8：1 文件、2 目录)、ops(u8：位 1 读、位 2 列目录)；网络请求为空)，共 24 个字段。网络请求的后 6 个字段为 0、空、空、0、0、空表，正文的同一 memfd 随帧传递；文件请求的 HTTP 字段（method 到 body_len）为空、port 与 body_len 为 0、binding 为空表，matched_key_kind 为 4、matched_key 是别名，cell 是对象的 [state、[]、[]、[]、approval、[]]（engine/fileobjects.py object_cell），不带 memfd（客户端只给 file_op 为 0 的 QUESTION 配 fd）；持久答复只改这个对象的审批模式或状态 |
| 0x42 | QUESTION_WITHDRAWN | 核心→客户端 | question_id(u64)、reason(u8：1 撤回（connector 撤回，含它的总时限到）、2 行关闭)；核心不设提问计时 |
| 0x43 | ANSWER | 客户端→核心 | question_id(u64)、verdict(u8：1 这次允许、2 允许，这一格以后不再问（审批模式改为不问）、3 这次拒绝、4 拒绝，这一格以后禁止（状态改为禁止、账户与点名的地址清空）)，共 2 个字段（648d60f2 3.2：持久答复作用于整格，只改审批模式或状态）。核心按当时的表与凭据记录复核（第二个检查点）：那一格在提问期间有任何改动、已换成别的格子覆盖、或凭据绑定不同，答复作废、请求以 policy_changed 拒，回 ERR(refused, superseded)；接受时回 OK，持久答复的 OK 带三者之一：`persisted` 已落盘；`unpersisted` 本次运行内已生效、没有可靠落盘，重启后可能丢（收紧，或只在目录 fsync 失败的写）；`not_applied` 没生效（放宽的写在 rename 之前失败，或表已不可用；"以后不再问"这次按"这次允许"处理）；未知或已答过的 question_id 回 ERR |
| 0x44 | ENTRY_PUT | 客户端→核心 | workspace_id、key_kind(u8)、key、state(u8：1 允许、2 禁止)、methods(list)、prefixes(list)、accounts(list)、approval(u8：1 不问、2 每次都问)、addresses(list：点名的非全局地址，K-57，设计 2026-11-05 落盘起；客户端 `entry put --address` 按用户写的原样与次序发，核心核并规范化)，共 9 个字段。addresses 只给精确的允许条目，模式、兜底与禁止条目带一项即拒；按写的项数至多 64 项（去重之前），连同方法、前缀、账户计入条目列表的 256 KiB 上限（§5）。一项的登记文法（connector/canonical.py named_item）：ASCII、不带 zone 后缀，是规范写法的单个 IP 地址或主机位为零的规范地址段，即写法恰等于 ipaddress 的规范文本（单个地址也可写成带 /32 或 /128 的形式）；主机名、带端口、方括号、首尾空白、掩码写法、大写的 IPv6、主机位非零都读不通，拒；与 IPv4 映射段 ::ffff:0:0/96 或 NAT64 众所周知前缀 64:ff9b::/96 相交的拒，包住它们的段也拒（这两段按内嵌的 IPv4 判，同一地址只认 IPv4 写法）；与 NEVER_CONNECT 的内置段（§3.2"条款 7 的连接判定"）相交的拒。登记时不核全局可达性，也不核部署方清单与宿主接口地址（连接时第一关拒）。任一项不过，整条 ERR、表不变。存的是规范文本（一律带前缀长），去重，按（版本、网络地址、前缀长）排序；镜像版本 3 带这一字段，版本 1、2 的镜像读作没点名 |
| 0x45 | ENTRY_DEL | 客户端→核心 | workspace_id、key_kind(u8)、key |
| 0x46 | CRED_PUT | 客户端→核心 | host_port、account、placement(u8)、word（placement 2 的认证词 `Bearer` 或 `token`，其余为空）、truth_a、truth_b、token_endpoint、registration_endpoint、device_authorization_endpoint，共 9 个字段，布局固定：非 Basic 的真值在 truth_a、truth_b 为空；Basic 的用户名在 truth_a（不含 `:`）、密码在 truth_b；后三项可缺省（flen 为 0）。同一（host_port、account）再登记即整份替换，并切断该账户在各行的上游连接（K-30、K-31） |
| 0x47 | CRED_DEL | 客户端→核心 | host_port、account |
| 0x48 | WS_CREATE | 客户端→核心 | root_path |
| 0x49 | WS_LIST | 客户端→核心 | （无） |
| 0x4A | WS_DELETE | 客户端→核心 | workspace_id |
| 0x4B | ROW_LIST | 客户端→核心 | （无） |
| 0x4C | ROW_START | 客户端→核心 | workspace_id、plan_name、accounts(list，host:port 与账户成对：本次 execution 在该目的地只用这个账户，由启动它的用户指定，agent-rm-model 3.1"每个目的地一个账户"；每个目的地至多一对，所指凭据记录必须已登记；工作区里列了多个账户的条目必须各指定一个，所指账户须是该条目列出的，否则 ERR 拒启动、detail 点名目的地；只列一个账户的条目不用指定，用那一个；第 6 块后加；传送计划不带账户，也不受多账户条目的约束，validation.md S-24)、policy_context(bytes：这一行的策略上下文，不透明，空为没有，至多 16 KiB，超了 ERR 拒启动；核心存在这次 execution 上，原样放进该行每条 PDP_REQUEST，不进任何记录，validation.md K-56；工作区改造加)，共 4 个字段。工作区被别的连接 hold 着时 ERR(busy)；持有者在 hold 期间只能起传送计划；传送计划只许持有这个工作区 hold 的连接起，否则 ERR(refused)（K-55） |
| 0x4D | ROW_STOP | 客户端→核心 | execution_id |
| 0x4E | WS_HOLD | 客户端→核心 | workspace_id。这条连接为导入、推进、导出持有这个工作区（K-55，工作区改造加）：工作区上有活着、关闭中或隔离中的行，或上一行还没关闭且域没清空，ERR(busy)，口径同起行；已被别的连接持有 ERR(busy)；同一连接再 hold 是空操作。OK 的 payload 是工作区根目录的路径、device、inode 与属主的 uid、gid（十进制文本），管理客户端据此核根目录、降权（A-10）。连接断开即放 |
| 0x4F | WS_RELEASE | 客户端→核心 | workspace_id。持有者放开 hold；不是这条连接持有的 ERR(unknown) |
| 0x51 | OK | 核心→客户端 | 对应请求的 kind(u8)、payload(list，内容按 kind) |
| 0x52 | ERR | 核心→客户端 | 对应请求的 kind(u8)、code(u8)、detail(bytes，不含真值) |
| 0x53 | OBJ_PUT | 客户端→核心 | workspace_id、alias（1–64 字节的字母、数字、- 与 _，工作区内唯一）、host_path（UTF-8，绝对路径，至多 4096 字节；客户端不折叠任何段、不解析链接：绝对路径原样发，相对路径只在前面接上当前目录与一个 /）、type(u8：1 文件、2 目录)、ops(u8：位 1 读、位 2 列目录；读必有，列目录只给目录)、state(u8)、approval(u8)（三种审批模式：允许为 1、1，每次都问为 1、2，拒绝为 2、1），共 7 个字段（宿主文件读，2026-11-04 起，validation.md H-01、H-02、H-22）。核心以 engine uid 解析路径（跟随符号链接，.. 作用在链接解析之后的目录上），以 O_PATH 打开目录对象本身或文件对象所在的目录，按打开之后的真实位置（/proc/self/fd 的指向）核与 engine 的部署根、状态目录、记录目录及各工作区存储根互相包含的拒（H-22，用户 2026-11-05 确认），记下的目录也是这个真实位置；同一别名再登记即整份替换；每个工作区至多 128 个对象。OK 的 payload 是 `persisted` 或 `unpersisted`、所开目录的 device、inode（十进制文本）；写序与写盘失败的规则同 ENTRY_PUT（K-17、K-18） |
| 0x54 | OBJ_DEL | 客户端→核心 | workspace_id、alias；OK 的 payload 是 `persisted` 或 `unpersisted` |

管理口上收到链路 A、B 的种类即断开；判定口上收到链路 D 的种类即断开（K-03）。判定口、文件判定口（§3.8）与 hook 口都没有登记或修改宿主文件对象的动词。

### 3.5 链路 E：管理客户端 ↔ pty 转发进程，附接 socket（第 5 块定；不在 TCB，只记义务）

附接监听 socket 由 spawner 绑在 rows 目录的行目录里（engine uid、0600），fd 交给隔间内的转发进程；管理客户端的 `attach` 连它。编码同 §2 的最简形式：`kind:u8  length:u32be  bytes`，没有字段表。

| kind | 名 | 方向 | 载荷 |
|---|---|---|---|
| 1 | INPUT | 客户端→转发进程 | 原样写进 pty master 的字节；Ctrl-C 就是 0x03，由行律发 SIGINT 给前台进程组 |
| 2 | RESIZE | 客户端→转发进程 | rows(u16be)、cols(u16be)，转发进程对 master 做 TIOCSWINSZ，内核向前台进程组发 SIGWINCH |
| 1 | OUTPUT | 转发进程→客户端 | 从 pty master 读到的字节，原样 |

转发进程不解析终端流；同一时刻只接受一条附接连接（后到的被 accept 后立即关闭）；无人附接时仍持续读 master 并丢弃，agent 不会因终端阻塞；帧长度上限 64 KiB，读不通的帧（未知 kind、RESIZE 不是 4 字节、超长）即断开该附接连接；slave 端消失（master 读到 EIO 或 EOF）即退出。终端记录由客户端做（A-04）。

### 3.6 链路 F：PDP ↔ 核心，hook 口（部署根下 hook/pdp.sock；第二阶段，648d60f2 4.2、4.3）

hook 口在部署根下自己的目录 `hook/` 里：部署方以 root 建一次，属主 engine uid、组为 PDP 专用的组、模式 2750（setgid，核心 bind 出的 socket 随之归这个组），核心启动时核对这三样，socket 设 0660；不进任何隔间。核心在 accept 时以 SO_PEERCRED 核对端 uid 等于目录 `pdp.uid`，不符即断开；同一时刻只接一个 PDP，第二个连接即断开（K-48）。成帧同 §2；收到不属于本链路的种类、字段数不对、读不通的帧即断开 PDP（K-49）。

| kind | 名 | 方向 | 字段 |
|---|---|---|---|
| 0x61 | PDP_REQUEST | 核心→PDP | epoch（engine 本次运行的周期标识）、admission(u64，全局准入序号；与 epoch 一起是请示编号，绑在发出它的那条连接上)、execution_id、workspace_id、sender_uid(u32)、method、scheme、host、port(u16)、path、query、headers(list)、stripped(list)、body_kind、form_keys(list)、body_len(u64)、matched_key_kind(u8)、matched_key、cell(list：state、methods、prefixes、accounts、approval、addresses 六项，同 QUESTION；addresses 是那一格点名的地址，设计 2026-11-05 落盘起)、binding(list：host_port、account、placement，不附凭据时为空，不含真值)、answer(u8：0 没问过用户，1–4 同 ANSWER.verdict)、policy_context(bytes：这一行起行时登记的策略上下文，原样，没登记为空；只取自这一行的 execution，不取自请求的任何字节，K-56；工作区改造加)，以上 22 个字段，策略上下文是第 22 个；宿主文件读（2026-11-04 起，H-09）在其后追加与 QUESTION 第 19–24 个字段相同的 6 个（file_op、alias、path、start、length、object），共 28 个字段。网络请求的正文的同一密封 memfd 随帧经 SCM_RIGHTS 传递（K-50），后 6 个字段为 0、空、空、0、0、空表；文件请求的 HTTP 字段与 binding 照 QUESTION 的写法为空，cell 是对象的状态与审批模式（六项的形状，三个列表与 addresses 都是空表），不带 memfd |
| 0x62 | PDP_ANSWER | PDP→核心 | epoch、admission(u64)、verdict(u8：1 允许、2 拒绝)，共 3 个字段；只接受这条连接上已发出、未答复、请求还在等的编号，每个编号只消费一次，其余丢弃并记诊断；verdict 不是这两个值即断开 |
| 0x63 | TABLE_QUERY | PDP→核心 | workspace_id |
| 0x64 | TABLE_SNAPSHOT | 核心→PDP | workspace_id、status(u8：1 有、2 没有这个工作区、3 工作区不可用、4 超过帧上限)、version(u64，该工作区表的内存版本)、entries(list，每项 key_kind、key 与 cell 的六项，共 8 个元素)、objects(list，宿主文件对象，2026-11-04 起：每项 alias、host_path、type(u8)、ops(u8)、mode(u8：1 允许、2 每次都问、3 拒绝)、available(u8：重启核对没过的为 0)；不含锚所开的目录、device 与 inode)，共 5 个字段；只读，不改变任何状态，不含凭据记录与真值 |

- 没有写表的动词。PDP 断开时它名下未答的请示一律以 unavailable 拒；没有 PDP 连着时请求一直等，PDP 连上后按准入序号补发，直到 connector 的总时限（K-47、C-15）。
- 核心只在 engine 自己的检查（底线、第一个检查点、问用户与第二个检查点）都过了之后才请示；PDP 答允许之后，允许记录先交记录队列、回执覆盖它之后过第三个检查点，才发 ALLOW（648d60f2 4.3 先落盘再放行，K-52）。
- 简易 PDP（pdp/simple.py，bin/simple-pdp，不在 TCB）：以 PDP 专用 uid 连这个口，对每条请示答允许，收到的 memfd 不读即关（P-01）；它不读策略上下文。测试用的变体 `simple-pdp --deny-context VALUE`：策略上下文（第 22 个字段）恰为 VALUE 的请示答拒绝，其余答允许（P-02），文件请求同样。

### 3.7 链路 G：隔间内 MCP server（或 agent）→ 文件 worker，文件口（不可信输入；宿主文件读，2026-11-04 起）

位置与身份（validation.md H-05）：spawner 为每行在部署根的 `rows/<execution>/file.sock` 建一个 AF_UNIX 监听 socket，属 uid_i、0600，listen 之前设 SO_PASSCRED，至多 16 个待接连接；child 把它 bind 进本行隔间的 `/run/w2/file.sock`；文件 worker 以 fd 3 继承它。worker 核验 accept 出的每个 fd 上 SO_PASSCRED=1、从不自己设置，不为 1 即关闭；每条消息每一片的内核章 uid 等于本行 uid_i 且 pid 大于 0，不符即关闭该连接、丢弃已读字节（读取器是 transport.c 的 w2_judge_receive，经 connector/reader.py 的 ProxyReader）；带 SCM_RIGHTS 的消息关闭所收 fd 并断开。每行文件口至多 16 条连接，第 17 条 accept 后即关。

连接模型：一条连接上可以先后发多个请求，同一时刻只有一个：客户端收到上一个请求的回复之后才发下一个，worker 发出回复之后才读下一帧。每个请求恰好一个回复帧，没有序号字段，连接内按次序对应。MCP server 的用法是每次工具调用开一条新连接，先发 FILE_LIST_OBJECTS，路径对上了再在同一条连接上发 FILE_LIST 或 FILE_READ（对象清单不缓存）。客户端在 worker 等核心时断开，worker 向核心撤回这个请求（FILE_WITHDRAW）。

编码同 §2：整数以大端定长字节放在一个 field（u8、u32、u64 的 flen 分别为 1、4、8），宽度不对即读不通；列表是一个 field，`count:u32be` 后接 count 个 `ilen:u32be bytes[ilen]`，列表项本身是列表时，项的 bytes 是一个完整的列表编码（同 §3.6 TABLE_SNAPSHOT 的 entries）。alias 是 ASCII；path、host_path 与目录项的 name 是宿主文件系统的原始字节，不转码、不规范化。

请求（MCP server → worker）：

| kind | 名 | 字段（次序固定） |
|---|---|---|
| 0x71 | FILE_LIST_OBJECTS | （无字段） |
| 0x72 | FILE_LIST | alias、path、start(u32：从第几条起，0 起数)，共 3 个字段 |
| 0x73 | FILE_READ | alias、path、offset(u64)、length(u32)，共 4 个字段 |

回复（worker → MCP server）：

| kind | 名 | 字段（次序固定） | 回答 |
|---|---|---|---|
| 0x74 | FILE_OBJECTS | objects(list，每项是 5 项的列表：alias、host_path、type(u8：1 文件、2 目录)、ops(u8：位 1 读、位 2 列目录)、mode(u8：1 允许、2 每次都问))，共 1 个字段 | FILE_LIST_OBJECTS |
| 0x75 | FILE_ENTRIES | more(u8：0 或 1)、entries(list，名与类型交替：name、type(u8：1 普通文件、2 目录、3 符号链接、4 其他、0 未知)；项数是条数的两倍)，共 2 个字段 | FILE_LIST |
| 0x76 | FILE_DATA | total_size(u64)、data，共 2 个字段 | FILE_READ |
| 0x77 | FILE_REFUSED | reason(u8，理由码，同 §3.8 FILE_DENY 的 1–13)，共 1 个字段 | 三种请求都可以 |

字段语义：
- FILE_OBJECTS：核心的 FILE_OBJECT_LIST 的对象表，原样转出：本行工作区里状态为允许、可用、审批模式为"不问"或"每次都问"的对象（H-21）；host_path 是用户登记时给的绝对路径（未解析链接），不含锚的目录、device 与 inode；次序随核心的表，MCP server 不依赖次序。传送行回空表。
- FILE_ENTRIES：从第 start 条起（os.scandir(fd) 的次序，不含 . 与 ..）至多 1000 条；more 为 1 当且仅当第 start+1000 条（从 0 数）存在。start 等于或超过条数时回空表、more 为 0。name 是 os.fsencode(DirEntry.name) 的字节。type 只取目录项自带的类型（d_type），不跟随符号链接；目录项不带类型、要再查才知道且查不成的，标 0 未知（H-16）。不回大小。目录在两页之间变动时，分页可能漏条或重条（局限，不处理）。
- FILE_DATA：total_size 是读时 fstat 的 st_size；data 是 pread 从 offset 起至多 length 字节（到文件尾即短；offset 在文件尾或之后为空）。
- FILE_REFUSED：核心的 FILE_DENY 的理由码原样转出；worker 自己只给两种：等核心超过总时限（330 s，同 C-15）回 timeout（撤回之后），核心交来的 fd 与请求的操作不符（读的不是普通文件、列的不是目录、FILE_ALLOW 的 op 不是这个请求的）回 unavailable。

上限：

| 项 | 上限 | 谁核 |
|---|---|---|
| 请求帧（length 字） | 8 KiB = 8192（FILE_READ 的最大正常形状 1 + (4+64) + (4+4096) + (4+8) + (4+4) = 4189） | worker：先读长度字，超了即断开、不读正文 |
| 回复帧（length 字） | 1 MiB = 1048576（最坏的 FILE_OBJECTS：128 个对象，每项 4191 字节，共 536,457 字节；FILE_DATA 至多 262,161；FILE_ENTRIES 至多 264,014） | MCP server（worker 自己不会发超的） |
| alias、path、length 的内容 | 别名文法 1–64 字节 `[A-Za-z0-9_-]`；相对路径规则（§3.8）；读的长度 1–262144 | 核心，第一个检查点，拒绝进记录（H-07）；worker 不核 |
| 每页条数 | 1000 | worker |

读不通的处理（worker 一侧；H-04）：帧的边界定不出的（长度字为 0 或超 8 KiB、kind 不是 0x71–0x73、带 fd、章不符），以及帧完整、kind 对，但字段数或整数宽度不对的，都直接断开这条连接，不回复，不交核心。读得通的帧，worker 不核 alias、path 与 length 的内容，按字段原样组成 FILE_ASK 交核心（FILE_LIST 的 u32 start 扩成 u64，length 为 0；FILE_LIST_OBJECTS 的 alias、path 为空，start、length 为 0），由核心按规则拒并写记录：别名不合文法回 not_registered，相对路径不合规则（含文件对象带非空路径）回 bad_path，长度为 0 或超 262144 回 too_large。

worker 怎么用核心交来的 fd（H-15、H-16）：FILE_ALLOW 带来的 fd 先 fstat，读要普通文件、列要目录，不符即以 unavailable 结束；读用 os.pread，列用 os.scandir(fd)；回复发出之前关掉这个 fd，请求之间不持任何目标 fd。worker 不按路径打开、stat 或列任何东西。

**spawn_prepared 的三个 fd**（spawner 与核心之间的 JSON 控制记录，不在本文编码之内，这里只记 fd 的约定）：spawner 经控制通道发给核心的 spawn_prepared 记录恰带三个 fd，次序是：agent 侧控制通道的 engine 端、判定口（链路 B）的核心端、文件判定口（链路 H）的核心端；记录的 JSON 带 connector_pid 与 worker_pid（validation.md H-06）。三个都必须是未命名、已连接、SO_PASSCRED=1 的 AF_UNIX stream；个数不是三或种类不符即判控制故障，所收 fd 全关（transport.c 的 w2_recv_control3）。别的记录不带 fd。worker 退出时 spawner 发 worker_exited（字段同 connector_exited），排在该行的 execution_empty 之前。

### 3.8 链路 H：文件 worker ↔ 核心，文件判定口（每行一对 socketpair；宿主文件读，2026-11-04 起）

spawner 为每行建一对 socketpair，核心那端在起 worker 之前设 SO_PASSCRED 与非阻塞，随 spawn_prepared 作第三个 fd 交给核心（engine/lifecycle.py 装成这一行的 FilePort），worker 那端作 fd 4 交给文件 worker（validation.md H-06）。worker 一端按帧读：先读长度字，再恰好读这一帧的字节，与帧的头几个字节一起到的 fd 属于这一帧；FILE_ALLOW 不恰带一个 fd、别的帧带 fd、fd 在帧中间到、种类不在本表、帧读不通、理由码不在 1–13，worker 关掉所收的全部 fd 并退出；文件判定口关闭，worker 即退出（同 C-28）。没人等的答复（撤回与答复交叉）所带的 fd 当场关掉。核心以 transport.c 的 w2_judge_receive 逐片核内核章：uid 等于 worker 专用 uid 且 pid 大于 0，不符即关该行。成帧同 §2，帧上限 1 MiB。validation.md 的"H 组"是 must 的编号，与这里的"链路 H"不是一回事。

| kind | 名 | 方向 | 字段（次序固定） |
|---|---|---|---|
| 0x81 | FILE_ASK | worker→核心 | seq(u64)、sender_uid(u32，worker 从文件口逐片核过的本行 uid_i)、op(u8：1 列出对象、2 列目录、3 读)、alias、path、start(u64：读的起始位置或列的起始序号)、length(u32：读的长度，列为 0)，共 7 个字段；不带 fd。列出对象时 alias、path 为空，start、length 为 0 |
| 0x82 | FILE_WITHDRAW | worker→核心 | seq(u64)，撤回这条口上的那个请求 |
| 0x91 | FILE_ALLOW | 核心→worker | seq(u64)、op(u8)；恰带一个 fd，经 SCM_RIGHTS：核心打开的目标（读：只读打开的普通文件；列：只读打开的目录） |
| 0x92 | FILE_DENY | 核心→worker | seq(u64)、reason(u8，理由码 1–13，词表见下) |
| 0x93 | FILE_OBJECT_LIST | 核心→worker | seq(u64)、objects(list，每项本身是一个 list：alias、host_path、type(u8)、ops(u8)、mode(u8：1 允许、2 每次都问)) |

- 核心只按字段表与整数宽度读 FILE_ASK：字段数、宽度不对，op 不是 1–3，列出对象带了 alias、path、start 或 length，列目录带了 length，sender_uid 不是本行 uid，带 fd，种类不在本表，seq 不严格递增（FILE_ASK 的 seq 由 worker 分配，从 1 起，与链路 B 的 seq 各自计数），都判文件判定口故障、关行（worker 在 TCB 内，交来读不通的帧就是缺陷，H-04）。alias、path 与 length 的内容不在这里核：读得通的帧照收，由核心的第一个检查点按规则拒并写记录（H-07）。FILE_WITHDRAW 的 seq 未知的丢弃并记诊断（withdraw_ignored，带 port 为 file，与链路 B 的同号区分），不断开。
- 列出对象由核心按本行工作区的表直接作答，不进队列、不问用户、不请示 PDP：列审批模式为允许与每次都问、且可用的对象；传送行回空表；每次作答记一条 file_objects_listed（H-21）。列目录与读进本行的同一条队列，与链路 B 的请求一次一个（K-15）；撤回、排队与在途查找一律按"口加 seq"，不跨口。
- 核心对列目录与读的判定：第一个检查点（传送行回 not_registered；工作区不可用回 unavailable；别名没登记或不合文法回 not_registered；对象不可用回 unavailable；对象记录为拒绝回 recorded_deny；操作不在对象的操作里回 op_not_granted；相对路径不合规则回 bad_path；读的长度不在 1–262144 回 too_large）→ 每次都问的经管理口提问（§3.4 QUESTION 的文件字段）→ 请示 PDP（§3.6 PDP_REQUEST 的文件字段）→ PDP 答允许后再过一次第一个检查点、核对对象还是基线那一个，然后从对象的锚往下打开目标（libw2sandbox 的 w2_open_beneath：openat2 带 RESOLVE_BENEATH、RESOLVE_NO_SYMLINKS、RESOLVE_NO_MAGICLINKS，不带 RESOLVE_NO_XDEV；先以 O_PATH 打开、fstat 核类型，读只收普通文件、列只收目录，对了才经 /proc/self/fd 重开为 O_RDONLY，列加 O_DIRECTORY，都带 O_CLOEXEC、O_NOCTTY、O_NONBLOCK；目录对象的空路径打开对象本身，文件对象打开登记的文件名）→ 允许记录落盘（读带按打开时 fstat 算的实际长度 max(0, min(length, 文件大小 − start))，列带起始序号）→ 第三个检查点（版本变了就重做第一个检查点，对象的别名、锚的 device 与 inode、文件名、状态与审批模式都没变才过）→ FILE_ALLOW。打开之后任何一步没过、行关闭或撤回，都关掉已打开的 fd、写拒绝记录；FILE_ALLOW 交给口之后核心关掉自己的那份；口的发送缓冲区满、FILE_ALLOW 只能排队时，队列持有自己的副本，这个请求在带 fd 的第一段真正发出之前仍按"口加 seq"可找到、没有完成：worker 撤回即取消队列项、关掉副本、记撤回（stage 为 delivering），行关闭时先把全部待交付的队列项取回、关掉副本，再逐条写拒绝记录并回 unavailable，每个 seq 恰一帧；真正发出之前按版本号再核一次（版本没变即发；变了就重做第一个检查点，与第三个检查点同样比对），没过就关掉副本、以 FILE_DENY(policy_changed) 代替这一帧、写拒绝记录；口关闭时排队的副本一并关掉（H-07、H-08、H-10、H-11、H-19）。
- 相对路径规则：按 `/` 分段，每段非空，不是 `.` 或 `..`，不含 NUL，总长不超过 4096 字节，不以 `/` 起；空串指对象本身；文件对象的相对路径只能为空。非 ASCII 字节照收。
- 理由词（码按次序 1–13，H-18）：not_registered、op_not_granted、bad_path、outside_or_symlink、wrong_type、too_large、user_denied、pdp_denied、recorded_deny、policy_changed、unavailable、timeout、not_found。打开失败的 errno 换词：ELOOP、EXDEV 为 outside_or_symlink；ENOENT 与读时的 ENOTDIR 为 not_found；EISDIR、EOPNOTSUPP 与列时的 ENOTDIR 为 wrong_type；ENAMETOOLONG（内核自己的路径上限，含 NUL 的 4096 字节或单段超过 255 字节）为 bad_path；其余为 unavailable。细的原因（errno 名）只进核心的 trace。
- 记录里的 alias 与 path 按 latin-1 解码成字符串（encode('latin-1') 还原原字节）；不记读到的内容，也不记列出的名字（H-20）。

## 4. 文法（REQUEST 的逐字段校验，C-05）

读不通的定义：下列任一条不成立。校验在替换、匹配之前；整帧拒，不产生 JUDGE：向前端回明确拒绝、原因词 clause，回完再断开该连接；字段数不对的完整帧同样如此。帧的边界都定不出来的（长度不合、超帧上限、种类不在本链路、带 fd、章不符）直接断开（validation.md C-36）。

| 字段 | 文法 | 拒绝项 |
|---|---|---|
| method | RFC 9110 token：`1*tchar`，tchar = `!#$%&'*+-.^_\`\|~` 或 DIGIT 或 ALPHA；长度 1–32 | 下列三个不分大小写在 schema 层拒（各接收方对小写方法的处置不一）：`CONNECT`（前端已终结 TLS，connector 不做隧道）；`TRACE` 与 IIS 的 `TRACK`（C-34：上游会把收到的请求连同替换后的真值回显进隔间）。其余大小写敏感，`get` 不等于 `GET` 且照原样发出。表条目的方法集合与请求共用这条检查 |
| scheme | `http` 或 `https`（小写） | 其余一律拒 |
| host | IPv4 点分十进制（四段 0–255，无前导零）；或 IPv6 字面量（不带方括号、不带 zone 后缀，RFC 5952 规范文本：小写、最长零段压缩；IPv4 映射地址 `::ffff:a.b.c.d` 拒（读法扩展，审阅点 A，报用户），内核把它连到 IPv4 的 a.b.c.d，同一目的地只留点分十进制一种写法。NAT64 众所周知前缀 `64:ff9b::/96` 的字面量同样拒；部署配置的其他 NAT64 前缀（--nat64-prefix）里的字面量文法照收，connector 在校验阶段同样拒（clause，提示改写成 IPv4 地址；§3.2"条款 7 的连接判定"，C-35），这一步不在规范形式层，因为文法不知道部署配置；主机名解析出的这类地址由 C-19 的地址过滤按内嵌 IPv4 判断）；或域名：1–253 字节，标签以 `.` 分隔，每个标签 1–63 字节、只含 `a-z0-9-`、首尾不为 `-`（A-label 形式的字节约束；`xn--` 标签的 punycode 部分须能解码并重编码为自身。读法变更（审阅点 A，报用户）：这里不核 IDNA2008 的字符许可、U-label 规范化与上下文规则（RFC 5890 §2.3.2.1），因为匹配只比较字节串、一个 host 一种写法即可，而标准库没有 IDNA2008 的表；设计 3.9 "域名已转 A-label" 在本表读作字节形式的要求，前端负责 IDNA 转换，connector 不以此为校验保证） | 任何非 ASCII 字节、大写字母、尾随 `.`、空标签、`%`（zone 后缀）、非规范的 IP 文本、全部标签都是十进制或 `0x` 十六进制数的名字（glibc 会把它当地址解析） |
| port | u16，1–65535 | 0 |
| path | 以 `/` 起；字节集合为 RFC 3986 的 `pchar / "/"`：unreserved（`A-Za-z0-9-._~`）、pct-encoded（`%HH`，H 为十六进制）、sub-delims（`!$&'()*+,;=`）、`:`、`@`；长度 ≤ 8 KiB | 条款 2：`%2e`、`%2E`（编码的点）、`%2f`、`%2F`（编码的斜杠）、反斜杠 `\`、空段（两个相邻 `/`）、不完整或非十六进制的 `%` 序列。条款 2 的读法扩展（审阅点 A，报用户 2026-10-29）：任何能在路径里明文出现的字节的 `%XX` 形式（非保留字符如 `%41`、`%74`；子分隔符如 `%2C`、`%3D`、`%2B`、`%3B`；以及 `%3A`、`%40`。上游按 RFC 3986 §6.2.2.2 解码非保留字符，WSGI 一类上游在路由前把保留字符也解码，解码后与明文等价，会绕过 K-43 的前缀匹配与条款 10 的端点相等；只有不能明文出现的字节才允许编码：空格 `%20`、`?` `%3F`、`#` `%23`、控制字符、非 ASCII，`%` 自身写作 `%25`）、编码的反斜杠 `%5c`、编码的 NUL `%00`（上游截断读法）、路径里任何位置的 `;`（路径参数：servlet 容器一类上游把段内 `;` 之后的部分剥掉再路由，`/admin;x/secret`、`/..;/` 在上游是另一条路径）一律拒。代价：把 `+`、`:`、`@`、`,` 等写成 `%XX` 的客户端记为适配失败，例如 pip 24.0 改写索引链接时把本地版本号里的 `+` 写成 `%2B`，从 PyTorch 一类索引装带本地版本号的 wheel 会失败（PyPI 不允许本地版本号，不受影响）。范围：一种写法的保证只对按 RFC 3986 解码一次的上游成立；解码两次（`%252e`）、解码后去空白或截断的上游是声明的残余（标准库 wsgiref 实测只解码一次）；条款 2 的读法放宽（同样报用户）：末尾一个 `/` 不算空段（/v1/ 一类路径常见，K-25 的端点相等比较去掉末尾斜杠后再比）。归一化：校验通过后把 `%HH` 的十六进制统一为大写，再做去点段（RFC 3986 5.2.4）；归一化后的路径是匹配对象也是发出对象（C-08） |
| query | 可缺省；字节集合为 `pchar / "/" / "?"`，`%` 序列同上；长度 ≤ 8 KiB | 非法字节；不参与匹配，原样发出 |
| headers | 名：token 且全小写，1–128 字节；值：RFC 9110 field-value，字节为 VCHAR（0x21–0x7E）、obs-text（0x80–0xFF）、SP、HTAB，且首尾不为空白，长度 ≤ 8 KiB；名的个数 ≤ 128；名值总字节 ≤ 64 KiB | 条款 3 禁用名（整帧拒）：`host`、`transfer-encoding`、`content-length`、`connection`、`keep-alive`、`te`、`trailer`、`upgrade`、`expect`（条款 3 清单外的新增禁用名，审阅点 A，报用户：100-continue 归前端，3.9 支持清单）、以 `proxy-` 起的任何名；条款 3 剥除名（剥掉并记录，不拒）：`x-http-method-override`、`x-http-method`、`x-method-override`；`authorization` 至多一个（实施注意 6）；`x-api-key`、`content-type` 也各至多一个（工程新增，不是实施注意 6 的原句：x-api-key 是三个放置位之一，两个值时替换目标不唯一；条款 10 的表单检查只认一个 content-type）；值含 CR、LF、NUL 整帧拒 |
| body | 字节串，长度 ≤ 64 MiB | 超限拒；每行在途正文总量 > 256 MiB 时该请求拒（C-07） |

## 5. 派生字段（C-12）

- body_kind：`content-type` 头值按 RFC 9110 媒体类型解析（按引号状态切分 `;`，`type/subtype` 后每个非空参数段须读得通：`token=token` 或 `token=quoted-string`，空参数段按 RFC 允许），取 `type/subtype`，小写，参数丢弃；没有该头为空串；有该头而 type/subtype 或任一参数解析不出即整帧拒（不落成空串，否则条款 10 的表单检查可被躲开）；该头至多一个。
- form_keys（线上表示：每个键是百分号解码、`+` 还原为空格之后的字节串，不再转义，NUL 与非 ASCII 字节原样进列表项；connector 内部以 latin-1 解码成 str 保存，发帧时按 latin-1 编回，逐字节不变）：只当 body_kind 等于 `application/x-www-form-urlencoded` 时解码：正文按 `&` 切分，每项取 `=` 之前的部分，`+` 换成空格，`%HH` 解码（非法的 `%` 序列按原字节保留），得键名列表（去重、保序）；值一律不取。预算（工程新增，不在工程项 4 的数值里）：扫描的项数 ≤ 8192（不论是否重复，限住 CPU），单个键编码后 ≤ 1 KiB，去重后键数 ≤ 4096，解码后全部键合计 ≤ 64 KiB，任一超出整帧拒。表单的 `charset` 参数若不是 ASCII 兼容的编码（缺省、utf-8、us-ascii、iso-8859-1、windows-1252 之外）整帧拒（新增拒绝条件，审阅点 A，报用户：按声明字符集解码参数名的上游会读到 `grant_type`，而键名检查看到的是别的字节）。带 `content-encoding`（非 identity）的表单正文第一版整帧拒（新增拒绝条件，审阅点 A，报用户）：编码后的正文看不到键，上游解压后能看到（条款 10 的两道检查之一会被躲开）。其他 body_kind 为空表。
- 尺寸闭合：一个通过校验的 REQUEST 编码成 JUDGE 后的上界是：头 64 KiB 加每对 8 B 的长度字；stripped 去重后至多 3 个名；path 与 query 各 8 KiB；form_keys 64 KiB 加每键 4 B 的长度字；body_kind ≤ 255 B（新增上限：type/subtype 合计 ≤ 255 字节，超出整帧拒；IANA 登记的媒体类型远短于此）；定长字段与长度字不足 1 KiB；合计低于 230 KiB，QUESTION 再加 execution_id、workspace_id、matched_key（各 ≤ 4 KiB）、凭据绑定（< 1 KiB）与命中的那一格（条目的 methods、prefixes、accounts、addresses 连长度字合计 ≤ 256 KiB，登记时超出即拒，工程默认）仍低于 1 MiB 的链路 B、D 帧上限；正文不在帧内。测试里构造最大请求并编码成完整 JUDGE 与 QUESTION 帧核对。
- 两个派生字段只供条款 10 的两道检查使用（K-25），不进匹配。

## 6. 上限（工程项 4）

| 项 | 上限 |
|---|---|
| method | 32 B |
| host | 253 B |
| path、query | 各 8 KiB |
| 头个数 / 头总字节 | 128 / 64 KiB |
| 头名 / 头值 | 128 B / 8 KiB |
| 表单键名个数 / 单键 / 合计（派生字段） | 4096 / 1 KiB / 64 KiB |
| 正文 | 64 MiB |
| 每行在途正文总量 | 256 MiB |
| 每行同时连接 | 64 |
| 每行排队请求（含等人的那一个） | 32 |
| 每条 fd 同时请求 | 1 |
| 链路 A 帧上限 | 64 MiB + 128 KiB |
| 链路 B、D 帧上限 | 1 MiB（正文不在帧内） |
| 链路 H 帧上限（宿主文件读） | 1 MiB |
| 链路 G 请求帧 / 回复帧上限（文件口） | 8 KiB / 1 MiB |
| 每行文件口同时连接 / 每条连接同时请求 | 16 / 1 |
| 一次读 / 一次列（宿主文件读） | 1–262144 字节 / 1000 条（带"还有"的标记） |
| 相对路径 / 登记的宿主路径 / 别名（宿主文件读） | 4096 B / 4096 B / 1–64 B |
| 每个工作区的宿主文件对象 | 128 |
| 每条条目点名的地址（ENTRY_PUT 的 addresses；ALLOW、ALLOW_NOCRED 的 named） | 64 项（登记时按写的项数算，去重之前；工程默认，validation.md K-57） |

## 7. 结果类别

- 回前端的 category（RESP_HEAD）：远端响应、明确拒绝、传输错误、结果未知四种（C-24）。
- 回核心的 REPORT result：远端响应、传输错误、结果未知、未发出四种（C-27）；明确拒绝由核心自己知道，不回报。
- 读法（第 4 块定）：请求的任何字节发出之前失败为传输错误；发出之后、完整的响应头到达之前失败（含上游关闭、畸形响应头、100 以外的 1xx）为结果未知，因为上游可能已经执行；响应头到达之后回报远端响应与状态码，正文随后被切断（上游失败、撤销）只由前端看到（RESP_END 之前关连接），REPORT 不另设类别。
- 替换之后的任何异常只映射成类别，不取异常消息（C-23）。
