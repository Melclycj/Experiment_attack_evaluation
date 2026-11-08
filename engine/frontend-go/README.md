# frontend-go — Go 版隔间内前端

与 `../frontend/engine_frontend.py`（mitmproxy 加 addon 加 translator）对外约定相同的隔间内 HTTP 前端，只用 Go 标准库（`net/http`、`crypto/tls`、`crypto/x509` 等），没有第三方模块。不在 TCB：它产生的规范形式帧由 connector 当不可信输入逐字段校验（SPEC-canonical-form.md §1、§3.1），所以换实现不重开可信基的证明。计划与进度见仓库根的 .goals/plans/engine-frontend-go.plan.md。

本目录在 engine-v2-go 里是默认前端：种子与门（checks/gate_seed.py、checks/run_gate.py 的 --frontend）用它，workload seccomp 白名单已按它重推（名字不变），engine-v2 之前全过的检查都已以它重跑通过；结果与 run 目录见 ../validation.md 文末「Go 前端版记录」。

## 构建与测试

```sh
# 工具链：go1.27.2 linux/amd64（官方 tarball，sha256 ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5，装在 /usr/local/go）
cd ExperimentLab/engine-v2-go/frontend-go
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o engine-frontend .   # 静态链接的 x86-64 ELF，约 9.4 MiB

# 前端集成测试（与 checks/run_engine_checks.py 的单元套件同一调用方式，以 uid 1000 在 WSL 里跑）
cd ExperimentLab/engine-v2-go
W2_FRONTEND_IMPL=go     python3 -m pytest -p no:cacheprovider -q tests/test_frontend.py   # 默认值；夹具现编本目录，W2_FRONTEND_GO_BIN 可指定已编好的二进制
W2_FRONTEND_IMPL=python python3 -m pytest -p no:cacheprovider -q tests/test_frontend.py
```

`../tests/test_frontend.py` 只改了启动夹具（`frontend_command()`），断言一条没动；两种实现都要 mitmproxy 的 venv，因为签证书池的 `make_ca_pool.py` 在 venv 里跑。

## 做法

| 文件 | 内容 |
|---|---|
| main.go | 命令行、CA 准备、监听 127.0.0.1:port、建 ready 文件、一个只开 HTTP/1 的 `http.Server` 同时服务监听口与隧道 |
| exchange.go | translator 的对应物：一个 HTTP/1.1 请求 → 一个 REQUEST 帧 → RESP_* 帧 → 一个流式 HTTP/1.1 响应；错误映射；截断时 `panic(http.ErrAbortHandler)` 让 net/http 不写最后的 0 chunk 就关连接 |
| tunnel.go | CONNECT：立刻回 200、不连任何地方；按收到的第一批字节判断是 TLS、HTTP 还是别的（mitmproxy `next_layer` 的规则），字节少到还判不出（不足三个字节，或三个字母之后还没有换行）就接着读，最多读满读缓冲、等 30 s；TLS 用本次 execution 的 CA 终结，HTTP 交回同一个 `http.Server`，别的直接关 |
| certs.go | `<confdir>/mitmproxy-ca.pem` 的布局（与 mitmproxy 相同）、叶证书签发与缓存、ALPN 选择 |
| host.go | 目的地与主机名：移植 mitmproxy 的 `parse_authority`、`is_valid_host`、absolute-form 拆分，以及 translator 的主机、路径归一化 |
| wire.go | 链路 A 的帧编码（SPEC §2、§3.1）与代理路径连接池 |
| measure/ | 边界行为探测脚本 `probe_edges.py`、内存测量脚本 `mem_measure.py` 及其原始输出（下两节的数从这里来） |

行为以 `engine_frontend.py` 的代码为准；它把一大半行为交给了 mitmproxy 12.3.1，那部分按 venv 里 mitmproxy 的源码对齐（mitmproxy 包里 http.py 的 pretty_host、proxy/layers/http/__init__.py 的 CONNECT 与 Expect、addons/next_layer.py、certs.py、addons/tlsconfig.py），再用 `measure/probe_edges.py` 对两种实现各跑一遍、逐项比对。

## 与 Python 版的行为对照

依据一栏：**测试** = `../tests/test_frontend.py` 两实现都过（只对 Go 跑的两条除外，见 F-02 一行）；**实测** = `measure/probe_edges.py` 两实现各跑一次的结果（`measure/probe-python.json`、`measure/probe-go.json`）；**读代码** = 只读了源码，没有跑。

| 行为 | 结论 | 依据 | 说明 |
|---|---|---|---|
| 启动参数 `[--ca-dir] [--confdir] [--translator-port] [--log-level] <proxy socket> <port> <ready file>` | 一致，一处不同 | 测试 | Go 接受后两个选项但不用（没有 translator 口；自己的日志总开）。不同：Go 的选项必须写在位置参数之前，argparse 允许穿插；child.c 与测试都把选项写在前面 |
| ready 文件 | 一致，错误路径不同 | 测试、读代码 | 监听建立后以 `O_CREAT\|O_EXCL`、0644 建。文件已存在时 Python 的 addon 报错但进程照跑（读代码），Go 退出码 1 |
| 监听地址 | 不同 | 测试、实测 | 都在 127.0.0.1:port；Python 另开 127.0.0.1:port+1 给 translator，Go 没有这个口。测试里 Python 6 次有 1 次因 port+1 被占而起不来，Go 6 次全过 |
| 本次 execution 的 CA（S-16） | 一致 | 测试 | `--ca-dir` 的 ca.key 加 ca.pem 拼进 `<confdir>/mitmproxy-ca.pem`（0600）后用它签；别的 execution 的 CA 不认（curl 退出码 60）。没有 `--ca-dir` 时自己生成：Python 是 RSA-2048，Go 是 P-256，Go 只写 `mitmproxy-ca.pem` 与 `mitmproxy-ca-cert.pem`，不写 .p12、.cer、dhparam（只影响测试路径） |
| 叶证书 | 一致 | 实测、读代码 | 名字是 SNI（没有 SNI 用本地地址）加 CONNECT 主机，密钥用 CA 自己的，有效期从两天前起 199 天，链为叶加 CA 文件里的全部证书；实测两实现给同一请求的叶证书主体与 SAN 相同 |
| TLS 版本与 ALPN | 一致 | 测试、实测 | 最低 TLS 1.2；只选 HTTP/1 的 ALPN；客户端只报 h2 时不选 ALPN、握手照常；`curl --http2` 得 HTTP/1.1。实测无 ALPN、只报 h2、报 h2 加 http/1.1 三种，两实现结果相同 |
| 规范形式帧与上限 | 一致 | 测试、读代码 | REQUEST 8 个字段；读 RESP_HEAD、RESP_CHUNK、RESP_END；帧上限 64 MiB + 128 KiB，正文上限 64 MiB（超出回 400；Go 在 Content-Length 已超时不读正文、不发 100 Continue） |
| 代理路径连接复用 | 一致 | 测试 | 完整响应后连接放回池里，否则关闭；上游 keep-alive 端到端成立 |
| 明文代理请求（absolute-form） | 一致，一处不同 | 测试、实测 | 不同：Host 头与 URL 的主机不一致时，Python 取 Host 头（mitmproxy `pretty_host`），Go 取 URL 的主机（net/http 已按 RFC 9112 §3.2.2 丢掉该 Host 头）；正常客户端两者相同 |
| 直接对代理口发 origin-form（带 Host） | 一致 | 实测 | 按 Host 头定目的地，scheme 为 http，缺省端口 80 |
| Expect: 100-continue | 一致 | 测试 | 回 100 Continue、收完正文、帧里没有 expect 头 |
| Expect 的其它值 | 不同 | 实测 | Python 丢掉 expect 头照转；Go 由 net/http 直接回 417 |
| 请求头的处理 | 一致，一处不同 | 测试、实测 | 去掉 host、content-length、transfer-encoding、connection、keep-alive、te、trailer、upgrade、expect、三个 x-engine-orig-* 与一切 proxy-*；名转小写，值原样。不同：不同名字之间的顺序，Python 保持客户端顺序，Go 按名字排序（同名多值保序） |
| chunked 上传 | 一致 | 测试 | 收完后以定长正文进帧 |
| 带 trailer 的 chunked 上传 | 不同 | 实测 | Python 连接被断、没有响应；Go 丢掉 trailer、正常转发 |
| Transfer-Encoding 与 Content-Length 同时出现 | 不同 | 实测 | Python（mitmproxy）回 400；Go 按 chunked 收（RFC 9112 §6.3 允许） |
| 折行的头（obs-fold） | 不同 | 实测 | Python 把带 CR LF 的值送进帧、connector 拒帧，客户端得 502；Go 展开成一个空格后照转 |
| 超过 100 个请求头 | 不同 | 实测 | Python 的 translator 回 431；Go 照转，由 connector 的 128 个名的上限把关 |
| 路径 | 一致 | 实测 | 以两个斜杠起的目标缩成一个斜杠（Python 3.12 http.server 的行为，Go 照做）；小写方法原样进帧；客户端写的 x-engine-orig-* 丢掉，其它 x-engine-* 照转 |
| 流式回传 | 一致 | 测试 | 每个 RESP_CHUNK 立刻作为一个 chunk 推出；SSE 5 段间隔 0.4 s 逐段到达 |
| 上游截断（RESP_END 之前断，SPEC §3.1） | HTTP/1.1 一致，HTTP/1.0 不同 | 实测 | HTTP/1.1 客户端：两实现都不写最后的 0 chunk、直接关连接，字节完全相同。HTTP/1.0 客户端：Go 按 RFC 以连接关闭定界，截断与正常结束分不开；Python 对 1.0 客户端也回 HTTP/1.1 chunked（1.0 客户端本不该收到 chunked） |
| 无正文响应 | 一致 | 测试 | HEAD、204、304 不带 Transfer-Encoding |
| 错误映射 | 状态码一致，文字不同 | 测试、实测 | 明确拒绝 → 403 带 x-engine-reason；传输错误、结果未知、响应头读不通、代理路径连不上 → 502；翻译不了 → 400。Python 用自定原因短语加 HTML 错误页，Go 用标准短语加一行纯文本 |
| 远端响应的状态行与头 | 一致，文字不同 | 实测 | 头名都保持 connector 给的小写；不同：头的顺序（Python 按 connector 的顺序，Go 按名字排序）、未知状态码的原因短语（Python 为空，Go 写 `status code N`）、客户端要求 `Connection: close` 时 Go 多回一个 `Connection: close` 头 |
| CONNECT 之后不是 TLS 的流（F-02） | 一致，一处不同 | 测试、实测 | 像 HTTP 的（前三字节是字母、首行有空格）当明文请求经 connector 判，不透传；其余（SSH 开头、首行没有空格）直接关闭；TLS 握手后没有 ALPN 时对解密后的字节用同一规则。HTTP/1.0 的 CONNECT 回 `HTTP/1.0 200`；CONNECT 没写端口回 400。不同（2026-11-03 整体审阅后）：第一批字节还判不出层时（不足 3 字节，或三个字母之后换行还没到），Go 接着读（上限读缓冲与 30 s），Python 按 mitmproxy 收到的第一批字节就判，TLS 首段只有 1–2 字节或首行在空格后被切开时会关连接；tests/test_frontend.py 的两条对应测试只对 Go 跑 |
| WebSocket 升级头 | 一致 | 实测 | upgrade、connection 丢掉，按普通 GET 判与发，sec-websocket-* 照转；上游不会回 101（connector 把 1xx 当结果未知） |
| 非 ASCII 的 Host | 不同 | 实测 | Python 把 UTF-8 字节按 latin-1 读成乱码再转 IDNA（实测得 `xn--b14cher-xwa2143e.test`，不是原名）；Go 由 net/http 回 400。没有引入 golang.org/x/net/idna：正常客户端发的都是 A-label |

## 测试结果（2026-10-31，WSL Ubuntu 24.04，内核 6.6.87.2，Python 3.12.3，go1.27.2）

搬进 engine-v2-go 之前、在 engine-v2 里跑的（那时夹具默认 python）：

- `W2_FRONTEND_IMPL=go`：6 次运行，每次 7 项全过。
- `W2_FRONTEND_IMPL=python`：6 次运行，5 次 7 项全过；1 次在启动时报 `OSError: [Errno 98] Address already in use`——translator 的 port+1 被别的连接占着，是 Python 版原有的偶发问题，Go 版没有这个口。
- 两种实现的警告相同：每个用例结束时测试里的 Core 线程读已关闭的 socket（`Bad file descriptor`），与前端无关。

## 内存对照

同一启动形式（门的形式：`--ca-dir` 加一个 `make_ca_pool.py` 生成的 CA 条目，代理路径上有一个不 accept 的监听 socket），ready 之后空闲 5 s，各读一次 `/proc/<pid>/smaps_rollup`（`measure/mem_measure.py`，原始输出 `measure/mem-result.json`）。Python 是 venv 的 python3.12 跑 `engine_frontend.py`。

| kB | Rss | Pss | Private_Clean | Private_Dirty | 私有合计 | Shared_Clean | 线程 | 到 ready |
|---|---|---|---|---|---|---|---|---|
| Python（mitmproxy） | 73,808 | 65,569 | 12,420 | 50,520 | 62,940 | 10,868 | 2 | 0.47 s |
| Go | 6,900 | 6,896 | 5,272 | 1,624 | 6,896 | 4 | 5 | 0.01 s |

只量了一次、只量了空闲状态。Go 的 Private_Clean 5.1 MiB 基本是二进制的代码页；多个隔间若映射同一个文件（同一 inode），这部分会变成共享的；若每个隔间的运行时树是各自的副本，则仍算私有（推断，没量）。

## 已知差异与没验证的事

- 上表"不同"的各行都是实测的边界输入，正常客户端（curl、Python、node、git、pip 走 HTTP/1.1）不会碰到；所有差异都发生在前端，connector 仍对帧逐字段校验，安全性不依赖前端。
- HTTP/1.0 客户端的截断不可见（见上表）。若要可见，可以在截断时对 1.0 连接发 RST 而不是 FIN；没有做。
- 没验证：TLS 里再套 TLS（Go 会再截取一层，按 mitmproxy 源码推断 Python 也是）；隧道里的 CONNECT（Go 回 400，Python 没测）；隧道内的 absolute-form 请求；超过 64 MiB 的正文（两边都 400，读代码）；并发很高、connector 的 accept 队列满时（Go 的 Unix socket connect 立即失败得 502，Python 的阻塞 connect 会等，推断）；SIGTERM（Go 立即退出，Python 走 mitmproxy 的关闭流程）。
- 在真实隔间里（agent 的 workload seccomp 策略下）跑过门 7.1 与 7.2 十项，全过（../validation.md「Go 前端版记录」）。隔间里运行中的内存没在本机量，归服务器上的 SOTA 内存测量。
- 就绪快带来的一处时序：Go 前端约 0.01 s 就绪，agent 随即 exec，它的第一屏可能在用户附接之前就打印出来，而 pty 转发进程在无人附接时丢掉输出（这是转发进程的设计）。门的运行器为此改为等不到提示就敲空行促它重印（实测）。交互式用户附接后看到的可能是空屏；按一下回车（shell 会重印提示）或改一下窗口大小（Claude Code 收到 SIGWINCH 会重画）应能恢复，这是推断，没有以真人附接实测过。
