# mcp-go — 隔间内的 MCP server（宿主文件只读）

给隔间里的 agent 提供三个 MCP 工具，经本行的文件口（链路 G）向文件 worker 请求读宿主上用户登记的文件与目录。只用 Go 标准库，静态链接。不在 TCB，只管 utility：它不持任何宿主 fd，也不做任何判定；它发出的每个请求都由 worker 与核心当不可信输入校验，所以 agent 绕过它、直接对文件口说链路 G，是允许且等价的。计划见仓库根的 .goals/plans/engine-v3-n16-file-read.plan.md（第 2 段 2.3c）。

## 启动形式

```
engine-mcp <文件 socket 路径> <端口> <ready 文件>
```

与 frontend-go 相同的三项尾参数。监听 127.0.0.1:<端口>，监听建立之后以 O_CREAT|O_EXCL、0644 建 ready 文件；文件已存在、端口被占或参数不合（端口不在 1–65535）都在建 ready 之前退出（退出码 1 或 2）。日志写 stderr，在隔间里是 /dev/null。

在隔间里（validation.md H-23）：种子里放在 /runtime/mcp/engine-mcp；目录的 `mcp_server` 写可执行文件与 argv（同 `frontend` 的形状），`mcp_port` 写端口（catalog.c 核它在 1–65535、不等于 `proxy_port`；测试与门用 3129）。child 在降权、装好 seccomp、收到 COMMIT 之后，于前端之后以同一处 start_helper 拉起它（只持 stdio，以 uid_i，在 agent 的 seccomp 名单下），在 argv 末尾补 `/run/w2/file.sock`、端口与 `/tmp/.w2-mcp-ready`；前端与它两份 ready 文件都在才 exec agent，它在写 ready 之前退出，起行即在 helpers 阶段失败。

## 构建与测试

```sh
# 工具链同 frontend-go：go1.27.2 linux/amd64，/usr/local/go
cd ExperimentLab/engine-v3/mcp-go
CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -buildvcs=false -ldflags='-s -w' -o engine-mcp .   # 种子用的旗标，静态 ELF，约 6.4 MiB
CGO_ENABLED=0 GOTOOLCHAIN=local go test ./...
```

种子用的构建由 checks/gate_seed.py 的 mcp_build 做（门与 engine 检查都调它），旗标是上面那一行：比前端多 `-ldflags='-s -w'`，去掉符号表与 DWARF（只有调试器读；Go 的 panic 栈来自 pclntab，不受影响），省约 3 MiB 种子空间（不去符号约 9.4 MiB）。构建出的二进制不进仓库。测试用一个假的文件口（测试里起的 unix socket 服务端，按 worker 的 8 KiB 请求上限读帧），不需要 engine。结果见 runs/20261103T201435Z-mcp-go-unit/ 与理由词对齐之后的 runs/20261103T215903Z-mcp-go-reasons/。

## 做法

| 文件 | 内容 |
|---|---|
| main.go | 命令行、监听、ready 文件、http.Server |
| mcp.go | Streamable HTTP 的无会话子集：单一端点 /mcp；POST 收一条 JSON-RPC，请求以一个 application/json 应答，通知与客户端的应答回 202；GET（服务端通知流）与 DELETE（结束会话）回 405；带 Origin 头而不是 http://127.0.0.1:<端口> 或 http://localhost:<端口> 的回 403；正文上限 1 MiB；不发 Mcp-Session-Id。认 initialize、ping、tools/list、tools/call |
| tools.go | 三个工具；宿主路径到对象的对应；理由词与每个词的下一步；读到的内容按文本或 base64 返回 |
| wire.go | 链路 G 的成帧与一次工具调用的连接 |

**协议版本。** 只说 2025-11-25：initialize 不论客户端提出哪个版本都回它；请求头 MCP-Protocol-Version 是别的版本的，回 400（传输规范的要求）。依据是 Claude Code 2.1.312 的实际行为：它先发一个带 mcp-method 头、版本 2026-07-28 的 server/discover 探测，得 400 就改走经典的 initialize，提出 2025-11-25，之后的请求都带这个版本（checks/gate_items.py 的 j_mcp 一项，以及 runs/20261102T150821Z-gate-rework 里 deepwiki 那一轮的请求头）。上面的运行目录里，真的 Claude Code 2.1.312 对本程序做 `claude mcp list` 得 ✔ Connected，往返与此相同。

**工具。**

- list_host_objects：无参数。回 JSON 文本：每个对象的宿主路径、类型、操作（read，目录另可有 list）、是否每次都问用户。
- list_host_directory：path（绝对宿主路径），start（默认 0）。回 JSON 文本：至多 1000 条的名字与类型（file、directory、symlink、other、unknown），不给大小；还有后续时 more 为 true，并给 next_start。名字不是 UTF-8 的放在 name_base64 里（这种名字写不进 JSON 字符串里的路径，用这三个工具读不到它）。
- read_host_file：path，offset（默认 0），length（1–262144，默认 262144）。回两个文本块：第一块说明返回的字节区间、文件总长与下一次的 offset；第二块是内容。读回的字节整体判 UTF-8：合法的按文本返回，否则整段按 base64（标准字母表、带填充）返回并在第一块注明；读在一个多字节字符中间截断的，这一次就整段按 base64 返回，不丢字节，下一次的 offset 紧接读回的最后一个字节。

**路径到对象。** 每次工具调用开一条到文件口的新连接，先要对象清单（不缓存：用户可以在运行中改），再按路径段匹配：宿主路径等于登记路径，或以"登记路径 + /"起头（所以 /a/bc 不在 /a/b 之下）；取最长的登记路径；文件对象只认与登记路径逐字节相等的整串；输入不做任何修剪。剥掉前缀与其后的 / 之后，余下的每个字节原样交给 worker，不做规范化（..、.、空段与末尾的 / 原样交出，由核心按路径规则以 bad_path 拒）。对不上任何登记路径的，当场回 not_registered，不发给 worker；余下部分超过 4096 字节的当场回 bad_path（发出去会超 worker 的请求帧上限）。

**拒绝。** 工具错误（isError）的文本与 connector 的拒绝正文同一格式：`engine refused`、`reason: <词>`、这个词的下一步。词是 worker 回的理由码按表转的，表是 SPEC-canonical-form.md §3.8 的 13 个码与词（码 1–13：not_registered、op_not_granted、bad_path、outside_or_symlink、wrong_type、too_large、user_denied、pdp_denied、recorded_deny、policy_changed、unavailable、timeout、not_found；validation.md H-18），与核心、worker 同一张，TestEachCodeShowsAsSpecWord 按码逐个核；表外的码显示成 unknown_reason_<码>。文件口连不上、中途断开或回复读不通时报 unavailable（码 11），并多一行说明文件口没有回答。

**上限。** 回复帧 1 MiB（最坏的对象清单：128 个对象、每个 4096 字节宿主路径，约 524 KiB）；对象至多 128 个；一次读的数据至多 262144 字节；一页至多 1000 条。超了的回复当读不通，长度字超上限的帧不读正文。等一个回复至多 345 s，比 worker 等核心的 330 s 长；agent 断开 HTTP 请求时，到文件口的连接随之关闭。

## 隔间里的端到端（2.3c）

engine 检查的 mcp 一例（checks/run_engine_checks.py、checks/file_read_cases.py、engine/testing/scenario.py:mcp）：这一行用部署的 workload seccomp 名单（checks/workload-allow.txt），种子里的本程序由 child 拉起、在名单下起来并作答；夹具以 HTTP/1.1 对 127.0.0.1:3129/mcp 发 initialize、notifications/initialized、tools/list 与六次工具调用，经本行的真文件 worker 与真核心读到登记目录里的文件；`..` 与目录内指向外面的符号链接被核心拒（bad_path、outside_or_symlink，记录里有），前缀外的绝对路径由本程序回 not_registered。见 runs/20261103T221228Z-engine-mcp-server、runs/20261103T222000Z-engine-mcp-server-3。

## 没验证的

- 隔间里的 `claude -p` 会话连 127.0.0.1 是否绕开代理：`claude mcp list` 在带代理变量与 NO_PROXY=localhost,127.0.0.1 时连得上（runs/20261103T201435Z-mcp-go-unit），会话那条路径没测（2.3d 的门）。
- 真客户端的 tools/call 往返：`claude mcp list` 只走到 tools/list；隔间里的端到端用的是 C 夹具，不是 Claude Code（2.3d 的门）。
- 非 UTF-8 内容的 base64 一支只有 Go 测试，没在隔间里走过。
- 内存只在 WSL 里、隔间外量过一次（空闲 VmRSS 约 5.6 MiB，未去符号的构建）。
