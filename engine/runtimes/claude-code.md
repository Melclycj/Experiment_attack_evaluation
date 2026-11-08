# Claude Code 的 runtime 说明

在 engine 的隔间里运行 Claude Code，至少要什么：种子里放什么，runtime 登记里配什么，工作区的表里放哪些条目。格式由用户 2026-10-30 定（建造计划 .goals/plans/engine-v2-build.plan.md 7.4 第 7 条）。三个 agent 共用的部分不在本文：seccomp 名单见 allowlist-derivation.md，工作工具与 engine 部件见 deployment.md 第 8 节。

**版本**：Claude Code 2.1.312，一个程序（claude.exe，293,592,432 字节，sha256 4f4178ce41d83e23341ebfbaecdbcf8ea6bf7baea0690025abe49eeec3a5d01d）。

**依据的运行**（都在 engine-v2-go 的 runs/20261101T194631Z-gate-p2-seed，实验用种子，2026-11-02）：门 7.1（p2seed-71b），门 7.2 里用到 Claude Code 的三项（p2seed-72 的 webfetch、mcp、claude-interactive），隔间里的推导集九行（p2seed-derive 的 claude-a 到 claude-h 与 claude-a-interactive，九行都过）。推导集的操作 (a)–(h) 见 allowlist-derivation.md。

**读法**：下表各项是"实测足够的集合"，即上面这些运行在所列的东西之下都做成了。"必需"只用于拿掉之后实测过做不成的项；本文还没有做过拿掉的测试，所以都写"未测"，能推断的另写推断。

## 一、种子

只写 agent 本身与它的依赖。

| 放什么 | 隔间里的位置 | 用到它的操作 | 必要性 |
|---|---|---|---|
| Claude Code 的程序（上面那一个文件） | /bin/claude（种子里 bin/claude） | 全部：(a)–(h)、交互 (a) | 未测（推断必需：它就是 agent） |
| 它链接的共享库：libc、libm、libpthread、libdl、librt 与动态加载器 | /lib/x86_64-linux-gnu、/lib64（组种子时按 ldd 补） | 全部 | 未测 |

Claude Code 的读文件、改文件、搜索工具不需要种子里另放程序。它的 shell 工具跑的命令（推导集的 ls、grep、python3、git、pip、uv、npm 等）用的是工作工具，三个 agent 共用。

## 二、登记

runtime 登记里配的环境变量与启动参数。HOME、HTTPS_PROXY、CA 路径等受管变量由 engine 设，登记里写什么都不算（deployment.md 第 2 节），不列在这里。

| 项 | 值 | 作用 | 必要性 |
|---|---|---|---|
| ANTHROPIC_API_KEY | 占位值（门里是 sk-ant-api03-w2gate-placeholder-…） | Claude Code 有了它才以 API key 方式发模型请求、带 x-api-key 头；真值由 engine 按凭据记录写进头里 | 未测（推断必需：没有它 Claude Code 要求登录） |
| CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC | 1 | 关掉遥测、错误上报一类的请求 | 未测（门与推导集都开着跑；关掉后这类请求没有条目会被当场拒，是否影响工作没测） |
| DISABLE_AUTOUPDATER | 1 | 关掉自动更新 | 未测 |
| --disallowedTools WebSearch | 启动参数 | 关掉服务端搜索（validation.md N-14 的演示配置） | 未测 |
| --model haiku | 启动参数 | 实验选的模型，解析为 claude-haiku-5-5 | 实验设计，不是运行所需 |
| -p 与 --permission-mode bypassPermissions | 启动参数 | 推导集的一次性运行；隔间里不再逐条问工具权限 | 只用于一次性运行 |
| --mcp-config | 启动参数，一份 HTTP 型 MCP server 的配置 | (h) 用 DeepWiki | 只用于 (h) |

交互界面首次启动有四个画面（主题、是否用这个 API key、安全说明、是否信任这个目录），用户在附接窗口里答；HOME 是每行新的 /tmp，所以每次起行都会再出现（deployment.md 第 2 节）。

## 三、条目

工作区的表里至少要放的条目，以及用到它的操作。"兜底"指部署时默认就有的那一条：任意目的地的 GET 放行、不带账户（engine/workspaces.py FALLBACK_DEFAULT）。

| 目的地 | 方法与路径 | 凭据记录（放置位） | 用到它的操作 | 必要性 |
|---|---|---|---|---|
| api.anthropic.com:443 | POST /v1/messages | 账户 gate，x-api-key | 全部 | 未测（推断必需：每一项的结果都来自模型回复） |
| api.anthropic.com:443 | GET /api/claude_code/settings（远端 404）、GET /api/claude_code/policy_limits | 同一账户，x-api-key | 每次启动都发 | 未测（被拒之后能否工作没测） |
| api.anthropic.com:443 | GET /api/web/domain_info | 不带凭据 | (g)：WebFetch 取页面之前先查域名 | 未测 |
| api.anthropic.com:443 | GET /api/hello | 不带凭据 | 交互 (a) | 未测 |
| example.com:443 | GET / | 不带凭据，兜底 | (g) | 未测 |
| mcp.deepwiki.com:443 | POST、GET /mcp（条目另放 DELETE） | 不带凭据 | (h)：先按新协议 POST 一次（远端 400，不经 engine 也是 400），再按旧协议初始化、调工具；GET 是服务端通知流 | 未测 |
| platform.claude.com:443 | GET /v1/oauth/hello | 不带凭据，兜底 | 交互 (a) | 未测 |
| downloads.claude.ai:443 | GET /claude-code-releases/plugins/claude-plugins-official/… | 不带凭据，兜底 | 交互 (a) 的首次启动下载官方插件包 | 未测 |

前两行合成门里的一条：api.anthropic.com:443 的 POST /v1/ 与 GET /api/，账户 gate，放置位 x-api-key。推导集里 git、pip、uv、npm 的目的地与 agent 无关，三个 agent 相同：github.com 用 git 账户（Basic）、registry.npmjs.org 用 npm 账户（Bearer），条目照门 7.2 的 git-push、npm 两项（checks/gate_items.py）；pypi.org 与 files.pythonhosted.org 只有不带凭据的 GET，走兜底。推导集九行里没有被拒的请求。
