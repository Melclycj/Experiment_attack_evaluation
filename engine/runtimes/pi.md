# Pi 的 runtime 说明

在 engine 的隔间里运行 Pi，至少要什么：种子里放什么，runtime 登记里配什么，工作区的表里放哪些条目。格式与读法同 runtimes/claude-code.md（建造计划 7.4 第 7 条）；seccomp 名单见 allowlist-derivation.md，工作工具与 engine 部件见 deployment.md 第 8 节。

**版本**：Pi 1.4.0，npm 包 @earendil-works/pi-coding-agent（包 sha256 d155c16ef6fa00960fbf58b2911536e80b05f33700e0b14fbd08967ede0c7428，依赖锁 65eac9debd8244b482fb114c287a2decc6026f853c9cc6c3c538cfe071f3a2ef，allowlist-derivation.md"三个 agent"）。Pi 要 node ≥22.19。

**依据的运行**（engine-v2-go 的 runs/20261101T194631Z-gate-p2-seed，实验用种子，2026-11-02）：推导集 Pi 一遍（p2seed-derive-pi，八行全过），以及第一遍推导集里 Pi 的七行（p2seed-derive 的 pi-a 到 pi-h，七行全过，第八行因部署的 uid 区间用完没起，见该目录 README）。Pi 没有抓网页工具，(g) 不适用。

**读法**：各项是"实测足够的集合"；没有做过拿掉某一项的测试，必要性都写"未测"，能推断的另写推断。

## 一、种子

只写 agent 本身与它的依赖。

| 放什么 | 隔间里的位置 | 用到它的操作 | 必要性 |
|---|---|---|---|
| node v22.23.4（node 程序；它链接的 libstdc++、libgcc_s、libm、libdl、libpthread、libc 与动态加载器） | /usr/bin/node；/lib/x86_64-linux-gnu、/lib64 | 全部 | 未测（推断必需：Pi 是 node 程序，1.4.0 要 ≥22.19） |
| Pi 的 npm 安装：整个 node_modules（16,588 个条目、112 MB），其中 linux-arm64 的一个预编译 .node 不放（目录检查只收 x86-64 的 ELF） | /usr/lib/pi/node_modules | 全部 | 未测（只放过整份） |
| 启动链接：pi 指向 node_modules 里 @earendil-works/pi-coding-agent/dist/bundle/cli.js（脚本首行 #!/usr/bin/env node） | /usr/bin/pi | 全部 | 未测（推断必需：一次性运行与交互都用 pi 这个名字起） |
| pi-tui 的 linux-x64 平台模块用到的 libxcb、libXau、libXdmcp、libbsd、libmd（组种子时按 ldd 补） | /lib/x86_64-linux-gnu | 未查（这个模块是否在隔间里加载没有看） | 未测 |
| ripgrep 15.2.0 与 fd 10.5.0 | /usr/bin/rg、/usr/bin/fd（工作工具，三个 agent 共用） | 交互 (a)：在 PATH 上找得到时 Pi 不下载（实测，见下） | 未测（没有它们时 Pi 首次进界面从 GitHub 发布页下载，宿主上实测；在隔间里要放行 github.com 的发布页下载） |

关于 ripgrep 与 fd：Pi 的工具管理先找自己的工具目录（HOME 下），再找 PATH 上的 rg、fd，都没有才去 GitHub 下载（读码：dist/utils/tools-manager.js）。隔间里 HOME 每行都是新的，PATH 上没有这两样时每次起行都会重新下载；放进种子之后，十五行里没有一次下载请求。

## 二、登记

HOME、HTTPS_PROXY、CA 路径等受管变量由 engine 设，不列在这里。

| 项 | 值 | 作用 | 必要性 |
|---|---|---|---|
| ANTHROPIC_API_KEY | 占位值 | Pi 以 API key 方式调 Anthropic、带 x-api-key 头；真值由 engine 写入 | 未测（推断必需） |
| PI_SKIP_VERSION_CHECK | 1 | 不查新版本 | 未测 |
| PI_TELEMETRY | 0 | 不发安装遥测 | 未测 |
| --model anthropic/claude-haiku-5-5 | 启动参数 | 实验选的模型 | 实验设计 |
| -p | 启动参数 | 推导集的一次性运行 | 只用于一次性运行 |
| ~/.pi/agent/mcp.json | 文件，写在这一行的 HOME 里 | (h) 用 DeepWiki；HOME 每行新建，所以每次运行前写一次 | 只用于 (h) |

Pi 没有逐条的权限询问，交互界面也没有首启画面要答。

## 三、条目

"兜底"指部署时默认就有的那一条：任意目的地的 GET 放行、不带账户。

| 目的地 | 方法与路径 | 凭据记录（放置位） | 用到它的操作 | 必要性 |
|---|---|---|---|---|
| api.anthropic.com:443 | POST /v1/messages | 账户 gate，x-api-key | 全部 | 未测（推断必需：每一项的结果都来自模型回复） |
| pi.dev:443 | GET /api/models/providers/anthropic（先 307 再 200） | 不带凭据，兜底 | 交互 (a)：进界面时取模型目录 | 未测 |
| mcp.deepwiki.com:443 | POST、GET /mcp（条目另放 DELETE） | 不带凭据 | (h) | 未测 |

一次性运行里 Pi 自己只发模型请求，启动时没有别的请求。推导集里 git、pip、uv、npm 的目的地与 agent 无关，同 runtimes/claude-code.md 末段。十五行里没有被拒的请求。
