# OpenCode 的 runtime 说明

在 engine 的隔间里运行 OpenCode，至少要什么：种子里放什么，runtime 登记里配什么，工作区的表里放哪些条目。格式与读法同 runtimes/claude-code.md（建造计划 7.4 第 7 条）；seccomp 名单见 allowlist-derivation.md，工作工具与 engine 部件见 deployment.md 第 8 节。

**版本**：OpenCode 1.19.5，npm 官方包 opencode-ai（包 sha256 1f97e49381f8a42a629482eff8be98aa96d62e2e94410a8ec98e738f9c787680），npm 的 postinstall 放好的程序 opencode.exe（214,386,864 字节，sha256 7df4e4136301f16589b0f30bf91a61380fca5f8ef22dd36570f5ebe1d4ec802c）。

**依据的运行**（engine-v2-go 的 runs/20261101T194631Z-gate-p2-seed，实验用种子，2026-11-02）：推导集 OpenCode 一遍（p2seed-derive-oc，九行，按 2026-11-02 改后的 (g) 预期结果九行都过），以及 (g) 的单独重跑与 ask 模式各一次（p2seed-derive-ocg、p2seed-derive-ocg-ask），见该目录 README。

**读法**：各项是"实测足够的集合"；没有做过拿掉某一项的测试，必要性都写"未测"，能推断的另写推断。

## 一、种子

只写 agent 本身与它的依赖。

| 放什么 | 隔间里的位置 | 用到它的操作 | 必要性 |
|---|---|---|---|
| OpenCode 的程序（上面那一个文件；npm 包里别的条目不放） | /usr/bin/opencode | 全部：(a)–(h)、交互 (a) | 未测（推断必需：它就是 agent） |
| 它链接的共享库：libc、libm、libpthread、libdl 与动态加载器 | /lib/x86_64-linux-gnu、/lib64（组种子时按 ldd 补） | 全部 | 未测 |

宿主上的推导用的是 npm 装出的整个包（21 个条目、429 MB，程序在里面有三份）；隔间里只放那一个程序，九行照样做成。

## 二、登记

HOME、HTTPS_PROXY、CA 路径等受管变量由 engine 设，不列在这里。

| 项 | 值 | 作用 | 必要性 |
|---|---|---|---|
| ANTHROPIC_API_KEY | 占位值 | OpenCode 以 API key 方式调 Anthropic、带 x-api-key 头；真值由 engine 写入 | 未测（推断必需） |
| OPENCODE_DISABLE_AUTOUPDATE | 1 | 不自动更新 | 未测 |
| OPENCODE_DISABLE_LSP_DOWNLOAD | 1 | 不下载语言服务器 | 未测 |
| -m anthropic/claude-haiku-5-5 | 启动参数 | 实验选的模型 | 实验设计 |
| run 与 --auto | 启动参数 | 推导集的一次性运行；--auto 自动答它的权限询问 | 只用于一次性运行 |
| OPENCODE_CONFIG_CONTENT | 一份 remote 型 MCP server 的配置 | (h) 用 DeepWiki | 只用于 (h) |

交互界面没有首启画面要答，退出用 /exit。

## 三、条目

"兜底"指部署时默认就有的那一条：任意目的地的 GET 放行、不带账户。

| 目的地 | 方法与路径 | 凭据记录（放置位） | 用到它的操作 | 必要性 |
|---|---|---|---|---|
| api.anthropic.com:443 | POST /v1/messages | 账户 gate，x-api-key | 全部；每次运行先有一条约 3 KB 的小请求，再是主对话的各轮（九行里每行合计 2 到 6 条） | 未测（推断必需：每一项的结果都来自模型回复） |
| models.opencode.ai:443 | GET /api.json | 不带凭据，兜底 | 每次启动都取模型目录 | 未测 |
| example.com:443 | GET / | 不带凭据，兜底 | (g) | 未测 |
| mcp.deepwiki.com:443 | POST、GET /mcp（条目另放 DELETE） | 不带凭据 | (h) | 未测 |

宿主上的推导里 OpenCode 每次启动还向 registry.npmjs.org 查约 17 个它自己的插件包（带 .npmrc 里的 npm 占位 token，allowlist-derivation.md"测量中看到的"）；隔间里九行都没有这类请求，原因没有查（种子里只放了程序本身是可能的原因，属推断）。推导集里 git、pip、uv、npm 的目的地与 agent 无关，同 runtimes/claude-code.md 末段。九行里没有被拒的请求。
