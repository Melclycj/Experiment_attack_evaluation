# 白名单推导（构建计划 7.4）

部署的 workload seccomp 名单从哪里来、怎样量。推导集与运行方式由用户 2026-10-30 确认。名单的结果、各来源的调用集合与去掉的名字记在 validation.md 的 D-12 与本文件末尾（量完再写）。

## 名单声称什么

- 名单是下面的推导集与另外几个来源在宿主上实测到的系统调用的并集，再去掉特权类调用与编译器拒收的名字（计划 7.4 第 4 条）。全部署一份，默认拒绝，覆盖 Claude Code、Pi、OpenCode 三个 agent。
- 不声称覆盖全部正常工作。名单外的调用在隔间里得 EPERM（native/sandbox/policy.c 的默认动作）。缺一个调用的代价是某一步做不成，属于可用性；隔离不因此变弱。
- 名单够不够这组操作用，由隔间里换上新名单后复跑整套推导集来判（计划 7.4 第 5 条）。对推导集以外的工作够不够用，由日后的评测集来量。

## 推导集与评测集

- 推导集只含下面这组自定操作。
- 评测集日后从 Terminal-Bench 的一个子集取。Terminal-Bench 的任务一个也不进推导集，所以只做推导、不做评测时，评测集不受影响。

## 怎样跑

- 三个 agent 用同一组操作、同一个 haiku 模型。
- 每次运行，agent 的标准输入输出接一个 pty，与隔间里接 pty slave 一致；HOME 设为这次运行新建的空目录，与隔间里统一设的 HOME=/tmp 一致（计划 7.4 第 4b 条）。
- 每一项单独留一份 strace 输出和一份代理记录，因为每个 agent 的 runtime 说明要按操作注明种子里的文件与放行的目的地是哪一项用到的（计划 7.4 第 7 条）。
- 一次性模式：每一项开一个新会话，(a) 到 (h) 依次在同一个工作区里跑，后面的项用前面建的文件。
- 交互模式：每个 agent 另开一次交互界面，答完首屏后发 (a) 那句话，再退出。量的是终端界面才用到的调用。
- 网络：agent 经宿主上的一个 mitmdump 代理出网，代理变量与 CA 变量照隔间的设法设。agent 拿到的凭据配置与隔间相同，只有占位值；代理上的一个 addon 把占位值换成真值，作用与 connector 相同，否则带占位值的请求被上游拒，后面的代码路径量不到。这个 addon 只用于宿主上的测量，不进 engine。
- 系统调用用 `strace -f` 记整棵进程树。

## 三个 agent

装在 WSL 的用户目录（/home/jerry/.local），不动系统目录。Pi 1.4.0 要求 Node 22.19.0 以上，宿主原有的 /opt/node-v22.18.0 不够，另装 nodejs.org 的 v22.23.4（node-v22.23.4-linux-x64.tar.xz，sha256 1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce，对照官方 SHASUMS256.txt 校验通过）；npm 也用这一份。三个 agent 都用 claude-haiku-5-5（Claude Code 的 haiku 在门里解析到的就是它）。

| agent | 包与版本 | sha256 | 一次性模式的权限 | MCP 配置（只在 (h)） | 关掉的非必要流量 |
|---|---|---|---|---|---|
| Claude Code | 2.1.312，种子用的同一个 claude.exe | 4f4178ce41d83e23341ebfbaecdbcf8ea6bf7baea0690025abe49eeec3a5d01d（claude.exe） | --permission-mode bypassPermissions | --mcp-config | CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC、DISABLE_AUTOUPDATER，--disallowedTools WebSearch（同门） |
| Pi | @earendil-works/pi-coding-agent 1.4.0（W2 选定的包） | d155c16ef6fa00960fbf58b2911536e80b05f33700e0b14fbd08967ede0c7428（npm 包）；依赖锁 65eac9debd8244b482fb114c287a2decc6026f853c9cc6c3c538cfe071f3a2ef | 没有权限询问 | HOME 下 .pi/agent/mcp.json | PI_SKIP_VERSION_CHECK、PI_TELEMETRY=0 |
| OpenCode | opencode-ai 1.19.5（npm 官方包，装 linux-x64 单文件程序） | 1f97e49381f8a42a629482eff8be98aa96d62e2e94410a8ec98e738f9c787680（npm 包）；程序 7df4e4136301f16589b0f30bf91a61380fca5f8ef22dd36570f5ebe1d4ec802c | --auto | OPENCODE_CONFIG_CONTENT | OPENCODE_DISABLE_AUTOUPDATE、OPENCODE_DISABLE_LSP_DOWNLOAD |

Pi 的内置工具只有读、shell、改、写（`pi --help` 第一行），没有网页抓取，(g) 对 Pi 不适用；Pi 自带 MCP 客户端（`pi mcp`），(h) 适用。

## 推导集

| 项 | 对 agent 说的话 | 预期结果 |
|---|---|---|
| (a) 只调模型 | Without using any tools, explain in three sentences what Linux seccomp is. | 流式回三句话，没有工具调用 |
| (b) 读写文件 | Using your file-writing tool, create calc/\_\_init\_\_.py defining add(a, b) that returns a + b, and tests/test_calc.py with two pytest tests for add. Then, using your file-editing tool, change add to take a third argument c with default 0 and update the tests to cover it. | 两个文件都在；add 有三个参数；测试用到第三个参数 |
| (c) shell 命令 | Using your shell tool, run each of these commands in the workspace and show their output: ls -la; cat calc/\_\_init\_\_.py; grep -rn 'def ' .; find . -name '\*.py'; sed -n '1,5p' tests/test_calc.py; wc -l calc/\_\_init\_\_.py tests/test_calc.py; diff calc/\_\_init\_\_.py tests/test_calc.py | 七条命令的输出都在回复里（diff 退出码 1 属正常） |
| (d) 跑测试 | Using your shell tool, run python3 -m pytest -q in the workspace and report the summary line. | 全部通过，0 failed |
| (e) git | Using your shell tool: run git init in the workspace and commit all files; clone https://github.com/octocat/Hello-World.git into /tmp/hw; clone https://github.com/Melclycj/Thesis-testbox.git into /tmp/tb, append one line with the current UTC time to w2-derive-log.txt, commit it and run git push. Use the author name w2-derive and the email w2-derive@users.noreply.github.com for both commits. | 工作区有一次提交；测试仓多出一个提交，经 GitHub API 单独核对 |
| (f) 包管理 | Using your shell tool: run python3 -m pip install --target /tmp/pip-t six; run uv venv /tmp/uvv and then uv pip install --python /tmp/uvv/bin/python six; run npm install --prefix /tmp/npm-t is-number. Then import each package once and show the output. | 三次安装都成功；三次 import 输出正确 |
| (g) 抓网页 | Fetch https://example.com/ with your web fetch tool and reply with the exact text of its h1 heading and nothing else. | 回复与页面一致：给出页面的 title（Example Domain），或说明页面没有 h1（页面现在没有 h1；预期结果用户 2026-11-02 改） |
| (h) MCP | Call the deepwiki read_wiki_structure tool for the repository facebook/react and reply with how many top-level topics it lists, as a number only. | 回一个数字；代理记录里有到 mcp.deepwiki.com 的 POST 2xx |

agent 没有某项要求的工具时，该项对这个 agent 记"不适用"，不给它装扩展，也不改用别的工具代替。

预期结果在宿主上用来确认这一项真的做成了：做成了，量到的调用才算这一项的。对不上的项重跑，或者记下原因。

## 另外量的来源

1. 门的十条命令：checks/gate_items.py 的 ITEMS，即 7.2 的九项与 7.3 加的交互式 Claude Code。在接 pty 的 bash 里原样跑一遍，不经过 agent，凭据照门的设法、只有占位值。门在隔间里也跑这十条，其中 curl 与 gh 不在推导集里。
2. 前端：只取前端进程本身。
3. pty 转发进程。
4. 启动代码：native/sandbox/child.c 从装 seccomp 过滤器到 execve agent 之间自己要用的调用，含拉起转发进程与前端的那段，读码列出。

## 结果

宿主上的测量在 runs/20261030T131500Z-derive-host（三个 agent 与门的十条命令）和 runs/20261030T132600Z-derive-host-helpers2（前端与 pty 转发进程）。装置是 checks/derive_host.py 与 checks/derive_proxy.py，三次试跑在 runs/20261030T130700Z-derive-host-smoke 起的三个目录。

- 推导集每一项、三个交互运行、门的十条命令都过预期结果（Pi 的 (g) 不适用）。
- 各来源的调用名个数：Claude Code 129、Pi 125、OpenCode 126、门的十条命令 128、前端 54、转发进程 19、启动代码（读码）14；合起来 146 个。
- 没有量到特权类调用。
- 量到但编译器本来就拒收、从名单里去掉的：clone3、sysinfo、io_uring_setup、io_uring_enter（后两个只有 OpenCode 用）。隔间里它们得 EPERM（clone3 得 ENOSYS）。
- 名单 142 个名字，在 checks/workload-allow.txt，checks/gate_seed.py 从它读。每个名字都能被 libseccomp 解析。
- 与此前门里手写的 205 个名字相比：多了 openat2、timer_create、timer_settime（都来自 Pi）；少了 66 个没量到的，包括 setuid 一族、unshare、memfd_create、execveat、sendmsg、ppoll、select、pipe、fork。

隔间里的复跑（计划 7.4 第 5 条，engine-v2-go 第二阶段第 9 步，2026-11-02）：在实验用种子（deployment.md 第 8 节）上，用这份 142 个名字的名单，三个 agent 各把推导集跑一遍，每项一次 execution，在隔间的 shell 里一次性运行 agent，另各一次交互 (a)（checks/run_gate.py --suite derive，判法在 checks/derive_cell.py：请求取自这一行自己的 trace，落在隔间 /tmp 里的东西由同一行里随后打的检查命令报告，工作区在宿主上核、推送在 GitHub 上核）。运行在 engine-v2-go 的 runs/20261101T194631Z-gate-p2-seed。

- 26 项都在隔间里走完并判过：Claude Code 9 项、Pi 8 项（(g) 不适用）、OpenCode 9 项；没有一项因为名单缺调用失败，没有请求被拒。这是"名单够这组操作用"的证据。
- (g) 的预期结果原先写作 h1 的文字"Example Domain"。example.com 现在的页面没有 h1，只有 title"Example Domain"和一段 p（2026-11-02 实测：ask 模式在模型请求正文里看到了 OpenCode 交给模型的整页 HTML），所以用户当天把预期结果改为"回复与页面一致"。OpenCode 每次都答"没有 h1"，有时另提 title；Claude Code 答"Example Domain"，是把 title 当作标题。按改后的预期结果，宿主那次与隔间里各次都过；改之前隔间里 OpenCode 有两次判为未过，逐次的前后对照在该运行目录的 README。
- ripgrep 与 fd 放进种子后，Pi 不再自己下载（Pi 的十五行里没有去 GitHub 发布页的请求）。
- 一个 engine 运行周期内 uid 不复用，门部署的保留区间是 16 个 uid，所以 26 项分几次 engine 运行跑完：第一次跑了 Claude Code 九项与 Pi 七项后用完区间，Pi、OpenCode 再各跑一次全套。

测量中看到的、给种子讨论与每个 agent 的 runtime 说明用的事实（来自代理记录）：

- OpenCode 每次启动取 models.opencode.ai/api.json，并向 registry.npmjs.org 查约 17 个它自己的插件包，查询带上了 .npmrc 里的 npm 占位 token。
- Pi 第一次进交互界面时从 GitHub 发布页下载 ripgrep 与 fd 放进 HOME，并取 pi.dev 的模型目录。据此推断：隔间里 HOME 每行都是新的（计划 7.4 第 4b 条），每次起行都会再下载一遍，未实测。
- Claude Code 交互界面首启从 downloads.claude.ai 下载官方插件包（与 7.3 的观察一致）。
