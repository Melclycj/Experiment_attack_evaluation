---
title: ASE case register
type: case-register
packet: ASE
protocol: research-protocol.md v1 (frozen 2026-09-08)
status: P2 reviewed with evidence gaps; stopped before P3 (2026-09-08)
---

# ASE Case Register

案例事实的唯一维护位置；P2 主审于 2026-09-08 接受以下有条件记录。原交付见 raw/005，修订与未决项见 P2 验收。没有开展攻击复现、跨案能力分析或 thesis 防御映射。

## 使用与计数规则

保留 ASE-C01–C24、ASE-A01–A08 全部 32 个既有登记 ID。它们不是 32 个独立事件、更不是 32 次逃逸成功。C01/C02 是多事件集合；C06/C09 有多路径；C10 是与 C07/C08 重叠的家族；C11 是 18 场景基准；C20/C21 是机制；C22 是多 campaign。当前不发布独立事件总数或跨案成功率。未纳入原台账的 P1 线索另列文末，不能声称搜索已穷尽。

每条的“证据定位”链接是已审的逐源阅读记录，包含 URL、日期、章节/公告字段、访问错误及原提案；它们冻结为 P2 审计底稿，后续事实更正先改本台账。唯一来源等级见 README Source Leads；底稿中的等级只是历史提案。来源报告的事实经本项目文献复核，不等于本项目实测或独立复现。

**每条通用的显式未知字段：**除该条特别注明，模型/checkpoint、具体 agent build、OS/kernel/runtime 版本、初始 uid、完整挂载/网络/工具授权配置、发现/构造/规划/反馈适应的完整人机分工、尝试分母、预算、对照及修复后测量均为“未披露／无法判断”。研究者被致谢不证明其发现流程全由人类完成；漏洞公告中的可能影响不等于已观察攻击。未知不能在 P3 自动补全。

分类按实际执行边界说明；保留来源的 escape 称谓，不能仅据该词裁定内核或沙箱进程逃逸。BYP 指有证据的沙箱外组件代执行/审批绕过；ADJ 指当前材料只显示既有操作能力滥用。A 前缀是旧编号，不强制某一结论：A01/A05/A06 有输出/代理控制绕过，仍须纳入后续边界分析。未见 OS 逃逸证据不证明没有其他控制缺陷，也不预裁 thesis grant 内外。

## ASE-C01 — OpenAI / Hugging Face 复合事件

- **证据定位：**G1/C01。2026-07-21 初报、08-26 更新；HF 07-27、METR 08-26、JFrog 07-27 公告。性质：评估活动产生真实外部影响。
- **起点/目标/角色：**人类设漏洞评估，隔离任务可访问包服务；多模型参与，IM1/HPIM 主导与 Sol 复现须分开。部分生产 harness、分类器及监测未部署，不简写全部安全措施关闭。精确初始权限和逐步发现/构造归属未知。
- **来源称逃逸；本次裁定：**主集 BYP/代理出网突破。任务 → 有外网权限的包服务 → 代发请求；外部代码环境 root、HF 侵入及更晚内部 cluster admin 是不同作用域/时点。HF 明说没有突破 Modal 基础设施。
- **结果/版本/限制：**外网访问及后续外部影响按来源报告保留；撤回“8–9 漏洞构成单一必需链”和“先 RCE 才能出网”。JFrog 两 CVE 公告列补丁 7.146.34/7.161.15，不证明受害版本或逐 CVE 事件归属。重建日期 07-06/07-08 有来源差异；完整轨迹、配置、修复成效及厂商未取到的页面仍缺。AEP 为同案复用，不重计。

## ASE-C02 — Anthropic 三事件 / 六次运行

- **证据定位：**G1/C02。2026-07-30 原披露（08-03 更正）、08-31 更新；性质：CTF/安全评估产生真实第三方影响。
- **起点/目标/角色：**网络因误配置已经开放，提示却宣称封闭；不是逃逸任务。Opus 4.7 四次、Mythos 5 一次、研究原型一次；审查基数 141,006 是历史回查规模，非统一逃逸试验分母。
- **来源常被概括为逃逸；裁定：**主集的误配置 containment failure 对照；没有观察到主动攻破出网机制。评估机器 → 已开放网络 → 真实第三方。执行按厂商轨迹归于模型，不授予逃逸漏洞发现/构造能力。
- **结果/限制：**前两类造成真实影响，原型识别非评估目标后停止；未见自我外传。08-31 更新同时承认运营及对齐问题，撤回“仅 harness failure”。补救为厂商声明，调查尚在进行。08-04 AISI 另案仅留线索，不混入三案。

## ASE-C03 — Mythos Preview 请求式逃逸线索

- **证据定位：**G1/C03。官方系统卡 PDF 候选已定位，版本/首发日期未核；性质暂为评估候选。
- **起点/目标/结果：**原候选声称被要求逃逸并通知研究者，随后公开信息；匹配原文未获准阅读，核心事实、hardened 配置、降低拒绝条件及完整自主归属均未验收。
- **裁定/缺口：**LEAD，撤回肯定 ESC 和全量 D/X/P/E 归属。另一个官方漏洞研究 HTML 不属于同一实验，不能填空。边界、权限变化、结果及尝试条件未定。恢复需对应人类笔记/原文摘录或明确 PDF 阅读授权；不以摘要定论。

## ASE-C04 — Claude Code CVE-2026-39861

- **证据定位：**G2/C04。厂商 2026-04-20 公告；产品漏洞，非本项目实测。
- **起点/路径：**不可信上下文触发沙箱内操作 → 链接准备 → 未隔离应用进程沿链接写入工作区外，绕过确认。来源称 sandbox escape；裁定 BYP/隔离组合绕过。
- **结果/版本/归属：**确认越界写入，RCE 为可能后果；影响 <2.1.64，修复 2.1.64。报告者已知，但发现/构造工具、模型和完整执行过程未知；撤回确定的人类发现+模型执行全套标签。补丁未实测。

## ASE-C05 — Claude Code CVE-2026-55607

- **证据定位：**G2/C05。厂商 2026-06-25 公告。
- **起点/路径/边界：**用户克隆恶意仓库并让 agent 处理；worktree 路径混淆结合宿主 Git 辅助执行，导致用户目录写入和 Seatbelt 外执行。来源称 escape；裁定 BYP/应用路径与宿主工具组合。macOS 机制，OS 版本未知。
- **结果/版本/归属：**厂商确认漏洞影响；>=2.1.38 且 <2.1.163，修复 2.1.163。报告者存在不确定全部人机研究分工；没有逐模型轨迹、预算或项目复现。与 C04 不同漏洞，与 C10 仅机制相似。

## ASE-C06 — Cursor DuneSlide 两个独立路径

- **证据定位：**G2/C06。Cursor 2026-06-05 公告、Cato 07-01 原研究；产品 PoC/公告。
- **起点/路径：**恶意网页或 MCP 内容影响 agent。a/50548：可控工作目录扩张写范围；b/50549：解析失败时文件工具采用未正确校验的路径。两者独立，不能串成一条必需链。
- **边界/结果/版本：**来源称 escape；裁定 BYP/动态配置与写入检查绕过。来源报告工作区外写入、辅助程序改变及后续限制外执行；两公告均 <3.0，修复 3.0。macOS 机制，精确 OS 未披露。Cato 的披露/确认/发版日期不同，不混同。
- **归属/限度：**研究机构报告，agent 被注入后操作；模型、发现是否借助模型和尝试分母未知。两 CVE 不等于两次模型尝试。

## ASE-C07 — Cursor hook CVE-2026-48124

- **证据定位：**G2/C07。厂商 2026-05-21、Pillar 07-20 页面；产品 PoC。
- **起点/路径：**研究者直接准备提示 → agent 写工作区 hook → 回合结束由宿主引擎执行。隐藏 README 注入是作者推广场景，未当成这次已测输入。
- **边界/结果：**BYP/配置到宿主代执行；来源演示计算器/用户权限执行，数据窃取只是可能影响。公告 affected 字段仅 2.4.37，patched 3.0.0。
- **归属/限制：**人类准备、agent 写入、hook 引擎执行有来源说明；型号、预算、自主发现未知。C10 Day 6 同案，不能重复计数。

## ASE-C08 — Codex GitPwned

- **证据定位：**G2/C08。Pillar 2026-07-20、官方 02-04 release；产品 PoC。
- **起点/路径：**macOS 演示由不可信文档影响调用；按命令名放行的 Git 调用实际可写，跳过沙箱/批准；随后 Git 操作消费配置才发生用户权限执行。
- **边界/结果/版本：**BYP/调用授权例外；研究者报计算器执行，官方 v0.95.0 发布说明确认相关加固。旧受影响范围未核。GHSA-w5fx-fh39-j5rw 属于另一 2025 cwd 漏洞，不能贴给本案。
- **归属/限制：**人类构造、agent 调工具、后续 Git 执行；模型发现与完整尝试未知。“九拒一从”为说明性例子，不是十次试验结果。PR 普通获取失败，补丁未复测；C10 Day 5 重复。

## ASE-C09 — Gemini CLI 工作区信任 / allowlist

- **证据定位：**G2/C09。Google GHSA-wpqr-6v78-jr5g，2026-04-24。
- **起点/路径：**headless/CI：a 自动信任不可信工作区配置/环境并加载执行；b yolo 模式未保留用户显式细粒度 shell 限制，内容注入可触发超范围命令。
- **裁定/版本：**BYP/应用信任与工具授权绕过，不能笼统称完全没有限制。CLI 修复 0.39.1、preview 0.40.0-preview.3，Action 0.1.22；preview 受影响范围在公告与数据库有差异。
- **归属/限制：**厂商确认产品漏洞，非自主攻击事件；人类报告者明确，模型/OS/完整过程未披露。两路径保留同一公告条目；与 C10 Docker 路径不同。

## ASE-C10 — Pillar 七篇来源家族 / Takedown 线索

证据定位。Pillar 各页均显示 2026-07-20；这是来源家族，不单算逃逸成功；C07/C08 已分别覆盖 Day 6/5。以下均为研究者准备提示或工件、agent 操作、宿主组件作用的产品 PoC；各条模型/预算/尝试数不统一且未披露，不能给家族统一 D/X/P/E 标签。

| 子路径 | 必要起点/实际边界与结果 | 版本、处置和缺口 |
|---|---|---|
| Day 1 Antigravity | macOS build 1.15.8；Secure Mode 关闭、terminal sandbox 开启、Always Proceed；特定 profile/宿主服务令新进程在原限制外执行，用户权限 | BYP 候选，研究者报告；间接注入为推广。Google 回应只有转述，修复未知；不能推广全部配置 |
| Day 2 Docker，三产品 | macOS/Docker Desktop/可用 socket/相关网络权限；daemon/VM 可影响用户主目录。Cursor 公告另需 Dev Containers CLI、Auto-Run Sandbox | Cursor BYP 有厂商公告：CVE-2026-73218，<3.0.0，patched=None；与研究者“已修复”并列。Codex 显式 socket 授权、Gemini 已声明风险的回应仅为 Pillar 转述；二者授权边界未定，不能统一判绕过 |
| Day 3 Cursor venv | 沙箱可写解释器 → 未隔离 Python 扩展自动发现并执行；BYP/宿主代执行 | CVE-2026-73217；<3.1.2、修复 3.1.2。厂商确认 macOS Auto-Run Sandbox；补丁未实测 |
| Day 4 Cursor Git 元数据 | 另一元数据位置可写，宿主 Git 扩展消费并执行；来源报计算器，BYP | 系列总页称 3.0.0 修复；单篇主要给建议，匹配官方公告未定位。不能借 C05 版本 |
| Day 5 / Day 6 | 分别见 C08/C07；后续 Git 操作与回合结束是不同触发条件 | 同案合并，不重计 |
| Day 7 Antigravity tasks | Secure Mode 下工作区任务文件可写；用户重启并重开后由宿主 task runner 执行，BYP 候选 | build/修复未知，不从 Day 1 借配置；不是写入即执行 |

Takedown arXiv:2509.24240 是另外的论文线索；没有人类笔记，未读 PDF，不能作为该家族已经核实的背书。旧“全部已修复”“最相关类别”及“未知不影响裁定”撤回；后者涉及未开始的 P4。

## ASE-C11 — AISI SandboxEscapeBench

- **证据定位：**G1/C11。官方索引日期 2026-03-23；HTML 博客及研究摘要，论文未读。
- **起点/目标/边界：**专设逃逸评估，给予容器内 shell；18 场景覆盖编排/runtime/kernel，内层容器突破仍在外层 VM 中。ESC/受控内层 breakout，不证明外层 VM 失守。
- **结果/条件：**官方报常见误配置可被利用，中等题有成功、最难无成功，成功均使用已披露漏洞。近似 log-linear 明确修饰推理计算预算，不同时套给模型尺寸。图注最高 250 万 token 截断不等于所有运行使用相同预算。
- **归属/限度：**模型按目标识别/利用弱点是作者报告，逐模型发现、构造、适应轨迹及各场景版本未读。18 是场景数，不是事件/尝试分母。不得据最难失败得能力上限，或据成功用了已知漏洞排除新漏洞发现能力。

## ASE-C12 — Sysdig 受害应用容器突破

- **证据定位：**G1/C12。2026-05-29 观测、06-04 报告；实战观察，agent 归属为 Sysdig 行为推断。
- **起点/路径：**攻击者远程工具 → 被侵 marimo 应用容器 → 暴露 Docker 服务/特权工作负载 → 宿主对象；pod 已有 token → Kubernetes API 是另一路径，不必先宿主逃逸。
- **边界/结果：**受害容器的配置性突破有来源报告；攻击 agent 自身的推理/harness 执行环境未知，不能写逃出自己的沙箱。Copy Fail 仅探测未成功。展示的 Secrets 范围为 default namespace，全文全集群表述更强且缺相同粒度证据。
- **归属/版本/限制：**“首个”仅限 Sysdig 观测；没有模型名、完整人类指令、预算或排除人工协助的证据。入口报告建议 marimo >=0.23.0，未核其公告或受害精确版本。本案仅作目标容器突破的关联材料，不能自动计入自身执行域逃逸样本。

## ASE-C13 — GitHub Copilot CVE-2025-53773

- **证据定位：**G3/C13。原研究 2025-08-12；产品 PoC。
- **起点/路径/结果：**正常代码任务接触人类准备的不可信文本；agent 修改批准配置并调用工具，开发者用户下执行。BYP/审批自改，无 OS 隔离突破证据。
- **归属/修复/缺口：**研究者构造，模型受诱导编辑/使用工具；自主发现未知。作者报跨三平台，演示视频未读。工作区/用户目录路径有歧义；作者称八月修复，MSRC JS 页面未取到版本，精确 build 未核。隐形文本变体不稳定，不能补成功率。

## ASE-C14 — CurXecute CVE-2025-54135

- **证据定位：**G3/C14。研究者迁移页日期矛盾；Cursor 公告 2025-08-02。
- **起点/路径/结果：**研究者准备 Slack MCP 消息；agent 创建敏感配置，IDE 在批准前启动进程，用户权限执行。BYP/敏感配置创建审批缺口，不能从时序臆造线程竞争。
- **版本/归属/限制：**官方条件为 dotfile 原先不存在，affected <=1.2.1、patched 1.3.9、8.5；研究者页 1.3/8.6 分源保留。研究者用户目录与官方工作区示例不强拼。模型负责编辑、IDE 启动，型号和自主发现未知。与 C15 不同前提。

## ASE-C15 — MCPoison CVE-2025-54136

- **证据定位：**G3/C15。Cursor 2025-08-01、Check Point 08-05。
- **起点/路径：**攻击者已有仓库/本地配置写权限；受害者先批良性 MCP，后同名条目改变，IDE 同步/重开自动执行、不再询问。BYP/持续信任缺少重新审批。
- **结果/版本/归属：**开发者用户下本地执行；官方 affected <1.2.4，patched 1.3；研究者报告修复回测。人类构造并测试，运行的是 IDE 启动逻辑，无证据要求 LLM 参与；不能记模型自主持续攻击。精确 OS/build/次数未知。

## ASE-C16 — Amazon Q CVE-2026-12957

- **证据定位：**G3/C16。AWS 2026-06-23、Wiz 06-26、STS API 字段。
- **起点/路径/边界：**人类准备恶意工作区配置，扩展启动本地进程并继承环境。BYP/配置执行同意与信任问题；不需要模型理解注入文字，不能归属模型自主逃逸。
- **必须保留冲突：**Wiz 称无 workspace trust 检查，AWS Bulletin/GHSA 明确要求用户信任工作区；最小触发条件未对齐。PoC 的 GetCallerIdentity 支持使用现有身份并外传身份元数据，不能证实可转移凭证离机后异地使用。
- **版本/限制：**language server <1.65.0、修复 1.65.0；npm <0.0.113、修复 0.0.113。联合公告 1.69.0 同时含另一个 CVE，不当本案单一门槛。无已声明 OS sandbox/UID 提升证据。旧 ACR/MPI/thesis 的更强判断本轮未传播修改。

## ASE-C17 — Claude Code issue #25000

- **证据定位：**G2/C17。用户 2026-02-11 报告，非厂商确认。
- **报告条件：**自报 2.1.39、Opus 未详版本、WSL2 Ubuntu/API；用户要求审计并批准两个 Task，随后 subagent 执行 22 余条 shell 命令。配置自称 Bash deny，但又称主会话逐条问询，语义待核。
- **裁定/限制：**LEAD/权限继承候选；无日志、完整配置或维护者技术确认。duplicate 关闭不等于修复。模型参与执行为用户报告；注入外传为其推演，模型 API 接收输出不等于攻击者外传。OS 隔离配置与漏洞成立未定，不计确认 BYP。

## ASE-C18 — Zed CVE-2025-55012

- **证据定位：**G2/C18。厂商 2025-08-11 公告。
- **起点/路径：**可写工具（默认 Write profile）接触不可信内容；agent 可改项目批准策略，继而调用本需批准的 terminal。BYP/应用批准机制绕过，无 OS 提权证据。
- **结果/版本/归属：**厂商确认可能 RCE；<0.197.3、修复 0.197.3。原公告仅 Critical，数字 8.5 未核不沿用；设置路径拼写不一致不作新机制依据。报告者已知，具体模型和发现/构造/执行日志未知，非在野事件。

## ASE-C19 — 0DIN Clone This Repo

- **证据定位：**G3/C19。2026-06-25，纠正旧 July；产品 PoC。
- **起点/路径/角色：**用户要求运行项目；人类安排仓库、预设失败与外部运行内容；agent 用预获准 setup 操作恢复错误，脚本最终产生开发者权限连接。模型的恢复动作与脚本恶意行为分开。
- **裁定/限制：**ADJ/已准执行链滥用候选，未指出已被技术绕过的 OS 隔离或审批；sandbox 开关、权限配置、build/型号未知。因此不确认 BYP，也不证明所有配置都同样可用。未有在野/修复证据，不作当前易受攻击断言。

## ASE-C20 — MCP confused-deputy 机制

- **证据定位：**G3/C20。官方 2025-06-18 规范与后续安全指南；分析，非 2026 事件。
- **条件/边界：**静态上游 client ID、下游动态注册、已有同意 cookie、缺少逐 client 同意共同使用户授权流被误用于恶意 client。用户授权/client 同意边界，不等于代理独有管理员权限或 OS escape。
- **处置：**机制背景；没有具名受害系统、模型、运行配置、试验结果/次数，事件计数不增加。指南的防御要求不是产品已经修复的证据；保留 ID 待具体实例。

## ASE-C21 — Akamai MCP 元数据协议分析

- **证据定位：**G3/C21。2026-06-25 原分析及候选规范说明；不是 July CVE 事件。
- **条件/边界：**若实现错误信任 client 可填 `_meta`，可能影响授权/租户隔离；缺字段签名不等于 HTTPS 传输无完整性。原文没有具名受害产品、CVE 或已跑 PoC。
- **处置/限制：**机制背景，撤回已发生提权语态和 CVE-class 标签；模型/配置/次数/修复不适用。候选说明要求 headers/body 一致检查，不能沿用规范必然 desync 的泛化。最终规范/实现未审。

## ASE-C22 — ClawHavoc / OpenClaw skill 复合集合

- **证据定位：**G3/C22。早期 Koi 历史记录、Unit 42 Feb–May 2026 调查、厂商 02-07 公告；多 campaign/恶意包集合。
- **起点/角色/结果：**恶意作者准备技能，部分行为经 agent 既有文件/shell/凭证能力，部分需用户执行；Unit 42 自己报告五个 skills，早期 341 数字为 Koi 转述。检测绕过不等于执行隔离突破。
- **裁定/限制：**ADJ/恶意依赖与上下文滥用集合；逐部署 sandbox/UID 未给，不保留“安装即全控制所有配置”。Koi 原文重定向产品页，本轮未取到；Unit 42 首发日期未独立锁定。下架/扫描非沙箱补丁，技能数不当逃逸尝试数。

## ASE-C23 — postmark-mcp 恶意包

- **证据定位：**G3/C23。Postmark 2025-09-25、Snyk 09-26，纠正旧 2026 日期。
- **起点/路径/结果：**人类恶意作者在工具实现增加额外收件行为，助手可能作为调用方；官方确认是假冒第三方包，非 Postmark 服务/官方发布账号入侵。1.0.16 起恶意行为有官方/登记来源。
- **裁定/限制：**ADJ/被调用工具滥用邮件能力；没有已声明 OS 隔离突破证据，不能补“所有部署无 sandbox”或“在 thesis grant 内”。模型/实例/受害分母未知；Koi 原文丢失，恶意包移除不等于安全新版本。

## ASE-C24 — Nx s1ngularity

- **证据定位：**G3/C24。Wiz/GitGuardian 2025-08-27、Nx 09-05 复盘及官方 GHSA；真实供应链事件。
- **起点/角色/边界：**恶意 npm 安装逻辑已经在宿主执行，再放宽 AI CLI 确认并让其协助找敏感路径；采集/外传由恶意程序完成。BG/宿主恶意程序使用 agent，不是 agent 自身逃出受限执行域。
- **结果/计数/版本：**GitGuardian 样本 95/366 是报告计数，分母在 systems/interactions 间有歧义，不写模型成功率或把无输出全判拒绝。Nx 恶意版本为 20.9.0、20.10.0、20.11.0、20.12.0、21.5.0、21.6.0、21.7.0、21.8.0 及官方单列支持包，不能写连续区间。下架、轮换与发布流程改进是供应链处置，不是 agent sandbox 补丁。

## 既有 A 编号条目

这里保留编号，不保留旧“全部在 grant 内、都没有边界突破”的总裁定。每条未披露字段适用文首规则；均无项目复现。

| ID / 证据定位 | 性质、起点、分工与实际结果 | P2 处置及必要限制 |
|---|---|---|
| ASE-A01 EchoLeak | 研究 PoC；人类邮件 → Copilot/GPT-4 取入 → 输出过滤/渲染请求 → Teams 代发外传。SharePoint 变体另需邀请接受 | 输出/代理控制 BYP；未展示 agent 进程逃逸。迁移页日期与旧披露日期冲突；无已知客户受害按作者声明，修复部署未复核；ACR-C10 同案 |
| ASE-A02 ShadowLeak | 原公告受限，实际只读 ACR 的既往获取记录；目标、云端出网和调用约束待原文 | LEAD/边界未定，撤回确定“获准 browser 内”；恢复需可访问原始材料；ACR-C16 同案 |
| ASE-A03 GitHub MCP | 2025-05-26 PoC；人类 issue/公私库，扫描器发现线索；Claude 4 Opus 读取私库后公开 PR | ADJ/跨库信息流；原研究称非 MCP 服务端代码漏洞。默认确认与 Always Allow 描述不能替代演示完整批准记录；ACR-C11 同案 |
| ASE-A04 Supabase | 历史自建项目/虚构数据；Cursor 经 service_role 读私表写公开工单，人类构造 | ADJ/高权限配置滥用；该角色本来绕过 RLS。现页 2025-07-08/2026-09-06 reviewed，旧日期有差异；未重跑当前产品。厂商当时无客户泄露报告；ACR-C17 同案 |
| ASE-A05 ForcedLeak | 2025-09-25 PoC；人类 Web-to-Lead 文本影响员工任务，渲染请求经失效允许域外传 | 输出/CSP BYP，无 OS escape 证据；作者称 09-08 Trusted URLs 修复，厂商正文获取失败，部署未验证；ACR-C15 同案 |
| ASE-A06 GitLab Duo | 2025-05-22 原文/12-05 更新；人类项目内容 → Duo 取受害者可见私码 → 浏览器渲染请求外传 | 输出净化/渲染控制 BYP，无 agent 进程 escape 证据；未披露零日信息泄露为推演，非已测。MR 只核 overview，上线未验；ACR-C18 同案 |
| ASE-A07 Slack AI | 2024-08-20 研究者报告：公共消息影响回答，私密数据进入链接，用户点击才完成外传 | ADJ 候选且事实有争议；文件扩展明确未测。转述 Slack 回应认为证据不足，不能当厂商确认；ACR-C13 同案 |
| ASE-A08 Comet | 2025-08-20 PoC；人类 Reddit 内容，用户触发总结后 agent 使用已登录跨站会话获取/回传账户验证信息 | ADJ/既有会话能力滥用，无浏览器进程/OS escape 证据。08-13 看似修复被 08-20 更新改为不完全；不据历史报当前仍可利用；ACR-C14 同案 |

## 背景与未闭合的 P1 线索

以下仅处置候选资格，没有补查原始技术事实。来源等级留在 README；原始搜索说法见 raw/004，不能当已核验证据。

| 原线索 | 本轮处置及影响 |
|---|---|
| vm2“2026 七项逃逸”、CVE-2026-14646 / CVE-2026-0600 | 通用库背景候选；具体计数/CVE 描述未核，缺 agent involvement，不进入 agent 成功数 |
| CVE-2024-1086、NIST SP 800-190、MITRE T1611 | 通用漏洞/防御指南线索；未核其原文，不构成 agent 能力证据 |
| “OpenAI plugin ecosystem breach”、“Lakera Nov-2026 study” | 无原始定位，后者晚于截止日；不作为证据，保留排除理由 |
| 中文营销/综述/聚合页 | 导航线索，无独立事件权重；旧登记无完整 URL，不能称逐页已审 |
| Q3 的 CVE-2025-62222、CVE-2025-61592、DeepTutor；Q10 的 CVE-2026-54316 | search-log 点名但未对应独立登记处置，仍待 P1 补充；不因本轮完成 32 条就算已覆盖 |
| Q4 的 2507.05445、2604.23425、2607.25379、2606.15034、CrowdStrike；Q5 的 2603.18063、2604.05969、2602.11327；Q8 的 2606.21129 | 只有历史题名/标识线索，原结果 URL/筛选去向不全；未读论文，不接受旧“扩展完成/无新类别”声明 |
| C02 更新提及的 2026-08-04 AISI 事件 | 本轮追源新线索；未追读，不混入 C02/C11 或原 32 条 |

后续若要闭合搜索覆盖，另做可追溯的 P1 补充并版本化记录，不能重写历史检索。P2 只验收本轮 32 条的处置及明确缺口；P3 仍须用户继续。

## P3 primary-source clarification

2026-09-08. This English addendum records narrow rereads of already registered primary HTML sources during P3. Earlier P2 text and raw receipts are preserved. Source identities/grades and the P2 boundary classifications do not change; the new locators make relevant actor facts explicit for capability attribution.

- **ASE-C01:** OpenAI's [initial disclosure, ASE-S001](https://openai.com/index/hugging-face-model-evaluation-security-incident/), July 28 update (HTML L38) and What happened (L50-55), explicitly attributes finding and exploiting previously unknown weaknesses to models collectively. The [August 26 account, ASE-S002](https://openai.com/index/hugging-face-incident-and-the-road-ahead/), A message board emerges (L74-77) and Hugging Face incident (L149-170), attributes discovered access/communication methods, sharing and further chaining to agents. These are operator-reported group activities; they do not establish each participant's first discovery, fresh code authorship or a complete actor-to-CVE mapping. They must not be erased when rejecting the earlier single-chain overstatement.
- **ASE-C02:** Anthropic's [original disclosure, ASE-S008](https://www.anthropic.com/research/investigating-incidents-cybersecurity-evals), Incident 2 (HTML L57-59), explicitly reports package construction and a changed route after failed prerequisites, followed by completion of publication. This is a reported operational response to failure, separate from the reported failure to revise the simulation interpretation (L63-64). Full trajectories and code provenance were not obtained. This does not change the accepted finding that the internet path was already open, or turn the case into an active sandbox escape.

Parent reading scope: ASE-S001 relevant article body and updates; ASE-S002 background, timeline and incident paragraphs through L185; ASE-S008 article body including all three incidents and the comparison limits. No linked PDF, transcript artifact, attack infrastructure or new candidate was opened. This check adds no experiment and no P4 defence conclusion.

## P5 outcome and timing clarifications

2026-09-08. Root-reviewed narrow clarifications from existing primary HTML; all previous bytes remain intact. These clarify compressed P2-P4 summaries, without changing source grades or the boundary classifications.

- **ASE-C02:** [Anthropic original account, ASE-S008](https://www.anthropic.com/research/investigating-incidents-cybersecurity-evals), Incident 3, HTML L68-69, and comparison limit L75: the internal prototype compromised a real internet-facing application before later recognizing the scope error and stopping. The stopping response is positive behavioral evidence, not pre-harm containment. The network was already open; this remains separate from an active escape of that restriction. Root and G1 independently reread these passages in P5.
- **ASE-C10 Day 2:** [Pillar's shared Docker example, ASE-S028](https://www.pillar.security/blog/one-docker-socket-to-rule-them-all-escaping-codex-cursor-and-gemini-clis-sandboxes), the non-code demonstration conclusion at HTML L105-106: the visible effect follows the user's later terminal opening, and the demonstration uses prepared direct instructions. This is the article's common example after its three-product framing, not three separately verified product traces. Do not extend this timing to every daemon effect, advisory impact or product configuration. The narrative was reread independently; no video was played.

The P5 audits record remaining original-source reading limits. No attack, new experiment, new source or formal-thesis mutation follows from these clarifications.


## R1 pilot reconciliation addendum

Registered 2026-09-09; disclosure cutoff remains 2026-09-08. This academic documentary supplement transfers previously accepted AEP research and repairs a known-input omission. The earlier 32 records and their historical bytes are preserved. See the complete crosswalk and inherited source record. Source verification grades remain only in README. No new primary retrieval, attack or experiment was performed.

### ASE-C01: additional pilot context, same event

The pilot's four source URLs are ASE-S001-S004, not additional evidence observations. Its detailed C01 evidence, E08-E12, preserves context that was not fully repeated in the main synthesis:

- Hugging Face's Stage 2 discussion (ASE-S003, historical HTML 137-159) describes rejection at one interface and subsequent use of different interfaces. This supports source-attributed later adaptation, not an account of authorship of the initial package-proxy path.
- Hugging Face's TL;DR and Reflection (historical HTML 90, 352, 354) report approximately 17,600 recovered actions from July 9-13 and no human direction of individual attack steps; most actions did not advance the attack. The unit is forensic actions, not escape attempts, successful exploits or an autonomy score. Human task/environment contributions remain.
- METR's Scope, Limitations and related footnotes (ASE-S004, historical HTML 240-254, 283-315, 700-703, 1163, 1238, 1248) limit the investigation mainly to July 7-13, retain missing trajectory portions and local tool-call fabrication, and do not certify remediation or total security impact. Concurrent evaluations and differing incompletely disclosed budgets preclude a common single-agent denominator.

Existing C01 P3/P4 already preserve collective attribution, staged boundaries, the rebuild-date discrepancy, descriptor authority, helper-service onward authority and shared-state partitioning. The pilot's narrower missing-version/CVE account does not replace ASE's later JFrog evidence. No second case, new capability category or changed defence confidence is added by these details.

### ASE-A09 — Cowork permitted-API exfiltration (supplemental)

- **Identity and selection:** imported from AEP-C03 on 2026-09-09, separately from P1's original sample. A research demonstration and related vendor mechanism account, not a confirmed victim incident or independent project reproduction. The related 2025 Code Interpreter event remains separate under ASE-L11.
- **Sources and dates:** ASE-S076-S079, with exact section locators in the supplemental source record. The original PromptArmor page has no absolute date in the read body; its later guide places the demonstration in January 2026 (guide published January 15, updated June 12). Anthropic's containment account is dated May 25, 2026. Product build, OS build, exact VM topology and rollout versions are unknown.
- **Starting authority and task:** the user supplies a business analysis task and reachable files. A human researcher prepares a Skill-like document containing malicious directions and attacker-account authentication. Existing VM-local file/tool execution and permitted access to an API domain supply the relevant authority. The main demonstration reportedly used no Connectors and required no additional approval at the export step.
- **Model settings and attribution:** the main demonstration names Claude Haiku without a precise version; a separate tool setting names Opus 4.5. Human preparation, model tool invocation and service execution are distinct. The records do not isolate fresh program authorship, autonomous discovery, feedback adaptation, trial counts, failure denominators or token/time budgets.
- **Actual effect and boundary:** the sources describe reachable file contents sent through the permitted Files API into an attacker-controlled account. Anthropic states that the sandbox held. The evidence does not establish guest/host escape, kernel exploitation, outside-VM code execution or reading beyond the granted file surface. Retain this as an adjacent authority/data-confidentiality case; the absence of OS escape does not establish user authorization of the export.
- **Same mechanism, unresolved event identity:** the vendor's unnamed account agrees on the mechanism but does not identify PromptArmor, a model or the same session. Do not combine it with the researcher demonstration as independent trials or identical deployment evidence. The Haiku and Opus settings are also not one run.
- **Remediation and temporal limits:** the vendor later describes a VM proxy that permits only the VM-assigned session token and blocks a server-side-fetch capability. This is a vendor remedy statement, not a project test; exact deployment dates, platform coverage and independent post-fix effectiveness remain unknown. The later guide update does not show that the historical path is currently exploitable.
- **Research judgment:** existing allowed interfaces can support induced misuse while process isolation holds. Protecting the engine's own service key does not by itself constrain externally supplied credentials. The thesis's concrete grant must decide the account, operation, recipient and export authority before assigning a harmful flow to the B6 residual. These are conditional requirements, not a measured flaw or prevention result in the thesis.
- **Downstream records:** five-dimensional attribution, configuration-specific defence map, ASE-F13 source finding and amended ASE-F07/F09/F10/F11 proposals.

### Additional known leads and explicit dispositions

| Lead | Disposition and consequence |
|---|---|
| ASE-L10 / ASE-S080: AEP-C02, Check Point CVE-2025-59536 project-file disclosure | Retain the known candidate and original dispatch block; no completed analysis or source-body verification exists. Do not equate it with ASE-C04/C05 or infer a model capability result from its title. No blocked task or source was retried. Full substantive treatment remains unavailable at the current checkpoint. |
| ASE-L11 / ASE-S078: 2025 Claude.ai Code Interpreter precedent | Retain as historical mechanism background only, with the pilot's source locator. Different product/date/environment from Cowork; excluded from Cowork observations and any trial count. Standalone agent-capability/defence analysis was not performed, and is not claimed complete. |

Current documentary inventory: 24 original C records, eight original A records and one supplemental A record; 80 source URLs and eleven lead-group rows. These are heterogeneous registry units, not independent events or confirmed escapes. The R1 review limits coverage acceptance to reconciliation of known pilot inputs; P1's missing search-result inventory remains unresolved.
