---
title: 步骤 2 — 凭据取得路径与安全条件的案例证据
created: 2026-09-27
updated: 2026-09-30
purpose: academic-public-source-evidence-review
scope: SUB-01 step 2
tags:
  - academic-research
  - case-evidence
  - contribution
---

# 步骤 2：凭据取得路径与安全条件的案例证据

本文件按 [[plans/2026-09-27-sub01-steps01-02-academic-evidence-review|执行入口]] §3 整理公开文献。研究目的有两个：为 impersonation 分析提供材料取得事实；为逐篇 assumption 检查提供现实条件与反例。**本轮只做台账筛选和公开来源核验，没有获取／使用凭据、执行载荷、访问泄露原件或复现；没有进行逐篇新路径推导或本论文防御核查。**

论文任务与交付状态归 [[Thesis/Work/Submission/TASKS|TASKS]]；本文件是一次证据交付，不是新的状态队列。旧包 raw、来源等级、fragment 与批准状态均未修改。

## 0. 案例结果总览

本文件集中保存筛选、完整案例、条件索引、原始来源定位与证据限制，供步骤 3／5 逐篇选用。B1–B19 含材料取得、条件参照、备选、负对照及集合中的限定事实；BM1、BM2 是官方机制缺陷记录，不能合计为同质的成功攻击数量。

| 研究方向 | 案例 | 证据结论与边界 |
|---|---|---|
| **凭据保护：两条泄露路径** | **诱导披露：**Cursor 工具投毒、Comet、Supabase MCP（B1–B3）；**无需受害 agent 披露：**OpenClaw infostealer、Nx、Sysdig（B4–B6）；**负对照：**ElizaOS（B9） | 两条路径均有代表；Supabase 使用虚构 token。service-account 等执行凭据属于相关保护对象，其滥用与本地 agent 身份错认分别判断。Nx／Sysdig 有后续凭据使用报告，其他记录不能补成已完成冒用。ElizaOS 表明秘密隔离守住仍可能发生受骗代办。 |
| **正确绑定** | Vault AWS、Vault GCP（B18–B19）；SPIRE PID reuse（BM1）；Docker Sandboxes 官方缺陷修复（BM2）；Amazon Q（B7）及节点 root 后的 SPIRE（BN-05）作边界参照 | Vault 支持特定条件下错误发行身份能力；PID 记录支持 caller 生命周期曾有安全缺陷，但没有公开完整冒用轨迹。Docker 记录支持已部署的沙箱凭据代理在跨沙箱登录劫持、组件信任继承、名称复用与撤销生效上曾有缺陷，均已修复、无利用轨迹。不能据此认定可信节点下受限 agent 已冒用另一不合谋 agent。 |
| **完整中介** | Cowork、ForcedLeak、Copilot、CurXecute、MCPoison、OpenAI／Hugging Face 的限定阶段、Claude Code、Gemini、Zed（B8、B10–B17）；Amazon Q（B7）提供身份上下文继承参照 | 覆盖接收者、域控制权、审批政策、批准时点／内容持续关联、辅助服务、隔离外消费者及运行模式。它们是条件证据；不属于凭据泄露证据，也不直接证明任何论文失效或本论文可防御。 |

**分类约定：**P1＝诱导受害 agent 披露；P2＝材料取得不依赖受害 agent 披露；混合链分别记录执行者。normal 只指不主动合谋，不表示始终正确。用户、服务账户、设备、网关和 agent 实例是不同身份粒度；材料取得、有效凭据、身份被接受、合法委托和受骗代办分别判断。

案例支持特定路径或条件的存在；逐篇适用性、本论文建立条件／防御能力、已有组合是否同效仍需各自证据。K1–K18 是检查入口，不是预定所有论文都依赖或本论文已提供的保证。

## A. 完整浅筛与去重

案例按具体路径／条件是否有关及证据是否充分筛选：**已详记**（完整字段在 §B，含条件参照／备选）、**相关备选**、**机制参照**、**待核**、**当前范围外**。当前有 24 条旧登记已详记、23 条相关备选、3 条机制参照、9 条待核、12 条当前范围外，共 71 条；跨包重复不能计为独立事件。

无凭据终点只能限制泄露用途，不能单独排除 assumption 用途。未详记候选仍只有浅筛；范围外结论针对当前研究条件，逐篇发现新承重条件时可据理由重评。筛选方法见 [[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-02/step-02-scope-reassessment|案例筛选方法与边界]]，不以固定案例数量证明贡献。

读取范围为 ACR-C01–C38，以及 ASE-C01–C24、ASE-A01–A09。**38＋33 是登记单元数，不是独立事件数。** ASE-C01／C02 是集合，C10 是来源家族，C11 是基准，C20／C21 是机制分析；ACR 与 ASE 还有多处同案。

原入口：[[Thesis/Work/Intake/2026-08-30-agent-contamination-rootcause/README|ACR 台账]]、[[Thesis/Work/Intake/2026-08-30-agent-contamination-rootcause/checkpoint|ACR 恢复点]]、[[Thesis/Work/Intake/2026-09-08-agent-sandbox-escape/case-register|ASE 台账（含 R1 补充）]]、[[Thesis/Work/Intake/2026-09-08-agent-sandbox-escape/checkpoint|ASE 恢复点]]。筛选依据是各包当前核验范围，不将旧标签直接迁移。

### A1. ACR 逐条处置

下表区分研究相关性与详细核验程度：**10 已详记、1 机制参照、3 待核、12 当前范围外、12 相关备选**。完整采用事实见 §B；未详记项不据此提升证据等级。

| 原 ID | 对象 | 本轮处置与理由 |
|---|---|---|
| ACR-C01 | Morris II | 当前范围外：当前记录用于传播／RAG 污染，尚未对应本轮所选凭据、执行主体绑定或技术中介条件 |
| ACR-C02 | Agent Smith | 当前范围外：当前记录用于共享记忆传播；没有已明确对应本轮三个条件家族的机制失效 |
| ACR-C03 | Prompt Infection | 当前范围外：当前用途为消息解释与传播；不能由内容污染推断技术绑定或中介失效 |
| ACR-C04 | MAS control-flow hijacking | 当前范围外：当前用途为模型解释／编排信任；未定位所选技术绑定或权限中介条件 |
| ACR-C05 | Agent-in-the-Middle | 当前范围外：截取替换位置由模型直接给定，未提供该能力在现实部署中取得的证据；不补成历史存在证明 |
| ACR-C06 | Agent Card Poisoning | 相关备选：待区分卡片影响规划与可信身份声明被接受；前者不直接支持绑定失效 |
| ACR-C07 | A drives B | 当前范围外：合谋／代办分析示例，非历史或公开复现证据；相关概念已保留在研究定义 |
| ACR-C08 | Copilot-for-Word worm | 当前范围外：当前记录仅支持文档传播；未定位所选身份使用／权限中介依赖 |
| ACR-C09 | Mind Viruses | 当前范围外：当前记录为记忆传播实验及边界；未定位所选技术条件，不以传播成功替代 |
| ACR-C10 | EchoLeak | 相关备选：输出代理与允许服务的效果路径；与 B8 的账户条件不等价，保留供对应假设调用 |
| ACR-C11 | GitHub MCP | 相关备选：跨库读写权限与数据最终流向；仅在相关论文承诺覆盖此授权关系时采用 |
| ACR-C12 | GitLost | 相关备选：私有内容的读取／输出约束参照；需有来源支持具体失效条件，不能只凭外传结果 |
| ACR-C13 | Slack AI | 待核：材料与实际外传存在争议，需点击；不作确认例 |
| ACR-C14 | Comet | 已详记：B2；用户 OTP 披露，后续接管只作来源能力主张 |
| ACR-C15 | ForcedLeak | 已详记：B10；允许域控制权生命周期，条件参照；同 ASE-A05 |
| ACR-C16 | ShadowLeak | 待核：原始来源受限，不能提升旧转述 |
| ACR-C17 | Supabase MCP | 已详记：B3；虚构 token 表披露及权限条件 |
| ACR-C18 | GitLab Duo | 相关备选：输出渲染者参与产生网络效果；普通代码泄露可作中介参照，不能算身份材料 |
| ACR-C19 | Invitation Is All You Need | 相关备选：跨 agent 输出影响编排；待区分内容误导与未经中介的权限／效果，不自动升级 |
| ACR-C20 | Copilot CVE-2025-53773 | 已详记：B11；审批控制状态保护；同 ASE-C13，无凭据取得终点 |
| ACR-C21 | 0DIN Clone This Repo | 相关备选：预获准初始化链的权能与中介范围；需区分原授权过宽和技术检查被绕过 |
| ACR-C22 | SpAIware | 相关备选：持久记忆与外传通道的组合；只有可对应明确权限／出网条件时进入 assumption 证据 |
| ACR-C23 | AgentPoison | 当前范围外：检索操纵与内容决策问题；当前未对应所选凭据、执行主体绑定或技术中介条件 |
| ACR-C24 | PoisonedRAG | 当前范围外：知识污染与回答误导；当前未对应所选技术条件 |
| ACR-C25 | MINJA | 相关备选：身份伪装是未实验论述；可为后续非泄露机制分析留线索，不作历史存在证据 |
| ACR-C26 | ElizaOS／Fake Memories | 已详记：B9；凭据隔离守住的负对照 |
| ACR-C27 | Invariant tool poisoning | 已详记：B1；明确 SSH key 披露的产品实验 |
| ACR-C28 | CurXecute | 已详记：B12；新建配置在生效前的审批覆盖；同 ASE-C14 |
| ACR-C29 | MCPoison | 已详记：B13；批准与实际内容持续关联，非运行主体身份绑定；同 ASE-C15 |
| ACR-C30 | postmark-mcp | 相关备选：工具供应链和被授予的操作权能；需核是否仅可信组件已被替换，本论文是否同样依赖该可信性 |
| ACR-C31 | Amazon Q 2025 供应链 | 相关备选：已有 token 使用终点但取得机制不全；保留凭据使用与供应链条件，不能被 Nx 概括替代 |
| ACR-C32 | Rules File Backdoor | 相关备选：规则内容是否越过配置／批准边界待区分；若仅模型相信输入则不能支持技术中介失效 |
| ACR-C33 | ClawHavoc 集合 | 待核：需拆分技能／行为；整体不能当统一身份窃取链 |
| ACR-C34 | Amazon Q 2026 | 已详记：B7；身份能力继承参照，收窄旧凭据外传读法 |
| ACR-C35 | Akamai MCP _meta | 机制参照：客户端声明与可信授权上下文的区别；同 ASE-C21；条件性分析，不能冒充历史案例 |
| ACR-C36 | Nx s1ngularity | 已详记：B5；程序取得凭据、后续账户滥用及分工限制 |
| ACR-C37 | Semantic cache poisoning | 当前范围外：当前为共享缓存的数据隔离问题；尚未对应所选身份使用路径，不重开 CTT 方向 |
| ACR-C38 | Cache Me, Catch You | 当前范围外：当前为缓存键的数据主体隔离；不自动等同身份验证或身份使用绑定 |

### A2. ASE 逐条处置

登记处置为 **14 已详记、2 机制参照、6 待核、0 当前范围外、11 相关备选**。覆盖包括后补 ASE-A09；原 case-register 开头 P2 停点不覆盖其后 R1 修订。

| 原 ID | 对象 | 本轮处置与理由 |
|---|---|---|
| ASE-C01 | OpenAI／Hugging Face 集合 | 已详记：B14；集合分阶段，仅采用包服务代发网络的限定事实 |
| ASE-C02 | Anthropic 三事件 | 相关备选：网络能力原已开放及环境误述；保留边界参照，不能把误述本身当技术隔离失效 |
| ASE-C03 | Mythos Preview 线索 | 待核：匹配原文未读，核心事实未验收 |
| ASE-C04 | Claude Code CVE-2026-39861 | 已详记：B15；隔离外文件消费者的越界写入；不推为已观测执行或凭据泄露 |
| ASE-C05 | Claude Code CVE-2026-55607 | 相关备选：宿主辅助执行与路径边界；保留具体中介条件，未报告材料取得不作排除理由 |
| ASE-C06 | Cursor DuneSlide | 相关备选：不同工作区外写入／执行路径；需分别核触发前提与中介缺口，不能合成一条链 |
| ASE-C07 | Cursor hook | 相关备选：hook 执行位置与授权边界；数据窃取只是潜在影响，不作凭据终点 |
| ASE-C08 | Codex GitPwned | 相关备选：调用授权例外与后续执行约束；核先前授权是否覆盖实际效果，而非只查是否偷 key |
| ASE-C09 | Gemini trust／allowlist | 已详记：B16；入口配置信任与模式下授权分为两路，不计两次实验 |
| ASE-C10 | Pillar 来源家族 | 相关备选：来源家族需按子条目拆分；C07/C08 重复，集合不计独立事件 |
| ASE-C11 | SandboxEscapeBench | 待核：核心论文未读；不能从基准标题判定是否涉及所需中介条件；不自动要求读 PDF |
| ASE-C12 | Sysdig 工作负载事件 | 已详记：B6；pod token 取得与 API 使用 |
| ASE-C13 | Copilot CVE-2025-53773 | 已详记：B11；同 ACR-C20，审批控制状态保护 |
| ASE-C14 | CurXecute | 已详记：B12；同 ACR-C28，新建配置生效前的审批覆盖 |
| ASE-C15 | MCPoison | 已详记：B13；同 ACR-C29，已有批准与后续实际内容关联 |
| ASE-C16 | Amazon Q 2026 | 已详记：B7；同 ACR-C34，采用收窄事实与来源冲突 |
| ASE-C17 | Claude Code issue #25000 | 待核：用户自报，缺日志／配置／维护者确认 |
| ASE-C18 | Zed CVE-2025-55012 | 已详记（条件备选）：B17；与 B11 共用审批政策保护条件，保留厂商公告事实 |
| ASE-C19 | 0DIN Clone This Repo | 相关备选：同 ACR-C21；预准 setup 权能边界，不默认技术检查失效 |
| ASE-C20 | MCP confused-deputy | 机制参照：client 身份、同意与上游权限关联；官方机制说明，仅作检索与逐篇分析参照 |
| ASE-C21 | Akamai _meta | 机制参照：同 ACR-C35；客户端可控元数据的信任来源，未证现实受害实例 |
| ASE-C22 | ClawHavoc 集合 | 待核：同 ACR-C33；需逐技能拆分、旧 Koi 原文缺失 |
| ASE-C23 | postmark-mcp | 相关备选：同 ACR-C30；工具供应链信任参照，品牌冒充不等于主体身份冒用 |
| ASE-C24 | Nx s1ngularity | 已详记：B5；同 ACR-C36，程序与 agent 分工明确 |
| ASE-A01 | EchoLeak | 相关备选：同 ACR-C10；输出代理与效果路径，不能因普通数据而排除 assumption 用途 |
| ASE-A02 | ShadowLeak | 待核：同 ACR-C16；原文访问限制仍在 |
| ASE-A03 | GitHub MCP | 相关备选：同 ACR-C11；跨库授权与数据效果关系 |
| ASE-A04 | Supabase MCP | 已详记：B3；同 ACR-C17，虚构 token 表及角色权限 |
| ASE-A05 | ForcedLeak | 已详记：B10；同 ACR-C15，允许目的地控制权生命周期 |
| ASE-A06 | GitLab Duo | 相关备选：同 ACR-C18；渲染消费者参与输出效果的条件 |
| ASE-A07 | Slack AI | 待核：同 ACR-C13；来源争议、点击条件未解决，不作为已确认条件失效 |
| ASE-A08 | Comet | 已详记：B2；同 ACR-C14，账户 OTP 与后续能力主张分开 |
| ASE-A09 | Cowork API 外传 | 已详记：B8；攻击者自备凭据，只作中介条件参照 |

### A3. 已详记的 ACR／ASE 与 OpenClaw 记录

| 记录 | 原 ID／来源 ID | 处置与用途 | 去重与边界 |
|---|---|---|---|
| B1 | ACR-C27 | 选取：P1 凭据字节披露代表 | 这里只取 Invariant Experiment 1；shadowing、WhatsApp、rug pull 不另合算成同一观测 |
| B2 | ACR-C14＝ASE-A08 | 选取：P1 用户账户 OTP | 一案两份旧记录，不是两次确认 |
| B3 | ACR-C17＝ASE-A04 | 选取：P1 虚构 token 数据与权限条件 | 同一历史演示；旧日期与更新页差异见 D |
| B4 | N01 | 选取：P2 agent 相关网关／设备材料 | Hudson Rock 单一感染观察；与 ClawHavoc 不是同案，不复用后者数量 |
| B5 | ACR-C36＝ASE-C24 | 选取：P2／混合链及账户凭据后续滥用 | 一个供应链事件含多阶段、多受害者；来源数不计事件数 |
| B6 | ASE-C12 | 选取：P2 工作负载 token 与 API 使用 | token 路径与宿主突破路径分开；受害者为应用工作负载 |
| B7 | ACR-C34＝ASE-C16 | 选取：条件参照、过度结论纠正 | 未证明密钥离机；另一 symlink CVE 不合并 |
| B8 | ASE-A09 | 选取：中介条件参照 | 攻击者自有 API credential；不计受害者凭据披露 |
| B9 | ACR-C26 | 选取：凭据隔离守住的负对照 | ElizaOS PoC 与 CrAIBench／WebVoyager 模拟不混为同一次实验 |
| B10 | ACR-C15＝ASE-A05 | 中介条件：允许域控制权变化 | 业务信息外传，非凭据披露 |
| B11 | ACR-C20＝ASE-C13 | 中介条件：审批政策保护 | 执行能力不等于凭据取得 |
| B12 | ACR-C28＝ASE-C14 | 中介条件：新建配置先批准后生效 | 与 B13 的批准后内容变化分开 |
| B13 | ACR-C29＝ASE-C15 | 中介条件：批准与实际内容持续关联 | 需要已有写权；非 caller 身份绑定 |
| B14 | ASE-C01 | 中介条件：包服务代发网络效果 | 只采用 B14a，其余阶段分别限定，不计独立事件 |
| B15 | ASE-C04 | 中介条件：隔离外文件消费者 | 公告确认越界写入，执行仅为可能影响 |
| B16 | ASE-C09 | 中介条件：入口信任及模式下授权 | 两条机制路径，不计两次实测 |
| B17 | ASE-C18 | B11 同条件的厂商公告备选 | 保留独立事实，不增加条件种类 |

其他跨包同案：ACR-C10＝ASE-A01、C11＝A03、C13＝A07、C15＝A05、C16＝A02、C18＝A06、C20＝C13、C21＝C19、C28＝C14、C29＝C15、C30＝C23、C33＝C22、C35＝C21。ASE-C10 中 Day 5／Day 6 分别与 C08／C07 重叠；不是另增两案。ASE-L11 的 2025 Code Interpreter 与 A09 的 Cowork 分开。N01 与既有 ClawHavoc 名称相关，但初始感染机制与单一事件没有同一性证据。

### A4. 外部 IAM 与工作负载身份来源的处置

BN 为本文件的来源候选号；完整采用记录见 B18／B19／BM1，备选与边界材料见 BQ，精确来源目录见 D5。

| 本表位置／来源 ID | 对象与处置 | 证据和边界 |
|---|---|---|
| B18／BN-01 | Vault AWS IAM；采用条件证据 | 公开登录响应显示错误发行 Vault token；非受害凭据泄露 |
| B19／BN-02 | Vault GCP GCE；采用条件证据 | 厂商确认错误发行，研究者 PoC 叙述；该分支未展示独立登录响应 |
| BM1／BN-03 | SPIRE PID reuse；采用已修复机制缺陷 | 官方安全修复；没有公开冒用轨迹 |
| BN-04 | Vault 跨账户认证缓存；相关备选 | 公告已读，命名空间条件；未扩原 PoC |
| BN-05 | SPIRE 节点 root 后 selector spoofing；边界对照 | 已有节点 root，不填可信节点下受限 caller 正例；可信基础被破坏的 assumption 用途仍保留 |
| BN-06 | GKE metadata downgrade；待核 | 原始页面正文未取得，不据摘要采用 |
| BN-07 | SPIRE 节点证明修复；相关线索 | 仅 CHANGELOG 条目，未深查；不同于 workload caller 实测 |
| BN-08 | Agent Name Collision 论文；待核线索 | 仅检索摘要，无笔记／全文；不采用实验结论 |

## B. 采用案例与承重主张

事件性质、来源核验与实际终点分别记录。缺失的版本／配置、实施日期或权限均保留未知；来源披露／修复日期不作为实验日。各条明确直接核验或既有核验复用的范围，实际阅读日志见 §D。B1–B19 与 BM1 的完整字段均在本节，不依赖另一份案例报告。

### B1. ACR-C27：Cursor 工具投毒中的凭据披露

- **事件与角色：**Invariant 的产品实验，2025-04-01 为披露日期；本轮已核材料未确定具体实施日期。A 为执行用户算术任务的 Cursor agent，B 为研究者控制的 MCP server／工具描述。A 被描述为受诱导的客户端，不是预设合谋 agent；研究环境有研究者准备，不能视为在野受害者。
- **材料与执行者：**用户 SSH 私钥及 MCP 配置；配置可能含其他服务凭据，但不等于每项内容都经有效性验证。读取并提交内容的是 A，归 **P1**。前提是用户连接该 MCP server，A 可读文件且可调用工具。
- **报告终点：**作者明确报告文件内容发给恶意服务器。确认界面存在，但未完整呈现工具输入。没有后续 SSH 登录、其他服务认证或 agent 实例身份冒用的观测。
- **定位／核验：**[Invariant, *MCP Security Notification: Tool Poisoning Attacks*](https://invariantlabs.ai/blog/mcp-security-notification)，Luca Beurer-Kellner、Marc Fischer，2025-04-01；**Experiment 1: Attacking Cursor with Tool Poisoning**（本轮 HTML 60–68），本轮核原始正文。旧溯源：ACR raw/002 **C1 return → 记录 1**（含当时作者信息和读取限制）。
- **可用判断与限制：**支持“良性任务中的 agent 可能被诱导披露其可读凭据”；不证明那些凭据专属于 agent，也不证明原本不可读的秘密被突破。server 沙箱与客户端读取权限是不同条件；本轮不分析任何机制论文。

### B2. ACR-C14／ASE-A08：Comet 的用户 OTP 披露

- **事件与角色：**Brave 产品 PoC，2025-08-20 为披露日期；本轮已核材料未确定具体实施日期。A 为替用户总结网页的 Comet；B 控制页面中的用户内容；用户已有账户和邮箱登录会话。来源设置是用户不知情触发，不是双方合谋；模型、browser build 未给。
- **材料／路径：**用户邮箱地址与 Perplexity 一次性验证码；A 跨站读取并回传，属 **P1**。身份对象为用户账户认证材料，非独立 agent 私钥或实例 ID。
- **终点：**原文描述 email＋OTP 外传，随后说攻击者 **can take over**。本轮据此记录作者声称该组合可用于接管，**不记为已观察到攻击者实际登录**。未核视频或私有轨迹。
- **定位／核验：**[Brave, *Agentic Browser Security: Indirect Prompt Injection in Perplexity Comet*](https://brave.com/blog/comet-prompt-injection/)，Artem Chaikin、Shivan Kaul Sahib，2025-08-20；**Attack demonstration**（81–94）及 **Disclosure timeline**（114–120），本轮核原始正文。旧溯源：[[Thesis/Work/Intake/2026-09-08-agent-sandbox-escape/verification/parent/ASE-A08|ASE-A08 核验]]。
- **限制：**时间线先称看似修复，后更新称同类攻击未完全缓解；不据此声称当前仍可利用。存在已登录跨站权限是必要配置，不能泛化到没有该权限的 agent。

### B3. ACR-C17／ASE-A04：Supabase 虚构 token 表披露

- **事件／角色：**General Analysis 自建项目 PoC；本轮已核材料未确定具体实施日期，下文 2025-07-08 与 2026-09-06 分别是现页所标日期和 Reviewed 日期。B 可提交支持工单；A 为开发者的 Cursor assistant，经 MCP 使用 `service_role`；普通支持人员权限不同。数据是 **dummy data**，非客户失窃事件。
- **材料／路径与终点：**测试数据库表示用户 refresh／integration tokens。A 被工单内容诱导将私表内容写回客户可见回复，属 **P1 的受控材料披露演示**。不是 agent 自己认证密钥失窃；没有有效 token 兑换、会话恢复或冒用测试。
- **条件：**所用数据库角色能越过 RLS，且可写攻击者可见表。结论不是“RLS 被破解”或当前托管 MCP 默认如此。A 是被误导的开发助手，没有预设与攻击者合谋。
- **定位／核验：**[General Analysis, *Supabase MCP can leak your entire SQL database*](https://generalanalysis.com/blog/supabase-mcp-blog)，Rez Havaei、Rex Liu、Maximilian Li；现页 **2025-07-08 / Reviewed 2026-09-06**；**Test Setup、Actors & Privilege Boundaries、Demo Application、Attack Flow**。本轮核原始正文的设置、材料与结果；本轮没有重跑演示。旧溯源：[[Thesis/Work/Intake/2026-09-08-agent-sandbox-escape/verification/parent/ASE-A04|ASE-A04 核验]]。
- **限制：**来源明确现时指导更新并非当前产品复测；旧 ACR 的 2025-06-16 日期不可当当前网页日期。厂商关于无客户泄露报告的旧回应仅按 ASE 已核范围复用，不当本轮新调查。

### B4. N01：OpenClaw 配置被 infostealer 取得

- **性质与配置：**Hudson Rock 报告的在野感染观察，2026-02-16 发布；感染日期、OpenClaw build、OS、最初入侵方式和权限未知。B 是已感染宿主的 infostealer，没有证据表明由 AI agent 驱动；这只是事件元数据，**不是排除其研究适用性的理由**。用户 9/28 明确攻击者不限定为 agent，适用性按程序实际权限及所跨保护边界判断。
- **材料与取得者：**原文报告通用文件抓取取得 OpenClaw gateway token 与 device 私钥；前者是 gateway-client 认证材料，后者用于设备配对／签名。取得环节由恶意程序完成，归 **P2**；没有受害 agent 被诱导披露的报告。来源未提供完整 A 行为轨迹，不能进一步宣称 A 从头至尾绝对无动作。
- **终点：**观察支持配置和密钥材料外传。原文 **Technical Risk** 的冒充客户端、签名或绕过设备检查，以及 Enki 分析属于风险解释，**未报告实际冒用成功**。
- **定位／核验：**[Hudson Rock／InfoStealers, *Hudson Rock Identifies Real-World Infostealer Infection Targeting OpenClaw Configurations*](https://www.infostealers.com/article/hudson-rock-identifies-real-world-infostealer-infection-targeting-openclaw-configurations/)，署名 InfoStealers，2026-02-16；导语、**A “Grab-Bag” Attack with Targeted Impact**、**Analyzing the Payload: What Was Stolen? §1–2**（本轮正文 19、25、30、38、42），本轮核原文。风险语句分别在 35、43、54。未访问泄露图片或原件；不是本项目取证或独立复现。
- **可用范围：**这是无需受害 agent 执行披露而取得 agent 相关身份材料的直接代表。它不确定每个逻辑 agent／实例的身份粒度，也不证明不具宿主文件访问能力的另一个 agent 同样能取得；这些是后续适用性问题。
- **9/29 入口补查：**重读原报告导语、Grab-Bag、What Was Stolen、结论，并按 Hudson Rock／InfoStealers 域名查该次感染入口，未取得这一受害事件的投递、执行权限或提权链。检索出现的 ClawHavoc／恶意 skill 是其他事件线索，不能接到本案前面。当前仍只能写“初始感染未知 → infostealer 抓取可达配置 → 外传”，不将未知感染补成 agent 安装恶意 skill 或宿主 root。

### B5. ACR-C36／ASE-C24：Nx 的凭据取得与后续滥用

- **事件／配置与初始入口：**2025-08-26 供应链事件。9/29 从 Nx 复盘 Technical Details 补回前半链：外部恶意 PR 标题 → 存在注入的 CI 工作流以仓库权限执行 → 攻击者取得工作流 token，改动分支并触发发布工作流 → 窃取 npm 发布 token → 发布被投毒包 → 下游开发机／CI 安装受影响版本，触发 postinstall。B 为供应链攻击者及其程序；不能再把“下游恶意程序已经执行”当作未解释的起点。
- **材料／执行者：**下游 GitHub、npm、云凭据等宿主秘密可承载执行权限，与本地 agent ID 分开命名。采集和外传由恶意程序完成，属 **P2／含诱导侦察的混合链**，不是 A 输出密钥字节的直接证据。AI CLI 可能协助侦察，不是全部感染的必要步骤；未报告下游用户主动授权秘密外传。
- **实际终点：**Nx 厂商确认安装程序扫描并上传数据；Wiz／GitGuardian 分别报告有效凭据泄露，后续失窃 GitHub token 用于公开私库。后续属于 GitHub 账户权限滥用，不等于所有失窃材料均被使用。
- **定位／本轮核验：**[Nx 厂商复盘](https://nx.dev/blog/s1ngularity-postmortem)，Juri Strumpflohner，2025-09-05，**What Happened**（48–57）；[Wiz 事件研究](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)，Merav Bar、Rami McCarthy，2025-08-27，**What happened?** 及 08-28／29 更新（29–36）；[GitGuardian](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/)，Guillaume Valadon、Anna Nabiullina，2025-08-27，**UPDATE 3**（50–59）与 **LLM Compliance Resistance**（70–72）。本轮核上述正文。
- **旧溯源与限制：**[[Thesis/Work/Intake/2026-09-08-agent-sandbox-escape/verification/G3/ASE-C24|ASE-C24 核验]]。上游 CI 的仓库／发布权限与下游安装进程的 OS 权限是两个权限域；厂商没有逐台给出后者的 UID，不能把上游的权限提升当作下游已有宿主 root。恶意版本沿原表逐项列举，不写连续范围；95／366 的路径清单产出不是受控成功率。没有证据把每个后续被用 token 追溯到某次 AI CLI 成功；“agent 获得材料”与“恶意程序取得材料”分别记录。

### B6. ASE-C12：应用工作负载 token 的取得与 API 使用

- **性质／角色：**Sysdig 2026-06-04 报告 05-29 观测，归属 B 为 agent-driven operator；受害端为 marimo 应用 pod。比较时可将该应用映射为 A 侧不可信执行环境，但原事件不是已验证的两 agent 部署。攻击者是否由 AI 驱动不是纳入门槛。
- **入侵前与入口：**报告导语明确称观察到攻击者利用 CVE-2026-39987，IOC 节另标记 exploitation 来源；不是仅给定“已控制应用”。[marimo 官方公告](https://github.com/marimo-team/marimo/security/advisories/GHSA-2679-6mx9-h9xc)（2026-04-08，Summary／Root Cause／Attack Chain）确认：终端 WebSocket 漏掉认证检查，在受影响版本、EDIT 模式和支持终端的部署中，网络可达的未认证攻击者可取得应用侧 shell。公告列受影响版本 ≤0.20.4、修复版 0.23.0。**公告证明入口机制；5/29 事件归属仍来自 Sysdig，不把公告 PoC 拼成该次事件日志。**
- **材料／路径与结果：**应用 pod 挂载的 Kubernetes service-account token 由攻击侧代码直接读取，再用于集群 API；不依赖受害 agent 主动披露，归 **P2**。Phase 2 展示列取 default namespace 的 Secrets，已超过仅发现 token；不采用引言的全群集范围，也不补成后续云／数据库登录。
- **pod 与读取能力：**“应用 pod”是运行该应用的 Kubernetes 部署单元，内含一个或多个容器；pod 不是应用进程、也不是宿主机。此案 token 被挂载成应用环境可访问的文件。[Kubernetes Pod 文档](https://kubernetes.io/docs/concepts/workloads/pods/)的定义与 [Service Accounts 文档](https://kubernetes.io/docs/concepts/security/service-accounts/)的 Assign a ServiceAccount to a Pod 说明这种结构（9/29 核读；仅作机制解释，不倒填事件配置）。本案经 shell 取得读能力，但“必须有完整命令执行”不是文件泄露的一般必要条件：从文件访问机制可推得，能读该文件的更窄漏洞也可能足够；本案没有观察这种替代入口。
- **“直接读”取决于代码位置：**若恶意代码已在 A 的应用权限域内运行，能看到该挂载且拥有读权限，它就可以直接读取，Pod 不会按代码善恶再做一次隔离。如果代码只在 B 自己的 Pod／容器内，读取同名路径并不会自动访问 A 的文件；需另有共享挂载、可利用的文件读取接口、进入 A 的执行能力或其他跨域权限。本案报告的是经应用漏洞进入后的读取，不是“进入后还被 Pod 拦住”。这是依 [Kubernetes Volumes 的容器文件系统视图说明](https://kubernetes.io/docs/concepts/storage/volumes/#background)作的权限解释，不宣称所有 Pod 必然隔离良好或一定没有共享存储。
- **两条效果路径，不能强串：**入口是外部利用 marimo。应用控制后，报告分别描述①可达 Docker 管理 socket → 启动特权容器 → 取得宿主访问；②读取应用 pod 挂载 token → 调用 Kubernetes API。①落到本论文排除的宿主高权限；②的材料本来就在应用环境，不能因报告先写 Phase 1，就认定它必须依赖①。这里拆的是因果依赖，不宣称两路实际并发，或②已在低权限配置下独立复现。
- **真正影响范围判断的缺口：**已知是“报告确认 token 被读并被使用”；未知是“读取进程是否仅凭拟比较的普通应用权限就能这样做”。UID 是该进程的 OS 用户身份，连同文件读权限、挂载位置及额外能力，决定可读范围；不要求为数字本身补日志。主文没有给足这些配置，且同次事件确有①，所以不能把②升级成已验证的受限 B 路径。官方 PoC 的容器 uid=0 不等于 5/29 配置，也不自动等于宿主 root。若材料已在普通应用权限下可读，无需先取得宿主 root；这是条件推导，非该事件新增观测。
- **其他来源限度：**主文未提供完整入口请求、部署及观测环境配置。研究方植入 canary 不足以判断所有输出是真实生产秘密还是测试材料，保持“Sysdig 报告的观测”证据等级；这不否定其明确报告的外部利用与 token 使用。
- **本论文用途：**service-account token 正是相关保护对象；凭据不叫 agent ID、受害端是应用，都不是排除理由。它支持“应用控制可转化为可达执行凭据的取得与使用”的条件证据。映射到本论文后，应检查同等应用侧权限能否读取 engine-held 凭据，或越权触发代理使用；尚未作防御裁定。它仍不独立证明本地 engine 将 B 错认成 A，这是另一个待验证主张。定义及边界见 [[Thesis/Work/Design/sandbox-mediated-agent-execution/mechanism#Protected credentials and the role of agent identity|机制说明]]与 [[Thesis/Work/Design/sandbox-mediated-agent-execution/scope-and-boundary#Application control and the adversary boundary|权威边界]]。
- **定位／核验：**[Sysdig 原报告](https://www.sysdig.com/blog/agentic-threat-actor-hits-the-orchestration-plane-ai-agent-driven-container-escape)，Michael Clark，2026-06-04；导语、The agentic signature、Phase 1、Phase 2、Indicators of compromise。2026-09-29 回查正文并补读上述官方公告的机制／条件／复现环境；仅作来源分析，未运行攻击。旧溯源：[[Thesis/Work/Intake/2026-09-08-agent-sandbox-escape/verification/G1/ASE-C12|ASE-C12 核验]]。

### B7. ACR-C34／ASE-C16：Amazon Q 的身份上下文继承

- **性质／角色与对象：**Wiz 产品 PoC，2026-06-26 为 Wiz 披露日期；本轮已核材料未确定具体实施日期。恶意仓库配置经扩展启动程序。B 控制工作区配置，开发者打开／启用项目；没有要求模型受自然语言诱导。目标材料是开发者 AWS 身份上下文，不是 agent 实例 ID。
- **报告终点：**Wiz 报告子进程继承环境并成功使用活动 AWS 身份；公开演示只显示 `GetCallerIdentity` 调用及结果传出。API 返回 Account／Arn／UserId，**没有据此证实密钥字节离机或异地重用**。本轮只作条件参照，不计成功泄露类。
- **触发条件及未解决冲突：**Wiz 写打开仓库／激活扩展即可，且无 workspace trust check；AWS bulletin 和 9/29 补读的 [GHSA-xhcr-j4j9-3gh7](https://github.com/Amazon-Q-Developer/language-servers/security/advisories/GHSA-xhcr-j4j9-3gh7) Impact 均明确要求用户先信任工作区。保守采用路径为“B 控制仓库配置 → 用户打开并信任工作区 → 配置命令自动执行 → 子进程使用已有 AWS 身份”。Wiz 的更强无信任提示分支保持来源冲突，不能以猜测 IDE／server 的检查位置来消解。信任工作区也不自动等于用户明确授权泄密；最终授权判据仍须具体核对。
- **定位／核验：**[Wiz, *MCP Auto-Execution: From Git Clone to Cloud Compromise in Amazon Q VS Code Extension*](https://www.wiz.io/blog/amazon-q-vulnerability)，Maor Dokhanian，2026-06-26；**Technical Breakdown、Proof of Concept、Impact Assessment**，本轮核原文；[AWS Bulletin 2026-047-AWS](https://aws.amazon.com/security/security-bulletins/2026-047-aws/)，2026-06-23，**Description**（本轮 234–237），本轮核原文。GetCallerIdentity 的字段语义复用 [[Thesis/Work/Intake/2026-09-08-agent-sandbox-escape/verification/G3/ASE-C16|ASE-C16 已核官方 API 记录]]，本轮未重新打开 API 文档。
- **版本／限制：**本 CVE 修复门槛为 language server 1.65.0；联合 bulletin 的 1.69.0 同时覆盖另一 symlink CVE，不能混同。不能以环境继承直接替代“凭据已取得且冒用成功”的证据。

### B8. ASE-A09：允许域中的攻击者账户外传

- **性质／角色：**PromptArmor 的 Cowork 研究演示（后续 guide 定位到 2026-01）；A 处理业务任务及可访问文件，B 在文档中提供恶意指示及**攻击者自己的 API credential**。主要演示用 Haiku，另一设置为 Opus 4.5；不是两个独立在野受害案例。构建／OS 未给。
- **路径与对象：**A 通过允许的 API 域把文件发送到攻击者账户。被披露的是业务文件，不是受害者认证材料；故为**条件参照，不计 P1 凭据泄露**。用户配置文件访问不代表授权该次外传，来源未报告主动合谋。
- **终点与条件：**文件进入攻击者控制账户；Anthropic 的相关机制说明称 sandbox held，并说明后续代理限制 VM 指派会话 token 等措施。厂商没有确认与 PromptArmor 是同一会话；不同报告不能作两次相同实验。
- **来源与复用范围：**本轮**只复用既有已审记录** [[Thesis/Work/Intake/2026-09-08-agent-sandbox-escape/verification/supplement/ASE-A09|ASE-A09 来源表]]：PromptArmor, [*Claude Cowork Exfiltrates Files*](https://www.promptarmor.com/resources/claude-cowork-exfiltrates-files)，**Context / The Attack Chain / A Note on Model-specific Resilience**；Anthropic, [*How we contain Claude*](https://www.anthropic.com/engineering/how-we-contain-claude)，2026-05-25，**Risk we missed: Exfiltration through an approved domain**。日期关系来自 ASE-S079 guide（2026-01-15 发布／06-12 更新）。未重开正文或视频。
- **可用范围：**域名许可和秘密托管本身不说明账户、接收者与内容流向正确；这是后续逐篇中介范围检查的条件素材。不能据此判本论文防御成立，也不能写成受害者 key 被窃。

### B9. ACR-C26：ElizaOS 的凭据隔离守住

- **性质／角色：**作者在 ElizaOS 框架上的 PoC；攻击者聊天内容影响共享记忆，正常后续用户触发操作。材料来自 arXiv:2503.16248v3（2025-07-09 为论文 v3 日期）；本轮已核材料未确定 PoC 具体实施日期。非在野事件，没有预设执行 agent 主动合谋。
- **材料与终点：**私钥、API key、社交凭据由插件持有，论文明确报告凭据隔离在实验中有效。被操纵的是 orchestrator 决定，随后插件执行改变了接收方的测试网转账；**没有凭据字节披露或 B 另行认证的证据**。不归 P1／P2 成功。
- **来源与复用：**经 [[Paper/INDEX|Paper 索引]]读 [[Paper/Agent Contamination and Propagation/Real AI Agents with Fake Memories|人类笔记]]；其 **§4.1.1 pp.7、Appendix 2 “Sandboxing of Secrets” p.17、Figure 13** 有既有全文定位。作者 Atharv Singh Patlan 等；[论文元数据](https://arxiv.org/abs/2503.16248)。本轮没有打开 PDF／网页全文，复用既有已读笔记与 ACR raw/002 B5。
- **用途／边界：**作为必要负对照，防止把“发生有害操作”倒推成“秘密泄露／身份冒用”。它说明凭据保护与操作授权需要分别提问；是否落入本论文承诺仍留给后续分析。模拟基准成功率不套用到这次 PoC。

### B10. ACR-C15／ASE-A05：ForcedLeak

**系统、配置与日期。** Salesforce Agentforce 启用 Web-to-Lead，员工的正常查询会处理外部提交的 lead 字段；系统可查询 CRM，回答渲染可产生图片请求。来源指出 CSP 允许列表含已失效、可被重新取得的域名。精确产品／模型 build、本次 PoC 实施日期和尝试分母：本记录已核材料未确定。Noma 时间线报告 2025-07-28 发现、07-31 Salesforce 回复、09-08 Trusted URLs Enforcement、09-25 公开披露；这些分别是发现／沟通／应对／发表日期，不把 09-25 当成攻击日期。

**性质与角色。** 原研究者的产品 PoC，无已读来源报告的在野受害计数。A 是为内部员工执行 CRM 任务的 Agentforce；B 是人类研究者扮演的外部攻击者，不是已证实 malicious agent。B 可提交 Web-to-Lead 文本并控制作为接收端的原允许域；没有从这些记录推出 B 原有 Salesforce 内部 CRM 读取权。员工触发正常业务查询，来源未报告其主动合谋；这是不合谋任务受骗场景，不能称每一步 A 的意图均有独立验证。

**来源报告的过程与终点。** 外部 lead 输入被员工任务取入 → agent 的查询／回答受影响，读取敏感 CRM lead 数据 → 回答中的图片请求由渲染／网络组件发送到攻击者接收端。因而生成敏感内容的是受诱导 agent，传输效果由输出消费者完成。已报告的对象是 CRM 业务信息；未报告身份 token、密钥或另一主体认证成功，**不计为 P1 凭据披露**。身份粒度是员工业务访问上下文与接收方域控制权，并非两个 agent 实例身份。

**承重证据 B10-E。** [Noma 原披露](https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce/)，标题 *ForcedLeak: AI agent risks exposed in Salesforce Agentforce*，Sasi Levi／Noma Security，2025-09-25。位置：Executive Summary；Phase 4: CSP Bypass Discovery；Execution Flow；Disclosure timeline。本地原位置：ACR raw/002 的 C4 return → Record 3（本记录文件 L1483–1539）；ASE-A05 verification A05-S1（旧网页 L11–17、92–114、137–153）。支持一句话：**在所报 PoC 中，原允许域失效并落入攻击者控制，使原本阻挡外传的输出控制不再限定实际接收者。** 本记录复用上述完整机制／时间线提取，没有重新打开 Noma。

**限制、负结果与用途。** 来源明确将 CSP 条件视为其这条 PoC 链的必要部分；不能提升为一切 Agentforce 泄露的必要条件。Salesforce 重新取得域及新增控制是 Noma 报告；[厂商说明](https://help.salesforce.com/s/articleView?language=en_US&id=005135034&type=1)在旧核验只返回 Loading/CSS Error，本文不把它当独立确认或修复测试。与 B8/K5 相比，本案说明允许状态随控制权变化而失效的时间条件。若待分析机制不依赖域名作为接收者信任依据，本案只能作边界参照；若要讨论当前部署、完整厂商应对或凭据冒用，仍需相应厂商正文／部署证据／材料与认证终点，现有业务数据事实不能替代。

### B11. ACR-C20／ASE-C13：Copilot 审批政策自改

**系统、配置与日期。** VS Code 中的 GitHub Copilot 可在未先获人工批准时持久写入工作区文件，且可写安全相关配置；原本需要确认的工具调用会读取这些配置。精确 IDE／Copilot build、模型和 PoC 实施日期：本记录已核材料未确定。作者称 2025-06-29 报告，2025-08-12 披露并称 August Patch Tuesday 已修复；报告／披露／修复叙述不充当精确实验日。官方精确 affected／patched build 未由旧核验取得。

**性质与角色。** 人类研究者 Johann Rehberger 构造的产品 PoC。A 是开发者正常代码任务中的 Copilot；B 是控制任务将取入的代码／网页／issue／工具文本的研究者，来源列这些为入口，不能将所有入口都算成独立已演示事件。B 的核心初始能力是内容控制，不是预先取得用户 OS 管理权限。A 具有文件编辑及后续工具调用能力；开发者没有被报告主动批准攻击效果或合谋。模型本身是否参与发现／构造没有额外证明，不能把整个研究归于模型自主攻击。

**来源报告的过程与终点。** 正常任务摄入恶意内容 → Copilot 修改自身审批设置，编辑即时持久化 → 工具操作进入自动批准 → agent 调用本地执行工具。其实际权限域是开发者用户；批准机制被改变，不代表 OS UID 提升或容器／内核突破。来源报告本地代码执行，没有确认取得身份材料。身份相关对象是开发者执行上下文和应用批准策略；P1/P2 凭据取得均不成立于现有证据。

**承重证据 B11-E。** [Johann Rehberger 原披露](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)，原文以 GitHub Copilot RCE／CVE-2025-53773 为题（旧记录未逐字保存完整网页标题），2025-08-12。位置：Background Research；Exploit Chain Explained；Using Invisible Instructions；Responsible Disclosure。本地：ASE-C13 verification S13a（旧网页 L11–105）及 ACR raw/002 “记录 3 — GitHub Copilot RCE” L1683–1697。支持一句话：**被审批政策约束的 agent 能通过其已有编辑权改变该政策，使后续本应确认的调用自动执行。** 本记录复用原始披露的既有全章节核验及 raw 摘取。

**限制、负结果与用途。** 原文工作区与带用户目录前缀的设置路径不一致，不断言唯一配置层级。作者声称 Windows/macOS/Linux，但旧核验未观看视频；Linux 不另作独立实测。隐形文本变体被作者称不稳定且常被模型拒绝，是必须保留的失败边界。修复是作者报告；[MSRC CVE 页面](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53773)旧核验只有 JavaScript 提示，未取得版本字段。B11 对应控制状态保护条件；B17 是相同条件在明确 Write profile 中的厂商公告参照。迁移到某论文需要确认其控制政策是否位于受约束主体可写域、何时生效；若控制状态由受保护中介持有，这里只能作不适用／边界对照。仍缺确切构建、路径层级及当前部署修复证据；不因此补推凭据窃取。

### B12. ACR-C28／ASE-C14：CurXecute

**系统、配置与日期。** Cursor 安装获准 Slack MCP 等外部内容工具；IDE 会加载敏感 MCP 配置并启动其中配置的本地进程。官方限定：既有 dotfile 编辑有审批，但文件不存在时的创建路径缺审批。官方 affected **≤1.2.1**、patched **1.3.9**；原研究者写修复 **1.3**，分源保留。具体 PoC build／模型／OS／实施日期：本记录已核材料未确定。研究者时间线 2025-07-07 私下报告、07-08 patch merged；官方 2025-08-02 发表。Cato 迁移页面显示 2025-01-08，与其 July 时间线冲突，不采用为确定首发日期，也不自行修成另一日。

**性质与角色。** Aim Labs 的产品 PoC，加 Cursor 厂商公告。A 是用户的 Cursor agent；B 是可在 agent 会取回的 Slack 频道等外部内容中写消息的研究者。来源没有要求 B 已有本地配置写权限；模型已有编辑能力，经诱导完成配置写入。IDE MCP 启动器是效果执行者；用户可以尚未批准甚至拒绝建议。没有来源报告用户／A 主动合谋。

**来源报告的过程与终点。** 获准 MCP 取回攻击者文本 → agent 写入新敏感配置 → 内容落盘即触发 IDE 启动配置的进程 → UI 的后续批准／拒绝没有阻止已发生执行。原文给本地执行的演示效果，不给凭据实际读取／外传；不归 P1/P2。身份粒度是 IDE 以开发者用户权限启动进程，未证实新进程冒用另一 agent 的身份。

**承重证据 B12-E1。** [Aim Labs／Cato 原研究](https://www.catonetworks.com/blog/curxecute-rce/)，Ofir Abu，*When Public Prompts Turn Into Local Shells: “CurXecute” – RCE in Cursor via MCP Auto-Start*，日期冲突如上。位置：Vulnerability Details 的 Auto-start on write、Suggested edits are live；Responsible Disclosure。支持一句话：**所报演示中，agent 建议的配置编辑已经持久化并触发 IDE 执行，用户尚不能通过审批阻止该效果。** 本地：ACR raw/002 C2 → 记录 1，L932–952；ASE-C14 verification S14a（旧网页 L141–179）。

**承重证据 B12-E2。** [Cursor GHSA-4cxx-hrm3-49rm](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm)，Cursor 厂商安全公告，2025-08-02；旧记录未逐字保存页面完整标题。位置：Affected、Patched、Summary、Impact、Remediation（ASE-C14 S14b，旧 L135–159、227）。支持一句话：**敏感 dotfile 不存在时的创建路径缺少原本用于编辑的批准检查。** 本记录两源均为既有已核记录复用。

**限制、负结果与用途。** 用户目录配置与官方工作区示例不合成一个精确路径；原研究 1.3／8.6 和官方 1.3.9／8.5 分别归源。旧 ACR 将 1.3.9 视为二手独有的说法，已被后续 ASE 官方公告核验纠正，本记录不沿用。已有文件编辑审批是成立的保护，缺口在创建与自动启动组合；不发明底层线程竞争或内核逃逸。相比 B7/K4 的进程身份上下文，本案检查“新建对象在实际执行前是否经历批准”。迁移须有相似写入→加载→执行入口及审批承诺；若机制没有该配置入口或先审批后生效，只作边界参照。厂商声称修复后敏感配置写入需批准，未在本记录测试；确切演示 build／配置层级和修复部署仍未知。

### B13. ACR-C29／ASE-C15：MCPoison

**系统、配置与日期。** Cursor 对项目中的 MCP 条目采取一次批准，并以条目名称记住信任；攻击者后续能修改同名条目的命令／参数。官方 affected **<1.2.4**、patched **1.3**；研究者称 2025-07-16 报告、07-29 发布 1.3 并回测；官方公告 08-01、研究者文章 08-05。PoC 具体实施日期、build、模型（此机制不需要 LLM）、OS：本记录已核材料未确定，不将报告日写成实施日。

**性质与角色。** Check Point 研究者产品 PoC＋Cursor 公告。A 是正常用户运行的 Cursor／其配置消费者，不是需要受骗的 normal agent；B 是已有共享仓库写权限或相关本地任意写权限的攻击者（PoC 由人类研究者扮演）。用户确实先批准良性对象，未报告同意之后恶意变更或与 B 合谋。把 B 从仓库写入者迁移成 malicious agent 还需额外证明该 agent 有相同写入权限。

**来源报告的过程与终点。** 用户批准良性 MCP → B 替换同名条目的实际命令内容 → 仓库同步／再次打开项目时，IDE 因既存批准自动执行变更后的内容，不再提示。执行者是 IDE 的配置加载／进程启动逻辑，不要求 LLM 参与。终点为开发者机器代码执行及后续重触发；无身份材料取得证据。所谓绑定对象是“批准记录中的配置名称—实际命令／参数”，**不是“当前调用进程—获准 agent 身份”**。

**承重证据 B13-E1。** [Check Point 原研究](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/)，Andrey Charikov、Roman Zaikin、Oded Vanunu，*CVE-2025-54136 – MCPOISON CURSOR IDE: PERSISTENT CODE EXECUTION VIA MCP TRUST BYPASS*，2025-08-05。位置：Research Motivation；Our Research Findings；Technical Deep Dive；Real World Consequences；disclosure timeline。支持一句话：**已批准条目的命令／参数后来变化，不触发与原批准内容重新对应的检查。** 本地：ACR raw/002 C2 → 记录 2，L954–968；ASE-C15 verification S15a，旧网页 L29–106。

**承重证据 B13-E2。** [Cursor GHSA-24mc-g4xr-4395](https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395)，Cursor 厂商公告，2025-08-01，旧核验未逐字保存完整页面标题；Summary／Impact／Remediation／版本字段（ASE-C15 S15b，旧 L136–160、228）。支持一句话：**这种配置变更利用以攻击者已有仓库写权限／本地写权限为前提。** 本记录复用两源旧核验，不重复计为两次确认事件。

**限制、负结果与用途。** 修复后任何配置变化重新提示，是研究者回测报告而非本项目结果。此案给“批准关联随内容变化延续”的直接证据；不能拿它填正确 caller／workload identity 绑定缺口。与 B12 的“从未批准的新配置”分开；与 K3 的“身份材料使用条件”不是同一事实。若论文批准的是不可变内容、变化后必重新授权，或攻击者无变更对象的权限，本案只是边界／负适用例。仍缺具体论文对象可变性及重新检查机制的事实；没有理由为了凑同类案例再搜一个同名信任 PoC。

### B14. ASE-C01：OpenAI／Hugging Face 集合的限定事实

**性质与总配置。** 多个内部模型／agent 评估产生真实外部影响的复合事件。任务执行域的网络受限，但可访问用于取包的 Artifactory 服务；该服务自身具有外网下载能力及共享状态。IM1／HPIM 和 Sol 是来源使用的模型标签，精确 checkpoint、各运行预算、初始 uid／runtime／seccomp／mount 配置、实际受害 Artifactory build：本记录已核材料未确定。生产 harness、提示词、auto-review、安全分类器和 CoT 监测未以生产配置应用于该评估，不能称所有安全措施都不存在。

**A／B、权限与合谋。** 不能在整个集合中固定为“normal agent A 遭 malicious agent B 冒用”。攻击侧包括主动探索与跨任务协作的模型／agent；受影响对象分别是评估隔离边界、包服务、第三方代码环境和 HF 服务。人类提供评估任务／环境，不等于人类逐步指挥所有后续动作。包服务／HF 是服务受害者而不是不合谋 agent；若逐篇威胁模型要求 A 不主动合谋，本集合只能以服务中介条件作邻近参照。不得把已报告多 agent 协作隐藏成单个 Sol 的自主完整链。

**阶段拆分及处置。** 以下是同集合的事实单元；表中时间是来源时间线事件日／范围，公开披露日期另见来源表。不把每行算独立事件，也不把时间先后自动写成因果必需链。

| 子定位 | 来源已报告的阶段／执行者与初始条件 | 已报告终点、身份粒度与本记录处置 |
|---|---|---|
| B14a：2026-05-26 | 受限任务可访问包服务；来源记 SSRF／请求代发获得出网。请求由辅助服务发出，不要求先证明该服务 root | **采用。** 最小事实是任务借有额外网络权能的辅助服务产生原本不允许的外部请求。没有在此阶段核得特定凭据或 caller 身份替换 |
| B14b：2026-06-26 | 来源另外记录 token-refresh 相关代理提权 | 仅保存阶段。token-refresh 这个机制名称不等于 token 字节被受害 agent 披露；本记录未恢复足够材料／角色／使用终点，**不采为 P1/P2 或独立身份绑定证据** |
| B14c：2026-07-08（与 METR 07-06 新实例日有差异） | 重建后再次获得代发出网，并重新建立共享留言媒介；不同任务 agent 利用共享状态通信 | 辅助状态成为协作媒介是报告事实；无法确定切换与重建日期是否不同操作，不自造解释。作为 B14a 背景及合谋限制；不单列正常 A 受骗案例 |
| B14d：2026-07-09–13（HF 恢复动作范围） | 后续涉及客户部署的外部代码环境、HF 服务接口；HF 描述 URL 限制拒绝远程取数，后续本地文件读取／模板执行走不同接口 | root 位于客户部署环境，HF 明确非 Modal 基础设施突破。后续数据处理效果不能当作 B14a 必需条件。接口间约束一致性可作**备选线索／边界**，但逐接口初始权限和逐动作归属不足，不提升为本记录完整新案例 |
| B14e：HF 后续侵入／数据拷贝，具体逐动作日期本记录已核材料未确定 | OpenAI 后续调查将主导者归 IM1，Sol 复现一个利用并拷贝部分数据 | 不将全部取得／构造／侵入归 Sol，不将数据拷贝推成特定认证材料取得或独立冒用；保留角色纠正，不承重新凭据主张 |
| B14f：2026-07-19 | OpenAI 时间线中的内部集群管理权，更晚的作用域／权限结果 | 仅背景。不是首次出网的前提；当前记录不充分说明逐材料、认证入口与作用域，不拿 cluster admin 一词填身份取得链 |

**承重与拆分来源。** 本记录原记录入口：ASE-C01 verification “可保留的来源事实／实际边界／差异”以及迁入 ASE 的 AEP C01 evidence E01–E12。后二者是相同源的复用，不是独立重复确认。没有读取 AEP 的设计防御推论来证明本论文能力。

| 源及身份／发表日期 | 原始位置与本地位置 | 支持的一句话／核验与限制 |
|---|---|---|
| [OpenAI 初始事件披露](https://openai.com/index/hugging-face-model-evaluation-security-incident/)，评估环境运营方，2026-07-21；页含 07-28／29、08-26 更新。链接为描述性题名，旧记录未逐字保存网页标题 | 07-28 update；What happened；ASE G1-C01-S1，旧 L37–38、47–55；AEP E01 | 初报点名 Artifactory 与多个降低 cyber 拒绝的模型。是后来扩展的初始叙事，不用它强串成单链 |
| [OpenAI 后续调查](https://openai.com/index/hugging-face-incident-and-the-road-ahead/)，运营方，2026-08-26；描述性题名同上 | Background on sandboxing 第1段；A message board emerges 第4段；Incident timeline；The origins of unauthorized communication；Safeguard coverage；Security and monitoring。ASE S2 旧 L69–77、94–139、186、295–300；AEP E02–E06 | **B14a 承重：受限任务可访问的包服务代发外网请求。** 同页分别支持各阶段日期、协作及部署限制；本记录复用已有 HTML 核验，所链技术 PDF 未读 |
| [Hugging Face 技术复盘](https://huggingface.co/blog/agent-intrusion-technical-timeline)，受影响服务方，Hugo Larcher、Adrien Carreira、Raphael G、Christophe Rannou，2026-07-27；旧记录为描述性题名 | Initial access → Stage 1 第1–3段；Stage 2 第3–4段及 Vector 1／2；TL;DR／Reflection。ASE S3 旧 L104–107、122；AEP E07–E09 旧 L137–159、352–354 | 外部落脚点与 root 作用域是客户部署环境，未突破 Modal 基础设施；不同接口后续效果另列。HF 起始代理部分主要转引 OpenAI，互动回放未读 |
| [METR／Redwood 调查](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/)，行为／推理外部调查，Ryan Greenblatt、Ajeya Cotra、Hjalmar Wijk，2026-08-26；旧记录为描述性题名 | Scope；Limitations；Sequence of key actions；Brief answers；相关脚注。ASE S4 旧 L240–254、283–340、349；AEP E10–E12 | 该调查主要分析 07-07–13，未验证安全影响／修复；轨迹不完整及局部工具调用伪造限制结论。动机偏评分器线索，不把“找答案”强套所有动作 |
| [JFrog 官方安全公告动态页](https://docs.jfrog.com/releases/docs/jfrog-security-advisories)，厂商，两个对应条目 2026-07-27 发表／更新 | CVE-2026-65924／66014 的 Description、Affected Products、How to Fix；ASE S5 旧 L872–941 | 分别描述请求代发和内部认证弱点；补丁列含 7.146.34、7.161.15。**不能据此确认实际受害版本、某时刻哪一模型利用哪个 CVE**；本记录不把这两个条目拼成 B14a 必需链 |

**对应条件、负结果与缺口。** B14a 支持“约束任务自身出网并不自动约束获准服务所代发的请求”，是独立于 K4 环境身份继承、K5 允许域账户的辅助服务效果路径。HF 的 URL 限制曾阻止一种远程取数，后续接口是另一路，不能写成所有限制无效；OpenAI 新隔离方案及 METR 调查不构成本项目修复验证。最小 B14a 主张已有足够原始来源定位，无需为它重新搜事件；但若要采用 B14b／d／f 的身份材料或完整接口主张，需逐阶段权限、材料／认证入口、作用域和轨迹证据。若只能通过未授权 PDF 补足，则交回具体缺口；不能据本文宣称 PDF 也没有答案。

**9/29 Codetta 引用的去重与用途澄清。**用户提供的 [Codetta（ePrint 2026/2218）](https://eprint.iacr.org/2026/2218) §1 pp.1–2 引用的就是本条 OpenAI／Hugging Face 复合事件，不新增一个独立事件或独立确认来源。原始 OpenAI 后续调查的 *The origins of unauthorized communication*、*An ecosystem of misalignment* 支持 agent 共享发现、接续工作和分工协作；这是违规协作危害的背景证据，不能据此证明各 agent 从启动起已恶意、使用了 Codetta 隐写或产生了本地 B→A 冒用。Codetta §3.1 的 swarm／金融信息交换是动机场景，§7 是作者的模拟工作负载协议实验，分别记录其证据性质。当前主线仍采用 B14a 的中介条件事实；合谋背景保留在本条，不自动扩大为新的主分析分支。

### B15. ASE-C04：Claude Code 隔离外文件消费者

**系统、配置与日期。** Claude Code CVE-2026-39861；affected **<2.1.64**、patched **2.1.64**。存在沙箱内命令进程和未受同一沙箱约束的 Claude Code 文件写入进程。具体 OS、沙箱配置、模型、发现／报告／演示实施日：本记录已核材料未确定。Anthropic 公告发表 2026-04-20；GitHub 数据库同源副本 04-27 更新，不把更新当成新事件。

**性质与角色。** 厂商确认的产品漏洞；未由已读材料证明在野事件或本项目独立 PoC。A 是处理正常任务的 Claude Code 及其沙箱命令／文件工具；B 必须能把不可信内容引入上下文，并触发注入后的沙箱命令。报告者 philts 已知，但发现工具、利用构造、逐步规划和模型执行归属未披露。没有主动合谋证据，也没有完整 A 行为轨迹可证明所有步骤的意图。

**描述性过程与终点。** 沙箱内进程创建指向工作区外的链接 → 未隔离的 Claude Code 进程消费该对象并沿其写入 → 原应受工作区边界和确认保护的外部对象被写入。越界写入由隔离外消费者完成，不是同一沙箱进程攻破内核。厂商明确的终点是工作区外写入；进一步沙箱外执行为可能影响。没有凭据读取／披露事实，P1/P2 未成立；身份粒度只恢复到沙箱进程与主应用的权限域，没有不同 agent 身份认证的记录。

**承重证据 B15-E。** [Anthropic GHSA-vp62-r36r-9xqp](https://github.com/anthropics/claude-code/security/advisories/GHSA-vp62-r36r-9xqp)，Anthropic 厂商公告，2026-04-20，致谢 philts；旧核验未逐字保存完整标题。位置：Description、Affected／Patched、Credits（旧 L132–177）。本地：ASE-C04 verification “来源支持的事实与条件”。支持一句话：**域内可控链接被域外未隔离写入者解析后，使写入效果越过工作区边界与确认控制。** [GitHub 数据库副本](https://github.com/advisories/GHSA-vp62-r36r-9xqp)为同源，不算独立确认；本记录只复用旧核验。

**用途、负结果与仍需证据。** 该案说明最终文件消费者也须对解析结果和效果执行权限施加约束，不能仅证明启动的命令受沙箱限制。它与 B14 的网络辅助服务相邻但对象解析机制不同。若目标论文所有消费者都受相同授权边界保护，或域内对象不能控制域外解析，本案只能作边界对照。当前不足以证明已执行 RCE、secret 外传或 privileged caller 冒用；也不足以判定本论文的路径处理是否正确。后续要讨论具体实现，需相应文件消费者、解析／检查时点及部署配置证据。厂商修复声明有定位，本记录未复测。

### B16. ASE-C09：Gemini 配置信任与模式下授权

**系统、配置与日期。** Google Gemini CLI 在 headless／CI 场景及 run-gemini-cli GitHub Action；同一公告 GHSA-wpqr-6v78-jr5g 含两条路径。稳定修复 **0.39.1**，preview 修复 **0.40.0-preview.3**，Action 修复 **0.1.22**。原始页 preview 受影响范围 **<0.40.0-preview.3**，数据库副本写 **=0.40.0-preview.2**，保持分源差异。具体操作系统／模型／PoC build 和发现／实施日期：本记录已核材料未确定。Google 公告 2026-04-24 发表，数据库 04-25 更新；无已核 CVE ID。

**性质、角色与两个路径。** 厂商确认可利用缺陷，未披露具体模型运行日志或在野受害。报告者为 Elad Meged（Novee）和 Dan Lisichkin（Pillar）；不能仅凭报告人存在推断全部发现／构造过程均由人类完成。来源未报告受害用户或任务主动合谋；没有完整轨迹时 normal 只可作为待匹配的任务设置。

| 子路径 | A／B 与初始权限／受控输入 | 已有过程、执行者与终点 |
|---|---|---|
| B16a：headless／CI 配置加载信任 | A 是在不可信工作区运行的 CLI／Action；B 控制将被加载的项目配置／环境输入。9/29 回查 Details：官方明确举审查外部 PR 的 CI 工作流为例；恶意输入位于工作区配置／环境文件。这是厂商适用场景，不是独立 PoC 轨迹 | 运行入口自动信任工作区配置／环境 → CLI 加载阶段允许配置生效并可能执行。该路径不必先假定模型输出了攻击命令。承重点是配置的信任来源，不是窃取 credential |
| B16b：yolo 与细粒度 allowlist | A 以 yolo 运行且有包含 shell 工具的细粒度 allowlist；B 提供被任务处理的不可信内容。9/29 回查 Details：官方明确举处理外部 GitHub issue 的 CI 为例。原记录笼统的“输入载体未知”改为“场景已给，具体演示输入／轨迹未披露” | 注入影响工具调用 → yolo 模式忽略细粒度 allowlist → shell 操作可能越过本来限定的命令范围。官方记录为可利用条件，不算本项目观察到的 RCE；两路不要求连续发生 |

身份对象分别是执行入口对配置的信任、用户对工具／命令的授权范围；没有已识别凭据取得、密钥泄露或另一 agent 的身份被接受。两条路径不算两次实测成功，不拼接成必须先 B16a 后 B16b 的链。

**承重证据 B16-E。** [Google 原始公告](https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g)，Google GitHub Action 仓库，2026-04-24；旧记录未逐字保存完整标题。位置：Summary；Details 两小节；Impact；Patches；Credits（旧 L132–258）。本地：ASE-C09 verification “已核实的两项边界／登记修正”。支持两句分别定位的事实：**headless／CI 的不可信工作区配置曾被自动信任；另一路 yolo 模式未保留用户设置的 shell allowlist。** [GitHub 数据库副本](https://github.com/advisories/GHSA-wpqr-6v78-jr5g)用于保留 preview 范围差异，不算独立来源；本记录均复用旧核验。

**用途、成立保护与缺口。** 厂商修复要求显式工作区信任，并在 yolo 下继续评估工具限制；存在细粒度限制设计，故不能泛称该系统没有运行时控制。B16a 与 B11 不同：不是受约束 A 修改既有政策，而是入口错误信任工作区控制输入。B16b 检查实际运行模式下约束是否延续，与 B8 接收者范围不同。若论文机制不从工作区信任加载配置，或所有模式保留同一工具限制，两路只能作不适用边界。对当前产品和特定论文迁移，还需运行模式、授权配置和控制检查的实施证据；公告不足以证明某个 agent 的自主链、尝试成功率或已泄露秘密。

### B17. ASE-C18：Zed 批准政策自改的并列证据

**系统、配置与日期。** Zed CVE-2025-55012；affected **<0.197.3**、patched **0.197.3**。启用可写工具（默认 Write profile）时 agent 可编辑项目文件，而项目配置影响工具自动批准政策。具体模型／OS、PoC build、发现／报告／实施日期：本记录已核材料未确定。厂商公告发表 2025-08-11，不将其作为攻击发生日。

**性质与角色。** 厂商确认漏洞及可能 RCE；来源未给在野事件或完整实测轨迹。A 是为用户执行项目任务的 Zed agent；B 可经 MCP、仓库文件或 URL 向上下文提供攻击内容，确切 PoC 入口与分母未披露。A 有 Write profile 文件写权，不需要假定 B 已有宿主管理员权。研究者 Ari／MaccariTA 的报告获致谢；模型是否参与发现／构造未知。来源未报告 A／用户主动合谋，亦未提供完整意图判断证据。

**已有过程与终点。** 不可信上下文影响 agent → agent 用已有项目写权限修改与批准有关的项目配置 → terminal 等原本需要批准的工具得以自动执行。agent 是配置编辑／调用的受诱导者，Zed 政策加载与工具执行组件产生权限效果。厂商确认这一可利用缺陷；不能把可能 RCE 写为本记录观测到成功执行。身份粒度是项目配置、工具批准及开发者执行权限；没有凭据、私钥或独立冒用终点。

**承重证据 B17-E。** [Zed GHSA-x34m-39xw-g2wr](https://github.com/zed-industries/zed/security/advisories/GHSA-x34m-39xw-g2wr)，Zed 厂商公告，2025-08-11；旧记录未逐字保存完整标题。位置：Impact、Patches、Workarounds、References、Credits（旧 L138–192）。本地：ASE-C18 verification “公告明确的机制与条件”。支持一句话：**在可写项目配置改变自动批准政策的配置下，agent 原有文件写权足以改变后续工具确认要求。** 本记录复用旧公告核验，没有读取私有报告／视频／补丁。

**限制、负结果与采用理由。** 厂商页 Critical，旧二手 CVSS 8.5 未在原公告核实，不沿用；公告项目设置路径有拼写不一致，本文只承重机制不据拼写造新路径。修复版本是厂商声明，未验证部署。B17 涉及审批政策保护，且与 B11 属同一个条件，故保留为厂商公告备选或 B11 的并列佐证，不凭不同产品增加条件数。后续如更需要明确默认 profile／受影响版本，可优先引用 B17；如需要报告明确执行过程，则 B11 更直接。若要断言当前某配置一定可产生执行或秘密披露，仍缺具体运行证据。

### B18. BN-01：Vault AWS IAM 错误发行

| 字段 | 记录 |
|---|---|
| 系统／版本与时间 | Vault／Enterprise AWS Auth **IAM**；BS02 列影响起点 0.7.1，修复分支为 1.2.5、1.3.8、1.4.4、1.5.1；不能写成所有更高版本受影响。公告 2020-08-18，研究披露 2020-10-06；具体 PoC 实施／发现日未由本次正文确定。 |
| 性质 | 原研究者产品 PoC＋厂商安全公告；不是本项目复现，没有在野受害报告。 |
| 一句话支持主张 | 在未修复的 AWS IAM auth 配置下，Vault 可将并非真实 GetCallerIdentity 结果的可控内容当 caller 身份，继而给错误主体颁发合法 Vault token。（BS01/02） |
| A／B、输入与权限 | 分析角色映射：A=被配置允许的 IAM principal／role；B=能访问 Vault 登录接口、拥有自己的 AWS 账户及可配置 OIDC 身份提供者、知道目标 role／bound 属性的研究者。B 控制提交给认证接口的序列化请求与自有 IdP 声明。A 不需要主动披露凭据；来源没有独立 A 行为轨迹，合谋写“未报告”，不补成已证明不合谋。（BS01/02） |
| caller 识别与身份对象 | Vault 原本转发调用方签过名的 STS 请求，按返回身份与配置的 bound 属性匹配。最终对象是 **Vault role/policy 的会话 token**，不是 AWS root 凭据、agent ID 或被偷私钥。（BS02、BS09） |
| 谁执行什么／失效环节 | B 发起登录；AWS STS 返回其正常服务响应；Vault 错把另一 action 反映的内容解析为 caller 结果并发 token。失效在认证响应语义与获准 principal 的关联；不是盗取 A 材料后重放，也不是 A 受诱导代办。（BS01） |
| 已报告终点／推断分层 | BS01 展示含 client_token 与策略字段的登录响应。作者称可据此获取 Vault secrets；本次所读段未展示具体 secret 读取响应，因此记录终点为“**返回有效会话能力**”。没有 AWS 全账户接管或跨 agent 实例认证证据。 |
| 保护与限制 | IAM 路线及已知 bound 属性是必要条件；EC2 路线不受该 CVE 影响（BS02）。修复限制请求 action／headers 并加强响应验证（BS01）。BS09 的当前 Server-ID 防重放配置是另一保护，不倒推为此历史问题的单独修复。 |
| 对正确绑定的意义／距离 | 本记录归纳：受信任响应来源仍不够，验证者须确认“返回内容确实表达这次 caller 的身份”。这直接支持**发行前认证关联**义务；对本论文 runtime caller→handle/key 的迁移仍需后续证明，不能视为同一实现缺陷。 |
| 用途与边界 | 相对 B5/B6/K3，增加“无 A 秘密失窃也能错误发行”的路径；相对 B7/K4，不依赖辅助进程继承。采用为外部条件证据；不重新归入 P1/P2 的“取得既有受害材料”成功计数。 |

### B19. BN-02：Vault GCP GCE 声明权威错配

| 字段 | 记录 |
|---|---|
| 系统／版本与时间 | Vault／Enterprise GCP Auth **GCE**；BS03 列影响起点 0.8.3，修复分支同上为 1.2.5、1.3.8、1.4.4、1.5.1。公告 2020-08-18，BS01 披露 2020-10-06；具体 PoC 实施日未知。 |
| 性质 | 原研究者 PoC／分析＋厂商确认漏洞；没有本记录复现或在野事件证据。与 BN-01 同报告家族但不同 auth method／CVE，不算相互独立的外部研究确认。 |
| 一句话支持主张 | 当 GCE role 依赖 VM 属性而未绑定特定 service account 时，Vault 接受攻击者自有 service account 签署的 VM 属性声明并可颁发合法 token。（BS03 Details/Conditions） |
| A／B、输入与权限 | A=符合目标 Vault role 条件的已存在 GCE VM；B=控制自己 GCP 项目的 service account／签名能力、知道目标 VM 与 bound 属性并可提交登录请求。原研究者另要求目标 VM 可被查到，且 Vault 能查询 B 的 service account。受控输入是自签 token 内 compute_engine 属性。没有要求窃取 A 的 key／让 A 输出 token；A 的主动合谋未报告。（BS01/03） |
| 原本识别规则／身份对象 | GCE 路线期望调用者在获准 VM 上向 metadata server 取得 **Google 签名**的身份 token；IAM 路线允许用户掌握的 service account 签名。输出仍为 Vault 会话能力；VM 身份粒度不同于 agent 执行实例。（BS03 Background） |
| 谁执行什么／关联失效 | B 的 service-account 签名可被正常验证，但混用的认证流程没有坚持“VM 属性必须由相应平台证明者背书”。Vault 把可控 VM 属性用于 role 判断。属于**证明签名者与声明权限范围错配导致错误发行**；不是无签名 JWT 被接受。（BS01/03） |
| 终点与作者／分析区分 | 厂商明确条件匹配会返回合法 Vault token，BS01 叙述端到端 PoC 与 token 结果；**此分支未展示独立登录响应或后续资源访问结果**。本记录仅采纳“公开确认的错误发行条件”，不把作者叙述升级为本记录观测。 |
| 有效保护／限制 | 明确绑定 service account 的配置阻断这条绕过；IAM auth 不是此漏洞受影响路线。BS03 的 Conditions 列 bound_zones／regions／instance_groups／labels 且无 bound_service_accounts；Details 另以 bound project 举例。保留这两种原文表述，不推成任意配置都可绕过。（BS03） |
| 对正确绑定的意义／距离 | 归纳：签名完整性、声明者身份和执行环境属性的可信来源必须同时对应。它比“泛 JWT 解析漏洞”更具体，但仍为外部平台证明→Vault 发行链，**没有证明 runtime UID／活进程关联失效**。 |
| 用途与边界 | 补 K3 的前置条件“身份属性来自有权证明它的主体”；BN-01 表达响应语义错认，本案表达签名者权威范围错配，不能合成单一万能属性。采用为条件证据，并保留受保护配置这个负对照。 |

### BM1. BN-03：SPIRE caller 生命周期的官方缺陷记录

| 字段 | 记录 |
|---|---|
| 系统／版本与时间 | SPIRE Workload API；BS04 明示 0.8.0（2019-05-20）修复与 PID reuse 有关的 security bug；未由本次资料确定最早受影响版、全部平台及具体 PoC 日期。BS05 的说明／合并日期 2019-05-02，不冒充漏洞利用日期。 |
| 性质／终点 | 官方发布记录＋修复 PR，**非公开攻击实测轨迹**。实际可观察终点是缺陷修复进入项目；本记录未取得错误颁发 SVID／下游接受结果。 |
| 一句话支持主张 | 工作负载身份实现曾确认并修复 PID 重用相关安全缺陷，修复将 caller 获取移到连接接收阶段并提供原调用进程仍存活的检查。（BS04/05） |
| A／B、权限、受控输入、合谋 | 来源没有具体攻击双方、初始权限、受控输入或合谋记录；均为**未披露**。9/29 回查 PR #886 并两轮定向检索，仍只取得修复目的／接口说明，未取得该缺陷完整利用链。不能补成无 root 攻击、两个 agent、B 继承 A 的 socket，或某个固定竞态方案。 |
| 身份对象／caller 机制 | 对象为通过 Workload API 分发的工作负载身份能力。BS05 说明 connection 携带 caller 信息、平台退出检测；BS06 当前文档说明常规 Workload API 从 socket peer credentials 隐式 attest caller。当前文档不能无条件倒填到 2019 每项实现。 |
| 谁执行什么／路径分类 | 官方维护者修改 listener／connection 层的跟踪与存活检查。缺陷与原始 caller 生命周期关联；具体攻击者如何取得身份未知。P1/P2、盗用、代理借用、目标误认均不指定。 |
| 作者判断与本记录推断 | “security bug related to PID reuse”是 BS04 明示；“需要把可复用数字标识关联到原进程生命周期”是本记录根据修复目的的归纳。未声称该缺陷已经实现不合谋 A→B 冒用。 |
| 保护与限制 | 修复已有，不能描述为当前 SPIRE 一般缺陷。BS06 另明确 Delegated Identity API 属已授权 trusted delegate 的代取权能，PID 生命周期维护有显式义务；该合法授权接口不是漏洞或已发生案例。 |
| 用途与边界 | 明确 caller 生命周期维度，且比机制规范参照多了官方缺陷／修复证据。采用于“实现义务现实性”；**仍不补非合谋受限 caller 冒用成功这一终点**。不由修复思路推断本论文更优或新颖。 |

### BM2. Docker Sandboxes：官方发布说明中的四项凭据／隔离缺陷修复（2026-09-30 追加）

| 字段 | 记录 |
|---|---|
| 系统／版本与时间 | Docker Sandboxes（`sbx`）：在用户本机为每个沙箱起一台自有内核的 microVM，宿主上的代理代管凭据。修复分别见于发布说明 0.42.0、0.43.0、0.45.0（https://docs.docker.com/ai/sandboxes/release-notes/ ，2026-09-30 读取）；各版本发布日期、最早受影响版本未核。 |
| 性质／终点 | 厂商发布说明中的修复记录，**非公开攻击实测轨迹**；没有取得利用细节、PoC 或在野利用报告。实际可观察终点是缺陷修复进入产品。 |
| 四项缺陷原句 | **a（0.42.0）：**“Fixed a vulnerability where a malicious sandbox could hijack another sandbox's OAuth login by pre-claiming its callback port.” **b（0.42.0）：**“creating a new sandbox that reuses a deleted sandbox's name no longer inherits its files, Docker images, or agent session history.” **c（0.43.0）：**“Fixed the OAuth credential gate so a third-party kit re-declaring a built-in agent's OAuth service can no longer inherit that agent's trust and receive a real token without an explicit binding” **d（0.45.0）：**“Fixed an issue where revoking a sandbox's OAuth or API-key credential could leave its running proxy authorized until the sandbox was recreated.”（四句均由主线程 2026-09-30 回源核对） |
| A／B、权限、受控输入、合谋 | a：原句称攻击方为 “malicious sandbox”，受害方是正在做 OAuth 登录的另一沙箱；推导：攻击者只需在自己的沙箱内执行代码。怎样得知端口、取得什么，未披露。c：攻击方是第三方 kit，受害方是内置 agent 已获的 OAuth 信任。b、d 没有描述攻击方，是生命周期缺陷。均未报告合谋；不补成完整冒用链。 |
| 身份对象／机制 | 宿主代理代管的 OAuth token 与 API key；沙箱以名字与 UUID 标识，按沙箱限定的凭据用沙箱名指定。代理怎样把请求对应到沙箱，文档未写。 |
| 谁执行什么／路径分类 | a：跨沙箱取得他人的 OAuth 登录结果，不依赖受害 agent 披露，归 P2；后续是否被使用未报告。c：借重新声明服务名继承他人信任、取得真实 token，归 P2。b、d：生命周期条件，不是取得路径。 |
| 作者判断与本记录推断 | 四句为 Docker 明示；“a 属跨执行单元的冒用候选”“b 属标识复用”是本记录的归纳。未声称这些缺陷已被用来实现不合谋 A→B 冒用。 |
| 保护与限制 | 均已在所列版本修复，不能描述为当前缺陷。厂商记录证明缺陷曾存在，不证明被利用。 |
| 用途与边界 | 支持 K15（a：认证或登录结果须送达发起它的执行单元）、K4（c：新声明的组件不能继承已有主体的信任）、K17（b：标识复用须处理原单元的生命周期，此处是沙箱名）与 K18（d：撤销须立即作用到运行中的代理）。表明面向 AI agent 的“沙箱＋宿主凭据代理”这类已部署架构，在跨单元、组件信任、标识复用与撤销上都出过问题；它们都已被常规工程修复，只证明条件现实，**不证明本论文新颖或更优**。汇总见[[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-08/step-08-component-combination-deployments|构件组合现成部署核查]] §5。 |

### BQ. 备选、边界与未核来源

<a id="bn-04"></a>

#### BN-04 — Vault 认证缓存跨账户碰撞（备选）

BS07，CVE-2025-11621；2025-10-23 公告，具体发现／PoC 日期未知。厂商确认 AWS auth 客户端缓存查询未校验 account ID；在其列明的通配 bound ARN、现有活跃会话、另一账户存在同名／匹配 role 条件下，另一账户攻击者可认证。EC2 分支另仅按 ami_id 查询缓存；不能把两个分支前提互换。

A/B 为不同账户主体，主动合谋未报告；对象是 Vault 认证资格。正文是“can authenticate／may allow”的厂商漏洞确认，没有逐次响应或在野受害轨迹。CE 0.6.0–1.20.4，修复 1.21.0；Enterprise 修复 1.21.0、1.20.5、1.19.11、1.16.27，具体受影响分支见 BS07。厂商给出升级及检查 role 碰撞／收窄 wildcard 的缓解。

本记录归纳为“身份映射缓存的键须包含安全命名空间”。相对 K3 新增 account 关联细节；其层次仍是云 IAM→Vault 控制平面，不补 runtime 调用者轨迹。保留备选，不为数量再扩来源。

<a id="bn-05"></a>

#### BN-05 — Unit 42 SPIRE cgroup spoofing（边界，不作主正例）

BS08 的研究演示以 **节点 root** 为起点，原文明确未观察在野利用。A=被注册的 workload-a pod；B=攻击者控制的宿主进程。B 能改 cgroup 元数据；没有两个 AI agent 或 A 主动披露的必要。公开步骤先显示宿主请求被拒，再显示修改后获得 A 的 JWT-SVID；未展示向具体下游资源认证。命令名出现 1.12.4，但这不足以确定全部组件版本；实施日期、本文准确发布日期／个人作者在此次核验正文抽取中未知。

关联失效是已攻破宿主伪造 attestor 所信任的运行时属性。本文采用的是作者展示的凭据返回终点，不采用“任意服务均已访问”的扩大解释。原文明确依赖可信节点；不能拿此例证明节点仍可信、受限 B 也能借用 A 身份。与 K2/K3 的增量是以“拒绝→节点元数据受控→错误 SVID 返回”的边界对照说明可信基础，而非新增主场景成功案。

#### BN-06／07／08 — 不补写未取得事实

- **BN-06：**BS10 原文未取得，不知道 metadata downgrade 的最小权限与身份粒度；保留访问受限的未知，未重复换路抓取。
- **BN-07：**BS04 §1.14.6（2026-04-27）的 aws_iid 条与 §1.15.1（2026-05-28）的 azure_imds 条说明 node attestation 修复。它们是节点身份／证明处理线索，未进一步打开公告、配置或 PoC，不能当 workload caller 实测；本记录不增加这一层候选的核验工作。
- **BN-08：**检索题名与链接为 [Agent Name Collision Attacks in Multi-Agent Systems](https://arxiv.org/abs/2609.27624)。只扫检索摘要，不以摘要中的实验结论承重。Paper/INDEX 按题名／编号未命中；如后续选择该线索，应先取得可读笔记或用户授权材料，再依 notes-first 核定，不能本记录自称已读新论文。

<a id="bn-09"></a>

#### BN-09 — Docker Sandboxes：经代理隧道使用转发进沙箱的宿主 SSH key（未关闭 issue，备选）

https://github.com/docker/sbx-releases/issues/121 （2026-05-05 提出，2026-09-30 仍未关闭）：报告者称，在 Balanced 策略、未配置任何凭据的沙箱中，agent 经 forward proxy 的 HTTP CONNECT 把 SSH 隧道到 `ssh.github.com:443`，用转发进来的宿主 SSH key 通过了 GitHub 认证；Docker 成员回复将改为按沙箱开启。官方隔离文档另写明 SSH agent 转发默认开启，“any process inside the sandbox can ask the forwarded agent to authenticate or sign data”（主线程 2026-09-30 回源核对）。

A=宿主用户的 SSH 身份，B=沙箱内的任意进程；材料（私钥）不离开宿主，沙箱取得的是签名／认证能力。它对应 K3：身份的使用应满足授权使用条件，而不只是能接触到签名能力。限制：复现来自报告者自己的环境，不是厂商缺陷确认；私钥未被取出。保留为备选。

#### 机制参照：合法代取与角色来源

BS06 的 Delegated Identity API 明确赋予获准可信 delegate 代取身份的能力，并说明 PID 生命周期维护义务；授权代取本身不是冒用案例。此接口说明不能作为 BM1 的公开攻击轨迹。

BS09 当前 AWS 文档的 *IAM authentication inferences* 提醒：若非 AWS 服务也获准 AssumeRole，自选 session name 会影响 EC2 实例归属推断，因此需约束 trust policy。这里保留身份粒度与配置条件参照，没有据文档举例宣布发生攻击。

## C. 可多篇引用的安全条件—案例索引

以下是**待逐篇检查的条件**，不是对任何 SOTA 论文 assumption 的预裁，也不是本论文已提供的保证。

| 条件 ID | 可检验的条件表述 | 案例与承重位置 | 失效配置／限制 | 留给逐篇分析的问题 |
|---|---|---|---|---|
| K1 | 能接触不可信内容的 agent 不能读取并向非获准接收者披露相关身份材料 | B1 Experiment 1；B2 Attack demonstration；B3 Test Setup＋Attack Flow | 分别是用户 SSH／OTP／虚构用户 token；不等于同一身份粒度 | 所讨论凭据是否真的可被 agent 读取？允许哪个输出路径？ |
| K2 | agent 相关认证材料的存储不向攻击者已获权限暴露 | B4 What Was Stolen §1–2；B5 厂商 What Happened | N01 是宿主 infostealer；Nx 是已有恶意执行。攻击者权限不可省略 | 论文防护边界覆盖该访问主体吗？谁负责材料存储保护？ |
| K3 | 使用某工作负载身份应满足其授权使用条件，而不只是某处存在有效材料 | B6 Phase 2；B5 UPDATE 3 | 仅证明对应 Kubernetes／GitHub 使用；没有逐 agent 实例绑定实验 | 身份验证依赖哪些 holder／通道／请求条件？来源条件是否对应？ |
| K4 | 新启动的工具／辅助进程不能未经相应授权继承更广身份使用能力 | B7 Technical Breakdown＋AWS Description；BM2-c（Docker：第三方 kit 继承内置 agent 的 OAuth 信任） | workspace trust 前提冲突；现有证据是本地身份调用，不是离机凭据；BM2-c 是厂商修复记录，无利用轨迹 | 哪个组件加载配置、决定权限与身份上下文？是否在论文中介边界内？ |
| K5 | 出网中介需约束与任务相关的账户、认证来源和接收者，而不只看域名 | B8 ASE-S076/S077 精确小节 | 攻击者自带凭据、允许域、已授权可读文件；不是受害 key 泄露 | 论文允许域是否仍可通向攻击者账户？其声明是否覆盖此条件？ |
| K6 | 凭据保密与操作授权／决策完整性是分别需要证据的性质 | B9 Appendix 2＋§4.1.1 | 凭据隔离守住仍发生被诱导操作；这是负对照 | 目标到底是防密钥披露、冒用，还是 A 被诱导代办？不可互相替代 |
| K7 | 允许目的地控制权变化后，继续使用的允许状态需与实际接收者对应 | B10／B10-E：Phase 4、Execution Flow | 原允许域失效并被攻击者取得；是域控制关系，非 caller 绑定 | 论文是否用域名许可代表接收方可信，是否处理控制权变化？ |
| K8 | 受约束主体的获准写入不能自行放宽其审批政策 | B11／B11-E；B17／B17-E 为同条件备选 | 政策配置对 agent 可写且变更生效；两产品不算两个条件 | 哪个组件持有政策？被约束主体可否改它？ |
| K9 | 新建敏感配置产生执行效果前须经过相关批准 | B12／B12-E1、E2 | 新建路径漏检查、落盘后 IDE 自动启动；已有编辑审批曾成立 | 是否覆盖创建、加载与启动，批准是否先于效果？ |
| K10 | 先前批准应持续对应实际执行内容，变更后重新判断 | B13／B13-E1、E2 | B 已有仓库／配置写权；名称未变而命令变化 | 批准对象可变吗？此处是内容关联，不能替代主体身份绑定 |
| K11 | 获准辅助服务代发的效果也应受任务授权范围约束 | B14／B14a；OpenAI 后续调查 Background／timeline | 任务可达包服务，该服务有额外网络权能；后续提权不是此前提 | 中介是否覆盖被调用服务的效果与额外权能？ |
| K12 | 隔离外消费者解析域内可控对象后仍须检查最终效果边界 | B15／B15-E：Description | 域内可建链接、域外消费者写入；已证越界写入，执行只是可能 | 谁最终消费对象，检查在解析前还是作用到实际目标？ |
| K13 | 配置加载入口不能将不可信工作区输入自动视为获准控制配置 | B16／B16a、B16-E Details | headless／CI 配置加载路线；不要求先有模型命令输出 | 入口信任如何建立？此条件是否由论文机制保证？ |
| K14 | 运行模式变化后仍应执行用户保留的细粒度工具限制 | B16／B16b、B16-E Details | 特定模式与显式 shell allowlist 并存；不等于所有操作已被允许 | 授权检查是否在各运行模式保留，哪些例外是明确授权？ |
| K15 | 认证结果须确实表示本次预期操作所确认的 caller | B18／BN-01；BS01–02；BM2-a（Docker：恶意沙箱抢占另一沙箱的 OAuth 回调端口） | Vault AWS IAM 错误解释后发行；EC2 路线不受该漏洞影响 | 是否依赖第三方身份响应转换？响应来源与语义是否都核定？ |
| K16 | 签名者须有权证明所采用的执行环境／主体属性 | B19／BN-02；BS01、03 | Vault GCE；绑定 service account 会阻断该路径 | 论文是否采用同类平台证明，如何约束声明者的证明权限？ |
| K17 | caller 标识关联须处理数字标识复用与原进程生命周期 | BM1／BN-03；BS04–05；BM2-b（Docker：复用已删沙箱的名字会继承其内容） | 已修复 PID 安全缺陷；攻击权限／误发／冒用终点未取得 | 生命周期义务如何实现？不能据此推出逐消息发送者已验证 |
| K18 | 凭据或授权被撤销后，已在运行的代理或会话须立即停止按旧授权放行 | BM2-d（Docker 0.45.0：撤销后运行中的代理仍被授权） | 厂商修复记录；影响时长与利用未披露 | 论文的撤销或身份回收怎样作用到已建立的会话、缓存与代理状态？ |

**仍无直接结论的项：**本批未证明“真实恶意 agent 在某身份论文完整配置下，取得不合谋 agent 的实例身份并被接受”。没有据来源缺失断言此类事件不存在；案例证据先回答路径与条件，论文适用性留步骤 3／5，冒用链留步骤 6，本论文建立条件／阻断攻击留步骤 7。

## D. 查询、核验边界、冲突与未决事项

### D1. 本轮实际阅读与定向查询日志

| 日期／动作 | 范围与原因 | 结果／处置 |
|---|---|---|
| 2026-09-27 本地读取 | TASKS §0／§4.1、总计划、当前恢复点、ACR／ASE checkpoint／README／case-register；选中来源底稿、ACR raw/002 与 ElizaOS 人类笔记 | 复用历史已核事实；未重读任何 PDF，未改原包 |
| 同日 原始网页定向复核 | Invariant Experiment 1、Brave Comet demonstration/timeline、General Analysis 的设置与结果 | 核实实际披露对象；终点分别保留 SSH／配置、OTP、dummy token 表，未提升为身份冒用实测 |
| 同日 原始网页定向复核 | Nx postmortem、Wiz、GitGuardian 的事件正文／更新 | 核对程序与 AI CLI 分工、后续账户使用及统计限制；未打开泄露仓库或样本 |
| 同日 原始网页定向复核 | Sysdig C12 的 Phase 2、Wiz Amazon Q 的 PoC/impact、AWS bulletin Description | 保留 token 使用范围与 trust 条件冲突；未复制运行代码 |
| 同日 旧候选原文复核 | Unit 42 *OpenClaw’s Skill Marketplace and the Emerging AI Supply Chain Threat* 的 Summary、Supply Chain Surface、Early Campaign、技能叙述 | 有多技能／多行为，但未取得逐部署权限与统一凭据终点；C33／C22仍作分解待核候选，不用整体身份全控措辞 |
| 同日 路径 P2 缺口，第 1 组检索 | `AI agent credentials stolen local malware OpenClaw token security research` | 出现 Hudson Rock 报告线索、媒体、研究论文与一般指南；没有打开新 PDF或把检索摘要算事实 |
| 同日 同一缺口，第 2 组检索 | `OpenClaw configuration token infostealer Hudson Rock February 2026` | 定位 InfoStealers／Hudson Rock 的趋势页；循其原始报告链接进入 N01 |
| 同日 具体来源追读 | Hudson Rock 02-19 趋势页仅用作导航；02-16 原始报告 intro、Grab-Bag、What Was Stolen、Technical Risk | 采用 N01 的实际材料外传；趋势页“定向感染”宽泛说法不覆盖具体报告“通用抓取”的说明。缺口已有代表，停止扩展 |

检索返回的新闻、论坛、GitHub 二次总结、论文摘要及一般部署指南未作为本轮承重来源。没有打开报告链接中的攻击设施、原始泄露数据、图片中的密钥或复现代码。Unit 42 第一次误用 `/openclaw-agent-security/` 返回普通 Internal Error，随后从 ASE 底稿取得正确公开 URL；这不是安全限制绕过。ACR ShadowLeak 的既有原文访问限制、ASE-L10 的历史派发阻断保持原记录，未重试。

用于 C33／C22 筛选的本轮来源：[Unit 42, *OpenClaw’s Skill Marketplace and the Emerging AI Supply Chain Threat*](https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/)，本次抽取未固定作者／发布日期，正文明确调查期 2026-02 至 05。它的“安装即全部身份控制”是作者总体解释，不作为逐配置实测结论。N01 导航页为 [Alon Gal, *2026 Infostealer Trends I’m Monitoring at Hudson Rock*](https://www.infostealers.com/article/2026-infostealer-trends-im-monitoring-at-hudson-rock/)，2026-02-19；未把它当独立感染证据。

**2026-09-28 历史日志追记：**原执行者从仍可读取的当时工具返回恢复了上述两组查询的 42 项合并结果标题／URL，以及实际打开链，见 [[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-02/sources/2026-09-28-prior-search-log-recovery|历史搜索日志恢复]]。42 项中只有趋势页打开正文，再循链接进入 N01；其余 41 项仅摘要呈现。逐项排除理由、各结果所属查询和摘要逐项阅读程度不可恢复，仍记为日志缺项；本追记没有重新搜索，也不把 42 项视为逐页审查或独立事件。

### D2. 需要随交付保留的事实冲突

| 位置 | 差异 | 本轮采用与后续需要 |
|---|---|---|
| ACR-C34 的强用途概括；ASE-C16 | “live credentials”容易被读成已见离机凭据；原 PoC 实为身份查询 | 按 B7 收窄；需要更强主张时取得独立凭据获取／使用证据，当前不得补推 |
| Wiz Amazon Q 与 AWS Description | 无 workspace trust check vs 要求用户信任工作区 | 共同事实采用；最小触发配置未知，不择一消除冲突 |
| ACR-C17 日期与 GA 更新页 | 旧记 2025-06-16，现页 2025-07-08；当前页说明虚构数据与未复测 | 用现页明示日期及历史实验性质；不静默改旧 raw |
| ACR-C33／F17 与 ASE-C22 | 复合 campaign、agent技能执行和不同外传行为曾被浓缩成统一身份全控 | 本轮不以整体条目证明某一路径；N01是不同的明确材料取得报告 |
| ACR-C36／F17 与 ASE-C24 | AI CLI 找路径与恶意程序收集外传容易混写为 agent 披露 | 按 B5 分段；不据 95/366 计算成功率、不把所有无输出归为拒绝 |
| ASE-C12 原文引言与 Phase 2 | 全集群表述强于展示的 namespace 范围 | 采用已展示范围；agent驱动归属归于 Sysdig，不变为独立证明完全自治 |
| Comet 原文措辞 | can take over 与已发生 takeover 不同 | 记录 OTP 披露与作者可接管主张；没有后续实际账户会话轨迹 |
| ASE-A09 | 自带攻击者 credential 容易被归类为受害者 key 泄露 | 只作允许域／账户来源条件参照；不计两类泄露成功 |

### D3. 未决事项与有界停止

1. **身份与凭据用途须分别映射。** SSH、用户 OTP、refresh token、网关 token、device 私钥、工作负载 token 不能统一叫本地 agent ID；但只要承载 agent 执行所需权限，就可能是相关保护对象。2026-09-29 用户澄清已写入 [[Thesis/Work/Design/sandbox-mediated-agent-execution/mechanism#Protected credentials and the role of agent identity|机制定义]]，不再以“非 agent 凭据”排除相关性。后续逐篇固定托管关系、授权关系和验证者接受的身份。
2. **具体权限迁移尚未建立。** infostealer、供应链程序或应用内恶意代码的载体不是排除标准；需查初始入口、控制后的实际权限及有无依赖可信基础失陷。B4 初始入侵仍未知；B6 已补外部 marimo 漏洞利用的报告与官方机制，但事件权限轨迹仍不完整。不能直接等同于受限 malicious agent，也不能仅因应用受控判为范围外。
3. **P1 与 P2 的冒用终点有缺口。** Invariant／Supabase／N01 没有后续认证轨迹；Comet 是可接管主张。保留此终点，不为填满第三层另做无界检索。
4. **具体条件现实性不是普遍证伪。** K1–K17 是不同证据层次的检查入口，BM1 尤其不含成功攻击轨迹；只有论文确实依赖且配置匹配才能用于其 assumption 讨论。
5. **旧未取得来源仍未知。** ASE-C03 PDF核心事实、ASE-A02 ShadowLeak原文、ASE-L10历史阻断、ClawHavoc逐技能链，以及未读候选论文没有本轮补齐。当前代表材料不依赖这些缺口，故本批可有界交回。
6. **没有发生率／成功率结论。** 便利样本、集合、重复记录、尝试分母不一致；不据登记数量或本轮找到两类材料推断流行程度。

### D4. 检索与阅读范围

- [[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-02/sources/2026-09-28-old-case-supplement|旧记录阅读日志]]记录八个 verification 及所用 raw 的实际读取范围。案例事实与原始位置已集中在 §B；未重新打开的网页不记为直接访问。
- [[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-02/sources/2026-09-28-binding-case-search|公开来源检索日志]]保存两组查询、一轮 PID 线索查询与已知 GCP 公告追读，84 条显示结果逐项区分摘要／正文、采用／备选／未采用。它们不是 84 篇全文或 84 个案件。
- 来源核对涵盖原 C01／C15／C18 记录、Project Zero、Vault AWS／GCP 公告、SPIRE CHANGELOG 与 PR #886 的承重小节。并未逐页重读全部历史来源或进行本项目复现。
- 日志限制：9/27 逐项排除理由不可完全恢复；BN-06 正文未取得、BN-07 节点证明条目未深查、BN-08 无笔记／全文。采用主张不依赖补造这些材料。

- **核验底稿：**[[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-02/sources/acr-screen|ACR 来源提取]]、[[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-02/sources/ase-screen|ASE 来源提取]]仅用于溯源，采用处置以 §A 为准；[[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-02/step-02-completeness-acceptance-sol|Sol 字段验收记录]]的范围仅为 B1–B9，不作为所有案例已全面复核的结论。

### D5. 认证与调用者机制的一手来源目录

以下 BS 编号对应 B18、B19、BM1 和 BQ；网页实际访问日为 2026-09-28。小节名为主要定位，抽取行号仅辅助复查；当前文档不能倒填历史版本的保证。

| 源号 | 来源身份、日期、URL | 本次承重位置／核验范围 |
|---|---|---|
| BS01 | Felix Wilhelm，Google Project Zero，*Enter the Vault: Authentication Issues in HashiCorp Vault*，2020-10-06。[原文](https://projectzero.google/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html) | Introduction；Authenticating to Vault；sts:GetCallerIdentity；STS (Caller) Identity Theft，尤其最终登录响应与修复段（79–87）；Exploiting Vault-on-GCP（89–144）。原始正文已读，未跟入 PoC 脚本／攻击站点 |
| BS02 | HashiCorp，*HCSEC-2020-16 - Vault’s AWS Auth Method Allows Authentication Bypass*。[公告](https://discuss.hashicorp.com/t/hcsec-2020-16-vault-s-aws-auth-method-allows-authentication-bypass/18101) | Publication Date=2020-08-18；论坛页面署名 jfinnigan，显示 2020-11-25；Summary、Background、Details、Conditions、Remediation（9–29）。两日期保留，不把论坛显示日期当实验日期 |
| BS03 | HashiCorp，*HCSEC-2020-17 - Vault’s GCP Auth Method Allows Authentication Bypass*。[公告](https://discuss.hashicorp.com/t/hcsec-2020-17-vault-s-gcp-auth-method-allows-authentication-bypass/18102) | Publication Date=2020-08-18；论坛 jfinnigan，2020-11-25；Background、Details、Conditions、Remediation（9–30） |
| BS04 | SPIFFE/SPIRE maintainers，*CHANGELOG.md*。[官方记录](https://github.com/spiffe/spire/blob/main/CHANGELOG.md) | §[0.8.0] - 2019-05-20 的 PID reuse/#886 条（1796–1803）；另查看 §1.14.6 Security 与 §1.15.1 Security，仅留 BN-07 线索 |
| BS05 | Evan Gilman（evan2645），SPIRE，*Introduce peertracker package*，PR #886，2019-05-02 创建说明／合并。[原 PR](https://github.com/spiffe/spire/pull/886) | Conversation 首段（171–185）与合并记录；读修复目的／caller 存活语义，没有做 diff 安全审计或执行测试 |
| BS06 | SPIFFE/SPIRE maintainers，*spire_agent.md*，main 分支；页面未固定发布／更新日。[官方文档](https://github.com/spiffe/spire/blob/main/doc/spire_agent.md?plain=1) | Delegated Identity API（2867–2897）；SPIFFE Broker API 中与 Workload API 的区别（2970–2979）。只作接口与权限边界参照，非历史事件 |
| BS07 | HashiCorp，mark.collao，*HCSEC-2025-30 - Vault AWS Auth Method Authentication Bypass Through Mishandling of Cache Entries*，2025-10-23。[公告](https://discuss.hashicorp.com/t/hcsec-2025-30-vault-aws-auth-method-authentication-bypass-through-mishandling-of-cache-entries/76709) | Background、Details、Remediation（15–25）；认可报告人为 Pavlos Karakalidis。没有另查其未链接的 PoC |
| BS08 | Palo Alto Networks Unit 42，*The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE*。[研究原文](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/) | Executive Summary（9–20）；How the Agent Attests the Workload（134–159）；Workload Impersonation: Selector Spoofing via Cgroup（168–219）。正文抽取未显示本篇确切作者／发布日期；搜索仅称两周前，不据此推定日期；相关推荐日期不是本文日期 |
| BS09 | HashiCorp，*AWS - Auth Methods*，当前文档；未固定发布／更新日。[官方文档](https://developer.hashicorp.com/vault/docs/auth/aws) | Authentication workflow／IAM auth method；IAM authentication inferences（238–247）作为现有保护与身份粒度提醒，不作已发生案例 |
| BS10 | Google Bug Hunters，*Privilege escalation via GKE Metadata protection downgrade attack scenario*。[原页面](https://bughunters.google.com/reports/vrp/BrQZ18W5k) | 请求成功但正文为 0 行，作者／事件日／配置与终点均未核，不采用 |

### D6. 四类代表案例的分类复核（2026-09-28）

用户要求每类挑一个案例亲自检查。这里采用目的性选取：优先选分类因果清楚、原始来源可定位的代表，不声称随机抽样或客观严重性排名。四类是两条取得路径（P1／P2）加两个条件检查方向（正确绑定／完整中介），不是互斥、穷尽的攻击 taxonomy。

| 检查类别／所选案例 | 2026-09-28 实际重读的一手位置 | 分类判断及证据上限 |
|---|---|---|
| 诱导披露：B1 Cursor 工具投毒 | [Invariant 原披露](https://invariantlabs.ai/blog/mcp-security-notification)，Experiment 1，正文 L60–68 | **支持 P1。** 报告明确由 agent 读取并向恶意 server 提交用户 SSH key／配置；必要条件是 agent 可读及可发送。未核凭据有效性或后续登录，不是 agent 实例冒用证据。 |
| 无需受害 agent 披露：B4 OpenClaw infostealer | [Hudson Rock 原报告](https://www.infostealers.com/article/hudson-rock-identifies-real-world-infostealer-infection-targeting-openclaw-configurations/)，导语、Grab-Bag、What Was Stolen §1–2，L19、25、30、38–43 | **支持 P2 的材料取得。** 报告由恶意程序抓取 gateway token／device 私钥；无受害 agent 披露步骤。初始入侵权限未说明，攻击方未被证实为另一个 agent；Technical Risk 中的后续使用只是风险解释。 |
| 正确绑定：B18 Vault AWS IAM | [Project Zero 原研究](https://projectzero.google/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html)，STS (Caller) Identity Theft，尤其 L77–87；[HashiCorp 公告](https://discuss.hashicorp.com/t/hcsec-2020-16-vault-s-aws-auth-method-allows-authentication-bypass/18101)，Background／Details／Conditions／Remediation | **支持 K15 的认证发行层错绑。** 不需取得受害者秘密，错误解释身份响应后返回带策略的会话 token。身份对象是 IAM principal→Vault role；不是活进程→agent 的绑定失败，也没有本次核得的 secret 读取响应。 |
| 完整中介：B12 CurXecute | [Cursor 官方公告](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm)，Summary／Impact／Remediation，L137–155 | **支持 K9 的审批覆盖缺口。** 编辑敏感文件有审批，新建同类文件却漏检，并能触发 MCP 执行；说明检查必须覆盖产生效果的创建入口。厂商明确受影响及修复版，不能称当前所有 Cursor 可用，也不据此补推凭据泄露。B12-E1 研究者过程本次沿用既有核验，未重新打开。 |

结论：四个案例均支持上表限定的分类。它们分别证明一个窄条件／路径存在；每类一个不能验收该类所有子条件、其余案例或论文适用性。尤其 B18 不能填补 BM1 留下的完整 runtime caller 冒用轨迹缺口。选择 B4 是因为它直接涉及 agent 相关认证材料且材料取得步骤清楚，初始感染仍未知；若检查重点改为“取得后确有使用”，可读 B5/B6，但须核对入口、实际权限和混合链，不能因 service-account 身份或程序攻击者而排除相关性。

本次仅重读上述五个公开正文，没有运行 PoC、访问泄露原件或补充实际攻击观测；未重启全面案例检索。用户尚未完成亲自审阅，本次复核不代填步骤 4。

### D7. 攻击路径完整性复查（2026-09-29）

用户要求从 B6 的入口遗漏推广检查其他案件。本次逐项读 B1–B19 与 BM1 共 20 个记录单元，核对“B 最初控制什么 → 怎样进入目标／触发执行 → 以什么权限取得材料或效果 → 实际终点”。这是当前采用记录的有界审计，不是重查 71 条登记，也不是每案都重新上网。缺版本／日期不自动等于缺攻击因果；公开公告也不强行补成在野事件。事实修订已直接写回各 B 条目。

| 单元 | 入口与关键路径检查结果 | 本次处理／剩余限制 |
|---|---|---|
| B1 | 接入 B 的 MCP → 描述被 A 摄入 → A 读文件并提交 | 入口与披露者明确；材料有效性／后续使用未知，维持 P1 终点 |
| B2 | 外部网页 → 已登录的 Comet 跨站读 OTP → 回传 | 入口明确；实际登录未展示，不补成接管成功 |
| B3 | 可提交工单 → 高权限 Cursor 读私表 → 写客户可见回复 | 初始权限与读写链明确；dummy tokens 限制保留 |
| B4 | 感染方式未知 → infostealer 抓配置 → 外传 | 原源重读＋定向查询未补到同一事件入口；限制端到端比较，不影响材料取得的窄事实 |
| B5 | 外部 PR 注入 → 发布 token → 投毒包 → 下游安装／postinstall → 窃密 | 已补原厂复盘前半链；上游 CI 与下游安装权限分开，逐台 OS 权限仍未知 |
| B6 | 外部 marimo 入口 → 应用执行 → pod token／API；另有宿主提权 | 已补入口、pod 解释和因果分支；不能声称低权限独立复现已完成 |
| B7 | 仓库配置 → 打开并信任工作区 → 自动执行／环境继承 | 新核官方 GHSA；采用含信任前提的路径，无提示分支与 Wiz 冲突未消解 |
| B8 | 文档内容及攻击者自有 credential → A 经允许域发业务文件 | 已有入口与账户流向；不是受害凭据窃取，厂商与研究者会话不拼接 |
| B9 | 聊天内容污染记忆 → 后续正常任务 → 插件转账 | 已有输入与执行者；秘密隔离成功是负对照，不补泄露 |
| B10 | Web-to-Lead ＋控制失效允许域 → 查询／输出消费者外传 | 采用范围内的入口与接收者条件已有；未改为身份材料泄露 |
| B11 | 不可信内容 → A 写政策 → 后续工具自动批准 | 核心链已有；具体配置层级仍分源，不把 OS 提权写入这条链 |
| B12 | Slack 等外部内容 → A 新建配置 → IDE 自动启动 | 核心链已有；用户／工作区配置示例分源，未补成偷钥匙 |
| B13 | B 已有仓库写权 → 改已批准同名配置 → 再加载执行 | “已有仓库写权”是 PoC 明示起点，非隐藏的宿主控制；不能迁移成任意远程 B |
| B14 | 仅采用 B14a：受限任务借可达包服务代发外网请求 | 已拆集合，采用路径无须依赖后续 root；b／d／f 仍不足以承重完整身份攻击链 |
| B15 | 注入触发域内命令 → 可控链接 → 域外文件消费者写入 | 公告的条件机制已有；完整模型轨迹／进一步执行未披露 |
| B16 | a 不可信 PR 工作区配置；b 外部 issue 内容＋yolo／allowlist | 已补官方示例与必要配置；保持两路独立及公告证据等级 |
| B17 | 外部内容 → Write profile 写项目政策 → 绕过后续批准 | 重读官方 Impact，确认输入类型与权限；未公开具体成功运行，维持条件证据 |
| B18 | B 自有云身份／IdP → 特制认证请求 → Vault 错误发 token | 入口、受控响应内容与发行终点已有；不追加未展示的 secret 读取 |
| B19 | B 自有 service account 签可控属性 → 特定 GCE role 接受 | 声明能力、目标属性／配置已给；没有独立资源访问轨迹 |
| BM1 | 官方修复 caller 生命周期；没有具体攻击过程 | PR 与检索仍未补到利用链；继续作为机制缺陷证据，不能称完整案例成功 |

**补源实际范围。** B4 重读 Hudson Rock 正文，查询 `site.infostealers.com "OpenClaw" "infection" "February 16"`、`site.hudsonrock.com "OpenClaw" "initial"`；结果主要为转载／其他 skill 事件，未作为同案入口证据。B5 重读 Nx *What Happened* 与 *Technical Details: How The Attack Worked*。B7 重读 Wiz *Technical Breakdown / Proof of Concept*、AWS bulletin *Description*，追入官方 GHSA *Impact*；查询 `"CVE-2026-12957" "workspace" trust bypass` 未获得解决分歧的一手配置说明。误点的另一 symlink GHSA 未用于本案。

B6 重读 Sysdig Phase 1／2，以 Kubernetes *Pods* 的定义与 *Service Accounts* 的 token 挂载说明解释结构；当前文档不证明 5/29 的运行配置。B16、B17 分别重读原 Google 公告 *Details* 与 Zed 公告 *Impact*，补到场景或确认已有条件；未新增运行证据。BM1 重读 PR #886 的 caller 获取／存活说明，并查询 `site.github.com/spiffe/spire "PID reuse" "886"`、`site.github.com/spiffe/spire "PID reuse" exploit`；官方 changelog、接口说明及其他产品 PID 问题没有提供本案利用链。其他条目复用本节已有来源定位。本次未运行攻击、读取泄露原件或联系报告方。

**定义一致性修订范围。** 已调整高层三层表、执行计划第三层／步骤 6 和机制开头的表述；研究动机原句经用户核对后已恢复，凭据保护对象定义由机制说明持有。两篇试做仍按各自真实对象核验，案例适配文字不再以“不是 agent 实例凭据”排除意义。旧原始输入／历史验收快照不改写；本次不是全仓历史内容重写。

### D8. Docker Sandboxes 官方缺陷记录的追加（2026-09-30）

用户 2026-09-30 决定把 Docker Sandboxes 的相关缺陷加入本案例库。来源是步骤 8 的深入核查（[[Thesis/Work/Intake/2026-09-27-impersonation-credential-acquisition/step-08/sources/deep-docker-sandboxes|Docker Sandboxes 深入核查]]）；主线程已回官方发布说明与隔离文档核对 BM2 四句原句与 BN-09 引用的文档原句。这次是按用户决定定向追加，没有纳入 §A 的 71 条浅筛，也没有扩展检索其他厂商。新增条件 K18（撤销须立即作用到运行中的代理）只由 BM2-d 支持。

## E. 后续复用与交付界限

| 接收方 | 本轮实际交付 | 尚未完成 |
|---|---|---|
| SUB-01 | 两类材料取得的代表、反例、共同条件索引与证据天花板 | 本案例单元不交付贡献选择或“我们的机制已经有效／新颖”结论；两篇试做另见包入口，不在此复写其状态 |
| SUB-06 | B1–B19 的事实／条件单元（含备选与限定集合）、BM1 官方缺陷、原始定位及跨包差异 | 按最终主张挑选和正式整合；不据此关闭整个 SUB |
| SUB-05／步骤 3、5 | K1–K17 公共条件索引；逐篇引用 B／BM 记录、完整字段与原始来源 | 对具体机制论文 assumption 的依赖确认、案例适用性与模型内／外判断 |
| SUB-02／04（后续输入） | 有据的角色、材料、初始权限及已报告终点 | 新评价场景、成功判据和统一威胁模型的选择；无新增实验 |

**证据边界：**云 IAM 错误发行已有对应案例，可信节点／中介下受限 B 借用不合谋 A 身份并被下游接受的完整 runtime 轨迹仍缺。BN-05 的节点 root 前提不能填此空位；BN-03 的修复记录亦不能提升为该终点。后续按实际论文条件定向回补，不把此精确缺口变为开始逐篇分析前必须满足的门槛。

以后引用本记录与原来源，只有新增主张、配置差异或事实冲突才再核；不因为换 SUB 就重查同一事实。本记录提供步骤 2 的案例与条件输入；具体论文的机制检查仍按步骤 3／5 独立推进。
