# UID binding 安全论证：方法复核（2026-09-13）

对应计划：uid-binding-security-argument.plan.md。

用户要求：本 session 完成计划，先复核方法准确性。本记录仅复核方法与修订执行要求，未推导向量表、未读取封存表、未修改论文设计文件，也不是 harness 独立审查。

## 结论

**路线成立，但原计划的完整性判据与证据统计不能原样使用。** 合适的定位是：在明确威胁模型、配置和前提下，针对本地身份绑定的结构化安全论证；攻击向量表是论证的阅读界面。文献支持这种组织方式，不会替本机制证明攻击枚举完整或实现正确。

## 逐项复核

| 原计划位置 / 主张 | 裁定与执行修正 | 依据 |
|---|---|---|
| Context (3)：系统安全论文采用威胁模型 → 攻击能力 → 防御的 Security Analysis | **成立，有直接先例。** OpenSSH 论文 §5 明确假定被攻陷子进程可执行其上下文内的任意系统调用，再讨论进程干扰、文件系统、monitor 接口等及未防住的行为。只借用这个论证结构，不借用它的历史平台结论、代码行数估算或安全保证。 | S1；已先读仓库 OpenSSH note。 |
| 同段把 CAE / GSN / reference monitor / Common Criteria 一起称为 “Formal backing” | **混淆角色。** CAE 提供 claim–argument–evidence 与分解有效性说明；GSN 是表达论证关系的记法；reference-monitor 三条件是设计要求；CC 提供需求与保证证据的追溯结构。它们都不是本表的形式化证明，也不是一个已经标准化的“adversary-vector table 方法”。 | S2–S6。 |
| Step 1：“每个输入至少有一个向量，且每个向量有输入”即可 closure | **不充分，须修改。** 这是双向追溯检查。一个输入可能有多种失败方式；攻击也可能改变多个输入之间的关系、判定步骤或状态转换。应从顶层失败条件分解，说明分支为何覆盖它；再以接口、判定路径、生命周期和组合路径核查，并记录未能排除的遗漏。 | 分解需要组合规则与有效条件（S2）；本条对原验收逻辑的反例分析是本次复核推论。 |
| Context (2)：逐行 closed / out of scope / open 即“完整”，并称沿用 CCT fixed point | **只能表示已有条目全部有交代。** CCT 自己要求冻结节点与边、迭代可达关系、检查所有实质不同路径；原计划省掉了这些步骤。若不实际给出状态/转换抽象与闭包记录，不得使用“fixed-point proof”。即使算出了固定点，也仅对该模型成立，还需说明抽象覆盖现实接口的依据。 | 仓库 CCT closeout plan §D1b–D2；S2 的分解条件。 |
| Step 3：以 `[M]` / `[R]` / `[S]` / open 作统一证据级别，再统计向量数 | **至少两轴。** `[M]` 是某条观察在某配置实测，`[R]` 是阅读来源所得支持；`[S]` 是要求已写而未建成，不能支持“已实现防御”；open 是论证状态。单个向量可同时依赖 `[R]` 内核行为、`[M]` 局部实验及 `[S]` 引擎要求。分别记证据/实现事实与向量处置，统计不能按 M/R/S 把向量硬分互斥组。原统计还漏掉了 `[R]`。 | S2、S3；仓库 CCT §D1b 已区分 evidence / claim form / maturity。 |
| 把 obligation #6 整体放在表后的 residual line | **保留总体状态，但不能据此漏掉与绑定直接相关的引擎路径。** #6 的完整引擎正确性确实超出本表；然而正确读凭证、强制经过检查、保持消息与 session/dispatch 对应等，属于顶层绑定主张所需条件，必须进入分解与映射。声明“不考虑完全恶意引擎”不自动证明诚实引擎实现无误。 | `mechanism.md` §Identity lifecycle、六条 obligation；S1 §5 对 monitor 接口的处理。 |
| Context (1)：因此归因到 “the process the spawner launched” | **粒度过强。** kernel 保证发送时的 uid；进程与其同 uid 后代不能由该字段区分。顶层目标应为受生命周期约束的 uid 对应 execution / principal class，并明确 same-uid 与 live-at-send 限制，不能声称识别唯一原始 PID。 | `mechanism.md` §Identity lifecycle；`kernel/kernel-uid-binding.md` §8。 |
| Why：FAR 数字是 counts, not rates | **主旨正确，数学措辞需收准。** 小数是人为选定测试集内的计数比值，不能由此估计真实攻击总体的误接受概率。跨 arm 的分母还不同。保留同一泄漏事件的机制对照与原始计数，不把零观测推广成“无攻击能成功”。确定性本身不是排斥统计评估的理由，问题是此处没有支持该总体推断的抽样设计。 | `REPORT-binding-far-contrast.md` §Native FAR / §Honest scope；`REPORT-binding-arm3-workload-per-engine.md` §Limitations；S3。 |

## 文献角色与核实范围

以下在线来源用于**本次方法审查**。在线查证与论文证据准入是两回事：新来源尚未经过 Intake / Paper 准入，不能仅凭本记录直接写入论文作为已接纳的方法依据。原始 PDF 未打开。

| ID | 来源与可定位位置 | 已核实内容 / 限制 |
|---|---|---|
| S1 | Provos, Friedl, Honeyman, *Preventing Privilege Escalation* (USENIX Security 2003), [官方 HTML §5 Security Analysis](https://www.usenix.org/legacy/events/sec03/tech/full_papers/provos_et_al/provos_et_al_html/index.html) | 直接方法先例，含对手能力、逐项防御、monitor 接口风险及残余行为；不提供本机制的穷尽性证明。仓库已有 note，但本次方法用途若进入论文仍需更新其贡献说明。 |
| S2 | Adelard CAE Framework，[Building Blocks](https://claimsargumentsevidence.org/notations/cae-building-blocks/)、[Decomposition](https://claimsargumentsevidence.org/notations/helping-hand/decomposition/) | 分解需明确属性、组成规则、组合关系及成立条件；side-warrant 说明子主张何以支持顶层主张。支持修订分解要求。 |
| S3 | SEI，[Assurance Cases and Confidence](https://www.sei.cmu.edu/blog/assurance-cases-and-confidence/)，Making a Sound Evaluation | 证据与连接证据到主张的论证都需要；只有测试或只有论证都不够。 |
| S4 | NIST CSRC，[reference monitor 定义](https://csrc.nist.gov/glossary/term/reference_monitor)（来源 SP 800-53 Rev.5） | 三条件是始终调用、不可篡改、小到足以进行可保证完整性的分析与测试。这里的 tamperproof 不能只缩写成一般的“隔离”，verifiable 也不等于已经验证正确。Anderson 1972 的历史指向本次仅作书目信息，未读原始 PDF。 |
| S5 | UK Ministry of Defence ASEMS，[Goal Structuring Notation and Claim Trees](https://www.asems.mod.uk/toolkit/goal-structuring-notation-and-claim-trees)，§1.1.1.1–1.1.1.10 | GSN 表达目标、证据、推理关系、假设和上下文；图形完整不保证论证正确。本次不声称遵循某版 GSN 标准，也不需要强行绘制 GSN 图。 |
| S6 | NIAP，[Protection Profile for General Purpose Operating Systems](https://commoncriteria.github.io/operatingsystem/master/operatingsystem.html)，§5.2.1 / §5.2.2 | 官方实例列出 Security Target、问题定义、direct rationale requirements 和保证活动。CC 的链条不能一概简写为必经 TOE security objectives；本表亦不构成 CC 评估。 |
| S7 | SEI，[Arguing Security – Creating Security Assurance Cases 目录页](https://www.sei.cmu.edu/library/arguing-security-creating-security-assurance-cases/)；[官方文档地址](https://insights.sei.cmu.edu/documents/383/2013_019_001_293637.pdf) | 目录页署 2013-07-05，搜索索引返回的文档首页署 January 2007，三位作者对应计划。**不能据目录页判 2007 错误。** 准入时需注明文档日期与目录日期差异；此轮不声称全文核读。 |
| S8 | 归纳不变量来源（2026-10-12 补）：Floyd 1967 *Assigning Meanings to Programs*；Ashcroft 1975 *Proving Assertions about Parallel Programs*；Lamport 1977 *Proving the Correctness of Multiprocess Programs*；TLA+ 定义见 [Lamport high-level-view](https://lamport.azurewebsites.net/tla/high-level-view.html) 与 [TLA+ 列表 Merz 2019-12-19](https://discuss.tlapl.us/msg03315.html) | Init ⇒ I、I ∧ Next ⇒ I′、I ⇒ goal 的标准归纳证明；三篇原文本轮未打开，书目信息来自二手检索。**未入库，不能在论文引用**；计划 Context (3) 据此描述方法。 |

四个仓库候选都先读了人类可读部分：Capsicum note 支持能力与隔离机制，但没有足够的逐段方法依据来把它认定为本表格式的先例；OpenSSH 可由官方 HTML §5 补核；seL4 是形式化内核正确性的参考，不能把其证明保证借给本表；Sandlock note 的 §6 是十项确定性检查与初步评估，不能由此声称攻击已穷尽。当前以 **OpenSSH 为具体先例、CAE 为论证组织指导** 已足够，其余只作角色明确的背景。

## 修订后的执行方法

1. 先写安全性质及其否定：在声明的 uid 粒度、发送时刻和生命周期条件下，什么事件构成错误归因。区分身份绑定与后续 grant 授权。
2. 从该失败条件分解出可能失效的判定条件、数据关系、读取/判定路径和状态转换；在填入防御之前，写出分支覆盖理由。输入↔向量对应只做追溯检查。
3. 对每一类写清对手动作、所需前提、失败因果链、防御为何切断这条链、来源和限制。检查组合与时序；不能排除的分支保留 open。
4. 对每条支持分别标注 `[M]` / `[R]`；对尚未实现的依赖标 `[S]`（等同设计文件 `[U]`）。从源文件搬入标签时按含义重判，不能照抄字母，因为 kernel note 某些 `[R]` 标题同时写着 not built。
5. 每个向量给一个最终处置：**supported under stated premises / conditional on unbuilt requirements / open / declared out of scope**。前一项仍须明确适用配置与证据限度，不叫“普遍已证明”。如果是合取链，只要有必要且未实现的依赖，就不能由旁边一项 `[M]` 将整行提升为实现已闭合。
6. 单独报告：列出多少向量、四种处置各多少、尚有哪些覆盖不确定性；另一份证据清单记录 M/R/S 的支持与依赖，不把它们当互斥的安全等级。
7. 对照 C1–C4 与六条 obligation；保留 #5、#6 的整体状态，并显式映射 #6 中本地绑定所依赖的部分。表完成只说明审查材料齐备，顶层安全结论仍受全部必要前提限制。

这七步是**针对本计划修订的工作方法**，不是声称从某篇文献逐字采用的标准程序。原计划的落盘批准与旧表“替换/并列”裁决仍保留。执行依赖按下方 2026-09-14 澄清理解。

## 2026-09-14 对覆盖论证的进一步澄清

用户指出：“现有材料为什么足以支持这些路径覆盖了所声明的错误归因？”此前回复把“可以开始构造论证”说成“现在已有足够依据写出覆盖成立”，这一跳没有依据，已撤回。**本次复核确认了工作方法需要哪些条件，没有确认现有材料已满足这些条件。**

W2 P2a 不仅补实测，还提供需要纳入覆盖分析的实际接口、状态机、异步操作和生命周期关系；P2b 提供真实配置。现有 kernel derivation 不能替代这一完整流程模型。现在最多整理候选路径、已有依据及缺失对象；待相关设计与实现稳定后再作最终分解与核对。W2 结束也不自动等于覆盖证明完成。后续依赖与工作区建议统一记在对应 plan 的“2026-09-14 clarification”，本记录不另维护工作状态。

## 文件检查

本次仅写入本记录并修订对应 plan。两文件无行尾空白；repo-audit 未对这两份文件报错。全仓检查 exit 1：83 个 Markdown 断链、3 个 wikilink 断链、35 个悬空 fragment 引用，位于其他文件；不能据此宣称全仓审计通过。没有修复其他 session 的文件，也未标记执行步骤完成。

## 2026-10-12 补充：出处核对后的三项修正

两位冷上下文 reviewer 于 2026-10-12 核对了本记录与计划的方法出处（计划 §Context (3) 持当前措辞；本节只记来源与修正，不改 9/13 的裁定）。

1. **条件式失败分解是本计划自己的构造，不是来源方法。** Provos 等 2003 §5 按对手动作触及的资源类别逐项走查，不从性质取反推导；本计划先证充分条件蕴含性质，取逆否，再对每条条件按判定输入做谓词二分（P / ¬P）。它与 attack tree（Schneier 1999，"with the goal as the root node and different ways of achieving that goal as leaf nodes"；作者自承 "there's always the chance that you forgot about an attack"）的区别在于：切分对象是判定的有限输入，不是对手的无界手段。论文须把它写成本文的方法，引 Provos §5 作结构先例，不把推导归为论文常规。
2. **归纳不变量是标准方法，补来源行 S8。** Step 3 的 Init ⇒ I、I ∧ Next ⇒ I′、I ⇒ goal 是状态机安全性质的归纳证明：Floyd 1967（inductive assertions）、Ashcroft 1975（invariance）、Lamport 1977 *Proving the Correctness of Multiprocess Programs*；TLA+ 的定义见 Lamport 的 high-level-view 页与 TLA+ 邮件列表 Merz 2019-12-19 的表述。以上均**未经 intake 入库，不能在论文中引用**；入库前论文只描述方法。
3. **CAE 不在本线使用。** 全文层面的 assurance-case 呈现（CAE、GSN）属论文整体，不属 uid 绑定这条线；本记录 S2、S5 的核对结果保留为历史，计划中 Step 2 的 "coverage warrant" 是本计划自己的要求（写明 P / ¬P 切分为何覆盖性质的否定），不再引 CAE 的 side-warrant。

同日决定：Step 3 默认附一次 TLA+/TLC 有界反例搜索（生命周期与并发子集），Alloy 6 备选；有界结果只算有界，手工归纳论证仍是主论证。

## 2026-10-12 出处核对（保留供论文使用）

冷上下文 reviewer 于 2026-10-12 联网核对了本线论证方式的出处；其问题清单已全部处理进 PLAN（同日各节），不保留。下面只留论文写相关方法、局限和替代方法时会用到的三张表和样本笔记。**表内来源均未经 intake 入库，论文引用前须入库；引文为 reviewer 从原页抄录，引用前再核一次原文。**

### 来源方各自主张什么（主张同类性）

| 来源 | 主张强度 | 残余处理 | 已核实位置 |
|---|---|---|---|
| Provos §5 | 弱于本计划：只说 "potential to contain"，粗估 2/3，明说 "there may be other ways" | 逐类说不能防的事 + 历史回溯 | 官方 HTML §5 |
| CAE side-warrant | 同类："whether the top-level claim can be deduced from the subclaims and under which circumstances the argument is valid" | 成立条件进 side-warrant | building-blocks 页 |
| TLA+ 不变式 | 同类：Init ⇒ Inv、Inv ∧ Next ⇒ Inv′，只对 Spec 成立 | Spec↔实现不在证明内 | Merz 帖、Lamport 页 |
| seL4 | 更强工具、同类主张："the C implementation adheres to its specification"；假设：*"the few lines of in-kernel assembly code are correct ... hardware behaves correctly, in-kernel hardware management (TLB and caches) is correct, and boot code is correct"*、*"assumes DMA to be off or to be trusted"*；*"There may still be unexpected features in the specification and one or more of the assumptions may not apply"*；*"the confidentiality proof makes no guarantees about the absence of covert timing channels"* | 假设清单 + spec 可能不对 + 明示未覆盖性质 | https://sel4.systems/About/FAQ.html |
| Garmr/Jenny | "all known PKRU-tampering attacks" **except signal context attacks**（已知攻击覆盖） | 显式例外 + §7.2 "Security and Completeness" 表 | ar5iv 2110.04788 |

### 顶会 security-analysis 节的样本（判断本线强弱时用）

- Provos 2003 §5：对手假设 *"an adversary can exploit a programming error in the slave process to gain complete control over it"*、*"can make any system call in the process context of the slave"*；TCB 假设 *"the system call interface to the operating system itself is secure"*（脚注：*"This assumption does not always hold."*）；逐类走查 process interference、file system、network trust、system information、monitor interface、resource exhaustion；残余 *"we cannot prevent the adversary from initiating local network connections"*、*"there may be other ways that an adversary might try to harm the system"*；历史回溯 5 个 OpenSSH 漏洞；粗估 *"two thirds of newly discovered or introduced programming errors will not result in privilege escalation"*。按对手触及的资源类别枚举，不从性质取反推导，不声称完整。
- ERIM 2019（ar5iv 1801.06822）§3.2/§3.4：*"ERIM makes no assumptions about the untrusted component (U)"*、*"The hardware, the OS kernel, and a small library ... are trusted"*；逐项绕过尝试配阻止手段；*"Side-channel and rowhammer attacks, and microachitectural leaks ... are beyond the scope"*；*"The rewrite strategy is arguably complete."*
- PKU Pitfalls 2020（USENIX Security，Connor 等）随后证明这类设计 *"vulnerable to generic attacks that bypass memory isolation"*，手段 *"use the kernel as a confused deputy"*，根因 *"a fundamentally different security model"*——"kernel 可信"不等于"kernel 对对手开放的接口无害"。本线"合法取得的特权不进出界行"正是这一教训，论文可点名。
- Garmr/Jenny（ar5iv 2110.04788）§7.2 "Security and Completeness"：all known except signal context；§3 划出 transient execution / fault injection。
- 领域常规（reviewer 推断）：威胁模型 → 机制 → 枚举攻击类逐项阻止 → 显式 out-of-scope → limitations；完整性不声称或"已知攻击全覆盖 + 例外"；无一例用派生分解或不变式。本线更强在派生分解、生命周期归纳不变量、出界行可见并核排除宽度、双轴证据与设计/实现分写、盲推导对照；更弱在实测基底（WSL2 加 Docker Desktop）、engine 未建成、手工证明曾无工具复核（已改为默认 TLC 有界检查）、`[R]` 项原无内核版本锚（已改）。

### 替代方法（同场景下谁能给更强的完整性主张）

| 方法 | 多得到什么 | 成本 | 仍相对什么 | 本线取舍 |
|---|---|---|---|---|
| TLA+/TLC | 边界内机械穷尽交错；直接回答 COV-4 与 D4 的 qmsg；fan-out 前找 I 反例 | 低 | M + 边界 | 已升为 Step 3 默认；主论证仍是手工不变式 |
| TLAPS | History completeness 机器检查 | 中高 | M | 仅学位论文想要 machine-checked 时 |
| Alloy 6 | 关系式表达 row/lease/channel 1:1 最自然；small scope hypothesis（sound but incomplete） | 低 | scope | TLC 的备选 |
| seL4 式 refinement | 关闭设计→代码差 | 人年级；engine 未建 | 仍列假设 | 不可行不必要 |
| Tamarin/ProVerif | 无密码学、对手是受内核语义约束的本地进程 | 中 | 符号模型 | 不匹配 |
| Attack tree/STRIDE | 分析员知识枚举（Schneier 1999 自承 "there's always the chance that you forgot about an attack"） | 低 | 分析员 | 作交叉检查；封存草表对照已是此角色 |
| 测试/fuzzing/探针 | 实现层证据，不给覆盖 | 低 | 基底与用例 | 保留；engine 建成后加 model-based 差分测试 |

所有方法都止于 M↔实现、A↔对手两差；seL4 的机器证明也写 *"one or more of the assumptions may not apply"*。

### 本轮核查过的来源（引用前须入库并复核原文）

| 来源 | URL | 核实内容 |
|---|---|---|
| Provos et al. 2003 官方 HTML | https://www.usenix.org/legacy/events/sec03/tech/full_papers/provos_et_al/provos_et_al_html/index.html | §5 对手假设、any system call 句、六类走查、残余句、5 个历史漏洞、two thirds、结尾句 |
| CAE Building Blocks | https://claimsargumentsevidence.org/notations/cae-building-blocks/ | 五 block 定义；side-warrant 原句；无 completeness 一词 |
| CAE Decomposition | https://claimsargumentsevidence.org/notations/helping-hand/decomposition/ | 属性/组成/组合规则；无 side-warrant、无 completeness |
| Lamport high-level-view | https://lamport.azurewebsites.net/tla/high-level-view.html | initial/next-state/invariance 原句；不讲证明 |
| TLA+ 列表（Merz 2019-12-19） | https://discuss.tlapl.us/msg03315.html | Init ⇒ Inv、Inv ∧ [Next]_vars ⇒ Inv′ |
| seL4 FAQ | https://sel4.systems/About/FAQ.html | 证明主张、假设清单、unexpected features、timing channel |
| ERIM ar5iv | https://ar5iv.labs.arxiv.org/html/1801.06822 | §3.2/§3.4、out-of-scope、arguably complete |
| PKU Pitfalls | https://www.usenix.org/conference/usenixsecurity20/presentation/connor | generic attacks、confused deputy、different security model |
| Garmr/Jenny ar5iv | https://ar5iv.labs.arxiv.org/html/2110.04788 | §3、§4.2、§7.2、except signal context |
| Schneier Attack Trees | https://www.schneier.com/academic/archives/1999/12/attack_trees.html | 定义、AND/OR、forgot about an attack |
| Alloy small scope（二手） | Jackson ZB2003 幻灯、Alloy 论坛检索 | small counterexamples、sound but incomplete |
| Lamport 1977 线索（二手） | microsoft.com 论文页、lamport.org/pubs 检索 | 归功 Ashcroft、推广 Floyd |

未能打开：sel4.systems 的 Info/FAQ/proof.html（404，改用 About/FAQ）；Lamport inductive-invariant.pdf；Bloomfield & Netkachova "Building Blocks for Assurance Cases" PDF（decomposition 的分区完整条件是否有明文未核实）；Tamarin 主页只有标语；MoD GSN 页、SEI Arguing Security 日期、Capsicum 未重核。
