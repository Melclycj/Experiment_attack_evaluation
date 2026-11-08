---
title: prove 2.1 — uid 绑定：论证方法说明
created: 2026-10-26
---

# 2.1 uid 绑定 — 论证方法说明

## 0 本文件

- **用途。** 说明本线的论证怎样组织、靠什么判官、方法学自哪些论文，供人读，也供写论文时解释方法。本线已完成；本文件只汇总、指路，不改任何结论。规则与过程在 PLAN 及其归档，
  结论表在 [security-argument.md](security-argument.md)，两者与本文件不一致时以它们为准。
- **事后整理。** 本文件写于 2026-10-26，是本线完成后整理的说明；本线的记录按 2026-10-24 之前的规则原文理解（PLAN 的 Rules that bind any re-run 一节）。

## 1 形状与要证什么

- **形状：对应。** 性质是"engine 接收时读到的标签，指向真正执行 `sendmsg` 的那个任务所属的 execution"：每个标为 X 的接收事件，
  之前都有一个属于 X 的任务的发送事件，并且发送时该任务仍持有这次分配的 uid。全文在
  [02 §0](work/spine/02-conditions-and-decomposition.md)。它有两部分：接收时成立的部分，与下游消费者沿用标签的部分（02 §3）。
- **形状的名字。** 这一形式与协议验证里的对应断言（Woo 与 Lam）和认证层次里的 agreement（Lowe）相同。本线只借用名字与形式，不借
  用协议模型（出处见 §3，原文未读）。

## 2 论证怎样组织

- **覆盖论证：自顶向下的条件分解。** 写出性质的充分条件 C-01…C-08（判定输入上的谓词，02 §2），证明它们合起来推出性质（02 §3），
  取逆否；再按"首个失败的条件"把违反性质的历史分成互不相交的格，每格末尾留一个余项，机械检查每段历史恰好落到一条路线
  （02 §4，覆盖理由在 02 §4.3）。这一分解是本线自己的做法，不是从来源方法搬来的（[method-review](method-review.md) 2026-10-12 补充
  第 1 条）。
- **不变量。** [03](work/spine/03-invariant.md)：接收字节部分与状态部分，加一张守卫清单；初态（03 §3）、每组的保持论证
  （work/groups）、蕴含（03 §4）。保持是手写论证。
- **判官。**
  - engine 原型的检查运行：记录在 ExperimentLab/engine/runs，由 ExperimentLab/engine/validation.md 逐条对到 engine-requirements
    的各条"必须"（sandbox 回归、集成运行、fuzz 等）。2026-10-19 起，原型实现并检查过的防御据此记为 supported。
  - TLC：只跑了有界的生命周期子集。03 §5 的 4 次运行（2026-10-14），与 [05-concurrency](work/05-concurrency.md) §5 的一批运行
    （2026-10-14/15）。它查的是子集内所有可达状态上不变量成立，不查"每一步保持"。
  - 没有反向测试。
- **自检。**
  - TLC 负对照：去掉成员资格检查那一半后，4 步之内违反 uid 独占、12 步之内出现错误归属（03 §5.4 第 2a、2b 次运行），说明模型不是空的。
  - 盲推导对照：主线程事先写好的草表在落盘前一直封存，落盘时才与本线的表逐条比对（work/convergence/reconcile.md §7）。
- **结论依赖。** 01、02、03 与证据登记表的版本（work/spine/VERSIONS.md）；engine 原型的提交与运行记录；TLC 模型与配置。
- **强度。** 结构化安全论证，相对于有版本的模型，不是机器检查的证明；38 条路线，35 条 supported under stated premises、1 条
  conditional on unbuilt requirements、0 条 open、2 条 declared out of scope（security-argument.md）。conditional 的一条是 C 帧读取器
  的内存安全，交给 2.2 用有界模型检查证明（2.2 的方法说明），证成后按 METHOD 规则 4 重跑这一条。

## 3 方法学自哪些论文

逐项核实的记录在 [method-review.md](method-review.md)（2026-09-13 复核与 2026-10-12 出处核对）。下表只列名字、学什么与为什么选。

| 来源 | 会议 | 学什么 | 为什么选它 |
|---|---|---|---|
| Provos、Friedl、Honeyman，Preventing Privilege Escalation（OpenSSH 权限分离） | USENIX Security 2003 | §5 的安全分析结构：先声明对手能力（被攻陷的子进程可做任意系统调用），按资源类别逐项走查防御，写明防不住的事，回溯历史漏洞 | 与本线同一类系统（特权监控进程 + 不可信子进程 + 私有 socketpair），是结构上最直接的先例；它不从性质推导、也不声称完整，本线在这两点上更强 |
| ERIM | USENIX Security 2019 | §3 逐项绕过尝试配阻止手段，侧信道等写成范围外 | 判断本线强弱时用的顶会安全分析样本 |
| PKU Pitfalls（Connor 等） | USENIX Security 2020 | 同类设计被"把 kernel 当 confused deputy"的通用攻击绕过 | 反面教训：kernel 可信不等于 kernel 对对手开放的接口无害；本线"合法取得的特权不进出界行"由此而来 |
| Garmr/Jenny（ar5iv 2110.04788） | 预印本页面，会议未在本线核实 | "所有已知攻击，信号上下文除外"的显式例外写法 | 结论措辞的样本 |
| Lamport 的 TLA+ 说明页；Merz 2019 的 TLA+ 邮件列表帖 | 网页，不是论文 | 初态 ⇒ 不变量、不变量 ∧ 下一步 ⇒ 不变量′ 的归纳形式 | 不变量三步的定义来源；Floyd 1967、Ashcroft 1975、Lamport 1977 的原文未读 |
| Woo、Lam，A Semantic Model for Authentication Protocols | IEEE S&P 1993（DOI 10.1109/risp.1993.287633） | 对应断言：每个结束事件之前有匹配的开始事件 | 给本线的性质形状一个通用名字；只核书目 |
| Lowe，A Hierarchy of Authentication Specifications | CSFW 1997（DOI 10.1109/csfw.1997.596782） | 认证层次：存活、新近存活、弱 agreement、agreement | 同上；"发送时仍持有 uid"接近带新近性的那几级；只核书目 |

## 4 怎样选的与局限

- **怎样选的。** 前四项是 2026-10-12 冷上下文 reviewer 联网核对的顶会安全分析节样本，用来判断本线的论证结构与强弱；归纳不变量
  的来源用来定义不变量三步；最后两项在 2026-10-25 的方法调研里补核书目，只为形状命名。
- **局限。** 这些来源都没有进 Paper/（OpenSSH 权限分离除外，已有笔记）；写进论文之前要读原文、建笔记（research 规则 4）。
  seL4 FAQ 与攻击树作为参照与交叉检查，不是本线方法的来源（method-review 2026-10-12 的替代方法表）。
