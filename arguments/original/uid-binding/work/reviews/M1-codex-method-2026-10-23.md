# M1 — uid-binding 方法的 Codex 审核（2026-10-23）

- **起因**：用户 2026-10-23 在 prove 1.1 计划审核时要求顺带审这条线的方法。
- **审核者**：Codex，经 codex plugin 由 1.1 的执行者派发；只读；没有读 no-bypass/。
- **读过的范围**：PLAN.md、两份存档（执行、COV）、security-argument.md、spine 01/02/03（03 略读）、抽查 R-G2-05、R-G2-11、R-GX-04。
- **审核范围**：方法与其应用能否支撑"相对于 M 完整"与各路线处置；不重推 kernel 事实。
- **结论**：does not hold。审核者说明：否定的是现有总结（36·0·0·2、0 open）的充分依据，不是断言绑定被攻破。

## 五条意见（要点）

| # | 位置 | 意见 | 严重度 |
|---|---|---|---|
| 1 | R-G2-11 §3–5；step4-brief §1 | 余项要靠"帧读取器没有内存错误"这一性质清空，实际证据是一小时 ASan/UBSan fuzz；"这批输入没暴露错误"推不出"余项为空"，处置仍记 supported | blocking |
| 2 | R-G2-05 §3、§5–6；01 §8 | 停止阅读的依据是按目录或协议分类（其余 30 个协议族的 queue writer、其余 sockfd_lookup 调用方），正文却用"没有其他 producer"一类全称措辞；缺每个截断点的影响契约 | should fix |
| 3 | R-GX-04 §4–6；第五次修订；security-argument | 未建的 supervisor 在第五次修订后改列部署前提，R-GX-04 由 conditional 转 supported；"0 conditional"因此分不清"防御已兑现"和"防御外置为假设" | should fix |
| 4 | PLAN 规则 4；执行存档 §Versioning；reconcile §5 | 重跑规则以引用变更 ID 为准；实际执行做过语义重审，但没有成为强制规则；新增入口或写入点可能不改旧 ID 却推翻"唯一读取路径"一类断言 | should fix |
| 5 | 02 §0–4.3；security-argument §Preface | 条件分解支持的是"坏历史分类的总覆盖"，不是"38 种机制已全部导出"；部分路线只属于 consumer 一侧（P_carry），最终表却只用 accept 时的性质介绍全部 38 条 | should fix |

审核者保留的优点：没有把有界 TLC 当无界证明；记录了抽象限制与模型—实现对应风险。

## 处理状态

does not hold，报告用户（2026-10-23），未改动这条线的任何文件。
