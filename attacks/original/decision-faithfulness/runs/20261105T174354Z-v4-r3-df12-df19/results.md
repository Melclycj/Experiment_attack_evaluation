# 20261105T174354Z-v4-r3-df12-df19 结果



| 子目标 | 配置 | 预期 | 实际 | 观察到的机制 | 与预期不符 | 配对 | 无效原因 | 观察文件 |
|---|---|---|---|---|---|---|---|---|
| DF-12/entry-del | engine | 预期机制挡住 | 预期机制挡住 | ended=False closed=True connector_matched=1 |  | undefended succeeded |  | obs-DF-12-entry-del-engine.json |
| DF-12/entry-del | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-entry-del-undefended.json |
| DF-12/entry-narrow-account | engine | 预期机制挡住 | 预期机制挡住 | ended=False closed=True connector_matched=1 |  | undefended succeeded |  | obs-DF-12-entry-narrow-account-engine.json |
| DF-12/entry-narrow-account | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-entry-narrow-account-undefended.json |
| DF-12/entry-deny | engine | 预期机制挡住 | 预期机制挡住 | ended=False closed=True connector_matched=1 |  | undefended succeeded |  | obs-DF-12-entry-deny-engine.json |
| DF-12/entry-deny | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-entry-deny-undefended.json |
| DF-12/cred-del | engine | 预期机制挡住 | 预期机制挡住 | ended=False closed=True connector_matched=1 |  | undefended succeeded |  | obs-DF-12-cred-del-engine.json |
| DF-12/cred-del | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-cred-del-undefended.json |
| DF-12/cred-put | engine | 预期机制挡住 | 预期机制挡住 | ended=False closed=True connector_matched=1 |  | undefended succeeded |  | obs-DF-12-cred-put-engine.json |
| DF-12/cred-put | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-cred-put-undefended.json |
| DF-16/control-verbs | engine | 预期机制挡住 | 预期机制挡住 | verb replies={'entry_put': 'unsupported_kind', 'answer': 'unsupported_kind', 'cred_put': 'unsupported_kind', 'row_start': 'unsupported_kind'} |  | no counterpart (METHOD rule 3) |  | obs-DF-16-control-verbs-engine.json |
| DF-16/control-verbs | undefended | 不设防下没有对应物 | 不设防下没有对应物 |  |  |  | 没有控制口与表：不设防下这个攻击没有对应物，按 METHOD 规则 3 写不成功的原因，不运行 |  |
| DF-17/ask-then-narrow | engine | 预期机制挡住 | 预期机制挡住 | reason=policy_changed superseded=1 decided=['answer_void'] |  | undefended succeeded |  | obs-DF-17-ask-then-narrow-engine.json |
| DF-17/ask-then-narrow | undefended | 成功 | 成功 |  |  |  |  | obs-DF-17-ask-then-narrow-undefended.json |
| DF-17/pdp-narrow | engine | 预期机制挡住 | 预期机制挡住 | reason=policy_changed decided=['recheck_failed'] |  | undefended succeeded |  | obs-DF-17-pdp-narrow-engine.json |
| DF-17/pdp-narrow | undefended | 成功 | 成功 |  |  |  |  | obs-DF-17-pdp-narrow-undefended.json |
| DF-17/pdp-deny | engine | 预期机制挡住 | 预期机制挡住 | reason=policy_changed decided=['recheck_failed'] |  | undefended succeeded |  | obs-DF-17-pdp-deny-engine.json |
| DF-17/pdp-deny | undefended | 成功 | 成功 |  |  |  |  | obs-DF-17-pdp-deny-undefended.json |
| DF-18/uncovered | engine | 预期机制挡住 | 预期机制挡住 | both not_authorized |  | no counterpart (METHOD rule 3) |  | obs-DF-18-uncovered-engine.json |
| DF-18/uncovered | undefended | 不设防下没有对应物 | 不设防下没有对应物 |  |  |  | 没有拒绝原因词：不设防下这个攻击没有对应物，按 METHOD 规则 3 写不成功的原因，不运行 |  |
| DF-18/covered | engine | 预期机制挡住 | 预期机制挡住 | both released to the upstream |  | no counterpart (METHOD rule 3) |  | obs-DF-18-covered-engine.json |
| DF-18/covered | undefended | 不设防下没有对应物 | 不设防下没有对应物 |  |  |  | 没有拒绝原因词：不设防下这个攻击没有对应物，按 METHOD 规则 3 写不成功的原因，不运行 |  |
| DF-19/word-mismatch | engine | 预期机制挡住 | 预期机制挡住 | header generated whole from the record |  | undefended succeeded |  | obs-DF-19-word-mismatch-engine.json |
| DF-19/word-mismatch | undefended | 成功 | 成功 |  |  |  |  | obs-DF-19-word-mismatch-undefended.json |
| DF-19/word-missing | engine | 预期机制挡住 | 预期机制挡住 | header generated whole from the record |  | undefended succeeded |  | obs-DF-19-word-missing-engine.json |
| DF-19/word-missing | undefended | 成功 | 成功 |  |  |  |  | obs-DF-19-word-missing-undefended.json |

## 正对照

| 编号 | 结果 | 说明 |
|---|---|---|
| PC-ALLOW | passed |  |
| PC-FALLBACK | passed |  |
| PC-STREAM | passed |  |
| PC-CRED | passed |  |
| PC-RECHECK | passed |  |
| PC-ONCE | passed |  |

预期机制的位置是 a9eff999 的源码位置（tests.md 第 3 节），不是运行时命中的位置。R=1 的上界不外推。
