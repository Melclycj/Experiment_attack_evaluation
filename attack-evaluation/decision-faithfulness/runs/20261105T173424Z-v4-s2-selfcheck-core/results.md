# 20261105T173424Z-v4-s2-selfcheck-core 结果

试跑，不算数。

| 子目标 | 配置 | 预期 | 实际 | 观察到的机制 | 与预期不符 | 配对 | 无效原因 | 观察文件 |
|---|---|---|---|---|---|---|---|---|
| DF-12/entry-del | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-12-entry-del-engine.json |
| DF-12/entry-del | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-entry-del-undefended.json |
| DF-12/entry-narrow-account | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-12-entry-narrow-account-engine.json |
| DF-12/entry-narrow-account | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-entry-narrow-account-undefended.json |
| DF-12/entry-deny | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-12-entry-deny-engine.json |
| DF-12/entry-deny | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-entry-deny-undefended.json |
| DF-12/cred-del | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-12-cred-del-engine.json |
| DF-12/cred-del | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-cred-del-undefended.json |
| DF-12/cred-put | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-12-cred-put-engine.json |
| DF-12/cred-put | undefended | 成功 | 成功 |  |  |  |  | obs-DF-12-cred-put-undefended.json |
| DF-17/pdp-narrow | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-17-pdp-narrow-engine.json |
| DF-17/pdp-narrow | undefended | 成功 | 成功 |  |  |  |  | obs-DF-17-pdp-narrow-undefended.json |
| DF-17/pdp-deny | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-17-pdp-deny-engine.json |
| DF-17/pdp-deny | undefended | 成功 | 成功 |  |  |  |  | obs-DF-17-pdp-deny-undefended.json |
| DF-07/once-twice | engine | 转人工 | 成功 |  |  |  |  | obs-DF-07-once-twice-engine.json |
| DF-07/once-twice | undefended | 成功 | 成功 |  |  |  |  | obs-DF-07-once-twice-undefended.json |
| DF-18/covered | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-18-covered-engine.json |
| DF-18/covered | undefended | 不设防下没有对应物 | 不设防下没有对应物 |  |  |  | 没有拒绝原因词：不设防下这个攻击没有对应物，按 METHOD 规则 3 写不成功的原因，不运行 |  |

## 正对照

| 编号 | 结果 | 说明 |
|---|---|---|

预期机制的位置是 a9eff999 的源码位置（tests.md 第 3 节），不是运行时命中的位置。R=1 的上界不外推。
