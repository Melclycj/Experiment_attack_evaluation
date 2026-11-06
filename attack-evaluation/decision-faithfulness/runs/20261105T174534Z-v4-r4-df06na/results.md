# 20261105T174534Z-v4-r4-df06na 结果



| 子目标 | 配置 | 预期 | 实际 | 观察到的机制 | 与预期不符 | 配对 | 无效原因 | 观察文件 |
|---|---|---|---|---|---|---|---|---|
| DF-06/no-answer | engine | 预期机制挡住 | 预期机制挡住 | reason=timeout withdrawn_stage=['asking'] window_withdrawals=1 |  | undefended succeeded |  | obs-DF-06-no-answer-engine.json |
| DF-06/no-answer | undefended | 成功 | 成功 |  |  |  |  | obs-DF-06-no-answer-undefended.json |

## 正对照

| 编号 | 结果 | 说明 |
|---|---|---|
| PC-ALLOW | passed |  |
| PC-FALLBACK | passed |  |
| PC-ONCE | passed |  |

预期机制的位置是 a9eff999 的源码位置（tests.md 第 3 节），不是运行时命中的位置。R=1 的上界不外推。
