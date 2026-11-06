# 20261105T174059Z-v4-r2-df05-df10 结果



| 子目标 | 配置 | 预期 | 实际 | 观察到的机制 | 与预期不符 | 配对 | 无效原因 | 观察文件 |
|---|---|---|---|---|---|---|---|---|
| DF-05/302 | engine | 预期机制挡住 | 预期机制挡住 | attack=remote 302; follow: reason=not_authorized decided=['address_not_named'] closed_at_validation=False decoy_conns=0 |  | undefended succeeded |  | obs-DF-05-302-engine.json |
| DF-05/302 | undefended | 成功 | 成功 |  |  |  |  | obs-DF-05-302-undefended.json |
| DF-05/307 | engine | 预期机制挡住 | 预期机制挡住 | attack=remote 307; follow: reason=not_authorized decided=['address_not_named'] closed_at_validation=False decoy_conns=0 |  | undefended succeeded |  | obs-DF-05-307-engine.json |
| DF-05/307 | undefended | 成功 | 成功 |  |  |  |  | obs-DF-05-307-undefended.json |
| DF-05/308 | engine | 预期机制挡住 | 预期机制挡住 | attack=remote 308; follow: reason=not_authorized decided=['address_not_named'] closed_at_validation=False decoy_conns=0 |  | undefended succeeded |  | obs-DF-05-308-engine.json |
| DF-05/308 | undefended | 成功 | 成功 |  |  |  |  | obs-DF-05-308-undefended.json |
| DF-06/deny | engine | 预期机制挡住 | 预期机制挡住 | reason=user_denied deny_answers=1 |  | undefended succeeded |  | obs-DF-06-deny-engine.json |
| DF-06/deny | undefended | 成功 | 成功 |  |  |  |  | obs-DF-06-deny-undefended.json |
| DF-07/once-twice | engine | 转人工 | 转人工 | questions=2 withdrawn=['asking'] |  | undefended succeeded |  | obs-DF-07-once-twice-engine.json |
| DF-07/once-twice | undefended | 成功 | 成功 |  |  |  |  | obs-DF-07-once-twice-undefended.json |
| DF-08/withdraw-swap | engine | 预期机制挡住 | 预期机制挡住 | answer_to_A=unknown_question b_questions=1 |  | undefended succeeded |  | obs-DF-08-withdraw-swap-engine.json |
| DF-08/withdraw-swap | undefended | 成功 | 成功 |  |  |  |  | obs-DF-08-withdraw-swap-undefended.json |
| DF-09/rebind | engine | 预期机制挡住 | 预期机制挡住 | upstream_arrivals=1 A_queries=1 |  | undefended succeeded |  | obs-DF-09-rebind-engine.json |
| DF-09/rebind | undefended | 成功 | 成功 |  |  |  |  | obs-DF-09-rebind-undefended.json |
| DF-10/account-then-none | engine | 预期机制挡住 | 预期机制挡住 | first=['placed'] second=['none'] |  | undefended succeeded |  | obs-DF-10-account-then-none-engine.json |
| DF-10/account-then-none | undefended | 成功 | 成功 |  |  |  |  | obs-DF-10-account-then-none-undefended.json |

## 正对照

| 编号 | 结果 | 说明 |
|---|---|---|
| PC-ALLOW | passed |  |
| PC-FALLBACK | passed |  |
| PC-ONCE | passed |  |
| PC-CELL | passed |  |
| PC-CRED | passed |  |

预期机制的位置是 a9eff999 的源码位置（tests.md 第 3 节），不是运行时命中的位置。R=1 的上界不外推。
