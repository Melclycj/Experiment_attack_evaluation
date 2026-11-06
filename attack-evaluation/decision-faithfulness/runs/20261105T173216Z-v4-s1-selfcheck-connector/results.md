# 20261105T173216Z-v4-s1-selfcheck-connector 结果

试跑，不算数。

| 子目标 | 配置 | 预期 | 实际 | 观察到的机制 | 与预期不符 | 配对 | 无效原因 | 观察文件 |
|---|---|---|---|---|---|---|---|---|
| DF-05/302 | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-05-302-engine.json |
| DF-05/302 | undefended | 成功 | 成功 |  |  |  |  | obs-DF-05-302-undefended.json |
| DF-05/307 | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-05-307-engine.json |
| DF-05/307 | undefended | 成功 | 成功 |  |  |  |  | obs-DF-05-307-undefended.json |
| DF-05/308 | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-05-308-engine.json |
| DF-05/308 | undefended | 成功 | 成功 |  |  |  |  | obs-DF-05-308-undefended.json |
| DF-01/close-after-read | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-01-close-after-read-engine.json |
| DF-01/close-after-read | undefended | 成功 | 成功 |  |  |  |  | obs-DF-01-close-after-read-undefended.json |
| DF-09/rebind | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-09-rebind-engine.json |
| DF-09/rebind | undefended | 成功 | 成功 |  |  |  |  | obs-DF-09-rebind-undefended.json |
| DF-19/word-mismatch | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-19-word-mismatch-engine.json |
| DF-19/word-mismatch | undefended | 成功 | 成功 |  |  |  |  | obs-DF-19-word-mismatch-undefended.json |
| DF-19/word-missing | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-19-word-missing-engine.json |
| DF-19/word-missing | undefended | 成功 | 成功 |  |  |  |  | obs-DF-19-word-missing-undefended.json |
| DF-10/account-then-none | engine | 预期机制挡住 | 成功 |  |  |  |  | obs-DF-10-account-then-none-engine.json |
| DF-10/account-then-none | undefended | 成功 | 成功 |  |  |  |  | obs-DF-10-account-then-none-undefended.json |

## 正对照

| 编号 | 结果 | 说明 |
|---|---|---|

预期机制的位置是 a9eff999 的源码位置（tests.md 第 3 节），不是运行时命中的位置。R=1 的上界不外推。
