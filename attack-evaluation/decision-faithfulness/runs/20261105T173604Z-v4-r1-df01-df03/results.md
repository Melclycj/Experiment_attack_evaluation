# 20261105T173604Z-v4-r1-df01-df03 结果



| 子目标 | 配置 | 预期 | 实际 | 观察到的机制 | 与预期不符 | 配对 | 无效原因 | 观察文件 |
|---|---|---|---|---|---|---|---|---|
| DF-01/close-after-read | engine | 预期机制挡住 | 预期机制挡住 | category=unknown reason=result_unknown upstream_failure=True |  | undefended succeeded |  | obs-DF-01-close-after-read-engine.json |
| DF-01/close-after-read | undefended | 成功 | 成功 |  |  |  |  | obs-DF-01-close-after-read-undefended.json |
| DF-03/post-unlisted | engine | 预期机制挡住 | 预期机制挡住 | reason=not_authorized decided=['not_covered'] |  | undefended succeeded |  | obs-DF-03-post-unlisted-engine.json |
| DF-03/post-unlisted | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-post-unlisted-undefended.json |
| DF-03/method-uncovered | engine | 预期机制挡住 | 预期机制挡住 | reason=not_authorized decided=['not_covered'] |  | undefended succeeded |  | obs-DF-03-method-uncovered-engine.json |
| DF-03/method-uncovered | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-method-uncovered-undefended.json |
| DF-03/path-uncovered | engine | 预期机制挡住 | 预期机制挡住 | reason=not_authorized decided=['not_covered'] |  | undefended succeeded |  | obs-DF-03-path-uncovered-engine.json |
| DF-03/path-uncovered | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-path-uncovered-undefended.json |
| DF-03/recorded-deny | engine | 预期机制挡住 | 预期机制挡住 | reason=recorded_deny decided=['recorded_deny'] |  | undefended succeeded |  | obs-DF-03-recorded-deny-engine.json |
| DF-03/recorded-deny | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-recorded-deny-undefended.json |
| DF-03/ip-loopback | engine | 预期机制挡住 | 预期机制挡住 | reason=clause admitted=False connector_closed=True decoy_conns=0 |  | undefended succeeded |  | obs-DF-03-ip-loopback-engine.json |
| DF-03/ip-loopback | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-ip-loopback-undefended.json |
| DF-03/ip-private | engine | 预期机制挡住 | 预期机制挡住 | reason=not_authorized decided=['address_not_named'] closed_at_validation=False decoy_conns=0 |  | undefended succeeded |  | obs-DF-03-ip-private-engine.json |
| DF-03/ip-private | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-ip-private-undefended.json |
| DF-03/ip-linklocal | engine | 预期机制挡住 | 预期机制挡住 | reason=clause admitted=False connector_closed=True decoy_conns=0 |  | undefended succeeded |  | obs-DF-03-ip-linklocal-engine.json |
| DF-03/ip-linklocal | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-ip-linklocal-undefended.json |
| DF-03/ip-interface | engine | 预期机制挡住 | 预期机制挡住 | reason=clause admitted=False connector_closed=True decoy_conns=0 |  | undefended succeeded |  | obs-DF-03-ip-interface-engine.json |
| DF-03/ip-interface | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-ip-interface-undefended.json |
| DF-03/name-private | engine | 预期机制挡住 | 预期机制挡住 | reason=not_authorized allow_recorded=True connector_refused_not_named=True decoy_conns=0 |  | undefended succeeded |  | obs-DF-03-name-private-engine.json |
| DF-03/name-private | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-name-private-undefended.json |
| DF-03/other-port | engine | 预期机制挡住 | 预期机制挡住 | reason=not_authorized decided=['not_covered'] |  | undefended succeeded |  | obs-DF-03-other-port-engine.json |
| DF-03/other-port | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-other-port-undefended.json |
| DF-03/other-workspace | engine | 预期机制挡住 | 预期机制挡住 | reason=not_authorized decided=['not_covered'] |  | undefended succeeded |  | obs-DF-03-other-workspace-engine.json |
| DF-03/other-workspace | undefended | 成功 | 成功 |  |  |  |  | obs-DF-03-other-workspace-undefended.json |

## 正对照

| 编号 | 结果 | 说明 |
|---|---|---|
| PC-ALLOW | passed |  |
| PC-FALLBACK | passed |  |

预期机制的位置是 a9eff999 的源码位置（tests.md 第 3 节），不是运行时命中的位置。R=1 的上界不外推。
