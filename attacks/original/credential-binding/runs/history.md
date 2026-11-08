这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。

# 运行历史（只汇总 COMPLETE.json 完整的运行）

| 攻击 | v4 | 最近试跑（不算数） |
|---|---|---|
| CB-01 | engine：预期机制挡住（20261105T175540Z-v4-cb-b1）<br>undefended：成功（20261105T175540Z-v4-cb-b1） | — |
| CB-02 | engine：预期机制挡住（20261105T175540Z-v4-cb-b1）<br>undefended：成功（20261105T175540Z-v4-cb-b1） | — |
| CB-03 | engine：预期机制挡住（20261105T175540Z-v4-cb-b1）<br>undefended：成功（20261105T175540Z-v4-cb-b1） | — |
| CB-04 | engine：预期机制挡住（20261105T175540Z-v4-cb-b1）<br>undefended：成功（20261105T175540Z-v4-cb-b1） | — |
| CB-05 | engine：预期机制挡住（20261105T175540Z-v4-cb-b1）<br>undefended：成功（20261105T175540Z-v4-cb-b1） | — |
| CB-06 | engine：预期机制挡住（20261105T180229Z-v4-cb-b2）<br>undefended：成功（20261105T180229Z-v4-cb-b2） | — |
| CB-07 | engine：预期机制挡住（20261105T230126Z-v4-cb-b4）<br>undefended：成功（20261105T230126Z-v4-cb-b4） | — |
| CB-08 | engine：预期机制挡住（20261105T230126Z-v4-cb-b4）<br>undefended：成功（20261105T230126Z-v4-cb-b4） | — |
| CB-09 | engine：预期机制挡住（20261105T231022Z-v4-cb-b5）<br>undefended：成功（20261105T231022Z-v4-cb-b5） | — |
| CB-10 | engine：预期机制挡住（20261105T234810Z-v4-cb-b7）<br>undefended：成功（20261105T234810Z-v4-cb-b7） | — |
| CB-11 | engine：预期机制挡住（20261105T233917Z-v4-cb-b6）<br>undefended：成功（20261105T233917Z-v4-cb-b6） | — |
| CB-12 | engine：预期机制挡住（20261105T180229Z-v4-cb-b2）<br>undefended：成功（20261105T180229Z-v4-cb-b2） | — |
| CB-14 | engine：预期机制挡住（20261105T235838Z-v4-cb-b8）<br>undefended：成功（20261105T235838Z-v4-cb-b8） | engine：成功（20261105T235449Z-v4-cb14-selfchk）；**挡住→成功**；判决不符；机制不符；预期机制未观察到 |
| PC-CREDENTIAL | engine：成功（20261105T235838Z-v4-cb-b8） | engine：成功（20261105T235449Z-v4-cb14-selfchk） |
| PC-DIALOGUE | engine：成功（20261105T235838Z-v4-cb-b8） | engine：成功（20261105T235449Z-v4-cb14-selfchk） |
| PC-FILE | engine：成功（20261105T235838Z-v4-cb-b8） | engine：成功（20261105T235449Z-v4-cb14-selfchk） |
| PC-PROXY | engine：成功（20261105T235838Z-v4-cb-b8） | engine：成功（20261105T235449Z-v4-cb14-selfchk） |

## 批次状态（包括无结果的失败运行）

- 20261105T175221Z-v4-cb10-selfchk：完整结束
- 20261105T175540Z-v4-cb-b1：完整结束
- 20261105T180229Z-v4-cb-b2：完整结束
- 20261105T180939Z-v4-cb-b3：完整结束
- 20261105T230126Z-v4-cb-b4：完整结束
- 20261105T231022Z-v4-cb-b5：完整结束
- 20261105T233917Z-v4-cb-b6：完整结束
- 20261105T234810Z-v4-cb-b7：完整结束
- 20261105T235449Z-v4-cb14-selfchk：完整结束
- 20261105T235838Z-v4-cb-b8：完整结束

同码比较包含 engine、harness、规格与脚本；每次运行的新诱饵路径与随机串不拆散比较。不将未测、试跑或清理失败当作正式通过。
