这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。

# 运行历史（只汇总 COMPLETE.json 完整的运行）

| 攻击 | v4 |
|---|---|
| BD-01 | engine：成功（20261106T003949Z-v4-nb-boundary） |
| BD-02 | engine：成功（20261106T003949Z-v4-nb-boundary） |
| NB-01 | engine：预期机制挡住（20261106T000734Z-v4-nb-files-a）<br>undefended：成功（20261106T000734Z-v4-nb-files-a） |
| NB-02 | engine：预期机制挡住（20261106T000734Z-v4-nb-files-a）<br>undefended：成功（20261106T000734Z-v4-nb-files-a） |
| NB-03 | engine：预期机制挡住（20261106T000734Z-v4-nb-files-a）<br>undefended：成功（20261106T000734Z-v4-nb-files-a） |
| NB-04 | engine：预期机制挡住（20261106T000734Z-v4-nb-files-a）<br>undefended：成功（20261106T000734Z-v4-nb-files-a） |
| NB-05 | engine：预期机制挡住（20261106T000734Z-v4-nb-files-a）<br>undefended：成功（20261106T000734Z-v4-nb-files-a） |
| NB-06 | engine：预期机制挡住（20261106T000734Z-v4-nb-files-a）<br>undefended：成功（20261106T000734Z-v4-nb-files-a） |
| NB-07 | engine：预期机制挡住（20261106T001019Z-v4-nb-files-b）<br>undefended：成功（20261106T001019Z-v4-nb-files-b） |
| NB-08 | engine：预期机制挡住（20261106T001019Z-v4-nb-files-b）<br>undefended：成功（20261106T001019Z-v4-nb-files-b） |
| NB-09 | engine：预期机制挡住（20261106T001019Z-v4-nb-files-b）<br>undefended：成功（20261106T001019Z-v4-nb-files-b） |
| NB-10 | engine：预期机制挡住（20261106T001019Z-v4-nb-files-b）<br>undefended：成功（20261106T001019Z-v4-nb-files-b） |
| NB-11 | engine：预期机制挡住（20261106T001019Z-v4-nb-files-b）<br>undefended：成功（20261106T001019Z-v4-nb-files-b） |
| NB-12 | engine：预期机制挡住（20261106T001324Z-v4-nb-files-c）<br>undefended：成功（20261106T001324Z-v4-nb-files-c） |
| NB-13 | engine：预期机制挡住（20261106T001324Z-v4-nb-files-c）<br>undefended：成功（20261106T001324Z-v4-nb-files-c） |
| NB-14 | engine：预期机制挡住（20261106T001324Z-v4-nb-files-c）<br>undefended：成功（20261106T001324Z-v4-nb-files-c） |
| NB-15 | engine：预期机制挡住（20261106T001850Z-v4-nb-files-d）<br>undefended：成功（20261106T001850Z-v4-nb-files-d） |
| NB-16 | engine：预期机制挡住（20261106T002242Z-v4-nb-connect）<br>undefended：成功（20261106T002242Z-v4-nb-connect） |
| NB-17 | engine：预期机制挡住（20261106T002242Z-v4-nb-connect）<br>undefended：成功（20261106T002242Z-v4-nb-connect） |
| NB-18 | engine：预期机制挡住（20261106T002242Z-v4-nb-connect）<br>undefended：成功（20261106T002242Z-v4-nb-connect） |
| NB-19 | engine：预期机制挡住（20261106T002242Z-v4-nb-connect）；预期机制未观察到<br>undefended：成功（20261106T002242Z-v4-nb-connect） |
| NB-20 | engine：预期机制挡住（20261106T003331Z-v4-nb-engine-a）<br>undefended：成功（20261106T003331Z-v4-nb-engine-a） |
| NB-21 | engine：预期机制挡住（20261106T003331Z-v4-nb-engine-a）<br>undefended：成功（20261106T003331Z-v4-nb-engine-a） |
| NB-22 | engine：预期机制挡住（20261106T003617Z-v4-nb-engine-b）<br>undefended：成功（20261106T003617Z-v4-nb-engine-b） |
| NB-23 | engine：预期机制挡住（20261106T003617Z-v4-nb-engine-b）<br>undefended：成功（20261106T003617Z-v4-nb-engine-b） |
| NB-24 | engine：预期机制挡住（20261106T003617Z-v4-nb-engine-b）<br>undefended：成功（20261106T003617Z-v4-nb-engine-b） |
| NB-25 | engine：预期机制挡住（20261106T002242Z-v4-nb-connect）<br>undefended：成功（20261106T002242Z-v4-nb-connect） |
| NB-26 | engine：预期机制挡住（20261106T003617Z-v4-nb-engine-b）<br>undefended：成功（20261106T003617Z-v4-nb-engine-b） |
| NB-27 | engine：预期机制挡住（20261106T002242Z-v4-nb-connect）；预期机制未观察到<br>undefended：成功（20261106T002242Z-v4-nb-connect） |
| NB-28 | engine：预期机制挡住（20261106T001850Z-v4-nb-files-d）<br>undefended：成功（20261106T001850Z-v4-nb-files-d） |
| PC-DIALOGUE | engine：成功（20261106T003949Z-v4-nb-boundary） |
| PC-FILE | engine：成功（20261106T003949Z-v4-nb-boundary） |
| PC-PROXY | engine：成功（20261106T003949Z-v4-nb-boundary） |

## 批次状态（包括无结果的失败运行）

- 20261106T000734Z-v4-nb-files-a：完整结束
- 20261106T001019Z-v4-nb-files-b：完整结束
- 20261106T001324Z-v4-nb-files-c：完整结束
- 20261106T001850Z-v4-nb-files-d：完整结束
- 20261106T002242Z-v4-nb-connect：完整结束
- 20261106T003331Z-v4-nb-engine-a：完整结束
- 20261106T003617Z-v4-nb-engine-b：完整结束
- 20261106T003949Z-v4-nb-boundary：完整结束

同码比较包含 engine、harness、规格与脚本；每次运行的新诱饵路径与随机串不拆散比较。不将未测、试跑或清理失败当作正式通过。
