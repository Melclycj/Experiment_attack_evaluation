---
title: 基线 v4 修订记录
created: 2026-11-05
---

# 基线 v4：engine 留档版本（engine-v3 @ a9eff999）

**是什么。** 证明区登记的第三个基线，也是 engine 的留档版本。用户 2026-11-05 定登记 v4：攻击评估、utility 与
SOTA 三条线的最后正式测试都在它上面做。被分析的目录仍是 ExperimentLab/engine-v3，kernel 不变。登记之后
engine-v3 不再改；要改就登记新版本，在 v4 上做过的测试按改动重跑。

## 1 改了什么

构造与 v3 相同：每行一个 connector，核心按访问矩阵判定，外部 PDP，允许记录先落盘再放行。v4 在它上面补了四项。

| 改动 | 在 v4 里做什么 | 代码 | 提交 |
|---|---|---|---|
| 宿主文件经 engine 只读 | 用户登记的宿主目录或文件成为表里的对象，核心按格子判定读请求；每行一个文件 worker，在核过凭据的文件口后面打开并读出文件；隔间里的 MCP server 把读文件的工具交给 agent | 新增 engine/fileobjects.py、engine/fileport.py、fileworker/ 下四个文件、bin/file-worker、mcp-go/（Go）、native/checks/check_open_beneath.c；核心的 hook、pdp、workspaces 等随改 | 0c0e2270、636a98a3、688ffcb7、64da1d30、11eae9df |
| token 响应按正文扣下 | 条款 10：响应正文里带新签发的凭据就扣下，不再看请求的编码；JSON 对象里一层的 token 也扣 | connector/upstream.py（第四项起这段在 connector/token_response.py） | c14e9e66、e99e227c |
| 非全局地址按 IP 或地址段点名 | 精确的允许条目可以点名非全局地址；没点名的非全局 IP 字面量在第一个检查点拒；连接前按那一格的点名集合判定整个解析结果，复用连接前重判；连接建立之后、发任何字节之前再判一次对端；部署方配置的 NAT64 前缀里的字面量在校验阶段拒 | engine 下 workspaces、hook、judgment、admin、pdp、fileobjects；connector 下 canonical、channel、session、upstream；client 下 admin、render | e82dde75、d8893dea |
| 本机探测做不成时失败即关 | 建不出探测 socket 就把地址当本机地址、拒；宿主不支持这一地址族（EAFNOSUPPORT）除外 | connector/upstream.py；为守住单文件 800 行，条款 10 的 token 响应认定原样挪进新文件 connector/token_response.py | a9eff999 |

## 2 为什么改

- 宿主文件只读与 token 响应按正文：计划 engine-v3-n16-file-read。设计依据是 c7eaf22c（token 响应按正文；宿主文件经
  engine 只读）与 985a4256（runtime 到 engine 的三条口，按准入排序）。N-16 那条阻断由用户裁定为声明的残余。
- 点名非全局地址：计划 engine-v3-private-net。用户 2026-11-04 同意普通私网目的地做成配置后可用、元数据地址配置了
  也拒，2026-11-05 定了键的形状与复核余项的裁定。设计依据是 f9c0063d 与 6fb56f9f。
- 失败即关：同一计划第二轮冷复核的发现，用户 2026-11-05 定修。
- 同期另有三个设计提交只改设计文本，engine 代码没有随之改动：1d2cad15（WebSocket 仍拒）、c43c70ac 与 285fa4f7
  （路径只收按 RFC 3986 只有一种含义的写法，与现行代码一致）。

验收层仍是 engine-v3 的 validation.md：上面各项的 must、验证方法与结果都在
它的逐条 must 一节，TCB 文件的 sha256 前缀在它开头"实现"一条。

## 3 文件对照

对照 v3 的 ExperimentLab/engine-v3（ef02e3db）与 v4 的同一目录（a9eff999），两边都不含 runs/：新增 30 个文件，
改动 66 个，删除 0 个，不变 92 个；测试与检查装置都算在内。v3 导出 158 个文件，v4 导出 188 个，相差的正是新增的
30 个。新增、删除、改动三项的计数由下面这条命令复现（去掉 runs/ 开头的行）：

```
git diff --no-renames --name-status ef02e3db:ExperimentLab/engine-v3 a9eff999:ExperimentLab/engine-v3
```

## 4 kernel

不变：microsoft/WSL2-Linux-Kernel，tag linux-msft-wsl-6.6.87.2（commit 427645e3）。kernel-files.txt 自 2026-10-27
起没有改；v4 取回的 140 个文件与 v3 取回时的 sha256 逐个相同。engine-v3 在 v4 代码上的最后几次运行都在
6.6.87.2-microsoft-standard-WSL2 上。

## 5 登记

2026-11-05 在 Windows 一侧运行（Python 3.13.6，Git 2.48.1），与 v3 一样用环境变量关掉 core.autocrlf
（GIT_CONFIG_COUNT=1、GIT_CONFIG_KEY_0=core.autocrlf、GIT_CONFIG_VALUE_0=false），否则 git archive 写出 CRLF，
check 按 blob 核时对不上：

```
python baseline.py export v4    # exported 188 engine files of a9eff999
python baseline.py kernel v4    # fetched 140 new file(s)
python baseline.py check v4
```

check 的结果：

```
baseline v4: OK | engine snapshot matches a9eff999 file by file (188 blobs); kernel 140/140 listed files match their fetch record (427645e3); engine working tree equals the baseline
```

## 6 留档时的检查与已知残余

v4 的代码就是下面这几次运行时的工作树（TCB 的 53 个文件 sha256 前缀逐个相同，记录的输入与工作树逐个相同）：

- engine 检查 engine-v3 的 runs/20261105T091304Z-engine-named-private-round3：非特权单元 1394 passed、69 skipped，
  root 单元 69 passed，集成 27 例全过。
- 门 engine-v3 的 runs/20261105T091810Z-gate-named-private-round3：7.1 过；7.2 十项都过。7.2 是第二次开跑，第一次在
  任何一项开始之前因宿主内存吃紧被 Claude Code 停掉，没有 record。

留档时声明的残余在 validation.md 的 N 行，其中 N-15 列了批准到执行之间的四条。冷复核报过、没有改的几项记在计划
engine-v3-private-net 的 Notes 里（第二轮与第三轮的裁定），都只关可用性或攻击者造不出的条件。
