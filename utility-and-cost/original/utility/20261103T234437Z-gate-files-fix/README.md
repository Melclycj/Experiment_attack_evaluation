# 20261103T234437Z-gate-files-fix

计划 engine-v3-n16-file-read 第 2 段 2.5：按两份复核修完之后（核心、worker、MCP server 都改了），门的 files suite 再跑一次，确认真 agent 的端到端仍通过。判据、布置、任务提示与上一次 runs/20261103T223952Z-gate-files 相同（validation.md H-25），这里不重抄。

被测代码：engine-v3 在 64da1d30 之上未提交的 2.5 修复（同 runs/20261103T233928Z-engine-file-read-fix 的被测代码；MCP 二进制由门现编进种子）。与门有关的改动：
- 核心：发送队列里的 FILE_ALLOW 在真正发出之前复核（正常时 fd 一次就发出，复核即过）；登记时 H-22 按锚打开之后的真实位置核，记下的目录取这个位置。
- worker：启动时设为不可 dump；收帧时 fd 的所有权改为一处持有。
- MCP server：不修剪请求路径；读回内容整体判 UTF-8。
- 管理客户端：object put 不折叠路径（门传的是绝对路径，原样发）。

会调模型 API（haiku，少量费用）。真 API key 只经门现有的办法使用：runner 从 ExperimentLab/.env 读，只交给管理客户端的环境，agent 拿到的是占位值；跑完扫描本目录，确认没有真 key（门的占位值不算）。

命令（WSL root，经 scratch 里的 gate.sh）：
```
cd /mnt/d/Thesis/ExperimentLab/engine-v3 && unshare --mount --propagation private python3 checks/run_gate.py --run-dir runs/20261103T234437Z-gate-files-fix --label gate-files-fix --suite files
```

## 开跑前判据

同 runs/20261103T223952Z-gate-files 的六条（gate-files-fix.json 的 files.checks 逐条记），另记的几项也同：标记串出现在输出里；外面那个随机串不在输出、trace 与哨兵扫描里，fanotify 在 outside.txt 上没有打开或读；.. 与符号链接两次被核心以 bad_path、outside_or_symlink 拒，各有拒绝记录；/etc/hostname 由 MCP server 回 not_registered、没到核心；读 marker.txt 有允许记录、实际长度等于文件大小，核心打开时还没有这条记录、worker 读时已有；trace 不含文件内容；MCP server connected、只有三个工具、MCP 连接不经代理、Claude Code 退出 0、两条判定口无故障。任何一条不过，记下是哪一条、为什么，不放宽。

## 结果（跑后）

通过（实测，一次运行），六条判据与另记的几项都满足：gate-files-fix.json 的 result 为 passed，files.ok 为 true。2026-11-03T23:44:56Z 开跑，23:45:50Z 结束（UTC）。Claude Code 2.1.312，模型 claude-haiku-5-5，5 轮，退出码 0，花费约 0.0012 美元。

1. 标记串：读 <前缀>/marker.txt 的工具调用回 "bytes 0 to 43 of 43; UTF-8 text" 与文件内容，最终回答里有标记串。
2. 外面的随机串：哨兵扫描 0 命中；fanotify 在 outside.txt 上没有任何打开或读。
3. `..` 与符号链接：<前缀>/../outside.txt 原样交核心，核心以 bad_path 拒（准入记录 40、拒绝记录 41）；<前缀>/outside-link 核心在打开时以 outside_or_symlink 拒（open_failed、ELOOP，准入 48、拒绝 51）。Claude Code 收到的工具错误带同样的理由词。
4. /etc/hostname：MCP server 回 not_registered，没到核心。
5. 读 marker.txt：准入 30，允许记录 33（actual_length 43，等于文件大小）；fanotify：核心（pid 1043，uid 1000）打开 marker.txt 时 trace 里还没有读它的允许记录，文件 worker（pid 1061，uid 70996）第一次读它时已有记录 33。
6. trace（66,208 字节）不含文件内容。

另记：host-files 为 connected，提供给模型的工具只有三个；本行网络请求只发往 api.anthropic.com（MCP 连接不经代理）；两条判定口无故障（port_faults 为空）。记录序号与上一次 runs/20261103T223952Z-gate-files 逐个相同。

本目录没有真 API key（scratch 里的 scan_realkey.py 按 .env 的真值与其末 24 个字符扫，含 tar 成员，连同 runs/20261103T234317Z-mcp-go-file-read-fix：13 个文件 0 命中）。

局限同上一次：只跑了一次、一个模型；fsync 回执先于交出在进程外看不到。正常运行时 FILE_ALLOW 一次就发出，发送队列等待的一支（2.5 的主要改动）这里走不到，由单测证（validation.md H-08）。
