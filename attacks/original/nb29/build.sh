#!/bin/sh
# NB-29 档 2 探针的两个二进制。在 WSL 上跑一次即可。
#   nb29.mz  —— mingw 交叉编的 Windows PE（文件以 MZ 开头），作为 Windows 进程跑时写宿主标记
#   pcexec   —— 静态 Linux 小程序，PC-EXEC 用（chroot 内无需 libs）
# 依赖：gcc-mingw-w64-x86-64（提供 x86_64-w64-mingw32-gcc）、gcc + libc 静态库。
set -eu
here="$(cd "$(dirname "$0")" && pwd)"

x86_64-w64-mingw32-gcc -O2 -s -o "$here/nb29.mz" "$here/nb29_marker.c"
gcc -static -O2 -s -o "$here/pcexec" "$here/pcexec.c"

# 自检：nb29.mz 必须以 MZ（0x4d 0x5a）开头，否则 binfmt 的 magic 匹配不上
head -c 2 "$here/nb29.mz" | od -An -tx1 | grep -q '4d 5a' || { echo "nb29.mz does not start with MZ" >&2; exit 1; }
echo "built: nb29.mz (PE, MZ-prefixed), pcexec (static)"
