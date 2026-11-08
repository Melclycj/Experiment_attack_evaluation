/* NB-29 标记程序：极小的 Windows 控制台程序。mingw 交叉编译成 PE/COFF（文件以 "MZ" 开头）。
 * 经 WSL binfmt 互操作作为 Windows 进程跑时，把一行标记写到 argv[1] 指的路径后退出。
 * 不联网、不读别处、不碰其他文件——只为让"Windows 进程确实起了"留一个宿主侧外部事实。
 * 构建见 build.sh：x86_64-w64-mingw32-gcc -O2 -s -o nb29.mz nb29_marker.c
 */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    FILE *f = fopen(argv[1], "w");
    if (!f) {
        return 1;
    }
    fputs("nb-decoy-nb29 windows process ran\n", f);
    fclose(f);
    return 0;
}
