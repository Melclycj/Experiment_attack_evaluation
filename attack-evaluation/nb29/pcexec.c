/* NB-29 的 PC-EXEC 小程序：仿隔间根里 exec 一个普通 Linux 程序，确认 exec 本身可用
 * （隔离出只有 MZ/binfmt 这条路被挡）。静态链接，chroot 内不需要 libs。
 * 构建见 build.sh：gcc -static -O2 -s -o pcexec pcexec.c
 */
int main(void) {
    return 0;
}
