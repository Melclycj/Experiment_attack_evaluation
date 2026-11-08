#define _GNU_SOURCE
#include "support.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* validation.md H-10, H-11, H-12 (plan engine-v3-n16-file-read 2.3a): w2_open_beneath, the one way the core opens a
 * host file. Each case prints one line with its return value and errno; the exit status is nonzero if any case is
 * wrong. Run as root, the two cases that need a mount (a bind mount under the prefix, /dev/null bound into it) run in
 * a mount namespace of their own; without root they are reported as skipped and the check fails (the sandbox
 * regression runs it as root). */

static int failures;
static char base[] = "/tmp/w2-open-beneath-XXXXXX";

static int count_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    int n = 0;
    if (!d) return -1;
    while (readdir(d)) ++n;
    closedir(d);
    return n;
}

static void refused(const char *name, int dirfd, const char *path, int want, int expected) {
    struct stat st;
    uint64_t started = w2_now();
    errno = 0;
    int fd = w2_open_beneath(dirfd, path, want, &st);
    int err = errno;
    unsigned long long ms = (unsigned long long)((w2_now() - started) / 1000000u);
    int ok = fd < 0 && err == expected && ms < 2000;
    printf("case %s rc=%d errno=%d expected=%d ms=%llu ok=%d\n", name, fd < 0 ? -1 : 0, err, expected, ms, ok);
    if (fd >= 0) close(fd);
    if (!ok) ++failures;
}

static void opened(const char *name, int dirfd, const char *path, int want, const char *where, const char *content) {
    struct stat out, now, ref;
    errno = 0;
    int fd = w2_open_beneath(dirfd, path, want, &out);
    int err = fd < 0 ? errno : 0, ok = fd >= 0;
    if (ok) {
        int flags = fcntl(fd, F_GETFL), fdflags = fcntl(fd, F_GETFD);
        /* the same file before and after the reopen through /proc/self/fd, read-only, not an O_PATH descriptor */
        ok = !stat(where, &ref) && !fstat(fd, &now) && out.st_dev == ref.st_dev && out.st_ino == ref.st_ino &&
             now.st_dev == ref.st_dev && now.st_ino == ref.st_ino && flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
             !(flags & O_PATH) && fdflags >= 0 && (fdflags & FD_CLOEXEC) &&
             (want == W2_OPEN_READ ? S_ISREG(now.st_mode) : S_ISDIR(now.st_mode));
        if (ok && content) {
            char buffer[64] = {0};
            ssize_t n = pread(fd, buffer, sizeof buffer - 1, 0);
            ok = n == (ssize_t)strlen(content) && !memcmp(buffer, content, (size_t)n);
        }
        if (ok && want == W2_OPEN_READ) ok = write(fd, "x", 1) < 0;
        close(fd);
    }
    printf("case %s rc=%d errno=%d ok=%d\n", name, fd < 0 ? -1 : 0, err, ok);
    if (!ok) ++failures;
}

static int put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int unlink_one(const char *path, const struct stat *st, int flag, struct FTW *ftw) {
    (void)st; (void)ftw;
    return flag == FTW_DP ? rmdir(path) : unlink(path);
}

static char *at(const char *rest) {
    static char buffers[8][PATH_MAX];
    static unsigned next;
    char *b = buffers[next++ % 8];
    snprintf(b, PATH_MAX, "%s/%s", base, rest);
    return b;
}

int main(void) {
    alarm(30);   /* nothing here may block: a FIFO opened for real would hang the core */
    if (!mkdtemp(base)) return 2;
    if (mkdir(at("a"), 0755) || mkdir(at("a/sub"), 0755) || mkdir(at("outside"), 0755) ||
        put(at("a/f.txt"), "hello") || put(at("a/sub/in.txt"), "inner") || put(at("outside/secret"), "SECRET") ||
        symlink("sub", at("a/mid")) || symlink("f.txt", at("a/last")) || symlink(at("outside/secret"), at("a/out")) ||
        symlink("../outside/secret", at("a/up")) || mkfifo(at("a/fifo"), 0644)) return 2;
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", at("a/sock"));
    if (sock < 0 || bind(sock, (struct sockaddr *)&addr, sizeof addr)) return 2;
    close(sock);
    bool root = geteuid() == 0;
    if (root) {
        /* a mount namespace of this check's own, so the two mounts never reach the caller */
        if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) || mkdir(at("a/mnt"), 0755) ||
            mount(at("outside"), at("a/mnt"), NULL, MS_BIND, NULL) || put(at("a/devnull"), "") ||
            mount("/dev/null", at("a/devnull"), NULL, MS_BIND, NULL)) return 2;
    }
    int anchor = open(at("a"), O_PATH | O_DIRECTORY | O_CLOEXEC);
    int proc = open("/proc/self", O_PATH | O_DIRECTORY | O_CLOEXEC);
    int dev = open("/dev", O_PATH | O_DIRECTORY | O_CLOEXEC);
    int target = open(base, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (anchor < 0 || proc < 0 || dev < 0 || target < 0) return 2;
    int fds_before = count_fds();

    opened("read_regular_file", anchor, "f.txt", W2_OPEN_READ, at("a/f.txt"), "hello");
    opened("read_below", anchor, "sub/in.txt", W2_OPEN_READ, at("a/sub/in.txt"), "inner");
    opened("list_directory", anchor, "sub", W2_OPEN_LIST, at("a/sub"), NULL);
    opened("list_the_anchor", anchor, ".", W2_OPEN_LIST, at("a"), NULL);
    /* H-10: no symlink anywhere on the path, nothing out of the prefix, no magic link */
    refused("symlink_in_the_middle", anchor, "mid/in.txt", W2_OPEN_READ, ELOOP);
    refused("symlink_last_segment", anchor, "last", W2_OPEN_READ, ELOOP);
    refused("symlink_absolute_outside", anchor, "out", W2_OPEN_READ, ELOOP);
    refused("symlink_relative_outside", anchor, "up", W2_OPEN_READ, ELOOP);
    refused("dotdot_out_of_the_prefix", anchor, "../outside/secret", W2_OPEN_READ, EXDEV);
    refused("dotdot_through_a_directory", anchor, "sub/../../outside/secret", W2_OPEN_READ, EXDEV);
    refused("absolute_path", anchor, at("outside/secret"), W2_OPEN_READ, EXDEV);
    char magic[32];
    snprintf(magic, sizeof magic, "fd/%d", target);
    refused("magic_link_proc_self_fd", proc, magic, W2_OPEN_LIST, ELOOP);
    refused("magic_link_proc_self_cwd", proc, "cwd", W2_OPEN_LIST, ELOOP);
    refused("magic_link_proc_self_exe", proc, "exe", W2_OPEN_READ, ELOOP);
    /* H-11: the type is checked on the O_PATH probe; a FIFO, a socket or a device is never opened for real */
    refused("read_a_directory", anchor, "sub", W2_OPEN_READ, EISDIR);
    refused("read_a_fifo_without_writer", anchor, "fifo", W2_OPEN_READ, EOPNOTSUPP);
    refused("read_a_unix_socket", anchor, "sock", W2_OPEN_READ, EOPNOTSUPP);
    refused("read_dev_null", dev, "null", W2_OPEN_READ, EOPNOTSUPP);
    refused("list_a_regular_file", anchor, "f.txt", W2_OPEN_LIST, ENOTDIR);
    refused("list_a_fifo", anchor, "fifo", W2_OPEN_LIST, ENOTDIR);
    refused("missing", anchor, "nope", W2_OPEN_READ, ENOENT);
    refused("file_in_the_middle", anchor, "f.txt/x", W2_OPEN_READ, ENOTDIR);
    refused("unknown_operation", anchor, "f.txt", 3, EINVAL);
    refused("empty_path", anchor, "", W2_OPEN_READ, EINVAL);
    refused("no_directory", -1, "f.txt", W2_OPEN_READ, EBADF);
    if (root) {
        /* H-10: no RESOLVE_NO_XDEV, a mount point under the prefix is the user's own layout */
        opened("bind_mount_under_the_prefix", anchor, "mnt/secret", W2_OPEN_READ, at("outside/secret"), "SECRET");
        refused("dev_null_bound_under_the_prefix", anchor, "devnull", W2_OPEN_READ, EOPNOTSUPP);
    } else {
        printf("case bind_mount_under_the_prefix skipped=not_root ok=0\n");
        printf("case dev_null_bound_under_the_prefix skipped=not_root ok=0\n");
        failures += 2;
    }
    int fds_after = count_fds();
    printf("case no_descriptor_left fds_before=%d fds_after=%d ok=%d\n", fds_before, fds_after,
           fds_before >= 0 && fds_before == fds_after);
    if (fds_before < 0 || fds_before != fds_after) ++failures;

    close(anchor); close(proc); close(dev); close(target);
    if (root) {
        umount2(at("a/mnt"), MNT_DETACH);
        umount2(at("a/devnull"), MNT_DETACH);
    }
    nftw(base, unlink_one, 16, FTW_DEPTH | FTW_PHYS);
    printf("open_beneath failures=%d\n", failures);
    return failures ? 1 : 0;
}
