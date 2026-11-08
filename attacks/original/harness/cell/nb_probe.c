/* 这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/* Finite interface, NOT an attack suite. Runner supplies request-derived args.
 * stdout = captured bytes only; stderr = JSONL syscall observations only.
 * Exit 0 = complete observations (including denied syscalls), NOT test success.
 * Exit 2 = protocol/setup/limit/identity error; killed signals come from waitpid.
 * No mkdir, O_CREAT, listeners, shell, arbitrary signal or negative PID surface.
 * Static build is deferred to the authorized host supervisor; see README §7.4.
 */
#define CAPTURE_LIMIT (2u * 1024u * 1024u)
#define INPUT_LIMIT 65536u
static unsigned char input[INPUT_LIMIT + 1];
static size_t input_size;

static void event(const char *step, long rc, int error) {
    if (fprintf(stderr, "{\"step\":\"%s\",\"rc\":%ld,\"errno\":%d}\n", step, rc, error) < 0
        || fflush(stderr) != 0) _exit(2);
}

static long observed(const char *step, long rc) {
    int error = rc < 0 ? errno : 0;
    event(step, rc, error);
    return rc;
}

static int invalid(const char *step) {
    event(step, -1, EINVAL);
    return 2;
}

static int emit(const unsigned char *data, size_t size) {
    while (size) {
        long n = syscall(SYS_write, STDOUT_FILENO, data, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { event("capture_write", n, n < 0 ? errno : EIO); return 2; }
        data += n;
        size -= (size_t)n;
    }
    return 0;
}

static int read_input(void) {
    while (input_size <= INPUT_LIMIT) {
        long n = syscall(SYS_read, STDIN_FILENO, input + input_size, sizeof(input) - input_size);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { event("input_read", n, errno); return 2; }
        if (!n) return 0;
        input_size += (size_t)n;
    }
    return invalid("input_limit");
}

static int number(const char *text, unsigned long long max, unsigned long long *out) {
    if (!*text || strspn(text, "0123456789") != strlen(text)) return 0;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(text, &end, 10);
    if (errno || !end || *end || !v || v > max) return 0;
    *out = v;
    return 1;
}

static int file_probe(const char *operation, const char *path) {
    int write_mode = strcmp(operation, "truncate") == 0;
    if (path[0] != '/' || strlen(path) >= PATH_MAX) return invalid("path");
    /* Target symlinks are intentional for file-view tests. The controller owns
     * target registration; output/capture safety is separately enforced in Python. */
    int flags = (write_mode ? O_WRONLY | O_TRUNC : O_RDONLY) | O_CLOEXEC | O_NONBLOCK;
    int fd = (int)observed("open", syscall(SYS_openat, AT_FDCWD, path, flags, 0));
    if (fd < 0) return 0;
    int status = 0;
    struct stat st;
    if (observed("fstat", syscall(SYS_fstat, fd, &st)) < 0) goto done;
    if (!S_ISREG(st.st_mode)) { status = invalid("nonregular_target"); goto done; }
    if (fprintf(stderr, "{\"step\":\"identity\",\"rc\":0,\"errno\":0,\"dev\":%llu,\"ino\":%llu,\"size\":%llu}\n",
                (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
                (unsigned long long)st.st_size) < 0 || fflush(stderr) != 0) _exit(2);
    if (write_mode) {
        size_t sent = 0;
        while (sent < input_size) {
            long n = observed("write", syscall(SYS_write, fd, input + sent, input_size - sent));
            if (n <= 0) goto done;
            sent += (size_t)n;
        }
        observed("fsync", syscall(SYS_fsync, fd));
    } else {
        unsigned char buffer[65536];
        size_t total = 0;
        for (;;) {
            size_t count = CAPTURE_LIMIT - total + 1;
            if (count > sizeof(buffer)) count = sizeof(buffer);
            long n = observed("read", syscall(SYS_read, fd, buffer, count));
            if (n <= 0) break;
            if ((size_t)n > CAPTURE_LIMIT - total) { status = invalid("capture_limit"); break; }
            total += (size_t)n;
            if (emit(buffer, (size_t)n)) { status = 2; break; }
        }
    }
done:
    observed("close", syscall(SYS_close, fd));
    return status;
}

static int network_probe(const char *operation, const char *address, const char *port) {
    unsigned long long value;
    struct sockaddr_in peer = { .sin_family = AF_INET };
    if (!number(port, 65535, &value) || inet_pton(AF_INET, address, &peer.sin_addr) != 1)
        return invalid("destination");
    peer.sin_port = htons((uint16_t)value);
    int udp = strcmp(operation, "udp") == 0;
    if (!input_size || (udp && input_size > 65507)) return invalid("network_input");
    int fd = (int)observed("socket", syscall(SYS_socket, AF_INET,
                           (udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_CLOEXEC, 0));
    if (fd < 0) return 0;
    int status = 0;
    struct timeval one_second = { .tv_sec = 1, .tv_usec = 0 };
    if (observed("send_timeout", syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_SNDTIMEO,
                                        &one_second, sizeof(one_second))) < 0) goto done;
    if (observed("recv_timeout", syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_RCVTIMEO,
                                        &one_second, sizeof(one_second))) < 0) goto done;
    if (observed("connect", syscall(SYS_connect, fd, &peer, sizeof(peer))) < 0) goto done;
    size_t sent = 0;
    while (sent < input_size) {
        long n = observed("send", syscall(SYS_sendto, fd, input + sent, input_size - sent,
                                          MSG_NOSIGNAL, NULL, 0));
        if (n <= 0) goto done;
        sent += (size_t)n;
        if (udp && sent != input_size) { status = invalid("partial_datagram"); goto done; }
    }
    /* Stream decoys frame the request by EOF. UDP must recv for ECONNREFUSED. */
    if (!udp && observed("shutdown", syscall(SYS_shutdown, fd, SHUT_WR)) < 0) goto done;
    unsigned char buffer[65536];
    size_t total = 0;
    for (;;) {
        long n = observed("recv", syscall(SYS_recvfrom, fd, buffer, sizeof(buffer), 0, NULL, NULL));
        if (n <= 0) break;
        if ((size_t)n > CAPTURE_LIMIT - total) { status = invalid("capture_limit"); break; }
        total += (size_t)n;
        if (emit(buffer, (size_t)n)) { status = 2; break; }
        if (udp) break;
    }
done:
    observed("close", syscall(SYS_close, fd));
    return status;
}

static int stop_probe(const char *pid_text, const char *start_text) {
    unsigned long long pid, expected;
    if (!number(pid_text, INT_MAX, &pid) || pid <= 1 ||
        !number(start_text, LLONG_MAX, &expected)) return invalid("process_target");
    char path[80], buffer[4096];
    snprintf(path, sizeof(path), "/proc/%llu/stat", pid);
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
    int open_error = fd < 0 ? errno : 0;
    event("proc_open", fd, open_error);
    if (fd >= 0) {
        long n = observed("proc_read", syscall(SYS_read, fd, buffer, sizeof(buffer) - 1));
        observed("proc_close", syscall(SYS_close, fd));
        if (n <= 0 || n == (long)sizeof(buffer) - 1) return invalid("process_identity");
        buffer[n] = 0;
        char *last = strrchr(buffer, ')');
        if (!last || last[1] != ' ') return invalid("process_identity");
        char *save = NULL, *word = strtok_r(last + 2, " \n", &save);
        for (int field = 3; field < 22 && word; field++) word = strtok_r(NULL, " \n", &save);
        unsigned long long actual;
        if (!word || !number(word, LLONG_MAX, &actual) || actual != expected)
            return invalid("process_identity_mismatch");
        event("process_identity_match", 0, 0);
    } else if (open_error != ENOENT) {
        return invalid("process_identity_unavailable");
    }
    /* ENOENT is the specified pid-namespace test. Host pinned pidfds establish
     * identity and restore stopped processes; this probe never restores by PID. */
    observed("kill", syscall(SYS_kill, (pid_t)pid, SIGSTOP));
    return 0;
}

static int stop_control(void) {
    pid_t child = fork();
    if (!child) { for (;;) pause(); }
    observed("control_fork", child);
    if (child < 0) return 2;
    int status = 2, state = 0;
    if (observed("control_stop", syscall(SYS_kill, child, SIGSTOP)) < 0) goto cleanup;
    pid_t waited;
    do { waited = waitpid(child, &state, WUNTRACED); } while (waited < 0 && errno == EINTR);
    int wait_error = waited < 0 ? errno : 0;
    event("control_wait_stop", waited, wait_error);
    /* A terminal wait has already reaped the child. ECHILD likewise means we
     * no longer own a waitable PID; never signal a possibly recycled number. */
    if ((waited == child && (WIFEXITED(state) || WIFSIGNALED(state))) ||
        (waited < 0 && wait_error == ECHILD)) return 2;
    if (waited != child || !WIFSTOPPED(state)) goto cleanup;
    char path[80], buffer[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)child);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) goto cleanup;
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (n <= 0 || n >= (ssize_t)sizeof(buffer) - 1) goto cleanup;
    buffer[n] = 0;
    char *last = strrchr(buffer, ')');
    if (!last || last[1] != ' ' || last[2] != 'T') goto cleanup;
    event("control_state", 0, 0);
    status = 0;
cleanup:
    /* Unreaped direct child: no PID reuse; only this local control uses numeric
     * recovery. Engine targets are restored by host-owned pidfds, never here. */
    if (observed("control_resume", syscall(SYS_kill, child, SIGCONT)) < 0) status = 2;
    if (observed("control_kill", syscall(SYS_kill, child, SIGTERM)) < 0) status = 2;
    pid_t reaped;
    do { reaped = waitpid(child, &state, 0); } while (reaped < 0 && errno == EINTR);
    observed("control_reap", reaped);
    if (reaped != child || !WIFSIGNALED(state) || WTERMSIG(state) != SIGTERM) status = 2;
    return status;
}

int main(int argc, char **argv) {
    if (argc < 3) return invalid("arguments");
    const char *op = argv[1];
    if (strcmp(op, "stop-control") == 0) {
        if (argc != 3 || strcmp(argv[2], "self") || read_input() || input_size) return invalid("control_args");
        int result = stop_control();
        if (!result) event("complete", 0, 0);
        return result;
    }
    int file = strcmp(op, "read") == 0 || strcmp(op, "truncate") == 0;
    int net = strcmp(op, "tcp") == 0 || strcmp(op, "udp") == 0;
    int stop = strcmp(op, "stop") == 0;
    if ((!file && !net && !stop) || (file ? argc != 3 : argc != 4)) return invalid("operation");
    if (read_input()) return 2;
    if ((strcmp(op, "read") == 0 || stop) && input_size) return invalid("unexpected_input");
    if (strcmp(op, "truncate") == 0 && !input_size) return invalid("empty_write");
    int status = file ? file_probe(op, argv[2]) : net ? network_probe(op, argv[2], argv[3])
                                                  : stop_probe(argv[2], argv[3]);
    if (!status) event("complete", 0, 0);
    return status;
}
