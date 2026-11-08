/* Fuzz entry 4 (block 4; validation.md K-02, K-24, C-02, C-03): the v2 judgment-port reader the core and the
 * connector both read with, w2_judge_receive -> w2_recv_credential_right -> w2_ancillary, plus w2_judge_peek,
 * over a real AF_UNIX socketpair, so every fragment carries the kernel's own SCM_CREDENTIALS.
 *
 * Input: the same op language as fuzz_frame.c (byte 0 chooses the expected and overflow uids; then ops: 0 send N
 * bytes, 1 send N bytes with one SCM_RIGHTS descriptor, 2 one out-of-band byte, 3 receive only).
 *
 * Oracle: ASan/UBSan; the return contract (1 -> 1..cap body bytes and a descriptor that is -1 or open; 2 -> progress
 * with peek's declared length within the cap; 0 -> nothing consumed; -1 -> dead, and a dead reader stays dead);
 * no descriptor survives the input: every returned descriptor is closed here, and at the end the lowest free fd is
 * the one measured before the pair was made (a leaked copy would occupy it). Must run as non-root. */
#define _GNU_SOURCE
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define DIE(msg) do { fprintf(stderr, "fuzz_judge: %s\n", msg); abort(); } while (0)
#define CAP (1u << 20)

static int lowest_free = -1;
static unsigned char out[CAP];

static int probe_fd(void) {
    int p = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (p < 0) DIE("open /dev/null");
    close(p);
    return p;
}

static void send_bytes(int fd, const uint8_t *p, size_t n, bool rights) {
    if (!n) return;
    struct iovec iov = {(void *)p, n};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    union {struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))];} control;
    int attached = -1;
    if (rights) {
        attached = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (attached < 0) DIE("open rights fd");
        memset(&control, 0, sizeof control);
        m.msg_control = control.bytes;
        m.msg_controllen = sizeof control.bytes;
        struct cmsghdr *h = CMSG_FIRSTHDR(&m);
        h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS; h->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(h), &attached, sizeof attached);
    }
    (void)sendmsg(fd, &m, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (attached >= 0) close(attached);
}

static bool drive(struct w2_judge_reader *r, int fd, uid_t expected, uid_t overflow) {
    for (int i = 0; i < 256; ++i) {
        size_t length = 0, declared = 0;
        int rights = -1, kind = -2;
        int rc = w2_judge_receive(r, fd, expected, overflow, out, sizeof out, &length, &rights);
        w2_judge_peek(r, &declared, &kind);
        if (declared > CAP || kind < -1 || kind > 255) DIE("peek out of range");
        if (rc == 1) {
            if (!length || length > CAP) DIE("complete frame with bad length");
            if (rights >= 0) { if (fcntl(rights, F_GETFD) < 0) DIE("returned descriptor is not open"); close(rights); }
            if (declared || kind != -1) DIE("peek after a complete frame is not reset");
            continue;
        }
        if (rights >= 0) DIE("descriptor returned without a complete frame");
        if (rc < 0) {
            size_t again = 0; int more = -1;
            if (w2_judge_receive(r, fd, expected, overflow, out, sizeof out, &again, &more) != -1) DIE("dead reader revived");
            if (more >= 0) DIE("descriptor from a dead reader");
            return false;
        }
        if (rc != 0 && rc != 2) DIE("unexpected return");
        if (rc == 0) {
            int pending = 0;
            if (ioctl(fd, FIONREAD, &pending) || pending <= 0) return true;
        }
    }
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (getuid() == 0) DIE("run as non-root");
    if (lowest_free < 0) lowest_free = probe_fd();
    if (!size) return 0;
    uid_t own = getuid();
    uid_t expected = (data[0] & 1) ? own + 1 : own;
    uid_t overflow = (data[0] & 2) ? own : 65534;
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds)) DIE("socketpair");
    int one = 1;
    if (setsockopt(fds[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof one)) DIE("SO_PASSCRED");
    int after_pair = probe_fd();
    struct w2_judge_reader *r = w2_judge_reader_new(CAP);
    if (!r) DIE("reader");
    size_t at = 1;
    bool alive = true;
    while (alive && at < size) {
        uint8_t op = data[at++] & 3;
        if (op == 0 || op == 1) {
            size_t n = 0;
            if (at + 2 <= size) { n = (size_t)data[at] << 8 | data[at + 1]; at += 2; }
            if (n > size - at) n = size - at;
            send_bytes(fds[1], data + at, n, op == 1);
            at += n;
        } else if (op == 2) {
            char b = 'x';
            (void)send(fds[1], &b, 1, MSG_OOB | MSG_NOSIGNAL | MSG_DONTWAIT);
        }
        alive = drive(r, fds[0], expected, overflow);
    }
    w2_judge_reader_free(r);   /* closes a descriptor held for an unfinished frame */
    if (probe_fd() != after_pair) DIE("a received descriptor was left open");
    close(fds[0]);
    close(fds[1]);
    if (probe_fd() != lowest_free) DIE("a received descriptor was left open");
    return 0;
}
