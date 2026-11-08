/* Fuzz entry 1 (R-G2-11): the data-channel receive path the engine calls through FFI,
 * w2_frame_receive -> w2_recv_credential -> w2_ancillary (framing and comparison only; the body is
 * parsed by the engine's Python json after copy-out, since 2026-10-19), over a real
 * AF_UNIX socketpair, so every fragment carries the kernel's own SCM_CREDENTIALS.
 *
 * Input: byte 0 chooses the expected uid (own or own+1) and the overflow uid (65534 or own);
 * then a sequence of ops, each one control byte:
 *   op 0  send the next N input bytes (N = next two bytes, big-endian, clamped)
 *   op 1  the same, with one SCM_RIGHTS descriptor attached
 *   op 2  send one out-of-band byte
 *   op 3  receive only
 * After every op the reader is driven until the socket is drained or the reader stops.
 *
 * Oracle: ASan/UBSan; the return contract (1 -> 1..W2_BODY_MAX bytes, a dead reader stays dead);
 * no received descriptor survives the input: with the socketpair still open, the lowest free fd at the end
 * equals the one right after the pair was made (a received copy lands on that number, the sender's own copy
 * is closed after each send). Must run as non-root:
 * uid 0 is a sentinel the comparison rejects, which would hide every accepting path. */
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

#define DIE(msg) do { fprintf(stderr, "fuzz_frame: %s\n", msg); abort(); } while (0)

static int lowest_free = -1;   /* before the pair: the pair itself is gone again at the end */
static unsigned char out[W2_BODY_MAX];

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
    (void)sendmsg(fd, &m, MSG_NOSIGNAL | MSG_DONTWAIT);   /* a short or failed send is part of the input space */
    if (attached >= 0) close(attached);
}

/* Returns false once the reader has stopped (dead). */
static bool drive(struct w2_frame_reader *r, int fd, uid_t expected, uid_t overflow) {
    for (int i = 0; i < 256; ++i) {
        size_t length = 0;
        int rc = w2_frame_receive(r, fd, expected, overflow, out, sizeof out, &length);
        if (rc == 1) {
            if (!length || length > W2_BODY_MAX) DIE("complete frame with bad length");
            continue;
        }
        if (rc < 0) {
            size_t again = 0;
            if (w2_frame_receive(r, fd, expected, overflow, out, sizeof out, &again) != -1) DIE("dead reader revived");
            return false;
        }
        if (rc != 0) DIE("unexpected return");
        int pending = 0;
        if (ioctl(fd, FIONREAD, &pending) || pending <= 0) return true;
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
    struct w2_frame_reader *r = w2_reader_new();
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
    w2_reader_free(r);
    if (probe_fd() != after_pair) DIE("a received descriptor was left open");
    close(fds[0]);
    close(fds[1]);
    if (probe_fd() != lowest_free) DIE("a received descriptor was left open");
    return 0;
}
