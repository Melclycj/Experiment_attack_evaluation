/* Fuzz entry 2 (R-G2-11): w2_ancillary on control buffers a real recvmsg rarely or never produces (entry 1
 * only reaches kernel-formed cmsg headers).
 *
 * transport.c is compiled for this entry with -Dclose=fuzz_close, so the SCM_RIGHTS values in a buffer are
 * recorded instead of closing descriptors of the fuzzing process.
 *
 * Byte 0: msg_flags selector (bit 0 MSG_TRUNC, bit 1 MSG_CTRUNC, bit 2 MSG_OOB) and, in bit 7, the mode.
 * Byte 1: credentials, early_failure, child pid given, expected uid choice.
 *
 * Raw mode (bit 7 clear): the rest is the control buffer itself, copied into an exact-size heap block so any
 * read past msg_controllen is caught. Oracle: ASan/UBSan; a rejection hands out no descriptor; an acceptance
 * never comes with MSG_TRUNC, MSG_CTRUNC or MSG_OOB; a credential read hands out no descriptor.
 *
 * Structured mode (bit 7 set): each further byte describes one well-formed header (as the kernel writes them,
 * truncated rights included): low 2 bits 0 = SCM_RIGHTS with (byte >> 2) descriptors, 1 = SCM_CREDENTIALS,
 * 2 = a header of another level, 3 = SCM_CREDENTIALS of the wrong length. Every descriptor value is distinct.
 * Oracle, in addition to the raw-mode one: every descriptor in the buffer is either closed exactly once or, on
 * an acceptance without credentials, is the single one handed out; nothing else is closed. */
#define _GNU_SOURCE
#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define DIE(msg) do { fprintf(stderr, "fuzz_ancillary: %s\n", msg); abort(); } while (0)
#define HEADERS_MAX 16
#define FD_BASE 100000
#define FDS_MAX (HEADERS_MAX * 63)

static int closed[FDS_MAX + 1];
static size_t nclosed;
static bool overflow_closes;
int fuzz_close(int fd) {
    if (nclosed < FDS_MAX + 1) closed[nclosed++] = fd; else overflow_closes = true;
    return 0;
}

static size_t build(const uint8_t *desc, size_t n, unsigned char *buf, size_t cap, int *fds, size_t *nfds) {
    size_t at = 0;
    *nfds = 0;
    for (size_t i = 0; i < n && i < HEADERS_MAX; ++i) {
        unsigned kind = desc[i] & 3, count = desc[i] >> 2;
        size_t data = kind == 0 ? count * sizeof(int) : kind == 1 ? sizeof(struct ucred)
                    : kind == 2 ? 4 : sizeof(struct ucred) - 1;
        if (at + CMSG_SPACE(data) > cap) break;
        struct cmsghdr h = {.cmsg_len = CMSG_LEN(data), .cmsg_level = kind == 2 ? IPPROTO_IP : SOL_SOCKET,
                            .cmsg_type = kind == 0 ? SCM_RIGHTS : SCM_CREDENTIALS};
        memcpy(buf + at, &h, sizeof h);
        unsigned char *payload = buf + at + CMSG_LEN(0);
        if (kind == 0) {
            for (unsigned j = 0; j < count; ++j) {
                int fd = FD_BASE + (int)*nfds;
                fds[(*nfds)++] = fd;
                memcpy(payload + j * sizeof(int), &fd, sizeof fd);
            }
        } else if (kind == 1 || kind == 3) {
            struct ucred c = {.pid = 4242, .uid = 1000, .gid = 1000};
            memcpy(payload, &c, data);
        } else {
            memset(payload, 0, data);
        }
        /* the last header is not padded, as the kernel leaves it */
        at += (i + 1 == n || i + 1 == HEADERS_MAX) ? CMSG_LEN(data) : CMSG_SPACE(data);
    }
    return at;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 2 + 8192) return 0;
    int flags = 0;
    if (data[0] & 1) flags |= MSG_TRUNC;
    if (data[0] & 2) flags |= MSG_CTRUNC;
    if (data[0] & 4) flags |= MSG_OOB;
    bool structured = data[0] & 0x80;
    bool credentials = data[1] & 1, early = data[1] & 2;
    pid_t child = (data[1] & 4) ? 4242 : 0;
    uid_t expected = (data[1] & 8) ? 1000 : 0;
    static int fds[FDS_MAX];
    size_t nfds = 0, len;
    unsigned char *control;
    if (structured) {
        size_t cap = HEADERS_MAX * CMSG_SPACE(63 * sizeof(int));
        unsigned char *scratch = malloc(cap);
        if (!scratch) DIE("malloc");
        len = build(data + 2, size - 2, scratch, cap, fds, &nfds);
        control = len ? malloc(len) : NULL;
        if (len && !control) DIE("malloc");
        if (len) memcpy(control, scratch, len);
        free(scratch);
    } else {
        len = size - 2;
        control = len ? malloc(len) : NULL;
        if (len && !control) DIE("malloc");
        if (len) memcpy(control, data + 2, len);
    }
    struct msghdr m = {.msg_control = control, .msg_controllen = len, .msg_flags = flags};
    int owned = -1;
    nclosed = 0;
    overflow_closes = false;
    int rc = w2_ancillary(&m, credentials, expected, child, 65534, early, &owned);
    if (rc != 0 && rc != -1) DIE("unexpected return");
    if (rc == -1 && owned != -1) DIE("rejection handed out a descriptor");
    if (rc == 0 && (flags & (MSG_TRUNC | MSG_CTRUNC | MSG_OOB))) DIE("accepted a truncated or out-of-band message");
    if (credentials && owned != -1) DIE("credential read handed out a descriptor");
    if (structured) {
        if (overflow_closes) DIE("more closes than descriptors");
        bool handed = rc == 0 && !credentials;
        if (handed && nfds > 1) DIE("accepted more than one descriptor");
        if (handed && nfds == 1 && owned != fds[0]) DIE("the one descriptor was not handed out");
        if (handed && nfds == 0 && owned != -1) DIE("a descriptor was handed out of an empty buffer");
        size_t expect = handed ? 0 : nfds;
        if (nclosed != expect) DIE("descriptors closed: wrong count");
        for (size_t i = 0; i < nclosed; ++i) {
            int v = closed[i] - FD_BASE;
            if (v < 0 || (size_t)v >= nfds) DIE("closed a descriptor that was not in the buffer");
            for (size_t j = 0; j < i; ++j) if (closed[j] == closed[i]) DIE("closed a descriptor twice");
        }
    }
    free(control);
    return 0;
}
