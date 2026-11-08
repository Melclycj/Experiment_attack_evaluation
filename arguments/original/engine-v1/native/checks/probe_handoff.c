#define _GNU_SOURCE
#include "contract.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* Trusted, unprivileged API probe, NOT a spawner/receiver implementation.
 * One driver acts as both ends of the control pair; a same-uid forked writer
 * supplies actual kernel credentials. No namespaces, mounts or policy. */
static pid_t child = -1;
static void fail(const char *what)
{
    int saved = errno;
    if (child > 0) { kill(child, SIGKILL); while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {} }
    fprintf(stderr, "%s: errno=%d\n", what, saved);
    exit(1);
}
#define REQUIRE(c) do { if (!(c)) fail(#c); } while (0)
static void configure(int fd)
{
    struct timeval t = {.tv_sec = 3};
    REQUIRE(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t) == 0);
    REQUIRE(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof t) == 0);
}
static int option(int fd, int name)
{
    int value = -1; socklen_t len = sizeof value;
    REQUIRE(getsockopt(fd, SOL_SOCKET, name, &value, &len) == 0);
    REQUIRE(len == sizeof value);
    return value;
}
static void unnamed(int fd)
{
    struct sockaddr_un a = {0}; socklen_t len = sizeof a;
    REQUIRE(getsockname(fd, (struct sockaddr *)&a, &len) == 0);
    REQUIRE(a.sun_family == AF_UNIX && len == sizeof(sa_family_t));
    len = sizeof a;
    REQUIRE(getpeername(fd, (struct sockaddr *)&a, &len) == 0);
    REQUIRE(a.sun_family == AF_UNIX && len == sizeof(sa_family_t));
}
static unsigned credential_pieces;
static void receive_verified(int fd, unsigned char out[16], pid_t expected_pid)
{
    size_t done = 0;
    while (done < 16) {
        /* Force bounded short reads; rebuild every msghdr and ancillary area. */
        size_t cap = 16 - done; if (cap > 3) cap = 3;
        struct iovec io = {.iov_base = out + done, .iov_len = cap};
        union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct ucred))]; } control = {0};
        struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
            .msg_control = control.bytes, .msg_controllen = sizeof control.bytes};
        ssize_t got = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
        if (got < 0 && errno == EINTR) continue;
        REQUIRE(got > 0 && !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        REQUIRE(c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS);
        REQUIRE(c->cmsg_len == CMSG_LEN(sizeof(struct ucred)) && CMSG_NXTHDR(&msg, c) == NULL);
        struct ucred u; memcpy(&u, CMSG_DATA(c), sizeof u);
        REQUIRE(u.uid == getuid() && u.pid == expected_pid && u.gid == getgid());
        ++credential_pieces; done += (size_t)got;
    }
}
static void child_main(int fd)
{
    alarm(5);
    unsigned char wire[16];
    struct w2_bootstrap sealed = {W2_BP_SEALED, W2_STAGE_NONE, 0}, received;
    if (w2_bootstrap_encode(&sealed, wire, sizeof wire) != W2_CONTRACT_OK) _exit(2);
    for (size_t i = 0; i < 16; ++i)
        if (send(fd, wire + i, 1, MSG_NOSIGNAL) != 1) _exit(3);
    size_t done = 0;
    while (done < 16) {
        ssize_t n = recv(fd, wire + done, 16 - done, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) _exit(4);
        done += (size_t)n;
    }
    if (w2_bootstrap_decode(wire, 16, &received) != W2_CONTRACT_OK
        || received.kind != W2_BP_COMMIT) _exit(5);
    /* Still trusted probe code: reflect bytes to verify post-handoff receive. */
    if (send(fd, wire, 16, MSG_NOSIGNAL) != 16) _exit(6);
    unnamed(fd);
    close(fd); _exit(0);
}
int main(void)
{
    REQUIRE(getuid() != 0);
    int ctl[2], data[2], one = 1;
    REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, ctl) == 0);
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, data) == 0);
    for (int i = 0; i < 2; ++i) { configure(ctl[i]); configure(data[i]); }
    REQUIRE(option(ctl[0], SO_PASSCRED) == 0 && option(ctl[1], SO_PASSCRED) == 0);
    REQUIRE(setsockopt(data[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof one) == 0);
    child = fork(); REQUIRE(child >= 0);
    if (child == 0) {
        close(ctl[0]); close(ctl[1]); close(data[0]); child_main(data[1]);
    }
    REQUIRE(close(data[1]) == 0);
    unsigned char wire[16]; struct w2_bootstrap m;
    receive_verified(data[0], wire, child);
    REQUIRE(w2_bootstrap_decode(wire, 16, &m) == W2_CONTRACT_OK && m.kind == W2_BP_SEALED);
    unnamed(data[0]);

    /* Only the fd transfer is under test: marker is NOT production control JSON. */
    char marker = 'H'; struct iovec io = {.iov_base = &marker, .iov_len = 1};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } ancillary = {0};
    struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
        .msg_control = ancillary.bytes, .msg_controllen = sizeof ancillary.bytes};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &data[0], sizeof(int));
    REQUIRE(sendmsg(ctl[0], &msg, MSG_NOSIGNAL) == 1);
    REQUIRE(close(data[0]) == 0);
    memset(&ancillary, 0, sizeof ancillary); marker = 0;
    msg.msg_controllen = sizeof ancillary.bytes; msg.msg_flags = 0;
    REQUIRE(recvmsg(ctl[1], &msg, MSG_CMSG_CLOEXEC) == 1 && marker == 'H');
    REQUIRE(!(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
    c = CMSG_FIRSTHDR(&msg);
    REQUIRE(c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS);
    REQUIRE(c->cmsg_len == CMSG_LEN(sizeof(int)) && CMSG_NXTHDR(&msg, c) == NULL);
    int transferred = -1; memcpy(&transferred, CMSG_DATA(c), sizeof transferred);
    REQUIRE((fcntl(transferred, F_GETFD) & FD_CLOEXEC) != 0);
    REQUIRE(option(transferred, SO_DOMAIN) == AF_UNIX);
    REQUIRE(option(transferred, SO_TYPE) == SOCK_STREAM && option(transferred, SO_PASSCRED) == 1);
    unnamed(transferred);
    m = (struct w2_bootstrap){W2_BP_COMMIT, W2_STAGE_NONE, 0};
    REQUIRE(w2_bootstrap_encode(&m, wire, sizeof wire) == W2_CONTRACT_OK);
    for (size_t i = 0; i < 16; ++i) REQUIRE(send(transferred, wire + i, 1, MSG_NOSIGNAL) == 1);
    receive_verified(transferred, wire, child);
    REQUIRE(w2_bootstrap_decode(wire, 16, &m) == W2_CONTRACT_OK && m.kind == W2_BP_COMMIT);
    unnamed(transferred);
    int status = 0; pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    REQUIRE(got == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    child = -1;
    REQUIRE(close(transferred) == 0 && close(ctl[0]) == 0 && close(ctl[1]) == 0);
    printf("{\"check\":\"SC-handoff\",\"result\":\"passed\",\"uid\":%u,"
           "\"credential_pieces\":%u,\"stream_endpoints_unnamed\":true,"
           "\"received_fd_cloexec\":true,\"passcred_preserved\":true,"
           "\"child_reaped\":true,\"scope\":\"trusted same-uid API probe; no isolation or policy\"}\n",
           (unsigned)getuid(), credential_pieces);
    return 0;
}
