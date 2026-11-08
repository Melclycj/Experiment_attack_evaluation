#ifndef W2_TRANSPORT_H
#define W2_TRANSPORT_H
#include "support.h"
#include <sys/socket.h>
/* Nonblocking return convention: >0 bytes, 0 EOF, -2 retry, -1 fatal.
 * Unexpected received rights are always closed, including a truncated record. */
ssize_t w2_recv_control(int fd,char *out,size_t cap,int *owned_fd);
ssize_t w2_recv_credential(int fd,void *out,size_t cap,uid_t expected,pid_t child,uid_t overflow);
/* max_rights: how many SCM_RIGHTS descriptors the message may carry (0 or 1); one is handed back in *owned_fd,
 * more invalidates the message and closes them all. */
int w2_ancillary(struct msghdr *msg,bool credentials,uid_t expected,pid_t child,
                 uid_t overflow,bool early_failure,size_t max_rights,int *owned_fd);
/* v2 judgment port (validation.md K-02, K-24): the credential pipeline of w2_recv_credential, plus at most one
 * SCM_RIGHTS descriptor per message, returned in *owned_fd (-1 when none). */
ssize_t w2_recv_credential_right(int fd,void *out,size_t cap,uid_t expected,uid_t overflow,int *owned_fd);
int w2_validate_channel(int fd);
json_t *w2_control_parse(const char *wire,size_t length);
int w2_send_control(int fd,const char *wire,size_t length,int attached_fd);
int w2_send_control_fds(int fd,const char *wire,size_t length,const int *fds,size_t nfds);
ssize_t w2_recv_control3(int fd,char *out,size_t cap,int fds[3]);
int w2_ancillary_rights(struct msghdr *msg,int *out,size_t cap,size_t *count);
int w2_send_fixed(int fd,const void *wire,size_t length,uint64_t deadline);
int w2_recv_fixed(int fd,void *wire,size_t length,uint64_t deadline);
struct w2_frame_reader { unsigned char wire[W2_FRAME_MAX];size_t used,needed;uint64_t deadline,cookie;uid_t expected,overflow;int fd;bool dead,bound; };
struct w2_frame_writer { unsigned char wire[W2_FRAME_MAX];size_t used,size;uint64_t deadline,cookie;int fd;bool dead,bound; };
int w2_frame_receive(struct w2_frame_reader *r,int fd,uid_t expected,uid_t overflow,
                     unsigned char *out,size_t cap,size_t *length);
int w2_frame_queue(struct w2_frame_writer *w,const void *body,size_t size,uint64_t deadline);
int w2_frame_send(struct w2_frame_writer *w,int fd);
/* Tiny FFI wrapper for independent test drivers; same final receiver, no
 * synthetic credential path. Caller owns returned bytes and the reader. */
struct w2_frame_reader *w2_reader_new(void);
void w2_reader_free(struct w2_frame_reader *r);
/* v2 judgment-port reader: same framing and per-fragment credential check as w2_frame_receive, bodies up to
 * max_body bytes, and one received descriptor per frame handed back with the completed frame (K-02, K-24).
 * A second descriptor inside one frame, or any other invalid ancillary data, kills the reader. */
struct w2_judge_reader { unsigned char *wire;size_t cap,used,needed;uint64_t deadline,cookie;uid_t expected,overflow;int fd,rights;bool dead,bound; };
struct w2_judge_reader *w2_judge_reader_new(size_t max_body);
void w2_judge_reader_free(struct w2_judge_reader *r);
/* Returns 1 with a complete frame, 2 after consuming a fragment of an incomplete frame, 0 when the socket would block,
 * -1 when the reader died (EPROTO). */
int w2_judge_receive(struct w2_judge_reader *r,int fd,uid_t expected,uid_t overflow,
                     unsigned char *out,size_t cap,size_t *length,int *rights_fd);
/* v2 connector, link A (SPEC §2; validation.md C-06, C-07): what the reader knows about the frame in progress.
 * *declared is the frame's declared length once the header is in (0 before), *kind the first body byte once it
 * arrived (-1 before), so the caller can refuse an unknown kind or an over-budget body before the rest is read. */
void w2_judge_peek(const struct w2_judge_reader *r,size_t *declared,int *kind);
/* v2 connector, link A (实施注意 2; C-03): whether a descriptor arrived with a fragment of the frame in progress, so the
 * proxy path can refuse it before the frame completes; the reader's free closes it. */
bool w2_judge_rights_held(const struct w2_judge_reader *r);
#endif
