#ifndef W2_TRANSPORT_H
#define W2_TRANSPORT_H
#include "support.h"
#include <sys/socket.h>
/* Nonblocking return convention: >0 bytes, 0 EOF, -2 retry, -1 fatal.
 * Unexpected received rights are always closed, including a truncated record. */
ssize_t w2_recv_control(int fd,char *out,size_t cap,int *owned_fd);
ssize_t w2_recv_credential(int fd,void *out,size_t cap,uid_t expected,pid_t child,uid_t overflow);
int w2_ancillary(struct msghdr *msg,bool credentials,uid_t expected,pid_t child,
                 uid_t overflow,bool early_failure,int *owned_fd);
int w2_validate_channel(int fd);
json_t *w2_control_parse(const char *wire,size_t length);
int w2_send_control(int fd,const char *wire,size_t length,int attached_fd);
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
#endif
