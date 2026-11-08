#define _GNU_SOURCE
/* The in-cell pty relay (agent-rm-model 3.3 对话通道, 4.1 对话通道的 pty 转发进程; build plan 工程项 9; validation.md F-05,
 * S-07, S-08, S-18). Not in the TCB: it runs inside the cell as uid_i under the agent's seccomp policy, started by the
 * child before the agent (child.c start_helper) with fd 3 = the master of the agent's pty and fd 4 = the row's attach
 * listening socket (bound by the spawner in the engine's rows directory, reachable only by the engine uid), stdio on
 * /dev/null and nothing else open.
 *
 * It copies bytes both ways and parses nothing of the terminal stream. On the attach socket it speaks a small framing
 * (SPEC-canonical-form.md §3.5): client → relay  kind 1 input bytes (written to the master as they are; a 0x03 is a
 * Ctrl-C for the line discipline), kind 2 resize (rows u16be, cols u16be → TIOCSWINSZ on the master, the kernel then
 * sends SIGWINCH to the foreground group); relay → client  kind 1 output bytes. One attached client at a time: a
 * second connection is accepted and closed at once. With no client attached the master is still drained so the agent
 * never blocks on its terminal. The relay exits when the slave side is gone (read on the master returns EIO or EOF) or
 * when the listener is closed under it.
 *
 * Exit codes keep the block-1 stub's contract: 3 fd 3 is not a pty master, 4 fd 4 is not a listening unix stream
 * socket, 5 another descriptor is open. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#define MASTER 3
#define LISTENER 4
#define FRAME_MAX 65536u
#define BUFFER 16384u

static int sockopt(int fd,int option) {int value=-1;socklen_t size=sizeof value;return getsockopt(fd,SOL_SOCKET,option,&value,&size)?-1:value;}

static int write_all(int fd,const unsigned char *p,size_t n) {
    while(n) {
        ssize_t w=write(fd,p,n);
        if(w<0){if(errno==EINTR)continue;return -1;}
        p+=(size_t)w;n-=(size_t)w;
    }
    return 0;
}

/* To the client socket with MSG_NOSIGNAL: a client that has gone away is an EPIPE and is dropped, never a SIGPIPE that
 * would end the relay and close the row's attach listener with it. */
static int send_all(int fd,const unsigned char *p,size_t n) {
    while(n) {
        ssize_t w=send(fd,p,n,MSG_NOSIGNAL);
        if(w<0){if(errno==EINTR)continue;return -1;}
        p+=(size_t)w;n-=(size_t)w;
    }
    return 0;
}

/* A frame to the client: kind 1, u32be length, bytes. */
static int send_output(int client,const unsigned char *p,size_t n) {
    unsigned char head[5]={1,(unsigned char)(n>>24),(unsigned char)(n>>16),(unsigned char)(n>>8),(unsigned char)n};
    return send_all(client,head,5)||send_all(client,p,n);
}

/* Frames from the client, parsed from a growing buffer. Returns -1 when the client must be dropped. */
static int handle_client_bytes(unsigned char *buf,size_t *used) {
    for(;;) {
        if(*used<5)return 0;
        unsigned kind=buf[0];uint32_t n=(uint32_t)buf[1]<<24|(uint32_t)buf[2]<<16|(uint32_t)buf[3]<<8|buf[4];
        if(n>FRAME_MAX)return -1;
        if(*used<5+n)return 0;
        if(kind==1) {
            if(n&&write_all(MASTER,buf+5,n))return -1;
        } else if(kind==2) {
            if(n!=4)return -1;
            struct winsize ws={0};ws.ws_row=(unsigned short)(buf[5]<<8|buf[6]);ws.ws_col=(unsigned short)(buf[7]<<8|buf[8]);
            if(ioctl(MASTER,TIOCSWINSZ,&ws))return -1;
        } else return -1;
        memmove(buf,buf+5+n,*used-5-n);*used-=5+n;
    }
}

int main(void) {
    unsigned pty_number;
    if(ioctl(MASTER,TIOCGPTN,&pty_number))return 3;
    if(sockopt(LISTENER,SO_DOMAIN)!=AF_UNIX||sockopt(LISTENER,SO_TYPE)!=SOCK_STREAM||sockopt(LISTENER,SO_ACCEPTCONN)!=1)return 4;
    for(int fd=5;fd<64;++fd)if(fcntl(fd,F_GETFD)>=0)return 5;
    int client=-1;unsigned char out[BUFFER],in[5+FRAME_MAX];size_t in_used=0;
    for(;;) {
        struct pollfd fds[3]={{MASTER,POLLIN,0},{LISTENER,POLLIN,0},{client,client>=0?POLLIN:0,0}};
        int ready=poll(fds,3,-1);
        if(ready<0){if(errno==EINTR)continue;return 0;}
        if(fds[0].revents&(POLLIN|POLLHUP|POLLERR)) {
            ssize_t n=read(MASTER,out,sizeof out);
            if(n<0&&errno==EINTR)continue;
            if(n<=0)return 0;                                  /* EIO or EOF: the slave side is gone (F-05) */
            if(client>=0&&send_output(client,out,(size_t)n)){close(client);client=-1;in_used=0;}
        }
        int fresh=0;
        if(fds[1].revents&(POLLIN|POLLERR|POLLHUP)) {
            int accepted=accept4(LISTENER,NULL,NULL,SOCK_CLOEXEC);
            if(accepted<0){if(errno==EINTR||errno==EAGAIN||errno==ECONNABORTED)continue;return 0;}
            if(client>=0)close(accepted);                       /* one at a time (F-05, engineering default) */
            else{client=accepted;fresh=1;}
        }
        /* fds[2] describes the client polled this round; a client accepted just now waits for the next poll */
        if(client>=0&&!fresh&&(fds[2].revents&(POLLIN|POLLHUP|POLLERR))) {
            ssize_t n=read(client,in+in_used,sizeof in-in_used);
            if(n<0&&errno==EINTR)continue;
            if(n<=0||(in_used+=(size_t)n,handle_client_bytes(in,&in_used))){close(client);client=-1;in_used=0;continue;}
            if(in_used==sizeof in){close(client);client=-1;in_used=0;}   /* a frame that never completes */
        }
    }
}
