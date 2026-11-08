#define _GNU_SOURCE
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { if(!(x)){fprintf(stderr,"CHECK failed %s:%d: %s errno=%d\n",__FILE__,__LINE__,#x,errno);exit(1);} }while(0)
/* Only the time following a real positive recvmsg is controlled. The production
 * ancillary parser still validates the kernel's actual SCM_CREDENTIALS. */
static bool controlled_clock;
static uint64_t clock_value,after_receive;
static int armed_fd=-1;
static unsigned observed_receives;
uint64_t __real_w2_now(void);
uint64_t __wrap_w2_now(void) {return controlled_clock?clock_value:__real_w2_now();}
ssize_t __real_recvmsg(int fd,struct msghdr *msg,int flags);
ssize_t __wrap_recvmsg(int fd,struct msghdr *msg,int flags) {
    ssize_t n=__real_recvmsg(fd,msg,flags);
    if(fd==armed_fd&&n>0){clock_value=after_receive;armed_fd=-1;++observed_receives;}
    return n;
}
static void pair(int fds[2],bool cred) {
    CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,fds)==0);
    int one=1;if(cred)CHECK(setsockopt(fds[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof one)==0);
}
static void json_checks(void) {
    const char *bad[]={"{\"x\":1,\"x\":2}","{\"x\":NaN}","{\"x\":1.5}",
        "{\"x\":\"\\u0000\"}","{\"x\":\"\xff\"}","{} {}","[]","{\"x\":1e9}"};
    for(size_t i=0;i<sizeof bad/sizeof bad[0];++i)CHECK(w2_json(bad[i],strlen(bad[i]))==NULL);
    json_t *good=w2_json("{\"x\":\"中文\"}",strlen("{\"x\":\"中文\"}"));CHECK(good);json_decref(good);
    uint64_t n;CHECK(w2_decimal("18446744073709551615",&n,true)&&n==UINT64_MAX);
    CHECK(!w2_decimal("18446744073709551616",&n,true));CHECK(!w2_decimal("01",&n,true));
    uid_t u;gid_t g;
    CHECK(!w2_environment_values(" 0 0 4294967295\n","65534\n","65534\n","1\n","0\n",&u,&g));
    CHECK(w2_environment_values("0 1000 1\n","65534","65534","1","0",&u,&g)<0);
    CHECK(w2_environment_values("0 0 4294967295","65534","65534","0","0",&u,&g)<0);
    CHECK(w2_environment_values("0 0 4294967295","65534","65534","1","1",&u,&g)<0);
    CHECK(w2_environment_values("0 0 4294967295","0","65534","1","0",&u,&g)<0);
    puts("strict JSON, uint64 and deployment precondition negatives passed");
}
static void synthetic_ancillary(void) {
    union {struct cmsghdr align;unsigned char bytes[2*CMSG_SPACE(sizeof(struct ucred))];} buffer;
    for(int kind=0;kind<6;++kind) {
        memset(&buffer,0,sizeof buffer);struct msghdr msg={.msg_control=buffer.bytes,.msg_controllen=CMSG_SPACE(sizeof(struct ucred))};
        struct cmsghdr *h=CMSG_FIRSTHDR(&msg);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_CREDENTIALS;h->cmsg_len=CMSG_LEN(sizeof(struct ucred));
        struct ucred cred={.pid=getpid(),.uid=getuid(),.gid=getgid()};
        if(kind==0)cred.uid=0;
        if(kind==1)cred.uid=65534;
        if(kind==2)cred.pid=0;
        if(kind==3)msg.msg_flags=MSG_CTRUNC;
        memcpy(CMSG_DATA(h),&cred,sizeof cred);
        if(kind==4){memcpy(buffer.bytes+CMSG_SPACE(sizeof cred),buffer.bytes,CMSG_SPACE(sizeof cred));msg.msg_controllen=sizeof buffer.bytes;}
        if(kind==5)h->cmsg_len=CMSG_LEN(sizeof cred)-1;
        int fd=-1;CHECK(w2_ancillary(&msg,true,getuid(),0,65534,false,&fd)<0);
    }
    puts("synthetic missing/truncated/duplicate/sentinel credentials rejected (not kernel-generated evidence)");
}
static void actual_ancillary(void) {
    int fds[2];char byte;pair(fds,false);CHECK(send(fds[1],"x",1,0)==1);
    CHECK(w2_recv_credential(fds[0],&byte,1,getuid(),0,65534)<0);close(fds[0]);close(fds[1]);
    pair(fds,true);CHECK(send(fds[1],"x",1,0)==1);
    CHECK(w2_recv_credential(fds[0],&byte,1,getuid()+1,0,65534)<0);close(fds[0]);close(fds[1]);
    pair(fds,true);int source=open("/dev/null",O_RDONLY|O_CLOEXEC);CHECK(source>=0);
    union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(int))];} c={0};
    struct iovec iov={(void *)"x",1};struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=c.bytes,.msg_controllen=sizeof c.bytes};
    struct cmsghdr *h=CMSG_FIRSTHDR(&msg);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;h->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(h),&source,sizeof source);
    CHECK(sendmsg(fds[1],&msg,0)==1);
    int before=dup(source);CHECK(before>=0);close(before);
    CHECK(w2_recv_credential(fds[0],&byte,1,getuid(),0,65534)<0);
    int after=dup(source);CHECK(after==before);close(after);close(source);close(fds[0]);close(fds[1]);
    puts("actual missing credentials, wrong expected uid, unexpected rights reject and descriptor cleanup passed");
}
static void receive_deadline_boundaries(void) {
    const unsigned char message[]={0,0,0,2,'{','}'};
    const char *names[]={"partial-header","complete-header","partial-body","complete-body"};
    for(unsigned kind=0;kind<4;++kind)for(int delta=-1;delta<=1;++delta) {
        int fds[2];pair(fds,true);struct w2_frame_reader r={0};
        unsigned char out[W2_BODY_MAX]={0};size_t size=0;
        controlled_clock=true;clock_value=UINT64_C(10000000000);
        size_t initial=kind<2?1:4;
        CHECK(send(fds[1],message,initial,0)==(ssize_t)initial);
        CHECK(w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size)==0);
        uint64_t deadline=r.deadline;
        CHECK(deadline==clock_value+UINT64_C(5000000000));
        if(kind==3) {
            CHECK(send(fds[1],message+4,1,0)==1);
            CHECK(w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size)==0);
            ++initial;CHECK(r.deadline==deadline);
        }
        size_t fragment=kind==1?3:1;
        CHECK(send(fds[1],message+initial,fragment,0)==(ssize_t)fragment);
        clock_value=deadline-1;after_receive=delta<0?deadline-1:deadline+(uint64_t)delta;
        armed_fd=fds[0];unsigned before=observed_receives;
        int result=w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size);
        CHECK(observed_receives==before+1&&armed_fd==-1);
        if(delta>=0) {
            CHECK(result==-1&&errno==EPROTO&&r.dead);
            CHECK(r.used==initial&&r.deadline==deadline&&size==0&&out[0]==0);
            CHECK(w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size)==-1);
        } else {
            CHECK(!r.dead&&result==(kind==3));
            if(kind!=3) {
                CHECK(r.deadline==deadline);
                size_t offset=initial+fragment;
                CHECK(send(fds[1],message+offset,sizeof message-offset,0)==(ssize_t)(sizeof message-offset));
                for(unsigned attempt=0;attempt<3&&result==0;++attempt)
                    result=w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size);
            }
            CHECK(result==1&&size==2&&!memcmp(out,"{}",2)&&!r.deadline);
        }
        printf("receive_deadline_boundary phase=%s delta_ns=%d actual_receives=1 deadline_ns=%" PRIu64 " rejected=%d\n",
               names[kind],delta,deadline,delta>=0);
        close(fds[0]);close(fds[1]);controlled_clock=false;
    }
}
static void frame_checks(void) {
    int fds[2];unsigned char out[W2_BODY_MAX];size_t size=0;
    pair(fds,true);struct w2_frame_reader r={0};
    const unsigned char message[]={0,0,0,2,'{','}'};
    for(size_t i=0;i<sizeof message;++i){CHECK(send(fds[1],message+i,1,0)==1);int got=w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size);CHECK(got==(i+1==sizeof message));}
    CHECK(size==2&&!memcmp(out,"{}",2));
    CHECK(send(fds[1],message,2,0)==2);CHECK(!w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size));
    close(fds[1]);CHECK(w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size)<0);close(fds[0]);
    pair(fds,true);memset(&r,0,sizeof r);CHECK(send(fds[1],message,1,0)==1);
    CHECK(!w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size));r.deadline=w2_now()-1;
    CHECK(w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size)<0);close(fds[0]);close(fds[1]);
    pair(fds,true);memset(&r,0,sizeof r);unsigned char large[4]={0,1,0,1};CHECK(send(fds[1],large,4,0)==4);
    CHECK(w2_frame_receive(&r,fds[0],getuid(),65534,out,sizeof out,&size)<0);close(fds[0]);close(fds[1]);
    pair(fds,false);int small=4096;CHECK(!setsockopt(fds[1],SOL_SOCKET,SO_SNDBUF,&small,sizeof small));
    unsigned char body[W2_BODY_MAX];memset(body,' ',sizeof body);body[0]='{';body[sizeof body-1]='}';
    struct w2_frame_writer w={0};CHECK(!w2_frame_queue(&w,body,sizeof body,w2_now()+UINT64_C(5000000000)));
    CHECK(!w2_frame_send(&w,fds[1]));size_t offset=w.used;CHECK(offset>0&&offset<w.size);
    CHECK(!w2_frame_send(&w,fds[1]));CHECK(w.used==offset);
    unsigned char wire[W2_FRAME_MAX];size_t received=0;
    for(size_t turn=0;turn<1000&&received<sizeof wire;++turn) {
        ssize_t n=recv(fds[0],wire+received,sizeof wire-received,MSG_DONTWAIT);
        if(n>0)received+=(size_t)n;
        CHECK(w2_frame_send(&w,fds[1])>=0);
    }
    CHECK(received==sizeof wire&&!memcmp(wire+4,body,sizeof body));
    CHECK(wire[0]==0&&wire[1]==1&&wire[2]==0&&wire[3]==0);
    close(fds[0]);close(fds[1]);
    puts("fragmented header/body, EOF, fixed deadline, oversize, max-body short-write/EAGAIN offset checks passed");
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--environment")){
        uid_t u;gid_t g;int rejected=w2_environment(&u,&g)!=0;
        char bytes[128]={0};int fd=open("/proc/self/uid_map",O_RDONLY|O_CLOEXEC);
        if(fd>=0){ssize_t n=read(fd,bytes,sizeof bytes-1);if(n>=0)bytes[n]=0;close(fd);}
        printf("environment_check rejected=%d uid_map=%s\n",rejected,bytes);return rejected?1:0;
    }
    CHECK(getuid()!=0);json_checks();synthetic_ancillary();actual_ancillary();frame_checks();receive_deadline_boundaries();return 0;
}
