#define _GNU_SOURCE
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>

#define KEYS(j,...) w2_keys((j),(const char *const[]){__VA_ARGS__},sizeof((const char *const[]){__VA_ARGS__})/sizeof(char *))
static bool eq(json_t *j,const char *key,const char *s) {const char *v=w2_str(j,key);return v&&!strcmp(v,s);}
static bool uint_field(json_t *j,const char *key,uint64_t max) {
    json_t *n=json_object_get(j,key);return json_is_integer(n)&&json_integer_value(n)>=0&&(uint64_t)json_integer_value(n)<=max;
}
static bool stage(json_t *j,const char *key) {
    const char *s=w2_str(j,key);if(!s)return false;
    for(unsigned i=1;i<=W2_STAGE_REAP;++i)if(!strcmp(s,w2_stage_name((enum w2_stage)i)))return true;
    return false;
}
static bool one_of(json_t *j,const char *key,const char *const *values,size_t n) {
    for(size_t i=0;i<n;++i)if(eq(j,key,values[i]))return true;
    return false;
}
json_t *w2_control_parse(const char *wire,size_t n) {
    if(n>W2_CONTROL_MAX)return NULL;
    json_t *j=w2_json(wire,n);uint64_t value;
    if(!j)return NULL;
    const char *type=w2_str(j,"type"),*epoch=w2_str(j,"engine_epoch");
    if(!uint_field(j,"v",1)||json_integer_value(json_object_get(j,"v"))!=1||!type||
       !epoch||strlen(epoch)!=32||!w2_decimal(w2_str(j,"seq"),&value,true))goto bad;
    for(size_t i=0;i<32;++i)if(!strchr("0123456789abcdef",epoch[i]))goto bad;
    if(!strcmp(type,"control_init")||!strcmp(type,"control_ready")) {
        if(!KEYS(j,"v","type","engine_epoch","seq","catalog_digest","protocol","runtime_storage_protocol","storage_profile_digest")||
           !w2_is_digest(w2_str(j,"catalog_digest"))||!eq(j,"protocol",W2_DATA_PROTOCOL)||
           !eq(j,"runtime_storage_protocol",W2_STORAGE_PROTOCOL)||!w2_is_digest(w2_str(j,"storage_profile_digest")))goto bad;
        return j;
    }
    const char *id=w2_str(j,"execution_id"),*lease=w2_str(j,"lease_id");
    if(!w2_is_id(id)||!w2_is_id(lease)||strlen(id)<34||strncmp(id,epoch,32)||id[32]!=':'||
       !w2_decimal(id+33,&value,true))goto bad;
    char wanted[W2_ID_CAP];int count=snprintf(wanted,sizeof wanted,"%s:u",id);
    if(count<0||(size_t)count>=sizeof wanted||strcmp(lease,wanted))goto bad;
    if(!strcmp(type,"spawn")) {
        if(!KEYS(j,"v","type","engine_epoch","seq","execution_id","lease_id","uid","gid",
           "launch_plan_id","launch_plan_digest","startup_deadline_ns")||
           !uint_field(j,"uid",UINT32_MAX-1)||!uint_field(j,"gid",UINT32_MAX-1)||
           !json_integer_value(json_object_get(j,"uid"))||!json_integer_value(json_object_get(j,"gid"))||
           !w2_is_id(w2_str(j,"launch_plan_id"))||!w2_is_digest(w2_str(j,"launch_plan_digest"))||
           !w2_decimal(w2_str(j,"startup_deadline_ns"),&value,true))goto bad;
    } else if(!strcmp(type,"spawn_prepared")) {
        if(!KEYS(j,"v","type","engine_epoch","seq","execution_id","lease_id","launch_plan_digest",
           "policy_digest","isolation_profile_digest","child_pid","sealed","copy_id")||
           !w2_is_digest(w2_str(j,"launch_plan_digest"))||!w2_is_digest(w2_str(j,"policy_digest"))||
           !w2_is_digest(w2_str(j,"isolation_profile_digest"))||!uint_field(j,"child_pid",INT32_MAX)||
           !json_integer_value(json_object_get(j,"child_pid"))||!json_is_true(json_object_get(j,"sealed")))goto bad;
        snprintf(wanted,sizeof wanted,"%s:r",id);if(!eq(j,"copy_id",wanted))goto bad;
    } else if(!strcmp(type,"runtime_status")) {
        const char *const reasons[]={"none","create_failed","delete_failed","job_timeout","worker_lost","identity_mismatch","control_lost"};
        if(!KEYS(j,"v","type","engine_epoch","seq","execution_id","lease_id","copy_id","state","basis","reason","attempt","os_errno")||
           !one_of(j,"reason",reasons,7)||!uint_field(j,"attempt",3))goto bad;
        snprintf(wanted,sizeof wanted,"%s:r",id);if(!eq(j,"copy_id",wanted))goto bad;
        bool no_errno=json_is_null(json_object_get(j,"os_errno"));unsigned attempt=(unsigned)json_integer_value(json_object_get(j,"attempt"));
        if(!no_errno&&(!uint_field(j,"os_errno",4095)||!json_integer_value(json_object_get(j,"os_errno"))))goto bad;
        if(eq(j,"state","released")) {
            if(!eq(j,"reason","none")||!no_errno||
               !((eq(j,"basis","not_materialized")&&!attempt)||(eq(j,"basis","tree_removed")&&attempt)))goto bad;
        } else if(!eq(j,"state","retained")||!eq(j,"basis","unconfirmed")||eq(j,"reason","none"))goto bad;
    } else if(!strcmp(type,"spawn_failed")) {
        const char *const codes[]={"invalid_spec","resource_exhausted","os_error","protocol_error","timeout","control_lost"};
        if(!KEYS(j,"v","type","engine_epoch","seq","execution_id","lease_id","stage","error_code","os_errno")||
           !stage(j,"stage")||!one_of(j,"error_code",codes,6)||
           (!json_is_null(json_object_get(j,"os_errno"))&&!uint_field(j,"os_errno",UINT32_MAX)))goto bad;
    } else if(!strcmp(type,"stop")) {
        const char *const reasons[]={"normal","timeout","protocol_error","startup_error","control_shutdown"};
        if(!KEYS(j,"v","type","engine_epoch","seq","execution_id","lease_id","reason")||!one_of(j,"reason",reasons,5))goto bad;
    } else if(!strcmp(type,"execution_empty")) {
        if(!KEYS(j,"v","type","engine_epoch","seq","execution_id","lease_id","basis","exit_code","signal","last_stage")||!stage(j,"last_stage"))goto bad;
        bool x=json_is_null(json_object_get(j,"exit_code")),s=json_is_null(json_object_get(j,"signal"));
        if(eq(j,"basis","never_created")) {if(!x||!s)goto bad;}
        else if(eq(j,"basis","pid1_reaped")) {
            if(x==s||(!x&&!uint_field(j,"exit_code",255))||(!s&&(!uint_field(j,"signal",64)||!json_integer_value(json_object_get(j,"signal")))))goto bad;
        } else goto bad;
    } else goto bad;
    return j;
bad:json_decref(j);return NULL;
}
int w2_ancillary(struct msghdr *m,bool credentials,uid_t expected,pid_t child,
                 uid_t overflow,bool early_failure,int *owned_fd) {
    int rights[256];size_t nrights=0,ncred=0;bool invalid=false;struct ucred cred={0};
    unsigned char *base=m->msg_control;size_t offset=0;
    /* Walk only complete in-buffer headers; collect rights even if other
     * headers/flags already make the message invalid. Never trust cmsg_len. */
    while(offset+sizeof(struct cmsghdr)<=m->msg_controllen) {
        struct cmsghdr h;memcpy(&h,base+offset,sizeof h);
        size_t remaining=m->msg_controllen-offset;
        if(h.cmsg_len<CMSG_LEN(0)||h.cmsg_len>remaining){invalid=true;break;}
        size_t bytes=h.cmsg_len-CMSG_LEN(0);unsigned char *data=base+offset+CMSG_LEN(0);
        if(h.cmsg_level==SOL_SOCKET&&h.cmsg_type==SCM_RIGHTS) {
            if(bytes%sizeof(int))invalid=true;
            for(size_t i=0;i+sizeof(int)<=bytes;i+=sizeof(int)) {
                int fd;memcpy(&fd,data+i,sizeof fd);
                if(nrights<256)rights[nrights++]=fd;else {close(fd);invalid=true;}
            }
        } else if(h.cmsg_level==SOL_SOCKET&&h.cmsg_type==SCM_CREDENTIALS) {
            ++ncred;
            if(bytes!=sizeof cred)invalid=true;else memcpy(&cred,data,sizeof cred);
        } else invalid=true;
        size_t step=CMSG_ALIGN(h.cmsg_len);
        if(step>remaining){offset=m->msg_controllen;break;}offset+=step;
    }
    if(m->msg_flags&(MSG_TRUNC|MSG_CTRUNC|MSG_OOB))invalid=true;
    if(credentials) {
        if(nrights||ncred!=1||cred.pid<=0||(child>0&&cred.pid!=child)||
           (!early_failure&&(cred.uid==0||cred.uid==overflow||cred.uid==(uid_t)-1||cred.uid!=expected)))invalid=true;
    } else if(ncred||nrights>1)invalid=true;
    if(invalid||credentials) {
        for(size_t i=0;i<nrights;++i)close(rights[i]);
    } else if(nrights==1)*owned_fd=rights[0];
    if(invalid){errno=EPROTO;return -1;}return 0;
}
int w2_validate_channel(int fd) {
    int value;socklen_t size=sizeof value;struct sockaddr_un local,peer;
    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&value,&size)||value!=SOCK_STREAM)return -1;
    size=sizeof value;if(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&value,&size)||value!=AF_UNIX)return -1;
    size=sizeof value;if(getsockopt(fd,SOL_SOCKET,SO_PASSCRED,&value,&size)||value!=1)return -1;
    socklen_t l=sizeof local,p=sizeof peer;
    if(getsockname(fd,(struct sockaddr *)&local,&l)||getpeername(fd,(struct sockaddr *)&peer,&p)||
       l!=sizeof(sa_family_t)||p!=sizeof(sa_family_t)||local.sun_family!=AF_UNIX||peer.sun_family!=AF_UNIX)return -1;
    int flags=fcntl(fd,F_GETFD);if(flags<0||!(flags&FD_CLOEXEC))return -1;
    return w2_nonblock(fd);
}
ssize_t w2_recv_control(int fd,char *out,size_t cap,int *owned_fd) {
    if(!out||cap<W2_CONTROL_MAX||!owned_fd){errno=EINVAL;return -1;}*owned_fd=-1;
    union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(256*sizeof(int))+CMSG_SPACE(sizeof(struct ucred))];} control;
    struct iovec iov={out,W2_CONTROL_MAX};
    struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof control.bytes};
    ssize_t n=recvmsg(fd,&m,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
    if(n<0)return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR?-2:-1;
    if(w2_ancillary(&m,false,0,0,0,false,owned_fd))return -1;
    json_t *j=n>0?w2_control_parse(out,(size_t)n):NULL;
    bool prepared=j&&eq(j,"type","spawn_prepared");
    if(!j||prepared!=(*owned_fd>=0)||(prepared&&w2_validate_channel(*owned_fd))) {
        if(*owned_fd>=0){close(*owned_fd);*owned_fd=-1;}
        json_decref(j);errno=EPROTO;return n==0?0:-1;
    }
    json_decref(j);return n;
}
ssize_t w2_recv_credential(int fd,void *out,size_t cap,uid_t expected,pid_t child,uid_t overflow) {
    union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(256*sizeof(int))];} control;
    struct iovec iov={out,cap};struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof control.bytes};
    ssize_t n=recvmsg(fd,&m,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
    if(n<0)return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR?-2:-1;
    int rights=-1;
    if(n==0) { /* No valid byte => no frame; still close any delivered rights. */
        (void)w2_ancillary(&m,true,expected,child,overflow,false,&rights);return 0;
    }
    if(w2_ancillary(&m,true,expected,child,overflow,false,&rights))return -1;
    return n;
}
int w2_send_control(int fd,const char *wire,size_t n,int attached) {
    union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(int))];} control;
    struct iovec iov={(void *)wire,n};struct msghdr m={.msg_iov=&iov,.msg_iovlen=1};
    if(attached>=0) {
        memset(&control,0,sizeof control);m.msg_control=control.bytes;m.msg_controllen=sizeof control.bytes;
        struct cmsghdr *h=CMSG_FIRSTHDR(&m);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;h->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(h),&attached,sizeof attached);
    }
    ssize_t sent=sendmsg(fd,&m,MSG_NOSIGNAL|MSG_DONTWAIT);
    if(sent<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    return sent==(ssize_t)n?1:-1;
}
static int wait_for(int fd,short events,uint64_t deadline) {
    uint64_t now=w2_now();if(!now||now>=deadline){errno=ETIMEDOUT;return -1;}
    uint64_t ms=(deadline-now+999999)/1000000;if(ms>1000)ms=1000;
    struct pollfd p={.fd=fd,.events=events|POLLPRI};int n=poll(&p,1,(int)ms);
    if(n<0&&errno==EINTR)return 0;
    if(n<0||p.revents&POLLPRI){errno=EPROTO;return -1;}return 0;
}
int w2_send_fixed(int fd,const void *wire,size_t n,uint64_t deadline) {
    size_t offset=0;
    while(offset<n) {
        if(w2_now()>=deadline){errno=ETIMEDOUT;return -1;}
        ssize_t sent=send(fd,(const char *)wire+offset,n-offset,MSG_NOSIGNAL|MSG_DONTWAIT);
        if(sent>0){offset+=(size_t)sent;continue;}
        if(sent<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)){if(wait_for(fd,POLLOUT,deadline))return -1;continue;}
        return -1;
    }
    return 0;
}
int w2_recv_fixed(int fd,void *wire,size_t n,uint64_t deadline) {
    size_t offset=0;
    while(offset<n) {
        if(w2_now()>=deadline){errno=ETIMEDOUT;return -1;}
        union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(256*sizeof(int))];} control;
        struct iovec iov={(char *)wire+offset,n-offset};
        struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof control.bytes};
        ssize_t got=recvmsg(fd,&m,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
        if(got<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)){if(wait_for(fd,POLLIN,deadline))return -1;continue;}
        if(got<=0)return -1;
        int rights=-1;
        if(w2_ancillary(&m,false,0,0,0,false,&rights))return -1;
        if(rights>=0){close(rights);errno=EPROTO;return -1;}
        offset+=(size_t)got;
    }
    return 0;
}
struct w2_frame_reader *w2_reader_new(void){return calloc(1,sizeof(struct w2_frame_reader));}
void w2_reader_free(struct w2_frame_reader *r){free(r);}
int w2_frame_receive(struct w2_frame_reader *r,int fd,uid_t expected,uid_t overflow,
                     unsigned char *out,size_t cap,size_t *length) {
    if(!r||r->dead||cap<W2_BODY_MAX||!out||!length){errno=EINVAL;return -1;}
    uint64_t cookie=0;socklen_t cookie_size=sizeof cookie;
    if(getsockopt(fd,SOL_SOCKET,SO_COOKIE,&cookie,&cookie_size)||cookie_size!=sizeof cookie)goto bad;
    if(r->bound&&(r->fd!=fd||r->cookie!=cookie||r->expected!=expected||r->overflow!=overflow))goto bad;
    if(!r->bound){r->bound=true;r->fd=fd;r->cookie=cookie;r->expected=expected;r->overflow=overflow;}
    struct pollfd urgent={.fd=fd,.events=POLLPRI};
    if(poll(&urgent,1,0)<0&&errno!=EINTR)goto bad;
    if(urgent.revents&POLLPRI)goto bad;
    if(r->used&&w2_now()>=r->deadline)goto bad;
    if(!r->needed)r->needed=4;
    ssize_t n=w2_recv_credential(fd,r->wire+r->used,r->needed-r->used,expected,0,overflow);
    if(n==-2)return 0;
    if(n<=0)goto bad;
    uint64_t received_at=w2_now();
    if(!r->used)r->deadline=received_at+UINT64_C(5000000000);
    else if(received_at>=r->deadline)goto bad;
    r->used+=(size_t)n;
    if(r->used<r->needed)return 0;
    if(r->needed==4) {
        uint32_t size=(uint32_t)r->wire[0]<<24|(uint32_t)r->wire[1]<<16|(uint32_t)r->wire[2]<<8|r->wire[3];
        if(!size||size>W2_BODY_MAX)goto bad;
        r->needed=4+size;return 0;
    }
    if(w2_now()>=r->deadline)goto bad;
    *length=r->used-4;memcpy(out,r->wire+4,*length);r->used=r->needed=0;r->deadline=0;return 1;
bad:r->dead=true;errno=EPROTO;return -1;
}
int w2_frame_queue(struct w2_frame_writer *w,const void *body,size_t n,uint64_t deadline) {
    if(!w||w->dead||w->size||!body||!n||n>W2_BODY_MAX||deadline<=w2_now())return -1;
    json_t *j=w2_frame_json(body,n);if(!j)return -1;json_decref(j);
    w->wire[0]=(unsigned char)(n>>24);w->wire[1]=(unsigned char)(n>>16);w->wire[2]=(unsigned char)(n>>8);w->wire[3]=(unsigned char)n;
    memcpy(w->wire+4,body,n);w->size=n+4;w->used=0;w->deadline=deadline;return 0;
}
int w2_frame_send(struct w2_frame_writer *w,int fd) {
    if(!w||w->dead)return -1;
    if(!w->size)return 1;
    uint64_t cookie=0;socklen_t cookie_size=sizeof cookie;
    if(getsockopt(fd,SOL_SOCKET,SO_COOKIE,&cookie,&cookie_size)||cookie_size!=sizeof cookie||
       (w->bound&&(w->fd!=fd||w->cookie!=cookie))){w->dead=true;return -1;}
    if(!w->bound){w->bound=true;w->fd=fd;w->cookie=cookie;}
    if(w2_now()>=w->deadline){w->dead=true;return -1;}
    ssize_t n=send(fd,w->wire+w->used,w->size-w->used,MSG_NOSIGNAL|MSG_DONTWAIT);
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    if(n<=0){w->dead=true;return -1;}
    w->used+=(size_t)n;if(w->used<w->size)return 0;
    w->used=w->size=0;return 1;
}
