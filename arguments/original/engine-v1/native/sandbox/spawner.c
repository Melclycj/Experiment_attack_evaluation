#define _GNU_SOURCE
#include "spawner.h"
#include "transport.h"
#include "storage.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct spawn_record {
    bool used,failed,failed_sent,sealed,prepared,empty,empty_sent,stopping,all_expected;
    bool pid_owned,copy_reserved,create_submitted,creation_finished,copy_ready,root_known;
    bool copy_released,copy_retained,copy_pending,copy_sent,delete_pending,root_removed;
    char execution[W2_ID_CAP],lease[W2_ID_CAP];
    struct w2_plan *plan;uid_t uid;gid_t gid;pid_t pid;
    int channel,status,os_errno;enum w2_stage stage;const char *error;
    unsigned char bootstrap[16];size_t received;uint64_t deadline;
    char copy[W2_COPY_CAP];uint64_t root_dev,root_ino,job,cleanup_deadline,retry_at;
    unsigned attempt;const char *copy_basis,*copy_reason;int copy_errno;
    uint64_t copy_generation;
};
struct history {uint64_t seq;char *wire;size_t size;};
struct terminal {
    char execution[W2_ID_CAP],lease[W2_ID_CAP];
    bool pid1_reaped;int wait_status;enum w2_stage last_stage;
    const char *copy_basis;unsigned cleanup_attempt;
};
struct loop {
    struct w2_catalog *catalog;int control;char epoch[W2_EPOCH_CAP];bool ready,ready_sent,lost;
    uint64_t incoming,outgoing,blocked_since,closing_since;
    uint64_t last_execution;
    struct spawn_record records[W2_EXECUTIONS_MAX];
    struct history history[1024];size_t history_next;
    struct terminal terminal[1024];size_t terminal_next;
    char *output;size_t output_size;struct spawn_record *owner;int output_kind;
    struct w2_store store;uint64_t reserved_bytes,reserved_nodes,worker_closing,worker_killed;
    size_t output_cursor,job_cursor;bool admission_blocked;
    uint64_t output_generation;bool output_released;
};
struct child_args {struct w2_plan *plan;struct w2_catalog *catalog;int channel,other,control,worker;char root[W2_PATH_CAP],source[W2_PATH_CAP],copy[W2_COPY_CAP];uint64_t deadline,dev,ino;};
static int child_entry(void *ptr) {
    struct child_args *a=ptr;close(a->other);close(a->control);close(a->worker);close(a->catalog->storage.lock_fd);
    return w2_child_launch(a->plan,a->channel,a->catalog->instances_fd,a->catalog->root_fd,a->copy,a->dev,a->ino,a->root,a->source,a->catalog->root,a->deadline);
}
static void fail_record(struct spawn_record *r,enum w2_stage stage,const char *error,int number) {
    if(!r->failed){r->failed=true;r->stage=stage;r->error=error;r->os_errno=number;}
    r->stopping=true;
    if(r->channel>=0){close(r->channel);r->channel=-1;}
    if(!r->pid)r->empty=true;
}
static struct spawn_record *find_record(struct loop *l,const char *id) {
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i)if(l->records[i].used&&!strcmp(l->records[i].execution,id))return &l->records[i];
    return NULL;
}
static bool tombstone(struct loop *l,const char *id,const char *lease) {
    for(size_t i=0;i<1024;++i)if(!strcmp(l->terminal[i].execution,id)&&!strcmp(l->terminal[i].lease,lease))return true;
    return false;
}
static int spawn(struct loop *l,json_t *j) {
    const char *id=w2_str(j,"execution_id"),*lease=w2_str(j,"lease_id");
    uint64_t counter;if(!w2_decimal(id+33,&counter,true)||counter<=l->last_execution)return -1;
    if(find_record(l,id)||tombstone(l,id,lease))return -1;
    struct spawn_record *r=NULL;
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i)if(!l->records[i].used){r=&l->records[i];break;}
    if(!r)return -1; /* bounded control failure; no untracked clone */
    l->last_execution=counter;
    memset(r,0,sizeof *r);r->used=true;r->channel=-1;r->all_expected=true;r->stage=W2_STAGE_VALIDATE;
    strcpy(r->execution,id);strcpy(r->lease,lease);
    int copy_length=snprintf(r->copy,sizeof r->copy,"%s:r",id);if(copy_length<0||(size_t)copy_length>=sizeof r->copy)return -1;
    r->copy_released=true;r->copy_pending=true;r->copy_basis="not_materialized";r->copy_reason="none";
    r->uid=(uid_t)json_integer_value(json_object_get(j,"uid"));r->gid=(gid_t)json_integer_value(json_object_get(j,"gid"));
    if(!w2_decimal(w2_str(j,"startup_deadline_ns"),&r->deadline,true))return -1;
    r->plan=w2_plan_find(l->catalog,w2_str(j,"launch_plan_id"),w2_str(j,"launch_plan_digest"));
    uint64_t now=w2_now();
    if(w2_fault("validate")||!r->plan||r->uid!=r->plan->workspace->uid||r->gid!=r->plan->workspace->gid||
       r->uid==l->catalog->overflow||r->gid==l->catalog->overflow_gid||r->deadline<=now||r->deadline-now>UINT64_C(300000000000)) {
        fail_record(r,W2_STAGE_VALIDATE,"invalid_spec",EINVAL);return 0;
    }
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i) {
        struct spawn_record *old=&l->records[i];
        if(old!=r&&old->used&&!old->empty&&(old->uid==r->uid||old->gid==r->gid||old->plan->workspace==r->plan->workspace)) {
            fail_record(r,W2_STAGE_VALIDATE,"resource_exhausted",EBUSY);return 0;
        }
    }
    if(l->admission_blocked||!l->store.ready||l->store.dead||
       r->plan->runtime->charge_bytes>l->catalog->storage.max_bytes-l->reserved_bytes||
       r->plan->runtime->charge_nodes>l->catalog->storage.max_nodes-l->reserved_nodes){
        fail_record(r,W2_STAGE_VALIDATE,"resource_exhausted",ENOSPC);return 0;
    }
    l->reserved_bytes+=r->plan->runtime->charge_bytes;l->reserved_nodes+=r->plan->runtime->charge_nodes;
    r->copy_reserved=true;r->copy_released=false;r->copy_pending=false;return 0;
}
static void clone_ready(struct loop *l,struct spawn_record *r) {
    if(!r->copy_ready||r->stopping||r->empty||r->pid)return;
    if(l->lost||l->admission_blocked||l->store.dead||w2_now()>=r->deadline){
        fail_record(r,W2_STAGE_VALIDATE,w2_now()>=r->deadline?"timeout":"os_error",w2_now()>=r->deadline?ETIMEDOUT:ECANCELED);return;
    }
    struct child_args args={.plan=r->plan,.catalog=l->catalog,.control=l->control,.worker=l->store.fd,.deadline=r->deadline,.dev=r->root_dev,.ino=r->root_ino};
    strcpy(args.copy,r->copy);
    int root_length=snprintf(args.root,sizeof args.root,"%s/sandbox-root",l->catalog->root);
    int source_length=snprintf(args.source,sizeof args.source,"%s/%s/%s",l->catalog->root,
                               w2_str(l->catalog->storage.entry,"objects_ref"),r->copy);
    if(root_length<0||source_length<0||(size_t)root_length>=sizeof args.root||(size_t)source_length>=sizeof args.source){fail_record(r,W2_STAGE_VALIDATE,"invalid_spec",ENAMETOOLONG);return;}
    int pair[2]={-1,-1};
    if(w2_fault("socketpair")||socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pair)) {fail_record(r,W2_STAGE_SOCKETPAIR,"os_error",errno);goto done;}
    int enable=1;
    if(w2_fault("passcred")||setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&enable,sizeof enable)) {fail_record(r,W2_STAGE_PASSCRED,"os_error",errno);goto done;}
    /* Finite kernel queues on both endpoints, independently of userspace
     * frame limits. Linux returns doubled accounting sizes; verify bounds. */
    for(int side=0;side<2;++side)for(int direction=0;direction<2;++direction) {
        int option=direction?SO_RCVBUF:SO_SNDBUF,value=65536,actual=0;socklen_t size=sizeof actual;
        char point[40];snprintf(point,sizeof point,"buffer.%d.%d.set",side,direction);
        if(w2_fault(point)||setsockopt(pair[side],SOL_SOCKET,option,&value,sizeof value)) {fail_record(r,W2_STAGE_SOCKETPAIR,"os_error",errno);goto done;}
        snprintf(point,sizeof point,"buffer.%d.%d.get",side,direction);
        if(w2_fault(point)||getsockopt(pair[side],SOL_SOCKET,option,&actual,&size)||size!=sizeof actual||actual<65536||actual>131072) {fail_record(r,W2_STAGE_SOCKETPAIR,"os_error",EINVAL);goto done;}
    }
    args.channel=pair[1];args.other=pair[0];
    size_t stack_size=1024*1024;void *stack=mmap(NULL,stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK,-1,0);
    if(stack==MAP_FAILED){fail_record(r,W2_STAGE_CLONE,"os_error",errno);goto done;}
    pid_t pid=w2_fault("clone")?-1:clone(child_entry,(char *)stack+stack_size,
                    CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC|SIGCHLD,&args);
    int saved=errno;munmap(stack,stack_size);
    if(pid<0){fail_record(r,W2_STAGE_CLONE,"os_error",saved);goto done;}
    r->pid=pid;r->pid_owned=true;r->channel=pair[0];pair[0]=-1;r->stage=W2_STAGE_CLONE;
done:
    if(pair[0]>=0)close(pair[0]);
    if(pair[1]>=0)close(pair[1]);
}
static int input(struct loop *l) {
    char wire[W2_CONTROL_MAX];int received=-1;
    ssize_t n=w2_recv_control(l->control,wire,sizeof wire,&received);
    if(received>=0){close(received);return -1;}
    if(n==-2)return 0;
    if(n<=0)return -1;
    json_t *j=w2_control_parse(wire,(size_t)n);if(!j)return -1;
    int result=-1;uint64_t seq;if(!w2_decimal(w2_str(j,"seq"),&seq,true))goto done;
    if(l->ready&&strcmp(l->epoch,w2_str(j,"engine_epoch")))goto done;
    if(seq<l->incoming) {
        for(size_t i=0;i<1024;++i)if(l->history[i].seq==seq&&l->history[i].size==(size_t)n&&!memcmp(l->history[i].wire,wire,(size_t)n)){result=0;goto done;}
        goto done;
    }
    if(seq!=l->incoming||seq==UINT64_MAX)goto done;
    const char *type=w2_str(j,"type");
    if(!l->ready) {
        if(strcmp(type,"control_init")||strcmp(w2_str(j,"catalog_digest"),l->catalog->digest)||
           strcmp(w2_str(j,"storage_profile_digest"),l->catalog->storage.digest))goto done;
        strcpy(l->epoch,w2_str(j,"engine_epoch"));l->ready=true;
    } else if(!strcmp(type,"spawn")) {
        if(!l->ready_sent||spawn(l,j))goto done;
    } else if(!strcmp(type,"stop")) {
        struct spawn_record *r=find_record(l,w2_str(j,"execution_id"));
        if(r) {
            if(strcmp(r->lease,w2_str(j,"lease_id")))goto done;
            if(!r->empty){r->stopping=true;if(!r->pid)r->empty=true;}
        } else if(!tombstone(l,w2_str(j,"execution_id"),w2_str(j,"lease_id")))goto done;
    } else goto done;
    struct history *h=&l->history[l->history_next++%1024];free(h->wire);h->wire=malloc((size_t)n);
    if(!h->wire)goto done;
    memcpy(h->wire,wire,(size_t)n);h->size=(size_t)n;h->seq=seq;++l->incoming;result=0;
done:json_decref(j);return result;
}
static void bootstrap(struct loop *l,struct spawn_record *r) {
    union {struct cmsghdr align;unsigned char data[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(256*sizeof(int))];} c;
    struct iovec iov={r->bootstrap+r->received,16-r->received};
    struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=c.data,.msg_controllen=sizeof c.data};
    ssize_t n=recvmsg(r->channel,&m,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
    int fd=-1;
    if(n<=0||w2_ancillary(&m,true,r->uid,r->pid,l->catalog->overflow,true,&fd)) {fail_record(r,W2_STAGE_SEALED,"protocol_error",EPROTO);return;}
    for(struct cmsghdr *h=CMSG_FIRSTHDR(&m);h;h=CMSG_NXTHDR(&m,h))if(h->cmsg_level==SOL_SOCKET&&h->cmsg_type==SCM_CREDENTIALS) {
        struct ucred u;memcpy(&u,CMSG_DATA(h),sizeof u);
        if(u.uid!=r->uid||!u.uid||u.uid==l->catalog->overflow)r->all_expected=false;
    }
    r->received+=(size_t)n;if(r->received<16)return;
    struct w2_bootstrap b;
    if(w2_bootstrap_decode(r->bootstrap,16,&b)||b.kind==W2_BP_COMMIT) {fail_record(r,W2_STAGE_SEALED,"protocol_error",EPROTO);return;}
    if(b.kind==W2_BP_FAIL) {fail_record(r,b.stage,"os_error",(int)b.os_errno);return;}
    if(!r->all_expected){fail_record(r,W2_STAGE_SEALED,"protocol_error",EPROTO);return;}
    r->sealed=true;r->stage=W2_STAGE_SEALED;
}
static json_t *event(struct loop *l,struct spawn_record *r,const char *type) {
    char seq[32];snprintf(seq,sizeof seq,"%llu",(unsigned long long)l->outgoing);
    json_t *j=json_pack("{s:i,s:s,s:s,s:s}","v",1,"type",type,"engine_epoch",l->epoch,"seq",seq);
    if(j&&r){json_object_set_new(j,"execution_id",json_string(r->execution));json_object_set_new(j,"lease_id",json_string(r->lease));}
    return j;
}
static int make_output(struct loop *l) {
    if(l->output||!l->ready||!l->store.ready)return 0;
    json_t *j=NULL;l->owner=NULL;
    if(!l->ready_sent) {
        j=event(l,NULL,"control_ready");l->output_kind=0;
        json_object_set_new(j,"catalog_digest",json_string(l->catalog->digest));json_object_set_new(j,"protocol",json_string(W2_DATA_PROTOCOL));
        json_object_set_new(j,"runtime_storage_protocol",json_string(W2_STORAGE_PROTOCOL));json_object_set_new(j,"storage_profile_digest",json_string(l->catalog->storage.digest));
    } else for(size_t turn=0;turn<W2_EXECUTIONS_MAX;++turn) {
        size_t i=(l->output_cursor+turn)%W2_EXECUTIONS_MAX;
        struct spawn_record *r=&l->records[i];if(!r->used)continue;
        if(r->failed&&!r->failed_sent) {
            j=event(l,r,"spawn_failed");l->output_kind=1;
            json_object_set_new(j,"stage",json_string(w2_stage_name(r->stage)));json_object_set_new(j,"error_code",json_string(r->error));
            json_object_set_new(j,"os_errno",r->os_errno?json_integer(r->os_errno):json_null());
        } else if(r->copy_pending&&(!r->empty||r->empty_sent)) {
            j=event(l,r,"runtime_status");l->output_kind=4;l->output_generation=r->copy_generation;l->output_released=r->copy_released;
            json_object_set_new(j,"copy_id",json_string(r->copy));json_object_set_new(j,"state",json_string(r->copy_released?"released":"retained"));
            json_object_set_new(j,"basis",json_string(r->copy_basis));json_object_set_new(j,"reason",json_string(r->copy_reason));
            json_object_set_new(j,"attempt",json_integer(r->attempt));json_object_set_new(j,"os_errno",r->copy_errno?json_integer(r->copy_errno):json_null());
        } else if(r->sealed&&!r->prepared&&!r->empty&&!r->stopping) {
            if(w2_fault("handoff")){fail_record(r,W2_STAGE_HANDOFF,"os_error",EIO);continue;}
            j=event(l,r,"spawn_prepared");l->output_kind=2;
            json_object_set_new(j,"launch_plan_digest",json_string(r->plan->digest));json_object_set_new(j,"policy_digest",json_string(r->plan->policy->digest));
            json_object_set_new(j,"isolation_profile_digest",json_string(w2_str(r->plan->entry,"isolation_profile_digest")));
            json_object_set_new(j,"child_pid",json_integer(r->pid));json_object_set_new(j,"sealed",json_true());
            json_object_set_new(j,"copy_id",json_string(r->copy));
        } else if(r->empty&&!r->empty_sent) {
            j=event(l,r,"execution_empty");l->output_kind=3;
            json_object_set_new(j,"basis",json_string(r->pid?"pid1_reaped":"never_created"));
            json_object_set_new(j,"exit_code",r->pid&&WIFEXITED(r->status)?json_integer(WEXITSTATUS(r->status)):json_null());
            json_object_set_new(j,"signal",r->pid&&WIFSIGNALED(r->status)?json_integer(WTERMSIG(r->status)):json_null());
            json_object_set_new(j,"last_stage",json_string(w2_stage_name(r->stage)));
        }
        if(j){l->owner=r;l->output_cursor=(i+1)%W2_EXECUTIONS_MAX;break;}
    }
    if(!j)return 0;
    l->output=json_dumps(j,JSON_COMPACT|JSON_ENSURE_ASCII);json_decref(j);
    if(!l->output)return -1;
    l->output_size=strlen(l->output);
    return l->output_size<=W2_CONTROL_MAX?0:-1;
}
static int output(struct loop *l) {
    if(make_output(l))return -1;
    if(!l->output)return 0;
    /* If an unsent prepared became stale, discard it before assigning a
     * successful sequence. Its fd is still owned by the original record. */
    if(l->output_kind==2&&(l->owner->empty||l->owner->stopping||l->owner->channel<0)) {
        free(l->output);l->output=NULL;l->owner=NULL;return 0;
    }
    int fd=l->output_kind==2?l->owner->channel:-1;
    int r=w2_send_control(l->control,l->output,l->output_size,fd);
    if(!r){if(!l->blocked_since)l->blocked_since=w2_now();return 0;}
    if(r<0||l->outgoing==UINT64_MAX)return -1;
    ++l->outgoing;l->blocked_since=0;
    if(l->output_kind==0)l->ready_sent=true;
    else if(l->output_kind==1)l->owner->failed_sent=true;
    else if(l->output_kind==2){l->owner->prepared=true;close(l->owner->channel);l->owner->channel=-1;}
    else if(l->output_kind==3)l->owner->empty_sent=true;
    else {
        if(l->owner->copy_generation==l->output_generation)l->owner->copy_pending=false;
        if(l->output_released)l->owner->copy_sent=true;
    }
    if(l->owner&&l->owner->empty_sent&&l->owner->copy_sent&&l->owner->copy_released&&!l->owner->copy_pending) {
        struct terminal *t=&l->terminal[l->terminal_next++%1024];strcpy(t->execution,l->owner->execution);strcpy(t->lease,l->owner->lease);
        t->pid1_reaped=l->owner->pid!=0;t->wait_status=l->owner->status;t->last_stage=l->owner->stage;
        t->copy_basis=l->owner->copy_basis;t->cleanup_attempt=l->owner->attempt;
        l->owner->used=false;
    }
    free(l->output);l->output=NULL;l->owner=NULL;return 0;
}
static void retain_copy(struct loop *l,struct spawn_record *r,const char *why,int number) {
    if(r->copy_released)return;
    if(!r->copy_retained||r->copy_reason!=why||r->copy_errno!=number){r->copy_pending=true;++r->copy_generation;}
    r->copy_retained=true;r->copy_basis="unconfirmed";r->copy_reason=why;r->copy_errno=number>0&&number<=4095?number:EIO;
    l->admission_blocked=true;r->stopping=true;if(!r->pid)r->empty=true;
}
static void release_copy(struct loop *l,struct spawn_record *r,const char *basis) {
    if(r->copy_released)return;
    if(r->copy_reserved){l->reserved_bytes-=r->plan->runtime->charge_bytes;l->reserved_nodes-=r->plan->runtime->charge_nodes;r->copy_reserved=false;}
    r->copy_released=true;r->copy_retained=false;r->copy_pending=true;++r->copy_generation;r->copy_basis=basis;r->copy_reason="none";r->copy_errno=0;
    l->admission_blocked=l->store.dead;
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i)if(l->records[i].used&&l->records[i].copy_retained)l->admission_blocked=true;
}
static void storage_progress(struct loop *l) {
    struct w2_job_result done;int got=l->store.closing?0:w2_store_poll(&l->store,&done);uint64_t now=w2_now();
    if(got>0){
        struct spawn_record *r=NULL;for(size_t i=0;i<W2_EXECUTIONS_MAX;++i)if(l->records[i].used&&!strcmp(l->records[i].copy,done.copy))r=&l->records[i];
        if(!r||r->job!=done.job){l->store.dead=true;got=-1;}else {
            bool deleting=r->delete_pending;r->job=0;r->delete_pending=false;
#ifdef W2_TESTING
            fprintf(stderr,"W2_JOB_DONE copy=%s job=%llu op=%s attempt=%u result=%s removed=%d\n",r->copy,(unsigned long long)done.job,deleting?"delete":"create",r->attempt,done.result,done.root_removed);
#endif
            if(deleting){
                if(!done.has_root||done.dev!=r->root_dev||done.ino!=r->root_ino||
                   (r->root_removed&&!done.root_removed)||
                   (strcmp(done.result,"removed")&&strcmp(done.result,"failed"))){l->store.dead=true;got=-1;}
                else if(!strcmp(done.result,"removed"))release_copy(l,r,"tree_removed");
                else {retain_copy(l,r,done.reason[0]?"delete_failed":"worker_lost",done.os_errno);r->cleanup_deadline=0;r->retry_at=now+(r->attempt==1?UINT64_C(1000000000):UINT64_C(5000000000));}
                r->root_removed|=done.root_removed;
            }else {
                r->creation_finished=true;r->root_known=done.has_root;r->root_dev=done.dev;r->root_ino=done.ino;
                if(done.root_removed||!strcmp(done.result,"removed")){l->store.dead=true;got=-1;}
                else if(!strcmp(done.result,"not_materialized")){fail_record(r,W2_STAGE_VALIDATE,!strcmp(done.reason,"job_timeout")?"timeout":"os_error",done.os_errno);release_copy(l,r,"not_materialized");}
                else if(strcmp(done.result,"ready")){fail_record(r,W2_STAGE_VALIDATE,"os_error",done.os_errno);retain_copy(l,r,"create_failed",done.os_errno);}
                else if(!done.has_root||done.dev!=(uint64_t)l->catalog->storage.objects_identity.st_dev){retain_copy(l,r,"identity_mismatch",ESTALE);}
                else {r->copy_ready=true;if(!r->stopping&&now<r->deadline)clone_ready(l,r);else {r->stopping=true;r->empty=true;}}
            }
        }
    }
    if(l->store.owned){int status;pid_t pid=waitpid(l->store.pid,&status,WNOHANG);
        if(pid==l->store.pid){l->store.owned=false;if(!l->store.closing){l->store.dead=true;got=-1;}}
        else if(pid<0&&errno!=EINTR){l->store.owned=false;l->store.dead=true;got=-1;}}
    if(got<0){l->admission_blocked=true;for(size_t i=0;i<W2_EXECUTIONS_MAX;++i)if(l->records[i].used){
        struct spawn_record *r=&l->records[i];if(!r->copy_released&&!r->prepared)fail_record(r,W2_STAGE_VALIDATE,"os_error",EIO);
        retain_copy(l,r,"worker_lost",EIO);
    }l->lost=true;}
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i){
        struct spawn_record *r=&l->records[i];if(!r->used||r->copy_released)continue;
        if(!r->prepared&&!r->stopping&&now>=r->deadline)fail_record(r,W2_STAGE_VALIDATE,"timeout",ETIMEDOUT);
        if((l->lost||r->stopping)&&!r->pid){r->stopping=true;r->empty=true;}
        if(r->job&&r->job==l->store.job&&(r->stopping||(!r->delete_pending&&now>=r->deadline))) {
            if(!r->delete_pending)(void)w2_store_cancel(&l->store);
        }
        if(!r->create_submitted&&r->empty){r->creation_finished=true;release_copy(l,r,"not_materialized");continue;}
        if(r->empty&&r->creation_finished&&r->root_known&&!r->copy_released&&!r->cleanup_deadline&&r->attempt<3&&now>=r->retry_at){
            ++r->attempt;r->cleanup_deadline=now+(uint64_t)l->catalog->storage.cleanup_ms*1000000;r->copy_generation++;if(r->copy_retained)r->copy_pending=true;
        }
        if(r->cleanup_deadline&&now>=r->cleanup_deadline&&!r->copy_released){
            retain_copy(l,r,"job_timeout",ETIMEDOUT);
            if(r->job)(void)w2_store_cancel(&l->store);
            else {r->cleanup_deadline=0;r->retry_at=now+(r->attempt==1?UINT64_C(1000000000):UINT64_C(5000000000));}
        }
    }
    if(l->store.dead||l->store.closing||!l->store.ready||l->store.job||l->store.output)return;
    /* One job, cleanup first, bounded round-robin intent slots. */
    for(int deleting=1;deleting>=0;--deleting)for(size_t turn=0;turn<W2_EXECUTIONS_MAX;++turn){
        size_t i=(l->job_cursor+turn)%W2_EXECUTIONS_MAX;struct spawn_record *r=&l->records[i];if(!r->used||r->copy_released)continue;
        bool eligible=deleting?(r->empty&&r->creation_finished&&r->root_known&&r->cleanup_deadline>now):
            (!r->create_submitted&&!r->stopping&&!l->lost&&!l->admission_blocked&&now<r->deadline);
        if(!eligible)continue;
        if(w2_store_submit(&l->store,r->copy,w2_str(r->plan->runtime->descriptor,"runtime_id"),deleting,
             deleting?r->cleanup_deadline:r->deadline,r->root_dev,r->root_ino,r->root_removed)){retain_copy(l,r,"worker_lost",EIO);l->store.dead=true;l->lost=true;return;}
        r->job=l->store.job;r->delete_pending=deleting!=0;r->create_submitted=true;l->job_cursor=(i+1)%W2_EXECUTIONS_MAX;
#ifdef W2_TESTING
        fprintf(stderr,"W2_JOB_SUBMIT copy=%s job=%llu op=%s attempt=%u\n",r->copy,(unsigned long long)r->job,deleting?"delete":"create",r->attempt);
#endif
        return;
    }
}
static void reap_and_stop(struct loop *l) {
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i) {
        struct spawn_record *r=&l->records[i];if(!r->used)continue;
        if(r->empty)continue;
        if(l->lost)r->stopping=true;
        if(r->stopping&&r->pid_owned) {
            /* Only this unreaped direct child's pid can be signalled. The
             * wait result below is the sole source of pid1_reaped. */
            int killed;
#ifdef W2_TESTING
            if(w2_fault("reap.echild")||w2_fault("reap.second.echild"))
                fprintf(stderr,"W2_TEST_TRACE kill pid=%d\n",r->pid);
            if(w2_fault("kill.esrch")){errno=ESRCH;killed=-1;}
            else if(w2_fault("kill.no-effect"))killed=0;
            else
#endif
            killed=w2_fault("kill")?-1:kill(r->pid,SIGKILL);
            if(killed) {
                if(errno!=ESRCH&&!r->failed)fail_record(r,W2_STAGE_REAP,"os_error",errno);
            }
        }
        if(r->pid_owned) {
            int status;pid_t got;
#ifdef W2_TESTING
            if(r->stopping&&(w2_fault("reap.echild")||
                (r->uid==70001&&w2_fault("reap.second.echild")))){errno=ECHILD;got=-1;}
            else
#endif
            got=w2_fault("reap")?-1:waitpid(r->pid,&status,WNOHANG);
            if(got==r->pid&&(WIFEXITED(status)||WIFSIGNALED(status))) {
                /* Reap may win the poll race. Consume a queued trusted FAIL
                 * before discarding its diagnostic channel. */
                while(r->channel>=0&&!r->sealed&&!r->failed&&r->received<16) {
                    size_t before=r->received;bootstrap(l,r);
                    if(r->received==before)break;
                }
                r->status=status;r->empty=true;r->pid_owned=false;
                if(r->channel>=0){close(r->channel);r->channel=-1;}
                if(!r->failed)r->stage=W2_STAGE_REAP;
            } else if(got<0&&errno!=EINTR) {
                /* ECHILD is uncertainty, never an empty fact. */
                int failure_errno=errno;
#ifdef W2_TESTING
                if(w2_fault("reap.echild")||w2_fault("reap.second.echild"))
                    fprintf(stderr,"W2_TEST_TRACE wait_error pid=%d\n",r->pid);
#endif
                r->pid_owned=false;
                fail_record(r,W2_STAGE_REAP,"os_error",failure_errno);l->lost=true;
            }
        }
    }
}
int w2_spawner_run(struct w2_catalog *catalog,int control) {
    struct loop *l=calloc(1,sizeof *l);if(!l)return 1;
    l->catalog=catalog;l->control=control;l->incoming=l->outgoing=1;
    if(w2_nonblock(control)){free(l);return 1;}
    struct sigaction action={.sa_handler=SIG_DFL};sigemptyset(&action.sa_mask);
    if(sigaction(SIGCHLD,&action,NULL)){free(l);return 1;}
    sigset_t mask;sigemptyset(&mask);if(sigprocmask(SIG_SETMASK,&mask,NULL)){free(l);return 1;}
    if(w2_store_start(&l->store,catalog,control)){l->store.dead=true;l->lost=true;}
    int result=l->store.dead?1:0;
    for(;;) {
        uint64_t now=w2_now();
        /* Consume queued stop/control loss before a READY result can clone. */
        if(!l->lost&&input(l))l->lost=true;
        if(l->blocked_since&&now-l->blocked_since>=UINT64_C(5000000000))l->lost=true;
        if(l->lost&&!l->closing_since){l->closing_since=now;shutdown(control,SHUT_RDWR);}
        reap_and_stop(l);
        storage_progress(l);
        if(l->store.dead)result=1;
        /* Errors can first occur inside reap. Start the closing budget there,
         * before checking elapsed time; earlier records get a complete next
         * stop sweep, not an immediate timeout relative to timestamp zero. */
        if(l->lost&&!l->closing_since){l->closing_since=w2_now();shutdown(control,SHUT_RDWR);}
        if(l->lost) {
            bool live=false,waiting=false;uint64_t closing_now=w2_now();
            for(size_t i=0;i<W2_EXECUTIONS_MAX;++i)if(l->records[i].used){
                struct spawn_record *r=&l->records[i];
                if(!r->empty||!r->copy_released)live=true;
                if(!r->empty&&closing_now-l->closing_since<UINT64_C(5000000000))waiting=true;
                if(!l->store.dead&&!r->copy_released){
                    if(r->job&&closing_now<(r->delete_pending?r->cleanup_deadline:r->deadline))waiting=true;
                    if(r->cleanup_deadline&&closing_now<r->cleanup_deadline)waiting=true;
                    if(!r->job&&r->empty&&r->creation_finished&&r->root_known&&r->attempt<3)waiting=true;
                }
            }
            if(!waiting&&!l->store.closing){
                if(live)result=1;
                w2_store_close(&l->store);l->worker_closing=w2_now();
            }
            if(l->store.closing&&!l->store.owned)break;
            if(l->worker_closing&&!l->worker_killed&&w2_now()-l->worker_closing>=UINT64_C(5000000000)){
                result=1;l->worker_killed=w2_now();if(l->store.owned)(void)kill(l->store.pid,SIGKILL);
            }
            if(l->worker_killed&&w2_now()-l->worker_killed>=UINT64_C(5000000000)){result=1;break;}
        }
        struct pollfd fds[1+W2_EXECUTIONS_MAX];struct spawn_record *owner[W2_EXECUTIONS_MAX];nfds_t nfds=1;
        fds[0]=(struct pollfd){.fd=l->lost?-1:control,.events=POLLIN|POLLPRI};
        for(size_t i=0;i<W2_EXECUTIONS_MAX;++i) {
            struct spawn_record *r=&l->records[i];if(!r->used||r->empty||r->prepared||r->stopping)continue;
            if(now>=r->deadline){fail_record(r,r->pid?W2_STAGE_SEALED:W2_STAGE_VALIDATE,"timeout",ETIMEDOUT);continue;}
            if(!r->sealed&&r->channel>=0){owner[nfds-1]=r;fds[nfds++]=(struct pollfd){.fd=r->channel,.events=POLLIN|POLLPRI};}
        }
        if(!l->lost&&output(l))l->lost=true;
        int n=poll(fds,nfds,10);if(n<0&&errno!=EINTR){l->lost=true;continue;}
        if(n<=0)continue;
        if(fds[0].revents&POLLPRI)l->lost=true;
        if(fds[0].revents&(POLLIN|POLLHUP|POLLERR|POLLNVAL)) {
            if(input(l))l->lost=true;
        }
        for(nfds_t i=1;i<nfds;++i)if(fds[i].revents) {
            if(fds[i].revents&POLLPRI)fail_record(owner[i-1],W2_STAGE_SEALED,"protocol_error",EPROTO);
            else bootstrap(l,owner[i-1]);
        }
    }
    for(size_t i=0;i<1024;++i)free(l->history[i].wire);
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i)if(l->records[i].channel>=0&&l->records[i].used)close(l->records[i].channel);
    free(l->output);close(control);free(l);return result;
}
