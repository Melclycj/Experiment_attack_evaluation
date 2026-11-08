#define _GNU_SOURCE
#include "spawner.h"
#include "transport.h"
#include "storage.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
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
    /* v2 per-row resources (validation.md S-01, S-08, S-11, S-12, S-14): the proxy and attach listening sockets,
     * the judgment socketpair, the connector process and its exit, the row directory. */
    int proxy_fd,attach_fd,judge_core,judge_conn,pty_master,pty_slave;pid_t connector_pid;int connector_status;
    bool connector_started,connector_exited,connector_exited_sent;char rows_dir[W2_PATH_CAP];
    bool connector_lost;   /* waitpid failed: no exit fact, and the pid is never signalled again (as pid 1's pid_owned) */
    /* the row's file worker (validation.md H-05, H-06, H-14, H-17): the file-port listening socket, the file judgment
     * socketpair, the worker process and its exit, kept as the connector's are */
    int file_fd,file_core,file_conn;pid_t worker_pid;int worker_status;
    bool worker_started,worker_exited,worker_exited_sent,worker_lost;
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
static int child_entry(void *ptr) {
    struct w2_child_args *a=ptr;close(a->other);close(a->control);close(a->worker);close(a->catalog->storage.lock_fd);
    return w2_child_launch(a);
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
    r->proxy_fd=r->attach_fd=r->judge_core=r->judge_conn=r->pty_master=r->pty_slave=-1;
    r->file_fd=r->file_core=r->file_conn=-1;
    strcpy(r->execution,id);strcpy(r->lease,lease);
    int copy_length=snprintf(r->copy,sizeof r->copy,"%s:r",id);if(copy_length<0||(size_t)copy_length>=sizeof r->copy)return -1;
    r->copy_released=true;r->copy_pending=true;r->copy_basis="not_materialized";r->copy_reason="none";
    r->uid=(uid_t)json_integer_value(json_object_get(j,"uid"));r->gid=(gid_t)json_integer_value(json_object_get(j,"gid"));
    if(!w2_decimal(w2_str(j,"startup_deadline_ns"),&r->deadline,true))return -1;
    r->plan=w2_plan_find(l->catalog,w2_str(j,"launch_plan_id"),w2_str(j,"launch_plan_digest"));
    uint64_t now=w2_now();
    /* v2: the uid is leased per execution from the reserved range (agent-rm-model 3.1); gid equals uid. */
    if(w2_fault("validate")||!r->plan||r->uid<l->catalog->range_first||r->uid>l->catalog->range_last||r->gid!=r->uid||
       r->uid==l->catalog->overflow||r->gid==l->catalog->overflow_gid||r->deadline<=now||r->deadline-now>UINT64_C(300000000000)) {
        fail_record(r,W2_STAGE_VALIDATE,"invalid_spec",EINVAL);return 0;
    }
    /* phase 2 (validation.md S-20): no FIFO, socket or device in the cell files, nothing writable but by root */
    if(w2_cell_files_check(l->catalog)){fail_record(r,W2_STAGE_VALIDATE,"invalid_spec",errno?errno:EINVAL);return 0;}
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
static int write_text(const char *path,const char *text) {
    int fd=open(path,O_WRONLY|O_CLOEXEC);if(fd<0)return -1;
    ssize_t n=write(fd,text,strlen(text));int saved=errno;close(fd);errno=saved;return n==(ssize_t)strlen(text)?0:-1;
}
/* A user namespace whose only mapping pairs the workspace owner with the execution uid; the child attaches it
 * to the workspace mount (MOUNT_ATTR_IDMAP), so on-disk owner files appear as the execution's uid and files it
 * creates land as the owner (agent-rm-model 3.1; evidence 2026-10-26). The uid_map line is "owner execution 1":
 * measured on this kernel (probe 2026-10-29), the other order leaves the owner unmapped (overflow, even for
 * root). The helper process only holds the namespace. */
static int make_idmap(uid_t execution_uid,uid_t owner_uid,gid_t execution_gid,gid_t owner_gid) {
    int sync[2];if(pipe2(sync,O_CLOEXEC))return -1;
    pid_t pid=fork();if(pid<0){int s=errno;close(sync[0]);close(sync[1]);errno=s;return -1;}
    if(!pid){close(sync[0]);if(unshare(CLONE_NEWUSER))_exit(1);char ok=1;if(write(sync[1],&ok,1)!=1)_exit(1);close(sync[1]);for(;;)pause();}
    close(sync[1]);char ok=0;int fd=-1;
    if(read(sync[0],&ok,1)==1&&ok==1){
        char path[64],text[80];
        snprintf(path,sizeof path,"/proc/%d/setgroups",(int)pid);
        if(!write_text(path,"deny")){
            snprintf(path,sizeof path,"/proc/%d/gid_map",(int)pid);snprintf(text,sizeof text,"%u %u 1",(unsigned)owner_gid,(unsigned)execution_gid);
            if(!write_text(path,text)){
                snprintf(path,sizeof path,"/proc/%d/uid_map",(int)pid);snprintf(text,sizeof text,"%u %u 1",(unsigned)owner_uid,(unsigned)execution_uid);
                if(!write_text(path,text)){snprintf(path,sizeof path,"/proc/%d/ns/user",(int)pid);fd=open(path,O_RDONLY|O_CLOEXEC);}
            }
        }
    }
    int saved=errno;close(sync[0]);kill(pid,SIGKILL);int status;while(waitpid(pid,&status,0)<0&&errno==EINTR);errno=saved;
    return fd;
}
static int bind_listen(const char *path,uid_t uid,gid_t gid,int backlog,bool passcred) {
    struct sockaddr_un a={.sun_family=AF_UNIX};if(strlen(path)>=sizeof a.sun_path){errno=ENAMETOOLONG;return -1;}
    strcpy(a.sun_path,path);int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return -1;int one=1;
    if((passcred&&setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&one,sizeof one))||bind(fd,(struct sockaddr *)&a,sizeof a)||
       chmod(path,0600)||chown(path,uid,gid)||listen(fd,backlog)){int s=errno;close(fd);unlink(path);errno=s;return -1;}   /* chmod before chown: no CAP_FOWNER */
    return fd;
}
/* v2: one row directory with the proxy listening socket (PASSCRED set before listen, owned by the execution uid:
 * only that uid connects to it, through the bind mount inside the cell) and the attach listening socket (owned by
 * the engine uid: only the admin client connects), plus the judgment socketpair whose core end carries PASSCRED. */
static int row_resources(struct loop *l,struct spawn_record *r) {
    char path[W2_PATH_CAP+32];
    if(snprintf(r->rows_dir,sizeof r->rows_dir,"%s/rows/%s",l->catalog->root,r->execution)>=(int)sizeof r->rows_dir||
       w2_fault("row.dir")||mkdir(r->rows_dir,0711)){fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",errno);return -1;}   /* root-owned, traversable (S-08) */
    snprintf(path,sizeof path,"%s/proxy.sock",r->rows_dir);
    if(w2_fault("row.proxy")||(r->proxy_fd=bind_listen(path,r->uid,r->gid,64,true))<0){fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",errno);return -1;}
    snprintf(path,sizeof path,"%s/attach.sock",r->rows_dir);
    if(w2_fault("row.attach")||(r->attach_fd=bind_listen(path,l->catalog->engine_uid,l->catalog->engine_gid,1,false))<0){fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",errno);return -1;}
    /* the row's file port (validation.md H-05): as the proxy socket, owned by the execution uid, 0600, PASSCRED before
     * listen, at most 16 pending; the child bind-mounts it at /run/w2/file.sock, the file worker inherits it as fd 3 */
    snprintf(path,sizeof path,"%s/file.sock",r->rows_dir);
    if(w2_fault("row.file")||(r->file_fd=bind_listen(path,r->uid,r->gid,16,true))<0){fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",errno);return -1;}
    /* v2 (validation.md S-16): one fresh CA per execution, taken from the deployment's pool (directories holding
     * ca.pem and ca.key, made offline by frontend/make_ca_pool.py) by moving it into the row directory, where the child
     * bind-mounts it read-only at /w2/ca. A pool entry is consumed by one execution and never reused. */
    char pool[W2_PATH_CAP+32],entry[W2_PATH_CAP+300];
    snprintf(pool,sizeof pool,"%s/%s",l->catalog->root,l->catalog->ca_pool_ref);
    DIR *pool_dir=w2_fault("row.ca")?NULL:opendir(pool);
    if(!pool_dir){fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",errno?errno:EIO);return -1;}
    struct dirent *e;bool ca_taken=false;
    while((e=readdir(pool_dir))) {
        if(e->d_name[0]=='.')continue;
        snprintf(entry,sizeof entry,"%s/%s",pool,e->d_name);snprintf(path,sizeof path,"%s/ca",r->rows_dir);
        if(!rename(entry,path)){ca_taken=true;break;}
    }
    closedir(pool_dir);
    if(!ca_taken){fail_record(r,W2_STAGE_ROW_SOCKETS,"resource_exhausted",ENOENT);return -1;}
    int pair[2];int one=1;
    if(w2_fault("row.judge")||socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)){fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",errno);return -1;}
    if(setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof one)||w2_nonblock(pair[0])){int s=errno;close(pair[0]);close(pair[1]);fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",s);return -1;}
    r->judge_core=pair[0];r->judge_conn=pair[1];
    /* the row's file judgment port (validation.md H-06): the same shape, the core end with PASSCRED and non-blocking */
    if(w2_fault("row.filejudge")||socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)){fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",errno);return -1;}
    if(setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof one)||w2_nonblock(pair[0])){int s=errno;close(pair[0]);close(pair[1]);fail_record(r,W2_STAGE_ROW_SOCKETS,"os_error",s);return -1;}
    r->file_core=pair[0];r->file_conn=pair[1];
    /* v2: the row's terminal (agent-rm-model 3.3 对话通道; validation.md S-07): the slave becomes the agent's stdio and
     * controlling terminal in the child, the master goes to the in-cell relay; the spawner keeps neither. */
    if(w2_fault("pty.open")||(r->pty_master=posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC))<0){fail_record(r,W2_STAGE_PTY,"os_error",errno);return -1;}
    if(w2_fault("pty.unlock")||grantpt(r->pty_master)||unlockpt(r->pty_master)){fail_record(r,W2_STAGE_PTY,"os_error",errno?errno:EIO);return -1;}
    char *slave_name=ptsname(r->pty_master);
    if(w2_fault("pty.slave")||!slave_name||(r->pty_slave=open(slave_name,O_RDWR|O_NOCTTY|O_CLOEXEC))<0){fail_record(r,W2_STAGE_PTY,"os_error",errno?errno:EIO);return -1;}
    return 0;
}
/* v2: a row process (the connector, the file worker) is the spawner's direct child, runs as its dedicated uid with no
 * capability and no_new_privs, and inherits only its listening fd (3), its judgment end (4) and /dev/null stdio
 * (validation.md S-11, H-14). argv is the catalog's, followed by the execution uid and id. One code path for both, so
 * the two starts cannot drift apart. Returns the pid, or -1. */
static pid_t start_row_process(struct spawn_record *r,uid_t uid,gid_t gid,const char *exe,char *const *catalog_argv,
                               int listen_fd,int judge_fd,const char *scope) {
    pid_t pid=fork();if(pid<0)return -1;
    if(!pid) {
        char uid_text[16],*argv[W2_ARGV_MAX+4];size_t n=0;
        for(;catalog_argv[n]&&n<W2_ARGV_MAX;++n)argv[n]=catalog_argv[n];
        snprintf(uid_text,sizeof uid_text,"%u",(unsigned)r->uid);argv[n++]=uid_text;argv[n++]=r->execution;argv[n]=NULL;
        /* both ends first move above 4, so that neither the stdio below nor the other end's place can land on them */
        int listener=fcntl(listen_fd,F_DUPFD_CLOEXEC,5),judge=fcntl(judge_fd,F_DUPFD_CLOEXEC,5);
        if(listener<0||judge<0)_exit(126);
        int devnull=open("/dev/null",O_RDWR|O_CLOEXEC);if(devnull<0)_exit(126);
        if(dup2(devnull,0)<0||dup2(devnull,1)<0||dup2(devnull,2)<0||dup2(listener,3)<0||dup2(judge,4)<0)_exit(126);
        if(fcntl(3,F_SETFD,0)||fcntl(4,F_SETFD,0)||syscall(SYS_close_range,5,~0u,0))_exit(126);
        if(clearenv()||setenv("PATH","/usr/bin:/bin",1)||setenv("LC_ALL","C.UTF-8",1))_exit(126);
        w2_fault_scope(scope);   /* test faults aimed at the agent child's drop stages do not fire here */
        enum w2_stage stage;if(w2_drop(uid,gid,&stage))_exit(125);
        execv(exe,argv);_exit(127);
    }
    return pid;
}
static int start_connector(struct loop *l,struct spawn_record *r) {
    if(w2_fault("connector.fork")){errno=EAGAIN;return -1;}
    pid_t pid=start_row_process(r,l->catalog->connector.uid,l->catalog->connector.gid,l->catalog->connector.exe,
                                l->catalog->connector.argv,r->proxy_fd,r->judge_conn,"connector.drop.");
    if(pid<0)return -1;
    r->connector_pid=pid;r->connector_started=true;close(r->judge_conn);r->judge_conn=-1;close(r->proxy_fd);r->proxy_fd=-1;
    return 0;
}
/* the row's file worker (validation.md H-14): fd 3 the file-port listener, fd 4 its end of the file judgment port */
static int start_worker(struct loop *l,struct spawn_record *r) {
    if(w2_fault("file_worker.fork")){errno=EAGAIN;return -1;}
    pid_t pid=start_row_process(r,l->catalog->file_worker.uid,l->catalog->file_worker.gid,l->catalog->file_worker.exe,
                                l->catalog->file_worker.argv,r->file_fd,r->file_conn,"file_worker.drop.");
    if(pid<0)return -1;
    r->worker_pid=pid;r->worker_started=true;close(r->file_conn);r->file_conn=-1;close(r->file_fd);r->file_fd=-1;
    return 0;
}
static void release_row(struct spawn_record *r) {
    if(r->proxy_fd>=0){close(r->proxy_fd);r->proxy_fd=-1;}
    if(r->attach_fd>=0){close(r->attach_fd);r->attach_fd=-1;}
    if(r->judge_core>=0){close(r->judge_core);r->judge_core=-1;}
    if(r->judge_conn>=0){close(r->judge_conn);r->judge_conn=-1;}
    if(r->file_fd>=0){close(r->file_fd);r->file_fd=-1;}
    if(r->file_core>=0){close(r->file_core);r->file_core=-1;}
    if(r->file_conn>=0){close(r->file_conn);r->file_conn=-1;}
    if(r->pty_slave>=0){close(r->pty_slave);r->pty_slave=-1;}
    if(r->pty_master>=0){close(r->pty_master);r->pty_master=-1;}
    if(r->rows_dir[0]){char path[W2_PATH_CAP+32];snprintf(path,sizeof path,"%s/proxy.sock",r->rows_dir);unlink(path);
        snprintf(path,sizeof path,"%s/file.sock",r->rows_dir);unlink(path);
        snprintf(path,sizeof path,"%s/attach.sock",r->rows_dir);unlink(path);
        snprintf(path,sizeof path,"%s/ca/ca.pem",r->rows_dir);unlink(path);     /* the execution's CA goes with the row */
        snprintf(path,sizeof path,"%s/ca/ca.key",r->rows_dir);unlink(path);
        snprintf(path,sizeof path,"%s/ca",r->rows_dir);rmdir(path);
        rmdir(r->rows_dir);r->rows_dir[0]=0;}
}
static void clone_ready(struct loop *l,struct spawn_record *r) {
    if(!r->copy_ready||r->stopping||r->empty||r->pid)return;
    if(l->lost||l->admission_blocked||l->store.dead||w2_now()>=r->deadline){
        fail_record(r,W2_STAGE_VALIDATE,w2_now()>=r->deadline?"timeout":"os_error",w2_now()>=r->deadline?ETIMEDOUT:ECANCELED);return;
    }
    struct w2_child_args args={.plan=r->plan,.catalog=l->catalog,.control=l->control,.worker=l->store.fd,.deadline=r->deadline,.dev=r->root_dev,.ino=r->root_ino,.uid=r->uid,.gid=r->gid,
                               .pty_master=-1,.pty_slave=-1,.attach=-1,.idmap=-1};
    int pair[2]={-1,-1};   /* before any jump to done: its cleanup closes only what this function opened */
    strcpy(args.copy,r->copy);
    int root_length=snprintf(args.root,sizeof args.root,"%s/sandbox-root",l->catalog->root);
    int source_length=l->catalog->shared_runtime   /* runtime_mode "shared": the seed itself (catalog.h) */
        ?snprintf(args.source,sizeof args.source,"%s/%s",l->catalog->root,r->plan->runtime->seed_ref)
        :snprintf(args.source,sizeof args.source,"%s/%s/%s",l->catalog->root,
                  w2_str(l->catalog->storage.entry,"objects_ref"),r->copy);
    if(root_length<0||source_length<0||(size_t)root_length>=sizeof args.root||(size_t)source_length>=sizeof args.source){fail_record(r,W2_STAGE_VALIDATE,"invalid_spec",ENAMETOOLONG);return;}
    if(row_resources(l,r)){goto done;}
    args.pty_master=r->pty_master;args.pty_slave=r->pty_slave;args.attach=r->attach_fd;strcpy(args.rows_dir,r->rows_dir);
    if(w2_fault("idmap")||(args.idmap=make_idmap(r->uid,r->plan->workspace->uid,r->gid,r->plan->workspace->gid))<0) {fail_record(r,W2_STAGE_VALIDATE,"os_error",errno);goto done;}
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
    close(r->pty_slave);r->pty_slave=-1;close(r->pty_master);r->pty_master=-1;   /* the child and its relay hold the terminal */
    if(start_connector(l,r)){fail_record(r,W2_STAGE_CONNECTOR,"os_error",errno);}
    else if(start_worker(l,r)){fail_record(r,W2_STAGE_FILE_WORKER,"os_error",errno);}
done:
    if(pair[0]>=0)close(pair[0]);
    if(pair[1]>=0)close(pair[1]);
    if(args.idmap>=0)close(args.idmap);
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
    if(n<=0||w2_ancillary(&m,true,r->uid,r->pid,l->catalog->overflow,true,0,&fd)) {fail_record(r,W2_STAGE_SEALED,"protocol_error",EPROTO);return;}
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
            json_object_set_new(j,"connector_pid",json_integer(r->connector_pid));
            json_object_set_new(j,"worker_pid",json_integer(r->worker_pid));
        } else if(r->connector_exited&&!r->connector_exited_sent) {
            j=event(l,r,"connector_exited");l->output_kind=5;
            json_object_set_new(j,"exit_code",WIFEXITED(r->connector_status)?json_integer(WEXITSTATUS(r->connector_status)):json_null());
            json_object_set_new(j,"signal",WIFSIGNALED(r->connector_status)?json_integer(WTERMSIG(r->connector_status)):json_null());
        } else if(r->worker_exited&&!r->worker_exited_sent) {
            j=event(l,r,"worker_exited");l->output_kind=6;      /* validation.md H-17 */
            json_object_set_new(j,"exit_code",WIFEXITED(r->worker_status)?json_integer(WEXITSTATUS(r->worker_status)):json_null());
            json_object_set_new(j,"signal",WIFSIGNALED(r->worker_status)?json_integer(WTERMSIG(r->worker_status)):json_null());
        } else if(r->empty&&!r->empty_sent&&(!r->connector_started||r->connector_exited_sent||r->connector_lost)&&
                  (!r->worker_started||r->worker_exited_sent||r->worker_lost)) {
            /* a started connector's and file worker's exits go first (K-22, H-17): the core releases the workspace and
             * the slot on all of them */
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
    if(l->output_kind==2&&(l->owner->empty||l->owner->stopping||l->owner->channel<0||l->owner->judge_core<0||
                           l->owner->file_core<0)) {
        free(l->output);l->output=NULL;l->owner=NULL;return 0;
    }
    int fds[3]={-1,-1,-1};size_t nfds=0;   /* the agent channel, the judgment end, the file judgment end (H-06) */
    if(l->output_kind==2){fds[0]=l->owner->channel;fds[1]=l->owner->judge_core;fds[2]=l->owner->file_core;nfds=3;}
    int r=w2_send_control_fds(l->control,l->output,l->output_size,fds,nfds);
    if(!r){if(!l->blocked_since)l->blocked_since=w2_now();return 0;}
    if(r<0||l->outgoing==UINT64_MAX)return -1;
    ++l->outgoing;l->blocked_since=0;
    if(l->output_kind==0)l->ready_sent=true;
    else if(l->output_kind==1)l->owner->failed_sent=true;
    else if(l->output_kind==2){l->owner->prepared=true;close(l->owner->channel);l->owner->channel=-1;close(l->owner->judge_core);l->owner->judge_core=-1;
        close(l->owner->file_core);l->owner->file_core=-1;}
    else if(l->output_kind==3)l->owner->empty_sent=true;
    else if(l->output_kind==5)l->owner->connector_exited_sent=true;
    else if(l->output_kind==6)l->owner->worker_exited_sent=true;
    else {
        if(l->owner->copy_generation==l->output_generation)l->owner->copy_pending=false;
        if(l->output_released)l->owner->copy_sent=true;
    }
    if(l->owner&&l->owner->empty_sent&&l->owner->copy_sent&&l->owner->copy_released&&!l->owner->copy_pending&&
       (!l->owner->connector_started||l->owner->connector_exited_sent)&&
       (!l->owner->worker_started||l->owner->worker_exited_sent)) {
        release_row(l->owner);
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
                /* A create cancelled because the row already stopped is not a new failure: the row is terminal (E-01: a
                 * spawn_failed never follows execution_empty). The cancelled job only releases the copy. */
                else if(!strcmp(done.result,"not_materialized")){if(!r->empty)fail_record(r,W2_STAGE_VALIDATE,!strcmp(done.reason,"job_timeout")?"timeout":"os_error",done.os_errno);release_copy(l,r,"not_materialized");}
                else if(strcmp(done.result,"ready")){if(!r->empty)fail_record(r,W2_STAGE_VALIDATE,"os_error",done.os_errno);retain_copy(l,r,"create_failed",done.os_errno);}
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
/* One row process (the connector, the file worker): killed once the row stops, waited for without blocking. */
static void reap_row_process(struct loop *l,struct spawn_record *r,pid_t pid,bool *exited,int *exit_status,bool *lost) {
    if((r->stopping||r->empty||l->lost)&&kill(pid,SIGKILL)&&errno!=ESRCH&&!r->failed)
        fail_record(r,W2_STAGE_REAP,"os_error",errno);
    int status;pid_t got=waitpid(pid,&status,WNOHANG);
    if(got==pid&&(WIFEXITED(status)||WIFSIGNALED(status))) {
        *exited=true;*exit_status=status;
        if(!r->empty){r->stopping=true;if(!r->pid)r->empty=true;}   /* a row does not outlive its connector or worker */
    } else if(got<0&&errno!=EINTR) {
        /* as for pid 1 (reap_and_stop): a wait error is uncertainty, never an exit fact; no exit code is made up */
        *lost=true;fail_record(r,W2_STAGE_REAP,"os_error",errno);l->lost=true;
    }
}
static void reap_connectors(struct loop *l) {
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i) {
        struct spawn_record *r=&l->records[i];if(!r->used)continue;
        if(r->connector_started&&!r->connector_exited&&!r->connector_lost)
            reap_row_process(l,r,r->connector_pid,&r->connector_exited,&r->connector_status,&r->connector_lost);
        if(r->worker_started&&!r->worker_exited&&!r->worker_lost)          /* validation.md H-17 */
            reap_row_process(l,r,r->worker_pid,&r->worker_exited,&r->worker_status,&r->worker_lost);
    }
}
static void reap_and_stop(struct loop *l) {
    reap_connectors(l);
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
/* v2: <root>/rows belongs to root, 0711 (validation.md S-08): only the spawner creates and removes the row directories,
 * the engine uid and the admin client traverse it to the attach sockets they own, and the spawner keeps no
 * CAP_DAC_OVERRIDE so the directory must stay its own. The engine's own state directory (<root>/state: mirrors,
 * credentials, admin.sock; K-33) is the engine's, 0700, created by cell.c. */
static int rows_dir(struct w2_catalog *c) {
    char rows[W2_PATH_CAP+16];
    if(snprintf(rows,sizeof rows,"%s/rows",c->root)>=(int)sizeof rows)return -1;
    if((mkdir(rows,0711)&&errno!=EEXIST)||chmod(rows,0711))return -1;
    return 0;
}
int w2_spawner_run(struct w2_catalog *catalog,int control) {
    if(rows_dir(catalog))return 1;
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
                if(!r->empty||!r->copy_released||(r->connector_started&&!r->connector_exited)||
                   (r->worker_started&&!r->worker_exited))live=true;
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
    for(size_t i=0;i<W2_EXECUTIONS_MAX;++i)if(l->records[i].used){if(l->records[i].channel>=0)close(l->records[i].channel);release_row(&l->records[i]);}
    free(l->output);close(control);free(l);return result;
}
