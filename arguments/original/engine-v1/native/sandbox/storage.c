#define _GNU_SOURCE
#include "storage.h"
#include "transport.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/btrfs.h>
#include <linux/magic.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define KEYS(j,...) w2_keys((j),(const char *const[]){__VA_ARGS__},sizeof((const char *const[]){__VA_ARGS__})/sizeof(char *))
static bool eq(json_t *j,const char *key,const char *s){const char *v=w2_str(j,key);return v&&!strcmp(v,s);}
static bool decimal(json_t *j,const char *key,uint64_t *n,bool positive){return w2_decimal(w2_str(j,key),n,positive);}
static bool small(json_t *j,const char *key,unsigned low,unsigned high,unsigned *out){
    json_t *v=json_object_get(j,key);json_int_t n=json_integer_value(v);
    if(!json_is_integer(v)||n<(json_int_t)low||n>(json_int_t)high)return false;
    *out=(unsigned)n;return true;
}
static bool hex_id(const char *s,size_t n){if(!s||strlen(s)!=n)return false;for(size_t i=0;i<n;++i)if(!strchr("0123456789abcdef",s[i]))return false;return true;}
static bool copy_id(const char *s){
    if(!s||strlen(s)>55||strlen(s)<36||s[32]!=':')return false;
    char epoch[33];memcpy(epoch,s,32);epoch[32]=0;if(!hex_id(epoch,32))return false;
    size_t n=strlen(s);if(strcmp(s+n-2,":r"))return false;
    char number[21];size_t digits=n-35;if(!digits||digits>20)return false;
    memcpy(number,s+33,digits);number[digits]=0;uint64_t value;return w2_decimal(number,&value,true);
}
static int fs_identity(int fd,char uuid[37],uint64_t *capacity){
    struct btrfs_ioctl_fs_info_args info={0};struct statvfs v;struct statfs fs;
    if(w2_checkpoint()||fstatfs(fd,&fs)||w2_checkpoint())return -1;
    if(fs.f_type!=BTRFS_SUPER_MAGIC){errno=ESTALE;return -1;}
    if(ioctl(fd,BTRFS_IOC_FS_INFO,&info)||w2_checkpoint()||fstatvfs(fd,&v)||w2_checkpoint())return -1;
    if(!v.f_frsize||v.f_blocks>UINT64_MAX/v.f_frsize){errno=EOVERFLOW;return -1;}
    *capacity=(uint64_t)v.f_blocks*v.f_frsize;
    const unsigned char *p=info.fsid;
    snprintf(uuid,37,"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);return 0;
}
static int empty_directory(int fd){
    if(w2_checkpoint())return -1;
    int copy=dup(fd);if(copy<0)return -1;
    if(w2_checkpoint()||lseek(copy,0,SEEK_SET)<0||w2_checkpoint()){int saved=errno;close(copy);errno=saved;return -1;}
    DIR *d=fdopendir(copy);if(!d){close(copy);return -1;}int rc=0;struct dirent *e;errno=0;
    for(;;){
        if(w2_checkpoint()){rc=-1;break;}
        errno=0;e=readdir(d);int saved=errno;
        if(w2_checkpoint()){rc=-1;break;}
        if(!e){errno=saved;if(saved)rc=-1;break;}
        if(strcmp(e->d_name,".")&&strcmp(e->d_name,"..")){rc=-1;break;}
    }
    int saved=errno;closedir(d);errno=saved;return rc;
}
int w2_storage_load(struct w2_catalog *c){
    struct w2_storage_profile *s=&c->storage;json_t *ref=json_object_get(c->document,"storage_profile");
    if(!KEYS(ref,"artifact_ref","artifact_digest")||!w2_is_digest(w2_str(ref,"artifact_digest")))return -1;
    s->entry=w2_json_at(c->root_fd,w2_str(ref,"artifact_ref"),s->digest);json_t *j=s->entry;unsigned count,uid,gid;
    if(!j||strcmp(s->digest,w2_str(ref,"artifact_digest"))||!KEYS(j,"storage_profile_id","store_id","filesystem_uuid",
       "store_root_ref","objects_ref","lock_ref","owner_uid","owner_gid","filesystem_kind","filesystem_capacity_bytes",
       "max_copies","max_reserved_bytes","max_reserved_nodes","max_tree_nodes","min_free_bytes","cleanup_timeout_ms")||
       !w2_is_id(w2_str(j,"storage_profile_id"))||!hex_id(w2_str(j,"store_id"),32)||!eq(j,"filesystem_kind","btrfs")||
       !small(j,"owner_uid",0,0,&uid)||!small(j,"owner_gid",0,0,&gid)||getuid()!=uid||getgid()!=gid||
       !small(j,"max_copies",16,16,&count)||!small(j,"max_tree_nodes",1,65536,&s->max_tree_nodes)||
       !small(j,"cleanup_timeout_ms",1000,300000,&s->cleanup_ms)||
       !decimal(j,"filesystem_capacity_bytes",&s->capacity,true)||!decimal(j,"max_reserved_bytes",&s->max_bytes,true)||
       !decimal(j,"max_reserved_nodes",&s->max_nodes,true)||!decimal(j,"min_free_bytes",&s->min_free,true)||s->min_free<UINT64_C(67108864))return -1;
    const char *root=w2_str(j,"store_root_ref"),*objects=w2_str(j,"objects_ref"),*lock=w2_str(j,"lock_ref");
    if(!w2_relative(root)||!objects||!lock)return -1;
    char want[W2_PATH_CAP];int n=snprintf(want,sizeof want,"%s/objects",root);if(n<0||(size_t)n>=sizeof want||strcmp(want,objects))return -1;
    n=snprintf(want,sizeof want,"%s/store.lock",root);if(n<0||(size_t)n>=sizeof want||strcmp(want,lock))return -1;
    s->root_fd=w2_open_at(c->root_fd,root,O_RDONLY|O_DIRECTORY);
    c->instances_fd=w2_open_at(c->root_fd,objects,O_RDONLY|O_DIRECTORY);
    s->lock_fd=w2_open_at(c->root_fd,lock,O_RDWR);struct stat st;
    if(s->root_fd<0||c->instances_fd<0||s->lock_fd<0||fstat(s->root_fd,&s->root_identity)||
       fstat(c->instances_fd,&s->objects_identity)||fstat(s->lock_fd,&st)||
       s->root_identity.st_uid!=0||s->root_identity.st_gid!=0||(s->root_identity.st_mode&07777)!=0700||
       s->objects_identity.st_uid!=0||s->objects_identity.st_gid!=0||(s->objects_identity.st_mode&07777)!=0700||
       st.st_uid!=0||st.st_gid!=0||!S_ISREG(st.st_mode)||(st.st_mode&07777)!=0600||st.st_nlink!=1||
       st.st_dev!=s->root_identity.st_dev||s->objects_identity.st_dev!=s->root_identity.st_dev)return -1;
    uint64_t capacity;if(fs_identity(s->root_fd,s->uuid,&capacity)||capacity!=s->capacity||!eq(j,"filesystem_uuid",s->uuid))return -1;
    strcpy(s->store_id,w2_str(j,"store_id"));uint64_t seed=0,max_bytes=0,max_nodes=0;size_t manifests=0;
    for(size_t i=0;i<c->runtime_count;++i){
        struct w2_runtime *r=&c->runtime[i];struct stat identity;if(fstat(r->seed_fd,&identity)||identity.st_dev!=s->root_identity.st_dev)return -1;
        if(r->charge_nodes>s->max_tree_nodes)return -1;
        if(r->charge_bytes>max_bytes)max_bytes=r->charge_bytes;
        if(r->charge_nodes>max_nodes)max_nodes=r->charge_nodes;
        bool duplicate=false,duplicate_manifest=false;
        for(size_t k=0;k<i;++k){struct stat old;if(fstat(c->runtime[k].seed_fd,&old))return -1;
            if(old.st_dev==identity.st_dev&&old.st_ino==identity.st_ino)duplicate=true;
            if(eq(c->runtime[k].descriptor,"component_manifest_digest",w2_str(r->descriptor,"component_manifest_digest")))duplicate_manifest=true;
        }
        if(!duplicate){if(seed>UINT64_MAX-r->charge_bytes)return -1;seed+=r->charge_bytes;}
        if(!duplicate_manifest)manifests+=r->manifest_bytes;
    }
    if(manifests>64u*1024u*1024u||max_bytes>UINT64_MAX/2||max_nodes>UINT64_MAX/2||s->max_bytes<2*max_bytes||s->max_nodes<2*max_nodes||
       seed>UINT64_MAX-s->max_bytes||seed+s->max_bytes>UINT64_MAX-s->min_free||s->capacity<seed+s->max_bytes+s->min_free)return -1;
    return c->recovery_mode?0:empty_directory(c->instances_fd);
}

static bool reason(json_t *j){const char *s=w2_str(j,"reason");const char *names[]={"none","create_failed","delete_failed","job_timeout","worker_lost","identity_mismatch","control_lost"};
    for(size_t i=0;i<7;++i)if(s&&!strcmp(s,names[i]))return true;
    return false;
}
json_t *w2_job_parse(const char *wire,size_t length){
    if(length>W2_JOB_MAX)return NULL;
    json_t *j=w2_json(wire,length);uint64_t n;unsigned value;
    if(!j||!small(j,"v",1,1,&value)||!decimal(j,"seq",&n,true))goto bad;
    if(eq(j,"type","init")||eq(j,"type","ready")){
        bool ready=eq(j,"type","ready");
        if((ready?!KEYS(j,"v","type","seq","store_id","storage_profile_digest","catalog_digest","ok","os_errno"):
                  !KEYS(j,"v","type","seq","store_id","storage_profile_digest","catalog_digest","deadline_ns"))||
           !hex_id(w2_str(j,"store_id"),32)||!w2_is_digest(w2_str(j,"storage_profile_digest"))||!w2_is_digest(w2_str(j,"catalog_digest")))goto bad;
        if(!ready&&!decimal(j,"deadline_ns",&n,true))goto bad;
        if(ready&&(!json_is_boolean(json_object_get(j,"ok"))||(!json_is_null(json_object_get(j,"os_errno"))&&!small(j,"os_errno",1,4095,&value))||
                  (json_is_true(json_object_get(j,"ok"))&&!json_is_null(json_object_get(j,"os_errno")))))goto bad;
    }else if(eq(j,"type","cancel")){
        if(!KEYS(j,"v","type","seq","job_id")||!decimal(j,"job_id",&n,true))goto bad;
    }else if(eq(j,"type","job")||eq(j,"type","job_done")){
        if(!copy_id(w2_str(j,"copy_id"))||!decimal(j,"job_id",&n,true))goto bad;
        bool no_dev=json_is_null(json_object_get(j,"root_dev")),no_ino=json_is_null(json_object_get(j,"root_ino"));
        if(!json_is_boolean(json_object_get(j,"root_removed")))goto bad;
        bool removed=json_is_true(json_object_get(j,"root_removed"));
        if(no_dev!=no_ino||(!no_dev&&(!decimal(j,"root_dev",&n,false)||!decimal(j,"root_ino",&n,true))))goto bad;
        if(removed&&no_dev)goto bad;
        if(eq(j,"type","job")){
            if(!KEYS(j,"v","type","seq","job_id","op","copy_id","runtime_id","deadline_ns","root_dev","root_ino","root_removed")||
               !w2_is_id(w2_str(j,"runtime_id"))||!decimal(j,"deadline_ns",&n,true)||
               (!eq(j,"op","create")&&!eq(j,"op","delete"))||eq(j,"op","create")!=no_dev||(eq(j,"op","create")&&removed))goto bad;
        }else{
            if(!KEYS(j,"v","type","seq","job_id","copy_id","result","root_dev","root_ino","root_removed","reason","os_errno")||!reason(j)||
               (!json_is_null(json_object_get(j,"os_errno"))&&!small(j,"os_errno",1,4095,&value)))goto bad;
            bool success=eq(j,"result","ready")||eq(j,"result","removed"),not_materialized=eq(j,"result","not_materialized");
            if((!success&&!not_materialized&&!eq(j,"result","failed"))||
               (success&&(!eq(j,"reason","none")||!json_is_null(json_object_get(j,"os_errno"))))||
               (!success&&eq(j,"reason","none"))||
               (not_materialized&&(!no_dev||removed||(!eq(j,"reason","create_failed")&&!eq(j,"reason","job_timeout"))))||
               (eq(j,"result","ready")&&(no_dev||removed))||(eq(j,"result","removed")&&(no_dev||!removed)))goto bad;
        }
    }else goto bad;
    return j;
bad:json_decref(j);return NULL;
}
static json_t *message(const char *type,uint64_t seq){char number[24];snprintf(number,sizeof number,"%llu",(unsigned long long)seq);return json_pack("{s:i,s:s,s:s}","v",1,"type",type,"seq",number);}
static void number(json_t *j,const char *key,uint64_t n){char value[24];snprintf(value,sizeof value,"%llu",(unsigned long long)n);json_object_set_new(j,key,json_string(value));}
static void init_fields(json_t *j,struct w2_catalog *c){json_object_set_new(j,"store_id",json_string(c->storage.store_id));json_object_set_new(j,"storage_profile_digest",json_string(c->storage.digest));json_object_set_new(j,"catalog_digest",json_string(c->digest));}
static bool init_matches(json_t *j,struct w2_catalog *c){return eq(j,"store_id",c->storage.store_id)&&eq(j,"storage_profile_digest",c->storage.digest)&&eq(j,"catalog_digest",c->digest);}
static int receive_job(int fd,uint64_t *sequence,json_t **out){
    unsigned char ancillary[CMSG_SPACE(256*sizeof(int))+CMSG_SPACE(sizeof(struct ucred))];char wire[W2_JOB_MAX];
    struct iovec iov={wire,sizeof wire};struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=ancillary,.msg_controllen=sizeof ancillary};
    ssize_t n=recvmsg(fd,&m,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    if(n<0)return -1;
    int owned=-1;int valid=w2_ancillary(&m,false,0,0,0,false,&owned);
    if(owned>=0){close(owned);return -1;}if(valid)return -1;
    if(!n)return -1;
    json_t *j=w2_job_parse(wire,(size_t)n);uint64_t seq;
    if(!j||!decimal(j,"seq",&seq,true)||seq!=*sequence||seq==UINT64_MAX){json_decref(j);return -1;}
    ++*sequence;*out=j;return 1;
}
static int send_job(int fd,json_t *j,uint64_t deadline){
    char *wire=json_dumps(j,JSON_COMPACT|JSON_ENSURE_ASCII);if(!wire)return -1;size_t size=strlen(wire);int result=-1;
    if(size>W2_JOB_MAX)goto done;
    while(w2_now()<deadline){int n=w2_send_control(fd,wire,size,-1);if(n){result=n>0?0:-1;break;}struct pollfd p={fd,POLLOUT,0};(void)poll(&p,1,10);}
done:free(wire);return result;
}
struct worker_context {int fd;uint64_t incoming,outgoing,job,previous_job,deadline;bool cancelled,closed;};
static int checkpoint(void *data){
    struct worker_context *w=data;if(w->closed){errno=EPIPE;return -1;}
    json_t *j=NULL;int rc=receive_job(w->fd,&w->incoming,&j);
    if(rc<0){w->closed=true;errno=EPIPE;return -1;}
    if(rc>0){uint64_t id;bool valid=eq(j,"type","cancel")&&decimal(j,"job_id",&id,true)&&(id==w->job||id==w->previous_job);
        if(valid&&id==w->job)w->cancelled=true;
        json_decref(j);if(!valid){w->closed=true;errno=EPROTO;return -1;}}
    if(w->cancelled){errno=ECANCELED;return -1;}if(w2_now()>=w->deadline){errno=ETIMEDOUT;return -1;}return 0;
}
static int store_identity(struct w2_catalog *c) {
    struct stat root,objects,lock;char uuid[37];uint64_t capacity;
    if(w2_checkpoint()||fstat(c->storage.root_fd,&root)||w2_checkpoint()||fstat(c->instances_fd,&objects)||w2_checkpoint()||
       fstat(c->storage.lock_fd,&lock)||w2_checkpoint()||fs_identity(c->storage.root_fd,uuid,&capacity))return -1;
    if(root.st_dev!=c->storage.root_identity.st_dev||root.st_ino!=c->storage.root_identity.st_ino||
       objects.st_dev!=c->storage.objects_identity.st_dev||objects.st_ino!=c->storage.objects_identity.st_ino||
       root.st_uid||root.st_gid||objects.st_uid||objects.st_gid||lock.st_uid||lock.st_gid||
       (root.st_mode&07777)!=0700||(objects.st_mode&07777)!=0700||(lock.st_mode&07777)!=0600||
       !S_ISREG(lock.st_mode)||lock.st_nlink!=1||lock.st_dev!=root.st_dev||
       strcmp(uuid,c->storage.uuid)||capacity!=c->storage.capacity){errno=ESTALE;return -1;}
    return 0;
}
static int worker(struct w2_catalog *c,int fd){
    struct worker_context w={.fd=fd,.incoming=1,.outgoing=1};enum w2_stage stage;
    umask(0);
    w2_fault_scope("worker.drop.");
    bool healthy=!w2_drop(0,0,&stage);
    w2_fault_scope("");
    json_t *j=NULL;uint64_t until=w2_now()+UINT64_C(5000000000);
    for(;;){int rc=receive_job(fd,&w.incoming,&j);if(rc<0||w2_now()>=until)return 1;if(rc>0)break;struct pollfd p={fd,POLLIN,0};(void)poll(&p,1,10);}
    if(!eq(j,"type","init")||!init_matches(j,c)||!decimal(j,"deadline_ns",&w.deadline,true)||
       w.deadline<=w2_now()||w.deadline-w2_now()>UINT64_C(300000000000)){json_decref(j);return 1;}json_decref(j);
    w2_checkpoint_configure(checkpoint,&w);
    if(healthy)healthy=!store_identity(c)&&!empty_directory(c->instances_fd);
    for(size_t i=0;i<c->runtime_count&&healthy;++i)healthy=!w2_runtime_verify_source(&c->runtime[i]);
    if(checkpoint(&w))healthy=false;
    w2_checkpoint_configure(NULL,NULL);
    j=message("ready",w.outgoing++);init_fields(j,c);json_object_set_new(j,"ok",json_boolean(healthy));json_object_set_new(j,"os_errno",healthy?json_null():json_integer(EIO));
    int rc=send_job(fd,j,w2_now()+UINT64_C(5000000000));json_decref(j);if(rc||!healthy)return 1;
    unsigned delete_jobs=0;
    for(;;){
        j=NULL;rc=receive_job(fd,&w.incoming,&j);if(rc<0)return 0;if(!rc){struct pollfd p={fd,POLLIN,0};(void)poll(&p,1,10);continue;}
        uint64_t id;if(!decimal(j,"job_id",&id,true)){json_decref(j);return 1;}
        if(eq(j,"type","cancel")){bool valid=id==w.previous_job;json_decref(j);if(!valid)return 1;continue;}
        if(!eq(j,"type","job")||id<=w.previous_job){json_decref(j);return 1;}
        struct w2_runtime *r=NULL;for(size_t i=0;i<c->runtime_count;++i)if(eq(c->runtime[i].descriptor,"runtime_id",w2_str(j,"runtime_id")))r=&c->runtime[i];
        if(!r){json_decref(j);return 1;}
        char copy[W2_COPY_CAP];strcpy(copy,w2_str(j,"copy_id"));bool deleting=eq(j,"op","delete"),has_root=false,root_removed=false;
        uint64_t dev=0,ino=0;w.job=id;w.cancelled=false;if(!decimal(j,"deadline_ns",&w.deadline,true)){json_decref(j);return 1;}
        bool known_removed=json_is_true(json_object_get(j,"root_removed"));
        if(deleting){(void)decimal(j,"root_dev",&dev,false);(void)decimal(j,"root_ino",&ino,true);has_root=true;root_removed=known_removed;}
        json_decref(j);w2_checkpoint_configure(checkpoint,&w);errno=0;
#ifdef W2_TESTING
        if(w2_fault("worker.exit"))_exit(9);
        size_t copy_length=strlen(copy);
        bool stall=(!deleting&&copy_length>=4&&!strcmp(copy+copy_length-4,":2:r")&&w2_fault("stall.copy"))||
                   (deleting&&copy_length>=4&&!strcmp(copy+copy_length-4,":1:r")&&w2_fault("stall.cleanup"));
        if(stall){while(!checkpoint(&w))(void)poll(NULL,0,10);rc=-1;}
        else
#endif
        if(deleting){
            ++delete_jobs;
#ifdef W2_TESTING
            if(w2_fault("delete.slow"))(void)poll(NULL,0,6100);
#endif
            if(w2_fault("delete.once")&&delete_jobs==1)rc=-1;
            else rc=w2_runtime_delete(c,r,copy,dev,ino,known_removed,&root_removed);
            root_removed|=known_removed;
        }else{
            struct statvfs fs;uint64_t available=0;
            if(checkpoint(&w)||store_identity(c)||w2_fault("create.statvfs")||fstatvfs(c->instances_fd,&fs)||checkpoint(&w)||!fs.f_frsize||fs.f_bavail>UINT64_MAX/fs.f_frsize)rc=-1;
            else {available=(uint64_t)fs.f_bavail*fs.f_frsize;
                if(available<r->charge_bytes+c->storage.min_free){errno=ENOSPC;rc=-1;}
                else rc=w2_runtime_create(c,r,copy,&dev,&ino,&has_root);}
        }
        int saved=errno;w2_checkpoint_configure(NULL,NULL);w.previous_job=id;w.job=0;
#ifdef W2_TESTING
        if(!deleting&&!rc&&w2_fault("worker.ready.late"))(void)poll(NULL,0,300);
#endif
        if(w.closed||(!has_root&&saved==EEXIST))return 1;
        const char *result=rc?(has_root?"failed":"not_materialized"):(deleting?"removed":"ready");
        /* A failed create which never materialized is a real release fact;
         * its spawn failure is decided by the parent from not_materialized. */
        const char *why=rc?(saved==ETIMEDOUT?"job_timeout":saved==ESTALE&&has_root?"identity_mismatch":deleting?"delete_failed":"create_failed"):"none";
        j=message("job_done",w.outgoing++);number(j,"job_id",id);json_object_set_new(j,"copy_id",json_string(copy));json_object_set_new(j,"result",json_string(result));
        if(has_root&&ino){number(j,"root_dev",dev);number(j,"root_ino",ino);}else{json_object_set_new(j,"root_dev",json_null());json_object_set_new(j,"root_ino",json_null());}
        json_object_set_new(j,"root_removed",json_boolean(root_removed));
        json_object_set_new(j,"reason",json_string(why));json_object_set_new(j,"os_errno",strcmp(why,"none")?json_integer(saved>0&&saved<=4095?saved:EIO):json_null());
        if(w2_fault("worker.result")){json_decref(j);return 1;}
        rc=send_job(fd,j,w2_now()+UINT64_C(5000000000));json_decref(j);if(rc)return 1;
    }
}
int w2_store_start(struct w2_store *s,struct w2_catalog *c,int engine_control){
    memset(s,0,sizeof *s);s->catalog=c;s->fd=-1;s->incoming=s->outgoing=s->next_job=1;s->init_deadline=w2_now()+UINT64_C(300000000000);
    if(flock(c->storage.lock_fd,LOCK_EX|LOCK_NB))return -1;
    int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pair))return -1;
    pid_t pid=fork();if(pid<0){close(pair[0]);close(pair[1]);return -1;}
    if(!pid){close(engine_control);close(pair[0]);_exit(worker(c,pair[1]));}
    close(pair[1]);s->fd=pair[0];s->pid=pid;s->owned=true;s->send_deadline=w2_now()+UINT64_C(5000000000);
    json_t *j=message("init",s->outgoing);init_fields(j,c);number(j,"deadline_ns",s->init_deadline);s->output=json_dumps(j,JSON_COMPACT|JSON_ENSURE_ASCII);json_decref(j);
    return s->output?0:-1;
}
int w2_store_poll(struct w2_store *s,struct w2_job_result *result){
    if(s->dead||s->fd<0)return -1;
    if(!s->ready&&w2_now()>=s->init_deadline)goto bad;
    if(s->output){if(w2_now()>=s->send_deadline)goto bad;int rc=w2_send_control(s->fd,s->output,strlen(s->output),-1);
        if(rc<0)goto bad;
        if(rc){free(s->output);s->output=NULL;++s->outgoing;}}
    json_t *j=NULL;int rc=receive_job(s->fd,&s->incoming,&j);if(rc<0)goto bad;if(!rc)return 0;
    if(!s->ready){bool valid=eq(j,"type","ready")&&init_matches(j,s->catalog)&&json_is_true(json_object_get(j,"ok"));json_decref(j);if(!valid)goto bad;s->ready=true;return 0;}
    uint64_t id;if(!eq(j,"type","job_done")||!decimal(j,"job_id",&id,true)||id!=s->job||!eq(j,"copy_id",s->copy)){json_decref(j);goto bad;}
    memset(result,0,sizeof *result);result->job=id;strcpy(result->copy,s->copy);strcpy(result->result,w2_str(j,"result"));strcpy(result->reason,w2_str(j,"reason"));
    result->has_root=!json_is_null(json_object_get(j,"root_dev"));if(result->has_root){(void)decimal(j,"root_dev",&result->dev,false);(void)decimal(j,"root_ino",&result->ino,true);}
    result->root_removed=json_is_true(json_object_get(j,"root_removed"));
    result->os_errno=(int)json_integer_value(json_object_get(j,"os_errno"));json_decref(j);s->job=0;s->cancelled=false;return 1;
bad:s->dead=true;return -1;
}
int w2_store_submit(struct w2_store *s,const char *copy,const char *runtime,bool deleting,uint64_t deadline,uint64_t dev,uint64_t ino,bool root_removed){
    if(s->dead||!s->ready||s->job||s->output||s->next_job==UINT64_MAX||s->outgoing==UINT64_MAX)return -1;
    json_t *j=message("job",s->outgoing);number(j,"job_id",s->next_job);json_object_set_new(j,"op",json_string(deleting?"delete":"create"));
    json_object_set_new(j,"copy_id",json_string(copy));json_object_set_new(j,"runtime_id",json_string(runtime));number(j,"deadline_ns",deadline);
    if(deleting){number(j,"root_dev",dev);number(j,"root_ino",ino);}else{json_object_set_new(j,"root_dev",json_null());json_object_set_new(j,"root_ino",json_null());}
    json_object_set_new(j,"root_removed",json_boolean(root_removed));
    s->output=json_dumps(j,JSON_COMPACT|JSON_ENSURE_ASCII);json_decref(j);if(!s->output||strlen(s->output)>W2_JOB_MAX){free(s->output);s->output=NULL;return -1;}
    s->job=s->next_job++;strcpy(s->copy,copy);s->send_deadline=w2_now()+UINT64_C(5000000000);return 0;
}
int w2_store_cancel(struct w2_store *s){
    if(s->dead||!s->job||s->cancelled)return 0;
    if(s->output)return 0;
    json_t *j=message("cancel",s->outgoing);number(j,"job_id",s->job);s->output=json_dumps(j,JSON_COMPACT);json_decref(j);
    if(!s->output)return -1;
    s->cancelled=true;s->send_deadline=w2_now()+UINT64_C(5000000000);return 0;
}
void w2_store_close(struct w2_store *s){if(s->fd>=0){close(s->fd);s->fd=-1;}free(s->output);s->output=NULL;s->closing=true;}
static int recovery_checkpoint(void *data){uint64_t deadline=*(uint64_t *)data;if(w2_now()>=deadline){errno=ETIMEDOUT;return -1;}return 0;}
int w2_recover_store(struct w2_catalog *c){
    if(!c->recovery_mode||flock(c->storage.lock_fd,LOCK_EX|LOCK_NB))return -1;
    enum w2_stage stage;if(w2_drop(0,0,&stage))return -1;
    uint64_t total_deadline=w2_now()+UINT64_C(16)*3*c->storage.cleanup_ms*1000000;
    char copies[16][W2_COPY_CAP];size_t count=0;
    int scan=dup(c->instances_fd);if(scan<0)return -1;if(lseek(scan,0,SEEK_SET)<0){close(scan);return -1;}
    DIR *directory=fdopendir(scan);if(!directory){close(scan);return -1;}struct dirent *entry;int result=0;errno=0;
    while((entry=readdir(directory))){if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
        if(count==16||!copy_id(entry->d_name)){result=-1;break;}strcpy(copies[count++],entry->d_name);}
    if(errno)result=-1;
    closedir(directory);if(result)return -1;
    for(size_t i=0;i<count;++i){
        struct stat st;if(fstatat(c->instances_fd,copies[i],&st,AT_SYMLINK_NOFOLLOW)||!S_ISDIR(st.st_mode)||
            st.st_uid!=0||st.st_gid!=0||((st.st_mode&07777)!=0755&&(st.st_mode&07777)!=0700)||st.st_dev!=c->storage.objects_identity.st_dev)return -1;
        struct w2_runtime *runtime=NULL;w2_checkpoint_configure(recovery_checkpoint,&total_deadline);
        for(size_t k=0;k<c->runtime_count;++k)if(!w2_runtime_matches(c,&c->runtime[k],copies[i])){runtime=&c->runtime[k];break;}
        if(!runtime){w2_checkpoint_configure(NULL,NULL);return -1;}
        bool known_removed=false,finished=false;
        for(unsigned attempt=0;attempt<3;++attempt){
            uint64_t deadline=w2_now()+(uint64_t)c->storage.cleanup_ms*1000000;if(deadline>total_deadline)deadline=total_deadline;
            w2_checkpoint_configure(recovery_checkpoint,&deadline);bool removed=false;
            int rc=w2_runtime_delete(c,runtime,copies[i],st.st_dev,st.st_ino,known_removed,&removed);known_removed|=removed;
            if(!rc){finished=true;break;}if(w2_now()>=total_deadline)break;
            if(attempt<2)(void)poll(NULL,0,attempt==0?1000:5000);
        }
        w2_checkpoint_configure(NULL,NULL);if(!finished)return -1;
    }
    if(w2_now()>=total_deadline||empty_directory(c->instances_fd)||fsync(c->instances_fd))return -1;
    struct statvfs fs;if(fstatvfs(c->instances_fd,&fs))return -1;
    if(!fs.f_frsize||fs.f_bavail>UINT64_MAX/fs.f_frsize){errno=EOVERFLOW;return -1;}
    if((uint64_t)fs.f_bavail*fs.f_frsize<c->storage.min_free){errno=ENOSPC;return -1;}
    if(w2_now()>=total_deadline){errno=ETIMEDOUT;return -1;}
    return 0;
}
