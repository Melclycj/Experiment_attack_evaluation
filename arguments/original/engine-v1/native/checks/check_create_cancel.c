#define _GNU_SOURCE
/* Uses the actual private checkpoint/parser and production file functions.
 * Only a source-open return boundary is controlled by link-time observers. */
#include "../sandbox/storage.c"
#include <assert.h>
#include <stdarg.h>
#include <linux/openat2.h>
#include <sys/syscall.h>

long __real_syscall(long number,...);
uint64_t __real_w2_now(void);
int __real_close(int fd);
int __real_fstat(int fd,struct stat *out);
static bool observing,source_returned,source_closed,force_deadline;
static int source_root,source_open_fd=-1,peer_fd=-1;
static unsigned destination_creates;
static const char *observer_mode;
static uint64_t observed_deadline;
static int store_root;
static bool store_stat_returned;

int __wrap_fstat(int fd,struct stat *out){
    int rc=__real_fstat(fd,out);
    if(observing&&fd==store_root&&!strncmp(observer_mode,"store-",6)){
        assert(!rc);store_stat_returned=true;
        if(!strcmp(observer_mode,"store-deadline"))force_deadline=true;
        else {errno=EIO;return -1;}
    }
    return rc;
}

uint64_t __wrap_w2_now(void){return force_deadline?observed_deadline:__real_w2_now();}
int __wrap_close(int fd){
    int rc=__real_close(fd);
    if(observing&&source_returned&&fd==source_open_fd&&!rc)source_closed=true;
    return rc;
}
long __wrap_syscall(long number,...){
    /* Only openat2 is reached by this test's catalog/file call graph. Fail if
     * it expands, instead of forwarding unknown variadic signatures. */
    assert(number==SYS_openat2);
    va_list args;va_start(args,number);
    int dir=va_arg(args,int);const char *path=va_arg(args,const char *);
    struct open_how *how=va_arg(args,struct open_how *);size_t size=va_arg(args,size_t);
    va_end(args);
    if(observing&&(how->flags&O_CREAT))++destination_creates;
    long rc=__real_syscall(number,dir,path,how,size);
    if(observing&&!source_returned&&dir==source_root&&!strcmp(path,"bin/agent-fixture")&&!(how->flags&O_CREAT)){
        assert(rc>=0);source_returned=true;source_open_fd=(int)rc;
        if(!strcmp(observer_mode,"deadline"))force_deadline=true;
        else if(!strcmp(observer_mode,"cancel")){
            const char cancel[]="{\"v\":1,\"type\":\"cancel\",\"seq\":\"1\",\"job_id\":\"1\"}";
            assert(send(peer_fd,cancel,sizeof cancel-1,0)==(ssize_t)sizeof cancel-1);
        }else if(!strcmp(observer_mode,"eof")){assert(!close(peer_fd));peer_fd=-1;}
    }
    return rc;
}
static size_t open_fds(void){
    DIR *dir=opendir("/proc/self/fd");assert(dir);struct dirent *entry;size_t count=0;
    while((entry=readdir(dir)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,".."))++count;
    closedir(dir);return count;
}
int main(int argc,char **argv){
    assert(argc==4);observer_mode=argv[3];
    bool normal=!strcmp(observer_mode,"normal");
    bool store_check=!strcmp(observer_mode,"store-deadline")||!strcmp(observer_mode,"store-io-error");
    assert(normal||store_check||!strcmp(observer_mode,"deadline")||!strcmp(observer_mode,"cancel")||!strcmp(observer_mode,"eof"));
    struct w2_catalog *c=calloc(1,sizeof *c);assert(c&&!w2_catalog_load(c,argv[1],argv[2]));
    enum w2_stage stage;assert(!w2_drop(0,0,&stage));
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pair));
    peer_fd=pair[1];source_root=c->runtime[0].seed_fd;store_root=c->storage.root_fd;
    struct worker_context w={.fd=pair[0],.incoming=1,.outgoing=1,.job=1,
                             .deadline=__real_w2_now()+UINT64_C(5000000000)};
    observed_deadline=w.deadline;
    const char *copy="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:r";
    size_t before=open_fds();uint64_t dev=0,ino=0;bool created=false;
    w2_checkpoint_configure(checkpoint,&w);observing=true;errno=0;
    if(store_check){
        int rc=store_identity(c),saved=errno;
        assert(store_stat_returned&&!source_returned&&!destination_creates);
        assert(rc==-1&&saved==(!strcmp(observer_mode,"store-deadline")?ETIMEDOUT:EIO));
        observing=false;force_deadline=false;w2_checkpoint_configure(NULL,NULL);
        assert(open_fds()==before);
        printf("{\"check\":\"store-identity-preserves-call-or-deadline-error\",\"mode\":\"%s\","
               "\"actual_fstat\":true,\"injected_io_error\":%s,\"os_errno\":%d,"
               "\"destination_create_calls\":0,\"fd_count_unchanged\":true,\"result\":\"passed\"}\n",
               observer_mode,!strcmp(observer_mode,"store-io-error")?"true":"false",saved);
        close(pair[0]);close(peer_fd);w2_catalog_free(c);free(c);return 0;
    }
    int rc=w2_runtime_create(c,&c->runtime[0],copy,&dev,&ino,&created),saved=errno;
    assert(source_returned&&source_closed&&created&&dev&&ino);
    assert(fcntl(source_open_fd,F_GETFD)==-1&&errno==EBADF);
    observing=false;force_deadline=false;w2_checkpoint_configure(NULL,NULL);
    size_t after=open_fds();assert(after==before-(!strcmp(observer_mode,"eof")?1u:0u));
    int expected=!strcmp(observer_mode,"deadline")?ETIMEDOUT:!strcmp(observer_mode,"cancel")?ECANCELED:EPIPE;
    if(normal)assert(!rc&&destination_creates==2);
    else assert(rc==-1&&saved==expected&&!destination_creates);
    struct stat root;assert(!fstatat(c->instances_fd,copy,&root,AT_SYMLINK_NOFOLLOW));
    assert((uint64_t)root.st_dev==dev&&(uint64_t)root.st_ino==ino);
    bool removed=false;assert(!w2_runtime_delete(c,&c->runtime[0],copy,dev,ino,false,&removed)&&removed);
    printf("{\"check\":\"source-open-return-before-destination-create\",\"mode\":\"%s\","
           "\"actual_source_open\":true,\"destination_create_calls\":%u,\"source_fd_closed\":true,"
           "\"fd_count_before\":%zu,\"fd_count_after\":%zu,\"partial_identity_preserved\":true,"
           "\"runtime_create_result\":%d,\"os_errno\":%d,\"private_cancel_consumed\":%s,"
           "\"private_eof_consumed\":%s,\"test_cleanup\":\"removed\",\"result\":\"passed\"}\n",
           observer_mode,destination_creates,before,after,rc,rc?saved:0,
           w.cancelled?"true":"false",w.closed?"true":"false");
    close(pair[0]);if(peer_fd>=0)close(peer_fd);w2_catalog_free(c);free(c);return 0;
}
