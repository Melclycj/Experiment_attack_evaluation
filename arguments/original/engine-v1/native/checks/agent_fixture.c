#define _GNU_SOURCE
/* Trusted post-exec observer. This is not a selected agent or a utility claim.
 * It writes independent kernel observations to its private work directory. */
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int report=-1;
static void text_file(const char *name,const char *path) {
    char buf[32768];int fd=open(path,O_RDONLY|O_CLOEXEC);ssize_t n=fd<0?-1:read(fd,buf,sizeof buf-1);
    if(fd>=0)close(fd);
    dprintf(report,"BEGIN %s\n",name);if(n>0){buf[n]=0;dprintf(report,"%s",buf);}else dprintf(report,"ERROR %d\n",errno);
    dprintf(report,"\nEND %s\n",name);
}
static void *thread(void *arg) {return arg;}
static int child_exit(void *unused) {(void)unused;_exit(0);}
static void result(const char *name,long value,int number) {dprintf(report,"%s=%ld errno=%d\n",name,value,number);}
static void emit(const char *body) {
    size_t n=strlen(body);unsigned char head[4]={(unsigned char)(n>>24),(unsigned char)(n>>16),(unsigned char)(n>>8),(unsigned char)n};
    for(size_t i=0;i<4;++i)if(send(3,head+i,1,MSG_NOSIGNAL)!=1)_exit(91);
    for(size_t i=0;i<n;++i)if(send(3,body+i,1,MSG_NOSIGNAL)!=1)_exit(92);
}
static void inspect(void) {
    /* Snapshot inherited descriptors before opening the report or /proc. */
    int inherited[64];for(int i=0;i<64;++i)inherited[i]=fcntl(i,F_GETFD);
    report=open("/work/report.txt",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(report<0)_exit(90);
    dprintf(report,"EXEC_MARKER pid=%d uid=%u gid=%u\n",getpid(),getuid(),getgid());
    const char *tree[]={"bin","bin/agent-fixture","link"};
    for(size_t i=0;i<3;++i){char path[128];struct stat st;snprintf(path,sizeof path,"/runtime/%s",tree[i]);if(!lstat(path,&st))dprintf(report,"runtime.%s dev=%llu inode=%llu\n",tree[i],(unsigned long long)st.st_dev,(unsigned long long)st.st_ino);}
    int persistent=open("/work/persistent",O_CREAT|O_EXCL|O_WRONLY,0600);
    dprintf(report,"persistent_existed=%d\n",persistent<0&&errno==EEXIST);
    if(persistent>=0){if(write(persistent,"preserved",9)!=9)_exit(94);close(persistent);}
    for(int i=0;i<64;++i)if(inherited[i]>=0)dprintf(report,"inherited_fd=%d flags=%d\n",i,inherited[i]);
    uid_t r,e,s;gid_t gr,ge,gs;getresuid(&r,&e,&s);getresgid(&gr,&ge,&gs);
    dprintf(report,"uids=%u,%u,%u gids=%u,%u,%u groups=%d\n",r,e,s,gr,ge,gs,getgroups(0,NULL));
    for(int i=0;i<4;++i){char path[64],target[1024];snprintf(path,sizeof path,"/proc/self/fd/%d",i);ssize_t n=readlink(path,target,sizeof target-1);if(n>=0){target[n]=0;dprintf(report,"fd%d=%s\n",i,target);}}
    text_file("status","/proc/self/status");text_file("mountinfo","/proc/self/mountinfo");text_file("net","/proc/self/net/dev");
    const char *ns[]={"mnt","pid","net","ipc","user"};
    for(size_t i=0;i<5;++i){char path[64],target[128];snprintf(path,sizeof path,"/proc/self/ns/%s",ns[i]);ssize_t n=readlink(path,target,sizeof target-1);if(n>=0){target[n]=0;dprintf(report,"ns.%s=%s\n",ns[i],target);}}
    errno=0;int fd=open("/runtime/bin/agent-fixture",O_WRONLY);result("runtime_write",fd,errno);if(fd>=0)close(fd);
    errno=0;int rc=access("/var/lib",F_OK);result("outside_visible",rc,errno);
    errno=0;rc=access("/.oldroot",F_OK);result("oldroot_visible",rc,errno);
    errno=0;rc=setuid(0);result("setuid_zero",rc,errno);
    errno=0;rc=unshare(CLONE_NEWUSER);result("unshare_user",rc,errno);
    errno=0;long value=syscall(SYS_clone3,NULL,0);result("clone3",value,errno);
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    errno=0;rc=clone(child_exit,(char *)stack+65536,CLONE_NEWUSER|SIGCHLD,NULL);result("clone_user",rc,errno);
    if(rc>0)waitpid(rc,NULL,0);
    munmap(stack,65536);
    pthread_t t;void *answer=NULL;rc=pthread_create(&t,NULL,thread,(void *)0x1234);
    if(!rc)rc=pthread_join(t,&answer);
    result("pthread",rc,answer==(void *)0x1234?0:EINVAL);
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/tmp/forbidden");
    errno=0;rc=bind(3,(struct sockaddr *)&address,sizeof address);result("bind",rc,errno);
    errno=0;rc=connect(3,(struct sockaddr *)&address,sizeof address);result("connect",rc,errno);
    errno=0;value=syscall(SYS_io_uring_setup,1,NULL);result("io_uring_setup",value,errno);
    errno=0;value=syscall(SYS_io_uring_enter,-1,0,0,0,NULL,0);result("io_uring_enter",value,errno);
    errno=0;value=syscall(SYS_io_uring_register,-1,0,NULL,0);result("io_uring_register",value,errno);
    errno=0;value=syscall(SYS_sysinfo,NULL);result("sysinfo",value,errno);errno=0;value=syscall(SYS_sync);result("sync",value,errno);errno=0;value=syscall(SYS_syncfs,-1);result("syncfs",value,errno);errno=0;fd=open("/proc/meminfo",O_RDONLY|O_CLOEXEC);result("proc_meminfo",fd,errno);if(fd>=0)close(fd);text_file("limits","/proc/self/limits");
    const char *abi[]={"ia32","x32"};
    for(int i=0;i<2;++i) {
        pid_t child=fork();if(!child){
            if(!i){long eax=20;__asm__ volatile("int $0x80":"+a"(eax)::"memory");_exit(99);}
            (void)syscall(0x40000000L|SYS_getpid);_exit(99);
        }
        int status=0;waitpid(child,&status,0);dprintf(report,"abi.%s.signal=%d exit=%d\n",abi[i],WIFSIGNALED(status)?WTERMSIG(status):0,WIFEXITED(status)?WEXITSTATUS(status):-1);
    }
    struct sockaddr_un addr; socklen_t n=sizeof addr;
    rc=getsockname(3,(struct sockaddr *)&addr,&n);dprintf(report,"socket.local.rc=%d size=%u\n",rc,(unsigned)n);
    int sndbuf=0,rcvbuf=0;socklen_t option_size=sizeof sndbuf;
    if(getsockopt(3,SOL_SOCKET,SO_SNDBUF,&sndbuf,&option_size)||
       getsockopt(3,SOL_SOCKET,SO_RCVBUF,&rcvbuf,&option_size))_exit(18);
    dprintf(report,"socket.sndbuf=%d rcvbuf=%d\n",sndbuf,rcvbuf);
    n=sizeof addr;rc=getpeername(3,(struct sockaddr *)&addr,&n);dprintf(report,"socket.peer.rc=%d size=%u\n",rc,(unsigned)n);
    /* Copy an executable into /work and execute it to test the actual mount. */
    int src=open("/runtime/bin/agent-fixture",O_RDONLY|O_CLOEXEC),dst=open("/work/program",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0700);
    char buffer[65536];ssize_t got;int copied=src>=0&&dst>=0;
    while(copied&&(got=read(src,buffer,sizeof buffer))>0){if(write(dst,buffer,(size_t)got)!=got)copied=0;}
    if(src>=0)close(src);
    if(dst>=0)close(dst);
    pid_t program=copied?fork():-1;
    if(program==0){char *args[]={"/work/program","work-child",NULL};execv(args[0],args);_exit(126);}
    int status=0;if(program>0)waitpid(program,&status,0);
    dprintf(report,"work_exec=%d\n",program>0&&WIFEXITED(status)?WEXITSTATUS(status):-1);
    int tmp=open("/tmp/private-marker",O_CREAT|O_EXCL|O_WRONLY,0600);result("private_tmp",tmp,errno);if(tmp>=0)close(tmp);
    int shm=open("/dev/shm/private-marker",O_CREAT|O_EXCL|O_WRONLY,0600);result("private_shm",shm,errno);if(shm>=0)close(shm);
    if(fsync(report))_exit(93);
    close(report);report=-1;
}
/* "agent <mode>": a scripted w2-local/2 peer for the engine's receive checks, with misbehaviour switches.
 * Progress goes to /work/agent.txt; the trusted runner reads it after the execution is empty. */
#define HELLO_BODY(adapter) "{\"v\":2,\"type\":\"hello\",\"adapter_id\":\"" adapter "\",\"protocol\":\"w2-local/2\"}"
static const char cancel_body[]="{\"v\":2,\"type\":\"cancel\",\"reply_to\":\"1\",\"reason\":\"user\"}";
static int note=-1;
static void read_all(void *out,size_t n) {
    size_t got=0;
    while(got<n){ssize_t r=read(3,(char *)out+got,n-got);if(r>0)got+=(size_t)r;else if(r<0&&errno==EINTR)continue;else _exit(96);}
}
static void wait_eof(void) {
    char buf[256];
    for(;;){ssize_t r=read(3,buf,sizeof buf);if(r>0)continue;if(r<0&&errno==EINTR)continue;break;}
}
static void sent(const char *what) {dprintf(note,"sent=%s\n",what);}
/* "agent task": serves task_starts after the welcome. Each task input is a ';'-separated script written by the
 * trusted driver; every frame received is logged verbatim as "frame=<json>" for the runner to check. */
static char frame_body[65537];
static size_t next_frame(void) {
    unsigned char head[4];size_t got=0;
    while(got<4){ssize_t r=read(3,head+got,4-got);if(r>0)got+=(size_t)r;else if(r<0&&errno==EINTR)continue;else return 0;}
    size_t n=(size_t)head[0]<<24|(size_t)head[1]<<16|(size_t)head[2]<<8|head[3];
    if(!n||n>65536)_exit(97);
    read_all(frame_body,n);frame_body[n]=0;dprintf(note,"frame=%s\n",frame_body);return n;
}
static int field(const char *body,const char *key,char *out,size_t cap) {
    char pattern[64];snprintf(pattern,sizeof pattern,"\"%s\":\"",key);
    const char *at=strstr(body,pattern);if(!at)return 0;at+=strlen(pattern);
    size_t i=0;while(at[i]&&at[i]!='"'&&i+1<cap){out[i]=at[i];++i;}out[i]=0;return 1;
}
static void emitf(const char *fmt,...) {
    static char buf[65536];va_list ap;va_start(ap,fmt);int n=vsnprintf(buf,sizeof buf,fmt,ap);va_end(ap);
    if(n<0||(size_t)n>=sizeof buf)_exit(89);
    emit(buf);dprintf(note,"sent=%s\n",buf);
}
static const char model_args[]="{\"messages\":[{\"role\":\"user\",\"text\":\"hi\"}],\"max_output_tokens\":16}";
static char call_id[32],prev_call[32],task_id[128];
static void wait_reply(const char *id,int want_cancel) {
    char kind[32],reply[32];
    for(;;) {
        if(!next_frame()){dprintf(note,"eof-in-wait\n");return;}
        if(!field(frame_body,"type",kind,sizeof kind)||!field(frame_body,"reply_to",reply,sizeof reply))continue;
        if(want_cancel&&!strcmp(kind,"cancel")&&!strcmp(reply,call_id))return;
        if(!want_cancel&&!strcmp(reply,id)&&(!strcmp(kind,"result")||!strcmp(kind,"error")))return;
    }
}
static void run_script(char *script) {
    for(char *save=NULL,*step=strtok_r(script,";",&save);step;step=strtok_r(NULL,";",&save)) {
        char op[16]="",a[64]="",b[96]="",c[64]="",d[256]="";
        sscanf(step,"%15s %63s %95s %63s %255s",op,a,b,c,d);
        const char *args=!strcmp(d,"M")?model_args:d;
        if(!strcmp(op,"req")||!strcmp(op,"oldreq"))
            emitf("{\"v\":2,\"type\":\"request\",\"id\":\"%s\",\"task_call_id\":\"%s\",\"task_id\":\"%s\",\"resource_id\":\"%s\",\"action\":\"%s\",\"args\":%s}",
                  a,!strcmp(op,"req")?call_id:prev_call,task_id,b,c,args);
        else if(!strcmp(op,"wait"))wait_reply(a,0);
        else if(!strcmp(op,"cancel"))emitf("{\"v\":2,\"type\":\"cancel\",\"reply_to\":\"%s\",\"reason\":\"user\"}",a);
        else if(!strcmp(op,"result"))emitf("{\"v\":2,\"type\":\"task_result\",\"reply_to\":\"%s\",\"status\":\"%s\",\"output\":\"fixture\"}",call_id,a);
        else if(!strcmp(op,"futureresult"))emitf("{\"v\":2,\"type\":\"task_result\",\"reply_to\":\"99\",\"status\":\"ok\",\"output\":\"\"}");
        else if(!strcmp(op,"hold")){wait_reply("",1);emitf("{\"v\":2,\"type\":\"task_result\",\"reply_to\":\"%s\",\"status\":\"cancelled\",\"output\":\"\"}",call_id);}
        else _exit(88);
    }
}
static void serve_tasks(void) {
    char kind[32],input[4096];
    while(next_frame()) {
        if(!field(frame_body,"type",kind,sizeof kind))continue;
        if(!strcmp(kind,"shutdown")){emitf("{\"v\":2,\"type\":\"bye\",\"reason\":\"normal\"}");return;}
        if(strcmp(kind,"task_start"))continue;
        memcpy(prev_call,call_id,sizeof call_id);
        if(!field(frame_body,"id",call_id,sizeof call_id)||!field(frame_body,"task_id",task_id,sizeof task_id)
           ||!field(frame_body,"input",input,sizeof input))_exit(87);
        run_script(input);
        if(fsync(note))_exit(93);
    }
}
static int agent(const char *mode) {
    note=open("/work/agent.txt",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(note<0)return 95;
    dprintf(note,"mode=%s pid=%d uid=%u\n",mode,getpid(),getuid());
    int f=fcntl(3,F_GETFL);if(f>=0)fcntl(3,F_SETFL,f&~O_NONBLOCK);
    if(!strcmp(mode,"early-request")) {
        emit("{\"v\":2,\"type\":\"request\",\"id\":\"1\",\"task_call_id\":\"1\",\"task_id\":\"t\",\"resource_id\":\"test-doc\",\"action\":\"document.read\",\"args\":{}}");
        sent("request");
    } else if(!strcmp(mode,"bad-adapter")) {
        emit(HELLO_BODY("other"));sent("hello adapter_id=other");
    } else {
        emit(HELLO_BODY("fixture"));sent("hello");
        unsigned char head[4];read_all(head,4);
        size_t n=(size_t)head[0]<<24|(size_t)head[1]<<16|(size_t)head[2]<<8|head[3];
        static char body[65536];if(!n||n>sizeof body)_exit(97);
        read_all(body,n);dprintf(note,"received=%.*s\n",(int)n,body);
        if(!strcmp(mode,"double-hello")){emit(HELLO_BODY("fixture"));sent("hello");}
        else if(!strcmp(mode,"bye")){emit("{\"v\":2,\"type\":\"bye\",\"reason\":\"normal\"}");sent("bye");}
        else if(!strcmp(mode,"partial")){unsigned char two[2]={0,0};if(send(3,two,2,MSG_NOSIGNAL)!=2)_exit(98);sent("partial-header");}
        else if(!strcmp(mode,"oob")){errno=0;ssize_t rc=send(3,"x",1,MSG_OOB|MSG_NOSIGNAL);dprintf(note,"sent=oob rc=%zd errno=%d\n",rc,errno);}
        else if(!strcmp(mode,"oversize")){unsigned char big[4]={0,1,0,1};if(send(3,big,4,MSG_NOSIGNAL)!=4)_exit(98);sent("length=65537");}
        else if(!strcmp(mode,"rights")) {
            size_t len=strlen(cancel_body);unsigned char wire[256];
            wire[0]=0;wire[1]=0;wire[2]=(unsigned char)(len>>8);wire[3]=(unsigned char)len;memcpy(wire+4,cancel_body,len);
            union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(int))];} control;memset(&control,0,sizeof control);
            struct iovec iov={wire,len+4};struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof control.bytes};
            struct cmsghdr *h=CMSG_FIRSTHDR(&m);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;h->cmsg_len=CMSG_LEN(sizeof(int));
            int passed=0;memcpy(CMSG_DATA(h),&passed,sizeof passed);
            errno=0;ssize_t rc=sendmsg(3,&m,MSG_NOSIGNAL);dprintf(note,"sent=cancel+rights rc=%zd errno=%d\n",rc,errno);
        } else if(!strcmp(mode,"fork-sender")) {
            pid_t child=fork();
            if(!child){emit(cancel_body);_exit(0);}
            int status=0;waitpid(child,&status,0);
            dprintf(note,"sent=cancel by child pid=%d exit=%d\n",child,WIFEXITED(status)?WEXITSTATUS(status):-1);
            emit(cancel_body);sent("cancel by parent");
            emit("{\"v\":2,\"type\":\"bye\",\"reason\":\"normal\"}");sent("bye");
        } else if(!strcmp(mode,"task"))serve_tasks();
        else if(strcmp(mode,"welcome"))_exit(99);
    }
    if(fsync(note))_exit(93);
    wait_eof();
    dprintf(note,"eof\n");close(note);
    return 0;
}
int main(int argc,char **argv) {
    if(argc>1&&!strcmp(argv[1],"work-child"))return 37;
    if(argc>2&&!strcmp(argv[1],"agent")){inspect();return agent(argv[2]);}
    if(argc>1&&!strcmp(argv[1],"linger")) {
        int fd=open("/work/linger.txt",O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(fd<0)return 90;
        dprintf(fd,"pid1=%d uid=%u\n",getpid(),getuid());
        pid_t child=fork();if(!child){setsid();for(;;)pause();}
        dprintf(fd,"descendant=%d\n",child);close(fd);
        emit("{\"v\":2,\"type\":\"hello\",\"adapter_id\":\"fixture\",\"protocol\":\"w2-local/2\"}");
        for(;;)pause();
    }
    inspect();
    emit("{\"v\":2,\"type\":\"hello\",\"adapter_id\":\"fixture\",\"protocol\":\"w2-local/2\"}");
    /* Wait for a trusted test driver's finish; blocking is confined to this
     * disposable fixture, not the production spawner event loop. */
    int f=fcntl(3,F_GETFL);if(f>=0)fcntl(3,F_SETFL,f&~O_NONBLOCK);
    char c;while(read(3,&c,1)<0&&errno==EINTR){};
    return 0;
}
