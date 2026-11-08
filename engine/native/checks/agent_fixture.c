#define _GNU_SOURCE
/* Trusted post-exec observer. This is not a selected agent or a utility claim.
 * It writes independent kernel observations to its private work directory. */
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
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
#define W2_TEST_MCP_PORT 3129   /* the mcp_port of the test deployments (run_sandbox_checks.py deployment) */
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
    {struct stat ws;if(!stat("/work",&ws))dprintf(report,"work.identity dev=%llu inode=%llu\n",
        (unsigned long long)ws.st_dev,(unsigned long long)ws.st_ino);}   /* S-25: the fixed subdirectory, not the root */
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
    /* v2: the terminal (S-07), the proxy/CA environment and the cell files (build plan 1.1, 1.5) */
    for(int i=0;i<3;++i){char name[8];snprintf(name,sizeof name,"tty.%d",i);errno=0;int t=isatty(i);result(name,t,errno);}
    const char *vars[]={"HTTPS_PROXY","HTTP_PROXY","NO_PROXY","NODE_EXTRA_CA_CERTS","SSL_CERT_FILE","GIT_SSL_CAINFO","HOME"};
    for(size_t i=0;i<7;++i){const char *v=getenv(vars[i]);dprintf(report,"env.%s=%s\n",vars[i],v?v:"(unset)");}
    errno=0;rc=access("/w2/ca/ca.pem",R_OK);result("ca_readable",rc,errno);
    errno=0;rc=access("/w2/ca/ca.key",R_OK);result("ca_key_readable",rc,errno);
    errno=0;fd=open("/w2/ca/ca.pem",O_WRONLY);result("ca_write",fd,errno);if(fd>=0)close(fd);
    errno=0;fd=open("/w2/ca/extra",O_WRONLY|O_CREAT,0644);result("ca_dir_write",fd,errno);if(fd>=0)close(fd);
    {struct sockaddr_un pa={.sun_family=AF_UNIX};strcpy(pa.sun_path,"/run/w2/proxy.sock");int ps=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
     errno=0;rc=ps<0?-1:connect(ps,(struct sockaddr *)&pa,sizeof pa);result("proxy_sock_connect",rc,errno);if(ps>=0)close(ps);}
    /* validation.md H-05: the row's file port reaches the agent's cell at /run/w2/file.sock */
    {struct sockaddr_un pa={.sun_family=AF_UNIX};strcpy(pa.sun_path,"/run/w2/file.sock");int ps=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
     errno=0;rc=ps<0?-1:connect(ps,(struct sockaddr *)&pa,sizeof pa);result("file_sock_connect",rc,errno);if(ps>=0)close(ps);}
    {int port=0;const char *hp=getenv("HTTPS_PROXY");if(hp)sscanf(hp,"http://127.0.0.1:%d",&port);
     struct sockaddr_in in={.sin_family=AF_INET,.sin_port=htons((unsigned short)port)};in.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
     int fs=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);errno=0;rc=fs<0?-1:connect(fs,(struct sockaddr *)&in,sizeof in);result("proxy_port_connect",rc,errno);if(fs>=0)close(fs);}
    /* phase 2 (validation.md S-19): the fixed socket-family filter; AF_ALG, AF_VSOCK and the uevent and diag netlink
     * protocols would open unprivileged without it, so their EPERM is the filter's */
    {static const struct {const char *name;int domain,type,protocol;} fam[]={
         {"fam.unix",AF_UNIX,SOCK_STREAM,0},{"fam.inet6",AF_INET6,SOCK_STREAM,0},
         {"fam.netlink_route",AF_NETLINK,SOCK_RAW,NETLINK_ROUTE},{"fam.netlink_uevent",AF_NETLINK,SOCK_DGRAM,NETLINK_KOBJECT_UEVENT},
         {"fam.netlink_diag",AF_NETLINK,SOCK_DGRAM,NETLINK_SOCK_DIAG},{"fam.vsock",AF_VSOCK,SOCK_STREAM,0},
         {"fam.packet",AF_PACKET,SOCK_DGRAM,0},{"fam.alg",AF_ALG,SOCK_SEQPACKET,0}};
     for(size_t i=0;i<sizeof fam/sizeof fam[0];++i){errno=0;int s=socket(fam[i].domain,fam[i].type|SOCK_CLOEXEC,fam[i].protocol);
         result(fam[i].name,s<0?-1:0,errno);if(s>=0)close(s);}
     errno=0;long hs=syscall(SYS_socket,(1L<<32)|AF_VSOCK,SOCK_STREAM,0);result("fam.vsock_high",hs<0?-1:0,errno);if(hs>=0)close((int)hs);
     int sv[2];errno=0;int prc=socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sv);result("fam.pair_unix",prc,errno);
     if(!prc){close(sv[0]);close(sv[1]);}
     errno=0;prc=socketpair(AF_VSOCK,SOCK_STREAM,0,sv);result("fam.pair_vsock",prc,errno);}
    /* phase 2 step 8 (validation.md D-14): a Unix socket and a FIFO that a host-user process made in the workspace;
     * only the runner's explicit-channel case makes them, every other row gets ENOENT */
    {struct sockaddr_un wa={.sun_family=AF_UNIX};strcpy(wa.sun_path,"/work/host.sock");int ws=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
     errno=0;rc=ws<0?-1:connect(ws,(struct sockaddr *)&wa,sizeof wa);result("work_sock_connect",rc,errno);
     if(!rc){errno=0;ssize_t s=send(ws,"cell-sock",9,MSG_NOSIGNAL);result("work_sock_send",(long)s,errno);}
     if(ws>=0)close(ws);
     errno=0;int wf=open("/work/host.fifo",O_WRONLY|O_NONBLOCK|O_CLOEXEC);result("work_fifo_open",wf<0?-1:0,errno);
     if(wf>=0){errno=0;ssize_t w=write(wf,"cell-fifo",9);result("work_fifo_write",(long)w,errno);close(wf);}}
    /* the workspace rework (validation.md S-25, D-17): asked by the runner's request file, the cell uid opens what it
     * can, /work to 0777 and a setuid file of its own, so the runner can show the host user still gets nowhere */
    if(!access("/work/.open-the-door",F_OK)) {
        errno=0;rc=chmod("/work",0777);result("door_work_chmod",rc,errno);
        int sf=open("/work/door-setuid",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0700);
        errno=0;rc=sf<0?-1:fchmod(sf,04755);result("door_setuid_file",rc,errno);if(sf>=0)close(sf);
    }
    errno=0;rc=access("/tmp/.w2-frontend-ready",F_OK);result("frontend_ready",rc,errno);
    /* validation.md H-23: the in-cell MCP server (in these runs the frontend's stand-in, same argv tail) listens on the
     * test deployments' mcp_port and wrote its own ready file before this exec */
    {struct sockaddr_in in={.sin_family=AF_INET,.sin_port=htons(W2_TEST_MCP_PORT)};in.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
     int ms=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);errno=0;rc=ms<0?-1:connect(ms,(struct sockaddr *)&in,sizeof in);
     result("mcp_port_connect",rc,errno);if(ms>=0)close(ms);}
    errno=0;rc=access("/tmp/.w2-mcp-ready",F_OK);result("mcp_ready",rc,errno);
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
    /* v2: bind and connect are allowed per row; probe them on a fresh AF_UNIX socket, never on the control channel
     * (binding fd 3 would give the channel a name, which the engine side requires it not to have). */
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/tmp/forbidden");
    {int ux=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
     errno=0;rc=ux<0?-1:bind(ux,(struct sockaddr *)&address,sizeof address);result("bind",rc,errno);
     errno=0;rc=ux<0?-1:connect(ux,(struct sockaddr *)&address,sizeof address);result("connect",rc,errno);
     if(ux>=0)close(ux);}
    /* v2 (validation.md S-10): the socket family on lo works; an address outside lo is unreachable in this netns;
     * the keyring calls stay forbidden. */
    {int s=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);result("inet.socket",s,errno);
     struct sockaddr_in in={.sin_family=AF_INET,.sin_port=0};in.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
     errno=0;rc=s<0?-1:bind(s,(struct sockaddr *)&in,sizeof in);result("inet.bind",rc,errno);
     errno=0;rc=s<0?-1:listen(s,1);result("inet.listen",rc,errno);
     socklen_t il=sizeof in;if(s>=0)getsockname(s,(struct sockaddr *)&in,&il);
     int cl=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);errno=0;rc=cl<0?-1:connect(cl,(struct sockaddr *)&in,sizeof in);result("inet.connect",rc,errno);
     errno=0;int ac=s<0?-1:accept4(s,NULL,NULL,SOCK_CLOEXEC);result("inet.accept",ac,errno);
     struct sockaddr_in out={.sin_family=AF_INET,.sin_port=htons(9)};out.sin_addr.s_addr=htonl(0x0AFFFFFEu);
     int oc=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);errno=0;rc=oc<0?-1:connect(oc,(struct sockaddr *)&out,sizeof out);result("inet.outside",rc,errno);
     if(ac>=0)close(ac);
     if(cl>=0)close(cl);
     if(s>=0)close(s);
     if(oc>=0)close(oc);}
    errno=0;value=syscall(SYS_keyctl,0,0,0,0,0);result("keyctl",value,errno);
    errno=0;value=syscall(SYS_add_key,"user","w2",NULL,0,0);result("add_key",value,errno);
    errno=0;value=syscall(SYS_request_key,"user","w2",NULL,0);result("request_key",value,errno);
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
/* "agent <mode>": a scripted peer of the agent-side control channel for the engine's receive checks, with
 * misbehaviour switches. The row is ACTIVE from the whole COMMIT and there is no handshake; every well-formed message
 * is answered 'unsupported_kind' (validation.md K-04). Progress goes to /work/agent.txt; the trusted runner reads it
 * after the execution is empty. A mode that logs answers sends one last message, the acknowledgement, only after the
 * log is on disk: the driver closes the row once it has seen that message, so no answer is lost to the close. */
static const char first_body[]="{\"v\":2,\"type\":\"request\",\"id\":\"1\"}";
static const char second_body[]="{\"v\":2,\"type\":\"request\",\"id\":\"2\"}";
static const char ack_body[]="{\"v\":2,\"type\":\"ack\"}";
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
/* Every frame received is logged verbatim as "frame=<json>" for the runner to check. */
static char frame_body[65537];
static size_t next_frame(void) {
    unsigned char head[4];size_t got=0;
    while(got<4){ssize_t r=read(3,head+got,4-got);if(r>0)got+=(size_t)r;else if(r<0&&errno==EINTR)continue;else return 0;}
    size_t n=(size_t)head[0]<<24|(size_t)head[1]<<16|(size_t)head[2]<<8|head[3];
    if(!n||n>65536)_exit(97);
    read_all(frame_body,n);frame_body[n]=0;dprintf(note,"frame=%s\n",frame_body);return n;
}
/* "agent proxy" (block 4 integration): one canonical-form request over the row's proxy path
 * (/run/w2/proxy.sock, validation.md S-01): GET http://localhost:80/, which the fallback entry allows without a
 * credential and the PDP allows; the connector resolves the name only then and its address filter refuses 127.0.0.1
 * (条款 7), so the whole judgment path runs with no network. (An IP literal would be refused before the core since
 * phase 2, C-35.)
 * The frames that come back are logged as proxy=... lines. */
static void put_field(unsigned char **p,const void *data,size_t n) {
    uint32_t len=htonl((uint32_t)n);memcpy(*p,&len,4);*p+=4;memcpy(*p,data,n);*p+=n;
}
static void proxy_request(void) {
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0){dprintf(note,"proxy=socket errno=%d\n",errno);return;}
    struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,"/run/w2/proxy.sock");
    if(connect(fd,(struct sockaddr *)&a,sizeof a)){dprintf(note,"proxy=connect errno=%d\n",errno);close(fd);return;}
    unsigned char frame[128],*p=frame+4;*p++=0x01;uint16_t port=htons(80);uint32_t zero=0;
    put_field(&p,"GET",3);put_field(&p,"http",4);put_field(&p,"localhost",9);put_field(&p,&port,2);put_field(&p,"/",1);
    put_field(&p,"",0);put_field(&p,&zero,4);put_field(&p,"",0);
    uint32_t total=htonl((uint32_t)(p-frame-4));memcpy(frame,&total,4);
    if(send(fd,frame,(size_t)(p-frame),MSG_NOSIGNAL)!=(ssize_t)(p-frame)){dprintf(note,"proxy=send errno=%d\n",errno);close(fd);return;}
    dprintf(note,"proxy=sent\n");
    unsigned char buf[4096];size_t got=0,at=0;int ended=0;
    while(!ended&&got<sizeof buf) {
        ssize_t r=read(fd,buf+got,sizeof buf-got);
        if(r<0&&errno==EINTR)continue;
        if(r<=0){dprintf(note,"proxy=eof\n");break;}
        got+=(size_t)r;
        while(at+4<=got) {   /* RESP_HEAD 0x11: category u8, status u16; RESP_CHUNK 0x12; RESP_END 0x13 */
            uint32_t n;memcpy(&n,buf+at,4);n=ntohl(n);if(!n||at+4+n>got)break;const unsigned char *b=buf+at+4;
            if(b[0]==0x11&&n>=12)dprintf(note,"proxy=head category=%u status=%u\n",b[5],(unsigned)(b[10]<<8|b[11]));
            else if(b[0]==0x12)dprintf(note,"proxy=chunk len=%u\n",(unsigned)(n-5));
            else if(b[0]==0x13){dprintf(note,"proxy=end\n");ended=1;}
            else dprintf(note,"proxy=kind %u\n",b[0]);
            at+=4+n;
        }
    }
    close(fd);
}
/* validation.md H-04, H-05, H-06 (2.3b integration): one FILE_LIST_OBJECTS on the row's file port (SPEC §3.7, link G);
 * the row's real file worker passes it to the core as FILE_ASK, the core answers from the table; the reply's bytes are
 * logged as one file=reply line. */
static void file_objects_request(void) {
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0){dprintf(note,"file=socket errno=%d\n",errno);return;}
    struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,"/run/w2/file.sock");
    if(connect(fd,(struct sockaddr *)&a,sizeof a)){dprintf(note,"file=connect errno=%d\n",errno);close(fd);return;}
    const unsigned char ask[5]={0,0,0,1,0x71};
    if(send(fd,ask,sizeof ask,MSG_NOSIGNAL)!=(ssize_t)sizeof ask){dprintf(note,"file=send errno=%d\n",errno);close(fd);return;}
    unsigned char buf[64];size_t got=0;
    while(got<sizeof buf) {
        ssize_t r=read(fd,buf+got,sizeof buf-got);
        if(r<0&&errno==EINTR)continue;
        if(r<=0)break;
        got+=(size_t)r;
        if(got>=4){uint32_t n;memcpy(&n,buf,4);if(got>=4+(size_t)ntohl(n))break;}
    }
    dprintf(note,"file=reply");
    for(size_t i=0;i<got;++i)dprintf(note," %02x",buf[i]);
    dprintf(note,"\n");
    close(fd);
}
/* "agent mcp" (2.3c; validation.md H-23, H-24): the row's MCP server over HTTP on the cell's loopback, with no real
 * agent. The runner writes JSON-RPC bodies, one per line, to /work/mcp-request.txt; each is POSTed to
 * http://127.0.0.1:<mcp_port>/mcp on a connection of its own (Connection: close), and the whole response, status line
 * and headers included, is logged as one "mcp=response <hex>" line for the runner to parse. */
static int send_all(int fd,const char *p,size_t n) {
    while(n){ssize_t w=send(fd,p,n,MSG_NOSIGNAL);if(w<0&&errno==EINTR)continue;if(w<=0)return 0;p+=w;n-=(size_t)w;}
    return 1;
}
static unsigned char mcp_reply[65536];
static char mcp_hex[2*sizeof mcp_reply+1];
static void mcp_post(const char *body,size_t len) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0){dprintf(note,"mcp=socket errno=%d\n",errno);return;}
    struct sockaddr_in in={.sin_family=AF_INET,.sin_port=htons(W2_TEST_MCP_PORT)};in.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,(struct sockaddr *)&in,sizeof in)){dprintf(note,"mcp=connect errno=%d\n",errno);close(fd);return;}
    char head[256];
    int h=snprintf(head,sizeof head,"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
                   "Accept: application/json, text/event-stream\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                   W2_TEST_MCP_PORT,len);
    if(!send_all(fd,head,(size_t)h)||!send_all(fd,body,len)){dprintf(note,"mcp=send errno=%d\n",errno);close(fd);return;}
    size_t got=0;
    while(got<sizeof mcp_reply){ssize_t r=read(fd,mcp_reply+got,sizeof mcp_reply-got);if(r<0&&errno==EINTR)continue;if(r<=0)break;got+=(size_t)r;}
    close(fd);
    for(size_t i=0;i<got;++i)snprintf(mcp_hex+2*i,3,"%02x",mcp_reply[i]);
    mcp_hex[2*got]=0;
    dprintf(note,"mcp=response %s\n",mcp_hex);
}
static void mcp_exchange(void) {
    static char lines[32768];
    int in=open("/work/mcp-request.txt",O_RDONLY|O_CLOEXEC);ssize_t n=in<0?-1:read(in,lines,sizeof lines-1);
    if(in>=0)close(in);
    if(n<=0){dprintf(note,"mcp=no-request errno=%d\n",errno);return;}
    lines[n]=0;
    for(char *line=lines;*line;) {
        char *end=strchr(line,'\n');size_t len=end?(size_t)(end-line):strlen(line);
        if(len)mcp_post(line,len);
        if(!end)break;
        line=end+1;
    }
}
static int agent(const char *mode) {
    note=open("/work/agent.txt",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(note<0)return 95;
    dprintf(note,"mode=%s pid=%d uid=%u\n",mode,getpid(),getuid());
    int f=fcntl(3,F_GETFL);if(f>=0)fcntl(3,F_SETFL,f&~O_NONBLOCK);
    if(!strcmp(mode,"basic")) {
        emit(first_body);sent("request id=1");
        if(!next_frame())dprintf(note,"eof-before-reply\n");
        if(fsync(note))_exit(93);
        emit(ack_body);sent("ack");
    }
    else if(!strcmp(mode,"partial")){unsigned char two[2]={0,0};if(send(3,two,2,MSG_NOSIGNAL)!=2)_exit(98);sent("partial-header");}
    else if(!strcmp(mode,"oob")){errno=0;ssize_t rc=send(3,"x",1,MSG_OOB|MSG_NOSIGNAL);dprintf(note,"sent=oob rc=%zd errno=%d\n",rc,errno);}
    else if(!strcmp(mode,"oversize")){unsigned char big[4]={0,1,0,1};if(send(3,big,4,MSG_NOSIGNAL)!=4)_exit(98);sent("length=65537");}
    else if(!strcmp(mode,"rights")) {
        size_t len=strlen(first_body);unsigned char wire[256];
        wire[0]=0;wire[1]=0;wire[2]=(unsigned char)(len>>8);wire[3]=(unsigned char)len;memcpy(wire+4,first_body,len);
        union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(int))];} control;memset(&control,0,sizeof control);
        struct iovec iov={wire,len+4};struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof control.bytes};
        struct cmsghdr *h=CMSG_FIRSTHDR(&m);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;h->cmsg_len=CMSG_LEN(sizeof(int));
        int passed=0;memcpy(CMSG_DATA(h),&passed,sizeof passed);
        errno=0;ssize_t rc=sendmsg(3,&m,MSG_NOSIGNAL);dprintf(note,"sent=request+rights rc=%zd errno=%d\n",rc,errno);
    } else if(!strcmp(mode,"fork-sender")) {
        /* A child and its parent share uid_i and the channel: both frames carry the row's uid and both are answered;
         * the driver closes the row after the acknowledgement. */
        pid_t child=fork();
        if(!child){emit(first_body);_exit(0);}
        int status=0;waitpid(child,&status,0);
        dprintf(note,"sent=request id=1 by child pid=%d exit=%d\n",child,WIFEXITED(status)?WEXITSTATUS(status):-1);
        emit(second_body);sent("request id=2 by parent");
        for(int i=0;i<2;++i)if(!next_frame()){dprintf(note,"eof-before-reply\n");break;}
        if(fsync(note))_exit(93);
        emit(ack_body);sent("ack");
    } else if(!strcmp(mode,"proxy")) {
        /* the ack tells the scenario the whole response was read, so it closes the row only after that */
        file_objects_request();
        proxy_request();
        if(fsync(note))_exit(93);
        emit(ack_body);sent("ack");
    } else if(!strcmp(mode,"mcp")) {
        mcp_exchange();
        if(fsync(note))_exit(93);
        emit(ack_body);sent("ack");
    }
    else _exit(99);
    if(fsync(note))_exit(93);
    wait_eof();
    dprintf(note,"eof\n");close(note);
    return 0;
}
int main(int argc,char **argv) {
    if(argc>1&&!strcmp(argv[1],"work-child"))return 37;
    /* "agent mcp" runs under the deployment's workload policy (run_engine_checks.py), which refuses some of inspect()'s
     * probes (getresuid among them), so that mode goes straight to its exchange */
    if(argc>2&&!strcmp(argv[1],"agent")){if(strcmp(argv[2],"mcp"))inspect();return agent(argv[2]);}
    if(argc>1&&!strcmp(argv[1],"linger")) {
        int fd=open("/work/linger.txt",O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(fd<0)return 90;
        dprintf(fd,"pid1=%d uid=%u\n",getpid(),getuid());
        pid_t child=fork();if(!child){setsid();for(;;)pause();}
        dprintf(fd,"descendant=%d\n",child);close(fd);
        emit(first_body);
        for(;;)pause();
    }
    inspect();
    /* The first frame after exec: the trusted driver checks it arrives under the row's uid. */
    emit(first_body);
    /* Wait for a trusted test driver's finish; blocking is confined to this
     * disposable fixture, not the production spawner event loop. */
    int f=fcntl(3,F_GETFL);if(f>=0)fcntl(3,F_SETFL,f&~O_NONBLOCK);
    char c;while(read(3,&c,1)<0&&errno==EINTR){};
    return 0;
}
