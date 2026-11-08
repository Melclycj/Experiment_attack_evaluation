#define _GNU_SOURCE
#include "spawner.h"
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <linux/openat2.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define W2_READY_FILE "/tmp/.w2-frontend-ready"
#define W2_MCP_READY_FILE "/tmp/.w2-mcp-ready"   /* host file reads (validation.md H-23): the in-cell MCP server's */
/* v2: the in-cell helpers (relay, frontend) are forked after the seccomp filter and before the agent, so every process
 * in the cell is confined alike; the helper child uses only close, fcntl, execve and exit, which every policy allows.
 * fd3/fd4 name the descriptors the helper receives as its 3 and 4 (-1: none); stdio is /dev/null. */
static pid_t start_helper(char *const exe,char *const *argv,const char *const *extra,int nullfd,int fd3,int fd4) {
    char *merged[W2_ARGV_MAX+8];size_t n=0;
    for(;argv[n]&&n<W2_ARGV_MAX;++n)merged[n]=argv[n];
    for(size_t i=0;extra&&extra[i]&&n<W2_ARGV_MAX+6;++i)merged[n++]=(char *)extra[i];
    merged[n]=NULL;
    pid_t pid=fork();if(pid)return pid;
    static char *const env[]={"PATH=/usr/bin:/bin","LC_ALL=C.UTF-8",NULL};
    for(int i=0;i<3;++i)close(i);
    for(int i=0;i<3;++i)if(fcntl(nullfd,F_DUPFD,i)!=i)_exit(126);
    int m=-1,at=-1;
    if(fd3>=0&&(m=fcntl(fd3,F_DUPFD,64))<0)_exit(126);
    if(fd4>=0&&(at=fcntl(fd4,F_DUPFD,64))<0)_exit(126);
    for(int i=3;i<64;++i)close(i);
    if(m>=0&&(fcntl(m,F_DUPFD,3)!=3||close(m)))_exit(126);
    if(at>=0&&(fcntl(at,F_DUPFD,4)!=4||close(at)))_exit(126);
    for(int i=64;i<256;++i)close(i);
    execve(exe,merged,env);_exit(127);
}
/* Both ready files (the frontend's and the MCP server's, H-23) before the agent; any helper that exits first fails the
 * start, as the frontend alone did. */
static int wait_ready(pid_t relay,pid_t frontend,pid_t mcp,uint64_t deadline) {
    for(;;) {
        if(!access(W2_READY_FILE,F_OK)&&!access(W2_MCP_READY_FILE,F_OK))return 0;
        int status;
        if(waitpid(relay,&status,WNOHANG)>0||waitpid(frontend,&status,WNOHANG)>0||waitpid(mcp,&status,WNOHANG)>0){errno=ECHILD;return -1;}
        if(w2_now()>=deadline){errno=ETIMEDOUT;return -1;}
        struct timespec nap={0,10000000};nanosleep(&nap,NULL);
    }
}
/* The agent's environment: the runtime descriptor's entries minus the managed names, then the proxy and CA variables
 * (agent-rm-model 3.3 第四点; build plan 1.5). HTTP_PROXY is set with HTTPS_PROXY so plain-http clients meet the same
 * frontend instead of an unreachable network. HOME is the cell's own /tmp for every runtime (build plan 7.4 4b): what is
 * written under HOME (caches, program state, session records, logins made inside the cell) is not kept past the row. */
static const char *const managed_env[]={"HTTPS_PROXY=","HTTP_PROXY=","NO_PROXY=","NODE_EXTRA_CA_CERTS=","SSL_CERT_FILE=","GIT_SSL_CAINFO=",
                                        "PIP_CERT=","REQUESTS_CA_BUNDLE=","CURL_CA_BUNDLE=","HOME=",NULL};
static void build_env(char *const *source,char **out,char *proxy_https,char *proxy_http) {
    size_t n=0;
    for(size_t i=0;source[i]&&i<W2_ENV_MAX;++i) {
        bool managed=false;for(size_t k=0;managed_env[k];++k)if(!strncmp(source[i],managed_env[k],strlen(managed_env[k])))managed=true;
        if(!managed)out[n++]=source[i];
    }
    /* the execution's CA (build plan 1.5, 5.3): node, OpenSSL-based tools, git, pip, requests and curl each read their
     * own variable; NO_PROXY names localhost so that the agent's own services on lo are reached directly, not through
     * the frontend (agent-rm-model 5.4; S-16) */
    out[n++]=proxy_https;out[n++]=proxy_http;out[n++]="NO_PROXY=localhost,127.0.0.1";out[n++]="NODE_EXTRA_CA_CERTS=/w2/ca/ca.pem";
    out[n++]="SSL_CERT_FILE=/w2/ca/ca.pem";out[n++]="GIT_SSL_CAINFO=/w2/ca/ca.pem";out[n++]="PIP_CERT=/w2/ca/ca.pem";
    out[n++]="REQUESTS_CA_BUNDLE=/w2/ca/ca.pem";out[n++]="CURL_CA_BUNDLE=/w2/ca/ca.pem";out[n++]="HOME=/tmp";out[n]=NULL;
}

#define TRY(s,p,call) do { stage=(s); if(w2_now()>=deadline){errno=ETIMEDOUT;goto fail;} if(w2_fault(p)||(call)<0)goto fail; }while(0)
static int mount_fd(int fd,const char *source,const char *target,bool readonly,enum w2_stage *stage,uint64_t deadline) {
    *stage=readonly?W2_STAGE_RUNTIME_MOUNT:W2_STAGE_WORK_MOUNT;
    if(w2_now()>=deadline){errno=ETIMEDOUT;return -1;}
    /* Resolve the frozen deployment name in THIS mount namespace. An inherited
     * file description still names the parent's mount object; using its proc
     * magic link as the bind source can fail EINVAL after CLONE_NEWNS. Compare
     * object identity with the retained anchor before binding the frozen name. */
    struct open_how how={.flags=O_PATH|O_DIRECTORY|O_CLOEXEC,.resolve=RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};
    int local=(int)syscall(SYS_openat2,AT_FDCWD,source,&how,sizeof how);struct stat a,b;
    if(local<0)return -1;
    int same=!fstat(fd,&a)&&!fstat(local,&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino;
    close(local);if(!same){errno=ESTALE;return -1;}
    if(w2_fault(readonly?"runtime.bind":"work.bind")||mount(source,target,NULL,MS_BIND|MS_REC,NULL))return -1;
    if(w2_fault(readonly?"runtime.remount":"work.remount")||
       mount(NULL,target,NULL,MS_REMOUNT|MS_BIND|MS_NOSUID|MS_NODEV|(readonly?(MS_RDONLY|MS_NOATIME):0),NULL))return -1;
    return 0;
}
/* v2: the workspace is attached through an idmapped mount (agent-rm-model 3.1): the execution's uid sees the
 * owner's files as its own and its new files land on disk as the owner; unmapped owners show as the overflow
 * uid. Identity is re-checked in this mount namespace exactly as mount_fd does for the runtime copy. */
static int mount_idmapped(int fd,const char *source,const char *target,int idmap,uid_t owner,enum w2_stage *stage,uint64_t deadline) {
    *stage=W2_STAGE_WORK_MOUNT;
    if(w2_now()>=deadline){errno=ETIMEDOUT;return -1;}
    struct open_how how={.flags=O_PATH|O_DIRECTORY|O_CLOEXEC,.resolve=RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};
    int local=(int)syscall(SYS_openat2,AT_FDCWD,source,&how,sizeof how);struct stat a,b;
    if(local<0)return -1;
    int same=!fstat(fd,&a)&&!fstat(local,&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino;
    if(!same){close(local);errno=ESTALE;return -1;}
    /* The cell gets the fixed subdirectory beneath the verified root, never the root itself: the root's 0700 stays
     * outside every cell (validation.md S-25). A symlink or a non-directory there fails the spawn. The root is the
     * owner's and this process holds no DAC override, so the one lookup below it runs with the owner's file-system
     * uid, restored at once; nothing else here depends on path permissions. */
    struct open_how below={.flags=O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
    uid_t before=(uid_t)setfsuid(owner);int sub=-1,saved=EPERM;
    if((uid_t)setfsuid((uid_t)-1)==owner){sub=(int)syscall(SYS_openat2,local,W2_WORKSPACE_TREE,&below,sizeof below);saved=errno;}
    (void)setfsuid(before);
    if((uid_t)setfsuid((uid_t)-1)!=before){if(sub>=0)close(sub);close(local);errno=EPERM;return -1;}
    close(local);if(sub<0){errno=saved;return -1;}
    int tree=w2_fault("work.bind")?-1:open_tree(sub,"",OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH);
    close(sub);if(tree<0)return -1;
    struct mount_attr attr={.attr_set=MOUNT_ATTR_IDMAP|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV,.userns_fd=(uint64_t)idmap};
    if(w2_fault("work.remount")||mount_setattr(tree,"",AT_EMPTY_PATH,&attr,sizeof attr)||
       move_mount(tree,"",AT_FDCWD,target,MOVE_MOUNT_F_EMPTY_PATH)){int saved=errno;close(tree);errno=saved;return -1;}
    close(tree);return 0;
}
int w2_child_launch(struct w2_child_args *a) {
    struct w2_plan *p=a->plan;int channel=a->channel,idmap=a->idmap;uid_t uid=a->uid;gid_t gid=a->gid;
    int objects_fd=a->catalog->instances_fd,deployment_fd=a->catalog->root_fd;
    const char *copy=a->copy,*root=a->root,*runtime_source=a->source,*deployment=a->catalog->root;
    uint64_t root_dev=a->dev,root_ino=a->ino,deadline=a->deadline;
    enum w2_stage stage=W2_STAGE_RUNTIME_MOUNT;int nullfd=-1,net=-1,runtime_fd=-1,workspace_fd=-1;
    struct open_how how={.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
    if(a->catalog->shared_runtime)   /* runtime_mode "shared": the seed beneath the deployment root (catalog.h) */
        TRY(W2_STAGE_RUNTIME_MOUNT,"runtime.open",(runtime_fd=(int)syscall(SYS_openat2,deployment_fd,p->runtime->seed_ref,&how,sizeof how)));
    else TRY(W2_STAGE_RUNTIME_MOUNT,"runtime.open",(runtime_fd=(int)syscall(SYS_openat2,objects_fd,copy,&how,sizeof how)));
    struct stat identity;TRY(W2_STAGE_RUNTIME_MOUNT,"runtime.identity",fstat(runtime_fd,&identity));
    if((uint64_t)identity.st_dev!=root_dev||(uint64_t)identity.st_ino!=root_ino){errno=ESTALE;goto fail;}
    TRY(W2_STAGE_MOUNT_PRIVATE,"mount_private",mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL));
    TRY(W2_STAGE_ROOT,"root.mount",mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=16777216,mode=0755"));
    TRY(W2_STAGE_ROOT,"root.chdir",chdir(root));
    const char *dirs[]={"runtime","work","proc","dev","tmp",".oldroot","run","w2"};
    for(size_t i=0;i<8;++i) {
        char point[80];snprintf(point,sizeof point,"root.mkdir.%s",dirs[i]);
        TRY(W2_STAGE_ROOT,point,mkdir(dirs[i],0755));
    }
    const char *links[]={"bin","lib","lib64","usr"};
    for(size_t i=0;i<4;++i) {
        char value[80],point[80];snprintf(value,sizeof value,"/runtime/%s",links[i]);snprintf(point,sizeof point,"root.link.%s",links[i]);
        TRY(W2_STAGE_ROOT,point,symlink(value,links[i]));
    }
    char source[W2_PATH_CAP];
    if(mount_fd(runtime_fd,runtime_source,"runtime",true,&stage,deadline))goto fail;
    int source_size=snprintf(source,sizeof source,"%s/%s",deployment,w2_str(p->workspace->entry,"source_ref"));
    if(source_size<0||(size_t)source_size>=sizeof source){errno=ENAMETOOLONG;goto fail;}
    TRY(W2_STAGE_WORK_MOUNT,"work.open",(workspace_fd=w2_workspace_open(deployment_fd,p->workspace)));
    if(mount_idmapped(workspace_fd,source,"work",idmap,p->workspace->uid,&stage,deadline))goto fail;
    TRY(W2_STAGE_WORK_MOUNT,"idmap.close",close(idmap));idmap=-1;
    TRY(W2_STAGE_WORK_MOUNT,"work.close",close(workspace_fd));workspace_fd=-1;
    /* v2: the row's proxy socket appears inside the cell at /run/w2/proxy.sock (validation.md S-01: only this uid's
     * cell reaches this row's socket) and the deployment's cell files (CA, placeholders) read-only at /w2. */
    TRY(W2_STAGE_ROOT,"proxy.mkdir",mkdir("run/w2",0755));
    int sock_target=-1;TRY(W2_STAGE_ROOT,"proxy.create",(sock_target=open("run/w2/proxy.sock",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600)));
    TRY(W2_STAGE_ROOT,"proxy.close",close(sock_target));sock_target=-1;
    char proxy_source[W2_PATH_CAP+32];snprintf(proxy_source,sizeof proxy_source,"%s/proxy.sock",a->rows_dir);
    TRY(W2_STAGE_ROOT,"proxy.bind",mount(proxy_source,"run/w2/proxy.sock",NULL,MS_BIND,NULL));
    /* the row's file port the same way, at /run/w2/file.sock (validation.md H-05): the in-cell MCP server connects to it,
     * the row's file worker accepts */
    TRY(W2_STAGE_ROOT,"file.create",(sock_target=open("run/w2/file.sock",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600)));
    TRY(W2_STAGE_ROOT,"file.close",close(sock_target));sock_target=-1;
    char file_source[W2_PATH_CAP+32];snprintf(file_source,sizeof file_source,"%s/file.sock",a->rows_dir);
    TRY(W2_STAGE_ROOT,"file.bind",mount(file_source,"run/w2/file.sock",NULL,MS_BIND,NULL));
    char files_source[W2_PATH_CAP+W2_STRING_MAX+2];snprintf(files_source,sizeof files_source,"%s/%s",deployment,a->catalog->cell_files_ref);
    TRY(W2_STAGE_ROOT,"cellfiles.bind",mount(files_source,"w2",NULL,MS_BIND|MS_REC,NULL));
    TRY(W2_STAGE_ROOT,"cellfiles.remount",mount(NULL,"w2",NULL,MS_REMOUNT|MS_BIND|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL));
    /* v2 (validation.md S-16): this execution's own CA (taken from the pool by the spawner into the row directory)
     * read-only at /w2/ca: the frontend signs with it, the agent trusts it, nobody in the cell can change it. */
    char ca_source[W2_PATH_CAP+32];snprintf(ca_source,sizeof ca_source,"%s/ca",a->rows_dir);
    TRY(W2_STAGE_ROOT,"ca.bind",mount(ca_source,"w2/ca",NULL,MS_BIND,NULL));
    TRY(W2_STAGE_ROOT,"ca.remount",mount(NULL,"w2/ca",NULL,MS_REMOUNT|MS_BIND|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL));
    TRY(W2_STAGE_PROC,"proc",mount("proc","proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,"subset=pid"));
    TRY(W2_STAGE_DEV_TMP,"dev.mount",mount("tmpfs","dev","tmpfs",MS_NOSUID|MS_NOEXEC,"size=1048576,mode=0755"));
    const char *devices[]={"null","zero","random","urandom"};
    for(size_t i=0;i<4;++i) {
        char from[80],to[80],point[80];snprintf(from,sizeof from,"/dev/%s",devices[i]);snprintf(to,sizeof to,"dev/%s",devices[i]);
        snprintf(point,sizeof point,"dev.create.%s",devices[i]);
        int fd=-1;TRY(W2_STAGE_DEV_TMP,point,(fd=open(to,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600)));
        TRY(W2_STAGE_DEV_TMP,"dev.close",close(fd));
        snprintf(point,sizeof point,"dev.bind.%s",devices[i]);TRY(W2_STAGE_DEV_TMP,point,mount(from,to,NULL,MS_BIND,NULL));
        snprintf(point,sizeof point,"dev.remount.%s",devices[i]);
        TRY(W2_STAGE_DEV_TMP,point,mount(NULL,to,NULL,MS_REMOUNT|MS_BIND|MS_NOSUID|MS_NOEXEC,NULL));
    }
    TRY(W2_STAGE_DEV_TMP,"tmp",mount("tmpfs","tmp","tmpfs",MS_NOSUID|MS_NODEV,"size=67108864,mode=1777"));
    TRY(W2_STAGE_DEV_TMP,"shm.mkdir",mkdir("dev/shm",01777));
    TRY(W2_STAGE_DEV_TMP,"shm",mount("tmpfs","dev/shm","tmpfs",MS_NOSUID|MS_NODEV,"size=67108864,mode=1777"));
    TRY(W2_STAGE_PIVOT,"pivot",syscall(SYS_pivot_root,".",".oldroot"));
    TRY(W2_STAGE_PIVOT,"pivot.chdir",chdir("/"));
    TRY(W2_STAGE_PIVOT,"pivot.detach",umount2("/.oldroot",MNT_DETACH));
    TRY(W2_STAGE_PIVOT,"pivot.rmdir",rmdir("/.oldroot"));
    TRY(W2_STAGE_LOOPBACK,"loopback.socket",(net=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)));
    struct ifreq req={0};strcpy(req.ifr_name,"lo");
    TRY(W2_STAGE_LOOPBACK,"loopback.get",ioctl(net,SIOCGIFFLAGS,&req));req.ifr_flags|=IFF_UP;
    TRY(W2_STAGE_LOOPBACK,"loopback.set",ioctl(net,SIOCSIFFLAGS,&req));
    TRY(W2_STAGE_LOOPBACK,"loopback.close",close(net));net=-1;
    TRY(W2_STAGE_STDIO,"stdio.open",(nullfd=open("/dev/null",O_RDWR|O_CLOEXEC)));
    /* v2: the agent's stdio is the row's pty slave (agent-rm-model 3.3 对话通道; validation.md S-07): a new session with
     * the slave as controlling terminal; the master goes to the in-cell relay. /dev/null stays open for the helpers. */
    TRY(W2_STAGE_STDIO,"stdio.setsid",setsid());
    TRY(W2_STAGE_STDIO,"stdio.ctty",ioctl(a->pty_slave,TIOCSCTTY,0));
    for(int i=0;i<3;++i) {
        char point[32];snprintf(point,sizeof point,"stdio.dup.%d",i);
        TRY(W2_STAGE_STDIO,point,dup2(a->pty_slave,i));
    }
#ifdef W2_TESTING
    if(w2_fault("channel_at_three")) {
        if(channel!=3){if(dup2(channel,3)<0)goto fail;close(channel);channel=3;}
        if(fcntl(3,F_SETFD,FD_CLOEXEC)<0)goto fail;
    }
#endif
    /* v2 descriptor layout before the agent: 3 agent channel (inherited), 4 pty master, 5 attach listener, 6 /dev/null;
     * the last three are close-on-exec: the relay and the frontend take what they need, the agent sees only 3. */
    int originals[4]={channel,a->pty_master,a->attach,nullfd},moved[4];
    for(int i=0;i<4;++i){char point[32];snprintf(point,sizeof point,"fd.move.%d",i);TRY(W2_STAGE_FD_CLEANUP,point,(moved[i]=fcntl(originals[i],F_DUPFD_CLOEXEC,64)));}
    for(int i=0;i<4;++i){char point[32];snprintf(point,sizeof point,"fd.dup.%d",i);TRY(W2_STAGE_FD_CLEANUP,point,dup2(moved[i],3+i));}
    channel=3;nullfd=6;
    TRY(W2_STAGE_FD_CLEANUP,"fd.cloexec",fcntl(3,F_SETFD,0));
    for(int i=4;i<7;++i){TRY(W2_STAGE_FD_CLEANUP,"fd.cloexec.helpers",fcntl(i,F_SETFD,FD_CLOEXEC));}
    TRY(W2_STAGE_FD_CLEANUP,"fd.close_range",syscall(SYS_close_range,7,~0u,0));struct rlimit core={1,1};TRY(W2_STAGE_FD_CLEANUP,"core.limit",setrlimit(RLIMIT_CORE,&core));
    /* v2: the identity is the execution's leased uid from the spawn record (agent-rm-model 3.1), never the
     * workspace owner's; the idmapped work mount above makes the owner's tree appear as this uid. */
    if(w2_drop(uid,gid,&stage))goto fail;
    TRY(W2_STAGE_POLICY,"policy",prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p->policy->program));
    unsigned char wire[W2_BOOTSTRAP_SIZE];struct w2_bootstrap message={W2_BP_SEALED,W2_STAGE_NONE,0};
    if(w2_bootstrap_encode(&message,wire,sizeof wire))goto fail;
    TRY(W2_STAGE_SEALED,"sealed",w2_send_fixed(3,wire,sizeof wire,deadline));
    TRY(W2_STAGE_COMMIT,"commit",w2_recv_fixed(3,wire,sizeof wire,deadline));
    if(w2_bootstrap_decode(wire,sizeof wire,&message)||message.kind!=W2_BP_COMMIT){errno=EPROTO;goto fail;}
    TRY(W2_STAGE_EXEC,"exec.cwd",chdir("/work"));
    char https_env[64],http_env[64],port_text[8],mcp_port_text[8];
    snprintf(https_env,sizeof https_env,"HTTPS_PROXY=http://127.0.0.1:%u",a->catalog->proxy_port);
    snprintf(http_env,sizeof http_env,"HTTP_PROXY=http://127.0.0.1:%u",a->catalog->proxy_port);
    snprintf(port_text,sizeof port_text,"%u",a->catalog->proxy_port);
    snprintf(mcp_port_text,sizeof mcp_port_text,"%u",a->catalog->mcp_port);
    char *env[W2_ENV_MAX+12];build_env(p->runtime->env,env,https_env,http_env);
    /* v2: the relay (pty master, attach listener) and the frontend start here, after commit and under the agent's
     * policy; the agent execs only once the frontend reports ready (build plan 1.3, 1.5). Host file reads (H-23): the
     * MCP server starts the same way after the frontend, with the same tail of arguments (the row's file port, its port,
     * its ready file), and the agent waits for its ready file too. */
    pid_t relay=-1,frontend=-1,mcp=-1;
    TRY(W2_STAGE_HELPERS,"helpers.relay",(relay=start_helper(a->catalog->relay.exe,a->catalog->relay.argv,NULL,nullfd,4,5)));
    const char *const extra[]={"/run/w2/proxy.sock",port_text,W2_READY_FILE,NULL};
    TRY(W2_STAGE_HELPERS,"helpers.frontend",(frontend=start_helper(a->catalog->frontend.exe,a->catalog->frontend.argv,extra,nullfd,-1,-1)));
    const char *const mcp_extra[]={"/run/w2/file.sock",mcp_port_text,W2_MCP_READY_FILE,NULL};
    TRY(W2_STAGE_HELPERS,"helpers.mcp",(mcp=start_helper(a->catalog->mcp.exe,a->catalog->mcp.argv,mcp_extra,nullfd,-1,-1)));
    TRY(W2_STAGE_HELPERS,"helpers.ready",wait_ready(relay,frontend,mcp,deadline));
    TRY(W2_STAGE_EXEC,"exec",execve(w2_str(p->runtime->descriptor,"executable"),p->runtime->argv,env));
fail: {
        int saved=errno;unsigned char error_wire[W2_BOOTSTRAP_SIZE];
        struct w2_bootstrap failure={W2_BP_FAIL,stage,(uint32_t)(saved>0?saved:EIO)};
        if(w2_bootstrap_encode(&failure,error_wire,sizeof error_wire)==W2_CONTRACT_OK)
            (void)w2_send_fixed(channel,error_wire,sizeof error_wire,w2_now()+UINT64_C(100000000));
        _exit(125);
    }
}
