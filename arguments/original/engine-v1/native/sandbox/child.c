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
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

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
int w2_child_launch(struct w2_plan *p,int channel,int objects_fd,int deployment_fd,const char *copy,
                    uint64_t root_dev,uint64_t root_ino,const char *root,const char *runtime_source,const char *deployment,uint64_t deadline) {
    enum w2_stage stage=W2_STAGE_RUNTIME_MOUNT;int nullfd=-1,net=-1,runtime_fd=-1,workspace_fd=-1;
    struct open_how how={.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
    TRY(W2_STAGE_RUNTIME_MOUNT,"runtime.open",(runtime_fd=(int)syscall(SYS_openat2,objects_fd,copy,&how,sizeof how)));
    struct stat identity;TRY(W2_STAGE_RUNTIME_MOUNT,"runtime.identity",fstat(runtime_fd,&identity));
    if((uint64_t)identity.st_dev!=root_dev||(uint64_t)identity.st_ino!=root_ino){errno=ESTALE;goto fail;}
    TRY(W2_STAGE_MOUNT_PRIVATE,"mount_private",mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL));
    TRY(W2_STAGE_ROOT,"root.mount",mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=16777216,mode=0755"));
    TRY(W2_STAGE_ROOT,"root.chdir",chdir(root));
    const char *dirs[]={"runtime","work","proc","dev","tmp",".oldroot"};
    for(size_t i=0;i<6;++i) {
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
    if(mount_fd(workspace_fd,source,"work",false,&stage,deadline))goto fail;
    TRY(W2_STAGE_WORK_MOUNT,"work.close",close(workspace_fd));workspace_fd=-1;
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
    for(int i=0;i<3;++i) {
        char point[32];snprintf(point,sizeof point,"stdio.dup.%d",i);
        TRY(W2_STAGE_STDIO,point,dup2(nullfd,i));
    }
    if(nullfd>3&&nullfd!=channel){TRY(W2_STAGE_STDIO,"stdio.close",close(nullfd));nullfd=-1;}
#ifdef W2_TESTING
    if(w2_fault("channel_at_three")) {
        if(channel!=3){if(dup2(channel,3)<0)goto fail;close(channel);channel=3;}
        if(fcntl(3,F_SETFD,FD_CLOEXEC)<0)goto fail;
    }
#endif
    if(channel!=3){TRY(W2_STAGE_FD_CLEANUP,"fd.dup",dup2(channel,3));channel=3;}
    int flags;TRY(W2_STAGE_FD_CLEANUP,"fd.get",(flags=fcntl(3,F_GETFD)));
    TRY(W2_STAGE_FD_CLEANUP,"fd.cloexec",fcntl(3,F_SETFD,flags&~FD_CLOEXEC));
    TRY(W2_STAGE_FD_CLEANUP,"fd.close_range",syscall(SYS_close_range,4,~0u,0));struct rlimit core={1,1};TRY(W2_STAGE_FD_CLEANUP,"core.limit",setrlimit(RLIMIT_CORE,&core));
    if(w2_drop(p->workspace->uid,p->workspace->gid,&stage))goto fail;
    TRY(W2_STAGE_POLICY,"policy",prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p->policy->program));
    unsigned char wire[W2_BOOTSTRAP_SIZE];struct w2_bootstrap message={W2_BP_SEALED,W2_STAGE_NONE,0};
    if(w2_bootstrap_encode(&message,wire,sizeof wire))goto fail;
    TRY(W2_STAGE_SEALED,"sealed",w2_send_fixed(3,wire,sizeof wire,deadline));
    TRY(W2_STAGE_COMMIT,"commit",w2_recv_fixed(3,wire,sizeof wire,deadline));
    if(w2_bootstrap_decode(wire,sizeof wire,&message)||message.kind!=W2_BP_COMMIT){errno=EPROTO;goto fail;}
    TRY(W2_STAGE_EXEC,"exec.cwd",chdir("/work"));
    TRY(W2_STAGE_EXEC,"exec",execve(w2_str(p->runtime->descriptor,"executable"),p->runtime->argv,p->runtime->env));
fail: {
        int saved=errno;unsigned char error_wire[W2_BOOTSTRAP_SIZE];
        struct w2_bootstrap failure={W2_BP_FAIL,stage,(uint32_t)(saved>0?saved:EIO)};
        if(w2_bootstrap_encode(&failure,error_wire,sizeof error_wire)==W2_CONTRACT_OK)
            (void)w2_send_fixed(channel,error_wire,sizeof error_wire,w2_now()+UINT64_C(100000000));
        _exit(125);
    }
}
