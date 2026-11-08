#define _GNU_SOURCE
#include "spawner.h"
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc,char **argv) {
    if(argc<6){fputs("usage: w2-cell ROOT CATALOG ENGINE_UID ENGINE_GID ENGINE_EXEC [ARG...]\n",stderr);return 2;}
    uint64_t uid,gid;
    if(!w2_decimal(argv[3],&uid,true)||uid>=UINT32_MAX||!w2_decimal(argv[4],&gid,true)||gid>=UINT32_MAX||argv[5][0]!='/')return 2;
    /* This executable is the clean launcher. No service state is loaded here;
     * arbitrary inherited fds are removed before the catalog or pre-fork. */
    if(syscall(SYS_close_range,3,~0u,0))return 2;
#ifdef W2_TESTING
    char *fault=getenv("W2_TEST_FAULT");char saved_fault[128]={0};
    if(fault&&strlen(fault)<sizeof saved_fault)strcpy(saved_fault,fault);
#endif
    /* Drop inherited environment bytes before pre-fork, not merely its pointer
     * table. Engine secrets are loaded by the engine after exec. CLI arguments
     * are deployment references; credentials must not be passed in argv. */
    extern char **environ;
    for(char **p=environ;p&&*p;++p)explicit_bzero(*p,strlen(*p));
    if(clearenv()||w2_limit_spawner_caps())return 2;
    struct w2_catalog *catalog=calloc(1,sizeof *catalog);if(!catalog)return 2;
    if(w2_require_spawner_caps()||w2_catalog_load(catalog,argv[1],argv[2])){perror("sandbox preflight");free(catalog);return 2;}
    if(uid==catalog->overflow||gid==catalog->overflow_gid){w2_catalog_free(catalog);free(catalog);return 2;}
    for(size_t i=0;i<catalog->workspace_count;++i)if(uid==catalog->workspace[i].uid||gid==catalog->workspace[i].gid){w2_catalog_free(catalog);free(catalog);return 2;}
    int channel[2];
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,channel)){perror("control socketpair");return 2;}
    pid_t child=fork();if(child<0){perror("prefork");return 2;}
    if(!child) {
        close(channel[0]);
#ifdef W2_TESTING
        w2_fault_configure(saved_fault);
#endif
        if(clearenv())_exit(2);
        int status=w2_spawner_run(catalog,channel[1]);w2_catalog_free(catalog);free(catalog);_exit(status);
    }
    close(channel[1]);
    /* Destroy the parent's clean catalog view before replacing its address
     * space with the unprivileged engine. Spawner has its own forked copy. */
    w2_catalog_free(catalog);free(catalog);
    if(channel[0]!=3){if(dup2(channel[0],3)<0)return 2;close(channel[0]);}
    if(fcntl(3,F_SETFD,0)||syscall(SYS_close_range,4,~0u,0))return 2;
    enum w2_stage stage;
    if(w2_drop((uid_t)uid,(gid_t)gid,&stage)){perror("engine drop");return 2;}
    if(clearenv()||setenv("PATH","/usr/bin:/bin",1)||setenv("LC_ALL","C.UTF-8",1))return 2;
    execv(argv[5],argv+5);perror("engine exec");return 2;
}
