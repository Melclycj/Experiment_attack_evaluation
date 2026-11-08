#define _GNU_SOURCE
#include "spawner.h"
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/stat.h>
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
    /* v2: the engine's uid is neither in the per-execution reserve nor the connector's (validation.md S-15), nor the
     * file worker's (H-14). */
    if((uid>=catalog->range_first&&uid<=catalog->range_last)||(gid>=catalog->range_first&&gid<=catalog->range_last)||
       uid==catalog->connector.uid||gid==catalog->connector.gid||
       uid==catalog->file_worker.uid||gid==catalog->file_worker.gid){w2_catalog_free(catalog);free(catalog);return 2;}
    /* The workspace owner is a dedicated uid that no host process runs as: never the engine's own ids, in the prototype
     * the host user's, which would put the host user back inside every workspace's storage (validation.md S-22). */
    for(size_t i=0;i<catalog->workspace_count;++i)
        if(catalog->workspace[i].uid==(uid_t)uid||catalog->workspace[i].gid==(gid_t)gid){
            fputs("a workspace is owned by the engine uid or gid\n",stderr);w2_catalog_free(catalog);free(catalog);return 2;}
    /* v2: the engine's identity, for the attach sockets the spawner hands it (S-08), and the engine's state directory
     * <root>/state (workspace mirrors, credential records, admin.sock): engine uid, 0700, never in any cell (K-33).
     * The spawner's row directories live beside it under <root>/rows (spawner.c rows_dir). */
    catalog->engine_uid=(uid_t)uid;catalog->engine_gid=(gid_t)gid;
    char state[W2_PATH_CAP+8];if(snprintf(state,sizeof state,"%s/state",argv[1])>=(int)sizeof state)return 2;
    struct stat st;
    if(!mkdir(state,0700)){if(chmod(state,0700)||chown(state,(uid_t)uid,(gid_t)gid)){perror("state directory");return 2;}}   /* chmod before chown: no CAP_FOWNER */
    else if(errno!=EEXIST||lstat(state,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=(uid_t)uid||st.st_gid!=(gid_t)gid||(st.st_mode&07777)!=0700){
        fputs("state directory exists with another owner or mode\n",stderr);return 2;}   /* an existing directory is only accepted as the engine's own 0700 */
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
