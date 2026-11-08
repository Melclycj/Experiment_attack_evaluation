#define _GNU_SOURCE
#include "spawner.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/* Dedicated privileged observer, not the product's unprivileged engine.
 * The spawner and preparing child run the actual production implementation.
 * Root is needed only to inspect their fds and perturb the disposable source. */
int main(int argc,char **argv) {
    assert(argc==6&&geteuid()==0);
    assert(!close_range(3,~0u,0));
    struct w2_catalog *c=calloc(1,sizeof *c);assert(c);
    assert(!w2_catalog_load(c,argv[1],argv[2]));
    int channel[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,channel));
    pid_t child=fork();assert(child>=0);
    if(!child){
        close(channel[0]);assert(!w2_limit_spawner_caps());
        int rc=w2_spawner_run(c,channel[1]);w2_catalog_free(c);free(c);_exit(rc);
    }
    close(channel[1]);w2_catalog_free(c);free(c);
    if(channel[0]!=3){assert(dup2(channel[0],3)==3);close(channel[0]);}
    assert(!fcntl(3,F_SETFD,0)&&!close_range(4,~0u,0));
    char *const args[]={"/usr/bin/python3",argv[3],argv[1],argv[2],"workspace-lifecycle",argv[4],argv[5],NULL};
    execv(args[0],args);_exit(2);
}
