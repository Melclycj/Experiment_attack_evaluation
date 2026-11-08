#define _GNU_SOURCE
#include "support.h"
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/wait.h>
#include <unistd.h>
struct child {int read_fd,write_fd;};
static int ready(void *ptr) {
    struct child *c=ptr;close(c->read_fd);enum w2_stage stage;
    if(w2_drop(70000,70000,&stage))_exit(2);
    if(write(c->write_fd,"R",1)!=1)_exit(3);
    close(c->write_fd);
    for(;;)pause();
}
int main(void) {
    int pipefd[2];if(pipe(pipefd))return 1;
    struct child args={pipefd[0],pipefd[1]};char *stack=malloc(1024*1024);if(!stack)return 1;
    pid_t pid=clone(ready,stack+1024*1024,CLONE_NEWPID|SIGCHLD,&args);if(pid<0)return 1;
    close(pipefd[1]);char marker;ssize_t n=read(pipefd[0],&marker,1);close(pipefd[0]);
    cap_t caps=cap_get_proc();cap_value_t value=CAP_KILL;int ok=0;
    if(n==1&&marker=='R'&&caps&&cap_set_flag(caps,CAP_EFFECTIVE,1,&value,CAP_CLEAR)==0&&cap_set_proc(caps)==0) {
        errno=0;int rc=kill(pid,SIGKILL);int number=errno;
        printf("without_CAP_KILL result=%d errno=%d\n",rc,number);
        ok=rc==-1&&number==EPERM;
    }
    if(!caps||cap_set_flag(caps,CAP_EFFECTIVE,1,&value,CAP_SET)||cap_set_proc(caps))return 1;
    int rc=kill(pid,SIGKILL);printf("with_CAP_KILL result=%d errno=%d\n",rc,rc?errno:0);
    int status;pid_t waited=waitpid(pid,&status,0);printf("actual_waitpid matched=%d signal=%d\n",waited==pid,WIFSIGNALED(status)?WTERMSIG(status):0);
    cap_free(caps);free(stack);
    return !(ok&&rc==0&&waited==pid&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
}
