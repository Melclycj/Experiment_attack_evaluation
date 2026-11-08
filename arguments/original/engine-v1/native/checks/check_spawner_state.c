#define _GNU_SOURCE
/* Includes the actual private state machine to control the precise intra-loop
 * ordering. A READY record is constructed; B is a real owned child. This is
 * a state/ordering test, separate from wire/kernel integration fixtures. */
#include "../sandbox/spawner.c"
#include <assert.h>
int main(void) {
    struct loop *l=calloc(1,sizeof *l);assert(l);
    struct spawn_record *a=&l->records[0],*b=&l->records[1];
    a->used=true;a->copy_ready=true;a->channel=-1;a->deadline=w2_now()+UINT64_C(5000000000);
    pid_t child=fork();assert(child>=0);if(!child){for(;;)pause();}
    b->used=b->stopping=b->pid_owned=true;b->uid=70001;b->pid=child;b->channel=-1;
    w2_fault_configure("reap.second.echild");reap_and_stop(l);
    assert(l->lost&&!a->stopping&&!b->empty&&!b->pid_owned);
    /* No plan is supplied: entering mount/socket/clone preparation is itself
     * an error after this transition, even if the next loop could stop it. */
    clone_ready(l,a);assert(a->stopping&&a->empty&&a->failed&&!a->pid);
    int status;assert(waitpid(child,&status,0)==child&&WIFSIGNALED(status));
    puts("{\"check\":\"A-ready-after-later-slot-B-reap-error-in-same-loop\",\"clone\":\"forbidden\",\"result\":\"passed\"}");
    free(l);return 0;
}
