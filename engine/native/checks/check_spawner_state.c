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
    free(l);
    /* overall review 2026-11-03, #3: a row whose resources fail (here its directory) reaches clone_ready's cleanup
     * before the socketpair and the idmap fd exist; the cleanup closes nothing it did not open, fd 0 included. */
    {
        if(fcntl(0,F_GETFD)<0)assert(open("/dev/null",O_RDONLY)==0);
        struct loop *m=calloc(1,sizeof *m);struct w2_catalog *cat=calloc(1,sizeof *cat);assert(m&&cat);
        struct w2_runtime runtime={0};struct w2_workspace workspace={0};
        struct w2_plan plan={.runtime=&runtime,.workspace=&workspace};
        strcpy(cat->root,"/nonexistent-w2-check");cat->shared_runtime=true;runtime.seed_ref="seed";m->catalog=cat;
        struct spawn_record *r=&m->records[0];
        r->used=r->copy_ready=true;r->channel=-1;r->plan=&plan;strcpy(r->execution,"e");strcpy(r->copy,"e:r");
        r->proxy_fd=r->attach_fd=r->judge_core=r->judge_conn=r->pty_master=r->pty_slave=-1;
        r->file_fd=r->file_core=r->file_conn=-1;
        r->deadline=w2_now()+UINT64_C(5000000000);
        w2_fault_configure("row.dir");clone_ready(m,r);w2_fault_configure("");
        assert(r->failed&&r->stage==W2_STAGE_ROW_SOCKETS&&!r->pid&&fcntl(0,F_GETFD)>=0);
        puts("{\"check\":\"row-resources-failure-closes-nothing-it-did-not-open\",\"fd0\":\"open\",\"result\":\"passed\"}");
        free(cat);free(m);
    }
    /* overall review 2026-11-03, #5: a connector wait that fails is uncertainty, never an exit fact: no exit code is
     * made up, the pid is not waited for or signalled again, and the spawner is lost (as for pid 1). */
    {
        struct loop *m=calloc(1,sizeof *m);assert(m);
        pid_t gone=fork();assert(gone>=0);if(!gone)_exit(0);
        assert(waitpid(gone,&status,0)==gone);              /* reaped here: no longer a child the record could wait for */
        struct spawn_record *r=&m->records[0];
        r->used=r->connector_started=true;r->channel=-1;r->connector_pid=gone;
        reap_connectors(m);
        assert(!r->connector_exited&&r->connector_lost&&r->failed&&r->stage==W2_STAGE_REAP&&m->lost);
        puts("{\"check\":\"connector-wait-error-is-no-exit-fact\",\"spawner\":\"lost\",\"result\":\"passed\"}");
        free(m);
    }
    /* recheck 2026-11-03: a row whose connector was started but whose start failed before spawn_prepared went out;
     * its domain is empty, its connector not yet reaped. The empty fact waits for connector_exited (K-22), so the core
     * never releases the slot on "no prepared, so no connector" and then meets a late connector_exited. */
    {
        struct loop *m=calloc(1,sizeof *m);assert(m);
        m->ready=m->ready_sent=m->store.ready=true;
        struct spawn_record *r=&m->records[0];
        r->used=r->connector_started=r->failed=r->failed_sent=r->empty=true;r->channel=-1;
        r->pid=4242;r->status=SIGKILL;                               /* cloned, then pid 1 reaped after a kill */
        strcpy(r->execution,"e");strcpy(r->lease,"e:u");
        assert(make_output(m)==0&&!m->output);                       /* nothing yet: the connector has not exited */
        r->connector_exited=true;
        assert(make_output(m)==0&&m->output&&m->output_kind==5&&strstr(m->output,"\"connector_exited\""));
        free(m->output);m->output=NULL;r->connector_exited_sent=true;
        assert(make_output(m)==0&&m->output&&m->output_kind==3&&strstr(m->output,"\"execution_empty\"")&&
               strstr(m->output,"\"pid1_reaped\""));
        free(m->output);m->output=NULL;
        puts("{\"check\":\"empty-waits-for-a-started-connectors-exit-before-prepared\",\"order\":\"connector_exited,execution_empty\",\"result\":\"passed\"}");
        free(m);
    }
    /* recheck 2026-11-03 (S-11): start_connector puts the proxy listener on 3 and the judgment end on 4 whatever numbers
     * they arrive under; here the judgment end arrives as 3 and the listener as 4, the order in which the listener used
     * to land on both. A python3 stand-in for the connector checks that 3 listens and 4 does not. Root: the child drops
     * to the connector uid before it execs. */
    {
        struct loop *m=calloc(1,sizeof *m);struct w2_catalog *cat=calloc(1,sizeof *cat);assert(m&&cat);
        cat->connector.uid=cat->connector.gid=70999;cat->connector.exe="/usr/bin/python3";
        cat->connector.argv[0]="python3";cat->connector.argv[1]="-I";cat->connector.argv[2]="-c";
        cat->connector.argv[3]="import socket,sys\n"
                              "a,b=socket.socket(fileno=3),socket.socket(fileno=4)\n"
                              "listens=[s.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN) for s in (a,b)]\n"
                              "a.detach();b.detach();sys.exit(0 if listens==[1,0] else 3)";
        m->catalog=cat;
        int s0=socket(AF_UNIX,SOCK_STREAM,0),p[2];assert(s0>=0&&!socketpair(AF_UNIX,SOCK_STREAM,0,p));
        struct sockaddr_un addr={.sun_family=AF_UNIX};
        int n=snprintf(addr.sun_path+1,sizeof addr.sun_path-1,"w2-check-%d",(int)getpid());   /* abstract name */
        assert(!bind(s0,(struct sockaddr *)&addr,(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+(size_t)n))&&!listen(s0,1));
        int listener=fcntl(s0,F_DUPFD,10),core=fcntl(p[0],F_DUPFD,10),conn=fcntl(p[1],F_DUPFD,10);
        assert(listener>=0&&core>=0&&conn>=0);close(s0);close(p[0]);close(p[1]);
        assert(dup2(conn,3)==3&&dup2(listener,4)==4);close(conn);close(listener);
        struct spawn_record *r=&m->records[0];
        r->used=true;r->channel=-1;r->uid=70001;strcpy(r->execution,"e");
        r->judge_conn=3;r->proxy_fd=4;r->judge_core=core;r->attach_fd=r->pty_master=r->pty_slave=-1;
        r->file_fd=r->file_core=r->file_conn=-1;
        assert(!start_connector(m,r));
        assert(waitpid(r->connector_pid,&status,0)==r->connector_pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
        puts("{\"check\":\"connector-ends-land-on-3-and-4-from-colliding-numbers\",\"fd3\":\"listener\",\"fd4\":\"judgment\",\"result\":\"passed\"}");
        close(core);free(cat);free(m);
    }
    /* validation.md H-14: the file worker starts the same way, from the same colliding numbers, as its own uid: a
     * python3 stand-in checks that 3 listens, 4 does not, 5-63 are closed and its uid and gid are the worker's. */
    {
        struct loop *m=calloc(1,sizeof *m);struct w2_catalog *cat=calloc(1,sizeof *cat);assert(m&&cat);
        cat->connector.uid=cat->connector.gid=70999;
        cat->file_worker.uid=cat->file_worker.gid=70996;cat->file_worker.exe="/usr/bin/python3";
        cat->file_worker.argv[0]="python3";cat->file_worker.argv[1]="-I";cat->file_worker.argv[2]="-c";
        cat->file_worker.argv[3]="import os,socket,sys\n"
                                "a,b=socket.socket(fileno=3),socket.socket(fileno=4)\n"
                                "listens=[s.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN) for s in (a,b)]\n"
                                "a.detach();b.detach()\n"
                                "def is_open(fd):\n"
                                "    try:\n"
                                "        os.fstat(fd)\n"
                                "        return True\n"
                                "    except OSError:\n"
                                "        return False\n"
                                "extra=[fd for fd in range(5,64) if is_open(fd)]\n"
                                "ids=(os.getresuid(),os.getresgid())\n"
                                "sys.exit(0 if listens==[1,0] and not extra and ids==((70996,)*3,(70996,)*3) else 3)";
        m->catalog=cat;
        int s0=socket(AF_UNIX,SOCK_STREAM,0),p[2];assert(s0>=0&&!socketpair(AF_UNIX,SOCK_STREAM,0,p));
        struct sockaddr_un addr={.sun_family=AF_UNIX};
        int n=snprintf(addr.sun_path+1,sizeof addr.sun_path-1,"w2-check-worker-%d",(int)getpid());
        assert(!bind(s0,(struct sockaddr *)&addr,(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+(size_t)n))&&!listen(s0,1));
        int listener=fcntl(s0,F_DUPFD,10),core=fcntl(p[0],F_DUPFD,10),conn=fcntl(p[1],F_DUPFD,10);
        assert(listener>=0&&core>=0&&conn>=0);close(s0);close(p[0]);close(p[1]);
        assert(dup2(conn,3)==3&&dup2(listener,4)==4);close(conn);close(listener);
        struct spawn_record *r=&m->records[0];
        r->used=true;r->channel=-1;r->uid=70001;strcpy(r->execution,"e");
        r->file_conn=3;r->file_fd=4;r->file_core=core;r->proxy_fd=r->judge_core=r->judge_conn=-1;
        r->attach_fd=r->pty_master=r->pty_slave=-1;
        assert(!start_worker(m,r)&&r->worker_started&&r->file_conn<0&&r->file_fd<0&&r->file_core==core);
        assert(waitpid(r->worker_pid,&status,0)==r->worker_pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
        puts("{\"check\":\"file-worker-ends-land-on-3-and-4-as-the-worker-uid\",\"fd3\":\"listener\",\"fd4\":\"file judgment\",\"uid\":70996,\"result\":\"passed\"}");
        close(core);free(cat);free(m);
    }
    /* H-17: a file worker wait that fails is uncertainty, never an exit fact (as for the connector) */
    {
        struct loop *m=calloc(1,sizeof *m);assert(m);
        pid_t gone=fork();assert(gone>=0);if(!gone)_exit(0);
        assert(waitpid(gone,&status,0)==gone);
        struct spawn_record *r=&m->records[0];
        r->used=r->worker_started=true;r->channel=-1;r->worker_pid=gone;
        reap_connectors(m);
        assert(!r->worker_exited&&r->worker_lost&&r->failed&&r->stage==W2_STAGE_REAP&&m->lost);
        puts("{\"check\":\"file-worker-wait-error-is-no-exit-fact\",\"spawner\":\"lost\",\"result\":\"passed\"}");
        free(m);
    }
    /* H-17: the empty fact waits for a started file worker's exit too; worker_exited goes before execution_empty, and a
     * worker that exits on its own stops its row */
    {
        struct loop *m=calloc(1,sizeof *m);assert(m);
        m->ready=m->ready_sent=m->store.ready=true;
        struct spawn_record *r=&m->records[0];
        r->used=r->connector_started=r->connector_exited=r->connector_exited_sent=true;
        r->worker_started=r->failed=r->failed_sent=r->empty=true;r->channel=-1;
        r->pid=4242;r->status=SIGKILL;
        strcpy(r->execution,"e");strcpy(r->lease,"e:u");
        assert(make_output(m)==0&&!m->output);                       /* nothing yet: the worker has not exited */
        r->worker_exited=true;r->worker_status=SIGKILL;
        assert(make_output(m)==0&&m->output&&m->output_kind==6&&strstr(m->output,"\"worker_exited\"")&&
               strstr(m->output,"\"signal\":9"));
        free(m->output);m->output=NULL;r->worker_exited_sent=true;
        assert(make_output(m)==0&&m->output&&m->output_kind==3&&strstr(m->output,"\"execution_empty\""));
        free(m->output);m->output=NULL;
        struct spawn_record *s=&m->records[1];
        pid_t quick=fork();assert(quick>=0);if(!quick)_exit(0);
        s->used=s->worker_started=true;s->channel=-1;s->worker_pid=quick;s->pid=4243;
        for(int i=0;i<200&&!s->worker_exited;++i){reap_connectors(m);if(!s->worker_exited)usleep(10000);}
        assert(s->worker_exited&&s->stopping&&!s->empty);        /* pid 1 still to be killed and reaped */
        puts("{\"check\":\"empty-waits-for-the-file-worker-exit\",\"order\":\"worker_exited,execution_empty\",\"result\":\"passed\"}");
        free(m);
    }
    /* H-06: the prepared record names the worker beside the connector */
    {
        struct loop *m=calloc(1,sizeof *m);assert(m);
        m->ready=m->ready_sent=m->store.ready=true;strcpy(m->epoch,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        struct w2_policy policy={0};strcpy(policy.digest,"sha256:pp");
        struct w2_plan plan={.entry=json_pack("{s:s}","isolation_profile_digest","sha256:ii"),.policy=&policy};
        strcpy(plan.digest,"sha256:dd");
        struct spawn_record *r=&m->records[0];
        r->used=r->sealed=true;r->channel=7;r->judge_core=8;r->file_core=9;r->plan=&plan;r->pid=4242;
        r->connector_pid=4243;r->worker_pid=4244;strcpy(r->execution,"e");strcpy(r->lease,"e:u");strcpy(r->copy,"e:r");
        assert(make_output(m)==0&&m->output&&m->output_kind==2&&strstr(m->output,"\"connector_pid\":4243")&&
               strstr(m->output,"\"worker_pid\":4244"));
        free(m->output);m->output=NULL;json_decref(plan.entry);
        puts("{\"check\":\"prepared-names-the-file-worker\",\"result\":\"passed\"}");
        free(m);
    }
    return 0;
}
