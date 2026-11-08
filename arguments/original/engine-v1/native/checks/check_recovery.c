#define _GNU_SOURCE
#include "storage.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* Link-time observers around production recovery, without W2_TESTING.
 * The actual fsync/fstatvfs complete on the disposable Btrfs store. Only the
 * subsequent monotonic clock is controlled to sample the deadline boundary;
 * this does not simulate a real blocked disk or a wall-clock latency sample. */
uint64_t __real_w2_now(void);
int __real_fsync(int fd);
int __real_fstatvfs(int fd, struct statvfs *out);
static bool armed, forced, sampled;
static int objects_fd, edge;
static const char *point;
static uint64_t start, budget, forced_time;
static unsigned sync_calls, stat_calls;

uint64_t __wrap_w2_now(void) {
    uint64_t now=__real_w2_now();
    if(armed&&!sampled){start=now;sampled=true;}
    return forced?forced_time:now;
}
static void advance(const char *where) {
    if(strcmp(point,where))return;
    assert(sampled&&!forced);
    forced_time=start+budget;
    if(edge<0)--forced_time;
    if(edge>0)++forced_time;
    forced=true;
}
int __wrap_fsync(int fd) {
    int rc=__real_fsync(fd),saved=errno;
    if(armed&&fd==objects_fd){assert(!rc);++sync_calls;advance("fsync");}
    errno=saved;return rc;
}
int __wrap_fstatvfs(int fd,struct statvfs *out) {
    int rc=__real_fstatvfs(fd,out),saved=errno;
    if(armed&&fd==objects_fd){assert(!rc);++stat_calls;advance("fstatvfs");}
    errno=saved;return rc;
}
int main(int argc,char **argv) {
    assert(argc==5);
    point=argv[3];
    assert(!strcmp(point,"normal")||!strcmp(point,"fsync")||!strcmp(point,"fstatvfs"));
    assert(!strcmp(argv[4],"-1")||!strcmp(argv[4],"0")||!strcmp(argv[4],"1"));
    edge=atoi(argv[4]);
    struct w2_catalog *c=calloc(1,sizeof *c);assert(c);
    assert(!w2_catalog_load_recovery(c,argv[1],argv[2]));
    objects_fd=c->instances_fd;
    budget=UINT64_C(16)*3*c->storage.cleanup_ms*1000000;
    uint64_t real_start=__real_w2_now();armed=true;errno=0;
    int rc=w2_recover_store(c),saved=errno;armed=false;
    uint64_t elapsed=__real_w2_now()-real_start;
    assert(sampled&&sync_calls==1&&stat_calls==1);
    bool expired=strcmp(point,"normal")&&edge>=0;
    assert(expired?(rc==-1&&saved==ETIMEDOUT):rc==0);
    assert(!strcmp(point,"normal")?!forced:forced);
    cap_t caps=cap_get_proc();char *text=cap_to_text(caps,NULL);
    assert(text&&!strcmp(text,"="));cap_free(text);cap_free(caps);
    assert(getuid()==0&&geteuid()==0&&prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
    printf("{\"check\":\"recovery-tail-deadline\",\"point\":\"%s\",\"boundary_offset_ns\":%d,"
           "\"clock_controlled\":%s,\"budget_ns\":%llu,\"actual_elapsed_ns\":%llu,"
           "\"actual_fsync_calls\":%u,\"actual_fstatvfs_calls\":%u,\"recovery_result\":%d,"
           "\"os_errno\":%d,\"posture\":\"capless-0:0-NNP\",\"result\":\"passed\"}\n",
           point,edge,forced?"true":"false",(unsigned long long)budget,
           (unsigned long long)elapsed,sync_calls,stat_calls,rc,rc?saved:0);
    w2_catalog_free(c);free(c);return 0;
}
