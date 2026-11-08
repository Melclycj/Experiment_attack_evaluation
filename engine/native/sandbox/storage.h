#ifndef W2_STORAGE_H
#define W2_STORAGE_H
#include "catalog.h"
struct w2_store {
    struct w2_catalog *catalog;
    int fd;pid_t pid;bool owned,ready,dead,closing;
    uint64_t incoming,outgoing,next_job,job,send_deadline,init_deadline;
    char *output;char copy[W2_COPY_CAP];bool cancelled;
};
struct w2_job_result {
    uint64_t job,dev,ino;bool has_root,root_removed;
    char copy[W2_COPY_CAP],result[24],reason[24];int os_errno;
};
int w2_store_start(struct w2_store *s,struct w2_catalog *catalog,int engine_control);
int w2_store_poll(struct w2_store *s,struct w2_job_result *result);
int w2_store_submit(struct w2_store *s,const char *copy,const char *runtime,
                    bool deleting,uint64_t deadline,uint64_t dev,uint64_t ino,bool root_removed);
int w2_store_cancel(struct w2_store *s);
void w2_store_close(struct w2_store *s);
json_t *w2_job_parse(const char *wire,size_t length);
int w2_runtime_create(struct w2_catalog *c,struct w2_runtime *r,const char *copy,
                      uint64_t *dev,uint64_t *ino,bool *created);
int w2_runtime_delete(struct w2_catalog *c,struct w2_runtime *r,const char *copy,
                      uint64_t dev,uint64_t ino,bool previously_removed,bool *removed);
int w2_runtime_matches(struct w2_catalog *c,struct w2_runtime *r,const char *copy);
int w2_runtime_verify_source(struct w2_runtime *r);
/* Trusted supervisor precondition: every old engine/spawner/worker/agent has
 * actually terminated. This function proves filesystem cleanup, not that fact. */
int w2_recover_store(struct w2_catalog *c);
#endif
