#ifndef W2_SPAWNER_H
#define W2_SPAWNER_H
#include "catalog.h"
/* Owns control fd until exit; caller must pre-fork before opening secrets. */
int w2_spawner_run(struct w2_catalog *catalog,int control);
/* Everything the cloned child needs; filled by the spawner, read-only in the child. v2 adds the pty pair, the
 * attach listener and the row directory (the proxy socket is bind-mounted from it). */
struct w2_child_args {
    struct w2_plan *plan;struct w2_catalog *catalog;int channel,other,control,worker,idmap,pty_master,pty_slave,attach;
    uid_t uid;gid_t gid;char root[W2_PATH_CAP],source[W2_PATH_CAP],copy[W2_COPY_CAP],rows_dir[W2_PATH_CAP];uint64_t deadline,dev,ino;
};
int w2_child_launch(struct w2_child_args *a);
#endif
