#ifndef W2_CATALOG_H
#define W2_CATALOG_H
#include "support.h"
#include <linux/filter.h>
struct w2_policy {
    json_t *entry; char digest[W2_DIGEST_CAP], bpf_digest[W2_DIGEST_CAP];
    struct sock_fprog program;
};
struct w2_runtime {
    json_t *descriptor, *manifest;
    char digest[W2_DIGEST_CAP]; int seed_fd;
    uint64_t charge_bytes,charge_nodes;
    size_t manifest_bytes;
    char *argv[W2_ARGV_MAX+1], *env[W2_ENV_MAX+1];
};
struct w2_workspace { json_t *entry; struct stat identity; uid_t uid; gid_t gid; };
struct w2_plan {
    json_t *entry; char digest[W2_DIGEST_CAP];
    struct w2_runtime *runtime; struct w2_policy *policy;
    struct w2_workspace *workspace;
};
struct w2_storage_profile {
    json_t *entry;
    char digest[W2_DIGEST_CAP],store_id[33],uuid[37];
    int root_fd,lock_fd;
    struct stat root_identity,objects_identity;
    uint64_t capacity,max_bytes,max_nodes,min_free;
    unsigned max_tree_nodes,cleanup_ms;
};
struct w2_catalog {
    int root_fd, instances_fd; char root[W2_PATH_CAP], digest[W2_DIGEST_CAP];
    uid_t overflow; gid_t overflow_gid; json_t *document;
    struct w2_runtime runtime[W2_ITEMS_MAX]; size_t runtime_count;
    struct w2_policy policy[W2_ITEMS_MAX]; size_t policy_count;
    struct w2_workspace workspace[W2_ITEMS_MAX]; size_t workspace_count;
    json_t *profile[W2_ITEMS_MAX]; char profile_digest[W2_ITEMS_MAX][W2_DIGEST_CAP]; size_t profile_count;
    struct w2_plan plan[W2_ITEMS_MAX]; size_t plan_count;
    struct w2_storage_profile storage;
    bool recovery_mode;
};
int w2_catalog_load(struct w2_catalog *c,const char *root,const char *file);
/* Returns a preparation-only fd after rechecking the frozen source identity. */
int w2_workspace_open(int deployment_fd,const struct w2_workspace *workspace);
void w2_catalog_free(struct w2_catalog *c);
struct w2_plan *w2_plan_find(struct w2_catalog *c,const char *id,const char *digest);
int w2_catalog_load_recovery(struct w2_catalog *c,const char *root,const char *file);
int w2_storage_load(struct w2_catalog *c);
int w2_policy_compile(int root,json_t *entry,struct w2_policy *policy);
#endif
