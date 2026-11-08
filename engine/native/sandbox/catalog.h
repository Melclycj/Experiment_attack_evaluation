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
    json_t *paths;   /* phase 2: manifest path -> its position in "files", built once (validation.md U-03) */
    char digest[W2_DIGEST_CAP]; int seed_fd; char *seed_ref;
    uint64_t charge_bytes,charge_nodes;
    size_t manifest_bytes;
    char *argv[W2_ARGV_MAX+1], *env[W2_ENV_MAX+1];
};
struct w2_workspace { json_t *entry; struct stat identity; uid_t uid; gid_t gid; };
/* The workspace root (a btrfs subvolume, the owner's, 0700) holds its content in this fixed subdirectory; a cell mounts
 * the subdirectory, never the root, so nothing in a cell can change the root's mode (agent-rm-model 3.1; S-25). */
#define W2_WORKSPACE_TREE "tree"
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
    /* v2 (agent-rm-model 3.1, 3.7): uids are leased per execution from this reserved range; every
     * connector runs as one dedicated uid outside the range and distinct from the engine's. */
    uid_t range_first,range_last;
    struct { uid_t uid; gid_t gid; char *exe; char *argv[W2_ARGV_MAX+1]; } connector;
    /* the row's file worker (validation.md H-14): every row's worker runs as this one dedicated uid, outside the range,
     * apart from the connector's, the PDP's, every workspace owner's and (cell.c) the engine's */
    struct { uid_t uid; gid_t gid; char *exe; char *argv[W2_ARGV_MAX+1]; } file_worker;
    /* v2 cell helpers (validation.md S-07, F-01): the in-cell pty relay and HTTP frontend the child starts after
     * dropping privileges and before the agent; the loopback port the agent's proxy variables name; the deployment
     * directory bind-mounted read-only at /w2 inside the cell (CA, placeholders). */
    struct { char *exe; char *argv[W2_ARGV_MAX+1]; } relay,frontend;
    unsigned proxy_port; char *cell_files_ref;
    /* host file reads (validation.md H-23): the in-cell MCP server the child starts beside the frontend, the same way and
     * under the same confinement, on the cell's loopback at mcp_port (each cell has its own network namespace, so every
     * row uses the same number); never the proxy port */
    struct { char *exe; char *argv[W2_ARGV_MAX+1]; } mcp;
    unsigned mcp_port;
    /* v2 (validation.md S-16): a directory of fresh CA directories (ca.pem, ca.key), one taken per execution */
    char *ca_pool_ref;
    /* deployment switch "runtime_mode" (default "shared" since the workspace rework, validation.md S-23): "shared" binds
     * the verified seed read-only in every cell; "copy" makes a verified per-execution reflink copy instead */
    bool shared_runtime;
    /* set by cell.c before the pre-fork: the engine's identity (owner of <root>/state and the attach sockets) */
    uid_t engine_uid; gid_t engine_gid;
};
int w2_catalog_load(struct w2_catalog *c,const char *root,const char *file);
/* Returns a preparation-only fd after rechecking the frozen source identity. */
int w2_workspace_open(int deployment_fd,const struct w2_workspace *workspace);
void w2_catalog_free(struct w2_catalog *c);
struct w2_plan *w2_plan_find(struct w2_catalog *c,const char *id,const char *digest);
int w2_catalog_load_recovery(struct w2_catalog *c,const char *root,const char *file);
int w2_storage_load(struct w2_catalog *c);
int w2_policy_compile(int root,json_t *entry,struct w2_policy *policy);
/* Phase 2 (validation.md S-20): the cell files directory holds only directories, regular files and symlinks
 * that stay beneath it, owned by root and writable by no group or other. 0, or -1 with errno set. */
int w2_cell_files_check(struct w2_catalog *c);
#endif
