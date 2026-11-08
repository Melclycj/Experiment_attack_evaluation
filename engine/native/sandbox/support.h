#ifndef W2_SUPPORT_H
#define W2_SUPPORT_H
#include "contract.h"
#include <jansson.h>
#include <sys/resource.h>
#include <sys/stat.h>
#define W2_CATALOG_MAX (1024u * 1024u)
#define W2_ITEMS_MAX 64u
#define W2_EXECUTIONS_MAX 16u
#define W2_PATH_CAP 4096u
#define W2_MANIFEST_MAX (16u * 1024u * 1024u)

uint64_t w2_now(void);
int w2_nonblock(int fd);
int w2_fault(const char *point);
void w2_fault_configure(const char *point);
void w2_fault_scope(const char *prefix);
int w2_digest(const void *data, size_t size, char out[W2_DIGEST_CAP]);
int w2_digest_fd(int fd, char out[W2_DIGEST_CAP]);
bool w2_is_digest(const char *s);
bool w2_is_id(const char *s);
bool w2_decimal(const char *s, uint64_t *out, bool positive);
json_t *w2_json(const char *data, size_t size);
json_t *w2_frame_json(const char *data, size_t size);
bool w2_keys(json_t *j, const char *const *keys, size_t count);
const char *w2_str(json_t *j, const char *key);
int w2_open_at(int root, const char *path, int flags);
int w2_read_at(int root, const char *path, size_t limit, char **out, size_t *size);
json_t *w2_json_at(int root, const char *path, char digest[W2_DIGEST_CAP]);
bool w2_relative(const char *path);
int w2_environment(uid_t *overflow, gid_t *overflow_gid);
int w2_environment_values(const char *map, const char *uid, const char *gid,
                          const char *yama, const char *ksm, uid_t *out, gid_t *out_gid);
int w2_drop(uid_t uid, gid_t gid, enum w2_stage *stage);
int w2_require_spawner_caps(void);
int w2_limit_spawner_caps(void);
void w2_checkpoint_configure(int (*check)(void *),void *context);
int w2_checkpoint(void);
/* Host file reads (validation.md H-10, H-11, H-12): open `path` beneath `dirfd` with openat2 (RESOLVE_BENEATH,
 * RESOLVE_NO_SYMLINKS, RESOLVE_NO_MAGICLINKS; no RESOLVE_NO_XDEV), first as O_PATH; only a regular file (read) or a
 * directory (list) is then reopened through /proc/self/fd as O_RDONLY (list: O_DIRECTORY too). Returns the descriptor
 * and fills *out (optional) with its fstat, or -1 with errno: EISDIR or EOPNOTSUPP for a read of a non-regular file,
 * ENOTDIR for a list of a non-directory, ESTALE if the reopened file is not the probed one, else openat2's own. */
#define W2_OPEN_READ 1
#define W2_OPEN_LIST 2
int w2_open_beneath(int dirfd, const char *path, int want, struct stat *out);
#endif
