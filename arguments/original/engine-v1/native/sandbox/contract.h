#ifndef W2_SANDBOX_CONTRACT_H
#define W2_SANDBOX_CONTRACT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Parsed local values, never a native-struct wire ABI.
 * Normative owners: engine-design/connections.md#e01-control / #e01-startup,
 * supporting-interfaces.md#e10-launch. Types do NOT validate their contents. */
#define W2_DATA_PROTOCOL "w2-local/2"
#define W2_CONTROL_VERSION 1u
#define W2_DATA_VERSION 2u
#define W2_CONTROL_MAX 16384u
#define W2_BODY_MAX 65536u
#define W2_FRAME_HEADER_SIZE 4u
#define W2_FRAME_MAX (W2_FRAME_HEADER_SIZE + W2_BODY_MAX)
#define W2_BOOTSTRAP_SIZE 16u
#define W2_BOOTSTRAP_VERSION 1u
#define W2_CHANNEL_FD 3
#define W2_ID_MAX 96u
#define W2_ID_CAP (W2_ID_MAX + 1u)
#define W2_EPOCH_CAP 33u
#define W2_DIGEST_CAP 72u
#define W2_ARGV_MAX 64u
#define W2_ENV_MAX 64u
#define W2_STRING_MAX 4096u
#define W2_EXEC_BYTES_MAX 16384u
#define W2_FRAME_TIMEOUT_MS 5000u
#define W2_STORAGE_PROTOCOL "w2-runtime-store/1"
#define W2_COPY_CAP 56u
#define W2_JOB_MAX 1024u

/* Explicit wire numbers: this diagnostic list is not an execution schedule. */
enum w2_stage {
    W2_STAGE_NONE = 0,
    W2_STAGE_VALIDATE = 1,
    W2_STAGE_SOCKETPAIR = 2,
    W2_STAGE_PASSCRED = 3,
    W2_STAGE_CLONE = 4,
    W2_STAGE_MOUNT_PRIVATE = 5,
    W2_STAGE_ROOT = 6,
    W2_STAGE_RUNTIME_MOUNT = 7,
    W2_STAGE_WORK_MOUNT = 8,
    W2_STAGE_PROC = 9,
    W2_STAGE_DEV_TMP = 10,
    W2_STAGE_PIVOT = 11,
    W2_STAGE_LOOPBACK = 12,
    W2_STAGE_STDIO = 13,
    W2_STAGE_FD_CLEANUP = 14,
    W2_STAGE_NO_NEW_PRIVS = 15,
    W2_STAGE_BOUNDING = 16,
    W2_STAGE_GROUPS_GID = 17,
    W2_STAGE_UID = 18,
    W2_STAGE_CAPS = 19,
    W2_STAGE_POLICY = 20,
    W2_STAGE_SEALED = 21,
    W2_STAGE_HANDOFF = 22,
    W2_STAGE_COMMIT = 23,
    W2_STAGE_EXEC = 24,
    W2_STAGE_REAP = 25
};

enum w2_bootstrap_kind { W2_BP_SEALED = 1, W2_BP_COMMIT = 2, W2_BP_FAIL = 3 };
enum w2_contract_result { W2_CONTRACT_OK = 0, W2_CONTRACT_INVALID = 1 };
struct w2_bootstrap {
    enum w2_bootstrap_kind kind;
    enum w2_stage stage;
    uint32_t os_errno;
};

/* Exact-size, host-endian-independent codec. Invalid input leaves output
 * unchanged. Success says nothing about credentials, policy or lifecycle.
 * Buffers and result objects must not overlap. No I/O or allocation occurs. */
enum w2_contract_result w2_bootstrap_encode(
    const struct w2_bootstrap *message, unsigned char *out, size_t out_len);
enum w2_contract_result w2_bootstrap_decode(
    const unsigned char *wire, size_t wire_len, struct w2_bootstrap *out);
const char *w2_stage_name(enum w2_stage stage);

struct w2_execution_ref {
    char engine_epoch[W2_EPOCH_CAP];
    char execution_id[W2_ID_CAP];
    char lease_id[W2_ID_CAP];
};
struct w2_control_ref {
    struct w2_execution_ref execution;
    uint64_t seq; /* serialized as canonical positive decimal JSON string */
};
struct w2_control_init {
    char engine_epoch[W2_EPOCH_CAP];
    uint64_t seq;
    char catalog_digest[W2_DIGEST_CAP];
    char storage_profile_digest[W2_DIGEST_CAP];
    /* type distinguishes control_init/control_ready; protocol is fixed. */
};
struct w2_spawn_request {
    struct w2_control_ref ref;
    uid_t uid; /* allocator reserves this workspace's registered uid (E-05/E-08) */
    gid_t gid; /* must match its registered workspace_gid; not task-selected */
    char launch_plan_id[W2_ID_CAP];
    char launch_plan_digest[W2_DIGEST_CAP];
    uint64_t startup_deadline_ns; /* absolute CLOCK_MONOTONIC, JSON string */
};
struct w2_spawn_prepared {
    struct w2_control_ref ref;
    char launch_plan_digest[W2_DIGEST_CAP];
    char policy_digest[W2_DIGEST_CAP];
    char isolation_profile_digest[W2_DIGEST_CAP];
    pid_t child_pid;
    bool sealed; /* must be true; not sufficient to establish prepared */
    char copy_id[W2_COPY_CAP];
    int owned_channel_fd; /* local received SCM_RIGHTS fd, NOT a JSON field */
};
enum w2_error_code {
    W2_ERROR_INVALID_SPEC, W2_ERROR_RESOURCE_EXHAUSTED, W2_ERROR_OS_ERROR,
    W2_ERROR_PROTOCOL_ERROR, W2_ERROR_TIMEOUT, W2_ERROR_CONTROL_LOST
};
struct w2_spawn_failure {
    struct w2_control_ref ref;
    enum w2_stage stage;
    enum w2_error_code error_code;
    bool has_os_errno;
    uint32_t os_errno;
};
enum w2_stop_reason {
    W2_STOP_NORMAL, W2_STOP_TIMEOUT, W2_STOP_PROTOCOL_ERROR,
    W2_STOP_STARTUP_ERROR, W2_STOP_CONTROL_SHUTDOWN
};
struct w2_stop_request {
    struct w2_control_ref ref;
    enum w2_stop_reason reason;
};
enum w2_empty_basis { W2_EMPTY_NEVER_CREATED, W2_EMPTY_PID1_REAPED };
enum w2_exit_kind { W2_EXIT_NONE, W2_EXIT_CODE, W2_EXIT_SIGNAL };
struct w2_execution_empty {
    struct w2_control_ref ref;
    enum w2_empty_basis basis;
    enum w2_exit_kind exit_kind; /* NONE iff never_created; validate on receipt */
    uint32_t exit_value;        /* ignored for NONE; only one terminal variant */
    enum w2_stage last_stage;
};
enum w2_runtime_view { W2_RUNTIME_PENDING, W2_RUNTIME_RETAINED, W2_RUNTIME_RELEASED };
struct w2_runtime_status {
    struct w2_control_ref ref;
    char copy_id[W2_COPY_CAP];
    enum w2_runtime_view state;
    char basis[24],reason[24];
    unsigned attempt;
    bool has_os_errno;
    uint32_t os_errno;
};

struct w2_launch_plan {
    char launch_plan_id[W2_ID_CAP];
    char runtime_id[W2_ID_CAP];
    char runtime_descriptor_digest[W2_DIGEST_CAP];
    char workspace_id[W2_ID_CAP];
    char workspace_layout_id[W2_ID_CAP];
    char policy_id[W2_ID_CAP];
    char policy_digest[W2_DIGEST_CAP];
    char isolation_profile_id[W2_ID_CAP];
    char isolation_profile_digest[W2_DIGEST_CAP];
};

/* Catalog-owned UTF-8 bytes, immutable for the entire preparation lifetime.
 * Length excludes NUL; validation and execve's terminated copies are future
 * catalog/launcher work. Never retain pointers into agent/parser buffers. */
struct w2_text { const char *data; size_t len; };
struct w2_env_entry { struct w2_text key, value; };
struct w2_runtime_descriptor_view {
    struct w2_text runtime_id, adapter_id, artifact_digest, dependency_digest;
    struct w2_text layout_id, executable, cwd, protocol;
    struct w2_text storage_profile_id,adapter_config_ref,adapter_config_digest;
    struct w2_text compatibility_profile,component_manifest_ref,component_manifest_digest;
    const struct w2_text *argv;
    size_t argc;
    const struct w2_env_entry *env;
    size_t envc;
};

/* No launch/stop/catalog implementation is supplied by this interface module.
 * In particular there is no stub that can report successful isolation. */
#endif
