#include "contract.h"
#include <string.h>

static void put_u32(unsigned char *p, uint32_t x)
{
    p[0] = (unsigned char)(x >> 24);
    p[1] = (unsigned char)(x >> 16);
    p[2] = (unsigned char)(x >> 8);
    p[3] = (unsigned char)x;
}
static uint32_t get_u32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static bool valid(const struct w2_bootstrap *m)
{
    if (m->kind == W2_BP_SEALED || m->kind == W2_BP_COMMIT)
        return m->stage == W2_STAGE_NONE && m->os_errno == 0;
    return m->kind == W2_BP_FAIL
        && m->stage >= W2_STAGE_VALIDATE && m->stage <= W2_STAGE_LAST;   /* v2: the helper stages are reportable too */
}
enum w2_contract_result w2_bootstrap_encode(
    const struct w2_bootstrap *m, unsigned char *out, size_t out_len)
{
    if (!m || !out || out_len != W2_BOOTSTRAP_SIZE || !valid(m))
        return W2_CONTRACT_INVALID;
    unsigned char wire[W2_BOOTSTRAP_SIZE] = {'W', '2', 'B', 'P', 0, 1, 0, 0};
    wire[7] = (unsigned char)m->kind;
    put_u32(wire + 8, (uint32_t)m->stage);
    put_u32(wire + 12, m->os_errno);
    memcpy(out, wire, sizeof wire);
    return W2_CONTRACT_OK;
}
enum w2_contract_result w2_bootstrap_decode(
    const unsigned char *wire, size_t wire_len, struct w2_bootstrap *out)
{
    if (!wire || !out || wire_len != W2_BOOTSTRAP_SIZE)
        return W2_CONTRACT_INVALID;
    if (memcmp(wire, "W2BP", 4) || wire[4] || wire[5] != W2_BOOTSTRAP_VERSION
        || wire[6] || wire[7] < W2_BP_SEALED || wire[7] > W2_BP_FAIL)
        return W2_CONTRACT_INVALID;
    uint32_t stage = get_u32(wire + 8);
    if (stage > W2_STAGE_LAST)
        return W2_CONTRACT_INVALID; /* range check before narrowing to enum */
    struct w2_bootstrap m = {
        .kind = (enum w2_bootstrap_kind)wire[7],
        .stage = (enum w2_stage)stage,
        .os_errno = get_u32(wire + 12)
    };
    if (!valid(&m))
        return W2_CONTRACT_INVALID;
    *out = m;
    return W2_CONTRACT_OK;
}
const char *w2_stage_name(enum w2_stage stage)
{
    static const char *const names[] = {
        NULL, "validate", "socketpair", "passcred", "clone", "mount_private",
        "root", "runtime_mount", "work_mount", "proc", "dev_tmp", "pivot",
        "loopback", "stdio", "fd_cleanup", "no_new_privs", "bounding",
        "groups_gid", "uid", "caps", "policy", "sealed", "handoff", "commit",
        "exec", "reap", "row_sockets", "pty", "helpers", "connector", "file_worker"
    };
    if (stage < W2_STAGE_VALIDATE || stage > W2_STAGE_LAST)
        return NULL;
    return names[stage];
}

