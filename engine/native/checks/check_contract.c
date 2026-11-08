#include "contract.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "contract check failed at line %d: %s\n", __LINE__, #c); \
    exit(1); } } while (0)

_Static_assert(CHAR_BIT == 8, "wire uses 8-bit octets");
_Static_assert(sizeof(uid_t) == 4 && (uid_t)-1 > 0, "target Linux uid_t ABI");
_Static_assert(sizeof(gid_t) == 4 && (gid_t)-1 > 0, "target Linux gid_t ABI");
_Static_assert(sizeof(pid_t) == 4 && (pid_t)-1 < 0, "target Linux pid_t ABI");
_Static_assert(W2_FRAME_MAX == 65540, "prefix is charged to frame bound");
_Static_assert(sizeof(((struct w2_spawn_request *)0)->startup_deadline_ns) == 8,
               "deadline must not narrow");
_Static_assert(sizeof(((struct w2_launch_plan *)0)->policy_digest) == 72,
               "digest text plus terminator");

/* Golden byte vectors come from E-01's field widths/values, not encode(). */
static const unsigned char sealed[16] =
    {0x57,0x32,0x42,0x50,0,1,0,1, 0,0,0,0, 0,0,0,0};
static const unsigned char commit[16] =
    {0x57,0x32,0x42,0x50,0,1,0,2, 0,0,0,0, 0,0,0,0};
static const unsigned char fail_policy[16] =
    {0x57,0x32,0x42,0x50,0,1,0,3, 0,0,0,20, 0,0,0,1};

static void rejected(const unsigned char *wire, size_t n)
{
    struct w2_bootstrap out = {W2_BP_FAIL, W2_STAGE_EXEC, 73};
    CHECK(w2_bootstrap_decode(wire, n, &out) == W2_CONTRACT_INVALID);
    CHECK(out.kind == W2_BP_FAIL && out.stage == W2_STAGE_EXEC && out.os_errno == 73);
}
static void golden(const unsigned char *wire, struct w2_bootstrap expected)
{
    unsigned char storage[18]; memset(storage, 0xa5, sizeof storage);
    struct w2_bootstrap out;
    CHECK(w2_bootstrap_encode(&expected, storage + 1, 16) == W2_CONTRACT_OK);
    CHECK(storage[0] == 0xa5 && storage[17] == 0xa5);
    CHECK(memcmp(storage + 1, wire, 16) == 0);
    /* deliberately unaligned input/output byte storage */
    CHECK(w2_bootstrap_decode(storage + 1, 16, &out) == W2_CONTRACT_OK);
    CHECK(out.kind == expected.kind && out.stage == expected.stage
          && out.os_errno == expected.os_errno);
}
int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--stages") == 0) {
        for (int i = 1; i <= W2_STAGE_REAP; ++i)
            printf("%d %s\n", i, w2_stage_name((enum w2_stage)i));
        return 0;
    }
    CHECK(argc == 1);
    CHECK(strcmp(W2_DATA_PROTOCOL, "w2-local/2") == 0);
    golden(sealed, (struct w2_bootstrap){W2_BP_SEALED, W2_STAGE_NONE, 0});
    golden(commit, (struct w2_bootstrap){W2_BP_COMMIT, W2_STAGE_NONE, 0});
    golden(fail_policy, (struct w2_bootstrap){W2_BP_FAIL, W2_STAGE_POLICY, 1});
    for (int stage = 1; stage <= (int)W2_STAGE_LAST; ++stage) {
        unsigned char wire[16]; memcpy(wire, fail_policy, 16);
        wire[11] = (unsigned char)stage;
        memset(wire + 12, 0xff, 4);
        golden(wire, (struct w2_bootstrap){W2_BP_FAIL, (enum w2_stage)stage, UINT32_MAX});
        memset(wire + 12, 0, 4);
        golden(wire, (struct w2_bootstrap){W2_BP_FAIL, (enum w2_stage)stage, 0});
    }
    for (size_t n = 0; n < 16; ++n) rejected(sealed, n);
    unsigned char longer[17]; memcpy(longer, sealed, 16); longer[16] = 0;
    rejected(longer, sizeof longer);
    for (size_t i = 0; i < 8; ++i) {
        unsigned char wire[16]; memcpy(wire, sealed, 16);
        wire[i] = 0xff; rejected(wire, 16);
    }
    for (size_t i = 8; i < 16; ++i) {
        unsigned char wire[16]; memcpy(wire, sealed, 16);
        wire[i] = 1; rejected(wire, 16);
        memcpy(wire, commit, 16); wire[i] = 1; rejected(wire, 16);
    }
    unsigned char bad[16]; memcpy(bad, fail_policy, 16);
    bad[11] = 0; rejected(bad, 16);
    bad[11] = (unsigned char)(W2_STAGE_LAST + 1); rejected(bad, 16);
    bad[8] = 0x80; rejected(bad, 16);
    rejected(NULL, 16);
    CHECK(w2_bootstrap_decode(sealed, 16, NULL) == W2_CONTRACT_INVALID);
    struct w2_bootstrap invalid[] = {
        {0, W2_STAGE_NONE, 0}, {4, W2_STAGE_NONE, 0},
        {W2_BP_SEALED, W2_STAGE_VALIDATE, 0}, {W2_BP_COMMIT, W2_STAGE_NONE, 1},
        {W2_BP_FAIL, W2_STAGE_NONE, 1}, {W2_BP_FAIL, (enum w2_stage)-1, 1},
        {W2_BP_FAIL, (enum w2_stage)(W2_STAGE_LAST + 1), 1}
    };
    unsigned char output[16], unchanged[16]; memset(unchanged, 0x5a, 16);
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        memcpy(output, unchanged, 16);
        CHECK(w2_bootstrap_encode(&invalid[i], output, 16) == W2_CONTRACT_INVALID);
        CHECK(memcmp(output, unchanged, 16) == 0);
    }
    struct w2_bootstrap good = {W2_BP_SEALED, W2_STAGE_NONE, 0};
    for (size_t n = 0; n <= 17; ++n) {
        if (n == 16) continue;
        memcpy(output, unchanged, 16);
        CHECK(w2_bootstrap_encode(&good, output, n) == W2_CONTRACT_INVALID);
        CHECK(memcmp(output, unchanged, 16) == 0);
    }
    CHECK(w2_bootstrap_encode(NULL, output, 16) == W2_CONTRACT_INVALID);
    CHECK(w2_bootstrap_encode(&good, NULL, 16) == W2_CONTRACT_INVALID);
    CHECK(w2_stage_name(W2_STAGE_NONE) == NULL);
    CHECK(w2_stage_name((enum w2_stage)-1) == NULL);
    CHECK(w2_stage_name((enum w2_stage)(W2_STAGE_LAST + 1)) == NULL);
    puts("{\"check\":\"SC-types/SC-bootstrap\",\"result\":\"passed\","
         "\"scope\":\"C ABI and pure codec only; no launch, identity or policy validation\"}");
    return 0;
}
