/* Fuzz entry 3 (R-G2-11, lowest priority): w2_control_parse, the control-record parser behind
 * w2_recv_control. Its input comes from the trusted spawner, not from an agent.
 *
 * Oracle: ASan/UBSan; an accepted record is a JSON object whose v is 1 and whose type is one of
 * the control types the parser knows. */
#define _GNU_SOURCE
#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIE(msg) do { fprintf(stderr, "fuzz_control: %s\n", msg); abort(); } while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    json_t *j = w2_control_parse((const char *)data, size);
    if (!j) return 0;
    static const char *const types[] = {"control_init", "control_ready", "spawn", "spawn_prepared",
                                        "runtime_status", "spawn_failed", "stop", "execution_empty"};
    const char *type = w2_str(j, "type");
    bool known = false;
    for (size_t i = 0; type && i < sizeof types / sizeof types[0]; ++i) known |= !strcmp(type, types[i]);
    if (!json_is_object(j) || json_integer_value(json_object_get(j, "v")) != 1 || !known) DIE("accepted a malformed record");
    json_decref(j);
    return 0;
}
