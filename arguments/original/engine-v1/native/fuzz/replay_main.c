/* Replays fuzz inputs through one entry's LLVMFuzzerTestOneInput in a gcc build (ASan/UBSan and
 * --coverage), so the corpus is also exercised by the production compiler. Each argument is a file. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    static uint8_t buffer[1 << 20];
    for (int i = 1; i < argc; ++i) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); return 2; }
        size_t n = fread(buffer, 1, sizeof buffer, f);
        if (ferror(f) || !feof(f)) { fprintf(stderr, "%s: unreadable or over 1 MiB\n", argv[i]); return 2; }
        fclose(f);
        LLVMFuzzerTestOneInput(buffer, n);
    }
    printf("replayed %d inputs\n", argc - 1);
    return 0;
}
