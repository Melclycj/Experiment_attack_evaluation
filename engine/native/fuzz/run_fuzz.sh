#!/bin/bash
# R-G2-11 fuzz run: four libFuzzer entries over transport.c (judge added in v2 block 4) (clang-18, ASan/UBSan) in parallel, then the
# final corpora and any crash inputs replayed through a gcc 13 ASan/UBSan --coverage build.
# Usage (WSL, non-root):  native/fuzz/run_fuzz.sh RUN_DIR SECONDS
# RUN_DIR must exist and hold only the README with the pre-run criteria; build and corpora live in a fresh /tmp directory and are copied in at the end.
set -euo pipefail
[ "$(id -u)" != 0 ] || { echo "run as non-root (uid 0 is a sentinel the receive comparison rejects)" >&2; exit 2; }
RUN_DIR=$(realpath -m "$1"); SECONDS_PER_ENTRY=$2
NATIVE=$(cd "$(dirname "$0")/.." && pwd)
[ "$(ls -A "$RUN_DIR")" = README.md ] || { echo "RUN_DIR must hold only README.md" >&2; exit 2; }
B=$(mktemp -d /tmp/engine-fuzz.XXXXXX)
ENTRIES="frame ancillary control judge"
declare -A MAX_LEN=([frame]=140000 [ancillary]=8194 [control]=20000 [judge]=140000)
SRC="$NATIVE/sandbox/support.c $NATIVE/sandbox/contract.c"
LIBS="-ljansson -lmd -lcap"
CLANG_FLAGS="-std=c17 -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined -I$NATIVE/sandbox"
GCC_FLAGS="-std=c17 -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined --coverage -I$NATIVE/sandbox"
log() { echo "$*" | tee -a "$RUN_DIR/commands.txt"; }

{
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "seconds_per_entry=$SECONDS_PER_ENTRY"
  echo "kernel=$(uname -r)"; clang-18 --version | head -1; gcc --version | head -1
  dpkg-query -W -f='${Package} ${Version}\n' libjansson-dev libmd-dev libcap-dev libclang-rt-18-dev
  (cd "$NATIVE" && sha256sum sandbox/transport.c sandbox/transport.h sandbox/support.c sandbox/support.h \
     sandbox/contract.c sandbox/contract.h fuzz/*.c fuzz/seeds.py fuzz/run_fuzz.sh)
} > "$RUN_DIR/environment.txt"

for e in $ENTRIES; do
  mkdir -p "$B/clang-$e" "$B/gcc-$e" "$B/corpus/$e" "$B/crash/$e"
  define=""; [ "$e" = ancillary ] && define="-Dclose=fuzz_close"
  # clang: transport.c is its own object so the close rename stays inside it
  log clang-18 $CLANG_FLAGS -fsanitize=fuzzer-no-link $define -c "$NATIVE/sandbox/transport.c" -o "$B/clang-$e/transport.o"
  clang-18 $CLANG_FLAGS -fsanitize=fuzzer-no-link $define -c "$NATIVE/sandbox/transport.c" -o "$B/clang-$e/transport.o"
  log clang-18 $CLANG_FLAGS -fsanitize=fuzzer "$NATIVE/fuzz/fuzz_$e.c" "$B/clang-$e/transport.o" $SRC $LIBS -o "$B/clang-$e/fuzz"
  clang-18 $CLANG_FLAGS -fsanitize=fuzzer "$NATIVE/fuzz/fuzz_$e.c" "$B/clang-$e/transport.o" $SRC $LIBS -o "$B/clang-$e/fuzz"
  # gcc replay build, one object per source so gcov finds transport.gcda / support.gcda here
  for s in sandbox/transport.c sandbox/support.c sandbox/contract.c fuzz/fuzz_$e.c fuzz/replay_main.c; do
    d=""; [ "$s" = sandbox/transport.c ] && d="$define"
    log gcc $GCC_FLAGS $d -c "$NATIVE/$s" -o "$B/gcc-$e/$(basename "$s" .c).o"
    gcc $GCC_FLAGS $d -c "$NATIVE/$s" -o "$B/gcc-$e/$(basename "$s" .c).o"
  done
  gcc $GCC_FLAGS "$B"/gcc-$e/*.o $LIBS -o "$B/gcc-$e/replay"
done

python3 -I "$NATIVE/fuzz/seeds.py" "$B/seeds"

for e in $ENTRIES; do
  log "$B/clang-$e/fuzz" -max_total_time="$SECONDS_PER_ENTRY" -max_len="${MAX_LEN[$e]}" -timeout=10 -rss_limit_mb=2048 \
      -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$B/crash/$e/" "$B/corpus/$e" "$B/seeds/$e"
  "$B/clang-$e/fuzz" -max_total_time="$SECONDS_PER_ENTRY" -max_len="${MAX_LEN[$e]}" -timeout=10 -rss_limit_mb=2048 \
      -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$B/crash/$e/" "$B/corpus/$e" "$B/seeds/$e" \
      > "$RUN_DIR/fuzz-$e.log" 2>&1 &
done
status=0
for e in $ENTRIES; do wait -n || status=1; done
echo "fuzz_exit_nonzero=$status" >> "$RUN_DIR/environment.txt"

for e in $ENTRIES; do
  inputs=$(find "$B/corpus/$e" "$B/seeds/$e" "$B/crash/$e" -type f | sort)
  set +e
  # shellcheck disable=SC2086
  (cd "$B/gcc-$e" && ./replay $inputs) > "$RUN_DIR/replay-$e.log" 2>&1
  replay_exit=$?
  echo "replay_${e}_exit=$replay_exit" >> "$RUN_DIR/environment.txt"
  [ "$replay_exit" = 0 ] || status=1
  (cd "$B/gcc-$e" && gcov -b -f -o . "$NATIVE/sandbox/transport.c" "$NATIVE/sandbox/support.c") > "$RUN_DIR/gcov-$e.txt" 2>&1
  set -e
  cp "$B/gcc-$e/transport.c.gcov" "$RUN_DIR/gcov-$e-transport.c.gcov" 2>/dev/null || true
  echo "corpus_${e}_files=$(find "$B/corpus/$e" -type f | wc -l) crash_${e}_files=$(find "$B/crash/$e" -type f | wc -l)" \
      >> "$RUN_DIR/environment.txt"
done
tar -C "$B" -cf "$RUN_DIR/corpora.tar" seeds corpus crash
echo "finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RUN_DIR/environment.txt"
rm -rf "$B"
echo "overall_status=$status" >> "$RUN_DIR/environment.txt"
echo "done: $RUN_DIR (status $status)"
exit "$status"
