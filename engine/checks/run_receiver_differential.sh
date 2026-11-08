#!/bin/sh
# Receiver differential (validation.md C-11) inside a disposable container: nothing is installed on the host and no port
# leaves the container. Usage (from WSL, docker available):  sh checks/run_receiver_differential.sh runs/<dir>
set -eu
engine=$(cd "$(dirname "$0")/.." && pwd)
out=$(mkdir -p "$1" && cd "$1" && pwd)
docker run --rm -v "$engine":/engine:ro -v "$out":/out python:3.12-slim sh -c '
  set -e
  apt-get update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nginx apache2 haproxy >/dev/null 2>&1
  { echo "container: $(cat /etc/os-release | sed -n s/^PRETTY_NAME=//p)"; python3 --version; } > /out/environment.txt
  python3 -I -B /engine/checks/receiver_differential.py --out /out
' 2>&1 | tee "$out/stdout.txt"
