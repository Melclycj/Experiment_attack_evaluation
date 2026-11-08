"""The driver's cgroup placement of engine rows, run alongside the engine's own checks (protocol.md 1: before the
placement is used, the engine's integration check is rerun under it). Run as root on the server:

    python3 -m driver.engine_mover <log.jsonl>        # until SIGTERM

Every 0.2 s: each process whose real uid is in the execution range (the cell) goes to sotamem/placement/u<uid>, and
each of a row's processes outside the cell (the connector, argv "... bin/connector ... <uid> <execution>", and the file
worker, argv "... bin/file-worker ... <uid> <execution>", each at its dedicated uid) goes to the cgroup of the uid it
serves; all with the unit quota (2 CPU, 4 GiB), as driver/engine_object.py places a unit. Processes inside a cgroup
the engine's checks made for themselves (the two-epoch case puts a cell in sys/fs/cgroup/engine-check-*-cell) are left
there and logged.
"""
from __future__ import annotations

import json
import signal
import sys
import time
from pathlib import Path

from .agent import make_cgroup, uid_procs
from .engine_object import CONNECTOR_UID, FILE_WORKER_UID, UID_COUNT, UID_FIRST
from .objects import UNIT_CPU_MAX, UNIT_MEM_MAX

RANGE = range(UID_FIRST, UID_FIRST + UID_COUNT)
ROW_PROGRAMS = {CONNECTOR_UID: "bin/connector", FILE_WORKER_UID: "bin/file-worker"}


def own_cgroup(pid: int) -> str:
    return Path(f"/proc/{pid}/cgroup").read_text().strip().split("::", 1)[-1]


def served_uid(p: dict) -> int | None:
    """The execution uid a process belongs to: its own for a cell process; for a row process outside the cell, the
    uid its argv ends with (spawner.c start_row_process appends the row's uid and execution id); None otherwise."""
    if p["uid"] not in ROW_PROGRAMS:
        return p["uid"]
    argv = p["argv"]
    if len(argv) >= 2 and argv[-2].isdigit() and ROW_PROGRAMS[p["uid"]] in " ".join(argv):
        return int(argv[-2])
    return None


def main(log: Path) -> int:
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    moved, skipped = 0, set()
    with log.open("a") as fh:
        fh.write(json.dumps({"t": time.time(), "event": "start"}) + "\n")
        while not stop:
            for p in uid_procs([*RANGE, *ROW_PROGRAMS]):
                try:
                    uid = served_uid(p)
                    if uid is None:
                        continue
                    here = own_cgroup(p["pid"])
                    target = f"/sotamem/placement/u{uid}"
                    if here == target:
                        continue
                    if here.startswith("/engine-check-"):
                        if p["pid"] not in skipped:
                            skipped.add(p["pid"])
                            fh.write(json.dumps({"t": time.time(), "event": "left", "pid": p["pid"], "cgroup": here}) + "\n")
                        continue
                    path = make_cgroup(f"placement/u{uid}", UNIT_CPU_MAX, UNIT_MEM_MAX)
                    Path(path, "cgroup.procs").write_text(str(p["pid"]))
                    moved += 1
                    fh.write(json.dumps({"t": time.time(), "event": "moved", "pid": p["pid"], "uid": p["uid"],
                                         "comm": p["comm"], "from": here, "to": target}) + "\n")
                except OSError:
                    continue  # exited meanwhile
            fh.flush()
            time.sleep(0.2)
        fh.write(json.dumps({"t": time.time(), "event": "stop", "moved": moved}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
