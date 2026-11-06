"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import os
from pathlib import Path
import re
import time

from common import token

MEMORY_MAX = 2 * 1024 * 1024 * 1024
PIDS_MAX = 1024
RUN_SECONDS = 600
ATTEMPT_SECONDS = 30


def mount_rows(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        split = parts.index("-")
        if split < 6 or len(parts) < split + 4:
            raise ValueError("malformed mountinfo")
        unescape = lambda s: re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), s)
        rows.append({"id": int(parts[0]), "parent": int(parts[1]),
                     "target": unescape(parts[4]), "optional": parts[6:split],
                     "fstype": parts[split + 1], "source": unescape(parts[split + 2])})
    return rows


def check_namespaces(before: dict, inside: dict, mountinfo: str) -> None:
    """before is captured by a host-side launcher BEFORE unshare.

    Comparing to /proc/1 inside a fresh PID namespace is wrong: that PID 1 is us.
    The launcher still needs to bind these observations to its actual child.
    """
    for kind in ("mnt", "net", "pid"):
        if not re.fullmatch(rf"{kind}:\[\d+\]", before.get(kind, "")) or not re.fullmatch(
                rf"{kind}:\[\d+\]", inside.get(kind, "")):
            raise ValueError("missing namespace identity")
        if before[kind] == inside[kind]:
            raise ValueError(f"{kind} namespace not isolated")
    rows = mount_rows(mountinfo)
    root = [r for r in rows if r["target"] == "/"]
    if len(root) != 1 or any(x.startswith(("shared:", "master:")) for r in rows for x in r["optional"]):
        raise ValueError("mount propagation is not private")
    if not any(r["target"] == "/proc" and r["fstype"] == "proc" for r in rows):
        raise ValueError("private proc mount missing")


def process_stat(text: str) -> dict:
    # comm may contain spaces and parentheses. The last ')' ends field 2.
    close = text.rfind(")")
    left = text.find("(")
    if left < 1 or close < left:
        raise ValueError("malformed process stat")
    fields = text[close + 1:].split()
    if len(fields) < 20:
        raise ValueError("short process stat")
    return {"pid": int(text[:left].strip()), "comm": text[left + 1:close],
            "state": fields[0], "start_time": int(fields[19])}


# Base line v4 (engine-v3 @ a9eff999) dedicated ids, none a host account or a reserved execution uid:
# the rows' file worker (validation.md H-14; catalog.c file_worker), the workspace storage owner (S-22;
# run_sandbox_checks.OWNER_ID), the PDP (deploy_catalog.PDP_UID) and the connector.
WORKER_UID, OWNER_UID = 70996, 70997
SERVICE_UIDS = (WORKER_UID, OWNER_UID, 70998, 70999)


def check_reserved_uids(first: int, last: int, accounts: list[int], process_uids: list[int]) -> None:
    if first > last or last - first + 1 > 65536 or any(first <= uid <= last for uid in SERVICE_UIDS):
        raise ValueError("invalid reserved uid range")
    reserved = lambda uid: first <= uid <= last or uid in SERVICE_UIDS
    if any(reserved(uid) for uid in accounts):
        raise ValueError("reserved uid has a host account")
    if any(reserved(uid) for uid in process_uids):
        raise ValueError("reserved uid already has a host process")


class Deadline:
    def __init__(self, seconds: float, clock=time.monotonic):
        if not 0 < seconds <= RUN_SECONDS:
            raise ValueError("invalid deadline")
        self.clock, self.end = clock, clock() + seconds

    def left(self, cap: float | None = None) -> float:
        remaining = self.end - self.clock()
        if remaining <= 0:
            raise TimeoutError("run/attempt deadline exceeded")
        return remaining if cap is None else min(remaining, cap)


class RunCgroup:
    """Owned cgroup only; controller stays outside. No fallback to unconstrained run.

    Requires a delegated parent with memory/pids enabled. Does NOT change the
    parent's subtree_control, move unrelated processes, or enable host controllers.
    """
    def __init__(self, parent: Path, label: str):
        self.path = parent / ("nb-decoy-" + token(label))
        self.created = False
        self.inode = None

    def create(self) -> None:
        from safeio import plain_path
        plain_path(self.path.parent)
        if os.name != "posix" or os.geteuid() != 0:
            raise RuntimeError("cgroup setup requires WSL root")
        cgroup_root = Path("/sys/fs/cgroup")
        if self.path.parent != cgroup_root and cgroup_root not in self.path.parent.parents:
            raise ValueError("cgroup must be under the kernel cgroup2 mount")
        if not any(r["target"] == str(cgroup_root) and r["fstype"] == "cgroup2"
                   for r in mount_rows(Path("/proc/self/mountinfo").read_text())):
            raise RuntimeError("unified cgroup2 mount missing")
        controllers = (self.path.parent / "cgroup.subtree_control").read_text().split()
        if not {"memory", "pids"} <= set(controllers):
            raise RuntimeError("parent has not delegated memory/pids controllers")
        self.path.mkdir(mode=0o700)  # exclusive; never reuse a pre-existing group
        self.created, self.inode = True, self.path.stat().st_ino
        for name, value in (("memory.max", MEMORY_MAX), ("memory.swap.max", 0), ("pids.max", PIDS_MAX)):
            (self.path / name).write_text(str(value))
        (self.path / "memory.oom.group").write_text("1")
        if not (self.path / "cgroup.kill").exists():
            raise RuntimeError("cgroup.kill unavailable")

    def _check(self) -> None:
        if not self.created or self.path.is_symlink() or self.path.stat().st_ino != self.inode:
            raise RuntimeError("cgroup ownership/identity lost")

    def enter_self(self) -> None:
        self._check()
        (self.path / "cgroup.procs").write_text(str(os.getpid()))

    def kill_and_wait(self, timeout: float = 10) -> None:
        self._check()
        relative = "/" + self.path.relative_to("/sys/fs/cgroup").as_posix()
        memberships = [line.split(":", 2)[2] for line in Path("/proc/self/cgroup").read_text().splitlines()
                       if line.startswith("0::")]
        if len(memberships) != 1 or memberships[0] == relative or memberships[0].startswith(relative + "/"):
            raise RuntimeError("controller must be outside the entire run cgroup subtree")
        if str(os.getpid()) in (self.path / "cgroup.procs").read_text().split():
            raise RuntimeError("controller accidentally joined run cgroup")
        (self.path / "cgroup.kill").write_text("1")
        end = time.monotonic() + timeout
        while True:
            events = dict(line.split() for line in (self.path / "cgroup.events").read_text().splitlines())
            if events.get("populated") == "0":
                return
            if time.monotonic() >= end:
                raise TimeoutError("cgroup still populated")
            time.sleep(.02)

    def remove(self) -> None:
        self._check()
        if (self.path / "cgroup.procs").read_text().strip():
            raise RuntimeError("cannot remove populated cgroup")
        self.path.rmdir()  # refuse if descendants remain
        self.created = False
