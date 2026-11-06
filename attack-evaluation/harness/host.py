"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import re
import stat

from common import utc
from env import check_reserved_uids
from safeio import plain_path

NAMESPACE_KINDS = ("mnt", "net", "pid")


def namespaces(proc: Path = Path("/proc")) -> dict:
    return {kind: os.readlink(proc / "self/ns" / kind) for kind in NAMESPACE_KINDS}


def status_uids(text: str) -> list[int]:
    match = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", text, re.MULTILINE)
    if not match:
        raise ValueError("process UID evidence missing/malformed")
    return [int(value) for value in match.groups()]


def host_process_uids(proc: Path = Path("/proc")) -> list[int]:
    """Scan before unshare. Fail closed on inaccessible live tasks, not on exits.

    Check threads as well: Linux credentials are task-local. Collect all four UID
    fields, not only effective UID. A snapshot is not a reservation against later
    external process creation; the engine's own start-time checks still apply.
    """
    found = set()
    for process in proc.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            tasks = list((process / "task").iterdir())
        except FileNotFoundError:
            continue
        for task in tasks:
            if not task.name.isdecimal():
                continue
            try:
                found.update(status_uids((task / "status").read_text()))
            except FileNotFoundError:
                continue
    return sorted(found)


def socket_metadata(path: Path) -> dict:
    """Presence/permissions only. Never connect to a real daemon or session bus."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"path": str(path), "exists": False}
    return {"path": str(path), "exists": True, "socket": stat.S_ISSOCK(info.st_mode),
            "symlink": stat.S_ISLNK(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode), "dev": info.st_dev, "ino": info.st_ino}


def crash_inventory(directory: Path) -> dict:
    """Names/metadata, not dump contents. Missing directory and unreadable differ."""
    directory = plain_path(directory, missing_leaf=True)
    if not directory.exists():
        return {"exists": False, "entries": {}}
    if not directory.is_dir():
        raise ValueError("crash path is not a directory")
    entries = {}
    for path in directory.iterdir():
        info = path.lstat()
        entries[path.name] = {"size": info.st_size, "mtime_ns": info.st_mtime_ns,
                              "mode": stat.S_IFMT(info.st_mode)}
    return {"exists": True, "entries": entries}


def compare_crashes(before: dict, after: dict) -> dict:
    new = sorted(set(after["entries"]) - set(before["entries"]))
    changed = sorted(name for name in set(before["entries"]) & set(after["entries"])
                     if before["entries"][name] != after["entries"][name])
    if new or changed:
        raise RuntimeError(f"new/changed Windows crash entries: {new + changed}")
    return {"new": new, "changed": changed}


def capture(capacity: dict, crash_directory: Path) -> dict:
    """Read-only outer preflight. No credentials, socket connections or mutations."""
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("outer preflight requires WSL root")
    kernel = platform.release()
    if "microsoft" not in kernel.lower() or platform.machine() != "x86_64":
        raise RuntimeError("this harness requires x86_64 WSL")
    import pwd
    accounts = [entry.pw_uid for entry in pwd.getpwall()]
    processes = host_process_uids()
    check_reserved_uids(capacity["first"], capacity["last"], accounts, processes)
    user = pwd.getpwuid(1000)
    if user.pw_gid != 1000:
        raise RuntimeError("host uid 1000 must have primary gid 1000")
    return {"captured_at": utc(), "kernel": kernel, "namespaces": namespaces(),
            "capacity": capacity, "reserved_uid_scan": {"accounts_clear": True, "tasks_clear": True},
            "host_user": {"uid": 1000, "gid": 1000, "groups": sorted(os.getgrouplist(user.pw_name, 1000))},
            "real_sockets": [socket_metadata(Path("/var/run/docker.sock")),
                             socket_metadata(Path("/run/user/1000/bus"))],
            "crash_directory": str(crash_directory), "crashes": crash_inventory(crash_directory),
            "kernel_match": False, "readings_match": False}
