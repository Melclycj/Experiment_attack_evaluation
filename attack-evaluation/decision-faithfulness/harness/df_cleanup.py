"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。"""
# Copied from attack_evaluation/harness at a70a1c69: mount_rows, check_namespaces, Deadline and RunCgroup from env.py,
# beneath, owned_root, mounted_id and Resources from cleanup.py. Changes: the deadline admits the 900 s DF-06 batch,
# the reserved uids include the workspace owner, and /etc/resolv.conf may be bind-mounted beside /etc/hosts.
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import time

from df_common import CONNECTOR_UID, LONG_RUN_SECONDS, MEMORY_MAX, OWNER_UID, PDP_UID, PIDS_MAX, WORKER_UID, token
from df_safeio import plain_path

ETC_TARGETS = (Path("/etc/hosts"), Path("/etc/resolv.conf"))
SERVICE_UIDS = (WORKER_UID, OWNER_UID, PDP_UID, CONNECTOR_UID)     # file worker since a9eff999 (H-14)


def mount_rows(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        split = parts.index("-")
        if split < 6 or len(parts) < split + 4:
            raise ValueError("malformed mountinfo")
        unescape = lambda s: re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), s)  # noqa: E731
        rows.append({"id": int(parts[0]), "parent": int(parts[1]),
                     "target": unescape(parts[4]), "optional": parts[6:split],
                     "fstype": parts[split + 1], "source": unescape(parts[split + 2])})
    return rows


def check_namespaces(before: dict, inside: dict, mountinfo: str) -> None:
    """before: the launcher's namespaces read BEFORE unshare; inside: the controller's own."""
    for kind in ("mnt", "net"):
        if not re.fullmatch(rf"{kind}:\[\d+\]", before.get(kind, "")) or not re.fullmatch(
                rf"{kind}:\[\d+\]", inside.get(kind, "")):
            raise ValueError("missing namespace identity")
        if before[kind] == inside[kind]:
            raise ValueError(f"{kind} namespace not isolated")
    rows = mount_rows(mountinfo)
    if len([r for r in rows if r["target"] == "/"]) != 1 or any(
            x.startswith(("shared:", "master:")) for r in rows for x in r["optional"]):
        raise ValueError("mount propagation is not private")


def check_reserved_uids(first: int, last: int, accounts: list[int], process_uids: list[int]) -> None:
    if first > last or last - first + 1 > 4096 or any(first <= uid <= last for uid in SERVICE_UIDS):
        raise ValueError("invalid reserved uid range")
    reserved = lambda uid: first <= uid <= last or uid in SERVICE_UIDS  # noqa: E731
    if any(reserved(uid) for uid in accounts):
        raise ValueError("reserved uid has a host account")
    if any(reserved(uid) for uid in process_uids):
        raise ValueError("reserved uid already has a host process")


class Deadline:
    def __init__(self, seconds: float, clock=time.monotonic):
        if not 0 < seconds <= LONG_RUN_SECONDS:
            raise ValueError("invalid deadline")
        self.clock, self.end = clock, clock() + seconds

    def left(self, cap: float | None = None) -> float:
        remaining = self.end - self.clock()
        if remaining <= 0:
            raise TimeoutError("run/attempt deadline exceeded")
        return remaining if cap is None else min(remaining, cap)


class RunCgroup:
    """Owned cgroup only; the controller stays outside. No fallback to an unconstrained run."""
    def __init__(self, parent: Path, label: str):
        self.path = parent / ("nb-decoy-" + token(label))
        self.created = False
        self.inode = None

    def create(self) -> None:
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

    def procs_path(self) -> Path:
        self._check()
        return self.path / "cgroup.procs"

    def kill_and_wait(self, timeout: float = 10) -> None:
        self._check()
        relative = "/" + self.path.relative_to("/sys/fs/cgroup").as_posix()
        memberships = [line.split(":", 2)[2] for line in Path("/proc/self/cgroup").read_text().splitlines()
                       if line.startswith("0::")]
        if len(memberships) != 1 or memberships[0] == relative or memberships[0].startswith(relative + "/"):
            raise RuntimeError("controller must be outside the entire run cgroup subtree")
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
        self.path.rmdir()
        self.created = False


def beneath(path: str, parent: str) -> bool:
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def owned_root(path: Path) -> Path:
    """Exact fresh temporary root, not merely any path sharing a string prefix."""
    path = plain_path(path)
    if path.parent not in (Path("/tmp"), Path("/var/lib")) or not path.name.startswith("nb-decoy-"):
        raise ValueError("cleanup root outside the allowed temporary parents")
    if not path.is_dir():
        raise ValueError("cleanup root is not a directory")
    return path


def mounted_id(path: Path) -> int:
    """Kernel identity of the VISIBLE mount, including stacked /etc binds."""
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = Path(f"/proc/self/fdinfo/{fd}").read_text()
        match = re.search(r"^mnt_id:\s*(\d+)$", info, re.MULTILINE)
        if match is None:
            raise RuntimeError("kernel did not report mount identity")
        return int(match[1])
    finally:
        os.close(fd)


class Resources:
    """Register immediately AFTER creation. Never deletes roots if process recovery, mount recovery or loop
    verification failed; the caller reports remaining paths and stops (TESTING rule 6). No lazy unmount."""
    def __init__(self, top_mount_id=mounted_id):
        self.roots, self.mounts, self.images = {}, [], []
        self.top_mount_id = top_mount_id
        self.etc_targets = set(ETC_TARGETS)

    def allow_etc_target(self, link: Path) -> Path:
        """/etc/resolv.conf may be a symlink (WSL generates it): the bind lands on its regular-file target."""
        target = Path(os.path.realpath(link))
        if link not in ETC_TARGETS or not target.is_file() or target.is_symlink():
            raise ValueError("resolver configuration target does not read")
        self.etc_targets.add(target)
        return target

    def add_root(self, path: Path) -> None:
        path = owned_root(path)
        info = path.stat()
        if path in self.roots:
            raise ValueError("duplicate resource registration")
        self.roots[path] = (info.st_dev, info.st_ino)

    def add_image(self, path: Path) -> None:
        path = plain_path(path)
        if not any(root in path.parents for root in self.roots) or not path.is_file():
            raise ValueError("image not within this run's roots")
        info = path.stat()
        self.images.append((path, info.st_dev, info.st_ino))

    def add_mount(self, target: Path, mountinfo: str) -> None:
        target = Path(os.path.abspath(target))
        if target not in self.etc_targets and not any(beneath(str(target), str(r)) for r in self.roots):
            raise ValueError("mount outside registered roots")
        visible_id = self.top_mount_id(target)
        found = [r for r in mount_rows(mountinfo) if r["target"] == str(target) and r["id"] == visible_id]
        if len(found) != 1:
            raise ValueError("ambiguous/missing owned mount")
        if any(t == target for t, _ in self.mounts):
            raise ValueError("duplicate mount registration")
        self.mounts.append((target, found[0]["id"]))

    def cleanup(self, *, stop_engine, cgroup, command, mountinfo, crash_check) -> dict:
        result = {"ok": False, "steps": [], "failures": [], "retained": []}

        def step(name, action):
            try:
                value = action()
                result["steps"].append({"step": name, "ok": True, "detail": value})
                return True
            except Exception as error:
                result["failures"].append({"step": name, "error": f"{type(error).__name__}: {error}"})
                return False

        step("stop-engine-and-wait-spawner", stop_engine)
        killed = step("kill-and-empty-cgroup", cgroup.kill_and_wait) if cgroup and cgroup.created else True
        if killed:
            for target, mid in reversed(self.mounts):
                def unmount(target=target, mid=mid):
                    current = [r for r in mount_rows(mountinfo()) if r["target"] == str(target) and r["id"] == mid]
                    if len(current) != 1 or self.top_mount_id(target) != mid:
                        raise RuntimeError("owned mount identity changed; refusing umount")
                    command(["/usr/bin/umount", str(target)], timeout=10)
                    if any(r["id"] == mid for r in mount_rows(mountinfo())):
                        raise RuntimeError("mount still present")
                step("unmount:" + str(target), unmount)
            for path, dev, ino in self.images:
                def verify_loop(path=path, dev=dev, ino=ino):
                    plain_path(path)
                    now = path.stat()
                    if (now.st_dev, now.st_ino) != (dev, ino):
                        raise RuntimeError("image identity changed")
                    output = command(["/usr/sbin/losetup", "--list", "--json", "--associated", str(path)], timeout=5)
                    if json.loads(output["stdout"] or "{}").get("loopdevices"):
                        raise RuntimeError("loop device remains attached")
                step("verify-loop:" + str(path), verify_loop)
        if not result["failures"]:
            for root, expected in reversed(list(self.roots.items())):
                def remove(root=root, expected=expected):
                    owned_root(root)
                    now = root.stat()
                    if (now.st_dev, now.st_ino) != expected:
                        raise RuntimeError("temporary root identity changed")
                    if any(beneath(r["target"], str(root)) for r in mount_rows(mountinfo())):
                        raise RuntimeError("unregistered mount remains under root")
                    if not shutil.rmtree.avoids_symlink_attacks:
                        raise RuntimeError("fd-based safe rmtree unavailable")
                    shutil.rmtree(root)
                    if root.exists():
                        raise RuntimeError("temporary root still exists")
                if not step("remove:" + str(root), remove):
                    break
        if cgroup and cgroup.created and killed:
            step("remove-cgroup", cgroup.remove)
        step("windows-crash-directory", crash_check)
        result["retained"] = [str(root) for root in self.roots if root.exists()]
        result["ok"] = not result["failures"] and not result["retained"]
        return result
