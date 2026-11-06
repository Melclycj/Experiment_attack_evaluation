"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil

from env import mount_rows
from safeio import plain_path


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
    """Kernel identity of the VISIBLE mount, including stacked /etc/hosts binds."""
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
    """Register immediately AFTER creation, before any later setup can fail.

    Never deletes roots if process recovery, mount recovery or loop verification
    failed. Caller must report remaining paths and stop; no lazy unmount fallback.
    """
    def __init__(self, top_mount_id=mounted_id):
        self.roots, self.mounts, self.images = {}, [], []
        self.top_mount_id = top_mount_id

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
        if target != Path("/etc/hosts") and not any(beneath(str(target), str(r)) for r in self.roots):
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
