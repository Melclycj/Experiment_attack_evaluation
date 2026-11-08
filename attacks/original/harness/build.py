"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import os
from pathlib import Path
import stat

from common import digest, identity
from safeio import atomic_write, plain_path, read_owned

EXCLUDE = ("runs", "__pycache__", ".pytest_cache")
SOURCE_LIMIT = 8 * 1024 * 1024
AS_BUILDER = ["/usr/bin/setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
              "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]


def source_paths(root: Path, exclude: tuple[str, ...] = EXCLUDE) -> list[Path]:
    """Entire source tree, not just git-tracked files; refuse links and special files.

    Excludes only explicit generated directories, never a source suffix or hidden
    file implicitly. Root-owned copied source is the exact input to the build.
    """
    root = plain_path(root)
    found = []
    for here, dirs, files in os.walk(root, followlinks=False):
        parent = Path(here)
        for name in dirs[:]:
            path = parent / name
            rel = path.relative_to(root).as_posix()
            if any(rel == e or rel.startswith(e + "/") for e in exclude) or name == "__pycache__":
                dirs.remove(name)
                continue
            plain_path(path)
        for name in files:
            path = plain_path(parent / name)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError(f"not a single-link source file: {path}")
            found.append(path)
    return sorted(found)


def inventory(root: Path, exclude: tuple[str, ...] = EXCLUDE) -> dict:
    root = plain_path(root)
    files = {p.relative_to(root).as_posix(): identity(read_owned(p, SOURCE_LIMIT))
             for p in source_paths(root, exclude)}
    if not files:
        raise ValueError("empty source tree")
    return {"files": files, "digest": digest(files), "excluded": list(exclude)}


def snapshot(source: Path, destination: Path, exclude: tuple[str, ...] = EXCLUDE) -> dict:
    """Exclusive copy; any concurrent source edit invalidates the snapshot."""
    source = plain_path(source)
    destination = plain_path(destination, missing_leaf=True)
    if destination == source or source in destination.parents:
        raise ValueError("snapshot destination must be outside source")
    before = inventory(source, exclude)
    destination.mkdir(mode=0o755)
    for rel, expected in before["files"].items():
        original, target = source / rel, destination / rel
        data = read_owned(original, SOURCE_LIMIT)
        if identity(data) != expected:
            raise ValueError(f"source changed while copying: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        atomic_write(target, data)
        target.chmod(0o555 if original.stat().st_mode & 0o111 else 0o444)
    after = inventory(source, exclude)
    copied = inventory(destination, exclude)
    if before != after or before != copied:
        raise ValueError("source set/content changed during snapshot")
    return copied


def capacity(executions: int, first_uid: int = 70000, spare_uids: int = 1) -> dict:
    if type(executions) is not int or executions < 1 or spare_uids < 1:
        raise ValueError("positive execution count plus an unused control uid required")
    count = executions + spare_uids
    if count > 65536 or first_uid < 65536:
        raise ValueError("invalid reserved uid range")
    last = first_uid + count - 1
    # v4: the file worker (70996) and the workspace owner (70997) join the PDP and connector outside the range.
    if any(first_uid <= uid <= last for uid in (70996, 70997, 70998, 70999)) or last >= 2**32 - 1:
        raise ValueError("reserved uid range overlaps a dedicated service uid or exceeds uid_t")
    return {"first": first_uid, "last": last, "ca_count": count,
            "executions": executions, "spare_uid": last, "simultaneous_copies": 3}


def storage_reservation(manifest: dict, simultaneous: int = 3) -> dict:
    if simultaneous < 3 or not manifest.get("files"):
        raise ValueError("three simultaneous rows and a nonempty seed are required")
    entries = manifest["files"]
    nodes = len(entries) + 1
    charge = nodes * 4096
    for entry in entries:
        size = entry["size"]
        if type(size) is not int or size < 0:
            raise ValueError("invalid component size")
        if entry["type"] == "file":
            charge += ((size + 4095) // 4096) * 4096
    return {"max_reserved_bytes": str(simultaneous * charge),
            "max_reserved_nodes": str(simultaneous * nodes), "max_copies": simultaneous,
            "min_free_bytes": str(64 * 1024 * 1024), "charge_per_copy": charge}


def compile_engine(source: Path, build_dir: Path, command) -> dict:
    """Called only inside the authorized run. command MUST enter the run cgroup.

    Builds production binaries and the frontend stub, not the engine check suite.
    No engine or probe is executed here.
    """
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("compile through the WSL root supervisor")
    source = plain_path(source)
    before = inventory(source)
    build_dir = plain_path(build_dir, missing_leaf=True)
    build_dir.mkdir(mode=0o755)
    os.chown(build_dir, 1000, 1000)
    products = ("w2-cell", "libw2sandbox.so", "w2-relay", "w2-frontend-stub", "w2-catalog")
    command([*AS_BUILDER, "/usr/bin/make", "-s", "-C", str(source / "native"),
             "BUILD_DIR=" + str(build_dir), *(str(build_dir / p) for p in products)], timeout=300)
    if inventory(source) != before:
        raise RuntimeError("build modified its input snapshot")
    return {name: identity(read_owned(build_dir / name, 64 * 1024 * 1024)) for name in products}
