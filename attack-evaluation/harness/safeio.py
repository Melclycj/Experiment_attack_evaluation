"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile

from common import MAX_FILE


def plain_path(path: Path, *, missing_leaf: bool = False) -> Path:
    """Reject symlinks/reparse points in every component, including existing parents.

    This checks a controller-owned tree. For a writable attack tree use read_beneath:
    a string-based parent check alone is not a race-safe read.
    """
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            if part == path and missing_leaf:
                continue
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"link/reparse point forbidden: {part}")
    return path


def relative_parts(rel: str) -> tuple[str, ...]:
    if not isinstance(rel, str) or "\\" in rel or ":" in rel or "\0" in rel:
        raise ValueError("expected a relative POSIX path")
    parts = tuple(rel.split("/"))
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError("empty, absolute or traversal path")
    return parts


def read_beneath(root: Path, rel: str, limit: int = MAX_FILE) -> bytes:
    """Linux openat walk: no symlinks, no FIFO/device reads, bounded, stable file.

    Intended for captures in work0 after its execution has stopped. Every parent is
    opened by fd; all opened fds are closed even when a child path fails.
    """
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("race-safe evidence reads require Linux")
    if limit < 0:
        raise ValueError("negative read limit")
    parts = relative_parts(rel)
    fds = []
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        # Walk root too, rather than trusting a mutable ancestor of it.
        absolute = Path(os.path.abspath(root))
        fd = os.open("/", flags | os.O_DIRECTORY)
        fds.append(fd)
        for name in (*absolute.parts[1:], *parts[:-1]):
            fd = os.open(name, flags | os.O_DIRECTORY, dir_fd=fd)
            fds.append(fd)
        fd = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=fd)
        fds.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("evidence must be a single-link regular file")
        if before.st_size > limit:
            raise ValueError("evidence file exceeds read limit")
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > limit:
                raise ValueError("evidence grew beyond read limit")
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, f) != getattr(after, f) for f in fields):
            raise ValueError("evidence changed during read")
        return b"".join(chunks)
    finally:
        for fd in reversed(fds):
            os.close(fd)


def read_owned(path: Path, limit: int = MAX_FILE) -> bytes:
    """Read a non-adversarial, controller-owned file (also usable in Windows tests)."""
    path = plain_path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("expected a bounded, single-link regular file")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("read limit exceeded")
    return data


def atomic_write(path: Path, data: bytes, *, replace: bool = False) -> None:
    """Only controller-owned directories. Existing files need explicit replacement."""
    path = plain_path(path, missing_leaf=True)
    if path.exists() and not replace:
        raise FileExistsError(path)
    fd, tmp = tempfile.mkstemp(prefix=".nb-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(tmp, path)
        elif os.name == "nt":
            # Windows rename is atomic and refuses an existing destination. Unlike
            # hardlink creation it also works in the desktop restricted token.
            os.rename(tmp, path)
        else:
            # link is atomic and fails if a peer has claimed the destination.
            os.link(tmp, path)
            os.unlink(tmp)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def file_snapshot(root: Path, rel: str, limit: int = MAX_FILE) -> dict:
    """Capture bytes and identity from the same open fd via /proc is unnecessary:
    consumers needing identity must use decoys.snapshot(), not stat this separately.
    This helper records bounded capture content only.
    """
    data = read_beneath(root, rel, limit)
    return {"path": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
