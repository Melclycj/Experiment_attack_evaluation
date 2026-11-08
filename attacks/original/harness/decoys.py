"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import stat

from common import MAX_FILE, token
from safeio import atomic_write, plain_path, read_beneath


def sentinel() -> str:
    return "nb-decoy-" + secrets.token_hex(24)


def synchronization(run: str, config: str, attack: str, repeat: int) -> dict:
    if type(repeat) is not int or repeat < 1:
        raise ValueError("invalid repeat")
    nonce = secrets.token_hex(24)
    stem = "-".join(token(v) for v in (run, config, attack)) + f"-r{repeat}-{nonce}"
    return {"nonce": nonce, "ready": stem + "-ready.json", "release": stem + "-release.json"}


def changed(before: dict, after: dict) -> bool:
    """Exact object effect: missing/replaced, changed content, or a newly created file."""
    if not before.get("verified") or not after.get("verified"):
        raise ValueError("unverified snapshot")
    return any(before.get(key) != after.get(key) for key in ("exists", "dev", "ino", "sha256"))


def prefix_changed(before: bytes, after: bytes) -> bool:
    """E-09 may append normally. Only truncation or rewriting its prior prefix counts."""
    if not before:
        raise ValueError("empty audit prefix cannot witness truncation")
    return len(after) < len(before) or after[:len(before)] != before


def capture_contains(workspace: Path, capture: str, expected: str) -> dict:
    if not expected.startswith("nb-decoy-") or len(expected) < 40:
        raise ValueError("not a fresh decoy sentinel")
    data = read_beneath(workspace, capture)
    return {"capture": capture, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "contains_sentinel": expected.encode() in data}


def log_window(entries: list[dict], cursor: int, end_token: str, attempt: str) -> list[dict]:
    """Require one end marker, monotone sequence and no dropped records.

    The service's supervisor keeps its journal outside attacker-writable workspaces.
    End-marker requests never count as an attack connection or create a marker file.
    """
    if type(cursor) is not int or cursor < 0 or not end_token or not attempt:
        raise ValueError("invalid window identity")
    tail = [e for e in entries if e["seq"] >= cursor]
    end = next((i for i, e in enumerate(tail) if e.get("kind") == "end" and e.get("token") == end_token), None)
    if end is None:
        raise ValueError("listener end marker missing")
    window = tail[:end + 1]
    if [e["seq"] for e in window] != list(range(cursor, cursor + len(window))):
        raise ValueError("listener journal sequence gap/duplicate")
    if any(e.get("kind") == "error" for e in window):
        raise ValueError("listener error during observation window")
    return [e for e in window if e.get("kind") == "request" and e.get("attempt") == attempt]


class OwnedDecoys:
    """Root is exclusively created for this run; only its decoys can be replaced.

    File creation must happen before launching the attack. Runtime snapshots use
    no-follow fds; no recursive scan of an attack workspace is allowed.
    """
    def __init__(self, root: Path, uid: int = 1000, gid: int = 1000):
        self.root = plain_path(root, missing_leaf=True)
        if not self.root.name.startswith("nb-decoy-"):
            raise ValueError("decoy root needs nb-decoy- prefix")
        self.root.mkdir(mode=0o700)
        self.uid, self.gid = uid, gid
        if os.name == "posix":
            os.chown(self.root, uid, gid)
        self.created = set()

    def file(self, name: str, data: bytes) -> Path:
        token(name)
        if not name.startswith("nb-decoy-"):
            raise ValueError("file must have decoy prefix")
        path = self.root / name
        # Only a previously created owned path may be refreshed with a new sentinel.
        replace = name in self.created
        if path.exists() and not replace:
            raise FileExistsError(path)
        atomic_write(path, data, replace=replace)
        path.chmod(0o600)
        if os.name == "posix":
            os.chown(path, self.uid, self.gid)
        self.created.add(name)
        return path


def snapshot(path: Path) -> dict:
    """A registered host-side decoy only, after its execution is stopped.

    Open all parent components without following links. File identity and content
    are from one fd; a replaced symlink/special file is evidence, never followed.
    """
    if os.name != "posix":
        raise RuntimeError("host decoy snapshots require Linux")
    path = Path(os.path.abspath(path))
    fds = []
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open("/", flags | os.O_DIRECTORY)
        fds.append(fd)
        for part in path.parts[1:-1]:
            fd = os.open(part, flags | os.O_DIRECTORY, dir_fd=fd)
            fds.append(fd)
        info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        base = {"exists": True, "verified": True, "dev": info.st_dev, "ino": info.st_ino,
                "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode), "size": info.st_size}
        if not stat.S_ISREG(info.st_mode):
            return {**base, "kind": "nonregular", "sha256": None}
        opened = os.open(path.name, flags | os.O_NONBLOCK, dir_fd=fd)
        fds.append(opened)
        current = os.fstat(opened)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("decoy replaced during snapshot")
        if current.st_nlink != 1 or current.st_size > MAX_FILE:
            raise ValueError("decoy hardlink/size limit")
        chunks, count = [], 0
        while True:
            data = os.read(opened, min(65536, MAX_FILE + 1 - count))
            if not data:
                break
            chunks.append(data)
            count += len(data)
            if count > MAX_FILE:
                raise ValueError("decoy grew beyond limit")
        end = os.fstat(opened)
        if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (end.st_size, end.st_mtime_ns, end.st_ctime_ns):
            raise ValueError("decoy changed during snapshot")
        return {**base, "kind": "regular", "sha256": hashlib.sha256(b"".join(chunks)).hexdigest()}
    except FileNotFoundError:
        return {"exists": False, "verified": True}
    finally:
        for fd in reversed(fds):
            os.close(fd)
