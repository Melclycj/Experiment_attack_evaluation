"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import os
from pathlib import Path
import select
import signal

from env import process_stat
from host import status_uids


def process_info(pid: int) -> dict:
    root = Path(f"/proc/{pid}")
    first = process_stat((root / "stat").read_text())
    ids = status_uids((root / "status").read_text())
    group = (root / "cgroup").read_text()
    argv = (root / "cmdline").read_bytes().split(b"\0")[:-1]
    after = process_stat((root / "stat").read_text())
    if first["start_time"] != after["start_time"]:
        raise RuntimeError("process replaced during identity read")
    return {**after, "uids": ids, "cgroup": group, "argv": [v.decode() for v in argv]}


class ProcessRef:
    """NB-23 identity, with pidfd for liveness/signals. No arbitrary host PID targets."""
    def __init__(self, pid: int, uid: int, cgroup):
        self.fd = None
        relative = "/" + cgroup.path.relative_to("/sys/fs/cgroup").as_posix()
        before = process_info(pid)
        if before["uids"] != [uid] * 4 or before["state"] in ("T", "t", "Z") or (
                "0::" + relative) not in before["cgroup"].splitlines():
            raise RuntimeError("process is not a live, expected-uid member of this run")
        self.fd = os.pidfd_open(pid)
        self.initial = before
        try:
            self.read()
        except BaseException:
            self.close()
            raise

    def exited(self):
        # poll, not select: a long batch holds over 1024 descriptors (select's ceiling).
        poller = select.poll()
        poller.register(self.fd, select.POLLIN)
        return bool(poller.poll(0))

    def read(self):
        if self.fd is None or self.exited():
            raise RuntimeError("pinned process exited")
        now = process_info(self.initial["pid"])
        if any(now[k] != self.initial[k] for k in ("pid", "start_time", "uids", "cgroup")) or self.exited():
            raise RuntimeError("process identity changed")
        return now

    def send(self, signum):
        self.read()
        signal.pidfd_send_signal(self.fd, signum)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def direct_children(pid: int) -> list[int]:
    return [int(v) for v in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]
