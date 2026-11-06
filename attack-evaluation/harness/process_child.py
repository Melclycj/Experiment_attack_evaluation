"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import os
import sys


def enter_and_exec(group_fd: int, ready_fd: int, argv: list[str]) -> None:
    """Trusted trampoline only. No target instruction runs before joining cgroup.

    Both fds are opened by the supervisor, not reconstructed from a writable path.
    The acknowledgement is not target output and is never forwarded to the target.
    The interpreter's small bootstrap is outside the cgroup; compilation, services,
    engine and all their descendants enter before exec. No preexec_fn in a threaded
    Python parent and no post-Popen PID-move race.
    """
    if not argv or not argv[0].startswith("/"):
        raise ValueError("absolute executable required")
    payload = str(os.getpid()).encode("ascii")
    if os.write(group_fd, payload) != len(payload):
        raise RuntimeError("short cgroup membership write")
    os.close(group_fd)
    if os.write(ready_fd, b"J") != 1:
        raise RuntimeError("short cgroup acknowledgement")
    os.close(ready_fd)
    os.execve(argv[0], argv, os.environ)


def main(argv: list[str]) -> int:
    if len(argv) < 4 or argv[2] != "--":
        raise ValueError("internal use: GROUP_FD READY_FD -- EXECUTABLE ...")
    try:
        enter_and_exec(int(argv[0]), int(argv[1]), argv[3:])
    except Exception as error:
        # Not a successful target invocation. Bounded diagnostic, no environment.
        print(f"cgroup trampoline failed: {type(error).__name__}: {error}"[:1000], file=sys.stderr)
        return 126
    return 126  # execve cannot return on success


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
