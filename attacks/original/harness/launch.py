"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import identity, json_bytes
from env import check_namespaces, process_stat
from host import NAMESPACE_KINDS, capture, namespaces
from safeio import plain_path, read_owned

MAX_BOOT = 65536


def sealed_boot(data: dict) -> int:
    """An inherited sealed memfd, never a caller-writable JSON path or env value."""
    import fcntl
    encoded = json_bytes(data)
    if len(encoded) > MAX_BOOT:
        raise ValueError("oversized outer context")
    fd = os.memfd_create("nb-decoy-host", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        if os.write(fd, encoded) != len(encoded):
            raise RuntimeError("short boot context write")
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_boot(fd: int) -> dict:
    import fcntl
    required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required != required:
        raise RuntimeError("outer context is not immutable")
    data = os.pread(fd, MAX_BOOT + 1, 0)
    if len(data) > MAX_BOOT:
        raise ValueError("oversized outer context")
    return json.loads(data)


def unshare_argv(boot_fd: int, ready_fd: int) -> list[str]:
    return ["/usr/bin/unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=KILL",
            "--mount-proc", "--propagation", "private", "/usr/bin/python3", "-I", "-B",
            str(Path(__file__).resolve()), "--inside", str(boot_fd), str(ready_fd)]


def verify_inside(boot: dict) -> dict:
    if os.geteuid() != 0 or os.getpid() != 1:
        raise RuntimeError("controller must be root PID 1 in the fresh PID namespace")
    before = boot["host"]["namespaces"]
    for kind in NAMESPACE_KINDS:
        actual = os.readlink(f"/proc/self/fd/{boot['namespace_fds'][kind]}")
        if actual != before[kind]:
            raise RuntimeError("inherited host namespace reference does not match snapshot")
    inside = namespaces()
    check_namespaces(before, inside, Path("/proc/self/mountinfo").read_text())
    if identity(read_owned(Path(boot["entry"]))) != boot["entry_identity"]:
        raise RuntimeError("controller changed between outer and inner launch")
    return inside


def inside_main(boot_fd: int, ready_fd: int) -> int:
    boot = read_boot(boot_fd)
    inside = verify_inside(boot)
    def interrupted(signum, _frame):
        raise InterruptedError(f"controller interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    # This proc fd refers to the OLD proc superblock and therefore the HOST PID
    # namespace, even after unshare --mount-proc replaced /proc in this process.
    host_pid = int(os.readlink("self", dir_fd=boot["host_proc_fd"]))
    report = json_bytes({"pid": host_pid, "namespaces": inside})
    if os.write(ready_fd, report) != len(report):
        raise RuntimeError("short namespace handshake")
    await_release(boot["go_fd"])
    for fd in [ready_fd, boot_fd, boot["go_fd"], boot["host_proc_fd"], *boot["namespace_fds"].values()]:
        os.close(fd)
    spec = importlib.util.spec_from_file_location("nb_run_controller", boot["entry"])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Future run.py owns its try/finally cleanup, including errors and these signals.
    return int(module.inside_main(boot["host"], boot["arguments"], boot["deadline"]))


def await_release(fd: int) -> None:
    # No import/deployment until the OUTER process verifies the actual child.
    if not select.select([fd], [], [], 10)[0] or os.read(fd, 2) != b"G":
        raise RuntimeError("outer supervisor did not release verified controller")


def verify_child(report: dict, unshare_pid: int, before: dict) -> int:
    """Bind the reported identity to the actual child, never to a claimed string."""
    pid = report["pid"]
    if type(pid) is not int or pid <= 1:
        raise ValueError("bad child PID")
    fd = os.pidfd_open(pid)
    try:
        proc = Path(f"/proc/{pid}")
        status = (proc / "status").read_text()
        import re
        if not re.search(rf"^PPid:\s+{unshare_pid}$", status, re.MULTILINE):
            raise RuntimeError("namespace worker is not our unshare child")
        info = process_stat((proc / "stat").read_text())
        if info["pid"] != pid:
            raise RuntimeError("child identity mismatch")
        for kind in NAMESPACE_KINDS:
            actual = os.readlink(proc / "ns" / kind)
            if actual == before[kind] or actual != report["namespaces"][kind]:
                raise RuntimeError("worker namespace mismatch")
        return fd
    except BaseException:
        os.close(fd)
        raise


def run_controller(entry: Path, arguments: list[str], capacity: dict, crash_directory: Path, *, absolute_deadline=None) -> dict:
    """Only call AFTER the user's batch-start approval. Not an attack CLI.

    The controller must provide inside_main(host, arguments, absolute_deadline).
    540 s is the work cutoff; its finally block reserves the last 60 s for cleanup.
    A stuck controller is killed at 600 s and reported as unverified cleanup.
    """
    now = time.monotonic()
    deadline = now + 600 if absolute_deadline is None else absolute_deadline
    if not 0 < deadline - now <= 600:
        raise TimeoutError("invalid/exhausted outer deadline")
    host = capture(capacity, crash_directory)
    entry = plain_path(entry)
    if entry.name != "run.py" or entry.parent != Path(__file__).resolve().parent:
        raise ValueError("only the adjacent run.py controller may be launched")
    # Invocation must use a frozen root-owned native Linux snapshot, not writable
    # source on DrvFS. The final entrypoint will arrange that snapshot, not this API.
    for path in [entry.parent, *entry.parent.glob("*.py")]:
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("controller snapshot must be root-owned and not group/world writable")
    if time.monotonic() >= deadline:
        raise TimeoutError("outer preflight exhausted the run deadline")
    fds, ns_fds = [], {}
    child_fd = None
    proc = None
    old_handlers = {}
    interrupted_at = None
    forced = False

    def forward(signum, _frame):
        nonlocal interrupted_at
        if interrupted_at is None:
            interrupted_at = time.monotonic()
            if child_fd is not None:
                try:
                    signal.pidfd_send_signal(child_fd, signum)
                except ProcessLookupError:
                    pass

    try:
        # Catch TERM/INT even during unshare startup; before the release handshake
        # the child has not been permitted to import a controller or mutate state.
        for signum in (signal.SIGTERM, signal.SIGINT):
            old_handlers[signum] = signal.signal(signum, forward)
        for kind in NAMESPACE_KINDS:
            ns_fds[kind] = os.open(f"/proc/self/ns/{kind}", os.O_RDONLY | os.O_CLOEXEC)
            fds.append(ns_fds[kind])
        proc_fd = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        fds.append(proc_fd)
        go_r, go_w = os.pipe2(os.O_CLOEXEC)
        fds.extend([go_r, go_w])
        boot_fd = sealed_boot({"go_fd": go_r, "host": host, "namespace_fds": ns_fds, "host_proc_fd": proc_fd,
                               "entry": str(entry), "entry_identity": identity(read_owned(entry)),
                               "arguments": arguments, "deadline": deadline})
        fds.append(boot_fd)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        fds.extend([ready_r, ready_w])
        proc = subprocess.Popen(unshare_argv(boot_fd, ready_w), close_fds=True,
                                pass_fds=tuple([*ns_fds.values(), proc_fd, boot_fd, ready_w, go_r]),
                                stdin=subprocess.DEVNULL, start_new_session=True,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"})
        os.close(ready_w)
        fds.remove(ready_w)
        if not select.select([ready_r], [], [], 5)[0]:
            raise TimeoutError("namespace controller did not acknowledge startup")
        report = json.loads(os.read(ready_r, 4096))
        child_fd = verify_child(report, proc.pid, host["namespaces"])

        if interrupted_at is not None:
            raise InterruptedError("interrupted before controller release")
        if os.write(go_w, b"G") != 1:
            raise RuntimeError("short controller release")
        os.close(go_w)
        fds.remove(go_w)
        while proc.poll() is None:
            now = time.monotonic()
            if now >= deadline or (interrupted_at is not None and now >= interrupted_at + 60):
                forced = True
                try:
                    signal.pidfd_send_signal(child_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)
                break
            time.sleep(.02)
        return {"exit_code": proc.returncode, "forced": forced, "host": host,
                "cleanup_verified": False if forced else None}
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        if proc is not None and proc.poll() is None:
            # Bootstrap failure; unshare --kill-child reaps the private PID tree.
            # Do NOT claim its files/loop devices were cleaned by this forced stop.
            proc.kill()
            proc.wait(timeout=5)
        if child_fd is not None:
            os.close(child_fd)
        for fd in reversed(fds):
            os.close(fd)


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "--inside":
        raise SystemExit("Internal launcher only; batch entrypoint is not yet connected")
    raise SystemExit(inside_main(int(sys.argv[2]), int(sys.argv[3])))
