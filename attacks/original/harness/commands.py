"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from common import MAX_FILE, utc
from env import Deadline
from safeio import plain_path

BASE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8", "HOME": "/nonexistent"}


def command_argv(argv) -> list[str]:
    if isinstance(argv, (str, bytes)):
        raise ValueError("shell command strings are forbidden")
    result = [os.fspath(v) for v in argv]
    if not result or not result[0].startswith("/") or any("\0" in v for v in result):
        raise ValueError("absolute executable and NUL-free argv required")
    if sum(len(v.encode()) for v in result) > 65536:
        raise ValueError("oversized command")
    return result


class CaptureBudget:
    """Shared across foreground commands AND background services, never unbounded."""
    def __init__(self, limit: int = MAX_FILE):
        if not 0 < limit <= MAX_FILE:
            raise ValueError("command capture limit may only be lowered")
        self.limit, self.used = limit, 0

    def consume(self, data: bytes) -> None:
        if self.used + len(data) > self.limit:
            raise ValueError("aggregate command output limit exceeded")
        self.used += len(data)


class ManagedProcess:
    def __init__(self, proc, pidfd: int, item: dict, end: float):
        self.proc, self.pidfd, self.item, self.end = proc, pidfd, item, end
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.streams = 2
        self.joined = False
        self.input_pending = bytearray()
        self.input_total = 0
        self.input_open = False

    def refresh(self) -> dict:
        self.item.update(exit_code=self.proc.poll(), joined=self.joined)
        for name, data in self.buffers.items():
            self.item[name] = bytes(data).decode("utf-8", "replace")
        return self.item


class Commands:
    """Single-threaded host supervisor; pump ALL pipes while waiting for any child.

    A deadline/output error aborts the whole run cgroup, not just the leader. The
    caller must then run cleanup (with its reserved cleanup deadline) and cannot
    continue the batch. Stdout/stdin are not files in attack-writable workspaces.
    """
    def __init__(self, cgroup, deadline: Deadline, *, budget=None, records=None):
        self.cgroup, self.deadline = cgroup, deadline
        self.budget = budget if budget is not None else CaptureBudget()
        self.records = records if records is not None else []
        self.selector = selectors.DefaultSelector()
        self.children = []
        self.failed = False

    def _membership_fd(self, group=None) -> int:
        group = self.cgroup if group is None else group
        if group is not self.cgroup and self.cgroup.path not in group.path.parents:
            raise ValueError("child group must be inside this run cgroup")
        group._check()
        plain_path(group.path)
        directory = os.open(group.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if os.fstat(directory).st_ino != group.inode:
                raise RuntimeError("cgroup replaced before child join")
            return os.open("cgroup.procs", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        finally:
            os.close(directory)

    def start(self, argv, *, timeout: float = 120, env=None, cwd=None, interactive=False, group=None) -> ManagedProcess:
        if os.name != "posix" or not hasattr(os, "pidfd_open"):
            raise RuntimeError("Linux pidfd supervisor required")
        if self.failed or not 0 < timeout <= 600:
            raise RuntimeError("failed supervisor or invalid timeout")
        argv = command_argv(argv)
        environment = dict(BASE_ENV)
        if env:
            # Explicit caller-supplied values only. Never inherit the shell's secrets.
            environment.update(env)
        if any(not isinstance(k, str) or not isinstance(v, str) or "=" in k or "\0" in k + v
               for k, v in environment.items()):
            raise ValueError("invalid command environment")
        if cwd is not None:
            cwd = plain_path(Path(cwd))
        seconds = self.deadline.left(timeout)
        group_fd = self._membership_fd() if group is None else self._membership_fd(group)
        ready_r = ready_w = None
        proc = None
        child = None
        try:
            ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
            helper = plain_path(Path(__file__).with_name("process_child.py"))
            proc = subprocess.Popen(["/usr/bin/python3", "-I", "-B", str(helper), str(group_fd),
                                     str(ready_w), "--", *argv], stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                    pass_fds=(group_fd, ready_w), env=environment, cwd=cwd,
                                    start_new_session=True)
            pidfd = os.pidfd_open(proc.pid)
            item = {"argv": argv, "started_at": utc(), "exit_code": None, "joined": False}
            child = ManagedProcess(proc, pidfd, item, time.monotonic() + seconds)
            self.children.append(child)
            self.records.append(item)
            if interactive:
                os.set_blocking(proc.stdin.fileno(), False)
                child.input_open = True
            for name in ("stdout", "stderr"):
                stream = getattr(proc, name)
                os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, (child, name))
            os.close(ready_w)
            ready_w = None
            os.set_blocking(ready_r, False)
            handshake_end = min(child.end, time.monotonic() + 5)
            while True:
                self.pump(.02)
                try:
                    acknowledgement = os.read(ready_r, 2)
                except BlockingIOError:
                    acknowledgement = None
                if acknowledgement == b"J":
                    child.joined = True
                    child.refresh()
                    return child
                if acknowledgement == b"" or time.monotonic() >= handshake_end:
                    raise RuntimeError("child failed to acknowledge cgroup entry")
        except BaseException:
            if proc is not None and child is None:
                # Still our unreaped direct child, cannot be a reused PID.
                proc.kill()
                proc.wait(timeout=5)
                for stream in (proc.stdout, proc.stderr, proc.stdin if interactive else None):
                    if stream is not None:
                        stream.close()
            self.abort()
            raise
        finally:
            for fd in (group_fd, ready_r, ready_w):
                if fd is not None:
                    os.close(fd)

    def pump(self, seconds: float = .02) -> None:
        try:
            for observer in getattr(self, "observers", ()):
                observer()
            left = self.deadline.left()
            now = time.monotonic()
            for child in self.children:
                if now >= child.end and (child.proc.poll() is None or child.streams):
                    raise TimeoutError("child/descendant output deadline exceeded")
            for key, _ in self.selector.select(min(max(seconds, 0), left)):
                child, name = key.data
                if name == "stdin":
                    try:
                        size = os.write(key.fileobj.fileno(), child.input_pending)
                    except BlockingIOError:
                        continue
                    if size <= 0:
                        raise BrokenPipeError("interactive input did not advance")
                    del child.input_pending[:size]
                    if not child.input_pending:
                        self.selector.unregister(key.fileobj)
                    continue
                chunk = os.read(key.fileobj.fileno(), 65536)
                if chunk:
                    self.budget.consume(chunk)
                    child.buffers[name].extend(chunk)
                else:
                    self.selector.unregister(key.fileobj)
                    key.fileobj.close()
                    child.streams -= 1
            for child in self.children:
                if child.proc.poll() is not None and not child.streams:
                    child.refresh()
                    child.item.setdefault("finished_at", utc())
        except BaseException:
            self.abort()
            raise

    def wait(self, child: ManagedProcess, *, allowed=(0,)) -> dict:
        if child not in self.children:
            raise ValueError("not an owned child")
        while child.proc.poll() is None or child.streams:
            self.pump()
        result = child.refresh()
        if result["exit_code"] not in allowed:
            raise RuntimeError(f"command exited {result['exit_code']}: {result['argv'][0]}")
        return result

    def __call__(self, argv, *, timeout: float = 120, allowed=(0,), env=None, cwd=None) -> dict:
        return self.wait(self.start(argv, timeout=timeout, env=env, cwd=cwd), allowed=allowed)

    def send_input(self, child: ManagedProcess, data: bytes, *, timeout=5) -> None:
        """Bounded nonblocking pipe input; never log typed bytes (may be secrets)."""
        if child not in self.children or not child.input_open or self.failed:
            raise ValueError("not an owned open input")
        if not isinstance(data, bytes) or len(data) > 65536 or child.input_total + len(data) > 1048576:
            raise ValueError("interactive input bound exceeded")
        if child.proc.poll() is not None:
            raise BrokenPipeError("interactive child exited")
        if not data:
            return
        end = time.monotonic() + self.deadline.left(timeout)
        child.input_total += len(data)
        child.input_pending.extend(data)
        self.selector.register(child.proc.stdin, selectors.EVENT_WRITE, (child, "stdin"))
        try:
            while child.input_pending:
                if time.monotonic() >= end:
                    raise TimeoutError("interactive input timed out")
                if child.proc.poll() is not None:
                    raise BrokenPipeError("interactive child exited during input")
                self.pump(.01)
        except BaseException:
            self.abort()
            raise

    def close_input(self, child: ManagedProcess) -> None:
        if child not in self.children:
            raise ValueError("not an owned child")
        if child.input_open:
            try:
                self.selector.unregister(child.proc.stdin)
            except KeyError:
                pass
            child.proc.stdin.close()
            child.input_pending.clear()
            child.input_open = False

    def send_signal(self, child: ManagedProcess, signum: int) -> None:
        if child not in self.children:
            raise ValueError("not an owned child")
        if child.proc.poll() is None:
            signal.pidfd_send_signal(child.pidfd, signum)

    def abort(self) -> None:
        self.failed = True
        errors = []
        for child in self.children:
            try:
                self.close_input(child)
            except Exception as error:
                errors.append(str(error))
        # One failed signal must not skip killing the cgroup or reaping siblings.
        for child in self.children:
            try:
                self.send_signal(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as error:
                errors.append(str(error))
        try:
            if self.cgroup.created:
                self.cgroup.kill_and_wait(timeout=5)
        except Exception as error:
            errors.append(str(error))
        for child in self.children:
            try:
                child.proc.wait(timeout=5)
                child.refresh()
                child.item.setdefault("finished_at", utc())
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError("process recovery incomplete: " + "; ".join(errors))

    def close(self) -> None:
        try:
            if any(c.proc.poll() is None or c.streams for c in self.children):
                self.abort()
        finally:
            for child in self.children:
                self.close_input(child)
            for key in list(self.selector.get_map().values()):
                key.fileobj.close()
            self.selector.close()
            for child in self.children:
                if child.pidfd is not None:
                    os.close(child.pidfd)
                    child.pidfd = None
