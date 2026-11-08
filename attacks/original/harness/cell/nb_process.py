"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
import selectors
import signal
import subprocess
import time

from nb_contract import LIMIT


def execute(argv, *, cwd, env, data=b"", timeout=5, limit=LIMIT):
    """Bounded argv-only child I/O; never inherit environment secrets or fd 3.

    This is a cell-side convenience, NOT the host's 30-second/cgroup supervisor.
    Detached descendants are the host's responsibility (also in undefended mode).
    Any timeout, incomplete pipe drain or cleanup error invalidates the attempt.
    Tests mock Popen/selectors; importing this module launches nothing.
    """
    if not isinstance(argv, (list, tuple)) or not argv or len(argv) > 128:
        raise ValueError("explicit bounded argv required")
    if any(not isinstance(x, str) or "\0" in x for x in argv) or not argv[0].startswith("/"):
        raise ValueError("absolute executable and NUL-free argv required")
    if sum(len(x.encode()) for x in argv) > 65536 or type(data) is not bytes or len(data) > 65536:
        raise ValueError("argument/input limit")
    if not 0 < timeout <= 30 or type(limit) is not int or not 0 < limit <= LIMIT:
        raise ValueError("time/output budget cannot be enlarged")
    if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                      or "=" in k or "\0" in k + v for k, v in env.items()):
        raise ValueError("explicit string environment required")
    end = time.monotonic() + timeout
    result = {"stdout": b"", "stderr": b"", "returncode": None, "signal": None, "error": None}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    proc, selector, sent, total = None, None, 0, 0
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                close_fds=True, start_new_session=True)
        selector = selectors.DefaultSelector()
        for name in buffers:
            stream = getattr(proc, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if data:
            os.set_blocking(proc.stdin.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            proc.stdin.close()
        while selector.get_map():
            left = end - time.monotonic()
            if left <= 0:
                result["error"] = "timeout"
                break
            for key, _ in selector.select(min(.05, left)):
                if key.data == "stdin":
                    try:
                        sent += os.write(key.fileobj.fileno(), data[sent:sent + 8192])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        result["error"] = "input_not_consumed"
                        sent = len(data)
                    if sent == len(data):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                try:
                    chunk = os.read(key.fileobj.fileno(), min(65536, limit - total + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                room = limit - total
                buffers[key.data].extend(chunk[:room])
                total += min(len(chunk), room)
                if len(chunk) > room:
                    result["error"] = "output_limit"
                    break
            if result["error"]:
                break
        if result["error"] is None:
            try:
                proc.wait(timeout=max(.001, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                result["error"] = "timeout"
    except OSError as exc:
        result["error"] = "process_io_error"
        result["errno"] = exc.errno
    finally:
        if proc is not None:
            # No poll/wait reaps the leader before a failing I/O path gets here.
            # The unreaped child pins its PID/PGID, avoiding killpg-after-PID-reuse.
            # On normal exit do not signal a reaped PID. Host owns all descendants.
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    result["error"] = "child_cleanup_failed"
            try:
                proc.wait(timeout=max(.001, min(1, end - time.monotonic())))
            except subprocess.TimeoutExpired:
                result["error"] = "child_reap_timeout"
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            result["returncode"] = proc.returncode
            if proc.returncode is not None and proc.returncode < 0:
                result["signal"] = -proc.returncode
        if selector is not None:
            selector.close()
        result.update({k: bytes(v) for k, v in buffers.items()})
    return result
