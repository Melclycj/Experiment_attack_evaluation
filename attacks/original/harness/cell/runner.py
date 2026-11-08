"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os


def inherited_fds():
    """Snapshot before opening request, payload or workspace fds. Python's own
    interpreter startup precedes this point; /proc enumeration's fd is closed
    before fstat, and is not recorded as an inherited descriptor. Do not close any.
    """
    result = []
    for name in sorted(os.listdir("/proc/self/fd"), key=int):
        fd = int(name)
        try:
            info = os.fstat(fd)
        except OSError as exc:
            if exc.errno == 9:  # enumeration's already closed fd
                continue
            raise
        result.append({"fd": fd, "type": info.st_mode & 0o170000,
                       "dev": info.st_dev, "ino": info.st_ino,
                       "target": os.readlink("/proc/self/fd/" + name)})
    return result


# Importing for offline unit tests has no /proc or process side effects.
BOOT_FDS = inherited_fds() if __name__ == "__main__" else None

import hashlib
import posixpath
from pathlib import Path
import signal
import sys
import time

# -I deliberately omits script/cwd from sys.path. Only this immutable payload
# directory is admitted, never /work or a request-supplied directory.
PAYLOAD = Path(__file__).absolute().parent
sys.path.insert(0, str(PAYLOAD))
from nb_contract import (ERROR, LIMIT, REQUEST, REQUEST_LIMIT, RESERVE, decode,
                         encoded, identifier, leaf, manifest, module_code, stem, validate_request)
from nb_io import Files, PublicationPending
from nb_process import execute


class Interrupted(Exception):
    pass


def interrupted(signum, _frame):
    raise Interrupted(f"runner signal {signum}")


class Context:
    """Module API: request-only targets, bounded observations, separate captures.

    Modules are reviewed Python code, not restricted Python sandboxes. These
    checks prevent harness mistakes; observations never authorize a conclusion.
    """
    def __init__(self, request, files, *, payload=PAYLOAD, cwd=None, inherited=(),
                 clock=time.monotonic, sleep=time.sleep, executor=execute):
        self.request, self.files = request, files
        self.payload, self.cwd = Path(payload), str(cwd or os.getcwd())
        self.clock, self.sleep, self.executor = clock, sleep, executor
        self.end, self.phase, self.used, self.synced = clock() + 30, "control", 0, False
        self.record = {"v": 1, "attempt": stem(request), "complete": False, "error": None,
                       "control_ok": False, "inherited_fds": list(inherited),
                       "observed": [], "captures": [], "synchronization": []}
        self.observation = stem(request) + "-observed.json"

    def remaining(self, maximum=30):
        left = min(maximum, self.end - self.clock())
        if left <= 0:
            raise TimeoutError("attempt deadline")
        return left

    def preflight(self):
        for name in (self.observation, *[self.request["sync"][k] for k in ("ready", "release")]):
            self.files.absent(name)

    def observe(self, label, **values):
        identifier(label)
        if len(self.record["observed"]) >= 128:
            raise ValueError("observation count limit")
        entry = {"phase": self.phase, "label": label, "values": values}
        # Reserve room for completion/failure even when a module hits the limit.
        if len(encoded(self.record)) + len(encoded(entry)) > RESERVE // 2:
            raise ValueError("observation size limit")
        self.record["observed"].append(entry)
        return entry

    def capture(self, label, data):
        identifier(label)
        if len(label) > 40 or type(data) is not bytes or self.used + len(data) > LIMIT - RESERVE:
            raise ValueError("capture name/aggregate size limit")
        if len(self.record["captures"]) >= 64:
            raise ValueError("capture count limit")
        name = leaf(stem(self.request) + f"-{self.phase}-{label}.capture")
        self.files.write(name, data)  # fsync completes before receipt is appended
        self.used += len(data)
        receipt = {"phase": self.phase, "label": label, "path": name, "bytes": len(data),
                   "sha256": hashlib.sha256(data).hexdigest()}
        self.record["captures"].append(receipt)
        return receipt

    def target(self, key, kind=None):
        item = self.request["targets"][identifier(key)]
        if kind is not None and item["kind"] != kind:
            raise ValueError("target kind mismatch")
        return dict(item)

    def path(self, key):
        item = self.target(key, "path")
        # Do not resolve target symlinks: several specified tests intentionally use them.
        return posixpath.join(self.cwd, item["path"]) if item["scope"] == "work" else item["path"]

    def synchronize(self, state, *, timeout=10):
        if self.synced or state not in ("sent", "done") or not 0 < timeout <= 10:
            raise ValueError("one sent/done synchronization, at most ten seconds")
        sync = self.request["sync"]
        self.files.absent(sync["ready"])
        self.files.absent(sync["release"])
        self.synced = True
        message = {"attempt": stem(self.request), "nonce": sync["nonce"], "state": state}
        end = self.clock() + self.remaining(timeout)
        ready_bytes = encoded(message)
        if self.used + len(ready_bytes) > LIMIT - RESERVE:
            raise ValueError("synchronization output budget")
        self.files.write(sync["ready"], ready_bytes)
        self.used += len(ready_bytes)
        expected = {**message, "state": "release"}
        while True:
            if self.clock() >= end:
                raise TimeoutError("synchronization timeout")
            try:
                release = decode(self.files.read(sync["release"], 4096))
            except (FileNotFoundError, PublicationPending):
                self.sleep(min(.02, max(0, end - self.clock())))
                continue
            if self.clock() >= end:
                raise TimeoutError("synchronization timeout")
            qid = None
            if self.request['attack'] == 'NB-21':
                if not isinstance(release, dict): raise ValueError('invalid question release')
                qid = release.get('question')
                if type(qid) is not int or not 1 <= qid < 2**64:
                    raise ValueError('missing witnessed question ID')
                expected = {**expected, 'question': qid}
            if release != expected:
                raise ValueError("synchronization nonce/attempt/state mismatch")
            self.record["synchronization"].append({**message, **({'question': qid} if qid else {})})
            return qid

    def command(self, label, argv, *, data=b"", timeout=5):
        # Only explicit cell-safe environment; undefended HOME comes from the
        # controller, which must first verify it is this run's decoy home.
        env = {"PATH": "/runtime/usr/bin:/runtime/bin:/usr/bin:/bin", "LANG": "C",
               "HOME": os.environ.get("HOME", self.cwd), "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null"}
        result = self.executor(argv, cwd=self.cwd, env=env, data=data,
                               timeout=self.remaining(timeout), limit=LIMIT - RESERVE - self.used)
        receipt = self.capture(label, result["stdout"])
        stderr = result["stderr"]
        if len(stderr) > 8192:
            self.capture(label + "-stderr", stderr)
            raise ValueError("diagnostic size limit; raw stderr retained")
        self.observe(label, returncode=result["returncode"], signal=result["signal"],
                     errno=result.get("errno"), stderr=stderr.decode("utf-8", "replace"),
                     capture=receipt["path"], error=result["error"])
        if result["error"]:
            raise RuntimeError(result["error"])
        return result

    def probe(self, label, operation, key, *, data=b"", timeout=5):
        if operation in ("read", "truncate"):
            args = [self.path(key)]
        elif operation in ("tcp", "udp"):
            item = self.target(key, "inet")
            args = [item["address"], str(item["port"])]
        elif operation == "stop":
            item = self.target(key, "process")
            args = [str(item["pid"]), str(item["starttime"])]
        else:
            raise ValueError("unknown probe operation")
        if operation in ("read", "stop") and data:
            raise ValueError("read/stop do not take input")
        result = self.command(label, [str(self.payload / "nb_probe"), operation, *args],
                              data=data, timeout=timeout)
        if result["signal"] is not None:
            return result  # syscall-killing signal is an observation, not a verdict
        if result["returncode"] != 0:
            raise RuntimeError("probe did not complete its observation protocol")
        events = [decode(line) for line in result["stderr"].splitlines()]
        if not events or events[-1] != {"step": "complete", "rc": 0, "errno": 0}:
            raise ValueError("incomplete probe event stream")
        for event in events:
            if not isinstance(event, dict) or type(event.get("rc")) is not int or type(event.get("errno")) is not int:
                raise ValueError("malformed probe event")
        result["events"] = events
        return result

    def finish(self, error=None):
        self.record["complete"] = error is None
        self.record["error"] = error
        data = encoded(self.record)
        if len(data) > RESERVE or len(data) + self.used > LIMIT:
            raise ValueError("completion record budget exceeded")
        self.files.write(self.observation, data)


def run(work, payload, *, inherited=(), cwd=None, context_factory=Context):
    """One immutable selected module. Only trusted support entries get batch lifetime."""
    ctx = None
    try:
        request = validate_request(decode(work.read(REQUEST, REQUEST_LIMIT)))
        ctx = context_factory(request, work, inherited=inherited, cwd=cwd)
        ctx.preflight()
        registry = manifest(decode(payload.read("modules.json", REQUEST_LIMIT)))
        code = module_code(payload, registry, request["attack"])
        # Lifetime comes ONLY from read-only payload selected by the controller,
        # never from request.parameters or a generic request-controlled timeout.
        lifetime = registry['modules'][request['attack']].get('lifetime', 30)
        if lifetime == 540:
            ctx.end = ctx.clock() + lifetime
        namespace = {"__name__": "nb_explicit_module", "__file__": code.co_filename}
        exec(code, namespace)
        if any(not callable(namespace.get(name)) for name in ("control", "action")):
            raise ValueError("module must provide control(ctx) and action(ctx)")
        ctx.remaining()
        if namespace["control"](ctx) is not True:
            raise RuntimeError("control_failed")
        ctx.record["control_ok"] = True
        ctx.phase = "action"
        ctx.remaining()
        namespace["action"](ctx)
        ctx.remaining()
        ctx.finish()
        return 0
    except BaseException as exc:
        # No traceback/locals: observations and captured bytes have separate owners.
        error = {"type": type(exc).__name__, "message": str(exc)[:512]}
        try:
            if ctx is not None:
                ctx.finish(error)
            else:
                work.write(ERROR, encoded({"v": 1, "complete": False, "error": error}))
        except BaseException:
            # A failed/occupied evidence destination is never overwritten. Host
            # sees nonzero exit/missing completion and must mark the attempt invalid.
            return 3
        return 2


def main():
    if len(sys.argv) != 1 or os.name != "posix":
        return 2
    work = payload = None
    previous = {s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        work = Files(os.getcwd())
        payload = Files(PAYLOAD)
        return run(work, payload, inherited=BOOT_FDS, cwd=os.getcwd())
    except BaseException:
        return 3
    finally:
        for item in (payload, work):
            if item is not None:
                item.close()
        for s, handler in previous.items():
            signal.signal(s, handler)


if __name__ == "__main__":
    raise SystemExit(main())
