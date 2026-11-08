"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Commands the controller runs, each recorded for run.json (TESTING rule 8: compile and run commands). Every long-lived
process starts inside the batch cgroup through a two-line shell prologue that moves itself there before exec, so no
process of the batch ever runs outside the cgroup the cleanup empties (TESTING rule 3).
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import time

from df_common import HOST_UID, PDP_UID

PATH_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"}
NO_CAPS = ["--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]
# the host user with its supplementary groups (METHOD rule 3: the agent runs as the host user), no capability
AS_HOST = ["/usr/bin/setpriv", f"--reuid={HOST_UID}", f"--regid={HOST_UID}", "--init-groups", *NO_CAPS]
AS_PDP = ["/usr/bin/setpriv", f"--reuid={PDP_UID}", f"--regid={PDP_UID}", "--clear-groups", *NO_CAPS]
ENTER = 'echo 0 > "$1" || exit 125; shift; exec "$@"'
OUTPUT_KEEP = 20000


class Commands:
    def __init__(self, procs: Path | None = None) -> None:
        self.records: list[dict] = []
        self.procs = procs                      # the batch cgroup's cgroup.procs, once created

    def __call__(self, argv: list, *, timeout: float = 120, allowed=(0,), env: dict | None = None,
                 data: bytes | None = None, in_cgroup: bool = False, raw: bool = False) -> dict:
        argv = [str(a) for a in argv]
        started = time.monotonic()
        full = self._enter(argv) if in_cgroup else argv
        p = subprocess.run(full, input=data, capture_output=True, timeout=timeout, env={**PATH_ENV, **(env or {})})
        item = {"argv": argv, "exit_code": p.returncode, "cgroup": in_cgroup,
                "stdout_bytes": p.stdout if raw else None,
                "stdout": p.stdout[-OUTPUT_KEEP:].decode("utf-8", "replace"),
                "stderr": p.stderr[-OUTPUT_KEEP:].decode("utf-8", "replace"),
                "elapsed_seconds": round(time.monotonic() - started, 3)}
        self.records.append({k: v for k, v in item.items() if k not in ("stdout", "stderr", "stdout_bytes")}
                            | {"stderr_tail": item["stderr"][-2000:]})
        if p.returncode not in allowed:
            raise RuntimeError(f"command failed ({p.returncode}): {' '.join(argv[-4:])}: {item['stderr'][-1500:]}")
        return item

    def _enter(self, argv: list[str]) -> list[str]:
        if self.procs is None:
            raise RuntimeError("the batch cgroup does not exist yet")
        return ["/bin/sh", "-c", ENTER, "sh", str(self.procs), *argv]

    def start(self, argv: list, *, stdin=None, stdout=None, stderr=None, env: dict | None = None,
              cwd: str | None = None) -> subprocess.Popen:
        """A long-lived process in the batch cgroup; recorded with its pid."""
        argv = [str(a) for a in argv]
        proc = subprocess.Popen(self._enter(argv), stdin=stdin, stdout=stdout, stderr=stderr,
                                env={**PATH_ENV, **(env or {})}, cwd=cwd, start_new_session=True)
        self.records.append({"argv": argv, "started_pid": proc.pid, "cgroup": True})
        return proc


def stop(proc: subprocess.Popen | None, timeout: float = 10) -> int | None:
    """SIGTERM, then SIGKILL; the cgroup kill in cleanup remains the backstop."""
    if proc is None or proc.poll() is not None:
        return None if proc is None else proc.returncode
    proc.terminate()
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.wait(timeout=5)


def host_accounts() -> list[int]:
    with open("/etc/passwd", encoding="utf-8") as f:
        return [int(line.split(":")[2]) for line in f if line.count(":") >= 6]


def process_uids(proc: Path = Path("/proc")) -> list[int]:
    out = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("Uid:"):
                    out += [int(x) for x in line.split()[1:]]
        except OSError:
            continue
    return out


def namespaces() -> dict:
    return {kind: os.readlink(f"/proc/self/ns/{kind}") for kind in ("mnt", "net", "pid")}
