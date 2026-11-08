"""Driver-side handle on the host agent (agent.py): start it as a child process, send one JSON command per line,
read the JSONL samples it writes. The driver and the agent both run as root on the measurement server."""
from __future__ import annotations

import itertools
import json
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

AGENT = Path(__file__).resolve().with_name("agent.py")


class AgentError(RuntimeError):
    pass


class Agent:
    """One running agent.py; commands are serialised (one in flight at a time)."""

    def __init__(self, run_dir: Path, interval: float = 1.0) -> None:
        sample_dir = run_dir / f"host-{time.strftime('%Y%m%dT%H%M%S')}"
        sample_dir.mkdir()
        self.samples_path = sample_dir / "host-samples.jsonl"
        self.proc = subprocess.Popen([sys.executable, str(AGENT), "serve", str(sample_dir), str(interval)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=open(run_dir / "agent.stderr.log", "ab"), text=True, encoding="utf-8",
                                     bufsize=1)
        # A reader thread owns stdout, so every call can time out instead of blocking the night on a dead pipe.
        self._lines: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        first = self._next_line(60)
        if not first or not json.loads(first).get("ready"):
            raise AgentError(f"agent did not start: {first!r}")
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def _read(self) -> None:
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _next_line(self, timeout: float) -> str | None:
        try:
            return self._lines.get(timeout=timeout)
        except queue.Empty:
            raise AgentError(f"no reply from the agent within {timeout:.0f}s") from None

    def call(self, op: str, rpc_timeout: float | None = None, **kwargs) -> dict:
        """One command; its reply must arrive within rpc_timeout (default: the command's own `timeout`, which goes
        to the agent, plus 60 s). Replies are matched by id: a late reply to a call that already timed out is
        discarded instead of being taken as the answer to this one."""
        limit = rpc_timeout if rpc_timeout is not None else float(kwargs.get("timeout", 120)) + 60
        deadline = time.monotonic() + limit
        with self._lock:
            if self.proc.poll() is not None:
                raise AgentError(f"agent exited ({self.proc.returncode})")
            cid = next(self._ids)
            self.proc.stdin.write(json.dumps({"op": op, "id": cid, **kwargs}) + "\n")
            self.proc.stdin.flush()
            while True:
                line = self._next_line(max(0.1, deadline - time.monotonic()))
                if not line:
                    raise AgentError(f"agent closed its output during {op}")
                reply = json.loads(line)
                if reply.get("id") == cid:
                    break
        if not reply.get("ok"):
            raise AgentError(f"{op}: {reply.get('error')}")
        return reply["result"]

    def _tail_lines(self, nbytes: int) -> list[str]:
        try:
            with open(self.samples_path, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - nbytes))
                return fh.read().decode("utf-8", "replace").splitlines()
        except OSError:
            return []

    def window(self, t0: float, t1: float) -> list[dict]:
        """Samples with t0 <= t <= t1, read from the file's tail (sample errors are skipped)."""
        span = max(1.0, time.time() - t0)
        rows = []
        for line in self._tail_lines(int(65536 + span * 8192)):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if t0 <= row.get("t", 0) <= t1 and "error" not in row:
                rows.append(row)
        return rows

    def latest(self) -> dict | None:
        """The newest valid sample (reads only the file's tail), or None."""
        for line in reversed(self._tail_lines(65536)):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" not in row:
                return row
        return None

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.kill()
