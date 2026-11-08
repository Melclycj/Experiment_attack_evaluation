"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The running batch as attempts see it: the E-09 file read incrementally, the PDP (the simple PDP by default, the
stand-in swapped in for the subgoals that need a held answer, tests.md 1.1), waiting for a row to close, and the
collection of one attempt's facts.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import threading
import time

from df_control import read_obs
from df_deploy import TREE, start_hold_pdp, start_simple_pdp
from df_judge import Facts
from df_proc import stop


class EventsFile:
    """E-09 as written so far; complete lines only, in file order (producer_seq order)."""

    def __init__(self, path: Path) -> None:
        self.path, self.records, self.pos, self.partial = path, [], 0, b""
        self.lock = threading.Lock()

    def _load(self) -> None:
        with self.lock:
            with self.path.open("rb") as f:
                f.seek(self.pos)
                data = f.read()
            self.pos += len(data)
            lines = (self.partial + data).split(b"\n")
            self.partial = lines.pop()
            self.records += [json.loads(line) for line in lines if line.strip()]

    def offset(self) -> int:
        self._load()
        return len(self.records)

    def read_from(self, index: int) -> list[dict]:
        self._load()
        return self.records[index:]


class Pdp:
    def __init__(self, env) -> None:
        self.env = env
        self.mode, self.proc = None, None
        self.events: list[dict] = []
        self.cond = threading.Condition()
        self.swaps: list[dict] = []

    def use(self, mode: str, limit: float = 15) -> None:
        if mode == self.mode and self.proc is not None and self.proc.poll() is None:
            return
        offset = self.env.events.offset()
        if self.proc is not None:
            stop(self.proc)
            self._wait_record("pdp_disconnected", offset, limit)
            offset = self.env.events.offset()
        if mode == "simple":
            log = (self.env.scratch / "nb-decoy-simple-pdp.log").open("ab")
            self.proc = start_simple_pdp(self.env.engine, self.env.root, self.env.command, log)
        else:
            self.proc = start_hold_pdp(self.env.engine, self.env.harness, self.env.root, self.env.command)
            threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()
        if self._wait_record("pdp_connected", offset, limit) is None:
            raise RuntimeError(f"the {mode} PDP did not connect")
        self.mode = mode
        self.swaps.append({"mode": mode, "t": time.time()})

    def _wait_record(self, kind: str, offset: int, limit: float) -> dict | None:
        end = time.monotonic() + limit
        while time.monotonic() < end:
            found = next((e for e in self.env.events.read_from(offset) if e.get("kind") == kind), None)
            if found:
                return found
            time.sleep(0.05)
        return None

    def _read(self, proc) -> None:
        for line in proc.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            with self.cond:
                self.events.append(event)
                self.cond.notify_all()

    def _send(self, line: str) -> None:
        if self.mode != "hold":
            raise RuntimeError("the PDP stand-in is not the connected PDP")
        self.proc.stdin.write(line.encode() + b"\n")
        self.proc.stdin.flush()

    def arm(self, tag: str) -> None:
        self._send(f"hold {tag}")

    def release(self) -> None:
        self._send("release")

    def wait(self, predicate, index: int, limit: float) -> dict | None:
        end = time.monotonic() + limit
        with self.cond:
            while True:
                found = next((e for e in self.events[index:] if predicate(e)), None)
                if found is not None:
                    return found
                left = end - time.monotonic()
                if left <= 0:
                    return None
                self.cond.wait(left)

    def close(self) -> None:
        stop(self.proc)


class Env:
    """Set up by df_batch; attributes: root, engine, harness, scripts, scratch, command, admin, watch, events, pdp,
    net, targets, uwork, ca_file, connector_logs."""

    def wait_row(self, execution: str, obs: Path, deadline: float, notes: dict) -> None:
        while time.monotonic() < deadline:
            if obs.exists():
                listed = self.admin.row_list()
                if not any(execution in item for item in listed.get("payload", [])):
                    notes.setdefault("row_closed_at", {})[execution] = time.time()
                    return
            time.sleep(0.1)
        notes["attempt_timeout"] = True
        notes.setdefault("row_stop", []).append(self.admin.row_stop(execution))
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if not any(execution in item for item in self.admin.row_list().get("payload", [])):
                return
            time.sleep(0.2)
        raise RuntimeError(f"row {execution} did not close after ROW_STOP")

    def connector_lines(self, execution: str) -> list[dict]:
        path = self.connector_logs / ("nb-decoy-connector-" + re.sub(r"[^A-Za-z0-9_-]", "-", execution) + ".log")
        if not path.exists():
            return [{"event": "nb-decoy-log-missing"}]
        out = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"raw": line[:500]})
        return out

    def facts(self, attempt, roles: list[str]) -> Facts:
        obs = {}
        for (ws, role), key in zip(attempt.case.rows if attempt.engine else [(None, None)], roles):
            work = self.root / ws / TREE if attempt.engine else self.uwork
            obs[key if attempt.engine else ""] = read_obs(work, attempt.nonce, role if attempt.engine else None)
        test, run = self.net.read("test"), self.net.read("run")
        end = attempt.end or time.time()
        window = lambda r: attempt.start - 1 <= r.get("t", 0) <= end + 1  # noqa: E731
        upstream = [r for r in test if r.get("nonce") == attempt.nonce and r.get("kind") in ("request", "block")]
        # decoy records: this attempt's requests, the connections accepted near its window, and every record of those
        # connections (another nonce read on one ties it to another attempt; a TLS failure shows as conn_error)
        decoy = [r for r in test + run if str(r.get("listener", "")).startswith("decoy")]
        near = {r.get("conn") for r in decoy if r.get("kind") == "connect" and window(r)}
        decoys = [r for r in decoy if r.get("nonce") == attempt.nonce or r.get("conn") in near]
        dns = [r for r in test if r.get("kind") == "dns" and r.get("epoch") == attempt.nonce]
        connector = [line for ex in attempt.executions for line in self.connector_lines(ex)]
        return Facts(attempt.config, attempt.nonce, obs, upstream=upstream, decoys=decoys, dns=dns,
                     events=attempt.events(), connector=connector,
                     questions=self.watch.events[attempt.q_index:] if self.watch else [],
                     pdp=self.pdp.events[attempt.pdp_index:], notes=attempt.notes,
                     executions=list(attempt.executions), window=(attempt.start, end))
