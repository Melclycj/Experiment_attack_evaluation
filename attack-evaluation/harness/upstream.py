"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import time

from common import json_bytes
from deploy_catalog import PYTHON


def wait_for(command, predicate, *, timeout=10, child=None):
    end = time.monotonic() + command.deadline.left(timeout)
    while True:
        command.pump(.01)
        if child is not None and child.proc.poll() is not None:
            raise RuntimeError("service exited before readiness/completion (not a test outcome)")
        value = predicate()
        if value:
            return value
        if time.monotonic() >= end:
            raise TimeoutError("service readiness/completion timed out (not a test outcome)")


class Upstream:
    def __init__(self, root, command, network, network_info):
        self.root, self.command, self.network, self.info = root, command, network, network_info
        self.child, self.current, self.closed = None, None, False
        self.cursor, self.pending, self.events = 0, b"", []

    def poll(self):
        data = bytes(self.child.buffers["stdout"])
        self.pending += data[self.cursor:]
        self.cursor = len(data)
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            self.events.append(json.loads(line))
        return self.events

    def exchange(self, mode, secret):
        result = self.command([*PYTHON, str(Path(__file__).with_name("https_client.py")),
                               str(self.root / "tls/ca.pem"), mode], timeout=5,
                              env={"NB_HTTPS_SECRET": secret})
        return json.loads(result["stdout"])

    def start(self):
        fd = self.info["upstream"]["fd"]
        if not self.network.prepared or self.network.closed or fd not in self.network.fds or self.child:
            raise RuntimeError("missing pinned private network or repeated service start")
        secret = secrets.token_hex(24)
        seconds = self.command.deadline.left(540)
        self.child = self.command.start(["/usr/bin/nsenter", f"--net=/proc/{os.getpid()}/fd/{fd}", "--",
                                        *PYTHON, str(Path(__file__).with_name("https_service.py")),
                                        str(self.root), str(seconds), "NB_READY_SECRET"],
                                       timeout=seconds, interactive=True, env={"NB_READY_SECRET": secret})
        wait_for(self.command, lambda: any(e.get("kind") == "ready" for e in self.poll()), child=self.child)
        if self.exchange("ready", secret) != {"ready": secret}:
            raise RuntimeError("HTTPS CA/hostname/readiness roundtrip failed")
        return self

    def begin(self, attempt):
        if self.current or self.closed or self.child is None:
            raise RuntimeError("HTTPS window cannot start")
        secret = secrets.token_hex(24)
        start = len(self.poll())
        self.command.send_input(self.child, json_bytes({"attempt": attempt, "secret": secret}))
        window = wait_for(self.command, lambda: next((e for e in self.poll()[start:]
                          if e.get("kind") == "window" and e.get("attempt") == attempt), None), child=self.child)
        self.current = (attempt, secret, window["cursor"], start)
        return window["cursor"]  # the secret is controller-only, never a runner request

    def end(self):
        if self.current is None:
            raise RuntimeError("no active HTTPS window")
        attempt, secret, cursor, start = self.current
        # Caller has already closed the row/process tree. One second effect window.
        until = time.monotonic() + 1
        while time.monotonic() < until:
            self.command.pump(.02)
        self.exchange("end", secret)
        marker = wait_for(self.command, lambda: next((e for e in self.poll()[start:]
                          if e.get("kind") == "end" and e.get("token") == secret), None), child=self.child)
        receipts = [e for e in self.poll()[start:] if e.get("kind") == "request"
                    and e.get("attempt") == attempt and cursor <= e["seq"] < marker["seq"]]
        self.current = None
        return {"cursor": cursor, "end": marker, "requests": receipts}

    def close(self):
        if self.closed:
            return
        if self.current:
            raise RuntimeError("unclosed observation window; cannot report successful service shutdown")
        if self.child:
            self.command.close_input(self.child)
            self.command.wait(self.child)
            self.poll()
            if self.pending:
                raise RuntimeError("truncated HTTPS journal")
        self.closed = True
