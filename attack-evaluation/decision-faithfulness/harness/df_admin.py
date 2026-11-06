"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The user's side of the management port (engine-v3 SPEC-canonical-form.md 3.4, link D), spoken with the pinned
engine's own framing (connector/canonical.py, client/link.py, both read from the batch's snapshot of a9eff999): one
short connection per verb, and one watching connection that keeps every QUESTION and QUESTION_WITHDRAWN with the time
it arrived. Answering a withdrawn question (DF-08) is a plain ANSWER frame; the production client is not needed.
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys
import threading
import time

KEY_KINDS = {"exact": 1, "pattern": 2, "fallback": 3}
STATES = {"allow": 1, "deny": 2}
APPROVALS = {"never": 1, "always": 2}
VERDICTS = {"allow-once": 1, "allow-cell": 2, "deny-once": 3, "deny-cell": 4}
PLACEMENT_BEARER = (2, b"Bearer")


def engine_modules(engine_dir: Path):
    """(canonical, Link) from the pinned snapshot; the snapshot directory goes first on sys.path."""
    if str(engine_dir) not in sys.path:
        sys.path.insert(0, str(engine_dir))
    canonical = importlib.import_module("connector.canonical")
    link = importlib.import_module("client.link")
    if Path(canonical.__file__).resolve().parents[1] != engine_dir.resolve():
        raise RuntimeError("engine modules did not come from the pinned snapshot")
    return canonical, link.Link


class Admin:
    def __init__(self, root: Path, engine_dir: Path) -> None:
        self.path = root / "state" / "admin.sock"
        self.c, self.Link = engine_modules(engine_dir)
        self.log: list[dict] = []

    def call(self, verb: str, kind: int, fields: list[bytes]) -> dict:
        c = self.c
        link = self.Link(self.path)
        try:
            got, reply = link.call(kind, fields)
        finally:
            link.close()
        if got == c.OK:
            payload = [x.decode("utf-8", "replace") for x in c.unpack_list(reply[1])]
            out = {"verb": verb, "ok": True, "payload": payload}
        else:
            out = {"verb": verb, "ok": False, "code": c.read_uint(reply[1], 1),
                   "detail": reply[2].decode("utf-8", "replace")}
        out.update(t=time.time(), mono=time.monotonic())
        self.log.append(out)
        return out

    # ---- verbs ----------------------------------------------------------------------------------------------
    def entry_put(self, ws: str, key: str, *, kind: str = "exact", state: str = "allow", methods=(), prefixes=(),
                  accounts=(), approval: str = "never") -> dict:
        """ENTRY_PUT has nine fields at a9eff999: the ninth is the entry's named non-global addresses (K-57). This unit
        names none, so the field is always the empty list."""
        c, e = self.c, str.encode
        return self.call(f"entry put {ws} {kind} {state} {key} m={list(methods)} p={list(prefixes)} "
                         f"a={list(accounts)} {approval}", c.ENTRY_PUT,
                         [e(ws), c.u8(KEY_KINDS[kind]), e(key), c.u8(STATES[state]),
                          c.pack_list([e(m) for m in methods]), c.pack_list([e(p) for p in prefixes]),
                          c.pack_list([e(a) for a in accounts]), c.u8(APPROVALS[approval]), c.pack_list([])])

    def entry_del(self, ws: str, key: str, *, kind: str = "exact") -> dict:
        c, e = self.c, str.encode
        return self.call(f"entry del {ws} {kind} {key}", c.ENTRY_DEL, [e(ws), c.u8(KEY_KINDS[kind]), e(key)])

    def cred_put(self, host_port: str, account: str, truth: bytes, *, token_endpoint: str = "") -> dict:
        c, e = self.c, str.encode
        placement, word = PLACEMENT_BEARER
        return self.call(f"cred put {host_port} {account} bearer endpoint={token_endpoint!r}", c.CRED_PUT,
                         [e(host_port), e(account), c.u8(placement), word, truth, b"", e(token_endpoint), b"", b""])

    def cred_del(self, host_port: str, account: str) -> dict:
        c, e = self.c, str.encode
        return self.call(f"cred del {host_port} {account}", c.CRED_DEL, [e(host_port), e(account)])

    def row_start(self, ws: str, plan: str) -> dict:
        c, e = self.c, str.encode
        return self.call(f"row start {ws} {plan}", c.ROW_START, [e(ws), e(plan), c.pack_list([]), b""])

    def row_stop(self, execution: str) -> dict:
        return self.call(f"row stop {execution}", self.c.ROW_STOP, [execution.encode()])

    def row_list(self) -> dict:
        return self.call("row list", self.c.ROW_LIST, [])

    def answer(self, question_id: int, verdict: str) -> dict:
        c = self.c
        return self.call(f"answer {question_id} {verdict}", c.ANSWER,
                         [c.u64(question_id), c.u8(VERDICTS[verdict])])


class Watch(threading.Thread):
    """The approval window: every question and withdrawal, in arrival order, with arrival times."""

    def __init__(self, admin: Admin) -> None:
        super().__init__(name="df-question-watch", daemon=True)
        self.c = admin.c
        self.link = admin.Link(admin.path)
        self.events: list[dict] = []
        self.cond = threading.Condition()
        self.closed = False

    def run(self) -> None:
        c = self.c
        try:
            while True:
                frames = self.link.receive()
                if frames is None:
                    break
                for kind, fields, fd in frames:
                    if fd is not None:
                        os.close(fd)                       # the body is not read
                    if kind == c.QUESTION:
                        event = {"event": "question", "question_id": c.read_uint(fields[0], 8),
                                 "execution": fields[1].decode(), "workspace": fields[2].decode(),
                                 "method": fields[5].decode(), "host": fields[7].decode(),
                                 "port": c.read_uint(fields[8], 2), "path": fields[9].decode(),
                                 "query": fields[10].decode()}
                    elif kind == c.QUESTION_WITHDRAWN:
                        event = {"event": "withdrawn", "question_id": c.read_uint(fields[0], 8),
                                 "reason": c.read_uint(fields[1], 1)}
                    else:
                        continue
                    event.update(t=time.time(), mono=time.monotonic())
                    with self.cond:
                        self.events.append(event)
                        self.cond.notify_all()
        except (OSError, ValueError):
            pass
        finally:
            with self.cond:
                self.closed = True
                self.cond.notify_all()

    def wait_for(self, predicate, limit: float) -> dict | None:
        end = time.monotonic() + limit
        with self.cond:
            while True:
                found = next((e for e in self.events if predicate(e)), None)
                if found is not None or self.closed:
                    return found
                left = end - time.monotonic()
                if left <= 0:
                    return None
                self.cond.wait(left)

    def question(self, tag: str, limit: float, after: int = 0) -> dict | None:
        """The first question whose query carries ``n=<tag>`` (nonce and step tag) and whose id is above ``after``."""
        return self.wait_for(lambda e: e["event"] == "question" and f"n={tag}" in e["query"]
                             and e["question_id"] > after, limit)

    def withdrawn(self, question_id: int, limit: float) -> dict | None:
        return self.wait_for(lambda e: e["event"] == "withdrawn" and e["question_id"] == question_id, limit)

    def close(self) -> None:
        try:
            self.link.sock.shutdown(2)              # SHUT_RDWR: wakes the reader before the descriptor goes
        except OSError:
            pass
        self.join(5)
        self.link.close()
