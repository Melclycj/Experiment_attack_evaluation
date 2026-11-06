"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

from pathlib import Path
import re

from build import AS_BUILDER
from common import token
from deploy_catalog import PYTHON
from net import QUESTION_HOST, UPSTREAM_HOST
from upstream import wait_for


# The production client's verdict prompt, verbatim (engine-v3 client/admin.py, unchanged since engine-v2-go; 648d60f2 3.2).
PROMPT = ("answer question {qid} [allow-once | deny-once | allow-always (allow, never ask on this cell again) | "
          "deny-always (deny on this cell from now on) | show]: ")
WORKSPACES = ("work0", "work1", "work2")


def execution_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}:[1-9][0-9]{0,19}", value):
        raise ValueError("invalid production execution id")
    return value


def current_question(text: str) -> dict | None:
    """Parse ONLY the production admin renderer, never attach/agent output.
    Cell bytes in this renderer have CR/LF and backslash escaped by client.render.
    A queued/withdrawn/already answered question is not an approval candidate.
    """
    headers = list(re.finditer(r"^── question (\d+) ── row ([A-Za-z0-9_:-]+) ── workspace (work[012]) ──$",
                               text, re.MULTILINE))
    if not headers:
        return None
    m = headers[-1]
    qid = int(m[1])
    body = text[m.end():]
    if re.search(rf"question {qid} (?:withdrawn|answered|is gone)", body):
        return None
    if PROMPT.format(qid=qid) not in body:
        return None
    values = dict(re.findall(r"^  (method|scheme|host|port|path) +([^\r\n]+)$", body, re.MULTILINE))
    if set(values) != {"method", "scheme", "host", "port", "path"}:
        return None
    return {"qid": qid, "execution": m[2], "workspace": m[3], **values}


class Interaction:
    def __init__(self, command, child):
        self.command, self.child, self.closed = command, child, False

    def send(self, data: bytes):
        if self.closed:
            raise ValueError("input already closed")
        self.command.send_input(self.child, data)

    def until(self, marker: bytes, *, timeout=10, start=0):
        if not marker or len(marker) > 4096:
            raise ValueError("bounded nonempty marker required")
        return wait_for(self.command, lambda: marker in bytes(self.child.buffers["stdout"])[start:],
                        timeout=timeout, child=self.child)

    def close(self):
        if not self.closed:
            self.command.close_input(self.child)
            self.command.wait(self.child)
            self.closed = True


class Management:
    """All I/O through the current production client under Commands. In particular
    QUESTION's SCM_RIGHTS/body memfd pairing and ATTACH framing are not reimplemented.
    Pipe-mode attach is supported by client.attach; EOF detaches, not Ctrl-].
    """
    def __init__(self, source: Path, root: Path, command, engine):
        self.command, self.engine = command, engine
        self.argv = [*AS_BUILDER, *PYTHON, str(source / "bin/engine-client"), "--root", str(root)]
        self.interactions, self.watcher, self.answered = [], None, set()

    def call(self, *args, timeout=5, allowed=(0,), env=None):
        if self.engine.proc.poll() is not None:
            raise RuntimeError("engine exited before admin operation")
        return self.command([*self.argv, "admin", *args], timeout=timeout, allowed=allowed, env=env)

    def ready(self):
        return wait_for(self.command, lambda: self.call("ws", "list", allowed=(0, 2))["exit_code"] == 0,
                        child=self.engine)

    def workspaces(self):
        return self.call("ws", "list")["stdout"]

    def rows(self):
        return self.call("row", "list")["stdout"]

    def credential(self, sentinel: str, witness: str, account="nb-decoy-account"):
        """A decoy credential record. 648d60f2 dropped the placeholder from the record, so the metadata file's own
        witness string rides in the OAuth token endpoint's path (never requested; NB-20's metadata branch)."""
        token(account)
        token(witness)
        if not sentinel or len(sentinel) > 4096 or "\0" in sentinel or sentinel == witness:
            raise ValueError("invalid decoy credential")
        return self.call("cred", "put", UPSTREAM_HOST + ":443", account, "api-key",
                         "--truth-env", "NB_DECOY_TRUTH", "--token-endpoint", f"https://{UPSTREAM_HOST}/{witness}",
                         env={"NB_DECOY_TRUTH": sentinel})

    def entry(self, workspace="work0", *, approval="never"):
        if workspace not in WORKSPACES or approval not in ("never", "always"):
            raise ValueError("invalid decoy entry")
        return self.call("entry", "put", workspace, "exact", "allow", UPSTREAM_HOST + ":443",
                         "--method", "GET", "--prefix", "/", "--approval", approval)

    def question_entry(self, workspace):
        """QUESTION_HOST's POST asks the user. Under 648d60f2 3.2 a request no cell covers is refused outright, so the
        question needs a covering cell marked ask-every-time; the default fallback still allows GET only."""
        if workspace not in WORKSPACES:
            raise ValueError("invalid decoy question entry")
        return self.call("entry", "put", workspace, "exact", "allow", QUESTION_HOST + ":443",
                         "--method", "POST", "--prefix", "/", "--approval", "always")

    def start_row(self, workspace, *, accounts=()):
        if workspace not in ("work0", "work1", "work2"):
            raise ValueError("unknown workspace")
        def attempt():
            options = []
            for host_port, account in accounts:
                token(account)
                if not host_port.startswith('nb-decoy-') or not host_port.endswith((':80', ':443', ':8443')):
                    raise ValueError('only decoy row account selections')  # :8443 = CB-14 条款 8 keep endpoint
                options.extend(('--account', host_port + '=' + account))
            result = self.call("row", "start", workspace, "nb-" + workspace[-1], *options, allowed=(0, 1))
            if result["exit_code"]:
                if "control not ready" not in result["stderr"]:
                    raise RuntimeError("row start refused: " + result["stderr"][:1024])
                return None
            m = re.fullmatch(r"execution=([A-Za-z0-9_:-]+)\s*", result["stdout"])
            if not m:
                raise RuntimeError("malformed row start reply")
            return execution_id(m[1])
        return wait_for(self.command, attempt, timeout=20, child=self.engine)

    def stop_row(self, execution):
        execution_id(execution)
        self.call("row", "stop", execution)
        return wait_for(self.command, lambda: not re.search(rf"^execution={re.escape(execution)}(?: |$)",
                        self.rows(), re.MULTILINE), timeout=10, child=self.engine)

    def _interactive(self, *args, timeout=30):
        child = self.command.start([*self.argv, *args], interactive=True, timeout=timeout)
        stream = Interaction(self.command, child)
        self.interactions.append(stream)
        return stream

    def attach(self, execution, *, timeout=30):
        execution_id(execution)
        stream = self._interactive("attach", execution, timeout=timeout)
        wait_for(self.command, lambda: f"attached to {execution};".encode() in stream.child.buffers["stderr"],
                 child=stream.child)
        return stream

    def watch(self):
        if self.watcher is not None:
            raise RuntimeError("one approval watcher per deployment")
        self.watcher = self._interactive("admin", "questions", timeout=self.command.deadline.left(540))
        self.watcher.until(b"watching for questions")
        return self.watcher

    def question(self, *, execution, method="POST", host=QUESTION_HOST, path, timeout=10):
        execution_id(execution)
        if host not in (QUESTION_HOST, UPSTREAM_HOST) or method not in ("POST", "GET"):
            raise ValueError("only this run's decoy questions are admissible")
        if self.watcher is None:
            raise RuntimeError("watch the admin stream before triggering the request")
        def match():
            q = current_question(bytes(self.watcher.child.buffers["stdout"]).decode("utf-8"))
            if q and q["qid"] not in self.answered and all(q[k] == v for k, v in {
                    "execution": execution, "method": method, "host": host, "path": path,
                    "scheme": "https", "port": "443"}.items()):
                return q
        return wait_for(self.command, match, timeout=timeout, child=self.watcher.child)

    def allow_once(self, question):
        if self.watcher is None:
            raise RuntimeError("no approval watcher")
        self.command.pump(0)
        current = current_question(bytes(self.watcher.child.buffers["stdout"]).decode("utf-8"))
        if current != question or question["qid"] in self.answered:
            raise RuntimeError("question was withdrawn/replaced/already answered")
        self.answered.add(question["qid"])
        start = len(self.watcher.child.buffers["stdout"])
        self.watcher.send(b"allow-once\n")
        self.watcher.until(f"question {question['qid']} answered".encode(), start=start)

    def close(self):
        for stream in reversed(self.interactions):
            stream.close()
