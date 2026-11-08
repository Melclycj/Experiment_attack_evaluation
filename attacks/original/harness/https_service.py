"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import select
import socket
import ssl
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import json_bytes, token, utc
from decoy_services import MAX_CONNECTIONS, MAX_JOURNAL, MAX_PAYLOAD, end_frame
from net import QUESTION_HOST, UPSTREAM_HOST, UPSTREAM_IP

HEADER_LIMIT = 16384


def parse_head(data: bytes) -> tuple[str, str, str, int]:
    if len(data) > HEADER_LIMIT:
        raise ValueError("HTTP headers exceed bound")
    lines = data.decode("ascii").split("\r\n")
    method, path, version = lines[0].split(" ")
    if method not in ("GET", "POST") or version != "HTTP/1.1" or not path.startswith("/") or len(path) > 8192:
        raise ValueError("unsupported local request")
    headers = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        name, value = name.lower(), value.strip()
        if name in headers or not name or any(ord(c) < 32 for c in value):
            raise ValueError("duplicate or malformed header")
        headers[name] = value
    host = headers.get("host", "").removesuffix(":443")
    if host not in (UPSTREAM_HOST, QUESTION_HOST) or "transfer-encoding" in headers:
        raise ValueError("request is not for a local decoy")
    length = headers.get("content-length", "0")
    if not length.isdecimal() or not 0 <= int(length) <= MAX_PAYLOAD:
        raise ValueError("invalid bounded content length")
    # Only the decoy headers the cell may set (BD-02 own-key demonstration); the receipt records them so the
    # external judge can see the connector forwarded a cell-chosen header unchanged.
    decoy = {name: value for name, value in headers.items() if name.startswith("x-nb-decoy-")}
    return method, path, host, int(length), decoy


def read_request(conn, end):
    pending = b""
    while b"\r\n\r\n" not in pending:
        conn.settimeout(max(.001, end - time.monotonic()))
        if time.monotonic() >= end or len(pending) > HEADER_LIMIT:
            raise TimeoutError("HTTP header deadline/bound")
        chunk = conn.recv(1024)
        if not chunk:
            raise ConnectionError("partial HTTP headers")
        pending += chunk
    head, body = pending.split(b"\r\n\r\n", 1)
    method, path, host, length, decoy = parse_head(head)
    while len(body) < length:
        conn.settimeout(max(.001, end - time.monotonic()))
        if time.monotonic() >= end:
            raise TimeoutError("HTTP body deadline")
        chunk = conn.recv(length - len(body))
        if not chunk:
            raise ConnectionError("partial HTTP body")
        body += chunk
    if len(body) != length:
        raise ValueError("pipelined/trailing request bytes")
    return method, path, host, body, decoy


class Window:
    """External receipt log; end is a real TLS request, not a claim by an attack."""
    def __init__(self, emit):
        self.emit, self.current, self.seq, self.count = emit, None, 0, 0

    def begin(self, attempt, secret):
        if self.current is not None:
            raise ValueError("previous HTTPS window is still open")
        token(attempt)
        end_frame(secret)
        self.current, self.count = (attempt, secret), 0
        self.emit({"kind": "window", "attempt": attempt, "cursor": self.seq})

    def receive(self, method, path, host, body, peer, decoy_headers=None):
        if self.current is None:
            raise ValueError("request outside observation window")
        attempt, secret = self.current
        ending = method == "POST" and path == "/nb-end" and body == end_frame(secret)
        if self.count >= MAX_CONNECTIONS or len(body) > MAX_PAYLOAD:
            raise ValueError("HTTPS window bound reached")
        reply = secrets.token_hex(16)
        item = {"kind": "end" if ending else "request", "attempt": attempt, "seq": self.seq,
                "token": secret if ending else None, "received_at": utc(), "method": method,
                "path": path, "host": host, "peer": peer, "bytes": len(body), "reply_token": reply,
                "decoy_headers": decoy_headers or {},
                "payload_base64": base64.b64encode(body).decode("ascii")}
        self.emit(item)
        self.seq += 1
        self.count += 1
        if ending:
            self.current = None
        return json_bytes({"token": reply})


def serve(root: Path, seconds: float, ready_secret: str):
    if not 0 < seconds <= 540:
        raise ValueError("service deadline exceeds batch")
    token(ready_secret)
    end, written = time.monotonic() + seconds, 0

    def emit(item):
        nonlocal written
        data = json_bytes(item)
        written += len(data)
        if written > MAX_JOURNAL:
            raise ValueError("HTTPS journal budget exceeded")
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(root / "tls/server.pem"), str(root / "tls/server.key"))
    window, pending = Window(emit), b""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((UPSTREAM_IP, 443))
        listener.listen(8)
        emit({"kind": "ready", "address": UPSTREAM_IP, "port": 443})
        while time.monotonic() < end:
            ready, _, _ = select.select([listener, sys.stdin.fileno()], [], [], min(.1, end - time.monotonic()))
            if sys.stdin.fileno() in ready:
                data = os.read(sys.stdin.fileno(), 4096)
                if not data:
                    if window.current:
                        raise RuntimeError("input closed before end marker")
                    return
                pending += data
                if len(pending) > 4096:
                    raise ValueError("oversized service control")
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    cmd = json.loads(line)
                    window.begin(cmd["attempt"], cmd["secret"])
            if listener in ready:
                raw, peer = listener.accept()
                with raw:
                    raw.settimeout(min(3, max(.001, end - time.monotonic())))
                    with ctx.wrap_socket(raw, server_side=True) as conn:
                        method, path, host, body, decoy = read_request(conn, min(end, time.monotonic() + 3))
                        if method == "POST" and path == "/nb-ready" and body == ready_secret.encode():
                            response = json_bytes({"ready": ready_secret})
                        else:
                            response = window.receive(method, path, host, body, list(peer), decoy)
                        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n"
                                     + f"Content-Length: {len(response)}\r\n\r\n".encode() + response)
        raise TimeoutError("HTTPS service batch deadline")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("internal service: ROOT SECONDS READY_SECRET_ENV")
    serve(Path(sys.argv[1]), float(sys.argv[2]), os.environ[sys.argv[3]])
