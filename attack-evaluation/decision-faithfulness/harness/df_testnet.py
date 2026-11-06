"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The batch's test network, one program per namespace (tests.md 1.2): the test upstream (HTTPS on 443 and 8443), the
decoy recorders (plain or TLS) and the test DNS. Every listener only records; none forwards. One JSON line per event in
the log the config names. Run as root inside the namespace by the controller:

    python3 -I -B df_testnet.py CONFIG.json

Endpoints of the upstream: /ok and any other path (200 "ok"), /redirect/30x (Location: the private decoy),
/close-after-read (reads the request, then drops the connection), /stream (one block, then waits for the gate file
gates/stream-<nonce> before the marked second block). The DNS answers only nb-decoy-rebind: the first A query in the
current epoch (gates/dns-epoch) gets the upstream's address, later ones the private decoy; AAAA gets no record.
"""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import sys
import threading
import time

NONCE = re.compile(r"n=([0-9a-f]{16})-([a-z0-9]{1,4})")
HEAD_MAX = 65536
BODY_MAX = 1024 * 1024
GATE_WAIT = 25.0
STATUS_TEXT = {200: "OK", 302: "Found", 307: "Temporary Redirect", 308: "Permanent Redirect"}


class Log:
    def __init__(self, path: str) -> None:
        self.f = open(path, "a", encoding="utf-8")
        self.lock = threading.Lock()

    def write(self, **record) -> None:
        record.setdefault("t", time.time())
        with self.lock:
            self.f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            self.f.flush()


def read_head(sock: socket.socket, buf: bytes) -> tuple[bytes | None, bytes]:
    while b"\r\n\r\n" not in buf:
        if len(buf) > HEAD_MAX:
            raise ValueError("request head too large")
        data = sock.recv(65536)
        if not data:
            return None, buf
        buf += data
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def parse_request(head: bytes) -> dict:
    lines = head.decode("latin-1").split("\r\n")
    method, target, _ = lines[0].split(" ", 2)
    path, _, query = target.partition("?")
    headers = [(k.strip().lower(), v.strip()) for k, _, v in (line.partition(":") for line in lines[1:])]
    return {"method": method, "path": path, "query": query, "headers": headers}


def read_body(sock: socket.socket, rest: bytes, headers: list) -> tuple[bytes, bytes]:
    length = int(dict(headers).get("content-length", "0"))
    if length > BODY_MAX:
        raise ValueError("body too large")
    while len(rest) < length:
        data = sock.recv(65536)
        if not data:
            raise ConnectionError("body cut")
        rest += data
    return rest[:length], rest[length:]


def response(status: int, headers: list, body: bytes) -> bytes:
    lines = [f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'Status')}", f"content-length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


class Server:
    def __init__(self, config: dict) -> None:
        self.c = config
        self.log = Log(config["log"])
        self.gates = Path(config["gates"])
        self.ids = itertools.count(1)
        self.tls = None
        if config.get("cert"):
            self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls.load_cert_chain(config["cert"], config["key"])
        self.dns_counts: dict[tuple[str, str], int] = {}
        self.dns_lock = threading.Lock()

    # ---- TCP listeners -----------------------------------------------------------------------------------------
    def listen(self, spec: dict) -> None:
        family = socket.AF_INET6 if ":" in spec["addr"] else socket.AF_INET
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((spec["addr"], spec["port"]))
        srv.listen(64)
        self.log.write(kind="listening", listener=spec["name"], addr=spec["addr"], port=spec["port"])
        threading.Thread(target=self._accept, args=(srv, spec), daemon=True).start()

    def _accept(self, srv: socket.socket, spec: dict) -> None:
        while True:
            sock, peer = srv.accept()
            conn = f"{spec['name']}:{next(self.ids)}"
            self.log.write(kind="connect", listener=spec["name"], conn=conn, peer=peer[0], port=spec["port"])
            target = self._upstream if spec["kind"] == "upstream" else self._recorder
            threading.Thread(target=self._guard, args=(target, sock, spec, conn), daemon=True).start()

    def _guard(self, target, sock: socket.socket, spec: dict, conn: str) -> None:
        try:
            sock.settimeout(30)
            if spec.get("tls"):
                sock = self.tls.wrap_socket(sock, server_side=True)
            target(sock, spec, conn)
        except Exception as e:                       # recorded: a decoy that was reached still counts
            self.log.write(kind="conn_error", listener=spec["name"], conn=conn, error=f"{type(e).__name__}: {e}")
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _recorder(self, sock: socket.socket, spec: dict, conn: str) -> None:
        sock.settimeout(3)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 8192:
                part = sock.recv(8192)
                if not part:
                    break
                data += part
        except socket.timeout:
            pass
        text = data[:2048].decode("latin-1")
        found = NONCE.search(text)
        self.log.write(kind="decoy", listener=spec["name"], conn=conn, bytes=len(data), head=text[:512],
                       nonce=found[1] if found else None, tag=found[2] if found else None)
        if data:
            sock.sendall(response(200, [("content-type", "text/plain")], b"decoy\n"))

    def _upstream(self, sock: socket.socket, spec: dict, conn: str) -> None:
        buf = b""
        while True:
            head, buf = read_head(sock, buf)
            if head is None:
                return
            req = parse_request(head)
            body, buf = read_body(sock, buf, req["headers"])
            found = NONCE.search(req["query"])
            nonce, tag = (found[1], found[2]) if found else (None, None)
            record = dict(kind="request", listener=spec["name"], port=spec["port"], conn=conn, nonce=nonce, tag=tag,
                          method=req["method"], path=req["path"], query=req["query"], headers=req["headers"],
                          body_len=len(body))
            path = req["path"]
            if path == "/close-after-read":
                self.log.write(**record, status=None, action="dropped")
                return
            if path.startswith("/redirect/") and path[10:] in ("302", "307", "308"):
                location = f"http://{self.c['private_ip']}/landing?n={nonce}-f"
                self.log.write(**record, status=int(path[10:]), location=location)
                sock.sendall(response(int(path[10:]), [("location", location)], b""))
            elif path == "/stream":
                self.log.write(**record, status=200, action="stream")
                self._stream(sock, conn, nonce)
                return
            else:
                self.log.write(**record, status=200)
                sock.sendall(response(200, [("content-type", "text/plain")], b"ok\n"))
            if dict(req["headers"]).get("connection", "").lower() == "close":
                return

    def _stream(self, sock: socket.socket, conn: str, nonce: str | None) -> None:
        sock.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n")
        first = b"nb-decoy-block-1\n"
        sock.sendall(b"%x\r\n%s\r\n" % (len(first), first))
        self.log.write(kind="block", conn=conn, nonce=nonce, block=1)
        gate = self.gates / f"stream-{nonce}"
        end = time.monotonic() + GATE_WAIT
        while not gate.exists():
            if time.monotonic() > end:
                self.log.write(kind="block", conn=conn, nonce=nonce, block=2, sent=False, why="gate_timeout")
                return
            time.sleep(0.02)
        second = f"DF-MARK-{nonce}\n".encode()
        try:
            sock.sendall(b"%x\r\n%s\r\n0\r\n\r\n" % (len(second), second))
            self.log.write(kind="block", conn=conn, nonce=nonce, block=2, sent=True)
        except OSError as e:
            self.log.write(kind="block", conn=conn, nonce=nonce, block=2, sent=False, why=type(e).__name__)

    # ---- the test DNS ------------------------------------------------------------------------------------------
    def dns(self, spec: dict) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind((spec["addr"], 53))
        self.log.write(kind="listening", listener="dns", addr=spec["addr"], port=53)
        threading.Thread(target=self._dns_loop, args=(srv, spec), daemon=True).start()

    def _dns_loop(self, srv: socket.socket, spec: dict) -> None:
        while True:
            data, peer = srv.recvfrom(4096)
            try:
                reply, record = self.dns_answer(data, spec)
            except (ValueError, IndexError, struct.error) as e:
                self.log.write(kind="dns_error", error=str(e))
                continue
            self.log.write(kind="dns", peer=peer[0], **record)
            srv.sendto(reply, peer)

    def epoch(self) -> str:
        try:
            return (self.gates / "dns-epoch").read_text().strip()
        except OSError:
            return ""

    def dns_answer(self, data: bytes, spec: dict) -> tuple[bytes, dict]:
        qid, _flags, qd = struct.unpack(">HHH", data[:6])
        if qd != 1:
            raise ValueError("one question expected")
        at, labels = 12, []
        while data[at]:
            labels.append(data[at + 1:at + 1 + data[at]].decode("ascii").lower())
            at += 1 + data[at]
        question_end = at + 5
        qtype = struct.unpack(">H", data[at + 1:at + 3])[0]
        name = ".".join(labels)
        question = data[12:question_end]
        record = {"name": name, "qtype": qtype, "epoch": self.epoch(), "answer": None}
        if name != spec["name"]:
            return struct.pack(">HHHHHH", qid, 0x8183, 1, 0, 0, 0) + question, record     # NXDOMAIN
        if qtype != 1:
            return struct.pack(">HHHHHH", qid, 0x8180, 1, 0, 0, 0) + question, record     # no record
        with self.dns_lock:
            key = (record["epoch"], name)
            self.dns_counts[key] = self.dns_counts.get(key, 0) + 1
            answer = spec["first"] if self.dns_counts[key] == 1 else spec["then"]
        record.update(answer=answer, count=self.dns_counts[key])
        rr = struct.pack(">HHHIH", 0xC00C, 1, 1, 0, 4) + socket.inet_aton(answer)
        return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + rr, record


def main(argv: list[str]) -> int:
    with open(argv[0], encoding="utf-8") as f:
        config = json.load(f)
    server = Server(config)
    for spec in config["listeners"]:
        server.listen(spec)
    if config.get("dns"):
        server.dns(config["dns"])
    server.log.write(kind="ready", pid=os.getpid())
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
