"""The in-cell HTTP frontend (agent-rm-model 4.2 代理口的形状, 6.3 TLS 行; build plan 工程项 12; validation.md F-01 to F-04).

Not in the TCB. It runs inside the cell as uid_i under the agent's seccomp policy, started by the child before the agent
with  argv: [options...] <proxy socket path> <port> <ready file>  (child.c start_helper). mitmproxy listens on
127.0.0.1:<port> in regular proxy mode, terminates TLS with the execution's CA, and an addon redirects every request to
the translator, a plain HTTP/1.1 server on 127.0.0.1 in the same process; the translator turns each fully-read request
into one canonical REQUEST frame on the row's proxy path (SPEC-canonical-form.md §3.1), and turns the RESP_* frames back
into a chunked HTTP/1.1 response that mitmproxy streams to the client. Nothing here reads policy or holds a credential:
the connector validates the frame as untrusted input (3.8 TCB 的输入行), so an agent speaking canonical form to the path
directly is equivalent to going through here.

Third-party: mitmproxy (and what it brings). Standard library otherwise.
"""
from __future__ import annotations

import argparse
import asyncio
import http.server
import logging
import os
import socket
import socketserver
import struct
import sys
import threading
from pathlib import Path

from mitmproxy import http as mhttp
from mitmproxy import tcp as mtcp
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

LOG = logging.getLogger('engine-frontend')
H_SCHEME, H_HOST, H_PORT = 'x-engine-orig-scheme', 'x-engine-orig-host', 'x-engine-orig-port'
# what the frontend owns or must not forward (SPEC §4 条款 3 forbids them in the frame; the translator drops them first)
DROPPED = frozenset({H_SCHEME, H_HOST, H_PORT, 'host', 'content-length', 'transfer-encoding', 'connection', 'keep-alive',
                     'te', 'trailer', 'upgrade', 'expect', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate'})
REQUEST, RESP_HEAD, RESP_CHUNK, RESP_END = 0x01, 0x11, 0x12, 0x13
CAT_REMOTE, CAT_REFUSED, CAT_TRANSPORT, CAT_UNKNOWN = 1, 2, 3, 4
STATUS_FOR = {CAT_REFUSED: (403, 'Forbidden'), CAT_TRANSPORT: (502, 'Bad Gateway'), CAT_UNKNOWN: (502, 'Bad Gateway')}
FRAME_LIMIT = 64 * 1024 * 1024 + 128 * 1024
BODY_LIMIT = 64 * 1024 * 1024


# ---- the wire (SPEC §2), kept local so the frontend needs nothing from the TCB tree ----
def u32(n: int) -> bytes:
    return struct.pack('>I', n)


def pack_frame(kind: int, fields: list[bytes]) -> bytes:
    payload = bytes([kind]) + b''.join(u32(len(f)) + f for f in fields)
    return u32(len(payload)) + payload


def pack_list(items: list[bytes]) -> bytes:
    return u32(len(items)) + b''.join(u32(len(i)) + i for i in items)


def unpack_fields(payload: bytes) -> list[bytes]:
    fields, pos = [], 0
    while pos < len(payload):
        n = int.from_bytes(payload[pos:pos + 4], 'big')
        fields.append(payload[pos + 4:pos + 4 + n])
        pos += 4 + n
    return fields


def unpack_list(data: bytes) -> list[bytes]:
    count, pos, out = int.from_bytes(data[:4], 'big'), 4, []
    for _ in range(count):
        n = int.from_bytes(data[pos:pos + 4], 'big')
        out.append(data[pos + 4:pos + 4 + n])
        pos += 4 + n
    return out


class ProxyPath:
    """Connections to the row's proxy path, one per in-flight request, kept for reuse after a complete response (the
    connector keeps its upstream connections per fd, so reusing ours keeps upstream keep-alive working)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._idle: list[socket.socket] = []
        self._lock = threading.Lock()

    def take(self) -> socket.socket:
        with self._lock:
            if self._idle:
                return self._idle.pop()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.path)
        return s

    def give_back(self, s: socket.socket) -> None:
        with self._lock:
            self._idle.append(s)


def read_frame(sock: socket.socket) -> tuple[int, list[bytes]] | None:
    head = b''
    while len(head) < 4:
        piece = sock.recv(4 - len(head))
        if not piece:
            return None
        head += piece
    length = int.from_bytes(head, 'big')
    if length < 1 or length > FRAME_LIMIT:
        return None
    body = bytearray()
    while len(body) < length:
        piece = sock.recv(min(65536, length - len(body)))
        if not piece:
            return None
        body += piece
    return body[0], unpack_fields(bytes(body[1:]))


class Translator(http.server.BaseHTTPRequestHandler):
    """One request from mitmproxy → one REQUEST frame → RESP_* frames → one chunked HTTP/1.1 response."""

    protocol_version = 'HTTP/1.1'
    proxy_path: ProxyPath                       # set on the server class

    def log_message(self, fmt, *args):          # mitmproxy's log is enough, and stderr is /dev/null in the cell
        pass

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (ConnectionError, socket.timeout):
            self.close_connection = True

    def _canonical_request(self) -> bytes | None:
        scheme = (self.headers.get(H_SCHEME) or '').strip().lower()
        host = (self.headers.get(H_HOST) or '').strip().lower().rstrip('.')
        port_text = (self.headers.get(H_PORT) or '').strip()
        if scheme not in ('http', 'https') or not host or not port_text.isdigit():
            return None
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        try:
            host_bytes = host.encode('idna') if any(ord(c) > 0x7E for c in host) else host.encode('ascii')
        except UnicodeError:
            return None
        target = self.path.encode('latin-1')
        path, _, query = target.partition(b'?')
        if not path.startswith(b'/'):
            path = b'/' + path
        items: list[bytes] = []
        for name, value in self.headers.items():
            lowered = name.lower()
            if lowered in DROPPED or lowered.startswith('proxy-'):
                continue
            items += [lowered.encode('latin-1'), value.encode('latin-1')]
        if 'chunked' in (self.headers.get('Transfer-Encoding') or '').lower():   # defensive: the addon sends a length
            body = self._read_chunked()
            if body is None:
                return None
        else:
            length = int(self.headers.get('Content-Length') or 0)
            if length > BODY_LIMIT:
                return None
            body = self.rfile.read(length) if length else b''
            if len(body) != length:
                return None
        return pack_frame(REQUEST, [self.command.encode('ascii'), scheme.encode(), host_bytes,
                                    struct.pack('>H', int(port_text)), path, query, pack_list(items), body])

    def _read_chunked(self) -> bytes | None:
        body = bytearray()
        while True:
            line = self.rfile.readline(1024)
            size_text = line.split(b';', 1)[0].strip()
            if not size_text:
                return None
            size = int(size_text, 16)
            if size == 0:
                while self.rfile.readline(65536) not in (b'\r\n', b'\n', b''):   # trailers, discarded
                    pass
                return bytes(body)
            if len(body) + size > BODY_LIMIT:
                return None
            piece = self.rfile.read(size)
            if len(piece) != size or self.rfile.readline(2) not in (b'\r\n', b'\n'):
                return None
            body += piece

    def do_ANY(self) -> None:
        frame = self._canonical_request()
        if frame is None:
            self.send_error(400, 'request cannot be translated')
            self.close_connection = True
            return
        try:
            sock = self.server.proxy_path.take()
        except OSError as e:
            LOG.warning('proxy path unreachable: %s', type(e).__name__)
            self.send_error(502, 'proxy path unreachable')
            self.close_connection = True
            return
        complete = False
        try:
            sock.sendall(frame)
            head = read_frame(sock)
            if head is None or head[0] != RESP_HEAD:
                LOG.warning('no response head from the connector (%s)', 'closed' if head is None else 'kind %#x' % head[0])
                self.send_error(502, 'no response from the connector')
                self.close_connection = True
                return
            category, status = head[1][0][0], int.from_bytes(head[1][1], 'big')
            raw_headers = unpack_list(head[1][2])
            headers = list(zip(raw_headers[0::2], raw_headers[1::2]))
            if category != CAT_REMOTE:
                status, reason = STATUS_FOR.get(category, (502, 'Bad Gateway'))
            else:
                reason = ''
            bodiless = self.command == 'HEAD' or status in (204, 304) or 100 <= status < 200
            self.send_response_only(status, reason or None)          # buffered with the headers, flushed by end_headers
            for name, value in headers:
                self.send_header(name.decode('latin-1'), value.decode('latin-1'))
            if not bodiless:
                self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            while True:
                got = read_frame(sock)
                if got is None:                                     # cut before RESP_END: the client sees it cut too
                    self.close_connection = True
                    return
                kind, fields = got
                if kind == RESP_CHUNK:
                    if fields[0] and not bodiless:
                        self.wfile.write(b'%x\r\n%s\r\n' % (len(fields[0]), fields[0]))
                        self.wfile.flush()
                elif kind == RESP_END:
                    if not bodiless:
                        self.wfile.write(b'0\r\n\r\n')
                    self.wfile.flush()
                    complete = True
                    return
                else:
                    self.close_connection = True
                    return
        except OSError as e:
            LOG.warning('exchange failed: %s', type(e).__name__)
            self.close_connection = True
        finally:
            if complete:
                self.server.proxy_path.give_back(sock)
            else:
                sock.close()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_TRACE = do_ANY

    def __getattr__(self, name: str):
        if name.startswith('do_'):                                  # any token method the client used (SPEC §4)
            return self.do_ANY
        raise AttributeError(name)


class TranslatorServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class EngineFront:
    """The mitmproxy addon: redirect to the translator, stream responses, refuse non-HTTP tunnels."""

    def __init__(self, translator_port: int, proxy_path: str, ready_file: str, listen_port: int) -> None:
        self.translator_port, self.proxy_path, self.ready_file, self.listen_port = translator_port, proxy_path, ready_file, listen_port
        self.server: TranslatorServer | None = None

    def running(self) -> None:
        TranslatorServer.proxy_path = ProxyPath(self.proxy_path)
        self.server = TranslatorServer(('127.0.0.1', self.translator_port), Translator)
        threading.Thread(target=self.server.serve_forever, daemon=True, name='translator').start()
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.settimeout(5)
            probe.connect(('127.0.0.1', self.listen_port))          # the proxy listener is up before 'ready' is said
        finally:
            probe.close()
        fd = os.open(self.ready_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)   # the child waits for this file
        os.close(fd)
        LOG.info('ready: proxy on 127.0.0.1:%d, translator on 127.0.0.1:%d', self.listen_port, self.translator_port)

    def request(self, flow: mhttp.HTTPFlow) -> None:
        r = flow.request
        r.headers[H_SCHEME], r.headers[H_HOST], r.headers[H_PORT] = r.scheme, r.pretty_host, str(r.port)
        r.scheme, r.host, r.port = 'http', '127.0.0.1', self.translator_port
        # the body is complete here: hand it to the translator with a length, never chunked (F-03)
        r.headers.pop('transfer-encoding', None)
        r.headers['content-length'] = str(len(r.raw_content or b''))

    def responseheaders(self, flow: mhttp.HTTPFlow) -> None:
        flow.response.stream = True                                 # SSE and chunked bodies go through as they arrive

    def tcp_start(self, flow: mtcp.TCPFlow) -> None:
        flow.kill()                                                 # a CONNECT whose first bytes are not TLS (F-02)


def prepare_ca(confdir: Path, ca_dir: Path | None) -> None:
    """mitmproxy reads <confdir>/mitmproxy-ca.pem (key then certificate). With --ca-dir the execution's CA from the
    read-only cell files is copied in; without it mitmproxy generates one (tests)."""
    confdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ca_dir is None:
        return
    combined = (ca_dir / 'ca.key').read_bytes() + (ca_dir / 'ca.pem').read_bytes()
    target = confdir / 'mitmproxy-ca.pem'
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(combined)


async def serve(args: argparse.Namespace) -> None:
    opts = Options(listen_host='127.0.0.1', listen_port=args.port, confdir=str(args.confdir), mode=['regular'])
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.options.update(connection_strategy='lazy', upstream_cert=False, http2=False, ssl_insecure=False)
    master.addons.add(EngineFront(args.translator_port, args.proxy_socket, args.ready_file, args.port))
    await master.run()


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog='engine-frontend')
    p.add_argument('--ca-dir', type=Path, default=None, help='directory with ca.pem and ca.key (the cell files)')
    p.add_argument('--confdir', type=Path, default=Path('/tmp/.w2-frontend'))
    p.add_argument('--translator-port', type=int, default=0)
    p.add_argument('--log-level', default='WARNING')
    p.add_argument('proxy_socket')
    p.add_argument('port', type=int)
    p.add_argument('ready_file')
    args = p.parse_args(argv)
    if not args.translator_port:
        args.translator_port = args.port + 1
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.WARNING), stream=sys.stderr)
    LOG.setLevel(logging.INFO)
    prepare_ca(args.confdir, args.ca_dir)
    asyncio.run(serve(args))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
