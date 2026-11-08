"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The attack side's two transports, standard library only (it runs inside the cell from the runtime seed):
ProxyConn speaks the canonical form (engine-v3 SPEC-canonical-form.md section 2, link A) to the row's proxy port;
DirectConn speaks HTTP/1.1 straight to the destination, for the undefended configuration (METHOD rule 3). Both yield
the same events, so one attack script serves both configurations.
"""
from __future__ import annotations

import socket
import ssl
import struct
import time

REQUEST, RESP_HEAD, RESP_CHUNK, RESP_END = 0x01, 0x11, 0x12, 0x13
CATEGORIES = {1: 'remote', 2: 'refused', 3: 'transport', 4: 'unknown'}
FRAME_MAX = 64 * 1024 * 1024 + 128 * 1024
PROXY_PATH = '/run/w2/proxy.sock'
BODY_KEEP = 4096


def field(data: bytes) -> bytes:
    return struct.pack('>I', len(data)) + data


def pack_list(items: list[bytes]) -> bytes:
    return struct.pack('>I', len(items)) + b''.join(field(i) for i in items)


def unpack_list(data: bytes) -> list[bytes]:
    count, at, out = struct.unpack_from('>I', data, 0)[0], 4, []
    for _ in range(count):
        n = struct.unpack_from('>I', data, at)[0]
        at += 4
        if at + n > len(data):
            raise ValueError('list item past its end')
        out.append(data[at:at + n])
        at += n
    if at != len(data):
        raise ValueError('bytes after the last list item')
    return out


def pack_frame(kind: int, fields: list[bytes]) -> bytes:
    body = bytes([kind]) + b''.join(field(f) for f in fields)
    return struct.pack('>I', len(body)) + body


def split_fields(body: bytes) -> list[bytes]:
    out, at = [], 0
    while at < len(body):
        n = struct.unpack_from('>I', body, at)[0]
        at += 4
        if at + n > len(body):
            raise ValueError('field past the frame end')
        out.append(body[at:at + n])
        at += n
    return out


def request_frame(req: dict) -> bytes:
    """req: method, scheme, host, port, path, query (str or None), headers [(name, value)], body (bytes)."""
    items = [x.encode('latin-1') for pair in req['headers'] for x in pair]
    return pack_frame(REQUEST, [req['method'].encode('ascii'), req['scheme'].encode('ascii'),
                                req['host'].encode('ascii'), struct.pack('>H', req['port']),
                                req['path'].encode('ascii'), (req['query'] or '').encode('ascii'),
                                pack_list(items), req['body']])


class ProxyConn:
    """One connection to the row's proxy port: one request at a time, responses as events."""

    def __init__(self, path: str = PROXY_PATH, timeout: float = 10.0) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.buf = b''
        self.address = None

    def send(self, req: dict) -> None:
        self.sock.sendall(request_frame(req))

    def event(self, timeout: float) -> tuple:
        """('head', category, status, headers) | ('chunk', bytes) | ('end',) | ('closed',) | ('timeout',)."""
        deadline = time.monotonic() + timeout
        while True:
            if len(self.buf) >= 4:
                n = struct.unpack_from('>I', self.buf, 0)[0]
                if not 0 < n <= FRAME_MAX:
                    raise ValueError('response frame length out of range')
                if len(self.buf) >= 4 + n:
                    body, self.buf = self.buf[4:4 + n], self.buf[4 + n:]
                    kind, fields = body[0], split_fields(body[1:])
                    if kind == RESP_HEAD:
                        items = unpack_list(fields[2])
                        headers = [(items[i].decode('latin-1'), items[i + 1].decode('latin-1'))
                                   for i in range(0, len(items), 2)]
                        return ('head', CATEGORIES.get(fields[0][0], 'unknown-category'),
                                struct.unpack('>H', fields[1])[0], headers)
                    if kind == RESP_CHUNK:
                        return ('chunk', fields[0])
                    if kind == RESP_END:
                        return ('end',)
                    raise ValueError(f'unexpected frame kind {kind:#x}')
            left = deadline - time.monotonic()
            if left <= 0:
                return ('timeout',)
            self.sock.settimeout(left)
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                return ('timeout',)
            except OSError:
                return ('closed',)
            if not data:
                return ('closed',)
            self.buf += data

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class DirectConn:
    """HTTP/1.1 to one destination, kept alive; the host is resolved by the system resolver at each new connection."""

    def __init__(self, scheme: str, host: str, port: int, ca_file: str | None, timeout: float = 10.0) -> None:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        self.address = infos[0][4][0]
        raw = socket.create_connection((self.address, port), timeout=timeout)
        if scheme == 'https':
            ctx = ssl.create_default_context(cafile=ca_file)
            self.sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            self.sock = raw
        self.host, self.port, self.scheme = host, port, scheme
        self.buf, self.state = b'', None

    def send(self, req: dict) -> None:
        target = req['path'] + ('?' + req['query'] if req['query'] else '')
        default = 443 if req['scheme'] == 'https' else 80
        host = req['host'] if req['port'] == default else f"{req['host']}:{req['port']}"
        lines = [f"{req['method']} {target} HTTP/1.1", f'host: {host}']
        lines += [f'{k}: {v}' for k, v in req['headers']]
        if req['body'] or req['method'] not in ('GET', 'HEAD'):
            lines.append(f"content-length: {len(req['body'])}")
        self.sock.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1') + req['body'])
        self.state = ('head',)

    def _fill(self, deadline: float) -> bool:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError
        self.sock.settimeout(left)
        try:
            data = self.sock.recv(65536)
        except socket.timeout as e:
            raise TimeoutError from e
        except OSError:
            return False
        self.buf += data
        return bool(data)

    def event(self, timeout: float) -> tuple:
        deadline = time.monotonic() + timeout
        try:
            while True:
                kind = self.state[0] if self.state else None
                if kind == 'head':
                    at = self.buf.find(b'\r\n\r\n')
                    if at >= 0:
                        head, self.buf = self.buf[:at].decode('latin-1'), self.buf[at + 4:]
                        lines = head.split('\r\n')
                        status = int(lines[0].split()[1])
                        headers = [(k.strip().lower(), v.strip()) for k, _, v in
                                   (line.partition(':') for line in lines[1:])]
                        names = dict(headers)
                        if 'chunked' in names.get('transfer-encoding', ''):
                            self.state = ('chunked',)
                        else:
                            self.state = ('length', int(names.get('content-length', '0')))
                        return ('head', 'remote', status, headers)
                elif kind == 'length':
                    left = self.state[1]
                    if left == 0:
                        self.state = None
                        return ('end',)
                    if self.buf:
                        take, self.buf = self.buf[:left], self.buf[left:]
                        self.state = ('length', left - len(take))
                        return ('chunk', take)
                elif kind == 'chunked':
                    at = self.buf.find(b'\r\n')
                    if at >= 0:
                        size = int(self.buf[:at].split(b';')[0], 16)
                        if size == 0:
                            if len(self.buf) >= at + 4:
                                self.buf, self.state = self.buf[at + 4:], None
                                return ('end',)
                        elif len(self.buf) >= at + 2 + size + 2:
                            data = self.buf[at + 2:at + 2 + size]
                            self.buf = self.buf[at + 2 + size + 2:]
                            return ('chunk', data)
                else:
                    return ('closed',)
                if not self._fill(deadline):
                    return ('closed',)
        except TimeoutError:
            return ('timeout',)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def collect(conn, timeout: float, *, first_chunk_only: bool = False, into: dict | None = None) -> dict:
    """Read one response (or its rest, given ``into``) until RESP_END, close or timeout."""
    out = into if into is not None else {'category': None, 'status': None, 'reason': None, 'headers': [],
                                         'body': b'', 'chunks': 0, 'ended': False, 'closed': False,
                                         'timeout': False}
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        ev = conn.event(left) if left > 0 else ('timeout',)
        if ev[0] == 'head':
            out['category'], out['status'], out['headers'] = ev[1], ev[2], ev[3]
            out['reason'] = next((v for k, v in ev[3] if k.lower() == 'x-engine-reason'), None)
            out['head_at'] = time.time()
        elif ev[0] == 'chunk':
            out['body'] += ev[1]
            out['chunks'] += 1
            out.setdefault('chunk_at', []).append(time.time())
            if first_chunk_only:
                return out
        else:
            out[{'end': 'ended', 'closed': 'closed', 'timeout': 'timeout'}[ev[0]]] = True
            return out
