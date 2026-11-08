"""Test rig for the connector (block 4): the connector runs in-process on a PASSCRED listener and a judgment socketpair;
the test plays the frontend (link A client) and the core (link B); scripted upstream receivers answer over TLS or
plain TCP on 127.0.0.1. Not a TCB module."""
from __future__ import annotations

import array
import errno
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from connector import canonical as c
from connector.main import Connector
from connector.reader import Native
from connector.upstream import tls_context

OVERFLOWUID = int(Path('/proc/sys/kernel/overflowuid').read_text())
TRUTH = b'SENTINEL-TRUTH-7f3a9c1e'           # the sentinel of the zero-hit test; also the ordinary truth of the rig


# ---- certificates ------------------------------------------------------------------------------------------------------------
@dataclass
class CA:
    directory: Path
    cert: str          # CA certificate (the connector's trust)
    api_cert: str      # server certificate for api.test / auth.test / 127.0.0.1, signed by the CA
    api_key: str
    selfsigned_cert: str   # api.test, not signed by the CA
    selfsigned_key: str

    @classmethod
    def make(cls) -> CA:
        d = Path(tempfile.mkdtemp(prefix='w2-connector-ca-'))
        run = lambda *a: subprocess.run(['openssl', *a], check=True, capture_output=True, cwd=d)
        run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2',
            '-subj', '/CN=w2 test ca', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=keyCertSign,cRLSign')
        run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'api.key', '-out', 'api.csr', '-subj', '/CN=api.test')
        (d / 'san.ext').write_text('subjectAltName=DNS:api.test,DNS:auth.test,IP:127.0.0.1\n')
        run('x509', '-req', '-in', 'api.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'api.pem',
            '-days', '2', '-extfile', 'san.ext')
        run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self.key', '-out', 'self.pem', '-days', '2',
            '-subj', '/CN=api.test', '-addext', 'subjectAltName=DNS:api.test')
        return cls(d, str(d / 'ca.pem'), str(d / 'api.pem'), str(d / 'api.key'), str(d / 'self.pem'), str(d / 'self.key'))


# ---- upstream receivers --------------------------------------------------------------------------------------------------------
@dataclass
class Received:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes
    connection: int        # index of the TCP connection that carried it
    sni: str | None

    def header(self, name: str) -> list[str]:
        return [v for n, v in self.headers if n.lower() == name.lower()]


Reply = Callable[[Received, socket.socket], bytes | None]   # bytes to write (keep the connection), None to close it


def simple_reply(body: bytes = b'ok', status: str = '200 OK', extra: str = '') -> Reply:
    def reply(_: Received, __: socket.socket) -> bytes:
        return (f'HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n{extra}\r\n').encode() + body
    return reply


class Upstream:
    """A raw HTTP/1.1 receiver: records every request as it arrived on the wire; replies by script. ``host`` is the
    address it listens on (127.0.0.1 unless a test places it elsewhere, e.g. in another network namespace)."""

    def __init__(self, tls: ssl.SSLContext | None = None, reply: Reply | None = None, tls11_only: bool = False,
                 port: int = 0, host: str = '127.0.0.1') -> None:
        self.tls, self.reply = tls, reply or simple_reply()
        self.sock = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.requests: list[Received] = []
        self.received_bytes: dict[int, int] = {}   # bytes read on each connection (by its index), whole requests or not
        self.connections = 0
        self.tls_failures = 0
        self.snis: list[str | None] = []
        self.lock = threading.Lock()
        self.stopped = False
        if tls is not None:
            tls.sni_callback = self._sni
        if tls11_only and tls is not None:
            tls.minimum_version = ssl.TLSVersion.TLSv1
            tls.maximum_version = ssl.TLSVersion.TLSv1_1
            tls.set_ciphers('DEFAULT:@SECLEVEL=0')
        self._last_sni: str | None = None
        threading.Thread(target=self._accept, daemon=True).start()

    def _sni(self, sock: Any, name: str | None, ctx: Any) -> None:
        self._last_sni = name

    def _accept(self) -> None:
        while not self.stopped:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                self.connections += 1
                index = self.connections
            threading.Thread(target=self._serve, args=(conn, index), daemon=True).start()

    def _serve(self, conn: socket.socket, index: int) -> None:
        conn.settimeout(10)
        sni = None
        try:
            if self.tls is not None:
                self._last_sni = None
                try:
                    conn = self.tls.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    with self.lock:
                        self.tls_failures += 1
                    conn.close()
                    return
                sni = self._last_sni
            with self.lock:
                self.snis.append(sni)
            buf = b''
            while True:
                while b'\r\n\r\n' not in buf:
                    piece = self._recv(conn, index)
                    if not piece:
                        return
                    buf += piece
                head, _, buf = buf.partition(b'\r\n\r\n')
                lines = head.decode('latin-1').split('\r\n')
                method, target, version = lines[0].split(' ', 2)
                headers = [tuple(l.split(': ', 1)) for l in lines[1:]]
                length = int(next((v for n, v in headers if n.lower() == 'content-length'), '0'))
                while len(buf) < length:
                    piece = self._recv(conn, index)
                    if not piece:
                        return
                    buf += piece
                body, buf = buf[:length], buf[length:]
                received = Received(method, target, version, headers, body, index, sni)   # type: ignore[arg-type]
                with self.lock:
                    self.requests.append(received)
                out = self.reply(received, conn)
                if out is None:
                    return
                conn.sendall(out)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _recv(self, conn: socket.socket, index: int) -> bytes:
        piece = conn.recv(65536)
        with self.lock:
            self.received_bytes[index] = self.received_bytes.get(index, 0) + len(piece)
        return piece

    def close(self) -> None:
        self.stopped = True
        self.sock.close()


def server_tls(ca: CA, cert: str | None = None, key: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert or ca.api_cert, key or ca.api_key)
    return ctx


# ---- the connector under test ---------------------------------------------------------------------------------------------------
class StubPolicy:
    """Resolves every name to the receiver's loopback address and allows it; counts resolutions (C-32). Mirrors the
    real Policy's methods (plan engine-v3-private-net): ``allowed`` and ``refusal`` judge a resolution list against the
    ALLOW frame's named list, ``never_connect`` is the first gate alone, for an IP literal at validation; no NAT64
    prefix is configured (``nat64``, asked of an IP literal at validation)."""

    def __init__(self, address: str = '127.0.0.1', allow: bool = True) -> None:
        self.address, self.allow, self.resolves = address, allow, 0
        self.nat64: tuple[Any, ...] = ()

    def resolve(self, host: bytes, is_ip: bool, port: int) -> list[str]:
        self.resolves += 1
        return [host.decode('ascii')] if is_ip else [self.address]

    def allowed(self, addresses: list[str], named: tuple[Any, ...] = ()) -> bool:
        return self.allow

    def refusal(self, addresses: list[str], named: tuple[Any, ...] = ()) -> bytes | None:
        return None if self.allow else b'clause'

    def never_connect(self, address: str) -> bool:
        return not self.allow


class Redirect:
    """Unit tests reach no network. Installed on socket.socket (pytest monkeypatch), so the connector's own code runs
    as it is: every TCP connect is recorded in ``attempts`` by the address the caller asked for; an address in ``to``
    (address text -> port) is carried to that receiver on 127.0.0.1, any other is refused at once without a packet.
    The caller never learns of the detour: the address it asked for is the one it recorded."""

    def __init__(self, monkeypatch: Any, to: dict[str, int] | None = None) -> None:
        self.to = dict(to or {})
        self.attempts: list[str] = []
        outer = self

        class Redirecting(socket.socket):
            def connect(self, address: Any) -> None:
                if self.family in (socket.AF_INET, socket.AF_INET6) and self.type == socket.SOCK_STREAM:
                    asked = str(address[0])
                    outer.attempts.append(asked)
                    port = outer.to.get(asked)
                    if port is None:
                        raise ConnectionRefusedError(errno.ECONNREFUSED, 'no receiver for this address in the test')
                    target = '127.0.0.1' if self.family == socket.AF_INET else '::ffff:127.0.0.1'
                    return super().connect((target, port))
                return super().connect(address)

        monkeypatch.setattr(socket, 'socket', Redirecting)


def named_field(named: Iterable[str]) -> bytes:
    """The named field of ALLOW and ALLOW_NOCRED (plan engine-v3-private-net 接口约定): a list of canonical prefix texts
    such as 10.0.0.5/32; the empty list names nothing."""
    return c.pack_list([n.encode('ascii') for n in named])


@dataclass
class Judge:
    seq: int
    uid: int
    method: bytes
    scheme: bytes
    host: bytes
    port: int
    path: bytes
    query: bytes
    headers: list[tuple[bytes, bytes]]
    stripped: list[bytes]
    body_kind: bytes
    form_keys: list[bytes]
    body_len: int
    memfd: int


class Rig:
    def __init__(self, tmp_path: Path, library: Path, ca: CA, **kw: Any) -> None:
        self.path = tmp_path / 'proxy.sock'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)      # the spawner's job (S-01), before listen
        self.listener.listen(64)
        self.core, connector_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.core.settimeout(5)
        self.logs: list[dict[str, Any]] = []
        self.fatal: list[str] = []
        self.policy = kw.pop('policy', StubPolicy())
        self.native = Native(library)
        self.connector = Connector(self.listener, connector_end, os.getuid(), 'e:1', self.native, self.policy,
                                   kw.pop('tls', tls_context(ca.cert)), OVERFLOWUID, on_fatal=self.fatal.append,
                                   log=lambda event, **f: self.logs.append({'event': event, **f}),
                                   connect_timeout=kw.pop('connect_timeout', 2.0), read_timeout=kw.pop('read_timeout', 5.0))
        self._parser = c.FrameParser(c.LIMITS.frame_bd, c.LINK_B_TO_CORE)
        self._fds: list[int] = []
        self._frames: list[tuple[int, list[bytes]]] = []
        self._last_seq = 0
        self.connector.start()

    def client(self) -> Client:
        return Client(self.path)

    def close(self) -> None:
        self.connector.stop()
        self.core.close()
        for fd in self._fds:
            os.close(fd)

    # ---- the core's side of the judgment port ----
    def _pump(self, timeout: float) -> bool:
        self.core.settimeout(timeout)
        try:
            data, ancillary, _, _ = self.core.recvmsg(1 << 20, socket.CMSG_SPACE(16 * 4))
        except socket.timeout:
            return False
        if not data:
            return False
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array('i')
                fds.frombytes(payload[:len(payload) - len(payload) % 4])
                self._fds += list(fds)
        self._frames += self._parser.feed(data)
        return True

    def core_frame(self, timeout: float = 5.0) -> tuple[int, list[bytes]] | None:
        deadline = time.monotonic() + timeout
        while not self._frames:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._pump(remaining):
                return None
        return self._frames.pop(0)

    def judge(self, timeout: float = 5.0) -> Judge | None:
        got = self.core_frame(timeout)
        if got is None:
            return None
        kind, f = got
        assert kind == c.JUDGE, kind
        assert self._fds, 'JUDGE without its memfd'
        memfd = self._fds.pop(0)
        seq = c.read_uint(f[0], 8)
        assert seq > self._last_seq, (seq, self._last_seq)     # what the core checks (K-36): the rig checks it too
        self._last_seq = seq
        items = c.unpack_list(f[8])
        return Judge(c.read_uint(f[0], 8), c.read_uint(f[1], 4), f[2], f[3], f[4], c.read_uint(f[5], 2),
                     f[6], f[7], list(zip(items[0::2], items[1::2])), c.unpack_list(f[9]), f[10], c.unpack_list(f[11]),
                     c.read_uint(f[12], 8), memfd)

    def send_core(self, kind: int, fields: list[bytes]) -> None:
        self.core.sendall(c.pack_frame(kind, fields))

    def allow(self, seq: int, placement: int = c.PLACE_BEARER, word: bytes | None = None, truth: bytes = TRUTH,
              truth_b: bytes = b'', account: bytes = b'alice', named: Iterable[str] = ()) -> None:
        """SPEC 3.2 ALLOW: the bearer placement carries its registered word (Bearer by default), Basic its password;
        the last field is the covering cell's named non-global addresses (K-59)."""
        if word is None:
            word = b'Bearer' if placement == c.PLACE_BEARER else b''
        self.send_core(c.ALLOW, [c.u64(seq), c.u8(placement), word, truth, truth_b, account, named_field(named)])

    def allow_nocred(self, seq: int, account_destination: bool = False, named: Iterable[str] = ()) -> None:
        self.send_core(c.ALLOW_NOCRED, [c.u64(seq), c.u8(1 if account_destination else 0), named_field(named)])

    def deny(self, seq: int, reason: int = 2) -> None:
        self.send_core(c.DENY, [c.u64(seq), c.u8(reason)])

    def revoke(self, key_kind: int, key: bytes, account: bytes, everyone: bool = False) -> None:
        self.send_core(c.REVOKE, [c.u8(key_kind), key, account, c.u8(2 if everyone else 1)])

    def report(self, timeout: float = 5.0) -> tuple[int, int, int] | None:
        """The next REPORT as (seq, result, status); other frames are kept for later."""
        got = self.core_frame(timeout)
        if got is None:
            return None
        kind, f = got
        assert kind == c.REPORT, (kind, f)
        return c.read_uint(f[0], 8), c.read_uint(f[1], 1), c.read_uint(f[2], 2)

    def withdraw(self, timeout: float = 5.0) -> int | None:
        got = self.core_frame(timeout)
        if got is None:
            return None
        kind, f = got
        assert kind == c.WITHDRAW, (kind, f)
        return c.read_uint(f[0], 8)

    def events(self, name: str) -> list[dict[str, Any]]:
        return [e for e in self.logs if e['event'] == name]


@dataclass
class Response:
    category: int
    status: int
    headers: list[tuple[bytes, bytes]]
    body: bytes = b''
    ended: bool = False
    closed: bool = False          # the connection closed before RESP_END (a cut response)

    def header(self, name: bytes) -> list[bytes]:
        return [v for n, v in self.headers if n == name]


class Client:
    """The frontend's side of one proxy connection."""

    def __init__(self, path: Path) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(str(path))
        self.sock.settimeout(5)
        self.parser = c.FrameParser(c.LIMITS.frame_a, c.LINK_A_OUT)
        self.frames: list[tuple[int, list[bytes]]] = []

    def request(self, method: bytes = b'GET', scheme: bytes = b'https', host: bytes = b'api.test', port: int = 443,
                path: bytes = b'/', query: bytes = b'', headers: tuple[tuple[bytes, bytes], ...] = (), body: bytes = b'') -> None:
        items: list[bytes] = []
        for name, value in headers:
            items += [name, value]
        self.raw(c.pack_frame(c.REQUEST, [method, scheme, host, c.u16(port), path, query, c.pack_list(items), body]))

    def raw(self, data: bytes) -> None:
        self.sock.sendall(data)

    def frame(self, timeout: float = 5.0) -> tuple[int, list[bytes]] | None:
        """The next frame from the connector, None at EOF or timeout."""
        self.sock.settimeout(timeout)
        while not self.frames:
            try:
                data = self.sock.recv(1 << 20)
            except socket.timeout:
                return None
            if not data:
                return None
            self.frames += self.parser.feed(data)
        return self.frames.pop(0)

    def head(self, timeout: float = 5.0) -> Response | None:
        got = self.frame(timeout)
        if got is None:
            return None
        kind, f = got
        assert kind == c.RESP_HEAD, (kind, f)
        items = c.unpack_list(f[2])
        return Response(c.read_uint(f[0], 1), c.read_uint(f[1], 2), list(zip(items[0::2], items[1::2])))

    def response(self, timeout: float = 5.0) -> Response | None:
        r = self.head(timeout)
        if r is None:
            return None
        while True:
            got = self.frame(timeout)
            if got is None:
                r.closed = True
                return r
            kind, f = got
            if kind == c.RESP_CHUNK:
                r.body += f[0]
            elif kind == c.RESP_END:
                r.ended = True
                return r

    def eof(self, timeout: float = 5.0) -> bool:
        """True when the connector closed the connection (nothing else arrives)."""
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(1) == b''
        except socket.timeout:
            return False
        except OSError:
            return True

    def close(self) -> None:
        self.sock.close()
