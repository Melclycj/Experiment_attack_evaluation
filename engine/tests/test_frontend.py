"""The in-cell HTTP frontend (frontend-go/ or frontend/engine_frontend.py; validation.md F-02, F-03, F-04, C-31) on the
host: the frontend in a subprocess, the real connector in-process (the rig) on the proxy path, a TLS receiver as the
upstream, curl and http.client as the agent's clients. The test plays the core and allows everything except deny.test.
Skipped when the mitmproxy venv is absent."""
from __future__ import annotations

import functools
import http.client
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Iterator

import pytest

from connector import canonical as c
from connector_rig import CA, Received, Rig, Upstream, server_tls, simple_reply

ENGINE = Path(__file__).resolve().parents[1]
FRONTEND_PYTHON = Path(os.environ.get('W2_FRONTEND_PYTHON', Path.home() / '.venvs/engine-v2-frontend/bin/python'))
# Which frontend runs: 'go' (frontend-go/, the default; built on first use unless W2_FRONTEND_GO_BIN names a binary) or
# 'python' (frontend/engine_frontend.py). The venv is needed either way: make_ca_pool.py runs in it.
FRONTEND_IMPL = os.environ.get('W2_FRONTEND_IMPL', 'go')
pytestmark = pytest.mark.skipif(not FRONTEND_PYTHON.exists(), reason='mitmproxy venv not found')
_go_build: list[tempfile.TemporaryDirectory] = []   # removed when the test process exits


@functools.cache
def frontend_command() -> tuple[str, ...]:
    if FRONTEND_IMPL == 'python':
        return str(FRONTEND_PYTHON), '-I', '-B', str(ENGINE / 'frontend/engine_frontend.py')
    assert FRONTEND_IMPL == 'go', FRONTEND_IMPL
    if os.environ.get('W2_FRONTEND_GO_BIN'):
        return (os.environ['W2_FRONTEND_GO_BIN'],)
    _go_build.append(tempfile.TemporaryDirectory(prefix='w2-frontend-go-'))
    binary = Path(_go_build[-1].name) / 'engine-frontend'
    subprocess.run([shutil.which('go') or '/usr/local/go/bin/go', 'build', '-trimpath', '-buildvcs=false', '-o', str(binary), '.'],
                   cwd=ENGINE / 'frontend-go', env={**os.environ, 'CGO_ENABLED': '0'}, check=True)
    return (str(binary),)


class Core(threading.Thread):
    """Answers the connector on the rig's core end: ALLOW_NOCRED for everything but deny.test; records what it saw."""

    def __init__(self, rig: Rig) -> None:
        super().__init__(daemon=True)
        self.rig, self.judges, self.reports, self.stop = rig, [], [], False

    def run(self) -> None:
        while not self.stop:
            got = self.rig.core_frame(timeout=0.3)
            if got is None:
                continue
            kind, f = got
            if kind == c.JUDGE:
                self.rig._fds.pop(0) if self.rig._fds else None
                j = dict(seq=c.read_uint(f[0], 8), method=f[2], scheme=f[3], host=f[4], port=c.read_uint(f[5], 2),
                         path=f[6], query=f[7], headers=c.unpack_list(f[8]), body_len=c.read_uint(f[12], 8))
                self.judges.append(j)
                if j['host'] == b'deny.test':
                    self.rig.deny(j['seq'], 2)
                else:
                    self.rig.allow_nocred(j['seq'])
            elif kind == c.REPORT:
                self.reports.append((c.read_uint(f[0], 8), c.read_uint(f[1], 1), c.read_uint(f[2], 2)))


class Frontend:
    def __init__(self, rig: Rig, tmp: Path, ca_dir: Path | None = None) -> None:
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.confdir, ready = tmp / 'conf', tmp / 'ready'
        self.cafile = (ca_dir / 'ca.pem') if ca_dir else self.confdir / 'mitmproxy-ca-cert.pem'
        self.log = (tmp / 'frontend.log').open('wb')
        extra = ['--ca-dir', str(ca_dir)] if ca_dir else []
        self.proc = subprocess.Popen([*frontend_command(),
                                      '--confdir', str(self.confdir), '--log-level', 'INFO', *extra, str(rig.path), str(self.port), str(ready)],
                                     stdout=self.log, stderr=subprocess.STDOUT)
        self.rig, self.logfile = rig, tmp / 'frontend.log'
        deadline = time.monotonic() + 20
        while not ready.exists() and time.monotonic() < deadline and self.proc.poll() is None:
            time.sleep(0.05)
        assert ready.exists() and self.cafile.exists(), (tmp / 'frontend.log').read_bytes()[-2000:]
        assert (self.confdir / 'mitmproxy-ca.pem').stat().st_mode & 0o777 == 0o600
        self.core = Core(rig)
        self.core.start()

    def curl(self, *args: str, timeout: float = 20) -> tuple[str, bytes]:
        done = subprocess.run(['curl', '-sS', '--proxy', f'http://127.0.0.1:{self.port}', '--cacert', str(self.cafile),
                               '-w', '\\n%{http_code} %{http_version}', *args], capture_output=True, timeout=timeout)
        out = done.stdout
        body, _, status = out.rpartition(b'\n')
        return status.decode().strip(), body

    def close(self) -> None:
        self.core.stop = True
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


@pytest.fixture
def fe(rig: Rig, tmp_path: Path) -> Iterator[Frontend]:
    f = Frontend(rig, tmp_path)
    yield f
    f.close()


def test_https_and_http_requests_reach_the_upstream_as_canonical_form(fe: Frontend, ca: CA) -> None:
    upstream = Upstream(server_tls(ca))
    status, body = fe.curl('-H', 'X-Probe: one', f'https://api.test:{upstream.port}/a/b?x=1')
    assert (status, body) == ('200 1.1', b'ok'), (fe.rig.logs, fe.logfile.read_bytes()[-1500:], fe.core.judges)
    [j] = fe.core.judges
    assert (j['method'], j['scheme'], j['host'], j['port'], j['path'], j['query']) == (b'GET', b'https', b'api.test', upstream.port, b'/a/b', b'x=1')
    names = [n for n in j['headers'][0::2]]
    assert b'x-probe' in names and not any(n.startswith(b'x-engine-') or n.startswith(b'proxy-') for n in names)
    assert not any(n in (b'host', b'content-length', b'transfer-encoding', b'connection') for n in names)
    [got] = upstream.requests
    assert got.header('host') == [f'api.test:{upstream.port}'] and got.sni == 'api.test' and got.header('x-probe') == ['one']
    plain = Upstream()
    status, body = fe.curl(f'http://api.test:{plain.port}/p')
    assert (status, body) == ('200 1.1', b'ok') and fe.core.judges[-1]['scheme'] == b'http'
    assert fe.core.reports and all(r[1] == c.RES_REMOTE for r in fe.core.reports)
    upstream.close()
    plain.close()


def test_chunked_upload_and_expect_continue_arrive_as_one_body(fe: Frontend, ca: CA, tmp_path: Path) -> None:
    payload = bytes(range(256)) * 300
    (tmp_path / 'payload').write_bytes(payload)
    upstream = Upstream(server_tls(ca), reply=lambda r, s: simple_reply(str(len(r.body)).encode())(r, s))
    status, body = fe.curl('-X', 'POST', '-H', 'Transfer-Encoding: chunked', '--data-binary', f'@{tmp_path / "payload"}',
                           f'https://api.test:{upstream.port}/up')
    assert (status, body) == ('200 1.1', str(len(payload)).encode())
    assert fe.core.judges[-1]['body_len'] == len(payload)
    assert upstream.requests[-1].header('content-length') == [str(len(payload))] and upstream.requests[-1].body == payload
    status, body = fe.curl('-X', 'PUT', '-H', 'Expect: 100-continue', '--data-binary', f'@{tmp_path / "payload"}',
                           f'https://api.test:{upstream.port}/expect')
    assert (status, body) == ('200 1.1', str(len(payload)).encode())
    assert b'expect' not in fe.core.judges[-1]['headers'][0::2]
    upstream.close()


def test_refusal_becomes_a_403_with_the_reason(fe: Frontend) -> None:
    done = subprocess.run(['curl', '-sS', '-i', '--proxy', f'http://127.0.0.1:{fe.port}', '--cacert', str(fe.cafile),
                           'http://deny.test/x'], capture_output=True, timeout=20)
    head = done.stdout.split(b'\r\n\r\n', 1)[0].lower()
    assert head.startswith(b'http/1.1 403') and b'x-engine-reason: user_denied' in head
    assert b'engine refused GET http://deny.test/x\nreason: user_denied\nThe user denied this request. Do not retry.' in done.stdout


def test_streamed_response_arrives_in_pieces(fe: Frontend, ca: CA) -> None:
    def stream(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n')
        for i in range(5):
            chunk = b'data: %d\n\n' % i
            sock.sendall(b'%x\r\n%s\r\n' % (len(chunk), chunk))
            time.sleep(0.4)
        sock.sendall(b'0\r\n\r\n')
        return None

    upstream = Upstream(server_tls(ca), reply=stream)
    ctx = ssl.create_default_context(cafile=str(fe.cafile))
    conn = http.client.HTTPSConnection('127.0.0.1', fe.port, context=ctx, timeout=20)
    conn.set_tunnel('api.test', upstream.port)
    conn.request('GET', '/stream')
    resp = conn.getresponse()
    assert resp.status == 200
    arrivals = []
    while True:
        piece = resp.read1(4096)
        if not piece:
            break
        arrivals.append((time.monotonic(), piece))
    assert b''.join(p for _, p in arrivals) == b''.join(b'data: %d\n\n' % i for i in range(5))
    assert arrivals[-1][0] - arrivals[0][0] >= 1.2, [t - arrivals[0][0] for t, _ in arrivals]   # streamed, not buffered
    conn.close()
    upstream.close()


def test_non_tls_connect_tunnel_is_never_a_tunnel_and_h2_is_not_offered(fe: Frontend, ca: CA) -> None:
    """F-02 reading: after CONNECT, bytes that are not TLS get no tunnel. A raw non-HTTP stream is killed; plain HTTP
    inside the tunnel is handled as a plain http request through the connector (never passed through)."""
    upstream = Upstream(server_tls(ca))
    raw = socket.create_connection(('127.0.0.1', fe.port), timeout=5)
    raw.sendall(b'CONNECT api.test:%d HTTP/1.1\r\nHost: api.test:%d\r\n\r\n' % (upstream.port, upstream.port))
    assert raw.recv(1024).startswith(b'HTTP/1.1 200')
    raw.sendall(b'XYZZY not tls not http\r\n\r\n')                             # a raw stream: no tunnel, nothing judged
    raw.settimeout(5)
    try:
        answer = raw.recv(4096)
    except (ConnectionError, socket.timeout):
        answer = b''
    assert (answer == b'' or answer.startswith(b'HTTP/1.1 4')) and upstream.requests == [] and not fe.core.judges
    raw.close()
    plain = socket.create_connection(('127.0.0.1', fe.port), timeout=5)
    plain.sendall(b'CONNECT api.test:%d HTTP/1.1\r\nHost: api.test:%d\r\n\r\n' % (upstream.port, upstream.port))
    assert plain.recv(1024).startswith(b'HTTP/1.1 200')
    plain.sendall(b'GET /inside HTTP/1.1\r\nHost: api.test:%d\r\n\r\n' % upstream.port)   # plain HTTP in the tunnel
    plain.settimeout(5)
    answer = plain.recv(4096)
    assert answer.startswith(b'HTTP/1.1 502') and b'x-engine-reason' in answer   # judged as http, the TLS upstream said no
    [j] = fe.core.judges
    assert (j['scheme'], j['path']) == (b'http', b'/inside') and upstream.requests == []
    plain.close()
    status, _ = fe.curl('--http2', f'https://api.test:{upstream.port}/h2')
    assert status == '200 1.1'                                                   # the frontend only speaks HTTP/1.1
    upstream.close()


GO_ONLY = pytest.mark.skipif(FRONTEND_IMPL == 'python', reason='mitmproxy decides the layer on the first bytes it '
                             'receives; the Go frontend reads on (frontend-go/README.md, the F-02 row)')


@GO_ONLY
def test_a_client_hello_that_arrives_a_byte_at_a_time_is_still_tls(fe: Frontend, ca: CA) -> None:
    """F-02 (overall review 2026-11-03, #12): the layer after CONNECT is decided once enough bytes are in; a client hello
    whose first segments hold one byte each is TLS all the same, terminated with the execution's CA, not a stream to
    close."""
    upstream = Upstream(server_tls(ca))
    raw = socket.create_connection(('127.0.0.1', fe.port), timeout=5)
    raw.sendall(b'CONNECT api.test:%d HTTP/1.1\r\nHost: api.test:%d\r\n\r\n' % (upstream.port, upstream.port))
    assert raw.recv(1024).startswith(b'HTTP/1.1 200')
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.create_default_context(cafile=str(fe.cafile)).wrap_bio(incoming, outgoing, server_hostname='api.test')
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    hello = outgoing.read()
    for piece in (hello[:1], hello[1:2], hello[2:]):
        raw.sendall(piece)
        time.sleep(0.2)
    raw.settimeout(5)
    while True:
        data = raw.recv(65536)
        assert data, 'the frontend closed the tunnel'
        incoming.write(data)
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            raw.sendall(outgoing.read())
    raw.sendall(outgoing.read())
    assert tls.version() in ('TLSv1.2', 'TLSv1.3') and fe.core.judges == []
    raw.close()
    upstream.close()


@GO_ONLY
def test_a_request_line_split_after_its_first_space_is_still_http(fe: Frontend, ca: CA) -> None:
    """F-02 (recheck 2026-11-03): after CONNECT, a request line that arrives as "GET " and then the rest is a request
    line still arriving, not a stream to close: it is judged as a plain http request, like a whole line."""
    upstream = Upstream(server_tls(ca))
    plain = socket.create_connection(('127.0.0.1', fe.port), timeout=5)
    plain.sendall(b'CONNECT api.test:%d HTTP/1.1\r\nHost: api.test:%d\r\n\r\n' % (upstream.port, upstream.port))
    assert plain.recv(1024).startswith(b'HTTP/1.1 200')
    plain.sendall(b'GET ')
    time.sleep(0.3)
    plain.sendall(b'/split HTTP/1.1\r\nHost: api.test:%d\r\n\r\n' % upstream.port)
    plain.settimeout(5)
    answer = plain.recv(4096)
    assert answer.startswith(b'HTTP/1.1 502') and b'x-engine-reason' in answer   # judged as http, the TLS upstream said no
    assert [(j['scheme'], j['path']) for j in fe.core.judges] == [(b'http', b'/split')] and upstream.requests == []
    plain.close()
    upstream.close()


def test_bodiless_responses_and_connection_reuse(fe: Frontend, ca: CA) -> None:
    upstream = Upstream(server_tls(ca), reply=lambda r, s: (b'HTTP/1.1 204 No Content\r\n\r\n' if r.target == '/nc' else simple_reply(b'ok')(r, s)))
    status, body = fe.curl(f'https://api.test:{upstream.port}/nc')
    assert (status, body) == ('204 1.1', b'')
    status, body = fe.curl('-I', f'https://api.test:{upstream.port}/head')
    assert status.startswith('200')
    status, body = fe.curl(f'https://api.test:{upstream.port}/one', f'https://api.test:{upstream.port}/two')
    assert status == '200 1.1' and body.endswith(b'ok')
    assert [r.connection for r in upstream.requests][-2:] == [upstream.requests[-1].connection] * 2   # keep-alive end to end
    upstream.close()


def test_frontend_signs_with_the_executions_ca_from_the_pool(rig: Rig, tmp_path: Path, ca: CA) -> None:
    """S-16 on the host: a pool entry made by frontend/make_ca_pool.py is the CA the frontend signs with; the agent's
    trust file is that entry's ca.pem, and only it."""
    pool = tmp_path / 'pool'
    subprocess.run([str(FRONTEND_PYTHON), '-I', '-B', str(ENGINE / 'frontend/make_ca_pool.py'), str(pool), '2'], check=True)
    entries = sorted(p for p in pool.iterdir() if p.is_dir())
    assert len(entries) == 2 and all((e / 'ca.pem').exists() and (e / 'ca.key').exists() for e in entries)
    fe = Frontend(rig, tmp_path, ca_dir=entries[0])
    try:
        upstream = Upstream(server_tls(ca))
        status, body = fe.curl(f'https://api.test:{upstream.port}/signed')
        assert (status, body) == ('200 1.1', b'ok')
        other = subprocess.run(['curl', '-sS', '--proxy', f'http://127.0.0.1:{fe.port}', '--cacert', str(entries[1] / 'ca.pem'),
                                f'https://api.test:{upstream.port}/other'], capture_output=True, timeout=20)
        assert other.returncode == 60 and b'certificate' in other.stderr.lower()      # another execution's CA does not vouch
        upstream.close()
    finally:
        fe.close()
