"""Edge behaviours of the two frontends, observed side by side (not a repository test). Run with W2_FRONTEND_IMPL set;
each probe records what the client saw and what the core judged into PROBE_OUT (JSON)."""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tests'))
from conftest import ca, library, rig  # noqa: E402,F401  (fixtures)
from connector_rig import Upstream, server_tls, simple_reply  # noqa: E402
from test_frontend import Frontend, fe  # noqa: E402,F401  (fixture)

OUT = Path(os.environ['PROBE_OUT'])
RESULTS: dict = json.loads(OUT.read_text()) if OUT.exists() else {}


def record(name: str, **seen) -> None:
    RESULTS[name] = seen
    OUT.write_text(json.dumps(RESULTS, indent=1, default=lambda b: b.decode('latin-1') if isinstance(b, bytes) else str(b)))


def raw(fe, data: bytes, timeout: float = 4.0, conn: socket.socket | None = None) -> bytes:
    s = conn or socket.create_connection(('127.0.0.1', fe.port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(data)
    out = b''
    try:
        while True:
            piece = s.recv(65536)
            if not piece:
                break
            out += piece
    except (socket.timeout, ConnectionError, ssl.SSLError):
        pass
    if conn is None:
        s.close()
    return out


def head_of(answer: bytes) -> list[str]:
    return answer.split(b'\r\n\r\n', 1)[0].decode('latin-1').split('\r\n')


def judged(fe) -> list[dict]:
    return [dict(method=j['method'], scheme=j['scheme'], host=j['host'], port=j['port'], path=j['path'], query=j['query'],
                 headers=[n + b': ' + v for n, v in zip(j['headers'][0::2], j['headers'][1::2])], body_len=j['body_len'])
            for j in fe.core.judges]


def P(fmt: bytes, p: int) -> bytes:
    return fmt.replace(b'PORT', str(p).encode())


def test_plain_requests(fe, ca) -> None:
    up = Upstream(reply=lambda r, s: simple_reply(b'ok', '299 Custom Thing', 'Date: upstream-date\r\nX-Up: y\r\nContent-Type: text/x\r\n')(r, s))
    H = b'Host: api.test:PORT\r\n'
    C = b'Connection: close\r\n\r\n'
    cases = {
        'absolute_host_mismatch': b'GET http://api.test:PORT/x HTTP/1.1\r\nHost: other.test:PORT\r\n' + C,
        'header_order': b'GET http://api.test:PORT/o HTTP/1.1\r\n' + H + b'X-B: 1\r\nX-A: 2\r\nX-B: 3\r\n' + C,
        'expect_unknown': b'POST http://api.test:PORT/e HTTP/1.1\r\n' + H + b'Expect: foo\r\nContent-Length: 2\r\n' + C + b'hi',
        'te_and_cl': b'POST http://api.test:PORT/t HTTP/1.1\r\n' + H + b'Transfer-Encoding: chunked\r\nContent-Length: 2\r\n' + C + b'2\r\nhi\r\n0\r\n\r\n',
        'obs_fold': b'GET http://api.test:PORT/f HTTP/1.1\r\n' + H + b'X-Fold: a\r\n b\r\n' + C,
        'http10': b'GET http://api.test:PORT/h10 HTTP/1.0\r\n' + H + b'\r\n',
        'websocket_upgrade': b'GET http://api.test:PORT/ws HTTP/1.1\r\n' + H + b'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n',
        'double_slash': b'GET http://api.test:PORT//a/b?q=1 HTTP/1.1\r\n' + H + C,
        'origin_form_at_proxy': b'GET /direct?z=9 HTTP/1.1\r\n' + H + C,
        'lowercase_method': b'get http://api.test:PORT/lc HTTP/1.1\r\n' + H + C,
        'orig_header_injection': b'GET http://api.test:PORT/inj HTTP/1.1\r\n' + H + b'X-Engine-Orig-Host: evil.test\r\nX-Engine-Other: z\r\n' + C,
        'too_many_headers': b'GET http://api.test:PORT/many HTTP/1.1\r\n' + H + b''.join(b'X-H%d: v\r\n' % i for i in range(110)) + C,
        'chunked_with_trailer': b'POST http://api.test:PORT/tr HTTP/1.1\r\n' + H + b'Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhi\r\n0\r\nX-Trailer: t\r\n\r\n',
        'absolute_query_no_slash': b'GET http://api.test:PORT?x=1 HTTP/1.1\r\n' + H + C,
        'non_ascii_host_header': b'GET /nh HTTP/1.1\r\nHost: b\xc3\xbccher.test:PORT\r\n' + C,
    }
    for name, data in cases.items():
        before, ups = len(fe.core.judges), len(up.requests)
        answer = raw(fe, P(data, up.port))
        record(name, status_and_headers=head_of(answer), body=answer.split(b'\r\n\r\n', 1)[-1][:200],
               judged=judged(fe)[before:], upstream=[(r.method, r.target, r.headers) for r in up.requests[ups:]])
    up.close()


def test_truncated_response(fe, ca) -> None:
    def cut(_, sock):
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n' + b'x' * 10)
        time.sleep(0.2)
        return None
    up = Upstream(reply=cut)
    answer = raw(fe, P(b'GET http://api.test:PORT/cut HTTP/1.1\r\nHost: api.test:PORT\r\n\r\n', up.port))
    record('truncated_response', raw_answer=answer, ends_with_last_chunk=answer.endswith(b'0\r\n\r\n'))
    up.close()


def tls_through(fe, port: int, alpn: list[str] | None, request: bytes, cafile: str) -> dict:
    s = socket.create_connection(('127.0.0.1', fe.port), timeout=5)
    s.sendall(P(b'CONNECT api.test:PORT HTTP/1.1\r\nHost: api.test:PORT\r\n\r\n', port))
    connect_answer = s.recv(1024)
    ctx = ssl.create_default_context(cafile=cafile)
    if alpn:
        ctx.set_alpn_protocols(alpn)
    try:
        t = ctx.wrap_socket(s, server_hostname='api.test')
    except (ssl.SSLError, OSError) as e:
        return dict(connect=connect_answer, handshake_error=type(e).__name__ + ': ' + str(e)[:120])
    cert = t.getpeercert()
    seen = dict(connect=connect_answer, alpn=t.selected_alpn_protocol(), version=t.version(),
                leaf_subject=cert.get('subject'), leaf_san=cert.get('subjectAltName'))
    seen['answer'] = head_of(raw(fe, request, conn=t))[:1]
    t.close()
    return seen


def test_tls_variants(fe, ca) -> None:
    up = Upstream(server_tls(ca))
    req = P(b'GET /tls HTTP/1.1\r\nHost: api.test:PORT\r\nConnection: close\r\n\r\n', up.port)
    for name, alpn in (('tls_no_alpn', None), ('tls_alpn_h2_only', ['h2']), ('tls_alpn_h2_http11', ['h2', 'http/1.1'])):
        record(name, **tls_through(fe, up.port, alpn, req, str(fe.cafile)))
    s = socket.create_connection(('127.0.0.1', fe.port), timeout=5)       # garbage after TLS, no ALPN
    s.sendall(P(b'CONNECT api.test:PORT HTTP/1.1\r\n\r\n', up.port))
    s.recv(1024)
    t = ssl.create_default_context(cafile=str(fe.cafile)).wrap_socket(s, server_hostname='api.test')
    record('tls_no_alpn_garbage', answer=raw(fe, b'\x00\x01binary\r\n', conn=t), judged=len(fe.core.judges))
    t.close()
    record('connect_http10', answer=raw(fe, P(b'CONNECT api.test:PORT HTTP/1.0\r\n\r\n', up.port), timeout=1.5)[:60])
    record('connect_no_port', answer=head_of(raw(fe, b'CONNECT api.test HTTP/1.1\r\nHost: api.test\r\n\r\n'))[:1])
    s = socket.create_connection(('127.0.0.1', fe.port), timeout=5)
    s.sendall(P(b'CONNECT api.test:PORT HTTP/1.1\r\n\r\n', up.port))
    s.recv(1024)
    record('connect_then_ssh', answer=raw(fe, b'SSH-2.0-probe\r\n', conn=s))
    s.close()
    up.close()


def test_unreachable_proxy_path(rig, tmp_path) -> None:
    rig.path.unlink()            # nothing listens on the proxy path any more
    fe = Frontend(rig, tmp_path)
    try:
        answer = raw(fe, b'GET http://api.test:1/x HTTP/1.1\r\nHost: api.test:1\r\nConnection: close\r\n\r\n')
        record('proxy_path_unreachable', status_and_headers=head_of(answer), body=answer.split(b'\r\n\r\n', 1)[-1][:300])
    finally:
        fe.close()
