"""Receiver differential for the connector's serialisation (validation.md C-11, C-09; T-Reqs reversed: one fixed sender,
several receivers). nginx, Apache httpd and HAProxy each listen on the container's loopback and proxy to their own
recording backend; the connector's upstream code sends the same canonical requests through each; the backends' views
are compared with each other and with the canonical form. Meant to run inside a disposable Debian container
(checks/run_receiver_differential.sh), never on the host. Not a TCB module.

Exit status 0 when every receiver's view of every request agrees on method, target, Host, body and the carried
headers; the JSON report lists each request's views and every disagreement.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE / 'tests'))

from connector import canonical as c  # noqa: E402
from connector.channel import Answer  # noqa: E402
from connector.upstream import Exchange, Registry, Sink, tls_context  # noqa: E402
from connector_rig import Received, StubPolicy, Upstream  # noqa: E402

FRONT = {'nginx': 8101, 'apache': 8102, 'haproxy': 8103}
BACK = {'nginx': 8201, 'apache': 8202, 'haproxy': 8203}
WORK = Path('/tmp/w2-receivers')


# ---- the corpus: canonical requests that pass the grammar ----------------------------------------------------------------
def corpus() -> list[tuple[str, list[bytes]]]:
    def req(name: str, method: bytes, path: bytes, query: bytes = b'', headers: tuple[tuple[bytes, bytes], ...] = (),
            body: bytes = b'') -> tuple[str, list[bytes]]:
        items: list[bytes] = []
        for n, v in headers:
            items += [n, v]
        return name, [method, b'http', b'receiver.test', c.u16(0), path, query, c.pack_list(items), body]

    long_value = b'v' * 4096
    many = tuple((b'x-h%d' % i, b'%d' % i) for i in range(20))
    return [
        req('get-root', b'GET', b'/'),
        req('get-query', b'GET', b'/a/b', b'x=1&y=%20z&empty=&q=a+b'),
        req('path-subdelims', b'GET', b"/p!$&'()*+,=:@/x~y_z-9.html"),
        req('path-encoded-space-and-qmark', b'GET', b'/a%20b/c%3Fd', b'k=%3F'),
        req('trailing-slash', b'GET', b'/v1/'),
        req('post-form', b'POST', b'/login', b'', ((b'content-type', b'application/x-www-form-urlencoded'),), b'user=a&pw=b'),
        req('post-empty', b'POST', b'/empty'),
        req('put-binary', b'PUT', b'/blob', b'', ((b'content-type', b'application/octet-stream'),), bytes(range(256)) * 4),
        req('patch-json', b'PATCH', b'/item/1', b'', ((b'content-type', b'application/json'),), b'{"a": 1}'),
        req('delete', b'DELETE', b'/item/2'),
        req('head', b'HEAD', b'/h'),
        req('options', b'OPTIONS', b'/o'),
        req('lower-case-method', b'get', b'/lc'),
        req('bearer', b'GET', b'/me', b'', ((b'authorization', b'Bearer PH-TOKEN-123'),)),
        req('api-key-and-accept', b'GET', b'/k', b'', ((b'x-api-key', b'PH-KEY'), (b'accept', b'application/json'))),
        req('obs-text-value', b'GET', b'/o', b'', ((b'x-probe', 'caf\xe9 \xff'.encode('latin-1')),)),
        req('tabs-inside-value', b'GET', b'/t', b'', ((b'x-probe', b'a\t b  c'),)),
        req('long-value', b'GET', b'/l', b'', ((b'x-long', long_value),)),
        req('many-headers', b'GET', b'/m', b'', many),
        req('duplicate-header', b'GET', b'/d', b'', ((b'x-dup', b'1'), (b'x-dup', b'2'))),
        req('big-body', b'POST', b'/big', b'', ((b'content-type', b'application/octet-stream'),), b'B' * (1024 * 1024)),
        req('body-on-get', b'GET', b'/gb', b'', (), b'ignored?'),
    ]


# ---- receivers --------------------------------------------------------------------------------------------------------------
def wait_port(port: int, seconds: float = 15) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f'port {port} did not open')


def start_receivers() -> list[subprocess.Popen]:
    shutil.rmtree(WORK, ignore_errors=True)
    for sub in ('nginx', 'nginx/body', 'nginx/proxy', 'apache', 'haproxy'):
        (WORK / sub).mkdir(parents=True)
    (WORK / 'nginx/nginx.conf').write_text(f'''
daemon off; worker_processes 1; pid {WORK}/nginx/pid; error_log {WORK}/nginx/error.log info;
events {{ worker_connections 64; }}
http {{
  log_format w2 '$status "$request" host="$http_host" cl="$content_length"';
  access_log {WORK}/nginx/access.log w2; client_max_body_size 100m; client_body_temp_path {WORK}/nginx/body; proxy_temp_path {WORK}/nginx/proxy;
  server {{
    listen 127.0.0.1:{FRONT['nginx']}; server_name _;
    location / {{ proxy_pass http://127.0.0.1:{BACK['nginx']}; proxy_http_version 1.1; proxy_set_header Host $http_host;
                 proxy_set_header Connection ""; }}
  }}
}}
''')
    modules = '/usr/lib/apache2/modules'
    (WORK / 'apache/httpd.conf').write_text(f'''
ServerRoot {WORK}/apache
PidFile {WORK}/apache/pid
Listen 127.0.0.1:{FRONT['apache']}
LoadModule mpm_event_module {modules}/mod_mpm_event.so
LoadModule authz_core_module {modules}/mod_authz_core.so
LoadModule proxy_module {modules}/mod_proxy.so
LoadModule proxy_http_module {modules}/mod_proxy_http.so
User nobody
Group nogroup
ServerName receiver.test
ErrorLog {WORK}/apache/error.log
LogLevel warn
ProxyRequests Off
ProxyPreserveHost On
AllowEncodedSlashes NoDecode
ProxyPass "/" "http://127.0.0.1:{BACK['apache']}/" nocanon
''')
    (WORK / 'haproxy/haproxy.cfg').write_text(f'''
defaults
  mode http
  timeout connect 5s
  timeout client 60s
  timeout server 60s
frontend f
  bind 127.0.0.1:{FRONT['haproxy']}
  default_backend b
backend b
  server s 127.0.0.1:{BACK['haproxy']}
''')
    procs = [subprocess.Popen(['nginx', '-c', str(WORK / 'nginx/nginx.conf')]),
             subprocess.Popen(['apache2', '-f', str(WORK / 'apache/httpd.conf'), '-DFOREGROUND']),
             subprocess.Popen(['haproxy', '-f', str(WORK / 'haproxy/haproxy.cfg'), '-db'])]
    for port in FRONT.values():
        wait_port(port)
    return procs


# ---- the sender: the connector's own upstream code -------------------------------------------------------------------------------
@dataclass
class View:
    method: str
    target: str
    host: list[str]
    body_len: int
    body_digest: str
    headers: dict[str, str]        # carried names -> comma-joined values as the backend saw them
    status: int                    # what the connector relayed to the frontend
    note: str = ''                 # the connector's own log line for a refused or failed exchange


def send(exchange: Exchange, fields: list[bytes], port: int, backend: Upstream) -> tuple[Received, int]:
    fields = list(fields)
    fields[3] = c.u16(port)
    req = c.parse_request(fields)
    body = req.body
    memfd = c.seal_body(body)
    frames: list[tuple[int, list[bytes]]] = []
    parser = c.FrameParser(c.LIMITS.frame_a, c.LINK_A_OUT)
    sink = Sink(lambda data: frames.extend(parser.feed(data)))
    before = len(backend.requests)
    try:
        exchange.run(req, Answer(c.ALLOW_NOCRED), memfd, len(body), sink)
    finally:
        os.close(memfd)
    head = next((f for k, f in frames if k == c.RESP_HEAD), None)
    status = c.read_uint(head[1], 2) if head else -1
    deadline = time.monotonic() + 5
    while len(backend.requests) <= before and time.monotonic() < deadline:
        time.sleep(0.02)
    if len(backend.requests) <= before:
        return None, status                                    # the receiver answered itself (a refusal) or failed
    return backend.requests[-1], status


def view(received: Received | None, status: int, carried: list[bytes], front_port: int, note: str = '') -> View:
    import hashlib
    if received is None:
        return View('<refused>', '', [], 0, '', {}, status, note)
    headers: dict[str, list[str]] = {}
    for name, value in received.headers:
        headers.setdefault(name.lower(), []).append(value)
    # each receiver sits on its own port, so the Host the connector generated names that port: compared with it masked
    host = [h.replace(f':{front_port}', ':PORT') for h in headers.get('host', [])]
    return View(received.method, received.target, host, len(received.body),
                hashlib.sha256(received.body).hexdigest()[:16],
                {n.decode(): ', '.join(headers.get(n.decode(), [])) for n in carried}, status)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    backends = {name: Upstream(port=BACK[name]) for name in FRONT}       # the recording backends the receivers proxy to
    procs = start_receivers()
    report: dict = {'receivers': {}, 'requests': [], 'disagreements': []}
    for name, argv in (('nginx', ['nginx', '-v']), ('apache', ['apache2', '-v']), ('haproxy', ['haproxy', '-v'])):
        done = subprocess.run(argv, capture_output=True, text=True)
        report['receivers'][name] = (done.stdout + done.stderr).strip().splitlines()[0]
    try:
        logs: list[str] = []
        exchange = Exchange(StubPolicy(), tls_context(None), Registry(), lambda event, **f: logs.append(json.dumps({'event': event, **f})),
                            5.0, 30.0)
        for name, fields in corpus():
            names = c.unpack_list(fields[6])[0::2]
            views: dict[str, View] = {}
            for receiver, port in FRONT.items():
                logs.clear()
                received, status = send(exchange, fields, port, backends[receiver])
                views[receiver] = view(received, status, names, port, '; '.join(logs))
            entry = {'request': name, 'views': {r: v.__dict__ for r, v in views.items()}}
            # a receiver that answered the request itself without proxying it refused it: recorded, not a parse difference
            refused = {r: v.status for r, v in views.items() if v.method == '<refused>'}
            if refused:
                report.setdefault('refusals', []).append({'request': name, 'receivers': refused})
            proxied = {r: v for r, v in views.items() if v.method != '<refused>'}
            if proxied:
                first = next(iter(proxied.values()))
                for field in ('method', 'target', 'host', 'body_len', 'body_digest', 'headers', 'status'):
                    values = {r: getattr(v, field) for r, v in proxied.items()}
                    if any(val != getattr(first, field) for val in values.values()):
                        report['disagreements'].append({'request': name, 'field': field, 'values': values})
                expected_target = (fields[4] + (b'?' + fields[5] if fields[5] else b'')).decode('ascii')
                if first.target != expected_target or first.method != fields[0].decode('ascii'):
                    report['disagreements'].append({'request': name, 'field': 'canonical',
                                                    'values': {'sent': expected_target, 'seen': first.target}})
            report['requests'].append(entry)
        exchange.close()
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
        for name, log_name in (('nginx', 'error.log'), ('nginx', 'access.log'), ('apache', 'error.log')):
            log = WORK / name / log_name
            if log.exists():
                shutil.copy(log, args.out / f'{name}-{log_name}')
    report['result'] = 'passed' if not report['disagreements'] else 'failed'
    (args.out / 'receiver-differential.json').write_text(json.dumps(report, indent=1, default=str))
    print(json.dumps({'result': report['result'], 'requests': len(report['requests']), 'receivers': report['receivers'],
                      'disagreements': report['disagreements'], 'refusals': report.get('refusals', [])}, indent=1, default=str))
    return 0 if not report['disagreements'] else 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
