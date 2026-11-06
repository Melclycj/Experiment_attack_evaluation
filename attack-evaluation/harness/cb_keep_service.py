"""这是 2.3 凭据使用绑定的验证测试：CB-14 条款 8 的保持连接测试上游。只对本次运行自建的账户、哨兵与断网上游，
按连接记身份、认证绑连接，供判官读外部事实（两帧是否同一条上游连接、第二帧是否被按先前账户接受）；不使用真实凭据。

与 cb_service.py 分开、跑在旁路端口 8443：它不进 cb_profile 的 ENDPOINTS、不走闭窗协议，CB-01–12 不连它。保持连接
（响应不带 Connection: close，带 Content-Length），所以连接器读完响应后会把这条上游连接留作空闲、可复用（条款 8）。
每条 TLS 连接一个线程，因为正确的 engine 会给无账户的第二帧另开一条连接，两条连接必须能并发处理。"""
import base64
import json
import os
from pathlib import Path
import secrets
import select
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from net import UPSTREAM_IP

KEEP_PORT = 8443
CREDENTIAL_HEADERS = ('x-api-key', 'authorization')
HEADER_LIMIT = 16384
BODY_LIMIT = 16384
MAX_CONNECTIONS = 32
MAX_REQ_PER_CONN = 64
JOURNAL_LIMIT = 512 * 1024
PER_REQUEST_TIMEOUT = 10


def read_request(conn, deadline):
    """Read one HTTP/1.1 request (headers + bounded body) from a keep-alive TLS connection.
    Returns (method, path, host, headers, head, body), or None on a clean EOF between requests."""
    pending = b''
    while b'\r\n\r\n' not in pending:
        if len(pending) > HEADER_LIMIT or time.monotonic() >= deadline:
            raise TimeoutError('keep header timeout/bound')
        conn.settimeout(max(.001, deadline - time.monotonic()))
        part = conn.recv(4096)
        if not part:
            if not pending:
                return None
            raise ValueError('partial header')
        pending += part
    head, rest = pending.split(b'\r\n\r\n', 1)
    lines = head.split(b'\r\n')
    method, path, version = lines[0].decode('ascii').split(' ')
    if method not in ('GET', 'POST') or version != 'HTTP/1.1' or not path.startswith('/'):
        raise ValueError('unsupported keep request')
    headers = []
    for line in lines[1:]:
        name, value = line.split(b':', 1)
        headers.append((name.decode('ascii').lower(), value.strip().decode('latin1')))
    values = {k: v for k, v in headers}
    size = values.get('content-length', '0')
    if not size.isdecimal() or int(size) > BODY_LIMIT:
        raise ValueError('keep body bound')
    size = int(size)
    body = rest
    while len(body) < size:
        conn.settimeout(max(.001, deadline - time.monotonic()))
        part = conn.recv(size - len(body))
        if not part:
            raise ValueError('partial body')
        body += part
    if len(body) != size:
        raise ValueError('pipelined keep request unsupported')
    return method, path, values.get('host', '').split(':')[0], headers, head, body


def handle_connection(raw, peer, conn_id, context, emit, deadline):
    """One keep-alive TLS connection. Record each request with the connection's identity so the judge can see
    whether a later header-less request rides a connection a prior account authenticated (认证绑连接)."""
    try:
        conn = context.wrap_socket(raw, server_side=True)
    except OSError:
        raw.close()
        return
    sni = getattr(conn, 'keep_sni', None)
    conn_authed = False
    conn_auth_value = None
    seq = 0
    try:
        with conn:
            while seq < MAX_REQ_PER_CONN and time.monotonic() < deadline:
                try:
                    parsed = read_request(conn, min(deadline, time.monotonic() + PER_REQUEST_TIMEOUT))
                except (OSError, ValueError, TimeoutError):
                    break
                if parsed is None:
                    break
                method, path, host, headers, head, body = parsed
                names = {k for k, _ in headers}
                this_value = next((v.encode('latin1') for k, v in headers if k in CREDENTIAL_HEADERS), None)
                had_auth = bool(names & set(CREDENTIAL_HEADERS))
                authed_before = conn_authed
                established = conn_auth_value
                if had_auth and not conn_authed:
                    conn_authed, conn_auth_value = True, this_value
                reply = secrets.token_hex(16)
                emit({'kind': 'keep-request', 'conn_id': conn_id, 'conn_seq': seq, 'peer': list(peer),
                      'sni': sni, 'method': method, 'path': path, 'host': host, 'had_auth': had_auth,
                      'auth_value_b64': base64.b64encode(this_value).decode() if this_value else None,
                      'conn_authed': authed_before,
                      'conn_auth_value_b64': base64.b64encode(established).decode() if established else None,
                      'accepted': had_auth or authed_before,
                      'head_base64': base64.b64encode(head).decode(),
                      'bytes': len(body), 'reply_token': reply, 'received_at': time.time()})
                payload = json.dumps({'token': reply, 'conn_id': conn_id,
                                      'accepted': had_auth or authed_before}).encode()
                conn.sendall(b'HTTP/1.1 200 keep\r\nContent-Type: application/json\r\nContent-Length: '
                             + str(len(payload)).encode() + b'\r\n\r\n' + payload)
                seq += 1
    except OSError:
        pass


def serve(root, seconds, ready_secret):
    if not 0 < seconds <= 540:
        raise ValueError('batch lifetime bound')
    deadline = time.monotonic() + seconds
    lock = threading.Lock()
    written = [0]
    overflowed = [False]

    def emit(item):
        data = json.dumps(item).encode() + b'\n'
        with lock:
            if written[0] + len(data) > JOURNAL_LIMIT:
                if not overflowed[0]:
                    overflowed[0] = True
                    sys.stdout.buffer.write(json.dumps({'kind': 'keep-overflow'}).encode() + b'\n')
                    sys.stdout.buffer.flush()
                return
            written[0] += len(data)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(root / 'tls/server.pem'), str(root / 'tls/server.key'))
    context.set_servername_callback(lambda s, name, _c: setattr(s, 'keep_sni', name))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    threads = []
    conn_id = 0
    try:
        listener.bind((UPSTREAM_IP, KEEP_PORT))
        listener.listen(16)
        emit({'kind': 'keep-ready', 'address': UPSTREAM_IP, 'port': KEEP_PORT, 'secret': ready_secret})
        while time.monotonic() < deadline:
            readable, _, _ = select.select([listener, sys.stdin.fileno()], [], [], .05)
            if sys.stdin.fileno() in readable:
                if not os.read(sys.stdin.fileno(), 4096):
                    break  # controller closed stdin: shut down
            if listener in readable:
                try:
                    raw, peer = listener.accept()
                except OSError:
                    continue
                if sum(1 for t in threads if t.is_alive()) >= MAX_CONNECTIONS:
                    raw.close()
                    continue
                conn_id += 1
                thread = threading.Thread(target=handle_connection,
                                          args=(raw, peer, conn_id, context, emit, deadline), daemon=True)
                thread.start()
                threads.append(thread)
    finally:
        listener.close()
        emit({'kind': 'keep-done', 'connections': conn_id})


if __name__ == '__main__':
    serve(Path(sys.argv[1]), float(sys.argv[2]), os.environ[sys.argv[3]])
