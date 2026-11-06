"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The runner the attack row starts (engine: argv of the df-runner runtime, cwd /work) or the controller starts as the
host user (undefended: DF_WORK names the work directory). It reads df-request.json, runs the named attack's branch,
and writes df-<nonce>-obs.json (fsync, rename) before it exits. Targets come only from the request (TESTING rule 4).
Synchronisation with the controller: the runner creates df-<nonce>-mark-<name> and waits for df-<nonce>-go-<name>.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import sys
import time
import traceback
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)                      # -I leaves the script directory off sys.path
import df_wire as w  # noqa: E402

REQUEST_NAME = 'df-request.json'
ATTACK = re.compile(r'(DF|PC)-[A-Z0-9-]{2,16}')
NONCE = re.compile(r'[0-9a-f]{16}')
WAIT_LIMIT = 10.0


def summary(result: dict) -> dict:
    body = result.get('body', b'')
    return {k: v for k, v in result.items() if k != 'body'} | {
        'body_len': len(body), 'body': body[:w.BODY_KEEP].decode('latin-1')}


class Ctx:
    def __init__(self, req: dict, work: str) -> None:
        self.req, self.work = req, work
        self.sub, self.nonce, self.config = req['sub'], req['nonce'], req['config']
        self.t = req['targets']
        self.steps: list[dict] = []
        self.notes: dict = {}
        self.secret = os.environ.get('DF_TRUTH', '') if self.config == 'undefended' else self.t['placeholder']

    # ---- targets -------------------------------------------------------------------------------------------------
    def url(self, name: str, path: str, tag: str, *, port: int | None = None, scheme: str = 'https') -> str:
        authority = self.t[name] + (f':{port}' if port else '')
        return f'{scheme}://{authority}{path}?n={self.nonce}-{tag}'

    def bearer(self) -> str:
        return 'Bearer ' + self.secret

    # ---- connections ---------------------------------------------------------------------------------------------
    def open(self, url: str):
        if self.config == 'engine':
            return w.ProxyConn()
        parts = urlsplit(url)
        return w.DirectConn(parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == 'https' else 80),
                            self.t.get('ca_file'))

    def request(self, method: str, url: str, headers=(), body: bytes = b'') -> dict:
        parts = urlsplit(url)
        return {'method': method, 'scheme': parts.scheme, 'host': parts.hostname,
                'port': parts.port or (443 if parts.scheme == 'https' else 80), 'path': parts.path or '/',
                'query': parts.query or None, 'headers': list(headers), 'body': body}

    def send(self, step: str, url: str, method: str = 'GET', headers=(), body: bytes = b'', conn=None):
        """Send without reading; returns the connection (the caller reads or closes it)."""
        record = {'step': step, 'method': method, 'url': url, 'sent_at': time.time()}
        self.steps.append(record)
        try:
            conn = conn or self.open(url)
            record['address'] = conn.address
            conn.send(self.request(method, url, headers, body))
        except OSError as e:
            record['error'] = f'{type(e).__name__}: {e}'
            return None
        return conn

    def call(self, step: str, url: str, method: str = 'GET', headers=(), body: bytes = b'', *, conn=None,
             timeout: float = 10.0, first_chunk_only: bool = False) -> dict:
        own = conn is None
        sent = self.send(step, url, method, headers, body, conn)
        record = self.steps[-1]
        if sent is None:
            return {'category': None, 'error': record['error']}
        result = w.collect(sent, timeout, first_chunk_only=first_chunk_only)
        record['result'] = summary(result)
        record['result_at'] = time.time()
        if own and not first_chunk_only:
            sent.close()
        result['conn'] = sent
        return result

    def resume(self, step: str, result: dict, timeout: float) -> dict:
        """Read the rest of a response begun with first_chunk_only."""
        record = {'step': step, 'resumed_at': time.time()}
        self.steps.append(record)
        w.collect(result['conn'], timeout, into=result)
        record['result'] = summary({k: v for k, v in result.items() if k != 'conn'})
        record['result_at'] = time.time()
        return result

    # ---- synchronisation -----------------------------------------------------------------------------------------
    def mark(self, name: str) -> None:
        path = os.path.join(self.work, f'df-{self.nonce}-mark-{name}')
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        try:
            os.write(fd, str(time.time()).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        self.notes.setdefault('marks', []).append([name, time.time()])

    def wait(self, name: str, limit: float = WAIT_LIMIT) -> bool:
        path = os.path.join(self.work, f'df-{self.nonce}-go-{name}')
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if os.path.exists(path):
                self.notes.setdefault('released', []).append([name, time.time()])
                return True
            time.sleep(0.05)
        self.notes.setdefault('wait_timeout', []).append(name)
        return False

    def note(self, key: str, value) -> None:
        self.notes[key] = value

    # ---- the agent-side control channel (engine only, fd 3; SPEC 3.3) -------------------------------------------
    def control(self) -> socket.socket:
        """A duplicate of fd 3: closing the agent's control channel ends the row (by design), so the socket object's
        own close must never reach fd 3 itself; fd 3 stays open until the runner exits after writing its record
        (R3, 2026-11-05: the object was collected when DF-16's run() returned and the row closed before the record)."""
        return socket.socket(fileno=os.dup(3))


def control_call(sock: socket.socket, message: dict, timeout: float = 5.0) -> dict | None:
    data = json.dumps(message, separators=(',', ':')).encode()
    sock.sendall(len(data).to_bytes(4, 'big') + data)
    sock.settimeout(timeout)
    head = b''
    while len(head) < 4:
        part = sock.recv(4 - len(head))
        if not part:
            return None
        head += part
    n, body = int.from_bytes(head, 'big'), b''
    while len(body) < n:
        part = sock.recv(n - len(body))
        if not part:
            return None
        body += part
    return json.loads(body)


def load(attack: str):
    if not ATTACK.fullmatch(attack):
        raise ValueError('attack id does not read')
    spec = importlib.util.spec_from_file_location('df_attack', os.path.join(HERE, attack + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_obs(work: str, nonce: str, obs: dict) -> None:
    final = os.path.join(work, f'df-{nonce}-obs.json')
    tmp = final + '.tmp'
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        os.write(fd, json.dumps(obs, ensure_ascii=False, default=str).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, final)


def main() -> int:
    work = os.environ.get('DF_WORK', '/work')
    with open(os.path.join(work, REQUEST_NAME), encoding='utf-8') as f:
        req = json.load(f)
    if not NONCE.fullmatch(req.get('nonce', '')) or req.get('config') not in ('engine', 'undefended'):
        raise SystemExit('request does not read')
    ctx = Ctx(req, work)
    obs = {'attack': req['attack'], 'sub': req['sub'], 'nonce': req['nonce'], 'config': req['config'],
           'role': req.get('role'), 'uid': os.getuid(), 'started_at': time.time(), 'completed': False}
    try:
        load(req['attack']).run(ctx)
        obs['completed'] = True
    except Exception as e:                    # recorded, never raised past here: the obs file must be written
        obs['error'] = f'{type(e).__name__}: {e}'
        obs['traceback'] = traceback.format_exc()[-4000:]
    obs.update(steps=ctx.steps, notes=ctx.notes, finished_at=time.time())
    if req['config'] == 'engine':
        # the connector logs a closed connection just after its refusal reply and is killed once this row empties:
        # stay a moment so that line is written before the row closes (round-2 review, finding 3)
        time.sleep(0.3)
    write_obs(work, req['nonce'] + ('-' + req['role'] if req.get('role') else ''), obs)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
