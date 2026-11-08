"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
import re
import select
import socket
import struct
import threading
from nb_contract import decode, encoded, fields, identifier
from nb_io import Files, PublicationPending
from nb_wire import open_request, response


def config(ctx, role):
    p = ctx.request['parameters']
    fields(p, 'role nonce name')
    if p['role'] != role or not re.fullmatch(r'[0-9a-f]{48}', p['nonce']):
        raise ValueError('support role/nonce mismatch')
    if not identifier(p['name']).startswith('nb-decoy-'):
        raise ValueError('invalid support abstract name')
    if set(ctx.request['targets']) != {role}:
        raise ValueError('support target mismatch')
    return p


class Mailbox:
    """Numbered immutable messages: stale/duplicate/nonmatching commands fail.
    The host also verifies liveness/socket ownership; ready alone is no witness.
    """
    def __init__(self, ctx, role):
        self.ctx, self.p, self.seq = ctx, config(ctx, role), 0
        self.written = 0
        self.files = Files(ctx.path(role))

    def emit(self, filename, **values):
        data = encoded({'nonce': self.p['nonce'], **values})
        if self.written + len(data) > 512 * 1024:
            raise ValueError('support journal byte budget')
        self.files.write(filename, data)
        self.written += len(data)

    def next(self):
        name = f'command-{self.seq:04d}.json'
        try:
            item = decode(self.files.read(name, 4096))
        except (FileNotFoundError, PublicationPending):
            return None
        if (type(item) is not dict or item.get('nonce') != self.p['nonce']
                or item.get('seq') != self.seq or self.seq >= 128):
            raise ValueError('support command identity/limit')
        self.seq += 1
        return item

    def close(self):
        self.files.close()


def receive(conn, ctx):
    data = bytearray()
    while True:
        conn.settimeout(ctx.remaining(3))
        chunk = conn.recv(min(4096, 16385 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > 16384:
            raise ValueError('victim request bound')


def victim(ctx):
    import base64
    box, listener = Mailbox(ctx, 'victim'), None
    current, seq, count = None, 0, 0
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind('\0' + box.p['name']); listener.listen(8)
        box.emit('ready.json', role='victim', name=box.p['name'])
        while True:
            ctx.remaining(540)
            command = box.next()
            if command is not None:
                op = command.get('op')
                if op == 'stop' and set(command) == {'nonce', 'seq', 'op'}:
                    if current is not None:
                        raise ValueError('victim stopped with unclosed window')
                    return
                fields(command, 'nonce seq op attempt secret')
                if (op != 'begin' or current is not None
                        or not re.fullmatch(r'[0-9a-f]{48}', command['secret'])):
                    raise ValueError('victim window command mismatch')
                identifier(command['attempt'])
                current, count = command, 0
                box.emit(f'window-{command["seq"]:04d}.json', cursor=seq, attempt=command['attempt'])
            if not select.select([listener], [], [], min(.02, ctx.remaining(540)))[0]:
                continue
            conn, _ = listener.accept()
            with conn:
                peer = dict(zip(('pid', 'uid', 'gid'), struct.unpack('3i', conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, 12))))
                data = receive(conn, ctx)
                if current is None or count >= 64 or seq >= 4096:
                    raise ValueError('connection outside victim window or record bound')
                ending = data == b'\0NB-END:' + current['secret'].encode() + b'\n'
                box.emit(f'event-{seq:06d}.json', seq=seq, kind='end' if ending else 'request',
                         attempt=current['attempt'], token=current['secret'] if ending else None,
                         peer=peer, bytes=len(data), payload_base64=base64.b64encode(data).decode())
                seq += 1; count += 1
                conn.sendall(data)
                if ending:
                    current = None
    finally:
        if listener is not None:
            listener.close()
        box.close()


def auxiliary(ctx):
    """Only a host-numbered POST instruction creates a pending question.
    The host must watch/verify it before an NB-21 action; no auto approval here.
    """
    box, conn, worker = Mailbox(ctx, 'auxiliary'), None, None
    done, result = threading.Event(), {}
    try:
        box.emit('ready.json', role='auxiliary')
        while True:
            ctx.remaining(540)
            command = box.next()
            if command is None:
                ctx.sleep(min(.02, ctx.remaining(540))); continue
            op = command.get('op')
            if op == 'stop':
                fields(command, 'nonce seq op')
                return
            fields(command, 'nonce seq op path')
            if op != 'question' or worker is not None:
                raise ValueError('unexpected/repeated auxiliary question')
            request_end = ctx.clock() + ctx.remaining(30)
            def remaining():
                left = min(ctx.remaining(30), request_end - ctx.clock())
                if left <= 0:
                    raise TimeoutError('auxiliary request deadline')
                return left
            conn = open_request('POST', 'nb-decoy-question.test', command['path'], remaining)
            # Sent != confirmed pending. Management.question is the host witness.
            box.emit(f'sent-{command["seq"]:04d}.json', path=command['path'])
            def read_result():
                try:
                    reply = response(conn, remaining)
                    import base64
                    result.update(category=reply['category'], status=reply['status'],
                                  body_base64=base64.b64encode(reply['body']).decode(), complete=True)
                except Exception as exc:
                    result.update(complete=False, error=type(exc).__name__ + ': ' + str(exc)[:256])
                finally:
                    done.set()
            worker = threading.Thread(target=read_result, daemon=True)
            worker.start()
            while not done.wait(min(.02, remaining())):
                pass
            worker.join(timeout=ctx.remaining(1))
            if worker.is_alive():
                raise TimeoutError('auxiliary request thread survived completion')
            box.emit(f'result-{command["seq"]:04d}.json', path=command['path'], **result)
            conn.close(); conn, worker = None, None
            done.clear(); result.clear()
    finally:
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        if worker is not None:
            worker.join(timeout=1)
            if worker.is_alive():
                raise RuntimeError('auxiliary request thread did not close')
        box.close()
