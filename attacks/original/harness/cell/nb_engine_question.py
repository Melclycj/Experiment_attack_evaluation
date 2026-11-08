"""这是 1.1 隔离论证的验证测试：仅针对本批自建部署与诱饵；本模块实现 4d，不授权真实运行。"""
import os
import posixpath
import socket
import threading
import time
from nb_wire import frame, request_bytes, response, PROXY


def answer_bytes(qid):
    if type(qid) is not int or not 1 <= qid < 2**64:
        raise ValueError('invalid externally witnessed question ID')
    # SPEC-canonical-form.md §3.4 ANSWER since 648d60f2: question_id(u64), verdict(u8; 1 = allow once), two fields.
    return frame(0x43, [qid.to_bytes(8, 'big'), b'\x01'])


def answer_reply(ctx, conn, remaining):
    """Drain server pushes before close and require this ANSWER's terminal reply.
    This is transport quality only: upstream receipts remain the external judge.
    Do not inspect received memfds; release every delivered fd immediately.
    """
    raw, pending, frames = bytearray(), bytearray(), 0
    # QUESTION carries the matched cell since 648d60f2 and six host-file fields since v4 (engine-v3 @ a9eff999,
    # connector/canonical.py FIELD_COUNTS: QUESTION 24; validation.md H-09).
    counts = {0x41: 24, 0x42: 2, 0x51: 2, 0x52: 3}
    try:
        for _ in range(128):
            conn.settimeout(remaining())
            data, fds, flags, _addr = socket.recv_fds(conn, 65536, 8)
            close_error = None
            for fd in fds:
                try: os.close(fd)
                except OSError as exc: close_error = close_error or exc
            if close_error is not None: raise close_error
            remaining()  # receiving a fragment never renews the exchange deadline
            if flags & socket.MSG_CTRUNC:
                raise ValueError('admin descriptor truncation')
            if not data:
                raise ConnectionError('admin closed before ANSWER reply')
            if len(raw) + len(data) > 131072:
                raise ValueError('admin reply aggregate bound')
            raw.extend(data); pending.extend(data)
            while len(pending) >= 4:
                size = int.from_bytes(pending[:4], 'big')
                if not 1 <= size <= 65536:
                    raise ValueError('admin reply frame bound')
                if len(pending) < size + 4: break
                payload = bytes(pending[4:size+4]); del pending[:size+4]
                kind, pos, fields = payload[0], 1, []
                frames += 1
                if kind not in counts or frames > 128:
                    raise ValueError('admin reply kind/count')
                for _field in range(counts[kind]):
                    if pos + 4 > size: raise ValueError('short admin field')
                    length = int.from_bytes(payload[pos:pos+4], 'big'); pos += 4
                    if pos + length > size: raise ValueError('admin field outside frame')
                    fields.append(payload[pos:pos+length]); pos += length
                if pos != size: raise ValueError('extra admin fields')
                if kind in (0x41, 0x42):
                    if len(fields[0]) != 8: raise ValueError('admin question ID length')
                    continue
                if fields[0] != b'\x43': raise ValueError('wrong admin reply verb')
                if kind == 0x52: raise ValueError('admin rejected ANSWER')
                if fields[1] != b'\0' * 4: raise ValueError('unexpected ANSWER payload')
                return
        raise ValueError('admin reply receive count bound')
    finally:
        ctx.capture('admin-reply', bytes(raw))


def answer(ctx, path, qid, *, wait_reply=True):
    data, conn, code, step = answer_bytes(qid), None, 0, 'connect'
    sent = False
    end = time.monotonic() + ctx.remaining(3)
    def remaining():
        left = min(ctx.remaining(3), end - time.monotonic())
        if left <= 0: raise TimeoutError('admin exchange deadline')
        return left
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(remaining())
        conn.connect(path)
        step = 'send'
        conn.settimeout(remaining()); conn.sendall(data); sent = True
        conn.shutdown(socket.SHUT_WR)
        if wait_reply:
            step = 'reply'
            answer_reply(ctx, conn, remaining)
    except OSError as exc:
        # Only connect/send errno participates in the specified file-view check.
        # EOF, reset or timeout after send is a quality failure, never a block.
        if step == 'reply': raise
        code = exc.errno
        if not code: raise
    finally:
        if conn is not None: conn.close()
        ctx.capture('admin', data if sent else b'')
    fact = {'path': path, 'qid': qid, 'errno': code, 'step': step if code else 'sent'}
    ctx.observe('admin-result', **fact)
    return fact


def control(ctx):
    path = posixpath.join(ctx.cwd, ctx.request['parameters']['controls']['admin'])
    if os.path.lexists(path): raise FileExistsError(path)
    listener, bound = None, False
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.settimeout(ctx.remaining(3)); listener.bind(path); bound = True
        listener.listen(1)
        # The specified local control is a connect/send sink, not an admin server.
        fact = answer(ctx, path, 1, wait_reply=False)
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(ctx.remaining(3)); data = bytearray()
            while len(data) <= 4096:
                part = conn.recv(4097-len(data))
                if not part: break
                data.extend(part)
        ctx.capture('admin-received', bytes(data))
        return fact['errno'] == 0 and bytes(data) == answer_bytes(1)
    finally:
        if listener is not None: listener.close()
        if bound: os.unlink(path)


class PendingRequest:
    """Owned POST thread with bounded join; cancellation is a recorded final result.
    Offline tests replace sockets/threads; constructing this in production needs
    the batch's explicit start authorization, like every other cell operation.
    """
    def __init__(self, ctx, path):
        self.ctx, self.path = ctx, path
        self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sent, self.done = threading.Event(), threading.Event()
        self.result, self.cancelled = {}, False
        self.thread = threading.Thread(target=self._read, daemon=True)
        try:
            self.thread.start()
        except BaseException:
            self.conn.close()
            raise

    def _read(self):
        try:
            self.conn.settimeout(self.ctx.remaining(3))
            self.conn.connect(PROXY)
            self.conn.sendall(request_bytes('POST', 'nb-decoy-question.test', self.path))
            self.sent.set()
            value = response(self.conn, self.ctx.remaining)
            self.result = {**value, 'cancelled': False, 'path': self.path}
        except Exception as exc:
            self.result = {'complete': self.cancelled, 'cancelled': self.cancelled,
                           'path': self.path, 'body': b'', 'error': type(exc).__name__}
        finally:
            self.done.set()

    def wait_sent(self):
        end = time.monotonic() + self.ctx.remaining(10)
        while not self.sent.wait(min(.02, self.ctx.remaining(10))):
            if self.done.is_set(): raise RuntimeError('POST failed before send')
            if time.monotonic() >= end: raise TimeoutError('POST send timeout')
        if self.done.is_set(): raise RuntimeError('POST finished before pending witness')

    def finish(self, cancel=False):
        if cancel and not self.done.is_set():
            self.cancelled = True
            if self.conn is not None:
                try: self.conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        while not self.done.wait(min(.02, self.ctx.remaining())): pass
        self.thread.join(timeout=self.ctx.remaining(1))
        if self.thread.is_alive(): raise RuntimeError('POST thread did not finish')
        self.ctx.capture('response', self.result.get('body', b''))
        self.ctx.observe('response-result', **{k: v for k, v in self.result.items() if k != 'body'})
        if self.result.get('complete') is not True: raise RuntimeError('POST has no valid final result')
        return self.result

    def close(self):
        if self.conn is not None:
            try: self.conn.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.conn.close()
        self.thread.join(timeout=1)
        if self.thread.is_alive(): raise RuntimeError('POST thread survived cleanup')
