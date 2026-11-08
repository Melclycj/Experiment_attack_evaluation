"""Judgment port of one row (agent-rm-model 3.7 connector 的地位, 3.9 两条口的先后; SPEC-canonical-form.md §3.2; validation.md
K-01, K-02, K-03, K-24, K-34, K-36, K-38).

The core end of the socketpair the spawner made for the row's connector. Frames are read by the native judgment reader
(transport.c w2_judge_receive): every fragment's kernel credential must carry the connector's dedicated uid, and a JUDGE
frame brings exactly one descriptor, the sealed memfd of the body. The port knows its row by being the row's object
(K-01): nothing here looks a row up by fd, uid or content. Decisions come from the hook; this module only moves frames.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
import errno
import fcntl
import os
import selectors
import socket
from typing import Any, Callable

from connector import canonical
from connector.canonical import (ALLOW, ALLOW_NOCRED, DENY, JUDGE, LINK_B_TO_CORE, REPORT, REVOKE, WITHDRAW, Malformed,
                                 pack_list, read_uint, u8, u32, u64, unpack_list, unpack_payload)
from .ffi import Frame, Native

FRAME_MAX = canonical.LIMITS.frame_bd          # link B frame limit (1 MiB)
OUT_QUEUE_MAX = 256                            # frames waiting to go to the connector before the port is faulted
REQUIRED_SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW

# DENY reasons (SPEC 3.2; 648d60f2 4.3 拒绝回复): one public word each, the finer cause goes to the trace only
DENY_RECORDED, DENY_USER, DENY_TIMEOUT, DENY_CLAUSE, DENY_UNAVAILABLE = 1, 2, 3, 4, 5
DENY_NOT_AUTHORIZED, DENY_PDP, DENY_POLICY_CHANGED, DENY_CREDENTIAL = 6, 7, 8, 9
DENY_CLOSED = DENY_QUEUE_FULL = DENY_UNAVAILABLE     # row closed, queue full: both unavailable
# REPORT results
REPORT_RESPONSE, REPORT_TRANSPORT_ERROR, REPORT_UNKNOWN, REPORT_NOT_SENT = 1, 2, 3, 4


class PortFault(Exception):
    """The connector broke the protocol: the port is closed and the row with it (K-02, K-03, K-36)."""


@dataclass(frozen=True)
class JudgedRequest:
    """The canonical request as the connector judged it, re-read through the same grammar (C-05) before use."""

    seq: int
    sender_uid: int
    method: bytes
    scheme: bytes
    host: bytes
    port: int
    path: bytes
    query: bytes | None
    headers: tuple[tuple[bytes, bytes], ...]
    stripped: tuple[bytes, ...]
    body_kind: str
    form_keys: tuple[str, ...]
    body_len: int

    def summary(self) -> dict[str, Any]:
        """The request's shape, carried by the records after admission (the PDP request): names and lengths only."""
        return {'seq': self.seq, 'method': self.method.decode(), 'scheme': self.scheme.decode(), 'host': self.host.decode(),
                'port': self.port, 'path': self.path.decode(), 'query_len': len(self.query or b''),
                'header_names': [n.decode() for n, _ in self.headers], 'stripped': [n.decode() for n in self.stripped],
                'body_kind': self.body_kind, 'form_keys': list(self.form_keys), 'body_len': self.body_len}

    def admission_record(self) -> dict[str, Any]:
        """The admission record (design 4.1, 2026-11-02; K-23): the request as it will be executed, every field but the
        body, once per request. The query is ASCII by the grammar; header values decode as latin-1, so encode('latin-1')
        gives the bytes back. Truth is never here: the connector places it after the release."""
        return {**self.summary(), 'query': None if self.query is None else self.query.decode('ascii'),
                'header_values': [v.decode('latin-1') for _, v in self.headers]}


def decode_judge(fields: list[bytes], row_uid: int) -> JudgedRequest:
    """SPEC 3.2 JUDGE: 13 fields. The request fields go through parse_request again (the connector is in the TCB, but a
    second reading costs nothing and keeps the core's view identical to the grammar); the sender uid must be the row's."""
    seq, sender_uid = read_uint(fields[0], 8), read_uint(fields[1], 4)
    if seq == 0:
        raise Malformed('seq 0')
    if sender_uid != row_uid:
        raise PortFault('JUDGE sender is not this row')
    req = canonical.parse_request([fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8], b''])
    stripped = tuple(unpack_list(fields[9], 16))
    body_kind = fields[10].decode('ascii')
    if body_kind != req.body_kind:
        raise Malformed('body_kind does not follow from the headers')
    keys = tuple(k.decode('latin-1') for k in unpack_list(fields[11], canonical.FORM_KEYS_MAX))
    if sum(len(k) for k in keys) > canonical.FORM_KEYS_BYTES_MAX:
        raise Malformed('form keys exceed the byte budget')
    body_len = read_uint(fields[12], 8)
    if body_len > canonical.LIMITS.body:
        raise Malformed('body_len exceeds the limit')
    return JudgedRequest(seq, sender_uid, req.method, req.scheme, req.host, req.port, req.path, req.query,
                         req.headers, stripped, body_kind, keys, body_len)


def check_memfd(fd: int, body_len: int) -> bool:
    """K-24: the three seals are present and the size is the declared body length. A plain file has no seals."""
    try:
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        return (seals & REQUIRED_SEALS) == REQUIRED_SEALS and os.fstat(fd).st_size == body_len
    except OSError:
        return False


class RawWriter:
    """Outgoing frames to the connector, in bytearrays zeroed once sent or dropped (the ALLOW frame holds truth)."""

    def __init__(self, loop: Any, sock: socket.socket, on_fault: Callable[[str], None]) -> None:
        self.loop, self.sock, self.on_fault = loop, sock, on_fault
        self.queue: list[bytearray] = []
        self.offset = 0
        self.watching = False

    def send(self, frame: bytearray) -> None:
        if len(self.queue) >= OUT_QUEUE_MAX:
            self.zero(frame)
            self.on_fault('connector does not drain its judgment port')
            return
        self.queue.append(frame)
        self.flush()

    def flush(self) -> None:
        while self.queue:
            frame = self.queue[0]
            try:
                n = self.sock.send(memoryview(frame)[self.offset:], socket.MSG_NOSIGNAL | socket.MSG_DONTWAIT)
            except (BlockingIOError, InterruptedError):
                if not self.watching:
                    self.loop.watch(self.sock.fileno(), selectors.EVENT_WRITE, self.flush)
                    self.watching = True
                return
            except OSError:
                self.discard()
                self.on_fault('judgment port write failed')
                return
            self.offset += n
            if self.offset >= len(frame):
                self.zero(frame)
                self.queue.pop(0)
                self.offset = 0
        if self.watching:
            self.loop.watch(self.sock.fileno(), selectors.EVENT_WRITE, None)
            self.watching = False

    def discard(self) -> None:
        for frame in self.queue:
            self.zero(frame)
        self.queue.clear()
        self.offset = 0

    @staticmethod
    def zero(frame: bytearray) -> None:
        frame[:] = bytes(len(frame))


def named_field(named: tuple[str, ...]) -> bytes:
    """The named field of ALLOW and ALLOW_NOCRED (SPEC §3.2; K-59): the cell's stored prefix texts, as a list."""
    return pack_list([x.encode('ascii') for x in named])


def frame_bytes(kind: int, fields: list[bytes | bytearray]) -> bytearray:
    """pack_frame for bytearray fields: the frame is built in one bytearray, so no second copy of the truth is left
    behind for the garbage collector (工程项 6; review B, S6)."""
    if len(fields) != canonical.FIELD_COUNT[kind]:
        raise ValueError('field count')
    size = 5 + sum(4 + len(f) for f in fields)
    frame = bytearray(size)                            # allocated once at its final size: no growth after the truth is in
    frame[0:4] = u32(size - 4)
    frame[4] = kind
    at = 5
    for f in fields:
        frame[at:at + 4] = u32(len(f))
        frame[at + 4:at + 4 + len(f)] = f
        at += 4 + len(f)
    return frame


class JudgmentPort:
    """One row's port. ``hook`` receives admit/withdraw/report; ``on_fault`` closes the row (K-02)."""

    def __init__(self, loop: Any, native: Native, ex: Any, sock: socket.socket, connector_uid: int, overflow: int,
                 hook: Any, on_fault: Callable[[Any, str], None], trace: Callable[..., None]) -> None:
        self.loop, self.native, self.ex, self.sock = loop, native, ex, sock
        self.connector_uid, self.overflow, self.hook, self.on_fault, self.trace = connector_uid, overflow, hook, on_fault, trace
        self.reader: int | None = native.judge_reader_new(FRAME_MAX)
        self.buffer = ctypes.create_string_buffer(FRAME_MAX)
        self.writer = RawWriter(loop, sock, lambda why: self.fault(why))
        self.last_seq = 0
        self.closed = False
        sock.setblocking(False)
        loop.watch(sock.fileno(), selectors.EVENT_READ, self._readable)

    # ---- inbound ----
    def _readable(self) -> None:
        for _ in range(64):                       # bounded work per loop step; the loop comes back for more
            if self.closed or self.reader is None:
                return
            kind, body, fd = self.native.judge_receive(self.reader, self.buffer, self.sock.fileno(), self.connector_uid,
                                                       self.overflow)
            if kind is Frame.IDLE:
                return
            if kind is Frame.MORE:
                continue
            if kind is Frame.REJECT:
                self.fault('judgment reader rejected a fragment')
                return
            try:
                self._frame(body, fd)
            except PortFault as e:
                if fd is not None:
                    os.close(fd)
                self.fault(str(e))
                return
            except Malformed as e:
                if fd is not None:
                    os.close(fd)
                self.fault(f'malformed frame: {e}')
                return

    def _frame(self, body: bytes, fd: int | None) -> None:
        if not body or body[0] not in LINK_B_TO_CORE:
            raise PortFault('kind not on the judgment port (K-03)')
        kind = body[0]
        fields = unpack_payload(kind, body[1:])
        if kind == JUDGE:
            if fd is None:
                raise PortFault('JUDGE without its memfd')
            request = decode_judge(fields, self.ex.lease.uid)
            if request.seq <= self.last_seq:
                raise PortFault('JUDGE seq does not increase (K-36)')
            self.last_seq = request.seq
            self.hook.admit(self.ex, self, request, fd)          # the hook owns the fd from here
            return
        if fd is not None:
            raise PortFault('descriptor on a non-JUDGE frame')
        if kind == WITHDRAW:
            self.hook.withdraw(self.ex, read_uint(fields[0], 8))
        elif kind == REPORT:
            self.hook.report(self.ex, read_uint(fields[0], 8), read_uint(fields[1], 1), read_uint(fields[2], 2))

    # ---- outbound ----
    def send_allow(self, seq: int, placement: int, word: bytes, truth_a: bytearray, truth_b: bytearray,
                   account: str, named: tuple[str, ...]) -> None:
        """The registered placement, its authorization word and the truths: the connector builds the whole header value
        from them (648d60f2 4.3 凭据, C-16). The account identifier rides along (SPEC 3.2): the connector keys upstream
        connections by it (条款 8) and matches REVOKE frames against it (C-26); it is an identifier, never a truth.
        ``named``: the passing cell's named addresses, stored prefix texts (K-59)."""
        frame = frame_bytes(ALLOW, [u64(seq), u8(placement), word, truth_a, truth_b, account.encode('utf-8'),
                                    named_field(named)])
        RawWriter.zero(truth_a)                    # the read buffers (工程项 6: five places only)
        RawWriter.zero(truth_b)
        self.writer.send(frame)

    def send_allow_nocred(self, seq: int, account_destination: bool, named: tuple[str, ...]) -> None:
        """account_destination: the matched entry names accounts, so the response's Set-Cookie is dropped (条款 10).
        ``named``: as for ALLOW (K-59)."""
        self.writer.send(frame_bytes(ALLOW_NOCRED, [u64(seq), u8(1 if account_destination else 0), named_field(named)]))

    def send_deny(self, seq: int, reason: int) -> None:
        self.writer.send(frame_bytes(DENY, [u64(seq), u8(reason)]))

    def send_revoke(self, key_kind: int, key: bytes, account: bytes, everyone: bool = False) -> None:
        """scope 1: the connections of this one account under the key; scope 2: every connection under the key,
        whatever its account and the credential-less ones too (SPEC 3.2; review B, NB2)."""
        self.writer.send(frame_bytes(REVOKE, [u8(key_kind), key, account, u8(2 if everyone else 1)]))

    # ---- end ----
    def fault(self, why: str) -> None:
        if self.closed:
            return
        self.trace('judgment_port_fault', execution_id=self.ex.execution_id, reason=why)
        self.on_fault(self.ex, why)

    def close(self) -> None:
        """Release the socket and the reader; the hook's row_closed runs separately (the lifecycle orders them)."""
        if self.closed:
            return
        self.closed = True
        self.loop.forget(self.sock.fileno())
        self.writer.discard()
        if self.reader is not None:
            self.native.judge_reader_free(self.reader)
            self.reader = None
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
