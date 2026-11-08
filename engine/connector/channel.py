"""Link B, the connector's end of the row's judgment port (agent-rm-model 4.2 三条口, 4.3 批准到执行的衔接;
SPEC-canonical-form.md §3.2; validation.md C-14, C-15, C-26, C-27, C-28, C-29).

One thread reads the port and hands each answer to the fd thread waiting under that sequence number; frames go out
under one lock, whole, with the body's sealed memfd riding the JUDGE frame. Sequence numbers start at 1 and never
repeat inside this process. An ALLOW frame holds the truth: it is read into a bytearray that only the replacement code
sees, and an ALLOW nobody waits for any more is zeroed at once and reported as not sent (C-14). A frame of a kind that
is not on this link, a frame that does not read (its named field included, K-59), or the port closing ends the
connector (C-28): without the core it has nothing to do, and the spawner reports its exit to the core. TCB module:
standard library only.
"""
from __future__ import annotations

import array
import ctypes
import ipaddress
import itertools
import os
import socket
import threading
from dataclasses import dataclass
from typing import Any, Callable

from . import canonical
from .canonical import (ALLOW, ALLOW_NOCRED, BEARER_WORDS, DENY, JUDGE, LINK_B_TO_CONNECTOR, PLACE_API_KEY, PLACE_BASIC,
                        PLACE_BEARER, REPORT, RES_UNSENT, REVOKE, WITHDRAW, FIELD_COUNT, Malformed, pack_frame, u16, u64, u8)

FRAME_MAX = canonical.LIMITS.frame_bd
SCRATCH = 65536


class Fault(Exception):
    """The core broke the protocol on this port."""


@dataclass(eq=False)
class Answer:
    """What the core said about one sequence number."""

    kind: int                         # ALLOW, ALLOW_NOCRED or DENY
    placement: int = 0
    word: bytes = b''                 # the registered authorization word of the bearer placement
    truth: bytearray | None = None    # the replacement buffer (工程项 6 five places); zeroed by whoever finishes with it
    truth_b: bytearray | None = None  # the Basic password
    account: bytes = b''
    account_destination: bool = False
    reason: int = 0
    named: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()   # the covering cell's named prefixes (K-59)

    def zero(self) -> None:
        for buf in (self.truth, self.truth_b):
            if buf is not None:
                buf[:] = bytes(len(buf))
        self.truth = self.truth_b = None


class Waiter:
    """An fd thread's wait for one answer: a pipe the channel thread writes a byte to when the answer is in. Publishing,
    reading and closing happen under the waiter's own lock, so a delivery never writes into a descriptor number the
    session has already closed and reused (review B, B5)."""

    __slots__ = ('seq', 'r', 'w', 'answer', 'lock', 'closed')

    def __init__(self, seq: int) -> None:
        self.seq = seq
        self.r, self.w = os.pipe()
        self.answer: Answer | None = None
        self.lock = threading.Lock()
        self.closed = False

    def publish(self, answer: Answer) -> bool:
        """Hand the answer over and wake the session; False when the session already left (the caller then zeroes)."""
        with self.lock:
            if self.closed:
                return False
            self.answer = answer
            try:
                os.write(self.w, b'x')
            except OSError:
                pass
            return True

    def take(self) -> Answer | None:
        with self.lock:
            return self.answer

    def retire(self) -> Answer | None:
        """The session stops waiting: from here on a publication is refused (and the channel thread zeroes and reports
        it, C-14); an answer published before this instant is handed back. Atomic with publish (review B, NS1)."""
        with self.lock:
            self.closed = True
            return self.answer

    def close(self) -> None:
        with self.lock:
            self.closed = True
            for fd in (self.r, self.w):
                try:
                    os.close(fd)
                except OSError:
                    pass


def read_uint(view: memoryview, size: int) -> int:
    if len(view) != size:
        raise Malformed(f'integer field of {len(view)} bytes, expected {size}')
    return int.from_bytes(view, 'big')


def split_fields(payload: memoryview, count: int) -> list[memoryview]:
    """unpack_payload over a memoryview: no copy of the bytes, so an ALLOW frame's truth is read in place."""
    fields: list[memoryview] = []
    pos = 0
    while pos < len(payload):
        if len(fields) >= count:
            raise Malformed(f'more than {count} fields')
        if pos + 4 > len(payload):
            raise Malformed('field length word beyond the frame')
        n = int.from_bytes(payload[pos:pos + 4], 'big')
        pos += 4
        if pos + n > len(payload):
            raise Malformed('field beyond the frame')
        fields.append(payload[pos:pos + n])
        pos += n
    if len(fields) != count:
        raise Malformed(f'{len(fields)} fields, expected {count}')
    return fields


class CoreChannel:
    def __init__(self, sock: socket.socket, registry: Any, on_fatal: Callable[[str], None],
                 log: Callable[..., None]) -> None:
        self.sock, self.registry, self.on_fatal, self.log = sock, registry, on_fatal, log
        self._seq = itertools.count(1)
        self._out = threading.Lock()                           # frames out and the sequence counter
        self._waiters: dict[int, Waiter] = {}
        self._wlock = threading.Lock()
        self.dead = False

    # ---- fd threads: submitting, waiting, frames out ----
    def submit(self, build: Callable[[int], list[bytes]], memfd: int) -> Waiter:
        """Allocate the sequence number, register the waiter and send the JUDGE frame as one step under the output
        lock: sequence numbers reach the core in the order they were allocated (SPEC §3.2, K-36; review B, S1) and no
        answer can arrive before its waiter exists."""
        with self._out:
            seq = next(self._seq)
            waiter = Waiter(seq)
            with self._wlock:
                self._waiters[seq] = waiter
            self._send_locked(pack_frame(JUDGE, build(seq)), memfd)
        return waiter

    def unregister(self, waiter: Waiter) -> Answer | None:
        """Stop waiting: the answer that already arrived is handed back for the caller to use or to zero; one that
        arrives later is refused at publication and handled there (C-14)."""
        with self._wlock:
            self._waiters.pop(waiter.seq, None)
        return waiter.retire()

    def withdraw(self, seq: int) -> None:
        self._send(pack_frame(WITHDRAW, [u64(seq)]))

    def report(self, seq: int, result: int, status: int) -> None:
        self._send(pack_frame(REPORT, [u64(seq), u8(result), u16(status)]))

    def _send(self, frame: bytes, fd: int | None = None) -> None:
        with self._out:
            self._send_locked(frame, fd)

    def _send_locked(self, frame: bytes, fd: int | None = None) -> None:
        if self.dead:
            return
        try:
            if fd is None:
                self.sock.sendall(frame)
            else:                                              # the descriptor rides the first byte of the frame
                sent = self.sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
                if sent < len(frame):
                    self.sock.sendall(frame[sent:])
        except OSError:
            self._fatal('judgment port write failed')

    # ---- the channel thread: frames in ----
    def run(self) -> None:
        """One receive buffer of fixed capacity for the thread's whole life: bytes are read straight into it, frames
        are parsed in place through views, the remainder is moved down with memmove and the vacated tail is zeroed.
        Nothing here grows, so no reallocation can leave an old block holding a truth behind (工程项 6; review B, OM3)."""
        cap = 4 + FRAME_MAX + SCRATCH
        buf = bytearray(cap)
        view = memoryview(buf)
        raw = (ctypes.c_char * cap).from_buffer(buf)
        base = ctypes.addressof(raw)
        used = 0
        try:
            while not self.dead:
                if used >= cap:
                    raise Fault('frame does not fit the receive buffer')
                n = self.sock.recv_into(view[used:])
                if n == 0:
                    self._fatal('judgment port closed')
                    return
                used += n
                while True:
                    consumed = self._frame(view, used)
                    if not consumed:
                        break
                    rest = used - consumed
                    ctypes.memmove(base, base + consumed, rest)
                    buf[rest:used] = bytes(used - rest)        # the vacated bytes may have held a truth
                    used = rest
        except OSError:
            self._fatal('judgment port read failed')
        except (Fault, Malformed) as e:
            self._fatal(f'core protocol: {e}')
        finally:
            buf[:] = bytes(cap)

    def _frame(self, view: memoryview, used: int) -> int:
        """Parse and dispatch the first whole frame in view[:used]; return the bytes it took, 0 when incomplete."""
        if used < 4:
            return 0
        length = int.from_bytes(view[:4], 'big')
        if length < 1 or length > FRAME_MAX:
            raise Fault('frame length outside the link B limit')
        if used >= 5 and view[4] not in LINK_B_TO_CONNECTOR:
            raise Fault('kind not on the judgment port (C-28)')
        if used < 4 + length:
            return 0
        kind = view[4]
        fields = split_fields(view[5:4 + length], FIELD_COUNT[kind])
        try:
            self._dispatch(kind, fields)
        finally:
            for f in fields:
                f.release()
        return 4 + length

    def _dispatch(self, kind: int, f: list[memoryview]) -> None:
        if kind == ALLOW:
            seq = read_uint(f[0], 8)
            account = bytes(f[5])
            if not account:                                    # the no-credential connections carry the empty account (OM7)
                raise Fault('ALLOW without an account identifier (条款 8)')
            placement, word = read_uint(f[1], 1), bytes(f[2])
            # the frame's shape follows the registered placement (SPEC 3.2): a word only for bearer, a password only
            # for Basic, a truth always
            if (placement not in (PLACE_API_KEY, PLACE_BEARER, PLACE_BASIC) or not len(f[3])
                    or (word in BEARER_WORDS) is not (placement == PLACE_BEARER) or (placement != PLACE_BEARER and word)
                    or bool(len(f[4])) is not (placement == PLACE_BASIC)):
                raise Fault('ALLOW does not have the shape of its placement (SPEC 3.2)')
            named = canonical.read_named(bytes(f[6]))         # K-59, C-28: read before the truth is copied out
            answer = Answer(ALLOW, placement, word, bytearray(f[3]), bytearray(f[4]) if placement == PLACE_BASIC else None,
                            account, True, named=named)
        elif kind == ALLOW_NOCRED:
            seq = read_uint(f[0], 8)
            answer = Answer(ALLOW_NOCRED, account_destination=bool(read_uint(f[1], 1)),
                            named=canonical.read_named(bytes(f[2])))
        elif kind == DENY:
            seq = read_uint(f[0], 8)
            answer = Answer(DENY, reason=read_uint(f[1], 1))
        elif kind == REVOKE:
            scope = read_uint(f[3], 1)
            if scope not in (1, 2) or (scope == 2 and len(f[2])) or (scope == 1 and not len(f[2])):
                raise Fault('REVOKE scope and account do not agree (SPEC 3.2)')
            cut = self.registry.revoke(read_uint(f[0], 1), bytes(f[1]), bytes(f[2]), scope == 2)
            self.log('revoked', key_kind=read_uint(f[0], 1), scope=scope, connections=cut)
            return
        else:
            raise Fault('kind not on the judgment port (C-28)')
        self._deliver(seq, answer)

    def _deliver(self, seq: int, answer: Answer) -> None:
        with self._wlock:
            waiter = self._waiters.pop(seq, None)
        if waiter is None or not waiter.publish(answer):       # C-14: nobody waits any more; truth is zeroed, nothing is sent
            answer.zero()
            self.log('answer_without_waiter', seq=seq, kind=answer.kind)
            if answer.kind in (ALLOW, ALLOW_NOCRED):
                self.report(seq, RES_UNSENT, 0)

    def _fatal(self, why: str) -> None:
        if self.dead:
            return
        self.dead = True
        self.log('judgment_port_fatal', reason=why)
        self.on_fatal(why)
