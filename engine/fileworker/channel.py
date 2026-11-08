"""Link H, the file worker's end of the row's file judgment port (SPEC-canonical-form.md §3.8; validation.md H-06,
H-08, H-15, H-17).

One thread reads the port and hands each answer to the session waiting under that sequence number; FILE_ASK and
FILE_WITHDRAW go out under one lock, whole. Sequence numbers start at 1 and never repeat inside this process; they are
this port's own, apart from the connector's (H-06). FILE_ALLOW carries the target the core opened as its one descriptor:
the frames are read one at a time, the length word first and then exactly the frame's bytes, so a descriptor that
arrives with a frame's first bytes is that frame's (the core sends it with the frame's first byte). A FILE_ALLOW without
exactly one descriptor, any other frame with one, a descriptor in the middle of a frame, a kind not on this link, a
frame that does not read or an answer of another shape closes every descriptor received and ends the worker; so does
the port closing (the worker exists only for its row; the spawner reports its exit to the core, H-17). An answer
nobody waits for any more has its descriptor closed at once. TCB module: standard library only.
"""
from __future__ import annotations

import itertools
import os
import socket
import threading
from dataclasses import dataclass
from typing import Callable

from connector import canonical
from connector.canonical import (FILE_ALLOW, FILE_ASK, FILE_DENY, FILE_OBJECT_LIST, FILE_REASONS, FILE_WITHDRAW,
                                 LINK_H_TO_WORKER, Malformed, pack_frame, read_uint, u64, unpack_list, unpack_payload)
from connector.channel import Waiter

FRAME_MAX = canonical.LIMITS.frame_h
FDS_MAX = 4               # room for more than one, so that a second descriptor is seen and refused, never cut silently


class Fault(Exception):
    """The core broke the protocol on this port."""


@dataclass(eq=False)
class FileAnswer:
    """What the core said about one sequence number."""

    kind: int                 # FILE_ALLOW, FILE_DENY or FILE_OBJECT_LIST
    op: int = 0               # FILE_ALLOW: the operation the descriptor was opened for
    fd: int = -1              # FILE_ALLOW: the opened target, owned by whoever holds this answer
    reason: int = 0           # FILE_DENY: the refusal code, 1..len(FILE_REASONS)
    objects: bytes = b''      # FILE_OBJECT_LIST: the list field as the core sent it

    def discard(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def close_all(fds: list[int]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


class CoreLink:
    def __init__(self, sock: socket.socket, on_fatal: Callable[[str], None], log: Callable[..., None]) -> None:
        self.sock, self.on_fatal, self.log = sock, on_fatal, log
        self._seq = itertools.count(1)
        self._out = threading.Lock()                           # frames out and the sequence counter
        self._waiters: dict[int, Waiter] = {}
        self._wlock = threading.Lock()
        self.dead = False

    # ---- session threads: asking, waiting, withdrawing ----
    def submit(self, build: Callable[[int], list[bytes]]) -> Waiter:
        """Allocate the sequence number, register the waiter and send the FILE_ASK as one step under the output lock:
        numbers reach the core in increasing order (K-36 for this port) and no answer can come before its waiter."""
        with self._out:
            seq = next(self._seq)
            waiter = Waiter(seq)
            with self._wlock:
                self._waiters[seq] = waiter
            self._send_locked(pack_frame(FILE_ASK, build(seq)))
        return waiter

    def unregister(self, waiter: Waiter) -> FileAnswer | None:
        """Stop waiting: an answer that already arrived is handed back for the caller to use or discard; one that
        arrives later is refused at publication and its descriptor closed there."""
        with self._wlock:
            self._waiters.pop(waiter.seq, None)
        return waiter.retire()

    def withdraw(self, seq: int) -> None:
        with self._out:
            self._send_locked(pack_frame(FILE_WITHDRAW, [u64(seq)]))

    def _send_locked(self, frame: bytes) -> None:
        if self.dead:
            return
        try:
            self.sock.sendall(frame)
        except OSError:
            self._fatal('core port write failed')

    # ---- the core thread: frames in ----
    def run(self) -> None:
        """``held`` owns every descriptor received for the frame being read, from the moment recv_fds returns it until
        _frame takes them: _read only adds to it, and the one way out below closes and empties it, so a descriptor is
        closed exactly once whichever receive fails or whichever check refuses (Codex review, minor 3)."""
        held: list[int] = []
        try:
            while not self.dead:
                head = self._read(4, held)
                if head is None:
                    self._fatal('core port closed')
                    return
                length = int.from_bytes(head, 'big')
                if length < 1 or length > FRAME_MAX:
                    raise Fault('frame length outside the link H limit')
                body = self._read(length, held, mid_frame=True)
                if body is None:
                    raise Fault('core port closed inside a frame')
                fds = held[:]
                held.clear()                       # _frame owns them now, and closes them if it refuses the frame
                self._frame(body, fds)
        except OSError:
            self._release(held)
            self._fatal('core port read failed')
        except (Fault, Malformed) as e:
            self._release(held)
            self._fatal(f'core protocol: {e}')

    @staticmethod
    def _release(held: list[int]) -> None:
        close_all(held)
        held.clear()

    def _read(self, n: int, held: list[int], mid_frame: bool = False) -> bytes | None:
        """Exactly n bytes, or None at a clean end of stream before any of them. Descriptors that come with them are
        added to ``held`` at once and never closed here; one that comes while the body of a frame is read is a fault (it
        is not this frame's)."""
        data = bytearray()
        while len(data) < n:
            chunk, fds, flags, _ = socket.recv_fds(self.sock, n - len(data), FDS_MAX, socket.MSG_CMSG_CLOEXEC)
            held.extend(fds)
            if flags & (socket.MSG_CTRUNC | getattr(socket, 'MSG_TRUNC', 0)):
                raise Fault('ancillary data cut')
            if fds and mid_frame:
                raise Fault('a descriptor in the middle of a frame')
            if not chunk:
                if not data and not mid_frame and not held:
                    return None
                raise Fault('core port closed inside a frame')
            data += chunk
        return bytes(data)

    def _frame(self, body: bytes, fds: list[int]) -> None:
        kind = body[0]
        try:
            if kind not in LINK_H_TO_WORKER:
                raise Fault('kind not on the file judgment port (H-06)')
            fields = unpack_payload(kind, body[1:])
            seq = read_uint(fields[0], 8)
            if kind == FILE_ALLOW:
                if len(fds) != 1:
                    raise Fault('FILE_ALLOW without exactly one descriptor')
                answer = FileAnswer(FILE_ALLOW, op=read_uint(fields[1], 1), fd=fds[0])
            elif fds:
                raise Fault('a descriptor with a frame that carries none')
            elif kind == FILE_DENY:
                reason = read_uint(fields[1], 1)
                if not 1 <= reason <= len(FILE_REASONS):
                    raise Fault(f'refusal code {reason} outside the word list (H-18)')
                answer = FileAnswer(FILE_DENY, reason=reason)
            else:
                unpack_list(fields[1], canonical.LIMITS.file_objects)            # the shape only: it must read
                answer = FileAnswer(FILE_OBJECT_LIST, objects=fields[1])
        except (Fault, Malformed):
            close_all(fds)
            raise
        self._deliver(seq, answer)

    def _deliver(self, seq: int, answer: FileAnswer) -> None:
        with self._wlock:
            waiter = self._waiters.pop(seq, None)
        if waiter is None or not waiter.publish(answer):       # nobody waits any more: the descriptor goes at once
            answer.discard()
            self.log('answer_without_waiter', seq=seq, kind=answer.kind)

    def _fatal(self, why: str) -> None:
        if self.dead:
            return
        self.dead = True
        self.log('core_port_fatal', reason=why)
        self.on_fatal(why)
