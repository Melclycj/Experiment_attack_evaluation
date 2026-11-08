"""One accepted file-port connection, one thread (SPEC-canonical-form.md §3.7 link G; validation.md H-04, H-05, H-13,
H-15, H-16, H-18).

The thread reads one request frame through the native credential-checking reader (every fragment's kernel stamp is the
row's uid and a pid above 0), checks the frame's shape only (kind on link G, field count, integer widths, at most 8 KiB)
and passes alias, path, start and length on to the core unchanged as FILE_ASK: whether they are allowed is the core's
first checkpoint (H-07), which records its refusals. A frame that does not read ends the connection unanswered. The
thread then waits for the core while watching the client; a client that leaves withdraws the request, a wait past the
connector's total limit withdraws it and answers timeout. The core's FILE_DENY becomes FILE_REFUSED with the same code;
its FILE_ALLOW brings the opened target, which the worker checks with fstat against the operation, reads with pread or
lists with scandir, answers from, and closes. Nothing here opens, stats or lists anything by path. TCB module: standard
library only.
"""
from __future__ import annotations

import os
import select
import socket
import stat
import threading
import time
from typing import Any

from connector import canonical as c
from connector.canonical import (FILE_ALLOW, FILE_DATA, FILE_DENY, FILE_ENTRIES, FILE_LIST, FILE_LIST_OBJECTS,
                                 FILE_OBJECTS, FILE_READ, FILE_REFUSED, LINK_G_IN, pack_frame, pack_list, read_uint,
                                 u32, u64, u8)
from connector.reader import Closed, FieldsUnreadable, ProxyReader
from .channel import FileAnswer

UNAVAILABLE = c.FILE_REASONS.index('unavailable') + 1
TIMEOUT = c.FILE_REASONS.index('timeout') + 1
OPS = {FILE_LIST_OBJECTS: c.FILE_OP_OBJECTS, FILE_LIST: c.FILE_OP_LIST, FILE_READ: c.FILE_OP_READ}


def ask_fields(kind: int, fields: list[bytes]) -> tuple[int, bytes, bytes, int, int]:
    """op, alias, path, start, length of a request that read as a frame; Closed when an integer has the wrong width
    (SPEC §3.7: a frame whose fields do not read ends the connection unanswered)."""
    try:
        if kind == FILE_LIST_OBJECTS:
            return c.FILE_OP_OBJECTS, b'', b'', 0, 0
        if kind == FILE_LIST:
            return c.FILE_OP_LIST, fields[0], fields[1], read_uint(fields[2], 4), 0
        return c.FILE_OP_READ, fields[0], fields[1], read_uint(fields[2], 8), read_uint(fields[3], 4)
    except c.Malformed as e:
        raise Closed(f'field does not read: {e}') from e


def entry_type(entry: Any) -> int:
    """H-16: the type the directory entry carries (d_type), never followed; when the entry carries none and finding it
    out would take another look that fails (the worker's uid may not search the directory), unknown."""
    try:
        if entry.is_symlink():
            return c.FILE_ENTRY_SYMLINK
        if entry.is_dir(follow_symlinks=False):
            return c.FILE_ENTRY_DIR
        if entry.is_file(follow_symlinks=False):
            return c.FILE_ENTRY_FILE
        return c.FILE_ENTRY_OTHER
    except OSError:
        return c.FILE_ENTRY_UNKNOWN


def do_read(fd: int, offset: int, length: int) -> bytes:
    """H-16: at most ``length`` bytes from ``offset`` (pread, short at the end of the file), and the file's size as
    fstat gives it now: FILE_DATA."""
    size = os.fstat(fd).st_size
    want = min(length, c.LIMITS.file_read)          # the core allowed at most this; the reply stays within its frame
    data = bytearray()
    while offset < size and len(data) < want:       # an offset at or past the end (any u64) reads nothing
        chunk = os.pread(fd, want - len(data), offset + len(data))
        if not chunk:
            break
        data += chunk
    return pack_frame(FILE_DATA, [u64(size), bytes(data)])


def do_list(fd: int, start: int) -> bytes:
    """H-16: entries from number ``start`` in the directory's own order, at most 1000; "more" when entry start+1000
    exists. Names come back as the bytes on disk, types from the entry alone, no size: FILE_ENTRIES."""
    items: list[bytes] = []
    more = 0
    with os.scandir(fd) as it:
        for i, entry in enumerate(it):
            if i < start:
                continue
            if i >= start + c.LIMITS.file_list:
                more = 1
                break
            items += [os.fsencode(entry.name), u8(entry_type(entry))]
    return pack_frame(FILE_ENTRIES, [u8(more), pack_list(items)])


def refused(code: int) -> bytes:
    return pack_frame(FILE_REFUSED, [u8(code)])


def served(answer: FileAnswer, op: int, start: int, length: int) -> bytes:
    """The reply to one answered request. The descriptor is checked against the operation first (H-15): a read takes a
    regular file, a list a directory; anything else ends the request as unavailable. The caller closes it."""
    if answer.kind == FILE_DENY:
        return refused(answer.reason)
    if answer.kind != FILE_ALLOW:
        return pack_frame(FILE_OBJECTS, [answer.objects]) if op == c.FILE_OP_OBJECTS else refused(UNAVAILABLE)
    if op == c.FILE_OP_OBJECTS or answer.op != op:
        return refused(UNAVAILABLE)
    try:
        mode = os.fstat(answer.fd).st_mode
        if op == c.FILE_OP_READ and stat.S_ISREG(mode):
            return do_read(answer.fd, start, length)
        if op == c.FILE_OP_LIST and stat.S_ISDIR(mode):
            return do_list(answer.fd, start)
    except OSError:
        pass
    return refused(UNAVAILABLE)


class Session(threading.Thread):
    def __init__(self, worker: Any, sock: socket.socket) -> None:
        super().__init__(name=f'file-session-{sock.fileno()}', daemon=True)
        self.w = worker
        self.sock = sock

    def run(self) -> None:
        try:
            self._serve()
        except Closed as e:
            self.w.log('connection_closed', reason=str(e))
        except Exception as e:                                 # never an exception message past this line
            self.w.log('connection_error', error=type(e).__name__)
        finally:
            try:
                self.sock.close()
            except OSError:
                pass
            self.w.session_ended(self)

    def _serve(self) -> None:
        self.sock.settimeout(self.w.read_timeout)             # bounds every write to the client
        reader = ProxyReader(self.w.native, self.sock.fileno(), self.w.uid, self.w.overflow, cap=c.LIMITS.frame_g_in)
        try:
            while not self.w.stopping:
                try:
                    kind, fields = reader.read_frame(LINK_G_IN, lambda n: True, self._readable)
                except FieldsUnreadable as e:                  # whole, but its fields do not split: unanswered
                    raise Closed(str(e)) from e
                op, alias, path, start, length = ask_fields(kind, fields)
                self.sock.sendall(self._request(op, alias, path, start, length))
        finally:
            reader.close()

    def _readable(self) -> bool:
        """Wait up to a second for bytes; back to the reader either way, so its per-frame deadline holds in silence."""
        if self.w.stopping:
            return False
        select.select([self.sock], [], [], 1.0)
        return not self.w.stopping

    def _request(self, op: int, alias: bytes, path: bytes, start: int, length: int) -> bytes:
        deadline = time.monotonic() + self.w.wait_timeout
        waiter = self.w.core.submit(lambda seq: [u64(seq), u32(self.w.uid), u8(op), alias, path, u64(start),
                                                 u32(length)])
        try:
            answer, state = self._await(waiter, deadline)
        finally:
            self.w.core.unregister(waiter)
            waiter.close()
        if state == 'gone':
            if answer is not None:
                answer.discard()
            raise Closed('client gone while waiting')
        if answer is None:
            return refused(TIMEOUT)
        try:
            return served(answer, op, start, length)
        finally:
            answer.discard()                                   # H-15: no target descriptor outlives its request

    def _await(self, waiter: Any, deadline: float) -> tuple[FileAnswer | None, str]:
        """Wait for the core while watching the client, until ``deadline``: ('answered' | 'gone' | 'timeout'), as the
        connector does (C-14, C-15). A withdrawal crosses an answer at most once; the late answer's descriptor is
        closed by the core link."""
        poller = select.poll()
        poller.register(waiter.r, select.POLLIN)
        poller.register(self.sock, select.POLLRDHUP)
        hangup = select.POLLRDHUP | select.POLLHUP | select.POLLERR
        while not self.w.stopping:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            events = dict(poller.poll(int(min(remaining, 1.0) * 1000)))
            if events.get(self.sock.fileno(), 0) & hangup:
                answer = self.w.core.unregister(waiter)
                if answer is None:
                    self.w.core.withdraw(waiter.seq)
                return answer, 'gone'
            if events.get(waiter.r, 0) & select.POLLIN:
                os.read(waiter.r, 1)
                if time.monotonic() < deadline:
                    return waiter.take(), 'answered'
                break
        answer = self.w.core.unregister(waiter)
        if answer is None:
            self.w.core.withdraw(waiter.seq)
        else:
            answer.discard()
        if self.w.stopping:
            return None, 'gone'
        return None, 'timeout'
