"""File judgment port of one row (SPEC-canonical-form.md §3.8 link H; validation.md H-04, H-06, H-08, H-21; plan
engine-v3-n16-file-read 2.3a).

The core end of the socketpair the spawner makes between the row's file worker and the core (2.3b wires it into the
lifecycle). Frames are read by the native judgment reader (transport.c w2_judge_receive), as on the connector's port:
every fragment's kernel credential must carry the worker's dedicated uid. The worker is in the TCB and passes the MCP
server's alias, path and length on unchecked, so this port reads FILE_ASK by its field table and integer widths only;
a frame that does not read that way is a defect and closes the row. Content rules are the first checkpoint's (hook,
fileobjects.check_file). Listing the objects is answered here from the row's table at once, never queued or asked
(H-21). FILE_ALLOW carries the opened target as its one descriptor; a frame that has to wait holds its own copy. Right
before that descriptor would go, the hook is asked whether it still may (a FILE_DENY takes the frame's place if not),
and told once it has gone; until then the hook can take the frame back (cancel_allow).
"""
from __future__ import annotations

import ctypes
import os
import selectors
import socket
from typing import Any, Callable

from connector import canonical
from connector.canonical import (FILE_ALLOW, FILE_ASK, FILE_DENY, FILE_OBJECT_LIST, FILE_OP_LIST, FILE_OP_OBJECTS,
                                 FILE_OP_READ, FILE_WITHDRAW, LINK_H_TO_CORE, Malformed, pack_frame, pack_list,
                                 read_uint, u64, u8, unpack_payload)
from . import fileobjects as fo
from .ffi import Frame, Native
from .judgment import PortFault
from .records import record_lifecycle

FRAME_MAX = canonical.LIMITS.frame_h           # link H frame limit (1 MiB)
OUT_QUEUE_MAX = 256                            # frames waiting to go to the worker before the port is faulted


def decode_ask(fields: list[bytes], row_uid: int) -> fo.FileRequest:
    """SPEC §3.8 FILE_ASK, 7 fields: seq(u64), sender_uid(u32), op(u8), alias, path, start(u64), length(u32). Widths,
    the op, the sender (the row's uid, which the worker checked per fragment) and the empty fields of a list-objects
    request are the frame's shape; alias, path and length are not judged here."""
    seq, sender_uid, op = read_uint(fields[0], 8), read_uint(fields[1], 4), read_uint(fields[2], 1)
    start, length = read_uint(fields[5], 8), read_uint(fields[6], 4)
    if seq == 0:
        raise Malformed('seq 0')
    if sender_uid != row_uid:
        raise PortFault('FILE_ASK sender is not this row')
    if op not in (FILE_OP_OBJECTS, FILE_OP_LIST, FILE_OP_READ):
        raise PortFault(f'FILE_ASK op {op}')
    if op == FILE_OP_OBJECTS and (fields[3] or fields[4] or start or length):
        raise PortFault('a list-objects FILE_ASK carries no alias, path, start or length')
    if op == FILE_OP_LIST and length:
        raise PortFault('a list FILE_ASK carries no length')
    return fo.FileRequest(seq, sender_uid, op, fields[3], fields[4], start, length)


class FilePort:
    """One row's file judgment port. ``hook`` receives admit_file / withdraw and lends its workspaces and recorder for
    the object list; ``on_fault`` closes the row."""

    def __init__(self, loop: Any, native: Native, ex: Any, sock: socket.socket, worker_uid: int, overflow: int,
                 hook: Any, on_fault: Callable[[Any, str], None], trace: Callable[..., None]) -> None:
        self.loop, self.native, self.ex, self.sock = loop, native, ex, sock
        self.worker_uid, self.overflow, self.hook, self.on_fault, self.trace = worker_uid, overflow, hook, on_fault, trace
        self.reader: int | None = native.judge_reader_new(FRAME_MAX)
        self.buffer = ctypes.create_string_buffer(FRAME_MAX)
        self.out: list[list[Any]] = []             # [frame, fd or None, offset, seq of a FILE_ALLOW whose fd waits]
        self.watching = False
        self.last_seq = 0
        self.closed = False
        sock.setblocking(False)
        loop.watch(sock.fileno(), selectors.EVENT_READ, self._readable)

    # ---- inbound ----
    def _readable(self) -> None:
        for _ in range(64):                       # bounded work per loop step
            if self.closed or self.reader is None:
                return
            kind, body, fd = self.native.judge_receive(self.reader, self.buffer, self.sock.fileno(), self.worker_uid,
                                                       self.overflow)
            if kind is Frame.IDLE:
                return
            if kind is Frame.MORE:
                continue
            if kind is Frame.REJECT:
                self.fault('file judgment reader rejected a fragment')
                return
            try:
                if fd is not None:                 # nothing the worker sends carries a descriptor (H-06)
                    raise PortFault('descriptor from the worker')
                self._frame(body)
            except (PortFault, Malformed) as e:
                if fd is not None:
                    os.close(fd)
                self.fault(str(e) if isinstance(e, PortFault) else f'malformed frame: {e}')
                return

    def _frame(self, body: bytes) -> None:
        if not body or body[0] not in LINK_H_TO_CORE:
            raise PortFault('kind not on the file judgment port (H-06)')
        kind = body[0]
        fields = unpack_payload(kind, body[1:])
        if kind == FILE_WITHDRAW:
            self.hook.withdraw(self.ex, read_uint(fields[0], 8), port=self)
            return
        request = decode_ask(fields, self.ex.lease.uid)
        if request.seq <= self.last_seq:
            raise PortFault('FILE_ASK seq does not increase')
        self.last_seq = request.seq
        if request.op == FILE_OP_OBJECTS:
            self._objects(request.seq)
        else:
            self.hook.admit_file(self.ex, self, request)

    def _objects(self, seq: int) -> None:
        """H-21: the row's own workspace table as it is now; a transfer row has none. One record per answer, with the
        aliases listed."""
        table = None if self.ex.plan.transfer else self.hook.workspaces.tables.get(self.ex.plan.workspace_id)
        objects = fo.visible_objects(table)
        if record_lifecycle(self.hook.recorder, 'file_objects_listed', self.ex, seq=seq,
                            aliases=[o.alias for o in objects]) is None:
            self.send_deny(seq, fo.FileReason.UNAVAILABLE)          # the record path failed: answer nothing
            return
        self._queue(pack_frame(FILE_OBJECT_LIST, [u64(seq), pack_list([fo.object_item(o) for o in objects])]))

    # ---- outbound ----
    def send_allow(self, seq: int, op: int, fd: int) -> None:
        """FILE_ALLOW with the opened target. The queue holds its own copy; the caller closes its descriptor. The hook
        hears file_allow_due right before the copy would go and file_allow_sent once it has."""
        self._queue(pack_frame(FILE_ALLOW, [u64(seq), u8(op)]), fd, seq)

    def send_deny(self, seq: int, reason: int) -> None:
        self._queue(pack_frame(FILE_DENY, [u64(seq), u8(fo.wire_reason(reason))]))

    def cancel_allow(self, seq: int) -> None:
        """Take back a FILE_ALLOW whose descriptor has not gone: its copy is closed and the frame never goes."""
        for item in self.out:
            if item[3] == seq and item[1] is not None and item[2] == 0:
                os.close(item[1])
                self.out.remove(item)
                return

    def _queue(self, frame: bytes, fd: int | None = None, seq: int = 0) -> None:
        if self.closed:
            return
        if len(self.out) >= OUT_QUEUE_MAX:
            self.fault('worker does not drain its file judgment port')
            return
        try:
            copy = os.dup(fd) if fd is not None else None
        except OSError:
            self.fault('cannot hold the target descriptor')
            return
        self.out.append([frame, copy, 0, seq if copy is not None else 0])
        self._flush()

    def _flush(self) -> None:
        while self.out and not self.closed:
            item = self.out[0]
            frame, fd, offset, seq = item
            if fd is not None and offset == 0:
                reason = self.hook.file_allow_due(self.ex, self, seq)
                if reason is not None:            # refused after all: the FILE_DENY goes in the FILE_ALLOW's place
                    os.close(fd)
                    item[:] = [pack_frame(FILE_DENY, [u64(seq), u8(fo.wire_reason(reason))]), None, 0, 0]
                    continue
            view = memoryview(frame)[offset:]
            try:
                if offset == 0 and fd is not None:
                    n = socket.send_fds(self.sock, [view], [fd], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                else:
                    n = self.sock.send(view, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            except (BlockingIOError, InterruptedError):
                if not self.watching:
                    self.loop.watch(self.sock.fileno(), selectors.EVENT_WRITE, self._flush)
                    self.watching = True
                return
            except OSError:
                self.fault('file judgment port write failed')
                return
            if fd is not None and offset == 0:      # the descriptor went with the frame's first bytes
                os.close(fd)
                item[1], item[3] = None, 0
                self.hook.file_allow_sent(self.ex, self, seq)
            item[2] += n
            if item[2] >= len(frame):
                self.out.pop(0)
        if self.watching and not self.closed:
            self.loop.watch(self.sock.fileno(), selectors.EVENT_WRITE, None)
            self.watching = False

    def _discard(self) -> None:
        for item in self.out:
            if item[1] is not None:
                os.close(item[1])
                item[1] = None
        self.out.clear()

    # ---- end ----
    def fault(self, why: str) -> None:
        if self.closed:
            return
        self.trace('file_port_fault', execution_id=self.ex.execution_id, reason=why)
        self.on_fault(self.ex, why)

    def close(self) -> None:
        """Release the socket, the reader and any queued descriptor; the hook's row_closed runs separately."""
        if self.closed:
            return
        self.closed = True
        self.loop.forget(self.sock.fileno())
        self._discard()
        if self.reader is not None:
            self.native.judge_reader_free(self.reader)
            self.reader = None
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
