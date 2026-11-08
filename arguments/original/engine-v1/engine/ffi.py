"""ctypes bindings to the reused C17 library (native/sandbox/transport.c, support.c).

Only these C paths touch the received bytes and ancillary data of the control and data sockets; the
engine adds sequence, correlation, phase and state rules on top (conn E-01 engine ↔ spawner 控制接口;
E-02 每条数据消息的接收管线).
"""
from __future__ import annotations

import ctypes
from enum import Enum
from pathlib import Path

CONTROL_MAX = 16384
BODY_MAX = 65536              # W2_BODY_MAX: one data frame body
UID_INVALID = 0xFFFFFFFF


class Sent(Enum):
    WHOLE = 'whole'          # the whole record went out
    NOTHING = 'nothing'      # EAGAIN / EINTR: known that nothing was sent (local)
    UNCERTAIN = 'uncertain'  # any other error: the record may have been sent


class Received(Enum):
    RECORD = 'record'
    RETRY = 'retry'
    EOF = 'eof'
    FAULT = 'fault'


class Frame(Enum):
    COMPLETE = 'complete'    # a whole body; every fragment compared with the expected uid
    MORE = 'more'            # bounded progress kept in the C reader, or nothing to read yet
    REJECT = 'reject'        # the C reader is dead; the channel must close


class Native:
    def __init__(self, library: Path) -> None:
        lib = ctypes.CDLL(str(library), use_errno=True)
        lib.w2_recv_control.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                                        ctypes.POINTER(ctypes.c_int)]
        lib.w2_recv_control.restype = ctypes.c_ssize_t
        lib.w2_send_control.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
        lib.w2_send_control.restype = ctypes.c_int
        lib.w2_environment_values.argtypes = [ctypes.c_char_p] * 5 + [
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
        lib.w2_environment_values.restype = ctypes.c_int
        lib.w2_reader_new.argtypes = []
        lib.w2_reader_new.restype = ctypes.c_void_p
        lib.w2_reader_free.argtypes = [ctypes.c_void_p]
        lib.w2_reader_free.restype = None
        lib.w2_frame_receive.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32,
                                         ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        lib.w2_frame_receive.restype = ctypes.c_int
        self.lib = lib

    def recv_control(self, fd: int) -> tuple[Received, bytes, int | None, int]:
        """One record. The C side closes any rights it rejects, including on a truncated record;
        a returned fd belongs to the caller, which must close it on every rejection."""
        buf = ctypes.create_string_buffer(CONTROL_MAX)
        owned = ctypes.c_int(-1)
        n = self.lib.w2_recv_control(fd, buf, CONTROL_MAX, ctypes.byref(owned))
        if n == -2:
            return Received.RETRY, b'', None, 0
        if n == 0:
            return Received.EOF, b'', None, 0
        if n < 0:
            return Received.FAULT, b'', None, ctypes.get_errno()
        return Received.RECORD, buf.raw[:n], (owned.value if owned.value >= 0 else None), 0

    def send_control(self, fd: int, wire: bytes) -> Sent:
        result = self.lib.w2_send_control(fd, wire, len(wire), -1)
        return {1: Sent.WHOLE, 0: Sent.NOTHING}.get(result, Sent.UNCERTAIN)

    def environment_values(self, uid_map: str, overflowuid: str, overflowgid: str,
                           yama: str, ksm: str) -> tuple[int, int] | None:
        uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
        status = self.lib.w2_environment_values(
            uid_map.encode(), overflowuid.encode(), overflowgid.encode(), yama.encode(), ksm.encode(),
            ctypes.byref(uid), ctypes.byref(gid))
        return None if status else (uid.value, gid.value)

    def reader_new(self) -> int:
        handle = self.lib.w2_reader_new()
        if not handle:
            raise MemoryError('w2_reader_new')
        return handle

    def reader_free(self, handle: int) -> None:
        self.lib.w2_reader_free(handle)

    def frame_receive(self, handle: int, buffer: ctypes.Array, fd: int, expected: int,
                      overflow: int) -> tuple[Frame, bytes]:
        """One recvmsg of at most the remaining header or body length. The buffer is Python-owned with a
        fixed capacity; C copies a complete body into it and returns no pointer into its own memory. uid_t
        values cross as unsigned 32-bit, never as signed integers (conn E-02 step 4)."""
        if len(buffer) < BODY_MAX or not 0 < expected < UID_INVALID or not 0 <= overflow < UID_INVALID:
            raise ValueError('frame_receive arguments out of range')
        length = ctypes.c_size_t(0)
        result = self.lib.w2_frame_receive(handle, fd, expected, overflow, buffer, BODY_MAX,
                                           ctypes.byref(length))
        if result == 1 and 0 < length.value <= BODY_MAX:
            return Frame.COMPLETE, buffer.raw[:length.value]
        if result == 0:
            return Frame.MORE, b''
        return Frame.REJECT, b''
