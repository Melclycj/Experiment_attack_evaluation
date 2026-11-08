"""ctypes bindings to the reused C17 library (native/sandbox/transport.c, support.c).

Only these C paths touch the received bytes and ancillary data of the control and data sockets; the
engine adds sequence, correlation, phase and state rules on top (conn E-01 engine ↔ spawner 控制接口;
E-02 每条数据消息的接收管线).
"""
from __future__ import annotations

import ctypes
import os
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
    IDLE = 'idle'            # judgment port only: the socket would block, nothing consumed
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
        lib.w2_send_control_fds.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int),
                                            ctypes.c_size_t]
        lib.w2_send_control_fds.restype = ctypes.c_int
        lib.w2_recv_control3.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int * 3)]
        lib.w2_recv_control3.restype = ctypes.c_ssize_t
        lib.w2_environment_values.argtypes = [ctypes.c_char_p] * 5 + [
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
        lib.w2_environment_values.restype = ctypes.c_int
        lib.w2_reader_new.argtypes = []
        lib.w2_reader_new.restype = ctypes.c_void_p
        lib.w2_judge_reader_new.argtypes = [ctypes.c_size_t]
        lib.w2_judge_reader_new.restype = ctypes.c_void_p
        lib.w2_judge_reader_free.argtypes = [ctypes.c_void_p]
        lib.w2_judge_reader_free.restype = None
        lib.w2_judge_receive.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_int)]
        lib.w2_judge_receive.restype = ctypes.c_int
        lib.w2_reader_free.argtypes = [ctypes.c_void_p]
        lib.w2_reader_free.restype = None
        lib.w2_frame_receive.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32,
                                         ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        lib.w2_frame_receive.restype = ctypes.c_int
        lib.w2_open_beneath.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
        lib.w2_open_beneath.restype = ctypes.c_int
        self.lib = lib

    def recv_control(self, fd: int) -> tuple[Received, bytes, list[int], int]:
        """One record. v2: a spawn_prepared carries exactly three fds (agent channel, judgment-port end, file
        judgment-port end; validation.md H-06), every other record none; the C side closes any rights it rejects, including on a truncated record. Returned fds belong
        to the caller, which must close them on every rejection."""
        buf = ctypes.create_string_buffer(CONTROL_MAX)
        owned = (ctypes.c_int * 3)(-1, -1, -1)
        n = self.lib.w2_recv_control3(fd, buf, CONTROL_MAX, ctypes.byref(owned))
        if n == -2:
            return Received.RETRY, b'', [], 0
        if n == 0:
            return Received.EOF, b'', [], 0
        if n < 0:
            return Received.FAULT, b'', [], ctypes.get_errno()
        return Received.RECORD, buf.raw[:n], [v for v in owned if v >= 0], 0

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

    # ---- v2 judgment port (K-02, K-24) ----
    def judge_reader_new(self, max_body: int) -> int:
        handle = self.lib.w2_judge_reader_new(max_body)
        if not handle:
            raise MemoryError('w2_judge_reader_new')
        return handle

    def judge_reader_free(self, handle: int) -> None:
        self.lib.w2_judge_reader_free(handle)

    def judge_receive(self, handle: int, buffer: ctypes.Array, fd: int, expected: int,
                      overflow: int) -> tuple[Frame, bytes, int | None]:
        """One recvmsg on the judgment port: the same per-fragment credential check as frame_receive, a body up to the
        reader's capacity, and the one descriptor a JUDGE frame carries (None when the frame carried none)."""
        if not 0 < expected < UID_INVALID or not 0 <= overflow < UID_INVALID:
            raise ValueError('judge_receive arguments out of range')
        length = ctypes.c_size_t(0)
        rights = ctypes.c_int(-1)
        result = self.lib.w2_judge_receive(handle, fd, expected, overflow, buffer, len(buffer), ctypes.byref(length),
                                           ctypes.byref(rights))
        if result == 1 and 0 < length.value <= len(buffer):
            return Frame.COMPLETE, buffer.raw[:length.value], (rights.value if rights.value >= 0 else None)
        if rights.value >= 0:
            os.close(rights.value)
        if result == 2:
            return Frame.MORE, b'', None          # a fragment consumed; call again
        if result == 0:
            return Frame.IDLE, b'', None
        return Frame.REJECT, b'', None

    # ---- host file reads (validation.md H-10, H-11) ----
    def open_beneath(self, dirfd: int, path: bytes, want: int) -> int:
        """support.c w2_open_beneath: ``path`` beneath ``dirfd`` with no symlink, no magic link and nothing out of the
        anchor, reopened read-only only if it is a regular file (want 1, read) or a directory (want 2, list). Returns
        the descriptor, owned by the caller; raises OSError with the C side's errno. A NUL would cut the path short in
        C, so it is refused here (the core's path rule refuses it first)."""
        if not isinstance(path, bytes) or b'\x00' in path:
            raise ValueError('open_beneath takes bytes without NUL')
        fd = self.lib.w2_open_beneath(dirfd, path, want, None)
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return fd

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
