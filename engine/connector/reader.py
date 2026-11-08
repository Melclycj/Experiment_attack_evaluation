"""Link A reader for one accepted proxy connection (agent-rm-model 4.2 代理口的身份规则; SPEC-canonical-form.md §2, §3.1;
validation.md C-01, C-02, C-03, C-06, C-07).

The bytes come through the native judgment-reader pipeline (transport.c w2_judge_receive, the same code the core reads
its judgment port with): every fragment's kernel credential must carry the row's uid and a pid above 0, a message whose
ancillary data is anything else kills the reader, a frame longer than the link's limit is refused at its header, a
frame that stalls for five seconds is refused, and the reader is bound to one socket. This module adds what the proxy
port does differently from the judgment port: a received descriptor is closed and ends the connection (实施注意 2), the
kind byte is checked as soon as it arrives, and the declared length is charged to the row's body budget before the body
is read. The frame's bytes are copied once into Python; the native buffer and the mapped output buffer are returned to
the kernel after a large frame. TCB module: standard library only.
"""
from __future__ import annotations

import ctypes
import mmap
import os
from pathlib import Path
from typing import Callable

from . import canonical

UID_INVALID = 0xFFFFFFFF
RELEASE_ABOVE = 1024 * 1024          # a frame beyond this size leaves the buffers' pages resident: rebuild them


class Closed(Exception):
    """The connection ends here: EOF, a refused fragment, a descriptor, a kind not on this link or an over-budget body."""


class FieldsUnreadable(Closed):
    """A whole frame, its boundaries known, whose fields do not split as its kind takes: refused, then closed (C-36)."""


class Native:
    """The judgment-reader entry points of libw2sandbox.so that the connector uses."""

    def __init__(self, library: Path) -> None:
        lib = ctypes.CDLL(str(library), use_errno=True)
        lib.w2_judge_reader_new.argtypes = [ctypes.c_size_t]
        lib.w2_judge_reader_new.restype = ctypes.c_void_p
        lib.w2_judge_reader_free.argtypes = [ctypes.c_void_p]
        lib.w2_judge_reader_free.restype = None
        lib.w2_judge_receive.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_int)]
        lib.w2_judge_receive.restype = ctypes.c_int
        lib.w2_judge_peek.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_int)]
        lib.w2_judge_peek.restype = None
        lib.w2_judge_rights_held.argtypes = [ctypes.c_void_p]
        lib.w2_judge_rights_held.restype = ctypes.c_bool
        self.lib = lib


class ProxyReader:
    """Frames of one accepted connection. ``read_frame`` blocks (through ``wait``) until a whole frame is in."""

    def __init__(self, native: Native, fd: int, expected_uid: int, overflow_uid: int,
                 cap: int = canonical.LIMITS.frame_a) -> None:
        if not 0 < expected_uid < UID_INVALID or not 0 <= overflow_uid < UID_INVALID:
            raise ValueError('reader uids out of range')
        self.native, self.fd, self.expected, self.overflow, self.cap = native, fd, expected_uid, overflow_uid, cap
        self.handle: int | None = None
        self.mm: mmap.mmap | None = None
        self.buf: ctypes.Array | None = None
        self._open()

    def _open(self) -> None:
        self.handle = self.native.lib.w2_judge_reader_new(self.cap)
        if not self.handle:
            raise MemoryError('w2_judge_reader_new')
        self.mm = mmap.mmap(-1, self.cap)                       # anonymous: pages exist only once written
        self.buf = (ctypes.c_char * self.cap).from_buffer(self.mm)

    def close(self) -> None:
        if self.handle is not None:
            self.native.lib.w2_judge_reader_free(self.handle)
            self.handle = None
        self.buf = None                                         # the mapping cannot close while exported
        if self.mm is not None:
            self.mm.close()
            self.mm = None

    def _peek(self) -> tuple[int, int]:
        declared, kind = ctypes.c_size_t(0), ctypes.c_int(-1)
        self.native.lib.w2_judge_peek(self.handle, ctypes.byref(declared), ctypes.byref(kind))
        return declared.value, kind.value

    def read_frame(self, allowed: frozenset[int], reserve: Callable[[int], bool],
                   wait: Callable[[], bool]) -> tuple[int, list[bytes]]:
        """One whole frame as (kind, fields). ``reserve(n)`` is called once with the declared frame length and refuses
        with False; ``wait()`` blocks until the socket is readable and returns False to abandon the connection."""
        assert self.handle is not None and self.mm is not None
        length, rights = ctypes.c_size_t(0), ctypes.c_int(-1)
        reserved = False
        while True:
            result = self.native.lib.w2_judge_receive(self.handle, self.fd, self.expected, self.overflow, self.buf,
                                                      self.cap, ctypes.byref(length), ctypes.byref(rights))
            if rights.value >= 0:                               # 实施注意 2: never a descriptor on this path
                os.close(rights.value)
                raise Closed('descriptor on the proxy path')
            if result == 1:
                n = length.value
                if n < 1 or n > self.cap:
                    raise Closed('reader returned an impossible length')
                kind = self.mm[0]
                if kind not in allowed or not reserved:
                    raise Closed('kind not on this link' if kind not in allowed else 'frame completed before its header')
                body = self.mm[1:n]
                if n > RELEASE_ABOVE:
                    self.close()
                    self._open()
                try:
                    return kind, canonical.unpack_payload(kind, body)
                except canonical.Malformed as e:
                    raise FieldsUnreadable(f'frame does not read: {e}') from e
            if result == 2:
                if self.native.lib.w2_judge_rights_held(self.handle):   # arrived with a fragment: refused at once (B7);
                    raise Closed('descriptor on the proxy path')         # close() frees the reader, which closes it
                declared, kind = self._peek()
                if kind >= 0 and kind not in allowed:
                    raise Closed('kind not on this link')
                if declared and not reserved:
                    if not reserve(declared):
                        raise Closed('over the row body budget')
                    reserved = True
                continue
            if result == 0:
                if not wait():
                    raise Closed('abandoned')
                continue
            raise Closed('reader refused a fragment')         # EOF, bad credential, truncation, OOB, stall
