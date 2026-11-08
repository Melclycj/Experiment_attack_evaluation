"""The management-port connection the client's two sides share: ``admin`` (engine uid) and the workspace transfers
(bin/engine-workspace, root). It lives apart from the admin module so that the root entry loads only this and
client/workspace.py of the client, the part that is TCB (README TCB 模块清单; validation.md A-10, K-41)."""
from __future__ import annotations

from collections import deque
import os
from pathlib import Path
import socket

from connector import canonical as c

ERR_NAMES = {1: 'malformed', 2: 'unknown', 3: 'refused', 4: 'unavailable', 5: 'unknown question', 6: 'not persisted',
             7: 'busy'}
FDS_PER_RECV = 8


FILE_OP_FIELD = 18      # SPEC §3.4 QUESTION: file_op, 0 for a network request (validation.md H-09)


def carries_fd(kind: int, fields: list[bytes]) -> bool:
    """A network request's QUESTION carries its body's memfd; a host file request's carries none."""
    return kind == c.QUESTION and fields[FILE_OP_FIELD] == c.u8(0)


class Link:
    """One connection to the management port: frames out; frames in, each network QUESTION paired with the memfd it
    carried (SCM_RIGHTS arrives with the frame's first byte, so fds pair with those frames in order; a file request's
    QUESTION has none and takes none)."""

    def __init__(self, path: Path) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(str(path))
        self.parser = c.FrameParser(c.LIMITS.frame_bd, c.LINK_D_TO_CLIENT)
        self.fds: deque[int] = deque()

    def send(self, frame: bytes) -> None:
        self.sock.sendall(frame)

    def receive(self) -> list[tuple[int, list[bytes], int | None]] | None:
        """Whatever whole frames the next read completes; None when the core closed the port."""
        data, fds, flags, _ = socket.recv_fds(self.sock, 65536, FDS_PER_RECV)
        self.fds.extend(fds)
        if flags & socket.MSG_CTRUNC:
            raise c.Malformed('more descriptors than one read can carry')
        if not data:
            return None
        out = []
        for kind, fields in self.parser.feed(data):
            out.append((kind, fields, self.fds.popleft() if carries_fd(kind, fields) and self.fds else None))
        return out

    def call(self, kind: int, fields: list[bytes]) -> tuple[int, list[bytes]]:
        """Send one verb and wait for its OK or ERR. Questions that arrive meanwhile are left to ``admin questions``."""
        self.send(c.pack_frame(kind, fields))
        while True:
            frames = self.receive()
            if frames is None:
                raise ConnectionError('the engine closed the management port')
            for got, reply, fd in frames:
                if fd is not None:
                    os.close(fd)
                if got in (c.OK, c.ERR) and c.read_uint(reply[0], 1) == kind:
                    return got, reply

    def close(self) -> None:
        while self.fds:
            os.close(self.fds.popleft())
        self.sock.close()
