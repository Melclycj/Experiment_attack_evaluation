"""The row's file worker process (plan engine-v3-n16-file-read, 文件读 定稿 部件与通道; validation.md H-05, H-13, H-14,
H-15, H-17).

Started by the spawner the way it starts the connector, as the dedicated file-worker uid that every row's worker shares,
with fd 3 = the row's file-port listening socket (SO_PASSCRED set by the spawner before listen, inherited by every
accepted connection) and fd 4 = the worker's end of the row's file judgment socketpair; argv ends with the row's uid and
execution id. The main thread accepts, checks that the accepted socket carries PASSCRED and that the row is under its
connection limit, and starts one Session thread per connection; the core thread reads the file judgment port. Losing
that port ends the process (as C-28 for the connector). The worker holds no privilege and touches no host path: every
target it reads or lists is a descriptor the core opened and handed over (H-15). Its first act is to make itself not
dumpable: every row's worker runs as the one worker uid, and another process of that uid must not read its
/proc/<pid>/fd (the targets it is reading) or ptrace it (H-14). TCB module: standard library only.
"""
from __future__ import annotations

import argparse
import ctypes
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from connector.main import inherited, stderr_log
from connector.reader import Native
from connector.session import WAIT_TIMEOUT
from .channel import CoreLink
from .session import Session

CONNECTIONS_MAX = 16                     # one row's file port (H-13)
WRITE_TIMEOUT = 30.0                     # a reply to the client, at most 1 MiB on the cell's own loopback socket
FILE_FD, CORE_FD = 3, 4
PR_SET_DUMPABLE = 4                      # <linux/prctl.h>


def not_dumpable() -> None:
    """prctl(PR_SET_DUMPABLE, 0). An exec resets the flag, so the worker sets it itself, after the spawner's exec.
    A failure ends the worker before it serves anything (fail closed)."""
    if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise SystemExit(f'cannot make the worker not dumpable: errno {ctypes.get_errno()}')


class Worker:
    def __init__(self, listener: socket.socket, core: socket.socket, uid: int, execution_id: str, native: Native,
                 overflow: int, on_fatal: Callable[[str], None] | None = None,
                 log: Callable[..., None] = stderr_log, wait_timeout: float = WAIT_TIMEOUT) -> None:
        self.listener, self.uid, self.execution_id = listener, uid, execution_id
        self.native, self.overflow, self.log = native, overflow, log
        self.wait_timeout, self.read_timeout = wait_timeout, WRITE_TIMEOUT
        self.core_sock = core
        self.core = CoreLink(core, self._fatal, log)
        self._on_fatal = on_fatal or (lambda why: os._exit(0 if why == 'core port closed' else 2))
        self._lock = threading.Lock()
        self.sessions: set[Session] = set()
        self.stopping = False
        self.threads: list[threading.Thread] = []

    # ---- threads ----
    def start(self) -> None:
        """Core thread and accept loop in the background (tests and the entry point)."""
        for target, name in ((self.core.run, 'core'), (self.serve_forever, 'accept')):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self.threads.append(t)

    def serve_forever(self) -> None:
        while not self.stopping:
            try:
                sock, _ = self.listener.accept()
            except OSError:
                if self.stopping:
                    return
                time.sleep(0.05)
                continue
            self._admit(sock)

    def _admit(self, sock: socket.socket) -> None:
        try:
            passcred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
        except OSError:
            sock.close()
            return
        if passcred != 1:                                      # H-05: the spawner set it on the listener, never us
            self.log('connection_refused', why='no_passcred')
            sock.close()
            return
        with self._lock:
            if len(self.sessions) >= CONNECTIONS_MAX:          # H-13: the 17th is closed at accept
                sock.close()
                self.log('connection_refused', why='limit')
                return
            session = Session(self, sock)
            self.sessions.add(session)
        session.start()

    def session_ended(self, session: Session) -> None:
        with self._lock:
            self.sessions.discard(session)

    def stop(self) -> None:
        self.stopping = True
        for s in (self.listener, self.core_sock):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        with self._lock:
            sessions = list(self.sessions)
        for session in sessions:
            try:
                session.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _fatal(self, why: str) -> None:
        self.stop()
        self._on_fatal(why)


# ---- entry point ----
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog='file-worker', add_help=False)
    p.add_argument('--library', required=True, type=Path)
    p.add_argument('uid', type=int)
    p.add_argument('execution_id')
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    not_dumpable()
    opts = parse_args(argv)
    if not 0 < opts.uid < 0xFFFFFFFF:
        raise SystemExit('row uid out of range')
    overflow = int(Path('/proc/sys/kernel/overflowuid').read_text())
    listener, core = inherited(FILE_FD, True), inherited(CORE_FD, False)
    worker = Worker(listener, core, opts.uid, opts.execution_id, Native(opts.library), overflow)
    stderr_log('file_worker_started', uid=opts.uid, execution_id=opts.execution_id)
    threading.Thread(target=worker.core.run, name='core', daemon=True).start()
    worker.serve_forever()
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
