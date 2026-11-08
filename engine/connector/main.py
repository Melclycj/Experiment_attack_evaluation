"""The row's connector process (agent-rm-model 4.1 connector 的地位, 4.2 三条口; validation.md S-11, C-01, C-04, C-28).

Started by the spawner as the dedicated connector uid with fd 3 = the row's proxy listening socket (SO_PASSCRED set by
the spawner before listen, inherited by every accepted connection) and fd 4 = the connector's end of the judgment
socketpair; argv ends with the row's uid and execution id. The main thread accepts, checks that the accepted socket
carries PASSCRED and that the row is under its connection limit, and starts one Session thread per connection; the
channel thread reads the judgment port. Losing the judgment port ends the process (C-28). TCB module: standard library
only.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .channel import CoreChannel
from .reader import Native
from .session import Budget, Session
from .upstream import CONNECT_TIMEOUT, READ_TIMEOUT, Policy, Registry, tls_context

CONNECTIONS_MAX = 64                     # 工程项 4
BODY_INFLIGHT_MAX = 256 * 1024 * 1024
PROXY_FD, JUDGMENT_FD = 3, 4


def stderr_log(event: str, **fields: Any) -> None:
    """Diagnostics: fixed words and numbers only (C-23, C-29); stderr is /dev/null under the spawner."""
    try:
        sys.stderr.write(json.dumps({'event': event, **fields}, separators=(',', ':')) + '\n')
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


class Connector:
    def __init__(self, listener: socket.socket, judgment: socket.socket, uid: int, execution_id: str, native: Native,
                 policy: Policy, tls: Any, overflow: int, on_fatal: Callable[[str], None] | None = None,
                 log: Callable[..., None] = stderr_log, connect_timeout: float = CONNECT_TIMEOUT,
                 read_timeout: float = READ_TIMEOUT) -> None:
        self.listener, self.judgment, self.uid, self.execution_id = listener, judgment, uid, execution_id
        self.native, self.policy, self.tls, self.overflow, self.log = native, policy, tls, overflow, log
        self.connect_timeout, self.read_timeout = connect_timeout, read_timeout
        self.registry = Registry()
        self.budget = Budget(BODY_INFLIGHT_MAX)
        self.channel = CoreChannel(judgment, self.registry, self._fatal, log)
        self._on_fatal = on_fatal or (lambda why: os._exit(0 if why == 'judgment port closed' else 2))
        self._lock = threading.Lock()
        self.sessions: set[Session] = set()
        self.stopping = False
        self.refused_connections = 0
        self.threads: list[threading.Thread] = []

    # ---- threads ----
    def start(self) -> None:
        """Channel thread and accept loop in the background (tests and the entry point)."""
        for target, name in ((self.channel.run, 'judgment'), (self.serve_forever, 'accept')):
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
        if passcred != 1:                                      # C-01: the spawner set it on the listener, never us
            self.log('connection_refused', why='no_passcred')
            sock.close()
            return
        with self._lock:
            if len(self.sessions) >= CONNECTIONS_MAX:          # C-04: the 65th is closed at accept
                self.refused_connections += 1
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
        for s in (self.listener, self.judgment):
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
    p = argparse.ArgumentParser(prog='connector', add_help=False)
    p.add_argument('--library', required=True, type=Path)
    p.add_argument('--ca-file', default=None)
    p.add_argument('--deny-address', action='append', default=[])
    p.add_argument('--nat64-prefix', action='append', default=[])
    p.add_argument('--connect-timeout', type=float, default=CONNECT_TIMEOUT)
    p.add_argument('--read-timeout', type=float, default=READ_TIMEOUT)
    p.add_argument('uid', type=int)
    p.add_argument('execution_id')
    return p.parse_args(argv)


def inherited(fd: int, listening: bool) -> socket.socket:
    try:
        sock = socket.socket(fileno=fd)
    except OSError as e:
        raise SystemExit(f'fd {fd} is not an open socket ({e.errno})') from None
    if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_STREAM:
        raise SystemExit(f'fd {fd} is not a unix stream socket')
    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != (1 if listening else 0):
        raise SystemExit(f'fd {fd} listening state')
    if listening and sock.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1:
        raise SystemExit('the proxy listener carries no SO_PASSCRED')
    return sock


def main(argv: list[str]) -> int:
    opts = parse_args(argv)
    if not 0 < opts.uid < 0xFFFFFFFF:
        raise SystemExit('row uid out of range')
    overflow = int(Path('/proc/sys/kernel/overflowuid').read_text())
    listener, judgment = inherited(PROXY_FD, True), inherited(JUDGMENT_FD, False)
    connector = Connector(listener, judgment, opts.uid, opts.execution_id, Native(opts.library),
                          Policy(opts.deny_address, opts.nat64_prefix), tls_context(opts.ca_file), overflow,
                          connect_timeout=opts.connect_timeout, read_timeout=opts.read_timeout)
    stderr_log('connector_started', uid=opts.uid, execution_id=opts.execution_id)
    threading.Thread(target=connector.channel.run, name='judgment', daemon=True).start()
    connector.serve_forever()
    return 0
