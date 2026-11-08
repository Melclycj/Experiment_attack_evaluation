"""The simple PDP (agent-rm-model 648d60f2 4.3 hook 表"默认规则"; validation.md P-01): a small program outside the
engine, run as the PDP's dedicated uid, that answers allow to every request on the hook port. It reads no body (the
memfd that comes with each request is closed at once) and writes no table: there is no verb for that. Experiments and
the gate use it; another PDP is another program on the same port.

It connects to ``SOCKET`` and connects again whenever the engine goes, so it can be started before the engine and live
across engine restarts. SIGTERM ends it.

It does not read the row's policy context (the request's 22nd field; the six fields of a host file request follow it,
validation.md H-09). ``--deny-context VALUE`` makes the test variant of validation.md P-02: it denies every request,
network or file, whose policy context is exactly VALUE and allows the rest. A file request comes without a memfd.
"""
from __future__ import annotations

import os
import signal
import socket
import sys
import time

from connector import canonical as c

RETRY_S = 0.2
CONTEXT_FIELD = 21          # SPEC §3.6 PDP_REQUEST: policy_context is the 22nd field


def serve(sock: socket.socket, deny_context: bytes | None = None) -> None:
    parser = c.FrameParser(c.LIMITS.frame_bd, c.LINK_F_TO_PDP)
    while True:
        data, fds, _, _ = socket.recv_fds(sock, 1 << 20, 8)
        for fd in fds:
            os.close(fd)                                  # the body is not read
        if not data:
            return
        for kind, fields in parser.feed(data):
            if kind == c.PDP_REQUEST:
                deny = deny_context is not None and fields[CONTEXT_FIELD] == deny_context   # P-02's test variant only
                sock.sendall(c.pack_frame(c.PDP_ANSWER, [fields[0], fields[1],
                                                         c.u8(c.PDP_DENY if deny else c.PDP_ALLOW)]))


def main(argv: list[str]) -> int:
    deny_context = None
    if len(argv) == 3 and argv[0] == '--deny-context':
        deny_context, argv = os.fsencode(argv[1]), argv[2:]
    if len(argv) != 1:
        sys.stderr.write('usage: simple-pdp [--deny-context VALUE] SOCKET\n')
        return 2
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(argv[0])
        except OSError:
            sock.close()
            time.sleep(RETRY_S)
            continue
        try:
            serve(sock, deny_context)
        except (OSError, c.Malformed):
            pass
        finally:
            sock.close()
        time.sleep(RETRY_S)
