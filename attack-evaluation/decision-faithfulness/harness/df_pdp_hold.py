"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The PDP stand-in that can hold its answer (tests.md 1.5; plan step 4): run as the PDP's dedicated uid, it connects to
the hook port like pdp/simple.py and answers allow to every request, as the simple PDP does; the one difference is
that a request whose query carries the tag it was told to hold gets its answer only when the controller releases it.
It reads no body (each memfd is closed at once) and writes no table (there is no verb for that).

    python3 -I -B df_pdp_hold.py ENGINE_DIR HOOK_SOCKET     (commands on stdin, events as JSON lines on stdout)

stdin: "hold <nonce>-<tag>" | "release" | "quit". stdout: connected, held, answered, released, closed.
"""
from __future__ import annotations

import json
import os
import select
import socket
import sys
import time


def emit(**event) -> None:
    event["t"] = time.time()
    sys.stdout.write(json.dumps(event, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main(argv: list[str]) -> int:
    engine_dir, hook = argv
    sys.path.insert(0, engine_dir)
    from connector import canonical as c
    hold_tag, held = None, []
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(hook)
            break
        except OSError:
            sock.close()
            time.sleep(0.2)
    emit(event="connected")
    parser = c.FrameParser(c.LIMITS.frame_bd, c.LINK_F_TO_PDP)

    def answer(fields: list[bytes]) -> None:
        sock.sendall(c.pack_frame(c.PDP_ANSWER, [fields[0], fields[1], c.u8(c.PDP_ALLOW)]))

    pending, stopping = b"", False
    while not stopping:
        ready, _, _ = select.select([sock, 0], [], [])
        if 0 in ready:
            data = os.read(0, 4096)                  # own line buffer: select never sees text a reader buffered
            pending += data if data else b"quit\n"
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                words = line.decode("ascii", "replace").split()
                if not words or words[0] == "quit":
                    stopping = True
                    break
                if words[0] == "hold" and len(words) == 2:
                    hold_tag = words[1]
                    emit(event="armed", tag=hold_tag)
                elif words[0] == "release":
                    for fields in held:
                        answer(fields)
                        emit(event="released", admission=c.read_uint(fields[1], 8))
                    held, hold_tag = [], None
        if sock in ready and not stopping:
            data, fds, _, _ = socket.recv_fds(sock, 1 << 20, 8)
            for fd in fds:
                os.close(fd)
            if not data:
                emit(event="closed")
                return 1
            for kind, fields in parser.feed(data):
                if kind != c.PDP_REQUEST:
                    continue
                admission, query = c.read_uint(fields[1], 8), fields[10].decode("ascii", "replace")
                info = {"admission": admission, "execution": fields[2].decode(), "path": fields[9].decode(),
                        "query": query}
                if hold_tag is not None and f"n={hold_tag}" in query:
                    held.append(fields)
                    emit(event="held", **info)
                else:
                    answer(fields)
                    emit(event="answered", **info)
    sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
