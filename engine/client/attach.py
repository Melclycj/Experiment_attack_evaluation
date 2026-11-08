"""The ``attach`` subcommand: the user's conversation window onto one row's pty (agent-rm-model 3.3 对话通道一列;
SPEC-canonical-form.md §3.5 link E; build plan 工程项 9; validation.md A-03, A-04).

It connects to ``<root>/rows/<execution>/attach.sock`` (the spawner binds it for the engine uid only, so only the engine
uid or root can attach), puts the user's terminal in raw mode and copies bytes both ways through the in-cell relay.
Raw mode turns off the local line discipline, so Ctrl-C reaches the relay as the byte 0x03 and the agent pty's own
line discipline sends SIGINT to the agent's foreground group; window size changes go over as RESIZE frames, which the
relay turns into TIOCSWINSZ and the kernel into SIGWINCH. Ctrl-] detaches without touching the row.

This window never shows a question and never talks to the management port (A-03). The terminal record is the
client's job (A-04): ``--record FILE`` writes what the user saw as an asciinema v2 file (output and resize events;
typed input is not recorded, so a secret typed at a no-echo prompt stays out of it), mode 0600. Before either, OSC 52
(the terminal's clipboard: set, and query, which the terminal answers on the input) is removed (A-06).
"""
from __future__ import annotations

import codecs
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import sys
import termios
import time
import tty

INPUT, RESIZE, OUTPUT = 1, 2, 1          # SPEC §3.5
FRAME_MAX = 65536
DETACH = 0x1D                            # Ctrl-]
READ_SIZE = 16384


def socket_path(root: str, execution: str) -> Path:
    if not execution or execution in ('.', '..') or any(ch in execution for ch in '/\0'):
        raise SystemExit(f'not an execution id: {execution!r}')
    return Path(root) / 'rows' / execution / 'attach.sock'


def frame(kind: int, payload: bytes) -> bytes:
    return bytes([kind]) + struct.pack('>I', len(payload)) + payload


def write_all(fd: int, data: bytes) -> None:
    while data:
        data = data[os.write(fd, data):]


# OSC introducers as a terminal may read them: 7-bit ESC ], the 8-bit C1 0x9D (any 0x9D byte: a terminal in 8-bit mode
# reads one inside a UTF-8 character as OSC too), U+009D in UTF-8, and ESC before either C1 form (ESC then a C1 control
# is that control). Ends of the string: BEL, ESC \, 0x9C (C2 9C ends at its 9C), and CAN, SUB or ESC with anything
# else, which abort the string in the terminal.
INTRODUCERS = (b'\x1b\xc2\x9d', b'\x1b]', b'\x1b\x9d', b'\xc2\x9d', b'\x9d')       # longest first
CANDIDATE = re.compile(rb'[\x1b\x9d\xc2]')
STRING_END = re.compile(rb'[\x07\x9c\x18\x1a\x1b]')
DIGITS = re.compile(rb'[0-9]*')
CARRY_MAX = 64          # an undecided introducer and its digits held across frames; longer and still possibly 52: drop


def is_clipboard(digits: bytes) -> bool | None:
    """True for OSC 52 (the terminal reads the number with leading zeros), False when the digits can no longer be 52,
    None while they still can."""
    s = digits.lstrip(b'0')
    return True if s == b'52' else None if b'52'.startswith(s) else False


class ClipboardFilter:
    """Removes every OSC 52 sequence from the relay's output stream, set and query alike, before it reaches the user's
    terminal (validation.md A-06): a set writes the cell's bytes into the user's clipboard, a query makes the terminal
    type the clipboard into the cell. Stateful across frames; every other byte passes unchanged. An ESC or a C2 right
    before an introducer goes with it, so no two passed pieces join into a new introducer."""

    def __init__(self) -> None:
        self.carry = b''
        self.dropping = False

    def feed(self, data: bytes) -> bytes:
        data, self.carry = self.carry + data, b''
        out, i, n = bytearray(), 0, len(data)
        while i < n:
            if self.dropping:
                m = STRING_END.search(data, i)
                if m is None:
                    return bytes(out)
                j = m.start()
                if data[j] == 0x1b:
                    if j + 1 == n:
                        self.carry = b'\x1b'
                        return bytes(out)
                    i = j + 2 if data[j + 1] == 0x5c else j      # ESC \ ends it; ESC anything else is read again
                else:
                    i = j + 1
                self.dropping = False
                continue
            m = CANDIDATE.search(data, i)
            if m is None:
                out += data[i:]
                break
            p = m.start()
            out += data[i:p]
            rest = data[p:p + 3]
            intro = next((x for x in INTRODUCERS if rest.startswith(x)), None)
            if intro is None:
                if p + len(rest) == n and any(len(rest) < len(x) and x.startswith(rest) for x in INTRODUCERS):
                    self.carry = data[p:]                        # an introducer cut by the frame boundary
                    break
                out += data[p:p + 1]
                i = p + 1
                continue
            k = DIGITS.match(data, p + len(intro)).end()
            verdict = is_clipboard(data[p + len(intro):k])
            if k == n and verdict is not False:                  # more digits may follow: 52 could become 520
                if n - p <= CARRY_MAX:
                    self.carry = data[p:]
                    break
                verdict = True                                   # too long to wait for, and could still be 52
            if verdict:                                          # True; None with the digits ended means not 52
                self.dropping, i = True, k
            else:
                out += data[p:k]
                i = k
        return bytes(out)


class Record:
    """An asciinema v2 recording: a JSON header line, then [seconds, code, data] lines."""

    def __init__(self, path: str, cols: int, rows: int) -> None:
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        self.start = time.monotonic()
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        self._line({'version': 2, 'width': cols, 'height': rows, 'timestamp': int(time.time())})

    def _line(self, item: object) -> None:
        write_all(self.fd, json.dumps(item, ensure_ascii=False).encode() + b'\n')

    def _event(self, code: str, data: str) -> None:
        self._line([round(time.monotonic() - self.start, 6), code, data])

    def output(self, data: bytes) -> None:
        text = self.decoder.decode(data)
        if text:
            self._event('o', text)

    def resize(self, cols: int, rows: int) -> None:
        self._event('r', f'{cols}x{rows}')

    def close(self) -> None:
        tail = self.decoder.decode(b'', final=True)
        if tail:
            self._event('o', tail)
        os.close(self.fd)


def attach(path: Path, record: str | None, stdin: int = 0, stdout: int = 1) -> int:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(str(path))
    except OSError as e:
        sock.close()
        print(f'cannot attach through {path}: {e.strerror}', file=sys.stderr)
        return 2
    terminal = os.isatty(stdin)
    cols, rows = os.get_terminal_size(stdin) if terminal else (80, 24)
    saved = termios.tcgetattr(stdin) if terminal else None
    wake_r, wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    old_handler = signal.signal(signal.SIGWINCH, lambda *_: os.write(wake_w, b'w')) if terminal else None
    rec = Record(record, cols, rows) if record else None
    print(f'attached to {path.parent.name}; Ctrl-] detaches', file=sys.stderr, flush=True)
    ending, pending = 'the relay closed the connection (the row ended, or another client is attached)', b''
    clipboard = ClipboardFilter()
    try:
        if terminal:
            tty.setraw(stdin)
            sock.sendall(frame(RESIZE, struct.pack('>HH', rows, cols)))
        while True:
            ready, _, _ = select.select([sock, stdin, wake_r], [], [])
            if sock in ready:
                data = sock.recv(65536)
                if not data:
                    break
                pending += data
                while len(pending) >= 5:
                    kind, n = pending[0], struct.unpack('>I', pending[1:5])[0]
                    if kind != OUTPUT or n > FRAME_MAX:
                        raise ConnectionError('the relay sent a frame that does not read')
                    if len(pending) < 5 + n:
                        break
                    payload, pending = pending[5:5 + n], pending[5 + n:]
                    shown = clipboard.feed(payload)
                    write_all(stdout, shown)
                    if rec:
                        rec.output(shown)
            if stdin in ready:
                data = os.read(stdin, READ_SIZE)
                if not data:
                    ending = 'end of input'
                    break
                cut = data.find(bytes([DETACH])) if terminal else -1
                if cut >= 0:
                    data, ending = data[:cut], 'detached'
                if data:
                    sock.sendall(frame(INPUT, data))
                if cut >= 0:
                    break
            if wake_r in ready:
                while True:
                    try:
                        if not os.read(wake_r, 64):
                            break
                    except BlockingIOError:
                        break
                cols, rows = os.get_terminal_size(stdin)
                sock.sendall(frame(RESIZE, struct.pack('>HH', rows, cols)))
                if rec:
                    rec.resize(cols, rows)
    except (ConnectionError, OSError) as e:
        ending = f'connection lost: {e}'
    finally:
        if saved is not None:
            termios.tcsetattr(stdin, termios.TCSAFLUSH, saved)
        if old_handler is not None:
            signal.signal(signal.SIGWINCH, old_handler)
        os.close(wake_r)
        os.close(wake_w)
        sock.close()
        if rec:
            rec.close()
    print(f'\r\n{ending}', file=sys.stderr, flush=True)
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser('attach', help="attach the terminal to one row's pty")
    p.add_argument('execution')
    p.add_argument('--record', help='write an asciinema v2 recording here (must not exist yet)')


def run(args) -> int:
    return attach(socket_path(args.root, args.execution), args.record)
