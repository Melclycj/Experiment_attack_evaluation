"""The attach subcommand (client/attach.py; validation.md A-04; SPEC §3.5) end to end: the real relay on a pty with a shell
on its slave, the client run as the user runs it — bin/engine-client on a terminal of its own — typing through it."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import termios
import time

import pytest

from test_relay import Stand, relay_binary  # noqa: F401  (fixture)

ENGINE = Path(__file__).resolve().parents[1]
EXECUTION = 'epoch:1'


def set_size(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))


class Terminal:
    """The user's terminal: a pty whose slave is the client's controlling terminal."""

    def __init__(self, root: Path, record: Path) -> None:
        self.master, slave = os.openpty()
        set_size(self.master, 33, 99)
        self.proc = subprocess.Popen([sys.executable, '-I', '-B', str(ENGINE / 'bin' / 'engine-client'), '--root', str(root),
                                      'attach', EXECUTION, '--record', str(record)],
                                     stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                                     preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.close(slave)
        self.seen = b''

    def type(self, data: bytes) -> None:
        os.write(self.master, data)

    def wait_for(self, marker: bytes, timeout: float = 8.0) -> bytes:
        deadline = time.monotonic() + timeout
        while marker not in self.seen and time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], 0.1)
            if ready:
                try:
                    self.seen += os.read(self.master, 65536)
                except OSError:                                  # EIO: the client has exited
                    break
        assert marker in self.seen, self.seen[-2000:]
        return self.seen

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(3)
        os.close(self.master)


def test_attach_round_trip_resize_ctrl_c_and_record(relay_binary: Path, tmp_path: Path) -> None:  # noqa: F811
    rows = tmp_path / 'rows' / EXECUTION
    rows.mkdir(parents=True)
    stand = Stand(relay_binary, rows)                            # binds rows/<execution>/attach.sock, as the spawner does
    record = tmp_path / 'session.cast'
    term = Terminal(tmp_path, record)
    try:
        term.wait_for(b'Ctrl-] detaches')
        term.type(b'echo ROUND-$((40+2))\r')                    # raw mode: the CR goes over as typed, the agent pty maps it
        term.wait_for(b'ROUND-42')
        term.type(b'stty size\r')
        term.wait_for(b'33 99')                                  # the client's size reached the agent's pty on attach
        set_size(term.master, 40, 120)                           # the kernel sends SIGWINCH to the client
        time.sleep(0.3)
        term.type(b'stty size\r')
        term.wait_for(b'40 120')
        term.type(b'sleep 30\r')
        time.sleep(0.5)
        term.type(b'\x03')                                       # Ctrl-C passes through raw mode as a byte ...
        time.sleep(0.3)
        term.type(b'echo STATUS-$?\r')                           # ... and the agent pty's line discipline sends SIGINT
        assert b'STATUS-130' in term.wait_for(b'STATUS-1')
        term.type(b'\x1d')                                       # Ctrl-] detaches; the row is untouched
        term.wait_for(b'detached')
        assert term.proc.wait(5) == 0
        assert stand.relay.poll() is None and stand.shell.poll() is None
    finally:
        term.close()
        stand.close()
    assert oct(record.stat().st_mode & 0o777) == '0o600'
    lines = record.read_text().splitlines()
    header, events = json.loads(lines[0]), [json.loads(x) for x in lines[1:]]
    assert header['version'] == 2 and (header['width'], header['height']) == (99, 33)
    assert ['r', '120x40'] in [e[1:] for e in events]
    output = ''.join(e[2] for e in events if e[1] == 'o')
    assert 'ROUND-42' in output and 'STATUS-130' in output
    assert all(e[1] in ('o', 'r') for e in events)              # typed input is not recorded


# ---- A-06: OSC 52 (the user's clipboard) never reaches the user's terminal ------------------------------------------
REMOVED = [
    b'a\x1b]52;c;aGk=\x07b',               # set, ended by BEL
    b'a\x1b]52;c;aGk=\x1b\\b',             # set, ended by ESC \
    b'a\x1b]52;c;aGk=\x9cb',               # 8-bit ST
    b'a\x1b]52;c;aGk=\xc2\x9cb',           # ST as U+009C in UTF-8
    b'a\x1b]52;c;?\x07b',                  # query: the terminal would type the clipboard into the cell
    b'a\x1b]52;;?\x1b\\b',                 # empty selection
    b'a\x1b]52\x07b',                      # no parameters
    b'a\x9d52;c;?\x9cb',                   # 8-bit OSC
    b'a\xc2\x9d52;c;?\xc2\x9cb',           # OSC as U+009D in UTF-8
    b'a\x1b\x9d52;c;?\x07b',               # ESC before the C1 control
    b'a\x1b\xc2\x9d52;c;?\x07b',
    b'a\x1b]052;c;?\x07b',                 # the terminal reads the number with its leading zeros
    b'a\x1b]' + b'0' * 200 + b'52;c;?\x07b',
    b'a\x1b]52;c;?\x18b',                  # CAN aborts the string in the terminal
    b'a\x1b]52;c;?\x1ab',                  # SUB too
]
KEPT = [
    b'\x1b]0;title\x07', b'\x1b]520;x\x07', b'\x1b]5;x\x07', b'\x1b]53;x\x1b\\', b'\x1b];x\x07',
    b'\x1b]8;;https://example.com/\x1b\\link\x1b]8;;\x1b\\',      # a hyperlink
    b'\x1b[2J\x1b[H\x1b[31mred\x1b[0m \xe2\x9c\x9d ok \xc2\xa3 \x9c\x07\x1b\x1b[1m',
]


def filtered(chunks: list[bytes]) -> bytes:
    from client.attach import ClipboardFilter
    f = ClipboardFilter()
    return b''.join(f.feed(c) for c in chunks)


def splits(data: bytes) -> list[list[bytes]]:
    """The whole input, every two-way split, and byte by byte: the relay's frames may cut anywhere."""
    return [[data]] + [[data[:s], data[s:]] for s in range(1, len(data))] + [[bytes([x]) for x in data]]


@pytest.mark.parametrize('data', REMOVED)
def test_osc52_removed_with_every_terminator_and_any_frame_cut(data: bytes) -> None:
    for chunks in splits(data):
        assert filtered(chunks) == b'ab', chunks


@pytest.mark.parametrize('data', KEPT)
def test_other_output_passes_unchanged(data: bytes) -> None:
    for chunks in splits(data):
        assert filtered(chunks) == data, chunks


def test_esc_ends_the_removed_string_and_is_read_again() -> None:
    assert filtered([b'a\x1b]52;c;?\x1b[31mb']) == b'a\x1b[31mb'
    assert filtered([b'a\x1b]52;c;?', b'\x1b]52;c;?\x07b']) == b'ab'


def test_no_two_passed_pieces_join_into_an_introducer() -> None:
    """ESC and an 8-bit OSC: the ESC goes with the removed sequence, so the text after it cannot pick it up."""
    out = filtered([b'\x1b\x9d52;\x07]52;c;?\x07'])
    assert out == b']52;c;?\x07' and b'\x1b' not in out


def test_unterminated_osc52_is_removed_until_its_end() -> None:
    from client.attach import ClipboardFilter
    f = ClipboardFilter()
    assert f.feed(b'x\x1b]52;c;' + b'A' * 100_000) == b'x'
    assert f.feed(b'B' * 1000) == b''
    assert f.feed(b'\x07y') == b'y'


def test_undecided_number_is_held_only_so_long() -> None:
    from client.attach import CARRY_MAX, ClipboardFilter
    f = ClipboardFilter()
    assert f.feed(b'\x1b]52') == b''                              # 52 so far: could still be 520
    assert f.feed(b'0;x\x07') == b'\x1b]520;x\x07'
    assert f.feed(b'\x1b]' + b'0' * CARRY_MAX) == b''             # still could be 52 and too long to hold: removed
    assert f.feed(b'52;?\x07z') == b'z'


def test_attach_removes_osc52_before_the_terminal_and_the_record(relay_binary: Path, tmp_path: Path) -> None:  # noqa: F811
    """End to end through the real relay and pty: the shell prints a query and a set between visible text."""
    rows = tmp_path / 'rows' / EXECUTION
    rows.mkdir(parents=True)
    stand = Stand(relay_binary, rows)
    record = tmp_path / 'session.cast'
    term = Terminal(tmp_path, record)
    try:
        term.wait_for(b'Ctrl-] detaches')
        term.type(b"printf 'OSC-A\\033]52;c;?\\007B\\033]52;c;aGk=\\033\\\\C\\n'\r")
        seen = term.wait_for(b'OSC-ABC')
        assert b'\x1b]52' not in seen and b'\x9d' not in seen
        term.type(b'\x1d')
        term.wait_for(b'detached')
    finally:
        term.close()
        stand.close()
    output = ''.join(e[2] for e in (json.loads(x) for x in record.read_text().splitlines()[1:]) if e[1] == 'o')
    assert 'OSC-ABC' in output and '\x1b]52' not in output


def test_attach_refuses_a_path_outside_the_rows_directory(tmp_path: Path) -> None:
    for bad in ('../state', 'a/b', '..', ''):
        run = subprocess.run([sys.executable, '-I', '-B', str(ENGINE / 'bin' / 'engine-client'), '--root', str(tmp_path),
                              'attach', bad], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=10)
        assert run.returncode != 0 and 'not an execution id' in run.stderr
