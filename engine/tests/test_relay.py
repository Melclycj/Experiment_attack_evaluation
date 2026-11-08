"""The in-cell pty relay (relay/relay.c; validation.md F-05; SPEC §3.5). Non-root: the relay is started here exactly as
the child starts it (fd 3 = pty master, fd 4 = the attach listener, stdio on /dev/null), a shell runs on the slave."""
from __future__ import annotations

import os
import select
import signal
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterator

import pytest

ENGINE = Path(__file__).resolve().parents[1]
INPUT, RESIZE, OUTPUT = 1, 2, 1


@pytest.fixture(scope='session')
def relay_binary(library: Path) -> Path:
    """Built next to the library by the same make invocation (conftest builds in a temp dir, the runner in its own)."""
    candidate = library.parent / 'w2-relay'
    if not candidate.exists():
        subprocess.run(['make', '-s', '-C', str(ENGINE / 'native'), f'BUILD_DIR={library.parent}', str(candidate)], check=True)
    return candidate


def frame(kind: int, payload: bytes) -> bytes:
    return bytes([kind]) + struct.pack('>I', len(payload)) + payload


class Stand:
    """A pty, a shell on its slave, the relay on its master, and the attach listener."""

    def __init__(self, relay: Path, tmp: Path) -> None:
        self.master, self.slave = os.openpty()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(tmp / 'attach.sock'))
        self.listener.listen(1)
        self.path = tmp / 'attach.sock'
        self.shell = subprocess.Popen(['/bin/sh', '-i'], stdin=self.slave, stdout=self.slave, stderr=self.slave,   # job control: Ctrl-C hits the foreground job
                                      start_new_session=True, preexec_fn=lambda: __import__('fcntl').ioctl(0, 0x540E, 0))  # TIOCSCTTY
        self.relay = subprocess.Popen([str(relay)], pass_fds=(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, preexec_fn=self._place_fds, close_fds=False)
        os.close(self.master)
        self.listener.close()

    def _place_fds(self) -> None:                           # in the relay child: master → 3, listener → 4, nothing else
        m, l = os.dup(self.master), os.dup(self.listener.fileno())
        os.dup2(m, 3)
        os.dup2(l, 4)
        os.closerange(5, 1024)

    def attach(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(self.path))
        s.settimeout(5)
        return s

    def close(self) -> None:
        for p in (self.shell, self.relay):
            if p.poll() is None:
                p.kill()
                p.wait(3)
        os.close(self.slave)


def read_output(s: socket.socket, until: bytes, timeout: float = 5.0) -> bytes:
    got, deadline = b'', time.monotonic() + timeout
    while until not in got and time.monotonic() < deadline:
        try:
            head = s.recv(5)
        except socket.timeout:
            break
        if not head:
            break
        assert head[0] == OUTPUT
        n = int.from_bytes(head[1:5], 'big')
        body = b''
        while len(body) < n:
            body += s.recv(n - len(body))
        got += body
    return got


@pytest.fixture
def stand(relay_binary: Path, tmp_path: Path) -> Iterator[Stand]:
    st = Stand(relay_binary, tmp_path)
    yield st
    st.close()


def test_bytes_go_both_ways_and_resize_reaches_the_slave(stand: Stand) -> None:
    client = stand.attach()
    client.sendall(frame(INPUT, b'echo RELAY-$((20+22))\n'))
    assert b'RELAY-42' in read_output(client, b'RELAY-42')
    client.sendall(frame(RESIZE, struct.pack('>HH', 33, 118)))
    client.sendall(frame(INPUT, b'stty size\n'))
    assert b'33 118' in read_output(client, b'33 118')
    client.close()


def test_ctrl_c_interrupts_the_foreground_process(stand: Stand) -> None:
    client = stand.attach()
    client.sendall(frame(INPUT, b'sleep 30\n'))
    time.sleep(0.5)
    client.sendall(frame(INPUT, b'\x03'))                   # Ctrl-C: the line discipline signals the foreground group
    time.sleep(0.3)
    client.sendall(frame(INPUT, b'echo STATUS-$?\n'))     # the shell is back within the 30 s: sleep was interrupted
    got = read_output(client, b'STATUS-1', timeout=5)
    assert b'STATUS-130' in got, got                       # 130 = 128 + SIGINT
    client.close()


def test_one_attached_client_at_a_time_and_draining_without_one(stand: Stand) -> None:
    first = stand.attach()
    second = stand.attach()
    second.settimeout(2)
    assert second.recv(1) == b''                            # accepted and closed at once
    first.sendall(frame(INPUT, b'echo ONE\n'))
    assert b'ONE' in read_output(first, b'ONE')
    first.sendall(frame(INPUT, b'yes | head -c 300000; echo DRAINED\n'))   # a flood of terminal output
    first.close()                                           # ... with nobody attached: the relay must drain it
    time.sleep(1.5)
    third = stand.attach()
    third.sendall(frame(INPUT, b'echo AFTER-$((1+1))\n'))
    assert b'AFTER-2' in read_output(third, b'AFTER-2', timeout=10)   # the shell did not block on its terminal
    third.close()


def test_a_client_gone_while_output_is_pending_is_dropped_not_fatal(stand: Stand) -> None:
    """Output pending on the master when the attached client has gone: the relay drops the client (EPIPE) and stays
    up, so the row can be attached again. The relay is stopped while the client leaves and the shell writes; on
    resuming both are ready in one poll and the master is served first, so the write to the gone client is certain
    (the relay once died of SIGPIPE here, closing the attach listener with it). The client leaves only once the relay
    is really stopped: before that, a relay woken for the stop could still see the EOF and drop the client itself."""
    client = stand.attach()
    client.sendall(frame(INPUT, b'sleep 1; echo PENDING-OUTPUT\n'))
    time.sleep(0.5)                                         # the relay has passed the line to the shell
    os.kill(stand.relay.pid, signal.SIGSTOP)
    deadline = time.monotonic() + 5
    while Path(f'/proc/{stand.relay.pid}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):  # t: traced
        assert time.monotonic() < deadline, 'relay did not stop'
        time.sleep(0.01)
    client.close()
    time.sleep(1.5)                                         # the shell has written while the relay was stopped
    os.kill(stand.relay.pid, signal.SIGCONT)
    time.sleep(0.5)
    assert stand.relay.poll() is None, f'relay ended with {stand.relay.returncode}'
    again = stand.attach()
    again.sendall(frame(INPUT, b'echo BACK-$((2+3))\n'))
    assert b'BACK-5' in read_output(again, b'BACK-5')
    again.close()


def test_a_client_accepted_in_the_round_its_predecessor_left_is_read_only_when_ready(stand: Stand) -> None:
    """F-05 (overall review 2026-11-03, #11): in one poll round the gone client is dropped and a new one accepted; that
    round's readiness was the gone client's, so the new one is read only after a poll of its own. It sends nothing
    here (a non-terminal attach sends no RESIZE): a read on it would block the relay, and no output would reach it."""
    client = stand.attach()
    client.sendall(frame(INPUT, b'sleep 1; echo PENDING-OUTPUT; sleep 2; echo LATER-OUTPUT\n'))
    time.sleep(0.5)
    os.kill(stand.relay.pid, signal.SIGSTOP)
    deadline = time.monotonic() + 5
    while Path(f'/proc/{stand.relay.pid}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
        assert time.monotonic() < deadline, 'relay did not stop'
        time.sleep(0.01)
    client.close()
    newcomer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    newcomer.connect(str(stand.path))                       # waits in the listen queue while the relay is stopped
    newcomer.settimeout(5)
    time.sleep(1.5)                                         # PENDING-OUTPUT is on the master
    os.kill(stand.relay.pid, signal.SIGCONT)
    assert b'LATER-OUTPUT' in read_output(newcomer, b'LATER-OUTPUT', timeout=8)
    newcomer.close()


def test_malformed_frames_drop_the_client_not_the_relay(stand: Stand) -> None:
    bad = stand.attach()
    bad.sendall(frame(RESIZE, b'\x00\x01'))                 # resize with the wrong length
    bad.settimeout(2)
    assert bad.recv(1) == b''
    bad2 = stand.attach()
    bad2.sendall(bytes([9]) + struct.pack('>I', 1) + b'x')   # unknown kind
    assert bad2.recv(1) == b''
    assert stand.relay.poll() is None                       # the relay itself is unharmed
    ok = stand.attach()
    ok.sendall(frame(INPUT, b'echo STILL\n'))
    assert b'STILL' in read_output(ok, b'STILL')
    ok.close()


def test_relay_exits_when_the_slave_side_is_gone(stand: Stand) -> None:
    client = stand.attach()
    client.sendall(frame(INPUT, b'exit\n'))
    stand.shell.wait(5)
    os.close(stand.slave)
    stand.slave = os.open('/dev/null', os.O_RDONLY)         # keep close() happy
    assert stand.relay.wait(5) == 0
    client.close()
