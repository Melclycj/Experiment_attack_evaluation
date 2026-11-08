"""The file port against real kernel credentials of chosen senders (validation.md H-05; as C-01 to C-03 for the proxy
port). Needs root to send as other uids and to make a pid namespace; the integration runner runs this file as root,
the unprivileged suite skips it."""
from __future__ import annotations

import os
from pathlib import Path
import select
import socket
import time

import pytest

from conftest import OVERFLOWUID
from connector import canonical as c
from connector.reader import Native
from fileworker.main import Worker

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='sends as other uids')

ROW_UID = 60000
WORKER_UID = 70996
ASK = c.pack_frame(c.FILE_LIST_OBJECTS, [])


def send_as(path: Path, uid: int, chunks: list[bytes]) -> socket.socket:
    """Connect as root, then write each chunk from a child running as ``uid``: the kernel stamps that uid on each
    message. Returns the connection for the test to read."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(path))
    s.settimeout(3)
    for chunk in chunks:
        pid = os.fork()
        if pid == 0:
            try:
                if uid != 0:
                    os.setgroups([])
                    os.setresgid(uid, uid, uid)
                    os.setresuid(uid, uid, uid)
                s.sendall(chunk)
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.waitpid(pid, 0)
        time.sleep(0.05)
    return s


def closed(s: socket.socket) -> bool:
    try:
        return s.recv(1) == b''
    except socket.timeout:
        return False
    except OSError:
        return True


class Rig:
    def __init__(self, tmp_path: Path, library: Path) -> None:
        self.path = tmp_path / 'file.sock'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.listener.bind(str(self.path))
        os.chmod(self.path, 0o777)                         # any uid may connect; the stamp decides
        self.listener.listen(16)
        self.core, self.worker_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.library = library
        self.worker: Worker | None = None

    def start(self) -> None:
        self.worker = Worker(self.listener, self.worker_end, ROW_UID, 'e', Native(self.library), OVERFLOWUID,
                             on_fatal=lambda why: None, log=lambda event, **f: None)
        self.worker.start()

    def asked(self, timeout: float = 0.5) -> bool:
        r, _, _ = select.select([self.core], [], [], timeout)
        return bool(r)

    def close(self) -> None:
        if self.worker is not None:
            self.worker.stop()
        self.core.close()


@pytest.fixture
def rig(library: Path, tmp_path: Path):
    r = Rig(tmp_path, library)
    r.start()
    yield r
    r.close()


def test_the_rows_uid_passes(rig: Rig) -> None:
    s = send_as(rig.path, ROW_UID, [ASK])
    assert rig.asked()
    length = int.from_bytes(rig.core.recv(4), 'big')
    body = rig.core.recv(length)
    fields = c.unpack_payload(body[0], body[1:])
    assert body[0] == c.FILE_ASK and c.read_uint(fields[1], 4) == ROW_UID
    s.close()


@pytest.mark.parametrize('uid', [ROW_UID + 1, 0, OVERFLOWUID, 70999, WORKER_UID],
                         ids=['other-row', 'root', 'overflow', 'connector', 'worker'])
def test_another_uid_is_refused_before_parsing(rig: Rig, uid: int) -> None:
    s = send_as(rig.path, uid, [ASK])
    assert closed(s) and not rig.asked()
    s.close()


def test_a_uid_change_inside_one_frame_is_refused(rig: Rig) -> None:
    s = send_as(rig.path, ROW_UID, [ASK[:3]])
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setresgid(ROW_UID + 1, ROW_UID + 1, ROW_UID + 1)
            os.setresuid(ROW_UID + 1, ROW_UID + 1, ROW_UID + 1)
            s.sendall(ASK[3:])
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.waitpid(pid, 0)
    assert closed(s) and not rig.asked()
    s.close()


def become(uid: int) -> None:
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)


def test_another_process_of_the_worker_uid_cannot_read_a_workers_descriptors() -> None:
    """H-14, N-28 (cold review, minor 1): every row's worker runs as the one worker uid. Started as the spawner starts
    the worker (the uid dropped, then exec, which makes the process dumpable again), a process that then calls
    fileworker.main.not_dumpable, as the worker does first, has /proc/<pid>/fd refused to another process of the same
    uid; the control, the same process without the call, is read by it."""
    import subprocess
    import sys
    probe = ('import sys\n'
             f'sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})\n'
             'from fileworker.main import not_dumpable\n'
             'if sys.argv[1] == "call":\n'
             '    not_dumpable()\n'
             'print("ready", flush=True)\n'
             'sys.stdin.read()\n')
    for call in ('control', 'call'):
        held = subprocess.Popen([sys.executable, '-I', '-B', '-c', probe, call], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True, preexec_fn=lambda: become(WORKER_UID))
        try:
            assert held.stdout.readline().strip() == 'ready'
            reader = os.fork()
            if reader == 0:
                try:
                    become(WORKER_UID)
                    try:
                        os.listdir(f'/proc/{held.pid}/fd')
                        os._exit(0)
                    except PermissionError:
                        os._exit(3)
                except BaseException:
                    os._exit(1)
            _, status = os.waitpid(reader, 0)
            assert os.waitstatus_to_exitcode(status) == (3 if call == 'call' else 0), call
        finally:
            held.stdin.close()
            held.wait(5)
            held.stdout.close()


def test_a_sender_whose_pid_the_worker_cannot_see_is_refused(library: Path, tmp_path: Path) -> None:
    """pid > 0 (H-05): the worker runs as pid 1 of a new pid namespace. A sender inside that namespace has a pid there
    and is served; the same row uid sending from outside it is stamped pid 0 and its connection closes."""
    rig = Rig(tmp_path, library)
    ready_r, ready_w = os.pipe()             # the namespace's first process: inside sender done, outside may send
    sent_r, sent_w = os.pipe()               # the test: outside sender done, the worker may start
    child = os.fork()
    if child == 0:
        try:
            os.unshare(os.CLONE_NEWPID)
            inner = os.fork()
            if inner == 0:                                     # pid 1 of the new namespace
                sender = os.fork()
                if sender == 0:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.connect(str(rig.path))                   # as root: the test directory is root's
                    os.setgroups([])
                    os.setresgid(ROW_UID, ROW_UID, ROW_UID)
                    os.setresuid(ROW_UID, ROW_UID, ROW_UID)
                    s.sendall(ASK)
                    time.sleep(3)                              # keep the connection open while the worker reads it
                    os._exit(0)
                time.sleep(0.2)
                os.write(ready_w, b'r')
                os.read(sent_r, 1)
                rig.start()
                time.sleep(2)
                os._exit(0)
            os.waitpid(inner, 0)
            os._exit(0)
        except BaseException:
            os._exit(1)
    try:
        assert os.read(ready_r, 1) == b'r'
        outside = send_as(rig.path, ROW_UID, [ASK])
        os.write(sent_w, b's')
        assert rig.asked(2), 'the inside sender was not served'
        length = int.from_bytes(rig.core.recv(4), 'big')
        rig.core.recv(length)
        assert closed(outside), 'the pid-0 sender was not cut'
        assert not rig.asked(0.5), 'the pid-0 sender reached the core'
        outside.close()
    finally:
        os.waitpid(child, 0)
        rig.core.close()
        rig.listener.close()
        for fd in (ready_r, ready_w, sent_r, sent_w):
            os.close(fd)
