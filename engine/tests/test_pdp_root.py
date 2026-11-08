"""The hook port against other uids (validation.md K-48; agent-rm-model 648d60f2 4.2): only the PDP uid is served; a
process of the PDP's group under another uid, root, and anyone outside the group are dropped or never get in."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import tempfile
import time

import pytest

from connector import canonical as c
from engine.pdp import HookPort
from test_hook import Harness

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='connects as other uids')

PDP = 70998


def connect_as(path: Path, uid: int, gid: int, h: Harness) -> str:
    """Fork, become uid/gid (the PDP's group as a supplementary group when gid differs), connect, ask for a table:
    'served' when a snapshot comes back, 'dropped' on EOF, the errno name when connect fails."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:                                          # child
        try:
            os.close(r)
            os.setgroups([PDP] if gid != PDP else [])
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            try:
                s.connect(str(path))
            except OSError as e:
                os.write(w, (os.strerror(e.errno) if e.errno else 'error').encode())
                os._exit(0)
            try:
                s.sendall(c.pack_frame(c.TABLE_QUERY, [b'work0']))
                data = s.recv(16)
            except ConnectionError:                       # closed with the query unread: a reset, still a drop
                data = b''
            os.write(w, b'served' if data else b'dropped')
        finally:
            os._exit(0)
    os.close(w)
    until = time.monotonic() + 5
    while time.monotonic() < until:
        h.pump()
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        time.sleep(0.02)
    out = os.read(r, 64).decode()
    os.close(r)
    return out


@pytest.fixture
def hp(native, tmp_path: Path):
    h = Harness(tmp_path, native)
    top = Path(tempfile.mkdtemp(dir='/tmp'))              # pytest's own tmp tree is 0700: other uids could not reach it
    top.chmod(0o755)
    d = top / 'hook'
    d.mkdir()
    os.chown(d, 0, PDP)
    os.chmod(d, 0o2750)
    yield h, HookPort(h.loop, h.recorder, d, PDP, PDP, 0, h.hook, h.tables)
    shutil.rmtree(top)


def test_only_the_pdp_uid_is_served(hp: tuple[Harness, HookPort]) -> None:
    h, p = hp
    assert os.stat(p.path).st_gid == PDP and oct(os.stat(p.path).st_mode & 0o777) == '0o660'
    assert connect_as(p.path, 1000, 1000, h) == 'dropped'           # the engine uid of the deployments, in the group
    assert connect_as(p.path, 70000, 70000, h) == 'dropped'         # a row's uid, given the group for the test
    assert connect_as(p.path, 0, 0, h) == 'dropped'                 # root passes the mode, not the uid check
    assert connect_as(p.path, PDP, PDP, h) == 'served'
    refused = [e['detail'] for e in h.recorder.events if e['kind'] == 'diagnostic' and e['name'] == 'pdp_refused']
    assert [d['uid'] for d in refused] == [1000, 70000, 0]


def test_outside_the_group_the_socket_is_out_of_reach(hp: tuple[Harness, HookPort]) -> None:
    h, p = hp
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            os.setgroups([])
            os.setresgid(70001, 70001, 70001)
            os.setresuid(70001, 70001, 70001)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(str(p.path))
                os.write(w, b'connected')
            except PermissionError:
                os.write(w, b'EACCES')
        finally:
            os._exit(0)
    os.close(w)
    os.waitpid(pid, 0)
    assert os.read(r, 16) == b'EACCES'
    os.close(r)
    assert p.link is None
