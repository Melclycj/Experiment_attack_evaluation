"""The proxy port against real kernel credentials of chosen senders (validation.md C-02; ER 164–167). Needs root to
send as other uids; the integration runner runs this file as root, the unprivileged suite skips it."""
from __future__ import annotations

import os
import socket
import time
from pathlib import Path

import pytest

from connector import canonical as c
from connector_rig import CA, OVERFLOWUID, Rig

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='sends as other uids')

ROW_UID = 60000
REQUEST = c.pack_frame(c.REQUEST, [b'GET', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([]), b''])


def send_as(sock: socket.socket, uid: int, data: bytes, must_send: bool = True) -> bool:
    """Write ``data`` on ``sock`` from a child running as ``uid``: the kernel stamps that uid on the message. Returns
    whether the write went through (the connector may already have closed the connection)."""
    pid = os.fork()
    if pid == 0:
        try:
            if uid != 0:
                os.setgroups([])
                os.setresgid(uid, uid, uid)
                os.setresuid(uid, uid, uid)
            sock.sendall(data)
            os._exit(0)
        except BaseException:
            os._exit(1)
    sent = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 0
    assert sent or not must_send
    return sent


@pytest.fixture
def row(library: Path, tmp_path: Path, ca: CA):
    r = Rig(tmp_path, library, ca)
    r.connector.uid = ROW_UID                                   # the row's uid; the test process (root) is never it
    yield r
    r.close()


def connect(row: Rig) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(row.path))
    s.settimeout(3)
    return s


def closed(s: socket.socket) -> bool:
    try:
        return s.recv(1) == b''
    except socket.timeout:
        return False
    except OSError:
        return True


def test_the_rows_uid_passes(row: Rig) -> None:
    s = connect(row)
    send_as(s, ROW_UID, REQUEST)
    j = row.judge()
    assert j is not None and j.uid == ROW_UID
    row.deny(j.seq, 2)
    assert s.recv(4) != b''
    s.close()


@pytest.mark.parametrize('uid', [ROW_UID + 1, 0, OVERFLOWUID, 70999])
def test_another_uid_is_refused_before_parsing(row: Rig, uid: int) -> None:
    s = connect(row)
    send_as(s, uid, REQUEST)
    assert closed(s)
    assert row.judge(timeout=0.5) is None
    s.close()


def test_uid_change_inside_one_frame_is_refused(row: Rig) -> None:
    s = connect(row)
    send_as(s, ROW_UID, REQUEST[:7])                            # the header and the kind from the row
    time.sleep(0.1)
    send_as(s, ROW_UID + 1, REQUEST[7:])                        # the rest from someone else
    assert closed(s)
    assert row.judge(timeout=0.5) is None
    s.close()


def test_connecting_as_root_does_not_help(row: Rig) -> None:
    """SO_PEERCRED says root connected; every message is still checked against the row's uid."""
    s = connect(row)
    send_as(s, 0, REQUEST[:4])
    time.sleep(0.1)
    send_as(s, ROW_UID, REQUEST[4:], must_send=False)           # the root fragment already ended the connection
    assert closed(s)
    assert row.judge(timeout=0.5) is None
    s.close()
