"""The file judgment port's core end against real kernel credentials of chosen senders (validation.md H-06: every
fragment must carry the file worker's dedicated uid; the row's uid, the connector's, the engine's or 0 close the row).
Needs root to send as other uids; the integration runner runs this file as root, the unprivileged suite skips it."""
from __future__ import annotations

import os
from pathlib import Path
import socket

import pytest

from conftest import OVERFLOWUID
from connector import canonical as c
from engine.fileport import FilePort
from test_file_hook import FileHarness, ask, recv_file

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='sends as other uids')

WORKER_UID = 70996


def send_as(sock: socket.socket, uid: int, data: bytes) -> None:
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
    assert os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 0


@pytest.mark.parametrize('uid', [WORKER_UID, 60000, 70999, 1000, 0, OVERFLOWUID],
                         ids=['worker', 'row', 'connector', 'engine', 'root', 'overflow'])
def test_only_the_worker_uid_is_heard_on_the_file_judgment_port(native, tmp_path: Path, uid: int) -> None:
    h = FileHarness(tmp_path, native)
    ex, conn = h.row(0)                                   # the row's uid is 60000
    _, port, _ = h.rows[ex.execution_id]
    core_end, worker_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    core_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    fport = FilePort(h.loop, h.native, ex, core_end, WORKER_UID, OVERFLOWUID, h.hook,
                     lambda row, why: h.faults.append((row.execution_id, why)), h.recorder.diagnostic)
    h.hook.register(ex, port, fport)
    try:
        worker_end.settimeout(2)
        send_as(worker_end, uid, ask(1, ex.lease.uid, c.FILE_OP_OBJECTS))
        h.pump()
        listed = [e for e in h.recorder.events if e['kind'] == 'file_objects_listed']
        if uid == WORKER_UID:
            assert not h.faults and len(listed) == 1 and recv_file(worker_end)[0] == c.FILE_OBJECT_LIST
        else:
            assert h.faults and h.faults[0][0] == ex.execution_id and listed == []
    finally:
        fport.close()
        worker_end.close()
        conn.close()
        h.close()
