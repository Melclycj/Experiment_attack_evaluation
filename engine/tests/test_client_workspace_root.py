"""The workspace client's children under a real drop (validation.md A-10; agent-rm-model 6.2 工作区进出行): a child started
by the client's own fork(), dropped for good to another uid, dies with the client even when the client is killed outright
(PR_SET_PDEATHSIG is cleared by a change of uid or gid, so it must be set after the drop; recheck 2026-11-03)."""
from __future__ import annotations

import ctypes
import os
import select
import signal
import time

import pytest

from client import workspace as w

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='drops to another uid')

OWNER = 70997                       # the test catalog's dedicated workspace owner (D-17)
PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER = 36, 37     # <linux/prctl.h>


def test_a_child_dropped_by_the_clients_fork_dies_with_the_client() -> None:
    """The client (here a forked root process) starts its child through w.fork(), which drops and then ties the child
    to it; the child reports its uid and pid on its stdout pipe and waits. The client is killed with SIGKILL; the child
    is SIGKILLed with it. The test process is a subreaper meanwhile, so the orphan comes back here to be reaped; on a
    failure every process the test made is killed and reaped before the subreaper flag goes back to what it was."""
    libc = ctypes.CDLL(None, use_errno=True)
    was = ctypes.c_int(0)
    assert libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(was), 0, 0, 0) == 0
    assert libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    r, wr = os.pipe()
    client = child = None
    try:
        client = os.fork()
        if not client:                                                 # stands for the root client
            os.close(r)

            def body() -> None:
                os.write(1, b'%d %d\n' % (os.getuid(), os.getpid()))
                time.sleep(60)

            w.fork(w.Ids(OWNER, OWNER), body, stdout=wr)
            os.close(wr)
            time.sleep(60)
            os._exit(0)
        os.close(wr)
        wr = None
        ready, _, _ = select.select([r], [], [], 10)
        assert ready, 'the child never reported'
        uid, child = (int(x) for x in os.read(r, 64).split())
        assert uid == OWNER                                            # the child really dropped before it reported
        os.kill(client, signal.SIGKILL)
        os.waitpid(client, 0)
        client = None
        ready, _, _ = select.select([r], [], [], 10)
        assert ready and os.read(r, 1) == b''                          # the child's end closed: it is gone
        _, status = os.waitpid(child, 0)
        child = None
        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    finally:
        for pid in (client, child):
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except (ProcessLookupError, ChildProcessError):
                    pass
        os.close(r)
        if wr is not None:
            os.close(wr)
        libc.prctl(PR_SET_CHILD_SUBREAPER, was.value, 0, 0, 0)
