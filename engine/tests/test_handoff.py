"""Handoff fd checks (engine-requirements §2: the delivered fd is a connected AF_UNIX stream socket with no nameable
address on either end and SO_PASSCRED = 1; the engine fails the handoff rather than set the option itself).

The positive case is test_lifecycle.py::test_channel_is_unnamed_stream_with_passcred. Here each wrong kind of fd is
handed over in a spawn_prepared record: the C receiver refuses the record, the engine faults the control link, no
Channel is installed and the delivered descriptor is not left open in the engine.
"""
from __future__ import annotations

import os
import socket
from typing import Callable

import pytest

from conftest import Harness, open_fds
from engine.objects import ExecState


def no_passcred() -> tuple[socket.socket, list[socket.socket]]:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return a, [b]


def datagram() -> tuple[socket.socket, list[socket.socket]]:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    a.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    return a, [b]


def named() -> tuple[socket.socket, list[socket.socket]]:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(f'\0engine-handoff-test-{os.getpid()}')
    listener.listen(1)
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.connect(listener.getsockname())
    accepted, _ = listener.accept()
    accepted.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    return accepted, [peer, listener]


def inet() -> tuple[socket.socket, list[socket.socket]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    peer = socket.create_connection(listener.getsockname())
    accepted, _ = listener.accept()
    return accepted, [peer, listener]


@pytest.mark.parametrize('make', [no_passcred, datagram, named, inet], ids=lambda f: f.__name__)
def test_wrong_handoff_fd_faults_and_installs_nothing(h: Harness,
                                                      make: Callable[[], tuple[socket.socket, list]]) -> None:
    ex = h.launch()
    engine_end, keep = make()
    before = open_fds()
    fields = dict(launch_plan_digest=ex.launch_plan_digest, policy_digest=ex.plan.policy_digest,
                  isolation_profile_digest=ex.plan.isolation_profile_digest, child_pid=4242, sealed=True,
                  copy_id=ex.execution_id + ':r')
    h.spawner.send('spawn_prepared', ex, fd=engine_end.fileno(), **fields)
    assert h.faulted()
    assert ex.channel is None and ex.state is ExecState.CLOSED
    assert open_fds() - before == set()          # the delivered copy was closed by the receiver
    engine_end.close()
    for s in keep:
        s.close()


def test_open_fds_sees_a_descriptor_on_a_number_a_listing_would_have_held() -> None:
    """Control for the leak checks: a descriptor opened between two snapshots is reported. A snapshot taken by
    listing /proc/self/fd held a directory fd on the lowest free number, which is where this one now lands."""
    before = open_fds()
    fd = os.open('/dev/null', os.O_RDONLY)
    try:
        assert fd not in before and fd in open_fds() - before
    finally:
        os.close(fd)
