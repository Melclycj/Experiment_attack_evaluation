"""Lifecycle: reservation, install, close, reclaim (conn E-01, E-04; rr E-08)."""
from __future__ import annotations

import gc
import os
import socket

import pytest

from conftest import Harness, open_fds
from engine.lifecycle import COMMIT, EXECUTIONS_MAX, Refused
from engine.objects import ExecState, LeaseState, Phase, StopState, Submission, ViewState, WorkspaceState


def run_to_starting(h: Harness, i: int = 0):
    ex = h.launch(i)
    child = h.spawner.prepared(ex)
    h.pump()
    return ex, child


def finish(h: Harness, ex) -> None:
    h.spawner.empty(ex)
    h.spawner.runtime(ex)
    h.pump()
    h.spawner.drain()


def stops(h: Harness, ex) -> list[dict]:
    h.spawner.drain()
    return [r for r in h.spawner.received if r['type'] == 'stop' and r['execution_id'] == ex.execution_id]


def test_normal_round_trip(h: Harness) -> None:
    ex = h.launch()
    spawn = h.spawner.drain()[-1]
    assert spawn['type'] == 'spawn' and spawn['seq'] == '2'
    assert (spawn['uid'], spawn['gid'], spawn['lease_id']) == (60000, 60000, ex.execution_id + ':u')
    assert int(spawn['startup_deadline_ns']) == ex.startup_deadline_ns
    assert (ex.state, ex.spawn_submission) == (ExecState.PREPARING, Submission.SUBMITTED)
    assert ex.session.expected_uid == ex.lease.uid == 60000
    child = h.spawner.prepared(ex)
    h.pump()
    assert ex.state is ExecState.STARTING and ex.channel.phase is Phase.HELLO
    assert ex.session.channel_id == ex.channel.channel_id == ex.execution_id + ':c'
    assert child.recv(64) == COMMIT
    h.lc.close_session(ex)
    assert ex.channel.phase is Phase.CLOSED and ex.channel.session is None
    assert child.recv(64) == b''  # engine end shut
    assert [s['reason'] for s in stops(h, ex)] == ['normal']
    assert ex.lease.state is LeaseState.HELD  # no empty fact yet
    finish(h, ex)
    assert ex.lease.state is LeaseState.FREE and h.workspaces['work0'].state is WorkspaceState.AVAILABLE
    assert ex.execution_id not in h.lc.executions and ex.execution_id in h.lc.tombstones
    assert len(h.events('uid_released')) == 1 and not h.lc.control.dead


def test_reservation_fields_write_once(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    for obj, name, value in [(ex, 'lease_id', 'x'), (ex, 'execution_id', 'x'), (ex, 'startup_deadline_ns', 1),
                             (ex.session, 'expected_uid', 1), (ex.session, 'channel_id', 'x'),
                             (ex.lease, 'uid', 1), (ex.channel, 'receiver_generation', 9), (ex, 'lease', None)]:
        with pytest.raises(AttributeError):
            setattr(obj, name, value)


def test_refusals_create_no_row(h: Harness) -> None:
    h.launch(0)
    before = h.lc.allocation_seq
    with pytest.raises(Refused):
        h.lc.launch('work0', 'observe-0', 'again')        # same workspace / uid held
    with pytest.raises(Refused):
        h.lc.launch('work1', 'observe-0', 'mismatch')     # plan names another workspace
    assert h.lc.allocation_seq == before and len(h.lc.executions) == 1


def test_pool_exhaustion_refuses(h: Harness) -> None:
    for i in range(EXECUTIONS_MAX):
        h.launch(i)
    with pytest.raises(Refused):
        h.launch(EXECUTIONS_MAX)


def test_local_withdrawal(native) -> None:
    class Blocked:
        def __init__(self, inner):
            self.inner, self.lib = inner, inner.lib
            self.block = False

        def recv_control(self, fd):
            return self.inner.recv_control(fd)

        def send_control(self, fd, wire):
            from engine.ffi import Sent
            return Sent.NOTHING if self.block else self.inner.send_control(fd, wire)

    h = Harness(native, wrap=Blocked)
    h.native.block = True
    ex = h.launch()
    assert ex.spawn_submission is Submission.LOCAL and ex.state is ExecState.RESERVED
    h.lc.close_session(ex)
    assert (ex.membership_empty, ex.empty_basis) == (True, 'local_never_submitted')
    assert ex.lease.state is LeaseState.FREE and ex.execution_id not in h.lc.executions
    h.native.block = False
    h.lc.control.flush()
    assert not [r for r in h.spawner.drain() if r['type'] in ('spawn', 'stop')]
    h.spawner.empty(ex)  # the row is already tombstoned: a conflicting late record faults the link
    assert h.faulted()


def test_fact_for_live_unsubmitted_row_faults(native) -> None:
    class Blocked:
        def __init__(self, inner):
            self.inner, self.lib = inner, inner.lib

        def recv_control(self, fd):
            return self.inner.recv_control(fd)

        def send_control(self, fd, wire):
            from engine.ffi import Sent
            return Sent.NOTHING if b'"spawn"' in wire else self.inner.send_control(fd, wire)

    h = Harness(native, wrap=Blocked)
    ex = h.launch()
    assert ex.spawn_submission is Submission.LOCAL and ex.execution_id in h.lc.executions
    h.spawner.failed(ex)
    assert h.faulted() and ex.empty_basis == 'local_never_submitted'


def test_uncertain_send_never_local(native) -> None:
    class Broken:
        def __init__(self, inner):
            self.inner, self.lib = inner, inner.lib

        def recv_control(self, fd):
            return self.inner.recv_control(fd)

        def send_control(self, fd, wire):
            from engine.ffi import Sent
            return Sent.UNCERTAIN if b'"spawn"' in wire else self.inner.send_control(fd, wire)

    h = Harness(native, wrap=Broken)
    ex = h.launch()
    assert ex.spawn_submission is Submission.UNCERTAIN and ex.state is ExecState.CLOSED
    assert not ex.membership_empty and ex.empty_basis is None
    assert ex.lease.state is LeaseState.QUARANTINED and h.lc.control.dead


def test_unwritable_control_faults_after_5s(native) -> None:
    class Stuck:
        def __init__(self, inner):
            self.inner, self.lib = inner, inner.lib

        def recv_control(self, fd):
            return self.inner.recv_control(fd)

        def send_control(self, fd, wire):
            from engine.ffi import Sent
            return Sent.NOTHING if b'"spawn"' in wire else self.inner.send_control(fd, wire)

    h = Harness(native, wrap=Stuck)
    ex = h.launch()
    h.clock.advance(4999)
    h.pump()
    assert not h.lc.control.dead
    h.clock.advance(1)
    h.pump()
    assert h.lc.control.dead and ex.empty_basis == 'local_never_submitted'


def test_empty_before_prepared(h: Harness) -> None:
    ex = h.launch()
    h.spawner.empty(ex, 'never_created')
    h.pump()
    assert ex.state is ExecState.CLOSED and ex.lease.state is LeaseState.FREE
    fds = open_fds()
    child = h.spawner.prepared(ex)
    h.pump()
    assert ex.channel is None and open_fds() - {child.fileno()} <= fds and child.recv(64) == b''
    assert not stops(h, ex) and not h.lc.control.dead


def test_prepared_on_closed_row_stops_once(h: Harness) -> None:
    ex = h.launch()
    h.lc.close_session(ex)
    child = h.spawner.prepared(ex)
    h.pump()
    assert ex.channel is None and child.recv(64) == b'' and len(stops(h, ex)) == 1


@pytest.mark.parametrize('override', [{}, {'policy_digest': 'sha256:' + '9' * 64},
                                      {'launch_plan_digest': 'sha256:' + '9' * 64}])
def test_prepared_again_or_mismatch_closes_fd_and_faults(h: Harness, override) -> None:
    ex = h.launch()
    if not override:
        first = h.spawner.prepared(ex)
        h.pump()
        assert first.recv(64) == COMMIT
    fds = open_fds()
    child = h.spawner.prepared(ex, **override)
    assert h.faulted()
    assert child.recv(64) == b'' and open_fds() - {child.fileno()} <= fds  # never installed, no COMMIT
    if override:
        assert ex.channel is None
    else:
        assert ex.channel.phase is Phase.CLOSED


def test_duplicate_terminal_ignored_conflict_faults(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    h.lc.close_session(ex)
    first = h.spawner.empty(ex)
    h.spawner.raw(first)  # old seq, same bytes: ignored
    h.spawner.raw(h.spawner.wire('execution_empty', ex, basis='pid1_reaped', exit_code=None, signal=9,
                                 last_stage='exec'))           # new seq, same terminal: ignored
    h.pump()
    assert not h.lc.control.dead and len(h.events('uid_released')) == 1
    h.spawner.send('execution_empty', ex, basis='pid1_reaped', exit_code=0, signal=None, last_stage='exec')
    assert h.faulted()


def test_seq_rules(h: Harness) -> None:
    ex = h.launch()
    h.spawner.send('spawn_failed', ex, seq=1, stage='validate', error_code='os_error', os_errno=None)
    assert h.faulted()  # old seq, different bytes


def test_seq_gap_faults(h: Harness) -> None:
    ex = h.launch()
    h.spawner.send('spawn_failed', ex, seq=5, stage='validate', error_code='os_error', os_errno=None)
    assert h.faulted()


def test_unknown_execution_and_lease_mismatch_fault(h: Harness, native) -> None:
    ex = h.launch()
    h.spawner.raw(h.spawner.wire('spawn_failed', None, stage='validate', error_code='os_error', os_errno=None,
                                 execution_id=ex.execution_id[:-1] + '9', lease_id=ex.execution_id[:-1] + '9:u'))
    assert h.faulted()
    h2 = Harness(native)
    ex2 = h2.launch()
    ex2_other = type('X', (), {'execution_id': ex2.execution_id, 'lease_id': ex2.execution_id + 'x:u'})
    h2.spawner.raw(h2.spawner.wire('spawn_failed', ex2_other, stage='validate', error_code='os_error',
                                   os_errno=None))
    assert h2.faulted()


def test_reap_failure_after_startup_failure_quarantines(h: Harness) -> None:
    ex = h.launch()
    h.spawner.failed(ex, 'exec')
    h.spawner.failed(ex, 'reap')
    h.pump()
    assert not h.lc.control.dead and ex.lease.state is LeaseState.QUARANTINED
    assert h.workspaces['work0'].state is WorkspaceState.QUARANTINED
    with pytest.raises(Refused):
        h.launch(0)


def test_conflicting_startup_failures_fault(h: Harness) -> None:
    ex = h.launch()
    h.spawner.failed(ex, 'validate')
    h.spawner.failed(ex, 'exec')
    assert h.faulted()


def test_empty_wait_quarantines_then_real_empty_lifts(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    h.lc.close_session(ex)
    assert ex.stop is StopState.SENT
    h.clock.advance(4999)
    h.pump()
    assert ex.lease.state is LeaseState.HELD
    h.clock.advance(1)
    h.pump()
    assert ex.lease.state is LeaseState.QUARANTINED
    with pytest.raises(Refused):
        h.launch(0)
    finish(h, ex)
    assert ex.lease.state is LeaseState.FREE and len(h.events('quarantine_lifted')) == 1


def test_startup_deadline_closes_with_timeout(h: Harness) -> None:
    ex = h.launch()
    h.clock.advance(30_000)
    h.pump()
    assert ex.close_reason == 'startup_deadline' and [s['reason'] for s in stops(h, ex)] == ['timeout']
    assert ex.lease.state is LeaseState.HELD


def test_runtime_retained_closes_admission(h: Harness) -> None:
    a, _ = run_to_starting(h, 0)
    b, _ = run_to_starting(h, 1)
    h.lc.close_session(a)
    h.spawner.empty(a)
    h.spawner.runtime(a, 'retained')
    h.pump()
    assert a.lease.state is LeaseState.FREE and a.execution_id in h.lc.executions  # slot kept
    assert b.state is ExecState.STARTING  # other execution continues
    with pytest.raises(Refused):
        h.launch(2)
    h.spawner.runtime(a, 'released')
    h.pump()
    assert h.lc.accepting_new and a.execution_id not in h.lc.executions
    h.spawner.runtime(a, 'retained')  # tombstone: conflicting late record
    assert h.faulted()


def test_control_fault_closes_all_and_quarantines(h: Harness) -> None:
    a, child = run_to_starting(h, 0)
    b = h.launch(1)
    h.spawner.sock.close()
    assert h.faulted()
    for ex in (a, b):
        assert ex.state is ExecState.CLOSED and ex.lease.state is LeaseState.QUARANTINED
    assert child.recv(64) == COMMIT and child.recv(64) == b''
    with pytest.raises(Refused):
        h.launch(2)


def occupy_below(target: int) -> list[int]:
    gc.collect()
    held = []
    while True:
        fd = os.open('/dev/null', os.O_RDONLY)
        if fd >= target:
            os.close(fd)
            return held
        held.append(fd)


def test_uid_and_fd_reuse_do_not_reach_new_row(h: Harness) -> None:
    first, _ = run_to_starting(h)
    old_channel, old_fd = first.channel, first.channel.owned_fd.fileno()
    h.lc.close_session(first)
    first_empty = h.spawner.empty(first)
    h.spawner.runtime(first)
    h.pump()
    holes = occupy_below(old_fd)  # make the kernel hand the new channel the old fd number
    second, child = run_to_starting(h)
    for fd in holes:
        os.close(fd)
    assert second.lease.uid == first.lease.uid and second.channel.owned_fd.fileno() == old_fd
    assert second.channel.receiver_generation > old_channel.receiver_generation
    h.lc._drive_commit(first, old_channel)
    h.lc._startup_deadline(first)
    h.lc._empty_deadline(first)
    h.spawner.raw(first_empty)  # old seq, same bytes
    h.spawner.send('execution_empty', first, basis='pid1_reaped', exit_code=None, signal=9, last_stage='exec')
    h.pump()
    assert not h.lc.control.dead
    assert (second.state, second.lease.state, second.channel.phase) == (ExecState.STARTING, LeaseState.HELD,
                                                                        Phase.HELLO)
    assert child.recv(64) == COMMIT


def test_tombstone_window(h: Harness) -> None:
    first = h.launch()
    h.lc.close_session(first)
    finish(h, first)
    for _ in range(1024):
        ex = h.launch(1)
        h.lc.close_session(ex)
        finish(h, ex)
    assert first.execution_id not in h.lc.tombstones
    h.spawner.empty(first)
    assert h.faulted()


def test_channel_is_unnamed_stream_with_passcred(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    sock = ex.channel.owned_fd
    assert sock.type == socket.SOCK_STREAM and sock.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1


def test_runtime_released_before_empty_on_open_row(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    h.spawner.runtime(ex)          # permitted order: storage fact first, row still open
    h.spawner.empty(ex)
    h.pump()
    assert not h.lc.control.dead and ex.slot_released and ex.execution_id not in h.lc.executions
    assert len(h.events('slot_released')) == 1


def test_workspace_reference_holds_workspace_and_slot(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    ws = h.workspaces['work0']
    ws.io_refs.add('observer')
    h.lc.close_session(ex)
    finish(h, ex)
    assert ex.lease.state is LeaseState.FREE                      # uid gate is independent
    assert ws.state is WorkspaceState.DRAINING and ex.execution_id in h.lc.executions
    with pytest.raises(Refused):
        h.launch(0)
    ws.io_refs.discard('observer')
    h.lc._reclaim(ex)
    assert ws.state is WorkspaceState.AVAILABLE and ex.slot_released


def test_reap_failures_bounded(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    h.lc.close_session(ex)
    h.spawner.failed(ex, 'reap')
    h.spawner.failed(ex, 'reap')   # same terminal again: ignored
    h.pump()
    assert not h.lc.control.dead and len(ex.spawn_failures) == 1
    h.spawner.send('spawn_failed', ex, stage='reap', error_code='os_error', os_errno=10)
    assert h.faulted()


def test_never_created_after_prepared_faults(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    h.spawner.empty(ex, 'never_created')
    assert h.faulted() and ex.lease.state is LeaseState.QUARANTINED


def test_unmapped_close_reason_changes_nothing(h: Harness) -> None:
    ex, _ = run_to_starting(h)
    with pytest.raises(ValueError):
        h.lc.close_session(ex, 'bye')
    assert ex.state is ExecState.STARTING and ex.channel.phase is Phase.HELLO and ex.stop is StopState.NONE


def test_commit_not_sent_after_startup_deadline(h: Harness) -> None:
    ex = h.launch()
    engine_end, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    engine_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    engine_end.setblocking(False)
    filled = 0
    try:
        while True:
            filled += engine_end.send(b'\0' * 65536)
    except BlockingIOError:
        pass
    h.spawner.send('spawn_prepared', ex, fd=engine_end.fileno(), launch_plan_digest=ex.launch_plan_digest,
                   policy_digest=ex.plan.policy_digest, isolation_profile_digest=ex.plan.isolation_profile_digest,
                   child_pid=4242, sealed=True, copy_id=ex.execution_id + ':r')
    engine_end.close()
    h.pump()
    assert ex.state is ExecState.STARTING and ex.channel.commit_offset < len(COMMIT)
    h.clock.advance(30_000)
    received = b''
    child.settimeout(2)
    while len(received) < filled:  # make the channel writable in the round the deadline expires
        received += child.recv(1 << 20)
    h.pump()
    assert ex.close_reason == 'startup_deadline'
    rest = b''
    while chunk := child.recv(1 << 20):
        rest += chunk
    assert COMMIT not in received + rest


def test_commit_continuation_rechecks_deadline(h: Harness) -> None:
    ex = h.launch()
    engine_end, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    engine_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    engine_end.setblocking(False)
    filled = 0
    try:
        while True:
            filled += engine_end.send(b'\0' * 65536)
    except BlockingIOError:
        pass
    h.spawner.send('spawn_prepared', ex, fd=engine_end.fileno(), launch_plan_digest=ex.launch_plan_digest,
                   policy_digest=ex.plan.policy_digest, isolation_profile_digest=ex.plan.isolation_profile_digest,
                   child_pid=4242, sealed=True, copy_id=ex.execution_id + ':r')
    engine_end.close()
    h.pump()
    child.settimeout(2)
    received = b''
    while len(received) < filled:
        received += child.recv(1 << 20)
    h.clock.advance(30_000)
    h.lc._drive_commit(ex, ex.channel)  # direct call, or time passing between fire_timers and dispatch
    assert ex.close_reason == 'startup_deadline'
    rest = b''
    while chunk := child.recv(1 << 20):
        rest += chunk
    assert COMMIT not in received + rest


def test_late_prepared_after_deadline_stops_once_with_timeout(h: Harness) -> None:
    ex = h.launch()
    h.clock.advance(30_000)
    child = h.spawner.prepared(ex)  # arrives in the round the deadline expires
    h.pump()
    assert ex.channel is None and child.recv(64) == b''
    assert [s['reason'] for s in stops(h, ex)] == ['timeout']


def test_released_then_retained_on_live_row_faults(h: Harness) -> None:
    ex = h.launch()
    h.spawner.runtime(ex)
    h.pump()
    assert ex.execution_id in h.lc.executions
    h.spawner.runtime(ex, 'retained')
    assert h.faulted()
