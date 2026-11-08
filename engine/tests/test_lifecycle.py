"""Lifecycle: reservation, install, close, reclaim (conn E-01, E-04; rr E-08)."""
from __future__ import annotations

import gc
import os
import socket

import pytest

from conftest import RANGE, Harness, open_fds
from engine.lifecycle import COMMIT, EXECUTIONS_MAX, Refused
from engine.objects import ExecState, LeaseState, Phase, StopState, Submission, ViewState, WorkspaceState


def run_to_active(h: Harness, i: int = 0):
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
    assert (spawn['uid'], spawn['gid'], spawn['lease_id']) == (RANGE[0], RANGE[0], ex.execution_id + ':u')
    assert int(spawn['startup_deadline_ns']) == ex.startup_deadline_ns
    assert (ex.state, ex.spawn_submission) == (ExecState.PREPARING, Submission.SUBMITTED)
    assert ex.session.expected_uid == ex.lease.uid == RANGE[0]
    child = h.spawner.prepared(ex)
    h.pump()
    assert ex.state is ExecState.ACTIVE and ex.channel.phase is Phase.DATA   # ACTIVE on the whole COMMIT, no handshake
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
    ex, _ = run_to_active(h)
    for obj, name, value in [(ex, 'lease_id', 'x'), (ex, 'execution_id', 'x'), (ex, 'startup_deadline_ns', 1),
                             (ex.session, 'expected_uid', 1), (ex.session, 'channel_id', 'x'),
                             (ex.lease, 'uid', 1), (ex.channel, 'receiver_generation', 9), (ex, 'lease', None)]:
        with pytest.raises(AttributeError):
            setattr(obj, name, value)


def test_the_users_account_choice_is_fixed_on_the_execution(h: Harness) -> None:
    """K-44: the accounts chosen at start ride on the execution (write-once, read-only) and in its spawn record."""
    ex = h.lc.launch('work0', 'observe-0', 'admin', {'api.github.com:443': 'carol'})
    assert dict(ex.accounts) == {'api.github.com:443': 'carol'}
    with pytest.raises(TypeError):
        ex.accounts['api.github.com:443'] = 'alice'                  # type: ignore[index]
    with pytest.raises(AttributeError):
        ex.accounts = {}
    assert h.events('spawn_requested')[-1]['detail']['accounts'] == {'api.github.com:443': 'carol'}


def test_an_entry_listing_several_accounts_needs_a_choice_at_start(h: Harness) -> None:
    """K-44: no start without the user's choice for each entry that lists several accounts; a choice must be one of the
    entry's accounts; a single-account entry needs no choice (agent-rm-model 3.1)."""
    from types import SimpleNamespace
    from engine.workspaces import Approval, EntryState, KeyKind, make_entry
    entries = [make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['GET'], [], ['alice', 'carol'], Approval.NEVER),
               make_entry(KeyKind.EXACT, 'api.anthropic.com:443', EntryState.ALLOW, ['POST'], [], ['main'], Approval.NEVER)]
    table = SimpleNamespace(unavailable=False, spawn_blocked=False, entries={e.identity: e for e in entries})
    h.lc.tables = SimpleNamespace(tables={'work0': table})
    with pytest.raises(Refused, match='no account chosen for api.github.com:443'):
        h.lc.launch('work0', 'observe-0', 'admin')
    with pytest.raises(Refused, match='bob is not listed'):
        h.lc.launch('work0', 'observe-0', 'admin', {'api.github.com:443': 'bob'})
    assert h.lc.executions == {}                                                  # refused before any row exists
    ex = h.lc.launch('work0', 'observe-0', 'admin', {'api.github.com:443': 'carol'})   # the Anthropic entry needs none
    assert dict(ex.accounts) == {'api.github.com:443': 'carol'}


def test_a_transfer_row_takes_no_account_and_needs_no_choice(h: Harness) -> None:
    """S-24, K-44: a transfer row hangs no entries, so an entry listing several accounts needs no choice at its start,
    and an account given for it is refused before any row exists."""
    from types import SimpleNamespace
    from conftest import DIGEST
    from engine.objects import Plan
    from engine.workspaces import Approval, EntryState, KeyKind, make_entry
    entries = [make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['GET'], [], ['alice', 'carol'], Approval.NEVER)]
    h.lc.tables = SimpleNamespace(tables={'work0': SimpleNamespace(unavailable=False, spawn_blocked=False,
                                                                   entries={e.identity: e for e in entries})})
    h.lc.catalog.plans['work0.push'] = Plan('work0.push', 'sha256:' + '3' * 64, 'work0', DIGEST, 'sha256:' + '2' * 64,
                                            transfer='push')
    with pytest.raises(Refused, match='takes no account'):
        h.lc.launch('work0', 'work0.push', 'admin', {'api.github.com:443': 'carol'})
    assert h.lc.executions == {}
    ex = h.lc.launch('work0', 'work0.push', 'admin')
    assert ex.plan.transfer == 'push' and dict(ex.accounts) == {}


def test_the_policy_context_is_kept_once_on_the_execution(h: Harness) -> None:
    """K-56: the context given at start is written once on the execution and never into the spawn record; over 16 KiB
    the start is refused before any row exists."""
    with pytest.raises(Refused, match='16 KiB'):
        h.lc.launch('work0', 'observe-0', 'admin', None, b'x' * (16 * 1024 + 1))
    assert h.lc.executions == {}
    context = b'ctx-' + b'x' * (16 * 1024 - 4)
    ex = h.lc.launch('work0', 'observe-0', 'admin', None, context)
    assert ex.policy_context == context
    with pytest.raises(AttributeError):
        ex.policy_context = b'other'
    assert 'ctx-' not in repr(h.events('spawn_requested'))


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
    ex, _ = run_to_active(h)
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
    ex, _ = run_to_active(h)
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
    a, _ = run_to_active(h, 0)
    b, _ = run_to_active(h, 1)
    h.lc.close_session(a)
    h.spawner.empty(a)
    h.spawner.runtime(a, 'retained')
    h.pump()
    assert a.lease.state is LeaseState.FREE and a.execution_id in h.lc.executions  # slot kept
    assert b.state is ExecState.ACTIVE  # other execution continues
    with pytest.raises(Refused):
        h.launch(2)
    h.spawner.runtime(a, 'released')
    h.pump()
    assert h.lc.accepting_new and a.execution_id not in h.lc.executions
    h.spawner.runtime(a, 'retained')  # tombstone: conflicting late record
    assert h.faulted()


def test_control_fault_closes_all_and_quarantines(h: Harness) -> None:
    a, child = run_to_active(h, 0)
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
    first, _ = run_to_active(h)
    old_channel, old_fd = first.channel, first.channel.owned_fd.fileno()
    h.lc.close_session(first)
    first_empty = h.spawner.empty(first)
    h.spawner.runtime(first)
    h.pump()
    holes = occupy_below(old_fd)  # make the kernel hand the new channel the old fd number
    second, child = run_to_active(h)
    for fd in holes:
        os.close(fd)
    # v2: no uid reuse within one engine start (K-21); the fd number is reused, the uid is not
    assert second.lease.uid != first.lease.uid and second.channel.owned_fd.fileno() == old_fd
    assert second.channel.receiver_generation > old_channel.receiver_generation
    h.lc._drive_commit(first, old_channel)
    h.lc._startup_deadline(first)
    h.lc._empty_deadline(first)
    h.spawner.raw(first_empty)  # old seq, same bytes
    h.spawner.send('execution_empty', first, basis='pid1_reaped', exit_code=None, signal=9, last_stage='exec')
    h.pump()
    assert not h.lc.control.dead
    assert (second.state, second.lease.state, second.channel.phase) == (ExecState.ACTIVE, LeaseState.HELD, Phase.DATA)
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
    ex, _ = run_to_active(h)
    sock = ex.channel.owned_fd
    assert sock.type == socket.SOCK_STREAM and sock.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1


def test_runtime_released_before_empty_on_open_row(h: Harness) -> None:
    ex, _ = run_to_active(h)
    h.spawner.runtime(ex)          # permitted order: storage fact first, row still open
    h.spawner.empty(ex)
    h.pump()
    assert not h.lc.control.dead and ex.slot_released and ex.execution_id not in h.lc.executions
    assert len(h.events('slot_released')) == 1


def test_workspace_reference_holds_workspace_and_slot(h: Harness) -> None:
    ex, _ = run_to_active(h)
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
    ex, _ = run_to_active(h)
    h.lc.close_session(ex)
    h.spawner.failed(ex, 'reap')
    h.spawner.failed(ex, 'reap')   # same terminal again: ignored
    h.pump()
    assert not h.lc.control.dead and len(ex.spawn_failures) == 1
    h.spawner.send('spawn_failed', ex, stage='reap', error_code='os_error', os_errno=10)
    assert h.faulted()


def test_never_created_after_prepared_faults(h: Harness) -> None:
    ex, _ = run_to_active(h)
    h.spawner.empty(ex, 'never_created')
    assert h.faulted() and ex.lease.state is LeaseState.QUARANTINED


def test_unmapped_close_reason_changes_nothing(h: Harness) -> None:
    ex, _ = run_to_active(h)
    with pytest.raises(ValueError):
        h.lc.close_session(ex, 'bye')
    assert ex.state is ExecState.ACTIVE and ex.channel.phase is Phase.DATA and ex.stop is StopState.NONE


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
    judgment, connector_end = h.spawner.judgment_pair()
    file_judgment, worker_end = h.spawner.judgment_pair()
    h.spawner.send('spawn_prepared', ex, fds=(engine_end.fileno(), judgment.fileno(), file_judgment.fileno()),
                   **h.spawner.prepared_fields(ex))
    for s in (engine_end, judgment, connector_end, file_judgment, worker_end):
        s.close()
    h.spawner.connectors_started.add(ex.execution_id)
    h.spawner.workers_started.add(ex.execution_id)
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
    judgment, connector_end = h.spawner.judgment_pair()
    file_judgment, worker_end = h.spawner.judgment_pair()
    h.spawner.send('spawn_prepared', ex, fds=(engine_end.fileno(), judgment.fileno(), file_judgment.fileno()),
                   **h.spawner.prepared_fields(ex))
    for s in (engine_end, judgment, connector_end, file_judgment, worker_end):
        s.close()
    h.spawner.connectors_started.add(ex.execution_id)
    h.spawner.workers_started.add(ex.execution_id)
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


# ---- v2: the row's connector (build plan items 7 and 13; validation.md K-22) ----------------------------------
@pytest.mark.parametrize('case', ['one-fd', 'two-fds', 'four-fds', 'no-connector-pid', 'no-worker-pid',
                                  'worker-pid-0'])
def test_prepared_needs_three_fds_and_both_pids(h: Harness, case: str) -> None:
    """H-06: a prepared record with another number of fds than three (the agent channel, the judgment end, the file
    judgment end), or without connector_pid or worker_pid, is a control fault, installs nothing and keeps no fd."""
    import array
    ex = h.launch()
    pairs = [socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM) for _ in range(4)]
    for a, _ in pairs:
        a.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    fields = h.spawner.prepared_fields(ex)
    if case.startswith('no-'):
        del fields[case[3:].replace('-', '_')]
    if case == 'worker-pid-0':
        fields['worker_pid'] = 0
    n = {'one-fd': 1, 'two-fds': 2, 'four-fds': 4}.get(case, 3)
    before = open_fds()
    wire = h.spawner.wire('spawn_prepared', ex, **fields)
    h.spawner.sock.sendmsg([wire], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [a.fileno() for a, _ in pairs[:n]]))])
    for a, _ in pairs:
        a.close()
    assert h.faulted() and ex.channel is None and ex.judgment is None and ex.file_judgment is None
    assert open_fds() - before <= {b.fileno() for _, b in pairs}
    for _, b in pairs:
        b.close()


def test_three_fds_install_the_channel_and_both_judgment_ends(h: Harness) -> None:
    """H-06: the third fd of a prepared record is the row's file judgment end, kept with the row (no hook in this
    harness: tests/test_core_wiring.py drives the port) and closed with it; worker_pid is the row's."""
    ex, child = run_to_active(h)
    assert child.recv(64) == COMMIT and ex.worker_pid == 4244 and ex.connector_pid == 4243
    assert ex.file_judgment is not None and ex.file_judgment.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
    h.lc.close_session(ex)
    assert ex.file_judgment is None and ex.judgment is None
    finish(h, ex)
    assert ex.execution_id in h.lc.tombstones
    child.close()


def test_workspace_and_slot_wait_for_the_worker_exit(h: Harness) -> None:
    """H-17: as for the connector (K-22), the workspace and the slot wait for the worker's exit as well."""
    ex, child = run_to_active(h)
    h.lc.close_session(ex)
    h.spawner.empty(ex, worker=False)
    h.spawner.runtime(ex)
    h.pump()
    assert ex.lease.state is LeaseState.FREE and not ex.workspace_released and not ex.slot_released
    assert h.lc.workspace_busy(ex.workspace_lease.workspace) is not None
    h.spawner.worker_exited(ex, exit_code=0)
    h.pump()
    assert ex.workspace_released and ex.slot_released and ex.execution_id in h.lc.tombstones
    assert h.events('worker_exited')[0]['detail'] == {'workspace_id': 'work0', 'exit_code': 0, 'signal': None} \
        and not h.lc.control.dead
    h.spawner.worker_exited(ex, exit_code=0)                 # a late duplicate with the same fact is ignored
    h.pump()
    assert not h.lc.control.dead
    h.spawner.worker_exited(ex, exit_code=1)                 # a conflicting one is a fault
    h.pump()
    assert h.lc.control.dead
    child.close()


def test_worker_exit_closes_an_open_row(h: Harness) -> None:
    """H-17: a row does not outlive its file worker."""
    ex, child = run_to_active(h)
    assert child.recv(64) == COMMIT
    h.spawner.worker_exited(ex, exit_code=None, signal=9)
    h.pump()
    assert ex.state is ExecState.CLOSED and ex.close_reason == 'worker_exited' and ex.file_judgment is None
    assert child.recv(64) == b'' and [s['reason'] for s in stops(h, ex)] == ['normal']
    finish(h, ex)
    assert ex.execution_id in h.lc.tombstones
    child.close()


def test_workspace_and_slot_wait_for_the_connector_exit(h: Harness) -> None:
    """execution_empty + runtime released release neither the workspace nor the slot until connector_exited arrives
    (K-22; overall review 2026-11-03, #4: the workspace too, so no hold or new row takes it before the connector is
    gone)."""
    ex, child = run_to_active(h)
    h.lc.close_session(ex)
    h.spawner.empty(ex, connector=False)
    h.spawner.runtime(ex)
    h.pump()
    assert ex.lease.state is LeaseState.FREE and not ex.workspace_released and not ex.slot_released
    assert h.lc.workspace_busy(ex.workspace_lease.workspace) is not None
    assert ex.execution_id in h.lc.executions and ex.execution_id not in h.lc.tombstones
    h.spawner.connector_exited(ex, exit_code=0)
    h.pump()
    assert ex.workspace_released and h.lc.workspace_busy(ex.workspace_lease.workspace) is None
    assert ex.slot_released and ex.execution_id in h.lc.tombstones and ex.execution_id not in h.lc.executions
    assert h.events('connector_exited')[0]['detail'] == {'workspace_id': 'work0', 'exit_code': 0, 'signal': None} \
        and not h.lc.control.dead
    h.spawner.connector_exited(ex, exit_code=0)              # a late duplicate with the same fact is ignored
    h.pump()
    assert not h.lc.control.dead
    h.spawner.connector_exited(ex, exit_code=1)              # a conflicting one is a fault
    h.pump()
    assert h.lc.control.dead
    child.close()


def test_connector_exit_closes_an_open_row(h: Harness) -> None:
    """A row does not outlive its connector: connector_exited on an open row closes it and stops the agent."""
    ex, child = run_to_active(h)
    assert child.recv(64) == COMMIT and ex.judgment is not None
    h.spawner.connector_exited(ex, exit_code=None, signal=9)
    h.pump()
    assert ex.state is ExecState.CLOSED and ex.close_reason == 'connector_exited' and ex.judgment is None
    assert child.recv(64) == b'' and [s['reason'] for s in stops(h, ex)] == ['normal']
    finish(h, ex)
    assert ex.execution_id in h.lc.tombstones
    child.close()
