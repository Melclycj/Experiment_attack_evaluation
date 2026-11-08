"""Control link, writer and event-loop rules (conn E-01 控制接口; E-04 控制链路故障)."""
from __future__ import annotations

import os
import selectors
import socket

from conftest import EPOCH, FakeClock, Gate, Harness, open_fds
from engine.ffi import Sent
from engine.lifecycle import Refused
from engine.loop import Loop
from engine.records import Recorder
from engine.objects import ExecState, LeaseState

import pytest


def test_old_seq_with_fd_closes_fd_and_faults(h: Harness) -> None:
    ex = h.launch()
    engine_end, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    engine_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    child.settimeout(2)
    wire = h.spawner.wire('spawn_prepared', ex, seq=1, launch_plan_digest=ex.launch_plan_digest,
                          policy_digest=ex.plan.policy_digest,
                          isolation_profile_digest=ex.plan.isolation_profile_digest, child_pid=7, sealed=True,
                          copy_id=ex.execution_id + ':r')
    fds = open_fds()
    h.spawner.raw(wire, engine_end.fileno())
    engine_end.close()
    assert h.faulted() and child.recv(64) == b'' and open_fds() - {child.fileno()} <= fds


def test_epoch_mismatch_faults(h: Harness) -> None:
    ex = h.launch()
    wire = h.spawner.wire('spawn_failed', ex, stage='validate', error_code='os_error', os_errno=None)
    h.spawner.raw(wire.replace(EPOCH.encode(), b'b' * 32))
    assert h.faulted()


def test_record_before_ready_faults(native) -> None:
    h = Harness(native, ready=False)
    h.spawner.drain()
    h.spawner.send('spawn_failed', None, stage='validate', error_code='os_error', os_errno=None,
                   execution_id=EPOCH + ':1', lease_id=EPOCH + ':1:u')
    assert h.faulted()


def test_ready_mismatch_faults(native) -> None:
    h = Harness(native, ready=False)
    init = h.spawner.drain()[0]
    h.spawner.send('control_ready', catalog_digest='sha256:' + 'e' * 64, protocol=init['protocol'],
                   runtime_storage_protocol=init['runtime_storage_protocol'],
                   storage_profile_digest=init['storage_profile_digest'])
    assert h.faulted() and not h.lc.control.ready


def test_wrong_direction_record_faults_without_escaping(h: Harness) -> None:
    ex = h.launch()
    h.spawner.send('control_init', catalog_digest='sha256:' + 'c' * 64, protocol='w2-local/2',
                   runtime_storage_protocol='w2-runtime-store/1', storage_profile_digest='sha256:' + 'd' * 64)
    assert h.faulted() and ex.lease.state is LeaseState.QUARANTINED


def test_outgoing_seq_bound(h: Harness) -> None:
    h.lc.control.out_seq = 2 ** 64
    ex = h.lc.launch('work0', 'observe-0', 'a')
    assert h.lc.control.dead and ex.empty_basis == 'local_never_submitted'
    assert not [r for r in h.spawner.drain() if r['type'] == 'spawn']


def test_stop_precedes_spawn_after_unblock(native) -> None:
    h = Harness(native, wrap=Gate)
    a = h.launch(0)
    h.native.result = Sent.NOTHING
    b = h.launch(1)
    h.lc.close_session(a)
    h.native.result = None
    h.lc.control.flush()
    sent = [(r['type'], r['execution_id']) for r in h.spawner.drain() if r['type'] in ('stop', 'spawn')]
    assert sent[-2:] == [('stop', a.execution_id), ('spawn', b.execution_id)]


def test_unwritable_period_reset_only_by_whole_send(native) -> None:
    h = Harness(native, wrap=Gate)
    h.native.result = Sent.NOTHING
    ex = h.launch()
    h.clock.advance(3000)
    h.lc.close_session(ex)       # withdraws the only queued record; nothing was sent
    h.clock.advance(4000)
    h.pump()
    assert not h.lc.control.dead  # nothing pending: not "full", no fault
    h.launch(1)                  # still unwritable: the period counts from the first block
    assert h.lc.control.dead


def test_idle_gap_then_whole_send_resets(native) -> None:
    h = Harness(native, wrap=Gate)
    h.native.result = Sent.NOTHING
    ex = h.launch()
    h.lc.close_session(ex)
    h.clock.advance(6000)
    h.native.result = None
    b = h.launch(1)
    assert not h.lc.control.dead and b.state is ExecState.PREPARING


def test_stall_checked_on_out_of_loop_flush(native) -> None:
    h = Harness(native, wrap=Gate)
    h.native.result = Sent.NOTHING
    ex = h.launch()
    h.clock.advance(5000)        # no loop round: the stall timer has not run
    h.native.result = None
    h.lc.control.flush()
    assert h.lc.control.dead and ex.empty_basis == 'local_never_submitted'


def test_expired_stall_beats_writable(native) -> None:
    h = Harness(native, wrap=Gate)
    h.native.result = Sent.NOTHING
    ex = h.launch()
    h.clock.advance(5000)
    h.native.result = None       # writable again in the same round the deadline expires
    h.pump()
    assert h.lc.control.dead and ex.spawn_submission.value == 'local'
    assert not [r for r in h.spawner.drain() if r['type'] == 'spawn']


def test_stale_selected_event_not_dispatched_to_new_registration() -> None:
    loop = Loop(FakeClock())  # type: ignore[arg-type]
    pairs = [socket.socketpair() for _ in range(2)]
    for a, b in pairs:
        b.send(b'x')  # both readable in the same select batch
    fresh_called = []
    state = {'swapped': False}

    def swap(victim: socket.socket) -> None:
        if state['swapped']:
            return
        state['swapped'] = True
        number = victim.fileno()
        loop.forget(number)
        replacement, _peer = socket.socketpair()
        victim.close()
        os.dup2(replacement.fileno(), number)
        replacement.close()
        state['keep'] = (_peer, number)
        loop.watch(number, selectors.EVENT_READ, lambda: fresh_called.append(number))

    (a0, _), (a1, _) = pairs
    loop.watch(a0.fileno(), selectors.EVENT_READ, lambda: swap(a1))
    loop.watch(a1.fileno(), selectors.EVENT_READ, lambda: swap(a0))
    loop.run_once(0)
    assert state['swapped'] and fresh_called == []  # the new object's socket had no data
    os.close(state['keep'][1])


def test_record_failure_closes_sessions_and_reclaim_carries_on(native) -> None:
    """si E-09: a failed record path closes every session and stops admission; stop and reap do not wait on it."""
    h = Harness(native)
    ex = h.launch()
    child = h.spawner.prepared(ex)
    h.pump()
    h.recorder.fail('sink broke')
    h.pump()
    assert child.recv(64) and ex.state is ExecState.CLOSED and ex.close_reason == 'record_fault'
    assert not h.lc.accepting_new
    h.spawner.drain()
    assert [r['reason'] for r in h.spawner.received if r['type'] == 'stop'] == ['control_shutdown']
    h.spawner.empty(ex)
    h.spawner.runtime(ex)
    h.pump()
    assert ex.lease.state is LeaseState.FREE and not h.lc.control.dead


def test_launch_refused_after_control_loss(h: Harness) -> None:
    h.spawner.sock.close()
    assert h.faulted()
    with pytest.raises(Refused):
        h.launch(0)
    assert Recorder('a' * 32, 65534, None).events.maxlen == 0  # production keeps nothing in memory


def test_spawn_not_sent_after_its_deadline_on_out_of_loop_flush(native) -> None:
    h = Harness(native, wrap=Gate)
    h.lc.startup_budget_ms = 1000          # below the 5 s stall period
    h.native.result = Sent.NOTHING
    ex = h.launch()
    h.clock.advance(1500)                  # no loop round: the startup timer has not run
    h.native.result = None
    h.lc.control.flush()                   # e.g. a trusted close of another row flushes now
    assert ex.close_reason == 'startup_deadline' and ex.empty_basis == 'local_never_submitted'
    assert not [r for r in h.spawner.drain() if r['type'] == 'spawn'] and not h.lc.control.dead
