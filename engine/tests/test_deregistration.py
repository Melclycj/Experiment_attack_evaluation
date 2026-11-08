"""AA-13 / engine-requirements §2: after close step 2 removes an fd's registration, the event library delivers no
readiness for that fd number, and nothing dispatches for the retired Channel (conn E-02 接收侧补充).

Exercised through the real close path, inside one loop round: the retired Channel's socket is readable in the
same select batch, it is closed and its fd number is reused by a new socket before that batch is processed."""
from __future__ import annotations

import os
import selectors
import socket

from conftest import Harness
from engine.objects import ExecState, Phase
from test_phases import REQUEST, frame, to_active


def test_backend_is_epoll(h: Harness) -> None:
    """The library under check: Python selectors' DefaultSelector, which is EpollSelector on Linux."""
    assert type(h.loop.selector) is selectors.EpollSelector


def same_round_close_and_reuse(h: Harness, new_has_data: bool) -> dict:
    ex, child = to_active(h)
    old_channel, old_fd = ex.channel, ex.channel.owned_fd.fileno()
    readable_calls: list = []
    real_readable = h.lc.data._readable

    def spy(ex_, channel):                      # every receive step the data plane runs, with its objects
        readable_calls.append((ex_, channel))
        return real_readable(ex_, channel)
    h.lc.data._readable = spy
    # Re-register the receiver so the spy sees the old Channel's dispatches (the attach closure captured the
    # original bound method).
    h.loop.watch(old_fd, selectors.EVENT_READ, h.lc._step(h.lc.data._readable, ex, old_channel))
    child.sendall(frame(REQUEST))               # the old Channel is readable in this round's select batch

    trigger_a, trigger_b = socket.socketpair()
    trigger_b.send(b'x')
    fresh: list = []
    state: dict = {}

    def earlier_decision() -> None:
        """Runs first in the round (priority fd): close the row, then reuse its fd number at once."""
        h.loop.forget(trigger_a.fileno())
        h.lc.close_session(ex)                   # close steps 1-4: unregister, shutdown, close the fd
        assert old_channel.phase is Phase.CLOSED
        replacement, peer = socket.socketpair()
        if replacement.fileno() == old_fd:       # the lowest free number is often the one just closed
            replacement.detach()
        else:
            os.dup2(replacement.fileno(), old_fd)    # the same fd number, a different socket
            replacement.close()
        if new_has_data:
            peer.send(b'y')
        state['peer'] = peer
        h.loop.watch(old_fd, selectors.EVENT_READ, lambda: fresh.append(h.loop.order))

    h.loop.watch(trigger_a.fileno(), selectors.EVENT_READ, earlier_decision)
    h.loop.priority.add(trigger_a.fileno())
    calls_before = len(readable_calls)
    h.loop.run_once(0)
    result = {'old_dispatched': [c for c in readable_calls[calls_before:] if c[1] is old_channel],
              'fresh_after_first_round': list(fresh), 'ex': ex, 'old_fd': old_fd}
    h.loop.run_once(0)
    result['fresh_after_second_round'] = list(fresh)
    h.loop.forget(old_fd)
    os.close(old_fd)
    state['peer'].close()
    trigger_a.close()
    trigger_b.close()
    return result


def test_retired_channel_gets_no_dispatch_and_new_socket_no_stale_event(h: Harness) -> None:
    r = same_round_close_and_reuse(h, new_has_data=False)
    assert r['old_dispatched'] == []                       # the old Channel's selected event was not run
    assert r['fresh_after_first_round'] == []              # nor handed to the new registration
    assert r['fresh_after_second_round'] == []             # and the new socket, idle, is never reported
    assert r['ex'].state is ExecState.CLOSED
    assert [e for e in h.events('message_received')
            if e['verified_subject']['execution_id'] == r['ex'].execution_id] == []   # the queued frame was never read


def test_new_socket_readiness_comes_from_its_own_select(h: Harness) -> None:
    """The old batch's event is dropped; the new socket's own readiness is reported by the next select."""
    r = same_round_close_and_reuse(h, new_has_data=True)
    assert r['old_dispatched'] == [] and r['fresh_after_first_round'] == []
    assert len(r['fresh_after_second_round']) >= 1
