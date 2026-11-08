"""The PDP, the three checkpoints and durable-before-release (agent-rm-model 648d60f2 4.2, 4.3; validation.md K-11,
K-15, K-16, K-22, K-46, K-47, K-48, K-49, K-50, K-52, K-53, K-54).

The hook-level tests drive the hook with the in-process FakePdp of test_hook (``hold`` keeps requests for the test to
answer). The hook-port tests run the real HookPort on a socket in a setgid directory, the test's own uid and group
standing in for the PDP's (the other-uid cases are in test_pdp_root.py).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Iterator

import pytest

from connector import canonical as c
from engine import records
from engine.judgment import DENY_NOT_AUTHORIZED, DENY_PDP, DENY_POLICY_CHANGED, DENY_UNAVAILABLE
from engine.pdp import HookDirRefused, HookPort
from engine.workspaces import Approval, EntryState, KeyKind, make_entry
from test_hook import EPOCH, Harness, allow, deny, judge_frame, memfd, recv_frame, send

ENGINE = Path(__file__).resolve().parents[1]
GH = 'api.github.com:443'


@pytest.fixture
def h(native, tmp_path: Path) -> Iterator[Harness]:
    harness = Harness(tmp_path, native)
    yield harness
    harness.close()


def silent(conn: socket.socket, s: float = 0.2) -> bool:
    conn.settimeout(s)
    try:
        conn.recv(1, socket.MSG_PEEK)                     # look, never consume
    except TimeoutError:
        return True
    finally:
        conn.settimeout(2)
    return False


# ---- K-47: every request the engine lets through goes to the PDP, which can only tighten ----------------------------------
def test_without_a_pdp_a_request_waits_and_a_pdp_that_connects_is_asked(h: Harness) -> None:
    allow(h, GH, ('GET',))
    h.pdp.link = None                                   # no PDP connected
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    h.pump()
    assert silent(conn) and h.pdp.requests == []
    h.pdp.link = object()
    h.hook.pdp_connected(h.pdp.link)
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED and len(h.pdp.requests) == 1


def test_a_pdp_deny_refuses_and_the_engines_refusals_never_reach_the_pdp(h: Harness) -> None:
    allow(h, GH, ('GET',))
    h.pdp.allow = False
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    send(conn, judge_frame(2, ex.lease.uid, method=b'POST'), memfd(b''))           # the table refuses it
    h.pump()
    kinds = [(k, c.read_uint(f[1], 1)) for k, f in (recv_frame(conn), recv_frame(conn))]
    assert kinds == [(c.DENY, DENY_PDP), (c.DENY, DENY_NOT_AUTHORIZED)] and len(h.pdp.requests) == 1


def test_the_request_to_the_pdp_is_what_will_run(h: Harness) -> None:
    """K-50: the request's own fields, the cell's key and content, the binding (never a truth), the user's answer."""
    h.credentials.register(GH, 'alice', 2, b'Bearer', b'ghp_truth', b'')
    allow(h, GH, ('POST',), accounts=('alice',))
    h.pdp.hold = True
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', path=b'/repos/a/issues', headers=((b'authorization', b'Bearer x'),),
                           body=b'{"t":1}'), memfd(b'{"t":1}'))
    h.pump()
    [f] = h.pdp.requests
    assert (f[0], c.read_uint(f[1], 8), f[2], f[3]) == (EPOCH.encode(), 1, ex.execution_id.encode(), b'work0')
    assert (f[5], f[6], f[7], c.read_uint(f[8], 2), f[9]) == (b'POST', b'https', b'api.github.com', 443, b'/repos/a/issues')
    assert c.unpack_list(f[11]) == [b'authorization', b'Bearer x'] and c.read_uint(f[15], 8) == 7
    assert (c.read_uint(f[16], 1), f[17]) == (int(KeyKind.EXACT), GH.encode())
    assert c.unpack_list(f[19]) == [GH.encode(), b'alice', c.u8(2)] and c.read_uint(f[20], 1) == 0
    assert all(b'ghp_truth' not in x for x in f)
    asked = h.events('pdp_requested')[-1]['detail']
    assert asked['key'] == GH and asked['account'] == 'alice' and 'methods' not in asked      # no cell content in the trace


def test_each_request_carries_its_own_rows_policy_context(h: Harness) -> None:
    """K-56: every request to the PDP carries, as its 22nd field (index 21; H-09 appends after it), the policy context registered for that row, unchanged
    and in the same frame as the kernel-attributed sender; a row without one sends an empty field; another row's
    context never appears; bytes the agent puts in its request (a header and a body shaped like a context) do not
    change it; no record holds it."""
    allow(h, GH, ('POST',))
    h.pdp.hold = True
    a_ex, a_conn = h.row(0, policy_context=b'ctx-A\x00\xff')
    b_ex, b_conn = h.row(1)
    send(a_conn, judge_frame(1, a_ex.lease.uid, method=b'POST', headers=((b'x-policy-context', b'ctx-B'),), body=b'ctx-B'),
         memfd(b'ctx-B'))
    send(b_conn, judge_frame(1, b_ex.lease.uid, method=b'POST', body=b'ctx-B'), memfd(b'ctx-B'))
    h.pump()
    assert len(h.pdp.requests) == 2 and all(len(f) == c.FIELD_COUNT[c.PDP_REQUEST] == 28 for f in h.pdp.requests)
    assert all(f[22] == c.u8(0) and f[23:27] == [b'', b'', c.u64(0), c.u64(0)] and c.unpack_list(f[27]) == []
               for f in h.pdp.requests)                         # H-09: a network request's file fields are empty
    by_row = {f[2]: f for f in h.pdp.requests}
    a_req, b_req = by_row[a_ex.execution_id.encode()], by_row[b_ex.execution_id.encode()]
    assert a_req[21] == b'ctx-A\x00\xff' and c.read_uint(a_req[4], 4) == a_ex.lease.uid
    assert b_req[21] == b'' and c.read_uint(b_req[4], 4) == b_ex.lease.uid
    assert 'ctx-A' not in repr(h.recorder.events)


def test_a_transfer_row_is_refused_at_the_first_checkpoint_and_never_reaches_the_pdp(h: Harness) -> None:
    """S-24: on a workspace with the fallback GET entry and a covering, never-ask exact allow entry, the same request
    goes to the PDP and through from an ordinary row, and is refused not_authorized at the first checkpoint from a
    transfer row, which hangs no entries; the PDP never hears of it."""
    allow(h, GH, ('GET',))
    plain, plain_conn = h.row(0)
    transfer, transfer_conn = h.row(1, transfer='push')
    send(plain_conn, judge_frame(1, plain.lease.uid), memfd(b''))
    h.pump()
    assert recv_frame(plain_conn)[0] == c.ALLOW_NOCRED and len(h.pdp.requests) == 1
    send(transfer_conn, judge_frame(1, transfer.lease.uid), memfd(b''))
    h.pump()
    kind, fields = recv_frame(transfer_conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_NOT_AUTHORIZED) and len(h.pdp.requests) == 1
    assert h.events('request_decided')[-1]['reason_code'] == 'transfer_row'


def test_answers_that_do_not_count_are_dropped(h: Harness) -> None:
    """K-49: another epoch, an unknown id, another connection, a second answer: dropped, noted, nothing released."""
    allow(h, GH, ('GET',))
    h.pdp.hold = True
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    h.pump()
    [f] = h.pdp.requests
    h.hook.pdp_answer(h.pdp.link, 'c' * 32, 1, True)
    h.hook.pdp_answer(h.pdp.link, EPOCH, 99, True)
    h.hook.pdp_answer(object(), EPOCH, 1, True)
    h.pump()
    assert silent(conn)
    h.pdp.answer(f)
    h.pdp.answer(f)                                       # the second is noted, not counted
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED and silent(conn)
    assert [e['name'] for e in h.recorder.events if e['kind'] == 'diagnostic'].count('pdp_answer_ignored') == 4


def test_a_pdp_that_goes_has_its_unanswered_requests_refused(h: Harness) -> None:
    allow(h, GH, ('GET',))
    h.pdp.hold = True
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    h.pump()
    h.hook.pdp_lost(h.pdp.link)
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_UNAVAILABLE)
    assert h.events('request_decided')[-1]['reason_code'] == 'pdp_disconnected'


def test_the_row_waits_while_its_request_is_with_the_pdp(h: Harness) -> None:
    """K-15: one request per row from admission to release; another row does not wait."""
    allow(h, GH, ('GET',))
    h.pdp.hold = True
    a, conn_a = h.row(0)
    b, conn_b = h.row(1)
    send(conn_a, judge_frame(1, a.lease.uid), memfd(b''))
    send(conn_a, judge_frame(2, a.lease.uid), memfd(b''))
    send(conn_b, judge_frame(1, b.lease.uid), memfd(b''))
    h.pump()
    assert [c.read_uint(f[1], 8) for f in h.pdp.requests] == [1, 3]          # a's second is not judged yet
    h.pdp.answer(h.pdp.requests[1])
    h.pump()
    assert recv_frame(conn_b)[0] == c.ALLOW_NOCRED and silent(conn_a)
    h.pdp.answer(h.pdp.requests[0])
    h.pump()
    assert recv_frame(conn_a)[0] == c.ALLOW_NOCRED and [c.read_uint(f[1], 8) for f in h.pdp.requests] == [1, 3, 2]


# ---- K-46: the third checkpoint ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize('change, released', [('uncovered', False), ('still_covers', True), ('credential', False),
                                              ('endpoint', False), ('other_endpoint', True), ('ask', False), ('unrelated', True),
                                              ('none', True), ('address_added', False), ('address_removed', False),
                                              ('address_kept', True)])
def test_a_change_while_the_pdp_judges_is_caught_at_the_third_checkpoint(h: Harness, change: str, released: bool) -> None:
    """K-46: the five items; the fifth, the cell's named addresses (plan engine-v3-private-net), refuses an address
    added or removed while the PDP judges, and passes a rewrite that keeps the same set."""
    h.credentials.register(GH, 'alice', 2, b'Bearer', b't', b'')
    named_before = ('10.0.0.0/8',) if change in ('address_removed', 'address_kept') else ()
    allow(h, GH, ('GET',), ('/repos',), accounts=('alice',), addresses=named_before)
    h.pdp.hold = True
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, headers=((b'authorization', b'Bearer x'),)), memfd(b''))
    h.pump()
    if change == 'uncovered':                             # narrowed so that it no longer covers the request
        allow(h, GH, ('GET',), ('/users',), accounts=('alice',))
    elif change == 'still_covers':                        # narrowed, still covering: the decision is the same
        allow(h, GH, ('GET',), ('/repos/a',), accounts=('alice',))
    elif change == 'credential':
        h.credentials.delete(GH, 'alice')
    elif change == 'endpoint':                            # the token endpoint list lives in the credential records
        h.credentials.register(GH, 'alice', 2, b'Bearer', b't', b'', token_endpoint='https://api.github.com/repos/a')
    elif change == 'other_endpoint':                      # an account this row cannot use: not its list (design 2026-11-02)
        h.credentials.register('other.example:443', 'o', 2, b'Bearer', b'o', b'', token_endpoint='https://api.github.com/repos/a')
    elif change == 'ask':                                 # the cell now asks: this request was never asked
        allow(h, GH, ('GET',), ('/repos',), accounts=('alice',), approval=Approval.ALWAYS)
    elif change == 'unrelated':
        allow(h, 'other.example:443', ('GET',))
    elif change == 'address_added':                       # the cell now names a private range it did not
        allow(h, GH, ('GET',), ('/repos',), accounts=('alice',), addresses=('10.0.0.0/8',))
    elif change == 'address_removed':
        allow(h, GH, ('GET',), ('/repos',), accounts=('alice',))
    elif change == 'address_kept':                        # rewritten, still covering, the same named set
        allow(h, GH, ('GET',), ('/repos/a',), accounts=('alice',), addresses=('10.0.0.0/8',))
    h.pdp.answer(h.pdp.requests[0])
    h.pump()
    frames = []
    while not silent(conn, 0.1):
        frames.append(recv_frame(conn))
    allowed = [k for k, _ in frames if k == c.ALLOW]
    denied = [c.read_uint(f[1], 1) for k, f in frames if k == c.DENY]
    assert (bool(allowed), denied) == ((True, []) if released else (False, [DENY_POLICY_CHANGED]))


def test_a_literal_whose_name_goes_while_the_pdp_judges_is_refused_at_the_third_checkpoint(h: Harness) -> None:
    """K-58, K-46: the redo of the first checkpoint applies the naming rule too: 10.0.0.5 named through 10.0.0.0/24
    when the PDP was asked, the cell renamed to 10.0.1.0/24 meanwhile: refused, policy_changed."""
    allow(h, '10.0.0.5:80', ('GET',), addresses=('10.0.0.0/24',))
    h.pdp.hold = True
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, scheme=b'http', host=b'10.0.0.5', port=80, path=b'/'), memfd(b''))
    h.pump()
    assert len(h.pdp.requests) == 1
    allow(h, '10.0.0.5:80', ('GET',), addresses=('10.0.1.0/24',))
    h.pdp.answer(h.pdp.requests[0])
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_POLICY_CHANGED)


def test_the_cell_the_pdp_is_asked_about_names_its_addresses(h: Harness) -> None:
    """K-50, K-57 (plan engine-v3-private-net 接口约定): the PDP_REQUEST's cell is pdp.entry_fields of the covering
    entry, six items, the sixth its named addresses in stored order."""
    from engine.pdp import entry_fields
    allow(h, 'gitlab.corp:443', ('GET',), addresses=('fd12:3456::/48', '10.0.0.0/8'))
    entry = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'gitlab.corp:443')]
    h.pdp.hold = True
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'gitlab.corp'), memfd(b''))
    h.pump()
    [f] = h.pdp.requests
    cell = c.unpack_list(f[18])
    assert f[18] == c.pack_list(entry_fields(entry)) and len(cell) == 6
    assert c.unpack_list(cell[5]) == [b'10.0.0.0/8', b'fd12:3456::/48']


def test_a_tightening_that_did_not_persist_still_moves_the_version(h: Harness) -> None:
    allow(h, GH, ('GET',))
    before = h.tables.tables['work0'].version
    h.tables.disk.fail_at = 'rename'
    result = h.tables.put('work0', make_entry(KeyKind.EXACT, GH, EntryState.DENY, ['GET'], [], [], Approval.NEVER))
    assert result.applied and not result.persisted                      # a deny is a tightening: in memory, unpersisted
    assert h.tables.tables['work0'].version == before + 1


# ---- K-16, K-22: withdrawal and row close at every stage; the allow record is followed by another (K-46) --------------------
def test_withdraw_and_close_while_with_the_pdp(h: Harness) -> None:
    allow(h, GH, ('GET',))
    h.pdp.hold = True
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    send(conn, judge_frame(2, ex.lease.uid), memfd(b''))
    h.pump()
    send(conn, c.pack_frame(c.WITHDRAW, [c.u64(1)]))
    h.pump()
    assert h.events('request_withdrawn')[-1]['detail']['stage'] == 'pdp'
    h.pdp.answer(h.pdp.requests[0])                          # too late: nothing is released for seq 1
    h.pump()
    assert c.read_uint(h.pdp.requests[1][1], 8) == 2           # the row went on to the next request
    h.close_row(ex)
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, 2, DENY_UNAVAILABLE)
    assert h.events('request_decided')[-1]['detail']['stage'] == 'pdp'


# ---- K-52, K-53: durable before release with a real record file and writer --------------------------------------------------
@pytest.fixture
def d(native, tmp_path: Path) -> Harness:
    evidence = tmp_path / 'events.jsonl'
    evidence.write_bytes(b'')
    harness = Harness(tmp_path, native, str(evidence))
    harness.evidence = evidence
    yield harness
    harness.recorder.close()


def stall(d: Harness) -> threading.Event:
    gate = threading.Event()
    real = d.recorder.fsync
    d.recorder.fsync = lambda fd: (gate.wait(10), real(fd))[1]
    return gate


def pump_until(d: Harness, conn: socket.socket, seconds: float = 3.0):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        d.loop.run_once(0.05)
        r, _, _ = select.select([conn], [], [], 0)
        if r:
            return recv_frame(conn)
    return None


def on_disk(d: Harness) -> list[dict]:
    return [json.loads(x) for x in d.evidence.read_bytes().splitlines() if x.strip()]


def test_no_allow_frame_before_its_record_is_durable(d: Harness) -> None:
    """A writer stopped before fsync holds the release back: an implementation that sent first would fail here."""
    allow(d, GH, ('GET',))
    gate = stall(d)
    ex, conn = d.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    for _ in range(20):
        d.loop.run_once(0.02)
    assert silent(conn) and d.hook.durable                       # the PDP allowed; the record waits for fsync
    gate.set()
    kind, fields = pump_until(d, conn)
    assert kind == c.ALLOW_NOCRED
    allowed = [e for e in on_disk(d) if e['kind'] == 'request_decided' and e['outcome'] == 'allow']
    assert [e['detail']['admission'] for e in allowed] == [1]


def test_a_failed_fsync_releases_nothing(d: Harness) -> None:
    allow(d, GH, ('GET',))
    d.recorder.fsync = lambda fd: (_ for _ in ()).throw(OSError(5, 'EIO'))
    ex, conn = d.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    kind, fields = pump_until(d, conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_UNAVAILABLE) and d.recorder.failed


def test_a_latch_closed_before_the_read_refuses_although_the_record_is_durable(d: Harness) -> None:
    """The latch and the receipt are read together: a fault that lands before that read refuses the release."""
    allow(d, GH, ('GET',))
    gate = stall(d)
    ex, conn = d.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    for _ in range(20):
        d.loop.run_once(0.02)
    gate.set()
    until = time.monotonic() + 3
    while d.recorder.status()[1] < max(p.record_seq for p in d.hook.durable.values()) and time.monotonic() < until:
        time.sleep(0.01)                                     # the receipt moved; the core has not read it yet
    d.recorder.fail('injected after the receipt')
    kind, fields = pump_until(d, conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_UNAVAILABLE)


def test_a_latch_closed_between_two_releases_of_one_receipt_refuses_the_second(d: Harness) -> None:
    """648d60f2 4.3: a latch closed after the read takes effect from the next release, so each release reads the latch
    and the receipt again, even when one fsync covered several records (review: Codex)."""
    allow(d, GH, ('GET',))
    gate = stall(d)
    rows = [d.row(0), d.row(1)]
    for ex, conn in rows:
        send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    until = time.monotonic() + 3
    while len(d.hook.durable) < 2 and time.monotonic() < until:
        d.loop.run_once(0.02)
    assert len(d.hook.durable) == 2
    gate.set()
    until = time.monotonic() + 3
    while d.recorder.status()[1] < max(p.record_seq for p in d.hook.durable.values()) and time.monotonic() < until:
        time.sleep(0.01)                                     # one receipt covers both records
    real = d.hook._third_checkpoint

    def then_latch(row, p) -> None:
        real(row, p)
        d.recorder.fail('injected between two releases')

    d.hook._third_checkpoint = then_latch
    frames = [pump_until(d, conn) for _, conn in rows]
    kinds = sorted((kind, c.read_uint(fields[1], 1) if kind == c.DENY else None) for kind, fields in frames)
    assert kinds == sorted([(c.ALLOW_NOCRED, None), (c.DENY, DENY_UNAVAILABLE)])


def test_the_wake_pipe_is_written_after_the_receipt_moves(d: Harness) -> None:
    d.recorder.record('table_changed', source_ref={'port': 'admin', 'object': 'x'}, detail={'n': 1})
    r, _, _ = select.select([d.recorder.wake_r], [], [], 3)
    assert r and d.recorder.status()[1] >= 1


def test_an_allow_record_not_released_is_followed_by_one(d: Harness) -> None:
    """K-46: the allow record is the release intent; a request it did not release has a later record."""
    allow(d, GH, ('GET',))
    gate = stall(d)
    ex, conn = d.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    for _ in range(20):
        d.loop.run_once(0.02)
    allow(d, GH, ('POST',))                                     # no longer covered: the third checkpoint refuses
    gate.set()
    kind, fields = pump_until(d, conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_POLICY_CHANGED)
    d.recorder.close()
    mine = [(e['kind'], e['outcome']) for e in on_disk(d) if e.get('detail', {}).get('admission') == 1]
    assert mine[-2:] == [('request_decided', 'allow'), ('request_decided', 'deny')]


CHILD = r'''
import os, sys
sys.path[:0] = [sys.argv[1], sys.argv[1] + '/tests']
from engine.ffi import Native
from test_hook import Harness, allow, judge_frame, memfd, recv_frame, send
from pathlib import Path
h = Harness(Path(sys.argv[2]), Native(Path(sys.argv[3])), sys.argv[4])
allow(h, 'api.github.com:443', ('GET',))
ex, conn = h.row()
send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
while True:
    h.loop.run_once(0.02)
    conn.setblocking(False)
    try:
        got = conn.recv(1, __import__('socket').MSG_PEEK)
    except BlockingIOError:
        continue
    print('ALLOW' if got else 'EOF', flush=True)
    os.kill(os.getpid(), 19)           # stop: the parent kills it
'''


def test_killed_right_after_the_allow_frame_the_record_is_on_disk(native, library: Path, tmp_path: Path) -> None:
    evidence = tmp_path / 'events.jsonl'
    evidence.write_bytes(b'')
    child = subprocess.Popen([sys.executable, '-c', CHILD, str(ENGINE), str(tmp_path), str(library), str(evidence)],
                             stdout=subprocess.PIPE, text=True)
    try:
        line = child.stdout.readline()
    finally:
        child.send_signal(signal.SIGKILL)
        child.wait(10)
    assert line.strip() == 'ALLOW'
    allowed = [json.loads(x) for x in evidence.read_bytes().splitlines()
               if b'"request_decided"' in x and b'"outcome":"allow"' in x]
    assert len(allowed) == 1 and allowed[0]['detail']['admission'] == 1


# ---- K-54: record size --------------------------------------------------------------------------------------------------------
def test_an_oversized_record_refuses_only_its_request(h: Harness, monkeypatch) -> None:
    allow(h, GH, ('GET',))
    monkeypatch.setattr(records, 'EVENT_MAX', 3000)
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, path=b'/repos/' + b'a' * 4000), memfd(b''))
    send(conn, judge_frame(2, ex.lease.uid), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, 1, DENY_UNAVAILABLE)
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED and h.recorder.failed is None


def test_a_request_at_every_limit_fits_its_records(h: Harness) -> None:
    allow(h, GH, ())
    ex, conn = h.row()
    name_max = c.LIMITS.header_name
    headers = tuple((b'x-' + b'h' * (name_max - 5) + b'%03d' % i, b'v') for i in range(127))
    headers += ((b'content-type', b'application/x-www-form-urlencoded'),)
    keys = tuple('\x00' * 15 + '%04d' % i for i in range(4096))[:3200]          # NULs: six bytes each in JSON
    send(conn, judge_frame(1, ex.lease.uid, path=b'/' + b'p' * 8190, headers=headers, form_keys=keys,
                           body_kind='application/x-www-form-urlencoded'), memfd(b''))
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED and h.recorder.failed is None



def test_a_request_with_every_header_value_and_the_query_at_their_limits_fits_its_records(h: Harness) -> None:
    """K-54 with the admission record carrying the values (design 4.1, 2026-11-02): header values at the header block
    limit, every byte obs-text (two bytes each in the record), and the query at its limit still fit one record."""
    allow(h, GH, ())
    ex, conn = h.row()
    per = c.LIMITS.header_value - 16
    count = c.LIMITS.header_bytes // (per + 16)
    headers = tuple((b'x-v%02d' % i, b'\xff' * per) for i in range(count))
    send(conn, judge_frame(1, ex.lease.uid, path=b'/' + b'p' * 8190, query=b'q' * c.LIMITS.query, headers=headers),
         memfd(b''))
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED and h.recorder.failed is None
    admitted = h.events('request_admitted')[-1]['detail']
    assert len(admitted['query']) == c.LIMITS.query and len(admitted['header_values']) == count

# ---- the hook port over a real socket (K-48, K-49) ------------------------------------------------------------------------------
def hook_dir(tmp_path: Path, mode: int = 0o2750) -> Path:
    path = tmp_path / 'hook'
    path.mkdir()
    os.chmod(path, mode)
    return path


def port(h: Harness, tmp_path: Path) -> HookPort:
    return HookPort(h.loop, h.recorder, hook_dir(tmp_path), os.getuid(), os.getgid(), os.getuid(), h.hook, h.tables)


def pdp_client(p: HookPort) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(p.path))
    s.settimeout(2)
    return s


def read_frames(h: Harness, s: socket.socket, want: int = 1) -> list[tuple[int, list[bytes], list[int]]]:
    parser, out, fds = c.FrameParser(c.LIMITS.frame_bd, c.LINK_F_TO_PDP), [], []
    until = time.monotonic() + 3
    while len(out) < want and time.monotonic() < until:
        h.pump()
        r, _, _ = select.select([s], [], [], 0.05)
        if not r:
            continue
        data, got, _, _ = socket.recv_fds(s, 1 << 20, 4)
        fds += got
        out += [(k, f, fds) for k, f in parser.feed(data)]
    return out


def test_a_frame_waiting_for_the_pdp_sends_its_own_copy_of_the_body(h: Harness, tmp_path: Path) -> None:
    """Cold review 2026-11-01: the request is withdrawn while its frame waits for a PDP that does not drain; its memfd is
    closed and a new descriptor may take the number. The PDP must still get the request's body, nothing else."""
    p = port(h, tmp_path)
    allow(h, GH, ('POST',))
    s = pdp_client(p)
    h.pump()
    link = p.link
    junk = 0
    while True:                                                    # fill the link so the next frame has to wait
        try:
            junk += link.sock.send(b'\0' * 65536, socket.MSG_DONTWAIT)
        except BlockingIOError:
            break
    ex, conn = h.row()
    body = memfd(b'{"x":1}')
    inode = os.fstat(body).st_ino
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', body=b'{"x":1}'), body)
    h.pump()
    assert link.out and link.out[0][1] is not None                 # queued, holding a descriptor
    send(conn, c.pack_frame(c.WITHDRAW, [c.u64(1)]))
    h.pump()
    assert h.events('request_withdrawn')
    decoys = [memfd(b'decoy') for _ in range(4)]                   # take the freed numbers
    data, fds = b'', []
    until = time.monotonic() + 5
    parsed: list = []
    while not parsed and time.monotonic() < until:
        h.pump()
        r, _, _ = select.select([s], [], [], 0.05)
        if r:
            chunk, got, _, _ = socket.recv_fds(s, 1 << 20, 4)
            data, fds = data + chunk, fds + got
        if len(data) > junk:
            parsed = c.FrameParser(c.LIMITS.frame_bd, c.LINK_F_TO_PDP).feed(data[junk:])
    assert [k for k, _ in parsed] == [c.PDP_REQUEST] and len(fds) == 1
    assert os.pread(fds[0], 16, 0) == b'{"x":1}'                   # the body, not a descriptor that took its number
    assert os.fstat(fds[0]).st_ino == inode
    assert link.out == [] and not link.dead
    for fd in fds + decoys:
        os.close(fd)
    s.close()


def test_a_pdp_lost_while_being_sent_the_waiting_requests_leaves_the_rest_for_the_next(h: Harness) -> None:
    """Cold review 2026-11-01: the link breaks on the first of the waiting requests; the ones after it are not tied to
    the dead link, and the next PDP is asked about them (K-49)."""
    class Breaking:
        dead = False

    class Pdp:
        def __init__(self) -> None:
            self.link, self.sent = None, []

        def send_request(self, link, fields, memfd) -> None:
            self.sent.append((link, c.read_uint(fields[1], 8)))
            if isinstance(link, Breaking) and not link.dead:
                link.dead = True
                h.hook.pdp_lost(link)

    pdp = Pdp()
    h.hook.pdp = pdp
    allow(h, GH, ('GET',))
    rows = [h.row(i) for i in range(2)]
    for ex, conn in rows:
        send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    h.pump()
    assert len(h.hook.pdp_waiting) == 2 and pdp.sent == []         # no PDP yet: both wait
    first = Breaking()
    h.hook.pdp_connected(first)
    assert len(pdp.sent) == 1                                       # the second was not handed to the dead link
    h.pump()
    kind, fields = recv_frame(rows[0][1])
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_UNAVAILABLE)   # the first: refused with the link
    [left] = h.hook.pdp_waiting.values()
    assert left.link is None
    second = object()
    h.hook.pdp_connected(second)
    assert pdp.sent[-1] == (second, left.admission)                 # the next PDP is asked about it


@pytest.mark.parametrize('mode', [0o750, 0o2770, 0o2755, 0o2700])
def test_the_hook_directory_must_be_the_deployments(h: Harness, tmp_path: Path, mode: int) -> None:
    with pytest.raises(HookDirRefused):
        HookPort(h.loop, h.recorder, hook_dir(tmp_path, mode), os.getuid(), os.getgid(), os.getuid(), h.hook, h.tables)


def test_a_pdp_on_the_socket_is_asked_and_its_answer_released(h: Harness, tmp_path: Path) -> None:
    p = port(h, tmp_path)
    assert oct(os.stat(p.path).st_mode & 0o777) == '0o660' and os.stat(p.path).st_gid == os.getgid()
    allow(h, GH, ('POST',))
    s = pdp_client(p)
    h.pump()
    assert h.events('pdp_connected')
    ex, conn = h.row()
    body = memfd(b'{"x":1}')
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', body=b'{"x":1}'), body)
    [(kind, fields, fds)] = read_frames(h, s)
    assert kind == c.PDP_REQUEST and len(fds) == 1 and os.pread(fds[0], 16, 0) == b'{"x":1}'
    assert os.fstat(fds[0]).st_ino == os.fstat(body).st_ino               # the same memfd the connector sealed
    for fd in fds:
        os.close(fd)
    s.sendall(c.pack_frame(c.PDP_ANSWER, [fields[0], fields[1], c.u8(c.PDP_ALLOW)]))
    kind, _ = pump_until(h, conn)
    assert kind == c.ALLOW_NOCRED
    s.close()


def test_a_second_pdp_is_refused_and_a_disconnect_refuses_the_unanswered(h: Harness, tmp_path: Path) -> None:
    p = port(h, tmp_path)
    allow(h, GH, ('GET',))
    first = pdp_client(p)
    h.pump()
    second = pdp_client(p)
    h.pump()
    assert second.recv(16) == b''                                         # dropped at accept
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    frames = read_frames(h, first)
    for fd in frames[0][2]:
        os.close(fd)
    first.close()
    kind, fields = pump_until(h, conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_UNAVAILABLE) and h.events('pdp_disconnected')


def test_the_table_query_reads_and_changes_nothing(h: Harness, tmp_path: Path) -> None:
    p = port(h, tmp_path)
    allow(h, GH, ('GET',), accounts=())
    s = pdp_client(p)
    h.pump()
    table = h.tables.tables['work0']
    before = (table.version, dict(table.entries))
    s.sendall(c.pack_frame(c.TABLE_QUERY, [b'work0']))
    [(kind, fields, _)] = read_frames(h, s)
    assert kind == c.TABLE_SNAPSHOT and c.read_uint(fields[1], 1) == c.SNAP_OK and c.read_uint(fields[2], 8) == before[0]
    keys = sorted(c.unpack_list(e)[1] for e in c.unpack_list(fields[3]))
    assert keys == [b'', GH.encode()] and (table.version, dict(table.entries)) == before
    s.sendall(c.pack_frame(c.TABLE_QUERY, [b'nope']))
    [(kind, fields, _)] = read_frames(h, s)
    assert c.read_uint(fields[1], 1) == c.SNAP_UNKNOWN


def test_the_table_snapshot_shows_each_cells_named_addresses(h: Harness, tmp_path: Path) -> None:
    """K-57 (plan engine-v3-private-net 接口约定): each snapshot entry is key kind, key and the same six-item cell as the
    PDP_REQUEST (pdp.entry_fields): eight items, the last the named addresses; the fallback's is empty."""
    p = port(h, tmp_path)
    allow(h, 'gitlab.corp:443', ('GET',), addresses=('fd12:3456::/48', '10.0.0.0/8'))
    s = pdp_client(p)
    h.pump()
    s.sendall(c.pack_frame(c.TABLE_QUERY, [b'work0']))
    [(kind, fields, _)] = read_frames(h, s)
    assert kind == c.TABLE_SNAPSHOT and c.read_uint(fields[1], 1) == c.SNAP_OK
    items = {c.unpack_list(e)[1]: c.unpack_list(e) for e in c.unpack_list(fields[3])}
    assert sorted(len(x) for x in items.values()) == [8, 8]
    assert c.unpack_list(items[b'gitlab.corp:443'][7]) == [b'10.0.0.0/8', b'fd12:3456::/48']
    assert c.unpack_list(items[b''][7]) == []
    s.close()


@pytest.mark.parametrize('frame', [c.pack_frame(c.ENTRY_PUT, [b''] * c.FIELD_COUNT[c.ENTRY_PUT]),   # a management verb
                                   c.pack_frame(c.PDP_REQUEST, [b''] * c.FIELD_COUNT[c.PDP_REQUEST]),                 # the core's own direction
                                   c.pack_frame(c.PDP_ANSWER, [EPOCH.encode(), c.u64(1), c.u8(7)]),   # no such verdict
                                   c.u32(5) + c.u8(c.PDP_ANSWER) + c.u32(0)])               # a frame that does not read
def test_a_frame_that_is_not_the_pdps_drops_the_pdp(h: Harness, tmp_path: Path, frame: bytes) -> None:
    p = port(h, tmp_path)
    s = pdp_client(p)
    h.pump()
    s.sendall(frame)
    h.pump()
    assert s.recv(16) == b'' and p.link is None and h.events('pdp_disconnected')


def test_the_simple_pdp_allows_every_request_and_reads_no_body(h: Harness, tmp_path: Path) -> None:
    """P-01: pdp/simple.py on the real port: each request answered allow, its memfd closed unread."""
    from pdp import simple
    p = port(h, tmp_path)
    allow(h, GH, ('GET', 'POST'))
    s = pdp_client(p)
    worker = threading.Thread(target=simple.serve, args=(s,), daemon=True)
    worker.start()
    h.pump()
    ex, conn = h.row()
    for seq in (1, 2):
        send(conn, judge_frame(seq, ex.lease.uid, method=b'POST', body=b'secret body'), memfd(b'secret body'))
    assert [pump_until(h, conn)[0] for _ in range(2)] == [c.ALLOW_NOCRED, c.ALLOW_NOCRED]
    assert [e['detail']['allow'] for e in h.events('pdp_answered')] == [True, True]
    s.shutdown(socket.SHUT_RDWR)
    worker.join(3)


def test_the_test_pdp_denies_by_the_rows_policy_context(h: Harness, tmp_path: Path) -> None:
    """P-02: the simple PDP's test variant on the real port denies every request of the row registered with the given
    context and allows the row without one; the plain simple PDP does not look at the context."""
    from pdp import simple
    p = port(h, tmp_path)
    allow(h, GH, ('GET',))
    s = pdp_client(p)
    worker = threading.Thread(target=simple.serve, args=(s, b'deny-me'), daemon=True)
    worker.start()
    h.pump()
    marked, marked_conn = h.row(0, policy_context=b'deny-me')
    plain, plain_conn = h.row(1)
    send(marked_conn, judge_frame(1, marked.lease.uid), memfd(b''))
    kind, fields = pump_until(h, marked_conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_PDP)
    send(plain_conn, judge_frame(1, plain.lease.uid), memfd(b''))
    assert pump_until(h, plain_conn)[0] == c.ALLOW_NOCRED
    s.shutdown(socket.SHUT_RDWR)
    worker.join(3)


def test_the_simple_pdp_answers_alike_with_or_without_a_policy_context(h: Harness, tmp_path: Path) -> None:
    """P-02: the plain simple PDP does not read the context: a row registered with one and a row without are both
    allowed."""
    from pdp import simple
    p = port(h, tmp_path)
    allow(h, GH, ('GET',))
    s = pdp_client(p)
    worker = threading.Thread(target=simple.serve, args=(s,), daemon=True)
    worker.start()
    h.pump()
    marked, marked_conn = h.row(0, policy_context=b'deny-me')
    plain, plain_conn = h.row(1)
    send(marked_conn, judge_frame(1, marked.lease.uid), memfd(b''))
    send(plain_conn, judge_frame(1, plain.lease.uid), memfd(b''))
    assert pump_until(h, marked_conn)[0] == pump_until(h, plain_conn)[0] == c.ALLOW_NOCRED
    s.shutdown(socket.SHUT_RDWR)
    worker.join(3)


def test_a_torn_tail_is_closed_before_the_first_record(tmp_path: Path) -> None:
    """K-53 前提 (工程默认): a record cut by a crash stays a line of its own; the next run's records start on fresh lines."""
    from conftest import OVERFLOWUID, FakeClock
    evidence = tmp_path / 'events.jsonl'
    evidence.write_bytes(b'{"kind":"old"}\n{"kind":"cut in the mid')
    r = records.Recorder('d' * 32, OVERFLOWUID, FakeClock(), str(evidence))
    r.record('table_changed', source_ref={'port': 'admin', 'object': 'x'}, detail={'n': 1})
    r.close()
    lines = evidence.read_bytes().split(b'\n')
    assert lines[1] == b'{"kind":"cut in the mid' and json.loads(lines[2])['kind'] == 'table_changed'


# ---- host file reads on the hook port (validation.md H-09, K-49, K-50, P-01, P-02) ---------------------------------------
def test_the_table_snapshot_lists_the_objects_without_their_anchors(native, tmp_path: Path) -> None:
    from test_file_hook import FileHarness
    h = FileHarness(tmp_path, native)
    p = port(h, tmp_path)
    h.obj('notes', h.host)
    h.obj('no', h.host / 'sub', mode='deny')
    h.obj('gone', h.host / 'sub', mode='ask')
    h.tables.tables['work0'].unavailable_objects.add('gone')
    s = pdp_client(p)
    h.pump()
    s.sendall(c.pack_frame(c.TABLE_QUERY, [b'work0']))
    [(kind, fields, _)] = read_frames(h, s)
    assert kind == c.TABLE_SNAPSHOT and len(fields) == 5
    items = sorted(c.unpack_list(x) for x in c.unpack_list(fields[4]))
    assert items == [[b'gone', str(h.host / 'sub').encode(), c.u8(2), c.u8(3), c.u8(c.FILE_MODE_ASK), c.u8(0)],
                     [b'no', str(h.host / 'sub').encode(), c.u8(2), c.u8(3), c.u8(c.FILE_MODE_DENY), c.u8(1)],
                     [b'notes', str(h.host).encode(), c.u8(2), c.u8(3), c.u8(c.FILE_MODE_ALLOW), c.u8(1)]]
    s.sendall(c.pack_frame(c.TABLE_QUERY, [b'nope']))
    [(kind, fields, _)] = read_frames(h, s)
    assert c.read_uint(fields[1], 1) == c.SNAP_UNKNOWN and c.unpack_list(fields[4]) == []
    s.close()
    h.close()


def test_the_simple_pdp_answers_a_file_request_and_its_test_variant_denies_by_context(native, tmp_path: Path) -> None:
    """P-01, P-02 and H-09: a file request comes without a memfd; the simple PDP allows it, and its test variant reads
    the policy context at the 22nd field, so a file request of the marked row is denied."""
    from pdp import simple
    from test_file_hook import FileHarness, read, recv_file
    h = FileHarness(tmp_path, native)
    p = port(h, tmp_path)
    h.obj('notes', h.host)
    s = pdp_client(p)
    worker_thread = threading.Thread(target=simple.serve, args=(s, b'deny-me'), daemon=True)
    worker_thread.start()
    h.pump()
    marked, _, marked_worker = h.file_row(0, policy_context=b'deny-me')
    plain, _, plain_worker = h.file_row(1)
    marked_worker.sendall(read(1, marked))
    plain_worker.sendall(read(1, plain))
    results = {}
    until = time.monotonic() + 5
    while len(results) < 2 and time.monotonic() < until:
        h.loop.run_once(0.05)
        for name, sock in (('marked', marked_worker), ('plain', plain_worker)):
            if name not in results and select.select([sock], [], [], 0)[0]:
                results[name] = recv_file(sock)
    assert results['marked'][0] == c.FILE_DENY and c.FILE_REASONS[c.read_uint(results['marked'][1][1], 1) - 1] == \
        'pdp_denied'
    assert results['plain'][0] == c.FILE_ALLOW and len(results['plain'][2]) == 1
    os.close(results['plain'][2][0])
    s.shutdown(socket.SHUT_RDWR)
    worker_thread.join(3)
    h.close()
