"""Regressions from the review-B rechecks (runs/20261029T070000Z-review-B-connector/review-codex-recheck-raw.txt):
B5 and S4 in their racing shapes, NB1 one-time approval keeps the destination's account constraints, NB2 a new or
broader prohibition revokes every connection under the key, NB3 the local-address probe on the embedded address,
NS1 cancellation versus publication, NS2 control bytes at the ends of a response header value."""
from __future__ import annotations

import errno
import ipaddress
import os
import select
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from connector import canonical as c
from connector import channel as channel_mod
from connector import upstream as up
from connector.channel import Answer, CoreChannel, Waiter
from connector_rig import CA, TRUTH, Redirect, Rig, Upstream, server_tls, simple_reply
from engine.hook import VERDICT_ALLOW_ONCE
from engine.judgment import DENY_CLAUSE, DENY_POLICY_CHANGED
from engine.workspaces import Approval, EntryState, KeyKind, make_entry
from test_connector_upstream import allowed_exchange
from test_hook import Harness, allow, deny, judge_frame, memfd, recv_frame, send


@pytest.fixture
def h(native, tmp_path: Path) -> Harness:
    return Harness(tmp_path, native)


# ---- NB1 ----
def test_allow_once_keeps_the_current_entrys_account_constraints(h: Harness) -> None:
    """NB1 under 648d60f2 3.2: a one-time allow can no longer override the cell's account constraints, because an answer
    binds the cell it was asked on; the cell gaining a second account while the question is open voids the answer."""
    h.credentials.register('api.github.com:443', 'alice', 2, b'Bearer', b'ta', b'')
    h.credentials.register('api.github.com:443', 'bob', 2, b'Bearer', b'tb', b'')
    allow(h, 'api.github.com:443', ('GET',), accounts=('alice',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, headers=((b'authorization', b'Bearer x'),)), memfd(b''))
    h.pump()
    qid = h.admin.questions[0][0]
    allow(h, 'api.github.com:443', ('GET',), accounts=('alice', 'bob'), approval=Approval.ALWAYS)
    assert h.hook.answer(qid, VERDICT_ALLOW_ONCE) == ('superseded', b'')
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_POLICY_CHANGED)
    assert h.events('request_decided')[-1]['reason_code'] == 'answer_void'


# ---- NB2 ----
def test_new_or_broader_prohibition_revokes_every_connection_under_the_key(h: Harness) -> None:
    allow(h, 'api.test:443', ('GET',), accounts=('alice',))
    ex, conn = h.row()
    # a newly inserted exact deny (old=None) revokes everything under its key
    entry = make_entry(KeyKind.EXACT, 'other.test:443', EntryState.DENY, [], [], [], Approval.NEVER)
    h.tables.put('work0', entry)
    h.hook.table_changed('work0', None, entry)
    h.pump()
    kind, f = recv_frame(conn)
    assert (kind, c.read_uint(f[0], 1), f[1], f[2], c.read_uint(f[3], 1)) == (c.REVOKE, 1, b'other.test:443', b'', 2)
    # an accountless pattern allowance turned into a deny revokes everything under the pattern key: the connector's
    # registry then cuts alice's exact-entry connection to api.test:443 as well (pattern .test:443 covers it)
    old = make_entry(KeyKind.PATTERN, 'test:443', EntryState.ALLOW, ['GET'], [], [], Approval.NEVER)
    new = make_entry(KeyKind.PATTERN, 'test:443', EntryState.DENY, [], [], [], Approval.NEVER)
    h.tables.put('work0', old)
    h.tables.put('work0', new)
    h.hook.table_changed('work0', old, new)
    h.pump()
    kind, f = recv_frame(conn)
    assert (kind, c.read_uint(f[0], 1), f[1], f[2], c.read_uint(f[3], 1)) == (c.REVOKE, 2, b'test:443', b'', 2)
    assert [e['detail']['account'] for e in h.events('entry_revoked')] == ['*', '*']


def test_registry_scope_two_cuts_every_account_under_the_key() -> None:
    registry = up.Registry()
    links = []
    for account in (b'alice', b'bob', b''):
        a, b = socket.socketpair()
        link = up.Link(b'api.test', 443, b'https', account, None, a, a)   # type: ignore[arg-type]
        registry.add(link)
        links.append((link, b))
    other_a, other_b = socket.socketpair()
    other = up.Link(b'api.example', 443, b'https', b'alice', None, other_a, other_a)   # type: ignore[arg-type]
    registry.add(other)
    assert registry.revoke(2, b'test:443', b'', everyone=True) == 3            # alice, bob and the credential-less one
    assert all(l.dead for l, _ in links) and not other.dead
    assert registry.revoke(1, b'api.example:443', b'bob') == 0 and registry.revoke(1, b'api.example:443', b'alice') == 1
    for l, b in links:
        l.sock.close()
        b.close()
    other_a.close()
    other_b.close()


def test_revoke_scope_two_cuts_credentialed_connections(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca))
    cl = rig.client()                                   # kept open: its idle alice connection must still be registered
    cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.allow(j.seq, account=b'alice')
    assert cl.response().status == 200 and rig.report()[0] == j.seq   # type: ignore[union-attr,index]
    rig.revoke(2, b'test:%d' % upstream.port, b'', everyone=True)
    deadline = time.monotonic() + 3
    while not rig.events('revoked') and time.monotonic() < deadline:
        time.sleep(0.02)
    assert rig.events('revoked')[-1] == {'event': 'revoked', 'key_kind': 2, 'scope': 2, 'connections': 1}
    cl.close()
    upstream.close()


# ---- NB3 ----
def test_local_probe_also_covers_the_embedded_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(up, 'is_local_address', lambda text: text == '8.8.8.8')   # as if 8.8.8.8 were this host's
    policy = up.Policy(include_interfaces=False)
    assert not policy.allowed(['8.8.8.8'])
    assert not policy.allowed(['64:ff9b::808:808'])                              # NAT64 spelling of the same host
    assert not policy.allowed(['::ffff:8.8.8.8'])
    assert policy.allowed(['1.1.1.1'])


# ---- plan engine-v3-private-net 点名 7.1, Codex blocking item: each address judged again at its own connect ----
@pytest.mark.parametrize('turns_local', [False, True], ids=['unchanged', 'turns-local'])
def test_each_address_is_judged_again_right_before_its_connect(tmp_path: Path, library: Path, ca: CA,
                                                               monkeypatch: pytest.MonkeyPatch, turns_local: bool) -> None:
    """条款 7 (C-19): the first address of the list refuses the connect; the second, which passed with the whole list,
    has become one of this host's own addresses since (an interface brought up). It is judged again right before its
    connect and the whole request is refused with clause: no connect to it, nothing sent, REPORT not sent. Unchanged,
    the second address is connected after the first failed."""
    first, second = '93.184.215.14', '93.184.215.15'
    upstream = Upstream()
    redirect = Redirect(monkeypatch, {second: upstream.port})          # the first has no receiver: refused at once
    monkeypatch.setattr(up, 'is_local_address',                        # this host's once the first has been tried
                        lambda text: turns_local and text == second and first in redirect.attempts)
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: [first, second]))
    try:
        j, resp, report = allowed_exchange(rig, upstream, nocred=True, scheme=b'http')
        assert resp is not None
        if turns_local:
            assert redirect.attempts == [first] and upstream.connections == 0 and not upstream.requests
            assert resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
            assert report == (j.seq, c.RES_UNSENT, 0)
        else:
            assert redirect.attempts == [first, second] and upstream.connections == 1
            assert (resp.category, resp.status, resp.body) == (c.CAT_REMOTE, 200, b'ok')
            assert report == (j.seq, c.RES_REMOTE, 200)
    finally:
        rig.close()
        upstream.close()


# ---- plan engine-v3-private-net 点名 9 (user ruling 2026-11-05): the connected peer judged again before any byte ----
@pytest.mark.parametrize('turns_local, scheme', [(True, b'http'), (True, b'https'), (False, b'http')],
                         ids=['turns-local-http', 'turns-local-https', 'unchanged'])
def test_the_connected_peer_is_judged_again_before_any_byte(tmp_path: Path, library: Path, ca: CA,
                                                            monkeypatch: pytest.MonkeyPatch, turns_local: bool,
                                                            scheme: bytes) -> None:
    """条款 7 (C-19, N-15): the kernel routes every SYN it resends anew, so the address may become this host's while
    connect() waits and the handshake end at a local service. Here connect() succeeds and right after it the address
    is this host's. The connected peer is judged again before any byte, a TLS ClientHello included: the request is
    refused with clause, the receiver reads zero bytes, REPORT not sent. The receiver speaks plain TCP for both schemes,
    so a ClientHello would be counted. Unchanged, the request is sent and answered."""
    address = '93.184.215.14'
    upstream = Upstream()
    redirect = Redirect(monkeypatch, {address: upstream.port})
    monkeypatch.setattr(up, 'is_local_address',                        # this host's once connect() has been called
                        lambda text: turns_local and text == address and address in redirect.attempts)
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: [address]))
    try:
        j, resp, report = allowed_exchange(rig, upstream, nocred=True, scheme=scheme)
        time.sleep(0.2)                                                # bytes sent have had their chance to arrive
        assert redirect.attempts == [address] and upstream.connections == 1     # the handshake (N-15's residual)
        assert resp is not None
        if turns_local:
            assert sum(upstream.received_bytes.values()) == 0 and not upstream.requests
            assert resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
            assert report == (j.seq, c.RES_UNSENT, 0)
        else:
            assert (resp.category, resp.status, resp.body) == (c.CAT_REMOTE, 200, b'ok')
            assert report == (j.seq, c.RES_REMOTE, 200)
    finally:
        rig.close()
        upstream.close()


def test_the_judgement_before_each_connect_comes_out_of_the_connect_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """C-20 (plan engine-v3-private-net 点名 9; Codex recheck): one connect deadline covers every address. Each
    judgement takes 4 s of a fake clock; each connect is given the deadline less the clock after its own judgement,
    never a remaining time computed before that judgement."""
    clock = [1000.0]
    timeouts: list[tuple[str, float]] = []

    class Slow(up.Policy):
        def refusal(self, addresses: list[str], named: up.Named = ()) -> bytes | None:
            clock[0] += 4.0
            return super().refusal(addresses, named)

    class Sock:
        def __init__(self, family: int, kind: int) -> None:
            self.timeout: float | None = None

        def settimeout(self, value: float) -> None:
            self.timeout = value

        def connect(self, address: tuple[str, int]) -> None:
            timeouts.append((address[0], self.timeout))       # type: ignore[arg-type]
            raise ConnectionRefusedError(errno.ECONNREFUSED, 'refused in the test')

        def close(self) -> None:
            pass

    tls = up.tls_context()
    policy = Slow(include_interfaces=False, resolver=lambda h, p: ['93.184.215.14', '93.184.215.15'])
    monkeypatch.setattr(up, 'is_local_address', lambda text: False)
    monkeypatch.setattr(up, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(up, 'socket', SimpleNamespace(socket=Sock, AF_INET=socket.AF_INET, AF_INET6=socket.AF_INET6,
                                                      SOCK_STREAM=socket.SOCK_STREAM))
    exchange = up.Exchange(policy, tls, up.Registry(), lambda *a, **k: None, connect_timeout=30.0)
    req = c.parse_request([b'GET', b'http', b'api.test', c.u16(80), b'/', b'', c.pack_list([]), b''])
    with pytest.raises(OSError, match='no address answered'):
        exchange._connect(req, (), b'')
    deadline = 1004.0 + 30.0                                  # set once the whole list was judged (that ends at 1004)
    assert timeouts == [('93.184.215.14', deadline - 1008.0), ('93.184.215.15', deadline - 1012.0)]


# ---- NS1, B5 ----
def test_publication_after_the_session_retired_the_waiter_is_zeroed_and_reported(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """The channel thread pops the waiter, then stalls; the session gives up (hang-up) and retires the waiter; the
    stalled publication must be refused, zeroed and reported as not sent."""
    gate = threading.Event()
    original = Waiter.publish

    def stalled(self, answer):
        gate.wait(3)
        return original(self, answer)

    monkeypatch.setattr(Waiter, 'publish', stalled)
    answers: list[Answer] = []

    class Recorded(Answer):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            answers.append(self)

    monkeypatch.setattr(channel_mod, 'Answer', Recorded)
    cl = rig.client()
    cl.request(headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.allow(j.seq, truth=TRUTH)                       # the channel thread pops the waiter and stalls in publish
    time.sleep(0.3)
    cl.close()                                          # the session sees the hang-up and retires the waiter
    time.sleep(0.3)
    gate.set()                                          # publication resumes: refused
    frames = [rig.core_frame(), rig.core_frame()]       # the session's WITHDRAW (it saw no answer) and the REPORT
    kinds = sorted(k for k, _ in frames if k is not None)   # type: ignore[misc]
    assert kinds == [c.WITHDRAW, c.REPORT]
    report = next(f for k, f in frames if k == c.REPORT)   # type: ignore[misc]
    assert (c.read_uint(report[0], 8), c.read_uint(report[1], 1)) == (j.seq, c.RES_UNSENT)
    assert len(answers) == 1 and answers[0].truth is None
    assert rig.policy.resolves == 0


# ---- S4 in its racing shape ----
def test_answer_and_hangup_together_never_send(rig: Rig) -> None:
    for _ in range(10):
        upstream = Upstream()
        cl = rig.client()
        cl.request(scheme=b'http', port=upstream.port)
        cl.raw(b'\x00')
        j = rig.judge()
        assert j is not None
        cl.close()
        rig.allow_nocred(j.seq)                          # arrives together with (or right after) the hang-up
        got = rig.core_frame()
        assert got is not None
        kind, f = got
        if kind == c.WITHDRAW:                           # the hang-up was seen first; the allow is then unsent
            assert rig.report() == (j.seq, c.RES_UNSENT, 0)
        else:
            assert kind == c.REPORT and c.read_uint(f[1], 1) == c.RES_UNSENT
        time.sleep(0.05)
        assert upstream.connections == 0 and rig.policy.resolves == 0
        upstream.close()


# ---- NS2 ----
@pytest.mark.parametrize('raw', [
    b'HTTP/1.1 200 OK\r\nX-Bad: \x0babc\x0c\r\nContent-Length: 2\r\n\r\nok',
    b'HTTP/1.1 200 OK\r\nX-Bad: abc\x0c\r\nContent-Length: 2\r\n\r\nok',
])
def test_control_bytes_at_the_ends_of_a_header_value_are_refused(rig: Rig, ca: CA, raw: bytes) -> None:
    upstream = Upstream(server_tls(ca), reply=lambda r, s: raw)
    j, resp, report = allowed_exchange(rig, upstream, nocred=True)
    assert resp is not None and resp.category == c.CAT_UNKNOWN and report == (j.seq, c.RES_UNKNOWN, 0)
    upstream.close()
    assert up.response_headers([('X-Ok', ' \tabc\t ')], False) == [(b'x-ok', b'abc')]


# ---- Opus recheck, new finding 2: multipart responses are legitimate ----
def test_multipart_response_is_relayed(rig: Rig, ca: CA) -> None:
    body = b'--b\r\nContent-Type: text/plain\r\n\r\none\r\n--b\r\nContent-Type: text/plain\r\n\r\ntwo\r\n--b--\r\n'
    upstream = Upstream(server_tls(ca), reply=simple_reply(body, extra='Content-Type: multipart/mixed; boundary=b\r\n'))
    j, resp, report = allowed_exchange(rig, upstream, nocred=True)
    assert resp is not None and resp.category == c.CAT_REMOTE and resp.body == body and resp.ended
    assert resp.header(b'content-type') == [b'multipart/mixed; boundary=b'] and report == (j.seq, c.RES_REMOTE, 200)
    ranges = Upstream(server_tls(ca), reply=simple_reply(body, '206 Partial Content', 'Content-Type: multipart/byteranges; boundary=b\r\n'))
    _, resp2, _ = allowed_exchange(rig, ranges, nocred=True)
    assert resp2 is not None and resp2.status == 206 and resp2.body == body
    upstream.close()
    ranges.close()


# ---- Codex round 3: B5 and S4 in the shapes it asked for; Opus 6; scope-2 account ----
def test_notification_and_close_are_serialised_on_the_waiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """B5: the answer is published and the wake-up byte is being written when the session closes the waiter; the close
    must wait, and the byte lands in this waiter's own pipe, never in a descriptor number that was reused."""
    w = Waiter(3)
    entered, release = threading.Event(), threading.Event()
    real_write = os.write

    def slow_write(fd, data):
        if fd == w.w:
            entered.set()
            release.wait(3)
        return real_write(fd, data)

    monkeypatch.setattr(channel_mod.os, 'write', slow_write)
    publisher = threading.Thread(target=lambda: w.publish(Answer(c.DENY, reason=2)))
    publisher.start()
    assert entered.wait(3)                                   # publication holds the waiter lock, mid-notification
    r_dup = os.dup(w.r)                                       # our own view of this waiter's pipe, outliving close()
    closer = threading.Thread(target=w.close)
    closer.start()
    time.sleep(0.2)
    assert closer.is_alive()                                  # close() waits for the lock: nothing is reused meanwhile
    r_fd = w.r
    release.set()
    publisher.join(3)
    closer.join(3)
    assert not closer.is_alive() and w.closed and w.take() is not None
    with pytest.raises(OSError):
        os.read(r_fd, 1)                                      # the waiter's own end is closed by then
    assert os.read(r_dup, 1) == b'x'                          # and the byte did land in this waiter's pipe
    os.close(r_dup)


def test_hangup_and_answer_ready_together_hangup_wins(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """S4: the session's first poll returns only once the client has hung up AND the answer is in; the hang-up must be
    acted on, the answer zeroed and reported as not sent, nothing resolved or connected."""
    import connector.session as session_mod
    gate, published = threading.Event(), threading.Event()
    real_poll = session_mod.select.poll
    first_results: list[list[tuple[int, int]]] = []

    class GatedPoll:
        def __init__(self):
            self.inner, self.first = real_poll(), True

        def register(self, *a):
            self.inner.register(*a)

        def poll(self, timeout):
            if self.first:
                self.first = False
                gate.wait(5)
                result = self.inner.poll(timeout)
                first_results.append(result)
                return result
            return self.inner.poll(timeout)

    real_publish = Waiter.publish

    def noted_publish(self, answer):
        ok = real_publish(self, answer)
        published.set()
        return ok

    monkeypatch.setattr(session_mod.select, 'poll', GatedPoll)
    monkeypatch.setattr(Waiter, 'publish', noted_publish)
    upstream = Upstream()
    cl = rig.client()
    cl.request(scheme=b'http', port=upstream.port)
    j = rig.judge()
    assert j is not None
    cl.close()                                                # both become ready before the session looks
    rig.allow_nocred(j.seq)
    assert published.wait(3)                                  # the answer is in the waiter before the first poll runs
    gate.set()
    got = rig.core_frame()
    assert first_results and len(first_results[0]) == 2       # the first poll saw both: the pipe and the hang-up
    assert any(ev & (select.POLLRDHUP | select.POLLHUP) for _, ev in first_results[0])
    assert got is not None and got[0] == c.REPORT and (c.read_uint(got[1][0], 8), c.read_uint(got[1][1], 1)) == (j.seq, c.RES_UNSENT)
    assert rig.core_frame(timeout=0.5) is None                # no WITHDRAW: the answer had arrived
    assert upstream.connections == 0 and rig.policy.resolves == 0
    upstream.close()


def test_cut_handle_survives_http_clients_own_close(rig: Rig, ca: CA, monkeypatch: pytest.MonkeyPatch) -> None:
    """Opus 6: a Connection: close response makes http.client close its socket when the last byte is read; the link is
    still registered then. Its number is given to an unrelated socket; a revoke at that instant cuts the link through
    its own dup and leaves the unrelated socket untouched."""
    seen: dict[str, object] = {}
    real_drop = up.Exchange._drop
    key = None

    def drop_after_probe(self, link):
        if link is not None and 'probed' not in seen:
            seen['probed'] = True
            seen['original_closed'] = link.sock.fileno() == -1          # http.client closed its socket already
            seen['handle_open'] = link.handle.fileno() >= 0
            a, b = socket.socketpair()                                  # the freed number is reused by a stranger
            seen['reused_number'] = a.fileno()
            seen['cut'] = rig.connector.registry.revoke(1, key, b'alice')    # a revoke right now
            seen['link_dead'] = link.dead
            a.sendall(b'still fine')                                    # the stranger is untouched
            seen['stranger'] = b.recv(16)
            a.close()
            b.close()
        return real_drop(self, link)

    monkeypatch.setattr(up.Exchange, '_drop', drop_after_probe)
    upstream = Upstream(server_tls(ca), reply=simple_reply(b'ok', extra='Connection: close\r\n'))
    key = b'api.test:%d' % upstream.port
    cl = rig.client()
    cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.allow(j.seq, account=b'alice')
    assert cl.response().body == b'ok' and rig.report()[0] == j.seq   # type: ignore[union-attr,index]
    deadline = time.monotonic() + 3
    while 'stranger' not in seen and time.monotonic() < deadline:
        time.sleep(0.02)
    assert seen == {'probed': True, 'original_closed': True, 'handle_open': True, 'reused_number': seen.get('reused_number'),
                    'cut': 1, 'link_dead': True, 'stranger': b'still fine'}
    assert len(rig.connector.registry) == 0 and not rig.fatal
    cl.close()
    upstream.close()


def test_scope_two_revoke_with_an_account_is_a_protocol_fault(rig: Rig) -> None:
    rig.send_core(c.REVOKE, [c.u8(1), b'api.test:443', b'alice', c.u8(2)])
    deadline = time.monotonic() + 3
    while not rig.fatal and time.monotonic() < deadline:
        time.sleep(0.02)
    assert rig.fatal and 'scope' in rig.fatal[0] and not rig.events('revoked')
