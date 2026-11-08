"""Regressions from review point B (runs/20261029T070000Z-review-B-connector): one test per finding kept.
B1 duplicate header fields (Cache-Control then, Content-Type since 2026-11-04), B2 deny set on both spellings, B5 waiter lifetime, B6 short body, B7 descriptor with a
fragment, S1 ordered submission, S2 budget release on a failed read, S3 the native frame deadline during silence,
S4 hang-up with pipelined bytes, S5 malformed response headers, S7 a ValueError carrying the truth, S8 RFC 6052."""
from __future__ import annotations

import array
import http.client
import ipaddress
import os
import socket
import threading
import time

import pytest

from conftest import open_fds
from connector import canonical as c
from connector import upstream as up
from connector.channel import Answer, Waiter
from connector.session import Budget
from connector_rig import CA, TRUTH, Received, Rig, Upstream, server_tls, simple_reply
from test_connector_upstream import allowed_exchange

REQUEST = c.pack_frame(c.REQUEST, [b'GET', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([]), b''])


# ---- B1 (every field of a repeated name counts; since the body rule of 2026-11-04 the field is Content-Type) ----
def test_token_response_counts_every_content_type_field(rig: Rig, ca: CA) -> None:
    raw = [('Content-Type', 'text/plain'), ('Cache-Control', 'private'), ('Content-Type', 'application/json')]
    post = c.Request(b'POST', b'https', b'a.test', False, 443, b'/', None, (), (), b'', 'application/json', ())
    assert up.token_candidate(post, raw) == frozenset({'application/json'})
    upstream = Upstream(server_tls(ca), reply=simple_reply(b'{"access_token":"NEW"}', extra='Content-Type: text/plain\r\nCache-Control: private\r\nContent-Type: application/json\r\n'))
    _, resp, _ = allowed_exchange(rig, upstream, nocred=True, method=b'POST', path=b'/t',
                                  headers=((b'content-type', b'application/json'),), body=b'{}')
    assert resp is not None and resp.header(b'x-engine-reason') == [b'response_withheld'] and b'NEW' not in resp.body
    upstream.close()


# ---- B2, S8 ----
def test_deny_set_holds_the_original_and_the_judged_address() -> None:
    v6 = ipaddress.ip_address('64:ff9b::808:808')
    assert not up.address_allowed('64:ff9b::808:808', frozenset({v6}), ())
    assert not up.address_allowed('::ffff:8.8.8.8', frozenset({ipaddress.ip_address('::ffff:8.8.8.8')}), ())
    assert not up.address_allowed('::ffff:8.8.8.8', frozenset({ipaddress.ip_address('8.8.8.8')}), ())
    assert up.address_allowed('64:ff9b::808:808', frozenset(), ())


def embed(prefix: ipaddress.IPv6Network, v4: int) -> str:
    """The RFC 6052 §2.2 spelling of an IPv4 address under a NAT64 prefix (the inverse of embedded_ipv4)."""
    n, base = prefix.prefixlen, int(prefix.network_address)
    if n == 96:
        bits = base | v4
    elif n == 64:
        bits = base | (v4 << 24)
    elif n == 32:
        bits = base | (v4 << 64)
    else:
        high_bits = 64 - n
        high, low = v4 >> (32 - high_bits), v4 & ((1 << (32 - high_bits)) - 1)
        bits = base | (high << 64) | (low << (128 - 72 - (32 - high_bits)))
    return str(ipaddress.IPv6Address(bits))


@pytest.mark.parametrize('prefix', ['2001:db8::/32', '2001:db8:100::/40', '2001:db8:1::/48', '2001:db8:1:200::/56',
                                    '2001:db8:1:2::/64', '2001:db8:1:2:3:4::/96'])
def test_rfc6052_prefix_lengths_embed_the_ipv4_address(prefix: str) -> None:
    net = ipaddress.ip_network(prefix)
    for text, allowed in (('8.8.8.8', True), ('10.0.0.1', False), ('192.168.7.9', False), ('1.1.1.1', True)):
        v4 = ipaddress.IPv4Address(text)
        spelled = embed(net, int(v4))
        assert up.embedded_ipv4(ipaddress.IPv6Address(spelled), net) == v4
        assert up.judged_address(ipaddress.ip_address(spelled), (net,)) == v4
        assert up.address_allowed(spelled, frozenset(), (net,)) is allowed
    policy = up.Policy(nat64=[prefix], include_interfaces=False)
    assert not policy.allowed([embed(net, int(ipaddress.IPv4Address('10.0.0.1')))])


# ---- B5 ----
def test_waiter_publication_after_close_is_refused() -> None:
    w = Waiter(7)
    assert w.publish(Answer(c.DENY, reason=2)) and w.take() is not None and os.read(w.r, 1) == b'x'
    w.close()
    assert not w.publish(Answer(c.ALLOW, truth=bytearray(b'x'), account=b'a'))      # the session left: nothing written
    w2 = Waiter(8)
    w2.close()
    assert not w2.publish(Answer(c.DENY, reason=1)) and w2.take() is None


# ---- B6 ----
def test_short_body_under_content_length_is_a_cut_not_a_completion(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca), reply=lambda r, s: (s.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc'), None)[1])
    j, resp, report = allowed_exchange(rig, upstream, nocred=True)
    assert resp is not None and resp.status == 200 and resp.body == b'abc' and resp.closed and not resp.ended
    assert report == (j.seq, c.RES_REMOTE, 200) and rig.events('response_cut')
    j2, resp2, _ = allowed_exchange(rig, upstream, nocred=True)
    assert resp2 is not None and resp2.closed and [r.connection for r in upstream.requests] == [1, 2]   # never reused
    upstream.close()


# ---- B7 ----
def test_descriptor_with_a_fragment_is_refused_before_the_frame_completes(rig: Rig) -> None:
    before = open_fds()
    cl = rig.client()
    r, w = os.pipe()
    cl.sock.sendmsg([REQUEST[:4]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [w]))])   # header only
    started = time.monotonic()
    assert cl.eof(timeout=3) and time.monotonic() - started < 2.5                   # refused on arrival, not at the deadline
    os.close(r)
    os.close(w)
    cl.close()
    time.sleep(0.2)
    assert open_fds() <= before


# ---- S1 ----
def test_concurrent_submissions_reach_the_core_in_increasing_order(rig: Rig) -> None:
    clients = [rig.client() for _ in range(8)]
    barrier = threading.Barrier(8)

    def go(cl, i):
        barrier.wait()
        cl.request(path=b'/%d' % i)

    threads = [threading.Thread(target=go, args=(cl, i)) for i, cl in enumerate(clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    seqs = []
    for _ in range(8):
        j = rig.judge()
        assert j is not None
        seqs.append(j.seq)
        rig.deny(j.seq, 2)
    assert seqs == sorted(seqs) == list(range(seqs[0], seqs[0] + 8))
    assert not rig.fatal
    for cl in clients:
        cl.close()


# ---- S2 ----
def test_budget_is_released_when_the_frame_never_completes(rig: Rig) -> None:
    rig.connector.budget = Budget(10_000)
    cl = rig.client()
    cl.raw(c.u32(1000) + c.u8(c.REQUEST))                                             # declares 1000 bytes, sends 1
    deadline = time.monotonic() + 2
    while rig.connector.budget.used == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert rig.connector.budget.used == 1000
    cl.close()
    deadline = time.monotonic() + 3
    while rig.connector.budget.used and time.monotonic() < deadline:
        time.sleep(0.02)
    assert rig.connector.budget.used == 0


# ---- S3 ----
def test_half_sent_frame_is_refused_after_the_native_deadline(rig: Rig) -> None:
    cl = rig.client()
    cl.raw(REQUEST[:7])
    started = time.monotonic()
    assert cl.eof(timeout=9)
    elapsed = time.monotonic() - started
    assert 4.5 <= elapsed <= 8, elapsed                                               # five seconds, serviced within a second


# ---- S4 ----
def test_hangup_is_seen_despite_pipelined_bytes(rig: Rig) -> None:
    cl = rig.client()
    cl.request()
    cl.raw(b'\x00')                                                                   # a pipelined byte, left unread
    j = rig.judge()
    assert j is not None
    time.sleep(0.2)
    cl.close()
    assert rig.withdraw() == j.seq
    rig.allow_nocred(j.seq)
    assert rig.report() == (j.seq, c.RES_UNSENT, 0)


# ---- S5 ----
@pytest.mark.parametrize('raw', [
    b'HTTP/1.1 200 OK\r\nX-Bad: a\x00b\r\nContent-Length: 2\r\n\r\nok',
    b'HTTP/1.1 200 OK\r\nNoColonHere\r\nContent-Length: 2\r\n\r\nok',
    b'HTTP/1.1 200 OK\r\nX Bad: v\r\nContent-Length: 2\r\n\r\nok',
])
def test_malformed_response_headers_are_not_relayed(rig: Rig, ca: CA, raw: bytes) -> None:
    upstream = Upstream(server_tls(ca), reply=lambda r, s: raw)
    j, resp, report = allowed_exchange(rig, upstream, nocred=True)
    assert resp is not None and resp.category == c.CAT_UNKNOWN and resp.ended and b'Bad' not in resp.body
    assert report == (j.seq, c.RES_UNKNOWN, 0)
    upstream.close()


# ---- S7 ----
def test_value_error_carrying_the_truth_never_leaves(rig: Rig, ca: CA, monkeypatch: pytest.MonkeyPatch) -> None:
    original = http.client.HTTPConnection.putheader

    def poisoned(self, header, *values):
        if any(TRUTH in bytes(v) for v in values if isinstance(v, (bytes, bytearray))):
            raise ValueError('Invalid header value %r' % (values[0],))              # the library's own message shape
        return original(self, header, *values)

    monkeypatch.setattr(http.client.HTTPConnection, 'putheader', poisoned)
    upstream = Upstream(server_tls(ca))
    j, resp, report = allowed_exchange(rig, upstream, headers=((b'authorization', b'Bearer PH'),))
    assert resp is not None and resp.category == c.CAT_TRANSPORT and resp.ended
    haystack = [repr(e) for e in rig.logs] + [repr(resp), repr(report), repr(j)]
    assert not any(TRUTH.decode() in h for h in haystack) and upstream.requests == []
    upstream.close()
