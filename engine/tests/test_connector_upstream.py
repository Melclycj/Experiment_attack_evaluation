"""The connector's upstream side against scripted receivers on 127.0.0.1 (validation.md C-09, C-11, C-16 to C-26, C-29,
C-33; 条款 1, 3, 4, 6, 7, 8, 10). The rig's policy resolves every name to the receiver and allows it; the real address
filter is tested on its own below (C-19). TLS receivers present the rig CA's certificate for api.test."""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from connector import canonical as c
from connector import upstream as up
from connector_rig import CA, TRUTH, Received, Redirect, Rig, StubPolicy, Upstream, server_tls, simple_reply


def allowed_exchange(rig: Rig, upstream: Upstream, *, placement: int = c.PLACE_BEARER, word: bytes | None = None,
                     truth_b: bytes = b'', account: bytes = b'alice', nocred: bool | None = None,
                     account_destination: bool = False, named: tuple[str, ...] = (), **request):
    """One request through the rig: judge, allow (with or without credential, naming ``named``), response and report."""
    cl = rig.client()
    request.setdefault('port', upstream.port)
    if not nocred and not any(n in (b'authorization', b'x-api-key') for n, _ in request.get('headers', ())):
        request['headers'] = tuple(request.get('headers', ())) + ((b'authorization', b'Bearer PH'),)   # a placeholder to replace
    cl.request(**request)
    j = rig.judge()
    assert j is not None
    if nocred:
        rig.allow_nocred(j.seq, account_destination, named=named)
    else:
        rig.allow(j.seq, placement, word, TRUTH, truth_b, account, named=named)
    resp = cl.response()
    report = rig.report()
    cl.close()
    return j, resp, report


# ---- C-16, C-17: the engine's whole header value at the registered placement, over TLS only ----
@pytest.mark.parametrize('placement, word, truth_b, header, expected', [
    (c.PLACE_API_KEY, b'', b'', (b'x-api-key', b'PH-KEY'), TRUTH),
    (c.PLACE_BEARER, b'Bearer', b'', (b'authorization', b'Bearer PH-TOK'), b'Bearer ' + TRUTH),
    (c.PLACE_BEARER, b'token', b'', (b'authorization', b'token PH-TOK'), b'token ' + TRUTH),
    # the registered word, not the request's: registered Bearer, the request said token (and the other way round)
    (c.PLACE_BEARER, b'Bearer', b'', (b'authorization', b'token PH-TOK'), b'Bearer ' + TRUTH),
    (c.PLACE_BEARER, b'token', b'', (b'authorization', b'Basic UEg6UEg='), b'token ' + TRUTH),
    # Basic is built from the registered user and password: the request's user name is not kept
    (c.PLACE_BASIC, b'', b'pass-truth', (b'authorization', b'Basic UEgtVVNFUjpzZWNyZXQ='), b'Basic ' + up.b64_into(bytearray(TRUTH + b':pass-truth'))),
    (c.PLACE_BASIC, b'', b'pass-truth', (b'authorization', b'Bearer not-basic-at-all'), b'Basic ' + up.b64_into(bytearray(TRUTH + b':pass-truth'))),
])
def test_placement_replaces_the_whole_value_at_one_position(rig: Rig, ca: CA, placement, word, truth_b, header, expected) -> None:
    upstream = Upstream(server_tls(ca))
    j, resp, report = allowed_exchange(rig, upstream, placement=placement, word=word, truth_b=truth_b,
                                       headers=(header, (b'x-other', b'kept')))
    assert resp is not None and (resp.category, resp.status, resp.body, resp.ended) == (c.CAT_REMOTE, 200, b'ok', True)
    assert report == (j.seq, c.RES_REMOTE, 200)
    [got] = upstream.requests
    assert got.header(header[0].decode()) == [bytes(expected).decode('latin-1')]
    assert got.header('x-other') == ['kept'] and got.sni == 'api.test'
    assert [n.lower() for n, _ in got.headers].count('authorization') <= 1
    upstream.close()


def test_without_credential_the_placeholder_travels_as_it_is_and_plaintext_never_carries_truth(rig: Rig) -> None:
    upstream = Upstream()                                                   # plain http receiver
    j, resp, report = allowed_exchange(rig, upstream, nocred=True, scheme=b'http',
                                       headers=((b'authorization', b'Bearer PH-TOK'),))
    assert resp is not None and resp.status == 200 and report == (j.seq, c.RES_REMOTE, 200)
    assert upstream.requests[0].header('authorization') == ['Bearer PH-TOK']   # 条款 4 / C-17: no replacement over http
    j, resp, report = allowed_exchange(rig, upstream, scheme=b'http', headers=((b'authorization', b'Bearer PH-TOK'),))
    assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
    assert report == (j.seq, c.RES_UNSENT, 0) and len(upstream.requests) == 1      # nothing was sent
    upstream.close()


def test_with_both_headers_only_the_registered_one_is_replaced(rig: Rig, ca: CA) -> None:
    """648d60f2 4.3: two placements carrying values, the registered one is replaced and the other goes as it is."""
    upstream = Upstream(server_tls(ca))
    for placement, kept in ((c.PLACE_API_KEY, ('authorization', 'Bearer agents-own')), (c.PLACE_BEARER, ('x-api-key', 'PH-KEY'))):
        allowed_exchange(rig, upstream, placement=placement,
                         headers=((b'x-api-key', b'PH-KEY'), (b'authorization', b'Bearer agents-own')))
        got = upstream.requests[-1]
        assert got.header(kept[0]) == [kept[1]]
        replaced = 'x-api-key' if placement == c.PLACE_API_KEY else 'authorization'
        assert got.header(replaced) == [(TRUTH if placement == c.PLACE_API_KEY else b'Bearer ' + TRUTH).decode('latin-1')]
    upstream.close()


def test_named_placement_absent_from_the_request_is_refused_not_added(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca))
    j, resp, report = allowed_exchange(rig, upstream, placement=c.PLACE_API_KEY, headers=((b'x-other', b'v'),))
    assert resp is not None and resp.header(b'x-engine-reason') == [b'credential']
    assert report == (j.seq, c.RES_UNSENT, 0) and upstream.requests == []
    upstream.close()


# ---- C-09, C-11: what the receiver gets is generated here ----
def test_host_sni_content_length_are_the_connectors_own(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca))
    j, resp, _ = allowed_exchange(rig, upstream, nocred=True, method=b'POST', path=b'/p', query=b'a=1&b=%20',
                                  headers=((b'content-type', b'text/plain'), (b'x-http-method-override', b'DELETE')), body=b'hello')
    [got] = upstream.requests
    assert (got.method, got.target, got.version) == ('POST', '/p?a=1&b=%20', 'HTTP/1.1')
    assert got.header('host') == [f'api.test:{upstream.port}'] and got.sni == 'api.test'
    assert got.header('content-length') == ['5'] and got.body == b'hello'
    names = [n.lower() for n, _ in got.headers]
    assert 'transfer-encoding' not in names and 'x-http-method-override' not in names
    assert got.header('accept-encoding') == ['identity']                 # a POST's response comes back readable (C-25)
    assert names.count('host') == 1
    j, _, _ = allowed_exchange(rig, upstream, nocred=True, method=b'GET', path=b'/g')
    assert upstream.requests[1].header('content-length') == []           # no body, no Content-Length on GET
    assert upstream.requests[1].header('accept-encoding') == []          # nothing added to other methods
    j, _, _ = allowed_exchange(rig, upstream, nocred=True, method=b'POST', path=b'/empty')
    assert upstream.requests[2].header('content-length') == ['0']
    upstream.close()


def test_host_header_omits_the_default_port_and_brackets_ipv6() -> None:
    def req(host: bytes, is_ip: bool, port: int, scheme: bytes = b'https') -> c.Request:
        return c.Request(b'GET', scheme, host, is_ip, port, b'/', None, (), (), b'', '', ())
    assert up.host_header(req(b'api.test', False, 443)) == b'api.test'
    assert up.host_header(req(b'api.test', False, 80, b'http')) == b'api.test'
    assert up.host_header(req(b'api.test', False, 8443)) == b'api.test:8443'
    assert up.host_header(req(b'2001:db8::1', True, 443)) == b'[2001:db8::1]'
    assert up.host_header(req(b'2001:db8::1', True, 8080)) == b'[2001:db8::1]:8080'
    assert up.host_header(req(b'1.2.3.4', True, 80, b'http')) == b'1.2.3.4'


# ---- C-20: certificate, hostname and version failures are transport errors; nothing is sent ----
@pytest.mark.parametrize('case', ['selfsigned', 'wrong_host', 'tls11'])
def test_tls_failures_send_nothing_and_map_to_transport_error(rig: Rig, ca: CA, case: str) -> None:
    if case == 'selfsigned':
        upstream, host = Upstream(server_tls(ca, ca.selfsigned_cert, ca.selfsigned_key)), b'api.test'
    elif case == 'wrong_host':
        upstream, host = Upstream(server_tls(ca)), b'other.test'
    else:
        upstream, host = Upstream(server_tls(ca), tls11_only=True), b'api.test'
    j, resp, report = allowed_exchange(rig, upstream, host=host, headers=((b'authorization', b'Bearer PH'),))
    assert resp is not None and resp.category == c.CAT_TRANSPORT and resp.header(b'x-engine-reason') == [b'transport_error']
    assert resp.body.startswith(b'engine refused GET https://' + host + b':%d/\nreason: transport_error\n' % upstream.port) and resp.ended
    assert report == (j.seq, c.RES_TRANSPORT, 0)
    deadline = time.monotonic() + 3                 # the receiver's thread records its side of the failed handshake after ours
    while upstream.tls_failures == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert upstream.requests == [] and upstream.tls_failures == 1
    assert rig.events('upstream_failure')[-1]['phase'] == 'connect'
    upstream.close()


def test_connect_timeout_and_idle_read_timeout(tmp_path: Path, library: Path, ca: CA) -> None:
    rig = Rig(tmp_path, library, ca, policy=StubPolicy(address='10.255.255.1'), connect_timeout=0.3, read_timeout=0.5)
    try:
        cl = rig.client()
        cl.request(scheme=b'http', port=9)
        j = rig.judge()
        assert j is not None
        rig.allow_nocred(j.seq)
        started = time.monotonic()
        resp = cl.response()
        assert resp is not None and resp.category == c.CAT_TRANSPORT and time.monotonic() - started < 3
        assert rig.report() == (j.seq, c.RES_TRANSPORT, 0)
        cl.close()
        rig.policy.address = '127.0.0.1'
        silent = Upstream(reply=lambda r, s: (time.sleep(3), None)[1])          # reads the request, never answers
        cl = rig.client()
        cl.request(scheme=b'http', port=silent.port)
        j = rig.judge()
        assert j is not None
        rig.allow_nocred(j.seq)
        resp = cl.response()
        assert resp is not None and resp.category == c.CAT_UNKNOWN and resp.header(b'x-engine-reason') == [b'result_unknown']
        assert rig.report() == (j.seq, c.RES_UNKNOWN, 0)
        assert rig.events('upstream_failure')[-1]['phase'] == 'sending'
        silent.close()
        cl.close()
    finally:
        rig.close()


# ---- C-18: 3xx is returned, never followed ----
def test_redirects_are_relayed_not_followed(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(b'', '301 Moved Permanently', 'Location: https://elsewhere.test/x\r\n'))
    j, resp, report = allowed_exchange(rig, upstream, nocred=True)
    assert resp is not None and (resp.category, resp.status) == (c.CAT_REMOTE, 301)
    assert resp.header(b'location') == [b'https://elsewhere.test/x'] and resp.ended
    assert report == (j.seq, c.RES_REMOTE, 301) and len(upstream.requests) == 1
    upstream.close()


# ---- C-21: connections per (host, port, account), reused only after a complete response ----
def test_connections_are_kept_per_account_and_not_shared(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca))
    cl = rig.client()
    seqs = []
    for account, nocred in ((b'alice', False), (b'alice', False), (b'bob', False), (b'', True), (b'', True)):
        cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
        j = rig.judge()
        assert j is not None
        if nocred:
            rig.allow_nocred(j.seq)
        else:
            rig.allow(j.seq, account=account)
        assert cl.response().status == 200   # type: ignore[union-attr]
        seqs.append(rig.report()[0])         # type: ignore[index]
    assert [r.connection for r in upstream.requests] == [1, 1, 2, 3, 3]   # alice reused, bob new, no-account new and reused
    cl.close()
    upstream.close()


def test_connection_with_an_unfinished_response_is_not_reused(rig: Rig, ca: CA) -> None:
    def slow(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
        for _ in range(10):
            try:
                sock.sendall(b'5\r\nhello\r\n')
            except OSError:
                return None
            time.sleep(0.15)
        sock.sendall(b'0\r\n\r\n')
        return None

    upstream = Upstream(server_tls(ca), reply=slow)
    cl = rig.client()
    cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.allow(j.seq)
    head = cl.head()
    assert head is not None and head.status == 200
    cl.close()                                                              # leaves mid-body
    assert rig.report() == (j.seq, c.RES_REMOTE, 200)
    j2, resp, _ = allowed_exchange(rig, upstream)
    assert resp is not None and resp.ended and resp.body == b'hello' * 10
    assert [r.connection for r in upstream.requests] == [1, 2]
    upstream.close()


# ---- C-24: each fd gets its own response ----
def test_two_connections_get_their_own_responses(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca), reply=lambda r, s: simple_reply(r.target.encode())(r, s))
    a, b = rig.client(), rig.client()
    a.request(port=upstream.port, path=b'/a', headers=((b'authorization', b'Bearer PH'),))
    b.request(port=upstream.port, path=b'/b', headers=((b'authorization', b'Bearer PH'),))
    first, second = rig.judge(), rig.judge()
    assert first is not None and second is not None
    rig.allow(second.seq)
    rig.allow(first.seq)
    ra, rb = a.response(), b.response()
    assert ra is not None and rb is not None and ra.body == b'/a' and rb.body == b'/b'
    assert {rig.report()[0], rig.report()[0]} == {first.seq, second.seq}   # type: ignore[index]
    a.close()
    b.close()
    upstream.close()


# ---- C-25: Set-Cookie at account destinations, token responses withheld ----
def test_set_cookie_is_dropped_for_account_destinations_only(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(b'ok', extra='Set-Cookie: s=1\r\nX-Keep: 1\r\n'))
    _, placed, _ = allowed_exchange(rig, upstream, headers=((b'authorization', b'Bearer PH'),))
    _, flagged, _ = allowed_exchange(rig, upstream, nocred=True, account_destination=True)
    _, public, _ = allowed_exchange(rig, upstream, nocred=True, account_destination=False)
    assert placed is not None and placed.header(b'set-cookie') == [] and placed.header(b'x-keep') == [b'1']
    assert flagged is not None and flagged.header(b'set-cookie') == []
    assert public is not None and public.header(b'set-cookie') == [b's=1']
    upstream.close()


def test_standard_token_response_does_not_enter_the_cell(rig: Rig, ca: CA) -> None:
    token = json.dumps({'access_token': 'NEW-TOKEN-xyz', 'token_type': 'bearer'}).encode()
    upstream = Upstream(server_tls(ca), reply=simple_reply(token, extra='Content-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nPragma: no-cache\r\n'))
    form = ((b'content-type', b'application/x-www-form-urlencoded'),)
    j, resp, report = allowed_exchange(rig, upstream, nocred=True, method=b'POST', path=b'/login', headers=form, body=b'user=a&pw=b')
    assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'response_withheld']
    assert b'NEW-TOKEN' not in resp.body and resp.ended and report == (j.seq, c.RES_REMOTE, 200)
    assert rig.events('token_response_withheld') == [{'event': 'token_response_withheld', 'status': 200, 'why': 'body'}]
    j, resp, report = allowed_exchange(rig, upstream, nocred=True, method=b'GET', path=b'/me')
    assert resp is not None and resp.category == c.CAT_REMOTE and resp.body == token     # not a POST: relayed
    upstream.close()


# ---- C-26: a REVOKE cuts the connections of that key and account, in use or idle ----
def test_revoke_cuts_a_streaming_response_and_leaves_others(rig: Rig, ca: CA) -> None:
    def stream(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
        for _ in range(12):
            try:
                sock.sendall(b'5\r\nhello\r\n')
            except OSError:
                return None
            time.sleep(0.15)
        try:
            sock.sendall(b'0\r\n\r\n')
        except OSError:
            pass
        return None

    upstream = Upstream(server_tls(ca), reply=stream)
    key = b'api.test:%d' % upstream.port
    cl = rig.client()
    cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.allow(j.seq, account=b'alice')
    head = cl.head()
    assert head is not None and head.status == 200
    assert cl.frame()[0] == c.RESP_CHUNK     # type: ignore[index]
    rig.revoke(1, key, b'bob')                                               # another account: not cut
    rig.revoke(2, b'test:%d' % upstream.port, b'alice')                      # pattern .test: cut
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        got = cl.frame(timeout=1.0)
        if got is None or got[0] == c.RESP_END:
            break
    assert got is None                                                       # closed before RESP_END: a cut response
    assert rig.report() == (j.seq, c.RES_REMOTE, 200)
    assert [e for e in rig.events('revoked')] == [{'event': 'revoked', 'key_kind': 1, 'scope': 1, 'connections': 0},
                                                  {'event': 'revoked', 'key_kind': 2, 'scope': 1, 'connections': 1}]
    cl.close()
    _, resp, _ = allowed_exchange(rig, upstream)                              # the row goes on with a new connection
    assert resp is not None and resp.ended and resp.body == b'hello' * 12
    assert len(upstream.requests) == 2
    upstream.close()


def test_key_covers_the_three_key_kinds() -> None:
    assert up.key_covers(1, b'api.test:443', b'api.test', 443) and not up.key_covers(1, b'api.test:443', b'api.test', 8443)
    assert up.key_covers(2, b'test:443', b'api.test', 443) and not up.key_covers(2, b'test:443', b'test', 443)
    assert not up.key_covers(2, b'test:443', b'xtest', 443) and not up.key_covers(2, b'test:x', b'api.test', 443)
    assert up.key_covers(3, b'', b'anything', 1) and not up.key_covers(4, b'', b'a', 1)


# ---- C-22, C-33: one send, no retry; malformed responses are a category, never their bytes ----
def test_upstream_closing_without_a_response_is_result_unknown_and_not_retried(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca), reply=lambda r, s: None)
    j, resp, report = allowed_exchange(rig, upstream, headers=((b'authorization', b'Bearer PH'),))
    assert resp is not None and resp.category == c.CAT_UNKNOWN and resp.body.startswith(b'engine refused GET https://api.test:%d/\nreason: result_unknown\n' % upstream.port)
    assert report == (j.seq, c.RES_UNKNOWN, 0) and len(upstream.requests) == 1
    upstream.close()


@pytest.mark.parametrize('name, raw', [
    ('status_line', b'HTTX/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'),
    ('header_too_long', b'HTTP/1.1 200 OK\r\nX-Long: ' + b'a' * 70000 + b'\r\nContent-Length: 0\r\n\r\n'),
    ('too_many_headers', b'HTTP/1.1 200 OK\r\n' + b''.join(b'X-%d: v\r\n' % i for i in range(120)) + b'Content-Length: 0\r\n\r\n'),
    ('bad_chunked', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n'),
])
def test_malformed_responses_map_to_a_category_without_their_bytes(rig: Rig, ca: CA, name: str, raw: bytes) -> None:
    upstream = Upstream(server_tls(ca), reply=lambda r, s: raw)
    j, resp, report = allowed_exchange(rig, upstream)
    assert resp is not None
    if name == 'bad_chunked':                                                # the head was fine: the body is cut
        assert resp.category == c.CAT_REMOTE and resp.status == 200 and resp.closed and not resp.ended
    else:
        assert resp.category == c.CAT_UNKNOWN and resp.ended
        assert resp.body.startswith(b'engine refused GET https://api.test:%d/\nreason: result_unknown\n' % upstream.port)
    assert report == (j.seq, c.RES_REMOTE if name == 'bad_chunked' else c.RES_UNKNOWN, 200 if name == 'bad_chunked' else 0)
    assert b'HTTX' not in resp.body and b'aaaa' not in resp.body and all('HTTX' not in json.dumps(e) for e in rig.logs)
    upstream.close()


# ---- C-23, C-29: the sentinel truth is seen once by the receiver and nowhere else ----
def test_sentinel_truth_appears_only_at_the_receiver(rig: Rig, ca: CA) -> None:
    good = Upstream(server_tls(ca))
    bad = Upstream(server_tls(ca), reply=lambda r, s: None)
    frames: list[bytes] = []
    j1, r1, rep1 = allowed_exchange(rig, good, headers=((b'authorization', b'Bearer PH'),))
    j2, r2, rep2 = allowed_exchange(rig, bad, headers=((b'authorization', b'Bearer PH'),))
    assert r1 is not None and r2 is not None and r1.status == 200 and r2.category == c.CAT_UNKNOWN
    assert good.requests[0].header('authorization') == ['Bearer ' + TRUTH.decode()]      # positive control: once
    haystack = [json.dumps(e) for e in rig.logs] + [repr(r1), repr(r2), repr(rep1), repr(rep2), repr(j1), repr(j2)]
    assert not any(TRUTH.decode() in h for h in haystack)
    good.close()
    bad.close()


# ---- C-19: the address filter ----
@pytest.mark.parametrize('address, ok', [
    ('8.8.8.8', True), ('2606:4700::1111', True), ('192.0.0.9', True),             # globally reachable
    ('10.0.0.1', False), ('172.16.5.5', False), ('192.168.1.1', False), ('127.0.0.1', False), ('0.0.0.0', False),
    ('169.254.169.254', False), ('100.64.0.1', False), ('198.18.0.1', False), ('192.0.0.8', False), ('240.0.0.1', False),
    ('255.255.255.255', False), ('224.0.0.1', False), ('::1', False), ('fe80::1', False), ('fc00::1', False), ('fd12::1', False),
    ('::ffff:10.0.0.1', False), ('::ffff:8.8.8.8', True),                           # IPv4-mapped: the embedded address
    ('64:ff9b::a00:1', False), ('64:ff9b::808:808', True),                         # NAT64 well-known prefix
    ('2001:db8::1', False), ('100::1', False), ('2002:a00:1::', False),             # documentation, discard, 6to4 of private
])
def test_address_filter_follows_iana_and_embedded_ipv4(address: str, ok: bool) -> None:
    assert up.address_allowed(address, frozenset(), ()) is ok


def test_configured_nat64_prefix_denied_addresses_and_interfaces() -> None:
    nat64 = (ipaddress.ip_network('2001:db8:64::/96'),)
    assert not up.address_allowed('2001:db8:64::a00:1', frozenset(), nat64)      # embeds 10.0.0.1
    assert up.address_allowed('2001:db8:64::808:808', frozenset(), nat64)        # embeds 8.8.8.8 (the prefix itself is documentation space)
    assert not up.address_allowed('8.8.8.8', frozenset({ipaddress.ip_address('8.8.8.8')}), ())
    assert not up.address_allowed('not-an-address', frozenset(), ())
    policy = up.Policy(denied=['203.0.113.7'], nat64=['64:ff9b:1::/96'], include_interfaces=False)
    assert policy.allowed(['8.8.8.8', '1.1.1.1'])
    assert not policy.allowed(['8.8.8.8', '10.0.0.1'])                             # reading one: the whole list must pass
    assert not policy.allowed(['203.0.113.7']) and not policy.allowed([])
    assert not policy.allowed(['64:ff9b:1::c0a8:1'])                              # configured prefix embeds 192.168.0.1
    with pytest.raises(ValueError):
        up.Policy(nat64=['64:ff9b::/65'], include_interfaces=False)                # not an RFC 6052 prefix length
    with pytest.raises(ValueError):
        up.Policy(nat64=['10.0.0.0/8'], include_interfaces=False)
    local = up.interface_addresses()
    assert ipaddress.ip_address('127.0.0.1') in local
    assert up.Policy(include_interfaces=True).denied >= frozenset(local)


def test_address_refused_before_connecting(tmp_path: Path, library: Path, ca: CA) -> None:
    rig = Rig(tmp_path, library, ca, policy=StubPolicy(allow=False))
    try:
        upstream = Upstream()
        j, resp, report = allowed_exchange(rig, upstream, nocred=True, scheme=b'http')
        assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
        assert report == (j.seq, c.RES_UNSENT, 0) and upstream.connections == 0 and rig.policy.resolves == 1
        upstream.close()
    finally:
        rig.close()


# ---- C-19, C-36, C-37: named non-global addresses (plan engine-v3-private-net; 设计 5.3 条款 7) ----
# The real Policy judges and a stub resolver answers; Redirect carries the connector's TCP connects to a receiver on
# 127.0.0.1 and records the address asked for, so a connect that must not happen would succeed and show.
DEPLOYED = dict(denied=['100.100.100.200'], nat64=['2001:db8:64::/96'])   # --deny-address, --nat64-prefix
# every never-connect kind with a named list that covers it (a core error: named or not, never connected)
NEVER = [('169.254.169.254', ('169.254.0.0/16',)), ('fe80::1', ('fe80::/10',)), ('127.0.0.2', ('127.0.0.0/8',)),
         ('0.0.0.0', ('0.0.0.0/8',)), ('::', ('::/128',)), ('::7f00:1', ('::/96',)), ('::1', ('::1/128',)),
         ('100.100.100.200', ('100.100.100.200/32',)),                     # on the deployer's --deny-address list
         ('interface', ()),                                                # a host interface address, named in never()
         ('::ffff:127.0.0.1', ('127.0.0.0/8', '::ffff:0:0/96')), ('64:ff9b::a9fe:a9fe', ('169.254.0.0/16', '64:ff9b::/96')),
         ('2001:db8:64::a9fe:a9fe', ('169.254.0.0/16', '2001:db8:64::/96')),   # under the configured NAT64 prefix
         ('224.0.0.1', ('224.0.0.0/4',)), ('255.255.255.255', ('255.255.255.255/32',)), ('ff02::1', ('ff00::/8',))]


def nets(*texts: str) -> tuple:
    return tuple(ipaddress.ip_network(t) for t in texts)


def never(address: str, named: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    """A NEVER case; 'interface' is a non-loopback, non-link-local address of this host (条款 7), named by itself."""
    if address != 'interface':
        return address, named
    found = sorted((a for a in up.interface_addresses() if not a.is_loopback and not a.is_link_local),
                   key=lambda a: (a.version, int(a)))
    if not found:
        pytest.skip('no non-loopback interface address on this host')
    return str(found[0]), (str(ipaddress.ip_network(found[0])),)


@pytest.mark.parametrize('address, named', [
    ('10.0.0.1', '10.0.0.0/8'), ('fd12::1', 'fd12::/16'), ('100.64.0.1', '100.64.0.1/32'), ('192.168.1.1', '192.168.1.0/24'),
    ('::ffff:10.0.0.5', '10.0.0.5/32'), ('64:ff9b::a00:5', '10.0.0.5/32'), ('2001:db8:64::a00:5', '10.0.0.5/32'),
])
def test_a_named_non_global_address_passes_and_an_unnamed_one_is_not_authorized(address: str, named: str) -> None:
    """C-19 second gate: a non-global address passes only inside the ALLOW frame's named list, a mapped or NAT64 address
    by the IPv4 address it embeds; outside it the word is not_authorized. A global address needs no name."""
    policy = up.Policy(**DEPLOYED)
    assert policy.refusal([address], nets(named)) is None and policy.allowed([address], nets(named))
    assert policy.refusal([address], ()) == b'not_authorized' and not policy.allowed([address], ())
    assert policy.refusal([address], nets('10.99.0.0/16', 'fd99::/16')) == b'not_authorized'
    assert policy.refusal(['8.8.8.8', '2606:4700::1111'], ()) is None


@pytest.mark.parametrize('address, named', NEVER, ids=[a for a, _ in NEVER])
def test_a_never_connect_address_is_a_clause_refusal_even_when_named(address: str, named: tuple[str, ...]) -> None:
    """C-19 first gate: link-local, the deployer's list, loopback, unspecified, ::/96, host interface addresses,
    multicast and limited broadcast, in every spelling, are refused with clause however the named list covers them; the
    first gate alone (never_connect) is what validation asks of an IP literal (C-35)."""
    address, named = never(address, named)
    policy = up.Policy(**DEPLOYED)
    assert policy.refusal([address], nets(*named)) == b'clause' and not policy.allowed([address], nets(*named))
    assert policy.refusal([address], ()) == b'clause'
    assert policy.never_connect(address)


@pytest.mark.parametrize('address', ['10.0.0.1', 'fd12::1', '100.64.0.1', '192.168.1.1', '198.18.0.1', '8.8.8.8',
                                     '2606:4700::1111', '2001:db8:64::a00:1'])
def test_the_first_gate_alone_passes_every_other_address(address: str) -> None:
    assert not up.Policy(**DEPLOYED).never_connect(address)


def test_one_address_that_fails_refuses_the_whole_list() -> None:
    """Reading one (C-19): an unnamed non-global address anywhere in the list makes the request not_authorized, a
    never-connect one makes it clause, both kinds make it clause; the IP judged is the one resolved, not the name."""
    policy, five = up.Policy(**DEPLOYED), nets('10.0.0.5/32')
    assert policy.refusal(['10.0.0.5', '8.8.8.8'], five) is None
    for addresses in (['10.0.0.6'], ['10.0.0.5', '10.0.0.6'], ['10.0.0.6', '10.0.0.5'], ['8.8.8.8', '10.0.0.6']):
        assert policy.refusal(addresses, five) == b'not_authorized', addresses
    assert policy.refusal(['10.0.0.5', '169.254.169.254'], nets('10.0.0.5/32', '169.254.0.0/16')) == b'clause'
    assert policy.refusal(['10.0.0.6', '169.254.169.254'], five) == b'clause'
    assert policy.refusal(['169.254.169.254', '10.0.0.6'], five) == b'clause'
    assert policy.refusal([], five) is not None and not policy.allowed([], five)
    # the named list is held against the embedded IPv4 address: naming the IPv6 spelling names nothing
    assert policy.refusal(['64:ff9b::a00:5'], nets('64:ff9b::a00:5/128')) == b'not_authorized'
    assert policy.refusal(['64:ff9b::a00:6'], five) == b'not_authorized'


@pytest.mark.parametrize('host, resolution, named, nocred, scheme, deployed', [
    pytest.param(b'10.0.0.1', [], ('10.0.0.0/8',), True, b'http', {}, id='literal-10.0.0.1'),
    pytest.param(b'fd12::1', [], ('fd12::/16',), True, b'http', {}, id='literal-fd12::1'),
    pytest.param(b'100.64.0.1', [], ('100.64.0.1/32',), True, b'http', {}, id='literal-100.64.0.1'),
    pytest.param(b'api.test', ['10.0.0.5'], ('10.0.0.5/32',), False, b'https', {}, id='name-allow'),
    pytest.param(b'api.test', ['fd12::5'], ('fd12::/64',), True, b'https', {}, id='name-v6'),
    pytest.param(b'api.test', ['10.0.0.5', '10.0.0.6'], ('10.0.0.5/32', '10.0.0.6/32'), True, b'http', {}, id='name-two-named'),
    pytest.param(b'api.test', ['8.8.8.8', '10.0.0.5'], ('10.0.0.5/32',), True, b'http', {}, id='name-global-and-named'),
    pytest.param(b'api.test', ['::ffff:10.0.0.5'], ('10.0.0.5/32',), True, b'http', {}, id='name-mapped'),
    pytest.param(b'api.test', ['64:ff9b::a00:5'], ('10.0.0.5/32',), True, b'http', {}, id='name-nat64'),
    pytest.param(b'api.test', ['2001:db8:64::a00:5'], ('10.0.0.5/32',), True, b'http', DEPLOYED, id='name-nat64-configured'),
])
def test_a_named_private_destination_is_connected(tmp_path: Path, library: Path, ca: CA, monkeypatch: pytest.MonkeyPatch,
                                                  host, resolution, named, nocred, scheme, deployed) -> None:
    """C-19, C-35: a non-global destination the covering cell names, as an IP literal (which reaches the core) or as a
    name the resolver answers, is connected at the first address of the list, through the real Policy."""
    upstream = Upstream(server_tls(ca) if scheme == b'https' else None)
    redirect = Redirect(monkeypatch, {a: upstream.port for a in [*resolution, host.decode()]})
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: list(resolution), **deployed))
    try:
        j, resp, report = allowed_exchange(rig, upstream, nocred=nocred, named=named, scheme=scheme, host=host)
        assert resp is not None and (resp.category, resp.status, resp.body, resp.ended) == (c.CAT_REMOTE, 200, b'ok', True)
        assert report == (j.seq, c.RES_REMOTE, 200)
        assert redirect.attempts == [(resolution or [host.decode()])[0]] and upstream.connections == 1
        if not nocred:
            assert upstream.requests[0].header('authorization') == ['Bearer ' + TRUTH.decode()]
    finally:
        rig.close()
        upstream.close()


@pytest.mark.parametrize('nocred', [True, False], ids=['allow_nocred', 'allow'])
@pytest.mark.parametrize('address, named', NEVER, ids=[a for a, _ in NEVER])
def test_a_never_connect_address_is_not_connected_however_the_allow_names_it(
        tmp_path: Path, library: Path, ca: CA, monkeypatch: pytest.MonkeyPatch, address, named, nocred) -> None:
    """C-19 after the allow (N-15's residual): a name that resolves to a never-connect address, under an ALLOW whose named
    list covers it (a core error), is refused with clause and nothing is connected."""
    address, named = never(address, named)
    upstream = Upstream(server_tls(ca))
    redirect = Redirect(monkeypatch, {address: upstream.port})
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: [address], **DEPLOYED))
    try:
        j, resp, report = allowed_exchange(rig, upstream, nocred=nocred, named=named)
        assert redirect.attempts == [] and upstream.connections == 0
        assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
        assert report == (j.seq, c.RES_UNSENT, 0)
    finally:
        rig.close()
        upstream.close()


@pytest.mark.parametrize('resolution, named, word', [
    (['10.0.0.6'], ('10.0.0.5/32',), b'not_authorized'),                 # the IP at connect time is not the named one
    (['10.0.0.5'], (), b'not_authorized'),                               # nothing named
    (['10.0.0.5', '10.0.0.6'], ('10.0.0.5/32',), b'not_authorized'),     # one named, one not: the whole request
    (['8.8.8.8', '10.0.0.6'], (), b'not_authorized'),
    (['64:ff9b::a00:6'], ('10.0.0.5/32',), b'not_authorized'),           # NAT64: the embedded 10.0.0.6 is not named
    (['10.0.0.6', '169.254.169.254'], ('10.0.0.5/32',), b'clause'),      # both kinds in one list
    (['10.0.0.5', '169.254.169.254'], ('10.0.0.5/32', '169.254.0.0/16'), b'clause'),
])
def test_a_name_that_resolves_outside_the_named_list_connects_nowhere(
        tmp_path: Path, library: Path, ca: CA, monkeypatch: pytest.MonkeyPatch, resolution, named, word) -> None:
    """C-19, C-36: the whole resolution list is judged before any connect; the refusal carries the template and the
    word's next step, and neither the resolved addresses nor the named list."""
    upstream = Upstream()
    redirect = Redirect(monkeypatch, {a: upstream.port for a in resolution})
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: list(resolution), **DEPLOYED))
    try:
        j, resp, report = allowed_exchange(rig, upstream, nocred=True, named=named, scheme=b'http')
        assert redirect.attempts == [] and upstream.connections == 0
        assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [word]
        assert resp.body.startswith(b'engine refused GET http://api.test:%d/\nreason: %s\n' % (upstream.port, word))
        assert up.NEXT_STEP[word] in resp.body and not any(t.encode() in resp.body for t in [*resolution, *named])
        assert report == (j.seq, c.RES_UNSENT, 0)
    finally:
        rig.close()
        upstream.close()


@pytest.mark.parametrize('nocred', [True, False], ids=['allow_nocred', 'allow'])
def test_a_retained_connection_is_judged_again_before_it_is_reused(tmp_path: Path, library: Path, ca: CA,
                                                                   monkeypatch: pytest.MonkeyPatch, nocred: bool) -> None:
    """C-37: before a kept connection is reused, the peer it connected to is judged against this request's named list.
    Named: reused. Not named: dropped without a byte on it, and the request takes the new-connection path (resolve
    again, judge the list): connected afresh to a named new address, not_authorized when nothing is named."""
    upstream = Upstream(None if nocred else server_tls(ca))
    resolution = ['10.0.0.5']
    redirect = Redirect(monkeypatch, {'10.0.0.5': upstream.port, '10.0.0.7': upstream.port})
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: list(resolution)))
    cl = rig.client()

    def one(named: tuple[str, ...]):
        cl.request(scheme=b'http' if nocred else b'https', port=upstream.port,
                   headers=() if nocred else ((b'authorization', b'Bearer PH'),))
        j = rig.judge()
        assert j is not None
        if nocred:
            rig.allow_nocred(j.seq, named=named)
        else:
            rig.allow(j.seq, named=named)
        resp, report = cl.response(), rig.report()
        assert resp is not None and resp.ended
        return resp, report, j

    try:
        assert one(('10.0.0.5/32',))[0].status == 200 and upstream.connections == 1
        assert one(('10.0.0.0/8',))[0].status == 200                       # the peer 10.0.0.5 is named: reused
        assert upstream.connections == 1 and [r.connection for r in upstream.requests] == [1, 1]
        sent = upstream.received_bytes[1]
        resolution[:] = ['10.0.0.7']                                       # the name now resolves elsewhere
        assert one(('10.0.0.7/32',))[0].status == 200                      # 10.0.0.5 not named: a new connection
        assert upstream.connections == 2 and [r.connection for r in upstream.requests] == [1, 1, 2]
        sent_2 = upstream.received_bytes[2]
        resp, report, j = one(())                                          # nothing named: neither kept nor new
        assert resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'not_authorized']
        assert report == (j.seq, c.RES_UNSENT, 0)
        time.sleep(0.2)
        assert upstream.received_bytes[1] == sent and upstream.received_bytes[2] == sent_2   # no byte on a dropped one
        assert upstream.connections == 2 and len(upstream.requests) == 3
        assert redirect.attempts == ['10.0.0.5', '10.0.0.7']
    finally:
        cl.close()
        rig.close()
        upstream.close()


def test_a_retained_connection_to_a_global_address_is_reused_with_nothing_named(
        tmp_path: Path, library: Path, ca: CA, monkeypatch: pytest.MonkeyPatch) -> None:
    """C-37: the re-judgment passes a global peer whatever the named list says; the connection is reused as before."""
    upstream = Upstream()
    redirect = Redirect(monkeypatch, {'93.184.215.14': upstream.port})
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: ['93.184.215.14']))
    try:
        cl = rig.client()
        for _ in range(2):
            cl.request(scheme=b'http', port=upstream.port)
            j = rig.judge()
            assert j is not None
            rig.allow_nocred(j.seq)
            resp = cl.response()
            assert resp is not None and resp.status == 200 and rig.report() == (j.seq, c.RES_REMOTE, 200)
        assert upstream.connections == 1 and [r.connection for r in upstream.requests] == [1, 1]
        assert redirect.attempts == ['93.184.215.14']
        cl.close()
    finally:
        rig.close()
        upstream.close()


def test_a_scope_two_revoke_cuts_a_response_from_a_named_address(tmp_path: Path, library: Path, ca: CA,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    """K-31, connector side: removing a named address revokes the whole key with scope 2 (SPEC 3.2); the response in
    flight from the named private address is cut (no RESP_END) and the report names what the upstream did."""
    def stream(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
        for _ in range(12):
            try:
                sock.sendall(b'5\r\nhello\r\n')
            except OSError:
                return None
            time.sleep(0.15)
        return None

    upstream = Upstream(reply=stream)
    Redirect(monkeypatch, {'10.0.0.5': upstream.port})
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: ['10.0.0.5']))
    try:
        cl = rig.client()
        cl.request(scheme=b'http', port=upstream.port)
        j = rig.judge()
        assert j is not None
        rig.allow_nocred(j.seq, named=('10.0.0.5/32',))
        head = cl.head()
        assert head is not None and head.status == 200 and cl.frame()[0] == c.RESP_CHUNK   # type: ignore[index]
        rig.revoke(1, b'api.test:%d' % upstream.port, b'', everyone=True)
        got = cl.frame(timeout=1.0)
        while got is not None and got[0] != c.RESP_END:
            got = cl.frame(timeout=1.0)
        assert got is None                                                   # closed before RESP_END: cut
        assert rig.report() == (j.seq, c.RES_REMOTE, 200)
        assert rig.events('revoked') == [{'event': 'revoked', 'key_kind': 1, 'scope': 2, 'connections': 1}]
        cl.close()
    finally:
        rig.close()
        upstream.close()


# ---- the response header rules ----
def test_response_headers_drop_framing_and_unfold() -> None:
    raw = [('Content-Length', '3'), ('Transfer-Encoding', 'chunked'), ('Connection', 'close'), ('Proxy-Authenticate', 'x'),
           ('X-Folded', 'a\r\n b'), ('Set-Cookie', 'k=v'), ('ETag', '"1"')]
    assert up.response_headers(raw, strip_cookies=False) == [(b'x-folded', b'a b'), (b'set-cookie', b'k=v'), (b'etag', b'"1"')]
    assert up.response_headers(raw, strip_cookies=True) == [(b'x-folded', b'a b'), (b'etag', b'"1"')]


def test_token_response_shape() -> None:
    """条款 10 by the body (C-25, user ruling 2026-11-04): a candidate by method and media type, a token response by an
    access_token in at most 64 KiB, at the top level or, in JSON, one level in (user ruling 2026-11-05); the request's
    encoding and Cache-Control play no part."""
    def req(method: bytes, kind: str = '') -> c.Request:
        return c.Request(method, b'https', b'a.test', False, 443, b'/', None, (), (), b'', kind, ())
    JSON, FORM = frozenset({'application/json'}), frozenset({c.FORM})
    json_type = [('Content-Type', 'application/json;charset=UTF-8')]
    # overall review 2026-11-03, #17: a lowercase post is a POST
    for method in (b'POST', b'post', b'Post'):
        assert up.token_candidate(req(method), json_type) == JSON
    for kind in ('', c.FORM, 'application/json', 'multipart/form-data'):
        assert up.token_candidate(req(b'POST', kind), json_type) == JSON
    assert not up.token_candidate(req(b'GET'), json_type) and not up.token_candidate(req(b'PUT'), json_type)
    assert up.token_candidate(req(b'POST'), [('content-type', ' APPLICATION/X-WWW-FORM-URLENCODED ; charset=utf-8')]) == FORM
    assert up.token_candidate(req(b'POST'), [('Content-Type', 'text/plain'), ('Content-Type', 'application/json')]) == JSON
    assert up.token_candidate(req(b'POST'), json_type + [('Content-Type', c.FORM)]) == JSON | FORM
    for other in ('text/event-stream', 'application/jsonx', 'text/json', 'application/problem+json', ''):
        assert not up.token_candidate(req(b'POST'), [('Content-Type', other)])
    assert not up.token_candidate(req(b'POST'), [('Cache-Control', 'no-store')])
    # the body: the top level and one level in (the direct keys of a top-level object value; user ruling 2026-11-05),
    # every member name at both levels, repeated names too; arrays, deeper levels and string values are not looked in
    assert up.token_body(JSON, b'{"access_token":"t","token_type":"bearer"}')
    assert up.token_body(JSON, b'{"x":1,"access_token":"a","x":2,"access_token":"b"}')
    assert up.token_body(JSON, b'\xef\xbb\xbf{"access_token":"t"}') and up.token_body(JSON, '{"access_token":"t"}'.encode('utf-16'))
    assert up.token_body(JSON, b'{"access\\u005ftoken":"t"}')                       # the decoded name counts
    assert up.token_body(JSON, b'{"data":{"access_token":"t"}}') and up.token_body(JSON, b'{"ok":true,"authed_user":{"id":"U","access_token":"t"}}')
    assert up.token_body(JSON, b'{"a":{"access_token":"t"},"a":{}}')                # a repeated outer name: each counts
    assert up.token_body(JSON, b'{"a":{"x":1,"access_token":"t","x":2}}') and up.token_body(JSON, b'{"a":{"access\\u005ftoken":"t"}}')
    assert not up.token_body(JSON, b'{"a":{"b":{"access_token":"t"}}}') and not up.token_body(JSON, b'[{"access_token":"t"}]')
    assert not up.token_body(JSON, b'{"a":[{"access_token":"t"}]}') and not up.token_body(JSON, b'{"a":"{\\"access_token\\":\\"t\\"}"}')
    assert not up.token_body(JSON, b'{"a":"access_token"}') and not up.token_body(JSON, b'{"a":{"x":"access_token"}}')
    assert not up.token_body(JSON, b'"access_token"') and not up.token_body(JSON, b'{"token":"t"}')
    assert not up.token_body(JSON, b'{"access_token":"t"') and not up.token_body(JSON, b'{"access_token":"t"} x')
    assert not up.token_body(JSON, b'{"access_token":"\xff"}') and not up.token_body(JSON, b'[' * 5000 + b']' * 5000)
    assert not up.token_body(JSON, b'access_token=t')                                 # a form body under the JSON type
    assert up.token_body(FORM, b'access_token=t&scope=repo') and up.token_body(FORM, b'scope=repo&access_token=')
    assert up.token_body(FORM, b'access%5Ftoken=t') and up.token_body(FORM, b'access_token')
    assert up.token_body(FORM, b'x=\xff&access_token=t')
    assert not up.token_body(FORM, b'x=access_token') and not up.token_body(FORM, b'{"access_token":"t"}')
    assert not up.token_body(FORM, b'authed_user%5Baccess_token%5D=t')               # a form: its own keys only, unchanged
    assert up.token_body(JSON | FORM, b'access_token=t') and up.token_body(JSON | FORM, b'{"access_token":"t"}')
    head = b'{"access_token":"t","pad":"'
    at = head + b'x' * (up.TOKEN_LIMIT - len(head) - 2) + b'"}'
    assert len(at) == 65536 and up.token_body(JSON, at) and not up.token_body(JSON, at[:-2] + b'x"}')
    # what the TCB cannot read is withheld: a content coding other than identity, a transfer coding other than chunked
    assert up.unreadable([('Content-Encoding', 'gzip')], False) == 'content_encoding'
    assert up.unreadable([('Content-Encoding', 'identity'), ('content-encoding', 'Br')], False) == 'content_encoding'
    assert up.unreadable([('Content-Encoding', 'identity, '), ('Content-Encoding', '')], False) == ''
    assert up.unreadable([('Transfer-Encoding', 'chunked')], True) == '' and up.unreadable([], False) == ''
    assert up.unreadable([('Transfer-Encoding', 'gzip, chunked')], True) == 'transfer_encoding'
    assert up.unreadable([('Transfer-Encoding', 'chunked')], False) == 'transfer_encoding'   # http.client did not dechunk
    assert up.unreadable([('Transfer-Encoding', 'chunked'), ('Transfer-Encoding', 'chunked')], True) == 'transfer_encoding'


# ---- 648d60f2 4.3 拒绝回复 (K-51, C-23, C-36, F-06): one template, the fixed words ----
WORDS = [b'not_authorized', b'recorded_deny', b'user_denied', b'pdp_denied', b'policy_changed', b'clause', b'credential',
         b'timeout', b'unavailable', b'response_withheld', b'transport_error', b'result_unknown']


def test_every_reason_word_has_its_next_step_and_the_body_echoes_only_the_request() -> None:
    assert sorted(up.NEXT_STEP) == sorted(WORDS)
    req = c.parse_request([b'POST', b'https', b'api.test', c.u16(443), b'/a/b', b'q=secret-query',
                           c.pack_list([b'x-api-key', b'sk-header-value']), b'{"body":"secret"}'])
    for word in WORDS:
        body = up.refusal_body(req, word)
        assert body.startswith(b'engine refused POST https://api.test/a/b\nreason: ' + word + b'\n')
        assert up.NEXT_STEP[word] in body
        assert b'secret' not in body and b'sk-header-value' not in body          # no query, header value or body
    assert b'retry' in up.NEXT_STEP[b'policy_changed'] and b'Do not retry' in up.NEXT_STEP[b'recorded_deny']
    assert b'widening an entry does not help' in up.NEXT_STEP[b'clause']


@pytest.mark.parametrize('resolution, named, word', [(['10.0.0.6'], ('10.0.0.5/32',), b'not_authorized'),
                                                     (['169.254.169.254'], ('169.254.0.0/16',), b'clause')])
def test_the_connect_time_address_refusals_use_the_template(monkeypatch: pytest.MonkeyPatch, resolution, named,
                                                            word: bytes) -> None:
    """The previous test's cases for the connector's own address refusals (C-36; plan engine-v3-private-net): an
    unnamed non-global address is not_authorized, a never-connect one clause; the fixed template with the word's next
    step, the request's own fields only, never the resolved address or the named list; nothing connected."""
    redirect = Redirect(monkeypatch)
    frames: list[bytes] = []
    exchange = up.Exchange(up.Policy(resolver=lambda h, p: list(resolution)), up.tls_context(), up.Registry(),
                           lambda *a, **k: None)
    body = b'{"body":"secret"}'
    req = c.parse_request([b'POST', b'https', b'api.test', c.u16(443), b'/a/b', b'q=secret-query',
                           c.pack_list([b'x-api-key', b'sk-header-value']), body])
    memfd = c.seal_body(body)
    try:
        assert exchange.run(req, up.Answer(c.ALLOW_NOCRED, named=nets(*named)), memfd, len(body),
                            up.Sink(frames.append)) == (c.RES_UNSENT, 0)
    finally:
        os.close(memfd)
    parser = c.FrameParser(c.LIMITS.frame_a, c.LINK_A_OUT)
    (k1, head), (k2, chunk), (k3, _) = [got for frame in frames for got in parser.feed(frame)]
    assert (k1, k2, k3) == (c.RESP_HEAD, c.RESP_CHUNK, c.RESP_END)
    assert c.read_uint(head[0], 1) == c.CAT_REFUSED and c.unpack_list(head[2]) == [b'x-engine-reason', word]
    assert chunk[0] == up.refusal_body(req, word) and up.NEXT_STEP[word] in chunk[0]
    assert not any(t.encode() in chunk[0] for t in [*resolution, *named]) and b'secret' not in chunk[0]
    assert redirect.attempts == []
