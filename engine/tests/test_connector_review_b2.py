"""Regressions from review point B, the cold Opus round (runs/20261029T070000Z-review-B-connector/review-opus-round1.md):
OB2 the fd-level shutdown on revocation, OS3 close-delimited bodies cut by a REVOKE, OS5 interim responses, OS8 the
host's own addresses, OM1 idle links cut, OM2 auto_open, OM5 upstream x-engine-* headers, OM6 the handshake deadline,
OM7 an ALLOW without an account."""
from __future__ import annotations

import socket
import time
from pathlib import Path

from connector import canonical as c
from connector import upstream as up
from connector_rig import CA, TRUTH, Received, Rig, Upstream, named_field, server_tls, simple_reply
from test_connector_upstream import allowed_exchange


def idle_links(rig: Rig) -> list[up.Link]:
    return [l for s in list(rig.connector.sessions) for l in s.exchange.links.values()]


def test_cut_keeps_the_tls_object_and_marks_the_link_dead(rig: Rig, ca: CA) -> None:
    """OB2: the fd-level shutdown is used, never SSLSocket.shutdown, so no racing send or recv falls back to the bare
    socket; OM1: a link cut while idle is replaced, not reused as a failure; OM2: http.client never connects itself."""
    upstream = Upstream(server_tls(ca))
    cl = rig.client()
    cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.allow(j.seq, account=b'alice')
    assert cl.response().status == 200 and rig.report()[0] == j.seq   # type: ignore[union-attr,index]
    [link] = idle_links(rig)
    assert link.conn.auto_open == 0
    rig.revoke(1, b'api.test:%d' % upstream.port, b'alice')
    deadline = time.monotonic() + 3
    while not link.dead and time.monotonic() < deadline:
        time.sleep(0.02)
    assert link.dead and link.sock._sslobj is not None                # the TLS object survives the cut
    cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
    j2 = rig.judge()
    assert j2 is not None
    rig.allow(j2.seq, account=b'alice')
    resp = cl.response()
    assert resp is not None and resp.status == 200 and resp.ended    # a new connection, not a failure
    assert [r.connection for r in upstream.requests] == [1, 2]
    cl.close()
    upstream.close()


def test_revoke_during_a_tls_body_never_relays_ciphertext(rig: Rig, ca: CA) -> None:
    """OB2 shape two: TLS records queued in the kernel while the client is slow; the REVOKE must cut the stream, not
    turn the queued records into body bytes."""
    body = b'A' * (2 * 1024 * 1024)
    upstream = Upstream(server_tls(ca), reply=simple_reply(body))
    cl = rig.client()
    cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.allow(j.seq, account=b'alice')
    head = cl.head()
    assert head is not None and head.status == 200
    time.sleep(0.5)                                                   # let records pile up unread
    rig.revoke(1, b'api.test:%d' % upstream.port, b'alice')
    deadline = time.monotonic() + 3                                   # read only once the cut is applied: the channel
    while not all(l.dead for l in list(rig.connector.registry._links)) and time.monotonic() < deadline:   # thread may
        time.sleep(0.01)                                              # take a GIL turn or two to get to the REVOKE
    got, ended = b'', False
    while True:
        frame = cl.frame(timeout=5)
        if frame is None:
            break
        if frame[0] == c.RESP_END:
            ended = True
            break
        if frame[0] == c.RESP_CHUNK:
            got += frame[1][0]
    assert got == b'A' * len(got) and len(got) < len(body)            # a prefix of the plaintext only, then the cut
    assert not ended
    assert rig.report() == (j.seq, c.RES_REMOTE, 200)
    cl.close()
    upstream.close()


def test_close_delimited_body_cut_by_revoke_is_not_complete(rig: Rig, ca: CA) -> None:
    """OS3 second half: a body delimited by connection close ends in EOF either way; the REVOKE's dead mark tells the
    cut from the end."""
    def stream(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n')
        for _ in range(12):
            try:
                sock.sendall(b'hello')
            except OSError:
                return None
            time.sleep(0.15)
        return None

    upstream = Upstream(server_tls(ca), reply=stream)
    cl = rig.client()
    cl.request(port=upstream.port, headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.allow(j.seq, account=b'alice')
    head = cl.head()
    assert head is not None and head.status == 200
    assert cl.frame()[0] == c.RESP_CHUNK     # type: ignore[index]
    rig.revoke(1, b'api.test:%d' % upstream.port, b'alice')
    while True:
        frame = cl.frame(timeout=3)
        if frame is None or frame[0] == c.RESP_END:
            break
    assert frame is None                                              # cut: no RESP_END
    cl.close()
    upstream.close()


def test_interim_response_other_than_100_is_a_failure_not_a_final_response(rig: Rig, ca: CA) -> None:
    """OS5: 103 Early Hints followed by a token response; the token must not land on the next request."""
    token = b'{"access_token":"NEW-TOKEN"}'

    def early_then_token(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 103 Early Hints\r\nLink: </x>; rel=preload\r\n\r\n')
        time.sleep(0.3)
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: %d\r\n\r\n' % len(token) + token)
        time.sleep(0.5)
        return None

    upstream = Upstream(server_tls(ca), reply=early_then_token)
    cl = rig.client()
    cl.request(port=upstream.port, method=b'POST', path=b'/token',
               headers=((b'content-type', b'application/x-www-form-urlencoded'),), body=b'a=b')
    j = rig.judge()
    assert j is not None
    rig.allow_nocred(j.seq)
    resp = cl.response()
    assert resp is not None and resp.category == c.CAT_UNKNOWN and resp.ended and b'NEW-TOKEN' not in resp.body
    assert rig.report() == (j.seq, c.RES_UNKNOWN, 0)
    plain = Upstream(server_tls(ca))
    cl.request(port=plain.port, path=b'/next')                        # the next request on the same fd gets its own answer
    j2 = rig.judge()
    assert j2 is not None
    rig.allow_nocred(j2.seq)
    resp2 = cl.response()
    assert resp2 is not None and resp2.body == b'ok'
    cl.close()
    upstream.close()
    plain.close()


def test_local_address_probe_sees_every_host_address() -> None:
    """OS8: the probe answers for loopback and for every interface address, not for a foreign one."""
    assert up.is_local_address('127.0.0.1') and up.is_local_address('::1')
    for addr in up.interface_addresses():
        if not addr.is_link_local:
            assert up.is_local_address(str(addr)), addr
    assert not up.is_local_address('203.0.113.9') and not up.is_local_address('2001:db8::9')
    assert not up.Policy(include_interfaces=False).allowed(['127.0.0.1'])


def test_upstream_x_engine_headers_are_dropped(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(b'ok', extra='X-Engine-Reason: user_deny\r\nX-Keep: 1\r\n'))
    _, resp, _ = allowed_exchange(rig, upstream, nocred=True)
    assert resp is not None and resp.header(b'x-engine-reason') == [] and resp.header(b'x-keep') == [b'1']     # OM5
    upstream.close()


def test_handshake_runs_under_the_connect_deadline(tmp_path: Path, library: Path, ca: CA) -> None:
    """OM6: a peer that accepts TCP and never answers the ClientHello is a transport error within the connect timeout,
    not after the read timeout."""
    rig = Rig(tmp_path, library, ca, connect_timeout=0.5, read_timeout=30.0)
    try:
        silent = Upstream(reply=lambda r, s: (time.sleep(5), None)[1])   # plain TCP: reads, never speaks TLS
        cl = rig.client()
        cl.request(port=silent.port)
        j = rig.judge()
        assert j is not None
        rig.allow_nocred(j.seq)
        started = time.monotonic()
        resp = cl.response()
        assert resp is not None and resp.category == c.CAT_TRANSPORT and time.monotonic() - started < 3
        assert rig.report() == (j.seq, c.RES_TRANSPORT, 0)
        silent.close()
        cl.close()
    finally:
        rig.close()


def test_allow_with_an_empty_account_is_a_protocol_fault(rig: Rig) -> None:
    cl = rig.client()
    cl.request(headers=((b'authorization', b'Bearer PH'),))
    j = rig.judge()
    assert j is not None
    rig.send_core(c.ALLOW, [c.u64(j.seq), c.u8(c.PLACE_BEARER), b'Bearer', TRUTH, b'', b'', named_field(())])   # OM7
    deadline = time.monotonic() + 3
    while not rig.fatal and time.monotonic() < deadline:
        time.sleep(0.02)
    assert rig.fatal and 'account' in rig.fatal[0]
    cl.close()


def test_revoke_stops_the_relay_at_the_next_piece() -> None:
    """Block 6 finding: shutdown(SHUT_RD) leaves the kernel's receive queue readable, so after a REVOKE the relay loop kept
    turning queued response bytes into RESP_CHUNK frames (measured up to 1.9 MiB after the cut). The loop must stop at the
    first piece read once the link is dead, send no RESP_END, and still report what the upstream answered."""
    class Dead:                                     # the link as Registry.revoke leaves it
        dead, key = False, (b'api.test', 443, b'https', b'alice')

        def close(self) -> None:
            self.dead = True

    class Endless:                                  # an upstream response whose bytes are all already queued
        status, length, will_close = 200, None, True
        msg = type('Msg', (), {'defects': []})()

        def __init__(self, link: Dead) -> None:
            self.link, self.reads = link, 0

        def getheaders(self) -> list[tuple[str, str]]:
            return [('Content-Type', 'text/event-stream')]

        def read1(self, n: int) -> bytes:
            self.reads += 1
            if self.reads == 3:
                self.link.dead = True               # the REVOKE lands while the third piece is being read
            return b'A' * 100 if self.reads <= 1000 else b''

        def isclosed(self) -> bool:
            return False

        def close(self) -> None:
            pass

    frames: list[bytes] = []
    exchange = up.Exchange(None, None, up.Registry(), lambda *a, **k: None)   # type: ignore[arg-type]
    req = c.Request(b'GET', b'https', b'api.test', False, 443, b'/stream', None, (), (), b'', '', ())
    link = Dead()
    resp = Endless(link)
    result = exchange._relay(req, up.Answer(c.ALLOW, account=b'alice'), link, resp, up.Sink(frames.append))   # type: ignore[arg-type]
    kinds = [f[4] for f in frames]
    assert kinds == [c.RESP_HEAD, c.RESP_CHUNK, c.RESP_CHUNK]         # the two pieces read before the cut, then nothing
    assert resp.reads == 3 and result == (c.RES_REMOTE, 200)
