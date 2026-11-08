"""条款 10 by the response body (validation.md C-25, N-16; user ruling 2026-11-04, plan engine-v3-n16-file-read): the
response to a POST is withheld when one of its Content-Type fields names JSON or a urlencoded form, its body is at most
64 KiB and has access_token among its top-level keys or, in JSON, among the direct keys of a top-level value that is
itself an object (user ruling 2026-11-05), whatever the request's own encoding and whatever its Cache-Control. A POST
goes out with Accept-Encoding: identity; a candidate still content-coded is withheld. Everything else passes byte for
byte; a candidate is held before it is judged, and a cut while it is held hands nothing out. The guarantee covers the
standard shapes only (user ruling 2026-11-05): the declared-boundary tests at the end record what lies outside it."""
from __future__ import annotations

import gzip
import json
import socket
import threading
import time

import pytest

from connector import canonical as c
from connector import upstream as up
from connector_rig import CA, Received, Rig, Upstream, server_tls, simple_reply
from test_connector_upstream import allowed_exchange

TOKEN_JSON = json.dumps({'access_token': 'NEW-TOKEN-json', 'token_type': 'bearer', 'expires_in': 3600}).encode()
TOKEN_FORM = b'access_token=NEW-TOKEN-form&scope=repo&token_type=bearer'                 # GitHub without Accept: json
GITHUB_CACHE = 'Cache-Control: max-age=0, private, must-revalidate\r\n'                  # no no-store (2026-11-04)
JSON_TYPE = 'Content-Type: application/json; charset=utf-8\r\n'

REQUESTS = {                                                        # the three non-form encodings and the form itself
    'json': ((b'content-type', b'application/json'),
             b'{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"d","client_id":"c"}'),
    'no-content-type': ((), b'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=d'),
    'multipart': ((b'content-type', b'multipart/form-data; boundary=xyz'),
                  b'--xyz\r\nContent-Disposition: form-data; name="grant_type"\r\n\r\nclient_credentials\r\n--xyz--\r\n'),
    'form': ((b'content-type', b'application/x-www-form-urlencoded'), b'grant_type=client_credentials'),
}


def post(rig: Rig, upstream: Upstream, encoding: str = 'json', method: bytes = b'POST', **kw):
    pair, body = REQUESTS[encoding]
    headers = ((pair,) if pair else ()) + tuple(kw.pop('headers', ()))
    return allowed_exchange(rig, upstream, nocred=True, method=method, path=b'/login/oauth/access_token',
                            headers=headers, body=body, **kw)


def assert_withheld(rig: Rig, j, resp, report, status: int = 200, why: str = 'body') -> None:
    assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'response_withheld']
    assert resp.ended and b'NEW-TOKEN' not in resp.body and report == (j.seq, c.RES_REMOTE, status)
    assert rig.events('token_response_withheld')[-1] == {'event': 'token_response_withheld', 'status': status, 'why': why}


def assert_relayed(rig: Rig, j, resp, report, body: bytes, status: int = 200) -> None:
    assert resp is not None and (resp.category, resp.status, resp.ended) == (c.CAT_REMOTE, status, True)
    assert resp.body == body and report == (j.seq, c.RES_REMOTE, status)              # byte for byte
    assert not rig.events('token_response_withheld')


def piece(data: bytes) -> bytes:
    return b'%x\r\n%s\r\n' % (len(data), data)


def chunked(*pieces: bytes) -> bytes:
    return b''.join(piece(p) for p in pieces) + b'0\r\n\r\n'


def token_of(size: int) -> bytes:
    """A JSON token response of exactly ``size`` bytes, access_token at the top level."""
    head, tail = b'{"access_token":"NEW-TOKEN-big","pad":"', b'"}'
    return head + b'x' * (size - len(head) - len(tail)) + tail


# ---- withheld whatever the request's encoding, with or without no-store ----
@pytest.mark.parametrize('encoding', list(REQUESTS))
@pytest.mark.parametrize('body, extra', [(TOKEN_JSON, JSON_TYPE),                       # no Cache-Control at all
                                         (TOKEN_FORM, 'Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n'
                                                      + GITHUB_CACHE)],
                         ids=['json-response', 'form-response'])
def test_token_response_is_withheld_whatever_the_request_encoding(rig: Rig, ca: CA, encoding: str, body: bytes,
                                                                  extra: str) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(body, extra=extra))
    j, resp, report = post(rig, upstream, encoding)
    assert_withheld(rig, j, resp, report)
    upstream.close()


@pytest.mark.parametrize('status, code', [('400 Bad Request', 400), ('201 Created', 201)])
def test_the_status_code_plays_no_part(rig: Rig, ca: CA, status: str, code: int) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(TOKEN_JSON, status, JSON_TYPE))
    j, resp, report = post(rig, upstream)
    assert_withheld(rig, j, resp, report, status=code)
    upstream.close()


# ---- one level in: the direct keys of a top-level object value count too (user ruling 2026-11-05) ----
SLACK = (b'{"ok":true,"app_id":"A1","authed_user":{"id":"U1","scope":"identify","access_token":"NEW-TOKEN-slack",'
         b'"token_type":"user"},"team":{"id":"T1"}}')                      # oauth.v2.access with a user token only


@pytest.mark.parametrize('body', [
    SLACK,
    b'{"authed_user":{"access_token":"NEW-TOKEN-dup"},"authed_user":{"id":"U1"}}',   # a repeated outer name: each counts
    b'{"data":{"x":1,"access_token":"a","x":2,"access_token":"NEW-TOKEN-b"}}',       # repeated inner names
], ids=['slack-authed-user', 'repeated-outer-name', 'repeated-inner-name'])
def test_access_token_one_level_in_is_withheld(rig: Rig, ca: CA, body: bytes) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(body, extra=JSON_TYPE))
    j, resp, report = post(rig, upstream)
    assert_withheld(rig, j, resp, report)
    upstream.close()


@pytest.mark.parametrize('body', [
    b'{"a":{"b":{"access_token":"NEW-TOKEN-third"}}}',                               # the third level
    b'{"data":[{"access_token":"NEW-TOKEN-in-array"}]}',                             # in an array
    b'{"data":"{\\"access_token\\":\\"NEW-TOKEN-in-string\\"}"}',                     # in a top-level string value
], ids=['third-level', 'in-array', 'in-string-value'])
def test_access_token_deeper_than_one_level_in_passes_byte_for_byte(rig: Rig, ca: CA, body: bytes) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(body, extra=JSON_TYPE))
    j, resp, report = post(rig, upstream)
    assert_relayed(rig, j, resp, report, body)
    upstream.close()


@pytest.mark.parametrize('fields, body', [
    (['APPLICATION/JSON'], TOKEN_JSON),
    (['application/json;charset=UTF-8'], TOKEN_JSON),
    (['Application/X-WWW-Form-Urlencoded ; charset=utf-8'], TOKEN_FORM),
    (['text/plain', 'application/json'], TOKEN_JSON),                    # one of several Content-Type fields
    (['application/x-www-form-urlencoded', 'text/html'], TOKEN_FORM),
], ids=['upper', 'charset', 'form-mixed-case', 'second-field', 'first-field'])
def test_media_type_spellings_are_recognised(rig: Rig, ca: CA, fields: list[str], body: bytes) -> None:
    extra = ''.join(f'Content-Type: {f}\r\n' for f in fields)
    upstream = Upstream(server_tls(ca), reply=simple_reply(body, extra=extra))
    j, resp, report = post(rig, upstream)
    assert_withheld(rig, j, resp, report)
    upstream.close()


# ---- Accept-Encoding: identity on every POST; a candidate still coded is withheld ----
def test_a_post_goes_out_with_accept_encoding_identity(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca))
    for method, given in ((b'POST', ((b'accept-encoding', b'gzip, br'),)), (b'post', ((b'accept-encoding', b'gzip'),)),
                          (b'POST', ())):
        post(rig, upstream, method=method, headers=given + ((b'x-other', b'kept'),))
        got = upstream.requests[-1]
        assert got.header('accept-encoding') == ['identity'] and got.header('x-other') == ['kept']
    allowed_exchange(rig, upstream, nocred=True, method=b'GET', path=b'/g', headers=((b'accept-encoding', b'gzip'),))
    assert upstream.requests[-1].header('accept-encoding') == ['gzip']          # other methods: as the agent wrote it
    allowed_exchange(rig, upstream, nocred=True, method=b'PUT', path=b'/p', body=b'x')
    assert upstream.requests[-1].header('accept-encoding') == []
    upstream.close()


@pytest.mark.parametrize('coding', ['gzip', 'GZIP', 'identity, gzip', 'br'])
@pytest.mark.parametrize('plain', [TOKEN_JSON, b'{"ok":true}'], ids=['token', 'no-token'])
def test_a_candidate_still_content_coded_is_withheld(rig: Rig, ca: CA, coding: str, plain: bytes) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(gzip.compress(plain, mtime=0), extra=JSON_TYPE + f'Content-Encoding: {coding}\r\n'))
    j, resp, report = post(rig, upstream)
    assert_withheld(rig, j, resp, report, why='content_encoding')               # never decoded in the TCB
    upstream.close()


def test_identity_coding_and_coded_non_candidates_are_judged_as_usual(rig: Rig, ca: CA) -> None:
    plain = b'{"ok":true}'
    upstream = Upstream(server_tls(ca), reply=simple_reply(plain, extra=JSON_TYPE + 'Content-Encoding: identity\r\n'))
    j, resp, report = post(rig, upstream)
    assert_relayed(rig, j, resp, report, plain)
    coded = gzip.compress(b'access_token=NEW-TOKEN', mtime=0)
    other = Upstream(server_tls(ca), reply=simple_reply(coded, extra='Content-Type: application/octet-stream\r\nContent-Encoding: gzip\r\n'))
    j, resp, report = post(rig, other)
    assert_relayed(rig, j, resp, report, coded)                                 # not a candidate: as it came
    assert resp is not None and resp.header(b'content-encoding') == [b'gzip']
    upstream.close()
    other.close()


@pytest.mark.parametrize('transfer, body, why', [
    ('chunked', chunked(TOKEN_JSON[:20], TOKEN_JSON[20:]), 'body'),             # dechunked by http.client, then judged
    ('gzip, chunked', chunked(gzip.compress(TOKEN_JSON, mtime=0)), 'transfer_encoding'),   # left coded by http.client
    ('gzip', gzip.compress(TOKEN_JSON, mtime=0), 'transfer_encoding'),
], ids=['chunked', 'gzip-chunked', 'gzip'])
def test_transfer_codings_other_than_chunked_are_withheld(rig: Rig, ca: CA, transfer: str, body: bytes, why: str) -> None:
    raw = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: %s\r\n\r\n' % transfer.encode()) + body
    upstream = Upstream(server_tls(ca), reply=lambda r, s: (s.sendall(raw), None)[1])
    j, resp, report = post(rig, upstream)
    assert_withheld(rig, j, resp, report, why=why)
    upstream.close()


# ---- what passes: byte for byte ----
@pytest.mark.parametrize('content_type, body', [
    ('application/json; charset=utf-8', b'{"error":"slow_down","error_description":"Too many requests",  "interval":10}\n'),
    ('application/x-www-form-urlencoded', b'error=authorization_pending&error_description=pending'),
    ('application/json', b'[{"access_token":"NEW-TOKEN-array"}]'),                    # a top-level array: not looked in
    ('application/json', b'{"access_token":"NEW-TOKEN-cut"'),                        # does not parse
    ('application/json', b'{"access_token":"NEW-TOKEN-tail"} trailing'),
    ('application/json', b'{"access_token":"NEW-TOKEN-\xff"}'),                      # not UTF-8
    ('application/json', b'[' * 5000 + b']' * 5000),                                 # deeper than the parser recurses
    ('application/x-www-form-urlencoded', b'grant=access_token'),                     # a value, not a key
    ('text/plain', TOKEN_JSON),                                                       # not a candidate
], ids=['json-error', 'form-error', 'array', 'truncated', 'trailing', 'not-utf8', 'deep', 'form-value', 'text'])
def test_what_is_not_a_token_response_passes_byte_for_byte(rig: Rig, ca: CA, content_type: str, body: bytes) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(body, '400 Bad Request', f'Content-Type: {content_type}\r\n' + GITHUB_CACHE))
    j, resp, report = post(rig, upstream)
    assert_relayed(rig, j, resp, report, body, status=400)
    upstream.close()


def test_a_token_response_to_another_method_passes(rig: Rig, ca: CA) -> None:
    upstream = Upstream(server_tls(ca), reply=simple_reply(TOKEN_JSON, extra=JSON_TYPE + 'Cache-Control: no-store\r\n'))
    for method in (b'GET', b'PUT', b'PATCH'):
        j, resp, report = allowed_exchange(rig, upstream, nocred=True, method=method, path=b'/t', body=b'' if method == b'GET' else b'{}')
        assert_relayed(rig, j, resp, report, TOKEN_JSON)
    upstream.close()


@pytest.mark.parametrize('framing', ['length', 'chunked', 'close'])
def test_the_64_kib_limit(rig: Rig, ca: CA, framing: str) -> None:
    """At 64 KiB the body is judged and withheld; one byte more and it passes, byte for byte, in every framing."""
    def reply_for(body: bytes):
        if framing == 'length':
            return simple_reply(body, extra=JSON_TYPE)
        if framing == 'chunked':
            pieces = [body[i:i + 1000] for i in range(0, len(body), 1000)]
            raw = b'HTTP/1.1 200 OK\r\n' + JSON_TYPE.encode() + b'Transfer-Encoding: chunked\r\n\r\n' + chunked(*pieces)
        else:                                                   # close-delimited, over plain http (a TLS close here
            raw = b'HTTP/1.1 200 OK\r\n' + JSON_TYPE.encode() + b'Connection: close\r\n\r\n' + body   # is a ragged EOF)
        return lambda r, s: (s.sendall(raw), None)[1]

    scheme = b'http' if framing == 'close' else b'https'
    tls = None if framing == 'close' else server_tls(ca)
    at, over = token_of(65536), token_of(65537)
    upstream = Upstream(tls, reply=reply_for(at))
    j, resp, report = post(rig, upstream, scheme=scheme)
    assert_withheld(rig, j, resp, report)
    upstream.close()
    rig.logs.clear()
    upstream = Upstream(server_tls(ca) if tls else None, reply=reply_for(over))
    j, resp, report = post(rig, upstream, scheme=scheme)
    assert_relayed(rig, j, resp, report, over)
    upstream.close()


# ---- SSE is never held ----
def test_sse_is_relayed_piece_by_piece_and_never_held(rig: Rig, ca: CA) -> None:
    go = threading.Event()
    first, last = b'data: {"access_token":"NEW-TOKEN-sse"}\n\n', b'data: done\n\n'

    def stream(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n'
                     + b'%x\r\n%s\r\n' % (len(first), first))
        go.wait(5)
        sock.sendall(b'%x\r\n%s\r\n0\r\n\r\n' % (len(last), last))
        return None

    upstream = Upstream(server_tls(ca), reply=stream)
    cl = rig.client()
    cl.request(method=b'POST', port=upstream.port, path=b'/v1/messages', headers=((b'content-type', b'application/json'),), body=b'{}')
    j = rig.judge()
    assert j is not None
    rig.allow_nocred(j.seq)
    try:
        head = cl.head(timeout=3)
        assert head is not None and head.category == c.CAT_REMOTE and head.status == 200
        got = cl.frame(timeout=3)
        assert got is not None and got[0] == c.RESP_CHUNK and got[1][0] == first     # before the upstream finished
    finally:
        go.set()
    body = b''
    while (got := cl.frame(timeout=3)) is not None and got[0] == c.RESP_CHUNK:
        body += got[1][0]
    assert body == last and got is not None and got[0] == c.RESP_END
    assert rig.report() == (j.seq, c.RES_REMOTE, 200) and not rig.events('token_response_withheld')
    cl.close()
    upstream.close()


# ---- a cut while the candidate is held hands nothing out ----
def frames_until_end(cl) -> list[int]:
    kinds = []
    while (got := cl.frame(timeout=3)) is not None:
        kinds.append(got[0])
        assert got[0] != c.RESP_CHUNK or b'NEW-TOKEN' not in got[1][0]
        if got[0] == c.RESP_END:
            break
    return kinds


def test_a_revoke_while_the_candidate_is_held_hands_nothing_out(rig: Rig, ca: CA) -> None:
    sent, go = threading.Event(), threading.Event()
    part, rest = b'{"access_token":"NEW-TOKEN-held",', b'"token_type":"bearer"}'

    def slow(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n'
                     + b'%x\r\n%s\r\n' % (len(part), part))
        sent.set()
        go.wait(5)
        try:
            sock.sendall(chunked(rest))
        except OSError:
            pass
        return None

    upstream = Upstream(server_tls(ca), reply=slow)
    cl = rig.client()
    cl.request(method=b'POST', port=upstream.port, path=b'/token', headers=((b'content-type', b'application/json'),), body=b'{}')
    j = rig.judge()
    assert j is not None
    rig.allow_nocred(j.seq)
    try:
        assert sent.wait(5)
        time.sleep(0.3)                                          # the first piece is in the connector's hold
        rig.revoke(1, b'api.test:%d' % upstream.port, b'', everyone=True)
        kinds = frames_until_end(cl)
    finally:
        go.set()
    assert kinds == [c.RESP_HEAD]                                # the head, then the cut: no byte of the body, no end
    assert rig.report() == (j.seq, c.RES_REMOTE, 200) and rig.events('response_cut')
    assert not rig.events('token_response_withheld')
    cl.close()
    upstream.close()


@pytest.mark.parametrize('scheme', [b'http', b'https'])
def test_a_candidate_cut_short_is_never_judged_on_its_part(rig: Rig, ca: CA, scheme: bytes) -> None:
    """The part read is itself a whole token response; Content-Length promised more. Over http the read ends early,
    over TLS the close without close_notify is an error: a cut either way, nothing of the part goes out."""
    part = b'{"access_token":"NEW-TOKEN-short"}'
    raw = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n' + part
    upstream = Upstream(server_tls(ca) if scheme == b'https' else None, reply=lambda r, s: (s.sendall(raw), None)[1])
    cl = rig.client()
    cl.request(method=b'POST', scheme=scheme, port=upstream.port, path=b'/token',
               headers=((b'content-type', b'application/json'),), body=b'{}')
    j = rig.judge()
    assert j is not None
    rig.allow_nocred(j.seq)
    assert frames_until_end(cl) == [c.RESP_HEAD]
    assert rig.report() == (j.seq, c.RES_REMOTE, 200) and rig.events('response_cut')
    cl.close()
    upstream.close()


@pytest.mark.parametrize('body', [b'{"ok":true,"note":"held then revoked"}', TOKEN_JSON], ids=['not-token', 'token'])
def test_a_revoke_while_the_held_candidate_is_judged_comes_first(rig: Rig, ca: CA, monkeypatch: pytest.MonkeyPatch,
                                                                 body: bytes) -> None:
    """Opus review 2026-11-04, minor 3, and the Codex recheck, minor 4: the candidate was read whole; the REVOKE lands
    while it is judged. Whatever the verdict, the REVOKE comes first: the head, then the cut; no withholding reply."""
    upstream = Upstream(server_tls(ca), reply=simple_reply(body, extra=JSON_TYPE))
    judged = up.token_body

    def judged_then_revoked(kinds: frozenset[str], held: bytes) -> bool:
        verdict = judged(kinds, held)
        rig.revoke(1, b'api.test:%d' % upstream.port, b'', everyone=True)
        deadline = time.monotonic() + 3                         # the channel thread applies the REVOKE
        while not all(link.dead for link in list(rig.connector.registry._links)) and time.monotonic() < deadline:
            time.sleep(0.01)
        return verdict

    monkeypatch.setattr(up, 'token_body', judged_then_revoked)
    cl = rig.client()
    cl.request(method=b'POST', port=upstream.port, path=b'/p', headers=((b'content-type', b'application/json'),), body=b'{}')
    j = rig.judge()
    assert j is not None
    rig.allow_nocred(j.seq)
    assert frames_until_end(cl) == [c.RESP_HEAD]
    assert rig.report() == (j.seq, c.RES_REMOTE, 200) and rig.events('response_cut')
    assert not rig.events('token_response_withheld')
    cl.close()
    upstream.close()


def test_a_failed_write_of_the_held_block_ends_the_exchange_without_waiting_for_the_tail(
        rig: Rig, ca: CA, monkeypatch: pytest.MonkeyPatch) -> None:
    """Codex recheck 2026-11-04, important 2: the candidate is past the hold; the client leaves after the hold's last
    hang-up check, so writing the head and the held block fails while the upstream pauses before its tail. The
    exchange ends and reports at once; it does not read again and wait for the tail."""
    sent, tail = threading.Event(), threading.Event()
    over = b'{"pad":"' + b'x' * (70 * 1024) + b'"}'
    first = up.TOKEN_LIMIT + 1                                    # exactly what the hold reads: nothing more is queued

    def paused(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n'
                     + piece(over[:first]))
        sent.set()
        tail.wait(10)
        try:
            sock.sendall(chunked(over[first:]))
        except OSError:
            pass
        return None

    upstream = Upstream(server_tls(ca), reply=paused)
    cl = rig.client()
    head_of = up.response_headers

    def client_leaves(*args, **kwargs):                          # after the hold, before the head and the held block
        cl.sock.close()
        return head_of(*args, **kwargs)

    monkeypatch.setattr(up, 'response_headers', client_leaves)
    cl.request(method=b'POST', port=upstream.port, path=b'/p', headers=((b'content-type', b'application/json'),), body=b'{}')
    j = rig.judge()
    assert j is not None
    rig.allow_nocred(j.seq)
    try:
        assert sent.wait(5)
        assert rig.report(timeout=3) == (j.seq, c.RES_REMOTE, 200)   # without the tail
    finally:
        tail.set()
    assert rig.events('response_cut') and not rig.events('token_response_withheld')
    upstream.close()


# ---- a client that leaves while the candidate is held ends the exchange at the next piece (Codex review 2026-11-04) ----
@pytest.mark.parametrize('scheme', [b'http', b'https'], ids=['upstream-http', 'upstream-https'])
def test_a_client_leaving_while_the_candidate_is_held_ends_the_exchange(rig: Rig, ca: CA, scheme: bytes) -> None:
    """Codex review 2026-11-04, important 2: an upstream that trickles a JSON body keeps the hold filling for minutes.
    The client leaves; the connector notices at the next piece, as the relay notices at its next write: it drops the
    upstream connection, reports what the upstream answered, and the session ends. The parameter is the upstream's
    scheme; the client is the rig's own proxy-port client, not a real HTTP or HTTPS client behind the frontend (a real
    client's cancellation does not reach the connector while the frontend waits for the head: a known cost, C-25)."""
    started, dropped, done = threading.Event(), threading.Event(), threading.Event()

    def trickle(_: Received, sock: socket.socket) -> None:
        sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n'
                     + piece(b'{"pad":"'))
        started.set()
        while not done.is_set():                                 # ten bytes every 50 ms: 64 KiB would take minutes
            try:
                sock.sendall(piece(b'x' * 10))
            except OSError:
                dropped.set()
                return None
            time.sleep(0.05)
        return None

    upstream = Upstream(server_tls(ca) if scheme == b'https' else None, reply=trickle)
    cl = rig.client()
    cl.request(method=b'POST', scheme=scheme, port=upstream.port, path=b'/v1/x',
               headers=((b'content-type', b'application/json'),), body=b'{}')
    j = rig.judge()
    assert j is not None
    rig.allow_nocred(j.seq)
    try:
        assert started.wait(5)
        time.sleep(0.3)                                          # a few pieces are in the hold
        cl.close()                                               # the client leaves; nothing was sent to it yet
        left = time.monotonic()
        assert rig.report(timeout=3) == (j.seq, c.RES_REMOTE, 200)
        assert dropped.wait(3) and time.monotonic() - left < 3   # the upstream connection was dropped
    finally:
        done.set()
    assert rig.events('response_cut') and not rig.events('token_response_withheld')
    upstream.close()


# ---- well past the hold: what was held, then the rest as it comes (Codex review 2026-11-04, minor 3) ----
@pytest.mark.parametrize('framing', ['length', 'chunked', 'close'])
@pytest.mark.parametrize('kind', ['json', 'form'])
def test_a_large_candidate_goes_out_before_the_upstream_ends_and_arrives_whole(rig: Rig, ca: CA, framing: str,
                                                                              kind: str) -> None:
    """200 KiB in two stages of 100 KiB: the first stage (past the 64 KiB hold) reaches the client while the upstream
    waits, and the whole body arrives byte for byte, in each framing. Only the client releases the tail, once the first
    stage is whole on its side and the tail is not yet sent; an upstream left waiting ends without it (Codex recheck
    2026-11-04, minor 3: a connector that held everything must fail here, not pass on a timed-out wait)."""
    stage = 100 * 1024
    if kind == 'json':
        body, media = b'{"pad":"' + b'x' * (2 * stage - 10) + b'"}', 'application/json'
    else:
        body, media = b'a=' + b'x' * (2 * stage - 6) + b'&b=1', 'application/x-www-form-urlencoded'
    first, rest = body[:stage], body[stage:]
    go, tail_sent = threading.Event(), threading.Event()

    def staged(_: Received, sock: socket.socket) -> None:
        head = f'HTTP/1.1 200 OK\r\nContent-Type: {media}\r\n'.encode()
        if framing == 'length':
            sock.sendall(head + b'Content-Length: %d\r\n\r\n' % len(body) + first)
        elif framing == 'chunked':
            sock.sendall(head + b'Transfer-Encoding: chunked\r\n\r\n' + piece(first))
        else:                                                    # close-delimited, over plain http
            sock.sendall(head + b'Connection: close\r\n\r\n' + first)
        if not go.wait(10):                                      # never released: end without the tail
            return None
        tail_sent.set()
        sock.sendall(chunked(rest) if framing == 'chunked' else rest)
        return None

    scheme = b'http' if framing == 'close' else b'https'
    upstream = Upstream(None if framing == 'close' else server_tls(ca), reply=staged)
    cl = rig.client()
    cl.request(method=b'POST', scheme=scheme, port=upstream.port, path=b'/p',
               headers=((b'content-type', b'application/json'),), body=b'{}')
    j = rig.judge()
    assert j is not None
    rig.allow_nocred(j.seq)
    got = b''
    head = cl.head(timeout=5)
    assert head is not None and (head.category, head.status) == (c.CAT_REMOTE, 200)
    while len(got) < len(first):                                 # all of the first stage, the upstream still waiting
        frame = cl.frame(timeout=3)
        assert frame is not None and frame[0] == c.RESP_CHUNK
        got += frame[1][0]
    assert got == first and not tail_sent.is_set()
    go.set()                                                     # the client, and only the client, releases the tail
    while (frame := cl.frame(timeout=5)) is not None and frame[0] == c.RESP_CHUNK:
        got += frame[1][0]
    assert frame is not None and frame[0] == c.RESP_END and got == body
    assert rig.report() == (j.seq, c.RES_REMOTE, 200) and not rig.events('token_response_withheld')
    cl.close()
    upstream.close()


# ---- the declared boundary (N-16; user ruling 2026-11-05): these record where the guarantee ends, not a defence ----
# Only the standard shapes (JSON, a urlencoded form) are guaranteed withheld. A token response in another shape passes
# as it came, and so does one the agent asks for in another shape when the server lets the Accept header choose
# (GitHub's token endpoint answers in XML for Accept: application/xml). A registered token endpoint is refused on the
# request side whatever the shape (K-25, the endpoint equality check; tests/test_matching.py).
XML_TYPE = 'Content-Type: application/xml; charset=utf-8\r\n'
TOKEN_XML = (b'<?xml version="1.0" encoding="UTF-8"?>\n<OAuth><token_type>bearer</token_type><scope>repo</scope>'
             b'<access_token>NEW-TOKEN-xml</access_token></OAuth>')                 # the shape of GitHub's XML answer


@pytest.mark.parametrize('body, extra', [(TOKEN_JSON, JSON_TYPE),
                                         (TOKEN_FORM, 'Content-Type: application/x-www-form-urlencoded\r\n')],
                         ids=['json', 'form'])
def test_declared_boundary_the_standard_shapes_are_withheld(rig: Rig, ca: CA, body: bytes, extra: str) -> None:
    """Inside the guarantee (the full matrix is above): a JSON and a form token response, each withheld."""
    upstream = Upstream(server_tls(ca), reply=simple_reply(body, extra=extra))
    j, resp, report = post(rig, upstream)
    assert_withheld(rig, j, resp, report)
    upstream.close()


def test_declared_boundary_an_xml_token_response_passes_as_it_came(rig: Rig, ca: CA) -> None:
    """Outside the guarantee: application/xml is not a candidate; the token reaches the cell byte for byte."""
    upstream = Upstream(server_tls(ca), reply=simple_reply(TOKEN_XML, extra=XML_TYPE + GITHUB_CACHE))
    j, resp, report = post(rig, upstream)
    assert_relayed(rig, j, resp, report, TOKEN_XML)
    assert resp is not None and b'NEW-TOKEN-xml' in resp.body
    upstream.close()


def answers_by_accept(r: Received, sock: socket.socket) -> bytes:
    """A token endpoint that answers in the format its Accept names, as GitHub's does: JSON, XML, or else a form."""
    accept = ','.join(r.header('accept')).lower()
    if 'application/json' in accept:
        body, media = TOKEN_JSON, 'application/json; charset=utf-8'
    elif 'xml' in accept:
        body, media = TOKEN_XML, 'application/xml; charset=utf-8'
    else:
        body, media = TOKEN_FORM, 'application/x-www-form-urlencoded; charset=utf-8'
    return simple_reply(body, extra=f'Content-Type: {media}\r\n' + GITHUB_CACHE)(r, sock)


def test_declared_boundary_an_agent_that_picks_the_format_by_accept_is_not_stopped(rig: Rig, ca: CA) -> None:
    """Outside the guarantee: the same JSON-bodied POST three times, only Accept differs. JSON and the default form are
    withheld; with Accept: application/xml the token passes, byte for byte. The connector leaves Accept as written."""
    upstream = Upstream(server_tls(ca), reply=answers_by_accept)
    for accept in (b'application/json', b''):
        j, resp, report = post(rig, upstream, headers=((b'accept', accept),) if accept else ())
        assert_withheld(rig, j, resp, report)
        rig.logs.clear()
    j, resp, report = post(rig, upstream, headers=((b'accept', b'application/xml'),))
    assert_relayed(rig, j, resp, report, TOKEN_XML)
    assert resp is not None and b'NEW-TOKEN-xml' in resp.body
    assert [got.header('accept') for got in upstream.requests] == [['application/json'], [], ['application/xml']]
    assert len({got.body for got in upstream.requests}) == 1 and upstream.requests[0].body == REQUESTS['json'][1]
    upstream.close()
