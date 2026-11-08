"""The connector's judgment port and the wait for the core (validation.md C-13, C-14, C-15, C-27, C-28, C-32; SPEC §3.2).
The test plays the core on the core end of the socketpair; no upstream is ever touched before an allow."""
from __future__ import annotations

import ipaddress
import os
import socket
import time
import types

import pytest

from connector import canonical as c
from connector import channel as channel_mod
from connector import session as session_mod
from connector_rig import TRUTH, Rig, Upstream


# ---- the JUDGE frame (SPEC §3.2, C-12, C-13) ----
def test_judge_carries_the_validated_request_and_a_sealed_memfd(rig: Rig) -> None:
    cl = rig.client()
    body = b'grant_type=x&b=2'
    cl.request(method=b'POST', host=b'auth.test', path=b'/a/./b/../c', query=b'q=1',
               headers=((b'content-type', b'application/x-www-form-urlencoded'), (b'x-http-method-override', b'DELETE'),
                        (b'authorization', b'Bearer PH-1')), body=body)
    j = rig.judge()
    assert j is not None
    assert (j.seq, j.uid, j.method, j.scheme, j.host, j.port) == (1, os.getuid(), b'POST', b'https', b'auth.test', 443)
    assert j.path == b'/a/c' and j.query == b'q=1'                       # normalised (C-08), query as given
    assert j.headers == [(b'content-type', b'application/x-www-form-urlencoded'), (b'authorization', b'Bearer PH-1')]
    assert j.stripped == [b'x-http-method-override'] and j.body_kind == b'application/x-www-form-urlencoded'
    assert j.form_keys == [b'grant_type', b'b'] and j.body_len == len(body)
    assert c.seals_ok(j.memfd, len(body)) and os.pread(j.memfd, 100, 0) == body
    with pytest.raises(OSError):
        os.pwrite(j.memfd, b'!', 0)                                      # sealed against writes (C-13)
    rig.deny(j.seq, 1)
    resp = cl.response()
    assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'recorded_deny']
    assert b'PH-1' not in resp.body and resp.body.startswith(b'engine refused POST https://auth.test/a/c\nreason: ')
    assert rig.report(timeout=0.3) is None                               # a refusal is the core's own; no REPORT (C-27)
    cl.close()


def test_sequence_numbers_increase_across_connections_and_never_repeat(rig: Rig) -> None:
    seen = []
    for _ in range(3):
        cl = rig.client()
        cl.request()
        j = rig.judge()
        assert j is not None
        seen.append(j.seq)
        rig.deny(j.seq, 2)
        assert cl.response().ended   # type: ignore[union-attr]
        cl.close()
    assert seen == [1, 2, 3]


# ---- C-32: nothing upstream before the allow ----
def test_no_resolution_and_no_connection_before_the_allow(rig: Rig) -> None:
    up = Upstream()
    cl = rig.client()
    cl.request(scheme=b'http', host=b'api.test', port=up.port)
    j = rig.judge()
    assert j is not None
    time.sleep(0.2)
    assert rig.policy.resolves == 0 and up.connections == 0
    rig.deny(j.seq, 4)
    assert cl.response().header(b'x-engine-reason') == [b'clause']   # type: ignore[union-attr]
    time.sleep(0.1)
    assert rig.policy.resolves == 0 and up.connections == 0
    up.close()
    cl.close()


# ---- C-15: the client leaving withdraws; C-14: an allow after that is zeroed and reported as not sent ----
def test_client_disconnect_while_waiting_sends_withdraw(rig: Rig) -> None:
    cl = rig.client()
    cl.request()
    j = rig.judge()
    assert j is not None
    cl.close()
    assert rig.withdraw() == j.seq
    assert rig.report(timeout=0.3) is None


def test_late_allow_is_zeroed_and_reported_not_sent(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[channel_mod.Answer] = []

    class Recorded(channel_mod.Answer):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            answers.append(self)

    monkeypatch.setattr(channel_mod, 'Answer', Recorded)
    cl = rig.client()
    cl.request()
    j = rig.judge()
    assert j is not None
    cl.close()
    assert rig.withdraw() == j.seq
    rig.allow(j.seq, truth=TRUTH)                                        # the core answered before it saw the withdraw
    assert rig.report() == (j.seq, c.RES_UNSENT, 0)
    assert rig.policy.resolves == 0
    assert len(answers) == 1 and answers[0].truth is None                # zeroed (truth dropped) at once
    assert rig.events('answer_without_waiter') == [{'event': 'answer_without_waiter', 'seq': j.seq, 'kind': c.ALLOW}]


def test_wait_timeout_withdraws_and_refuses(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_mod, 'WAIT_TIMEOUT', 0.5)
    cl = rig.client()
    cl.request()
    j = rig.judge()
    assert j is not None
    assert rig.withdraw() == j.seq
    resp = cl.response()
    assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'timeout']
    cl.request(path=b'/again')                                           # the connection stays usable
    j2 = rig.judge()
    assert j2 is not None and j2.seq == j.seq + 1
    rig.deny(j2.seq, 2)
    cl.close()


class _Channel:
    """What the wait uses of the core channel: taking the waiter back, withdrawing, reporting."""

    def __init__(self) -> None:
        self.withdrawn: list[int] = []
        self.reports: list[tuple[int, int]] = []

    def unregister(self, waiter: channel_mod.Waiter) -> channel_mod.Answer | None:
        return waiter.retire()

    def withdraw(self, seq: int) -> None:
        self.withdrawn.append(seq)

    def report(self, seq: int, result: int, status: int) -> None:
        self.reports.append((seq, result))


@pytest.mark.parametrize('late', ['before_the_wait', 'while_polling'])
def test_an_allow_in_after_the_total_limit_is_zeroed_and_never_sent(monkeypatch: pytest.MonkeyPatch, late: str) -> None:
    """C-15, C-14 (overall review 2026-11-03, #10): the request's one total limit runs from the hand-over to the core;
    an allow taken at or after it is late: zeroed, reported unsent, and the client refused as timed out."""
    channel = _Channel()
    session = object.__new__(session_mod.Session)
    near, far = socket.socketpair()
    session.c, session.sock = types.SimpleNamespace(channel=channel, stopping=False), near
    waiter = channel_mod.Waiter(7)
    truth = bytearray(b'sk-sentinel-truth')
    assert waiter.publish(channel_mod.Answer(c.ALLOW, c.PLACE_API_KEY, b'', truth, None, b'alice'))
    clock = iter([101.0] if late == 'before_the_wait' else [99.5, 101.0])
    monkeypatch.setattr(session_mod, 'time', types.SimpleNamespace(monotonic=lambda: next(clock, 101.0)))
    try:
        assert session._await(waiter, 100.0) == (None, 'timeout')
        assert channel.reports == [(7, c.RES_UNSENT)] and channel.withdrawn == [] and truth == bytes(len(truth))
    finally:
        waiter.close()
        near.close()
        far.close()


def test_deny_reasons_become_fixed_words(rig: Rig) -> None:
    words = {1: b'recorded_deny', 2: b'user_denied', 3: b'timeout', 4: b'clause', 5: b'unavailable', 6: b'not_authorized',
             7: b'pdp_denied', 8: b'policy_changed', 9: b'credential', 99: b'denied'}
    for reason, word in words.items():
        cl = rig.client()
        cl.request()
        j = rig.judge()
        assert j is not None
        rig.deny(j.seq, reason)
        resp = cl.response()
        assert resp is not None and resp.header(b'x-engine-reason') == [word] and resp.ended
        cl.close()


# ---- C-28: the port's kind table is closed in both directions ----
def allow_frame(*fields: bytes) -> bytes:
    """An ALLOW from its fields before the named one, naming nothing (plan engine-v3-private-net 接口约定)."""
    return c.pack_frame(c.ALLOW, [*fields, c.pack_list([])])


def raw_frame(kind: int, fields: list[bytes]) -> bytes:
    """A link B frame with exactly these fields, whatever the codec's count (the named field rides last)."""
    payload = c.u8(kind) + b''.join(c.u32(len(f)) + f for f in fields)
    return c.u32(len(payload)) + payload


@pytest.mark.parametrize('frame', [
    c.pack_frame(c.QUESTION, [b''] * c.FIELD_COUNT[c.QUESTION]),       # a link D kind
    c.pack_frame(c.JUDGE, [b''] * 13),                                  # the connector's own direction
    c.u32(6) + c.u8(c.DENY) + c.u32(1) + b'x',                          # DENY with one field: does not read
    # ALLOW whose shape is not its placement's (SPEC 3.2): a word on x-api-key, a bearer without its word or with
    # another word, a Basic without its password, a password on bearer, an empty truth, an unknown placement
    allow_frame(c.u64(1), c.u8(c.PLACE_API_KEY), b'Bearer', b't', b'', b'a'),
    allow_frame(c.u64(1), c.u8(c.PLACE_BEARER), b'', b't', b'', b'a'),
    allow_frame(c.u64(1), c.u8(c.PLACE_BEARER), b'Basic', b't', b'', b'a'),
    allow_frame(c.u64(1), c.u8(c.PLACE_BASIC), b'', b'u', b'', b'a'),
    allow_frame(c.u64(1), c.u8(c.PLACE_BEARER), b'Bearer', b't', b'p', b'a'),
    allow_frame(c.u64(1), c.u8(c.PLACE_API_KEY), b'', b'', b'', b'a'),
    allow_frame(c.u64(1), c.u8(4), b'', b't', b'', b'a'),
    c.u32(c.LIMITS.frame_bd + 1) + b'\x33',                              # over the link limit
])
def test_frame_not_on_the_port_ends_the_connector(rig: Rig, frame: bytes) -> None:
    rig.core.sendall(frame)
    deadline = time.monotonic() + 3
    while not rig.fatal and time.monotonic() < deadline:
        time.sleep(0.02)
    assert len(rig.fatal) == 1 and rig.connector.stopping
    assert rig.events('judgment_port_fatal')


def test_port_closed_by_the_core_ends_the_connector(rig: Rig) -> None:
    rig.core.close()
    deadline = time.monotonic() + 3
    while not rig.fatal and time.monotonic() < deadline:
        time.sleep(0.02)
    assert rig.fatal == ['judgment port closed']


# ---- K-59, C-28: the named field of ALLOW and ALLOW_NOCRED (plan engine-v3-private-net 接口约定) ----
NAMED = c.pack_list([b'10.0.0.5/32', b'fd12:3456::/48'])
BAD_NAMED = [
    pytest.param(b'10.0.0.5/32', id='not-a-list'), pytest.param(b'', id='empty-field'),
    pytest.param(c.pack_list([b'10.0.0.5/32']) + b'\x00', id='trailing-bytes'),
    pytest.param(c.pack_list([b'gitlab.corp']), id='host-name'), pytest.param(c.pack_list([b'10.0.0.5:80']), id='port'),
    pytest.param(c.pack_list([b'10.0.0.05/32']), id='leading-zero'), pytest.param(c.pack_list([b'10.0.0.5/24']), id='host-bits'),
    pytest.param(c.pack_list([b'10.0.0.5']), id='no-prefix-length'), pytest.param(c.pack_list([b'FD12::/16']), id='upper-case'),
    pytest.param(c.pack_list([b'fd12:0::/16']), id='not-rfc5952'), pytest.param(c.pack_list([b'10.0.0.0/08']), id='prefix-spelling'),
    pytest.param(c.pack_list([b'10.0.0.5/32\xff']), id='not-ascii'), pytest.param(c.pack_list([b'']), id='empty-item'),
    pytest.param(c.pack_list([b'10.0.%d.%d/32' % (i // 256, i % 256) for i in range(65)]), id='sixty-five-items'),
]


def named_frame(kind: int, seq: int, named: bytes) -> bytes:
    """ALLOW (bearer, account alice) or ALLOW_NOCRED with ``named`` as its last field."""
    if kind == c.ALLOW:
        return raw_frame(c.ALLOW, [c.u64(seq), c.u8(c.PLACE_BEARER), b'Bearer', b't', b'', b'alice', named])
    return raw_frame(c.ALLOW_NOCRED, [c.u64(seq), c.u8(0), named])


@pytest.mark.parametrize('kind', [c.ALLOW, c.ALLOW_NOCRED], ids=['allow', 'allow_nocred'])
def test_the_named_field_is_read_into_the_answer(rig: Rig, monkeypatch: pytest.MonkeyPatch, kind: int) -> None:
    """K-59: ALLOW reads its 7th field and ALLOW_NOCRED its 3rd into Answer.named, a tuple of networks (empty when
    nothing is named); an answer nobody waits for is read whole, then zeroed and reported not sent (C-14)."""
    answers: list[channel_mod.Answer] = []

    class Recorded(channel_mod.Answer):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            answers.append(self)

    monkeypatch.setattr(channel_mod, 'Answer', Recorded)
    rig.core.sendall(named_frame(kind, 999, NAMED))
    assert rig.report(timeout=3) == (999, c.RES_UNSENT, 0) and not rig.fatal
    rig.core.sendall(named_frame(kind, 1000, c.pack_list([])))
    assert rig.report(timeout=3) == (1000, c.RES_UNSENT, 0) and not rig.fatal
    assert [a.kind for a in answers] == [kind, kind] and all(isinstance(a.named, tuple) for a in answers)
    assert sorted(map(str, answers[0].named)) == ['10.0.0.5/32', 'fd12:3456::/48'] and answers[1].named == ()
    assert all(isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for n in answers[0].named)


@pytest.mark.parametrize('kind', [c.ALLOW, c.ALLOW_NOCRED], ids=['allow', 'allow_nocred'])
@pytest.mark.parametrize('named', BAD_NAMED)
def test_a_named_field_that_does_not_read_ends_the_connector(rig: Rig, kind: int, named: bytes) -> None:
    """C-28 (plan engine-v3-private-net): an ALLOW or ALLOW_NOCRED whose named field does not read (not a list, an item
    that is not exactly a canonical prefix text, more than 64 items) is a core protocol fault and the connector exits.
    Control first: the same frame with a field that reads is taken."""
    rig.core.sendall(named_frame(kind, 999, NAMED))
    assert rig.report(timeout=3) == (999, c.RES_UNSENT, 0) and not rig.fatal
    rig.core.sendall(named_frame(kind, 1000, named))
    deadline = time.monotonic() + 3
    while not rig.fatal and time.monotonic() < deadline:
        time.sleep(0.02)
    assert len(rig.fatal) == 1 and rig.connector.stopping and rig.events('judgment_port_fatal')
