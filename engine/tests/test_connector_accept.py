"""The connector's proxy port: accept-time checks and the link A reader (validation.md C-01, C-03, C-04, C-05, C-06, C-07).
Non-root: the sender is this process, whose uid the rig registers as the row's uid."""
from __future__ import annotations

import array
import os
import re
import socket
import time
from pathlib import Path

import pytest

from conftest import open_fds
from connector import canonical as c
from connector.session import Budget
from connector_rig import Rig

ENGINE = Path(__file__).resolve().parents[1]


# ---- C-01: PASSCRED is the spawner's, checked and never set ----
def test_accepted_socket_without_passcred_is_closed(rig: Rig, tmp_path: Path) -> None:
    bare = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bare.bind(str(tmp_path / 'bare.sock'))
    bare.listen(1)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(tmp_path / 'bare.sock'))
    accepted, _ = bare.accept()
    rig.connector._admit(accepted)
    client.settimeout(2)
    assert client.recv(1) == b''                                   # closed at accept, no session
    assert rig.events('connection_refused') == [{'event': 'connection_refused', 'why': 'no_passcred'}]
    assert accepted.fileno() == -1
    bare.close()
    client.close()


def test_connector_source_never_sets_passcred() -> None:
    for path in sorted((ENGINE / 'connector').glob('*.py')):
        text = path.read_text(encoding='utf-8')
        assert not re.search(r'setsockopt\([^)]*SO_PASSCRED', text), path.name


# ---- C-03: a descriptor on the proxy path ends the connection and is not kept ----
def test_descriptor_on_the_proxy_path_is_closed_and_the_connection_dropped(rig: Rig) -> None:
    before = open_fds()
    cl = rig.client()
    r, w = os.pipe()
    frame = c.pack_frame(c.REQUEST, [b'GET', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([]), b''])
    cl.sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [w]))])
    assert cl.eof()                                                # dropped without a response
    assert rig.judge(timeout=0.5) is None                          # and nothing reached the core
    os.close(r)
    os.close(w)
    cl.close()
    time.sleep(0.2)
    assert open_fds() <= before                                    # the received copy did not linger


# ---- C-04: one request per connection at a time; the 65th connection is closed ----
def test_second_request_is_not_read_before_the_response_ended(rig: Rig) -> None:
    cl = rig.client()
    cl.request(path=b'/one')
    cl.request(path=b'/two')
    first = rig.judge()
    assert first is not None and first.path == b'/one'
    assert rig.judge(timeout=0.5) is None                          # /two stays in the kernel buffer
    rig.deny(first.seq, 2)
    resp = cl.response()
    assert resp is not None and resp.category == c.CAT_REFUSED and resp.ended
    second = rig.judge()
    assert second is not None and second.path == b'/two' and second.seq == first.seq + 1
    rig.deny(second.seq, 2)
    assert cl.response().ended   # type: ignore[union-attr]
    cl.close()


def test_sixty_fifth_connection_is_closed_at_accept(rig: Rig) -> None:
    clients = [rig.client() for _ in range(64)]
    deadline = time.monotonic() + 5
    while len(rig.connector.sessions) < 64 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert len(rig.connector.sessions) == 64
    extra = rig.client()
    assert extra.eof()
    assert rig.connector.refused_connections == 1
    for cl in clients:
        cl.close()
    extra.close()


# ---- C-05 / C-06: a frame that does not read, or a kind not on this link, ends the connection before the core ----
@pytest.mark.parametrize('fields', [
    [b'GET', b'https', b'API.TEST', c.u16(443), b'/', b'', c.pack_list([]), b''],            # upper-case host
    [b'GET', b'https', b'api.test', c.u16(443), b'/a/../..%2f', b'', c.pack_list([]), b''],  # encoded slash
    [b'GET', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([b'host', b'x']), b''],       # forbidden header
    [b'GET', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([b'authorization', b'a', b'authorization', b'b']), b''],
    [b'CONNECT', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([]), b''],
    [b'connect', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([]), b''],      # C-05 in any case
    [b'TRACE', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([b'x-api-key', b'sk-w2-placeholder']), b''],
    [b'trace', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([]), b''],        # C-34 in any case
    [b'TRACK', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([b'x-api-key', b'sk-w2-placeholder']), b''],
    [b'GET', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([])],                 # seven fields
])
def test_request_that_does_not_read_drops_the_connection_without_a_judge(rig: Rig, fields: list[bytes]) -> None:
    """C-05, C-36: a whole frame whose fields do not read, the wrong number of them included, never reaches the core;
    the client gets the refusal with the word clause and no echo of the fields, then the connection ends."""
    cl = rig.client()
    payload = c.u8(c.REQUEST) + b''.join(c.u32(len(f)) + f for f in fields)
    cl.raw(c.u32(len(payload)) + payload)
    resp = cl.response()
    assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
    assert resp.body.startswith(b'engine refused a request that does not read\nreason: clause\n') and resp.ended
    assert cl.eof()
    assert rig.judge(timeout=0.5) is None
    cl.close()


def test_kind_not_on_link_a_drops_the_connection(rig: Rig) -> None:
    cl = rig.client()
    cl.raw(c.pack_frame(c.RESP_END, []))                             # the connector's own direction
    assert cl.eof()
    cl2 = rig.client()
    cl2.raw(c.pack_frame(c.JUDGE, [b''] * 13))                        # a link B kind
    assert cl2.eof()
    assert rig.judge(timeout=0.3) is None
    cl.close()
    cl2.close()


# ---- C-07: limits at the reader ----
def test_frame_over_the_link_limit_is_refused_at_its_header(rig: Rig) -> None:
    cl = rig.client()
    cl.raw(c.u32(c.LIMITS.frame_a + 1) + b'\x01')
    assert cl.eof()
    cl.close()


def test_body_over_the_row_budget_is_refused_before_it_is_read(rig: Rig) -> None:
    rig.connector.budget = Budget(1000)
    cl = rig.client()
    cl.request(method=b'POST', body=b'x' * 2000)
    assert cl.eof()
    assert rig.judge(timeout=0.3) is None
    assert rig.connector.budget.used == 0
    ok = rig.client()
    ok.request(method=b'POST', body=b'x' * 500)
    j = rig.judge()
    assert j is not None and j.body_len == 500
    frame = c.pack_frame(c.REQUEST, [b'POST', b'https', b'api.test', c.u16(443), b'/', b'', c.pack_list([]), b'x' * 500])
    assert rig.connector.budget.used == len(frame) - 4            # the whole declared frame is charged while in flight
    rig.deny(j.seq, 2)
    assert ok.response().ended   # type: ignore[union-attr]
    time.sleep(0.1)
    assert rig.connector.budget.used == 0
    cl.close()
    ok.close()


# ---- C-35 (648d60f2 5.3 条款 7): an IP literal is judged at validation, before the core ----
# Since plan engine-v3-private-net only the first gate (never connect, named or not) is asked there: a non-global
# literal outside it goes to the core, whose first checkpoint looks for a name (K-58); the connect-time gates follow.
@pytest.mark.parametrize('host, judged', [(b'10.0.0.1', True), (b'127.0.0.1', False), (b'::1', False),
                                          (b'64:ff9b::a00:1', False), (b'8.8.8.8', True), (b'api.test', True),
                                          (b'fd12::1', True), (b'100.64.0.1', True)])
def test_an_ip_literal_is_judged_before_the_core(library: Path, tmp_path: Path, ca, host: bytes, judged: bool) -> None:
    from connector import upstream as up
    from connector_rig import Rig
    resolved: list[str] = []
    policy = up.Policy(include_interfaces=False, resolver=lambda h, p: resolved.append(h) or ['93.184.215.14'])
    rig = Rig(tmp_path, library, ca, policy=policy)
    try:
        cl = rig.client()
        cl.request(host=host, scheme=b'http', port=80)
        if judged:
            assert rig.judge() is not None and resolved == []          # a host name is not resolved before the allow
        else:
            resp = cl.response()
            assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
            assert rig.judge(timeout=0.5) is None and cl.eof()
        cl.close()
    finally:
        rig.close()


@pytest.mark.parametrize('host', ['169.254.169.254', 'fe80::1', '127.0.0.2', '0.0.0.0', '::', '::7f00:1',
                                  '100.100.100.200', 'interface', '2001:db8:64::a9fe:a9fe', '224.0.0.1',
                                  '255.255.255.255', '::ffff:127.0.0.1', '64:ff9b::a9fe:a9fe'])
def test_a_never_connect_literal_is_refused_at_validation(library: Path, tmp_path: Path, ca, host: str) -> None:
    """C-35, C-36 (plan engine-v3-private-net): a literal in the first gate (link-local, loopback, unspecified, ::/96,
    the deployer's list, a host interface address, a configured NAT64 prefix embedding link-local, multicast, limited
    broadcast) is refused with clause before the core, which never gets a JUDGE; the mapped and 64:ff9b spellings are
    refused there already by the grammar."""
    from connector import upstream as up
    from test_connector_upstream import DEPLOYED, never
    host, _ = never(host, ())
    resolved: list[str] = []
    rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: resolved.append(h) or [], **DEPLOYED))
    try:
        cl = rig.client()
        cl.request(host=host.encode(), scheme=b'http', port=80)
        resp = cl.response()
        assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
        assert rig.judge(timeout=0.5) is None and cl.eof() and resolved == []
        cl.close()
    finally:
        rig.close()


@pytest.mark.parametrize('host, judged', [(b'2a00:64::a00:5', False), (b'fd00:64::a00:5', False), (b'10.0.0.5', True)],
                         ids=['global-prefix', 'ula-prefix', 'control-10.0.0.5'])
def test_a_literal_under_a_configured_nat64_prefix_is_refused_at_validation(library: Path, tmp_path: Path, ca,
                                                                              host: bytes, judged: bool) -> None:
    """C-35, C-36, K-58 (plan engine-v3-private-net 点名 9, user ruling 2026-11-05): an IP literal under a deployer's
    NAT64 prefix (--nat64-prefix), globally reachable (2a00:64::/96) or a ULA (fd00:64::/96), is refused at validation
    with clause, as the grammar refuses 64:ff9b::/96, and the connection ends with a reason that says to write the IPv4
    address: the core never gets a JUDGE, so it never judges as written what the connector judges by the embedded
    10.0.0.5. Control: the plain literal 10.0.0.5 still goes to the core, whose first checkpoint looks for its name."""
    from connector import upstream as up
    resolved: list[str] = []
    policy = up.Policy(include_interfaces=False, nat64=['2a00:64::/96', 'fd00:64::/96'],
                       resolver=lambda h, p: resolved.append(h) or [])
    rig = Rig(tmp_path, library, ca, policy=policy)
    try:
        cl = rig.client()
        cl.request(host=host, scheme=b'http', port=80)
        if judged:
            assert rig.judge() is not None
        else:
            assert rig.judge(timeout=1.0) is None, 'the literal reached the core'
            resp = cl.response()
            assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
            assert cl.eof() and any('IPv4' in e['reason'] for e in rig.events('connection_closed'))
        assert resolved == []
        cl.close()
    finally:
        rig.close()
