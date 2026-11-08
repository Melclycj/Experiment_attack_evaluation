"""条款 7, the per-connection local probe fails closed (validation.md C-19, C-35; plan engine-v3-private-net 点名 10, user
2026-11-05; second-round cold review, minor 2). The probe asks whether an address is this host's right now by
connecting an unsent UDP socket to it. When the probe socket itself cannot be made (descriptors run out: EMFILE,
ENFILE, ENOBUFS), the address counts as this host's and the request is refused with clause; only a probe whose
connect() fails (no route) says that the address is not this host's, and so does an address family the host does not
support (EAFNOSUPPORT: it holds no address of that family and makes no TCP socket of it either). socket.socket is
replaced for the test, so the check does not depend on the module the probe lives in."""
from __future__ import annotations

import errno
import ipaddress
import socket
from pathlib import Path

import pytest

from connector import canonical as c
from connector import upstream as up
from connector_rig import CA, Redirect, Rig, Upstream
from test_connector_upstream import allowed_exchange

ADDRESS = '10.0.0.5'                                     # non-global, named below: only the probe can refuse it
NAMED = (ipaddress.ip_network('10.0.0.5/32'),)


def break_the_probe(monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    """Replace socket.socket (whatever it is now, the rig's Redirect included) by a subclass whose SOCK_DGRAM sockets
    fail: 'socket' at creation with EMFILE, 'family' at creation of an AF_INET6 one with EAFNOSUPPORT, 'connect' at
    connect() with ENETUNREACH. Every other socket is made and connected as before."""
    base = socket.socket

    class Broken(base):  # type: ignore[valid-type, misc]
        def __init__(self, family: int = -1, type: int = -1, proto: int = -1, fileno: int | None = None) -> None:
            if how == 'socket' and type == socket.SOCK_DGRAM:
                raise OSError(errno.EMFILE, 'Too many open files (the test)')
            if how == 'family' and type == socket.SOCK_DGRAM and family == socket.AF_INET6:
                raise OSError(errno.EAFNOSUPPORT, 'Address family not supported by protocol (the test)')
            super().__init__(family, type, proto, fileno)

        def connect(self, address: tuple) -> None:
            if how == 'connect' and self.type == socket.SOCK_DGRAM:
                raise OSError(errno.ENETUNREACH, 'Network is unreachable (the test)')
            return super().connect(address)

    monkeypatch.setattr(socket, 'socket', Broken)


@pytest.mark.parametrize('how, word, never', [
    ('socket', b'clause', True),                         # the probe cannot be made: this host's, refused
    ('connect', None, False),                            # no route: not this host's, as before
    ('none', None, False),                               # positive control: the probe runs as it is
], ids=['socket-fails', 'connect-fails', 'normal'])
def test_a_probe_that_cannot_be_made_counts_as_this_hosts(monkeypatch: pytest.MonkeyPatch, how: str,
                                                          word: bytes | None, never: bool) -> None:
    """C-19 gate one, the probe: a real Policy, nothing denied and no interface enumerated, so only the probe can
    refuse. A named private address and a global one are refused with clause when the probe socket cannot be made;
    a probe whose connect() fails, and a normal probe, let both pass. The literal check at validation (C-35,
    Policy.never_connect) follows the same probe."""
    policy = up.Policy(include_interfaces=False)
    if how != 'none':
        break_the_probe(monkeypatch, how)
    assert policy.refusal([ADDRESS], NAMED) == word
    assert policy.refusal(['8.8.8.8']) == word
    assert policy.never_connect(ADDRESS) is never


def test_an_unsupported_family_is_not_this_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    """C-19, the one exception to failing closed: a host without IPv6 support cannot make an AF_INET6 probe socket
    (EAFNOSUPPORT). It holds no IPv6 address and cannot connect to one either, so the address is not this host's: a
    named non-global IPv6 address and a global one pass, and the IPv4 probe runs as before."""
    policy = up.Policy(include_interfaces=False)
    break_the_probe(monkeypatch, 'family')
    assert up.is_local_address('fd12::5') is False and up.is_local_address('2001:4860:4860::8888') is False
    assert policy.refusal(['fd12::5'], (ipaddress.ip_network('fd12::/64'),)) is None
    assert policy.refusal(['2001:4860:4860::8888']) is None
    assert not policy.never_connect('fd12::5') and not policy.never_connect('2001:4860:4860::8888')
    assert policy.refusal([ADDRESS], NAMED) is None


@pytest.mark.parametrize('broken', [True, False], ids=['socket-fails', 'normal'])
def test_no_connection_when_the_probe_cannot_be_made(tmp_path: Path, library: Path, ca: CA,
                                                     monkeypatch: pytest.MonkeyPatch, broken: bool) -> None:
    """C-19 through the connector: the ALLOW names 10.0.0.5/32 and the name resolves to it. With the probe socket
    failing, nothing is connected, the request is refused with clause and REPORT says not sent. Normal, it is
    connected and answered."""
    upstream = Upstream()
    redirect = Redirect(monkeypatch, {ADDRESS: upstream.port})
    rig = Rig(tmp_path, library, ca, policy=up.Policy(include_interfaces=False, resolver=lambda h, p: [ADDRESS]))
    if broken:
        break_the_probe(monkeypatch, 'socket')
    try:
        j, resp, report = allowed_exchange(rig, upstream, nocred=True, scheme=b'http', named=(ADDRESS + '/32',))
        assert resp is not None
        if broken:
            assert redirect.attempts == [] and upstream.connections == 0 and not upstream.requests
            assert resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
            assert report == (j.seq, c.RES_UNSENT, 0)
        else:
            assert redirect.attempts == [ADDRESS] and upstream.connections == 1
            assert (resp.category, resp.status, resp.body) == (c.CAT_REMOTE, 200, b'ok')
            assert report == (j.seq, c.RES_REMOTE, 200)
    finally:
        rig.close()
        upstream.close()
