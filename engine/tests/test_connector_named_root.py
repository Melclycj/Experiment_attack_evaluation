"""Named non-global destinations over a real network path (validation.md C-19, C-37, R-14; plan engine-v3-private-net,
新 root 测试). Two fresh network namespaces joined by a veth pair: the connector (the rig with the real Policy and a stub
resolver) runs in the near one, receivers listen in the far one, and decoys listen where the connector must never
connect even when the ALLOW names them: link-local metadata, an address on --deny-address, the near side's own veth
address, the loopback range and the IPv4-compatible range. Every receiver counts the connections it accepts; a positive
control first shows each one reachable from the connector's side. Needs root. The root namespace's network is not
touched: the two namespaces are anonymous, held only by this process's descriptors and sockets, and vanish with them."""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from connector import canonical as c
from connector import upstream as up
from connector_rig import CA, Client, Rig, Upstream, simple_reply
from test_connector_root import ROW_UID, send_as

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='builds network namespaces')

IP = shutil.which('ip') or '/usr/sbin/ip'
PORT = 80
DENIED = '100.100.100.200'                                   # the deployer's list (--deny-address)
FAR = ('10.99.0.2', '10.99.0.3', '169.254.169.254', DENIED, '::7f00:1')
NEAR = ('10.99.0.1', '127.0.0.2')                           # the connector's own side
RESOLVE = {'named.test': ['10.99.0.2'], 'unnamed.test': ['10.99.0.3'], 'mixed.test': ['10.99.0.2', '10.99.0.3'],
           'metadata.test': ['169.254.169.254'], 'cloud.test': [DENIED], 'own.test': ['10.99.0.1'],
           'loop.test': ['127.0.0.2'], 'compat.test': ['::7f00:1']}


@contextmanager
def inside(ns: int) -> Iterator[None]:
    """The calling thread in network namespace ``ns`` for the block. Sockets made meanwhile live there for good, and
    so do threads started meanwhile (the rig's connector threads, a receiver's accept thread)."""
    home = os.open('/proc/thread-self/ns/net', os.O_RDONLY)
    os.setns(ns, os.CLONE_NEWNET)
    try:
        yield
    finally:
        os.setns(home, os.CLONE_NEWNET)
        os.close(home)


def fresh_namespace() -> int:
    """A new, empty network namespace held by the returned descriptor; the calling thread is moved back at once."""
    home = os.open('/proc/thread-self/ns/net', os.O_RDONLY)
    try:
        os.unshare(os.CLONE_NEWNET)
        try:
            return os.open('/proc/thread-self/ns/net', os.O_RDONLY)
        finally:
            os.setns(home, os.CLONE_NEWNET)
    finally:
        os.close(home)


def configure(*commands: tuple[str, ...]) -> None:
    """``ip`` commands, run in the calling thread's namespace (a child inherits it). DAD is off so that addresses are
    usable at once (the sysctl is per namespace, written from inside it)."""
    for name in ('all', 'default'):
        Path(f'/proc/sys/net/ipv6/conf/{name}/accept_dad').write_text('0')
    for cmd in commands:
        subprocess.run([IP, *cmd], check=True, capture_output=True)


@dataclass
class Net:
    near: int
    far: int
    receivers: dict[str, Upstream]

    def counts(self) -> dict[str, int]:
        return {a: r.connections for a, r in self.receivers.items()}


@pytest.fixture(scope='module')
def net() -> Iterator[Net]:
    home = os.readlink('/proc/thread-self/ns/net')
    near, far = fresh_namespace(), fresh_namespace()
    receivers: dict[str, Upstream] = {}
    try:
        with inside(near):
            configure(('link', 'set', 'lo', 'up'),
                      ('link', 'add', 'pnnear', 'type', 'veth', 'peer', 'name', 'pnfar', 'netns', f'/proc/{os.getpid()}/fd/{far}'))
        with inside(far):
            configure(('link', 'set', 'lo', 'up'), *(('addr', 'add', a + ('/24' if a.startswith('10.') else '/32'), 'dev', 'pnfar')
                                                     for a in FAR if ':' not in a),
                      ('-6', 'addr', 'add', 'fd99::2/64', 'dev', 'pnfar', 'nodad'),
                      ('-6', 'addr', 'add', '::7f00:1/128', 'dev', 'pnfar', 'nodad'), ('link', 'set', 'dev', 'pnfar', 'up'))
            for a in FAR:
                receivers[a] = Upstream(reply=simple_reply(a.encode()), port=PORT, host=a)
        with inside(near):
            configure(('addr', 'add', '10.99.0.1/24', 'dev', 'pnnear'), ('-6', 'addr', 'add', 'fd99::1/64', 'dev', 'pnnear', 'nodad'),
                      ('link', 'set', 'dev', 'pnnear', 'up'), ('route', 'add', '169.254.169.254/32', 'dev', 'pnnear'),
                      ('route', 'add', DENIED + '/32', 'dev', 'pnnear'),
                      ('-6', 'route', 'add', '::7f00:1/128', 'via', 'fd99::2', 'dev', 'pnnear'))
            for a in NEAR:
                receivers[a] = Upstream(reply=simple_reply(a.encode()), port=PORT, host=a)
            for a in receivers:                    # positive control: every receiver answers the connector's side
                socket.create_connection((a, PORT), timeout=5).close()
        deadline = time.monotonic() + 5
        while any(n != 1 for n in Net(near, far, receivers).counts().values()) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert Net(near, far, receivers).counts() == {a: 1 for a in receivers}
        yield Net(near, far, receivers)
    finally:
        for r in receivers.values():
            r.close()
        os.close(near)
        os.close(far)
        assert os.readlink('/proc/thread-self/ns/net') == home


def connector(tmp_path: Path, library: Path, ca: CA) -> Rig:
    """The rig in the calling thread's namespace with the real Policy and the stub resolver; the row's uid is not root,
    whose messages the proxy port refuses (C-02), so requests are written by send_as."""
    rig = Rig(tmp_path, library, ca, policy=up.Policy(denied=[DENIED], resolver=lambda h, p: list(RESOLVE[h])))
    rig.connector.uid = ROW_UID
    return rig


def request(cl: Client, host: bytes) -> None:
    send_as(cl.sock, ROW_UID, c.pack_frame(c.REQUEST, [b'GET', b'http', host, c.u16(PORT), b'/', b'', c.pack_list([]), b'']))


def exchange(net: Net, library: Path, tmp_path: Path, ca: CA, host: bytes, named: tuple[str, ...]):
    """One plain-http request from the near namespace, the test playing the core: ALLOW_NOCRED naming ``named``.
    Returns (judge, response, report); judge is None when the request never reached the core."""
    with inside(net.near):
        rig = connector(tmp_path, library, ca)
        try:
            cl = rig.client()
            request(cl, host)
            j = rig.judge()
            if j is None:
                return None, cl.response(timeout=1), None
            rig.allow_nocred(j.seq, named=named)
            resp, report = cl.response(), rig.report()
            cl.close()
            return j, resp, report
        finally:
            rig.close()


def settled(net: Net, before: dict[str, int]) -> dict[str, int]:
    time.sleep(0.3)                                # an accept that should not happen has had its chance
    return {a: n - before[a] for a, n in net.counts().items()}


@pytest.mark.parametrize('host, named', [(b'named.test', ('10.99.0.2/32',)), (b'10.99.0.2', ('10.99.0.0/24',))],
                         ids=['name', 'ip-literal'])
def test_a_named_private_destination_is_connected(net: Net, library: Path, tmp_path: Path, ca: CA, host: bytes,
                                                  named: tuple[str, ...]) -> None:
    """C-19, C-35: 10.99.0.2 named by the covering cell is connected, as a name and as an IP literal (which reaches the
    core); one connection at that receiver and none anywhere else."""
    before = net.counts()
    j, resp, report = exchange(net, library, tmp_path, ca, host, named)
    assert j is not None, 'the request never reached the core'
    assert resp is not None and (resp.category, resp.status, resp.body) == (c.CAT_REMOTE, 200, b'10.99.0.2')
    assert report == (j.seq, c.RES_REMOTE, 200)
    assert settled(net, before) == {a: int(a == '10.99.0.2') for a in net.receivers}


@pytest.mark.parametrize('host, named, word', [
    pytest.param(b'unnamed.test', ('10.99.0.2/32',), b'not_authorized', id='10.99.0.3-not-named'),
    pytest.param(b'mixed.test', ('10.99.0.2/32',), b'not_authorized', id='one-named-one-not'),
    pytest.param(b'metadata.test', ('169.254.0.0/16',), b'clause', id='169.254.169.254-named'),
    pytest.param(b'cloud.test', (DENIED + '/32',), b'clause', id='deny-address-named'),
    pytest.param(b'own.test', ('10.99.0.0/24',), b'clause', id='own-veth-10.99.0.1-named'),
    pytest.param(b'loop.test', ('127.0.0.0/8',), b'clause', id='127.0.0.2-named'),
    pytest.param(b'compat.test', ('::/96',), b'clause', id='::7f00:1-named'),
])
def test_a_refused_destination_gets_no_connection(net: Net, library: Path, tmp_path: Path, ca: CA, host: bytes,
                                                  named: tuple[str, ...], word: bytes) -> None:
    """C-19, R-14: an unnamed private address, or a list holding one, is not_authorized; a never-connect address (the
    ALLOW naming it is a core error) is clause; in every case no receiver, reachable as the control showed, gets a
    connection."""
    before = net.counts()
    j, resp, report = exchange(net, library, tmp_path, ca, host, named)
    assert settled(net, before) == {a: 0 for a in net.receivers}
    assert j is not None and resp is not None and resp.category == c.CAT_REFUSED
    assert report == (j.seq, c.RES_UNSENT, 0)
    assert resp.header(b'x-engine-reason') == [word]


def test_a_retained_connection_is_reused_only_while_its_peer_is_named(net: Net, library: Path, tmp_path: Path,
                                                                      ca: CA) -> None:
    """C-37 over the real path: two requests named 10.99.0.2 share one connection; a third whose ALLOW names nothing
    is not_authorized, and the kept connection carries no byte of it."""
    receiver = net.receivers['10.99.0.2']
    before, requests = net.counts(), len(receiver.requests)
    with inside(net.near):
        rig = connector(tmp_path, library, ca)
        try:
            cl = rig.client()

            def one(named: tuple[str, ...]):
                request(cl, b'named.test')
                j = rig.judge()
                assert j is not None
                rig.allow_nocred(j.seq, named=named)
                resp = cl.response()
                assert resp is not None
                return resp, rig.report(), j.seq

            for named in (('10.99.0.2/32',), ('10.99.0.0/24',)):          # named: one connection, kept and reused
                resp, report, seq = one(named)
                assert (resp.status, resp.body, report) == (200, b'10.99.0.2', (seq, c.RES_REMOTE, 200))
            index = receiver.requests[-1].connection
            assert [r.connection for r in receiver.requests[requests:]] == [index, index]
            sent = receiver.received_bytes[index]
            resp, report, seq = one(())                                    # nothing named: the kept one is not used
            assert resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'not_authorized']
            assert report == (seq, c.RES_UNSENT, 0)
            cl.close()
        finally:
            rig.close()
    assert settled(net, before) == {a: int(a == '10.99.0.2') for a in net.receivers}
    assert len(receiver.requests) == requests + 2 and receiver.received_bytes[index] == sent


FLIP = '10.98.0.9'                     # routed out through a dummy device, which drops every SYN


def test_a_destination_that_turns_local_while_connecting_gets_no_byte(library: Path, tmp_path: Path, ca: CA) -> None:
    """C-19, N-15 (plan engine-v3-private-net 点名 9; the scratch measurement of 2026-11-05 redone as a test). In a
    fresh namespace of its own the connector's side routes 10.98.0.9 out through a dummy device, so every SYN to it is
    dropped; a listener on 0.0.0.0:80 there stands for a service of this host. The ALLOW names 10.98.0.9, both gates
    pass and connect() starts; 1.5 s in, 10.98.0.9 is added to the namespace's lo, and the next SYN the kernel resends
    is routed to the listener. The handshake ends there (the declared residual: one connection), but the connected peer
    is judged again before any byte: the listener reads zero bytes, the request is refused with clause, REPORT not
    sent."""
    ns = fresh_namespace()
    local: Upstream | None = None
    try:
        with inside(ns):
            configure(('link', 'set', 'lo', 'up'), ('link', 'add', 'pnflip', 'type', 'dummy'),
                      ('addr', 'add', '10.98.0.1/24', 'dev', 'pnflip'), ('link', 'set', 'dev', 'pnflip', 'up'))
            local = Upstream(reply=simple_reply(b'host-local service'), port=PORT, host='0.0.0.0')
            rig = Rig(tmp_path, library, ca, policy=up.Policy(resolver=lambda h, p: [FLIP]), connect_timeout=10.0)
            rig.connector.uid = ROW_UID
            try:
                assert not up.is_local_address(FLIP)
                cl = rig.client()
                request(cl, b'flip.test')
                j = rig.judge()
                assert j is not None
                # started in this namespace, so the timer thread and the ip it runs act on it
                flip = threading.Timer(1.5, configure, args=(('addr', 'add', FLIP + '/32', 'dev', 'lo'),))
                flip.start()
                rig.allow_nocred(j.seq, named=(FLIP + '/32',))
                resp, report = cl.response(timeout=15), rig.report(timeout=15)
                flip.join()
                cl.close()
            finally:
                rig.close()
            time.sleep(0.3)                    # bytes sent have had their chance to arrive
            assert up.is_local_address(FLIP)
        assert sum(local.received_bytes.values()) == 0 and not local.requests, 'the local service read the request'
        assert local.connections == 1                                # the handshake itself reached it (N-15)
        assert resp is not None and resp.category == c.CAT_REFUSED and resp.header(b'x-engine-reason') == [b'clause']
        assert report == (j.seq, c.RES_UNSENT, 0)
    finally:
        if local is not None:
            local.close()
        os.close(ns)
