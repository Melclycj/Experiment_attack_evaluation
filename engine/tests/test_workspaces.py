"""Workspace entry table and its mirror (validation.md K-05, K-08, K-13, K-14, K-17, K-18, K-19, K-20, K-29; named
non-global addresses, K-57, plan engine-v3-private-net)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from engine import workspaces as w
from engine.workspaces import (Approval, Disk, Entry, EntryInvalid, EntryState, KeyKind, WorkspaceStore,
                               WorkspaceUnavailable, make_entry, narrows)


def allow(key: str, methods=('GET',), prefixes=(), accounts=(), approval=Approval.NEVER, kind=KeyKind.EXACT) -> Entry:
    return make_entry(kind, key, EntryState.ALLOW, methods, prefixes, accounts, approval)


def deny(key: str, methods=(), prefixes=(), kind=KeyKind.EXACT) -> Entry:
    return make_entry(kind, key, EntryState.DENY, methods, prefixes, (), Approval.NEVER)


def named(key: str, addresses, methods=('GET',), prefixes=(), kind=KeyKind.EXACT, state=EntryState.ALLOW) -> Entry:
    """An entry whose sixth field names non-global addresses (plan engine-v3-private-net; validation.md K-57)."""
    return make_entry(kind, key, state, methods, prefixes, (), Approval.NEVER, addresses=addresses)


# ---- K-05 / K-29: the entry schema is closed and validated with the connector's grammar --------------------------------
def test_entry_fields_are_validated_like_requests() -> None:
    e = allow('api.github.com:443', ('GET', 'POST'), ('/repos/a/', '/a/../b'), ('alice',))
    assert e.key == 'api.github.com:443' and e.prefixes == ('/repos/a', '/b') and e.accounts == {'alice'}
    with pytest.raises(EntryInvalid):
        allow('API.github.com:443')                        # upper case host
    with pytest.raises(EntryInvalid):
        allow('api.github.com')                            # no port
    with pytest.raises(EntryInvalid):
        allow('api.github.com:0')
    with pytest.raises(EntryInvalid):
        allow('api.github.com:443', prefixes=('/u/a%40b',))   # encoded literal byte: never matches a request
    with pytest.raises(EntryInvalid):
        allow('api.github.com:443', prefixes=('repos',))      # no leading slash
    with pytest.raises(EntryInvalid):
        allow('api.github.com:443', methods=('GE T',))
    with pytest.raises(EntryInvalid):
        allow('api.github.com:443', methods=('CONNECT',))
    for trace in ('connect', 'TRACE', 'trace', 'TRACK', 'track'):   # C-05, C-34: no entry allows what the reader refuses
        with pytest.raises(EntryInvalid):
            allow('api.github.com:443', methods=(trace,))
    with pytest.raises(EntryInvalid):
        allow('api.github.com:443', accounts=('a/b',))
    with pytest.raises(EntryInvalid):
        make_entry(9, 'x', 1, (), (), (), 1)


def test_pattern_entries_carry_no_accounts_and_fallback_key_is_empty() -> None:
    p = allow('*.wikipedia.org:443', kind=KeyKind.PATTERN)
    assert p.key == 'wikipedia.org:443'
    with pytest.raises(EntryInvalid):                      # 条款 5 / K-29
        allow('wikipedia.org:443', accounts=('alice',), kind=KeyKind.PATTERN)
    with pytest.raises(EntryInvalid):
        allow('10.0.0.1:443', kind=KeyKind.PATTERN)       # an IP literal is no suffix
    with pytest.raises(EntryInvalid):
        allow('x', kind=KeyKind.FALLBACK)
    assert allow('', kind=KeyKind.FALLBACK).identity == (KeyKind.FALLBACK, '')
    with pytest.raises(EntryInvalid):
        make_entry(KeyKind.EXACT, 'h:443', EntryState.DENY, (), (), ('alice',), Approval.NEVER)


def test_mirror_entry_roundtrip_and_rejects_foreign_keys() -> None:
    e = allow('api.github.com:443', ('GET',), ('/repos',), ('alice',), Approval.ALWAYS)
    assert w.entry_from_json(json.loads(json.dumps(w.entry_to_json(e)))) == e
    bad = w.entry_to_json(e)
    bad['extra'] = 1
    with pytest.raises(EntryInvalid):
        w.entry_from_json(bad)
    with pytest.raises(EntryInvalid):
        w.entry_from_json({**w.entry_to_json(e), 'methods': 'GET'})
    with pytest.raises(EntryInvalid):
        w.entry_from_json({**w.entry_to_json(e), 'state': True})


# ---- K-18 classification --------------------------------------------------------------------------------------------
def test_narrowing_classification() -> None:
    old = allow('h:443', ('GET', 'POST'), ('/a', '/b'), ('alice', 'bob'), Approval.NEVER)
    assert narrows(old, deny('h:443'))                                       # deny
    assert narrows(old, None)                                                # delete an allow
    assert narrows(old, allow('h:443', ('GET',), ('/a',), ('alice',), Approval.ALWAYS))   # strict subset, asks more
    assert not narrows(old, allow('h:443', ('GET', 'POST', 'DELETE'), ('/a', '/b'), ('alice', 'bob')))
    assert not narrows(old, allow('h:443', ('GET',), (), ('alice',)))        # prefixes any = wider
    assert not narrows(old, allow('h:443', ('GET',), ('/a',), ('carol',)))   # a new account
    assert not narrows(None, allow('h:443'))                                 # a new allow
    assert not narrows(deny('h:443'), allow('h:443'))                        # deny -> allow
    assert not narrows(deny('h:443'), None)                                  # deleting a deny removes a refusal


def test_naming_fewer_addresses_narrows_and_naming_any_other_relaxes() -> None:
    """K-18 (plan engine-v3-private-net): the named set counts as narrowing only when it only shrinks; any item added,
    a swap, or a prefix replaced by another prefix (even one inside it) relaxes. Read as sets of stored texts."""
    old = named('gitlab.corp:443', ('10.0.0.0/8', 'fd12:3456::/48'))
    assert narrows(old, named('gitlab.corp:443', ('10.0.0.0/8',)))
    assert narrows(old, named('gitlab.corp:443', ()))
    assert narrows(old, named('gitlab.corp:443', ('fd12:3456::/48', '10.0.0.0/8')))          # the same set
    assert narrows(old, named('gitlab.corp:443', ('10.0.0.0/8',), methods=('GET',), prefixes=('/api',)))
    assert not narrows(old, named('gitlab.corp:443', ('10.0.0.0/8', 'fd12:3456::/48', '192.168.0.0/16')))
    assert not narrows(old, named('gitlab.corp:443', ('10.0.0.0/8', '192.168.0.0/16')))       # one out, one in
    assert not narrows(named('gitlab.corp:443', ()), named('gitlab.corp:443', ('10.0.0.5',)))
    assert not narrows(named('gitlab.corp:443', ('10.0.0.0/24',)), named('gitlab.corp:443', ('10.0.0.0/8',)))
    assert not narrows(named('gitlab.corp:443', ('10.0.0.0/8',)), named('gitlab.corp:443', ('10.0.0.0/24',)))


@pytest.mark.parametrize('fewer', [True, False])
def test_an_address_change_that_does_not_persist_applies_only_when_it_narrows(tmp_path: Path, fewer: bool) -> None:
    """K-18 at the store: a write that fails before the rename applies in memory and blocks spawns when the named set
    only shrank, and does not apply when an address was added."""
    store = fresh_store(tmp_path)
    old = named('gitlab.corp:443', ('10.0.0.0/8', 'fd12:3456::/48'))
    assert store.put('work0', old).persisted
    store.disk = FailingDisk('rename')
    new = named('gitlab.corp:443', ('10.0.0.0/8',) if fewer else ('10.0.0.0/8', 'fd12:3456::/48', '192.168.0.0/16'))
    r = store.put('work0', new)
    assert not r.persisted and r.applied is fewer
    assert store.tables['work0'].entries[new.identity] == (new if fewer else old)
    assert store.tables['work0'].spawn_blocked is fewer


# ---- K-57: the sixth field, named non-global addresses (plan engine-v3-private-net) ------------------------------------
NOT_NAMEABLE = [
    # not a strict address or prefix: host names, a port, a zone, host bits, brackets, blanks, out of range
    'gitlab.corp', 'gitlab.corp:443', '10.0.0.5:80', 'fe80::1%eth0', 'fd12:3456::1%eth0', 'fd12:3456::1%1',
    '10.0.0.5/24', '1.2.3.4/0', '[fd12::1]', '', ' 10.0.0.5', '10.0.0.5 ', '10.0.0.0/33', 'fd12::/129',
    '10.0.0.0/8/8', '10.0.0.256',
    # not the canonical spelling (the stored text is str(ipaddress.ip_network(item)))
    '010.0.0.5', 'FD12::1', 'fd12:0::1', '10.0.0.0/08', '10.0.0.0/255.0.0.0', 'fd12:3456:0::/48', '１０.0.0.5',
    # the IPv4-mapped range and the NAT64 well-known prefix: one address, the IPv4 spelling only
    '::ffff:10.0.0.5', '::ffff:a00:5', '::ffff:0:0/96', '::ffff:127.0.0.1', '64:ff9b::a00:5', '64:ff9b::/96',
    '64:ff9b::a00:0/120',
    # ... and a prefix holding either of them (plan Notes 裁定: refused in either direction; ::ffff:0:0/95 has host bits)
    '64:ff9b::/95', '::fffe:0:0/95', '::ffff:0:0/95',
    # meeting a built-in never-connect range: link-local, loopback, unspecified, IPv4-compatible, multicast, broadcast
    '169.254.0.0/16', '169.254.169.254', 'fe80::/64', 'fe80::1', '127.0.0.0/8', '127.0.0.2', '::1', '0.0.0.0/8',
    '0.1.2.3', '::', '::/96', '::7f00:1', '224.0.0.0/4', '239.1.2.3', 'ff02::1', '255.255.255.255', '0.0.0.0/0',
    '::/0', 'fc00::/6', '128.0.0.0/1',
]


@pytest.mark.parametrize('item', NOT_NAMEABLE)
def test_an_item_that_is_not_a_nameable_address_refuses_the_entry(item: str) -> None:
    """K-57: every item is checked at registration; one that fails refuses the whole entry."""
    with pytest.raises(EntryInvalid):
        named('gitlab.corp:443', (item,))
    with pytest.raises(EntryInvalid):
        named('gitlab.corp:443', ('10.0.0.0/8', item))


@pytest.mark.parametrize('item, stored', [('10.0.0.0/8', '10.0.0.0/8'), ('10.0.0.5', '10.0.0.5/32'),
                                          ('10.0.0.5/32', '10.0.0.5/32'), ('fd12:3456::/48', 'fd12:3456::/48'),
                                          ('fd12:3456::1', 'fd12:3456::1/128'), ('100.64.0.0/10', '100.64.0.0/10'),
                                          ('100.100.100.200', '100.100.100.200/32'),   # a deployment-list address:
                                          ('192.168.0.0/16', '192.168.0.0/16')])        # refused at connect, not here
def test_a_nameable_address_is_stored_as_its_canonical_prefix(item: str, stored: str) -> None:
    """K-57: a canonical single address is stored with its full prefix length, a canonical prefix as it is. The
    deployment's metadata list and the host's interface addresses are not checked here (C-19 refuses them)."""
    e = named('gitlab.corp:443', (item,))
    assert e.addresses == (stored,)
    assert named('10.0.0.5:80', (item,)).addresses == (stored,)          # an IP key names like any exact key


def test_named_addresses_are_deduplicated_and_kept_in_order_and_default_to_none() -> None:
    """K-57 (接口约定): within one entry the items are deduplicated and sorted by (version, network address, prefix
    length); an entry made without the field names nothing."""
    e = named('gitlab.corp:443', ('fd12:3456::/48', '10.0.0.5', '10.0.0.0/24', '10.0.0.5/32', '10.0.0.0/8',
                                  '192.168.0.0/16', 'fd12:3456::1'))
    assert e.addresses == ('10.0.0.0/8', '10.0.0.0/24', '10.0.0.5/32', '192.168.0.0/16', 'fd12:3456::/48',
                           'fd12:3456::1/128')
    assert allow('gitlab.corp:443').addresses == () and w.FALLBACK_DEFAULT.addresses == ()
    assert named('gitlab.corp:443', ()).addresses == ()


@pytest.mark.parametrize('kind, key, state', [(KeyKind.PATTERN, 'corp:443', EntryState.ALLOW),
                                              (KeyKind.FALLBACK, '', EntryState.ALLOW),
                                              (KeyKind.EXACT, 'gitlab.corp:443', EntryState.DENY),
                                              (KeyKind.PATTERN, 'corp:443', EntryState.DENY),
                                              (KeyKind.FALLBACK, '', EntryState.DENY)])
def test_only_an_exact_allow_entry_names_addresses(kind: KeyKind, key: str, state: EntryState) -> None:
    """K-57, N-12 (design 3.2): a pattern, the fallback and a deny entry carry no addresses, as accounts (K-29)."""
    with pytest.raises(EntryInvalid):
        named(key, ('10.0.0.0/8',), methods=(), kind=kind, state=state)
    assert named(key, (), methods=(), kind=kind, state=state).addresses == ()


def test_an_entry_names_at_most_64_addresses_and_stays_within_the_entry_bound() -> None:
    """K-57: the 65th item is refused (engineering default 64); with the methods, prefixes and accounts the addresses
    count toward ENTRY_LISTS_MAX, which keeps a QUESTION within its frame (SPEC §6)."""
    items = tuple(f'10.{i}.0.0/16' for i in range(65))
    assert len(named('gitlab.corp:443', items[:64]).addresses) == 64
    with pytest.raises(EntryInvalid):
        named('gitlab.corp:443', items)
    # 31 prefixes of 8191 bytes and one of 8080: inside the bound alone, over it with two addresses on top
    big = [f'/{i:02d}' + 'p' * 8188 for i in range(31)] + ['/zz' + 'q' * 8077]
    assert named('gitlab.corp:443', (), prefixes=big)
    with pytest.raises(EntryInvalid):
        named('gitlab.corp:443', ('10.0.0.0/8', 'fd12:3456::/48'), prefixes=big)


# ---- K-20: registration by device and inode, no nesting ----------------------------------------------------------------
def test_register_by_identity_and_reject_nesting(tmp_path: Path) -> None:
    (tmp_path / 'a').mkdir()
    (tmp_path / 'a' / 'inner').mkdir()
    (tmp_path / 'b').mkdir()
    store = WorkspaceStore(tmp_path / 'state')
    store.load()
    r = store.register('work0', str(tmp_path / 'a'))
    assert r.persisted and r.applied
    st = os.stat(tmp_path / 'a')
    assert (store.tables['work0'].device, store.tables['work0'].inode) == (st.st_dev, st.st_ino)
    assert store.tables['work0'].entries[(KeyKind.FALLBACK, '')] == w.FALLBACK_DEFAULT      # K-08 default fallback
    with pytest.raises(EntryInvalid):
        store.register('work1', str(tmp_path / 'a'))                 # same identity
    with pytest.raises(EntryInvalid):
        store.register('work1', str(tmp_path / 'a' / 'inner'))       # nested under a registered root
    with pytest.raises(EntryInvalid):
        store.register('work1', str(tmp_path))                       # contains a registered root
    with pytest.raises(EntryInvalid):
        store.register('work0', str(tmp_path / 'b'))                 # id taken
    with pytest.raises(EntryInvalid):
        store.register('bad id', str(tmp_path / 'b'))
    assert store.register('work1', str(tmp_path / 'b')).persisted
    assert sorted(p.name for p in (tmp_path / 'state' / 'workspaces').iterdir()) == ['work0.json', 'work1.json']
    assert oct(os.stat(tmp_path / 'state' / 'workspaces').st_mode & 0o777) == '0o700'
    assert oct(os.stat(tmp_path / 'state' / 'workspaces' / 'work0.json').st_mode & 0o777) == '0o600'


# ---- K-17 / K-19: write order and rebuild at every crash point ---------------------------------------------------------
class FailingDisk(Disk):
    def __init__(self, fail_at: str) -> None:
        self.fail_at = fail_at

    def write_tmp(self, tmp, data):
        if self.fail_at == 'write':
            raise OSError('disk full')
        super().write_tmp(tmp, data)
        if self.fail_at == 'after_write':            # crash before rename: tmp exists, final is old
            raise OSError('crash')

    def rename(self, tmp, final):
        if self.fail_at == 'rename':
            raise OSError('rename failed')
        super().rename(tmp, final)

    def fsync_dir(self, directory):
        if self.fail_at == 'fsync_dir':
            raise OSError('fsync dir failed')
        super().fsync_dir(directory)


def fresh_store(tmp_path: Path, disk: Disk | None = None) -> WorkspaceStore:
    (tmp_path / 'root').mkdir(exist_ok=True)
    store = WorkspaceStore(tmp_path / 'state', disk)
    store.load()
    if 'work0' not in store.tables:
        store.register('work0', str(tmp_path / 'root'))
    return store


def reload(tmp_path: Path) -> WorkspaceStore:
    store = WorkspaceStore(tmp_path / 'state')
    store.load()
    return store


def test_persisted_change_survives_restart_and_tmp_is_cleaned(tmp_path: Path) -> None:
    store = fresh_store(tmp_path)
    e = allow('api.github.com:443', ('GET',), ('/repos',), ('alice',))
    assert store.put('work0', e).persisted
    again = reload(tmp_path)
    assert again.tables['work0'].entries[e.identity] == e and not again.tables['work0'].unavailable
    (tmp_path / 'state' / 'workspaces' / 'work0.json.tmp').write_bytes(b'garbage')
    again = reload(tmp_path)
    assert not (tmp_path / 'state' / 'workspaces' / 'work0.json.tmp').exists()
    assert again.tables['work0'].entries[e.identity] == e


@pytest.mark.parametrize('fail_at', ['write', 'after_write', 'rename', 'fsync_dir'])
def test_relaxing_change_at_each_failure_point(tmp_path: Path, fail_at: str) -> None:
    store = fresh_store(tmp_path)
    store.disk = FailingDisk(fail_at)
    e = allow('api.github.com:443', ('GET', 'POST'))
    r = store.put('work0', e)
    assert not r.persisted
    rebuilt = reload(tmp_path).tables['work0']
    if fail_at == 'fsync_dir':
        # the rename happened: the name on disk holds the new table; memory applies, the workspace is blocked
        assert r.applied and r.stage == 'fsync_dir' and e.identity in store.tables['work0'].entries
        assert store.tables['work0'].spawn_blocked and rebuilt.entries[e.identity] == e
    else:
        assert not r.applied and e.identity not in store.tables['work0'].entries
        assert not store.tables['work0'].spawn_blocked
        assert e.identity not in rebuilt.entries and not rebuilt.unavailable   # old mirror intact


@pytest.mark.parametrize('fail_at', ['write', 'rename', 'fsync_dir'])
def test_tightening_change_applies_in_memory_and_blocks_spawn(tmp_path: Path, fail_at: str) -> None:
    store = fresh_store(tmp_path)
    assert store.put('work0', allow('api.github.com:443', ('GET', 'POST'))).persisted
    blocked = []
    store.on_blocked = blocked.append
    store.disk = FailingDisk(fail_at)
    d = deny('api.github.com:443', ('POST',))
    r = store.put('work0', d)
    assert r.applied and not r.persisted and store.tables['work0'].entries[d.identity] == d
    assert store.tables['work0'].spawn_blocked and blocked == ['work0']
    rebuilt = reload(tmp_path).tables['work0']
    if fail_at == 'fsync_dir':
        assert rebuilt.entries[d.identity] == d
    else:
        assert rebuilt.entries[d.identity].state is EntryState.ALLOW              # disk still old


def test_deleting_an_allow_that_a_coarser_allow_takes_over_is_relaxing(tmp_path: Path) -> None:
    """K-18, K-43 (overall review 2026-11-03, #7): while an exact key exists its destination never falls back to a coarser
    key; deleting it hands the destination to the next key, and when that key allows (here the default fallback, GET
    anywhere without asking) the deletion can let through what the exact entry refused or asked about. A write that
    fails before the rename leaves it out of memory, as for any relaxing change."""
    store = fresh_store(tmp_path)
    e = allow('api.example.com:443', ('GET',), ('/public',), approval=Approval.ALWAYS)
    assert store.put('work0', e).persisted
    store.disk = FailingDisk('rename')
    r = store.delete('work0', e.key_kind, e.key)
    assert not r.applied and store.tables['work0'].entries[e.identity] == e and not store.tables['work0'].spawn_blocked


def test_deleting_an_allow_with_no_coarser_allow_is_tightening(tmp_path: Path) -> None:
    """K-18 (overall review 2026-11-03, #7): with a deny fallback and no pattern over the host, the deleted entry's
    destination is refused afterwards; the deletion only removes permission and applies in memory even unpersisted.
    A pattern over another domain does not take the destination over."""
    store = fresh_store(tmp_path)
    assert store.put('work0', deny('', kind=KeyKind.FALLBACK)).persisted
    assert store.put('work0', allow('other.org:443', kind=KeyKind.PATTERN)).persisted
    e = allow('api.example.com:443', ('GET',), ('/public',))
    assert store.put('work0', e).persisted
    store.disk = FailingDisk('rename')
    r = store.delete('work0', e.key_kind, e.key)
    assert r.applied and not r.persisted and e.identity not in store.tables['work0'].entries
    assert store.tables['work0'].spawn_blocked


def test_a_short_write_is_written_on_until_the_mirror_is_whole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """K-17 (overall review 2026-11-03, #8): os.write may take only part of the buffer (a filling disk, a quota); the
    mirror is written on until whole before it is synced and renamed, never left truncated under the final name."""
    store = fresh_store(tmp_path)
    real_write = os.write
    monkeypatch.setattr(w.os, 'write', lambda fd, data: real_write(fd, bytes(data[:7])))
    e = allow('api.github.com:443', ('GET',), ('/repos',))
    assert store.put('work0', e).persisted
    monkeypatch.undo()
    again = reload(tmp_path).tables['work0']
    assert not again.unavailable and again.entries[e.identity] == e


def test_broken_mirror_makes_workspace_unavailable_not_empty(tmp_path: Path) -> None:
    store = fresh_store(tmp_path)
    (tmp_path / 'root2').mkdir()
    store.register('work1', str(tmp_path / 'root2'))
    (tmp_path / 'state' / 'workspaces' / 'work0.json').write_bytes(b'{"v":1,"entries":[}')
    again = reload(tmp_path)
    assert again.tables['work0'].unavailable and again.tables['work0'].entries == {}
    assert not again.tables['work1'].unavailable
    with pytest.raises(WorkspaceUnavailable):
        again.put('work0', allow('h:443'))
    assert again.put('work1', allow('h:443')).persisted
    # a mirror naming another workspace, or with a foreign key, is broken too
    good = json.loads((tmp_path / 'state' / 'workspaces' / 'work1.json').read_bytes())
    (tmp_path / 'state' / 'workspaces' / 'work0.json').write_bytes(json.dumps(good).encode())
    assert reload(tmp_path).tables['work0'].unavailable
    good['extra'] = 1
    (tmp_path / 'state' / 'workspaces' / 'work1.json').write_bytes(json.dumps(good).encode())
    assert reload(tmp_path).tables['work1'].unavailable


# ---- the mirror with named addresses (K-57; plan engine-v3-private-net 接口约定: mirror version 3) ----------------------
def mirror_path(tmp_path: Path) -> Path:
    return tmp_path / 'state' / 'workspaces' / 'work0.json'


def test_a_version_3_mirror_carries_the_named_addresses(tmp_path: Path) -> None:
    """K-57, K-17: the mirror is version 3; every entry has the key "addresses", the list of stored texts in stored
    order (empty for an entry that names none); a restart reads them back."""
    store = fresh_store(tmp_path)
    e = named('gitlab.corp:443', ('fd12:3456::/48', '10.0.0.5'))
    assert store.put('work0', e).persisted
    mirror = json.loads(mirror_path(tmp_path).read_bytes())
    assert mirror['v'] == 3
    assert {x['key']: x['addresses'] for x in mirror['entries']} == {'gitlab.corp:443': ['10.0.0.5/32', 'fd12:3456::/48'],
                                                                     '': []}
    assert w.entry_from_json(json.loads(json.dumps(w.entry_to_json(e)))) == e
    again = reload(tmp_path).tables['work0']
    assert not again.unavailable and again.entries[e.identity] == e
    assert again.entries[e.identity].addresses == ('10.0.0.5/32', 'fd12:3456::/48')


@pytest.mark.parametrize('version', [1, 2])
def test_an_older_mirror_reads_with_nothing_named_and_is_rewritten_as_version_3(tmp_path: Path, version: int) -> None:
    """K-57: a version 1 or 2 mirror has no "addresses" key and reads as naming nothing; the next write is version 3."""
    store = fresh_store(tmp_path)
    assert store.put('work0', allow('gitlab.corp:443')).persisted
    old = json.loads(mirror_path(tmp_path).read_bytes())
    old['v'] = version
    for x in old['entries']:
        x.pop('addresses', None)
    if version == 1:
        old.pop('objects', None)
    mirror_path(tmp_path).write_bytes(json.dumps(old).encode())
    again = reload(tmp_path)
    table = again.tables['work0']
    assert not table.unavailable
    assert table.entries[(KeyKind.EXACT, 'gitlab.corp:443')].addresses == ()
    assert table.entries[(KeyKind.FALLBACK, '')].addresses == ()
    assert again.put('work0', allow('other.corp:443')).persisted
    assert json.loads(mirror_path(tmp_path).read_bytes())['v'] == 3


@pytest.mark.parametrize('addresses, readable', [
    (['10.0.0.0/8'], True),
    (['gitlab.corp'], False), (['169.254.0.0/16'], False), (['10.0.0.5/24'], False), (['::ffff:a00:5'], False),
    ('10.0.0.0/8', False), ([1], False), ([f'10.{i}.0.0/16' for i in range(65)], False)])
def test_a_version_3_mirror_is_read_with_the_registration_rules(tmp_path: Path, addresses, readable: bool) -> None:
    """K-19, K-57: a version 3 mirror whose addresses do not pass registration makes the workspace unavailable, never
    an entry that names less or more than was registered."""
    store = fresh_store(tmp_path)
    assert store.put('work0', allow('gitlab.corp:443')).persisted
    mirror = json.loads(mirror_path(tmp_path).read_bytes())
    mirror['v'] = 3
    for x in mirror['entries']:
        x['addresses'] = addresses if x['key'] == 'gitlab.corp:443' else []
    mirror_path(tmp_path).write_bytes(json.dumps(mirror).encode())
    table = reload(tmp_path).tables['work0']
    assert table.unavailable is not readable
    if readable:
        assert table.entries[(KeyKind.EXACT, 'gitlab.corp:443')].addresses == ('10.0.0.0/8',)
    else:
        assert table.entries == {}


@pytest.mark.parametrize('case', ['fallback_names', 'v3_without_key', 'v2_with_key'])
def test_a_mirror_whose_entries_break_the_named_address_schema_is_unavailable(tmp_path: Path, case: str) -> None:
    """K-05 schema closed, K-19: addresses on the fallback entry; a version 3 entry without the key; a version 2 entry
    with it. Each makes the workspace unavailable."""
    store = fresh_store(tmp_path)
    assert store.put('work0', allow('gitlab.corp:443')).persisted
    mirror = json.loads(mirror_path(tmp_path).read_bytes())
    mirror['v'] = 2 if case == 'v2_with_key' else 3
    for x in mirror['entries']:
        x['addresses'] = []
    fallback = next(x for x in mirror['entries'] if x['key'] == '')
    if case == 'fallback_names':
        fallback['addresses'] = ['10.0.0.0/8']
    elif case == 'v3_without_key':
        del fallback['addresses']
    mirror_path(tmp_path).write_bytes(json.dumps(mirror).encode())
    assert reload(tmp_path).tables['work0'].unavailable


def test_a_root_replaced_between_runs_is_not_recognized(tmp_path: Path) -> None:
    """K-20: at start a workspace is recognized by the device and inode it was registered with, not by its path; a
    directory put at the registered path (another inode), or a root that is gone, leaves it unavailable, never its
    old entries attached to whatever is there now."""
    store = fresh_store(tmp_path)
    assert store.put('work0', allow('api.github.com:443')).persisted
    assert not reload(tmp_path).tables['work0'].unavailable
    (tmp_path / 'root').rename(tmp_path / 'root-old')
    (tmp_path / 'root').mkdir()
    again = reload(tmp_path)
    assert again.tables['work0'].unavailable and again.tables['work0'].entries == {}
    (tmp_path / 'root').rmdir()
    assert reload(tmp_path).tables['work0'].unavailable


def test_delete_entry_and_workspace(tmp_path: Path) -> None:
    store = fresh_store(tmp_path)
    e = allow('h:443')
    store.put('work0', e)
    assert store.delete('work0', KeyKind.EXACT, 'h:443').persisted and e.identity not in store.tables['work0'].entries
    with pytest.raises(EntryInvalid):
        store.delete('work0', KeyKind.EXACT, 'h:443')
    store.delete_workspace('work0')
    assert 'work0' not in store.tables and not (tmp_path / 'state' / 'workspaces' / 'work0.json').exists()
    with pytest.raises(EntryInvalid):
        store.put('work0', e)


def test_a_deny_entry_has_no_accounts_and_entries_are_bounded() -> None:
    """K-05 (648d60f2 3.2 禁止格子不带账户) and the entry bound that keeps a QUESTION within its frame (SPEC §6)."""
    with pytest.raises(EntryInvalid):
        make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.DENY, ['GET'], [], ['alice'], Approval.NEVER)
    big = [f'/{i:02d}' + 'p' * 8188 for i in range(32)]           # 32 distinct prefixes of 8 KiB: over 256 KiB together
    with pytest.raises(EntryInvalid):
        make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['GET'], big, [], Approval.NEVER)
    assert make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['GET'], big[:30], [], Approval.NEVER)
