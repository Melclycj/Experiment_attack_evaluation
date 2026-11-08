"""Host file objects in the workspace table (validation.md H-01, H-02, H-03, H-22; the relative-path rule of H-07; plan
engine-v3-n16-file-read 2.3a).

The store registers an object by resolving the user's path as the engine uid, following symlinks, and opening the
directory (the object itself, or the file's parent) with O_PATH: the anchor every later open starts from. The mirror
keeps the resolved directory and its device and inode; a restart reopens and compares them.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from conftest import settled_fds as open_fds
from connector import canonical as c
from engine import fileobjects as fo
from engine.workspaces import (Approval, Disk, EntryInvalid, EntryState, KeyKind, WorkspaceStore,
                               WorkspaceUnavailable, make_entry)

DIR, FILE = c.FILE_TYPE_DIR, c.FILE_TYPE_FILE
READ, LIST = c.FILE_OPS_READ, c.FILE_OPS_LIST
MODES = {'allow': (1, 1), 'ask': (1, 2), 'deny': (2, 1)}


class FailingDisk(Disk):
    def __init__(self, fail_at: str) -> None:
        self.fail_at = fail_at

    def write_tmp(self, tmp, data):
        if self.fail_at == 'write':
            raise OSError('disk full')
        super().write_tmp(tmp, data)

    def rename(self, tmp, final):
        if self.fail_at == 'rename':
            raise OSError('rename failed')
        super().rename(tmp, final)

    def fsync_dir(self, directory):
        if self.fail_at == 'fsync_dir':
            raise OSError('fsync dir failed')
        super().fsync_dir(directory)


OPENED: list[WorkspaceStore] = []


class Store(WorkspaceStore):
    """A store whose anchors the test module releases after each test (the anchors are plain descriptors)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        OPENED.append(self)


@pytest.fixture(autouse=True)
def release_anchors():
    yield
    while OPENED:
        OPENED.pop().close()


def store(tmp_path: Path, protected=None, state: Path | None = None) -> WorkspaceStore:
    (tmp_path / 'root').mkdir(exist_ok=True)
    s = Store(state or tmp_path / 'state', protected=protected)
    s.load()
    if 'work0' not in s.tables:
        s.register('work0', str(tmp_path / 'root'))
    return s


def reload(tmp_path: Path, protected=None, state: Path | None = None) -> WorkspaceStore:
    s = Store(state or tmp_path / 'state', protected=protected)
    s.load()
    return s


def host(tmp_path: Path) -> Path:
    h = tmp_path / 'host'
    h.mkdir(exist_ok=True)
    (h / 'notes.txt').write_bytes(b'hello')
    (h / 'sub').mkdir(exist_ok=True)
    return h


def put(s: WorkspaceStore, alias: str, path, type_: int = DIR, ops: int = READ | LIST, mode: str = 'allow'):
    return s.register_object('work0', alias, str(path), type_, ops, *MODES[mode])


def mirror(tmp_path: Path, state: Path | None = None) -> bytes:
    return ((state or tmp_path / 'state') / 'workspaces' / 'work0.json').read_bytes()


# ---- H-01: register, replace, delete; the mirror reads back what memory holds -----------------------------------------
def test_register_replace_delete_and_the_mirror_reads_back(tmp_path: Path) -> None:
    h = host(tmp_path)
    s = store(tmp_path)
    result, obj = put(s, 'notes', h)
    assert result.persisted and result.applied
    assert (obj.alias, obj.host_path, obj.type, obj.ops, obj.state, obj.approval) == \
        ('notes', str(h), DIR, READ | LIST, EntryState.ALLOW, Approval.NEVER)
    result, one = put(s, 'one', h / 'notes.txt', FILE, READ, 'ask')
    assert result.persisted and one.approval is Approval.ALWAYS
    table = s.tables['work0']
    assert set(table.objects) == {'notes', 'one'} and set(table.anchors) == {'notes', 'one'}
    again = reload(tmp_path).tables['work0']
    assert again.objects == table.objects and not again.unavailable_objects
    assert json.loads(mirror(tmp_path))['v'] == 3                    # version 3 since the named addresses (K-57)
    result, replaced = put(s, 'notes', h, DIR, READ, 'deny')         # same alias: replaced whole
    assert result.persisted and s.tables['work0'].objects['notes'] == replaced and replaced.state is EntryState.DENY
    assert s.delete_object('work0', 'one').persisted
    assert set(reload(tmp_path).tables['work0'].objects) == {'notes'}
    with pytest.raises(EntryInvalid):
        s.delete_object('work0', 'one')
    with pytest.raises(EntryInvalid):
        s.register_object('nope', 'x', str(h), DIR, READ, 1, 1)


@pytest.mark.parametrize('case', ['file_with_list', 'relative_path', 'alias_slash', 'alias_empty', 'alias_long',
                                  'alias_unicode', 'mode_deny_ask', 'mode_unknown_state', 'mode_unknown_approval',
                                  'type_unknown', 'ops_none', 'ops_unknown', 'ops_list_only_file', 'dir_given_a_file',
                                  'file_given_a_dir', 'missing', 'nul_in_path', 'long_path'])
def test_registration_refusals_leave_table_and_mirror_unchanged(tmp_path: Path, case: str) -> None:
    h = host(tmp_path)
    s = store(tmp_path)
    put(s, 'keep', h)
    before, objects, version = mirror(tmp_path), dict(s.tables['work0'].objects), s.tables['work0'].version
    fds = open_fds()
    args = {'file_with_list': ('one', str(h / 'notes.txt'), FILE, READ | LIST, 1, 1),
            'relative_path': ('x', 'host/notes.txt', FILE, READ, 1, 1),
            'alias_slash': ('a/b', str(h), DIR, READ, 1, 1),
            'alias_empty': ('', str(h), DIR, READ, 1, 1),
            'alias_long': ('x' * 65, str(h), DIR, READ, 1, 1),
            'alias_unicode': ('café', str(h), DIR, READ, 1, 1),
            'mode_deny_ask': ('x', str(h), DIR, READ, 2, 2),
            'mode_unknown_state': ('x', str(h), DIR, READ, 3, 1),
            'mode_unknown_approval': ('x', str(h), DIR, READ, 1, 3),
            'type_unknown': ('x', str(h), 3, READ, 1, 1),
            'ops_none': ('x', str(h), DIR, 0, 1, 1),
            'ops_unknown': ('x', str(h), DIR, READ | 4, 1, 1),
            'ops_list_only_file': ('x', str(h / 'notes.txt'), FILE, LIST, 1, 1),
            'dir_given_a_file': ('x', str(h / 'notes.txt'), DIR, READ, 1, 1),
            'file_given_a_dir': ('x', str(h / 'sub'), FILE, READ, 1, 1),
            'missing': ('x', str(h / 'nope'), DIR, READ, 1, 1),
            'nul_in_path': ('x', str(h) + '\x00/sub', DIR, READ, 1, 1),
            'long_path': ('x', '/' + 'a' * 4096, DIR, READ, 1, 1)}[case]
    with pytest.raises(EntryInvalid):
        s.register_object('work0', *args)
    assert mirror(tmp_path) == before and s.tables['work0'].objects == objects
    assert s.tables['work0'].version == version and open_fds() == fds          # no anchor left open


def test_alias_grammar() -> None:
    for good in ('a', 'A-z_0', 'x' * 64):
        assert fo.check_alias(good) == good
    for bad in ('', 'x' * 65, 'a.b', 'a/b', 'café', ' a', 'a\x00'):
        with pytest.raises(EntryInvalid):
            fo.check_alias(bad)


# ---- H-02: the anchor --------------------------------------------------------------------------------------------------
def test_the_anchor_follows_a_symlink_and_records_device_and_inode(tmp_path: Path) -> None:
    h = host(tmp_path)
    (tmp_path / 'via').symlink_to(h)
    (h / 'alias.txt').symlink_to('notes.txt')
    s = store(tmp_path)
    _, d = put(s, 'notes', tmp_path / 'via')
    real = os.stat(h)
    assert d.host_path == str(tmp_path / 'via') and d.dir_path == str(h) and d.name == ''
    assert (d.device, d.inode) == (real.st_dev, real.st_ino)
    anchor = s.tables['work0'].anchors['notes']
    assert (os.fstat(anchor).st_dev, os.fstat(anchor).st_ino) == (real.st_dev, real.st_ino)
    _, f = put(s, 'one', h / 'alias.txt', FILE, READ)
    assert (f.dir_path, f.name, f.inode) == (str(h), 'notes.txt', real.st_ino)   # the parent; the resolved name
    stored = json.loads(mirror(tmp_path))['objects']
    assert {o['alias']: (o['device'], o['inode']) for o in stored} == {'notes': (real.st_dev, real.st_ino),
                                                                        'one': (real.st_dev, real.st_ino)}


def test_replacing_or_deleting_an_object_closes_its_old_anchor(tmp_path: Path) -> None:
    h = host(tmp_path)
    s = store(tmp_path)
    put(s, 'notes', h)
    fds = open_fds()
    put(s, 'notes', h / 'sub')
    assert len(open_fds()) == len(fds) and s.tables['work0'].objects['notes'].dir_path == str(h / 'sub')
    s.delete_object('work0', 'notes')
    assert len(open_fds()) == len(fds) - 1 and 'notes' not in s.tables['work0'].anchors


def test_object_count_limit(tmp_path: Path) -> None:
    h = host(tmp_path)
    s = store(tmp_path)
    for i in range(c.LIMITS.file_objects):
        put(s, f'o{i}', h, DIR, READ)
    with pytest.raises(EntryInvalid):
        put(s, 'one-more', h, DIR, READ)
    assert put(s, 'o0', h / 'sub', DIR, READ)[0].persisted                   # replacing within the limit is fine
    assert len(s.tables['work0'].objects) == c.LIMITS.file_objects == 128


# ---- H-03: the check at restart --------------------------------------------------------------------------------------
@pytest.mark.parametrize('change', ['replaced', 'deleted'])
def test_restart_marks_a_replaced_or_missing_directory_unavailable(tmp_path: Path, change: str) -> None:
    h = host(tmp_path)
    (tmp_path / 'other').mkdir()
    s = store(tmp_path)
    put(s, 'a', h / 'sub')
    put(s, 'b', tmp_path / 'other')
    s.put('work0', make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ('GET',), (), (), Approval.NEVER))
    if change == 'replaced':                                                   # the same name, another directory
        os.rename(h / 'sub', h / 'sub-old')                                    # (kept, so its inode is not reused)
        (h / 'sub').mkdir()
    else:
        os.rmdir(h / 'sub')
    again = reload(tmp_path).tables['work0']
    assert again.unavailable_objects == {'a'} and 'a' not in again.anchors and 'b' in again.anchors
    assert not again.unavailable and (KeyKind.EXACT, 'api.github.com:443') in again.entries
    assert set(again.objects) == {'a', 'b'}                                   # kept, not re-registered on its own


def test_restart_keeps_a_file_object_whose_file_was_replaced(tmp_path: Path) -> None:
    h = host(tmp_path)
    s = store(tmp_path)
    put(s, 'one', h / 'notes.txt', FILE, READ)
    (h / 'new.txt').write_bytes(b'second')
    os.rename(h / 'new.txt', h / 'notes.txt')                                # an editor's whole-file replace
    again = reload(tmp_path).tables['work0']
    assert not again.unavailable_objects and 'one' in again.anchors


def test_a_version_1_mirror_reads_as_no_objects(tmp_path: Path) -> None:
    s = store(tmp_path)
    data = json.loads(mirror(tmp_path))
    del data['objects']
    for entry in data['entries']:                                             # nor named addresses (K-57)
        del entry['addresses']
    data['v'] = 1
    (tmp_path / 'state' / 'workspaces' / 'work0.json').write_text(json.dumps(data))
    again = reload(tmp_path).tables['work0']
    assert not again.unavailable and again.objects == {} and again.entries == s.tables['work0'].entries
    data['v'] = 2                                                             # a v2 mirror must carry its objects
    (tmp_path / 'state' / 'workspaces' / 'work0.json').write_text(json.dumps(data))
    assert reload(tmp_path).tables['work0'].unavailable


# ---- H-01 with K-18: tightening applies even unpersisted; relaxing only once the name on disk holds it ---------------
@pytest.mark.parametrize('fail_at', ['write', 'rename', 'fsync_dir'])
@pytest.mark.parametrize('change', ['delete', 'deny', 'drop_list', 'ask'])
def test_a_tightening_object_change_applies_at_every_failure_point(tmp_path: Path, fail_at: str, change: str) -> None:
    h = host(tmp_path)
    s = store(tmp_path)
    put(s, 'notes', h)
    blocked: list[str] = []
    s.on_blocked = blocked.append
    s.disk = FailingDisk(fail_at)
    if change == 'delete':
        r = s.delete_object('work0', 'notes')
    elif change == 'deny':
        r = s.set_object_mode('work0', 'notes', EntryState.DENY, Approval.NEVER)
    elif change == 'drop_list':
        r, _ = put(s, 'notes', h, DIR, READ)
    else:
        r = s.set_object_mode('work0', 'notes', EntryState.ALLOW, Approval.ALWAYS)
    assert r.applied and not r.persisted and s.tables['work0'].spawn_blocked and blocked == ['work0']
    now = s.tables['work0'].objects.get('notes')
    assert (now is None) if change == 'delete' else (now.state, now.ops, now.approval) == \
        {'deny': (EntryState.DENY, READ | LIST, Approval.NEVER), 'drop_list': (EntryState.ALLOW, READ, Approval.NEVER),
         'ask': (EntryState.ALLOW, READ | LIST, Approval.ALWAYS)}[change]


@pytest.mark.parametrize('fail_at', ['write', 'rename', 'fsync_dir'])
@pytest.mark.parametrize('change', ['new', 'add_list', 'other_dir', 'allow_again'])
def test_a_relaxing_object_change_applies_only_once_on_disk(tmp_path: Path, fail_at: str, change: str) -> None:
    h = host(tmp_path)
    s = store(tmp_path)
    put(s, 'notes', h, DIR, READ, 'deny' if change == 'allow_again' else 'allow')
    before = dict(s.tables['work0'].objects)
    fds = open_fds()
    s.disk = FailingDisk(fail_at)
    alias, path, ops = {'new': ('fresh', h / 'sub', READ), 'add_list': ('notes', h, READ | LIST),
                        'other_dir': ('notes', h / 'sub', READ), 'allow_again': ('notes', h, READ)}[change]
    r, _ = put(s, alias, path, DIR, ops)
    assert not r.persisted
    if fail_at == 'fsync_dir':
        assert r.applied and s.tables['work0'].spawn_blocked and s.tables['work0'].objects[alias].ops == ops
    else:
        assert not r.applied and s.tables['work0'].objects == before and not s.tables['work0'].spawn_blocked
        assert open_fds() == fds                                              # the new anchor was closed


# ---- H-22: paths that hold the engine's own files ---------------------------------------------------------------------
def engine_layout(tmp_path: Path) -> tuple[Path, Path, Path, tuple[str, ...]]:
    deploy = tmp_path / 'deploy'
    (deploy / 'state').mkdir(parents=True)
    (deploy / 'catalog.json').write_text('{}')
    records = tmp_path / 'runs' / 'r1'
    records.mkdir(parents=True)
    (tmp_path / 'beside').mkdir()
    (tmp_path / 'beside' / 'f.txt').write_text('x')
    return deploy, deploy / 'state', records, (str(deploy), str(deploy / 'state'), str(records))


@pytest.mark.parametrize('target', ['deploy', 'deploy_parent', 'in_state', 'records_parent', 'records', 'file_in_deploy',
                                    'file_in_records'])
def test_a_path_holding_the_engines_own_files_is_refused(tmp_path: Path, target: str) -> None:
    deploy, state, records, protected = engine_layout(tmp_path)
    (state / 'inner').mkdir()
    (records / 'events.jsonl').write_text('')
    (tmp_path / 'root').mkdir()
    s = Store(state, protected=protected)
    s.load()
    s.register('work0', str(tmp_path / 'root'))
    path, type_ ={'deploy': (deploy, DIR), 'deploy_parent': (tmp_path, DIR), 'in_state': (state / 'inner', DIR),
                   'records_parent': (records.parent, DIR), 'records': (records, DIR),
                   'file_in_deploy': (deploy / 'catalog.json', FILE),
                   'file_in_records': (records / 'events.jsonl', FILE)}[target]
    with pytest.raises(EntryInvalid, match='engine'):
        s.register_object('work0', 'x', str(path), type_, READ, 1, 1)
    assert s.tables['work0'].objects == {}
    assert s.register_object('work0', 'beside', str(tmp_path / 'beside'), DIR, READ, 1, 1)[0].persisted
    assert s.register_object('work0', 'f', str(tmp_path / 'beside' / 'f.txt'), FILE, READ, 1, 1)[0].persisted


def test_the_store_protects_its_own_state_directory_by_default(tmp_path: Path) -> None:
    s = store(tmp_path)
    with pytest.raises(EntryInvalid, match='engine'):
        s.register_object('work0', 'x', str(tmp_path), DIR, READ, 1, 1)


def test_moving_the_deployment_under_an_object_makes_it_unavailable_at_restart(tmp_path: Path) -> None:
    deploy, state, records, protected = engine_layout(tmp_path)
    (tmp_path / 'root').mkdir()
    s = Store(state, protected=protected)
    s.load()
    s.register('work0', str(tmp_path / 'root'))
    assert s.register_object('work0', 'beside', str(tmp_path / 'beside'), DIR, READ, 1, 1)[0].persisted
    moved = tmp_path / 'beside' / 'deploy-now-here'
    moved.mkdir()
    again = Store(state, protected=(str(moved), str(state), str(records)))
    again.load()
    assert again.tables['work0'].unavailable_objects == {'beside'} and 'beside' not in again.tables['work0'].anchors


def test_a_link_swapped_in_after_the_path_resolved_is_caught_where_the_anchor_opened(tmp_path: Path,
                                                                                   monkeypatch) -> None:
    """H-22 (cold review, minor 3): the check is made on where the anchor really opened, not on the resolved text.
    Between the resolution and the open, a host process turns one directory on the way into a symlink to the state
    directory: the anchor lands in the state directory and the registration is refused, nothing left open."""
    deploy, state, records, protected = engine_layout(tmp_path)
    (tmp_path / 'root').mkdir()
    (state / 'inner').mkdir()
    (tmp_path / 'host' / 'up' / 'inner').mkdir(parents=True)
    s = Store(state, protected=protected)
    s.load()
    s.register('work0', str(tmp_path / 'root'))
    wanted = str(tmp_path / 'host' / 'up' / 'inner')
    real = fo.os.path.realpath

    def racing(path, *args, **kwargs):
        out = real(path, *args, **kwargs)
        if path == wanted and not (tmp_path / 'host' / 'up-old').exists():
            os.rename(tmp_path / 'host' / 'up', tmp_path / 'host' / 'up-old')
            (tmp_path / 'host' / 'up').symlink_to(state)
        return out
    monkeypatch.setattr(fo.os.path, 'realpath', racing)
    fds = open_fds()
    with pytest.raises(EntryInvalid, match='engine'):
        s.register_object('work0', 'x', wanted, DIR, READ, 1, 1)
    monkeypatch.undo()
    assert s.tables['work0'].objects == {} and open_fds() == fds
    assert (tmp_path / 'host' / 'up').is_symlink()                          # the swap did happen in between


def test_a_restart_checks_where_the_anchor_opens_not_the_recorded_text(tmp_path: Path) -> None:
    """H-03, H-22 at restart (cold review, minor 3): the recorded directory moved into the state directory and the
    recorded text now leads there through a symlink, with the same device and inode. The check on where the anchor
    opened makes the object unavailable."""
    deploy, state, records, protected = engine_layout(tmp_path)
    (tmp_path / 'root').mkdir()
    (tmp_path / 'host' / 'up' / 'inner').mkdir(parents=True)
    s = Store(state, protected=protected)
    s.load()
    s.register('work0', str(tmp_path / 'root'))
    assert s.register_object('work0', 'x', str(tmp_path / 'host' / 'up' / 'inner'), DIR, READ, 1, 1)[0].persisted
    s.close()
    os.rename(tmp_path / 'host' / 'up' / 'inner', state / 'inner')         # the same directory, now in the state dir
    os.rename(tmp_path / 'host' / 'up', tmp_path / 'host' / 'up-old')
    (tmp_path / 'host' / 'up').symlink_to(state)
    assert os.stat(tmp_path / 'host' / 'up' / 'inner').st_ino == s.tables['work0'].objects['x'].inode
    again = Store(state, protected=protected)
    again.load()
    assert again.tables['work0'].unavailable_objects == {'x'} and 'x' not in again.tables['work0'].anchors


# ---- H-03 with K-19: a mirror whose object path cannot be opened leaves that object unavailable, not the engine -------
@pytest.mark.parametrize('case', ['nul_in_directory', 'nul_in_name', 'surrogate_in_directory', 'surrogate_in_name'])
def test_an_object_path_that_cannot_reach_an_open_leaves_only_that_object_unavailable(tmp_path: Path, case: str) -> None:
    """Cold review, minor 4: the mirror is the engine's own (0700, written only by it), so this is damage or tampering.
    The start goes on; the object is unavailable; its workspace's other objects and entries work."""
    h = host(tmp_path)
    s = store(tmp_path)
    put(s, 'a', h / 'sub')
    put(s, 'one', h / 'notes.txt', FILE, READ)
    put(s, 'b', h)
    data = json.loads(mirror(tmp_path))
    bad = 'one' if case.endswith('name') else 'a'
    for o in data['objects']:
        if o['alias'] == bad:
            key = 'name' if case.endswith('name') else 'dir_path'
            o[key] = o[key] + ('\x00x' if case.startswith('nul') else '\ud800')
    (tmp_path / 'state' / 'workspaces' / 'work0.json').write_text(json.dumps(data))
    again = reload(tmp_path).tables['work0']
    assert not again.unavailable and again.unavailable_objects == {bad} and bad not in again.anchors
    assert set(again.anchors) == {'a', 'one', 'b'} - {bad} and set(again.objects) == {'a', 'one', 'b'}
    assert again.entries == s.tables['work0'].entries


@pytest.mark.parametrize('target', ['own_root', 'in_own_root', 'holds_roots', 'other_root', 'in_other_root',
                                    'file_in_root'])
def test_a_path_holding_or_in_a_workspace_storage_root_is_refused(tmp_path: Path, target: str) -> None:
    """H-22 (main thread 2026-11-04, 按失败即关; design 3.3 "不进这一列：工作区本身"): the storage root of any workspace
    of the engine, this one's or another's, counts as the engine's own: an object that is, holds or lies in it is
    refused; a path beside the roots registers."""
    deploy, state, records, protected = engine_layout(tmp_path)
    stores = tmp_path / 'stores'
    for d in (stores / 'w0' / 'sub', stores / 'w1' / 'sub'):
        d.mkdir(parents=True)
    (stores / 'w0' / 'f.txt').write_text('x')
    s = Store(state, protected=protected)
    s.load()
    s.register('work0', str(stores / 'w0'))
    s.register('work1', str(stores / 'w1'))
    path, type_ = {'own_root': (stores / 'w0', DIR), 'in_own_root': (stores / 'w0' / 'sub', DIR),
                   'holds_roots': (stores, DIR), 'other_root': (stores / 'w1', DIR),
                   'in_other_root': (stores / 'w1' / 'sub', DIR), 'file_in_root': (stores / 'w0' / 'f.txt', FILE)}[target]
    with pytest.raises(EntryInvalid, match='workspace'):
        s.register_object('work0', 'x', str(path), type_, READ, 1, 1)
    assert s.tables['work0'].objects == {}
    assert s.register_object('work0', 'beside', str(tmp_path / 'beside'), DIR, READ, 1, 1)[0].persisted


def test_a_workspace_root_found_under_an_object_at_restart_makes_it_unavailable(tmp_path: Path) -> None:
    """H-22 at restart: a workspace whose storage root now lies in an object's directory leaves the object unavailable.
    (Registering such a workspace while the object is there is refused outright.)"""
    deploy, state, records, protected = engine_layout(tmp_path)
    (tmp_path / 'root').mkdir()
    (tmp_path / 'beside' / 'ws1').mkdir()
    s = Store(state, protected=protected)
    s.load()
    s.register('work0', str(tmp_path / 'root'))
    assert s.register_object('work0', 'beside', str(tmp_path / 'beside'), DIR, READ, 1, 1)[0].persisted
    with pytest.raises(EntryInvalid, match='object'):
        s.register('work1', str(tmp_path / 'beside' / 'ws1'))
    assert 'work1' not in s.tables
    other = Store(tmp_path / 'other-state', protected=protected)          # the same workspace, registered elsewhere,
    other.load()                                                          # and its mirror put beside work0's
    other.register('work1', str(tmp_path / 'beside' / 'ws1'))
    (state / 'workspaces' / 'work1.json').write_bytes((tmp_path / 'other-state' / 'workspaces' / 'work1.json').read_bytes())
    again = Store(state, protected=protected)
    again.load()
    assert again.tables['work0'].unavailable_objects == {'beside'} and 'beside' not in again.tables['work0'].anchors
    for st in (s, other, again):
        st.close()


# ---- the relative-path rule (H-07; checked by the core at the first checkpoint) ---------------------------------------
@pytest.mark.parametrize('path,type_,ok', [
    (b'', DIR, True), (b'a', DIR, True), (b'a/b/c.txt', DIR, True), (b'x' * 4096, DIR, True),
    (b'caf\xc3\xa9/\xff\xfe', DIR, True), (b'.hidden', DIR, True), (b'...', DIR, True),
    (b'a//b', DIR, False), (b'a/', DIR, False), (b'/a', DIR, False), (b'/', DIR, False), (b'.', DIR, False),
    (b'..', DIR, False), (b'a/./b', DIR, False), (b'a/../b', DIR, False), (b'../x', DIR, False),
    (b'a\x00b', DIR, False), (b'x' * 4097, DIR, False),
    (b'', FILE, True), (b'a', FILE, False), (b'.', FILE, False)])
def test_the_relative_path_rule(path: bytes, type_: int, ok: bool) -> None:
    assert (fo.check_rel_path(path, type_) is None) is ok


def test_reasons_follow_the_closed_word_list() -> None:
    """H-18's 13 words, codes 1–13 in the order of the list (proposal 第二节)."""
    assert c.FILE_REASONS == ('not_registered', 'op_not_granted', 'bad_path', 'outside_or_symlink', 'wrong_type',
                              'too_large', 'user_denied', 'pdp_denied', 'recorded_deny', 'policy_changed',
                              'unavailable', 'timeout', 'not_found')
    assert [r.name.lower() for r in fo.FileReason] == list(c.FILE_REASONS)
    assert [int(r) for r in fo.FileReason] == list(range(1, 14))


@pytest.mark.parametrize('mode', ['allow', 'ask', 'deny'])
def test_an_objects_cell_has_the_six_items_of_an_entrys_and_names_nothing(mode: str) -> None:
    """H-09 with plan engine-v3-private-net 接口约定: QUESTION and PDP_REQUEST carry one cell shape (pdp.entry_fields);
    a file object's cell is its state and approval mode in that shape, the three lists and the sixth item (named
    addresses) empty."""
    from engine.pdp import entry_fields
    from engine.workspaces import FALLBACK_DEFAULT
    state, approval = MODES[mode]
    cell = c.unpack_list(fo.object_cell(fo.make_object('notes', '/home/u/notes', DIR, READ | LIST, state, approval)))
    assert len(cell) == len(entry_fields(FALLBACK_DEFAULT)) == 6
    assert cell == [c.u8(state), c.pack_list([]), c.pack_list([]), c.pack_list([]), c.u8(approval), c.pack_list([])]


@pytest.mark.parametrize('err,op,word', [('ELOOP', 3, 'outside_or_symlink'), ('EXDEV', 2, 'outside_or_symlink'),
                                         ('ENOENT', 3, 'not_found'), ('ENOTDIR', 3, 'not_found'),
                                         ('ENOTDIR', 2, 'wrong_type'), ('EISDIR', 3, 'wrong_type'),
                                         ('EOPNOTSUPP', 3, 'wrong_type'), ('EACCES', 3, 'unavailable'),
                                         ('ENAMETOOLONG', 3, 'bad_path'),
                                         ('ESTALE', 3, 'unavailable')])
def test_open_errors_map_to_words(err: str, op: int, word: str) -> None:
    import errno
    assert fo.reason_for_errno(getattr(errno, err), op).name.lower() == word


@pytest.mark.parametrize('size,start,length,actual', [(100, 0, 10, 10), (100, 95, 10, 5), (100, 100, 10, 0),
                                                      (100, 500, 10, 0), (0, 0, 262144, 0)])
def test_actual_length(size: int, start: int, length: int, actual: int) -> None:
    assert fo.actual_length(size, start, length) == actual


def test_an_unknown_workspace_or_an_unavailable_one_refuses_registration(tmp_path: Path) -> None:
    h = host(tmp_path)
    s = store(tmp_path)
    s.tables['work0'].unavailable = True
    with pytest.raises(WorkspaceUnavailable):
        s.register_object('work0', 'x', str(h), DIR, READ, 1, 1)
