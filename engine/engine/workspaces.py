"""Workspace entry table (agent-rm-model 3.2 格子, 3.3 网络目的地 column; validation.md K-05, K-08, K-13, K-14, K-17–K-20).

One table per workspace: the set of recorded entries (allowed / forbidden cells) the rows of that workspace hold by
reference. Memory is the only authority; ``state/workspaces/<id>.json`` is the mirror that survives a restart and is
written by this module alone, in a fixed order (K-17): temp file, fsync, rename, fsync of the directory, then the
in-memory change, then the caller's reply. A workspace whose mirror cannot be read is unavailable, never an empty table
(K-19). Workspaces are identified by their root's device and inode, never by path or uid (K-20).

The table also holds the workspace's host file objects (validation.md H-01–H-03, H-22; engine/fileobjects.py), keyed by
alias, written with the entries in the same mirror and by the same rules; their anchors (O_PATH directory descriptors)
live in memory only and are opened again at start. A version 1 mirror has no objects and reads as none.

An exact allow entry may name non-global addresses (validation.md K-57; plan engine-v3-private-net): a version 3 mirror
carries them on every entry; a version 1 or 2 mirror has none and reads as naming nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterable

from connector import canonical

MIRROR_VERSION = 3
MIRROR_KEYS_V1 = frozenset({'v', 'workspace_id', 'device', 'inode', 'root', 'entries'})
ENTRY_KEYS_V2 = frozenset({'key_kind', 'key', 'state', 'methods', 'prefixes', 'accounts', 'approval'})
ENTRY_KEYS_V3 = ENTRY_KEYS_V2 | {'addresses'}
ACCOUNT_MAX = 128           # account identifier length, bytes
WORKSPACE_ID_MAX = 128


# an entry's methods, prefixes and accounts together, with their length words: a QUESTION (and a request to the PDP)
# carries the cell beside the request, and both must fit the 1 MiB link D frame (SPEC §6 尺寸闭合; 工程默认)
ENTRY_LISTS_MAX = 256 * 1024


class KeyKind(IntEnum):
    EXACT = 1       # host:port
    PATTERN = 2     # *.suffix:port, stored as "suffix:port"
    FALLBACK = 3    # the one fallback entry; key is ''


class EntryState(IntEnum):
    ALLOW = 1
    DENY = 2


class Approval(IntEnum):
    NEVER = 1       # 不问: recorded verdict applies without asking
    ALWAYS = 2      # 每次都问: every request goes to the user


class EntryInvalid(ValueError):
    """An entry or key that does not read; the table is unchanged."""


class WorkspaceUnavailable(Exception):
    """The workspace's mirror did not read at start (K-19); nothing may run on it."""


@dataclass(frozen=True)
class Entry:
    """One cell (K-05). Empty ``methods`` or ``prefixes`` mean "any"; ``accounts`` may be non-empty only on an exact key
    (条款 5, K-29). Prefixes are normalised paths and match on segment boundaries. ``addresses``: the named non-global
    addresses, stored prefix texts, deduplicated and sorted; non-empty only on an exact allow entry (K-57)."""

    key_kind: KeyKind
    key: str
    state: EntryState
    methods: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    accounts: frozenset[str] = frozenset()
    approval: Approval = Approval.NEVER
    addresses: tuple[str, ...] = ()

    @property
    def identity(self) -> tuple[KeyKind, str]:
        return (self.key_kind, self.key)


FALLBACK_DEFAULT = Entry(KeyKind.FALLBACK, '', EntryState.ALLOW, frozenset({'GET'}), (), frozenset(), Approval.NEVER)


# ---- validation of keys and entries (the registration-time counterpart of the connector's grammar) --------------------
def check_host_port(text: str) -> str:
    """"host:port" with the host in canonical form (A-label bytes, lower case, or an IP literal) and port 1..65535."""
    host, sep, port = text.rpartition(':')
    if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535 or port != str(int(port)):
        raise EntryInvalid('key is not host:port')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        canonical.check_host(host.encode('ascii'))
    except (UnicodeEncodeError, canonical.Malformed) as e:
        raise EntryInvalid(f'host does not read: {e}') from None
    return f'{host}:{int(port)}'


def check_suffix_port(text: str) -> str:
    """"suffix:port" of a pattern key: the suffix is a host name of at least one label (not an IP literal)."""
    suffix, sep, port = text.rpartition(':')
    if not sep or not suffix or not port.isdigit() or not 1 <= int(port) <= 65535 or port != str(int(port)):
        raise EntryInvalid('pattern key is not suffix:port')
    if suffix.startswith('*.'):
        suffix = suffix[2:]
    try:
        _, is_ip = canonical.check_host(suffix.encode('ascii'))
    except (UnicodeEncodeError, canonical.Malformed) as e:
        raise EntryInvalid(f'pattern suffix does not read: {e}') from None
    if is_ip:
        raise EntryInvalid('pattern suffix cannot be an IP literal')
    return f'{suffix}:{int(port)}'


def check_prefix(text: str) -> str:
    """A path prefix goes through the connector's path grammar and normalisation (条款 2), so a recorded prefix is
    spelt the one way an accepted request can be spelt (review A, 交后续块 1)."""
    try:
        normalised = canonical.check_path(text.encode('ascii'))
    except (UnicodeEncodeError, canonical.Malformed) as e:
        raise EntryInvalid(f'prefix does not read: {e}') from None
    text = normalised.decode('ascii')
    return text if text == '/' else text.rstrip('/')


def check_method(text: str) -> str:
    try:
        canonical.check_method(text.encode('ascii'))
    except (UnicodeEncodeError, canonical.Malformed) as e:
        raise EntryInvalid(f'method does not read: {e}') from None
    return text


def check_account(text: str) -> str:
    if not text or len(text.encode('utf-8')) > ACCOUNT_MAX or any(c in text for c in '/\\\x00') or text in ('.', '..') \
            or not text.isprintable():
        raise EntryInvalid('account identifier does not read')
    return text


def check_workspace_id(text: str) -> str:
    if not text or len(text) > WORKSPACE_ID_MAX or not all(c.isalnum() or c in '-_' for c in text):
        raise EntryInvalid('workspace id does not read')
    return text


def check_addresses(items: Iterable[str]) -> tuple[str, ...]:
    """K-57: every named item through canonical.named_item, at most LIMITS.named_addresses as written (before the
    deduplication); stored deduplicated, sorted by (version, network address, prefix length)."""
    items = list(items)
    if len(items) > canonical.LIMITS.named_addresses:
        raise EntryInvalid(f'an entry names at most {canonical.LIMITS.named_addresses} addresses')
    try:
        nets = {ipaddress.ip_network(canonical.named_item(x)) for x in items}
    except canonical.Malformed as e:
        raise EntryInvalid(f'named address does not read: {e}') from None
    return tuple(str(n) for n in sorted(nets, key=lambda n: (n.version, int(n.network_address), n.prefixlen)))


def make_entry(key_kind: int, key: str, state: int, methods: Iterable[str], prefixes: Iterable[str],
               accounts: Iterable[str], approval: int, addresses: Iterable[str] = ()) -> Entry:
    """Build and validate an entry from management-port or mirror input (K-05 schema closed, K-29, K-57)."""
    try:
        kind, st, ap = KeyKind(key_kind), EntryState(state), Approval(approval)
    except ValueError:
        raise EntryInvalid('unknown key kind, state or approval') from None
    if kind is KeyKind.EXACT:
        key = check_host_port(key)
    elif kind is KeyKind.PATTERN:
        key = check_suffix_port(key)
    elif key != '':
        raise EntryInvalid('fallback key must be empty')
    accounts = frozenset(check_account(a) for a in accounts)
    if accounts and kind is not KeyKind.EXACT:
        raise EntryInvalid('accounts only on an exact entry (条款 5)')
    if accounts and st is EntryState.DENY:
        raise EntryInvalid('a deny entry carries no accounts')
    addresses = check_addresses(addresses)
    if addresses and (kind is not KeyKind.EXACT or st is EntryState.DENY):
        raise EntryInvalid('only an exact allow entry names addresses (design 3.2; N-12)')
    entry = Entry(kind, key, st, frozenset(check_method(m) for m in methods),
                  tuple(dict.fromkeys(check_prefix(p) for p in prefixes)), accounts, ap, addresses)
    if sum(len(x.encode()) + 4 for x in (*entry.methods, *entry.prefixes, *entry.accounts, *entry.addresses)) \
            > ENTRY_LISTS_MAX:
        raise EntryInvalid(f"the entry's lists exceed {ENTRY_LISTS_MAX} bytes")
    return entry


def entry_to_json(e: Entry) -> dict[str, Any]:
    return {'key_kind': int(e.key_kind), 'key': e.key, 'state': int(e.state), 'methods': sorted(e.methods),
            'prefixes': list(e.prefixes), 'accounts': sorted(e.accounts), 'approval': int(e.approval),
            'addresses': list(e.addresses)}


def entry_from_json(d: Any, version: int = MIRROR_VERSION) -> Entry:
    """An entry of a mirror of ``version``: a closed key set per version, version 3 with "addresses" (K-57), 1 and 2
    without; read with the registration rules."""
    if not isinstance(d, dict) or set(d) != (ENTRY_KEYS_V3 if version == MIRROR_VERSION else ENTRY_KEYS_V2):
        raise EntryInvalid('entry object has the wrong keys')
    for name in ('methods', 'prefixes', 'accounts', 'addresses'):
        if not isinstance(d.get(name, []), list) or not all(isinstance(x, str) for x in d.get(name, [])):
            raise EntryInvalid(f'{name} is not a list of strings')
    if not all(isinstance(d[k], int) and not isinstance(d[k], bool) for k in ('key_kind', 'state', 'approval')) \
            or not isinstance(d['key'], str):
        raise EntryInvalid('entry scalar has the wrong type')
    return make_entry(d['key_kind'], d['key'], d['state'], d['methods'], d['prefixes'], d['accounts'], d['approval'],
                      d.get('addresses', ()))


def narrows(old: Entry | None, new: Entry | None) -> bool:
    """Whether replacing ``old`` by ``new`` can only remove permission from this one entry (K-18 收紧类: deny, delete,
    narrowing, revoke). Anything that could let a request through that the old table refused is relaxing. Entry-level
    only: a deleted allow hands its destinations to the next existing key, which the table-level check in
    WorkspaceStore._change weighs too (K-43)."""
    if new is None:                                       # deletion
        return old is None or old.state is EntryState.ALLOW
    if new.state is EntryState.DENY:
        return True
    if old is None or old.state is EntryState.DENY:       # a new allow, or deny -> allow
        return False
    def wider(a: frozenset[str] | tuple[str, ...], b: frozenset[str] | tuple[str, ...]) -> bool:
        """whether set/tuple b allows at least what a allows (empty = any)"""
        if not a:
            return not b
        return not b or set(a) <= set(b)
    return (wider(new.methods, old.methods) and wider(new.prefixes, old.prefixes) and new.accounts <= old.accounts
            and new.approval >= old.approval and set(new.addresses) <= set(old.addresses))   # K-57: only shrinks


# ---- the mirror (K-17 write order, K-18 failure rules, K-19 rebuild) ------------------------------------------------------
class Disk:
    """The five steps of one mirror write, each overridable by tests to fail at that step."""

    def write_tmp(self, tmp: Path, data: bytes) -> None:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
        try:
            view = memoryview(data)
            while view:                                   # a short write is written on, never left truncated
                view = view[os.write(fd, view):]
            self.fsync_fd(fd)
        finally:
            os.close(fd)

    def fsync_fd(self, fd: int) -> None:
        os.fsync(fd)

    def rename(self, tmp: Path, final: Path) -> None:
        os.replace(tmp, final)

    def fsync_dir(self, directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@dataclass
class WriteResult:
    persisted: bool                 # the mirror holds the new table
    applied: bool                   # memory holds the new table
    stage: str = ''                 # failing step, when any: 'write', 'rename', 'fsync_dir'


@dataclass(eq=False)
class WorkspaceTable:
    workspace_id: str
    device: int
    inode: int
    root: str                                       # registered root path: the admin listing, and found again at start
    entries: dict[tuple[KeyKind, str], Entry] = field(default_factory=dict)
    spawn_blocked: bool = False                     # an unpersisted change stops new spawns (K-18)
    unavailable: bool = False                       # mirror unreadable at start (K-19)
    # in memory only: +1 on every change that takes effect in memory, persisted or not; a cell's revision is the
    # version of its last change, so a cell changed and changed back still has another revision (K-45, K-46)
    version: int = 0
    revs: dict[tuple[Any, str], int] = field(default_factory=dict)     # entries by identity, objects by ('file', alias)
    objects: dict[str, Any] = field(default_factory=dict)              # alias -> fileobjects.FileObject (H-01)
    anchors: dict[str, int] = field(default_factory=dict)              # alias -> O_PATH directory fd, memory only (H-02)
    unavailable_objects: set[str] = field(default_factory=set)         # anchors that did not check out at start (H-03)

    def covering_entries(self) -> tuple[Entry, ...]:
        return tuple(self.entries.values())

    def to_json(self) -> dict[str, Any]:
        from .fileobjects import object_to_json
        return {'v': MIRROR_VERSION, 'workspace_id': self.workspace_id, 'device': self.device, 'inode': self.inode,
                'root': self.root, 'entries': [entry_to_json(e) for e in self.entries.values()],
                'objects': [object_to_json(o) for o in self.objects.values()]}

    @classmethod
    def from_json(cls, d: Any) -> WorkspaceTable:
        from .fileobjects import object_from_json
        keys = MIRROR_KEYS_V1 | {'objects'} if isinstance(d, dict) and d.get('v') in (2, MIRROR_VERSION) else MIRROR_KEYS_V1
        if not isinstance(d, dict) or set(d) != keys or type(d['v']) is not int or d['v'] not in (1, 2, MIRROR_VERSION) \
                or not isinstance(d['entries'], list) or not isinstance(d.get('objects', []), list) \
                or not all(isinstance(d[k], int) and not isinstance(d[k], bool) for k in ('device', 'inode')) \
                or not isinstance(d['root'], str):
            raise EntryInvalid('mirror has the wrong shape')
        table = cls(check_workspace_id(d['workspace_id']), d['device'], d['inode'], d['root'])
        for item in d['entries']:
            e = entry_from_json(item, d['v'])                # versions 1 and 2 name no addresses (K-57)
            if e.identity in table.entries:
                raise EntryInvalid('duplicate entry key in mirror')
            table.entries[e.identity] = e
        for item in d.get('objects', []):                   # a version 1 mirror has none (H-01)
            o = object_from_json(item)
            if o.alias in table.objects:
                raise EntryInvalid('duplicate object alias in mirror')
            table.objects[o.alias] = o
        if len(table.objects) > canonical.LIMITS.file_objects:
            raise EntryInvalid('more objects than a workspace holds')
        return table


def _release_anchors(table: WorkspaceTable) -> None:
    for fd in table.anchors.values():
        os.close(fd)
    table.anchors.clear()


class WorkspaceStore:
    """All workspace tables of one engine and their mirrors under ``state_dir/workspaces``."""

    def __init__(self, state_dir: Path, disk: Disk | None = None, on_blocked: Callable[[str], None] | None = None,
                 protected: Iterable[str] | None = None) -> None:
        """``protected``: the engine's own directories no file object may hold or lie in (H-22): the deployment root,
        the state directory and the record directory; the state directory alone when not given."""
        self.directory = Path(state_dir) / 'workspaces'
        self.disk = disk or Disk()
        self.tables: dict[str, WorkspaceTable] = {}
        self.on_blocked = on_blocked
        self.protected = tuple(str(p) for p in (protected if protected is not None else (state_dir,)))

    def close(self) -> None:
        """Release every object's anchor (engine stop; a store loaded again)."""
        for table in self.tables.values():
            _release_anchors(table)

    # ---- start: rebuild from the mirrors (K-19) ----
    def load(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        loaded: list[WorkspaceTable] = []
        for path in sorted(self.directory.glob('*.json')):
            wid = path.stem
            if wid in self.tables:                        # loaded again: the old table's anchors go with it
                _release_anchors(self.tables[wid])
            try:
                table = WorkspaceTable.from_json(json.loads(path.read_bytes()))
                if table.workspace_id != wid:
                    raise EntryInvalid('mirror names another workspace')
            except (OSError, ValueError, EntryInvalid):
                self.tables[wid] = WorkspaceTable(wid, 0, 0, '', unavailable=True)   # never an empty table
                continue
            # K-20: recognized by the registered device and inode, not by the path; whatever now sits at the
            # registered path, or nothing, leaves the workspace unavailable rather than carrying its entries
            try:
                st = os.stat(table.root)
            except OSError:
                st = None
            if st is None or (st.st_dev, st.st_ino) != (table.device, table.inode):
                self.tables[wid] = WorkspaceTable(wid, 0, 0, '', unavailable=True)
                continue
            self.tables[wid] = table
            loaded.append(table)
        # H-03, H-22: each object's anchor again, by the recorded directory, once every workspace's storage root is
        # known; another directory there, none, or one that holds the engine's own files or a workspace's storage
        # leaves that object unavailable, never re-registered on its own
        from .fileobjects import reopen_anchor
        roots = self.storage_roots()
        for table in loaded:
            for alias, obj in table.objects.items():
                fd = reopen_anchor(obj, self.protected, roots)
                if fd is None:
                    table.unavailable_objects.add(alias)
                else:
                    table.anchors[alias] = fd
        for tmp in self.directory.glob('*.json.tmp'):     # a crash between write and rename leaves a temp file
            try:
                tmp.unlink()
            except OSError:
                pass

    def storage_roots(self) -> tuple[str, ...]:
        """Every workspace's registered storage root: no file object may be, hold or lie in one (H-22)."""
        return tuple(t.root for t in self.tables.values() if t.root)

    # ---- registration (K-20, D-10) ----
    def register(self, workspace_id: str, root: str) -> WriteResult:
        wid = check_workspace_id(workspace_id)
        if wid in self.tables:
            raise EntryInvalid('workspace id already registered')
        real = os.path.realpath(root)
        st = os.stat(real)
        if not os.path.isdir(real):
            raise EntryInvalid('workspace root is not a directory')
        from .fileobjects import overlaps
        for other in self.tables.values():           # H-22 the other way round: a root no registered object reaches
            for obj in other.objects.values():
                if overlaps(obj.dir_path, obj.name, obj.type, real):
                    raise EntryInvalid(f'a host file object holds or lies in this workspace root ({obj.alias})')
        for other in self.tables.values():
            if (other.device, other.inode) == (st.st_dev, st.st_ino):
                raise EntryInvalid('workspace root already registered under another id')
            if other.root and (real == other.root or real.startswith(other.root.rstrip('/') + '/')
                               or other.root.startswith(real.rstrip('/') + '/')):
                raise EntryInvalid('workspace roots must not nest (K-20)')
        table = WorkspaceTable(wid, st.st_dev, st.st_ino, real)
        table.entries[FALLBACK_DEFAULT.identity] = FALLBACK_DEFAULT
        result = self._write(table)
        if result.applied:
            self.tables[wid] = table
        return result

    def delete_workspace(self, workspace_id: str) -> None:
        table = self.tables.pop(workspace_id, None)
        if table is None:
            raise EntryInvalid('unknown workspace')
        _release_anchors(table)
        try:
            (self.directory / f'{workspace_id}.json').unlink()
        except FileNotFoundError:
            pass

    # ---- entry changes (K-13, K-14, K-17, K-18) ----
    def put(self, workspace_id: str, entry: Entry) -> WriteResult:
        table = self._table(workspace_id)
        return self._change(table, entry.identity, entry)

    def delete(self, workspace_id: str, key_kind: KeyKind, key: str) -> WriteResult:
        table = self._table(workspace_id)
        if (key_kind, key) not in table.entries:
            raise EntryInvalid('no such entry')
        return self._change(table, (key_kind, key), None)

    # ---- host file objects (H-01, H-02, H-22; the same write order and failure rules as entries, K-17, K-18) ----
    def register_object(self, workspace_id: str, alias: str, host_path: str, type_: int, ops: int, state: int,
                        approval: int) -> tuple[WriteResult, Any]:
        """OBJ_PUT: validate, resolve and anchor (fileobjects.anchor), then write; the same alias again replaces the
        object whole. EntryInvalid (table and mirror unchanged, nothing left open) when any of it fails."""
        from . import fileobjects as fo
        table = self._table(workspace_id)
        spec = fo.make_object(alias, host_path, type_, ops, state, approval)
        if spec.alias not in table.objects and len(table.objects) >= canonical.LIMITS.file_objects:
            raise EntryInvalid(f'a workspace holds at most {canonical.LIMITS.file_objects} objects')
        fd, obj = fo.anchor(spec, self.protected, self.storage_roots())
        return self._change_object(table, obj.alias, obj, fd), obj

    def set_object_mode(self, workspace_id: str, alias: str, state: EntryState, approval: Approval) -> WriteResult:
        """A persistent answer (H-09): only the object's state or approval mode changes; its anchor stays."""
        table = self._table(workspace_id)
        old = table.objects.get(alias)
        if old is None:
            raise EntryInvalid('no such object')
        return self._change_object(table, alias, replace(old, state=state, approval=approval))

    def delete_object(self, workspace_id: str, alias: str) -> WriteResult:
        table = self._table(workspace_id)
        if alias not in table.objects:
            raise EntryInvalid('no such object')
        return self._change_object(table, alias, None)

    def _change_object(self, table: WorkspaceTable, alias: str, new: Any, anchor: int | None = None) -> WriteResult:
        """As _change, for one object; ``anchor`` is the new object's freshly opened anchor, installed (and the old one
        closed) only if the change takes effect, closed otherwise."""
        from .fileobjects import narrows
        old = table.objects.get(alias)
        tightening = narrows(old, new, alias in table.unavailable_objects)
        proposed = dict(table.objects)
        if new is None:
            del proposed[alias]
        else:
            proposed[alias] = new
        result = self._write(replace(table, objects=proposed))
        if result.persisted or tightening or result.stage == 'fsync_dir':
            table.objects = proposed
            table.version += 1
            table.revs[('file', alias)] = table.version
            result.applied = True
            if new is None or anchor is not None:                # a new anchor replaces the old; a deletion drops it
                previous = table.anchors.pop(alias, None)
                if previous is not None:
                    os.close(previous)
                if anchor is not None:
                    table.anchors[alias] = anchor
                table.unavailable_objects.discard(alias)
        elif anchor is not None:
            os.close(anchor)
        if not result.persisted and result.applied:
            table.spawn_blocked = True
            if self.on_blocked:
                self.on_blocked(table.workspace_id)
        return result

    def _table(self, workspace_id: str) -> WorkspaceTable:
        table = self.tables.get(workspace_id)
        if table is None:
            raise EntryInvalid('unknown workspace')
        if table.unavailable:
            raise WorkspaceUnavailable(workspace_id)
        return table

    def _change(self, table: WorkspaceTable, identity: tuple[KeyKind, str], new: Entry | None) -> WriteResult:
        old = table.entries.get(identity)
        tightening = narrows(old, new)
        if tightening and new is None and old is not None:
            # K-43: while the deleted key existed its destinations never fell back to a coarser key; once it is gone the
            # next key decides them, and if that key allows, the deletion can let through what this entry refused
            from .matching import heir
            successor = heir(table.entries, identity)
            tightening = successor is None or successor.state is EntryState.DENY
        proposed = dict(table.entries)
        if new is None:
            del proposed[identity]
        else:
            proposed[identity] = new
        candidate = replace(table, entries=proposed)
        result = self._write(candidate)
        # K-18: a tightening change takes effect in memory even unpersisted; a relaxing change that failed before the
        # rename does not take effect; one that failed only at the directory fsync did reach the disk name and applies.
        if result.persisted or tightening or result.stage == 'fsync_dir':
            table.entries = proposed
            table.version += 1
            table.revs[identity] = table.version
            result.applied = True
        if not result.persisted and result.applied:
            table.spawn_blocked = True
            if self.on_blocked:
                self.on_blocked(table.workspace_id)
        return result

    def _write(self, table: WorkspaceTable) -> WriteResult:
        """K-17: temp file + fsync, rename, fsync the directory. Reports which step failed, if any."""
        final = self.directory / f'{table.workspace_id}.json'
        tmp = self.directory / f'{table.workspace_id}.json.tmp'
        data = json.dumps(table.to_json(), separators=(',', ':'), sort_keys=True).encode()
        try:
            self.disk.write_tmp(tmp, data)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            return WriteResult(False, False, 'write')
        try:
            self.disk.rename(tmp, final)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            return WriteResult(False, False, 'rename')
        try:
            self.disk.fsync_dir(self.directory)
        except OSError:
            return WriteResult(False, True, 'fsync_dir')
        return WriteResult(True, True)
