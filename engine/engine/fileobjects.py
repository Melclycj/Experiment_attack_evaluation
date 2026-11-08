"""Host file objects and file requests in the core (plan engine-v3-n16-file-read, 文件读 定稿; validation.md H-01, H-02,
H-03, H-07, H-10, H-11, H-18, H-20, H-21, H-22).

A file object is a directory or a file on the host, outside the workspace, that the user registered under an alias in a
workspace's table. Registration resolves the user's path as the engine uid, following symlinks (the user's own choice),
and opens a directory with O_PATH: the object itself, or the file's parent with the file's name kept. That descriptor,
the anchor, is the only starting point for opening a target; the mirror keeps the resolved directory and its device and
inode, which a restart checks again. A file object pins its directory, not the file's own inode: a file replaced whole
(written anew and renamed) is read in its new version.

A file request (list a directory, read a file) names an alias and a relative path. The core checks both at the first
checkpoint (check_file); after the PDP allows, it opens the target beneath the anchor through w2_open_beneath
(open_target), so nothing the agent sends is resolved outside the anchor, no symlink is followed, and only a regular
file (read) or a directory (list) is ever opened for real. The words a refusal can carry are the closed list of H-18.

TCB module: standard library only.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import errno
from enum import IntEnum
import os
import re
import stat
from typing import Any, Callable, Iterable

from connector import canonical as c
from connector.canonical import pack_list, u16, u64, u8
from .judgment import (DENY_NOT_AUTHORIZED, DENY_PDP, DENY_POLICY_CHANGED, DENY_RECORDED, DENY_TIMEOUT,
                       DENY_UNAVAILABLE, DENY_USER)
from .workspaces import Approval, EntryInvalid, EntryState

O_PATH = getattr(os, 'O_PATH', 0o10000000)
ANCHOR_FLAGS = O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
ALIAS = re.compile(r'[A-Za-z0-9_-]{1,64}')
OP_NAMES = {c.FILE_OP_OBJECTS: 'objects', c.FILE_OP_LIST: 'list', c.FILE_OP_READ: 'read'}
TYPE_NAMES = {c.FILE_TYPE_FILE: 'file', c.FILE_TYPE_DIR: 'directory'}
MODES = {(EntryState.ALLOW, Approval.NEVER): c.FILE_MODE_ALLOW, (EntryState.ALLOW, Approval.ALWAYS): c.FILE_MODE_ASK,
         (EntryState.DENY, Approval.NEVER): c.FILE_MODE_DENY}
OBJECT_KEYS = frozenset({'alias', 'host_path', 'type', 'ops', 'state', 'approval', 'dir_path', 'name', 'device', 'inode'})


class FileReason(IntEnum):
    """The refusal words of a file request, code = position in canonical.FILE_REASONS (H-18). A distinct type, so the
    hook's shared paths can pass the core's DENY_* codes and the file-only words alike (wire_reason)."""

    NOT_REGISTERED = 1
    OP_NOT_GRANTED = 2
    BAD_PATH = 3
    OUTSIDE_OR_SYMLINK = 4
    WRONG_TYPE = 5
    TOO_LARGE = 6
    USER_DENIED = 7
    PDP_DENIED = 8
    RECORDED_DENY = 9
    POLICY_CHANGED = 10
    UNAVAILABLE = 11
    TIMEOUT = 12
    NOT_FOUND = 13


# the refusals the hook's shared paths give, in the words the network side already has (proposal 第二节: 沿用网络一侧的
# 词); a transfer row has no objects, so its refusal reads as not registered; anything else is unavailable (fail closed)
FROM_CORE = {DENY_RECORDED: FileReason.RECORDED_DENY, DENY_USER: FileReason.USER_DENIED, DENY_TIMEOUT: FileReason.TIMEOUT,
             DENY_UNAVAILABLE: FileReason.UNAVAILABLE, DENY_NOT_AUTHORIZED: FileReason.NOT_REGISTERED,
             DENY_PDP: FileReason.PDP_DENIED, DENY_POLICY_CHANGED: FileReason.POLICY_CHANGED}


def wire_reason(reason: int) -> int:
    """The FILE_DENY code of a refusal: a FileReason as it is, a core DENY_* code by FROM_CORE."""
    if isinstance(reason, FileReason):
        return int(reason)
    return int(FROM_CORE.get(reason, FileReason.UNAVAILABLE))


class FileRefused(Exception):
    """Opening the target failed after the PDP allowed: the request is refused with ``reason``; ``detail`` (the errno's
    name) goes to the trace only (H-18)."""

    def __init__(self, reason: FileReason, detail: str) -> None:
        super().__init__(detail)
        self.reason, self.detail = reason, detail


# ---- objects (H-01, H-02) -------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class FileObject:
    alias: str
    host_path: str          # as the user gave it (absolute, links unresolved): the prefix the MCP server matches on
    type: int               # canonical.FILE_TYPE_FILE or FILE_TYPE_DIR
    ops: int                # canonical.FILE_OPS_* bits
    state: EntryState
    approval: Approval
    dir_path: str = ''      # the resolved directory the anchor opens: the object itself, or the file's parent
    name: str = ''          # a file object's resolved file name (one segment); '' for a directory object
    device: int = 0         # of dir_path, read from the anchor
    inode: int = 0

    @property
    def mode(self) -> int:
        return MODES[(self.state, self.approval)]

    @property
    def target(self) -> tuple[int, str, str, int, int]:
        """What a request is opened against: the type, the anchor's directory and identity, the file name."""
        return (self.type, self.dir_path, self.name, self.device, self.inode)


def check_alias(text: str) -> str:
    if not isinstance(text, str) or not ALIAS.fullmatch(text):
        raise EntryInvalid('alias does not read: 1-64 letters, digits, - or _')
    return text


def check_host_path(text: str) -> str:
    if not isinstance(text, str) or not text.startswith('/') or '\x00' in text or \
            len(os.fsencode(text)) > c.LIMITS.host_path:
        raise EntryInvalid(f'host path must be absolute, without NUL, at most {c.LIMITS.host_path} bytes')
    return text


def make_object(alias: str, host_path: str, type_: int, ops: int, state: int, approval: int) -> FileObject:
    """The five registered items, validated (H-01); the anchor is not opened here."""
    alias, host_path = check_alias(alias), check_host_path(host_path)
    if type_ not in TYPE_NAMES:
        raise EntryInvalid('type is file or directory')
    allowed = (c.FILE_OPS_READ, c.FILE_OPS_READ | c.FILE_OPS_LIST) if type_ == c.FILE_TYPE_DIR else (c.FILE_OPS_READ,)
    if ops not in allowed:
        raise EntryInvalid('operations: read, and list on a directory only')
    if (state, approval) not in ((1, 1), (1, 2), (2, 1)):
        raise EntryInvalid('mode is allow, ask every time or deny')
    return FileObject(alias, host_path, type_, ops, EntryState(state), Approval(approval))


def _within(path: str, top: str) -> bool:
    return path == top or path.startswith(top.rstrip('/') + '/')


def overlaps(dir_path: str, name: str, type_: int, top: str) -> bool:
    """A directory object that is, holds or lies under ``top``; a file object whose file lies under it."""
    target = dir_path if type_ == c.FILE_TYPE_DIR else os.path.join(dir_path, name)
    return _within(target, top) or (type_ == c.FILE_TYPE_DIR and _within(top, target))


def check_not_engine_owned(dir_path: str, name: str, type_: int, protected: Iterable[str],
                           workspaces: Iterable[str] = ()) -> None:
    """H-22 (按失败即关，用户 2026-11-05 确认，提案待裁定 3): a directory object that is, holds or lies under the deployment root,
    the state directory or the record directory is refused; a file object only if the file itself lies in one. The
    storage root of every workspace of the engine counts the same (main thread 2026-11-04; design 3.3 "不进这一列：
    工作区本身")."""
    for top in protected:
        real = os.path.realpath(top)
        if overlaps(dir_path, name, type_, real):
            raise EntryInvalid(f"the path holds or lies in the engine's own files ({real})")
    for top in workspaces:
        real = os.path.realpath(top)
        if overlaps(dir_path, name, type_, real):
            raise EntryInvalid(f"the path holds or lies in a workspace's storage ({real})")


def opened_path(fd: int) -> str:
    """Where an opened directory really is: the kernel's own path of the descriptor (/proc/self/fd/N), not the text it
    was opened by, so a check on it cannot be raced by a symlink swapped in before the open (cold review, minor 3). A
    directory removed meanwhile, or one this process cannot name, has no such path: EntryInvalid."""
    try:
        where = os.readlink(f'/proc/self/fd/{fd}')
    except OSError as e:
        raise EntryInvalid(f'cannot name the opened directory: {e.strerror}') from None
    if not where.startswith('/') or where.endswith(' (deleted)'):
        raise EntryInvalid('the opened directory has no path now')
    return where


def anchor(spec: FileObject, protected: Iterable[str], workspaces: Iterable[str] = ()) -> tuple[int, FileObject]:
    """H-02: resolve as the engine uid, following symlinks; open the directory with O_PATH; a file object's file must
    exist and be a regular file now. H-22 is checked on where the anchor opened (opened_path), and that is the directory
    recorded. Returns the anchor (owned by the caller) and the object with its directory and identity. EntryInvalid on
    any failure, nothing left open."""
    try:
        real = os.path.realpath(spec.host_path, strict=True)
    except (OSError, ValueError) as e:
        raise EntryInvalid(f'host path does not resolve: {getattr(e, "strerror", None) or e}') from None
    dir_path, name = (real, '') if spec.type == c.FILE_TYPE_DIR else os.path.split(real)
    if spec.type == c.FILE_TYPE_FILE and not name:
        raise EntryInvalid('a file object names a file')
    try:
        fd = os.open(dir_path, ANCHOR_FLAGS)
    except OSError as e:
        raise EntryInvalid(f'cannot open the directory: {e.strerror}') from None
    try:
        dir_path = opened_path(fd)
        check_not_engine_owned(dir_path, name, spec.type, protected, workspaces)
        st = os.fstat(fd)
        if spec.type == c.FILE_TYPE_FILE and not stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
            raise EntryInvalid('a file object must be a regular file')
    except (OSError, EntryInvalid) as e:
        os.close(fd)
        if isinstance(e, EntryInvalid):
            raise
        raise EntryInvalid(f'cannot read the object: {e.strerror}') from None
    return fd, replace(spec, dir_path=dir_path, name=name, device=st.st_dev, inode=st.st_ino)


def reopen_anchor(obj: FileObject, protected: Iterable[str], workspaces: Iterable[str] = ()) -> int | None:
    """H-03, H-22 at start: the recorded directory again; None (the object is unavailable) when it does not open, is
    another directory now, or, where it opened (opened_path), holds or lies in the engine's own files or a workspace's
    storage. A recorded directory or file name that cannot reach an open (a NUL byte, a lone surrogate: the mirror
    damaged or tampered with) leaves this object unavailable, never the start (K-19)."""
    try:
        raw = (os.fsencode(obj.dir_path), os.fsencode(obj.name))
    except ValueError:
        return None
    if any(b'\x00' in part for part in raw):
        return None
    try:
        fd = os.open(obj.dir_path, ANCHOR_FLAGS)
    except (OSError, ValueError):
        return None
    try:
        check_not_engine_owned(opened_path(fd), obj.name, obj.type, protected, workspaces)
        st = os.fstat(fd)
    except (EntryInvalid, OSError, ValueError):
        os.close(fd)
        return None
    if (st.st_dev, st.st_ino) != (obj.device, obj.inode):
        os.close(fd)
        return None
    return fd


def narrows(old: FileObject | None, new: FileObject | None, old_unavailable: bool = False) -> bool:
    """K-18 收紧类 for objects (H-01): deleting, turning to deny, dropping an operation, or asking where it did not ask,
    on the same target. Anything else may let a request through that the old table refused."""
    if new is None or new.state is EntryState.DENY:
        return True
    if old is None or old.state is EntryState.DENY or old_unavailable:
        return False
    return new.target == old.target and not new.ops & ~old.ops and new.approval >= old.approval


def same_decision(a: FileObject | None, b: FileObject | None) -> bool:
    """H-07's comparison at the third checkpoint (and before the open): the same object (alias, the anchor's device
    and inode, the file name), the same state and approval mode. The operation still granted and the object still
    available are the first checkpoint's, which ran before this."""
    return a is not None and b is not None and a.alias == b.alias and a.target == b.target and a.state is b.state \
        and a.approval is b.approval


def object_to_json(o: FileObject) -> dict[str, Any]:
    return {'alias': o.alias, 'host_path': o.host_path, 'type': o.type, 'ops': o.ops, 'state': int(o.state),
            'approval': int(o.approval), 'dir_path': o.dir_path, 'name': o.name, 'device': o.device, 'inode': o.inode}


def object_from_json(d: Any) -> FileObject:
    if not isinstance(d, dict) or set(d) != OBJECT_KEYS:
        raise EntryInvalid('object has the wrong keys')
    if not all(isinstance(d[k], int) and not isinstance(d[k], bool) for k in
               ('type', 'ops', 'state', 'approval', 'device', 'inode')) or \
            not all(isinstance(d[k], str) for k in ('alias', 'host_path', 'dir_path', 'name')):
        raise EntryInvalid('object field has the wrong type')
    obj = make_object(d['alias'], d['host_path'], d['type'], d['ops'], d['state'], d['approval'])
    if not d['dir_path'].startswith('/') or '/' in d['name'] or (d['name'] == '') != (obj.type == c.FILE_TYPE_DIR):
        raise EntryInvalid('object directory or name does not read')
    return replace(obj, dir_path=d['dir_path'], name=d['name'], device=d['device'], inode=d['inode'])


# ---- requests (H-04 on the core's side, H-07, H-20) ----------------------------------------------------------------------
@dataclass(frozen=True)
class FileRequest:
    """FILE_ASK as the core read it (SPEC §3.8): the worker passed the alias and the path on as the MCP server sent
    them; their rules are checked at the first checkpoint, not when the frame is read."""

    seq: int
    sender_uid: int
    op: int
    alias: bytes
    path: bytes
    start: int              # a read's offset, a list's first entry
    length: int             # a read's length; 0 for a list

    def summary(self) -> dict[str, Any]:
        """H-20: the request's every field, alias and path as latin-1 text (encode('latin-1') gives the bytes back)."""
        return {'seq': self.seq, 'request_kind': 'file', 'file_op': OP_NAMES.get(self.op, str(self.op)),
                'alias': self.alias.decode('latin-1'), 'path': self.path.decode('latin-1'), 'start': self.start,
                'length': self.length}

    def admission_record(self) -> dict[str, Any]:
        return self.summary()


def check_rel_path(path: bytes, type_: int) -> str | None:
    """H-07's rule; None when the path reads, else why not. Split on /, every segment non-empty and neither . nor ..,
    no NUL, at most 4096 bytes, not starting with /; empty means the object itself, and is all a file object takes."""
    if len(path) > c.LIMITS.file_path:
        return f'longer than {c.LIMITS.file_path} bytes'
    if b'\x00' in path:
        return 'NUL byte'
    if not path:
        return None
    if type_ == c.FILE_TYPE_FILE:
        return 'a file object takes no path'
    if path.startswith(b'/'):
        return 'absolute'
    if any(seg in (b'', b'.', b'..') for seg in path.split(b'/')):
        return 'an empty, . or .. segment'
    return None


def check_file(transfer: bool, table: Any, r: FileRequest) -> tuple[tuple[FileReason, str] | None, FileObject | None,
                                                                    tuple[tuple[str, Any], ...]]:
    """The file part of the first checkpoint (H-07), in order: a transfer row hangs no objects; the workspace; the alias;
    the object's availability, its recorded deny, the operation; the path rule; a read's length. Returns the refusal
    (reason, basis), the object, and detail for the record."""
    if transfer:
        return (FileReason.NOT_REGISTERED, 'transfer_row'), None, ()
    if table is None or table.unavailable:
        return (FileReason.UNAVAILABLE, 'workspace_unavailable'), None, ()
    try:
        alias = check_alias(r.alias.decode('ascii'))
    except (UnicodeDecodeError, EntryInvalid):
        return (FileReason.NOT_REGISTERED, 'alias_grammar'), None, ()
    obj = table.objects.get(alias)
    if obj is None:
        return (FileReason.NOT_REGISTERED, 'not_registered'), None, ()
    if alias in table.unavailable_objects or alias not in table.anchors:
        return (FileReason.UNAVAILABLE, 'object_unavailable'), obj, ()
    if obj.state is EntryState.DENY:
        return (FileReason.RECORDED_DENY, 'recorded_deny'), obj, ()
    if not obj.ops & (c.FILE_OPS_LIST if r.op == c.FILE_OP_LIST else c.FILE_OPS_READ):
        return (FileReason.OP_NOT_GRANTED, 'op_not_granted'), obj, ()
    why = check_rel_path(r.path, obj.type)
    if why is not None:
        return (FileReason.BAD_PATH, 'bad_path'), obj, (('why', why),)
    if r.op == c.FILE_OP_READ and not 1 <= r.length <= c.LIMITS.file_read:
        return (FileReason.TOO_LARGE, 'too_large'), obj, ()
    return None, obj, ()


def reason_for_errno(err: int, op: int) -> FileReason:
    """H-18: what an open failure tells the agent. ENOTDIR is a missing directory on the way for a read, a target of the
    wrong type for a list (w2_open_beneath gives it for a list of a non-directory). ENAMETOOLONG is the kernel's own
    path limit (a segment over 255 bytes, or the 4096 bytes the rule allows plus the NUL): the path, not the object."""
    if err in (errno.ELOOP, errno.EXDEV):
        return FileReason.OUTSIDE_OR_SYMLINK
    if err == errno.ENAMETOOLONG:
        return FileReason.BAD_PATH
    if err == errno.ENOENT or (err == errno.ENOTDIR and op != c.FILE_OP_LIST):
        return FileReason.NOT_FOUND
    if err in (errno.ENOTDIR, errno.EISDIR, errno.EOPNOTSUPP):
        return FileReason.WRONG_TYPE
    return FileReason.UNAVAILABLE


def open_target(opener: Callable[[int, bytes, int], int], anchor_fd: int, obj: FileObject,
                r: FileRequest) -> tuple[int, os.stat_result]:
    """H-10, H-11: beneath the anchor only, through w2_open_beneath (``opener``); a directory object's empty path is
    the anchor itself ("."), a file object is opened by its registered name. FileRefused on failure."""
    path = os.fsencode(obj.name) if obj.type == c.FILE_TYPE_FILE else (r.path or b'.')
    try:
        fd = opener(anchor_fd, path, 2 if r.op == c.FILE_OP_LIST else 1)
    except OSError as e:
        raise FileRefused(reason_for_errno(e.errno or 0, r.op), errno.errorcode.get(e.errno or 0, str(e.errno))) from None
    except ValueError:
        raise FileRefused(FileReason.BAD_PATH, 'path does not reach the open') from None
    try:
        return fd, os.fstat(fd)
    except OSError as e:
        os.close(fd)
        raise FileRefused(FileReason.UNAVAILABLE, errno.errorcode.get(e.errno or 0, 'fstat')) from None


def actual_length(size: int, start: int, length: int) -> int:
    """H-20, N-27: the bytes a read can hand over, by the size at the open: max(0, min(length, size - start))."""
    return max(0, min(length, size - start))


# ---- what goes on the frames (SPEC §3.4, §3.6, §3.8) ----------------------------------------------------------------------
NETWORK_FIELDS = [u8(0), b'', b'', u64(0), u64(0), pack_list([])]       # the six appended fields of a network request
BLANK_HTTP = [b'', b'', b'', u16(0), b'', b'', pack_list([]), pack_list([]), b'', pack_list([]), u64(0)]


def request_fields(r: FileRequest, obj: FileObject) -> list[bytes]:
    """QUESTION's fields 19–24 and PDP_REQUEST's 23–28 for a file request (H-09)."""
    return [u8(r.op), r.alias, r.path, u64(r.start), u64(r.length),
            pack_list([os.fsencode(obj.host_path), u8(obj.type), u8(obj.ops)])]


def object_cell(obj: FileObject) -> bytes:
    """The cell a file request's QUESTION and PDP_REQUEST show, in pdp.entry_fields' six-item shape: the object's state
    and approval mode, no lists, no named addresses."""
    return pack_list([u8(int(obj.state)), pack_list([]), pack_list([]), pack_list([]), u8(int(obj.approval)),
                      pack_list([])])


def visible_objects(table: Any) -> list[FileObject]:
    """H-21: allowed and ask-every-time objects that are available; a recorded deny or an unavailable one is not
    listed."""
    if table is None or table.unavailable:
        return []
    return [o for alias, o in sorted(table.objects.items())
            if o.state is EntryState.ALLOW and alias not in table.unavailable_objects and alias in table.anchors]


def object_item(o: FileObject) -> bytes:
    """One FILE_OBJECT_LIST item: alias, the registered host path, type, operations, mode; never the anchor's directory,
    device or inode."""
    return pack_list([o.alias.encode('ascii'), os.fsencode(o.host_path), u8(o.type), u8(o.ops), u8(o.mode)])


def snapshot_items(table: Any) -> list[bytes]:
    """TABLE_SNAPSHOT's objects (H-09, K-49): every object, each item as in FILE_OBJECT_LIST plus available(u8)."""
    if table is None or table.unavailable:
        return []
    return [pack_list(c.unpack_list(object_item(o)) +
                      [u8(0 if alias in table.unavailable_objects or alias not in table.anchors else 1)])
            for alias, o in sorted(table.objects.items())]
