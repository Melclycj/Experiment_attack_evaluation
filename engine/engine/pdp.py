"""The hook port (agent-rm-model 648d60f2 4.2 身份与四条口, 4.3 hook; SPEC-canonical-form.md §3.6 link F; validation.md
K-03, K-40, K-48, K-49, K-50).

``<root>/hook/pdp.sock``: an AF_UNIX socket in a directory of its own, outside the engine's state directory and never
inside any cell. The deployment makes the directory once, as root: owner the engine uid, group the PDP's dedicated
group, mode 2750 (setgid, so the socket the core binds there belongs to that group too); the core checks this at start
and makes the socket 0660. At accept the core compares the peer's uid (SO_PEERCRED, the one exception K-40 names) with
the PDP uid of the catalog and drops anyone else. One PDP at a time: a second connection is dropped while one is up.

Three verbs and no other: a request to the PDP (core to PDP), the PDP's answer (allow or deny), and a read-only table
query answered with a snapshot that changes nothing. No verb writes a table. Request ids are the engine's epoch and the
global admission number, bound to the connection they went out on; an answer counts once, only for an id issued on its
own connection, unanswered, whose request still waits. When the PDP goes, its unanswered requests are refused.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import selectors
import socket
import stat
import struct
from typing import Any

from connector import canonical
from connector.canonical import (LINK_F_TO_CORE, PDP_ALLOW, PDP_ANSWER, PDP_DENY, PDP_REQUEST, SNAP_OK, SNAP_TOO_LARGE, SNAP_UNAVAILABLE,
                                 SNAP_UNKNOWN, TABLE_QUERY, TABLE_SNAPSHOT, FrameParser, Malformed, pack_frame,
                                 pack_list, read_uint, u64, u8)

FRAME_MAX = canonical.LIMITS.frame_bd
OUT_MAX = 4096                     # frames waiting to go to the PDP before it is dropped as not draining
DIR_MODE = 0o2750
SOCKET_NAME = 'pdp.sock'


class HookDirRefused(Exception):
    """The hook directory is not the one the deployment was to make (K-48)."""


def check_hook_dir(path: Path, engine_uid: int, pdp_gid: int) -> None:
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != engine_uid or st.st_gid != pdp_gid or \
            stat.S_IMODE(st.st_mode) != DIR_MODE:
        raise HookDirRefused(f'{path}: a directory owned by the engine uid, group the PDP group, mode 2750 expected')


def entry_fields(e: Any) -> list[bytes]:
    """A cell as the QUESTION, the PDP_REQUEST and the table snapshot carry it: state, methods, prefixes, accounts,
    approval and the named addresses in stored order (K-28, K-50, K-57)."""
    return [u8(int(e.state)), pack_list([x.encode() for x in sorted(e.methods)]),
            pack_list([x.encode() for x in e.prefixes]), pack_list([x.encode() for x in sorted(e.accounts)]),
            u8(int(e.approval)), pack_list([x.encode('ascii') for x in e.addresses])]


@dataclass(eq=False)
class PdpLink:
    """One connected PDP and its outgoing frames (each with the memfd it carries, if any)."""

    sock: socket.socket
    parser: FrameParser = field(default_factory=lambda: FrameParser(FRAME_MAX, LINK_F_TO_CORE))
    out: list[list[Any]] = field(default_factory=list)      # [frame, fd or None, offset]
    watching: bool = False
    dead: bool = False


class HookPort:
    def __init__(self, loop: Any, recorder: Any, hook_dir: Path, pdp_uid: int, pdp_gid: int, engine_uid: int, hook: Any,
                 workspaces: Any) -> None:
        check_hook_dir(hook_dir, engine_uid, pdp_gid)
        self.loop, self.recorder, self.hook, self.workspaces = loop, recorder, hook, workspaces
        self.pdp_uid = pdp_uid
        self.path = hook_dir / SOCKET_NAME
        self.link: PdpLink | None = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)
        try:
            self.listener.bind(str(self.path))
        finally:
            os.umask(old_umask)
        os.chmod(self.path, 0o660)
        if os.lstat(self.path).st_gid != pdp_gid:              # the setgid directory gave it the PDP group
            raise HookDirRefused('the hook socket did not take the PDP group')
        self.listener.listen(2)
        self.listener.setblocking(False)
        loop.watch(self.listener.fileno(), selectors.EVENT_READ, self._accept)
        hook.pdp = self

    # ---- connections (K-48) ----
    def _accept(self) -> None:
        try:
            sock, _ = self.listener.accept()
        except (BlockingIOError, InterruptedError):
            return
        # the one place the core reads a peer credential (K-40): the PDP's identity at accept, fixed by the kernel
        _, uid, _ = struct.unpack('iII', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != self.pdp_uid or self.link is not None:
            self.recorder.diagnostic('pdp_refused', uid=uid, reason='not the PDP uid' if uid != self.pdp_uid else 'a PDP is connected')
            sock.close()
            return
        sock.setblocking(False)
        link = PdpLink(sock)
        self.link = link
        self.loop.watch(sock.fileno(), selectors.EVENT_READ, lambda: self._readable(link))
        self._record('pdp_connected')
        self.hook.pdp_connected(link)

    def _drop(self, link: PdpLink, why: str) -> None:
        if link.dead:
            return
        link.dead = True
        self.loop.forget(link.sock.fileno())
        for item in link.out:
            if item[1] is not None:                              # the frame's own copy of the body memfd
                os.close(item[1])
                item[1] = None
        link.out.clear()
        try:
            link.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        link.sock.close()
        if self.link is link:
            self.link = None
        self._record('pdp_disconnected', reason=why)
        self.hook.pdp_lost(link)

    # ---- inbound: answers and table queries (K-49) ----
    def _readable(self, link: PdpLink) -> None:
        try:
            data = link.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._drop(link, 'read failed')
            return
        if not data:
            self._drop(link, 'closed by the PDP')
            return
        try:
            frames = link.parser.feed(data)
        except Malformed as e:
            self._drop(link, f'malformed: {e}')                 # a verb of another port, or a frame that does not read
            return
        for kind, fields in frames:
            if link.dead:
                return
            try:
                if kind == PDP_ANSWER:
                    epoch, admission, verdict = fields[0].decode('ascii'), read_uint(fields[1], 8), read_uint(fields[2], 1)
                    if verdict not in (PDP_ALLOW, PDP_DENY):
                        raise Malformed(f'verdict {verdict}')
                    self.hook.pdp_answer(link, epoch, admission, verdict == PDP_ALLOW)
                elif kind == TABLE_QUERY:
                    self._snapshot(link, fields[0])
            except (Malformed, UnicodeDecodeError) as e:
                self._drop(link, f'malformed: {e}')
                return

    def _snapshot(self, link: PdpLink, field_: bytes) -> None:
        """Read-only: the workspace's entries, its host file objects (H-09: alias, the registered host path, type,
        operations, mode and whether the object is available; never the anchor's directory, device or inode) and its
        table version; nothing is changed, no credential is shown."""
        from .fileobjects import snapshot_items
        wid = field_.decode('utf-8', 'replace')
        table = self.workspaces.tables.get(wid)
        if table is None:
            status, version, entries, objects = SNAP_UNKNOWN, 0, [], []
        elif table.unavailable:
            status, version, entries, objects = SNAP_UNAVAILABLE, table.version, [], []
        else:
            status, version = SNAP_OK, table.version
            entries = [pack_list([u8(int(e.key_kind)), e.key.encode()] + entry_fields(e)) for e in table.entries.values()]
            objects = snapshot_items(table)
        frame = pack_frame(TABLE_SNAPSHOT, [field_, u8(status), u64(version), pack_list(entries), pack_list(objects)])
        if len(frame) - 4 > FRAME_MAX:
            frame = pack_frame(TABLE_SNAPSHOT, [field_, u8(SNAP_TOO_LARGE), u64(version), pack_list([]), pack_list([])])
        self._queue(link, frame, None)

    # ---- outbound: one request per request (K-50) ----
    def send_request(self, link: PdpLink, fields: list[bytes], memfd: int | None) -> None:
        """The queued frame holds its own copy of the body memfd. The request's descriptor is closed as soon as the
        request is withdrawn or its row closes, and the next descriptor the engine opens may take its number (a client
        connection, a judgment socket); a frame still waiting for the PDP to drain must not send by that number. A file
        request has no body and no memfd (H-09)."""
        if link.dead:
            return
        try:
            fd = os.dup(memfd) if memfd is not None else None
        except OSError:
            self._drop(link, 'cannot hold the request body')
            return
        self._queue(link, pack_frame(PDP_REQUEST, fields), fd)

    def _queue(self, link: PdpLink, frame: bytes, fd: int | None) -> None:
        if link.dead or len(link.out) >= OUT_MAX:
            if fd is not None:
                os.close(fd)
            if not link.dead:
                self._drop(link, 'the PDP does not drain its port')
            return
        link.out.append([frame, fd, 0])
        self._flush(link)

    def _flush(self, link: PdpLink) -> None:
        while link.out and not link.dead:
            item = link.out[0]
            frame, fd, offset = item
            view = memoryview(frame)[offset:]
            try:
                if offset == 0 and fd is not None:
                    n = socket.send_fds(link.sock, [view], [fd], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                else:
                    n = link.sock.send(view, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            except (BlockingIOError, InterruptedError):
                if not link.watching:
                    self.loop.watch(link.sock.fileno(), selectors.EVENT_WRITE, lambda: self._flush(link))
                    link.watching = True
                return
            except OSError:
                self._drop(link, 'write failed')
                return
            if fd is not None and offset == 0:                  # the descriptor went with the frame's first bytes
                os.close(fd)
                item[1] = None
            item[2] += n
            if item[2] >= len(frame):
                link.out.pop(0)
        if link.watching and not link.dead:
            self.loop.watch(link.sock.fileno(), selectors.EVENT_WRITE, None)
            link.watching = False

    def _record(self, kind: str, **detail: Any) -> None:
        try:
            self.recorder.record(kind, 'observed', 'none', source_ref={'port': 'hook', 'object': 'pdp'},
                                 detail=detail or None)
        except Exception:                        # RecordFault latched already; the round hook closes the rows
            pass

    def close(self) -> None:
        if self.link is not None:
            self._drop(self.link, 'engine stopping')
        self.loop.forget(self.listener.fileno())
        self.listener.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
