"""Management port (agent-rm-model 3.4, 3.7 核心对外三条口; SPEC-canonical-form.md §3.4; validation.md K-27, K-28, K-29).

``state/admin.sock``: AF_UNIX, owned by the engine uid, mode 0600, never inside any cell. Verbs are the closed set of the
link D table; a frame of another link disconnects the client (K-03). Questions carry the request as the core will
execute it, with the same memfd (K-28), and the credential binding the engine computed (account and placement, or
none; never a truth). Entry and credential changes go through the stores, which validate (K-05, K-29, K-30) and persist (K-17);
the reply says whether the mirror holds the change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import selectors
import socket
from typing import Any

from connector import canonical
from connector.canonical import (ANSWER, CRED_DEL, CRED_PUT, ENTRY_DEL, ENTRY_PUT, ERR, KEY_KIND_FILE, LINK_D_TO_CORE,
                                 OBJ_DEL, OBJ_PUT, OK, QUESTION, QUESTION_WITHDRAWN, ROW_LIST, ROW_START, ROW_STOP,
                                 WS_CREATE, WS_DELETE, WS_HOLD, WS_LIST, WS_RELEASE, FrameParser, Malformed, pack_frame,
                                 pack_list, read_uint, u16, u64, u8, unpack_list)
from . import fileobjects as fo
from .matching import Binding, Match
from .pdp import entry_fields
from .workspaces import (Entry, EntryInvalid, KeyKind, WorkspaceUnavailable, check_account, check_host_port, check_workspace_id,
                         make_entry)

CLIENTS_MAX = 4
FRAME_MAX = canonical.LIMITS.frame_bd
OUT_BYTES_MAX = 16 << 20            # bytes waiting to go to one client before it is dropped as not draining
# ERR codes
ERR_MALFORMED, ERR_UNKNOWN, ERR_REFUSED, ERR_UNAVAILABLE, ERR_UNKNOWN_QUESTION, ERR_NOT_PERSISTED, ERR_BUSY = 1, 2, 3, 4, 5, 6, 7


def text(field: bytes, limit: int = 4096) -> str:
    if len(field) > limit:
        raise Malformed('field too long')
    try:
        return field.decode('utf-8')
    except UnicodeDecodeError:
        raise Malformed('field is not UTF-8') from None


def texts(field: bytes, limit: int = 256) -> list[str]:
    return [text(x) for x in unpack_list(field, limit)]


@dataclass(eq=False)
class Client:
    sock: socket.socket
    parser: FrameParser
    out: list[list[Any]] = field(default_factory=list)      # [frame, fd or None, offset, question id or None], in order
    queued: int = 0                                         # bytes in ``out`` not yet sent
    watching: bool = False
    dead: bool = False


class AdminPort:
    def __init__(self, loop: Any, recorder: Any, state_dir: Path, hook: Any, workspaces: Any, credentials: Any,
                 lifecycle: Any, catalog_workspaces: dict[str, str]) -> None:
        """``catalog_workspaces`` maps the deployment's workspace ids to their root paths: WS_CREATE binds a table to one
        of them by identity (D-10); the spawner mounts only catalog workspaces."""
        self.loop, self.recorder, self.hook = loop, recorder, hook
        self.workspaces, self.credentials, self.lifecycle = workspaces, credentials, lifecycle
        self.catalog_workspaces = catalog_workspaces
        self.path = Path(state_dir) / 'admin.sock'
        self.clients: list[Client] = []
        self.pending_questions: dict[int, bytes] = {}       # question_id -> frame (resent to a client that connects)
        self.pending_fds: dict[int, int | None] = {}        # None: a file request's question carries no memfd
        self.holds: dict[str, Client] = {}                  # workspace id -> the one connection holding it (K-55)
        hook.admin = self
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        old_umask = os.umask(0o177)
        try:
            self.listener.bind(str(self.path))
        finally:
            os.umask(old_umask)
        os.chmod(self.path, 0o600)
        self.listener.listen(CLIENTS_MAX)
        self.listener.setblocking(False)
        loop.watch(self.listener.fileno(), selectors.EVENT_READ, self._accept)

    # ---- connections ----
    def _accept(self) -> None:
        try:
            sock, _ = self.listener.accept()
        except (BlockingIOError, InterruptedError):
            return
        if len(self.clients) >= CLIENTS_MAX:
            sock.close()
            return
        sock.setblocking(False)
        client = Client(sock, FrameParser(FRAME_MAX, LINK_D_TO_CORE))
        self.clients.append(client)
        self.loop.watch(sock.fileno(), selectors.EVENT_READ, lambda: self._readable(client))
        for qid, frame in self.pending_questions.items():
            self._send(client, frame, self.pending_fds.get(qid), qid)

    def _drop(self, client: Client) -> None:
        if client.dead:
            return
        client.dead = True
        self.loop.forget(client.sock.fileno())
        for item in client.out:
            if item[1] is not None:                         # the frame's own copy of a question's memfd
                os.close(item[1])
                item[1] = None
        client.out.clear()
        try:
            client.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client.sock.close()
        if client in self.clients:
            self.clients.remove(client)
        for wid in [w for w, holder in self.holds.items() if holder is client]:    # K-55: a hold ends with its connection
            del self.holds[wid]

    def _readable(self, client: Client) -> None:
        try:
            data = client.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._drop(client)
            return
        if not data:
            self._drop(client)
            return
        try:
            frames = client.parser.feed(data)
        except Malformed:
            self._drop(client)                      # K-03: a kind of another link, or a frame that does not read
            return
        for kind, fields in frames:
            try:
                self._dispatch(client, kind, fields)
            except Malformed as e:
                self._err(client, kind, ERR_MALFORMED, str(e))
            except WorkspaceUnavailable as e:
                self._err(client, kind, ERR_UNAVAILABLE, str(e))
            except (EntryInvalid, ValueError, OSError) as e:     # refused by a store's validation or by the filesystem
                self._err(client, kind, ERR_REFUSED, f'{type(e).__name__}: {e}')
            if client.dead:
                return

    def _send(self, client: Client, frame: bytes, fd: int | None = None, question_id: int | None = None) -> None:
        """Frames go out whole and in order through the client's queue: one the socket takes only in part goes on when
        the client reads (K-28). A queued QUESTION holds its own copy of the memfd, since the request's descriptor closes
        when the question is answered or withdrawn and the number may be taken by another file meanwhile."""
        if client.dead:
            return
        if client.queued + len(frame) > OUT_BYTES_MAX:
            self._drop(client)
            return
        if fd is not None:
            try:
                fd = os.dup(fd)
            except OSError:
                self._drop(client)
                return
        client.out.append([frame, fd, 0, question_id])
        client.queued += len(frame)
        self._flush(client)

    def _flush(self, client: Client) -> None:
        while client.out and not client.dead:
            item = client.out[0]
            frame, fd, offset, _ = item
            view = memoryview(frame)[offset:]
            try:
                if offset == 0 and fd is not None:
                    n = socket.send_fds(client.sock, [view], [fd], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                else:
                    n = client.sock.send(view, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            except (BlockingIOError, InterruptedError):
                if not client.watching:
                    self.loop.watch(client.sock.fileno(), selectors.EVENT_WRITE, lambda: self._flush(client))
                    client.watching = True
                return
            except OSError:
                self._drop(client)
                return
            if fd is not None and offset == 0:              # the descriptor went with the frame's first bytes
                os.close(fd)
                item[1] = None
            item[2] += n
            client.queued -= n
            if item[2] >= len(frame):
                client.out.pop(0)
        if client.watching and not client.dead:
            self.loop.watch(client.sock.fileno(), selectors.EVENT_WRITE, None)
            client.watching = False

    def _reply(self, client: Client, kind: int, fields: list[bytes]) -> None:
        self._send(client, pack_frame(kind, fields))

    def _ok(self, client: Client, verb: int, payload: list[bytes] | None = None) -> None:
        self._reply(client, OK, [u8(verb), pack_list(payload or [])])

    def _err(self, client: Client, verb: int, code: int, detail: str = '') -> None:
        self._reply(client, ERR, [u8(verb), u8(code), detail.encode()[:256]])

    # ---- questions to the user (K-28) ----
    def question(self, question_id: int, ex: Any, workspace_id: str, m: Match | None, request: Any, memfd: int,
                 binding: Binding | None = None, entry: Entry | None = None, obj: fo.FileObject | None = None) -> None:
        """SPEC §3.4 QUESTION: 18 fields of the network request and its cell, then 6 of a file request (H-09). A file
        request (``obj``) has empty HTTP fields, its object's mode as the cell, and no memfd; a network request has
        file_op 0 and empty file fields."""
        head = [u64(question_id), ex.execution_id.encode(), workspace_id.encode()]
        if obj is not None:
            fields = head + [u8(KEY_KIND_FILE), obj.alias.encode('ascii')] + fo.BLANK_HTTP + \
                [pack_list([]), fo.object_cell(obj)] + fo.request_fields(request, obj)
            fd = None
        else:
            assert m is not None
            fields = head + [
                u8(int(m.key_kind) if m.key_kind else 0), (m.key or '').encode(),
                request.method, request.scheme, request.host, u16(request.port), request.path, request.query or b'',
                pack_list([x for pair in request.headers for x in pair]), pack_list(list(request.stripped)),
                request.body_kind.encode(), pack_list([k.encode('latin-1') for k in request.form_keys]),
                u64(request.body_len),
                pack_list([] if binding is None else
                          [binding.host_port.encode(), binding.account.encode(), u8(binding.placement.value)]),
                pack_list([] if entry is None else entry_fields(entry))] + fo.NETWORK_FIELDS   # the PDP_REQUEST's cell
            fd = memfd
        frame = pack_frame(QUESTION, fields)
        self.pending_questions[question_id] = frame
        self.pending_fds[question_id] = fd
        for client in list(self.clients):
            self._send(client, frame, fd, question_id)

    def withdrawn(self, question_id: int, reason: int) -> None:
        unseen = self._forget_question(question_id)
        if reason:
            frame = pack_frame(QUESTION_WITHDRAWN, [u64(question_id), u8(reason)])
            for client in list(self.clients):
                if client not in unseen:                    # a client that never got the question gets no withdrawal
                    self._send(client, frame)

    def _forget_question(self, question_id: int) -> list[Client]:
        """A question answered or withdrawn is no longer sent to clients that connect, and a client's copy that has not
        begun to go out comes off its queue with its memfd: a client that does not read holds at most one descriptor per
        question still open, so a row's withdrawn questions take no place in the core (3.4 每行上限). The clients whose
        copy came off are returned."""
        self.pending_questions.pop(question_id, None)
        self.pending_fds.pop(question_id, None)
        unseen = []
        for client in self.clients:
            for item in [i for i in client.out if i[3] == question_id and i[2] == 0]:
                client.out.remove(item)
                client.queued -= len(item[0])
                if item[1] is not None:
                    os.close(item[1])
                unseen.append(client)
        return unseen

    # ---- verbs ----
    def _dispatch(self, client: Client, kind: int, fields: list[bytes]) -> None:
        if kind == ANSWER:
            qid, verdict = read_uint(fields[0], 8), read_uint(fields[1], 1)
            error, note = self.hook.answer(qid, verdict)
            if error not in (None, 'superseded'):
                self._err(client, kind, ERR_UNKNOWN_QUESTION if error == 'unknown_question' else ERR_REFUSED, error)
                return
            self._forget_question(qid)
            if error:                                   # the answer was void: the request was refused (K-45)
                self._err(client, kind, ERR_REFUSED, error)
            else:
                self._ok(client, kind, [note] if note else [])
        elif kind == ENTRY_PUT:
            wid = check_workspace_id(text(fields[0]))
            entry = make_entry(read_uint(fields[1], 1), text(fields[2]), read_uint(fields[3], 1), texts(fields[4]),
                               texts(fields[5]), texts(fields[6]), read_uint(fields[7], 1), texts(fields[8]))   # K-57
            table = self.workspaces.tables.get(wid)
            old = table.entries.get(entry.identity) if table is not None else None
            result = self.workspaces.put(wid, entry)
            if not result.applied:
                self._err(client, kind, ERR_NOT_PERSISTED, result.stage)
                return
            self.hook.table_changed(wid, old, entry, result.persisted)
            self._record('table_changed', wid, verb='put', key_kind=int(entry.key_kind), key=entry.key,
                         state=int(entry.state), persisted=result.persisted)
            self._ok(client, kind, [b'persisted' if result.persisted else b'unpersisted'])
        elif kind == ENTRY_DEL:
            wid = check_workspace_id(text(fields[0]))
            key_kind, key = KeyKind(read_uint(fields[1], 1)), text(fields[2])
            table = self.workspaces.tables.get(wid)
            old = table.entries.get((key_kind, key)) if table is not None else None
            result = self.workspaces.delete(wid, key_kind, key)
            if not result.applied:
                self._err(client, kind, ERR_NOT_PERSISTED, result.stage)
                return
            self.hook.table_changed(wid, old, None, result.persisted)
            self._record('table_changed', wid, verb='delete', key_kind=int(key_kind), key=key, persisted=result.persisted)
            self._ok(client, kind, [b'persisted' if result.persisted else b'unpersisted'])
        elif kind == OBJ_PUT:
            # H-01, H-02, H-22: the core resolves and anchors the path itself; the OK names the anchor's identity
            wid = check_workspace_id(text(fields[0]))
            alias, host_path = text(fields[1], canonical.LIMITS.alias), text(fields[2], canonical.LIMITS.host_path)
            result, obj = self.workspaces.register_object(wid, alias, host_path, read_uint(fields[3], 1),
                                                          read_uint(fields[4], 1), read_uint(fields[5], 1),
                                                          read_uint(fields[6], 1))
            if not result.applied:
                self._err(client, kind, ERR_NOT_PERSISTED, result.stage)
                return
            self._record('table_changed', wid, verb='object_put', alias=obj.alias, host_path=obj.host_path,
                         type=obj.type, ops=obj.ops, mode=obj.mode, persisted=result.persisted)
            self._ok(client, kind, [b'persisted' if result.persisted else b'unpersisted', str(obj.device).encode(),
                                    str(obj.inode).encode()])
        elif kind == OBJ_DEL:
            wid, alias = check_workspace_id(text(fields[0])), text(fields[1], canonical.LIMITS.alias)
            result = self.workspaces.delete_object(wid, alias)
            if not result.applied:
                self._err(client, kind, ERR_NOT_PERSISTED, result.stage)
                return
            self._record('table_changed', wid, verb='object_delete', alias=alias, persisted=result.persisted)
            self._ok(client, kind, [b'persisted' if result.persisted else b'unpersisted'])
        elif kind == CRED_PUT:
            before = set(self.credentials.records)
            record = self.credentials.register(text(fields[0]), text(fields[1]), read_uint(fields[2], 1), fields[3], fields[4],
                                               fields[5], text(fields[6]), text(fields[7]), text(fields[8]))
            self._record('credential_changed', record.host_port, verb='put', account=record.account,
                         placement=int(record.placement.value))
            if (record.host_port, record.account) in before:          # overwritten: its connections are cut (K-31)
                self.hook.credential_changed(record.host_port, record.account)
            self._report_leftover()
            self._ok(client, kind)
        elif kind == CRED_DEL:
            host_port, account = text(fields[0]), text(fields[1])
            self.credentials.delete(host_port, account)
            self._record('credential_changed', host_port, verb='delete', account=account)
            self.hook.credential_changed(host_port, account)
            self._report_leftover()
            self._ok(client, kind)
        elif kind == WS_CREATE:
            root = text(fields[0])
            real = os.path.realpath(root)
            wid = next((w for w, p in self.catalog_workspaces.items() if os.path.realpath(p) == real), None)
            if wid is None:
                self._err(client, kind, ERR_UNKNOWN, 'root is not a catalog workspace')
                return
            result = self.workspaces.register(wid, real)
            self._record('workspace_changed', wid, verb='create', persisted=result.persisted)
            self._ok(client, kind, [wid.encode(), b'persisted' if result.persisted else b'unpersisted'])
        elif kind == WS_LIST:
            items = []
            for wid, table in sorted(self.workspaces.tables.items()):
                flags = b'unavailable' if table.unavailable else (b'blocked' if table.spawn_blocked else b'ok')
                items += [wid.encode(), table.root.encode(), flags, str(len(table.entries)).encode()]
            self._ok(client, kind, items)
        elif kind == WS_DELETE:
            # refused while a connection holds the workspace or a row leases it, including one not yet on the hook
            # (reserved, preparing): the launch's own measure (K-14, K-20, K-55)
            wid = check_workspace_id(text(fields[0]))
            ws = self.lifecycle.workspaces.get(wid)
            busy = 'held by a connection' if wid in self.holds else \
                'a row is live on this workspace' if any(row.workspace_id == wid for row in self.hook.rows.values()) else \
                None if ws is None else self.lifecycle.workspace_busy(ws)
            if busy is not None:
                self._err(client, kind, ERR_BUSY, busy)
                return
            self.workspaces.delete_workspace(wid)
            self._record('workspace_changed', wid, verb='delete')
            self._ok(client, kind)
        elif kind == ROW_LIST:
            items = []
            for ex in self.lifecycle.executions.values():
                items += [ex.execution_id.encode(), ex.plan.workspace_id.encode(), ex.state.value.encode(),
                          str(ex.lease.uid).encode()]
            self._ok(client, kind, items)
        elif kind == ROW_START:
            wid, plan = check_workspace_id(text(fields[0])), text(fields[1])
            table = self.workspaces.tables.get(wid)
            if table is None or table.unavailable or table.spawn_blocked:       # K-18, K-19: no new spawn
                self._err(client, kind, ERR_UNAVAILABLE, 'workspace unavailable or blocked')
                return
            pairs = texts(fields[2])
            if len(pairs) % 2:
                raise Malformed('accounts is not host:port / account pairs')
            accounts: dict[str, str] = {}
            for host_port, account in zip(pairs[0::2], pairs[1::2]):       # 3.1: one account per destination, the user's
                host_port, account = check_host_port(host_port), check_account(account)
                if host_port in accounts:
                    raise EntryInvalid(f'two accounts for {host_port}')
                if (host_port, account) not in self.credentials.records:
                    raise EntryInvalid(f'no credential record for {account} at {host_port}')
                accounts[host_port] = account
            # K-55, design 4.2: during a hold nobody else starts a row on this workspace, and the holder starts only
            # transfer plans; a transfer plan starts only under the starting connection's own hold (S-24)
            holder, launch_plan = self.holds.get(wid), self.lifecycle.catalog.plans.get(plan)
            transfer = launch_plan is not None and bool(launch_plan.transfer)
            if holder is not None and holder is not client:
                self._err(client, kind, ERR_BUSY, 'workspace held by another connection')
                return
            if holder is client and not transfer:
                self._err(client, kind, ERR_REFUSED, 'during a hold only transfer plans start')
                return
            if transfer and holder is not client:
                self._err(client, kind, ERR_REFUSED, "a transfer plan starts only under this connection's hold")
                return
            try:
                ex = self.lifecycle.launch(wid, plan, 'admin', accounts, fields[3])     # K-56: the context, as given
            except Exception as e:      # Refused
                self._err(client, kind, ERR_REFUSED, f'{type(e).__name__}: {e}')     # the reason names no truth
                return
            self._ok(client, kind, [ex.execution_id.encode()])
        elif kind == ROW_STOP:
            eid = text(fields[0])
            ex = self.lifecycle.executions.get(eid)
            if ex is None:
                self._err(client, kind, ERR_UNKNOWN, 'no such row')
                return
            self.lifecycle.close_session(ex, 'trusted_close')
            self._ok(client, kind)
        elif kind == WS_HOLD:
            # K-55: one connection holds a workspace for import, push or export; refused while any row is live on it
            # (the launch's own measure) or another connection holds it. The OK carries what the client verifies the
            # workspace root against and the owner it drops to (A-10). Holding again on the same connection is a no-op.
            wid = check_workspace_id(text(fields[0]))
            table, ws = self.workspaces.tables.get(wid), self.lifecycle.workspaces.get(wid)
            if table is None or ws is None:
                self._err(client, kind, ERR_UNKNOWN, 'no such registered workspace')
                return
            holder = self.holds.get(wid)
            if holder is not None and holder is not client:
                self._err(client, kind, ERR_BUSY, 'held by another connection')
                return
            busy = None if holder is client else self.lifecycle.workspace_busy(ws)
            if busy is not None:
                self._err(client, kind, ERR_BUSY, busy)
                return
            self.holds[wid] = client
            self._ok(client, kind, [table.root.encode(), str(table.device).encode(), str(table.inode).encode(),
                                    str(ws.workspace_uid).encode(), str(ws.workspace_gid).encode()])
        elif kind == WS_RELEASE:
            wid = check_workspace_id(text(fields[0]))
            if self.holds.get(wid) is not client:
                self._err(client, kind, ERR_UNKNOWN, 'not held by this connection')
                return
            del self.holds[wid]
            self._ok(client, kind)
        else:
            self._drop(client)

    def _report_leftover(self) -> None:
        """Old truth files a credential change could not remove: names only, never contents."""
        if self.credentials.leftover:
            files, self.credentials.leftover = self.credentials.leftover, []
            self.recorder.diagnostic('credential_truth_left_behind', files=files)

    def _record(self, kind: str, subject: str, **detail: Any) -> None:
        self.recorder.record(kind, 'observed', 'none', source_ref={'port': 'admin', 'object': subject}, detail=detail)

    def close(self) -> None:
        for client in list(self.clients):
            self._drop(client)
        self.loop.forget(self.listener.fileno())
        self.listener.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
