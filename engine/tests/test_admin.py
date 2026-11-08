"""Management port (validation.md K-03, K-27, K-28, K-29, K-30; SPEC §3.4) over a real AF_UNIX socket."""
from __future__ import annotations

import array
import os
from pathlib import Path
import socket
import stat
from types import SimpleNamespace
from typing import Any, Iterator

import pytest

from conftest import OVERFLOWUID, FakeClock
from connector import canonical as c
from engine.admin import ERR_BUSY, ERR_MALFORMED, ERR_NOT_PERSISTED, ERR_REFUSED, ERR_UNKNOWN, ERR_UNKNOWN_QUESTION, AdminPort
from engine.credentials import CredentialStore
from engine.hook import Hook
from engine.lifecycle import Lifecycle
from engine.loop import Loop
from engine.objects import ExecState, WorkspaceRecord, WorkspaceState
from engine.pdp import entry_fields
from engine.records import Recorder
from engine.workspaces import FALLBACK_DEFAULT, Approval, EntryState, KeyKind, WorkspaceStore, make_entry
from test_hook import EPOCH, Harness as HookHarness, judge_frame, memfd, recv_frame, send

OWNER = 70997       # the dedicated workspace owner uid of the test catalog (agent-rm-model 3.1; D-17)


class FakeLifecycle:
    # the real lifecycle's own measure of a free workspace, so the hold is tested against what launch uses (K-55)
    workspace_busy = staticmethod(Lifecycle.workspace_busy)

    def __init__(self) -> None:
        self.executions: dict[str, Any] = {}
        self.launched: list[tuple[str, str]] = []
        self.accounts: list[dict[str, str]] = []
        self.contexts: list[bytes] = []
        self.closed: list[str] = []
        plans = {'observe-0': '', 'work0.push': 'push', 'work0.export': 'export', 'work1.push': 'push'}
        self.catalog = SimpleNamespace(plans={name: SimpleNamespace(launch_plan_id=name, transfer=kind)
                                              for name, kind in plans.items()})
        self.workspaces = {wid: WorkspaceRecord(wid, 'private-work-v1', wid, OWNER, OWNER) for wid in ('work0', 'work1')}

    def launch(self, workspace_id: str, plan: str, agent: str, accounts=None, policy_context: bytes = b''):
        self.launched.append((workspace_id, plan))
        self.accounts.append(dict(accounts or {}))
        self.contexts.append(policy_context)
        row = type('Ex', (), {})()
        row.execution_id, row.plan, row.state = f'{EPOCH}:{len(self.launched)}', type('P', (), {'workspace_id': workspace_id})(), type('S', (), {'value': 'ACTIVE'})()
        row.lease = type('L', (), {'uid': 70000})()
        self.executions[row.execution_id] = row
        return row

    def close_session(self, ex, reason: str) -> None:
        self.closed.append(ex.execution_id)


class AdminHarness:
    def __init__(self, tmp_path: Path, native, hooks: Any = HookHarness) -> None:
        self.hooks = hooks(tmp_path, native)                # hook, stores, loop, recorder
        self.lifecycle = FakeLifecycle()
        (tmp_path / 'root2').mkdir()
        self.admin = AdminPort(self.hooks.loop, self.hooks.recorder, tmp_path / 'state', self.hooks.hook, self.hooks.tables,
                               self.hooks.credentials, self.lifecycle,
                               {'work0': str(tmp_path / 'root'), 'work1': str(tmp_path / 'root2')})
        self.path = tmp_path / 'state' / 'admin.sock'

    def connect(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(self.path))
        s.settimeout(2)
        self.hooks.pump()
        return s

    def call(self, client: socket.socket, kind: int, fields: list[bytes]) -> tuple[int, list[bytes]]:
        client.sendall(c.pack_frame(kind, fields))
        self.hooks.pump()
        return recv_frame(client)

    def pump(self) -> None:
        self.hooks.pump()

    def close(self) -> None:
        """The port's clients (with the question memfds queued to them) and the hook harness's descriptors."""
        self.admin.close()
        self.hooks.close()


@pytest.fixture
def a(native, tmp_path: Path) -> Iterator[AdminHarness]:
    harness = AdminHarness(tmp_path, native)
    yield harness
    harness.close()


def entry_put(*fields: bytes) -> list[bytes]:
    """ENTRY_PUT's fields as SPEC §3.4 gives them: workspace_id, key_kind, key, state, methods, prefixes, accounts,
    approval and, 9th, the named addresses (a list, the items as the user wrote them; plan engine-v3-private-net)."""
    return list(fields)


def named_put(key: bytes = b'gitlab.corp:443', addresses=(), kind: int = 1, state: int = 1, methods=(b'GET',),
              accounts=(), approval: int = 1, wid: bytes = b'work0') -> list[bytes]:
    return entry_put(wid, c.u8(kind), key, c.u8(state), c.pack_list(list(methods)), c.pack_list([]),
                     c.pack_list(list(accounts)), c.u8(approval), c.pack_list([x.encode() for x in addresses]))


def test_socket_permissions_and_verb_set(a: AdminHarness) -> None:
    st = os.stat(a.path)
    assert stat.S_ISSOCK(st.st_mode) and oct(st.st_mode & 0o777) == '0o600' and st.st_uid == os.getuid()
    client = a.connect()
    kind, fields = a.call(client, c.WS_LIST, [])
    assert kind == c.OK and c.read_uint(fields[0], 1) == c.WS_LIST
    items = c.unpack_list(fields[1])
    assert items[0] == b'work0' and items[2] == b'ok'
    # a kind of another link disconnects the client (K-03)
    client.sendall(c.pack_frame(c.JUDGE, [b''] * 13))
    a.pump()
    assert client.recv(16) == b''


def test_entry_put_del_and_validation(a: AdminHarness) -> None:
    client = a.connect()
    put = entry_put(b'work0', c.u8(1), b'api.github.com:443', c.u8(1), c.pack_list([b'GET', b'POST']),
                    c.pack_list([b'/repos/a/']), c.pack_list([]), c.u8(1), c.pack_list([]))
    kind, fields = a.call(client, c.ENTRY_PUT, put)
    assert kind == c.OK and c.unpack_list(fields[1]) == [b'persisted']
    entry = a.hooks.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')]
    assert entry.methods == {'GET', 'POST'} and entry.prefixes == ('/repos/a',)
    # 条款 5 / K-29: a pattern entry with an account is refused
    bad = entry_put(b'work0', c.u8(2), b'github.io:443', c.u8(1), c.pack_list([b'GET']), c.pack_list([]),
                    c.pack_list([b'alice']), c.u8(1), c.pack_list([]))
    kind, fields = a.call(client, c.ENTRY_PUT, bad)
    assert kind == c.ERR and (c.read_uint(fields[0], 1), c.read_uint(fields[1], 1)) == (c.ENTRY_PUT, ERR_REFUSED)
    kind, fields = a.call(client, c.ENTRY_PUT, [b'nope', *put[1:]])
    assert kind == c.ERR
    kind, fields = a.call(client, c.ENTRY_DEL, [b'work0', c.u8(1), b'api.github.com:443'])
    assert kind == c.OK and (KeyKind.EXACT, 'api.github.com:443') not in a.hooks.tables.tables['work0'].entries
    kind, fields = a.call(client, c.ENTRY_DEL, [b'work0', c.u8(1), b'api.github.com:443'])
    assert kind == c.ERR
    assert [e['detail']['verb'] for e in a.hooks.events('table_changed')] == ['put', 'delete']


def test_a_credential_change_cuts_connections_although_the_old_truth_will_not_go(a: AdminHarness, monkeypatch) -> None:
    """K-31: removing the old generation's truth is cleanup; when it fails the change still answers OK, every live row
    still gets the REVOKE, and the file names (never the contents) go out as a diagnostic (cold recheck 2026-11-01)."""
    client = a.connect()
    put = [b'api.github.com:443', b'alice', c.u8(2), b'Bearer', b'truth-one', b'', b'', b'', b'']
    assert a.call(client, c.CRED_PUT, put)[0] == c.OK
    ex, conn = a.hooks.row()
    real_unlink = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        if '.truth_' in self.name and self.exists():
            raise PermissionError('unlink refused')
        real_unlink(self, missing_ok)

    monkeypatch.setattr(Path, 'unlink', unlink)
    put[4] = b'truth-two'
    assert a.call(client, c.CRED_PUT, put)[0] == c.OK
    assert a.call(client, c.CRED_DEL, put[:2])[0] == c.OK
    for _ in range(2):                                           # the overwrite, then the delete
        kind, fields = recv_frame(conn)
        assert (kind, fields[1], fields[2]) == (c.REVOKE, b'api.github.com:443', b'alice')
    left = [e['detail']['files'] for e in a.hooks.events('diagnostic') if e.get('name') == 'credential_truth_left_behind']
    assert left == [['api.github.com:443/alice.1.truth_a'],
                    ['api.github.com:443/alice.1.truth_a', 'api.github.com:443/alice.2.truth_a']]
    assert a.hooks.credentials.leftover == []
    assert all('truth-one' not in repr(e) and 'truth-two' not in repr(e) for e in a.hooks.recorder.events)


def test_credentials_and_workspaces(a: AdminHarness) -> None:
    client = a.connect()
    kind, _ = a.call(client, c.CRED_PUT, [b'api.github.com:443', b'alice', c.u8(2), b'Bearer', b'ghp_truth', b'',
                                          b'https://github.com/login/oauth/access_token', b'', b''])
    assert kind == c.OK and ('api.github.com:443', 'alice') in a.hooks.credentials.records
    kind, fields = a.call(client, c.CRED_PUT, [b'api.github.com:443', b'bob', c.u8(2), b'', b'x', b'', b'', b'', b''])
    assert kind == c.ERR                                               # K-30: the bearer placement registers its word
    kind, fields = a.call(client, c.CRED_PUT, [b'api.github.com:443', b'bob', c.u8(2), b'token', b'bad\r', b'', b'', b'', b''])
    assert kind == c.ERR                                               # K-30 control character
    assert all(b'ghp_truth' not in repr(e).encode() for e in a.hooks.recorder.events)
    kind, _ = a.call(client, c.CRED_DEL, [b'api.github.com:443', b'alice'])
    assert kind == c.OK and a.hooks.credentials.records == {}
    # workspaces: WS_CREATE binds a catalog workspace by its root identity; unknown roots are refused
    kind, fields = a.call(client, c.WS_CREATE, [str(a.path.parent.parent / 'root2').encode()])
    assert kind == c.OK and c.unpack_list(fields[1])[0] == b'work1'
    kind, fields = a.call(client, c.WS_CREATE, [b'/nonexistent'])
    assert kind == c.ERR and c.read_uint(fields[1], 1) == ERR_UNKNOWN
    kind, fields = a.call(client, c.WS_LIST, [])
    assert c.unpack_list(fields[1])[0::4] == [b'work0', b'work1']
    kind, _ = a.call(client, c.WS_DELETE, [b'work1'])
    assert kind == c.OK and 'work1' not in a.hooks.tables.tables


def test_rows_start_stop_list_and_busy_workspace(a: AdminHarness) -> None:
    client = a.connect()
    kind, fields = a.call(client, c.ROW_START, [b'work0', b'observe-0', c.pack_list([]), b''])
    assert kind == c.OK and a.lifecycle.launched == [('work0', 'observe-0')]
    eid = c.unpack_list(fields[1])[0]
    kind, fields = a.call(client, c.ROW_LIST, [])
    assert c.unpack_list(fields[1])[0] == eid
    kind, fields = a.call(client, c.ROW_START, [b'work9', b'observe-0', c.pack_list([]), b''])
    assert kind == c.ERR                                               # unknown table
    a.hooks.tables.tables['work0'].spawn_blocked = True                # K-18: an unpersisted change blocks new spawns
    kind, fields = a.call(client, c.ROW_START, [b'work0', b'observe-0', c.pack_list([]), b''])
    assert kind == c.ERR
    a.hooks.tables.tables['work0'].spawn_blocked = False
    kind, _ = a.call(client, c.ROW_STOP, [eid])
    assert kind == c.OK and a.lifecycle.closed == [eid.decode()]
    kind, fields = a.call(client, c.ROW_STOP, [b'nope'])
    assert kind == c.ERR
    # a workspace with a live row cannot be deleted
    ex, _ = a.hooks.row(0, 'work0')
    kind, fields = a.call(client, c.WS_DELETE, [b'work0'])
    assert kind == c.ERR and c.read_uint(fields[1], 1) == ERR_BUSY


def test_question_reaches_the_client_with_the_memfd_and_answer_returns(a: AdminHarness) -> None:
    client = a.connect()
    a.hooks.tables.put('work0', make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['POST'], [], [],
                                           Approval.ALWAYS))
    ex, conn = a.hooks.row()
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', path=b'/repos/a/issues', body=b'{}'), memfd(b'{}'))
    a.pump()
    # QUESTION with the memfd attached (K-28)
    data, fds, _, _ = socket.recv_fds(client, 65536, 4)
    body = data[4:]
    assert body[0] == c.QUESTION and len(fds) == 1
    fields = c.unpack_payload(c.QUESTION, body[1:])
    qid = c.read_uint(fields[0], 8)
    assert fields[1] == ex.execution_id.encode() and fields[2] == b'work0' and fields[5] == b'POST' and fields[9] == b'/repos/a/issues'
    assert os.pread(fds[0], 10, 0) == b'{}'
    os.close(fds[0])
    # a second client that connects now sees the pending question too
    late = a.connect()
    data2, fds2, _, _ = socket.recv_fds(late, 65536, 4)
    assert data2[4] == c.QUESTION and len(fds2) == 1
    os.close(fds2[0])
    kind, fields = a.call(client, c.ANSWER, [c.u64(qid), c.u8(3)])
    assert kind == c.OK
    assert recv_frame(conn)[0] == c.DENY
    kind, fields = a.call(client, c.ANSWER, [c.u64(qid), c.u8(3)])
    assert kind == c.ERR and c.read_uint(fields[1], 1) == ERR_UNKNOWN_QUESTION
    # the withdrawn frame when the row closes while asking
    send(conn, judge_frame(2, ex.lease.uid, method=b'POST', path=b'/x'), memfd(b''))
    a.pump()
    data, fds, _, _ = socket.recv_fds(client, 65536, 4)
    os.close(fds[0])
    qid2 = c.read_uint(c.unpack_payload(c.QUESTION, data[5:])[0], 8)
    a.hooks.close_row(ex)
    a.pump()
    kind, fields = recv_frame(client)
    assert kind == c.QUESTION_WITHDRAWN and (c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (qid2, 2)


def test_question_carries_the_engines_credential_binding(a: AdminHarness) -> None:
    """K-28 (648d60f2 3.2): the QUESTION carries the binding the engine computed for the request (account and placement
    from the entry and the record, not from the request's value); the truth never travels on this port."""
    client = a.connect()
    kind, _ = a.call(client, c.CRED_PUT, [b'api.github.com:443', b'alice', c.u8(1), b'', b'sk-truth', b'', b'', b'', b''])
    assert kind == c.OK
    kind, _ = a.call(client, c.ENTRY_PUT, entry_put(b'work0', c.u8(1), b'api.github.com:443', c.u8(1),
                                                    c.pack_list([b'POST']), c.pack_list([]), c.pack_list([b'alice']),
                                                    c.u8(2), c.pack_list([])))     # ask every time
    assert kind == c.OK
    ex, conn = a.hooks.row()
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', path=b'/x', headers=((b'x-api-key', b'PH-KEY'),)), memfd(b''))
    a.pump()
    data, fds, _, _ = socket.recv_fds(client, 65536, 4)
    for fd in fds:
        os.close(fd)
    fields = c.unpack_payload(c.QUESTION, data[5:])
    assert c.unpack_list(fields[16]) == [b'api.github.com:443', b'alice', c.u8(1)]
    assert b'sk-truth' not in data


def test_row_start_carries_the_users_account_per_destination(a: AdminHarness) -> None:
    """K-44 (agent-rm-model 3.1): the user names, at start, the one account the execution uses at a destination; the pair
    must name a registered credential record, at most one account per destination."""
    client = a.connect()
    start = lambda pairs: a.call(client, c.ROW_START, [b'work0', b'observe-0', c.pack_list(pairs), b''])   # noqa: E731
    kind, fields = start([b'api.github.com:443', b'carol'])
    assert kind == c.ERR and c.read_uint(fields[1], 1) == ERR_REFUSED          # no such credential record
    kind, _ = a.call(client, c.CRED_PUT, [b'api.github.com:443', b'carol', c.u8(2), b'Bearer', b't', b'', b'', b'', b''])
    assert kind == c.OK
    kind, fields = start([b'api.github.com:443', b'carol', b'api.github.com:443', b'carol'])
    assert kind == c.ERR and c.read_uint(fields[1], 1) == ERR_REFUSED          # two pairs for one destination
    kind, fields = start([b'api.github.com:443'])
    assert kind == c.ERR and c.read_uint(fields[1], 1) == ERR_MALFORMED        # not pairs
    assert a.lifecycle.launched == []
    kind, _ = start([b'api.github.com:443', b'carol'])
    assert kind == c.OK and a.lifecycle.accounts == [{'api.github.com:443': 'carol'}]


def test_row_start_refusal_says_why(a: AdminHarness) -> None:
    """K-44: a start refused for a missing account choice tells the user which destination needs one."""
    from engine.lifecycle import Refused

    def refuse(*_args, **_kw):
        raise Refused('no account chosen for api.github.com:443, whose entry lists several')
    a.lifecycle.launch = refuse                                                       # type: ignore[method-assign]
    client = a.connect()
    kind, fields = a.call(client, c.ROW_START, [b'work0', b'observe-0', c.pack_list([]), b''])
    assert kind == c.ERR and c.read_uint(fields[1], 1) == ERR_REFUSED and b'api.github.com:443' in fields[2]


def start(a: AdminHarness, client: socket.socket, plan: bytes, workspace: bytes = b'work0',
          context: bytes = b'') -> tuple[int, list[bytes]]:
    return a.call(client, c.ROW_START, [workspace, plan, c.pack_list([]), context])


def code(fields: list[bytes]) -> int:
    return c.read_uint(fields[1], 1)


def test_row_start_hands_the_policy_context_to_the_launch(a: AdminHarness) -> None:
    """K-56 (agent-rm-model 3.1 策略上下文): ROW_START's fourth field is the row's opaque policy context, passed on as
    given; an empty field means none."""
    client = a.connect()
    assert start(a, client, b'observe-0', context=b'\x00opaque\xff')[0] == c.OK
    assert start(a, client, b'observe-0')[0] == c.OK
    assert a.lifecycle.contexts == [b'\x00opaque\xff', b'']


def test_a_hold_is_one_connections_and_names_the_root_and_its_owner(a: AdminHarness) -> None:
    """K-55: one connection holds a workspace; the OK carries the root's path, device and inode and the owner ids the
    client checks and drops to (A-10); a second connection is refused; release and disconnect both end the hold."""
    first, second = a.connect(), a.connect()
    kind, fields = a.call(first, c.WS_HOLD, [b'work0'])
    table = a.hooks.tables.tables['work0']
    assert kind == c.OK and c.unpack_list(fields[1]) == [table.root.encode(), str(table.device).encode(),
                                                         str(table.inode).encode(), b'70997', b'70997']
    assert a.call(first, c.WS_HOLD, [b'work0'])[0] == c.OK                       # again on the same connection: a no-op
    kind, fields = a.call(second, c.WS_HOLD, [b'work0'])
    assert kind == c.ERR and code(fields) == ERR_BUSY
    kind, fields = a.call(second, c.WS_RELEASE, [b'work0'])
    assert kind == c.ERR and code(fields) == ERR_UNKNOWN                          # only the holder releases
    assert a.call(first, c.WS_RELEASE, [b'work0'])[0] == c.OK
    assert a.call(second, c.WS_HOLD, [b'work0'])[0] == c.OK                       # released: the other may hold
    second.close()
    a.pump()
    assert a.call(first, c.WS_HOLD, [b'work0'])[0] == c.OK                       # disconnect released it
    kind, fields = a.call(first, c.WS_HOLD, [b'nope'])
    assert kind == c.ERR and code(fields) == ERR_UNKNOWN


def test_a_hold_is_refused_while_a_row_still_holds_the_workspace(a: AdminHarness) -> None:
    """K-55: the hold uses the launch's measure of a free workspace: a live lease, a draining or quarantined row, or a
    previous row not yet CLOSED with its domain empty all refuse it."""
    client = a.connect()
    ws = a.lifecycle.workspaces['work0']
    for state in (WorkspaceState.LEASED, WorkspaceState.DRAINING, WorkspaceState.QUARANTINED):
        ws.state = state
        kind, fields = a.call(client, c.WS_HOLD, [b'work0'])
        assert kind == c.ERR and code(fields) == ERR_BUSY, state
    ws.state = WorkspaceState.AVAILABLE
    ws.last_execution = SimpleNamespace(state=ExecState.CLOSED, membership_empty=False)   # closed, domain not yet empty
    kind, fields = a.call(client, c.WS_HOLD, [b'work0'])
    assert kind == c.ERR and code(fields) == ERR_BUSY
    ws.last_execution = SimpleNamespace(state=ExecState.CLOSED, membership_empty=True)
    assert a.call(client, c.WS_HOLD, [b'work0'])[0] == c.OK


def test_during_a_hold_only_the_holder_starts_and_only_transfer_plans(a: AdminHarness) -> None:
    """K-55, S-24: while one connection holds work0, another cannot start any row there and the holder can start only a
    transfer plan; a transfer plan never starts without the starting connection's own hold. Other workspaces are not
    affected."""
    holder, other = a.connect(), a.connect()
    kind, fields = start(a, holder, b'work0.push')
    assert kind == c.ERR and code(fields) == ERR_REFUSED                          # no hold: no transfer
    assert a.call(holder, c.WS_HOLD, [b'work0'])[0] == c.OK
    kind, fields = start(a, other, b'observe-0')
    assert kind == c.ERR and code(fields) == ERR_BUSY                             # someone else's hold
    kind, fields = start(a, other, b'work0.push')
    assert kind == c.ERR and code(fields) == ERR_BUSY
    kind, fields = start(a, holder, b'observe-0')
    assert kind == c.ERR and code(fields) == ERR_REFUSED                          # the holder: transfers only
    assert start(a, holder, b'work0.push')[0] == c.OK
    assert start(a, holder, b'work0.export')[0] == c.OK
    assert a.call(other, c.WS_CREATE, [a.admin.catalog_workspaces['work1'].encode()])[0] == c.OK
    kind, fields = start(a, other, b'work1.push', b'work1')
    assert kind == c.ERR and code(fields) == ERR_REFUSED                          # work1 is not held by `other`
    assert a.lifecycle.launched == [('work0', 'work0.push'), ('work0', 'work0.export')]


def test_a_question_larger_than_the_socket_queue_reaches_a_slow_client_whole(a: AdminHarness) -> None:
    """K-28 (overall review 2026-11-03, #1): a QUESTION the client's socket cannot take at once goes on, in order, as the
    client reads; the frames after it are not spliced into its gap, and each memfd travels once, with its first bytes."""
    client = a.connect()
    a.admin.clients[0].sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)   # a small queue: every send is partial
    a.hooks.tables.put('work0', make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['POST'], [], [],
                                           Approval.ALWAYS))
    pad = [(b'x-pad-%d' % i, b'v' * 1000) for i in range(30)]
    rows = [a.hooks.row(i) for i in range(2)]
    for ex, conn in rows:
        send(conn, judge_frame(1, ex.lease.uid, method=b'POST', headers=pad, body=b'{}'), memfd(b'{}'))
    parser, frames, fds = c.FrameParser(c.LIMITS.frame_bd, c.LINK_D_TO_CLIENT), [], []
    client.settimeout(0.05)
    for _ in range(400):
        a.hooks.pump(1)
        try:
            data, got, _, _ = socket.recv_fds(client, 65536, 8)
        except TimeoutError:
            continue
        fds += got
        frames += parser.feed(data)
        if len(frames) == 2:
            break
    assert [kind for kind, _ in frames] == [c.QUESTION, c.QUESTION] and len(fds) == 2
    assert sorted(fields[1] for _, fields in frames) == sorted(ex.execution_id.encode() for ex, _ in rows)
    for fd in fds:
        assert os.pread(fd, 10, 0) == b'{}'
        os.close(fd)


def test_questions_gone_before_a_stuck_client_read_them_leave_no_descriptor_behind(a: AdminHarness) -> None:
    """3.4 每行上限 (recheck 2026-11-03): a client that does not read keeps its queue, but a question withdrawn before its
    copy began to go out comes off that queue with its memfd; the core's descriptors do not grow with the number of
    questions a row's agent makes and withdraws. (An answered question leaves the same way: Hook.answer cancels it
    through withdrawn(qid, 0) into the same _forget_question; this test drives the withdrawal, the path an agent drives.)"""
    client = a.connect()
    a.admin.clients[0].sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)   # stuck after the first frame
    a.hooks.tables.put('work0', make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['POST'], [], [],
                                           Approval.ALWAYS))
    pad = [(b'x-pad-%d' % i, b'v' * 1000) for i in range(8)]
    ex, conn = a.hooks.row()
    before = len(os.listdir('/proc/self/fd'))
    for seq in range(1, 201):
        send(conn, judge_frame(seq, ex.lease.uid, method=b'POST', headers=pad, body=b'{}'), memfd(b'{}'))
        a.hooks.pump(2)
        send(conn, c.pack_frame(c.WITHDRAW, [c.u64(seq)]))
        a.hooks.pump(2)
    assert len(a.hooks.hook.questions) == 0 and len(os.listdir('/proc/self/fd')) - before < 10
    client.close()


def test_a_workspace_is_not_deleted_while_held_or_while_a_row_is_reserved_on_it(a: AdminHarness) -> None:
    """K-14, K-20 (overall review 2026-11-03, #18): deleting a workspace's table is refused while a connection holds it
    and while a row leases it that has not reached the hook yet (reserved, preparing)."""
    holder, other = a.connect(), a.connect()
    assert a.call(holder, c.WS_HOLD, [b'work0'])[0] == c.OK
    kind, fields = a.call(other, c.WS_DELETE, [b'work0'])
    assert kind == c.ERR and code(fields) == ERR_BUSY
    assert a.call(holder, c.WS_RELEASE, [b'work0'])[0] == c.OK
    a.lifecycle.workspaces['work0'].state = WorkspaceState.LEASED                  # reserved, no judgment port yet
    kind, fields = a.call(other, c.WS_DELETE, [b'work0'])
    assert kind == c.ERR and code(fields) == ERR_BUSY
    assert 'work0' in a.hooks.tables.tables


# ---- host file objects (validation.md H-01, H-09; plan engine-v3-n16-file-read 2.3a) ---------------------------------
def object_put(wid: bytes, alias: bytes, path: bytes, type_: int = 2, ops: int = 3, state: int = 1,
               approval: int = 1) -> list[bytes]:
    return [wid, alias, path, c.u8(type_), c.u8(ops), c.u8(state), c.u8(approval)]


def test_objects_are_put_and_deleted_through_the_port(a: AdminHarness, tmp_path: Path) -> None:
    """H-01: OBJ_PUT registers by the core's own resolution of the path; the OK says whether the mirror holds it and
    names the anchor's device and inode; OBJ_DEL removes by alias; both are table_changed records."""
    host = tmp_path / 'host'
    host.mkdir()
    (host / 'n.txt').write_text('x')
    client = a.connect()
    kind, fields = a.call(client, c.OBJ_PUT, object_put(b'work0', b'notes', str(host).encode(), approval=2))
    st = os.stat(host)
    assert kind == c.OK and c.read_uint(fields[0], 1) == c.OBJ_PUT
    assert c.unpack_list(fields[1]) == [b'persisted', str(st.st_dev).encode(), str(st.st_ino).encode()]
    obj = a.hooks.tables.tables['work0'].objects['notes']
    assert (obj.ops, obj.approval, obj.dir_path) == (3, Approval.ALWAYS, str(host))
    for bad in (object_put(b'work0', b'one', str(host / 'n.txt').encode(), type_=1, ops=3),     # list on a file
                object_put(b'work0', b'x', b'host'),                                              # not absolute
                object_put(b'nope', b'x', str(host).encode()),                                    # no such workspace
                object_put(b'work0', b'a/b', str(host).encode()),                                 # alias grammar
                object_put(b'work0', b'x', str(host).encode(), state=2, approval=2),              # not a mode
                object_put(b'work0', b'x', str(tmp_path).encode())):                              # H-22: holds state/
        kind, fields = a.call(client, c.OBJ_PUT, bad)
        assert kind == c.ERR and code(fields) == ERR_REFUSED, bad
    kind, fields = a.call(client, c.OBJ_PUT, object_put(b'work0', b'x', b'/\xff'))                 # not UTF-8 text
    assert kind == c.ERR and code(fields) == ERR_MALFORMED
    assert set(a.hooks.tables.tables['work0'].objects) == {'notes'}
    kind, fields = a.call(client, c.OBJ_DEL, [b'work0', b'notes'])
    assert kind == c.OK and c.unpack_list(fields[1]) == [b'persisted']
    kind, fields = a.call(client, c.OBJ_DEL, [b'work0', b'notes'])
    assert kind == c.ERR and code(fields) == ERR_REFUSED
    changed = [e['detail'] for e in a.hooks.events('table_changed')]
    assert [(d['verb'], d['alias']) for d in changed] == [('object_put', 'notes'), ('object_delete', 'notes')]
    assert (changed[0]['host_path'], changed[0]['type'], changed[0]['ops'], changed[0]['mode']) == (str(host), 2, 3, 2)


def test_a_file_question_carries_the_object_and_no_descriptor(native, tmp_path: Path) -> None:
    """H-09: the QUESTION's six appended fields carry the file request and the object; the HTTP fields are empty, the
    cell is the object's state and approval, and no memfd goes with it. A network QUESTION carries file_op 0 and its
    memfd, so the client pairs descriptors with the right frames."""
    from test_file_hook import FileHarness, allowed, read
    a = AdminHarness(tmp_path, native, FileHarness)
    client = a.connect()
    a.hooks.obj('notes', a.hooks.host, mode='ask')
    a.hooks.tables.put('work0', make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['POST'], [], [],
                                           Approval.ALWAYS))
    ex, conn, worker = a.hooks.file_row()
    worker.sendall(read(1, ex))
    a.pump()
    data, fds, _, _ = socket.recv_fds(client, 1 << 20, 4)
    assert data[4] == c.QUESTION and fds == []
    f = c.unpack_payload(c.QUESTION, data[5:])
    assert len(f) == 24 and (c.read_uint(f[3], 1), f[4]) == (c.KEY_KIND_FILE, b'notes')
    assert f[5:16] == [b'', b'', b'', c.u16(0), b'', b'', c.pack_list([]), c.pack_list([]), b'', c.pack_list([]), c.u64(0)]
    # the cell is the six items of pdp.entry_fields, the sixth (named addresses) empty for an object
    assert len(entry_fields(FALLBACK_DEFAULT)) == 6
    assert c.unpack_list(f[16]) == [] and c.unpack_list(f[17]) == [c.u8(1), c.pack_list([]), c.pack_list([]),
                                                                   c.pack_list([]), c.u8(2), c.pack_list([])]
    assert (c.read_uint(f[18], 1), f[19], f[20], c.read_uint(f[21], 8), c.read_uint(f[22], 8)) == \
        (c.FILE_OP_READ, b'notes', b'notes.txt', 0, 4096)
    assert c.unpack_list(f[23]) == [str(a.hooks.host).encode(), c.u8(2), c.u8(3)]
    kind, fields = a.call(client, c.ANSWER, [f[0], c.u8(1)])
    assert kind == c.OK
    os.close(allowed(a.hooks, worker, 1))
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', path=b'/x', body=b'{}'), memfd(b'{}'))
    a.pump()
    data, fds, _, _ = socket.recv_fds(client, 1 << 20, 4)
    f = c.unpack_payload(c.QUESTION, data[5:])
    assert len(fds) == 1 and (c.read_uint(f[18], 1), f[19], f[20], c.unpack_list(f[23])) == (0, b'', b'', [])
    os.close(fds[0])
    a.hooks.close()


# ---- named non-global addresses on the port (validation.md K-57, K-28; plan engine-v3-private-net) ------------------------
def refused(fields: list[bytes]) -> bool:
    return c.read_uint(fields[0], 1) == c.ENTRY_PUT and c.read_uint(fields[1], 1) == ERR_REFUSED


def test_entry_put_refuses_an_address_that_cannot_be_named_and_leaves_the_table(a: AdminHarness) -> None:
    """K-57: ENTRY_PUT's 9th field carries the items as the user wrote them; the core checks each, and one that fails
    refuses the whole entry with ERR_REFUSED, the table and its version unchanged, nothing recorded."""
    from test_workspaces import NOT_NAMEABLE
    client = a.connect()
    table = a.hooks.tables.tables['work0']
    before = (table.version, dict(table.entries))
    for item in NOT_NAMEABLE:
        kind, fields = a.call(client, c.ENTRY_PUT, named_put(addresses=('10.0.0.0/8', item)))
        assert kind == c.ERR and refused(fields), item
        assert (table.version, dict(table.entries)) == before, item
    assert a.hooks.events('table_changed') == []


def test_entry_put_stores_named_addresses_as_canonical_prefixes(a: AdminHarness) -> None:
    """K-57: accepted items are stored deduplicated, as canonical prefixes, in stored order."""
    client = a.connect()
    kind, fields = a.call(client, c.ENTRY_PUT, named_put(addresses=('fd12:3456::/48', '10.0.0.5', '10.0.0.0/8',
                                                                    '10.0.0.5/32')))
    assert kind == c.OK and c.unpack_list(fields[1]) == [b'persisted']
    entry = a.hooks.tables.tables['work0'].entries[(KeyKind.EXACT, 'gitlab.corp:443')]
    assert entry.addresses == ('10.0.0.0/8', '10.0.0.5/32', 'fd12:3456::/48')


def test_entry_put_names_addresses_only_on_an_exact_allow_and_at_most_64(a: AdminHarness) -> None:
    """K-57, N-12: a pattern, the fallback or a deny entry with addresses is refused, as is the 65th item; the same
    entries without addresses, and 64 items, are taken."""
    client = a.connect()
    table = a.hooks.tables.tables['work0']
    others = [named_put(b'*.corp:443', kind=2), named_put(b'', kind=3), named_put(b'gitlab.corp:443', state=2, methods=()),
              named_put(b'*.corp:443', kind=2, state=2, methods=())]
    for put in others:
        with_addresses = put[:8] + [c.pack_list([b'10.0.0.0/8'])]
        before = (table.version, dict(table.entries))
        kind, fields = a.call(client, c.ENTRY_PUT, entry_put(*with_addresses))
        assert kind == c.ERR and refused(fields) and (table.version, dict(table.entries)) == before, put[:3]
    items = [f'10.{i}.0.0/16' for i in range(65)]
    kind, fields = a.call(client, c.ENTRY_PUT, named_put(addresses=items))
    assert kind == c.ERR and refused(fields) and (KeyKind.EXACT, 'gitlab.corp:443') not in table.entries
    assert a.call(client, c.ENTRY_PUT, named_put(addresses=items[:64]))[0] == c.OK
    assert len(table.entries[(KeyKind.EXACT, 'gitlab.corp:443')].addresses) == 64
    for put in others:
        assert a.call(client, c.ENTRY_PUT, put)[0] == c.OK, put[:3]


def test_a_question_shows_the_cells_named_addresses_as_the_pdp_sees_them(a: AdminHarness) -> None:
    """K-28 (plan engine-v3-private-net): the QUESTION's cell is built as the PDP_REQUEST's (pdp.entry_fields), byte
    for byte: six items, the sixth the named addresses in stored order."""
    client = a.connect()
    kind, _ = a.call(client, c.ENTRY_PUT, named_put(addresses=('fd12:3456::/48', '10.0.0.0/8'), methods=(b'POST',),
                                                    approval=2))
    assert kind == c.OK
    entry = a.hooks.tables.tables['work0'].entries[(KeyKind.EXACT, 'gitlab.corp:443')]
    ex, conn = a.hooks.row()
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', host=b'gitlab.corp', path=b'/api', body=b'{}'), memfd(b'{}'))
    a.pump()
    data, fds, _, _ = socket.recv_fds(client, 1 << 20, 4)
    for fd in fds:
        os.close(fd)
    q = c.unpack_payload(c.QUESTION, data[5:])
    assert q[17] == c.pack_list(entry_fields(entry))
    kind, _ = a.call(client, c.ANSWER, [q[0], c.u8(1)])
    assert kind == c.OK
    [asked] = a.hooks.pdp.requests
    assert asked[18] == q[17]
    cell = c.unpack_list(q[17])
    assert len(cell) == 6 and c.unpack_list(cell[5]) == [b'10.0.0.0/8', b'fd12:3456::/48']
