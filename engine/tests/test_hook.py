"""Judgment port and hook (validation.md K-01–K-03, K-09, K-11, K-12, K-15, K-16, K-22, K-24, K-25, K-31, K-36–K-38, K-42).

The test plays the connector on the connector end of a socketpair: frames go out with the kernel's own credential
(the test's uid, which the harness registers as the connector uid) and one sealed memfd per JUDGE frame.
"""
from __future__ import annotations

import array
from collections import deque
from dataclasses import dataclass, field
import fcntl
import os
from pathlib import Path
import selectors
import socket
from typing import Any, Iterator

import pytest

from conftest import OVERFLOWUID, FakeClock
from connector import canonical as c
from engine.hook import Hook, VERDICT_ALLOW_CELL, VERDICT_ALLOW_ONCE, VERDICT_DENY_CELL, VERDICT_DENY_ONCE
from engine import matching as m
from engine.judgment import (DENY_CLAUSE, DENY_CLOSED, DENY_CREDENTIAL, DENY_NOT_AUTHORIZED, DENY_POLICY_CHANGED,
                             DENY_QUEUE_FULL, DENY_RECORDED, DENY_USER, JudgmentPort)
from engine.loop import Loop
from engine.records import Recorder
from engine.workspaces import Approval, Disk, EntryState, KeyKind, WorkspaceStore, make_entry
from engine.credentials import CredentialStore

EPOCH = 'b' * 32


@dataclass
class Lease:
    uid: int


@dataclass
class Plan:
    workspace_id: str
    transfer: str = ''          # agent-rm-model 3.1 传送 execution (S-24)


@dataclass(eq=False)
class Row:
    execution_id: str
    lease: Lease
    plan: Plan
    launch_plan_digest: str = 'sha256:' + '1' * 64
    lease_id: str = ''
    state: Any = None
    accounts: dict[str, str] = field(default_factory=dict)      # agent-rm-model 3.1: host:port -> the chosen account
    policy_context: bytes = b''                                 # agent-rm-model 3.1 策略上下文 (K-56)


class FakeAdmin:
    def __init__(self) -> None:
        self.questions: list[tuple] = []
        self.withdrawals: list[tuple[int, int]] = []

    def question(self, qid, ex, workspace_id, m, request, memfd, binding=None, entry=None, obj=None):
        """``obj``: the host file object a file request asks about (H-09); a file request has no match and no memfd."""
        self.questions.append((qid, ex.execution_id, workspace_id, m.key_kind if m else None, m.key if m else None,
                               request.seq, memfd, binding, entry, obj))

    def withdrawn(self, qid, reason):
        self.withdrawals.append((qid, reason))


class FakePdp:
    """The hook port's side the hook calls (``link``, ``send_request``), with a PDP behind it in-process: by default it
    answers allow one loop round later; ``hold`` keeps the requests for the test to answer; ``allow`` False denies."""

    def __init__(self, hook: Any, loop: Any) -> None:
        self.hook, self.loop = hook, loop
        self.link: Any = object()
        self.requests: list[list[bytes]] = []
        self.hold = False
        self.allow = True
        hook.pdp = self

    def send_request(self, link: Any, fields: list[bytes], memfd: int) -> None:
        self.requests.append(fields)
        if not self.hold:
            self.loop.soon(lambda: self.answer(fields, self.allow, link))

    def answer(self, fields: list[bytes], allow: bool = True, link: Any = None) -> None:
        self.hook.pdp_answer(link or self.link, fields[0].decode(), c.read_uint(fields[1], 8), allow)


class SwitchDisk(Disk):
    """A mirror disk a test can make fail at one step (K-18)."""

    fail_at = ''

    def rename(self, tmp, final):
        if self.fail_at == 'rename':
            raise OSError('rename failed')
        super().rename(tmp, final)

    def fsync_dir(self, directory):
        if self.fail_at == 'fsync_dir':
            raise OSError('directory fsync failed')
        super().fsync_dir(directory)


class Harness:
    def __init__(self, tmp_path: Path, native, evidence: str | None = None) -> None:
        """``evidence``: a record file and a real writer thread (K-52, K-53); without it records count durable at once."""
        self.clock = FakeClock()
        self.loop = Loop(self.clock)
        self.recorder = Recorder(EPOCH, OVERFLOWUID, self.clock, evidence, keep=100_000)
        (tmp_path / 'root').mkdir(exist_ok=True)
        self.tables = WorkspaceStore(tmp_path / 'state', SwitchDisk())
        self.tables.load()
        self.tables.register('work0', str(tmp_path / 'root'))
        self.credentials = CredentialStore(tmp_path / 'state')
        self.credentials.load()
        self.hook = Hook(self.loop, self.recorder, self.tables, self.credentials, self.recorder.diagnostic)
        self.admin = FakeAdmin()
        self.hook.admin = self.admin
        self.pdp = FakePdp(self.hook, self.loop)
        self.loop.watch(self.recorder.wake_r, selectors.EVENT_READ, self.hook.on_wake)
        self.native = native
        self.faults: list[tuple[str, str]] = []
        self.rows: dict[str, tuple[Row, JudgmentPort, socket.socket]] = {}

    def row(self, i: int = 0, workspace: str = 'work0', accounts: dict[str, str] | None = None, transfer: str = '',
            policy_context: bytes = b'') -> tuple[Row, socket.socket]:
        core_end, connector_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        core_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        ex = Row(f'{EPOCH}:{i + 1}', Lease(60000 + i), Plan(workspace, transfer), lease_id=f'{EPOCH}:{i + 1}:u',
                 accounts=dict(accounts or {}), policy_context=policy_context)
        port = JudgmentPort(self.loop, self.native, ex, core_end, os.getuid(), OVERFLOWUID, self.hook,
                            lambda row, why: self.faults.append((row.execution_id, why)), self.recorder.diagnostic)
        self.hook.register(ex, port)
        self.rows[ex.execution_id] = (ex, port, connector_end)
        connector_end.settimeout(2)
        return ex, connector_end

    def close_row(self, ex: Row) -> None:
        _, port, _ = self.rows[ex.execution_id]
        self.hook.row_closed(ex)
        port.close()

    def pump(self, rounds: int = 5) -> None:
        for _ in range(rounds):
            self.loop.run_once(0)

    def events(self, kind: str) -> list[dict]:
        return [e for e in self.recorder.events if e['kind'] == kind]

    def close(self) -> None:
        """The body memfds the hook still holds for requests a test left in flight (released as a row's close releases
        them, K-22) and the record writer's pipe are plain descriptors, never collected: released here, with each row's
        socket ends, not left to the end of the run (the suite would pass the 1024 a select() takes)."""
        for ex, port, connector_end in self.rows.values():
            self.hook.row_closed(ex)
            port.close()
            connector_end.close()
        self.recorder.close()


def memfd(body: bytes, seals: int = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW) -> int:
    fd = os.memfd_create('body', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(fd, body)
    if seals:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    return fd


def judge_frame(seq: int, uid: int, method=b'GET', scheme=b'https', host=b'api.github.com', port=443, path=b'/repos/a',
                query=b'', headers=(), stripped=(), body_kind='', form_keys=(), body=b'') -> bytes:
    fields = [c.u64(seq), c.u32(uid), method, scheme, host, c.u16(port), path, query,
              c.pack_list([x for pair in headers for x in pair]), c.pack_list(list(stripped)), body_kind.encode(),
              c.pack_list([k.encode('latin-1') for k in form_keys]), c.u64(len(body))]
    return c.pack_frame(c.JUDGE, fields)


def send(sock: socket.socket, frame: bytes, fd: int | None = None) -> None:
    if fd is None:
        sock.sendall(frame)
    else:
        sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
        os.close(fd)


def recv_frame(sock: socket.socket) -> tuple[int, list[bytes]]:
    head = sock.recv(4, socket.MSG_WAITALL)
    body = sock.recv(int.from_bytes(head, 'big'), socket.MSG_WAITALL)
    return body[0], c.unpack_payload(body[0], body[1:])


def allow(h: Harness, key: str, methods=('GET',), prefixes=(), accounts=(), approval=Approval.NEVER, kind=KeyKind.EXACT,
          addresses=()):
    """``addresses``: the cell's named non-global addresses (K-57), passed only when some are named."""
    named = {'addresses': addresses} if addresses else {}
    h.tables.put('work0', make_entry(kind, key, EntryState.ALLOW, methods, prefixes, accounts, approval, **named))


def deny(h: Harness, key: str, methods=(), prefixes=(), kind=KeyKind.EXACT):
    h.tables.put('work0', make_entry(kind, key, EntryState.DENY, methods, prefixes, (), Approval.NEVER))


@pytest.fixture
def h(native, tmp_path: Path) -> Iterator[Harness]:
    harness = Harness(tmp_path, native)
    yield harness
    harness.close()


# ---- the recorded decisions without asking (K-12, K-43) ----------------------------------------------------------------------
def test_recorded_allow_without_credential_and_recorded_deny(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('GET',), ('/repos',))
    deny(h, 'evil.example:443')
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, body=b'x'), memfd(b'x'))
    h.pump()
    kind, fields = recv_frame(conn)
    assert kind == c.ALLOW_NOCRED and c.read_uint(fields[0], 8) == 1
    send(conn, judge_frame(2, ex.lease.uid, host=b'evil.example'), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_RECORDED)
    decided = h.events('request_decided')
    assert [(e['outcome'], e['reason_code']) for e in decided] == [('allow', 'recorded_allow'), ('deny', 'recorded_deny')]
    assert [e['detail']['admission'] for e in h.events('request_admitted')] == [1, 2]      # K-42 admission order
    assert not h.faults



def test_the_admission_record_carries_every_field_but_the_body(h: Harness) -> None:
    """Design 4.1 (2026-11-02): the trace records the request as it will be executed, every field but the body, once
    per request in the admission record; header values decode as latin-1, so the bytes come back exactly; the body
    leaves only its kind and length."""
    allow(h, 'api.github.com:443', ('POST',))
    ex, conn = h.row()
    headers = ((b'content-type', b'text/plain'), (b'x-note', b'caf\xe9 "q"'))
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', query=b'a=1&b=%20', headers=headers,
                           body_kind='text/plain', body=b'body-secret'), memfd(b'body-secret'))
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED
    admitted = h.events('request_admitted')[-1]['detail']
    assert admitted['query'] == 'a=1&b=%20' and admitted['header_names'] == ['content-type', 'x-note']
    assert [v.encode('latin-1') for v in admitted['header_values']] == [b'text/plain', b'caf\xe9 "q"']
    assert admitted['body_len'] == len(b'body-secret')
    assert all('body-secret' not in repr(e) for e in h.recorder.events)
    assert 'header_values' not in h.events('pdp_requested')[-1]['detail']          # recorded once per request

def test_credential_placed_from_the_record_not_the_request(h: Harness) -> None:
    """K-09, K-10, K-26: the binding comes from the entry's account and its record; the ALLOW carries the registered
    placement, word and truth; nothing of the request's header value is used."""
    h.credentials.register('api.github.com:443', 'alice', 2, b'token', b'ghp_truth', b'')
    allow(h, 'api.github.com:443', ('GET',), accounts=('alice',))
    allow(h, 'api.github.com:80', ('GET',), accounts=('alice',))
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, headers=((b'authorization', b'Bearer anything-at-all'),)), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert kind == c.ALLOW and (c.read_uint(fields[1], 1), fields[2], fields[3], fields[4], fields[5]) == \
        (2, b'token', b'ghp_truth', b'', b'alice')
    assert all(b'ghp_truth' not in repr(e).encode() for e in h.recorder.events)         # K-23: no truth in records
    # over http the same header goes without a credential (K-26): :80 has its own entry and no record for :80
    send(conn, judge_frame(2, ex.lease.uid, scheme=b'http', port=80, headers=((b'authorization', b'Bearer x'),)), memfd(b''))
    h.pump()
    kind, _ = recv_frame(conn)
    assert kind == c.DENY                     # :80 has no credential record: a carried header without one is refused
    h.credentials.register('api.github.com:80', 'alice', 2, b'Bearer', b'plain', b'')
    send(conn, judge_frame(3, ex.lease.uid, scheme=b'http', port=80, headers=((b'authorization', b'Bearer x'),)), memfd(b''))
    h.pump()
    kind, _ = recv_frame(conn)
    assert kind == c.ALLOW_NOCRED             # K-26: a record, but plain http never carries the truth
    # no credential header: allowed without a credential although the entry names an account
    send(conn, judge_frame(4, ex.lease.uid, headers=((b'x-other', b'v'),)), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.ALLOW_NOCRED, 1)


def test_the_account_is_the_one_chosen_at_start(h: Harness) -> None:
    """K-44: an entry allowing alice and carol; one execution started for carol, one started without a choice. The
    request's header value never picks: the first gets carol's truth whatever it sends, the second is refused."""
    h.credentials.register('api.github.com:443', 'alice', 2, b'Bearer', b'ghp_alice', b'')
    h.credentials.register('api.github.com:443', 'carol', 2, b'Bearer', b'ghp_carol', b'')
    allow(h, 'api.github.com:443', ('GET',), accounts=('alice', 'carol'))
    chosen, conn = h.row(0, accounts={'api.github.com:443': 'carol'})
    unchosen, conn2 = h.row(1)
    for ex, sock in ((chosen, conn), (unchosen, conn2)):
        for seq, ph in ((1, b'PH-ALICE'), (2, b'PH-CAROL')):
            send(sock, judge_frame(seq, ex.lease.uid, headers=((b'authorization', b'Bearer ' + ph),)), memfd(b''))
    h.pump()
    got = [recv_frame(conn) for _ in range(2)]
    assert all(k == c.ALLOW and f[3] == b'ghp_carol' and f[5] == b'carol' for k, f in got)
    got2 = [recv_frame(conn2) for _ in range(2)]
    assert all((k, c.read_uint(f[1], 1)) == (c.DENY, DENY_CREDENTIAL) for k, f in got2)  # several accounts, none designated
    # carol is taken off the entry: the execution started for her is refused, not moved to alice
    allow(h, 'api.github.com:443', ('GET',), accounts=('alice',))
    send(conn, judge_frame(3, chosen.lease.uid, headers=((b'authorization', b'Bearer x'),)), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_CREDENTIAL)
    # the execution started without a choice now uses the only account, read live
    send(conn2, judge_frame(3, unchosen.lease.uid, headers=((b'authorization', b'Bearer x'),)), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn2)
    assert kind == c.ALLOW and fields[3] == b'ghp_alice'


def test_replacing_or_deleting_a_record_cuts_its_account_everywhere(h: Harness) -> None:
    """K-31 (648d60f2 4.3): the credential store is shared, so every live row gets the REVOKE of that account."""
    h.credentials.register('api.github.com:443', 'alice', 2, b'Bearer', b'one', b'')
    ex0, conn0 = h.row(0)
    ex1, conn1 = h.row(1)
    h.hook.credential_changed('api.github.com:443', 'alice')
    for conn in (conn0, conn1):
        kind, fields = recv_frame(conn)
        assert kind == c.REVOKE and (c.read_uint(fields[0], 1), fields[1], fields[2], c.read_uint(fields[3], 1)) == \
            (int(KeyKind.EXACT), b'api.github.com:443', b'alice', 1)


def test_clause_10_shapes_are_refused_before_matching(h: Harness) -> None:
    allow(h, 'auth.example:443', ('POST',))
    allow(h, 'api.example:443', ('GET',), accounts=('a',))                  # the row can use account a
    h.credentials.register('api.example:443', 'a', 2, b'Bearer', b't', b'', token_endpoint='https://auth.example/oauth/token')
    ex, conn = h.row()
    form = ((b'content-type', b'application/x-www-form-urlencoded'),)
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', host=b'auth.example', path=b'/anything', headers=form,
                           body_kind='application/x-www-form-urlencoded', form_keys=('grant_type',), body=b'grant_type=x'),
         memfd(b'grant_type=x'))
    send(conn, judge_frame(2, ex.lease.uid, method=b'POST', host=b'auth.example', path=b'/oauth/token/'), memfd(b''))
    h.pump()
    for _ in range(2):
        kind, fields = recv_frame(conn)
        assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_CLAUSE)
    assert [e['reason_code'] for e in h.events('request_decided')] == ['clause10_token_form', 'clause10_endpoint']


def test_clause_10_lists_only_the_endpoints_of_accounts_this_row_can_use(h: Harness, tmp_path: Path) -> None:
    """条款 10 (design 2026-11-02): the endpoint list is the one of the accounts this row's binding can take. An endpoint
    another workspace registered, or one of an account the row was not given, is not this row's: the fallback GET to it
    goes on to the PDP exactly like one nobody registered, so the refusal tells the agent nothing about other rows."""
    allow(h, '', ('GET',), kind=KeyKind.FALLBACK)
    allow(h, 'api.example:443', ('GET',), accounts=('mine', 'spare'))
    h.credentials.register('api.example:443', 'mine', 2, b'Bearer', b't', b'', token_endpoint='https://auth.example/own/token')
    h.credentials.register('api.example:443', 'spare', 2, b'Bearer', b's', b'', token_endpoint='https://auth.example/spare/token')
    (tmp_path / 'root1').mkdir()
    h.tables.register('work1', str(tmp_path / 'root1'))
    h.tables.put('work1', make_entry(KeyKind.EXACT, 'api.other:443', EntryState.ALLOW, ('GET',), (), ('theirs',), Approval.NEVER))
    h.credentials.register('api.other:443', 'theirs', 2, b'Bearer', b'u', b'', token_endpoint='https://oauth.other/token')
    ex, conn = h.row(accounts={'api.example:443': 'mine'})
    expected = [(b'oauth.other', b'/token', c.ALLOW_NOCRED),          # another workspace's account
                (b'auth.example', b'/spare/token', c.ALLOW_NOCRED),   # listed in the cell, not designated for this row
                (b'auth.example', b'/own/token', c.DENY)]             # this row's account
    for seq, (host, path, want) in enumerate(expected, 1):
        send(conn, judge_frame(seq, ex.lease.uid, host=host, path=path), memfd(b''))
        h.pump()
        kind, fields = recv_frame(conn)
        assert kind == want, (host, path)
    assert c.read_uint(fields[1], 1) == DENY_CLAUSE
    assert [e['reason_code'] for e in h.events('request_decided') if e['outcome'] == 'deny'] == ['clause10_endpoint']


# ---- default deny (648d60f2 3.2; K-08, K-12, K-43) ----------------------------------------------------------------------------
def test_no_cell_an_uncovering_cell_and_a_recorded_deny_refuse_without_asking(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('GET',), ('/repos',))
    deny(h, 'evil.example:443')
    ex, conn = h.row()
    cases = [(1, dict(method=b'POST'), DENY_NOT_AUTHORIZED, 'not_covered'),             # the exact cell does not cover
             (2, dict(path=b'/users/a'), DENY_NOT_AUTHORIZED, 'not_covered'),
             (3, dict(host=b'unknown.example', method=b'POST'), DENY_NOT_AUTHORIZED, 'not_covered'),   # fallback: GET only
             (4, dict(host=b'evil.example'), DENY_RECORDED, 'recorded_deny')]
    for seq, kw, _, _ in cases:
        send(conn, judge_frame(seq, ex.lease.uid, **kw), memfd(b''))
    h.pump()
    for seq, _, reason, basis in cases:
        kind, fields = recv_frame(conn)
        assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, seq, reason)
    assert [e['reason_code'] for e in h.events('request_decided')] == [x[3] for x in cases]
    assert h.admin.questions == []                                            # nobody was asked
    # no entry at all, not even the fallback: refused too
    h.tables.delete('work0', KeyKind.FALLBACK, '')
    send(conn, judge_frame(5, ex.lease.uid, host=b'unknown.example'), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_NOT_AUTHORIZED) and h.events('request_decided')[-1]['reason_code'] == 'no_entry'


def test_the_table_reason_is_reported_before_clause_10(h: Harness) -> None:
    """648d60f2 4.3 拒绝回复: a request the table refuses is reported with the table's reason, not with 条款 10, so an
    agent cannot probe which token endpoints are registered; the trace keeps the finer cause."""
    allow(h, 'api.example:443', ('GET',), accounts=('a',))                  # the endpoint is this row's account's
    h.credentials.register('api.example:443', 'a', 2, b'Bearer', b't', b'', token_endpoint='https://auth.example/oauth/token')
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', host=b'auth.example', path=b'/oauth/token'), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_NOT_AUTHORIZED)
    assert h.events('request_decided')[-1]['detail']['clause10'] == 'clause10_endpoint'


# ---- asking the user, the four answers (648d60f2 3.2; K-13, K-15, K-16, K-45) --------------------------------------------------
def asked(h: Harness, conn, ex, seq: int, **kw) -> int:
    send(conn, judge_frame(seq, ex.lease.uid, **kw), memfd(b''))
    h.pump()
    return h.admin.questions[-1][0]


def test_only_an_ask_every_time_cell_asks_and_once_answers_change_nothing(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('POST',), ('/repos/a',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    before = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')]
    qid = asked(h, conn, ex, 1, method=b'POST', path=b'/repos/a/issues')
    assert h.admin.questions[0][5] == 1 and h.admin.questions[0][4] == 'api.github.com:443'
    assert h.hook.answer(qid, VERDICT_ALLOW_ONCE) == (None, b'')
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED
    qid = asked(h, conn, ex, 2, method=b'POST', path=b'/repos/a/issues')          # asks again: once is not recorded
    assert len(h.admin.questions) == 2
    assert h.hook.answer(qid, VERDICT_DENY_ONCE) == (None, b'')
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_USER)
    assert h.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')] == before
    assert h.hook.answer(qid, VERDICT_ALLOW_ONCE) == ('unknown_question', b'')     # answered already
    assert [e['detail']['verdict'] for e in h.events('question_answered')] == [1, 3]


def test_allow_always_stops_asking_on_the_whole_cell_and_nothing_else(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('POST',), ('/repos/a',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    qid = asked(h, conn, ex, 1, method=b'POST', path=b'/repos/a/issues')
    assert h.hook.answer(qid, VERDICT_ALLOW_CELL) == (None, b'persisted')
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED
    entry = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')]
    assert (entry.state, entry.methods, entry.prefixes, entry.approval) == (EntryState.ALLOW, {'POST'}, ('/repos/a',), Approval.NEVER)
    send(conn, judge_frame(2, ex.lease.uid, method=b'POST', path=b'/repos/a/pulls'), memfd(b''))   # same cell: no question
    send(conn, judge_frame(3, ex.lease.uid, method=b'GET', path=b'/repos/a'), memfd(b''))          # not widened: refused
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED and len(h.admin.questions) == 1
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_NOT_AUTHORIZED)
    again = WorkspaceStore(h.tables.directory.parent)                              # it survives a restart
    again.load()
    assert again.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')] == entry


def test_allow_always_that_does_not_persist_counts_as_this_time(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('POST',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    qid = asked(h, conn, ex, 1, method=b'POST')
    h.tables.disk.fail_at = 'rename'                         # the mirror write fails before the rename: not applied
    assert h.hook.answer(qid, VERDICT_ALLOW_CELL) == (None, b'not_applied')
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED                                       # this time allowed
    assert h.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')].approval is Approval.ALWAYS


def test_allow_always_that_reached_the_disk_name_is_in_effect_and_says_so(h: Harness) -> None:
    """Cold review 2026-11-01: a write that failed only at the directory fsync applies (K-18), so the note must not tell
    the user it counted as this time only."""
    allow(h, 'api.github.com:443', ('POST',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    qid = asked(h, conn, ex, 1, method=b'POST')
    h.tables.disk.fail_at = 'fsync_dir'
    assert h.hook.answer(qid, VERDICT_ALLOW_CELL) == (None, b'unpersisted')
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED
    assert h.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')].approval is Approval.NEVER


def test_deny_always_turns_the_whole_cell_into_a_deny_and_cuts_its_connections(h: Harness) -> None:
    h.credentials.register('api.github.com:443', 'alice', 2, b'Bearer', b't', b'')
    allow(h, 'api.github.com:443', ('GET',), accounts=('alice',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    qid = asked(h, conn, ex, 1, headers=((b'authorization', b'Bearer x'),))
    assert h.admin.questions[0][7] == m.Binding('api.github.com:443', 'alice', m.Placement.AUTHORIZATION_BEARER)
    assert h.hook.answer(qid, VERDICT_DENY_CELL) == (None, b'persisted')
    h.pump()
    # the deny goes to the request, and the allow cell with alice becoming a deny cuts every connection under its key
    got = [recv_frame(conn) for _ in range(2)]
    assert c.read_uint(next(f for k, f in got if k == c.DENY)[1], 1) == DENY_USER
    revokes = [(c.read_uint(f[0], 1), f[1], f[2], c.read_uint(f[3], 1)) for k, f in got if k == c.REVOKE]
    assert revokes == [(1, b'api.github.com:443', b'', 2)]                   # K-31: scope 2, every connection
    entry = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')]
    assert (entry.state, entry.methods, entry.accounts) == (EntryState.DENY, {'GET'}, frozenset())   # accounts cleared
    send(conn, judge_frame(2, ex.lease.uid), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_RECORDED) and len(h.admin.questions) == 1


@pytest.mark.parametrize('change', ['methods', 'more_specific', 'changed_back', 'credential', 'deny'])
def test_an_answer_to_a_changed_cell_is_void(h: Harness, change: str) -> None:
    """K-45: the answer binds the cell it was asked on and the binding shown; any change to that cell while the question
    was open (even one changed back), another cell now covering the request, a different binding or a recorded deny
    voids the answer and refuses the request; the next request is judged anew."""
    h.credentials.register('api.github.com:443', 'alice', 2, b'Bearer', b't', b'')
    allow(h, 'github.com:443', ('GET',), approval=Approval.ALWAYS, kind=KeyKind.PATTERN)
    allow(h, 'api.github.com:443', ('GET',), accounts=('alice',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    qid = asked(h, conn, ex, 1, headers=((b'authorization', b'Bearer x'),))
    if change == 'methods':
        allow(h, 'api.github.com:443', ('GET', 'POST'), accounts=('alice',), approval=Approval.ALWAYS)
    elif change == 'more_specific':                          # the exact cell goes; the pattern now covers the request
        h.tables.delete('work0', KeyKind.EXACT, 'api.github.com:443')
    elif change == 'changed_back':
        allow(h, 'api.github.com:443', ('GET', 'POST'), accounts=('alice',), approval=Approval.ALWAYS)
        allow(h, 'api.github.com:443', ('GET',), accounts=('alice',), approval=Approval.ALWAYS)
    elif change == 'credential':                              # the record goes: the binding is not the one shown
        h.credentials.delete('api.github.com:443', 'alice')
    else:
        deny(h, 'api.github.com:443')
    assert h.hook.answer(qid, VERDICT_ALLOW_ONCE) == ('superseded', b'')
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, 1, DENY_POLICY_CHANGED)
    assert h.events('question_answered')[-1]['detail'].get('superseded') is True


def test_an_unrelated_change_does_not_void_the_answer(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('GET',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    qid = asked(h, conn, ex, 1)
    allow(h, 'other.example:443', ('GET',))
    assert h.hook.answer(qid, VERDICT_ALLOW_ONCE) == (None, b'')
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED


def test_same_row_queues_behind_a_question_other_row_does_not_wait(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('GET',))
    allow(h, 'ask.example:443', ('GET',), approval=Approval.ALWAYS)
    a, conn_a = h.row(0)
    b, conn_b = h.row(1)
    send(conn_a, judge_frame(1, a.lease.uid, host=b'ask.example'), memfd(b''))   # asks
    send(conn_a, judge_frame(2, a.lease.uid), memfd(b''))                         # recorded allow, but queued behind
    send(conn_b, judge_frame(1, b.lease.uid), memfd(b''))                         # other row: immediate
    h.pump()
    assert recv_frame(conn_b)[0] == c.ALLOW_NOCRED
    conn_a.settimeout(0.2)
    with pytest.raises(TimeoutError):
        conn_a.recv(1)
    h.hook.answer(h.admin.questions[0][0], VERDICT_DENY_ONCE)
    h.pump()
    conn_a.settimeout(2)
    assert recv_frame(conn_a)[0] == c.DENY and recv_frame(conn_a)[0] == c.ALLOW_NOCRED


def test_queue_limit_and_no_timer_in_the_core(h: Harness) -> None:
    """K-15: 1 asking + 31 queued = 32, the 33rd is refused. The core keeps no question timer: the connector's total
    limit withdraws a request that waits too long (C-15)."""
    allow(h, 'api.github.com:443', ('POST',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    for seq in range(1, 34):
        send(conn, judge_frame(seq, ex.lease.uid, method=b'POST'), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, 33, DENY_QUEUE_FULL)
    h.clock.advance(3_600_000)                                   # an hour: the core refuses nothing by itself
    h.pump()
    conn.settimeout(0.2)
    with pytest.raises(TimeoutError):
        conn.recv(1)
    assert h.admin.withdrawals == [] and len(h.admin.questions) == 1


def test_withdraw_and_report(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('GET',))
    allow(h, 'api.github.com:443', ('GET', 'POST'), approval=Approval.ALWAYS)
    allow(h, 'plain.example:443', ('GET',))
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST'), memfd(b''))     # asking
    send(conn, judge_frame(2, ex.lease.uid, method=b'POST'), memfd(b''))     # queued
    send(conn, judge_frame(3, ex.lease.uid, host=b'plain.example'), memfd(b''))   # queued (recorded allow, no asking)
    h.pump()
    send(conn, c.pack_frame(c.WITHDRAW, [c.u64(2)]))                        # withdraw a queued one
    send(conn, c.pack_frame(c.WITHDRAW, [c.u64(1)]))                        # withdraw the asking one
    h.pump()
    qid = h.admin.questions[0][0]
    assert h.admin.withdrawals == [(qid, 1)]
    assert h.hook.answer(qid, VERDICT_ALLOW_ONCE) == ('unknown_question', b'')   # K-16: no allow after withdraw
    kind, fields = recv_frame(conn)
    assert kind == c.ALLOW_NOCRED and c.read_uint(fields[0], 8) == 3       # seq 3 advanced after the queue drained
    send(conn, c.pack_frame(c.REPORT, [c.u64(3), c.u8(1), c.u16(200)]))
    send(conn, c.pack_frame(c.REPORT, [c.u64(3), c.u8(1), c.u16(200)]))     # duplicate: recorded, ignored
    send(conn, c.pack_frame(c.WITHDRAW, [c.u64(99)]))                       # unknown: recorded, ignored
    h.pump()
    assert [e['detail']['stage'] for e in h.events('request_withdrawn')] == ['queued', 'asking']
    assert h.events('request_reported') == [] and not h.hook.rows[ex.execution_id].inflight   # bookkeeping, not recorded
    assert not [e for e in h.recorder.events if e['kind'] == 'diagnostic' and e['name'] == 'request_completed']
    diags = [e['name'] for e in h.recorder.events if e['kind'] == 'diagnostic']
    assert diags.count('report_ignored') == 1 and diags.count('withdraw_ignored') == 1 and not h.faults


# ---- protocol faults (K-02, K-03, K-24, K-36) ------------------------------------------------------------------------------------
def test_memfd_without_seals_or_wrong_size_is_refused(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('GET',))
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, body=b'xy'), memfd(b'xy', seals=fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK))
    send(conn, judge_frame(2, ex.lease.uid, body=b'xy'), memfd(b'x'))                        # size mismatch
    plain = os.open('/dev/null', os.O_RDONLY)
    send(conn, judge_frame(3, ex.lease.uid), plain)                                        # not a memfd
    h.pump()
    for seq in (1, 2, 3):
        kind, fields = recv_frame(conn)
        assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, seq, DENY_CLAUSE)
    assert all(e['reason_code'] == 'memfd_unsealed' for e in h.events('request_decided')) and not h.faults


@pytest.mark.parametrize('case', ['no_fd', 'seq_repeat', 'foreign_kind', 'wrong_sender', 'fd_on_withdraw', 'obj_put'])
def test_protocol_breaches_close_the_row(h: Harness, case: str) -> None:
    allow(h, 'api.github.com:443', ('GET',))
    ex, conn = h.row()
    if case == 'no_fd':
        send(conn, judge_frame(1, ex.lease.uid))
    elif case == 'seq_repeat':
        send(conn, judge_frame(5, ex.lease.uid), memfd(b''))
        send(conn, judge_frame(5, ex.lease.uid), memfd(b''))
    elif case == 'foreign_kind':
        send(conn, c.pack_frame(c.ANSWER, [c.u64(1), c.u8(1)]))
    elif case == 'wrong_sender':
        send(conn, judge_frame(1, ex.lease.uid + 1), memfd(b''))
    elif case == 'obj_put':                                  # H-01: no registration verb on the judgment port
        send(conn, c.pack_frame(c.OBJ_PUT, [b'work0', b'x', b'/', c.u8(2), c.u8(1), c.u8(1), c.u8(1)]))
    else:
        send(conn, c.pack_frame(c.WITHDRAW, [c.u64(1)]), memfd(b''))
    h.pump()
    assert h.faults and h.faults[0][0] == ex.execution_id
    assert any(e['kind'] == 'diagnostic' and e['name'] == 'judgment_port_fault' for e in h.recorder.events)


def test_row_close_refuses_queued_and_asking_and_drops_inflight(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('GET',))
    allow(h, 'api.github.com:443', ('GET', 'POST'), approval=Approval.ALWAYS)
    allow(h, 'plain.example:443', ('GET',))
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'plain.example'), memfd(b''))   # allowed -> in flight
    send(conn, judge_frame(2, ex.lease.uid, method=b'POST'), memfd(b''))    # asking
    send(conn, judge_frame(3, ex.lease.uid, method=b'POST'), memfd(b''))    # queued
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED
    qid = h.admin.questions[0][0]
    h.close_row(ex)
    h.pump()
    for seq in (3, 2):
        kind, fields = recv_frame(conn)
        assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, seq, DENY_CLOSED)
    assert h.admin.withdrawals == [(qid, 2)]
    assert conn.recv(16) == b''                                              # the port is gone
    assert ex.execution_id not in h.hook.rows


# ---- K-14: a table change is one loop step; the next request sees it -----------------------------------------------------------
def test_table_change_applies_to_the_next_request_in_order(h: Harness) -> None:
    allow(h, 'api.github.com:443', ('GET',))
    allow(h, 'ask.example:443', ('GET',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'ask.example'), memfd(b''))   # asks: later requests queue behind it
    send(conn, judge_frame(2, ex.lease.uid), memfd(b''))                     # GET, queued; the table allows it now
    h.pump()
    deny(h, 'api.github.com:443', ('GET',))                                  # the change lands while seq 2 waits
    h.hook.table_changed('work0', None, h.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')])
    h.hook.answer(h.admin.questions[0][0], VERDICT_DENY_ONCE)
    h.pump()
    kind, fields = recv_frame(conn)                                          # the new deny revokes everything under its key
    assert (kind, c.read_uint(fields[0], 1), fields[1], c.read_uint(fields[3], 1)) == (c.REVOKE, 1, b'api.github.com:443', 2)
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, 1, DENY_USER)
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, 2, DENY_RECORDED)   # judged after the change
    send(conn, judge_frame(3, ex.lease.uid), memfd(b''))
    allow(h, 'api.github.com:443', ('GET',))                                 # relaxed again before seq 3 is read
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED


def test_deleting_an_accountless_allow_entry_revokes_its_connections(h: Harness) -> None:
    """B8: an allowance without accounts still had connections (account ''); its deletion cuts them."""
    allow(h, 'files.pythonhosted.org:443', ('GET',))
    ex, conn = h.row()
    old = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'files.pythonhosted.org:443')]
    h.hook.table_changed('work0', old, None)
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[0], 1), fields[1], fields[2], c.read_uint(fields[3], 1)) == \
        (c.REVOKE, 1, b'files.pythonhosted.org:443', b'', 2)
    assert [e['detail']['account'] for e in h.events('entry_revoked')] == ['*']


def test_completion_is_recorded_only_under_the_measurement_switch(native, tmp_path: Path) -> None:
    """648d60f2 4.3 engine 不记完成 (K-23, C-27): with the gate's measurement switch, a diagnostic only."""
    h = Harness(tmp_path, native)
    h.hook.measure_completion = True
    allow(h, 'api.github.com:443', ('GET',))
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid), memfd(b''))
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED
    send(conn, c.pack_frame(c.REPORT, [c.u64(1), c.u8(1), c.u16(204)]))
    h.pump()
    assert h.events('request_reported') == []
    [done] = [e for e in h.recorder.events if e['kind'] == 'diagnostic' and e['name'] == 'request_completed']
    assert (done['detail']['seq'], done['detail']['status'], done['detail']['measurement_only']) == (1, 204, True)


def test_a_port_that_fails_during_a_revocation_closes_its_row_and_the_others_still_get_theirs(h: Harness) -> None:
    """K-31 (overall review 2026-11-03, #9): a judgment port whose write fails while a revocation goes out closes its row
    at once (the lifecycle's fault handler, wired here as it is in the engine), from inside the loop over the rows; the
    loop goes on over the rows still open, and the core keeps running."""
    h.credentials.register('api.github.com:443', 'alice', 2, b'Bearer', b'one', b'')
    allow(h, 'api.github.com:443', ('GET',), accounts=('alice',))
    old = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')]
    rows = [h.row(i) for i in range(4)]
    for ex, _ in rows:
        h.rows[ex.execution_id][1].on_fault = lambda row, why: h.hook.row_closed(row)
    (ex0, conn0), (ex1, conn1), (ex2, conn2), (ex3, conn3) = rows
    conn0.close()
    conn2.close()                                                   # rows 0 and 2: every write now fails
    h.hook.credential_changed('api.github.com:443', 'alice')
    assert ex0.execution_id not in h.hook.rows and ex2.execution_id not in h.hook.rows
    assert recv_frame(conn1)[0] == c.REVOKE and recv_frame(conn3)[0] == c.REVOKE
    conn3.close()                                                   # now row 3 fails while the table change goes out
    h.hook.table_changed('work0', old, None)
    assert ex3.execution_id not in h.hook.rows and recv_frame(conn1)[0] == c.REVOKE


def test_a_row_keeps_nothing_per_request_once_its_requests_are_done(h: Harness) -> None:
    """3.4 每行上限 (overall review 2026-11-03, #16): a row's state does not grow with the number of requests it has had;
    a withdraw for an old or an unknown sequence number is still told apart in the diagnostic."""
    allow(h, 'api.github.com:443', ('GET',))
    ex, conn = h.row()
    for seq in range(1, 51):
        send(conn, judge_frame(seq, ex.lease.uid), memfd(b''))
        h.pump()
        assert recv_frame(conn)[0] == c.ALLOW_NOCRED
        send(conn, c.pack_frame(c.REPORT, [c.u64(seq), c.u8(1), c.u16(200)]))
        h.pump()
    row = h.hook.rows[ex.execution_id]
    assert not [name for name, value in vars(row).items() if isinstance(value, (set, dict, list, deque)) and value]
    send(conn, c.pack_frame(c.WITHDRAW, [c.u64(7)]))
    send(conn, c.pack_frame(c.WITHDRAW, [c.u64(99)]))
    h.pump()
    ignored = [e['detail'] for e in h.recorder.events if e['kind'] == 'diagnostic' and e['name'] == 'withdraw_ignored']
    assert [(d['seq'], d['known'], d['port']) for d in ignored] == [(7, True, 'judgment'), (99, False, 'judgment')]


# ---- named non-global addresses (plan engine-v3-private-net; validation.md K-58, K-59, K-31) -----------------------------
def named_field(kind: int, fields: list[bytes]) -> list[bytes]:
    """The named-address field (K-59; SPEC §3.2): the last of ALLOW's 7 fields, of ALLOW_NOCRED's 3, as its items."""
    assert len(fields) == {c.ALLOW: 7, c.ALLOW_NOCRED: 3}[kind], f'{len(fields)} fields: no named-address field'
    return c.unpack_list(fields[-1])


def silent_for(conn: socket.socket, s: float = 0.2) -> bool:
    conn.settimeout(s)
    try:
        conn.recv(1, socket.MSG_PEEK)
    except TimeoutError:
        return True
    finally:
        conn.settimeout(2)
    return False


@pytest.mark.parametrize('host', [b'10.0.0.5', b'192.168.1.10', b'172.16.0.1', b'100.64.0.1', b'fd12:3456::1',
                                  b'169.254.169.254'])   # the last never gets here (C-35); if it did, refused alike
def test_a_non_global_ip_literal_nobody_named_is_refused_at_the_first_checkpoint(h: Harness, host: bytes) -> None:
    """K-58: under the fallback entry (GET anywhere, never ask) a request to a non-global IP literal that no covering
    cell names is refused at once with not_authorized, recorded as address_not_named; the PDP and the management port
    hear nothing of it."""
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, scheme=b'http', host=host, port=80, path=b'/'), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, 1, DENY_NOT_AUTHORIZED)
    decided = h.events('request_decided')[-1]
    assert (decided['outcome'], decided['reason_code']) == ('deny', 'address_not_named')
    assert h.pdp.requests == [] and h.events('pdp_requested') == []
    assert h.admin.questions == [] and h.events('question_asked') == []


@pytest.mark.parametrize('host, port, prefix', [(b'10.0.0.5', 80, '10.0.0.0/24'), (b'fd12:3456::1', 443, 'fd12:3456::/48')])
def test_an_ip_key_does_not_name_itself_and_naming_its_prefix_lets_it_on(h: Harness, host: bytes, port: int,
                                                                          prefix: str) -> None:
    """K-58, K-59 (design 3.2): an exact entry keyed by the IP literal does not name it; once the cell names a prefix
    holding it, the request goes on to the PDP and the ALLOW_NOCRED carries the cell's named list."""
    key = f'{host.decode()}:{port}'
    scheme = b'http' if port == 80 else b'https'
    allow(h, key, ('GET',))
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, scheme=scheme, host=host, port=port, path=b'/'), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_NOT_AUTHORIZED)
    assert h.events('request_decided')[-1]['reason_code'] == 'address_not_named' and h.pdp.requests == []
    allow(h, key, ('GET',), addresses=(prefix,))
    send(conn, judge_frame(2, ex.lease.uid, scheme=scheme, host=host, port=port, path=b'/'), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert kind == c.ALLOW_NOCRED and named_field(kind, fields) == [prefix.encode()]
    assert len(h.pdp.requests) == 1


def test_an_ask_every_time_cell_that_does_not_name_the_literal_asks_nothing(h: Harness) -> None:
    """K-58: the refusal is the table's, at the first checkpoint, before any question."""
    allow(h, '10.0.0.5:80', ('GET',), approval=Approval.ALWAYS)
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, scheme=b'http', host=b'10.0.0.5', port=80, path=b'/'), memfd(b''))
    h.pump()
    assert h.admin.questions == [] and h.events('question_asked') == [] and h.pdp.requests == []
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_NOT_AUTHORIZED)
    assert h.events('request_decided')[-1]['reason_code'] == 'address_not_named'


def test_a_name_on_another_cell_does_not_reach_the_literal(h: Harness) -> None:
    """K-58 (design 3.2: a name works only for the requests its cell covers): an exact entry for a host name names
    10.0.0.0/8; a request to the IP literal 10.0.0.5 is covered by the fallback, which names nothing."""
    allow(h, 'gitlab.corp:443', ('GET',), addresses=('10.0.0.0/8',))
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'10.0.0.5', port=443, path=b'/'), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_NOT_AUTHORIZED)
    assert h.events('request_decided')[-1]['reason_code'] == 'address_not_named' and h.pdp.requests == []


@pytest.mark.parametrize('host, port', [(b'93.184.216.34', 80), (b'2606:4700::1111', 443)])
def test_a_global_ip_literal_is_not_held_to_naming(h: Harness, host: bytes, port: int) -> None:
    """K-58: a globally reachable literal is judged as before (here: the fallback GET goes on to the PDP)."""
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, scheme=b'http' if port == 80 else b'https', host=host, port=port, path=b'/'),
         memfd(b''))
    h.pump()
    assert recv_frame(conn)[0] == c.ALLOW_NOCRED and len(h.pdp.requests) == 1


def test_a_literal_nobody_named_reports_the_table_reason_before_clause_10(h: Harness) -> None:
    """K-58, K-51 (648d60f2 4.3 拒绝回复): a token-shaped form to an un-named private literal is refused not_authorized,
    not clause; the trace keeps the 条款 10 hit."""
    allow(h, '10.0.0.5:80', ('POST',))
    ex, conn = h.row()
    form = ((b'content-type', b'application/x-www-form-urlencoded'),)
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', scheme=b'http', host=b'10.0.0.5', port=80, path=b'/token',
                           headers=form, body_kind='application/x-www-form-urlencoded', form_keys=('grant_type',),
                           body=b'grant_type=x'), memfd(b'grant_type=x'))
    h.pump()
    kind, fields = recv_frame(conn)
    assert (kind, c.read_uint(fields[1], 1)) == (c.DENY, DENY_NOT_AUTHORIZED)
    decided = h.events('request_decided')[-1]
    assert decided['reason_code'] == 'address_not_named' and decided['detail']['clause10'] == 'clause10_token_form'


def test_the_allow_frames_carry_the_covering_cells_named_addresses(h: Harness) -> None:
    """K-59: ALLOW and ALLOW_NOCRED each carry the named list of the cell that passed, in stored texts and stored
    order; nothing of the request (a header shaped like a name) gets in."""
    h.credentials.register('gitlab.corp:443', 'alice', 2, b'Bearer', b't', b'')
    allow(h, 'gitlab.corp:443', ('GET',), accounts=('alice',), addresses=('fd12:3456::/48', '10.0.0.0/8'))
    ex, conn = h.row()
    shaped = (b'x-named', b'0.0.0.0/0')
    send(conn, judge_frame(1, ex.lease.uid, host=b'gitlab.corp', headers=((b'authorization', b'Bearer x'), shaped)),
         memfd(b''))
    send(conn, judge_frame(2, ex.lease.uid, host=b'gitlab.corp', headers=(shaped,)), memfd(b''))
    h.pump()
    kind, fields = recv_frame(conn)
    assert kind == c.ALLOW and named_field(kind, fields) == [b'10.0.0.0/8', b'fd12:3456::/48']
    kind, fields = recv_frame(conn)
    assert kind == c.ALLOW_NOCRED and named_field(kind, fields) == [b'10.0.0.0/8', b'fd12:3456::/48']


def test_a_pattern_or_fallback_allow_names_nothing(h: Harness) -> None:
    """K-59: a pattern or the fallback cell names no address, so its ALLOW_NOCRED carries an empty list."""
    allow(h, 'wikipedia.org:443', ('GET',), kind=KeyKind.PATTERN)
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'en.wikipedia.org'), memfd(b''))
    send(conn, judge_frame(2, ex.lease.uid, host=b'example.com'), memfd(b''))
    send(conn, judge_frame(3, ex.lease.uid, scheme=b'http', host=b'93.184.216.34', port=80), memfd(b''))
    h.pump()
    for _ in range(3):
        kind, fields = recv_frame(conn)
        assert kind == c.ALLOW_NOCRED and named_field(kind, fields) == []


def test_after_the_third_checkpoint_redoes_the_first_the_field_is_the_redos_cell(h: Harness) -> None:
    """K-59, K-46: the cell is rewritten while the PDP judges (the version moves; methods widened, the same addresses
    in another order): the redo passes and the ALLOW_NOCRED carries the redo's cell's list."""
    allow(h, 'gitlab.corp:443', ('GET',), ('/api',), addresses=('10.0.0.0/8', 'fd12:3456::/48'))
    h.pdp.hold = True
    ex, conn = h.row()
    send(conn, judge_frame(1, ex.lease.uid, host=b'gitlab.corp', path=b'/api/x'), memfd(b''))
    h.pump()
    version = h.tables.tables['work0'].version
    allow(h, 'gitlab.corp:443', ('GET', 'POST'), ('/api',), addresses=('fd12:3456::/48', '10.0.0.0/8'))
    assert h.tables.tables['work0'].version == version + 1
    h.pdp.answer(h.pdp.requests[0])
    h.pump()
    kind, fields = recv_frame(conn)
    assert kind == c.ALLOW_NOCRED and named_field(kind, fields) == [b'10.0.0.0/8', b'fd12:3456::/48']


@pytest.mark.parametrize('verdict', [VERDICT_ALLOW_CELL, VERDICT_DENY_CELL])
def test_a_persistent_answer_on_a_cell_that_names_addresses(h: Harness, verdict: int) -> None:
    """648d60f2 3.2 with K-57: "allow, never ask again" changes only the approval mode, so the cell keeps its named
    addresses; "deny from now on" makes a deny entry, which names none (accounts cleared as before). Either way the
    mirror reads back."""
    allow(h, 'gitlab.corp:443', ('GET',), approval=Approval.ALWAYS, addresses=('10.0.0.0/8',))
    ex, conn = h.row()
    qid = asked(h, conn, ex, 1, host=b'gitlab.corp')
    assert h.hook.answer(qid, verdict) == (None, b'persisted')
    entry = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'gitlab.corp:443')]
    if verdict == VERDICT_ALLOW_CELL:
        assert (entry.state, entry.approval, entry.addresses) == (EntryState.ALLOW, Approval.NEVER, ('10.0.0.0/8',))
    else:
        assert (entry.state, entry.addresses) == (EntryState.DENY, ())
    again = WorkspaceStore(h.tables.directory.parent)
    again.load()
    assert not again.tables['work0'].unavailable and again.tables['work0'].entries[entry.identity] == entry


@pytest.mark.parametrize('after', [('10.0.0.0/8',), (), ('192.168.0.0/16',)])
def test_a_cell_that_loses_named_addresses_cuts_every_connection_under_its_key(h: Harness, tmp_path: Path,
                                                                              after: tuple[str, ...]) -> None:
    """K-31 (user 2026-11-05): an entry that loses any named address sends REVOKE scope 2 for its key (account empty)
    to the connector of every row of that workspace, as a removed allow does; another workspace's rows get nothing."""
    allow(h, 'gitlab.corp:443', ('GET',), addresses=('10.0.0.0/8', 'fd12:3456::/48'))
    old = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'gitlab.corp:443')]
    (tmp_path / 'root1').mkdir()
    h.tables.register('work1', str(tmp_path / 'root1'))
    rows = [h.row(0), h.row(1)]
    _, other = h.row(2, workspace='work1')
    allow(h, 'gitlab.corp:443', ('GET',), addresses=after)
    new = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'gitlab.corp:443')]
    h.hook.table_changed('work0', old, new)
    h.pump()
    for _, conn in rows:
        kind, fields = recv_frame(conn)
        assert (kind, c.read_uint(fields[0], 1), fields[1], fields[2], c.read_uint(fields[3], 1)) == \
            (c.REVOKE, int(KeyKind.EXACT), b'gitlab.corp:443', b'', 2)
        assert silent_for(conn)                                     # one frame per row
    assert silent_for(other)
    assert [e['detail']['key'] for e in h.events('entry_revoked')] == ['gitlab.corp:443'] * 2


@pytest.mark.parametrize('after', [('10.0.0.0/8', 'fd12:3456::/48', '192.168.0.0/16'), ('fd12:3456::/48', '10.0.0.0/8')])
def test_a_cell_that_names_more_addresses_or_the_same_cuts_nothing(h: Harness, after: tuple[str, ...]) -> None:
    """K-31: only losing an address cuts; adding addresses or writing the same set again sends no REVOKE."""
    allow(h, 'gitlab.corp:443', ('GET',), addresses=('10.0.0.0/8', 'fd12:3456::/48'))
    old = h.tables.tables['work0'].entries[(KeyKind.EXACT, 'gitlab.corp:443')]
    ex, conn = h.row()
    allow(h, 'gitlab.corp:443', ('GET',), addresses=after)
    h.hook.table_changed('work0', old, h.tables.tables['work0'].entries[(KeyKind.EXACT, 'gitlab.corp:443')])
    h.pump()
    assert silent_for(conn) and h.events('entry_revoked') == []
