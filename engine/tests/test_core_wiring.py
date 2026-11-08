"""The judgment port follows the row's lifecycle (validation.md K-01, K-22): created at spawn_prepared from the record's
second descriptor, bound to that row's object, closed with the row, with queued requests refused."""
from __future__ import annotations

import os
from pathlib import Path
import socket

import pytest

from conftest import Harness
from connector import canonical as c
from engine.credentials import CredentialStore
from engine.hook import Hook
from engine.judgment import DENY_CLOSED
from engine.lifecycle import COMMIT
from engine.objects import ExecState
from engine.workspaces import Approval, EntryState, KeyKind, WorkspaceStore, make_entry
from test_hook import FakePdp, judge_frame, memfd, recv_frame, send


def with_core(h: Harness, tmp_path: Path) -> Hook:
    (tmp_path / 'root').mkdir(exist_ok=True)
    tables = WorkspaceStore(tmp_path / 'state')
    tables.load()
    for wid in ('work0', 'work1', 'work2'):
        (tmp_path / wid).mkdir(exist_ok=True)
        tables.register(wid, str(tmp_path / wid))
    credentials = CredentialStore(tmp_path / 'state')
    credentials.load()
    hook = Hook(h.loop, h.recorder, tables, credentials, h.recorder.diagnostic)
    FakePdp(hook, h.loop)                    # answers allow one round later (test_hook.FakePdp)
    h.lc.hook, h.lc.tables = hook, tables
    # the harness's connector and worker uid are the test's own uid: frames from this process carry it
    h.lc.catalog = type(h.lc.catalog)(**{**h.lc.catalog.__dict__, 'connector_uid': os.getuid(),
                                         'worker_uid': os.getuid()})
    return hook


def file_ask(seq: int, uid: int, op: int, alias: bytes = b'', path: bytes = b'', start: int = 0,
             length: int = 0) -> bytes:
    return c.pack_frame(c.FILE_ASK, [c.u64(seq), c.u32(uid), c.u8(op), alias, path, c.u64(start), c.u32(length)])


def test_the_file_port_is_born_with_the_row_and_dies_with_it(h: Harness, tmp_path: Path) -> None:
    """H-06: the record's third fd becomes the row's file judgment port, registered with the hook beside the judgment
    port; listing the objects is answered on it; closing the row refuses the file request waiting at the question
    (unavailable) and closes the port."""
    hook = with_core(h, tmp_path)
    (tmp_path / 'host').mkdir()
    hook.workspaces.register_object('work0', 'notes', str(tmp_path / 'host'), c.FILE_TYPE_DIR,
                                    c.FILE_OPS_READ | c.FILE_OPS_LIST, 1, 2)          # allowed, ask every time
    ex = h.launch()
    core_end, connector_end = h.spawner.judgment_pair()          # kept open: a closed judgment port closes the row
    core_file, worker_end = h.spawner.judgment_pair()
    child = h.spawner.prepared(ex, judgment=core_end, file_judgment=core_file)
    h.pump()
    assert child.recv(64) == COMMIT and ex.execution_id in h.lc.file_ports
    assert hook.rows[ex.execution_id].file_port is h.lc.file_ports[ex.execution_id]
    worker_end.settimeout(2)
    worker_end.sendall(file_ask(1, ex.lease.uid, c.FILE_OP_OBJECTS))
    h.pump()
    kind, fields = recv_frame(worker_end)
    assert kind == c.FILE_OBJECT_LIST and [c.unpack_list(i)[0] for i in c.unpack_list(fields[1])] == [b'notes']
    worker_end.sendall(file_ask(2, ex.lease.uid, c.FILE_OP_READ, b'notes', b'a.txt', 0, 10))   # waits for the user
    h.pump()
    h.lc.close_session(ex)
    h.pump()
    kind, fields = recv_frame(worker_end)
    assert (kind, c.read_uint(fields[0], 8), c.FILE_REASONS[c.read_uint(fields[1], 1) - 1]) == \
        (c.FILE_DENY, 2, 'unavailable')
    assert worker_end.recv(16) == b'' and ex.execution_id not in h.lc.file_ports and ex.execution_id not in hook.rows
    assert ex.file_judgment is None and not h.lc.control.dead
    for s in (worker_end, connector_end, child):
        s.close()


def test_a_worker_protocol_breach_closes_the_row(h: Harness, tmp_path: Path) -> None:
    """H-06: a FILE_ASK whose sender is not the row closes the row (the worker checked the stamp; a defect)."""
    with_core(h, tmp_path)
    ex = h.launch()
    core_end, connector_end = h.spawner.judgment_pair()
    core_file, worker_end = h.spawner.judgment_pair()
    child = h.spawner.prepared(ex, judgment=core_end, file_judgment=core_file)
    h.pump()
    assert child.recv(64) == COMMIT and ex.state is ExecState.ACTIVE
    worker_end.sendall(file_ask(1, ex.lease.uid + 7, c.FILE_OP_OBJECTS))
    h.pump()
    assert ex.state is ExecState.CLOSED and ex.close_reason == 'protocol_error'
    assert any(e['kind'] == 'diagnostic' and e['name'] == 'file_port_fault' for e in h.recorder.events)
    for s in (worker_end, connector_end, child):
        s.close()


def test_port_is_born_with_the_row_and_dies_with_it(h: Harness, tmp_path: Path) -> None:
    hook = with_core(h, tmp_path)
    hook.workspaces.put('work0', make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['GET'], [], [], Approval.NEVER))
    hook.workspaces.put('work0', make_entry(KeyKind.EXACT, 'ask.example:443', EntryState.ALLOW, ['GET'], [], [], Approval.ALWAYS))
    ex = h.launch()
    core_end, connector_end = h.spawner.judgment_pair()
    core_file, worker_end = h.spawner.judgment_pair()            # kept open: a closed file port closes the row too
    child = h.spawner.prepared(ex, judgment=core_end, file_judgment=core_file)
    core_end.close()
    h.pump()
    assert child.recv(64) == COMMIT and ex.execution_id in h.lc.ports and ex.execution_id in hook.rows
    connector_end.settimeout(2)
    send(connector_end, judge_frame(1, ex.lease.uid), memfd(b''))
    send(connector_end, judge_frame(2, ex.lease.uid, host=b'ask.example'), memfd(b''))   # asks, stays pending
    h.pump()
    assert recv_frame(connector_end)[0] == c.ALLOW_NOCRED
    assert len(h.events('request_admitted')) == 2
    h.lc.close_session(ex)
    h.pump()
    kind, fields = recv_frame(connector_end)
    assert (kind, c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)) == (c.DENY, 2, DENY_CLOSED)
    assert connector_end.recv(16) == b'' and ex.execution_id not in h.lc.ports and ex.execution_id not in hook.rows
    assert ex.state is ExecState.CLOSED and not h.lc.control.dead


def test_connector_protocol_breach_closes_the_row(h: Harness, tmp_path: Path) -> None:
    with_core(h, tmp_path)
    ex = h.launch()
    core_end, connector_end = h.spawner.judgment_pair()
    core_file, worker_end = h.spawner.judgment_pair()
    child = h.spawner.prepared(ex, judgment=core_end, file_judgment=core_file)
    core_end.close()
    h.pump()
    assert child.recv(64) == COMMIT
    send(connector_end, judge_frame(1, ex.lease.uid + 7), memfd(b''))     # a sender that is not this row (K-02)
    h.pump()
    assert ex.state is ExecState.CLOSED and ex.close_reason == 'protocol_error'
    assert any(e['kind'] == 'diagnostic' and e['name'] == 'judgment_port_fault' for e in h.recorder.events)


def test_blocked_or_unavailable_table_refuses_new_spawn(h: Harness, tmp_path: Path) -> None:
    hook = with_core(h, tmp_path)
    hook.workspaces.tables['work0'].spawn_blocked = True
    with pytest.raises(Exception):
        h.lc.launch('work0', 'observe-0', 'agent-0')
    hook.workspaces.tables['work1'].unavailable = True
    with pytest.raises(Exception):
        h.lc.launch('work1', 'observe-1', 'agent-1')
    assert h.lc.launch('work2', 'observe-2', 'agent-2') is not None
