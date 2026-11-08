"""The engine checks' two host-file-read cases (plan engine-v3-n16-file-read 2.3c), the runner's side.

worker-kill (validation.md H-17 on the whole machine): the runner, as root, kills the row's real file worker while the
agent waits; the engine (uid 1000) cannot signal the worker's uid. mcp (H-23, H-24): a directory on the host registered
in work0, the fixture ("agent mcp") speaking HTTP to the row's real MCP server, and what the fixture logged checked
here. The engine's side of both is engine/testing/scenario.py (worker_kill, mcp); checks/run_engine_checks.py wires them.
"""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import re
import secrets
import signal
import time
from typing import Any

from gate_seed import MCP_ARGV
from run_sandbox_checks import WORKER_ID, save_json


def real_mcp(root: Path) -> None:
    """The seed's real MCP server (mcp/engine-mcp, built by gate_seed.mcp_build) in place of the frontend's stand-in."""
    catalog = json.loads((root / 'catalog.json').read_text())
    catalog['mcp_server'] = {'executable': MCP_ARGV[0], 'argv': MCP_ARGV}
    save_json(root / 'catalog.json', catalog)


def host_files(top: Path) -> dict[str, Any]:
    """The host directory the mcp case registers, outside every directory of the engine's (H-22): notes/notes.txt with
    one random marker, outside.txt beside notes/ with another, notes/escape a symlink to ../outside.txt."""
    top.chmod(0o755)
    markers = {'inside': 'w2-mcp-inside-' + secrets.token_hex(16), 'outside': 'w2-mcp-outside-' + secrets.token_hex(16)}
    (top / 'notes').mkdir(mode=0o755)
    (top / 'notes/notes.txt').write_text(f'a host file read through the engine: {markers["inside"]}\n')
    (top / 'outside.txt').write_text(f'outside the registered directory: {markers["outside"]}\n')
    (top / 'notes/escape').symlink_to('../outside.txt')
    return {'notes': str(top / 'notes'), 'markers': markers}


def mcp_requests(notes: str) -> list[dict[str, Any]]:
    """What the fixture POSTs, in order: initialize, the initialized notification, tools/list, then six tool calls."""
    calls = [('list_host_objects', {}), ('list_host_directory', {'path': notes}),
             ('read_host_file', {'path': notes + '/notes.txt'}), ('read_host_file', {'path': notes + '/../outside.txt'}),
             ('read_host_file', {'path': notes + '/escape'}), ('read_host_file', {'path': '/etc/hostname'})]
    return [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
             'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                        'clientInfo': {'name': 'agent-fixture', 'version': '1'}}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}] + \
        [{'jsonrpc': '2.0', 'id': 3 + i, 'method': 'tools/call', 'params': {'name': name, 'arguments': arguments}}
         for i, (name, arguments) in enumerate(calls)]


def write_requests(path: Path, notes: str, owner: int) -> None:
    """The request file in the workspace's subdirectory, one JSON body per line, the owner's (the cell sees it as its
    own through the idmapped mount)."""
    path.write_text(''.join(json.dumps(body, separators=(',', ':')) + '\n' for body in mcp_requests(notes)))
    os.chown(path, owner, owner)
    path.chmod(0o600)


def http_responses(note: str) -> list[tuple[int, str, Any]]:
    """The fixture's "mcp=response <hex>" lines: status, content type and the JSON body (None when empty)."""
    out = []
    for line in note.splitlines():
        if not line.startswith('mcp='):
            continue
        assert line.startswith('mcp=response '), line
        head, _, body = bytes.fromhex(line[len('mcp=response '):]).partition(b'\r\n\r\n')
        lines = head.decode('latin-1').split('\r\n')
        headers = {k.strip().lower(): v.strip() for k, v in (h.split(':', 1) for h in lines[1:])}
        if headers.get('transfer-encoding', '').lower() == 'chunked':
            chunks = b''
            while True:
                size_line, _, body = body.partition(b'\r\n')
                size = int(size_line.split(b';')[0], 16)
                if not size:
                    break
                chunks, body = chunks + body[:size], body[size + 2:]
            body = chunks
        out.append((int(lines[0].split()[1]), headers.get('content-type', ''), json.loads(body) if body.strip() else None))
    return out


def check_mcp(note: str, notes: str, markers: dict[str, str]) -> dict[str, Any]:
    """H-23, H-24 seen from the agent's side: the protocol round trip, the three tools, the read and the three refusals."""
    got = http_responses(note)
    assert len(got) == 9, (len(got), note[:2000])
    (s0, t0, init), (s1, _, _), (s2, _, tools), *calls = got
    assert s0 == 200 and t0.startswith('application/json'), (s0, t0)
    assert init['result']['protocolVersion'] == '2025-11-25' and 'tools' in init['result']['capabilities'], init
    assert s1 == 202 and s2 == 200, (s1, s2)
    assert sorted(t['name'] for t in tools['result']['tools']) == ['list_host_directory', 'list_host_objects',
                                                                  'read_host_file'], tools
    assert all(s == 200 for s, _, _ in calls), [s for s, _, _ in calls]
    results = [body['result'] for _, _, body in calls]
    objects = json.loads(results[0]['content'][0]['text'])['objects']
    assert objects == [{'path': notes, 'type': 'directory', 'operations': ['read', 'list'], 'approval': 'allowed'}], objects
    entries = sorted((e['name'], e['type']) for e in json.loads(results[1]['content'][0]['text'])['entries'])
    assert entries == [('escape', 'symlink'), ('notes.txt', 'file')], entries
    read = results[2]
    assert not read['isError'] and read['content'][1]['text'] == Path(notes, 'notes.txt').read_text(), read
    assert markers['inside'] in read['content'][1]['text']
    words = []
    for result, word in zip(results[3:], ('bad_path', 'outside_or_symlink', 'not_registered')):
        assert result['isError'] and f'\nreason: {word}\n' in result['content'][0]['text'], (word, result)
        words.append(word)
    assert markers['outside'] not in json.dumps(got), 'the outside marker reached the agent'
    return {'statuses': [s0, s1, s2] + [s for s, _, _ in calls], 'refusals': words,
            'read_text': read['content'][0]['text']}


def kill_worker_when_running(note: Path, killed: dict[str, Any]) -> None:
    """H-17 on the whole machine: once the fixture logged its acknowledgement (the row is up, the agent waits), SIGKILL
    the row's real file worker, the one process of the worker's uid running bin/file-worker."""
    until = time.monotonic() + 60
    while time.monotonic() < until:
        if note.exists() and 'sent=ack' in note.read_text(errors='replace'):
            for proc in Path('/proc').iterdir():
                try:
                    if not proc.name.isdigit() or b'bin/file-worker' not in (proc / 'cmdline').read_bytes() or \
                            not re.search(rf'^Uid:\s+{WORKER_ID}\s', (proc / 'status').read_text(), re.M):
                        continue
                    os.kill(int(proc.name), signal.SIGKILL)
                except OSError:
                    continue
                killed.update(pid=int(proc.name), at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
                return
        time.sleep(0.05)
    killed['error'] = 'no running file worker to kill'
