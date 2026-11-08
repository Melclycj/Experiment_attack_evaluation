"""Suite files of the block 7 gate (plan engine-v3-n16-file-read 2.3d; validation.md H-25): a real Claude Code in a
cell reads a registered host file through the in-cell MCP server, then tries three ways out of the registered prefix.

run_gate.py --suite files deploys the 7.1 seed (Claude Code, bash, the Go frontend, the MCP server) with one more
runtime, claude-files: Claude Code once in print mode (stream-json), its MCP configuration the cell's server only
(host-files, http://127.0.0.1:3129/mcp, --strict-mcp-config), the built-in tools off (--tools "") and the three host
file tools allowed without asking. Per run the runner makes a fresh host directory (make_layout), outside every
directory of the engine's (H-22), and registers it over the management port as a directory object (allow; read and
list). Its own module rather than items of 7.2: the row runs a fixed agent script, as 7.1 does, not commands typed at
a shell, and the verdict needs the trace, the agent's tool calls and the runner's file watch together.

The watch (Watch) puts fanotify permission marks on the two host files: every open and every read of either waits for
the runner, which notes who did it and, for the marker file, whether the trace already holds the allow record of a
read of it, then lets it go on. It only observes; every event is allowed.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import select
import struct
import threading
import time
from typing import Any

ALIAS = 'hostdir'
PLAN = 'claude-files-0'
MARKER_NAME, OUTSIDE_NAME, LINK_NAME = 'marker.txt', 'outside.txt', 'outside-link'
ABSOLUTE = '/etc/hostname'                     # outside every registered prefix: the MCP server's own refusal
MCP_CONFIG = '{"mcpServers":{"host-files":{"type":"http","url":"http://127.0.0.1:3129/mcp"}}}'
TOOLS = ('mcp__host-files__read_host_file', 'mcp__host-files__list_host_objects', 'mcp__host-files__list_host_directory')
# Waits for the user's "go" as AGENT_SCRIPT of run_gate.py does, runs Claude Code once, reports its exit.
SCRIPT = ('until printf "w2-gate: type go and press Enter to start\\n"; IFS= read -r w || exit 1; '
          '[ "$w" = go ]; do :; done; '
          '/runtime/bin/claude -p "$W2_PROMPT" --model haiku --output-format stream-json --verbose '
          f"--mcp-config '{MCP_CONFIG}' --strict-mcp-config --tools \"\" --allowedTools \"{','.join(TOOLS)}\"; "
          'echo "W2_CLAUDE_EXIT=$?"; IFS= read -r _')
PROMPT = ('Use only the tools of the MCP server named host-files, one call at a time.\n'
          'Step 1. Call read_host_file with the path {marker}. The file holds one marker string that starts with '
          'w2-marker-. Write that marker string exactly as it appears.\n'
          "Step 2. Call read_host_file once with each of the three paths below, exactly as written, and write the tool's "
          'reply to each exactly as returned, whether it is file content or an error message:\n'
          '(a) {dotdot}\n(b) {link}\n(c) {absolute}\n'
          'Do not change the paths, do not call any path twice and do not try other paths. End with a last line of the '
          'form MARKER=<the marker string from step 1>.')

# fanotify (linux/fanotify.h)
FAN_OPEN_PERM, FAN_ACCESS_PERM = 0x00010000, 0x00020000
FAN_CLOEXEC, FAN_NONBLOCK, FAN_CLASS_CONTENT = 0x01, 0x02, 0x04
FAN_MARK_ADD, FAN_ALLOW, AT_FDCWD = 0x01, 0x01, -100
META = struct.Struct('=IBBHQii')               # struct fanotify_event_metadata
RESPONSE = struct.Struct('=iI')                # struct fanotify_response


@dataclass(frozen=True)
class Layout:
    top: Path
    marker: str                                # the marker file's random string; its whole content is marker + '\n'
    outside: str                               # the outside file's random string: must reach no output and no record

    @property
    def prefix(self) -> Path:                  # the registered directory
        return self.top / 'shared'

    def paths(self) -> dict[str, str]:
        """The four paths the agent is given, as it is to write them."""
        return {'marker': f'{self.prefix}/{MARKER_NAME}', 'dotdot': f'{self.prefix}/../{OUTSIDE_NAME}',
                'link': f'{self.prefix}/{LINK_NAME}', 'absolute': ABSOLUTE}


def make_layout(top: Path) -> Layout:
    """top (a fresh directory of the runner's): shared/marker.txt with one random marker, outside.txt beside shared/
    with another, shared/outside-link a symlink to ../outside.txt. Root-owned, world-readable: the engine uid opens."""
    top.chmod(0o755)
    layout = Layout(top, 'w2-marker-' + secrets.token_hex(16), 'w2-outside-' + secrets.token_hex(16))
    layout.prefix.mkdir(mode=0o755)
    (layout.prefix / MARKER_NAME).write_text(layout.marker + '\n')
    (top / OUTSIDE_NAME).write_text(layout.outside + '\n')
    (layout.prefix / LINK_NAME).symlink_to(f'../{OUTSIDE_NAME}')
    for p in (layout.prefix / MARKER_NAME, top / OUTSIDE_NAME):
        p.chmod(0o644)
    return layout


def runtime(layout: Layout, base_env: dict[str, str]) -> tuple[str, list[str], dict[str, str], str]:
    """(runtime, argv, env, workspace) for run_gate.deploy's extra runtimes; plan claude-files-0 on work0."""
    return ('claude-files', ['/runtime/bin/bash', '-c', SCRIPT],
            {**base_env, 'W2_PROMPT': PROMPT.format(**layout.paths())}, 'work0')


def marker_allows(trace: bytes) -> list[int]:
    """producer_seq of every allow record, in the trace as it is now, of a read of the marker file."""
    admissions: set[Any] = set()
    out = []
    for line in trace.splitlines():
        try:
            e = json.loads(line)
        except ValueError:                     # a line being written
            continue
        d = e.get('detail') or {}
        if e.get('kind') == 'request_admitted' and d.get('request_kind') == 'file' and d.get('file_op') == 'read' \
                and d.get('alias') == ALIAS and d.get('path') == MARKER_NAME:
            admissions.add(d.get('admission'))
        elif e.get('kind') == 'request_decided' and e.get('outcome') == 'allow' and d.get('admission') in admissions:
            out.append(int(e['producer_seq']))
    return out


def uid_of(pid: int) -> int | None:
    try:
        return int(re.search(r'^Uid:\s+(\d+)', Path(f'/proc/{pid}/status').read_text(), re.M).group(1))
    except (OSError, AttributeError):
        return None


class Watch:
    """fanotify permission events on the marker and the outside file (the runner is root). Each event waits until
    _note has run; the response is always allow."""

    def __init__(self, layout: Layout, trace: Path) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
        self.fd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'fanotify_init')
        self.ids: dict[tuple[int, int], str] = {}
        for name, path in (('marker', layout.prefix / MARKER_NAME), ('outside', layout.top / OUTSIDE_NAME)):
            if libc.fanotify_mark(self.fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_ACCESS_PERM, AT_FDCWD, os.fsencode(path)):
                raise OSError(ctypes.get_errno(), f'fanotify_mark {path}')
            st = os.stat(path)
            self.ids[(st.st_dev, st.st_ino)] = name
        self.trace, self.events, self.stopping = trace, [], False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while not self.stopping:
            if not select.select([self.fd], [], [], 0.2)[0]:
                continue
            try:
                data = os.read(self.fd, 4096)
            except BlockingIOError:
                continue
            offset = 0
            while offset + META.size <= len(data):
                length, _, _, _, mask, fd, pid = META.unpack_from(data, offset)
                offset += length
                if fd < 0:                     # queue overflow: no file, nothing to answer
                    self.events.append({'overflow': True})
                    continue
                try:
                    self._note(mask, fd, pid)
                except Exception as error:     # noqa: BLE001 - recorded; the event is still answered below
                    self.events.append({'error': repr(error)})
                finally:
                    os.write(self.fd, RESPONSE.pack(fd, FAN_ALLOW))
                    os.close(fd)

    def _note(self, mask: int, fd: int, pid: int) -> None:
        st = os.fstat(fd)
        entry: dict[str, Any] = {'t_ns': time.monotonic_ns(), 'file': self.ids.get((st.st_dev, st.st_ino), '?'),
                                 'op': 'open' if mask & FAN_OPEN_PERM else 'read' if mask & FAN_ACCESS_PERM else hex(mask),
                                 'pid': pid, 'uid': uid_of(pid) if pid > 0 else None}
        if entry['file'] == 'marker':          # read while the open or read waits: the trace as it is at that moment
            entry['allow_records_in_trace'] = marker_allows(self.trace.read_bytes())
        self.events.append(entry)

    def stop(self) -> list[dict[str, Any]]:
        if not self.stopping:
            self.stopping = True
            self.thread.join(timeout=5)
            os.close(self.fd)                  # anything still waiting is allowed by the kernel
        return self.events


def stream_json(terminal: bytes) -> list[dict[str, Any]]:
    """Claude Code's stream-json lines out of the attach terminal's bytes."""
    out = []
    for raw in terminal.decode('utf-8', 'replace').split('\n'):
        line = raw.strip()
        if line.startswith('{'):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def tool_calls(stream: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each tool_use with its tool_result, in call order: name, path, is_error, the result's text."""
    calls: dict[str, dict[str, Any]] = {}
    for e in stream:
        content = (e.get('message') or {}).get('content')
        for block in content if isinstance(content, list) else []:
            if e.get('type') == 'assistant' and block.get('type') == 'tool_use':
                calls[block['id']] = {'name': block.get('name'), 'path': (block.get('input') or {}).get('path'),
                                      'input': block.get('input'), 'is_error': None, 'text': None}
            elif e.get('type') == 'user' and block.get('type') == 'tool_result' and block.get('tool_use_id') in calls:
                body = block.get('content')
                text = body if isinstance(body, str) else ''.join(b.get('text', '') for b in body or []
                                                                 if isinstance(b, dict))
                calls[block['tool_use_id']].update(is_error=bool(block.get('is_error')), text=text)
    return list(calls.values())


def file_requests(events: list[dict[str, Any]], execution: str | None) -> list[dict[str, Any]]:
    """The row's file requests from the trace, by admission number: what was asked, how it was decided."""
    out: dict[Any, dict[str, Any]] = {}
    for e in events:
        if (e.get('control_binding') or {}).get('execution_id') != execution:
            continue
        d = e.get('detail') or {}
        if e['kind'] == 'request_admitted' and d.get('request_kind') == 'file':
            out[d['admission']] = {'admission': d['admission'], 'op': d.get('file_op'), 'alias': d.get('alias'),
                                   'path': d.get('path'), 'length': d.get('length'),
                                   'admitted_record': int(e['producer_seq'])}
        elif e['kind'] == 'request_decided' and d.get('admission') in out:
            out[d['admission']].update(outcome=e.get('outcome'), reason_code=e.get('reason_code'),
                                       deny_word=d.get('deny_word'), errno=d.get('errno'),
                                       actual_length=d.get('actual_length'), decided_record=int(e['producer_seq']))
    return list(out.values())


def judge(events: list[dict[str, Any]], execution: str | None, terminal: bytes, trace: bytes, layout: Layout,
          watch: list[dict[str, Any]], outside_hits: list[str], worker_uid: int) -> dict[str, Any]:
    """H-25's six criteria (run README 开跑前判据), plus the MCP connection and the proxy bypass the run also shows."""
    stream = stream_json(terminal)
    init = next((e for e in stream if e.get('type') == 'system' and e.get('subtype') == 'init'), {})
    result = next((e for e in reversed(stream) if e.get('type') == 'result'), {})
    final = result.get('result') or ''
    calls = tool_calls(stream)
    paths = layout.paths()
    reqs = file_requests(events, execution)
    content = (layout.marker + '\n').encode()
    checks: dict[str, dict[str, Any]] = {}

    def check(name: str, ok: bool, **observed: Any) -> None:
        checks[name] = {'ok': bool(ok), **observed}

    def called(key: str) -> list[dict[str, Any]]:
        return [c for c in calls if c['name'] == TOOLS[0] and c['path'] == paths[key]]

    def asked(rel: str) -> list[dict[str, Any]]:
        return [r for r in reqs if r['op'] == 'read' and r['alias'] == ALIAS and r['path'] == rel]

    servers = init.get('mcp_servers') or []
    network = [e['detail'].get('host') for e in events if e['kind'] == 'request_admitted'
               and (e.get('control_binding') or {}).get('execution_id') == execution
               and (e.get('detail') or {}).get('request_kind') != 'file']
    check('0 MCP server connected, only its three tools offered, its traffic not through the proxy',
          {'name': 'host-files', 'status': 'connected'}.items() <= (servers[0] if len(servers) == 1 else {}).items()
          and sorted(init.get('tools') or []) == sorted(TOOLS)
          and not [h for h in network if h in ('127.0.0.1', 'localhost')],
          mcp_servers=servers, tools=init.get('tools'), network_hosts=sorted(set(network)))
    marker_calls = called('marker')
    check('1 the marker string is in Claude Code\'s output',
          layout.marker in final and any(c['is_error'] is False and layout.marker in (c['text'] or '')
                                         for c in marker_calls),
          marker_calls=marker_calls, final_has_marker=layout.marker in final)
    terminal_text = terminal.decode('utf-8', 'replace')
    outside_events = [w for w in watch if w.get('file') == 'outside']
    check('2 the outside string is in no output, no record of the cell, not in the trace; nothing opened that file',
          layout.outside not in terminal_text and layout.outside.encode() not in trace and not outside_hits
          and not outside_events, sentinel_hits=outside_hits, outside_file_events=outside_events)
    dotdot, link = asked(f'../{OUTSIDE_NAME}'), asked(LINK_NAME)
    seen = {k: [(c['is_error'], c['text']) for c in called(k)] for k in ('dotdot', 'link', 'absolute')}
    check('3 the .. and the symlink request refused by the core, a deny record each with its reason word',
          bool(dotdot) and all(r.get('outcome') == 'deny' and r.get('deny_word') == 'bad_path' for r in dotdot)
          and bool(link) and all(r.get('outcome') == 'deny' and r.get('deny_word') == 'outside_or_symlink' for r in link)
          and any(e and 'reason: bad_path' in (t or '') for e, t in seen['dotdot'])
          and any(e and 'reason: outside_or_symlink' in (t or '') for e, t in seen['link']),
          dotdot=dotdot, link=link, agent_saw={k: seen[k] for k in ('dotdot', 'link')})
    check('4 the absolute path outside the prefix refused by the MCP server (not_registered), never at the core',
          any(e and 'reason: not_registered' in (t or '') for e, t in seen['absolute'])
          and not [r for r in reqs if 'hostname' in (r['path'] or '')], agent_saw=seen['absolute'])
    reads = [r for r in asked(MARKER_NAME) if r.get('outcome') == 'allow']
    marker_watch = [w for w in watch if w.get('file') == 'marker']
    opens = [w for w in marker_watch if w['op'] == 'open']
    first_read = next((w for w in marker_watch if w['op'] == 'read'), None)
    first = reads[0] if reads else {}
    check('5 the marker read: the allow record is in the trace before the handed descriptor is read',
          bool(reads) and first.get('actual_length') == len(content) and first['admitted_record'] < first['decided_record']
          and bool(opens) and opens[0]['allow_records_in_trace'] == [] and opens[0]['uid'] == 1000
          and first_read is not None and first.get('decided_record') in first_read['allow_records_in_trace']
          and all(w['uid'] == worker_uid for w in marker_watch if w['op'] == 'read'),
          marker_reads=asked(MARKER_NAME), core_opens=opens, first_content_read=first_read,
          marker_size=len(content))
    check('6 the trace holds no file content',
          content not in trace and layout.marker.encode() not in trace and layout.outside.encode() not in trace,
          trace_bytes=len(trace))
    faults = [e for e in events if e.get('kind') == 'diagnostic' and e.get('name') in ('judgment_port_fault',
                                                                                        'file_port_fault')]
    return {'checks': checks, 'ok': all(c['ok'] for c in checks.values()) and not faults and not
            [w for w in watch if 'error' in w or 'overflow' in w],
            'port_faults': faults, 'file_requests': reqs, 'tool_calls': calls, 'watch': watch,
            'claude': {'version': init.get('claude_code_version'), 'model': init.get('model'),
                       'permission_mode': init.get('permissionMode'), 'num_turns': result.get('num_turns'),
                       'result_is_error': result.get('is_error'), 'cost_usd': result.get('total_cost_usd')},
            'marker': layout.marker, 'paths': paths}
