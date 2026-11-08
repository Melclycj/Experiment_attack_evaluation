"""How the admin client draws what the core sends (agent-rm-model 3.4 审批通道的客户端; build plan 工程项 10; validation.md
A-01). Not in the TCB, but inside 3.7 "决策通道可信": the core guarantees the QUESTION is the canonical form it will
execute, and drawing it faithfully is this module's duty.

Every byte that came from the cell is untrusted. Nothing is executed or rendered: bytes outside printable ASCII become
\\xHH, so a header value or body cannot move the cursor, clear the screen or forge a prompt on the user's terminal; a
backslash is doubled so the escaping cannot be imitated. Long fields are cut with a marker that says how long they
were; the body shows only its first bytes and its total length. A host is shown as the A-label (punycode) the core
matches on, never decoded to Unicode, and flagged when a label is an IDN.
"""
from __future__ import annotations

from dataclasses import dataclass
import os

from connector import canonical as c

FIELD_SHOW = 512           # bytes of one field drawn before the cut marker
BODY_PREVIEW = 512         # bytes of the body drawn in a question
FORM_KEYS_SHOW = 32        # form keys drawn in a question
SHOW_CHUNK = 65536         # pread size when the user asks for the whole body
PLACEMENTS = {1: 'x-api-key', 2: 'authorization (registered word and token)', 3: 'authorization basic (registered user and password)'}
WITHDRAW_REASONS = {1: 'the request was withdrawn by its client', 2: 'the row closed', 3: 'no answer within 300 s: refused'}


def escape(data: bytes) -> str:
    out = []
    for b in data:
        if b == 0x5C:
            out.append('\\\\')
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f'\\x{b:02x}')
    return ''.join(out)


def clip(data: bytes, limit: int = FIELD_SHOW) -> str:
    if len(data) <= limit:
        return escape(data)
    return f'{escape(data[:limit])} …[cut: {len(data)} bytes in total]'


def show_host(host: bytes, full: bool = False) -> str:
    text = escape(host) if full else clip(host)
    if any(label.startswith(b'xn--') for label in host.split(b'.')):
        text += '   [IDN: shown as its punycode A-label]'
    return text


def show_key(kind: int, key: bytes) -> str:
    if kind == 0:
        return 'no entry matched'
    if kind == 3:
        return 'the fallback entry'
    if kind == 2:
        return f'pattern entry *.{clip(key)}'
    return f'exact entry {clip(key)}' if kind == 1 else f'entry of kind {kind} {clip(key)}'


@dataclass
class Question:
    """One QUESTION frame (SPEC §3.4), fields as bytes, plus the body memfd the core passed with it."""

    qid: int
    execution_id: bytes
    workspace_id: bytes
    key_kind: int
    key: bytes
    method: bytes
    scheme: bytes
    host: bytes
    port: int
    path: bytes
    query: bytes
    headers: list[tuple[bytes, bytes]]
    stripped: list[bytes]
    body_kind: bytes
    form_keys: list[bytes]
    body_len: int
    binding: tuple[str, str, int] | None      # (host_port, account, placement) the engine will attach, or none
    # state, methods, prefixes, accounts, approval, named addresses (pdp.entry_fields; K-57)
    cell: tuple[int, list[bytes], list[bytes], list[bytes], int, list[bytes]] | None
    fd: int | None
    # a host file request (H-09): its operation (0 for a network request), alias, relative path, start and length, and
    # the object (the host path the user registered, its type and operations)
    file_op: int = 0
    alias: bytes = b''
    file_path: bytes = b''
    start: int = 0
    length: int = 0
    obj: tuple[bytes, int, int] | None = None

    @classmethod
    def parse(cls, fields: list[bytes], fd: int | None) -> 'Question':
        flat = c.unpack_list(fields[11])
        if len(flat) % 2:
            raise c.Malformed('header list is not name/value pairs')
        u = c.unpack_list(fields[16])
        if len(u) not in (0, 3):
            raise c.Malformed('the credential binding is not host_port, account, placement')
        binding = (u[0].decode('ascii', 'replace'), u[1].decode('utf-8', 'replace'), c.read_uint(u[2], 1)) if u else None
        e = c.unpack_list(fields[17])
        if len(e) not in (0, 6):
            raise c.Malformed('the cell is not state, methods, prefixes, accounts, approval, addresses')
        cell = (c.read_uint(e[0], 1), c.unpack_list(e[1]), c.unpack_list(e[2]), c.unpack_list(e[3]),
                c.read_uint(e[4], 1), c.unpack_list(e[5])) if e else None
        o = c.unpack_list(fields[23])
        if len(o) not in (0, 3):
            raise c.Malformed('the object is not host_path, type, ops')
        return cls(c.read_uint(fields[0], 8), fields[1], fields[2], c.read_uint(fields[3], 1), fields[4], fields[5],
                   fields[6], fields[7], c.read_uint(fields[8], 2), fields[9], fields[10],
                   list(zip(flat[0::2], flat[1::2])), c.unpack_list(fields[12]), fields[13], c.unpack_list(fields[14]),
                   c.read_uint(fields[15], 8), binding, cell, fd, file_op=c.read_uint(fields[18], 1), alias=fields[19],
                   file_path=fields[20], start=c.read_uint(fields[21], 8), length=c.read_uint(fields[22], 8),
                   obj=(o[0], c.read_uint(o[1], 1), c.read_uint(o[2], 1)) if o else None)

    @property
    def host_port(self) -> str:
        return f'{self.host.decode("ascii", "replace")}:{self.port}'

    def body(self, limit: int | None) -> bytes:
        """Read the body from the memfd by position: the fd shares its file offset with the core and the connector,
        so a plain read would move it under them."""
        if self.fd is None:
            return b''
        want = self.body_len if limit is None else min(limit, self.body_len)
        parts, pos = [], 0
        while pos < want:
            chunk = os.pread(self.fd, min(SHOW_CHUNK, want - pos), pos)
            if not chunk:
                break
            parts.append(chunk)
            pos += len(chunk)
        return b''.join(parts)

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def show_cell(cell: tuple[int, list[bytes], list[bytes], list[bytes], int, list[bytes]] | None) -> str:
    """The cell the persistent answers act on (648d60f2 3.2): its whole range as it is now, with the non-global
    addresses it names when it names any (A-01)."""
    if cell is None:
        return '(none)'
    state, methods, prefixes, accounts, approval, addresses = cell
    def items(xs: list[bytes], empty: str) -> str:
        return ','.join(escape(x) for x in xs) if xs else empty
    return (f'{"allow" if state == 1 else "deny"}; methods {items(methods, "any")}; paths {items(prefixes, "any")}; '
            f'accounts {items(accounts, "none")}; {"ask every time" if approval == 2 else "never ask"}'
            + (f'; addresses {items(addresses, "")}' if addresses else ''))


def file_lines(q: Question, cut) -> list[str]:
    """A host file request (H-09): the operation, the object as the user registered it, the relative path and the
    range; no HTTP field and no body."""
    host_path, type_, ops = q.obj or (b'', 0, 0)
    kind = {c.FILE_TYPE_FILE: 'file', c.FILE_TYPE_DIR: 'directory'}.get(type_, f'type {type_}')
    granted = ', '.join(name for bit, name in ((c.FILE_OPS_READ, 'read'), (c.FILE_OPS_LIST, 'list')) if ops & bit)
    state, approval = (q.cell[0], q.cell[4]) if q.cell else (0, 0)
    mode = 'ask every time' if (state, approval) == (1, 2) else 'allow, never ask' if state == 1 else 'deny'
    lines = [f'  host file    {"read" if q.file_op == c.FILE_OP_READ else "list directory"}',
             f'  object       {cut(q.alias)} -> {cut(host_path)} ({kind}; {granted or "none"})',
             f'  mode         {mode}',
             f'  path         {cut(q.file_path) if q.file_path else "(the object itself)"}']
    if q.file_op == c.FILE_OP_READ:
        lines += [f'  start        {q.start}', f'  length       {q.length} bytes']
    else:
        lines.append(f'  first entry  {q.start}')
    return lines


def question_lines(q: Question, full: bool = False) -> list[str]:
    """The question drawn field by field (A-01). ``full`` lifts the cuts and draws the whole body, still escaped."""
    cut = escape if full else clip
    if q.file_op:
        return [f'── question {q.qid} ── row {cut(q.execution_id)} ── workspace {cut(q.workspace_id)} ──'] + \
            file_lines(q, cut)
    lines = [f'── question {q.qid} ── row {cut(q.execution_id)} ── workspace {cut(q.workspace_id)} ──',
             f'  matched      {show_key(q.key_kind, q.key)}',
             f'  cell         {show_cell(q.cell)}',
             f'  method       {cut(q.method)}',
             f'  scheme       {cut(q.scheme)}',
             f'  host         {show_host(q.host, full)}',
             f'  port         {q.port}',
             f'  path         {cut(q.path)}',
             f'  query        {cut(q.query) if q.query else "(none)"}',
             f'  headers      {len(q.headers)}']
    lines += [f'    {cut(n)}: {cut(v)}' for n, v in q.headers]
    if q.stripped:
        lines.append(f'  stripped     {", ".join(cut(s) for s in q.stripped)}   (method-override headers, not sent)')
    if q.binding is not None:
        hp, account, placement = q.binding
        where = PLACEMENTS.get(placement, f'placement {placement}')
        lines.append(f'  credential   account "{escape(account.encode())}" at {escape(hp.encode())}, written into {where}')
    else:
        lines.append('  credential   none attached')
    lines.append(f'  body         {cut(q.body_kind) if q.body_kind else "(no content-type)"}, {q.body_len} bytes')
    if q.form_keys:
        shown = q.form_keys if full else q.form_keys[:FORM_KEYS_SHOW]
        more = '' if len(shown) == len(q.form_keys) else f' …[{len(q.form_keys)} keys in total]'
        lines.append(f'  form keys    {", ".join(cut(k) for k in shown)}{more}')
    if q.body_len:
        data = q.body(None if full else BODY_PREVIEW)
        tail = '' if full or q.body_len <= BODY_PREVIEW else f' …[first {BODY_PREVIEW} of {q.body_len} bytes]'
        lines.append(f'    {escape(data)}{tail}')
    return lines


def reply_lines(verb: int, payload: list[bytes]) -> list[str]:
    """An OK payload drawn by the verb it answers (SPEC §3.4)."""
    def rows(width: int, names: tuple[str, ...]) -> list[str]:
        groups = [payload[i:i + width] for i in range(0, len(payload), width)]
        return [' '.join(f'{n}={escape(v)}' for n, v in zip(names, g)) for g in groups] or ['(none)']
    if verb == c.WS_LIST:
        return rows(4, ('workspace', 'root', 'state', 'entries'))
    if verb == c.ROW_LIST:
        return rows(4, ('execution', 'workspace', 'state', 'uid'))
    if verb == c.WS_CREATE:
        return rows(2, ('workspace', 'mirror'))
    if verb == c.ROW_START:
        return rows(1, ('execution',))
    if verb in (c.ENTRY_PUT, c.ENTRY_DEL, c.OBJ_DEL):
        return rows(1, ('mirror',))
    if verb == c.OBJ_PUT:
        return rows(3, ('mirror', 'device', 'inode'))
    return ['ok']
