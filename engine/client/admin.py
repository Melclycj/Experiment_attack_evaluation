"""The ``admin`` subcommand: the user's side of the management port (agent-rm-model 3.4 审批通道的客户端, 3.7 默认规则;
SPEC-canonical-form.md §3.4 link D; build plan 工程项 10; validation.md A-01, A-02, A-03, A-05).

``admin questions`` watches ``<root>/state/admin.sock`` and asks the user about each QUESTION, one at a time, with one
of four words (648d60f2 3.2; A-02): allow or deny this time, or act on the whole cell the question shows — allow and
stop asking on this cell, or deny on this cell from now on. The persistent answers change only the cell's approval mode
or its state, never its methods, paths or key, so there is no range to fill in. The other verbs are one frame each:
entries, credentials, workspaces, rows.

This window is only ever fed by the management port. It never reads a pty, and the attach subcommand never shows a
question (A-03): bytes the agent writes to its terminal cannot reach the stream the approval prompt is read from.
A credential's truth is read from a file, an environment variable or a no-echo prompt — never from argv, which other
processes can read — and is never printed.
"""
from __future__ import annotations

from enum import Enum
import getpass
import os
from pathlib import Path
import selectors
import sys
from typing import Callable, TextIO

from connector import canonical as c
from engine.admin import ERR_UNKNOWN_QUESTION
from .link import ERR_NAMES, Link
from .render import WITHDRAW_REASONS, Question, escape, question_lines, reply_lines

VERDICTS = {'allow-once': 1, 'allow-always': 2, 'deny-once': 3, 'deny-always': 4}
KEY_KINDS = {'exact': 1, 'pattern': 2, 'fallback': 3}
STATES = {'allow': 1, 'deny': 2}
APPROVALS = {'never': 1, 'always': 2}
# host file objects (validation.md H-01): the type, and the mode as the entry's state and approval mode
OBJECT_TYPES = {'file': c.FILE_TYPE_FILE, 'dir': c.FILE_TYPE_DIR}
OBJECT_MODES = {'allow': (1, 1), 'ask': (1, 2), 'deny': (2, 1)}
# the registered placement and its authorization word (648d60f2 4.3 凭据)
PLACEMENTS = {'api-key': (1, b''), 'bearer': (2, b'Bearer'), 'token': (2, b'token'), 'basic': (3, b'')}


class Step(Enum):
    VERDICT = 'verdict'
    WAITING = 'waiting'          # the ANSWER went out; its OK or ERR has not come back


class Session:
    """The question/answer state machine, free of I/O: frames and input lines in, output lines and frames out."""

    def __init__(self) -> None:
        self.queue: list[Question] = []
        self.step: Step | None = None

    @property
    def current(self) -> Question | None:
        return self.queue[0] if self.queue else None

    def prompt(self) -> str:
        q = self.current
        if q is None or self.step is not Step.VERDICT:
            return ''
        return (f'answer question {q.qid} [allow-once | deny-once | allow-always (allow, never ask on this cell again) | '
                f'deny-always (deny on this cell from now on) | show]: ')

    # ---- frames from the core ----
    def on_frame(self, kind: int, fields: list[bytes], fd: int | None) -> list[str]:
        if kind == c.QUESTION:
            q = Question.parse(fields, fd)
            if any(x.qid == q.qid for x in self.queue):
                q.close()
                return []
            self.queue.append(q)
            if len(self.queue) == 1:
                return self._begin()
            return [f'(question {q.qid} queued; {len(self.queue) - 1} waiting behind the open one)']
        if kind == c.QUESTION_WITHDRAWN:
            qid, reason = c.read_uint(fields[0], 8), c.read_uint(fields[1], 1)
            note = f'question {qid} withdrawn: {WITHDRAW_REASONS.get(reason, f"reason {reason}")}'
            q = self.current
            if q is not None and q.qid == qid:
                if self.step is Step.WAITING:          # the core will answer the ANSWER with an error; advance then
                    return [note]
                return [note] + self._advance()
            for x in self.queue:
                if x.qid == qid:
                    x.close()
                    self.queue.remove(x)
                    break
            return [note]
        verb = c.read_uint(fields[0], 1)
        if verb == c.ANSWER and self.step is Step.WAITING and self.current is not None:
            q = self.current
            if kind == c.OK:
                note = c.unpack_list(fields[1])
                tail = ('; the cell is changed' if note == [b'persisted'] else
                        '; the cell is changed for this run, but not safely on disk: a restart may lose it'
                        if note == [b'unpersisted'] else
                        '; the cell change did not take effect: it counted as this time only' if note == [b'not_applied'] else '')
                return [f'question {q.qid} answered{tail}'] + self._advance()
            code, detail = c.read_uint(fields[1], 1), fields[2]
            if code == ERR_UNKNOWN_QUESTION or detail == b'superseded':
                return [f'question {q.qid} is gone: {escape(detail)}'] + self._advance()
            self.step = Step.VERDICT
            return [f'the core refused the answer ({ERR_NAMES.get(code, code)}: {escape(detail)}); question {q.qid} is still open']
        return [f'unexpected reply {kind:#x} to verb {verb:#x}']

    def _begin(self) -> list[str]:
        q = self.current
        if q is None:
            self.step = None
            return ['(no open question; waiting)']
        self.step = Step.VERDICT
        return question_lines(q)

    def _advance(self) -> list[str]:
        q = self.queue.pop(0)
        q.close()
        return self._begin()

    # ---- lines from the user ----
    def on_line(self, line: str) -> tuple[list[str], bytes | None]:
        q, text = self.current, line.strip()
        if q is None or self.step is None:
            return ['(no open question)'], None
        if self.step is Step.WAITING:
            return ['(waiting for the core to take the answer)'], None
        if text == 'show':
            return question_lines(q, full=True), None
        verdict = VERDICTS.get(text)
        if verdict is None:
            return ['type one of the four words, or show'], None
        self.step = Step.WAITING
        return [], c.pack_frame(c.ANSWER, [c.u64(q.qid), c.u8(verdict)])

    def close(self) -> None:
        for q in self.queue:
            q.close()
        self.queue.clear()


def watch(link: Link, stdin: int, out: TextIO) -> int:
    """``admin questions``: the interactive loop over the management port and the user's line input."""
    session, pending = Session(), b''

    def emit(lines: list[str]) -> None:
        for line in lines:
            out.write(line + '\n')
        out.write(session.prompt())
        out.flush()

    sel = selectors.DefaultSelector()
    sel.register(link.sock, selectors.EVENT_READ, 'core')
    sel.register(stdin, selectors.EVENT_READ, 'user')
    emit(['watching for questions; end of input (Ctrl-D) quits, open questions then time out at the core'])
    try:
        while True:
            for key, _ in sel.select():
                if key.data == 'core':
                    frames = link.receive()
                    if frames is None:
                        emit(['the engine closed the management port'])
                        return 1
                    for kind, fields, fd in frames:
                        emit(session.on_frame(kind, fields, fd))
                    continue
                data = os.read(stdin, 4096)
                if not data:
                    out.write('\n')
                    return 0
                pending += data
                while b'\n' in pending:
                    raw, pending = pending.split(b'\n', 1)
                    lines, frame = session.on_line(raw.decode('utf-8', 'replace'))
                    if frame is not None:
                        link.send(frame)
                    emit(lines)
    finally:
        session.close()
        sel.close()


def read_secret(path: str | None, env: str | None, prompt: str, ask: Callable[[str], str] = getpass.getpass) -> bytes:
    """A truth value from a file (one trailing newline dropped), an environment variable, or a no-echo prompt."""
    if path is not None:
        data = Path(path).read_bytes()
        return data[:-2] if data.endswith(b'\r\n') else data[:-1] if data.endswith(b'\n') else data
    if env is not None:
        try:
            return os.environb[env.encode()]
        except KeyError:
            raise SystemExit(f'environment variable {env} is not set') from None
    if not sys.stdin.isatty():
        raise SystemExit('no truth given: use a --*-file or --*-env option, or run on a terminal to be prompted')
    try:
        return ask(prompt).encode('latin-1')
    except UnicodeEncodeError:
        raise SystemExit('the truth must be latin-1 text') from None


def read_policy_context(path: str | None) -> bytes:
    """The row's opaque policy context (agent-rm-model 3.1; A-11): the bytes of a file, never of argv, at most 16 KiB;
    none given is empty."""
    if path is None:
        return b''
    with open(path, 'rb') as f:
        data = f.read(c.LIMITS.policy_context + 1)
    if len(data) > c.LIMITS.policy_context:
        raise SystemExit(f'the policy context in {path} is larger than {c.LIMITS.policy_context} bytes')
    return data


def unfolded_absolute(path: str) -> str:
    """A host path for OBJ_PUT (H-02): an absolute one as typed; a relative one with only the working directory and a
    / put in front. No segment is folded (no abspath or normpath): with a symlink before a "..", folding the text would
    name another directory than the kernel resolves, so the core alone resolves it, following symlinks as the engine
    uid."""
    return path if path.startswith('/') else os.getcwd() + '/' + path


def verb_frame(args) -> tuple[int, list[bytes]]:
    """The one frame a non-interactive admin verb sends."""
    e = lambda s: s.encode()            # noqa: E731
    lst = lambda xs: c.pack_list([e(x) for x in xs])    # noqa: E731
    if args.area == 'entry' and args.action == 'put':
        return c.ENTRY_PUT, [e(args.workspace), c.u8(KEY_KINDS[args.kind]), e(args.key), c.u8(STATES[args.state]),
                             lst(args.method), lst(args.prefix), lst(args.account), c.u8(APPROVALS[args.approval]),
                             lst(args.address)]       # as written, in order: the core checks and normalises (K-57)
    if args.area == 'entry':
        return c.ENTRY_DEL, [e(args.workspace), c.u8(KEY_KINDS[args.kind]), e(args.key)]
    if args.area == 'object' and args.action == 'put':
        state, approval = OBJECT_MODES[args.mode]
        ops = c.FILE_OPS_READ | (c.FILE_OPS_LIST if args.list else 0)
        return c.OBJ_PUT, [e(args.workspace), e(args.alias), os.fsencode(unfolded_absolute(args.path)),
                           c.u8(OBJECT_TYPES[args.type]), c.u8(ops), c.u8(state), c.u8(approval)]
    if args.area == 'object':
        return c.OBJ_DEL, [e(args.workspace), e(args.alias)]
    if args.area == 'cred' and args.action == 'put':
        truth_a = read_secret(args.truth_file, args.truth_env,
                              'basic user part: ' if args.placement == 'basic' else 'truth: ')
        truth_b = read_secret(args.truth_b_file, args.truth_b_env, 'basic password part: ') \
            if args.placement == 'basic' else b''
        placement, word = PLACEMENTS[args.placement]
        return c.CRED_PUT, [e(args.host_port), e(args.account), c.u8(placement), word,
                            truth_a, truth_b, e(args.token_endpoint), e(args.registration_endpoint),
                            e(args.device_authorization_endpoint)]
    if args.area == 'cred':
        return c.CRED_DEL, [e(args.host_port), e(args.account)]
    if args.area == 'ws':
        if args.action == 'create':
            return c.WS_CREATE, [e(args.root_path)]
        return (c.WS_LIST, []) if args.action == 'list' else (c.WS_DELETE, [e(args.workspace)])
    if args.action == 'start':
        if any('=' not in item for item in args.account):
            raise SystemExit('--account takes host:port=account')
        pairs = [part for item in args.account for part in item.partition('=')[::2]]
        return c.ROW_START, [e(args.workspace), e(args.plan), lst(pairs), read_policy_context(args.policy_context)]
    return (c.ROW_LIST, []) if args.action == 'list' else (c.ROW_STOP, [e(args.execution)])


def add_parser(sub) -> None:
    p = sub.add_parser('admin', help='answer questions and manage entries, credentials, workspaces and rows')
    areas = p.add_subparsers(dest='area', required=True)
    areas.add_parser('questions', help='watch for questions and answer them')
    entry = areas.add_parser('entry').add_subparsers(dest='action', required=True)
    put = entry.add_parser('put', help='add or replace an entry (one entry per key)')
    put.add_argument('workspace')
    put.add_argument('kind', choices=KEY_KINDS)
    put.add_argument('state', choices=STATES)
    put.add_argument('key', nargs='?', default='', help='host:port, *.suffix:port, or nothing for the fallback entry')
    put.add_argument('--method', action='append', default=[], help='repeatable; none = any method')
    put.add_argument('--prefix', action='append', default=[], help='repeatable; none = any path')
    put.add_argument('--account', action='append', default=[], help='repeatable; exact allow entries only (条款 5)')
    put.add_argument('--approval', choices=APPROVALS, default='never')
    put.add_argument('--address', action='append', default=[],
                     help='repeatable; a non-global IP address or prefix (CIDR) this cell names; exact allow entries only')
    rm = entry.add_parser('del')
    rm.add_argument('workspace')
    rm.add_argument('kind', choices=KEY_KINDS)
    rm.add_argument('key', nargs='?', default='')
    obj = areas.add_parser('object', help='host files the rows of a workspace may read through the engine').add_subparsers(
        dest='action', required=True)
    oput = obj.add_parser('put', help='register or replace a host file or directory under an alias')
    oput.add_argument('workspace')
    oput.add_argument('alias', help='1-64 letters, digits, - or _; unique in the workspace')
    oput.add_argument('path', help='the host path; the engine resolves it, following symlinks')
    oput.add_argument('--type', choices=OBJECT_TYPES, required=True)
    oput.add_argument('--list', action='store_true', help='a directory may also be listed (read is always given)')
    oput.add_argument('--mode', choices=OBJECT_MODES, default='allow', help='allow, ask every time, or deny')
    odel = obj.add_parser('del')
    odel.add_argument('workspace')
    odel.add_argument('alias')
    cred = areas.add_parser('cred').add_subparsers(dest='action', required=True)
    cput = cred.add_parser('put', help='register a credential record; the truth never comes from the command line')
    cput.add_argument('host_port')
    cput.add_argument('account')
    cput.add_argument('placement', choices=PLACEMENTS,
                      help='x-api-key; authorization with the word Bearer or token; authorization Basic')
    for name in ('truth', 'truth-b'):
        cput.add_argument(f'--{name}-file')
        cput.add_argument(f'--{name}-env')
    for name in ('token-endpoint', 'registration-endpoint', 'device-authorization-endpoint'):
        cput.add_argument(f'--{name}', default='', help='OAuth account: refused as a destination (条款 10)')
    cdel = cred.add_parser('del')
    cdel.add_argument('host_port')
    cdel.add_argument('account')
    ws = areas.add_parser('ws').add_subparsers(dest='action', required=True)
    ws.add_parser('create').add_argument('root_path')
    ws.add_parser('list')
    ws.add_parser('delete').add_argument('workspace')
    row = areas.add_parser('row').add_subparsers(dest='action', required=True)
    row.add_parser('list')
    start = row.add_parser('start')
    start.add_argument('workspace')
    start.add_argument('plan')
    start.add_argument('--account', action='append', default=[], metavar='HOST:PORT=ACCOUNT',
                       help='repeatable: the one account this execution uses at that destination (3.1)')
    start.add_argument('--policy-context', metavar='FILE',
                       help="a file of at most 16 KiB of opaque bytes the engine hands to the PDP with this row's requests")
    row.add_parser('stop').add_argument('execution')


def run(args) -> int:
    path = Path(args.root) / 'state' / 'admin.sock'
    frame = None if args.area == 'questions' else verb_frame(args)      # read any truth before connecting
    try:
        link = Link(path)
    except OSError as e:
        print(f'cannot reach the management port {path}: {e.strerror}', file=sys.stderr)
        return 2
    try:
        if frame is None:
            return watch(link, sys.stdin.fileno(), sys.stdout)
        kind, reply = link.call(*frame)
    except (ConnectionError, c.Malformed) as e:
        print(f'management port: {e}', file=sys.stderr)
        return 2
    finally:
        link.close()
    if kind == c.OK:
        print('\n'.join(reply_lines(frame[0], c.unpack_list(reply[1]))))
        return 0
    code = c.read_uint(reply[1], 1)
    print(f'refused ({ERR_NAMES.get(code, code)}): {escape(reply[2])}', file=sys.stderr)
    return 1
