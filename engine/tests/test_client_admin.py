"""The admin client (client/admin.py, client/render.py; validation.md A-01, A-02, A-03, A-05; SPEC §3.4): how a question
is drawn, the four answers (648d60f2 3.2: the persistent two act on the whole cell shown), and the verbs end to end
against the real management port (engine/admin.py over an AF_UNIX socket, the core loop pumped by the test or by a
thread)."""
from __future__ import annotations

import ast
import io
import os
from pathlib import Path
import threading
import time
from typing import Iterator

import pytest

from client import admin as cli
from client.main import main as client_main
from client.render import BODY_PREVIEW, FIELD_SHOW, Question, escape, question_lines
from connector import canonical as c
from engine.workspaces import Approval, EntryState, KeyKind, make_entry
from test_admin import AdminHarness, entry_put
from test_hook import judge_frame, memfd, recv_frame, send

ENGINE = Path(__file__).resolve().parents[1]


def cell_field(cell: tuple) -> bytes:
    """A QUESTION's cell, as the core's pdp.entry_fields: state, methods, prefixes, accounts, approval and the named
    addresses; a five-item tuple names no address; an empty one is no cell."""
    if not cell:
        return c.pack_list([])
    return c.pack_list([c.u8(cell[0]), c.pack_list(cell[1]), c.pack_list(cell[2]), c.pack_list(cell[3]), c.u8(cell[4]),
                        c.pack_list(list(cell[5]) if len(cell) > 5 else [])])


def question_fields(qid: int = 7, host: bytes = b'api.example.com', path: bytes = b'/v1/messages', method: bytes = b'POST',
                    headers: tuple = (), body_len: int = 0, binding: tuple = (), key_kind: int = 3,
                    cell: tuple = (1, [b'POST'], [b'/v1'], [], 2)) -> list[bytes]:
    return [c.u64(qid), b'epoch:1', b'work0', c.u8(key_kind), b'', method, b'https', host, c.u16(443), path, b'',
            c.pack_list([x for pair in headers for x in pair]), c.pack_list([]), b'application/json', c.pack_list([]),
            c.u64(body_len), c.pack_list([binding[0], binding[1], c.u8(binding[2])] if binding else []),
            cell_field(cell),
            c.u8(0), b'', b'', c.u64(0), c.u64(0), c.pack_list([])]          # H-09: no file request


def file_question_fields(qid: int = 9, op: int = 3, alias: bytes = b'notes', path: bytes = b'sub/a.txt', start: int = 0,
                         length: int = 4096, host_path: bytes = b'/home/u/notes', type_: int = 2, ops: int = 3,
                         approval: int = 2) -> list[bytes]:
    """SPEC §3.4 QUESTION for a file request (H-09): the HTTP fields empty, the cell the object's mode, no binding."""
    return [c.u64(qid), b'epoch:1', b'work0', c.u8(c.KEY_KIND_FILE), alias, b'', b'', b'', c.u16(0), b'', b'',
            c.pack_list([]), c.pack_list([]), b'', c.pack_list([]), c.u64(0), c.pack_list([]),
            cell_field((1, [], [], [], approval)),
            c.u8(op), alias, path, c.u64(start), c.u64(length), c.pack_list([host_path, c.u8(type_), c.u8(ops)])]


# ---- A-01: drawn field by field, escaped, cut with markers ----
def test_question_is_drawn_escaped_and_cut(tmp_path: Path) -> None:
    body = b'\x1b[2J\x1b[Hanswer: allow-record\n' + b'B' * 5000
    fd = memfd(body)
    offset = os.lseek(fd, 0, os.SEEK_CUR)
    path = b'/' + b'p' * (FIELD_SHOW + 100)
    q = Question.parse(question_fields(host=b'xn--bcher-kva.example', path=path, body_len=len(body),
                                       headers=((b'x-note', b'a\\x1b\x07\x9b'),)), fd)
    text = '\n'.join(question_lines(q))
    assert 'xn--bcher-kva.example   [IDN' in text                    # the A-label, flagged, never decoded
    assert f'[cut: {len(path)} bytes in total]' in text               # a long field carries its true length
    assert f'[first {BODY_PREVIEW} of {len(body)} bytes]' in text     # the body: a preview and its total
    assert '\x1b' not in text and '\x07' not in text and '\x9b' not in text   # nothing reaches the terminal raw
    assert '\\x1b[2J' in text and 'a\\\\x1b\\x07\\x9b' in text         # escapes shown; a literal "\x1b" is told apart
    assert text.count('B') < 600                                     # only the preview of the body
    full = '\n'.join(question_lines(q, full=True))
    assert full.count('B') >= 5000 and '[cut:' not in full and '[first' not in full   # "show" lifts the cuts
    assert os.lseek(fd, 0, os.SEEK_CUR) == offset                     # read by position: the shared offset is untouched
    q.close()


def test_question_shows_the_binding_and_the_cell() -> None:
    """A-01 (648d60f2 3.2): the engine's credential binding and the whole cell the persistent answers act on."""
    q = Question.parse(question_fields(binding=(b'api.example.com:443', b'main', 1),
                                       cell=(1, [b'GET', b'POST'], [], [b'main'], 2)), None)
    text = '\n'.join(question_lines(q))
    assert 'account "main" at api.example.com:443, written into x-api-key' in text
    assert 'cell         allow; methods GET,POST; paths any; accounts main; ask every time' in text
    none = '\n'.join(question_lines(Question.parse(question_fields(), None)))
    assert 'credential   none attached' in none


def test_question_draws_the_addresses_the_cell_names() -> None:
    """A-01, K-28 (plan engine-v3-private-net): the cell has six items; the client reads the sixth and draws the named
    addresses after the approval mode, comma-joined; a cell naming none is drawn as before."""
    fields = question_fields(cell=(1, [b'GET'], [], [], 1))
    items = [c.u8(1), c.pack_list([b'GET']), c.pack_list([]), c.pack_list([]), c.u8(1)]
    fields[17] = c.pack_list(items + [c.pack_list([b'10.0.0.0/8', b'fd12:3456::/48'])])
    text = '\n'.join(question_lines(Question.parse(fields, None)))
    assert 'cell         allow; methods GET; paths any; accounts none; never ask; addresses 10.0.0.0/8,fd12:3456::/48' \
        in text
    fields[17] = c.pack_list(items + [c.pack_list([])])
    assert '  cell         allow; methods GET; paths any; accounts none; never ask' in \
        question_lines(Question.parse(fields, None))


# ---- A-02: four words, each one frame of the question id and the verdict ----
def test_four_words_each_send_one_answer_at_once() -> None:
    s = cli.Session()
    s.on_frame(c.QUESTION, question_fields(qid=1), None)
    for line in ('allow', 'yes', 'ALLOW-ONCE', 'allow-record'):           # not one of the four words: nothing is sent
        assert s.on_line(line) == (['type one of the four words, or show'], None)
    assert 'allow-always' in s.prompt() and 'this cell' in s.prompt()
    for word, verdict in (('allow-once', 1), ('allow-always', 2), ('deny-once', 3), ('deny-always', 4)):
        s = cli.Session()
        s.on_frame(c.QUESTION, question_fields(qid=5), None)
        _, frame = s.on_line(word)
        assert c.unpack_payload(c.ANSWER, frame[5:]) == [c.u64(5), c.u8(verdict)]
        assert s.on_line('deny-once') == (['(waiting for the core to take the answer)'], None)   # one answer in flight


def test_replies_advance_and_say_whether_the_cell_change_held() -> None:
    s = cli.Session()
    s.on_frame(c.QUESTION, question_fields(qid=1), None)
    s.on_frame(c.QUESTION, question_fields(qid=2), None)
    s.on_line('allow-always')
    lines = s.on_frame(c.OK, [c.u8(c.ANSWER), c.pack_list([b'not_applied'])], None)
    assert 'this time only' in lines[0] and s.current.qid == 2            # the next question opens
    s.on_line('deny-always')
    lines = s.on_frame(c.OK, [c.u8(c.ANSWER), c.pack_list([b'persisted'])], None)
    assert lines[0] == 'question 2 answered; the cell is changed' and s.current is None
    s.on_frame(c.QUESTION, question_fields(qid=3), None)
    s.on_line('allow-always')
    lines = s.on_frame(c.OK, [c.u8(c.ANSWER), c.pack_list([b'unpersisted'])], None)
    assert 'changed for this run' in lines[0] and 'this time only' not in lines[0]   # in effect, not durable


def test_withdrawal_and_refusal_while_answering() -> None:
    s = cli.Session()
    s.on_frame(c.QUESTION, question_fields(qid=1), None)
    lines = s.on_frame(c.QUESTION_WITHDRAWN, [c.u64(1), c.u8(1)], None)
    assert 'withdrawn' in lines[0] and s.current is None and s.on_line('allow-once') == (['(no open question)'], None)
    s.on_frame(c.QUESTION, question_fields(qid=2), None)
    s.on_line('allow-once')
    lines = s.on_frame(c.ERR, [c.u8(c.ANSWER), c.u8(3), b'unknown_verdict'], None)
    assert 'still open' in lines[0] and s.step is cli.Step.VERDICT and s.current.qid == 2   # refused: ask again
    s.on_line('allow-once')
    lines = s.on_frame(c.ERR, [c.u8(c.ANSWER), c.u8(3), b'superseded'], None)
    assert 'gone' in lines[0] and s.current is None                  # the cell changed meanwhile: the answer was void


# ---- end to end against the real management port ----
@pytest.fixture
def a(native, tmp_path: Path) -> Iterator[AdminHarness]:
    harness = AdminHarness(tmp_path, native)
    yield harness
    harness.close()


def test_allow_always_answered_end_to_end(a: AdminHarness) -> None:
    link = cli.Link(a.path)
    a.pump()
    kind, _ = a.call(link.sock, c.CRED_PUT, [b'api.github.com:443', b'alice', c.u8(1), b'', b'sk-truth', b'',
                                            b'', b'', b''])
    assert kind == c.OK
    kind, _ = a.call(link.sock, c.ENTRY_PUT, entry_put(b'work0', c.u8(1), b'api.github.com:443', c.u8(1),
                                                       c.pack_list([b'POST']), c.pack_list([]), c.pack_list([b'alice']),
                                                       c.u8(2), c.pack_list([])))     # ask every time
    assert kind == c.OK
    ex, conn = a.hooks.row()
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', path=b'/repos/a/issues', headers=((b'x-api-key', b'PH-KEY'),),
                           body=b'{"t":1}'), memfd(b'{"t":1}'))
    a.pump()
    s = cli.Session()
    lines = [x for f in link.receive() for x in s.on_frame(*f)]
    assert any('{"t":1}' in x for x in lines) and any('account "alice"' in x for x in lines)
    assert any('cell         allow; methods POST; paths any; accounts alice; ask every time' in x for x in lines)
    _, frame = s.on_line('allow-always')
    link.send(frame)
    a.pump()
    assert recv_frame(conn)[0] == c.ALLOW                             # the request went on with alice's truth
    assert s.on_frame(*link.receive()[0])[0] == 'question 1 answered; the cell is changed'
    entry = a.hooks.tables.tables['work0'].entries[(KeyKind.EXACT, 'api.github.com:443')]
    assert (entry.state, entry.methods, entry.prefixes, entry.accounts, entry.approval) == \
        (EntryState.ALLOW, {'POST'}, (), {'alice'}, Approval.NEVER)     # the whole cell, only its approval mode
    link.close()


def test_verbs_through_the_command_line(a: AdminHarness, tmp_path: Path, capsys, monkeypatch) -> None:
    """The command line as the user types it, against the port served by a thread (A-05: the three endpoints)."""
    stop = threading.Event()
    server = threading.Thread(target=lambda: [a.hooks.loop.run_once(0.01) for _ in iter(stop.is_set, True)])
    server.start()
    try:
        truth = tmp_path / 'truth'
        truth.write_bytes(b'ghp_truth\n')                             # one trailing newline is dropped
        root = ['--root', str(tmp_path)]
        assert client_main(root + ['admin', 'cred', 'put', 'api.github.com:443', 'alice', 'bearer',
                                   '--truth-file', str(truth),
                                   '--token-endpoint', 'https://github.com/login/oauth/access_token',
                                   '--registration-endpoint', 'https://github.com/register',
                                   '--device-authorization-endpoint', 'https://github.com/login/device/code']) == 0
        monkeypatch.setenv('BASIC_USER', 'u')
        monkeypatch.setenv('BASIC_PASS', 'p')
        assert client_main(root + ['admin', 'cred', 'put', 'git.example.com:443', 'bob', 'basic',
                                   '--truth-env', 'BASIC_USER', '--truth-b-env', 'BASIC_PASS']) == 0
        assert client_main(root + ['admin', 'entry', 'put', 'work0', 'exact', 'allow', 'api.github.com:443',
                                   '--method', 'GET', '--prefix', '/repos', '--account', 'alice']) == 0
        assert client_main(root + ['admin', 'entry', 'put', 'work0', 'pattern', 'allow', '*.github.io:443',
                                   '--account', 'alice']) == 1        # 条款 5: refused at registration
        assert client_main(root + ['admin', 'entry', 'put', 'work0', 'fallback', 'deny']) == 0
        assert client_main(root + ['admin', 'ws', 'list']) == 0
        assert client_main(root + ['admin', 'row', 'start', 'work0', 'observe-0', '--account', 'api.github.com:443=alice']) == 0
        with pytest.raises(SystemExit):
            client_main(root + ['admin', 'row', 'start', 'work0', 'observe-0', '--account', 'api.github.com:443'])
        context = tmp_path / 'context'                                # A-11: the policy context comes from a file
        context.write_bytes(b'\x00opaque\n')
        assert client_main(root + ['admin', 'row', 'start', 'work0', 'observe-0', '--account', 'api.github.com:443=alice',
                                   '--policy-context', str(context)]) == 0
        context.write_bytes(b'x' * (16 * 1024 + 1))
        with pytest.raises(SystemExit):                               # over 16 KiB: refused before anything is sent
            client_main(root + ['admin', 'row', 'start', 'work0', 'observe-0', '--policy-context', str(context)])
        assert client_main(root + ['admin', 'row', 'stop', 'nope']) == 1
    finally:
        stop.set()
        server.join(5)
    out, err = capsys.readouterr()
    assert 'workspace=work0' in out and 'entries=2' in out and 'refused' in err
    assert 'ghp_truth' not in out + err
    record = a.hooks.credentials.records[('api.github.com:443', 'alice')]
    assert len(record.endpoints) == 3 and len(a.hooks.credentials.endpoints_of({(record.host_port, record.account)})) == 3     # A-05
    assert a.hooks.credentials.read_truths('api.github.com:443', 'alice') == (bytearray(b'ghp_truth'), bytearray())
    assert a.hooks.credentials.read_truths('git.example.com:443', 'bob') == (bytearray(b'u'), bytearray(b'p'))
    assert a.hooks.credentials.records[('api.github.com:443', 'alice')].word == b'Bearer'   # the bearer choice's word
    assert a.hooks.tables.tables['work0'].entries[(KeyKind.FALLBACK, '')].state is EntryState.DENY
    assert a.lifecycle.accounts == [{'api.github.com:443': 'alice'}] * 2           # K-44: the account chosen at start
    assert a.lifecycle.contexts == [b'', b'\x00opaque\n']                           # A-11, K-56: the file's bytes as given


def admin_args(argv: list[str]):
    import argparse
    parser = argparse.ArgumentParser(prog='engine-client')
    cli.add_parser(parser.add_subparsers(dest='command', required=True))
    return parser.parse_args(argv)


def test_entry_put_sends_each_address_as_written_in_order() -> None:
    """K-57 (plan engine-v3-private-net): ``entry put --address ITEM`` is repeatable; ENTRY_PUT's 9th field carries
    the items in the order written, as written (the core checks and normalises them); none given is an empty list."""
    args = admin_args(['admin', 'entry', 'put', 'work0', 'exact', 'allow', 'gitlab.corp:443', '--method', 'GET',
                       '--address', 'fd12:3456::/48', '--address', '10.0.0.5', '--address', 'FD12::1'])
    kind, fields = cli.verb_frame(args)
    assert kind == c.ENTRY_PUT and len(fields) == 9
    assert c.unpack_list(fields[8]) == [b'fd12:3456::/48', b'10.0.0.5', b'FD12::1']
    assert c.unpack_payload(c.ENTRY_PUT, c.pack_frame(kind, fields)[5:]) == fields
    kind, fields = cli.verb_frame(admin_args(['admin', 'entry', 'put', 'work0', 'exact', 'allow', 'gitlab.corp:443']))
    assert len(fields) == 9 and c.unpack_list(fields[8]) == []


def test_named_addresses_through_the_command_line(a: AdminHarness, tmp_path: Path, capsys) -> None:
    """K-57 end to end: the core stores what the user named as canonical prefixes, and refuses an entry with a host
    name in the field, saying so."""
    stop = threading.Event()
    server = threading.Thread(target=lambda: [a.hooks.loop.run_once(0.01) for _ in iter(stop.is_set, True)])
    server.start()
    try:
        root = ['--root', str(tmp_path)]
        assert client_main(root + ['admin', 'entry', 'put', 'work0', 'exact', 'allow', 'gitlab.corp:443',
                                   '--address', '10.0.0.5', '--address', '10.0.0.0/8']) == 0
        assert client_main(root + ['admin', 'entry', 'put', 'work0', 'exact', 'allow', 'wiki.corp:443',
                                   '--address', 'wiki.corp']) == 1
    finally:
        stop.set()
        server.join(5)
    _, err = capsys.readouterr()
    assert 'refused' in err
    entries = a.hooks.tables.tables['work0'].entries
    assert entries[(KeyKind.EXACT, 'gitlab.corp:443')].addresses == ('10.0.0.0/8', '10.0.0.5/32')
    assert (KeyKind.EXACT, 'wiki.corp:443') not in entries


def test_truth_never_comes_from_argv_and_watch_reads_lines(a: AdminHarness, monkeypatch) -> None:
    parser_src = (ENGINE / 'client' / 'admin.py').read_text()
    assert "add_argument('truth'" not in parser_src and "add_argument('--truth'," not in parser_src
    monkeypatch.setattr('sys.stdin', io.StringIO(''))
    with pytest.raises(SystemExit):
        cli.read_secret(None, None, 'truth: ')                        # no terminal and no source: refuse, never guess
    # watch(): a question arrives, the user types the four words through a pipe; end of input quits
    link = cli.Link(a.path)
    a.pump()
    a.hooks.tables.put('work0', make_entry(KeyKind.EXACT, 'api.github.com:443', EntryState.ALLOW, ['POST'], [], [],
                                           Approval.ALWAYS))
    ex, conn = a.hooks.row()
    send(conn, judge_frame(1, ex.lease.uid, method=b'POST', path=b'/x'), memfd(b''))
    a.pump()
    r, w = os.pipe()
    out, result = io.StringIO(), []
    user = threading.Thread(target=lambda: result.append(cli.watch(link, r, out)))
    user.start()
    deadline = time.monotonic() + 5
    while 'answer question 1' not in out.getvalue() and time.monotonic() < deadline:
        time.sleep(0.02)
    os.write(w, b'deny-once\n')                                       # typed only once the question is on screen
    os.close(w)
    user.join(5)
    assert result == [0]
    a.pump()
    assert recv_frame(conn)[0] == c.DENY and 'answer question 1' in out.getvalue()
    os.close(r)
    link.close()


def test_a_file_question_is_drawn_escaped_with_its_object() -> None:
    """H-09 / A-01: a file request's question names the operation, the object (alias, the host path the user
    registered, its type and operations), the relative path, the start and the length; every byte is escaped."""
    q = Question.parse(file_question_fields(path=b'sub/\x1b[2Jcaf\xe9', host_path=b'/home/u/no\x07tes', start=7,
                                            length=100), None)
    text = '\n'.join(question_lines(q))
    assert 'host file    read' in text and 'object       notes -> /home/u/no\\x07tes (directory; read, list)' in text
    assert 'path         sub/\\x1b[2Jcaf\\xe9' in text and 'start        7' in text and 'length       100 bytes' in text
    assert 'mode         ask every time' in text and '\x1b' not in text and '\x07' not in text
    assert 'method' not in text and 'credential' not in text                 # no HTTP lines for a file request
    whole = '\n'.join(question_lines(Question.parse(file_question_fields(op=2, path=b'', type_=2), None)))
    assert 'host file    list directory' in whole and 'path         (the object itself)' in whole
    assert 'first entry  0' in whole and 'length' not in whole
    one = '\n'.join(question_lines(Question.parse(file_question_fields(path=b'', type_=1, ops=1), None)))
    assert '(file; read)' in one
    s = cli.Session()
    s.on_frame(c.QUESTION, file_question_fields(qid=4), None)
    _, frame = s.on_line('deny-always')
    assert c.unpack_payload(c.ANSWER, frame[5:]) == [c.u64(4), c.u8(4)]


def test_the_link_pairs_descriptors_only_with_network_questions(tmp_path: Path) -> None:
    """A file QUESTION carries no memfd: one read holding a file question and then a network question's first byte
    (with its descriptor) gives the descriptor to the network question."""
    import socket as so
    from client.link import Link
    server = so.socket(so.AF_UNIX, so.SOCK_STREAM)
    server.bind(str(tmp_path / 's'))
    server.listen(1)
    link = Link(tmp_path / 's')
    peer, _ = server.accept()
    fd = memfd(b'{"body":1}')
    so.send_fds(peer, [c.pack_frame(c.QUESTION, file_question_fields(qid=1)) + c.pack_frame(c.QUESTION, question_fields(qid=2))],
                [fd])
    os.close(fd)
    frames = link.receive()
    assert [(c.read_uint(f[0], 8), got is None) for _, f, got in frames] == [(1, True), (2, False)]
    assert os.pread(frames[1][2], 16, 0) == b'{"body":1}'
    os.close(frames[1][2])
    link.close()
    peer.close()
    server.close()


def test_object_verbs_through_the_command_line(a: AdminHarness, tmp_path: Path, capsys) -> None:
    """H-01: admin object put/del; the client sends the absolute path as typed (symlinks are the core's to resolve)."""
    host = tmp_path / 'host'
    (host / 'sub').mkdir(parents=True)
    (tmp_path / 'via').symlink_to(host)
    stop = threading.Event()
    server = threading.Thread(target=lambda: [a.hooks.loop.run_once(0.01) for _ in iter(stop.is_set, True)])
    server.start()
    old = os.getcwd()
    try:
        os.chdir(tmp_path)
        root = ['--root', str(tmp_path)]
        assert client_main(root + ['admin', 'object', 'put', 'work0', 'notes', 'via', '--type', 'dir', '--list',
                                   '--mode', 'ask']) == 0
        assert client_main(root + ['admin', 'object', 'put', 'work0', 'one', 'via/sub', '--type', 'file']) == 1
        assert client_main(root + ['admin', 'object', 'put', 'work0', 'ro', str(host / 'sub'), '--type', 'dir']) == 0
        assert client_main(root + ['admin', 'object', 'del', 'work0', 'ro']) == 0
        with pytest.raises(SystemExit):
            client_main(root + ['admin', 'object', 'put', 'work0', 'x', 'via', '--type', 'dir', '--mode', 'never'])
    finally:
        os.chdir(old)
        stop.set()
        server.join(5)
    out, err = capsys.readouterr()
    st = os.stat(host)
    assert f'mirror=persisted device={st.st_dev} inode={st.st_ino}' in out and 'refused' in err
    obj = a.hooks.tables.tables['work0'].objects['notes']
    assert (obj.host_path, obj.dir_path, obj.ops, obj.approval) == (str(tmp_path / 'via'), str(host), 3, Approval.ALWAYS)
    assert set(a.hooks.tables.tables['work0'].objects) == {'notes'}
    a.hooks.tables.close()


def test_the_client_folds_no_segment_and_the_core_follows_the_link_before_dotdot(a: AdminHarness, tmp_path: Path,
                                                                                 capsys) -> None:
    """H-01, H-02 (Codex review, important 2): with host/link -> other/sub, the path host/link/../notes is
    other/notes as the kernel resolves it, and host/notes if the text is folded first. The client sends an absolute
    path as typed and a relative one with only the working directory put in front; the core resolves it, following
    the link, and anchors other/notes."""
    (tmp_path / 'other' / 'sub').mkdir(parents=True)
    (tmp_path / 'other' / 'notes').mkdir()
    (tmp_path / 'host' / 'notes').mkdir(parents=True)
    (tmp_path / 'host' / 'link').symlink_to(tmp_path / 'other' / 'sub')
    stop = threading.Event()
    server = threading.Thread(target=lambda: [a.hooks.loop.run_once(0.01) for _ in iter(stop.is_set, True)])
    server.start()
    old = os.getcwd()
    try:
        os.chdir(tmp_path)
        cwd = os.getcwd()
        root = ['--root', str(tmp_path)]
        assert client_main(root + ['admin', 'object', 'put', 'work0', 'rel', 'host/link/../notes', '--type', 'dir']) == 0
        assert client_main(root + ['admin', 'object', 'put', 'work0', 'abs', f'{cwd}/host/link/../notes',
                                   '--type', 'dir']) == 0
        assert client_main(root + ['admin', 'object', 'put', 'work0', 'dot', './host//link/../notes',
                                   '--type', 'dir']) == 0
    finally:
        os.chdir(old)
        stop.set()
        server.join(5)
    capsys.readouterr()
    objects = a.hooks.tables.tables['work0'].objects
    assert {k: o.host_path for k, o in objects.items()} == {'rel': f'{cwd}/host/link/../notes',
                                                            'abs': f'{cwd}/host/link/../notes',
                                                            'dot': f'{cwd}/./host//link/../notes'}
    assert {o.dir_path for o in objects.values()} == {str(tmp_path / 'other' / 'notes')}
    a.hooks.tables.close()


def test_two_windows_share_no_input() -> None:
    """A-03: the attach module never touches the management port, the admin module never opens a relay socket."""
    def imports(name: str) -> set[str]:
        tree = ast.parse((ENGINE / 'client' / name).read_text())
        return {n.module or '' for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | \
               {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    attach_src, admin_src = (ENGINE / 'client' / 'attach.py').read_text(), (ENGINE / 'client' / 'admin.py').read_text()
    assert not {m for m in imports('attach.py') if 'admin' in m or 'render' in m or 'canonical' in m}
    assert 'admin.sock' not in attach_src and 'attach.sock' not in admin_src and 'Question' not in attach_src
    assert escape(b'\\') == '\\\\'
