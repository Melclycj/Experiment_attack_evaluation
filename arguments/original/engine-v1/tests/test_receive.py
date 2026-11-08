"""Receive pipeline pieces: strict parse, schema, frozen input, the single writer, structure (conn E-02)."""
from __future__ import annotations

import json
import re
import socket

import pytest

from conftest import ENGINE
from engine.ffi import BODY_MAX
from engine.receive import Invalid, parse_body, validate
from engine.writer import CONTROL_RESERVE, OUTPUT_MAX, FrameWriter, Written, make_out

HELLO = {'v': 2, 'type': 'hello', 'protocol': 'w2-local/2', 'adapter_id': 'fixture'}
REQUEST = {'v': 2, 'type': 'request', 'id': '1', 'task_call_id': '1', 'task_id': 'task-1',
           'resource_id': 'test-doc', 'action': 'document.read', 'args': {'path': ['a', {'b': 1}]}}


def nested(depth: int) -> bytes:
    return (b'{"a":' * (depth - 1)) + b'{}' + b'}' * (depth - 1)


@pytest.mark.parametrize('body', [
    b'\xef\xbb\xbf{"v":2}',                              # BOM
    '{"v":2}'.encode('utf-16'),                          # not UTF-8 (json.loads would sniff it)
    b'{"v":2,"v":2}',                                    # duplicate key
    b'{"v":NaN}', b'{"v":Infinity}', b'{"v":-Infinity}',
    b'{"v":2.0}', b'{"v":1e9}',                          # no non-integer numbers
    b'{"v":"\\ud800"}', b'{"\\udc00":1}',                # lone surrogate escapes
    b'{"v":"\xed\xa0\x80"}',                             # encoded surrogate
    b'{"v":"\xff"}',                                     # invalid UTF-8
    b'{} {}', b'[]', b'"x"', b'',
    b'{"v":9007199254740992}', b'{"v":-9007199254740992}',
    nested(17),
    json.dumps({'a': list(range(4096))}).encode(),       # 4,097 members and elements
])
def test_parse_rejects(body: bytes) -> None:
    with pytest.raises(Invalid):
        parse_body(body)


@pytest.mark.parametrize('body,code', [(b'{"v":2,"v":2}', 'duplicate_key'), (b'{"v":NaN}', 'constant'),
                                       (b'{"v":1.5}', 'non_integer'), (b'{"v":', 'json')])
def test_parse_codes(body: bytes, code: str) -> None:
    with pytest.raises(Invalid) as error:
        parse_body(body)
    assert str(error.value) == code


def test_parse_limits_accepted() -> None:
    assert parse_body(nested(16))
    assert parse_body(json.dumps({'a': list(range(4095))}).encode())
    assert parse_body(b'{"v":9007199254740991,"w":-9007199254740991}')
    assert parse_body('{"x":"中文"}'.encode())


@pytest.mark.parametrize('change', [
    {'v': 2.5}, {'v': '2'}, {'v': True}, {'v': 1},
    {'type': 'welcome'}, {'type': 'result'}, {'type': 'Hello'}, {'type': 7},
    {'uid': 1000}, {'agent_id': 'a'}, {'sender_uid': 1}, {'grant_ref': 'grant-1'}, {'execution_id': 'x'},
    {'adapter_id': 'a' * 97}, {'adapter_id': 'bad id'}, {'adapter_id': 1},
    {'protocol': 'w2-local/1'},
])
def test_hello_schema_rejects(change: dict) -> None:
    with pytest.raises(Invalid):
        validate({**HELLO, **change})


@pytest.mark.parametrize('change', [
    {'grant_ref': 'grant-1'}, {'uid': 60000}, {'local_agent_id': 'agent-0'},
    {'id': '0'}, {'id': '01'}, {'id': '18446744073709551616'}, {'id': 1}, {'task_call_id': '-1'},
    {'task_id': 'a' * 97}, {'resource_id': ''}, {'args': []}, {'args': 'x'},
    {'timeout_ms': 0}, {'timeout_ms': 300001}, {'timeout_ms': True}, {'timeout_ms': '10'},
])
def test_request_schema_rejects(change: dict) -> None:
    with pytest.raises(Invalid):
        validate({**REQUEST, **change})


def test_request_schema_without_grant_ref() -> None:
    """Grant and grant_ref stay engine-internal (user decision 2026-10-04); the agent sends no grant field."""
    assert validate({**REQUEST, 'id': '18446744073709551615', 'timeout_ms': 300000})
    missing = dict(REQUEST)
    del missing['task_call_id']
    with pytest.raises(Invalid):
        validate(missing)


@pytest.mark.parametrize('body', [
    {'v': 2, 'type': 'cancel', 'reply_to': '1', 'reason': 'other'},
    {'v': 2, 'type': 'cancel', 'reply_to': '1', 'reason': 'user', 'id': '2'},
    {'v': 2, 'type': 'task_result', 'reply_to': '1', 'status': 'done', 'output': ''},
    {'v': 2, 'type': 'task_result', 'reply_to': '1', 'status': 'ok', 'output': 1},
    {'v': 2, 'type': 'bye', 'reason': 'later'},
    {'v': 2, 'type': 'bye'},
])
def test_other_schemas_reject(body: dict) -> None:
    with pytest.raises(Invalid):
        validate(body)


def test_args_frozen_copy() -> None:
    from engine.receive import Request, _message
    message = _message(None, validate(dict(REQUEST)), 1)  # type: ignore[arg-type]
    assert isinstance(message, Request)
    with pytest.raises(TypeError):
        message.args['path'] = 'x'   # type: ignore[index]
    assert message.args['path'] == ('a', {'b': 1}) and isinstance(message.args['path'], tuple)
    with pytest.raises(TypeError):
        message.args['path'][1]['b'] = 2


def test_ffi_uid_bounds(native) -> None:
    import ctypes
    handle, buffer = native.reader_new(), ctypes.create_string_buffer(BODY_MAX)
    try:
        for expected in (0, 2 ** 32 - 1, 2 ** 32, -1):
            with pytest.raises(ValueError):
                native.frame_receive(handle, buffer, 0, expected, 65534)
    finally:
        native.reader_free(handle)


# ---- single writer ------------------------------------------------------------------------
def test_writer_short_writes_keep_frame_order() -> None:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    a.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    b.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    writer, done = FrameWriter(a), []
    big = {'v': 2, 'type': 'x', 'pad': ''}
    big['pad'] = 'a' * (BODY_MAX - len(json.dumps(big, separators=(',', ':'))))
    assert writer.queue(make_out(body=big, on_sent=lambda: done.append('big')))
    assert writer.queue(make_out(body={'v': 2, 'type': 'y'}, on_sent=lambda: done.append('small')))
    while writer.flush() is Written.PARTIAL:   # one sendmsg per flush
        pass
    assert 0 < writer.offset < BODY_MAX + 4 and len(writer.frames) == 1 and done == []
    first = json.dumps(big, separators=(',', ':')).encode()
    second = b'{"v":2,"type":"y"}'
    expected = len(first).to_bytes(4, 'big') + first + len(second).to_bytes(4, 'big') + second
    received = b''
    b.setblocking(False)
    for _ in range(10_000):
        try:
            received += b.recv(65536)
        except BlockingIOError:
            pass
        if writer.flush() is Written.DONE and len(received) >= len(expected):
            break
    assert received == expected
    assert done == ['big', 'small'] and writer.offset == 0 and writer.used == 0


def test_writer_bounded_and_fails_closed() -> None:
    """1 MiB per session; the last 8 KiB only for control records of at most 1,024 bytes (conn E-03)."""
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    writer = FrameWriter(a)
    body = {'v': 2, 'type': 'x', 'pad': 'a' * 60_000}
    size = make_out(body=body).size
    while writer.queue(make_out(body=body)):
        pass
    assert writer.used <= OUTPUT_MAX - CONTROL_RESERVE < writer.used + size
    small = make_out(body={'v': 2, 'type': 'cancel', 'reply_to': '1', 'reason': 'user'}, control=True)
    assert writer.queue(small)                         # the reserve still admits a control record
    with pytest.raises(ValueError):
        make_out(body={'v': 2, 'pad': 'a' * 2000}, control=True)
    b.close()
    statuses = {writer.flush() for _ in range(3)}
    # Failure marks the writer dead; its records stay until close step 2 discards them.
    assert Written.FAILED in statuses and writer.dead and writer.frames
    dropped = []
    writer.frames[0].on_drop = lambda: dropped.append(1)
    writer.discard()
    assert not writer.frames and writer.used == 0 and dropped == [1]
    assert not writer.queue(make_out(body={'v': 2}))
    with pytest.raises(ValueError):
        make_out(body={'pad': 'a' * BODY_MAX})


def test_writer_withdraws_only_unstarted_records() -> None:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    a.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    writer, dropped = FrameWriter(a), []
    owner = object()
    first = make_out(owner=owner, body={'v': 2, 'pad': 'a' * 60_000}, on_drop=lambda: dropped.append(1))
    second = make_out(owner=owner, body={'v': 2, 'pad': 'b'}, on_drop=lambda: dropped.append(2))
    assert writer.queue(first) and writer.queue(second)
    assert writer.flush() in (Written.PARTIAL, Written.BLOCKED) and writer.started
    writer.withdraw_owner(owner)
    assert dropped == [2] and writer.current is first   # the started frame completes; the other went
    assert not writer.withdraw(first)


# ---- structure ----------------------------------------------------------------------------
def sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding='utf-8') for p in (ENGINE / 'engine').rglob('*.py')}


CREDENTIAL_OPTION = re.compile(r'setsockopt|SO_PASSCRED|SO_PEERCRED|PEERCRED|getpeereid')


def test_no_credential_option_written_or_peer_credential_read() -> None:
    """engine-requirements §2 (the engine never clears PASSCRED on its end) and §3 (the data channel takes no
    SO_PEERCRED reading as identity): the engine sets no socket option and reads no peer credential at all; the
    only credential path is the per-fragment SCM_CREDENTIALS comparison in transport.c. transport.c may read
    SO_PASSCRED (the handoff check) but never sets it nor reads SO_PEERCRED."""
    assert CREDENTIAL_OPTION.search('sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)')   # the scan bites
    hits = {name: CREDENTIAL_OPTION.findall(text) for name, text in sources().items()}
    assert not any(hits.values()), hits
    transport = (ENGINE / 'native' / 'sandbox' / 'transport.c').read_text(encoding='utf-8')
    assert not re.search(r'setsockopt|SO_PEERCRED', transport)
    assert re.findall(r'getsockopt\([^)]*SO_PASSCRED', transport) == ['getsockopt(fd,SOL_SOCKET,SO_PASSCRED']


def test_c_reader_parses_no_body() -> None:
    """The C reader frames and compares only (conn E-02, the body is parsed by Python json): no JSON call lies
    between the per-fragment comparison and the copy-out, so no third-party parser runs on agent bytes beside
    the reader's binding fields. The body of w2_frame_receive is cut at the next top-level definition."""
    transport = (ENGINE / 'native' / 'sandbox' / 'transport.c').read_text(encoding='utf-8')
    start = transport.index('int w2_frame_receive(')
    body = transport[start:transport.index('\n}\n', start)]
    assert 'memcpy(out' in body and 'w2_recv_credential' in body   # the cut holds the function
    assert not re.search(r'json', body), re.findall(r'.*json.*', body)


def test_verified_context_has_one_constructor() -> None:
    found = {name for name, text in sources().items() if re.search(r'\bVerifiedContext\(', text)}
    assert found == {'receive.py'}
    receive = sources()['receive.py']
    assert len(re.findall(r'\bVerifiedContext\(', receive)) == 1


def test_no_python_reader_on_sockets() -> None:
    """Received bytes come only from the C library (w2_frame_receive, w2_recv_control). business.py reads
    regular files beneath the document root at start-up (openat2 + fstat S_ISREG), never a socket."""
    pattern = re.compile(r'\.(recv|recvmsg|recv_into|recvfrom|recvmsg_into|makefile|read)\(|os\.read\(')
    hits = {name: pattern.findall(text) for name, text in sources().items() if name != 'business.py'}
    assert not any(hits.values()), hits
