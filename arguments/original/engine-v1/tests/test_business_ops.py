"""Business catalog loading (rr E-05), the frozen operation's bytes (rr E-06) and the recorder's guards (si E-09)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
from typing import Any

import pytest

from conftest import OVERFLOWUID, FakeClock
from engine.business import load_business
from engine.operations import LP, ArgsInvalid, check_args
from engine.records import ControlBinding, RecordFault, Recorder, VerifiedSubject
from engine.startup import StartupRefused


def sha(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def write(root: Path, name: str, value: Any) -> str:
    data = json.dumps(value).encode()
    (root / name).write_bytes(data)
    return sha(data)


def deployment(root: Path, text: bytes = b'hello\n', **override: Any) -> str:
    (root / 'docs').mkdir()
    (root / 'docs' / 'a.txt').write_bytes(text)
    doc = {'resource_id': 'doc-a', 'descriptor_id': 'd-a', 'kind': 'engine_local', 'allowed_actions': ['document.read'],
           'source_ref': 'a.txt', 'content_identity': sha(text), 'byte_length': len(text),
           'media_type': 'text/plain; charset=utf-8', **override}
    provider = {'provider_config_id': 'p', 'adapter_kind': 'chat-tools-sse', 'wire_profile': 'chat-tools-core',
                'endpoint': {'scheme': 'http', 'host': 'localhost', 'port': 8080, 'path': '/v1/chat/completions',
                             'ip': '127.0.0.1'}, 'model_id': 'm', 'credential_ref': 'none',
                'credential_version_ref': 'none', 'provider_partition_id': 'pp', 'state_mode': 'stateless_completion',
                'deployment_evidence_ref': 'ev'}
    model = {'resource_id': 'model', 'descriptor_id': 'd-m', 'kind': 'model', 'allowed_actions': ['model.generate'],
             'provider_config_ref': 'p', 'max_input_bytes': 1024, 'max_output_tokens': 64, 'max_output_bytes': 4096}
    write(root, 'business.json', {
        'document_root': 'docs',
        'resource_descriptor_refs': [{'descriptor_ref': 'doc.json', 'descriptor_digest': write(root, 'doc.json', doc)},
                                     {'descriptor_ref': 'model.json',
                                      'descriptor_digest': write(root, 'model.json', model)}],
        'provider_config_refs': [{'artifact_ref': 'p.json', 'artifact_digest': write(root, 'p.json', provider)}]})
    return 'business.json'


def test_loads_snapshot_and_model(tmp_path: Path) -> None:
    catalog = load_business(tmp_path, deployment(tmp_path))
    doc = catalog.resources['doc-a']
    assert doc.blob == b'hello\n' and doc.content_identity == sha(b'hello\n')
    (tmp_path / 'docs' / 'a.txt').write_bytes(b'changed')   # the snapshot is what requests see
    assert catalog.resources['doc-a'].blob == b'hello\n'
    assert catalog.resources['model'].provider.ip == '127.0.0.1'


@pytest.mark.parametrize('case', ['symlink', 'digest', 'unknown_field', 'dotdot', 'length', 'fifo', 'bad_utf8'])
def test_loader_refuses(tmp_path: Path, case: str) -> None:
    override: dict[str, Any] = {}
    text = b'hello\n'
    if case == 'digest':
        override = {'content_identity': sha(b'other')}
    elif case == 'unknown_field':
        override = {'alias': 'x'}
    elif case == 'dotdot':
        override = {'source_ref': '../business.json'}
    elif case == 'length':
        override = {'byte_length': 3}
    elif case == 'bad_utf8':
        text = b'\xff\xfe'
        override = {}
    name = deployment(tmp_path, text, **override)
    if case == 'symlink':
        (tmp_path / 'docs' / 'a.txt').unlink()
        (tmp_path / 'outside.txt').write_bytes(b'hello\n')
        (tmp_path / 'docs' / 'a.txt').symlink_to(tmp_path / 'outside.txt')
    if case == 'fifo':
        (tmp_path / 'docs' / 'a.txt').unlink()
        os.mkfifo(tmp_path / 'docs' / 'a.txt')
    with pytest.raises(StartupRefused):
        load_business(tmp_path, name)


def test_document_parameter_bytes_layout(native) -> None:
    from reqkit import harness, request, running, send, frames
    h = harness(native)
    seen = []
    ex, child, binding, call = running(h)
    real = __import__('engine.operations', fromlist=['freeze_operation']).freeze_operation
    import engine.requests as requests_module
    requests_module.freeze_operation = lambda *a: seen.append(real(*a)) or seen[-1]
    try:
        send(child, request('1', call))
        frames(h, child)
    finally:
        requests_module.freeze_operation = real
    c = seen[0]
    r = c.resource
    target = LP(r.resource_id.encode()) + LP(r.content_identity.encode()) + LP(str(r.byte_length).encode())
    assert c.target_identity_bytes == target and c.body_bytes == b'{}'
    assert c.parameter_bytes == (LP(b'w2-operation') + LP(r.descriptor_digest.encode()) + LP(b'test-doc')
                                 + LP(b'document.read') + LP(target) + LP(b'{}'))
    assert c.argument_hash == sha(c.parameter_bytes) and c.operation_id == ex.session.session_id + ':r:1'
    assert struct.unpack('>I', c.parameter_bytes[:4])[0] == len(b'w2-operation')


@pytest.mark.parametrize('args', [
    {'messages': [], 'max_output_tokens': 1},
    {'messages': [{'role': 'user', 'text': 'x', 'url': 'http://x'}], 'max_output_tokens': 1},
    {'messages': [{'role': 'user', 'text': 'x'}], 'max_output_tokens': 1, 'model': 'other'},
    {'messages': [{'role': 'user', 'text': 'x'}], 'max_output_tokens': 4097},
    {'messages': [{'role': 'user', 'text': 'x'}], 'max_output_tokens': 1, 'tool_choice': 'required'},
    {'messages': [{'role': 'user', 'text': 'x' * 33_000}], 'max_output_tokens': 1},
])
def test_model_args_closed_shape(args: dict) -> None:
    with pytest.raises(ArgsInvalid):
        check_args('model.generate', args)


SRC = {'request_key': 'k'}


def subject(uid: int, expected: int | None = None) -> VerifiedSubject:
    return VerifiedSubject('e', 'a', 's', 'c', 1, uid if expected is None else expected, uid, None)


@pytest.mark.parametrize('kind,kw', [
    ('request_received', {'verified_subject': subject(0)}),                       # a sentinel as a principal
    ('request_received', {'verified_subject': subject(OVERFLOWUID)}),
    ('request_received', {'verified_subject': subject(60001, 60000)}),            # not the comparison result
    ('request_received', {}),                                                     # no subject on a verified kind
    ('receive_rejected', {'verified_subject': subject(60000)}),                   # a subject on a rejection
    ('spawn_requested', {}),                                                      # control fact without binding
    ('request_received', {'verified_subject': subject(60000), 'control_binding': ControlBinding('e', 'l', 'd', 1)}),
    ('request_received', {'verified_subject': subject(60000), 'agent_report': {'x': 1}}),
])
def test_recorder_type_guards_latch(kind: str, kw: dict) -> None:
    r = Recorder('a' * 32, OVERFLOWUID, FakeClock(), None, keep=10)
    with pytest.raises(RecordFault):
        r.record(kind, source_ref=SRC, **kw)
    assert r.failed is not None and 'source_ref' not in r.failed and not r.has_room(1)
    with pytest.raises(RecordFault):
        r.record('session_active', control_binding=ControlBinding('e', 'l', 'd', 1), source_ref=SRC)


def test_recorder_requires_a_structured_source_and_names_the_event() -> None:
    r = Recorder('e' * 32, OVERFLOWUID, FakeClock(), None, keep=10)
    r.record('session_active', control_binding=ControlBinding('e', 'l', 'd', 1), source_ref=SRC)
    event = r.events[-1]
    assert event['event_id'] == 'e' * 32 + ':engine:1' and event['source_ref'] == SRC
    with pytest.raises(RecordFault):
        r.record('session_active', control_binding=ControlBinding('e', 'l', 'd', 1))


def test_recorder_worker_writes_and_receipts(tmp_path: Path) -> None:
    path = tmp_path / 'events.jsonl'
    path.touch()
    r = Recorder('b' * 32, OVERFLOWUID, FakeClock(), str(path))
    for _ in range(50):
        r.record('session_active', control_binding=ControlBinding('e', 'l', 'd', 60000), source_ref=SRC)
    r.record('request_received', verified_subject=subject(60000), source_ref=SRC)
    receipt = r.close()
    lines = [json.loads(x) for x in path.read_text().splitlines()]
    assert len(lines) == 51 and [x['producer_seq'] for x in lines] == [str(i) for i in range(1, 52)]
    assert receipt == {'engine_epoch': 'b' * 32, 'producer': 'engine', 'last_durable_seq': '51',
                       'evidence_complete': True, 'error_code': None}


def test_recorder_stall_fails_after_5s() -> None:
    clock = FakeClock()
    r = Recorder('c' * 32, OVERFLOWUID, clock, None)
    r.pending.append((1, b'x'))     # simulate a worker that never makes progress
    assert r.check() is None
    clock.advance(5_000)
    assert r.check() == 'no durable progress for 5000 ms'


def test_oversize_event_latches() -> None:
    r = Recorder('d' * 32, OVERFLOWUID, FakeClock(), None)
    with pytest.raises(RecordFault):
        r.record('session_active', control_binding=ControlBinding('e', 'l', 'd', 1), source_ref=SRC,
                 detail={'x': 'a' * 5000})
    assert r.failed == 'event over 4 KiB'
