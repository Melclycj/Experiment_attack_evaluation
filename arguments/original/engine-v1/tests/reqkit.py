"""Helpers for the request and task tests: in-memory catalog resources, a session driven to a running call over a
real AF_UNIX stream pair (the SELF workspace, whose uid is this process's), and frame I/O on the agent end."""
from __future__ import annotations

import hashlib
import json
import socket
import struct
from typing import Any

from conftest import SELF, Harness, catalog, plan
from engine.business import DocumentResource, ModelResource, ProviderConfig
from engine.startup import Catalog
from test_phases import frame, read_frame, to_active

DOC_TEXT = 'grüße, ✓ document line\n' * 1200            # ≈ 31 KB, multi-byte, several 8 KiB chunks
OTHER_TEXT = 'other document\n'
TOOLS = ({'name': 'read_file', 'description': 'read a workspace file', 'input_schema': {'type': 'object'}},)


def digest(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def document(resource_id: str, text: str) -> DocumentResource:
    blob = text.encode()
    return DocumentResource(resource_id, 'd-' + resource_id, digest(b'descriptor:' + blob), resource_id + '.txt',
                            digest(blob), len(blob), blob)


PROVIDER = ProviderConfig('local-model', 'chat-tools-sse', 'chat-tools-core', 'http', 'localhost', 8080,
                          '/v1/chat/completions', '127.0.0.1', 'model-x', 'none', 'none', 'p-1', 'stateless_completion',
                          'ev-1')


def resources() -> dict[str, Any]:
    return {'test-doc': document('test-doc', DOC_TEXT), 'other-doc': document('other-doc', OTHER_TEXT),
            'test-model': ModelResource('test-model', 'd-model', 'sha256:' + '7' * 64, PROVIDER, 48 * 1024, 4096,
                                        256 * 1024)}


def DOC_RULE(res: dict[str, Any]) -> dict[str, Any]:
    return {'resource_id': 'test-doc', 'action': 'document.read',
            'limits': {'max_output_bytes': res['test-doc'].byte_length}}


MODEL_RULE = {'resource_id': 'test-model', 'action': 'model.generate',
              'limits': {'max_input_bytes': 48 * 1024, 'max_output_tokens': 4096, 'max_output_bytes': 256 * 1024}}


def tool_catalog() -> Catalog:
    """The same catalog with the SELF plan declaring a tool set (reached through Execution → Plan)."""
    base = catalog()
    plans = dict(base.plans)
    p = plan(SELF)
    plans[f'observe-{SELF}'] = type(p)(p.launch_plan_id, p.launch_plan_digest, p.workspace_id, p.policy_digest,
                                       p.isolation_profile_digest, p.adapter_id, TOOLS)
    return Catalog(base.catalog_digest, base.storage_profile_digest, plans, base.workspaces)


def harness(native: Any, **kw: Any) -> Harness:
    return Harness(native, resources=resources(), **kw)


def send(child: socket.socket, body: dict[str, Any]) -> None:
    child.sendall(frame(body))


def request(rid: str, call: Any, resource: str = 'test-doc', action: str = 'document.read',
            args: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    return {'v': 2, 'type': 'request', 'id': rid, 'task_call_id': call.call_id, 'task_id': call.binding.task_id,
            'resource_id': resource, 'action': action, 'args': {} if args is None else args, **extra}


def task_result(call: Any, status: str = 'ok', output: str = 'done') -> dict[str, Any]:
    return {'v': 2, 'type': 'task_result', 'reply_to': call.call_id, 'status': status, 'output': output}


def frames(h: Harness, child: socket.socket, rounds: int = 60) -> list[dict[str, Any]]:
    """Pump, reading every whole frame the engine wrote to the agent end."""
    out: list[dict[str, Any]] = []
    buf = b''
    child.setblocking(False)
    for _ in range(rounds):
        h.pump(1)
        while True:
            try:
                data = child.recv(1 << 20)
            except BlockingIOError:
                break
            if not data:
                break
            buf += data
        while len(buf) >= 4 and len(buf) >= 4 + struct.unpack('>I', buf[:4])[0]:
            size = struct.unpack('>I', buf[:4])[0]
            out.append(json.loads(buf[4:4 + size]))
            buf = buf[4 + size:]
    child.setblocking(True)
    return out


def running(h: Harness, rules: list[dict[str, Any]] | None = None, ttl_ms: int = 600_000,
            timeout_ms: int = 300_000) -> tuple[Any, socket.socket, Any, Any]:
    """ACTIVE session with one bound task and its task_start delivered."""
    ex, child = to_active(h)
    res = h.lc.requests.resources
    binding = h.lc.grant_task(ex, [DOC_RULE(res)] if rules is None else rules, ttl_ms)
    call = h.lc.task_start(binding, 'do the task', timeout_ms)
    h.pump()
    start = json.loads(read_frame(child))
    assert start['type'] == 'task_start' and start['id'] == call.call_id and start['task_id'] == binding.task_id
    assert set(start) == {'v', 'type', 'id', 'task_id', 'input', 'timeout_ms'}   # no grant field
    h.pump()
    return ex, child, binding, call


def kinds(h: Harness) -> list[str]:
    return [e['kind'] for e in h.recorder.events if e['kind'] != 'diagnostic']
