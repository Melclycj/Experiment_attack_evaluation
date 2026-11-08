"""Business args, the frozen operation and its summary (rr E-06 Grant 规则、操作冻结与最终分派; E-07 业务 schema).

freeze_operation is the one place that serialises and hashes an operation. The CandidateOperation it returns has no
execution right; only authorize() (called by the request manager's final decision) wraps it into the one-use
AuthorizedOperation a handler accepts. Every object an operation needs is reached from its RequestEntry by
reference: the entry's Session → Execution → Plan for the declared tools, the catalog resource for the target.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import struct
from types import MappingProxyType
from typing import Any, Mapping

from .business import DocumentResource, ModelResource, ProviderConfig
from .startup import ID

MODEL_BODY_MAX = 64 * 1024
MESSAGES_MAX, TEXT_MAX, MESSAGES_TEXT_MAX = 64, 32 * 1024, 48 * 1024
TOOL_CALLS_MAX, TOOL_ARGUMENTS_MAX, TOOL_CALLS_BYTES_MAX = 8, 16 * 1024, 32 * 1024
TOOL_NAME = re.compile(r'[a-zA-Z0-9_-]{1,64}')
OPERATION_ID_MAX = 160


class ArgsInvalid(ValueError):
    """The args do not match the action's only legal shape; the argument is a bounded code."""


def thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [thaw(v) for v in value]
    return value


def compact(value: Any) -> bytes:
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha256(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def _text(value: Any) -> str:
    if type(value) is not str or len(value.encode()) > TEXT_MAX:
        raise ArgsInvalid('text')
    return value


def check_tool_calls(calls: Any, names: frozenset[str] | None) -> list[dict[str, Any]]:
    """Format only (no schema check of arguments, no reading of their meaning). ``names`` None skips the
    declared-set check (history in a request is the agent's own record, not a new call)."""
    if type(calls) is not list or not 0 < len(calls) <= TOOL_CALLS_MAX:
        raise ArgsInvalid('tool_calls')
    total = 0
    for call in calls:
        if type(call) is not dict or set(call) != {'id', 'name', 'arguments'}:
            raise ArgsInvalid('tool_calls.item')
        if type(call['id']) is not str or not ID.fullmatch(call['id']):
            raise ArgsInvalid('tool_calls.id')
        if type(call['name']) is not str or not TOOL_NAME.fullmatch(call['name']):
            raise ArgsInvalid('tool_calls.name')
        if names is not None and call['name'] not in names:
            raise ArgsInvalid('tool_calls.undeclared')
        if type(call['arguments']) is not dict:
            raise ArgsInvalid('tool_calls.arguments')
        size = len(compact(call['arguments']))
        if size > TOOL_ARGUMENTS_MAX:
            raise ArgsInvalid('tool_calls.arguments_size')
        total += len(compact(call))
    if total > TOOL_CALLS_BYTES_MAX:
        raise ArgsInvalid('tool_calls.size')
    return calls


def check_args(action: str, frozen: Mapping[str, Any]) -> dict[str, Any]:
    args = thaw(frozen)
    if action == 'document.read':
        if args != {}:
            raise ArgsInvalid('document.read takes {}')
        return args
    if action != 'model.generate':
        raise ArgsInvalid('action')
    if not {'messages', 'max_output_tokens'} <= set(args) <= {'messages', 'max_output_tokens', 'tool_choice'}:
        raise ArgsInvalid('model.fields')
    if type(args['max_output_tokens']) is not int or not 1 <= args['max_output_tokens'] <= 4096:
        raise ArgsInvalid('max_output_tokens')
    if args.get('tool_choice', 'auto') not in ('auto', 'none'):
        raise ArgsInvalid('tool_choice')
    messages = args['messages']
    if type(messages) is not list or not 0 < len(messages) <= MESSAGES_MAX:
        raise ArgsInvalid('messages')
    total = 0
    for m in messages:
        if type(m) is not dict:
            raise ArgsInvalid('message')
        keys, role = set(m), m.get('role')
        if role in ('system', 'user', 'assistant') and keys == {'role', 'text'}:
            total += len(_text(m['text']).encode())
        elif role == 'assistant' and keys in ({'role', 'tool_calls'}, {'role', 'text', 'tool_calls'}):
            total += len(_text(m.get('text', '')).encode())
            check_tool_calls(m['tool_calls'], None)
        elif role == 'tool' and keys == {'role', 'tool_call_id', 'text'}:
            if type(m['tool_call_id']) is not str or not ID.fullmatch(m['tool_call_id']):
                raise ArgsInvalid('tool_call_id')
            total += len(_text(m['text']).encode())
        else:
            raise ArgsInvalid('message.shape')
    if total > MESSAGES_TEXT_MAX:
        raise ArgsInvalid('messages.size')
    return args


def within_limits(resource: Any, limits: Mapping[str, int], args: dict[str, Any]) -> bool:
    """A request must satisfy one rule whole."""
    if isinstance(resource, DocumentResource):
        return limits['max_output_bytes'] >= resource.byte_length
    return (args['max_output_tokens'] <= limits['max_output_tokens']
            and len(compact(args['messages'])) <= limits['max_input_bytes'])


def LP(data: bytes) -> bytes:
    return struct.pack('>I', len(data)) + data


def _model_body(provider: ProviderConfig, args: dict[str, Any], tools: tuple[Any, ...]) -> bytes:
    """The fixed outbound mapping of rr E-07, serialised once."""
    messages = []
    for m in args['messages']:
        out: dict[str, Any] = {'role': m['role']}
        if 'tool_call_id' in m:
            out['tool_call_id'] = m['tool_call_id']
        if 'text' in m:
            out['content'] = m['text']
        if 'tool_calls' in m:
            out['tool_calls'] = [{'id': c['id'], 'type': 'function',
                                  'function': {'name': c['name'], 'arguments': compact(c['arguments']).decode()}}
                                 for c in m['tool_calls']]
        messages.append(out)
    body: dict[str, Any] = {'model': provider.model_id, 'messages': messages}
    if tools:
        body['tools'] = [{'type': 'function', 'function': {'name': t['name'], 'description': t['description'],
                                                           'parameters': t['input_schema']}} for t in tools]
        body['tool_choice'] = args.get('tool_choice', 'auto')
    body.update(max_tokens=args['max_output_tokens'], stream=True, n=1, temperature=0,
                stream_options={'include_usage': False})
    if provider.wire_profile == 'llama-chat-tools':
        body.update(cache_prompt=False, parse_tool_calls=True, reasoning_format='none')
    return compact(body)


@dataclass(frozen=True, eq=False)
class CandidateOperation:
    operation_id: str
    request: Any                     # the RequestEntry; the candidate lives in its slot
    resource: Any
    rule: Any
    action: str
    target_identity: Mapping[str, Any]
    target_identity_bytes: bytes
    parameter_bytes: bytes
    argument_hash: str
    body_bytes: bytes
    body_hash: str
    credential_version_ref: str | None
    prepared: Any                    # the document blob, or the frozen model body (no I/O is set up here)
    tool_names: frozenset[str]

    def summary(self, decision_id: str | None = None) -> dict[str, Any]:
        """OperationSummary for E-09: no URL secrets, token or provider error."""
        entry = self.request
        out = {'operation_id': self.operation_id, 'resource_id': self.resource.resource_id,
               'descriptor_digest': self.resource.descriptor_digest, 'action': self.action,
               'target_identity': dict(self.target_identity), 'argument_hash': self.argument_hash,
               'body_hash': self.body_hash, 'grant_ref': entry.grant_state.grant.grant_ref}
        if decision_id is not None:
            out['authorization_decision_id'] = decision_id
        return out


_AUTHORIZER = object()


@dataclass(frozen=True, eq=False)
class AuthorizedOperation:
    candidate: CandidateOperation
    authorization_decision_id: str
    grant_state_generation: int
    authorized_at_ns: int
    _token: object

    def __post_init__(self) -> None:
        if self._token is not _AUTHORIZER:
            raise TypeError('AuthorizedOperation is built only by authorize()')


def authorize(candidate: CandidateOperation, decision_id: str, generation: int, now_ns: int) -> AuthorizedOperation:
    """Called only inside the request manager's final, non-yielding decision."""
    return AuthorizedOperation(candidate, decision_id, generation, now_ns, _AUTHORIZER)


def freeze_operation(entry: Any, resource: Any, rule: Any, args: dict[str, Any]) -> CandidateOperation:
    message = entry.message
    operation_id = f'{entry.session.session_id}:r:{message.id}'
    if len(operation_id) > OPERATION_ID_MAX:
        raise ArgsInvalid('operation_id')
    tools = entry.session.execution_ref.plan.tools    # RequestEntry → Session → Execution → Plan
    names = frozenset(t['name'] for t in tools)
    if isinstance(resource, DocumentResource):
        body = b'{}'
        target = {'resource_id': resource.resource_id, 'content_identity': resource.content_identity}
        target_bytes = LP(resource.resource_id.encode()) + LP(resource.content_identity.encode()) + \
            LP(str(resource.byte_length).encode())
        credential, prepared = None, resource.blob
    elif isinstance(resource, ModelResource):
        p = resource.provider
        body = _model_body(p, args, tools)
        if len(body) > MODEL_BODY_MAX:
            raise ArgsInvalid('model.body_size')
        target = {'provider_config_id': p.provider_config_id, 'provider_partition_id': p.provider_partition_id}
        target_bytes = b''.join(LP(str(v).encode()) for v in (
            p.provider_config_id, p.scheme, p.host, p.port, p.path, p.ip, p.model_id, p.credential_version_ref,
            p.provider_partition_id))
        credential, prepared = p.credential_version_ref, body
    else:
        raise ArgsInvalid('resource kind')
    parameter = (LP(b'w2-operation') + LP(resource.descriptor_digest.encode()) + LP(resource.resource_id.encode())
                 + LP(message.action.encode()) + LP(target_bytes) + LP(body))
    return CandidateOperation(operation_id, entry, resource, rule, message.action, MappingProxyType(target),
                              target_bytes, parameter, sha256(parameter), body, sha256(body), credential, prepared,
                              names)
