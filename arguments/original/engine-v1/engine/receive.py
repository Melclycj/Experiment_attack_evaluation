"""Receive pipeline of the data channel (conn E-02 每条数据消息的接收管线, engine 内部的 VerifiedContext).

The only path from the socket to a message. One C FrameReader per Channel (transport.c, via FFI) compares
every positive-length fragment, the four header bytes included, with the row's immutable expected uid before
buffering it, and hands Python only a whole body. Python parses that body strictly and builds the message.

receive_step is the only constructor of VerifiedContext. Every label field comes from the Channel it was
invoked on and the Session reached through it, never from the message.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import json
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping, Union

from .ffi import BODY_MAX, Frame, Native
from .loop import Clock
from .objects import Channel, Session
from .startup import ID, PROTOCOL

SAFE_INTEGER = 2 ** 53 - 1
UINT64_MAX = 2 ** 64 - 1
DEPTH_MAX = 16          # nesting levels, the top object included
ELEMENTS_MAX = 4096     # members and array elements over the whole body
DECIMAL = re.compile(r'[1-9][0-9]{0,19}')


class FrameReader:
    """The C FrameReader of one Channel and its fixed, Python-owned body buffer."""

    def __init__(self, native: Native) -> None:
        self.native = native
        self.handle: int | None = native.reader_new()
        self.buffer = ctypes.create_string_buffer(BODY_MAX)

    def receive(self, fd: int, expected: int, overflow: int) -> tuple[Frame, bytes]:
        if self.handle is None:
            raise RuntimeError('FrameReader used after its Channel was retired')
        return self.native.frame_receive(self.handle, self.buffer, fd, expected, overflow)

    def free(self) -> None:
        if self.handle is not None:
            handle, self.handle = self.handle, None
            self.native.reader_free(handle)


# ---- strict parse (conn E-02 step 5 and 接收侧补充) ------------------------------------------
class Invalid(ValueError):
    """The body is not a strict, schema-valid agent message. The argument is a bounded reason code built
    only from fixed strings and schema names, never from the body: a failed frame has no subject and its
    diagnostic carries no agent text."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise Invalid('duplicate_key')
        result[key] = value
    return result


def _constant(name: str) -> Any:
    raise Invalid('constant')


def _float(text: str) -> Any:
    raise Invalid('non_integer')


def _text(value: str) -> None:
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise Invalid('lone_surrogate') from None


def _values(value: Any, depth: int, count: list[int]) -> None:
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > SAFE_INTEGER:
            raise Invalid('integer_range')
        return
    if type(value) is str:
        _text(value)
        return
    if type(value) not in (dict, list):
        raise Invalid('value_type')
    if depth >= DEPTH_MAX:
        raise Invalid('depth')
    count[0] += len(value)
    if count[0] > ELEMENTS_MAX:
        raise Invalid('elements')
    if type(value) is dict:
        for key, item in value.items():
            _text(key)
            _values(item, depth + 1, count)
    else:
        for item in value:
            _values(item, depth + 1, count)


def parse_body(body: bytes) -> dict[str, Any]:
    """Strict UTF-8 first (no BOM): bytes never reach json.loads, which would sniff UTF-16/32."""
    if not 0 < len(body) <= BODY_MAX:
        raise Invalid('body_length')
    if body.startswith(b'\xef\xbb\xbf'):
        raise Invalid('bom')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant,
                           parse_float=_float)
    except Invalid:
        raise   # a hook's own bounded code (duplicate_key, constant, non_integer)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Invalid('json') from None
    if type(value) is not dict:
        raise Invalid('not_object')
    _values(value, 0, [0])
    return value


# ---- schema (conn E-02 数据消息字段、方向与关联) ----------------------------------------------
def _decimal(value: Any) -> bool:
    """Positive uint64 decimal string without leading zeros."""
    return type(value) is str and DECIMAL.fullmatch(value) is not None and int(value) <= UINT64_MAX


def _name(value: Any) -> bool:
    return type(value) is str and ID.fullmatch(value) is not None


def _one_of(*allowed: str) -> Callable[[Any], bool]:
    return lambda value: type(value) is str and value in allowed


def _range(low: int, high: int) -> Callable[[Any], bool]:
    return lambda value: type(value) is int and low <= value <= high


# Agent → engine types only: (required, optional) fields besides v and type. No type carries an identity,
# grant or routing field; any such field is an unknown field and rejects the message.
SCHEMAS: dict[str, tuple[dict[str, Callable[[Any], bool]], dict[str, Callable[[Any], bool]]]] = {
    'hello': ({'protocol': _one_of(PROTOCOL), 'adapter_id': _name}, {}),
    'request': ({'id': _decimal, 'task_call_id': _decimal, 'task_id': _name, 'resource_id': _name,
                 'action': _name, 'args': lambda v: type(v) is dict}, {'timeout_ms': _range(1, 300_000)}),
    'cancel': ({'reply_to': _decimal, 'reason': _one_of('user', 'timeout', 'shutdown')}, {}),
    'task_result': ({'reply_to': _decimal, 'status': _one_of('ok', 'error', 'cancelled'),
                     'output': lambda v: type(v) is str}, {}),
    'bye': ({'reason': _one_of('normal', 'error')}, {}),
}


def validate(body: dict[str, Any]) -> dict[str, Any]:
    kind = body.get('type')
    if type(kind) is not str or kind not in SCHEMAS:
        raise Invalid('type')
    if type(body.get('v')) is not int or body['v'] != 2:
        raise Invalid('version')
    required, optional = SCHEMAS[kind]
    fields = set(body) - {'v', 'type'}
    if not set(required) <= fields or not fields <= set(required) | set(optional):
        raise Invalid(f'{kind}.fields')
    for key, check in (required | optional).items():
        if key in body and not check(body[key]):
            raise Invalid(f'{kind}.{key}')
    return body


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


# ---- messages -------------------------------------------------------------------------------
@dataclass(frozen=True, eq=False)
class VerifiedContext:
    """Sender attribution of one whole frame; not an authorization. session_ref and channel_ref are the objects
    the frame arrived on; every consumer reaches its Session, Execution and writer through them. The request
    binding (request key, TaskCall, TaskBinding, grant, deadline) is resolved by admission through session_ref
    and held by the RequestEntry, never by a lookup on these ids (conn E-02 VerifiedContext; E-03)."""

    execution_id: str
    local_agent_id: str
    session_id: str
    channel_id: str
    receiver_generation: int
    expected_uid: int
    sender_uid: int          # the result of the per-fragment comparison, never a later comparand
    sender_pid: int | None   # first build: C hands over no pid summary, so always None (diagnostic only)
    received_at: int         # engine monotonic ns when C handed over the whole frame
    session_ref: Session
    channel_ref: Channel


@dataclass(frozen=True, eq=False)
class Hello:
    context: VerifiedContext
    adapter_id: str


@dataclass(frozen=True, eq=False)
class Request:
    context: VerifiedContext
    id: str
    task_call_id: str
    task_id: str
    resource_id: str
    action: str
    args: Mapping[str, Any]   # frozen copy of untrusted operation input
    timeout_ms: int | None
    size: int                 # body bytes, for the session's input quota


@dataclass(frozen=True, eq=False)
class Cancel:
    context: VerifiedContext
    reply_to: str
    reason: str


@dataclass(frozen=True, eq=False)
class TaskResult:
    context: VerifiedContext
    reply_to: str
    status: str
    output: str


@dataclass(frozen=True, eq=False)
class Bye:
    context: VerifiedContext
    reason: str


Message = Union[Hello, Request, Cancel, TaskResult, Bye]


@dataclass(frozen=True)
class NeedMore:
    pass


@dataclass(frozen=True)
class Reject:
    cause: str       # 'closed' | 'receive_rejected' | 'invalid' | 'phase'
    detail: str = ''  # a bounded reason code, never agent text


NEED_MORE = NeedMore()


def _message(context: VerifiedContext, body: dict[str, Any], size: int) -> Message:
    kind = body['type']
    if kind == 'hello':
        return Hello(context, body['adapter_id'])
    if kind == 'request':
        return Request(context, body['id'], body['task_call_id'], body['task_id'], body['resource_id'],
                       body['action'], _freeze(body['args']), body.get('timeout_ms'), size)
    if kind == 'cancel':
        return Cancel(context, body['reply_to'], body['reason'])
    if kind == 'task_result':
        return TaskResult(context, body['reply_to'], body['status'], body['output'])
    return Bye(context, body['reason'])


def receive_step(channel: Channel, overflow: int, clock: Clock,
                 phase: Callable[[dict[str, Any]], str | None]) -> NeedMore | Message | Reject:
    """One receive step: at most one recvmsg. Reject means the caller closes the original channel.

    ``phase`` is the caller's direction/phase rule for the current state; it sees the schema-valid body and
    returns a bounded refusal code or None. It runs before any VerifiedContext exists (conn E-02 steps 5–6),
    so a message refused by phase never carries a subject."""
    session, reader = channel.session, channel.frame_reader
    # Pre-read check on Session.admission (CLOSED from close step 1): nothing is read on a closed row.
    if session is None or session.admission != 'OPEN' or reader is None:
        return Reject('closed')
    status, body = reader.receive(channel.owned_fd.fileno(), session.expected_uid, overflow)
    if status is Frame.MORE:
        return NEED_MORE
    if status is Frame.REJECT:
        return Reject('receive_rejected')
    received_at = clock.now_ns()
    try:
        fields = validate(parse_body(body))
    except Invalid as error:
        return Reject('invalid', str(error))
    refused = phase(fields)
    if refused is not None:
        return Reject('phase', refused)
    context = VerifiedContext(session.execution_id, session.local_agent_id, session.session_id,
                              channel.channel_id, channel.receiver_generation, session.expected_uid,
                              session.expected_uid, None, received_at, session, channel)
    return _message(context, fields, len(body))
