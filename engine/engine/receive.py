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
from typing import Any

from .ffi import BODY_MAX, Frame, Native
from .loop import Clock
from .objects import Channel, Session

SAFE_INTEGER = 2 ** 53 - 1
DEPTH_MAX = 16          # nesting levels, the top object included
ELEMENTS_MAX = 4096     # members and array elements over the whole body


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


# ---- message (agent-rm-model 3.9 两条口的先后: the first build's verb set is empty) -----------------
ECHO_MAX = 64   # characters of an id echoed in the reply; the reply must fit one control frame (writer.make_out)


def validate(body: dict[str, Any]) -> dict[str, Any]:
    """The one message definition: a JSON object with a string ``type``. No other field is read; every such message
    is answered 'unsupported_kind' (validation.md K-04)."""
    if type(body.get('type')) is not str:
        raise Invalid('type')
    return body


def _echo(body: dict[str, Any]) -> str | int | None:
    """The message's own id, or reply_to, for the reply; only a short string or an integer, else null."""
    for key in ('id', 'reply_to'):
        value = body.get(key)
        if (type(value) is str and len(value) <= ECHO_MAX) or type(value) is int:
            return value
    return None


@dataclass(frozen=True, eq=False)
class VerifiedContext:
    """Sender attribution of one whole frame; not an authorization. session_ref and channel_ref are the objects
    the frame arrived on; every consumer reaches its Session, Execution and writer through them, never through a
    field of the message (conn E-02 VerifiedContext)."""

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
class Message:
    context: VerifiedContext
    reply_to: str | int | None   # echoed in the reply, never interpreted
    size: int                    # body bytes


@dataclass(frozen=True)
class NeedMore:
    pass


@dataclass(frozen=True)
class Reject:
    cause: str       # 'closed' | 'receive_rejected' | 'invalid'
    detail: str = ''  # a bounded reason code, never agent text


NEED_MORE = NeedMore()


def receive_step(channel: Channel, overflow: int, clock: Clock) -> NeedMore | Message | Reject:
    """One receive step: at most one recvmsg. Reject means the caller closes the original channel."""
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
    context = VerifiedContext(session.execution_id, session.local_agent_id, session.session_id,
                              channel.channel_id, channel.receiver_generation, session.expected_uid,
                              session.expected_uid, None, received_at, session, channel)
    return Message(context, _echo(fields), len(body))
