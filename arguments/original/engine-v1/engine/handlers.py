"""Handlers behind the OperationHandle interface (conn E-03 流接口、序号与背压; rr E-07).

start() accepts only an AuthorizedOperation and its sink; it neither routes, resolves a path nor serialises. Each
pull_one is one demand and yields at most one data event, posted to the loop so it arrives as its own decision.
The sink is bound to the original RequestEntry: a handler cannot name a session, fd or seq. release() posts one
released notice once the handle holds nothing more.

DocumentReadHandler serves the start-up snapshot. StubModelConnector stands in for the chat-tools-sse connector
with E-07's result shapes and completion evidence; it opens no connection and its output is fixed configuration,
not generated text (BUILD-PLAN §1: model call chain is an interface only).
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Callable

from .loop import Loop
from .operations import ArgsInvalid, AuthorizedOperation, check_tool_calls, compact, sha256

CHUNK_MAX = 8192


@dataclass(frozen=True)
class StubConfig:
    text: str = 'stub reply'
    tool_calls: tuple[Any, ...] | None = None   # None: a text reply; else the fixed calls (format-checked)


STUB = StubConfig()


class Handle:
    def __init__(self, loop: Loop, op: AuthorizedOperation, sink: Any) -> None:
        self.loop, self.op, self.sink = loop, op, sink
        self.cancelled = False
        self.done = False
        self.release_requested = False
        self.released = False

    def _post(self, deliver: Callable[[], None]) -> None:
        self.loop.soon(deliver)

    def pull_one(self, max_text_bytes: int = CHUNK_MAX) -> None:
        if self.cancelled or self.done or self.release_requested:
            return
        self._produce(min(max_text_bytes, CHUNK_MAX))

    def _produce(self, limit: int) -> None:
        raise NotImplementedError

    def cancel(self, reason: str) -> None:
        self.cancelled = True     # idempotent; events already posted still arrive and only release

    def release(self) -> None:
        if not self.release_requested:
            self.release_requested = True
            self._post(self._release_done)

    def _release_done(self) -> None:
        """The handle drops its cursor and buffers; only then is released reported (once)."""
        self.op = None            # type: ignore[assignment]
        self.released = True
        self.sink.released()

    def _evidence(self, kind: str, output: bytes, **extra: Any) -> dict[str, Any]:
        return {'operation_id': self.op.candidate.operation_id, 'kind': kind, 'body_hash': self.op.candidate.body_hash,
                'output_digest': sha256(output), 'output_bytes': str(len(output)),
                'observed_at_ns': str(self.loop.clock.now_ns()), **extra}


def _cut(data: bytes, start: int, limit: int) -> int:
    """End of the next chunk: at most ``limit`` bytes, never inside a UTF-8 sequence."""
    end = min(start + limit, len(data))
    while end < len(data) and data[end] & 0xC0 == 0x80:
        end -= 1
    return end


class DocumentReadHandler(Handle):
    def __init__(self, loop: Loop, op: AuthorizedOperation, sink: Any) -> None:
        super().__init__(loop, op, sink)
        self.blob: bytes = op.candidate.prepared
        self.cursor = 0
        self.hasher = hashlib.sha256()

    def _produce(self, limit: int) -> None:
        if self.cursor < len(self.blob):
            end = _cut(self.blob, self.cursor, limit)
            part = self.blob[self.cursor:end]
            self.cursor = end
            self.hasher.update(part)
            text = part.decode('utf-8')
            self._post(lambda: self.sink.chunk(text))
            return
        self.done = True
        resource = self.op.candidate.resource
        if ('sha256:' + self.hasher.hexdigest(), self.cursor) != (resource.content_identity, resource.byte_length):
            self._post(lambda: self.sink.failure('internal_error', None))
            return
        evidence = self._evidence('document_snapshot_delivered', self.blob)
        self._post(lambda: self.sink.complete({}, evidence))

    def _release_done(self) -> None:
        self.blob = b''
        super()._release_done()


class StubModelConnector(Handle):
    def __init__(self, loop: Loop, op: AuthorizedOperation, sink: Any) -> None:
        super().__init__(loop, op, sink)
        self.config = STUB
        self.output = self.config.text.encode()
        self.cursor = 0

    def _produce(self, limit: int) -> None:
        candidate = self.op.candidate
        if len(self.output) > candidate.rule.limits['max_output_bytes']:
            self.done = True
            self._post(lambda: self.sink.failure('upstream_error', None))   # over budget: never a truncated success
            return
        if self.cursor < len(self.output):
            end = _cut(self.output, self.cursor, limit)
            text = self.output[self.cursor:end].decode('utf-8')
            self.cursor = end
            self._post(lambda: self.sink.chunk(text))
            return
        self.done = True
        if self.config.tool_calls is None:
            evidence = self._evidence('model_stream_complete', self.output, finish_reason='stop')
            self._post(lambda: self.sink.complete({}, evidence))
            return
        try:
            calls = check_tool_calls([dict(c) for c in self.config.tool_calls], candidate.tool_names)
        except ArgsInvalid:
            self._post(lambda: self.sink.failure('upstream_error', None))
            return
        data = compact(calls)
        evidence = self._evidence('model_stream_complete', self.output, finish_reason='tool_calls',
                                  tool_calls_digest=sha256(data), tool_calls_bytes=str(len(data)))
        self._post(lambda: self.sink.complete({'tool_calls': calls}, evidence))


HANDLERS: dict[str, type[Handle]] = {'document.read': DocumentReadHandler, 'model.generate': StubModelConnector}


def start(loop: Loop, op: AuthorizedOperation, sink: Any) -> Handle:
    if type(op) is not AuthorizedOperation:
        raise TypeError('handlers start only an AuthorizedOperation')
    return HANDLERS[op.candidate.action](loop, op, sink)
