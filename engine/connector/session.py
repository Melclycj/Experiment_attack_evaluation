"""One accepted proxy connection, one thread (agent-rm-model 4.3 connector 怎样发出, 两条口的先后; SPEC-canonical-form.md
§3.1, §3.2; validation.md C-01 to C-04, C-07, C-13, C-14, C-15, C-22, C-23, C-24, C-27, C-30, C-32).

The thread reads one REQUEST frame (credential-checked by the native reader), validates it through the canonical
grammar, seals the body in a memfd, hands the request to the core under a fresh sequence number, waits for the answer
while watching the client, and then either refuses (DENY, timeout) or performs the one approved exchange and reports it.
It never reads the next frame before the response ended (C-04); a request that does not read ends the connection
without reaching the core (C-05); before the core's allow nothing is resolved or connected (C-32). TCB module: standard
library only.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import os
import select
import socket
import threading
import time
from typing import Any, Callable

from . import canonical
from .canonical import (ALLOW, ALLOW_NOCRED, CAT_REFUSED, DENY, LINK_A_IN, RES_UNSENT, pack_list, u16, u32, u64)
from .channel import Answer, Waiter
from .reader import Closed, FieldsUnreadable, ProxyReader
from .upstream import Exchange, Sink, refusal_body

WAIT_TIMEOUT = 330.0                 # one total limit per request, from the hand-over to the core (C-15; 工程默认)
# the public reason words of a core DENY (648d60f2 4.3 拒绝回复; SPEC 3.2): the finer cause stays in the core's trace
DENY_WORDS = {1: b'recorded_deny', 2: b'user_denied', 3: b'timeout', 4: b'clause', 5: b'unavailable', 6: b'not_authorized',
              7: b'pdp_denied', 8: b'policy_changed', 9: b'credential'}


class Budget:
    """The row's in-flight body bytes (工程项 4: 256 MiB), charged from the frame's declared length (C-07)."""

    def __init__(self, limit: int) -> None:
        self.limit, self.used = limit, 0
        self._lock = threading.Lock()

    def reserve(self, n: int) -> bool:
        with self._lock:
            if self.used + n > self.limit:
                return False
            self.used += n
            return True

    def release(self, n: int) -> None:
        with self._lock:
            self.used -= n


def judge_fields(seq: int, uid: int, req: canonical.Request, body_len: int) -> list[bytes]:
    """The 13 JUDGE fields (SPEC §3.2) for a validated request."""
    items: list[bytes] = []
    for name, value in req.headers:
        items += [name, value]
    return [u64(seq), u32(uid), req.method, req.scheme, req.host, u16(req.port), req.path,
            req.query if req.query is not None else b'', pack_list(items), pack_list(list(req.stripped)),
            req.body_kind.encode('ascii'), pack_list([k.encode('latin-1') for k in req.form_keys]), u64(body_len)]


class Session(threading.Thread):
    def __init__(self, connector: Any, sock: socket.socket) -> None:
        super().__init__(name=f'session-{sock.fileno()}', daemon=True)
        self.c = connector
        self.sock = sock
        self.exchange = Exchange(connector.policy, connector.tls, connector.registry, connector.log,
                                 connector.connect_timeout, connector.read_timeout)

    # ---- lifecycle ----
    def run(self) -> None:
        try:
            self._serve()
        except Closed as e:
            self.c.log('connection_closed', reason=str(e))
        except Exception as e:                                 # never an exception message past this line (C-23)
            self.c.log('connection_error', error=type(e).__name__)
        finally:
            self.exchange.close()
            try:
                self.sock.close()
            except OSError:
                pass
            self.c.session_ended(self)

    def _serve(self) -> None:
        self.sock.settimeout(self.c.read_timeout)             # bounds every write to the client
        reader = ProxyReader(self.c.native, self.sock.fileno(), self.c.uid, self.c.overflow)
        try:
            while not self.c.stopping:
                reserved = 0

                def reserve(n: int) -> bool:
                    nonlocal reserved
                    if not self.c.budget.reserve(n):
                        return False
                    reserved = n
                    return True

                try:                                           # the reservation is released however the frame ends (S2)
                    try:
                        kind, fields = reader.read_frame(LINK_A_IN, reserve, self._readable)
                    except FieldsUnreadable:                   # C-36: whole, so refused like fields that do not parse
                        self._refuse(None, b'clause')
                        raise
                    self._request(fields)
                finally:
                    self.c.budget.release(reserved)
        finally:
            reader.close()

    def _readable(self) -> bool:
        """Wait up to a second for bytes; return to the reader either way, so the native per-frame deadline is judged
        during silence too (a frame left half-sent is refused five seconds after its first fragment; S3)."""
        if self.c.stopping:
            return False
        select.select([self.sock], [], [], 1.0)
        return not self.c.stopping

    # ---- one request ----
    def _request(self, fields: list[bytes]) -> None:
        try:
            req = canonical.parse_request(fields)
        except canonical.Malformed as e:
            # C-36: the frame was whole, its fields do not read: refused with the word clause, then the connection ends
            # (the frame's boundaries were known; one that could not be framed never reaches here)
            self._refuse(None, b'clause')
            raise Closed(f'request does not read: {e}') from e
        if req.is_ip and self.c.policy.never_connect(req.host.decode('ascii')):
            # C-35 (5.3 条款 7): an IP literal is held against the first gate (never connected, named or not) here,
            # before the core, the user or the PDP see it; another non-global literal goes to the core, whose first
            # checkpoint looks for a name (K-58), and both gates are asked again before connecting (C-19). A host name
            # is resolved only after the allow (C-32)
            self._refuse(req, b'clause')
            raise Closed('IP literal refused at validation (条款 7)')
        if req.is_ip and any(ipaddress.ip_address(req.host.decode('ascii')) in p for p in self.c.policy.nat64):
            # C-35: a literal under a deployer's NAT64 prefix is refused as the grammar refuses 64:ff9b::/96, so the core
            # never judges as written what the connector judges by the IPv4 address it embeds
            self._refuse(req, b'clause')
            raise Closed('NAT64 configured-prefix literal; write the IPv4 address (条款 7)')
        fields.clear()                                         # the caller's reference too: the body lives on only in the memfd
        body_len = len(req.body)
        memfd = canonical.seal_body(req.body)
        req = dataclasses.replace(req, body=b'')               # (review B, OM4)
        deadline = time.monotonic() + WAIT_TIMEOUT             # C-15: the one total limit runs from the hand-over
        try:
            waiter = self.c.channel.submit(lambda seq: judge_fields(seq, self.c.uid, req, body_len), memfd)
            seq = waiter.seq
            try:
                answer, state = self._await(waiter, deadline)
            finally:
                self.c.channel.unregister(waiter)
                waiter.close()
            if state == 'gone':
                if answer is not None:
                    answer.zero()
                    if answer.kind in (ALLOW, ALLOW_NOCRED):   # C-14: approved after the client left: not sent
                        self.c.channel.report(seq, RES_UNSENT, 0)
                raise Closed('client gone while waiting')
            if answer is None:                                 # timed out: withdrawn, refused
                self._refuse(req, b'timeout')
                return
            if answer.kind == DENY:
                self._refuse(req, DENY_WORDS.get(answer.reason, b'denied'))
                return
            sink = Sink(self.sock.sendall, self._hung_up)
            result, status = self.exchange.run(req, answer, memfd, body_len, sink)
            self.c.channel.report(seq, result, status)        # C-27: one report per approved request
            if sink.client_gone:
                raise Closed('client gone during the response')
        finally:
            os.close(memfd)

    def _await(self, waiter: Waiter, deadline: float) -> tuple[Answer | None, str]:
        """Wait for the core while watching the client, until ``deadline``: ('answered' | 'gone' | 'timeout'). Bytes the
        client sends before the response are left unread (C-04), so its departure is watched as a hang-up (POLLRDHUP),
        which the kernel reports even with unread bytes queued; a hang-up seen together with an answer counts first
        (C-14, C-15; S4). An answer taken at or after the deadline, or while the connector stops, is late: zeroed, an
        allow reported unsent, and the request refused as timed out (C-15)."""
        poller = select.poll()
        poller.register(waiter.r, select.POLLIN)
        poller.register(self.sock, select.POLLRDHUP)           # POLLHUP and POLLERR are reported regardless
        hangup = select.POLLRDHUP | select.POLLHUP | select.POLLERR
        while not self.c.stopping:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            events = dict(poller.poll(int(min(remaining, 1.0) * 1000)))
            if events.get(self.sock.fileno(), 0) & hangup:
                answer = self.c.channel.unregister(waiter)
                if answer is None:
                    self.c.channel.withdraw(waiter.seq)
                return answer, 'gone'
            if events.get(waiter.r, 0) & select.POLLIN:
                os.read(waiter.r, 1)
                if time.monotonic() < deadline:
                    return waiter.take(), 'answered'
                break
        answer = self.c.channel.unregister(waiter)
        if answer is None:
            self.c.channel.withdraw(waiter.seq)
        else:
            answer.zero()
            if answer.kind in (ALLOW, ALLOW_NOCRED):         # C-14: approved too late: not sent
                self.c.channel.report(waiter.seq, RES_UNSENT, 0)
        return None, 'timeout'

    def _hung_up(self) -> bool:
        """Whether the client has left, asked without waiting and without reading: the hang-up _await watches for, which
        the kernel reports even with the next request's bytes queued unread (C-04)."""
        poller = select.poll()
        poller.register(self.sock, select.POLLRDHUP)           # POLLHUP and POLLERR are reported regardless
        return any(events & (select.POLLRDHUP | select.POLLHUP | select.POLLERR) for _, events in poller.poll(0))

    def _refuse(self, req: canonical.Request | None, word: bytes) -> None:
        sink = Sink(self.sock.sendall)
        sink.head(CAT_REFUSED, 0, [(b'x-engine-reason', word)])
        sink.chunk(refusal_body(req, word))
        sink.end()
        if sink.client_gone:
            raise Closed('client gone')
