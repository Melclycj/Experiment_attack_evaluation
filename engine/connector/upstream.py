"""Upstream side of the connector (agent-rm-model 4.3 connector 怎样发出 and 凭据; 5.3 条款 1, 3, 4, 6, 7, 8, 10;
6.2 不转发字节行; validation.md C-09, C-11, C-16 to C-26, C-29, C-30, C-33, C-35 to C-37).

Pure functions and small classes over the approved Request object: name resolution and the two gates of 条款 7 over
the whole address list at connect time (never-connect ranges, the deny set, the host's own addresses; then global
reachability or the ALLOW's named list), asked again of a kept connection's peer before reuse, the TLS context (TLS
1.2 or later, system or configured trust, hostname checked), the credential placed at exactly the position the core
named (条款 4, 9; only replaced, never added), the request serialised by http.client with Host and Content-Length
owned here (条款 1, 3), the response read back with read1 so that chunked and SSE bodies stream, 3xx returned as they
are (条款 6), framing headers and, for an account destination, Set-Cookie dropped, a token response withheld by its
body (条款 10, judged in token_response.py; a POST goes out with Accept-Encoding: identity, a JSON or form response
to it is held up to 64 KiB before it is judged), connections kept per fd thread and per (host, port, account)
(条款 8) in a row-wide registry that revocation cuts. Every failure after the credential was placed is a fixed
category, never an exception message (C-23). TCB module: standard library only.
"""
from __future__ import annotations

import email.errors
import errno
import fcntl
import http.client
import ipaddress
import os
import re
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from . import canonical
from .canonical import (ALLOW, CAT_REFUSED, CAT_REMOTE, CAT_TRANSPORT, CAT_UNKNOWN, PLACE_API_KEY, PLACE_BASIC,
                        PLACE_BEARER, RES_REMOTE, RES_TRANSPORT, RES_UNKNOWN, RES_UNSENT, Request)
from .channel import Answer
from .token_response import TOKEN_LIMIT, token_body, token_candidate, unreadable

CONNECT_TIMEOUT = 30.0                    # 工程项 14
READ_TIMEOUT = 600.0
CHUNK = 65536
NAT64_WKP = ipaddress.ip_network('64:ff9b::/96')
SIOCGIFADDR = 0x8915
BODY_METHODS = frozenset({b'POST', b'PUT', b'PATCH'})     # Content-Length is sent for these even when the body is empty
FRAMING = frozenset({b'transfer-encoding', b'content-length', b'connection', b'keep-alive', b'te', b'trailer', b'upgrade'})
COOKIES = frozenset({b'set-cookie', b'set-cookie2'})
OBS_FOLD = re.compile(rb'\r?\n[ \t]*')                 # RFC 9112 §5.2: obs-fold is replaced by one space
BODY_STRUCTURE_DEFECTS = (email.errors.StartBoundaryNotFoundDefect, email.errors.CloseBoundaryNotFoundDefect,
                          email.errors.MultipartInvariantViolationDefect, email.errors.NoBoundaryInMultipartDefect)
B64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Named = tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]      # an ALLOW's named prefixes (Answer.named, K-59)


class Refused(Exception):
    """The connector itself refuses to send: the result is a refusal to the frontend and 'not sent' to the core. The
    message stays in the connector's own log; the frontend gets the fixed word of ``REFUSED_WORDS``."""


# ---- the refusal reply (648d60f2 4.3 拒绝回复; K-51, C-23, C-36, F-06) ------------------------------------------------------
# The connector's own refusals in the fixed words: an address that meets gate one of 条款 7 and plain http are clauses
# (条款 7, 4); a non-global address the covering cell does not name is not authorized (C-19, C-36); a registered
# placement missing from the request is a credential refusal.
REFUSED_WORDS = {'address': b'clause', 'address_not_named': b'not_authorized', 'plaintext': b'clause',
                 'the named placement is not in the request': b'credential'}
NEXT_STEP = {
    b'not_authorized': b'No entry in this workspace covers this request, or the entry that covers it does not name the '
                       b'private address it goes to. Ask the user to add or widen an entry, or to name the address on the '
                       b"exact entry, in the engine's management client.",
    b'recorded_deny': b'The user recorded a deny that covers this request. Do not retry.',
    b'user_denied': b'The user denied this request. Do not retry.',
    b'pdp_denied': b'The policy decision point denied this request. Do not retry.',
    b'policy_changed': b'The table or a credential record changed while this request waited. You may retry.',
    b'clause': b"The request breaks one of the engine's fixed rules. Rewrite the request; widening an entry does not help.",
    b'credential': b'The request carries a credential header and no usable credential record exists for it. Ask the user '
                   b'to register one, or send the request without the header.',
    b'timeout': b'The request waited too long for an answer. You may retry.',
    b'unavailable': b'The engine could not take the request now: the row is closing, its queue is full, the policy '
                    b'decision point is gone, or the record path failed.',
    b'response_withheld': b'The request was sent and may have taken effect; its response was withheld because it carried a '
                          b'new credential. Do not retry blindly.',
    b'transport_error': b'The request could not be sent upstream. It had no effect; you may retry.',
    b'result_unknown': b'The request was sent upstream, but its result is not known. It may have taken effect; do not '
                       b'retry blindly.',
}


def refusal_body(req: Request | None, word: bytes) -> bytes:
    """The fixed template: the request's own method, destination and path (none for a request that does not read), the
    reason word and its next step. Nothing else of the table, the records or the upstream (648d60f2 4.3)."""
    what = describe(req) if req is not None else b'a request that does not read'
    return (b'engine refused ' + what + b'\nreason: ' + word + b'\n' + NEXT_STEP.get(word, b'') + b'\n')


# ---- 条款 7: the address filter, two gates (C-19, C-35, C-37) -------------------------------------------------------------
NAT64_PREFIX_LENGTHS = (32, 40, 48, 56, 64, 96)        # RFC 6052 §2.2


def embedded_ipv4(addr: ipaddress.IPv6Address, prefix: ipaddress.IPv6Network) -> ipaddress.IPv4Address:
    """RFC 6052 §2.2: the IPv4 address embedded under a NAT64 prefix of length 32, 40, 48, 56, 64 or 96; bits 64–71
    ('u') are skipped, the suffix is ignored."""
    bits, n = int(addr), prefix.prefixlen
    if n == 96:
        v4 = bits & 0xFFFFFFFF
    elif n == 64:
        v4 = (bits >> 24) & 0xFFFFFFFF                        # bits 72..103
    elif n == 32:
        v4 = (bits >> 64) & 0xFFFFFFFF                        # bits 32..63
    else:                                                     # 40, 48, 56: split around the u byte
        high_bits = 64 - n
        high = (bits >> 64) & ((1 << high_bits) - 1)          # bits n..63
        low_bits = 32 - high_bits
        low = (bits >> (128 - 72 - low_bits)) & ((1 << low_bits) - 1)   # bits 72..72+low_bits-1
        v4 = (high << low_bits) | low
    return ipaddress.IPv4Address(v4)


def judged_address(addr: IPAddress, nat64: tuple[ipaddress.IPv6Network, ...]) -> IPAddress:
    """The address the global-reachability question is asked about: an IPv4-mapped or NAT64 IPv6 address is judged by
    the IPv4 address it embeds (6.2 全局可达行; 条款 7)."""
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        for prefix in (NAT64_WKP, *nat64):
            if addr in prefix:
                return embedded_ipv4(addr, prefix)
    return addr


def first_gate(original: IPAddress, judged: IPAddress, denied: frozenset[IPAddress]) -> bool:
    """Gate one of 条款 7 (C-19): never connected, whatever the ALLOW names. Both the address the socket would connect
    to and the address it stands for are held against the built-in ranges (canonical.NEVER_CONNECT: link-local,
    loopback, unspecified, ::/96, and, an engineering addition, multicast and the limited broadcast) and the deny set
    (the deployer's list and the host's interface addresses), so no spelling gets past it."""
    return any(a in denied or any(a in r for r in canonical.NEVER_CONNECT) for a in (original, judged))


def address_refusal(text: str, denied: frozenset[IPAddress], nat64: tuple[ipaddress.IPv6Network, ...],
                    named: Named = ()) -> bytes | None:
    """One address through both gates of 条款 7 (C-19), the per-connection local probe aside: b'clause' when gate one
    refuses it (or it does not read); else None when the judged address is globally reachable (is_global follows the
    two IANA special-purpose registries) or lies in the ALLOW's named list, b'not_authorized' when it does not."""
    try:
        original = ipaddress.ip_address(text)
    except ValueError:
        return b'clause'
    judged = judged_address(original, nat64)
    if first_gate(original, judged, denied):
        return b'clause'
    return None if judged.is_global or any(judged in net for net in named) else b'not_authorized'


def address_allowed(text: str, denied: frozenset[IPAddress], nat64: tuple[ipaddress.IPv6Network, ...],
                    named: Named = ()) -> bool:
    return address_refusal(text, denied, nat64, named) is None


def interface_addresses() -> set[IPAddress]:
    """Every address on the host's interfaces (条款 7: the connector never connects to the host itself)."""
    out: set[IPAddress] = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _, name in socket.if_nameindex():
            try:
                packed = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', name.encode()[:15]))
            except OSError:
                continue
            out.add(ipaddress.IPv4Address(packed[20:24]))
    try:
        for line in Path('/proc/net/if_inet6').read_text().splitlines():
            out.add(ipaddress.IPv6Address(bytes.fromhex(line.split()[0])))
    except (OSError, ValueError, IndexError):
        pass
    return out


def getaddrinfo(host: str, port: int) -> list[str]:
    seen: dict[str, None] = {}
    for _, _, _, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        seen[str(sockaddr[0])] = None
    return list(seen)


class Policy:
    """What the connector consults before it connects: the resolver and the two gates of 条款 7. Tests supply an object
    with the same methods (resolve, refusal, allowed, never_connect) and nat64, the configured prefixes (a literal under
    one is refused at validation, C-35); nothing else in the connector decides about addresses."""

    def __init__(self, denied: Iterable[str] = (), nat64: Iterable[str] = (),
                 resolver: Callable[[str, int], list[str]] = getaddrinfo, include_interfaces: bool = True) -> None:
        addresses = {ipaddress.ip_address(a) for a in denied}
        if include_interfaces:
            addresses |= interface_addresses()
        self.denied = frozenset(addresses)
        self.nat64 = tuple(ipaddress.ip_network(p) for p in nat64)
        if any(n.version != 6 or n.prefixlen not in NAT64_PREFIX_LENGTHS for n in self.nat64):
            raise ValueError('a NAT64 prefix is an IPv6 /32, /40, /48, /56, /64 or /96 (RFC 6052)')
        self._resolver = resolver

    def resolve(self, host: bytes, is_ip: bool, port: int) -> list[str]:
        if is_ip:
            return [host.decode('ascii')]
        return self._resolver(host.decode('ascii'), port)

    def _word(self, address: str, named: Named) -> bytes | None:
        """One address through both gates. Beside the filter, gate one probes the address and the one it embeds for
        being this host's own at this moment (条款 7; review B, OS8; NB3)."""
        word = address_refusal(address, self.denied, self.nat64, named)
        if word != b'clause' and (is_local_address(address) or
                                  is_local_address(str(judged_address(ipaddress.ip_address(address), self.nat64)))):
            return b'clause'
        return word

    def refusal(self, addresses: list[str], named: Named = ()) -> bytes | None:
        """Reading one (C-19): every address of the resolution list passes both gates, or the whole request is refused
        and nothing is connected. The word: clause when any address meets gate one (alone or beside unnamed ones),
        not_authorized when the only failures are non-global addresses the named list does not hold. An empty list
        connects nowhere and keeps the word the address check always gave, clause."""
        if not addresses:
            return b'clause'
        words = {self._word(a, named) for a in addresses}
        return b'clause' if b'clause' in words else b'not_authorized' if b'not_authorized' in words else None

    def allowed(self, addresses: list[str], named: Named = ()) -> bool:
        return self.refusal(addresses, named) is None

    def never_connect(self, address: str) -> bool:
        """Gate one alone, for an IP literal at validation (C-35): whether it is never connected, named or not."""
        return self._word(address, ()) == b'clause'


def is_local_address(text: str) -> bool:
    """Whether ``text`` is an address of this host right now, secondary and later-added addresses included: an
    unconnected UDP socket connected to it is given that very address as its source (no packet is sent). A probe that
    cannot be made counts as this host's (C-19, fail closed), save for an address family the host does not support;
    a connect() that fails (no route) means it is not."""
    family = socket.AF_INET6 if ':' in text else socket.AF_INET
    try:
        probe = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as e:  # no descriptor (EMFILE, ENFILE, ENOBUFS): unprobed, a later-added local address would pass
        # EAFNOSUPPORT: the host holds no address of that family and cannot make a TCP socket of it either: not local
        return e.errno != errno.EAFNOSUPPORT
    try:
        with probe:
            probe.connect((text, 9))
            return probe.getsockname()[0].split('%', 1)[0] == text
    except OSError:
        return False


# ---- TLS (C-20) ----------------------------------------------------------------------------------------------------------
def tls_context(ca_file: str | None = None) -> ssl.SSLContext:
    """ssl.create_default_context verifies the chain and the hostname; the minimum version is pinned here because the
    3.12.3 default context reports MINIMUM_SUPPORTED (0.1 实测)."""
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(['http/1.1'])
    return ctx


# ---- the credential placed (C-16, C-17, C-29) ------------------------------------------------------------------------------
def b64_into(data: bytearray) -> bytearray:
    """Standard base64 of a bytearray into a bytearray allocated once at its final size, so the Basic value never
    passes through an immutable copy or a reallocation that leaves an old block behind (OM3)."""
    n = len(data)
    out = bytearray(4 * ((n + 2) // 3))
    o = 0
    for i in range(0, n, 3):
        b0, b1, b2 = data[i], data[i + 1] if i + 1 < n else 0, data[i + 2] if i + 2 < n else 0
        out[o] = B64[b0 >> 2]
        out[o + 1] = B64[((b0 & 3) << 4) | (b1 >> 4)]
        out[o + 2] = B64[((b1 & 15) << 2) | (b2 >> 6)] if i + 1 < n else 0x3D
        out[o + 3] = B64[b2 & 63] if i + 2 < n else 0x3D
        o += 4
    return out


def joined(*parts: bytes | bytearray) -> bytearray:
    """Concatenation into one bytearray of the final size: no intermediate copies of a part that holds truth (OM3)."""
    out = bytearray(sum(len(p) for p in parts))
    at = 0
    for p in parts:
        out[at:at + len(p)] = p
        at += len(p)
    return out


def header_value(answer: Answer) -> bytearray:
    """The whole header value built from the registered credential, nothing taken from the request (648d60f2 4.3 凭据,
    5.4; C-16): x-api-key is the truth; authorization is the registered word, a space and the truth; Basic is "Basic "
    and base64 of the registered user and password. Built in bytearrays of their final size (OM3)."""
    truth = answer.truth or bytearray()
    if answer.placement == PLACE_API_KEY:
        return joined(truth)
    if answer.placement == PLACE_BEARER:
        return joined(answer.word, b' ', truth)
    plain = joined(truth, b':', answer.truth_b or bytearray())
    encoded = b64_into(plain)
    plain[:] = bytes(len(plain))
    value = joined(b'Basic ', encoded)
    encoded[:] = bytes(len(encoded))
    return value


def placed_headers(headers: tuple[tuple[bytes, bytes], ...], answer: Answer) -> list[tuple[bytes, bytes | bytearray]]:
    """The request's headers with the engine's value at the one header the registered placement names; everything else
    byte for byte, a second header of the other placement included. Values that hold the truth are bytearrays for the
    caller to zero. An answer without a credential changes nothing; a placement the request does not carry is refused,
    never added (only replaced)."""
    if answer.kind != ALLOW or answer.truth is None:
        return list(headers)
    name_of = b'x-api-key' if answer.placement == PLACE_API_KEY else b'authorization'
    out: list[tuple[bytes, bytes | bytearray]] = []
    done = False
    for name, value in headers:
        if not done and name == name_of:
            out.append((name, header_value(answer)))
            done = True
        else:
            out.append((name, value))
    if not done:
        raise Refused('the named placement is not in the request')     # only replaced, never added
    return out


def zero_values(headers: list[tuple[bytes, bytes | bytearray]]) -> None:
    for _, value in headers:
        if isinstance(value, bytearray):
            value[:] = bytes(len(value))


# ---- serialisation (条款 1, 3; C-09, C-11, C-30) -------------------------------------------------------------------------------
def host_header(req: Request) -> bytes:
    default = 443 if req.scheme == b'https' else 80
    host = b'[' + req.host + b']' if req.is_ip and b':' in req.host else req.host
    return host if req.port == default else host + b':%d' % req.port


def request_target(req: Request) -> str:
    return (req.path + (b'?' + req.query if req.query is not None else b'')).decode('ascii')


# ---- the response (条款 6, 10; C-18, C-24, C-25, C-33) ------------------------------------------------------------------------
class Malformed(Exception):
    """The upstream's response head does not read as HTTP (C-33): it is a failure category, never relayed."""


def response_headers(raw: list[tuple[str, str]], strip_cookies: bool, defects: list | None = None) -> list[tuple[bytes, bytes]]:
    """Header pairs for the RESP_HEAD frame: names lower-case, obs-fold unfolded, framing headers (the frontend frames
    the body again), Proxy-* and, for an account destination, Set-Cookie dropped. The standard-library parser is
    permissive, so the result is held to the field grammar here: a parser defect, a name that is not a token or a value
    with a byte outside VCHAR / obs-text / SP / HTAB after unfolding is Malformed."""
    if any(not isinstance(d, BODY_STRUCTURE_DEFECTS) for d in defects or ()):
        raise Malformed('response head has a parser defect')        # header defects only: a multipart head without its
    # body is reported by the email parser as a boundary defect, which says nothing about the headers (review B recheck)
    out: list[tuple[bytes, bytes]] = []
    for name, value in raw:
        lowered = name.encode('latin-1').lower()
        if not 1 <= len(lowered) <= canonical.LIMITS.header_name or any(c not in canonical.LOWER_TCHAR for c in lowered):
            raise Malformed('response header name is not a token')
        unfolded = OBS_FOLD.sub(b' ', value.encode('latin-1'))
        if any(not (0x21 <= c <= 0x7E or c >= 0x80 or c in (0x20, 0x09)) for c in unfolded):
            raise Malformed('response header value has a control byte')   # checked before trimming (NS2)
        unfolded = unfolded.strip(b' \t')                                   # only HTTP whitespace is trimmed
        if lowered in FRAMING or lowered.startswith((b'proxy-', b'x-engine-')) or (strip_cookies and lowered in COOKIES):
            continue                                           # x-engine-*: the connector's own words, never the upstream's (OM5)
        out.append((lowered, unfolded))
    return out


# ---- connections (条款 8; C-21, C-26) -------------------------------------------------------------------------------------------
def key_covers(key_kind: int, key: bytes, host: bytes, port: int) -> bool:
    """Which destinations a REVOKE key names: exact host:port, pattern .suffix:port, or every destination."""
    if key_kind == 1:
        return key == host + b':%d' % port
    if key_kind == 2:
        suffix, _, key_port = key.rpartition(b':')
        return key_port.isdigit() and int(key_port) == port and host.endswith(b'.' + suffix) and len(host) > len(suffix) + 1
    return key_kind == 3


@dataclass(eq=False)
class Link:
    """One upstream connection: who it is for, the http.client object that speaks on it, the socket to cut, and the
    address it connected to (judged again before every reuse, C-37)."""

    host: bytes
    port: int
    scheme: bytes
    account: bytes
    conn: http.client.HTTPConnection
    sock: socket.socket
    handle: socket.socket              # a dup of the same socket, owned here alone: the cut goes through it (see cut)
    peer: str = ''                     # the address text connect() was given
    dead: bool = False                 # cut by a REVOKE or a failure: never reused, a body read on it is a cut body

    @property
    def key(self) -> tuple[bytes, int, bytes, bytes]:
        return self.host, self.port, self.scheme, self.account

    def cut(self) -> None:
        """Shut the transport down from any thread, through the link's own dup of the descriptor. Not SSLSocket.shutdown:
        that first drops its TLS object, after which a send or recv racing on another thread would go to the bare socket
        (truth in clear, ciphertext relayed as body; review B, OB2). Not the fd http.client holds either: the library
        closes it by itself at the end of a Connection: close response, and a number closed and reused under a racing
        shutdown would cut a stranger (review B recheck, Opus 6). The dup is closed only by close(), under the registry
        lock, so its number cannot be reused while a revoke runs."""
        self.dead = True
        try:
            self.handle.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def close(self) -> None:
        self.cut()
        for closing in (self.conn.close, self.handle.close):
            try:
                closing()
            except OSError:
                pass


class Registry:
    """Every live upstream connection of this row, in use or idle, so that a REVOKE cuts all of them (C-26)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._links: set[Link] = set()

    def add(self, link: Link) -> None:
        with self._lock:
            self._links.add(link)

    def remove(self, link: Link) -> None:
        with self._lock:
            self._links.discard(link)

    def revoke(self, key_kind: int, key: bytes, account: bytes, everyone: bool = False) -> int:
        """Cut the connections of one account under the key, or with ``everyone`` every connection under it."""
        with self._lock:                                   # cut under the lock: a link cannot be closed (and its fd number
            hits = [l for l in self._links if (everyone or l.account == account) and key_covers(key_kind, key, l.host, l.port)]
            for link in hits:                              # reused) while it is being shut down, since _drop removes it
                link.cut()                                 # under the same lock before closing (review B recheck, minor 6)
        return len(hits)

    def __len__(self) -> int:
        with self._lock:
            return len(self._links)


# ---- one exchange (C-22, C-30) -----------------------------------------------------------------------------------------------------
class Sink:
    """Where the response frames go: the fd thread's client socket. Writes after the client is gone are dropped.
    ``hung_up``, given by the session, tells whether the client has left without reading a byte of it: the hold, which
    writes nothing, asks it where the relay would have learnt it from a failed write."""

    def __init__(self, write: Callable[[bytes], None], hung_up: Callable[[], bool] | None = None) -> None:
        self._write = write
        self._hung_up = hung_up
        self.client_gone = False
        self.head_sent = False

    def gone(self) -> bool:
        if not self.client_gone and self._hung_up is not None and self._hung_up():
            self.client_gone = True
        return self.client_gone

    def _send(self, frame: bytes) -> None:
        if self.client_gone:
            return
        try:
            self._write(frame)
        except OSError:
            self.client_gone = True

    def head(self, category: int, status: int, headers: list[tuple[bytes, bytes]]) -> None:
        items: list[bytes] = []
        for name, value in headers:
            items += [name, value]
        self.head_sent = True
        self._send(canonical.pack_frame(canonical.RESP_HEAD, [u8(category), canonical.u16(status), canonical.pack_list(items)]))

    def chunk(self, data: bytes) -> None:
        self._send(canonical.pack_frame(canonical.RESP_CHUNK, [data]))

    def end(self) -> None:
        self._send(canonical.pack_frame(canonical.RESP_END, []))


u8 = canonical.u8


class Exchange:
    """The upstream exchanges of one fd thread. ``links`` are the idle connections it keeps (reused only after their
    response was read to the end); the registry sees them all."""

    def __init__(self, policy: Policy, tls: ssl.SSLContext, registry: Registry, log: Callable[..., None],
                 connect_timeout: float = CONNECT_TIMEOUT, read_timeout: float = READ_TIMEOUT) -> None:
        self.policy, self.tls, self.registry, self.log = policy, tls, registry, log
        self.connect_timeout, self.read_timeout = connect_timeout, read_timeout
        self.links: dict[tuple[bytes, int, bytes, bytes], Link] = {}

    def close(self) -> None:
        for link in self.links.values():
            self.registry.remove(link)
            link.close()
        self.links.clear()

    def _connect(self, req: Request, named: Named, account: bytes) -> Link:
        """Resolve and judge the whole list at the moment of connecting, against both gates of 条款 7 and this request's
        named list (C-19, reading one: any failure refuses the request and nothing is tried); then, under one connect
        deadline that the later judgements spend too (工程项 14: 30 s; review B, OM6), each address judged again before
        its connect, TCP connect, the connected peer judged once more before any byte, the TLS handshake; then the read
        timeout for the rest of the connection's life."""
        addresses = self.policy.resolve(req.host, req.is_ip, req.port)
        word = self.policy.refusal(addresses, named)
        if word is not None:
            raise Refused('address_not_named' if word == b'not_authorized' else 'address')
        host_text = req.host.decode('ascii')
        deadline = time.monotonic() + self.connect_timeout
        sock: socket.socket | None = None
        peer = ''
        for address in addresses:                              # all of them passed both gates; the first that answers
            word = self.policy.refusal([address], named)       # 条款 7 (C-19): judged again right before its connect,
            if word is not None:                               # it may have become this host's since: the whole request
                raise Refused('address_not_named' if word == b'not_authorized' else 'address')     # is refused
            remaining = deadline - time.monotonic()            # after the judgement: its time is the deadline's (C-20)
            if remaining <= 0:
                break
            family = socket.AF_INET6 if ':' in address else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                sock.settimeout(remaining)
                sock.connect((address, req.port))
                peer = address
                break
            except OSError:
                sock.close()
                sock = None
        if sock is None:
            raise OSError('no address answered within the connect deadline')
        try:   # every SYN the kernel resends is routed anew, so the address may have become this host's while connect()
            word = self.policy.refusal([peer], named)          # waited: the peer (for TCP, the address connect() was
            if word is not None:                               # given) is judged again before any byte, TLS included
                raise Refused('address_not_named' if word == b'not_authorized' else 'address')
            sock.settimeout(max(deadline - time.monotonic(), 0.001))
            if req.scheme == b'https':                         # chain and hostname checked here (条款 4); a ragged EOF
                sock = self.tls.wrap_socket(sock, server_hostname=host_text, suppress_ragged_eofs=False)   # is an error
            sock.settimeout(self.read_timeout)
        except BaseException:
            sock.close()
            raise
        conn = http.client.HTTPConnection(host_text, req.port)
        conn.sock = sock
        conn.auto_open = 0                                     # never let http.client connect by itself (review B, OM2)
        handle = socket.socket(fileno=os.dup(sock.fileno()))   # the cut's own descriptor (see Link.cut)
        link = Link(req.host, req.port, req.scheme, account, conn, sock, handle, peer)
        self.registry.add(link)
        return link

    def _drop(self, link: Link | None) -> None:
        if link is not None:
            self.registry.remove(link)                     # out of the registry first, then closed (see Registry.revoke)
            link.close()

    def run(self, req: Request, answer: Answer, memfd: int, body_len: int, sink: Sink) -> tuple[int, int]:
        """Send the approved request once and relay the response. Returns the REPORT (result, status)."""
        account = answer.account if answer.kind == ALLOW else b''
        key = (req.host, req.port, req.scheme, account)
        link = self.links.pop(key, None)
        # cut while idle (REVOKE, OM1), or its peer fails this request's gates (C-37: judged again against this ALLOW's
        # named list): dropped with nothing written on it, and the request takes the fresh path (resolve, judge, connect)
        if link is not None and (link.dead or self.policy.refusal([link.peer], answer.named) is not None):
            self._drop(link)
            link = None
        headers: list[tuple[bytes, bytes | bytearray]] = []
        phase = 'connect'
        try:
            try:
                if answer.kind == ALLOW and req.scheme != b'https':
                    raise Refused('plaintext')                 # 条款 4: a truth never travels over http (C-17)
                if link is None:
                    link = self._connect(req, answer.named, account)
                headers = placed_headers(req.headers, answer)
                conn = link.conn
                conn.putrequest(req.method.decode('ascii'), request_target(req), skip_host=True, skip_accept_encoding=True)
                conn.putheader('Host', host_header(req))
                if body_len or req.method in BODY_METHODS:
                    conn.putheader('Content-Length', str(body_len))
                post = req.method.upper() == b'POST'           # 条款 10 (C-25): the response to a POST comes back
                if post:                                       # uncoded, so a token response can be read; the
                    conn.putheader('Accept-Encoding', 'identity')   # agent's accept-encoding is not sent
                for name, value in headers:
                    if not (post and name == b'accept-encoding'):
                        conn.putheader(name, value)
                phase = 'sending'
                conn.endheaders()
                offset = 0
                while offset < body_len:
                    piece = os.pread(memfd, min(CHUNK, body_len - offset), offset)
                    if not piece:
                        raise OSError('body short')
                    conn.send(piece)
                    offset += len(piece)
                resp = conn.getresponse()
                phase = 'response'
            finally:
                zero_values(headers)
                answer.zero()
        except Refused as e:
            self._drop(link)
            self.log('request_refused', why=str(e))
            word = REFUSED_WORDS.get(str(e), b'clause')
            sink.head(CAT_REFUSED, 0, [(b'x-engine-reason', word)])
            sink.chunk(refusal_body(req, word))
            sink.end()
            return RES_UNSENT, 0
        except Exception as e:                                 # only the category leaves here, never the message (C-23)
            self._drop(link)
            category, result = (CAT_TRANSPORT, RES_TRANSPORT) if phase == 'connect' else (CAT_UNKNOWN, RES_UNKNOWN)
            self.log('upstream_failure', phase=phase, category=category, error=type(e).__name__)
            word = b'transport_error' if category == CAT_TRANSPORT else b'result_unknown'
            sink.head(category, 0, [(b'x-engine-reason', word)])
            sink.chunk(refusal_body(req, word))
            sink.end()
            return result, 0
        return self._relay(req, answer, link, resp, sink)

    def _withhold(self, req: Request, link: Link, sink: Sink, status: int, why: str) -> tuple[int, int]:
        """条款 10: the response does not enter the cell; the connection, with whatever of it is unread, is dropped."""
        self._drop(link)
        self.log('token_response_withheld', status=status, why=why)
        sink.head(CAT_REFUSED, 0, [(b'x-engine-reason', b'response_withheld')])   # 648d60f2 4.3: sent, may have acted
        sink.chunk(refusal_body(req, b'response_withheld'))
        sink.end()
        return RES_REMOTE, status

    def _hold(self, resp: http.client.HTTPResponse, link: Link, sink: Sink) -> tuple[bytes, bool] | None:
        """A candidate's body read, before any of it leaves, up to one byte past TOKEN_LIMIT or to its end: the bytes and
        whether the body ended. None when it was cut meanwhile, as the relay loop would see a cut: a REVOKE, a failed
        read, an early EOF under a known Content-Length, or the client gone (asked after every piece, as the relay
        learns it at every write; Codex review 2026-11-04). A part is never judged."""
        parts: list[bytes] = []
        size = 0
        try:
            while size <= TOKEN_LIMIT:
                piece = resp.read1(TOKEN_LIMIT + 1 - size)
                if link.dead or sink.gone():
                    return None
                if not piece:
                    return None if resp.length is not None and resp.length > 0 else (b''.join(parts), True)
                parts.append(piece)
                size += len(piece)
        except Exception as e:                                 # cut, timed out or malformed while held
            self.log('upstream_body_failure', error=type(e).__name__)
            return None
        return b''.join(parts), False

    def _relay(self, req: Request, answer: Answer, link: Link, resp: http.client.HTTPResponse, sink: Sink) -> tuple[int, int]:
        status = resp.status
        raw = resp.getheaders()
        if status < 200:                                       # an interim response other than 100 (which http.client
            self._drop(link)                                   # skips): the final one would land on the next request
            self.log('upstream_failure', phase='response', category=CAT_UNKNOWN, error='InterimResponse', status=status)
            sink.head(CAT_UNKNOWN, 0, [(b'x-engine-reason', b'result_unknown')])      # (review B, OS5)
            sink.chunk(refusal_body(req, b'result_unknown'))
            sink.end()
            return RES_UNKNOWN, 0
        # 条款 10: the token never enters the cell. A candidate is held, up to one byte past the limit or to its end, before
        # anything of it leaves; held is None when it was cut meanwhile, b'' (not ended) for every other response
        held: bytes | None = b''
        ended = False
        kinds = token_candidate(req, raw)
        if kinds:
            why = unreadable(raw, resp.chunked)
            if why:
                return self._withhold(req, link, sink, status, why)
            got = self._hold(resp, link, sink)
            token = got is not None and got[1] and token_body(kinds, got[0])
            if link.dead:                                      # a REVOKE while it was judged comes first, whatever the
                got = None                                     # verdict: the head, then the cut (Codex recheck)
            elif token:
                return self._withhold(req, link, sink, status, 'body')
            held, ended = got if got is not None else (None, False)
        try:
            headers = response_headers(raw, answer.account_destination, getattr(resp.msg, 'defects', None))
        except Malformed as e:                                 # C-33: the head does not read; the request was sent
            self._drop(link)
            self.log('upstream_failure', phase='response', category=CAT_UNKNOWN, error=type(e).__name__)
            sink.head(CAT_UNKNOWN, 0, [(b'x-engine-reason', b'result_unknown')])
            sink.chunk(refusal_body(req, b'result_unknown'))
            sink.end()
            return RES_UNKNOWN, 0
        sink.head(CAT_REMOTE, status, headers)
        complete = False
        if held is not None:                                   # None: cut while held, so the head and then the cut, no
            try:                                               # byte of what was held (nothing at all if the client left)
                if held and not link.dead:                     # not a token response: what was held goes out unchanged
                    sink.chunk(held)
                # a client gone or a REVOKE before the first read is a cut now, not after one more blocking read
                while not ended and not sink.client_gone and not link.dead:
                    piece = resp.read1(CHUNK)
                    # a REVOKE stops the relay at the next piece: shutdown(SHUT_RD) does not purge what the kernel already
                    # queued, so reads keep succeeding until that drains (measured: up to 1.9 MiB after the cut, block 6)
                    if not piece or link.dead:
                        break
                    sink.chunk(piece)
                    if sink.client_gone:
                        break
                # an early EOF under a known Content-Length is a cut body, not a complete one (read1 does not raise for
                # it); a connection cut by a REVOKE ended a close-delimited body the same way (OS3)
                if not sink.client_gone and not link.dead and not (resp.length is not None and resp.length > 0):
                    complete = True
            except Exception as e:                             # cut, timed out or malformed mid-body: the stream ends short
                self.log('upstream_body_failure', error=type(e).__name__)
        if complete:
            sink.end()
            if not resp.isclosed():
                resp.close()
            if resp.will_close:
                self._drop(link)
            else:
                self.links[link.key] = link                    # reusable: its response was read to the end (条款 8)
        else:
            sink.client_gone = True                            # no RESP_END: the frontend sees the cut (SPEC §3.1)
            self._drop(link)
            self.log('response_cut', status=status)
        # the REPORT names what the upstream did (it answered, with this status); a cut body is the frontend's to see
        return RES_REMOTE, status


def describe(req: Request) -> bytes:
    """The request in the error body: canonical fields only (placeholders at most), never anything the upstream said."""
    return req.method + b' ' + req.scheme + b'://' + host_header(req) + req.path
