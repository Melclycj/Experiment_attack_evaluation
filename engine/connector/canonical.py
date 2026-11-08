"""Canonical form: wire codec, request grammar, path normalisation, derived fields and body sealing
(SPEC-canonical-form.md §2, §4, §5, §6; agent-rm-model 3.9 代理口的形状, 条款 1–3; validation.md C-05–C-08,
C-10, C-12, C-13).

TCB module: standard library only. Everything that arrives on the proxy path is untrusted; a field that does
not read raises Malformed and the caller drops the whole frame and the connection. Nothing here consults
policy, credentials or the network.
"""
from __future__ import annotations

from dataclasses import dataclass
import codecs
import fcntl
import ipaddress
import os
import re
import struct
from urllib.parse import unquote_to_bytes

# ---- §6 limits ----------------------------------------------------------------------------------
KIB, MIB = 1024, 1024 * 1024


@dataclass(frozen=True)
class Limits:
    method: int = 32
    host: int = 253
    path: int = 8 * KIB
    query: int = 8 * KIB
    header_count: int = 128
    header_bytes: int = 64 * KIB
    header_value: int = 8 * KIB
    header_name: int = 128
    body: int = 64 * MIB
    frame_a: int = 64 * MIB + 128 * KIB     # link A: body travels inside the frame
    frame_bd: int = 1 * MIB                 # links B and D: the body is a memfd, not frame bytes
    policy_context: int = 16 * KIB          # ROW_START's opaque policy context (agent-rm-model 3.1; validation.md K-56)
    # host file reads (plan engine-v3-n16-file-read; validation.md H-13; proposal 第二节 工程选择)
    file_read: int = 256 * KIB              # one read, bytes
    file_list: int = 1000                   # one list, entries
    file_path: int = 4096                   # a relative path, bytes
    host_path: int = 4096                   # a registered host path, bytes
    alias: int = 64                         # an object's alias, bytes
    file_objects: int = 128                 # objects per workspace
    frame_h: int = 1 * MIB                  # link H, the file judgment port
    frame_g_in: int = 8 * KIB               # link G, a request on the file port (FILE_READ is at most 4189 bytes)
    frame_g_out: int = 1 * MIB              # link G, a reply (128 objects with 4096-byte host paths: 536,457 bytes)
    named_addresses: int = 64               # named non-global addresses per entry, items as written (validation.md K-57)


LIMITS = Limits()


class Malformed(ValueError):
    """The frame or a field does not read; the caller rejects the whole frame (C-05)."""


# ---- §3 frame kinds -----------------------------------------------------------------------------
# link A (cell -> connector, untrusted; connector -> frontend)
REQUEST, RESP_HEAD, RESP_CHUNK, RESP_END = 0x01, 0x11, 0x12, 0x13
# link B (connector <-> core, judgment port)
JUDGE, WITHDRAW, REPORT, ALLOW, ALLOW_NOCRED, DENY, REVOKE = 0x21, 0x22, 0x23, 0x31, 0x32, 0x33, 0x34
# link D (admin client <-> core)
QUESTION, QUESTION_WITHDRAWN, ANSWER = 0x41, 0x42, 0x43
ENTRY_PUT, ENTRY_DEL, CRED_PUT, CRED_DEL = 0x44, 0x45, 0x46, 0x47
WS_CREATE, WS_LIST, WS_DELETE, ROW_LIST, ROW_START, ROW_STOP = 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D
WS_HOLD, WS_RELEASE = 0x4E, 0x4F            # the workspace hold for import, push and export (validation.md K-55)
OK, ERR = 0x51, 0x52
OBJ_PUT, OBJ_DEL = 0x53, 0x54               # host file objects, registered by the user only (validation.md H-01)
# link F (core <-> PDP, the hook port; 648d60f2 4.2): requests out, answers and read-only table queries in
PDP_REQUEST, PDP_ANSWER, TABLE_QUERY, TABLE_SNAPSHOT = 0x61, 0x62, 0x63, 0x64
# link H (file worker <-> core, the file judgment port; validation.md H-06, H-08): requests in, decisions out; FILE_ALLOW
# carries the opened target as its one descriptor
FILE_ASK, FILE_WITHDRAW = 0x81, 0x82
FILE_ALLOW, FILE_DENY, FILE_OBJECT_LIST = 0x91, 0x92, 0x93
# link G (in-cell MCP server -> file worker, the file port; untrusted; validation.md H-04, H-05): one request at a
# time per connection, each answered by exactly one reply
FILE_LIST_OBJECTS, FILE_LIST, FILE_READ = 0x71, 0x72, 0x73
FILE_OBJECTS, FILE_ENTRIES, FILE_DATA, FILE_REFUSED = 0x74, 0x75, 0x76, 0x77

LINK_A_IN = frozenset({REQUEST})                         # what the connector accepts on the proxy path
LINK_A_OUT = frozenset({RESP_HEAD, RESP_CHUNK, RESP_END})
LINK_B_TO_CORE = frozenset({JUDGE, WITHDRAW, REPORT})
LINK_B_TO_CONNECTOR = frozenset({ALLOW, ALLOW_NOCRED, DENY, REVOKE})
LINK_D_TO_CORE = frozenset({ANSWER, ENTRY_PUT, ENTRY_DEL, CRED_PUT, CRED_DEL, WS_CREATE, WS_LIST, WS_DELETE,
                            ROW_LIST, ROW_START, ROW_STOP, WS_HOLD, WS_RELEASE, OBJ_PUT, OBJ_DEL})
LINK_D_TO_CLIENT = frozenset({QUESTION, QUESTION_WITHDRAWN, OK, ERR})
LINK_F_TO_CORE = frozenset({PDP_ANSWER, TABLE_QUERY})
LINK_F_TO_PDP = frozenset({PDP_REQUEST, TABLE_SNAPSHOT})
LINK_H_TO_CORE = frozenset({FILE_ASK, FILE_WITHDRAW})
LINK_H_TO_WORKER = frozenset({FILE_ALLOW, FILE_DENY, FILE_OBJECT_LIST})
LINK_G_IN = frozenset({FILE_LIST_OBJECTS, FILE_LIST, FILE_READ})
LINK_G_OUT = frozenset({FILE_OBJECTS, FILE_ENTRIES, FILE_DATA, FILE_REFUSED})

# field counts per kind (SPEC §3): a frame with another count does not read
FIELD_COUNT = {
    REQUEST: 8, RESP_HEAD: 3, RESP_CHUNK: 1, RESP_END: 0,
    JUDGE: 13, WITHDRAW: 1, REPORT: 3, ALLOW: 7, ALLOW_NOCRED: 3, DENY: 2, REVOKE: 4,   # ALLOW: placement, word, two truths, account, named; ALLOW_NOCRED: account_destination, named (K-59); REVOKE + scope
    QUESTION: 24, QUESTION_WITHDRAWN: 2, ANSWER: 2, ENTRY_PUT: 9, ENTRY_DEL: 3, CRED_PUT: 9, CRED_DEL: 2,   # ENTRY_PUT + named addresses (K-57); CRED_PUT: truth_a, truth_b always present (SPEC §3.4); QUESTION + 6 file fields (H-09)
    WS_CREATE: 1, WS_LIST: 0, WS_DELETE: 1, ROW_LIST: 0, ROW_START: 4, ROW_STOP: 1, OK: 2, ERR: 3,   # ROW_START + policy_context
    WS_HOLD: 1, WS_RELEASE: 1, OBJ_PUT: 7, OBJ_DEL: 2,
    PDP_REQUEST: 28, PDP_ANSWER: 3, TABLE_QUERY: 1, TABLE_SNAPSHOT: 5,      # PDP_REQUEST + the row's policy_context + 6 file fields; TABLE_SNAPSHOT + objects
    FILE_ASK: 7, FILE_WITHDRAW: 1, FILE_ALLOW: 2, FILE_DENY: 2, FILE_OBJECT_LIST: 2,
    FILE_LIST_OBJECTS: 0, FILE_LIST: 3, FILE_READ: 4, FILE_OBJECTS: 1, FILE_ENTRIES: 2, FILE_DATA: 2, FILE_REFUSED: 1,
}

# result categories (SPEC §7)
CAT_REMOTE, CAT_REFUSED, CAT_TRANSPORT, CAT_UNKNOWN = 1, 2, 3, 4          # RESP_HEAD.category
RES_REMOTE, RES_TRANSPORT, RES_UNKNOWN, RES_UNSENT = 1, 2, 3, 4           # REPORT.result
PLACE_API_KEY, PLACE_BEARER, PLACE_BASIC = 1, 2, 3                        # ALLOW.placement
PDP_ALLOW, PDP_DENY = 1, 2                                                 # PDP_ANSWER.verdict
SNAP_OK, SNAP_UNKNOWN, SNAP_UNAVAILABLE, SNAP_TOO_LARGE = 1, 2, 3, 4        # TABLE_SNAPSHOT.status
BEARER_WORDS = (b'Bearer', b'token')                                      # ALLOW.word of PLACE_BEARER
# host file reads (SPEC §3.4, §3.6, §3.8; validation.md H-01, H-09, H-18)
FILE_OP_OBJECTS, FILE_OP_LIST, FILE_OP_READ = 1, 2, 3                     # FILE_ASK.op; QUESTION/PDP_REQUEST file_op (0: none)
FILE_TYPE_FILE, FILE_TYPE_DIR = 1, 2                                      # an object's type
FILE_OPS_READ, FILE_OPS_LIST = 1, 2                                       # an object's operations, bits
FILE_MODE_ALLOW, FILE_MODE_ASK, FILE_MODE_DENY = 1, 2, 3                  # an object's approval mode as listed
KEY_KIND_FILE = 4                                                         # matched_key_kind of a file request (key: alias)
# FILE_ENTRIES item types, from the directory entry's d_type alone (validation.md H-16)
FILE_ENTRY_UNKNOWN, FILE_ENTRY_FILE, FILE_ENTRY_DIR, FILE_ENTRY_SYMLINK, FILE_ENTRY_OTHER = 0, 1, 2, 3, 4
# the closed list of refusal words a file request can get; the code is the position, 1–13 (H-18)
FILE_REASONS = ('not_registered', 'op_not_granted', 'bad_path', 'outside_or_symlink', 'wrong_type', 'too_large',
                'user_denied', 'pdp_denied', 'recorded_deny', 'policy_changed', 'unavailable', 'timeout', 'not_found')


# ---- §2 wire codec -----------------------------------------------------------------------------
def u16(n: int) -> bytes:
    return struct.pack('>H', n)


def u32(n: int) -> bytes:
    return struct.pack('>I', n)


def u64(n: int) -> bytes:
    return struct.pack('>Q', n)


def u8(n: int) -> bytes:
    return struct.pack('>B', n)


def read_uint(field: bytes, size: int) -> int:
    if len(field) != size:
        raise Malformed(f'integer field of {len(field)} bytes, expected {size}')
    return int.from_bytes(field, 'big')


def pack_list(items: list[bytes]) -> bytes:
    return u32(len(items)) + b''.join(u32(len(i)) + i for i in items)


def unpack_list(data: bytes, max_items: int | None = None) -> list[bytes]:
    if len(data) < 4:
        raise Malformed('list field shorter than its count')
    count, pos, items = int.from_bytes(data[:4], 'big'), 4, []
    if max_items is not None and count > max_items:
        raise Malformed(f'list of {count} items exceeds {max_items}')
    if count > (len(data) - 4) // 4:
        raise Malformed('list count larger than the field can hold')
    for _ in range(count):
        if pos + 4 > len(data):
            raise Malformed('list item length beyond the field')
        n = int.from_bytes(data[pos:pos + 4], 'big')
        pos += 4
        if pos + n > len(data):
            raise Malformed('list item beyond the field')
        items.append(data[pos:pos + n])
        pos += n
    if pos != len(data):
        raise Malformed('trailing bytes after the list')
    return items


def pack_frame(kind: int, fields: list[bytes]) -> bytes:
    if kind not in FIELD_COUNT or len(fields) != FIELD_COUNT[kind]:
        raise ValueError(f'kind {kind:#x} takes {FIELD_COUNT.get(kind)} fields, got {len(fields)}')
    payload = u8(kind) + b''.join(u32(len(f)) + f for f in fields)
    return u32(len(payload)) + payload


def unpack_payload(kind: int, payload: bytes) -> list[bytes]:
    """Split the bytes after the kind byte into exactly FIELD_COUNT[kind] fields (SPEC §2)."""
    if kind not in FIELD_COUNT:
        raise Malformed(f'unknown kind {kind:#x}')
    fields, pos = [], 0
    while pos < len(payload):
        if len(fields) >= FIELD_COUNT[kind]:
            raise Malformed(f'kind {kind:#x}: more than {FIELD_COUNT[kind]} fields')
        if pos + 4 > len(payload):
            raise Malformed('field length word beyond the frame')
        n = int.from_bytes(payload[pos:pos + 4], 'big')
        pos += 4
        if pos + n > len(payload):
            raise Malformed('field beyond the frame')
        fields.append(payload[pos:pos + n])
        pos += n
    if len(fields) != FIELD_COUNT[kind]:
        raise Malformed(f'kind {kind:#x}: {len(fields)} fields, expected {FIELD_COUNT[kind]}')
    return fields


def _precheck_fields(buf: bytearray, length: int) -> None:
    """Walk the field length words already buffered: more fields than the kind takes, or a field running past the
    frame's declared end, are Malformed before the rest of the frame is read (SPEC §2)."""
    kind, limit = buf[4], FIELD_COUNT.get(buf[4], 0)
    end, pos, fields = 4 + length, 5, 0
    while pos + 4 <= len(buf) and pos + 4 <= end:
        n = int.from_bytes(buf[pos:pos + 4], 'big')
        fields += 1
        if fields > limit:
            raise Malformed(f'kind {kind:#x}: more than {limit} fields')
        if pos + 4 + n > end:
            raise Malformed('field beyond the frame')
        pos += 4 + n


class FrameParser:
    """Incremental reader for one connection: feed bytes, take whole frames. A frame whose length word exceeds
    the link's limit is Malformed before any of its bytes are read (SPEC §2)."""

    __slots__ = ('_buf', '_limit', '_allowed', '_one')

    def __init__(self, limit: int, allowed: frozenset[int], one_at_a_time: bool = False) -> None:
        """one_at_a_time: hand out at most one frame per call; the connector reads the next REQUEST only after
        RESP_END went out (C-04), so bytes of a second request stay buffered until then."""
        self._buf, self._limit, self._allowed, self._one = bytearray(), limit, allowed, one_at_a_time

    def feed(self, data: bytes) -> list[tuple[int, list[bytes]]]:
        self._buf += data
        out = []
        while True:
            if len(self._buf) < 4:
                return out
            length = int.from_bytes(self._buf[:4], 'big')
            if length < 1 or length > self._limit:
                raise Malformed(f'frame length {length} outside 1..{self._limit}')
            if len(self._buf) >= 5 and self._buf[4] not in self._allowed:   # before buffering the rest
                raise Malformed(f'kind {self._buf[4]:#x} not on this link')
            if len(self._buf) >= 5:
                _precheck_fields(self._buf, length)
            if len(self._buf) < 4 + length:
                return out
            kind = self._buf[4]
            fields = unpack_payload(kind, bytes(self._buf[5:4 + length]))
            del self._buf[:4 + length]
            out.append((kind, fields))
            if self._one:
                return out

    @property
    def pending(self) -> int:
        return len(self._buf)

    def next_frame(self) -> tuple[int, list[bytes]] | None:
        """The next whole frame already buffered, if any (one_at_a_time mode)."""
        got = self.feed(b'')
        return got[0] if got else None


# ---- §4 request grammar -------------------------------------------------------------------------
TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
LOWER_TCHAR = frozenset(c for c in TCHAR if not (65 <= c <= 90))
UNRESERVED = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~')
SUB_DELIMS = frozenset(b"!$&'()*+,;=")
PCHAR = UNRESERVED | SUB_DELIMS | frozenset(b':@')
PATH_BYTES = PCHAR | frozenset(b'/%')
QUERY_BYTES = PATH_BYTES | frozenset(b'?')
HEX = frozenset(b'0123456789abcdefABCDEF')
LABEL = re.compile(rb'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
FORBIDDEN_NAMES = frozenset({b'host', b'transfer-encoding', b'content-length', b'connection', b'keep-alive', b'te',
                             b'trailer', b'upgrade', b'expect'})   # expect: 100-continue is the frontend's (3.9 支持清单)
SINGLE_NAMES = frozenset({b'authorization', b'x-api-key', b'content-type'})   # at most one of each (实施注意 6; 条款 10)
# Bytes that may appear literally in a path have exactly one spelling: their %XX form is refused (条款 2 的读法扩展).
# '%' itself is the exception: a literal percent can only be written %25.
LITERAL_PATH_BYTES = PATH_BYTES - frozenset(b'%')
BODY_KIND_MAX = 255                 # type/subtype together (SPEC §5 size closure)
NAT64_WKP = ipaddress.ip_network('64:ff9b::/96')   # well-known NAT64 prefix: the IPv4 address is the one spelling
HEX_UPPER = b'0123456789ABCDEF'
NUMERIC_LABEL = re.compile(rb'^(0x[0-9a-f]+|[0-9]+)$')
STRIPPED_NAMES = frozenset({b'x-http-method-override', b'x-http-method', b'x-method-override'})
FORM = 'application/x-www-form-urlencoded'
FORM_KEYS_MAX = 4096          # bound on the derived key list (SPEC §5)
FORM_ITEMS_MAX = 2 * FORM_KEYS_MAX   # bound on '&'-separated items scanned at all, unique or not (CPU bound)
FORM_KEY_MAX = 1024           # one encoded key, bytes
FORM_KEYS_BYTES_MAX = 64 * KIB  # all decoded keys together: keeps a JUDGE frame under the link B limit (SPEC §6)
PARAM = re.compile(rb'^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+=(?:[!#$%&\'*+\-.^_`|~0-9A-Za-z]+|"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*")$')


@dataclass(frozen=True)
class Request:
    """A request that passed the grammar: the only shape the connector ever hands to the core or serialises."""
    method: bytes
    scheme: bytes
    host: bytes              # canonical: lower-case A-label name, or the canonical text of an IP literal
    is_ip: bool
    port: int
    path: bytes              # after RFC 3986 5.2.4 dot-segment removal (C-08)
    query: bytes | None      # None = absent; never used for matching
    headers: tuple[tuple[bytes, bytes], ...]   # stripped names removed, names lower-case
    stripped: tuple[bytes, ...]                # override names that were present (recorded, C-10)
    body: bytes
    body_kind: str           # derived (SPEC §5)
    form_keys: tuple[str, ...]


def _check_method(m: bytes, lim: Limits) -> bytes:
    if not 1 <= len(m) <= lim.method or any(c not in TCHAR for c in m):
        raise Malformed('method is not a token within the limit')
    # CONNECT: the frontend ended TLS and the connector makes no tunnel (C-05). TRACE, and IIS's TRACK: the upstream echoes
    # the request it received, the replaced credential included, into the cell (C-34). All three in any case: receivers
    # disagree on lower-case methods (runs/20261029T063000Z-receiver-differential).
    if m.upper() in (b'CONNECT', b'TRACE', b'TRACK'):
        raise Malformed(f'{m.upper().decode()} is refused at the schema layer')
    return m


def _check_scheme(s: bytes) -> bytes:
    if s not in (b'http', b'https'):
        raise Malformed('scheme is not http or https')
    return s


def _check_host(h: bytes, lim: Limits) -> tuple[bytes, bool]:
    if not 1 <= len(h) <= lim.host or any(c > 0x7E or c < 0x21 for c in h):
        raise Malformed('host length or non-ASCII byte')
    text = h.decode('ascii')
    if text != text.lower():
        raise Malformed('host has upper-case letters')
    if ':' in text or text.replace('.', '').isdigit():
        if '%' in text:
            raise Malformed('IP literal with a zone suffix')
        try:
            addr = ipaddress.ip_address(text)
        except ValueError as e:
            raise Malformed('host is not a valid IP literal') from e
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            # the kernel connects ::ffff:a.b.c.d to the IPv4 address a.b.c.d: one destination, one spelling (SPEC §4)
            raise Malformed('IPv4-mapped IPv6 literal; write the IPv4 address')
        if isinstance(addr, ipaddress.IPv6Address) and addr in NAT64_WKP:
            raise Malformed('NAT64 well-known-prefix literal; write the IPv4 address')   # configured prefixes: C-35
        if str(addr) != text:
            raise Malformed('IP literal is not in canonical text form (RFC 5952)')
        return h, True
    labels = h.split(b'.')
    if all(NUMERIC_LABEL.match(label) for label in labels):
        raise Malformed('hex or short IPv4 spelling is not a host name')   # glibc would resolve it as an address
    for label in labels:
        if not LABEL.match(label):
            raise Malformed('host label is not a valid A-label')
        if label.startswith(b'xn--'):
            try:   # the punycode part must decode and re-encode to itself; character permission (RFC 5892) is the
                   # frontend's and the registry's concern, not a matching concern (SPEC §4)
                text_part = codecs.decode(label[4:], 'punycode')
                if not text_part or codecs.encode(text_part, 'punycode') != label[4:]:
                    raise ValueError
            except (UnicodeError, ValueError) as e:
                raise Malformed('xn-- label is not valid punycode') from e
    return h, False


def _check_pct(data: bytes, where: str) -> None:
    i = 0
    while True:
        i = data.find(b'%', i)
        if i < 0:
            return
        if i + 2 >= len(data):
            raise Malformed(f'{where}: incomplete percent-encoding')
        if data[i + 1] not in HEX or data[i + 2] not in HEX:
            raise Malformed(f'{where}: non-hex percent-encoding')
        i += 3


def _upper_pct(data: bytes) -> bytes:
    """RFC 3986 §6.2.2.1: percent-encodings in upper-case hex, so that one byte has one spelling."""
    out, i = bytearray(), 0
    while i < len(data):
        if data[i] == 0x25:
            out += b'%' + data[i + 1:i + 3].upper()
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def _remove_dot_segments(path: bytes) -> bytes:
    """RFC 3986 §5.2.4 applied to an absolute path."""
    out: list[bytes] = []
    for seg in path.split(b'/')[1:]:
        if seg == b'.':
            continue
        if seg == b'..':
            if out:
                out.pop()
            continue
        out.append(seg)
    # a trailing "." or ".." keeps the trailing slash, as the RFC's output does
    if path.endswith((b'/.', b'/..')):
        out.append(b'')
    return b'/' + b'/'.join(out)


def _check_path(p: bytes, lim: Limits) -> bytes:
    if not p.startswith(b'/') or len(p) > lim.path:
        raise Malformed('path must start with / and fit the limit')
    if any(c not in PATH_BYTES for c in p):
        raise Malformed('path has a byte outside pchar / "/"')
    _check_pct(p, 'path')
    low = p.lower()
    if b'%2e' in low or b'%2f' in low:
        raise Malformed('path has an encoded dot or slash (条款 2)')
    for i in range(len(p) - 2):
        if p[i] == 0x25:                                  # well-formed here: _check_pct ran first
            byte = int(p[i + 1:i + 3], 16)
            if byte in LITERAL_PATH_BYTES or byte in (0x5C, 0x00):   # backslash; NUL (upstream truncation)
                raise Malformed('path encodes a byte that may appear literally, a backslash or NUL (条款 2 的读法扩展)')
    segments = p.split(b'/')[1:]
    if any(seg == b'' for seg in segments[:-1]):
        raise Malformed('path has an empty segment (条款 2)')
    if b';' in p:   # path parameters: servlet containers strip ';...' from a segment before routing, so '/admin;x' and
                    # '/..;/' read as another path upstream than here (条款 2 的读法扩展)
        raise Malformed('path parameter (;) in the path (条款 2 的读法扩展)')
    return _remove_dot_segments(_upper_pct(p))


def _check_query(q: bytes, lim: Limits) -> bytes | None:
    if len(q) == 0:
        return None
    if len(q) > lim.query or any(c not in QUERY_BYTES for c in q):
        raise Malformed('query has a byte outside pchar / "/" / "?" or exceeds the limit')
    _check_pct(q, 'query')
    return q


def _check_headers(items: list[bytes], lim: Limits) -> tuple[tuple[tuple[bytes, bytes], ...], tuple[bytes, ...]]:
    if len(items) % 2:
        raise Malformed('header list has an odd number of items')
    pairs = list(zip(items[0::2], items[1::2]))
    if len(pairs) > lim.header_count:
        raise Malformed('too many headers')
    total = sum(len(n) + len(v) for n, v in pairs)
    if total > lim.header_bytes:
        raise Malformed('headers exceed the byte limit')
    kept, stripped, seen_single = [], [], set()
    for name, value in pairs:
        if not 1 <= len(name) <= lim.header_name or any(c not in LOWER_TCHAR for c in name):
            raise Malformed('header name is not a lower-case token')
        if len(value) > lim.header_value or any(not (0x21 <= c <= 0x7E or c >= 0x80 or c in (0x20, 0x09)) for c in value):
            raise Malformed('header value has a byte outside field-value (CR, LF, NUL or control)')
        if value[:1] in (b' ', b'\t') or value[-1:] in (b' ', b'\t'):
            raise Malformed('header value has leading or trailing whitespace')
        if name in FORBIDDEN_NAMES or name.startswith(b'proxy-'):
            raise Malformed(f'forbidden header {name.decode()} (条款 3)')
        if name in STRIPPED_NAMES:
            stripped.append(name)
            continue
        if name in SINGLE_NAMES:
            if name in seen_single:
                raise Malformed(f'more than one {name.decode()} header (实施注意 6)')
            seen_single.add(name)
        kept.append((name, value))
    return tuple(kept), tuple(dict.fromkeys(stripped))


# ---- §5 derived fields ------------------------------------------------------------------------
def _split_params(value: bytes) -> list[bytes]:
    """Split a field value on ';' outside quoted-strings (a quoted-string may contain ';' and backslash escapes)."""
    parts, start, quoted, i = [], 0, False, 0
    while i < len(value):
        c = value[i]
        if quoted:
            if c == 0x5C and i + 1 < len(value):
                i += 1
            elif c == 0x22:
                quoted = False
        elif c == 0x22:
            quoted = True
        elif c == 0x3B:
            parts.append(value[start:i])
            start = i + 1
        i += 1
    parts.append(value[start:])
    return parts


FORM_CHARSETS = frozenset({b'utf-8', b'utf8', b'us-ascii', b'ascii', b'iso-8859-1', b'latin1', b'windows-1252'})


def form_charset_ok(headers: tuple[tuple[bytes, bytes], ...]) -> bool:
    """A form's charset parameter, when present, must keep ASCII key names as single bytes (读法扩展，报用户):
    an upstream decoding UTF-16 parameter names would read grant_type where 条款 10's key check sees other bytes."""
    for name, value in headers:
        if name == b'content-type':
            for param in _split_params(value)[1:]:
                key, sep, raw = param.strip(b' \t').partition(b'=')
                if sep and key.strip().lower() == b'charset':
                    return raw.strip().strip(b'"').lower() in FORM_CHARSETS
    return True


def media_type(headers: tuple[tuple[bytes, bytes], ...]) -> str:
    """type/subtype of the content-type header, lower-case, parameters dropped; '' when absent; Malformed when the
    header is present but is not a media type (a reader that falls back to '' would let 条款 10 be dodged)."""
    for name, value in headers:
        if name == b'content-type':
            main, *params = _split_params(value)
            main = main.strip().lower()
            parts = main.split(b'/')
            if len(parts) != 2 or not all(p and all(c in LOWER_TCHAR for c in p) for p in parts):
                raise Malformed('content-type is not a media type')
            if len(main) > BODY_KIND_MAX:
                raise Malformed('media type longer than %d bytes' % BODY_KIND_MAX)
            for param in params:   # parameters are dropped, but each must read as token=token|quoted-string (RFC 9110 §5.6.6)
                param = param.strip(b' \t')
                if param and not PARAM.match(param):     # an empty segment is allowed by the RFC's *( OWS ";" OWS [ parameter ] )
                    raise Malformed('content-type parameter does not read')
            return main.decode('ascii')
    return ''


def form_keys(body_kind: str, body: bytes) -> tuple[str, ...]:
    """Key names of an urlencoded form body, decoded, de-duplicated, order kept; values never read."""
    if body_kind != FORM or not body:
        return ()
    seen: dict[str, None] = {}
    total, start, items = 0, 0, 0
    while start <= len(body):
        items += 1
        if items > FORM_ITEMS_MAX:
            raise Malformed('more than %d form items' % FORM_ITEMS_MAX)
        end = body.find(b'&', start)
        if end < 0:
            end = len(body)
        eq = body.find(b'=', start, end)
        key_end = end if eq < 0 else eq
        if key_end - start > FORM_KEY_MAX:
            raise Malformed('form key longer than %d bytes' % FORM_KEY_MAX)
        key = unquote_to_bytes(body[start:key_end].replace(b'+', b' ')).decode('latin-1')
        if key not in seen:
            seen[key] = None
            total += len(key)
            if len(seen) > FORM_KEYS_MAX or total > FORM_KEYS_BYTES_MAX:
                raise Malformed('form keys exceed the count or byte budget')
        start = end + 1
    return tuple(seen)


# ---- the request as a whole ------------------------------------------------------------------
def parse_request(fields: list[bytes], lim: Limits = LIMITS) -> Request:
    """Fields of a REQUEST frame (SPEC §3.1) -> a validated, normalised Request; Malformed on any failure."""
    if len(fields) != FIELD_COUNT[REQUEST]:
        raise Malformed('REQUEST field count')
    f_method, f_scheme, f_host, f_port, f_path, f_query, f_headers, f_body = fields
    method = _check_method(f_method, lim)
    scheme = _check_scheme(f_scheme)
    host, is_ip = _check_host(f_host, lim)
    port = read_uint(f_port, 2)
    if port == 0:
        raise Malformed('port 0')
    path = _check_path(f_path, lim)
    query = _check_query(f_query, lim)
    if len(f_headers) > lim.header_bytes + 8 * (2 * lim.header_count + 1):   # count word plus 2 length words per pair
        raise Malformed('header list field exceeds the byte limit')
    headers, stripped = _check_headers(unpack_list(f_headers, 2 * lim.header_count), lim)
    if len(f_body) > lim.body:
        raise Malformed('body exceeds the limit')
    kind = media_type(headers)
    if kind == FORM and any(name == b'content-encoding' and value.strip().lower() != b'identity' for name, value in headers):
        raise Malformed('an encoded form body cannot be inspected for 条款 10 (first build refuses it)')
    if kind == FORM and not form_charset_ok(headers):
        raise Malformed('form charset is not ASCII-compatible (读法扩展，报用户)')
    return Request(method, scheme, host, is_ip, port, path, query, headers, stripped, f_body, kind,
                   form_keys(kind, f_body))


# Public names of the field checks for the core (registration-time validation of entry keys, prefixes and endpoints
# uses the same grammar the connector applies to requests; review A 交后续块 1).
def check_host(h: bytes, lim: Limits = LIMITS) -> tuple[bytes, bool]:
    return _check_host(h, lim)


def check_path(p: bytes, lim: Limits = LIMITS) -> bytes:
    return _check_path(p, lim)


def check_method(m: bytes, lim: Limits = LIMITS) -> bytes:
    return _check_method(m, lim)


# ---- 条款 7: named non-global addresses (plan engine-v3-private-net 接口约定; validation.md K-57, K-59, C-19) ------------
# Built in, never connected even when a cell names them: link-local (cloud metadata among it), loopback and unspecified
# (the kernel connects those to this host), IPv4-compatible ::/96, and, an engineering addition, multicast and the
# limited broadcast. The deployment's metadata list and the host's own addresses are the connector's (--deny-address).
NEVER_CONNECT = tuple(ipaddress.ip_network(n) for n in (
    '169.254.0.0/16', 'fe80::/10', '127.0.0.0/8', '::1/128', '0.0.0.0/8', '::/128', '::/96', '224.0.0.0/4', 'ff00::/8',
    '255.255.255.255/32'))
# an address under these is judged by the IPv4 address it embeds, so it is named by that spelling only (C-19)
IPV4_SPELT = (ipaddress.ip_network('::ffff:0:0/96'), NAT64_WKP)


def named_item(text: str) -> str:
    """One item of an entry's named addresses as registered (K-57) -> its stored text, the canonical prefix text
    str(ip_network(item)): a canonical single address (stored with its full prefix length) or a canonical prefix with
    zero host bits; ASCII, no zone. Refused (Malformed): anything else, an item meeting the IPv4-mapped range or the
    NAT64 well-known prefix in either direction (inside or holding it), or one meeting a NEVER_CONNECT range."""
    if not text or not text.isascii() or '%' in text:
        raise Malformed('a named address is an ASCII IP address or prefix without a zone')
    try:
        net = ipaddress.ip_network(text)                  # strict: a prefix with host bits set does not read
    except ValueError as e:
        raise Malformed(f'not an IP address or prefix: {e}') from None
    if text != (str(net) if '/' in text else str(net.network_address)):
        raise Malformed('a named address is not in canonical text form')
    if any(net.version == r.version and net.overlaps(r) for r in IPV4_SPELT):
        raise Malformed('IPv4-mapped or NAT64 well-known prefix; name the IPv4 address')
    if any(net.version == r.version and net.overlaps(r) for r in NEVER_CONNECT):
        raise Malformed('meets a range never connected even when named')
    return str(net)


def read_named(field: bytes) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """The named field of ALLOW and ALLOW_NOCRED (K-59; SPEC §3.2): at most LIMITS.named_addresses items, each the
    ASCII canonical prefix text str(ip_network(item)), else Malformed. NEVER_CONNECT is not consulted here: the
    connector's first gate refuses those ranges at connect time, so a frame naming them (a core error) still connects
    to none of them."""
    out = []
    for item in unpack_list(field, LIMITS.named_addresses):
        try:
            text = item.decode('ascii')
            net = ipaddress.ip_network(text)
        except ValueError as e:                           # UnicodeDecodeError is a ValueError
            raise Malformed(f'a named address does not read: {e}') from None
        if str(net) != text:
            raise Malformed('a named address is not a canonical prefix text')
        out.append(net)
    return tuple(out)


def encode_request(r: Request) -> bytes:
    """The REQUEST frame for a Request (used by tests and by an agent that speaks canonical form directly)."""
    items: list[bytes] = []
    for name, value in r.headers:
        items += [name, value]
    return pack_frame(REQUEST, [r.method, r.scheme, r.host, u16(r.port), r.path, r.query or b'', pack_list(items),
                                r.body])


# ---- body sealing (SPEC §3.2; 工程项 16) -----------------------------------------------------
F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_GROW, F_SEAL_WRITE = 1, 2, 4, 8
REQUIRED_SEALS = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
F_ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
F_GET_SEALS = getattr(fcntl, 'F_GET_SEALS', 1034)
MFD_ALLOW_SEALING = getattr(os, 'MFD_ALLOW_SEALING', 2)


def seal_body(body: bytes) -> int:
    """A sealed memfd holding exactly `body`: no process can write it or change its length afterwards."""
    fd = os.memfd_create('w2-body', os.MFD_CLOEXEC | MFD_ALLOW_SEALING)
    try:
        view, written = memoryview(body), 0
        while written < len(body):
            written += os.write(fd, view[written:])
        fcntl.fcntl(fd, F_ADD_SEALS, REQUIRED_SEALS)
    except BaseException:
        os.close(fd)
        raise
    return fd


def seals_ok(fd: int, expected_len: int) -> bool:
    """Core side: the three seals are present and the size is the declared one (K-24)."""
    try:
        seals = fcntl.fcntl(fd, F_GET_SEALS)
        return (seals & REQUIRED_SEALS) == REQUIRED_SEALS and os.fstat(fd).st_size == expected_len
    except (OSError, ValueError):      # ValueError: a negative descriptor
        return False
