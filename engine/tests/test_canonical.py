"""Canonical form (SPEC-canonical-form.md §2, §4, §5; validation.md C-05, C-06, C-07, C-08, C-10, C-12, C-13, K-41):
one positive and negative case per grammar rule, the attack shapes of 条款 1–3 all refused, derived fields, body
sealing, and the TCB import scan. Non-root."""
from __future__ import annotations

import ast
import errno
import ipaddress
import os
import sys
from pathlib import Path

import pytest

from connector import canonical as c

ENGINE = Path(__file__).resolve().parents[1]


def req(method=b'GET', scheme=b'https', host=b'api.example.test', port=443, path=b'/v1/x', query=b'',
        headers=(), body=b'') -> list[bytes]:
    items: list[bytes] = []
    for name, value in headers:
        items += [name, value]
    return [method, scheme, host, c.u16(port), path, query, c.pack_list(items), body]


def parse(**kw) -> c.Request:
    return c.parse_request(req(**kw))


def refused(**kw) -> str:
    with pytest.raises(c.Malformed) as e:
        parse(**kw)
    return str(e.value)


# ---- §2 codec -----------------------------------------------------------------------------------
def test_field_counts_follow_the_spec_tables() -> None:
    assert c.FIELD_COUNT[c.REQUEST] == 8 and c.FIELD_COUNT[c.JUDGE] == 13 and c.FIELD_COUNT[c.QUESTION] == 24
    assert c.FIELD_COUNT[c.REVOKE] == 4      # ALLOW and ALLOW_NOCRED: test_allow_frames_and_entry_put_carry_the_named_field
    assert c.FIELD_COUNT[c.ANSWER] == 2
    # the workspace rework (SPEC §3.4, §3.6): the hold and its release, ROW_START's policy context, the PDP's copy of it
    assert (c.WS_HOLD, c.WS_RELEASE) == (0x4E, 0x4F) and {c.WS_HOLD, c.WS_RELEASE} <= c.LINK_D_TO_CORE
    assert c.FIELD_COUNT[c.WS_HOLD] == c.FIELD_COUNT[c.WS_RELEASE] == 1
    assert c.FIELD_COUNT[c.ROW_START] == 4 and c.FIELD_COUNT[c.PDP_REQUEST] == 28
    assert c.LIMITS.policy_context == 16 * 1024
    # host file reads (SPEC §3.4, §3.6, §3.8; validation.md H-01, H-09): the two registration verbs, the six fields
    # QUESTION and PDP_REQUEST append, the objects TABLE_SNAPSHOT appends, and link H
    assert (c.OBJ_PUT, c.OBJ_DEL) == (0x53, 0x54) and {c.OBJ_PUT, c.OBJ_DEL} <= c.LINK_D_TO_CORE
    assert (c.FIELD_COUNT[c.OBJ_PUT], c.FIELD_COUNT[c.OBJ_DEL], c.FIELD_COUNT[c.TABLE_SNAPSHOT]) == (7, 2, 5)
    assert (c.FILE_ASK, c.FILE_WITHDRAW, c.FILE_ALLOW, c.FILE_DENY, c.FILE_OBJECT_LIST) == (0x81, 0x82, 0x91, 0x92, 0x93)
    assert [c.FIELD_COUNT[k] for k in (c.FILE_ASK, c.FILE_WITHDRAW, c.FILE_ALLOW, c.FILE_DENY, c.FILE_OBJECT_LIST)] == \
        [7, 1, 2, 2, 2]
    assert c.LINK_H_TO_CORE == {c.FILE_ASK, c.FILE_WITHDRAW}
    assert c.LINK_H_TO_WORKER == {c.FILE_ALLOW, c.FILE_DENY, c.FILE_OBJECT_LIST}
    assert (c.LIMITS.file_read, c.LIMITS.file_list, c.LIMITS.file_path, c.LIMITS.host_path, c.LIMITS.alias,
            c.LIMITS.file_objects, c.LIMITS.frame_h) == (262144, 1000, 4096, 4096, 64, 128, 1 << 20)
    # link G, the file port (SPEC §3.7; validation.md H-04, H-13): three requests in, four replies out; the request
    # frame at most 8 KiB, the reply at most 1 MiB (128 objects with 4096-byte host paths need about 524 KiB)
    assert (c.FILE_LIST_OBJECTS, c.FILE_LIST, c.FILE_READ) == (0x71, 0x72, 0x73)
    assert (c.FILE_OBJECTS, c.FILE_ENTRIES, c.FILE_DATA, c.FILE_REFUSED) == (0x74, 0x75, 0x76, 0x77)
    assert [c.FIELD_COUNT[k] for k in sorted(c.LINK_G_IN | c.LINK_G_OUT)] == [0, 3, 4, 1, 2, 2, 1]
    assert c.LINK_G_IN == {c.FILE_LIST_OBJECTS, c.FILE_LIST, c.FILE_READ}
    assert c.LINK_G_OUT == {c.FILE_OBJECTS, c.FILE_ENTRIES, c.FILE_DATA, c.FILE_REFUSED}
    assert (c.LIMITS.frame_g_in, c.LIMITS.frame_g_out) == (8192, 1 << 20)
    assert (c.FILE_ENTRY_UNKNOWN, c.FILE_ENTRY_FILE, c.FILE_ENTRY_DIR, c.FILE_ENTRY_SYMLINK, c.FILE_ENTRY_OTHER) == \
        (0, 1, 2, 3, 4)


def test_allow_frames_and_entry_put_carry_the_named_field() -> None:
    """Plan engine-v3-private-net 接口约定 (K-57, K-59, C-19, C-28): the named non-global addresses are ALLOW's 7th,
    ALLOW_NOCRED's 3rd and ENTRY_PUT's 9th (last) field; at most 64 of them; the built-in never-connect ranges."""
    assert c.FIELD_COUNT[c.ALLOW] == 7 and c.FIELD_COUNT[c.ALLOW_NOCRED] == 3 and c.FIELD_COUNT[c.ENTRY_PUT] == 9
    assert c.LIMITS.named_addresses == 64
    assert {ipaddress.ip_network(str(n)) for n in c.NEVER_CONNECT} == {ipaddress.ip_network(n) for n in (
        '169.254.0.0/16', 'fe80::/10', '127.0.0.0/8', '::1/128', '0.0.0.0/8', '::/128', '::/96', '224.0.0.0/4', 'ff00::/8',
        '255.255.255.255/32')}


def test_read_named_takes_exact_canonical_prefix_texts_only() -> None:
    """read_named, the reader of the named field: a list of at most 64 ASCII items, each exactly
    str(ipaddress.ip_network(item)); anything else is Malformed. It leaves the never-connect ranges to the connector's
    first gate, so a frame naming them (a core error) reads and is refused at connect time."""
    read = c.read_named
    assert read(c.pack_list([])) == ()
    got = read(c.pack_list([b'10.0.0.5/32', b'10.0.0.0/8', b'fd12:3456::/48']))
    assert isinstance(got, tuple) and sorted(map(str, got)) == ['10.0.0.0/8', '10.0.0.5/32', 'fd12:3456::/48']
    assert all(isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for n in got)
    assert len(read(c.pack_list([b'10.0.%d.0/24' % i for i in range(64)]))) == 64
    assert {str(n) for n in read(c.pack_list([b'169.254.0.0/16', b'::/96', b'127.0.0.0/8']))} == \
        {'169.254.0.0/16', '::/96', '127.0.0.0/8'}
    for bad in (b'10.0.0.5/32', b'', c.pack_list([b'10.0.0.5/32']) + b'\x00', c.pack_list([b'gitlab.corp']),
                c.pack_list([b'gitlab.corp:443']), c.pack_list([b'10.0.0.5:80']), c.pack_list([b'10.0.0.05/32']),
                c.pack_list([b'10.0.0.5/24']), c.pack_list([b'10.0.0.5']), c.pack_list([b'FD12::/16']),
                c.pack_list([b'fd12:0::/16']), c.pack_list([b'10.0.0.0/08']), c.pack_list([b'10.0.0.5/32\xff']),
                c.pack_list([b'']), c.pack_list([b'10.0.0.5/32', b'example.test']),
                c.pack_list([b'10.0.%d.%d/32' % (i // 256, i % 256) for i in range(65)])):
        with pytest.raises(c.Malformed):
            read(bad)


def test_cred_put_has_a_fixed_nine_field_layout() -> None:
    assert c.FIELD_COUNT[c.CRED_PUT] == 9
    frame = c.pack_frame(c.CRED_PUT, [b'h:443', b'acct', c.u8(1), b'PH', b'truth', b'', b'', b'', b''])
    assert c.unpack_payload(c.CRED_PUT, frame[5:])[5] == b''


def test_frame_roundtrip_every_kind() -> None:
    for kind, count in c.FIELD_COUNT.items():
        fields = [bytes([i]) * i for i in range(count)]
        frame = c.pack_frame(kind, fields)
        assert int.from_bytes(frame[:4], 'big') == len(frame) - 4 and frame[4] == kind
        assert c.unpack_payload(kind, frame[5:]) == fields


def test_frame_field_count_is_closed() -> None:
    with pytest.raises(ValueError):
        c.pack_frame(c.REQUEST, [b''] * 7)
    with pytest.raises(c.Malformed):
        c.unpack_payload(c.REQUEST, c.pack_frame(c.JUDGE, [b''] * 13)[5:])
    with pytest.raises(c.Malformed, match='more than'):      # stops at the ninth field, never materialises the rest
        c.unpack_payload(c.REQUEST, c.pack_frame(c.JUDGE, [b''] * 13)[5:] + c.u32(0) * 10_000)
    with pytest.raises(c.Malformed):
        c.unpack_payload(c.RESP_CHUNK, c.u32(5) + b'abc')        # field beyond the frame
    with pytest.raises(c.Malformed):
        c.unpack_payload(0x7F, b'')


def test_parser_reassembles_split_frames_and_rejects_foreign_kinds() -> None:
    p = c.FrameParser(limit=c.LIMITS.frame_a, allowed=c.LINK_A_IN)
    frame = c.pack_frame(c.REQUEST, req())
    assert p.feed(frame[:3]) == [] and p.feed(frame[3:10]) == []
    got = p.feed(frame[10:] + frame)
    assert [k for k, _ in got] == [c.REQUEST, c.REQUEST] and got[0][1] == req()
    with pytest.raises(c.Malformed, match='not on this link'):
        p.feed(c.pack_frame(c.RESP_END, []))            # the connector never accepts a response kind
    p2 = c.FrameParser(limit=c.LIMITS.frame_bd, allowed=c.LINK_B_TO_CORE)
    with pytest.raises(c.Malformed, match='not on this link'):
        p2.feed(c.pack_frame(c.ANSWER, [b''] * 2))      # an admin verb on the judgment port
    p3 = c.FrameParser(limit=16, allowed=c.LINK_A_IN)
    with pytest.raises(c.Malformed, match='frame length'):
        p3.feed(c.u32(17))                               # refused before any payload byte is read
    with pytest.raises(c.Malformed):
        c.FrameParser(limit=16, allowed=c.LINK_A_IN).feed(c.u32(0))
    p4 = c.FrameParser(limit=c.LIMITS.frame_a, allowed=c.LINK_A_IN)
    with pytest.raises(c.Malformed, match='not on this link'):
        p4.feed(c.u32(50_000_000) + bytes([c.RESP_HEAD]))   # refused at the fifth byte, nothing buffered


LINKS = [(c.LINK_A_IN, c.LIMITS.frame_a), (c.LINK_A_OUT, c.LIMITS.frame_a), (c.LINK_B_TO_CORE, c.LIMITS.frame_bd),
         (c.LINK_B_TO_CONNECTOR, c.LIMITS.frame_bd), (c.LINK_D_TO_CORE, c.LIMITS.frame_bd), (c.LINK_D_TO_CLIENT, c.LIMITS.frame_bd),
         (c.LINK_F_TO_CORE, c.LIMITS.frame_bd), (c.LINK_F_TO_PDP, c.LIMITS.frame_bd),
         (c.LINK_H_TO_CORE, c.LIMITS.frame_h), (c.LINK_H_TO_WORKER, c.LIMITS.frame_h),
         (c.LINK_G_IN, c.LIMITS.frame_g_in), (c.LINK_G_OUT, c.LIMITS.frame_g_out)]


def test_every_link_rejects_every_other_links_kinds() -> None:
    """C-06 / K-03: the twelve kind sets (link F is the hook port, K-49; link H the file judgment port, H-06; link G
    the file port, H-04) are disjoint and each reader accepts only its own."""
    sets = [allowed for allowed, _ in LINKS]
    assert sum(len(x) for x in sets) == len(set().union(*sets)) == len(c.FIELD_COUNT)
    for allowed, limit in LINKS:
        for other, _ in LINKS:
            if other is allowed:
                continue
            for kind in other:
                with pytest.raises(c.Malformed, match='not on this link'):
                    c.FrameParser(limit, allowed).feed(c.pack_frame(kind, [b''] * c.FIELD_COUNT[kind]))
        for kind in allowed:
            assert c.FrameParser(limit, allowed).feed(c.pack_frame(kind, [b''] * c.FIELD_COUNT[kind]))[0][0] == kind


def test_one_frame_at_a_time_mode() -> None:
    p = c.FrameParser(c.LIMITS.frame_a, c.LINK_A_IN, one_at_a_time=True)
    two = c.pack_frame(c.REQUEST, req()) * 2
    assert len(p.feed(two)) == 1 and p.pending > 0
    assert p.next_frame() is not None and p.next_frame() is None and p.pending == 0


def test_list_codec() -> None:
    items = [b'', b'a', b'bc' * 100]
    assert c.unpack_list(c.pack_list(items)) == items
    for bad in (b'', c.u32(1), c.u32(1) + c.u32(9) + b'ab', c.u32(0) + b'x', c.u32(0xFFFFFFFF)):
        with pytest.raises(c.Malformed):
            c.unpack_list(bad)
    with pytest.raises(c.Malformed, match='exceeds'):
        c.unpack_list(c.pack_list([b''] * 3), max_items=2)


# ---- §4 method / scheme / host / port ----------------------------------------------------------
@pytest.mark.parametrize('m', [b'GET', b'get', b'PROPFIND', b"!#$%&'*+-.^_`|~0a", b'M' * 32])
def test_method_tokens_accepted_verbatim(m: bytes) -> None:
    assert parse(method=m).method == m


@pytest.mark.parametrize('m', [b'', b'CONNECT', b'connect', b'Connect', b'G ET', b'GET\r', b'G\xc3T', b'A' * 33, b'GET/',
                               b'TRACE', b'trace', b'Trace', b'TRACK', b'track'])
def test_method_refused(m: bytes) -> None:
    refused(method=m)


def test_scheme() -> None:
    for s in (b'http', b'https'):
        assert parse(scheme=s).scheme == s
    for s in (b'HTTP', b'ftp', b'', b'https:'):
        refused(scheme=s)


@pytest.mark.parametrize('h,is_ip', [(b'api.example.test', False), (b'localhost', False), (b'xn--bcher-kva.example', False),
                                     (b'a-b.c0', False), (b'127.0.0.1', True), (b'::1', True), (b'2001:db8::1', True),
                                     (b'3com.example', False),
                                     (b'xn--fa-hia.example', False), (b'xn--n3h.example', False),
                                     (b'a' * 63 + b'.' + b'b' * 63 + b'.' + b'c' * 63 + b'.' + b'd' * 61, False)])
def test_host_accepted(h: bytes, is_ip: bool) -> None:
    r = parse(host=h)
    assert (r.host, r.is_ip) == (h, is_ip)


@pytest.mark.parametrize('h', [b'', b'API.example.test', 'bücher.example'.encode(), b'a..b', b'-a.b', b'a-.b',
                               b'example.test.', b'[::1]', b'2001:0db8::1', b'2001:DB8::1', b'01.2.3.4', b'1.2.3',
                               b'1.2.3.256', b'a' * 64 + b'.b', b'a.' * 127 + b'bcd', b'a b', b'a_b.c', b'fe80::1%eth0',
                               b'fe80::1%25eth0', b'xn--', b'xn--zz.example', b'xn--bcher-kva-.example',
                               b'0x7f.1', b'0x01020304', b'1.0x2.3.4', b'0x7f000001', b'::ffff:102:304', b'::ffff:1.2.3.4', b'64:ff9b::7f00:1',
                               b'a' * 63 + b'.' + b'b' * 63 + b'.' + b'c' * 63 + b'.' + b'd' * 62])
def test_host_refused(h: bytes) -> None:
    refused(host=h)


def test_port() -> None:
    assert parse(port=65535).port == 65535 and parse(port=1).port == 1
    refused(port=0)
    with pytest.raises(c.Malformed):
        c.parse_request(req()[:3] + [b'\x01\xbb\x00'] + req()[4:])     # wrong integer width


# ---- §4 path (条款 2) --------------------------------------------------------------------------
@pytest.mark.parametrize('p,norm', [(b'/', b'/'), (b'/a/b', b'/a/b'), (b'/a/b/', b'/a/b/'), (b'/a/../b', b'/b'),
                                    (b'/a/./b', b'/a/b'), (b'/../x', b'/x'), (b'/a/..', b'/'), (b'/a/.', b'/a/'),
                                    (b'/a/b/../../c', b'/c'), (b'/a%20b', b'/a%20b'), 
                                    (b'/repos/a', b'/repos/a'), (b'/a%20b%3f%23', b'/a%20b%3F%23'), (b'/%e4%b8%ad', b'/%E4%B8%AD'),
                                    (b'/100%25', b'/100%25'), (b'/' + b'p' * 8191, b'/' + b'p' * 8191)])
def test_path_normalised(p: bytes, norm: bytes) -> None:
    assert parse(path=p).path == norm


@pytest.mark.parametrize('p', [b'', b'a/b', b'/%2e%2e/x', b'/%2E%2E/x', b'/a/%2e/b', b'/a%2fb', b'/a%2Fb', b'/a\\b',
                               b'//a', b'/a//b', b'/%zz', b'/%4', b'/a%', b'/a b', b'/a\r', b'/a"b', b'/a<b', b'/a#f',
                               b'/a?x', b'/' + b'x' * (8 * 1024), '/ä'.encode(),
                               b'/%41bc', b'/repos/%61dmin', b'/oauth/%74oken', b'/a%7Eb', b'/a%5cb', b'/a%5Cb',
                               b'/repos/a/..;/admin', b'/.;x/b', b'/oauth/..;/token', b'/repos/a/..%3b/admin', b'/a/..%3B/b',
                               b'/admin;x/secret', b'/a;/b', b'/a/b;', b'/~u/x;y=1,2@z:1',
                               b'/v1/projects/p%3AsetIamPolicy', b'/u/a%40b', b'/a%2Cb', b'/a%3Db', b'/a%21b', b'/a%2Bb',
                               b'/a%27b', b'/a%28b%29', b'/a%2Ab', b'/a%24b', b'/a%26b', b'/a%3ab%3A', b'/a%7Eb', b'/a%2Db',
                               b'/admin%00', b'/a%00b'])
def test_path_refused(p: bytes) -> None:
    refused(path=p)


def test_query() -> None:
    assert parse(query=b'').query is None
    assert parse(query=b'a=1&b=%20?c/d').query == b'a=1&b=%20?c/d'
    assert parse(query=b'q' * 8192).query == b'q' * 8192
    for q in (b'a b', b'%zz', b'a\n', b'x' * (8 * 1024 + 1), 'ä'.encode()):
        refused(query=q)


# ---- §4 headers (条款 1, 3; 实施注意 6) ---------------------------------------------------------
def test_headers_kept_lower_case_tokens_with_field_values() -> None:
    r = parse(headers=((b'x-api-key', b'PLACEHOLDER'), (b'accept', b'*/*'), (b'x-obs', b'caf\xc3\xa9'),
                       (b'x-tab', b'a\tb')))
    assert r.headers == ((b'x-api-key', b'PLACEHOLDER'), (b'accept', b'*/*'), (b'x-obs', b'caf\xc3\xa9'),
                         (b'x-tab', b'a\tb'))


@pytest.mark.parametrize('name', [b'host', b'transfer-encoding', b'content-length', b'connection', b'keep-alive',
                                  b'te', b'trailer', b'upgrade', b'expect', b'proxy-authorization', b'proxy-connection', b'proxy-x'])
def test_forbidden_headers_refused(name: bytes) -> None:
    assert '条款 3' in refused(headers=((name, b'v'),))


def test_agent_supplied_host_refused_whatever_the_case_of_the_name() -> None:
    refused(headers=((b'host', b'evil.test'),))          # 条款 1
    refused(headers=((b'Host', b'evil.test'),))          # not a lower-case token either


@pytest.mark.parametrize('name', [b'x-http-method-override', b'x-http-method', b'x-method-override'])
def test_method_override_headers_stripped_and_recorded(name: bytes) -> None:
    r = parse(headers=((name, b'DELETE'), (b'accept', b'*/*')))
    assert r.headers == ((b'accept', b'*/*'),) and r.stripped == (name,)


def test_one_authorization_header_at_most() -> None:
    assert len(parse(headers=((b'authorization', b'Bearer PLACEHOLDER'),)).headers) == 1
    msg = refused(headers=((b'authorization', b'Bearer PLACEHOLDER'), (b'authorization', b'Basic eDp5')))
    assert 'authorization' in msg
    refused(headers=((b'x-api-key', b'A'), (b'x-api-key', b'B')))
    refused(headers=((b'content-type', b'application/json'), (b'content-type', b'application/x-www-form-urlencoded')))


@pytest.mark.parametrize('name,value', [(b'X-Api-Key', b'v'), (b'', b'v'), (b'a b', b'v'), (b'a:b', b'v'),
                                        (b'x', b'a\r\nb'), (b'x', b'a\nb'), (b'x', b'a\x00b'), (b'x', b' a'),
                                        (b'x', b'a '), (b'x', b'a\x7fb'), (b'x' * 129, b'v'), (b'x', b'v' * (8 * 1024 + 1))])
def test_bad_header_name_or_value_refused(name: bytes, value: bytes) -> None:
    refused(headers=((name, value),))


def test_header_count_and_byte_limits() -> None:
    assert len(parse(headers=tuple((b'h%03d' % i, b'v') for i in range(128))).headers) == 128
    refused(headers=tuple((b'h%03d' % i, b'v') for i in range(129)))
    assert parse(headers=((b'n' * 128, b'v' * 8192),)).headers[0] == (b'n' * 128, b'v' * 8192)
    refused(headers=((b'n' * 129, b'v'),))
    refused(headers=((b'n', b'v' * 8193),))
    at_limit = tuple((b'h%03d' % i, b'v' * (8192 - 4)) for i in range(8))        # 8 × 8192 = 64 KiB exactly
    assert len(parse(headers=at_limit).headers) == 8
    refused(headers=at_limit[:-1] + ((b'h007', b'v' * (8192 - 3)),))             # one byte over
    with pytest.raises(c.Malformed, match='exceeds'):    # a list claiming millions of items is refused on its count
        c.parse_request(req()[:6] + [c.u32(16_000_000) + b'\0' * 64] + req()[7:])
    with pytest.raises(c.Malformed, match='odd'):
        c.parse_request(req()[:6] + [c.pack_list([b'a'])] + req()[7:])


def test_body_limit_and_in_frame_body() -> None:
    for n in (9, 10):
        assert c.parse_request(req(body=b'x' * n), c.Limits(body=10)).body == b'x' * n
    with pytest.raises(c.Malformed, match='body'):
        c.parse_request(req(body=b'x' * 11), c.Limits(body=10))


def test_every_scalar_limit_plus_minus_one() -> None:
    """C-07: each limit accepts its exact value and refuses one more (method 32, path/query 8 KiB, header value 8 KiB,
    frame length)."""
    assert parse(method=b'M' * 31).method == b'M' * 31 and parse(method=b'M' * 32).method == b'M' * 32 and refused(method=b'M' * 33)
    assert parse(path=b'/' + b'p' * 8191).path == b'/' + b'p' * 8191 and refused(path=b'/' + b'p' * 8192)
    assert parse(query=b'q' * 8191).query == b'q' * 8191 and parse(query=b'q' * 8192).query == b'q' * 8192 and refused(query=b'q' * 8193)
    assert len(parse(headers=tuple((b'h%03d' % i, b'v') for i in range(127))).headers) == 127
    one_under = tuple((b'h%03d' % i, b'v' * (8192 - 4)) for i in range(7)) + ((b'h007', b'v' * (8192 - 5)),)   # 65535
    assert len(parse(headers=one_under).headers) == 8
    form = (b'content-type', b'application/x-www-form-urlencoded')
    assert parse(headers=(form,), body=b'A' * 1024 + b'=v').form_keys == ('A' * 1024,)
    with pytest.raises(c.Malformed, match='longer'):
        parse(headers=(form,), body=b'A' * 1025 + b'=v')
    with pytest.raises(c.Malformed, match='items'):
        parse(headers=(form,), body=b'ab&' * 8192 + b'c')                     # 8193 items
    assert parse(headers=((b'content-type', b'a' * 127 + b'/' + b'b' * 127),)).body_kind == 'a' * 127 + '/' + 'b' * 127
    refused(headers=((b'content-type', b'a' * 128 + b'/' + b'b' * 127),))                  # 256 bytes
    assert parse(headers=((b'n' * 128, b'v' * 8192),)).headers and refused(headers=((b'n' * 128, b'v' * 8193),))
    frame = c.pack_frame(c.REQUEST, req())
    assert c.FrameParser(len(frame) - 4, frozenset({c.REQUEST})).feed(frame) == [(c.REQUEST, req())]
    with pytest.raises(c.Malformed, match='frame length'):
        c.FrameParser(len(frame) - 5, frozenset({c.REQUEST})).feed(frame)


def test_parser_refuses_too_many_fields_before_the_frame_is_complete() -> None:
    """SPEC §2: the ninth field length word of a REQUEST is Malformed on arrival, with the frame far from complete."""
    p = c.FrameParser(c.LIMITS.frame_a, frozenset({c.REQUEST}))
    head = c.u32(c.LIMITS.frame_a) + bytes([c.REQUEST]) + c.u32(0) * 8
    assert p.feed(head) == [] and p.pending == len(head)
    with pytest.raises(c.Malformed, match='more than'):
        p.feed(c.u32(0))
    p = c.FrameParser(c.LIMITS.frame_a, frozenset({c.REQUEST}))
    with pytest.raises(c.Malformed, match='beyond'):          # a field running past the declared end, seen early
        p.feed(c.u32(100) + bytes([c.REQUEST]) + c.u32(200))
    p = c.FrameParser(c.LIMITS.frame_a, frozenset({c.REQUEST}))
    frame = c.pack_frame(c.REQUEST, req())
    out = []
    for i in range(len(frame)):                                # byte-by-byte feeding reassembles one frame
        out += p.feed(frame[i:i + 1])
    assert out == [(c.REQUEST, req())]


# ---- §5 derived fields -------------------------------------------------------------------------
def test_media_type_and_form_keys() -> None:
    r = parse(headers=((b'content-type', b'Application/X-WWW-Form-Urlencoded; charset=utf-8'),),
              body=b'grant_type=refresh_token&client_id=x&a%20b=1&c+d=2&grant_type=again&novalue')
    assert r.body_kind == c.FORM
    assert r.form_keys == ('grant_type', 'client_id', 'a b', 'c d', 'novalue')
    assert parse(headers=((b'content-type', b'application/json'),), body=b'grant_type=x').form_keys == ()
    refused(headers=((b'content-type', b'text'),))                 # present but not a media type: refused
    refused(headers=((b'content-type', b'application /x-www-form-urlencoded'),))
    for bad in (b'application/x-www-form-urlencoded;not-a-parameter', b'application/x-www-form-urlencoded; x=',
                b'application/x-www-form-urlencoded; x="unterminated', b'text/plain; charset'):
        refused(headers=((b'content-type', bad),))
    assert parse(headers=((b'content-type', b'Text/HTML; charset="utf-8"; q=1'),)).body_kind == 'text/html'
    for ok in (b'text/plain; x="a;b"', b'text/plain; x="a\\;b"', b'text/plain;', b'text/plain; ; x=1'):   # RFC 9110 §5.6.6
        assert parse(headers=((b'content-type', ok),)).body_kind == 'text/plain'
    assert parse(headers=((b'content-type', b'Application/JSON'),)).body_kind == 'application/json'
    keys = parse(headers=((b'content-type', b'application/x-www-form-urlencoded'),), body=b'&'.join(b'k%d' % i for i in range(4096))).form_keys
    assert len(keys) == 4096
    with pytest.raises(c.Malformed, match='budget'):
        parse(headers=((b'content-type', b'application/x-www-form-urlencoded'),), body=b'&'.join(b'k%d' % i for i in range(4097)))
    with pytest.raises(c.Malformed, match='items'):        # repeated or empty items count too (CPU bound, not only unique keys)
        parse(headers=((b'content-type', b'application/x-www-form-urlencoded'),), body=b'ab&' * 8193)
    with pytest.raises(c.Malformed, match='items'):
        parse(headers=((b'content-type', b'application/x-www-form-urlencoded'),), body=b'&' * (64 * 1024 * 1024))
    assert parse(headers=((b'content-type', b'application/x-www-form-urlencoded'),), body=b'ab&' * 8191 + b'c').form_keys == ('ab', 'c')
    form = (b'content-type', b'application/x-www-form-urlencoded')
    with pytest.raises(c.Malformed, match='longer'):       # one key of 1 KiB + 1 (encoded) is refused before decoding
        parse(headers=(form,), body=b'%41' * 342)
    assert parse(headers=(form,), body=b'%41' * 341 + b'=v').form_keys == ('A' * 341,)
    with pytest.raises(c.Malformed, match='budget'):       # 65 keys of 1 KiB exceed the 64 KiB decoded total
        parse(headers=(form,), body=b'&'.join(b'%02x' % i * 512 for i in range(65)))
    # the size closure (SPEC §5): the largest accepted request still encodes into a JUDGE under the link B limit
    fixed = (form, (b'content-encoding', b'identity'), (b'x-http-method', b'A'), (b'x-http-method-override', b'B'),
             (b'x-method-override', b'C'), (b'x-http-method', b'D'))
    room = c.LIMITS.header_bytes - sum(len(n) + len(v) for n, v in fixed)      # fill to 128 headers and 64 KiB exactly
    fill = [(b'h%03d' % i, b'v' * (room // 122 - 4)) for i in range(122)]
    fill[-1] = (fill[-1][0], fill[-1][1] + b'v' * (room - sum(len(n) + len(v) for n, v in fill)))
    big = parse(method=b'M' * 32, path=b'/' + b'p' * 8191, query=b'q' * 8192, headers=fixed + tuple(fill),
                body=b'&'.join(b'k%015d' % i for i in range(4096)))                  # 4096 keys of 16 B = 64 KiB
    stripped_bytes = sum(len(n) + len(v) for n, v in fixed[2:])                      # the four override headers
    assert len(big.headers) == 124 and sum(len(n) + len(v) for n, v in big.headers) + stripped_bytes == c.LIMITS.header_bytes
    assert len(big.form_keys) == 4096 and sum(len(k) for k in big.form_keys) == c.FORM_KEYS_BYTES_MAX
    assert big.stripped == (b'x-http-method', b'x-http-method-override', b'x-method-override')   # de-duplicated
    request_fields = c.unpack_payload(c.REQUEST, c.encode_request(big)[5:])[:7]                      # method .. headers
    judge = c.pack_frame(c.JUDGE, [c.u64(1), c.u32(70000)] + request_fields
                         + [c.pack_list(list(big.stripped)), big.body_kind.encode(),
                            c.pack_list([k.encode('latin-1') for k in big.form_keys]), c.u64(len(big.body))])
    assert len(judge) - 4 < c.LIMITS.frame_bd and c.FrameParser(c.LIMITS.frame_bd, frozenset({c.JUDGE})).feed(judge)
    question = c.pack_frame(c.QUESTION, [c.u64(7), b'e' * 4096, b'w' * 4096, c.u8(1), b'k' * 4096]
                            + c.unpack_payload(c.JUDGE, judge[5:])[2:13]
                            + [c.pack_list([b'h' * 259, b'a' * 128, c.u8(1)]),                  # the binding
                               c.pack_list([c.u8(1), c.pack_list([b'm' * 32] * 8), c.pack_list([b'/' + b'p' * 8191] * 30),
                                            c.pack_list([b'a' * 128] * 8), c.u8(2)])]           # a cell at the entry bound
                            + [c.u8(0), b'', b'', c.u64(0), c.u64(0), c.pack_list([])])     # no file request (H-09)
    assert len(question) - 4 < c.LIMITS.frame_bd and c.FrameParser(c.LIMITS.frame_bd, frozenset({c.QUESTION})).feed(question)
    assert parse(headers=(form,), body=b'a=1&&=x&b%zz=2&c').form_keys == ('a', '', 'b%zz', 'c')   # bad % stays literal
    keys = parse(headers=(form,), body=b'%00=1&%ff=2&a%2Bb=3&' + bytes([0xC3, 0xA9]) + b'=4').form_keys   # NUL and non-ASCII bytes survive
    assert keys == (chr(0), chr(255), 'a+b', chr(0xC3) + chr(0xA9))
    assert [k.encode('latin-1') for k in keys] == [bytes([0]), bytes([255]), b'a+b', bytes([0xC3, 0xA9])]
    refused(headers=(form, (b'content-encoding', b'gzip')), body=b'x')             # encoded form: 条款 10 blind spot
    assert parse(headers=(form, (b'content-encoding', b'identity')), body=b'k=1').form_keys == ('k',)
    for ok in (b'application/x-www-form-urlencoded; charset=utf-8', b'application/x-www-form-urlencoded; charset="UTF-8"',
               b'application/x-www-form-urlencoded; charset=US-ASCII', b'application/x-www-form-urlencoded; q=1'):
        assert parse(headers=((b'content-type', ok),), body=b'grant_type=x').form_keys == ('grant_type',)
    for bad in (b'application/x-www-form-urlencoded; charset=utf-16le', b'application/x-www-form-urlencoded; charset="UTF-16"',
                b'application/x-www-form-urlencoded; charset=utf-32'):
        refused(headers=((b'content-type', bad),), body=b'g\x00r\x00')              # non-ASCII-compatible form charset
    assert parse(headers=((b'content-type', b'text/plain; charset=utf-16le'),), body=b'x').body_kind == 'text/plain'
    assert parse(headers=((b'content-type', b'application/json'), (b'content-encoding', b'gzip')), body=b'x').body_kind == 'application/json'
    assert parse().body_kind == '' and parse().form_keys == ()


def test_encode_parse_roundtrip() -> None:
    r = parse(method=b'POST', host=b'api.example.test', path=b'/a/../b', query=b'q=1',
              headers=((b'x-api-key', b'PH'), (b'x-http-method', b'PUT')), body=b'{}')
    again = c.parse_request(c.unpack_payload(c.REQUEST, c.encode_request(r)[5:]))
    assert again == c.Request(r.method, r.scheme, r.host, r.is_ip, r.port, r.path, r.query, r.headers, (), r.body,
                              r.body_kind, r.form_keys)


# ---- body sealing (工程项 16; K-24) --------------------------------------------------------------
def test_sealed_body_cannot_be_written_or_resized() -> None:
    fd = c.seal_body(b'hello')
    try:
        assert c.seals_ok(fd, 5) and not c.seals_ok(fd, 4)
        for op in (lambda: os.pwrite(fd, b'X', 0), lambda: os.ftruncate(fd, 1), lambda: os.ftruncate(fd, 99)):
            with pytest.raises(OSError) as e:
                op()
            assert e.value.errno == errno.EPERM
        fd2 = os.open(f'/proc/self/fd/{fd}', os.O_RDWR)          # a second open of the same memfd
        try:
            with pytest.raises(OSError):
                os.pwrite(fd2, b'Y', 0)
        finally:
            os.close(fd2)
        assert os.pread(fd, 10, 0) == b'hello'
    finally:
        os.close(fd)


def test_unsealed_or_ordinary_fds_fail_the_seal_check(tmp_path: Path) -> None:
    fd = os.memfd_create('unsealed', os.MFD_CLOEXEC | c.MFD_ALLOW_SEALING)
    try:
        assert not c.seals_ok(fd, 0)
    finally:
        os.close(fd)
    for missing in (c.F_SEAL_WRITE, c.F_SEAL_SHRINK, c.F_SEAL_GROW):      # K-24: any one seal missing is refused
        fd = os.memfd_create('two-seals', os.MFD_CLOEXEC | c.MFD_ALLOW_SEALING)
        try:
            import fcntl
            fcntl.fcntl(fd, c.F_ADD_SEALS, c.REQUIRED_SEALS & ~missing)
            assert not c.seals_ok(fd, 0)
        finally:
            os.close(fd)
    plain = os.open(tmp_path / 'f', os.O_RDWR | os.O_CREAT)
    try:
        assert not c.seals_ok(plain, 0)
    finally:
        os.close(plain)
    assert not c.seals_ok(-1, 0)


# ---- K-41: TCB modules import only the standard library -------------------------------------
def imported_names(source: str) -> list[str]:
    """Every top-level module named by an import statement anywhere in the file (ast, not a regex)."""
    names = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.append(node.module)
    return names


TCB_DIRECTORIES = ('engine', 'connector', 'fileworker')     # fileworker: the row's file worker (validation.md H-15)
# of the management client, the part bin/engine-workspace loads to run the workspace transfers as root (validation.md
# A-10, K-41); the rest of client/ runs as the engine uid, inside the trusted decision channel
TCB_CLIENT = ('__init__.py', 'link.py', 'workspace.py')


def tcb_files() -> list[Path]:
    files = [p for directory in TCB_DIRECTORIES for p in sorted((ENGINE / directory).glob('*.py'))]
    files += [ENGINE / 'client' / name for name in TCB_CLIENT]
    assert all(p.exists() for p in files), 'no TCB files found'
    return files


def test_readme_tcb_list_names_every_tcb_module() -> None:
    """K-41: the README's TCB list is the named list the import scan is read against; it must match the directories,
    and for the client exactly the modules its root entry loads."""
    import re
    readme = (ENGINE / 'README.md').read_text(encoding='utf-8')
    listed = {}
    for line in readme.splitlines():
        for directory in (*TCB_DIRECTORIES, 'client'):
            if line.startswith(f'- {directory}/'):
                listed[directory] = set(re.findall(r'[a-z_]+\.py', line))
    for directory in TCB_DIRECTORIES:
        actual = {p.name for p in (ENGINE / directory).glob('*.py')}
        assert listed.get(directory) == actual, (directory, listed.get(directory), actual)
    assert listed.get('client') == set(TCB_CLIENT), listed.get('client')


def test_the_workspace_entry_loads_only_the_tcb_part_of_the_client() -> None:
    """K-41, A-10: what bin/engine-workspace (run as root) loads of the client is exactly TCB_CLIENT; the admin
    window, the attach window and their rendering stay out of the root process."""
    import subprocess
    probe = ('import atexit, runpy, sys\n'
             'atexit.register(lambda: print(sorted(m for m in sys.modules if m.split(".")[0] == "client")))\n'
             f'sys.argv = [{str(ENGINE / "bin/engine-workspace")!r}, "--help"]\n'
             'runpy.run_path(sys.argv[0], run_name="__main__")\n')
    done = subprocess.run([sys.executable, '-I', '-B', '-c', probe], capture_output=True, text=True, timeout=60)
    expected = sorted('client' if name == '__init__.py' else 'client.' + name[:-3] for name in TCB_CLIENT)
    loaded = done.stdout.strip().splitlines()[-1]
    assert loaded == str(expected), (loaded, done.stderr[-400:])


def test_tcb_imports_only_the_standard_library() -> None:
    offenders = []
    for path in tcb_files():
        for name in imported_names(path.read_text(encoding='utf-8')):
            top = name.split('.')[0]
            if top not in sys.stdlib_module_names and top not in TCB_DIRECTORIES:
                offenders.append((path.name, name))
    assert offenders == []


def test_import_scan_can_see_a_third_party_import(tmp_path: Path) -> None:
    """Reverse control for the scan: planted non-stdlib imports are reported, including the second name of a line."""
    (tmp_path / 'x.py').write_text('import os, requests\nfrom mitmproxy import http\ndef f():\n    import yaml\n')
    found = imported_names((tmp_path / 'x.py').read_text())
    assert [n for n in found if n.split('.')[0] not in sys.stdlib_module_names] == ['requests', 'mitmproxy', 'yaml']
