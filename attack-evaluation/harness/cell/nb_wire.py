"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import re
import socket
import struct

PROXY = '/run/w2/proxy.sock'
HOSTS = ('nb-decoy-upstream.test', 'nb-decoy-question.test')
MAX_FRAME = 65536


def frame(kind, fields):
    payload = bytes([kind]) + b''.join(struct.pack('>I', len(x)) + x for x in fields)
    return struct.pack('>I', len(payload)) + payload


def _pack_headers(headers):
    # Decoy-only: the cell may set x-nb-decoy-* headers (BD-02 own-key demonstration), nothing else. The field is a
    # flat packed list [name0, value0, ...] matching SPEC-canonical-form.md §3.1 headers(list).
    flat = []
    for name, value in headers:
        if not re.fullmatch(rb'x-nb-decoy-[a-z0-9-]{1,40}', name):
            raise ValueError('only x-nb-decoy-* request headers permitted')
        if not value or len(value) > 256 or any(b < 32 for b in value):
            raise ValueError('bounded printable decoy header value required')
        flat += [name, value]
    return struct.pack('>I', len(flat)) + b''.join(struct.pack('>I', len(x)) + x for x in flat)


def request_bytes(method, host, path, body=b'', headers=()):
    # Narrow subset of production SPEC-canonical-form.md §3.1. Cross-tested
    # against current connector.canonical; never import engine code inside a cell.
    if method not in ('GET', 'POST') or host not in HOSTS:
        raise ValueError('only local decoy GET/POST permitted')
    if not re.fullmatch(r'/nb-decoy-[A-Za-z0-9_-]{1,96}', path) or len(body) > 16384:
        raise ValueError('bounded decoy path/body required')
    return frame(1, [method.encode(), b'https', host.encode(), struct.pack('>H', 443),
                     path.encode(), b'', _pack_headers(headers), body])


def exact(conn, size, remaining):
    out = bytearray()
    while len(out) < size:
        conn.settimeout(remaining())
        data = conn.recv(size - len(out))
        if not data:
            raise ConnectionError('proxy response truncated before RESP_END')
        out.extend(data)
    return bytes(out)


def response(conn, remaining):
    head, body, total = None, bytearray(), 0
    for _ in range(128):
        size = int.from_bytes(exact(conn, 4, remaining), 'big')
        if not 1 <= size <= MAX_FRAME or total + size > 2 * MAX_FRAME:
            raise ValueError('proxy response frame/aggregate bound')
        raw = exact(conn, size, remaining)
        kind, pos, fields = raw[0], 1, []
        count = {0x11: 3, 0x12: 1, 0x13: 0}.get(kind)
        if count is None:
            raise ValueError('unexpected proxy response kind')
        for _field in range(count):
            if pos + 4 > size:
                raise ValueError('short response field')
            length = int.from_bytes(raw[pos:pos+4], 'big'); pos += 4
            if pos + length > size:
                raise ValueError('response field outside frame')
            fields.append(raw[pos:pos+length]); pos += length
        if pos != size:
            raise ValueError('extra response fields')
        total += size
        if kind == 0x11:
            if head is not None or len(fields[0]) != 1 or len(fields[1]) != 2:
                raise ValueError('duplicate/malformed response header')
            category, status = fields[0][0], int.from_bytes(fields[1], 'big')
            if category not in (1, 2, 3, 4) or (category != 1 and status != 0):
                raise ValueError('invalid response category/status')
            validate_headers(fields[2])
            head = {'category': category, 'status': status}
        elif head is None:
            raise ValueError('response body/end before header')
        elif kind == 0x12:
            body.extend(fields[0])
            if len(body) > MAX_FRAME:
                raise ValueError('response body bound')
        else:
            return {**head, 'body': bytes(body), 'complete': True}
    raise ValueError('proxy response frame count bound')


def validate_headers(data):
    if len(data) < 4:
        raise ValueError('short header list')
    count, pos = int.from_bytes(data[:4], 'big'), 4
    if count > 256 or count % 2:
        raise ValueError('header list count')
    for _ in range(count):
        if pos + 4 > len(data):
            raise ValueError('short header item')
        size = int.from_bytes(data[pos:pos+4], 'big'); pos += 4 + size
        if pos > len(data):
            raise ValueError('header item outside list')
    if pos != len(data):
        raise ValueError('trailing header bytes')


def open_request(method, host, path, remaining, body=b'', headers=()):
    wire = request_bytes(method, host, path, body, headers)
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(remaining())
        conn.connect(PROXY)
        conn.sendall(wire)
        return conn
    except BaseException:
        conn.close()
        raise


def exchange(method, host, path, remaining, body=b'', headers=()):
    with open_request(method, host, path, remaining, body, headers) as conn:
        return response(conn, remaining)
