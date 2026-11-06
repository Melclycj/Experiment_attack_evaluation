"""这是 1.1 隔离论证的验证测试：仅针对本次自建诱饵，不操作外部目标。
NB-26 的有界 rtnetlink 编码/解码；列网卡与 veth 请求共用 sendto/内核应答路径。"""
import errno
import socket
import struct
import time

HDR = struct.Struct('=IHHII')
IFINFO = struct.Struct('=BBHiII')


def attr(kind, value):
    size = len(value) + 4
    return struct.pack('=HH', size, kind) + value + bytes((-size) % 4)


def ifname(name):
    if not isinstance(name, str) or not name.startswith('nbd') or not name.isalnum() or len(name) > 15:
        raise ValueError('bounded per-attempt decoy interface name required')
    return name.encode() + b'\0'


def veth(pid, local, peer, seq):
    if type(pid) is not int or not 1 < pid < 2**31:
        raise ValueError('owned holder pid required')
    info = IFINFO.pack(0, 0, 0, 0, 0, 0)
    # IFLA_LINKINFO / INFO_DATA / VETH_INFO_PEER nests an ifinfomsg.
    other = info + attr(3, ifname(peer)) + attr(19, struct.pack('=I', pid))
    link = attr(1, b'veth\0') + attr(2 | 0x8000, attr(1 | 0x8000, other))
    body = info + attr(3, ifname(local)) + attr(18 | 0x8000, link)
    return HDR.pack(HDR.size + len(body), 16, 1 | 4 | 0x200 | 0x400, seq, 0) + body


def dump(seq):
    body = IFINFO.pack(0, 0, 0, 0, 0, 0)
    return HDR.pack(HDR.size + len(body), 18, 1 | 0x300, seq, 0) + body


def attributes(data):
    result, pos = {}, 0
    while pos < len(data):
        if pos + 4 > len(data):
            raise ValueError('short attribute')
        size, kind = struct.unpack_from('=HH', data, pos)
        if size < 4 or pos + size > len(data) or (kind & 0x3fff) in result:
            raise ValueError('invalid/duplicate attribute')
        result[kind & 0x3fff] = data[pos + 4:pos + size]
        pos += (size + 3) & ~3
    return result


def messages(data, seq):
    pos, result = 0, []
    while pos < len(data):
        if len(data) - pos < HDR.size:
            raise ValueError('truncated netlink header')
        size, kind, flags, actual, pid = HDR.unpack_from(data, pos)
        if size < HDR.size or pos + size > len(data) or actual != seq or flags & 0x10:
            raise ValueError('netlink length/sequence/dump-interrupted mismatch')
        result.append((kind, data[pos + HDR.size:pos + size]))
        pos += (size + 3) & ~3
    return result


def exchange(packet, *, listing=False, factory=None, clock=time.monotonic):
    factory = factory or socket.socket
    seq = HDR.unpack_from(packet)[3]
    result = {'send_rc': None, 'send_errno': 0, 'ack_errno': None, 'links': [], 'complete': False,
              'request_hex': packet.hex(), 'replies_hex': []}
    sock = None
    try:
        sock = factory(getattr(socket, 'AF_NETLINK', 16), socket.SOCK_RAW, 0)
        sock.settimeout(1)
        sock.bind((0, 0))
        try:
            result['send_rc'] = sock.sendto(packet, (0, 0))
        except OSError as exc:
            result['send_rc'], result['send_errno'] = -1, exc.errno
            return result
        if result['send_rc'] != len(packet):
            raise ValueError('short netlink send')
        end, total = clock() + 2, 0
        while clock() < end and total <= 32768:
            data, address = sock.recvfrom(32769)
            total += len(data)
            if address[0] != 0 or total > 32768:
                raise ValueError('nonkernel/oversized reply')
            result['replies_hex'].append(data.hex())
            for kind, body in messages(data, seq):
                if kind == 2:
                    if len(body) < 4:
                        raise ValueError('short NLMSG_ERROR')
                    code = struct.unpack_from('=i', body)[0]
                    if code > 0:
                        raise ValueError('positive kernel error')
                    result['ack_errno'] = code
                    result['complete'] = not listing or code != 0
                elif kind == 3 and listing:
                    if body and (len(body) < 4 or struct.unpack_from('=i', body)[0] != 0):
                        raise ValueError('failed dump completion')
                    result['complete'] = True
                elif kind == 16 and listing:
                    if len(body) < IFINFO.size:
                        raise ValueError('short link')
                    attrs = attributes(body[IFINFO.size:])
                    name = attrs[3]
                    if not name.endswith(b'\0'):
                        raise ValueError('unterminated interface')
                    result['links'].append({'ifindex': IFINFO.unpack_from(body)[3], 'ifname': name[:-1].decode()})
                else:
                    raise ValueError('unexpected netlink reply type')
            if result['complete']:
                return result
        raise TimeoutError('netlink reply bound')
    except OSError as exc:
        result['io_errno'] = exc.errno or errno.ETIMEDOUT
        return result
    finally:
        if sock is not None:
            sock.close()
