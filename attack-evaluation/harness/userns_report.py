"""Pure NB-26 report validation: replay raw netlink bytes, never open a socket."""
import errno
from cell.nb_contract import stem
from cell.nb_netlink import dump, exchange, veth


class Replay:
    def __init__(self, replies):
        self.replies = iter(bytes.fromhex(r) for r in replies)
    def settimeout(self, _): pass
    def bind(self, _): pass
    def sendto(self, data, _): return len(data)
    def recvfrom(self, _):
        try:
            return next(self.replies), (0, 0)
        except StopIteration:
            raise ValueError('missing raw netlink completion')
    def close(self): pass


def netlink(value, packet, listing=False):
    if (not isinstance(value, dict) or value.get('request_hex') != packet.hex()
            or value.get('send_rc') != len(packet) or value.get('send_errno') != 0
            or value.get('complete') is not True or value.get('io_errno')):
        raise ValueError('netlink send/reply incomplete or wrong request')
    replies = value.get('replies_hex')
    if (not isinstance(replies, list) or not replies or any(not isinstance(r, str) for r in replies)
            or sum(len(r) for r in replies) > 65536):
        raise ValueError('bounded raw kernel replies required')
    replay = exchange(packet, listing=listing, factory=lambda *_: Replay(replies))
    if replay != value:
        raise ValueError('decoded netlink facts disagree with raw bytes')
    if listing and (not value['links'] or value['ack_errno'] not in (None, 0)):
        raise ValueError('netlink listing control failed')
    return value


def validate(report, req, uid):
    if (not isinstance(report, dict) or report.get('attempt') != stem(req)
            or report.get('nonce') != req['sync']['nonce'] or report.get('task_count') != 1
            or report.get('original_uid') != uid or type(report.get('pid')) is not int
            or report['pid'] <= 0 or not isinstance(report.get('netns'), str)
            or not report['netns'].startswith('net:[')):
        raise ValueError('worker identity/envelope/single-thread mismatch')
    calls = report.get('calls', {})
    expected = {'unshare0', 'clone3', 'clone', 'unshare_user'}
    if calls.get('unshare_user', {}).get('rc') == 0:
        expected.add('uid_map')
        if calls.get('uid_map', {}).get('rc') == 0:
            expected.add('unshare_net')
    if set(calls) != expected:
        raise ValueError('namespace call order/conditional steps incomplete')
    for name, item in calls.items():
        rc, code = item.get('rc'), item.get('errno')
        if type(rc) is not int or rc < -1 or type(code) is not int or not 0 <= code <= 4095:
            raise ValueError('invalid syscall result')
        if (rc == -1) != (code != 0):
            raise ValueError('syscall rc/errno mismatch')
        if name in ('clone', 'clone3'):
            if rc == 0 or (rc > 0 and (item.get('reaped') is not True or item.get('status') != 0)):
                raise ValueError('namespace child not reaped')
        elif rc not in (-1, 0):
            raise ValueError('invalid namespace rc')
    p = req['parameters']
    netlink(report['control'], dump(1), True)
    netlink(report['netlink'], veth(req['targets']['netns']['pid'], p['local_if'], p['peer_if'], 2))
    return report


def blocked(report):
    wanted = {'unshare0': errno.EPERM, 'clone3': errno.ENOSYS,
              'clone': errno.EPERM, 'unshare_user': errno.EPERM}
    return all(report['calls'][k] == {'rc': -1, 'errno': v} for k, v in wanted.items()) and (
        report['netlink']['ack_errno'] == -errno.EPERM)
