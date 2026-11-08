"""4e pure/mock fixture identities and netlink bytes; never starts a worker or socket."""
import copy
import errno
import stat
import struct
from types import SimpleNamespace
from unittest.mock import Mock
from cell.nb_contract import encoded, stem
from cell.nb_netlink import HDR, IFINFO, attr, dump, exchange, veth
from common import json_bytes
from decoys import synchronization
from foura_fixtures import receipt, NONCE
from userns_report import Replay


def req(config='engine', repeat=1):
    return {'v': 1, 'run': 'offline4e', 'config': config, 'attack': 'NB-26', 'repeat': repeat,
        'targets': {'netns': {'kind': 'process', 'pid': 42, 'starttime': 77}},
        'parameters': {'local_if': 'nbdl1', 'peer_if': 'nbdp1'},
        'sync': synchronization('offline4e', config, 'NB-26', repeat)}


def message(kind, body, seq, flags=0):
    return HDR.pack(HDR.size + len(body), kind, flags, seq, 0) + body


def listing():
    body = IFINFO.pack(0, 0, 0, 1, 0, 0) + attr(3, b'lo\0')
    return [message(16, body, 1).hex(), message(3, struct.pack('=i', 0), 1).hex()]


def report(request, success=False, uid=None):
    p = request['parameters']
    ctl = exchange(dump(1), listing=True, factory=lambda *_: Replay(listing()))
    packet = veth(request['targets']['netns']['pid'], p['local_if'], p['peer_if'], 2)
    ack = message(2, struct.pack('=i', 0 if success else -errno.EPERM), 2).hex()
    value = exchange(packet, factory=lambda *_: Replay([ack]))
    calls = {k: {'rc': -1, 'errno': v} for k, v in {
        'unshare0': errno.EPERM, 'clone3': errno.ENOSYS, 'clone': errno.EPERM,
        'unshare_user': errno.EPERM}.items()}
    if success:
        calls.update({k: {'rc': 0, 'errno': 0} for k in ('unshare0', 'unshare_user', 'uid_map', 'unshare_net')})
    return {'task_count': 1, 'control': ctl, 'calls': calls, 'netlink': value,
            'attempt': stem(request), 'nonce': request['sync']['nonce'], 'pid': 3,
            'original_uid': uid if uid is not None else (70001 if request['config']=='engine' else 1000),
            'netns': 'net:[444]'}


def candidate_rows(peer=False):
    return [{'ifindex': 1, 'ifname': 'lo'}] + ([{'ifindex': 2, 'ifname': 'nbdp1'}] if peer else [])


class FakeCandidate:
    def __init__(self, rt):
        rt.candidate = self
        self.rt = rt
        self.ref = Mock()
        self.ref.read.return_value = {'pid': 42, 'start_time': 77, 'uids': [0]*4, 'cgroup': 'owned'}
        self.before = {'pid': 42, 'starttime': 77, 'net': 'net:[555]', 'user': 'user:[1]',
                       'links': candidate_rows()}
        self.current = copy.deepcopy(self.before)
    def read(self): return copy.deepcopy(self.current)
    def close(self): self.ref.close()


def boot():
    return [{'fd': i, 'dev': 1, 'ino': 100+i, 'type': stat.S_IFSOCK if i==3 else stat.S_IFCHR,
             'target': 'socket:[103]' if i==3 else '/dev/pts/7'} for i in range(4)]


def fd_observation(p, success=False):
    from cell.nb_fd import ascent
    cwd = '/work' if p['config']=='engine' else str(p['cwd'])
    identity = {'dev': 1, 'ino': 2, 'type': stat.S_IFDIR}
    obs, captures = {'inherited_fds': boot(), 'observed': [], 'captures': []}, {}
    def ev(label, phase='action', **v):
        obs['observed'].append({'label': label, 'phase': phase, 'values': v})
    ev('cwd-start', path=cwd, identity=identity)
    ev('cwd-end', identity=identity, restored=True)
    before = p['before']['control']
    ev('cwd-control', 'control', path=ascent(cwd+'/'+p['parameters']['control']), open_errno=0,
       chdir_errno=0, restored=True, identity={'dev':before['dev'],'ino':before['ino']})
    receipt(obs,captures,'cwd-control',p['parameters']['control_sentinel'].encode(),'control')
    for item in boot():
        label='fd-'+str(item['fd'])
        ev(label+'-eligibility', startup=item, live=True)
        ev(label,fd=item['fd'],path=ascent(p['targets']['key']['path']), restored=True,
           open_errno=errno.ENOTDIR,chdir_errno=errno.ENOTDIR,identity=None)
        receipt(obs,captures,label,b'')
    before=p['before']['target']
    ev('cwd',fd=None,path=ascent(p['targets']['key']['path']),restored=True,
       open_errno=0 if success else errno.ENOENT,chdir_errno=0,
       identity={'dev':before['dev'],'ino':before['ino']} if success else None)
    receipt(obs,captures,'cwd',p['tokens']['key'].encode() if success else b'')
    return obs,captures
