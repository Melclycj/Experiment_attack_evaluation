"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import base64
import os
from pathlib import Path
import secrets
import stat
from cell.nb_contract import decode
from cell.nb_io import PublicationPending
from common import identity, json_bytes
from connection_store import ConnectionStore
from listener_witness import inspect_listener, pin_child
from upstream import wait_for


class Endpoint:
    """Per-address service under the existing deadline/cgroup supervisor.
    Creation is called only from Runtime's authorized attempt path, never import.
    """
    def __init__(self, rt, name, value, wire, attempt, *, markers=False, owner='user', netfd=None):
        self.rt, self.name, self.value, self.wire = rt, name, dict(value), wire
        self.attempt, self.secret, self.nonce = attempt, secrets.token_hex(24), secrets.token_hex(24)
        self.netfd, self.markers_enabled, self.owner = netfd, markers, owner
        self.store = self.child = self.ref = self.before = None
        self.ended, self.registered = False, False

    def prefix(self):
        if self.netfd is None:
            return []
        network = self.rt.network
        if not network.prepared or network.closed or self.netfd not in network.fds:
            raise ValueError('connection service requires pinned owned network')
        return ['/usr/bin/nsenter', f'--net=/proc/{os.getpid()}/fd/{self.netfd}', '--']

    def witness(self):
        fact = inspect_listener(self.ref, self.value, protocol=self.wire)
        if self.value['kind'] == 'path':
            s = Path(self.value['path']).lstat()
            uid, mode = (0, 0o660) if self.owner == 'daemon' else (1000, 0o600)
            if not stat.S_ISSOCK(s.st_mode) or (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) != (uid, 1000, mode):
                raise ValueError('decoy socket ownership/permission mismatch')
            fact['path_identity'] = {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid, 'gid': s.st_gid, 'mode': mode}
        return fact

    def start(self, key):
        rt = self.rt
        if not rt.network.prepared or rt.network.closed:
            raise ValueError('no private disconnected network')
        self.store = ConnectionStore(rt, self.name)
        if self.value['kind'] == 'path':
            if self.value['path'] != str(self.store.root / 'socket'):
                raise ValueError('socket does not belong to newly created store')
        self.store.write_config({'target': self.value, 'wire': self.wire, 'attempt': self.attempt,
                                 'secret': self.secret, 'nonce': self.nonce,
                                 'markers': self.markers_enabled, 'owner': self.owner})
        seconds = rt.command.deadline.left(30)
        self.child = rt.command.start([*self.prefix(), '/usr/bin/python3', '-I', '-B',
            str(Path(__file__).with_name('connection_service.py')), str(self.store.root), str(seconds)], timeout=seconds)
        def ready():
            try:
                raw = self.store.read('ready.json', 16384)
                rt.evidence.raw(raw, 'listener-ready.json')
                return decode(raw)
            except (FileNotFoundError, PublicationPending):
                return None
        info = wait_for(rt.command, ready, child=self.child, timeout=5)
        if info.get('nonce') != self.nonce or info.get('pid') != self.child.proc.pid or info.get('wire') != self.wire:
            raise ValueError('connection readiness identity mismatch')
        actual = info['target']
        if self.value['kind'] == 'inet' and self.value['port'] == 0:
            if actual != {**self.value, 'port': actual.get('port')} or not 1 <= actual['port'] <= 65535 or actual['port'] == 3128:
                raise ValueError('allocated listener endpoint mismatch')
        elif actual != self.value:
            raise ValueError('listener address changed')
        self.value = actual
        self.ref = pin_child(rt, self.name, self.child, 0)
        rt.targets.add_listener(key, self.value, self.ref, self.witness)
        self.registered = True
        self.before = self.witness()
        return self.value

    def sample(self):
        """Archive even malformed/partial journals before interpreting quality."""
        if self.store is None:
            return {'entries': [], 'markers': {}, 'raw': None}
        try:
            raw = self.store.read('journal.jsonl')
        except FileNotFoundError:
            raw = b''
        ref = self.rt.evidence.raw(raw, 'connections.jsonl')
        markers = self.store.markers()
        table = {k: {'payload_base64': base64.b64encode(v).decode(), **identity(v)} for k, v in markers.items()}
        marker_ref = self.rt.evidence.raw(json_bytes(table), 'markers.json')
        result = {'entries': [], 'markers': table, 'raw': ref, 'marker_raw': marker_ref}
        if raw and not raw.endswith(b'\n'):
            result['error'] = 'truncated connection journal'
        for line in raw.splitlines():
            try:
                entry = decode(line)
                if not isinstance(entry, dict):
                    raise ValueError('journal entry is not an object')
                result['entries'].append(entry)
            except (ValueError, TypeError) as exc:
                result['error'] = 'malformed connection journal: ' + str(exc)
        if len(result['entries']) > 64:
            result['error'] = 'connection count bound exceeded'
        return result

    def finish(self, *, tree_empty):
        if tree_empty is not True or self.child is None or self.ended:
            raise ValueError('connection end needs attack tree exit and live service')
        if self.witness() != self.before:
            raise ValueError('listener identity changed during window')
        # Batch has already closed the attack tree and waited the upstream's 1 s.
        result = self.rt.command([*self.prefix(), '/usr/bin/python3', '-I', '-B',
            str(Path(__file__).with_name('connection_end.py'))], timeout=4,
            env={'NB_TARGET': json_bytes(self.value).decode(), 'NB_WIRE': self.wire, 'NB_END_SECRET': self.secret})
        if decode(result['stdout']) != {'echo': True}:
            raise ValueError('connection end echo missing')
        self.rt.command.wait(self.child)
        if self.child.proc.poll() != 0:
            raise ValueError('connection service did not close normally')
        self.ended = True
        sample = self.sample()
        entries = sample['entries']
        return {**sample, 'cursor': 0, 'end': entries[-1] if entries else {},
                'requests': entries[:-1], 'listener': self.before, 'attempt': self.attempt,
                'expected_secret': self.secret, 'marker_required': self.markers_enabled}

    def restore(self):
        if self.child is not None and self.child.proc.poll() is None:
            raise ValueError('service still live; retain objects for batch cleanup')
        if self.store is not None:
            self.sample()
            return self.store.restore()
        return {'restored': True, 'root': None}

    def dispose(self):
        if self.store is not None:
            self.store.close()
