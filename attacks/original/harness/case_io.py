"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import hashlib
import os
import stat
from pathlib import Path
from cell.nb_contract import leaf
from cell.nb_io import Files
from common import json_bytes
from decoys import snapshot
from run_transport import publish, workspace_entry


class WorkspaceFiles:
    """Exact flat names only; restore never recursively removes a writable tree.
    May be used only for this batch's workspace before/after its writer is stopped.
    No previously existing user file can become an owned cleanup target.
    """
    def __init__(self, runtime, workspace, config=None):
        # The arm's own workspace (tests.md 1.7): the runtime's current arm unless one is named.
        self.root = Path(workspace_entry(runtime, workspace, config)['mount'])
        if not any(self.root == p or p in self.root.parents for p in runtime.resources.roots):
            raise ValueError('workspace outside exact run roots')
        self.files, self.names = Files(self.root), []
        self.identity = os.fstat(self.files.fd)

    def reserve(self, name):
        leaf(name)
        if not name.startswith('nb-decoy-') or name in self.names:
            raise ValueError('unique decoy name required')
        self.files.absent(name)
        self.names.append(name)
        return name

    def write(self, name, data):
        self.reserve(name)
        publish(self.files, name, data)
        return snapshot(self.root / name)

    def restore(self):
        if self.files.fd is None:
            return {'restored': True, 'names': list(self.names)}
        now = self.root.stat(follow_symlinks=False)
        if (now.st_dev, now.st_ino) != (self.identity.st_dev, self.identity.st_ino):
            raise ValueError('workspace changed before restoration')
        for name in reversed(self.names):
            try:
                info = os.stat(name, dir_fd=self.files.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(info.st_mode):
                raise ValueError('unexpected directory at owned file; retain for cleanup')
            os.unlink(name, dir_fd=self.files.fd)  # symlink itself, never target
            self.files.absent(name)
        os.fsync(self.files.fd)
        self.files.close()
        return {'restored': True, 'names': list(self.names)}

    def close(self):
        self.files.close()


def capture(observation, captures, label, phase='action'):
    items = [x for x in observation.get('captures', []) if x.get('label') == label and x.get('phase') == phase]
    if len(items) != 1:
        raise ValueError('missing/duplicate phase-labelled capture: ' + label)
    item = items[0]
    data = captures[item['path']]
    if item.get('bytes') != len(data) or item.get('sha256') != hashlib.sha256(data).hexdigest():
        raise ValueError('capture receipt does not match archived bytes')
    return data


def event(observation, label, phase='action'):
    found = [x['values'] for x in observation.get('observed', [])
             if x.get('label') == label and x.get('phase') == phase]
    if len(found) != 1 or not isinstance(found[0], dict):
        raise ValueError('missing/duplicate observation: ' + label)
    return found[0]


def closed_window(window, attempt=None):
    end, cursor, requests = window['end'], window['cursor'], window['requests']
    if (end.get('kind') != 'end' or not end.get('token') or type(cursor) is not int
            or end.get('seq') != cursor + len(requests)
            or (attempt is not None and end.get('attempt') != attempt)):
        raise ValueError('unclosed/mismatched external window')
    if [x.get('seq') for x in requests] != list(range(cursor, end['seq'])) or any(
            x.get('kind') != 'request' or x.get('attempt') != end.get('attempt') for x in requests):
        raise ValueError('external window has gaps/foreign requests')
    return requests


def positive_fact(effect, fact, *, reason=''):
    return {'expected_mechanism': 'allowed', 'observed_mechanism': 'allowed' if effect else None,
            'control_ok': True, 'external_effect': bool(effect), 'external_fact': fact,
            'expected_observation': False, 'invalid_reason': reason if not effect else ''}


def record_restore(rt, value):
    rt.evidence.raw(json_bytes(value), 'restore.json')
