"""NB-26 外部观察：只读取本批持有的 netns、固定 pidfd 身份与网卡列表。"""
import json
import os
from pathlib import Path
from process_identity import ProcessRef, process_info
from net import IP, validate_links


def ns(pid, kind):
    return os.readlink(f'/proc/{pid}/ns/{kind}')


def links(rows):
    if not isinstance(rows, list) or len(rows) > 16:
        raise ValueError('bounded link list required')
    result = sorted([{'ifindex': r['ifindex'], 'ifname': r['ifname']} for r in rows],
                    key=lambda r: r['ifindex'])
    if (any(type(r['ifindex']) is not int or r['ifindex'] <= 0 or not isinstance(r['ifname'], str) for r in result)
            or len({r['ifindex'] for r in result}) != len(result)
            or len({r['ifname'] for r in result}) != len(result)):
        raise ValueError('invalid/duplicate link identity')
    return result


class Candidate:
    def __init__(self, rt):
        self.rt, self.ref = rt, None
        value = rt.deployment.network_info['candidate']
        self.pid, self.fd = value['pid'], value['fd']
        holders = [c for c in rt.network.holders if c.proc.pid == self.pid]
        if len(holders) != 1 or holders[0].proc.poll() is not None or self.fd not in rt.network.fds:
            raise ValueError('candidate is not a live owned namespace holder')
        self.child = holders[0]
        self.ref = ProcessRef(self.pid, 0, rt.cgroup)
        try:
            self.net, self.user = ns(self.pid, 'net'), ns(self.pid, 'user')
            if self.user != ns(os.getpid(), 'user') or self.net == ns(os.getpid(), 'net'):
                raise ValueError('candidate must be separate netns in initial user namespace')
            self.before = self.read()
            validate_links(self.before['links'])
        except BaseException:
            self.close()
            raise

    def read(self):
        info = self.ref.read()
        if (self.child.proc.poll() is not None or self.fd not in self.rt.network.fds
                or ns(self.pid, 'net') != self.net or ns(self.pid, 'user') != self.user
                or os.readlink(f'/proc/self/fd/{self.fd}') != self.net):
            raise ValueError('candidate namespace identity changed')
        raw = self.rt.network.in_namespace(self.fd, [IP, '-j', 'link', 'show'], timeout=2)
        rows = links(json.loads(raw['stdout']))
        self.ref.read()
        return {'pid': info['pid'], 'starttime': info['start_time'], 'net': self.net,
                'user': self.user, 'links': rows}

    def close(self):
        if self.ref is not None:
            self.ref.close()
            self.ref = None


def worker_ref(rt, uid, report, *, group=None, pid=None):
    """Host procfs identity, never trust a cell-supplied host PID."""
    group = group or rt.cgroup
    matches = []
    for value in (group.path / 'cgroup.procs').read_text().split():
        candidate = int(value)
        if pid is not None and candidate != pid:
            continue
        try:
            info = process_info(candidate)
            if info['uids'] != [uid] * 4 or not any(v.endswith('/nb26_worker.py') for v in info['argv']):
                continue
            status = (Path('/proc') / value / 'status').read_text()
            nspid = next(s for s in status.splitlines() if s.startswith('NSpid:')).split()[1:]
            if int(nspid[-1]) != report['pid'] or ns(candidate, 'net') != report['netns']:
                continue
            if len(list((Path('/proc') / value / 'task').iterdir())) != 1:
                raise ValueError('worker is not externally single-threaded')
            matches.append(candidate)
        except FileNotFoundError:
            continue
    if len(matches) != 1 or report['original_uid'] != uid:
        raise ValueError('live worker identity/uid is not uniquely witnessed')
    return ProcessRef(matches[0], uid, group)


def effect(before, after, peer):
    if any(before[k] != after[k] for k in ('pid', 'starttime', 'net', 'user')):
        raise ValueError('namespace identity changed across observation')
    base, now = links(before['links']), links(after['links'])
    added = [r for r in now if r not in base]
    if any(r not in now for r in base) or any(r['ifname'] != peer for r in added) or len(added) > 1:
        raise ValueError('unexpected candidate interface change')
    return len(added) == 1
