"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import re
import stat
import time
from env import RunCgroup
from process_identity import process_info
from safeio import plain_path
from upstream import wait_for


class AttemptGroup(RunCgroup):
    """Leaf of the same bounded batch cgroup; no host controllers changed.
    Needed to prove the undefended leader AND detached descendants have exited.
    Memory/pids restrictions are inherited from the batch, never relaxed.
    """
    def __init__(self, parent, label):
        parent._check()
        self.parent = parent
        super().__init__(parent.path, label)

    def create(self):
        self.parent._check()
        plain_path(self.path.parent)
        self.path.mkdir(mode=0o700)
        self.created, self.inode = True, self.path.stat().st_ino

    def empty(self):
        self._check()
        events = dict(line.split() for line in (self.path / 'cgroup.events').read_text().splitlines())
        return events.get('populated') == '0'


def as_host(groups):
    if not groups or any(type(g) is not int or g < 0 for g in groups):
        raise ValueError('explicit host supplementary groups required')
    return ['/usr/bin/setpriv', '--reuid=1000', '--regid=1000',
            '--groups=' + ','.join(map(str, groups)), '--bounding-set=-all',
            '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']


class Row:
    def __init__(self, runtime, config, workspace, label, seconds):
        self.runtime, self.config, self.workspace = runtime, config, workspace
        self.group, self.child, self.execution, self.uid = None, None, None, None
        self.closed, self.interaction = False, None
        self.kernel_only = False
        self.label, self.seconds = label, seconds

    def start(self):
        if self.config not in ('engine', 'undefended'):
            raise ValueError('unknown row configuration')
        if self.workspace not in ('work0', 'work1', 'work2') or (
                self.workspace == 'work2' and self.config != 'engine'):
            raise ValueError('invalid row workspace/configuration')
        if self.child is not None or self.execution is not None or self.group is not None or self.closed:
            raise ValueError('row lifecycle is single-use')
        rt = self.runtime
        if self.config == 'engine':
            options = getattr(rt, 'row_accounts', {}).get(self.workspace, ())
            self.execution = rt.deployment.admin.start_row(self.workspace, **({'accounts': options} if options else {}))
            rows = rt.deployment.admin.rows()
            match = re.search(r'^execution=' + re.escape(self.execution) +
                              r' workspace=\S+ state=\S+ uid=(\d+)$', rows, re.MULTILINE)
            if match:
                self.uid = int(match[1])
                if not rt.cap['first'] <= self.uid <= rt.cap['last']:
                    raise ValueError('row uid outside reserved batch range')
        else:
            from undefended import launch_context
            cwd, environment = launch_context(rt, self.workspace)
            self.group = AttemptGroup(rt.cgroup, self.label)
            self.group.create()
            self.child = rt.command.start([*as_host(rt.host['host_user']['groups']),
                '/usr/bin/python3.12', '-I', '-B', str(rt.payload['runner.py'])],
                cwd=cwd, env=environment, timeout=self.seconds, group=self.group)
        return self

    def poll(self):
        rt = self.runtime
        if self.execution:
            if self.kernel_only:
                # NB-23 cannot depend on the control plane it tries to stop.
                # A missing UID cannot use the normal fallback exclusion heuristic.
                if self.uid is None or not rt.cap['first'] <= self.uid <= rt.cap['last']:
                    raise ValueError('kernel-only barrier requires pinned row uid')
            else:
                rows = rt.deployment.admin.rows()
                if re.search(r'^execution=' + re.escape(self.execution) + r'(?: |$)', rows, re.MULTILINE):
                    return False
            # Admin disappearance is only the lifecycle barrier; verify kernel
            # tasks too. When a very short row was already gone at first list,
            # exclude only the pinned live support uids, never arbitrary uids.
            support = {r.uid for r in rt.rows if r is not self and r.uid is not None and not r.closed}
            for name in (rt.cgroup.path / 'cgroup.procs').read_text().split():
                try:
                    info = process_info(int(name))
                except FileNotFoundError:
                    continue
                uids = info['uids']
                if any(u == self.uid if self.uid is not None else
                       rt.cap['first'] <= u <= rt.cap['last'] and u not in support for u in uids):
                    return False
            return True
        return self.child.proc.poll() is not None and self.group.empty()

    def finish(self):
        if not self.poll():
            raise RuntimeError('row/process tree has not exited')
        if self.child:
            result = self.runtime.command.wait(self.child, allowed=tuple(range(-64, 256)))
        self.closed = True
        if self.group and self.group.created:
            self.group.remove()
        return {'tree_empty': True, 'runner_ok': result['exit_code'] == 0 if self.child else None,
                'execution': self.execution,
                'uid': self.uid, 'source': ('kernel-only' if self.kernel_only else 'admin-retired+kernel')
                if self.execution else 'cgroup.events'}

    def attach(self):
        if not self.execution or self.closed or self.interaction:
            raise ValueError('attach requires one live engine row')
        rt = self.runtime
        endpoint = rt.deployment.root / 'rows' / self.execution / 'attach.sock'
        def ready():
            match = re.search(r'^execution=' + re.escape(self.execution) + r' workspace=' +
                re.escape(self.workspace) + r' state=(\w+) uid=(\d+)$',
                rt.deployment.admin.rows(), re.MULTILINE)
            if match is None:
                raise RuntimeError('row disappeared or changed workspace before attach')
            uid = int(match[2])
            if not rt.cap['first'] <= uid <= rt.cap['last'] or (self.uid is not None and uid != self.uid):
                raise ValueError('attach row uid changed')
            if match[1] == 'PREPARING':
                return False
            if match[1] != 'ACTIVE':
                raise RuntimeError('row is not attachable: ' + match[1])
            try:
                info = endpoint.lstat()
            except FileNotFoundError:
                return False
            plain_path(endpoint)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 1000 or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError('attach endpoint type/owner/mode mismatch')
            self.uid = uid
            return True
        # ROW_START acknowledges allocation, not relay/socket readiness. Waiting
        # consumes the existing attempt deadline; it never grants extra time.
        wait_for(rt.command, ready, timeout=10, child=rt.deployment.engine)
        self.interaction = rt.deployment.admin.attach(self.execution, timeout=rt.command.deadline.left(30))
        return self.interaction

    def stop(self):
        if self.closed:
            return
        if self.execution:
            if not self.poll():
                self.runtime.deployment.admin.stop_row(self.execution)
        if self.group and self.group.created:
            self.group.kill_and_wait(timeout=self.runtime.command.deadline.left(5))
            self.group.remove()
        self.closed = True
