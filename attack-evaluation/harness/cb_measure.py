"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Host half of the approved connector wrapper. No process is launched here.
import json
import os
from pathlib import Path
import re
import stat
from common import identity, json_bytes
from process_identity import ProcessRef, process_info
from safeio import atomic_write, read_beneath

LIMIT = 262144


def validate_ready(ready, name, source, group_text, spawner_pid, info):
    if set(ready) != {'v','pid','ppid','execution','row_uid','nonce','uid','target','argv',
                      'logs','production_fds','log_limit'} or ready['v'] != 1:
        raise ValueError('wrapper ready schema')
    execution = ready['execution']
    if (not isinstance(execution, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}:[1-9][0-9]{0,19}', execution)
            or name != 'nb-decoy-' + execution.replace(':','-') + '.ready'
            or type(ready['pid']) is not int or ready['pid'] <= 1
            or ready['uid'] != 70999 or type(ready['row_uid']) is not int or ready['row_uid'] < 65536
            or not re.fullmatch(r'[0-9a-f]{48}', ready['nonce'])
            or ready['target'] != str(source / 'bin/connector')
            or not isinstance(ready['argv'], list)
            or ready['argv'][:1] != [ready['target']]
            or ready['argv'][-2:] != [str(ready['row_uid']), execution]
            or type(ready['log_limit']) is not int or not 0 < ready['log_limit'] <= LIMIT):
        raise ValueError('wrapper invocation/identity mismatch')
    if (info['pid'] != ready['pid'] or info['ppid'] != spawner_pid or ready['ppid'] != spawner_pid
            or info['uids'] != [70999] * 4 or group_text not in info['cgroup'].splitlines()
            or info['argv'][-len(ready['argv']):] != ready['argv']):
        raise ValueError('wrapper process does not belong to this deployment')
    if set(ready['logs']) != {'stdout','stderr'} or set(ready['production_fds']) != {'3','4'}:
        raise ValueError('wrapper descriptor coverage incomplete')
    for fd in ('3','4'):
        if ready['production_fds'][fd].get('mode') != stat.S_IFSOCK:
            raise ValueError('production descriptor is not a socket')
    for kind, log in ready['logs'].items():
        if (set(log) != {'name','dev','ino','mode'} or log['mode'] != stat.S_IFREG
                or log['name'] != name[:-6] + '-' + kind):
            raise ValueError('wrapper log name/type mismatch')
    if len({(v['dev'],v['ino']) for v in ready['logs'].values()}) != 2:
        raise ValueError('stdout and stderr aliases')


def wrapper_process(pid):
    before = process_info(pid)
    status = Path('/proc',str(pid),'status').read_text()
    parent = re.search(r'^PPid:\s*(\d+)$',status,re.MULTILINE)
    after = process_info(pid)
    if parent is None or any(before[k] != after[k] for k in ('pid','start_time','uids','cgroup','argv')):
        raise ValueError('wrapper identity changed during parent check')
    return {**after,'ppid':int(parent[1])}


def environment(ref, *, proc=Path('/proc')):
    before = ref.read()
    path = proc / str(before['pid']) / 'environ'
    with path.open('rb') as f:
        raw = f.read(LIMIT + 1)
    after = ref.read()
    if (len(raw) > LIMIT or (raw and not raw.endswith(b'\0'))
            or any(before[k] != after[k] for k in ('pid','start_time','uids','cgroup','argv'))):
        raise ValueError('incomplete/replaced process environment')
    return {'role':'connector','stage':'before-exec','process':after,'pidfd_pinned':True,
            'identity':identity(raw)}, raw


def descriptor_identity(pid, fd):
    s = Path('/proc',str(pid),'fd',str(fd)).stat()
    return {'dev':s.st_dev,'ino':s.st_ino,'mode':stat.S_IFMT(s.st_mode)}


def bounded_log(root, descriptor, bound, *, final, prior=b''):
    path = root / descriptor['name']
    before = path.lstat()
    if (stat.S_IFMT(before.st_mode) != stat.S_IFREG or before.st_nlink != 1
            or before.st_uid != 70999 or stat.S_IMODE(before.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (descriptor['dev'],descriptor['ino'])):
        raise ValueError('connector log identity/owner/type changed')
    data = read_beneath(root, descriptor['name'], bound)
    after = path.lstat()
    if (after.st_dev,after.st_ino) != (before.st_dev,before.st_ino) or not data.startswith(prior):
        raise ValueError('connector log replaced/truncated')
    # Reaching the cap is ambiguous even with an otherwise normal exit.
    return data, {'complete':bool(final and len(data) < bound), 'identity':identity(data),
                  'reason': 'output-cap-reached' if len(data) >= bound else '' if final else 'process-live'}


class ConnectorMeasurement:
    def __init__(self, deployment):
        self.deployment = deployment
        self.items, self.errors = {}, []
        self.finished = False

    def pump(self):
        if self.finished:
            return
        d = self.deployment
        if d.cb_logs is None:
            raise ValueError('measurement requires the selected credential deployment')
        for path in sorted(d.cb_logs.glob('*.ready')):
            if path.name in self.items:
                continue
            ready = json.loads(read_beneath(d.cb_logs, path.name, 16384))
            info = wrapper_process(ready.get('pid', -1)) if type(ready.get('pid')) is int and ready['pid'] > 1 else {}
            spawner = d.refs['spawner'].read()
            relative = '/' + d.command.cgroup.path.relative_to('/sys/fs/cgroup').as_posix()
            validate_ready(ready,path.name,d.source,'0::'+relative,spawner['pid'],info)
            if not d.cap['first'] <= ready['row_uid'] <= d.cap['last']:
                raise ValueError('wrapper row uid outside this batch reservation')
            ref = ProcessRef(ready['pid'],70999,d.command.cgroup)
            try:
                receipt, raw = environment(ref)
                d.command.budget.consume(raw)
                logs = {}
                for kind, desc in ready['logs'].items():
                    raw_log, checked = bounded_log(d.cb_logs,desc,ready['log_limit'],final=False)
                    d.command.budget.consume(raw_log)
                    logs[kind] = {'data':raw_log, **checked}
                for fd, want in ready['production_fds'].items():
                    if descriptor_identity(ready['pid'],fd) != want:
                        raise ValueError('production descriptor identity changed')
                # Register ownership BEFORE releasing an exec which can exit immediately.
                self.items[path.name] = {'ready':ready,'ref':ref,'environment':receipt,
                                         'environment_bytes':raw,'logs':logs,'released':False}
                release = d.cb_logs / (path.name[:-6] + '.release')
                atomic_write(release,json_bytes(ready)); release.chmod(0o644)
                self.items[path.name]['released'] = True
            except BaseException:
                if path.name not in self.items:
                    ref.close()
                raise

    def collect(self, execution=None):
        results = []
        for name, item in self.items.items():
            if execution is not None and item['ready']['execution'] != execution:
                continue
            exited = item['ref'].exited()
            for kind, desc in item['ready']['logs'].items():
                data, result = bounded_log(self.deployment.cb_logs,desc,item['ready']['log_limit'],
                                           final=exited,prior=item['logs'][kind]['data'])
                self.deployment.command.budget.consume(data[len(item['logs'][kind]['data']):])
                item['logs'][kind] = {'data':data,**result}
            results.append(item)
        if execution is not None and len(results) != 1:
            raise ValueError('row has no unique captured connector')
        return results

    def finalize(self):
        self.pump()
        results = self.collect()
        # Orphan output/pending files expose startup failures rather than silently
        # disappearing when no ready message was published.
        expected = set()
        for name, item in self.items.items():
            expected.update((name,name[:-6]+'.release'))
            expected.update(v['name'] for v in item['ready']['logs'].values())
        actual = {p.name for p in self.deployment.cb_logs.iterdir()}
        if actual != expected:
            self.errors.append('unclaimed-or-missing-wrapper-files:'+repr(sorted(actual ^ expected)))
        for item in results:
            if not item['released'] or not all(v['complete'] for v in item['logs'].values()):
                self.errors.append('incomplete-connector:'+item['ready']['execution'])
        self.finished = True
        return results

    def archive(self, evidence):
        rows = []
        for item in self.items.values():
            row = {'ready':item['ready'],'environment':item['environment'],
                   'environment_raw':evidence.raw(item['environment_bytes'],'connector.environ'),
                   'released':item['released'],'logs':{}}
            for kind, log in item['logs'].items():
                row['logs'][kind] = {k:v for k,v in log.items() if k != 'data'}
                row['logs'][kind]['raw'] = evidence.raw(log['data'],'connector-'+kind)
            rows.append(row)
        return {'configuration':'approved-launch-wrapper-2026-11-03','rows':rows,
                'complete':self.finished and not self.errors,
                'errors':list(self.errors) + ([] if self.finished else ['not-finalized'])}

    def close(self):
        for item in self.items.values():
            item['ref'].close()
