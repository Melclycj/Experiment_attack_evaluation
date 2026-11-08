"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import time
from unittest.mock import patch
from common import identity, utc
from record import RunDirectory
from run_evidence import Evidence
from run_registry import Case

class Adapter:
    def __init__(self, rt, attack):
        self.rt, self.attack = rt, attack
    def contract(self):
        return {'attack': self.attack, 'targets': ['file'], 'construction': 'offline-file', 'operations': ['read']}
    def prepare(self, config, repeat, contract):
        self.rt.event('prepare-attempt')
        return {'targets': {'file': {'kind': 'path', 'scope': 'host', 'path': '/tmp/nb-decoy-test/file'}},
                'parameters': {}, 'before': {'sha256': 'offline'}}
    def interact(self, handle, prepared):
        self.rt.event('interact')
    def synchronize(self, prepared, ready):
        self.rt.event('sync')
        return {'external': 'offline-mock-witness'}
    def observe(self, prepared, observed, captures, window):
        self.rt.event('judge')
        succeeded = self.rt.active == 'undefended' or self.attack.startswith('PC-')
        return {'file': {'expected_mechanism': 'file-view', 'observed_mechanism': 'file-view',
                         'control_ok': True, 'external_effect': succeeded, 'external_fact': {'before': 0, 'after': int(succeeded)},
                         'expected_observation': not succeeded, 'prerequisite_ok': succeeded}}
    def restore(self, prepared):
        self.rt.event('restore')

class FakeRuntime:
    """No process API, socket, compiler, engine, namespace, cgroup or mount."""
    def __init__(self, path, cases, fail=None, error=RuntimeError):
        self.fail, self.error, self.events = fail, error, []
        self.end, self.work_end = time.monotonic() + 600, time.monotonic() + 540
        self.bundle = {'run': '20261031T000000Z-offline',
                       'script_identities': {c.attack: identity(b'offline-test-module') for c in cases}}
        self.evidence = Evidence(RunDirectory(path, self.bundle['run']))
        self.host = {'kernel_match': False, 'readings_match': False}
        self.engine_identity = {'files': {'file': identity(b'offline-engine')}, 'baseline': None}
        self.stage, self.active, self.records = 'new', None, []
        self.resources, self.work = SimpleNamespace(roots={}), path
        self.command = SimpleNamespace(deadline=SimpleNamespace(end=self.work_end))
        upstream = SimpleNamespace(begin=lambda _: self.event('begin'), end=lambda: self.window())
        self.deployment = SimpleNamespace(upstream=upstream, manifest={'digest': 'offline'}, evidence_bytes=b'')
        self.targets = SimpleNamespace(verify=lambda targets: self.verify(targets))
    def event(self, name):
        self.events.append(name)
        if self.fail == name:
            raise self.error('injected ' + name)
    def verify(self, targets):
        self.event('verify'); return {'file': {'verified': True}}
    def prepare(self):
        for stage in ('cgroup', 'baseline-host', 'build', 'payload', 'deployment'):
            self.stage = stage; self.event(stage)
        self.stage = 'ready'
    def arm(self, config):
        self.event('arm-' + config); self.active = config
    def paired_targets(self, targets, contract):
        return targets
    def paths_accessible(self, targets):
        self.event('access')
    def start(self, config, **kwargs):
        self.event('start-' + config)
        return SimpleNamespace(poll=lambda: True, finish=lambda: self.finish())
    def finish(self):
        self.event('tree-empty'); return {'tree_empty': True}
    def window(self):
        self.event('window'); return {'requests': [], 'end': {'kind': 'end'}}
    def pump(self):
        self.event('pump')
    def close(self):
        self.event('close'); return {'ok': True, 'failures': [], 'retained': [], 'steps': []}

def cases(sync=None):
    return [Case('NB-01', 'NB-01.py', lambda rt: Adapter(rt, 'NB-01'), {'mechanism': 'file-view'}, sync=sync),
            Case('PC-FILE', 'PC-FILE.py', lambda rt: Adapter(rt, 'PC-FILE'), {'outcome': 'succeeded'}, kind='control'),
            Case('NB-02', 'NB-02.py', lambda rt: Adapter(rt, 'NB-02'), {'mechanism': 'file-view'})]

def header(rt):
    return {'run': rt.bundle['run'], 'engine': rt.engine_identity, 'harness': identity(b'offline-harness'),
            'spec': identity(b'offline-spec'), 'configs': {}, 'host': rt.host, 'policy': {}, 'deployment': {},
            'commands': [], 'started_at': utc(), 'finished_at': utc(), 'cleanup': {'ok': False}}

def patches(rt, stack):
    stack.enter_context(patch('run_batch.alarm', lambda _: nullcontext()))
    stack.enter_context(patch('run_batch.prepare_request', lambda *a: rt.event('request')))
    def collect(*args):
        rt.event('collect'); return {'control_ok': True, 'complete': True, 'captures': []}, {}
    stack.enter_context(patch('run_batch.collect', collect))
    def sync(work, req, state, observe):
        return None if rt.fail == 'sync-missing' else observe({'state': state})
    stack.enter_context(patch('run_batch.synchronize', sync))
