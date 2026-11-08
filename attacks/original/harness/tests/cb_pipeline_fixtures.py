"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Real CredentialBatch, CredentialCase, reference rows, judge, restore and report.
# Only the production row boundary (a live engine/undefended row) and the admin
# socket / test service process are replaced; the service window logic is real.
from contextlib import nullcontext
from dataclasses import replace
import hashlib
import json
import secrets
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from cb_judge_fixtures import Engine as Diagnostics, traffic
from cb_profile import ENDPOINTS, HOSTS
from cb_registry import registry
from cb_runtime import CredentialRuntime
from cb_scan import Scan
from cb_sentinels import new_credential
from cb_service import Windows
from common import identity, json_bytes, utc
from host import crash_inventory
from cb_output import CountedRunDirectory
from run_evidence import Evidence

RUN = '20261103T000000Z-cboffline'
PLACEMENT = {'api-key':1,'bearer':2,'token':2,'basic':3}


class Admin:
    """In-memory management port that writes the same metadata/truth/mirror files."""
    def __init__(self, root, rt):
        self.root, self.rt, self.calls, self.entries = root, rt, [], {}

    def call(self, *argv):
        self.calls.append(argv)
        self.rt.event('admin-' + argv[0] + '-' + argv[1])
        verb = argv[:2]
        if verb == ('cred', 'put'):
            key, account, placement = argv[2:5]
            options = dict(zip(argv[5::2], argv[6::2]))
            base = self.root / 'state/credentials' / key
            base.mkdir(parents=True, exist_ok=True)
            meta = {'v':2,'account':account,'host_port':key,'placement':PLACEMENT[placement],
                    'word':{'bearer':'Bearer','token':'token'}.get(placement,''),'has_truth_b':placement=='basic',
                    'token_endpoint':'','registration_endpoint':'','device_authorization_endpoint':'','generation':1}
            (base / (account + '.json')).write_bytes(json_bytes(meta))
            (base / (account + '.1.truth_a')).write_bytes(Path(options['--truth-file']).read_bytes())
            if '--truth-b-file' in options:
                (base / (account + '.1.truth_b')).write_bytes(Path(options['--truth-b-file']).read_bytes())
        elif verb == ('cred', 'del'):
            for path in list((self.root / 'state/credentials' / argv[2]).iterdir()):
                if path.name.startswith(argv[3] + '.'):path.unlink()
        elif verb == ('entry', 'put'):
            accounts = [argv[i + 1] for i, a in enumerate(argv) if a == '--account']
            self.entries[(argv[2], argv[5])] = accounts;self.mirror(argv[2])
        elif verb == ('entry', 'del'):
            self.entries.pop((argv[2], argv[4]), None);self.mirror(argv[2])
        else:
            raise ValueError('unexpected admin verb')
        return {'ok': True, 'argv': list(argv[:2])}

    def mirror(self, workspace):
        path = self.root / 'state/workspaces' / (workspace + '.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json_bytes({k[1]: v for k, v in self.entries.items() if k[0] == workspace}))


class Upstream:
    """Real cb_service.Windows journal; requests are injected instead of read from sockets."""
    def __init__(self):
        self.events, self.current, self.child = [], None, object()
        self.service = Windows(self.events.append)

    def begin(self, attempt):
        self.secret = secrets.token_hex(24);self.start = len(self.events)
        self.service.command({'op':'begin','attempt':attempt,'secret':self.secret})
        self.current = attempt

    def request(self, host, path, heads=(), body=b'', method='GET', port=443, sni=None):
        headers = [('host', host), *[(k, v.decode()) for k, v in heads]]
        if body:headers.append(('content-length', str(len(body))))
        head = (method + ' ' + path + ' HTTP/1.1\r\n' + '\r\n'.join(k + ': ' + v for k, v in headers)).encode()
        return self.service.receive(method, path, host, headers, head, body, port=port,
                                    sni=sni or (host if port == 443 else None), peer=['10.0.0.2', 40000])

    def route(self, source, path):
        if self.current is None:raise RuntimeError('route control outside an attempt window')
        self.request(HOSTS['sink'], path, sni=source)
        return {'source': source, 'host': HOSTS['sink'], 'path': path, 'status': 200, 'ok': True}

    def end(self):
        for host, port in ENDPOINTS:
            self.request(host, '/nb-end', body=self.secret.encode(), method='POST', port=port)
        self.service.command({'op':'finish','secret':self.secret})
        events = self.events[self.start:];self.current = None
        return {'cursor': events[0]['cursor'], 'end': events[-1],
                'requests': [e for e in events if e['kind'] == 'request'],
                'endpoints': [e for e in events if e['kind'] == 'endpoint-end']}


class Targets:
    def __init__(self, rt):
        self.rt, self.live = rt, {}
    def add_listener(self, key, target, ref, inspect):
        if key in self.live:raise ValueError('target already owned')
        self.live[key] = target
    def verify(self, targets):
        self.rt.event('verify')
        if any(self.live.get(k) != v for k, v in targets.items()):raise ValueError('unowned target')
        return {k: {'verified': True} for k in targets}
    def release(self, key, value):
        if self.live.pop(key, None) != value:raise ValueError('released an unowned target')


class Control:
    """Stands in for one measured 1.1 control: owns accounts, returns an allowed fact."""
    def __init__(self, rt, attack):
        self.rt, self.attack, self.files = rt, attack, None
    def contract(self):
        return {'attack':self.attack,'targets':['control'],'construction':'offline-control','operations':['allowed']}
    def prepare(self, config, repeat, contract):
        values = {k: new_credential('nb-decoy-' + k + '-' + secrets.token_hex(12), HOSTS['api-key'], 443, 'api-key')
                  for k in 'ABC'}
        self.rt.own(values.values(), self.attack, config)
        target = {'kind': 'inet', 'address': '192.0.2.1', 'port': 443}
        self.rt.targets.add_listener('control', target, None, None)
        prepared = {'targets': {'control': target}, 'parameters': {}, 'before': {}, 'all_accounts': list(values.values())}
        if getattr(self.rt, 'control_metadata', True):
            prepared['metadata'] = [{'credential': c.metadata()} for c in values.values()]
        return prepared
    def interact(self, handle, prepared):
        pass
    def observe(self, prepared, observation, captures, window):
        return {'control': {'external_effect': True, 'control_ok': True}}
    def restore(self, prepared):
        self.rt.event('restore-' + self.attack);self.rt.targets.release('control', prepared['targets']['control'])


class Engine:
    def __init__(self):
        self.proc, self.streams = SimpleNamespace(poll=lambda: 0), 0
        self.buffers = {'stdout': bytearray(), 'stderr': bytearray()}


class Measurement:
    finished, errors, items = True, [], {}
    def archive(self, evidence):
        return {'configuration': 'offline', 'rows': [], 'complete': True, 'errors': []}


class Runtime:
    """No process, socket, compiler, engine, namespace, cgroup or mount."""
    own = CredentialRuntime.own
    arm = CredentialRuntime.arm
    use, workspace = CredentialRuntime.use, CredentialRuntime.workspace  # v4: each arm's own work0

    def __init__(self, path, cases, *, dump='not-produced', fail=None, leak=None):
        self.events, self.fail, self.leak, self.dump, self.serial = [], fail, leak, dump, 0
        self.end = time.monotonic() + 600;self.work_end = self.end - 60
        self.bundle = {'run': RUN, 'unit': 'credential-binding',
                       'script_identities': {c.attack: identity(b'offline-module') for c in cases}}
        (path / 'runs').mkdir()
        self.evidence = Evidence(CountedRunDirectory(path / 'runs', RUN))
        (path / 'crashes').mkdir()
        self.host = {'kernel_match': False, 'readings_match': False, 'crash_directory': str(path / 'crashes'),
                     'crashes': crash_inventory(path / 'crashes')}
        self.engine_identity = {'files': {'file': identity(b'offline-engine')}, 'baseline': None}
        self.stage, self.active, self.records, self.rows = 'new', None, [], []
        root = path / 'deploy';scratch = path / 'scratch'
        workspaces = {w: {'mount': str(root / 'w' / w)} for w in ('work0', 'work1', 'work2')}
        for w in workspaces.values():Path(w['mount']).mkdir(parents=True)
        scratch.mkdir()
        self.resources = SimpleNamespace(roots={root: 'deployment', scratch: 'scratch'})
        self.command = SimpleNamespace(deadline=None)
        self.deployment = SimpleNamespace(root=root, scratch=scratch, workspaces=workspaces,
            host_workspaces=workspaces,  # offline: arms share; the v4 split is tested in test_9_engine_v4
            admin=Admin(root, self), upstream=Upstream(), manifest={'digest': 'offline'},
            evidence_bytes=b'', engine=Engine(), cb_measure=Measurement(), refs={})
        self.targets = Targets(self)
        self.cb_accounts, self.row_accounts, self.undefended_environment = [], {}, {}
        self.cb_attempts, self.cb_owners, self.cb_e09_seen = [], {}, b''
        self.late_e09 = b'';self.late_dump = b''

    def event(self, name):
        self.events.append(name)
        if self.fail is not None and self.fail(name):raise RuntimeError('injected ' + name)

    def prepare(self):
        self.event('prepare');self.stage = 'ready'

    def close(self):
        self.event('close')
        if self.late_e09:self.deployment.evidence_bytes = self.late_e09
        if self.late_dump:(Path(self.host['crash_directory']) / 'wsl-crash-late.dmp').write_bytes(self.late_dump)
        return {'ok': True, 'failures': [], 'retained': [], 'steps': []}


def coverage(rt, prepared, observation, captures):
    scan = Scan(prepared['all_accounts'])
    scan.add('upstream', 'upstream-index', b'', complete=True, provenance={'scan_owner': 'cb_judge.request_scan'})
    for name, data in captures.items():
        scan.add('responses', 'capture', data, complete=True, provenance={'workspace_name': name})
    if not captures:scan.unavailable('responses', 'runner', 'no verified captures')
    scan.add('trace', 'runner-observation', json_bytes(observation), complete=True, provenance={'offline': True})
    for outlet in ('e09', 'core-connector-output', 'environ'):
        scan.add(outlet, 'offline-' + outlet, b'', complete=True, provenance={'offline': True})
    if rt.dump == 'not-produced':
        # Stand-in for cb_outlets' record under the WSL rule; the rule itself is tested in test_cb_collect.
        scan.not_produced('core-dump', 'lifecycle', {'offline': 'stand-in'})
    else:
        scan.unavailable('core-dump', 'lifecycle', 'pipe-core-collector-not-accounted')
    if rt.leak:rt.leak(prepared, scan)
    return scan.result()


def run_row(rt, case, prepared, files, *, config, workspace='work0', interact=None, on_sync=None):
    rt.serial += 1;rt.event('row-' + workspace + '-' + config)
    p = prepared['parameters'];p['attempt_nonce'] = secrets.token_hex(24)
    up = rt.deployment.upstream;up.begin(p['attempt_nonce'])
    obs = {'complete': True, 'control_ok': True, 'observed': [], 'captures': []};captures = {}
    def capture(label, data, phase='action'):
        name = 'nb-decoy-' + label + '-' + secrets.token_hex(4);captures[name] = data
        obs['captures'].append({'phase':phase,'label':label,'path':name,'bytes':len(data),
                                'sha256':hashlib.sha256(data).hexdigest()})
    def observation(label, phase='action', **values):
        obs['observed'].append({'phase': phase, 'label': label, 'values': values})
    synced = on_sync(prepared, {'ready': True}) if on_sync else None
    engine = None
    if p.get('reference'):
        account = rt.row_accounts['work1'][0][1]
        c = next(c for c in prepared['all_accounts'] if c.account == account)
        up.request(c.host, p['path'], [(c.header, c.value)])
        capture('config', json_bytes({'credential': p['placeholder']}));observation('config', read=True, errno=None)
        capture('reference', b'wire');capture('reference-body', json_bytes({'token': 'nonsecret'}))
        observation('reference', status=200, category=1, complete=True)
    elif prepared.get('spec'):
        engine = Diagnostics() if config == 'engine' else None
        traffic(prepared['spec'], p, prepared['accounts'], config, up.request, capture, observation, engine)
    else:
        capture('control', b'nonsecret control receipt')
        if getattr(rt, 'control_traffic', None):rt.control_traffic(up, prepared)
    rt.event('row-traffic-' + case.attack + '-' + config)
    window = up.end()
    result = {'observation': obs, 'captures': captures, 'window': window,
              'coverage': coverage(rt, prepared, obs, captures), 'tree': {'tree_empty': True},
              'row': ('work1' if p.get('reference') else workspace) + ':' + str(rt.serial), 'synchronization': synced}
    result['evidence'] = rt.evidence.raw(json_bytes({k: v for k, v in result.items() if k != 'captures'}))
    result['diagnostics'] = engine.bytes() if engine else None
    return result


def cases(targets=(), controls=('PC-FILE', 'PC-PROXY', 'PC-DIALOGUE')):
    found = registry(targets)
    for name in controls:
        found[name] = replace(found[name], factory=lambda rt, a=name: Control(rt, a))
    return found


def header(rt):
    return {'run': RUN, 'unit': 'credential-binding', 'engine': rt.engine_identity,
            'harness': identity(b'offline-harness'), 'spec': identity(b'offline-spec'), 'configs': {},
            'host': rt.host, 'policy': {}, 'deployment': {}, 'commands': [], 'started_at': utc(),
            'finished_at': utc(), 'cleanup': {'ok': False}}


def patches(rt, stack):
    for name in ('run_batch.alarm', 'cb_batch.alarm'):
        stack.enter_context(patch(name, lambda _: nullcontext()))
    for name in ('cb_batch.run_row', 'cb_references.run_row'):
        stack.enter_context(patch(name, lambda *a, **k: run_row(*a, **k)))
    # Disk durability is an OS boundary here; the suite has a 60-second watchdog.
    stack.enter_context(patch('os.fsync', lambda fd: None))
    stack.enter_context(patch('cb_adapter.pin_child', lambda *a: 'pinned-service'))
    stack.enter_context(patch('cb_adapter.inspect_listener', lambda *a: {'listening': True}))
