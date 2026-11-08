"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from common import identity
from foura_fixtures import receipt, NONCE
from nb_conn_spec import SPECS, DIRECT, MARKERS, payload, expected
from run_registry import CASES
from run_transport import request
from test_4a_integration import OfflineRuntime


def token(text):
    return 'nb-decoy-' + hashlib.sha256(text.encode()).hexdigest()[:48]


def targets(attack):
    result = {}
    for i, (key, (wire, where)) in enumerate(SPECS[attack].items()):
        result[key] = ({'kind': 'inet', 'address': '93.184.216.2' if where == 'global' else '127.0.0.1', 'port': 42000 + i}
                       if where in ('global', 'loopback') else
                       {'kind': 'path', 'scope': 'host', 'path': '/tmp/nb-decoy-' + key + '/socket'} if where == 'path' else
                       {'kind': 'abstract', 'name': 'nb-decoy-' + key})
    return result


def prepared(attack, config='engine'):
    p = {'controls': {k: 'nb-decoy-ctl-' + k for k in SPECS[attack]}}
    for key in SPECS[attack]:
        p['control_' + key] = token('control-' + key)
        p['sentinel_' + key] = token('action-' + key)
    value = {'targets': targets(attack), 'parameters': p, 'before': {}, 'attempt': 'offline-attempt',
             'config': config, 'uid': 70001 if config == 'engine' else 1000}
    value['request'] = request('offline', config, CASES[attack], 1, value)
    return value


def local_target(attack, key, p):
    wire, where = SPECS[attack][key]
    return ({'kind': 'inet', 'address': '127.0.0.1', 'port': 47000} if wire != 'unix' else
            {'kind': 'path', 'scope': 'work', 'path': p['controls'][key]} if where == 'path' else
            {'kind': 'abstract', 'name': p['controls'][key]})


def probe_events(wire, data, failure=None):
    rows = []
    def add(step, rc=0):
        rows.append({'step': step, 'rc': -1 if failure and step == failure[0] else rc,
                     'errno': failure[1] if failure and step == failure[0] else 0})
        return rows[-1]['errno'] == 0
    add('socket', 7)
    add('send_timeout'); add('recv_timeout')
    if add('connect'):
        add('send', len(data))
        if wire != 'udp':
            add('shutdown')
        if add('recv', len(data)) and wire != 'udp':
            add('recv')
    add('close'); add('complete')
    return b''.join((json.dumps(r) + '\n').encode() for r in rows)


def observations(attack, p, succeeded=False):
    obs, captures = {'complete': True, 'control_ok': True, 'observed': [], 'captures': []}, {}
    for phase in ('control', 'action'):
        for key, (wire, where) in SPECS[attack].items():
            data = payload(attack, p['parameters'][('control_' if phase == 'control' else 'sentinel_') + key])
            success = phase == 'control' or succeeded
            _, step, code = expected(attack, key)
            value = local_target(attack, key, p['parameters']) if phase == 'control' else p['targets'][key]
            result = {'target': value, 'step': 'complete' if success else step, 'errno': 0 if success else code,
                      'rc': 0 if success else -1}
            receipt(obs, captures, key, data if success else b'', phase)
            obs['observed'].append({'label': key + '-result', 'phase': phase, 'values': result})
            if attack in DIRECT:
                obs['observed'].append({'label': key, 'phase': phase, 'values': {
                    'returncode': 0, 'signal': None, 'error': None,
                    'stderr': probe_events(wire, data, None if success else (step, code)).decode()}})
            if phase == 'control':
                receipt(obs, captures, key + '-received', data, phase)
    return obs, captures


def service_window(attack, key, p, succeeded=False):
    value = p['targets'][key]
    data = payload(attack, p['parameters']['sentinel_' + key])
    peer = {'pid': 22, 'uid': p['uid'], 'gid': p['uid']} if value['kind'] != 'inet' else {
        'address': ['127.0.0.1' if value['address'] == '127.0.0.1' else '93.184.216.1', 48000]}
    item = {'kind': 'request', 'seq': 0, 'attempt': p['attempt'], 'token': None,
            'bytes': len(data), 'payload_base64': base64.b64encode(data).decode(), 'peer': peer, 'mark': True}
    end_data = b'\0NB-END:' + NONCE.encode() + b'\n'
    end = {'kind': 'end', 'seq': int(succeeded), 'token': NONCE, 'attempt': p['attempt'],
           'payload_base64': base64.b64encode(end_data).decode(), 'bytes': len(end_data), 'mark': False}
    return {'cursor': 0, 'end': end, 'requests': [item] if succeeded else [],
            'listener': {'target': value, 'listening': True, 'inode': 55}, 'expected_secret': NONCE,
            'markers': {'nb-decoy-0000': {'payload_base64': base64.b64encode(data).decode(), **identity(data)}}
                       if succeeded and attack in MARKERS else {}, 'marker_required': attack in MARKERS}


class FakeEndpoint:
    """Replacement at the OS boundary only: no actual listener/service process."""
    def __init__(self, rt, name, value, wire, attempt, **kw):
        self.rt, self.name, self.value, self.wire, self.attempt = rt, name, value, wire, attempt
        self.ref, self.ended = Mock(), False
        self.ref.read.return_value = {'pid': 12, 'start_time': 2, 'uids': [0]*4, 'cgroup': 'owned'}
        self.rt.deployment.refs[name] = self.ref
    def start(self, key):
        self.key = key
        if self.value['kind'] == 'inet' and self.value['port'] == 0:
            self.value = {**self.value, 'port': 42000 + len(self.rt.endpoints)}
        self.before = {'target': self.value, 'listening': True, 'inode': 55}
        self.rt.targets.add_listener(key, self.value, self.ref, lambda: self.before)
        self.rt.endpoints[key] = self
        return self.value
    def finish(self, **kw):
        self.ended = True
        return self.rt.model_window(self.key)
    def sample(self):
        return self.rt.model_window(self.key)
    def restore(self):
        return {'restored': True}
    def dispose(self):
        pass


class ConnectionRuntime(OfflineRuntime):
    def __init__(self, root, cases, stack):
        super().__init__(root, cases, stack)
        self.rows, self.endpoints, self.requests = [], {}, []
        self.deployment.scratch = next(iter(self.resources.roots))
        self.deployment.network_info = {'upstream': {'fd': 77}}
        self.deployment.refs['victim'] = self.ref
        victim = {'ref': self.ref, 'target': {'kind': 'abstract', 'name': 'nb-decoy-victim-stable'}}
        self.support = SimpleNamespace(items={'victim': victim}, current=None)
        def begin(attempt):
            self.support.current = {'attempt': attempt, 'secret': NONCE}
            return {'cursor': 0, 'attempt': attempt}
        def end(**kw):
            result = self.model_window('victim-listener'); self.support.current = None
            return result
        self.support.begin_window, self.support.end_window = begin, end
        stack.enter_context(patch('connection_cases.Endpoint', FakeEndpoint))
        stack.enter_context(patch('connection_cases.inspect_listener', side_effect=lambda ref, target: {
            'listening': True, 'target': target, 'inode': 55}))
        stack.enter_context(patch('nb_conn_actions.operation', side_effect=self.operation))
        stack.enter_context(patch('nb_conn_control.local_control', side_effect=self.control))

    def start(self, config, **kwargs):
        row = super().start(config, **kwargs)
        row.uid = 70001; self.requests.append(self.req)
        return row

    def control(self, ctx, attack, key, operation):
        data = payload(attack, ctx.request['parameters']['control_' + key])
        operation(ctx, attack, key, local_target(attack, key, ctx.request['parameters']), data)
        ctx.capture(key + '-received', data)
        return True

    def operation(self, ctx, attack, key, value, data):
        succeeded = ctx.phase == 'control' or ctx.request['config'] == 'undefended'
        _, step, code = expected(attack, key)
        result = {'step': 'complete' if succeeded else step, 'errno': 0 if succeeded else code,
                  'rc': 0 if succeeded else -1}
        ctx.capture(key, data if succeeded else b'')
        if attack in DIRECT:
            ctx.observe(key, returncode=0, signal=None, error=None,
                        stderr=probe_events(SPECS[attack][key][0], data, None if succeeded else (step, code)).decode())
        ctx.observe(key + '-result', target=value, **result)
        return data if succeeded else b'', result

    def model_window(self, key):
        p = {'targets': self.req['targets'], 'parameters': self.req['parameters'],
             'attempt': self.support.current['attempt'] if key == 'victim-listener' else self.endpoints[key].attempt,
             'uid': 70001 if self.active == 'engine' else 1000}
        return service_window(self.req['attack'], key, p, self.active == 'undefended')
