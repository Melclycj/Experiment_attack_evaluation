"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import hashlib
from pathlib import Path
from case_io import WorkspaceFiles, closed_window, record_restore
from cell.nb_conn_spec import MARKERS, SPECS, fresh_fields
from common import json_bytes
from connection_endpoint import Endpoint
from connection_observe import observe_target
from decoys import sentinel
from listener_witness import inspect_listener
from net import UPSTREAM_IP


class ConnectionCase:
    """Six finite cases: exact owned decoys, independently closed address windows."""
    def __init__(self, runtime, attack):
        self.rt, self.attack = runtime, attack
        self.sessions, self.registered, self.choices = {}, {}, {}
        self.files, self.victim = None, False

    def contract(self):
        return {'attack': self.attack, 'targets': list(SPECS[self.attack]),
                'construction': 'connection-spec-4c-v1',
                'operations': ['c-syscalls' if self.attack in ('NB-17', 'NB-18') else 'python-socket',
                               'independent-address-control', 'end-marked-window'],
                'fresh_parameters': fresh_fields(self.attack)}

    def name(self, key):
        seed = self.rt.bundle['run'] + ':' + self.attack + ':' + key
        return 'nb-decoy-n' + hashlib.sha256(seed.encode()).hexdigest()[:16]

    def prepare(self, config, repeat, contract):
        if config not in ('engine', 'undefended') or contract != self.contract() or self.sessions or self.files:
            raise ValueError('connection contract/config/lifecycle mismatch')
        rt = self.rt
        prepared = {'targets': {}, 'parameters': {'controls': {}}, 'before': {},
                    'config': config, 'attempt': sentinel(), 'uid': None}
        self.files = WorkspaceFiles(rt, 'work0')
        try:
            for key, (wire, where) in SPECS[self.attack].items():
                name = self.name(key)
                p = prepared['parameters']
                p['controls'][key] = self.files.reserve('nb-decoy-c' + name[-16:])
                p['control_' + key], p['sentinel_' + key] = sentinel(), sentinel()
                if where == 'victim':
                    victim = rt.support.items['victim']
                    value = dict(victim['target'])
                    rt.targets.add_listener(key, value, victim['ref'],
                                            lambda v=victim: inspect_listener(v['ref'], v['target']))
                    self.victim = True
                    self.registered[key] = value
                    prepared['before'][key] = {'window': rt.support.begin_window(prepared['attempt']),
                        'listener': inspect_listener(victim['ref'], value)}
                    prepared['victim_secret'] = rt.support.current['secret']
                else:
                    value = self.choices.get(key)
                    if value is None:
                        value = ({'kind': 'inet', 'address': UPSTREAM_IP if where == 'global' else '127.0.0.1', 'port': 0}
                                 if where in ('global', 'loopback') else
                                 {'kind': 'path', 'scope': 'host', 'path': str(Path(rt.deployment.scratch) / name / 'socket')}
                                 if where == 'path' else {'kind': 'abstract', 'name': name})
                    fd = rt.deployment.network_info['upstream']['fd'] if where == 'global' else None
                    endpoint = Endpoint(rt, name, value, wire, prepared['attempt'],
                        markers=self.attack in MARKERS, owner='daemon' if self.attack == 'NB-19' else 'user', netfd=fd)
                    self.sessions[key] = endpoint  # before any launch/preparation can fail
                    value = endpoint.start(key)
                    self.registered[key] = dict(value)
                    prepared['before'][key] = {'listener': endpoint.before, 'cursor': 0}
                if key in self.choices and self.choices[key] != value:
                    raise ValueError('paired address changed between configurations')
                self.choices[key] = dict(value)
                prepared['targets'][key] = value
            return prepared
        except BaseException:
            # Preserve partial service data; never pretend a live service restored.
            self.restore(prepared)
            raise

    def interact(self, handle, prepared):
        prepared['uid'] = handle.uid if prepared['config'] == 'engine' else 1000
        if type(prepared['uid']) is not int:
            raise ValueError('connection attacker identity unavailable')

    def synchronize(self, prepared, ready):
        raise ValueError('connection cases have no live release synchronization')

    def observe(self, prepared, observation, captures, window):
        rt, facts = self.rt, {}
        live = any(r.workspace == 'work0' and not r.closed for r in rt.rows)
        if live:
            raise ValueError('connection observation precedes attack tree exit')
        general = ''
        try:
            if closed_window(window, prepared['request']['sync']['nonce']):
                raise ValueError('unexpected upstream request in direct connection case')
        except (ValueError, KeyError, TypeError) as exc:
            general = str(exc)
        for key in prepared['targets']:
            report = {}
            try:
                if SPECS[self.attack][key][1] == 'victim':
                    report = rt.support.end_window(tree_empty=True)
                    report.update(expected_secret=prepared['victim_secret'], marker_required=False, markers={})
                    if report.get('listener') != prepared['before'][key]['listener']:
                        report['error'] = 'victim listener identity changed during window'
                else:
                    report = self.sessions[key].finish(tree_empty=True)
            except (ValueError, RuntimeError, OSError, KeyError) as exc:
                reason = type(exc).__name__ + ': ' + str(exc)
                if key in self.sessions:
                    try:
                        report = self.sessions[key].sample()
                    except Exception as sample_error:
                        reason += '; evidence: ' + str(sample_error)
                elif self.victim and rt.support.current is not None:
                    try:
                        report = rt.support.sample_window()
                    except Exception as sample_error:
                        report = {'entries': rt.support.current.get('entries', [])}
                        reason += '; evidence: ' + str(sample_error)
                report['error'] = reason
            if general:
                report['error'] = report.get('error') or general
            raw = rt.evidence.raw(json_bytes(report), 'connection-window.json')
            facts[key] = observe_target(self.attack, key, prepared, observation, captures, report, raw)
        return facts

    def restore(self, prepared):
        rt, errors, restored = self.rt, [], []
        live = any(r.workspace == 'work0' and not r.closed for r in rt.rows)
        if live:
            errors.append('attack tree still live; retain objects for global cleanup')
        if self.victim and rt.support.current is not None:
            errors.append('victim observation window still open')
        for key, endpoint in self.sessions.items():
            try:
                if live:
                    endpoint.sample()
                else:
                    restored.append(endpoint.restore())
            except Exception as exc:
                errors.append(key + ': ' + str(exc))
        if self.files is not None and not live:
            try:
                restored.append(self.files.restore())
            except Exception as exc:
                errors.append('local controls: ' + str(exc))
        if not errors:
            for key, value in self.registered.items():
                rt.targets.release(key, value)
            for endpoint in self.sessions.values():
                if endpoint.ref is not None:
                    endpoint.ref.close()
                    del rt.deployment.refs[endpoint.name]
            self.sessions, self.registered, self.files, self.victim = {}, {}, None, False
        record_restore(rt, {'restored': not errors, 'objects': restored, 'errors': errors})
        if errors:
            raise RuntimeError('connection restoration incomplete: ' + '; '.join(errors))

    def dispose(self):
        # No live-object deletion here. Global cgroup/scratch cleanup is the owner.
        for endpoint in self.sessions.values():
            endpoint.dispose()
        if self.files is not None:
            self.files.close()
