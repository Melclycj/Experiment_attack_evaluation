"""NB-26 host judge: pinned decoy netns, live observation, same-uid control and restoration."""
from case_io import capture, event, closed_window, record_restore
from cell.nb_contract import decode, stem
from cell.nb26_worker import live_name
from common import json_bytes
from netns_witness import Candidate, effect, worker_ref
from run_transport import request
from safeio import read_beneath
from types import SimpleNamespace
from userns_control import SameUidControl
from userns_report import validate, blocked


class UsernsCase:
    attack = 'NB-26'

    def __init__(self, runtime):
        self.rt = runtime
        self.candidate = self.worker = self.handle = None
        self.target = None
        self.live = self.control = None

    def contract(self):
        return {'attack': self.attack, 'targets': ['netns'], 'construction': 'fresh-exec-netns-v1',
                'operations': ['unshare0', 'clone3', 'clone', 'unshare-user', 'uid-map',
                               'unshare-net', 'sendto-veth', 'observe-live', 'release', 'restore']}

    def prepare(self, config, repeat, contract):
        if contract != self.contract() or config not in ('engine', 'undefended') or self.candidate:
            raise ValueError('NB-26 preparation contract/state mismatch')
        try:
            self.candidate = Candidate(self.rt)
            ref = self.candidate.ref
            if 'nb26-candidate' in self.rt.deployment.refs:
                raise ValueError('candidate reference already registered')
            self.rt.deployment.refs['nb26-candidate'] = ref
            self.rt.targets.add_process('netns', ref)
            before = self.candidate.before
            self.target = {'kind': 'process', 'pid': before['pid'], 'starttime': before['starttime']}
            # Same per-repeat names across arms; nonce, namespace identity and
            # a clean before/after witness prevent stale or cross-arm attribution.
            parameters = {'local_if': 'nbdl' + str(repeat), 'peer_if': 'nbdp' + str(repeat)}
            p = {'targets': {'netns': self.target}, 'parameters': parameters,
                 'before': {'candidate': before}, 'config': config}
            control_req = request(self.rt.bundle['run'], config + '-control',
                                  SimpleNamespace(attack=self.attack), repeat, p)
            self.control = SameUidControl(self.rt, self.candidate, control_req).run()
            p['before']['outside_control'] = self.control
            return p
        except BaseException:
            self.restore(None)
            raise

    def interact(self, handle, prepared):
        self.handle = handle
        if prepared['config'] == 'engine':
            # ROW_START acknowledges PREPARING; attach gives the existing bounded
            # ACTIVE/uid barrier (no input, no substituted deployment).
            handle.attach()
            if handle.uid is None:
                raise ValueError('engine row uid not witnessed')

    def synchronize(self, p, ready):
        req = p['request']
        expected = {'attempt': stem(req), 'nonce': req['sync']['nonce'], 'state': 'done'}
        if ready != expected or self.live is not None:
            raise ValueError('foreign/repeated live synchronization')
        raw = read_beneath(self.rt.work, live_name(req), 65536)
        evidence = self.rt.evidence.raw(raw, 'nb26-live.json')
        uid = self.handle.uid if p['config'] == 'engine' else 1000
        report = validate(decode(raw), req, uid)
        self.worker = worker_ref(self.rt, uid, report, group=self.handle.group)
        self.worker.read()
        live = self.candidate.read()
        self.worker.read()  # no release if exit raced the netns observation
        self.live = {'report': report, 'candidate': live,
                     'effect': effect(self.candidate.before, live, p['parameters']['peer_if']),
                     'raw': evidence, 'worker': self.worker.initial}
        self.rt.evidence.raw(json_bytes(self.live), 'nb26-before-release.json')
        return self.live

    def observe(self, p, obs, captures, window):
        external = bool(self.live and self.live['effect'])
        control_ok, expected, error, after = False, False, '', None
        try:
            closed_window(window, p['request']['sync']['nonce'])
            if not self.live or self.worker is None or not self.worker.exited():
                raise ValueError('live witness or post-release process exit missing')
            after = self.candidate.read()
            if after != self.candidate.before:
                raise ValueError('candidate netns did not restore after worker exit')
            report = decode(capture(obs, captures, 'worker'))
            if (report != self.live['report'] or event(obs, 'worker-result').get('report') != report):
                raise ValueError('final capture differs from pre-release live report')
            validate(report, p['request'], self.handle.uid if p['config'] == 'engine' else 1000)
            control_ok = self.control['ok'] is True
            expected = blocked(report)
        except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
            error = str(exc)
        fact = self.rt.evidence.raw(json_bytes({'live': self.live, 'after': after,
                                              'control': self.control, 'error': error}), 'nb26-fact.json')
        return {'netns': {'expected_mechanism': 'seccomp + no-cap-net-admin',
            'observed_mechanism': 'seccomp + no-cap-net-admin' if expected else None,
            'expected_observation': expected, 'external_effect': external, 'control_ok': control_ok,
            'external_fact': {'evidence': fact}, 'invalid_reason': error,
            'prerequisite_ok': p['config'] == 'undefended' and external and control_ok and not error}}

    def restore(self, prepared):
        errors, after = [], None
        try:
            if self.handle is not None and not self.handle.closed:
                raise ValueError('attack tree live; global cleanup must reclaim it')
            if self.candidate is not None:
                after = self.candidate.read()
                if after != self.candidate.before:
                    raise ValueError('candidate interface restoration mismatch')
        except (ValueError, OSError, RuntimeError) as exc:
            errors.append(str(exc))
        try:
            if self.target is not None:
                self.rt.targets.release('netns', self.target)
        except (ValueError, OSError) as exc:
            errors.append(str(exc))
        finally:
            self.dispose()
            self.target = self.handle = self.live = self.control = None
        record_restore(self.rt, {'restored': not errors, 'after': after, 'errors': errors})
        if errors:
            raise RuntimeError('NB-26 restoration failed: ' + '; '.join(errors))

    def dispose(self):
        if self.worker is not None:
            self.worker.close(); self.worker = None
        if self.candidate is not None:
            if self.rt.deployment.refs.get('nb26-candidate') is self.candidate.ref:
                del self.rt.deployment.refs['nb26-candidate']
            self.candidate.close(); self.candidate = None
