"""离线回归：NB-23 保留四/三目标差异及逐目标前提，不启动进程或发送信号。"""
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from batch_fixtures import Adapter, FakeRuntime, cases, header, patches
from record import load_run
from run_batch import Batch
from run_runtime import Runtime

ROLES = {'core': 'core', 'spawner': 'spawner', 'victim': 'victim-connector',
         'auxiliary': 'auxiliary-connector'}


class SignalAdapter(Adapter):
    def contract(self):
        return {'attack': self.attack, 'targets': list(ROLES), 'construction': 'offline-signals',
                'operations': ['stop'], 'process_roles': dict(ROLES),
                'targets_by_config': {'engine': list(ROLES),
                                      'undefended': ['core', 'spawner', 'auxiliary']}}

    def prepare(self, config, repeat, contract):
        self.rt.event('prepare-attempt')
        # Mocks only; no pid inspection, process creation, or signals.
        self.rt.rows = [SimpleNamespace(workspace='work1', closed=False,
                                       execution='victim' if config == 'engine' else None),
                        SimpleNamespace(workspace='work2', closed=False, execution='auxiliary')]
        targets = {}
        for index, key in enumerate(contract['targets_by_config'][config]):
            fact = {'pid': (100 if config == 'engine' else 200) + index, 'start_time': 1234}
            refkey = 'connector:' + key if key in ('victim', 'auxiliary') else key
            self.rt.deployment.refs[refkey] = Mock(read=Mock(return_value=fact))
            targets[key] = {'kind': 'process', 'pid': fact['pid'], 'starttime': fact['start_time']}
        return {'targets': targets, 'parameters': {}, 'before': {'fixture': True}}

    def observe(self, prepared, observed, captures, window):
        self.rt.event('judge')
        result = {}
        for key in prepared['targets']:
            success = self.rt.active == 'undefended' and key == 'core'
            mechanism = 'pid-namespace' if self.rt.active == 'engine' else 'uid-permission'
            result[key] = {'expected_mechanism': mechanism, 'observed_mechanism': mechanism,
                           'control_ok': True, 'external_effect': success,
                           'external_fact': {'fixture': key, 'stopped': success},
                           'expected_observation': True, 'prerequisite_ok': self.rt.active == 'undefended'}
        return result


class ApplicabilityTests(unittest.TestCase):
    def exercise(self, adapter=SignalAdapter, attack='NB-23'):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = cases()[:2]
            chosen[0] = replace(chosen[0], attack=attack, module=attack + '.py',
                                factory=lambda rt: adapter(rt, attack))
            rt = FakeRuntime(Path(tmp), chosen); patches(rt, stack)
            rt.deployment.refs = {}; rt.rows = []
            rt.paired_targets = lambda targets, contract: Runtime.paired_targets(rt, targets, contract)
            code = Batch(rt, chosen, ['engine', 'undefended'], header(rt)).execute()
            meta, rows = load_run(rt.evidence.directory.path)
            return code, meta, rows, rt.events

    def test_four_three_targets_execute_without_exempting_pairing(self):
        code, meta, rows, events = self.exercise()
        self.assertIsNone(meta['controller_error'])
        self.assertEqual(events.count('start-engine'), 2)  # NB-23 plus positive control
        self.assertEqual(events.count('start-undefended'), 1)
        engine = rows[0]; peer = rows[2]
        targets = {t['id']: t for t in engine['attempts'][0]['targets']}
        self.assertEqual(set(targets), set(ROLES))
        self.assertEqual({t['id'] for t in peer['attempts'][0]['targets']}, set(ROLES) - {'victim'})
        self.assertEqual(engine['request_contract'], peer['request_contract'])
        self.assertEqual(engine['applicable_targets'], list(ROLES))
        self.assertEqual(peer['applicable_targets'], ['core', 'spawner', 'auxiliary'])
        for key in ('core', 'spawner', 'auxiliary'):
            self.assertEqual(targets[key]['outcome'], 'blocked')
        self.assertEqual(targets['victim']['outcome'], 'invalid')
        self.assertEqual(targets['victim']['invalid_reason'], 'undefended-target-prerequisite-unsatisfied')
        self.assertEqual(code, 1)  # tests.md 1.4 is NOT relaxed by applicability
        self.assertIsNone(engine['upper_bound'])

    def test_undeclared_target_omission_rejected(self):
        class Missing(SignalAdapter):
            def prepare(self, config, repeat, contract):
                value = super().prepare(config, repeat, contract)
                value['targets'].pop('spawner')
                return value
        _, meta, _, events = self.exercise(Missing)
        self.assertIsNotNone(meta['controller_error'])
        self.assertNotIn('start-engine', events)

    def test_not_allowed_to_exclude_core_to_make_arm_pass(self):
        class Missing(SignalAdapter):
            def contract(self):
                value = super().contract()
                value['targets_by_config']['undefended'].remove('core')
                return value
        _, meta, _, events = self.exercise(Missing)
        self.assertIsNotNone(meta['controller_error'])
        self.assertNotIn('start-engine', events)

    def test_nb23_exception_cannot_be_reused_for_other_attack(self):
        _, meta, _, events = self.exercise(attack='NB-01')
        self.assertIsNotNone(meta['controller_error'])
        self.assertNotIn('start-engine', events)

    def test_undeclared_extra_branch_rejected(self):
        class Extra(SignalAdapter):
            def prepare(self, config, repeat, contract):
                value = super().prepare(config, repeat, contract)
                value['targets']['other'] = value['targets']['core']
                return value
        _, meta, _, events = self.exercise(Extra)
        self.assertIsNotNone(meta['controller_error'])
        self.assertNotIn('start-engine', events)

    def test_shared_stable_parameters_still_must_match(self):
        class Changed(SignalAdapter):
            def prepare(self, config, repeat, contract):
                value = super().prepare(config, repeat, contract)
                value['parameters']['operation'] = config
                return value
        _, meta, _, events = self.exercise(Changed)
        self.assertIn('request changed', meta['controller_error']['message'])
        self.assertNotIn('start-undefended', events)

    def test_pinned_role_mismatch_rejected(self):
        class Changed(SignalAdapter):
            def prepare(self, config, repeat, contract):
                value = super().prepare(config, repeat, contract)
                value['targets']['core']['pid'] += 10
                return value
        _, meta, _, events = self.exercise(Changed)
        self.assertIn('pinned role', meta['controller_error']['message'])
        self.assertNotIn('start-engine', events)

    def test_declared_matrix_cannot_omit_union_target(self):
        class Changed(SignalAdapter):
            def contract(self):
                value = super().contract()
                value['targets_by_config']['engine'].remove('victim')
                return value
        _, meta, _, events = self.exercise(Changed)
        self.assertIsNotNone(meta['controller_error'])
        self.assertNotIn('start-engine', events)
