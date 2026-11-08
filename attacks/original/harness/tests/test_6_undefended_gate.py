"""这是 1.1 隔离论证的验证测试：M05 配置判定门；纯 mock 与临时文件，不运行真实攻击。"""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from batch_fixtures import Adapter, FakeRuntime, header, patches
from record import load_run
from run_batch import Batch
from run_registry import CASES, Case


def fact(mechanism='file-view', **updates):
    external = ({'diagnostic': {'matched': True, 'errno': 1}, 'mock_host_identity_verified': True}
                if mechanism == 'uid-permission' else {'errno': 2, 'mock': True})
    return dict(expected_mechanism=mechanism, observed_mechanism=mechanism,
                control_ok=True, external_effect=False, external_fact=external,
                expected_observation=True, prerequisite_ok=False, **updates)


class FactAdapter(Adapter):
    def contract(self):
        return dict(attack=self.attack, targets=list(self.rt.facts), construction='offline-config-gate',
                    operations=['mock-observation'])

    def prepare(self, config, repeat, contract):
        return dict(targets={k: dict(kind='path', scope='host', path='/tmp/nb-decoy-config/'+k)
                             for k in self.rt.facts}, parameters={}, before={}, config=config)

    def observe(self, *args):
        return deepcopy(self.rt.facts)


class ConfigurationGate(unittest.TestCase):
    def exercise(self, attack='NB-01', config='undefended', facts=None, configs=None):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            case = replace(CASES[attack], factory=lambda rt: FactAdapter(rt, attack), branches=())
            rt = FakeRuntime(Path(tmp), [case]); rt.facts = facts or {'file': fact()}
            rt.targets.verify = lambda targets: {k: {'verified': True} for k in targets}
            patches(rt, stack)
            code = Batch(rt, [case], configs or [config], header(rt)).execute()
            meta, rows = load_run(rt.evidence.directory.path)
            self.assertTrue(meta['cleanup_ok'])
            return code, rows, rt.facts

    def target(self, **kwargs):
        code, rows, original = self.exercise(**kwargs)
        return code, rows[0]['attempts'][0]['targets'][0], original

    def test_familiar_denial_cannot_pass_any_ordinary_undefended_attack(self):
        for attack, case in CASES.items():
            if case.kind != 'attack' or attack == 'NB-23': continue
            with self.subTest(attack=attack):
                code, t, _ = self.target(attack=attack)
                self.assertEqual(code, 1)
                self.assertEqual(t['outcome'], 'invalid')
                self.assertIn('host-condition-unresolved', t['invalid_reason'])
                self.assertIsNone(t['observed_mechanism'])
                self.assertFalse(t['prerequisite_ok'])
                self.assertEqual(t['external_fact']['errno'], 2)
                self.assertFalse(t['external_fact']['undefended_diagnosis']['cause_verified'])

    def test_nb23_verified_uid_permission_exceptions_remain_blocked(self):
        for key in ('spawner', 'victim', 'auxiliary'):
            value = fact('uid-permission'); value['prerequisite_ok'] = True
            with self.subTest(key=key):
                _, t, _ = self.target(attack='NB-23', facts={key: value})
                self.assertEqual(t['outcome'], 'blocked')
                self.assertTrue(t['prerequisite_ok'])
                self.assertEqual(t['observed_mechanism'], 'uid-permission')

    def test_nb23_core_and_victim_cannot_borrow_exception(self):
        # Keep this historical test ID: victim cannot borrow an unverified
        # peer premise, while core can never use the UID-permission exception.
        for key in ('core', 'victim', 'unknown'):
            value = fact('uid-permission'); value['prerequisite_ok'] = key != 'victim'
            _, t, _ = self.target(attack='NB-23', facts={key: value})
            self.assertEqual(t['outcome'], 'invalid')
            self.assertFalse(t['prerequisite_ok'])

    def test_nb23_exception_requires_host_verified_prerequisite(self):
        for key in ('spawner', 'victim', 'auxiliary'):
            with self.subTest(key=key):
                _, t, _ = self.target(attack='NB-23', facts={key: fact('uid-permission')})
                self.assertEqual(t['outcome'], 'invalid')

    def test_same_role_and_mechanism_do_not_exempt_another_attack(self):
        value = fact('uid-permission'); value['prerequisite_ok'] = True
        _, t, _ = self.target(attack='NB-01', facts={'spawner': value})
        self.assertEqual(t['outcome'], 'invalid')

    def test_expected_mechanism_alone_cannot_exempt_nb23(self):
        value = fact('pid-namespace'); value['prerequisite_ok'] = True
        _, t, _ = self.target(attack='NB-23', facts={'spawner': value})
        self.assertEqual(t['outcome'], 'invalid')

    def test_successful_undefended_effect_is_not_suppressed(self):
        value = fact(); value.update(external_effect=True, prerequisite_ok=True)
        code, t, _ = self.target(facts={'file': value})
        self.assertEqual(code, 0); self.assertEqual(t['outcome'], 'succeeded')
        self.assertTrue(t['external_effect']); self.assertTrue(t['prerequisite_ok'])

    def test_existing_quality_failure_keeps_reason_and_candidate_effect(self):
        value = fact(invalid_reason='broken capture')
        value.update(external_effect=True, prerequisite_ok=True)
        _, t, _ = self.target(facts={'file': value})
        self.assertEqual(t['outcome'], 'invalid'); self.assertTrue(t['external_effect'])
        self.assertEqual(t['invalid_reason'], 'broken capture')
        self.assertFalse(t['prerequisite_ok'])

    def test_pending_question_is_not_relabelled_as_a_block(self):
        _, t, _ = self.target(facts={'file': fact(pending_question_verified=True)})
        self.assertEqual(t['outcome'], 'escalated')

    def test_invalid_undefended_denial_cannot_satisfy_engine_pairing(self):
        value = fact(); value['prerequisite_ok'] = True
        code, rows, _ = self.exercise(facts={'file': value}, configs=['engine', 'undefended'])
        self.assertEqual(code, 1)
        self.assertEqual(rows[1]['outcome'], 'invalid')
        t = rows[0]['attempts'][0]['targets'][0]
        self.assertFalse(t['pairing']['satisfied']); self.assertEqual(t['outcome'], 'invalid')
        self.assertIsNone(rows[0]['upper_bound'])

    def test_gate_does_not_mutate_adapter_facts(self):
        original = {'file': fact()}; before = deepcopy(original)
        _, _, after = self.exercise(facts=original)
        self.assertEqual(after, before)

    def test_positive_control_success_is_unchanged(self):
        value = fact(); value.update(external_effect=True, prerequisite_ok=True)
        code, t, _ = self.target(attack='PC-FILE', config='engine', facts={'file': value})
        self.assertEqual(code, 0); self.assertEqual(t['outcome'], 'succeeded')

    def test_real_connection_judges_no_longer_allow_undefended_false_block(self):
        from test_5_pipeline import SocketAdapter
        for attack, key in [('NB-16', 'relay'), ('NB-17', 'global'), ('NB-18', 'loopback'), ('NB-25', 'host')]:
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
                chosen = [replace(CASES[attack], factory=lambda rt, a=attack: SocketAdapter(rt, a))]
                rt = FakeRuntime(Path(tmp), chosen); rt.missing = key; patches(rt, stack)
                self.assertEqual(Batch(rt, chosen, ['undefended'], header(rt)).execute(), 1)
                _, rows = load_run(rt.evidence.directory.path)
                target = next(t for t in rows[0]['attempts'][0]['targets'] if t['id'] == key)
                self.assertEqual(target['outcome'], 'invalid')
                self.assertIn('host-condition-unresolved', target['invalid_reason'])

    @unittest.skipUnless(os.name == 'posix', 'Linux temporary pinned file pipeline; execution remains mocked')
    def test_real_file_judge_undefended_enoent_is_invalid(self):
        from fourb_fixtures import FileRuntime, simulated_operation
        def denied(ctx, attack, key, path, **kw):
            config = ctx.request['config']
            if ctx.phase == 'action': ctx.request['config'] = 'engine'
            try: return simulated_operation(ctx, attack, key, path, **kw)
            finally: ctx.request['config'] = config
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = [CASES['NB-07']]; rt = FileRuntime(Path(tmp), chosen, stack, operation=denied)
            self.assertEqual(Batch(rt, chosen, ['undefended'], header(rt)).execute(), 1)
            _, rows = load_run(rt.evidence.directory.path)
            self.assertEqual(rows[0]['outcome'], 'invalid')
            self.assertIn('host-condition-unresolved', rows[0]['invalid_reason'])


if __name__ == '__main__':
    unittest.main()
