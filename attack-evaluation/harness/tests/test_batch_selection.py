"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from dataclasses import replace
import unittest
from run_config import batch_capacity, schedule, selection
from run_registry import CASES, SUPPORT
from run_rows import as_host
from batch_fixtures import cases

class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.chosen = cases(); self.registry = {c.attack: c for c in self.chosen}; self.ids = list(self.registry)
    def test_current_registry_does_not_invent_attacks(self):
        self.assertEqual({k for k,c in CASES.items() if c.kind == 'control'}, {'PC-FILE', 'PC-PROXY', 'PC-DIALOGUE'})
        self.assertTrue(callable(SUPPORT))
        self.assertTrue(all(c.kind == 'control' for k,c in CASES.items() if k.startswith('PC-')))
        with self.assertRaisesRegex(ValueError, 'not implemented'):
            selection(['NB-29'], ['engine'], CASES)
    def test_explicit_list_resolves(self):
        self.assertEqual(selection(self.ids, ['engine','undefended'], self.registry), self.chosen)
    def test_bad_config_orders(self):
        for configs in ([], ['undefended','engine'], ['engine','engine'], ['all'], ['other']):
            with self.subTest(configs=configs), self.assertRaises(ValueError):
                selection(self.ids, configs, self.registry)
    def test_duplicate_empty_unknown_ids(self):
        for ids in ([], ['NB-01','NB-01'], ['NB-29']):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                selection(ids, ['engine'], self.registry)
    def test_positive_control_required(self):
        with self.assertRaisesRegex(ValueError, 'positive control'):
            selection(['NB-01'], ['engine'], self.registry)
    def test_pc_not_undefended(self):
        with self.assertRaises(ValueError): selection(self.ids, ['undefended'], self.registry)
    def test_tail_order(self):
        extra = [replace(self.chosen[0], attack=x, module=x+'.py') for x in ('NB-22','NB-23')]
        order = schedule(extra + self.chosen, ['engine','undefended'])
        self.assertEqual([c.attack for cfg,c in order if cfg=='undefended'][-2:], ['NB-23','NB-22'])
        self.assertNotIn(('undefended','PC-FILE'), [(cfg,c.attack) for cfg,c in order])
    def test_capacity_includes_support(self):
        cap = batch_capacity(self.chosen, ['engine','undefended'])
        self.assertGreater(cap['executions'], 5); self.assertEqual(cap['simultaneous_copies'], 3)
    def test_capacity_cannot_expand(self):
        with self.assertRaises(ValueError):
            batch_capacity([replace(c, repeats=1000) for c in self.chosen], ['engine','undefended'])
    def test_undefended_host_groups(self):
        argv = as_host([4,27,1000])
        self.assertIn('--groups=4,27,1000', argv); self.assertNotIn('--clear-groups', argv)
        self.assertIn('--no-new-privs', argv); self.assertIn('--reuid=1000', argv)
    def test_spec_rejects_substitution(self):
        for spec in (replace(self.chosen[0], module='../x.py'), replace(self.chosen[0], repeats=True),
                     replace(self.chosen[0], kind='control'), replace(self.chosen[0], sync='anything')):
            with self.subTest(spec=spec), self.assertRaises(ValueError): spec.validate()
