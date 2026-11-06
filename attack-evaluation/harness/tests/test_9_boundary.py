"""这是 1.1 隔离论证的验证测试：BD-01 演示边界（kind='boundary'）的注册与调度；全部离线，不启动部署。"""
import unittest

from run_config import schedule, selection
from run_registry import CASES, Case


class BoundaryRegistration(unittest.TestCase):
    def test_bd_cases_are_engine_only_boundary_cases(self):
        for attack in ('BD-01', 'BD-02'):
            case = CASES[attack]
            self.assertEqual((case.kind, case.module), ('boundary', attack + '.py'))
            self.assertEqual(case.expected, {'outcome': 'succeeded'})
            self.assertEqual(case.expectation('engine'), {'outcome': 'succeeded'})

    def test_id_prefix_fixes_the_kind(self):
        Case('BD-01', 'BD-01.py', lambda rt: None, {'outcome': 'succeeded'}, kind='boundary').validate()
        for bad in ('attack', 'control'):
            with self.subTest(kind=bad), self.assertRaisesRegex(ValueError, 'kind disagrees'):
                Case('BD-01', 'BD-01.py', lambda rt: None, {'outcome': 'succeeded'}, kind=bad).validate()
        with self.assertRaisesRegex(ValueError, 'kind disagrees'):
            Case('NB-01', 'NB-01.py', lambda rt: None, {'outcome': 'blocked'}, kind='boundary').validate()

    def test_boundary_runs_only_with_engine(self):
        selection(['PC-PROXY', 'BD-01'], ['engine'], CASES)
        with self.assertRaisesRegex(ValueError, 'run only with engine'):
            selection(['BD-01'], ['undefended'], CASES)

    def test_boundary_dropped_from_the_undefended_arm(self):
        cases = selection(['PC-PROXY', 'BD-01'], ['engine', 'undefended'], CASES)
        plan = schedule(cases, ['engine', 'undefended'])
        self.assertIn(('engine', CASES['BD-01']), plan)
        self.assertNotIn(('undefended', CASES['BD-01']), plan)


if __name__ == '__main__':
    unittest.main()
