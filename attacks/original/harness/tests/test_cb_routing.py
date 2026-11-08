"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from cb_case_plan import plan
from cb_registry import capacity_for, registry
from cell.cb_spec import BRANCHES
from run_boot import stage
from run_config import options
from run_registry import CASES
from run_units import cases_for

GO='ExperimentLab/engine-v3'  # registered baseline v4
BASE=['--repo','/offline-repo','--unit','credential-binding','--label','offline','--crash-directory','/offline/crashes']


def cli(*extra,attacks='CB-10,PC-CREDENTIAL',configs='engine'):
    with patch('run_config.read_owned',return_value=b'x = 1\n') as read,patch('run_config.plain_path',lambda p:p):
        args,cases=options([*BASE,'--attacks',attacks,'--configs',configs,*extra],CASES)
    return args,cases,read


class Registry(unittest.TestCase):
    def test_every_case_has_the_frozen_expectation_and_sync(self):
        for name,case in registry().items():
            with self.subTest(case=name):
                if name in BRANCHES:
                    self.assertEqual(case.sync,'sent')
                    self.assertEqual(case.expected['location'],
                                     'credential-binding/tests.md §2.13' if name=='CB-14'
                                     else 'credential-binding/tests.md §3')
                    self.assertEqual(case.expectation('engine')['outcome'],
                                     'succeeded' if name=='PC-CREDENTIAL' else 'blocked')
                else:
                    self.assertEqual(case.kind,'control');self.assertEqual(case.branches,())
                if case.kind=='attack':self.assertEqual(case.expectation('undefended'),{'outcome':'succeeded'})

    def test_target_selector_keeps_spec_order_and_only_narrows_named_case(self):
        cases=registry(['CB-10:basic-308','CB-10:api-key-302'])
        self.assertEqual(cases['CB-10'].branches,('api-key-302','basic-308'))
        self.assertEqual(cases['CB-07'].branches,BRANCHES['CB-07'])
        cases['CB-10'].validate()

    def test_bad_selectors_fail_before_any_case_exists(self):
        for bad in (['CB-10'],['CB-10:'],['CB-10:api-key-301'],['CB-13:api-key-host'],['NB-01:source'],
                    ['CB-10:api-key-302','CB-10:api-key-302']):
            with self.subTest(bad=bad),self.assertRaises(ValueError):registry(bad)
        with self.assertRaisesRegex(ValueError,'credential-binding only'):cases_for('no-bypass',CASES,['CB-10:api-key-302'])

    def test_invented_subset_rejected_by_case_validation(self):
        from dataclasses import replace
        case=registry()['CB-10']
        for branches in (('basic-308','api-key-302'),('api-key-301',)):
            with self.subTest(branches=branches),self.assertRaises(ValueError):
                replace(case,branches=branches).validate()
        with self.assertRaises(ValueError):replace(case,sync=None).validate()


class Capacity(unittest.TestCase):
    def test_reference_rows_counted_per_target_and_arm(self):
        cases=registry(['CB-09:api-key-selected','CB-06:basic-own','CB-01:api-key-mcp'])
        selected=[cases[k] for k in ('CB-01','PC-CREDENTIAL','CB-06','CB-09')]
        expected=0
        for config in ('engine','undefended'):
            for case in selected:
                if config=='undefended' and case.kind=='control':continue
                expected+=sum(len(plan(case.attack,b)['references'])+1 for b in case.branches)
        cap=capacity_for(selected,['engine','undefended'])
        self.assertEqual(cap['executions'],expected)
        # CB-09 and CB-06 own two references; never one uid per attack ID.
        self.assertEqual(expected,2*(2+3+3)+4*2)

    def test_measured_controls_need_one_row_each(self):
        cases=registry()
        cap=capacity_for([cases['PC-FILE'],cases['PC-PROXY'],cases['PC-DIALOGUE']],['engine'])
        self.assertEqual(cap['executions'],3)

    def test_large_ids_must_be_split_but_each_split_fits(self):
        from cb_registry import MAX_TARGETS
        cases=registry()
        large=[n for n,b in BRANCHES.items() if len(b)>MAX_TARGETS]
        self.assertEqual(large,['CB-07','CB-10'])
        for name in large:
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'split the rest'):
                capacity_for([cases[name]],['engine'])
        halves=[]
        for name,branches in BRANCHES.items():
            for i in range(0,len(branches),MAX_TARGETS):
                halves.append(registry([name+':'+b for b in branches[i:i+MAX_TARGETS]])[name])
        self.assertLessEqual(capacity_for(halves,['engine','undefended'])['ca_count'],1024)


class CommandLine(unittest.TestCase):
    def test_target_subset_and_capacity_reach_frozen_options(self):
        args,cases,read=cli('--target','CB-10:api-key-302')
        by={c.attack:c for c in cases}
        self.assertEqual(by['CB-10'].branches,('api-key-302',))
        self.assertEqual(by['PC-CREDENTIAL'].branches,BRANCHES['PC-CREDENTIAL'])
        self.assertEqual(args.cap,capacity_for(cases,['engine']))
        paths=[c.args[0].as_posix() for c in read.call_args_list]
        self.assertTrue(all('credential-binding/scripts/' in p for p in paths))

    def test_selector_for_unselected_case_rejected(self):
        with self.assertRaisesRegex(ValueError,'unselected'):cli('--target','CB-07:api-key-body')

    def test_engine_attack_batch_still_needs_interspersed_control(self):
        with self.assertRaisesRegex(ValueError,'positive control'):cli(attacks='CB-10')
        with self.assertRaisesRegex(ValueError,'mixed between'):cli(attacks='CB-10,CB-11,PC-CREDENTIAL')
        cli('--target','CB-10:api-key-302',attacks='CB-10,PC-CREDENTIAL,CB-11')
        with self.assertRaisesRegex(ValueError,'split the rest'):cli(attacks='CB-10,PC-CREDENTIAL,CB-11')

    def test_undefended_arm_never_runs_controls(self):
        with self.assertRaisesRegex(ValueError,'only with engine'):cli(attacks='CB-10,PC-CREDENTIAL',configs='undefended')
        cli('--target','CB-10:api-key-302',attacks='CB-10',configs='undefended')

    def test_variant_only_engine_only_cb10_self_check(self):
        cli('--variant','redirect-credentials','--target','CB-10:api-key-302')
        for extra,attacks,configs in ((('--variant','redirect-credentials'),'CB-10,PC-CREDENTIAL,CB-11','engine'),
                                      (('--variant','redirect-credentials'),'CB-10,PC-CREDENTIAL','engine,undefended'),
                                      (('--variant','redirect-credentials'),'CB-11,PC-CREDENTIAL','engine')):
            with self.subTest(attacks=attacks,configs=configs),self.assertRaisesRegex(ValueError,'variant'):
                cli(*extra,attacks=attacks,configs=configs)
        with patch('run_config.read_owned',return_value=b''),patch('run_config.plain_path',lambda p:p),\
                self.assertRaisesRegex(ValueError,'variant'):
            options(['--repo','/r','--attacks','PC-FILE','--configs','engine','--label','x',
                     '--crash-directory','/c','--variant','redirect-credentials'],CASES)


class FrozenBundle(unittest.TestCase):
    def test_stage_freezes_unit_targets_and_unit_paths(self):
        args,cases,_=cli('--target','CB-10:api-key-302','--target','CB-10:token-307')
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp);repo=root/'repo';frozen=root/'frozen';frozen.mkdir()
            (repo/'Thesis/Work/Submission/attack_evaluation/credential-binding/runs').mkdir(parents=True)
            args.repo=repo;args.engine_path=GO;args.cgroup_parent=root;args.cert_python='/offline/python'
            stack.enter_context(patch('run_boot.os',SimpleNamespace(name='posix',geteuid=lambda:0)))
            stack.enter_context(patch('run_boot.tempfile.mkdtemp',return_value=str(frozen)))
            stack.enter_context(patch('run_boot.claim',return_value={'mock':True}))
            stack.enter_context(patch('run_boot.bind'))
            stack.enter_context(patch('run_boot.snapshot',return_value={'digest':'offline'}))
            read=stack.enter_context(patch('run_boot.read_owned',return_value=b'x = 1\n'))
            bundle=stage(args,cases,{},time.monotonic()+600)
        self.assertEqual(bundle['unit'],'credential-binding')
        self.assertEqual(bundle['targets'],['CB-10:api-key-302','CB-10:token-307'])
        self.assertEqual(bundle['support_modules'],{})
        self.assertIn('credential-binding/runs',Path(bundle['output']).as_posix())
        sources=[c.args[0].as_posix() for c in read.call_args_list]
        self.assertTrue(any(s.endswith('credential-binding/tests.md') for s in sources))
        self.assertFalse(any('no-bypass' in s for s in sources))
        # The controller rebuilds exactly the same narrowed cases from the bundle.
        rebuilt=cases_for(bundle['unit'],CASES,bundle['targets'])
        self.assertEqual(rebuilt['CB-10'].branches,('api-key-302','token-307'))
        self.assertEqual(rebuilt['CB-10'].branches,{c.attack:c for c in cases}['CB-10'].branches)


if __name__=='__main__':unittest.main()
