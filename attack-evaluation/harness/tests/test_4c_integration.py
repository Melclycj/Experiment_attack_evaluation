"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from batch_fixtures import header
from fourc_fixtures import ConnectionRuntime, FakeEndpoint
from nb_conn_spec import SPECS
from record import load_run
from run_batch import Batch
from run_registry import CASES
from run_config import selection


class AssemblyTests(unittest.TestCase):
    def test_all_six_are_explicit_and_not_branch_row_reinterpretations(self):
        self.assertEqual(set(SPECS),{'NB-16','NB-17','NB-18','NB-19','NB-25','NB-27'})
        for attack in SPECS:
            self.assertEqual(selection([attack],['undefended'],CASES),[CASES[attack]])
            self.assertEqual(CASES[attack].branches,())
            self.assertEqual(CASES[attack].repeats,1)
            self.assertIsNone(CASES[attack].sync)
            self.assertEqual(CASES[attack].expectation('undefended'),{'outcome':'succeeded'})
            self.assertIn('spawner.c:clone_ready(CLONE_NEWNET)',CASES[attack].expected['location'])
            self.assertEqual('w2_child_launch(pivot_root)' in CASES[attack].expected['location'],
                             attack in ('NB-19','NB-27'))
        for n in (n for n in range(1,29) if f'NB-{n:02}' not in CASES):
            with self.assertRaisesRegex(ValueError,'not implemented'):
                selection([f'NB-{n:02}'],['undefended'],CASES)


@unittest.skipUnless(os.name=='posix','real pinned temporary file transport; sockets/processes mocked')
class PipelineTests(unittest.TestCase):
    def execute(self, cases, configs, stack, root):
        rt=ConnectionRuntime(root,cases,stack);batch=Batch(rt,cases,configs,header(rt))
        return rt,batch

    def test_all_six_two_configurations_real_payload_collect_judge_restore(self):
        cases=[CASES['PC-FILE']]+[CASES[k] for k in SPECS]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt,batch=self.execute(cases,['engine','undefended'],stack,Path(tmp))
            self.assertEqual(batch.execute(),0,batch.error)
            meta,rows=load_run(rt.evidence.directory.path)
            self.assertEqual(len(rows),13);self.assertTrue(meta['cleanup']['ok'])
            for row in rows:
                self.assertEqual(row['outcome'],'blocked' if row['kind']=='attack' and row['config']=='engine' else 'succeeded')
                if row['attack'] in SPECS:
                    self.assertEqual(len(row['attempts'][0]['targets']),len(SPECS[row['attack']]))
            self.assertFalse(set(rt.targets.items) & {k for spec in SPECS.values() for k in spec})
            self.assertFalse(list(rt.work.glob('nb-decoy-c*')))
            by_attack={}
            for req in rt.requests:
                if req['attack'] not in SPECS:continue
                if req['attack'] in by_attack:self.assertEqual(req['targets'],by_attack[req['attack']])
                by_attack[req['attack']]=req['targets']

    def test_missing_capture_preserves_candidate_effect_and_stops_next_case(self):
        cases=[CASES['NB-16'],CASES['NB-17']]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt,batch=self.execute(cases,['undefended'],stack,Path(tmp))
            original=rt.operation
            def broken(ctx,*args):
                result=original(ctx,*args)
                if ctx.phase=='action':ctx.record['captures']=[]
                return result
            stack.enter_context(patch('nb_conn_actions.operation',side_effect=broken))
            self.assertEqual(batch.execute(),1)
            target=batch.rows[0]['attempts'][0]['targets'][0]
            self.assertEqual(target['outcome'],'invalid');self.assertTrue(target['external_effect'])
            self.assertIn('not-started',batch.rows[1]['invalid_reason'])

    def test_missing_end_marker_cannot_count_as_blocked(self):
        cases=[CASES['NB-16'],CASES['NB-17']]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt,batch=self.execute(cases,['undefended'],stack,Path(tmp))
            original=rt.model_window
            def broken(key):
                win=original(key);win['end']={};return win
            rt.model_window=broken
            self.assertEqual(batch.execute(),1);self.assertIn('not-started',batch.rows[1]['invalid_reason'])
            self.assertTrue(batch.rows[0]['attempts'][0]['targets'][0]['external_effect'])

    def test_restore_failure_retains_raw_window_and_stops_next_case(self):
        cases=[CASES['NB-16'],CASES['NB-17']]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt,batch=self.execute(cases,['undefended'],stack,Path(tmp))
            stack.enter_context(patch.object(FakeEndpoint,'restore',side_effect=ValueError('offline restore failure')))
            self.assertEqual(batch.execute(),1);self.assertIn('restore failure',batch.error['message'])
            self.assertIn('not-started',batch.rows[1]['invalid_reason'])
            self.assertTrue(list(rt.evidence.directory.path.glob('*connection-window.json')))

    def test_each_address_needs_own_undefended_pair(self):
        cases=[CASES['PC-FILE'],CASES['NB-17']]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt,batch=self.execute(cases,['engine','undefended'],stack,Path(tmp))
            original_op,original_window=rt.operation,rt.model_window
            def op(ctx,*args):
                if ctx.phase=='action' and args[1]=='loopback':
                    saved=ctx.request['config'];ctx.request['config']='engine'
                    try:return original_op(ctx,*args)
                    finally:ctx.request['config']=saved
                return original_op(ctx,*args)
            def win(key):
                saved=rt.active
                if key=='loopback':rt.active='engine'
                try:return original_window(key)
                finally:rt.active=saved
            stack.enter_context(patch('nb_conn_actions.operation',side_effect=op));rt.model_window=win
            self.assertEqual(batch.execute(),1)
            self.assertIn('host-condition-unresolved',batch.error['message'])
            _,rows=load_run(rt.evidence.directory.path)
            engine=next(r for r in rows if r['attack']=='NB-17' and r['config']=='engine')
            self.assertEqual({t['id']:t['outcome'] for t in engine['attempts'][0]['targets']},
                             {'global':'blocked','loopback':'invalid'})
            peer=next(r for r in rows if r['attack']=='NB-17' and r['config']=='undefended')
            targets={t['id']:t for t in peer['attempts'][0]['targets']}
            self.assertEqual(targets['global']['outcome'],'succeeded')
            self.assertEqual(targets['loopback']['outcome'],'invalid')
            self.assertFalse(targets['loopback']['external_effect'])
            self.assertFalse(targets['loopback']['prerequisite_ok'])
