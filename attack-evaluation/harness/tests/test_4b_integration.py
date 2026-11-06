"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from batch_fixtures import header, FakeRuntime, Adapter, patches
from cell_payload import CORE, CELL, prepare_payload
from file_cases import FileCase
from foura_fixtures import SCRIPTS
from fourb_fixtures import FileRuntime, simulated_operation
from nb_file_spec import KINDS, HOME_FILES
from record import load_run
from run_batch import Batch
from run_config import selection, batch_capacity
from run_registry import CASES, SUPPORT_MODULES, Case
from test_cell_payload import elf_fixture


class AssemblyTests(unittest.TestCase):
    def test_exact_sixteen_file_cases_three_controls_and_two_supports(self):
        expected={f'NB-{i:02}' for i in [*range(1,16),28]}
        self.assertEqual(set(KINDS),expected)
        self.assertTrue(expected | {'PC-FILE','PC-PROXY','PC-DIALOGUE'} <= set(CASES))
        for key in expected:
            self.assertEqual(selection([key],['undefended'],CASES),[CASES[key]])
        for i in (n for n in range(1,29) if f'NB-{n:02}' not in CASES):
            with self.assertRaisesRegex(ValueError,'not implemented'):
                selection([f'NB-{i:02}'],['undefended'],CASES)

    def test_explicit_payload_has_all_twenty_seven_modules_and_shared_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);probe=root/'structural-only';probe.write_bytes(elf_fixture())
            modules={k:SCRIPTS/c.module for k,c in CASES.items()}
            modules.update({k:SCRIPTS/v for k,v in SUPPORT_MODULES.items()})
            with patch('subprocess.Popen',side_effect=AssertionError('no compiler')):
                payload=prepare_payload(CELL,probe,modules,root/'stage',support_modules=SUPPORT_MODULES)
            reg=json.loads(payload['modules.json'].read_bytes())
            self.assertEqual(set(reg['modules']), set(CASES) | set(SUPPORT_MODULES))
            for name in ('nb_file_spec.py','nb_file_diag.py','nb_file_actions.py'):
                self.assertIn(name,CORE);self.assertEqual(payload[name].read_bytes(),(CELL/name).read_bytes())
            for key in KINDS:
                item=reg['modules'][key]
                self.assertEqual(hashlib.sha256(payload[item['path']].read_bytes()).hexdigest(),item['sha256'])
                self.assertEqual(item.get('lifetime',30),30)

    def test_branch_capacity_reserved_without_relaxing_limits(self):
        c=CASES['NB-15'];flat=replace(c,branches=())
        self.assertGreater(batch_capacity([c],['engine','undefended'])['executions'],
                           batch_capacity([flat],['engine','undefended'])['executions'])
        self.assertEqual(batch_capacity([c],['engine','undefended'])['simultaneous_copies'],3)

    def test_only_declared_nb15_alias_rows_can_partition(self):
        for c in (replace(CASES['NB-04'],branches=('source','mount')),
                  replace(CASES['NB-15'],branches=('source',)),replace(CASES['NB-15'],sync='done')):
            with self.assertRaises(ValueError):c.validate()


@unittest.skipUnless(os.name=='posix','temporary files with mocked cell operations, no process launch')
class FileBatchTests(unittest.TestCase):
    def test_all_sixteen_two_arms_payload_collect_judge_restore_pairing(self):
        cases=[CASES['NB-01'],CASES['PC-FILE']]+[CASES[k] for k in KINDS if k!='NB-01']
        with tempfile.TemporaryDirectory(prefix='nb-decoy-4b-') as tmp,ExitStack() as stack:
            rt=FileRuntime(Path(tmp),cases,stack);batch=Batch(rt,cases,['engine','undefended'],header(rt))
            self.assertEqual(batch.execute(),0,batch.error)
            meta,rows=load_run(rt.evidence.directory.path)
            self.assertTrue(meta['cleanup']['ok']);self.assertEqual(len(rows),33)
            self.assertTrue(all(r['outcome']==('succeeded' if r['kind']=='control' or r['config']=='undefended' else 'blocked') for r in rows))
            # Existing PC registration belongs to the outer fixture; every
            # file-case target must have been released independently.
            self.assertFalse(set(rt.targets.items) & {'file','source','mount',*HOME_FILES})
            self.assertFalse(list(rt.work.glob('nb-decoy-file-*')))
            nb15=[r for r in rt.branch_requests if r['attack']=='NB-15']
            self.assertEqual([list(r['targets']) for r in nb15],[['source'],['mount'],['source'],['mount']])
            self.assertEqual(len({r['sync']['nonce'] for r in nb15}),4)
            for row in rows:
                if row['attack']=='NB-15':
                    self.assertEqual(row['repeats'],1);self.assertEqual(len(row['attempts'][0]['targets']),2)

    def test_nb15_second_path_failure_never_inherits_first_effect(self):
        cases=[CASES['NB-15']]
        def boundary(ctx,attack,key,path,**kwargs):
            if ctx.phase=='action' and key=='mount':
                ctx.capture(key,b'');value={'path':path,'valid':True,'rc':-1,'errno':2,'signal':None,'identity':None}
                ctx.observe(key+'-result',**value);return value
            return simulated_operation(ctx,attack,key,path,**kwargs)
        with tempfile.TemporaryDirectory(prefix='nb-decoy-4b-') as tmp,ExitStack() as stack:
            rt=FileRuntime(Path(tmp),cases,stack,operation=boundary);batch=Batch(rt,cases,['undefended'],header(rt))
            self.assertEqual(batch.execute(),1)
            self.assertIn('host-condition-unresolved',batch.error['message'])
            targets=batch.rows[0]['attempts'][0]['targets']
            self.assertEqual([t['outcome'] for t in targets],['succeeded','invalid'])
            self.assertEqual([t['external_effect'] for t in targets],[True,False])
            self.assertEqual([t['prerequisite_ok'] for t in targets],[True,False])

    def test_nb15_pairing_requires_both_paths_own_undefended_effect(self):
        cases=[CASES['PC-FILE'],CASES['NB-15']]
        def boundary(ctx,attack,key,path,**kwargs):
            if ctx.phase=='action' and key=='mount':
                ctx.capture(key,b'');value={'path':path,'valid':True,'rc':-1,'errno':2,'signal':None,'identity':None}
                ctx.observe(key+'-result',**value);return value
            return simulated_operation(ctx,attack,key,path,**kwargs)
        with tempfile.TemporaryDirectory(prefix='nb-decoy-4b-') as tmp,ExitStack() as stack:
            rt=FileRuntime(Path(tmp),cases,stack,operation=boundary);batch=Batch(rt,cases,['engine','undefended'],header(rt))
            self.assertEqual(batch.execute(),1)
            self.assertIn('host-condition-unresolved',batch.error['message'])
            meta,rows=load_run(rt.evidence.directory.path)
            row=next(r for r in rows if r['attack']=='NB-15' and r['config']=='engine')
            self.assertEqual([t['outcome'] for t in row['attempts'][0]['targets']],['blocked','invalid'])
            self.assertIsNone(row['upper_bound'])
            peer=next(r for r in rows if r['attack']=='NB-15' and r['config']=='undefended')
            targets=peer['attempts'][0]['targets']
            self.assertEqual([t['outcome'] for t in targets],['succeeded','invalid'])
            self.assertEqual([t['prerequisite_ok'] for t in targets],[True,False])

    def test_nb15_second_path_preparation_error_retains_first_path_evidence(self):
        original=FileCase.prepare_branch
        def prepare(self,config,repeat,contract,key):
            if key=='mount':raise ValueError('injected second path')
            return original(self,config,repeat,contract,key)
        cases=[CASES['NB-15'],CASES['NB-04']]
        with tempfile.TemporaryDirectory(prefix='nb-decoy-4b-') as tmp,ExitStack() as stack:
            rt=FileRuntime(Path(tmp),cases,stack);stack.enter_context(patch.object(FileCase,'prepare_branch',prepare))
            batch=Batch(rt,cases,['undefended'],header(rt));self.assertEqual(batch.execute(),1)
            targets=batch.rows[0]['attempts'][0]['targets']
            self.assertEqual([t['outcome'] for t in targets],['succeeded','invalid'])
            self.assertIn('not-started',batch.rows[1]['invalid_reason'])
            self.assertTrue(list(rt.evidence.directory.path.glob('*.capture')))

    def test_missing_capture_stops_following_case_and_archives_partial_record(self):
        cases=[CASES['NB-04'],CASES['NB-01']]
        def broken(ctx,attack,key,path,**kwargs):
            value=simulated_operation(ctx,attack,key,path,**kwargs)
            if ctx.phase=='action':ctx.record['captures']=[]
            return value
        with tempfile.TemporaryDirectory(prefix='nb-decoy-4b-') as tmp,ExitStack() as stack:
            rt=FileRuntime(Path(tmp),cases,stack,operation=broken);batch=Batch(rt,cases,['undefended'],header(rt))
            self.assertEqual(batch.execute(),1);self.assertEqual(batch.rows[0]['outcome'],'invalid')
            self.assertIn('not-started',batch.rows[1]['invalid_reason'])

    def test_restore_failure_stops_remaining_cases(self):
        original=FileCase.restore
        def broken(self,p):original(self,p);raise RuntimeError('injected restore failure')
        cases=[CASES['NB-04'],CASES['NB-01']]
        with tempfile.TemporaryDirectory(prefix='nb-decoy-4b-') as tmp,ExitStack() as stack:
            rt=FileRuntime(Path(tmp),cases,stack);stack.enter_context(patch.object(FileCase,'restore',broken))
            batch=Batch(rt,cases,['undefended'],header(rt));self.assertEqual(batch.execute(),1)
            self.assertIn('restore failure',batch.error['message'])
            self.assertIn('not-started',batch.rows[1]['invalid_reason'])


class BranchDeadlineTests(unittest.TestCase):
    def test_both_paths_share_exact_deadline_and_one_repetition(self):
        case=CASES['NB-15'];batch=Batch.__new__(Batch)
        from unittest.mock import Mock
        batch.rt=Mock(work_end=1000)
        batch.rt.evidence.raw.return_value={'file':'offline.json'}
        fact={'id':'source','outcome':'blocked','invalid_reason':''}
        batch.attempt_row=Mock(return_value={'targets':[fact],'evidence':{'file':'row.json'}})
        with patch('run_batch.time.monotonic',return_value=100):result=batch.attempt(case,'engine',1)
        self.assertEqual([c.args[3] for c in batch.attempt_row.call_args_list],[130,130])
        self.assertEqual([c.args[4] for c in batch.attempt_row.call_args_list],['source','mount'])
        self.assertEqual(result['repeat'],1)

    def test_first_path_timeout_leaves_second_unstarted(self):
        from unittest.mock import Mock
        batch=Batch.__new__(Batch);batch.rt=Mock(work_end=1000)
        batch.rt.evidence.raw.return_value={'file':'offline.json'}
        batch.attempt_row=Mock(side_effect=TimeoutError('bounded'))
        with patch('run_batch.time.monotonic',return_value=100):result=batch.attempt(CASES['NB-15'],'engine',1)
        self.assertEqual(batch.attempt_row.call_count,1)
        self.assertEqual([t['outcome'] for t in result['targets']],['invalid','invalid'])
        self.assertIn('not-started',result['targets'][1]['invalid_reason'])
