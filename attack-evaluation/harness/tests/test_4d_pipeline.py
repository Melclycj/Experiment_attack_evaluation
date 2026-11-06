"""这是 1.1 隔离论证的验证测试：4d 临时文件判官及故障恢复；不启动外部进程。"""
from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from batch_fixtures import header
from fourd_fixtures import ObjectRuntime
from engine_objects import EngineFile
from engine_cases import EngineCase
from record import load_run
from run_batch import Batch
from run_registry import CASES


@unittest.skipUnless(os.name=='posix','temporary file pipeline, modeled commands/sockets/processes only')
class Pipeline(unittest.TestCase):
    def exercise(self,ids,configs,alter=None):
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            cases=[CASES[k] for k in ids]
            rt=ObjectRuntime(Path(tmp),cases,stack)
            if alter:alter(rt,stack)
            batch=Batch(rt,cases,configs,header(rt));code=batch.execute()
            meta,rows=load_run(rt.evidence.directory.path)
            raw={p.name:p.read_bytes() for p in rt.evidence.directory.path.iterdir() if p.is_file()}
            return code,meta,rows,rt,raw

    def test_credential_audit_and_question_pairing_real_payload_transport(self):
        code,meta,rows,rt,raw=self.exercise(['NB-20','NB-21','NB-22'],['engine','undefended'])
        self.assertEqual(code,0,meta.get('controller_error'));self.assertEqual(len(rows),6)
        for row in rows:self.assertEqual(row['outcome'],'blocked' if row['config']=='engine' else 'succeeded',row)
        self.assertFalse(rt.targets.items)
        self.assertTrue(any('audit-before.bin' in k for k in raw))
        self.assertTrue(any('question-final.json' in k for k in raw))
        engine=next(r for r in rows if r['attack']=='NB-20' and r['config']=='engine')
        self.assertEqual({t['id'] for t in engine['attempts'][0]['targets']},{'truth','metadata'})

    def test_signals_keep_unpaired_victim_invalid_and_resume_core(self):
        code,meta,rows,rt,_=self.exercise(['NB-23'],['engine','undefended'])
        self.assertEqual(code,0);self.assertIsNone(meta['controller_error'])
        engine={t['id']:t for t in rows[0]['attempts'][0]['targets']}
        self.assertEqual(engine['victim']['outcome'],'blocked')
        self.assertTrue(engine['victim']['pairing']['satisfied'])
        self.assertEqual(len(rows[1]['attempts'][0]['targets']),6)  # v4: plus the two row file workers
        # Old missing-peer invalidity remains a separate regression fixture.
        for key in ('core','spawner','victim','auxiliary','victim-worker','auxiliary-worker'):
            self.assertEqual(engine[key]['outcome'],'blocked')
        self.assertEqual(rows[1]['outcome'],'succeeded')
        self.assertEqual(rt.deployment.refs['core'].read()['state'],'S')
        self.assertEqual(len(rt.deployment.refs['core'].signals),1)

    def test_missing_truth_capture_preserves_candidate_upstream_effect_and_stops_batch(self):
        def alter(rt,stack):
            original=rt.execute_command
            def executor(ctx,argv,**kw):
                raw=original(ctx,argv,**kw)
                if ctx.phase=='action' and argv[1]=='read' and argv[2].endswith('.truth_a'):
                    rt.arrivals.append({'payload':raw['stdout'].decode()})
                    # Return real data; later corrupt its receipt, not fake a safe denial.
                    original_capture=ctx.capture
                    def capture(label,data):
                        value=original_capture(label,data)
                        if label=='truth':ctx.record['captures'].pop()
                        return value
                    ctx.capture=capture
                return raw
            rt.execute_command=executor
        code,meta,rows,_,raw=self.exercise(['NB-20','NB-22'],['undefended'],alter)
        self.assertEqual(code,1);self.assertIn('not-started',rows[1]['invalid_reason'])
        facts=[json.loads(v) for k,v in raw.items() if 'engine-object-facts.json' in k]
        self.assertEqual(len(facts),1)
        self.assertTrue(facts[0]['truth']['external_effect'])
        self.assertTrue(facts[0]['truth']['external_fact']['upstream_sentinel'])

    def test_bad_question_owner_never_publishes_release_or_runs_other_case(self):
        def alter(rt,stack):
            rt.deployment.admin.question.side_effect=lambda **kw:{'qid':7,'execution':'foreign:1'}
        code,meta,rows,rt,raw=self.exercise(['NB-21','NB-20'],['engine'],alter)
        self.assertEqual(code,1);self.assertIn('witness mismatch',meta['controller_error']['message'])
        self.assertIn('not-started',rows[1]['invalid_reason'])
        self.assertFalse(any('release' in name for name in raw))
        self.assertTrue(meta['cleanup']['ok']);self.assertFalse(any(t.is_alive() for t in rt.threads))

    def test_failed_final_auxiliary_result_does_not_close_window_as_success(self):
        def alter(rt,stack):
            original=rt.arm
            def arm(config):
                original(config)
                def fail():raise ValueError('auxiliary missing final result')
                rt.support.question_result=fail
            rt.arm=arm
        code,meta,rows,_,raw=self.exercise(['NB-21','NB-20'],['undefended'],alter)
        self.assertEqual(code,1);self.assertIn('missing final result',meta['controller_error']['message'])
        self.assertIn('not-started',rows[1]['invalid_reason'])

    def test_audit_append_only_does_not_count_as_truncation(self):
        def alter(rt,stack):
            original=rt.execute_command
            def executor(ctx,argv,**kw):
                if ctx.phase=='action' and argv[1]=='truncate':
                    with rt.paths['e09'].open('ab') as f:f.write(b'legitimate append')
                    old=ctx.request['config'];ctx.request['config']='engine'
                    try:return original(ctx,argv,**kw)
                    finally:ctx.request['config']=old
                return original(ctx,argv,**kw)
            rt.execute_command=executor
        code,meta,rows,_,_=self.exercise(['NB-22'],['undefended'],alter)
        self.assertEqual(code,1);self.assertFalse(rows[0]['attempts'][0]['targets'][0]['external_effect'])
        self.assertEqual(rows[0]['outcome'],'invalid')
        self.assertIn('host-condition-unresolved',rows[0]['invalid_reason'])
        self.assertFalse(rows[0]['attempts'][0]['targets'][0]['prerequisite_ok'])

    def test_mirror_recovery_failure_invalidates_batch_without_erasing_raw(self):
        def alter(rt,stack):stack.enter_context(patch.object(EngineFile,'restore',side_effect=ValueError('restore refused')))
        code,meta,rows,_,raw=self.exercise(['NB-21','NB-20'],['undefended'],alter)
        self.assertEqual(code,1);self.assertIn('restore refused',meta['controller_error']['message'])
        self.assertIn('not-started',rows[1]['invalid_reason']);self.assertTrue(any('mirror-after.bin' in k for k in raw))

    def test_signal_observation_failure_still_resumes_every_target(self):
        def alter(rt,stack):
            original=rt.evidence.raw
            def raw(data,suffix='json'):
                if suffix=='engine-object-facts.json':raise ValueError('observation archive failure')
                return original(data,suffix)
            rt.evidence.raw=raw
        code,meta,rows,rt,_=self.exercise(['NB-23'],['undefended'],alter)
        self.assertEqual(code,1);self.assertEqual(rt.deployment.refs['core'].read()['state'],'S')
        self.assertEqual(len(rt.deployment.refs['core'].signals),1)
