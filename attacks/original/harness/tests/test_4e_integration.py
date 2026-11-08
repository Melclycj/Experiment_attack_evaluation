"""4e registration/payload and paired offline evidence pipeline, never a real attack run."""
from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from batch_fixtures import header
from cell_payload import CELL, CORE, prepare_payload
from fd_case import FdCase
from foure_runtime import SpecialRuntime
from foura_fixtures import SCRIPTS
from record import load_run
from run_batch import Batch
from run_registry import CASES
from test_cell_payload import elf_fixture


class AssemblyTests(unittest.TestCase):
    def test_exact_4e_registration_and_sync_semantics(self):
        self.assertIsNone(CASES['NB-24'].sync);self.assertEqual(CASES['NB-26'].sync,'done')
        for key in ('NB-24','NB-26'):
            self.assertEqual(CASES[key].validate().repeats,1)
            self.assertEqual(CASES[key].branches,())
            self.assertEqual(CASES[key].expectation('undefended'),{'outcome':'succeeded'})

    def test_payload_includes_all_imported_worker_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);probe=root/'structural-only';probe.write_bytes(elf_fixture())
            with patch('subprocess.Popen',side_effect=AssertionError('no subprocess')):
                files=prepare_payload(CELL,probe,{k:SCRIPTS/CASES[k].module for k in ('NB-24','NB-26')},root/'payload')
            for name in ('nb_fd.py','nb_netlink.py','nb_userns.py','nb26_worker.py'):
                self.assertIn(name,CORE);self.assertEqual(files[name].read_bytes(),(CELL/name).read_bytes())
            self.assertEqual(set(json.loads(files['modules.json'].read_bytes())['modules']),{'NB-24','NB-26'})


@unittest.skipUnless(os.name=='posix','pinned temporary file transport; syscall/network/process boundaries mocked')
class PipelineTests(unittest.TestCase):
    def build(self,tmp,stack,failure=None,cases=None):
        cases=cases or [CASES['NB-24'],CASES['PC-FILE'],CASES['NB-26']]
        rt=SpecialRuntime(Path(tmp),cases,stack,failure)
        original=FdCase.prepare
        def prepare(adapter,*args):
            value=original(adapter,*args);rt.adapter=adapter;rt.prepared=value;return value
        stack.enter_context(patch.object(FdCase,'prepare',prepare))
        return rt,Batch(rt,cases,['engine','undefended'],header(rt))

    def test_both_arms_real_contract_payload_capture_judge_restore_and_pairing(self):
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt,b=self.build(tmp,stack)
            self.assertEqual(b.execute(),0,b.error)
            meta,rows=load_run(rt.evidence.directory.path)
            self.assertTrue(meta['cleanup']['ok']);self.assertEqual(len(rows),5)
            for row in rows:
                self.assertEqual(row['outcome'],'blocked' if row['kind']=='attack' and row['config']=='engine' else 'succeeded')
            self.assertFalse(set(rt.targets.items)&{'key','netns'})
            self.assertFalse(list(rt.work.glob('nb-decoy-file-*')))
            q=[r for r in rt.requests if r['attack']=='NB-26']
            self.assertEqual(q[0]['targets'],q[1]['targets']);self.assertEqual(q[0]['parameters'],q[1]['parameters'])
            self.assertNotEqual(q[0]['sync']['nonce'],q[1]['sync']['nonce'])

    def test_fd_missing_capture_stops_next_case_with_evidence(self):
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt,b=self.build(tmp,stack,'fd-missing-capture')
            self.assertEqual(b.execute(),1);self.assertEqual(b.rows[0]['outcome'],'invalid')
            self.assertIn('not-started',b.rows[1]['invalid_reason'])
            self.assertTrue(list(rt.evidence.directory.path.glob('*.capture')))

    def test_nb26_missing_capture_preserves_observed_effect_but_invalidates(self):
        cases=[CASES['NB-26']]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt=SpecialRuntime(Path(tmp),cases,stack,'worker-capture')
            b=Batch(rt,cases,['undefended'],header(rt));self.assertEqual(b.execute(),1)
            f=b.rows[0]['attempts'][0]['targets'][0]
            self.assertTrue(f['external_effect']);self.assertEqual(f['outcome'],'invalid')

    def test_no_release_on_bad_live_nonce_or_worker_exit(self):
        for failure in ('live-nonce','worker-exit'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
                rt,b=self.build(tmp,stack,failure,cases=[CASES['NB-26'],CASES['PC-FILE']])
                self.assertEqual(b.execute(),1);self.assertIn('not-started',b.rows[1]['invalid_reason'])
                self.assertFalse((rt.work/rt.req['sync']['release']).exists())
                self.assertTrue(list(rt.evidence.directory.path.glob('*nb26-live.json')))

    def test_failed_post_exit_restoration_stops_batch(self):
        cases=[CASES['NB-26'],CASES['NB-24']]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt=SpecialRuntime(Path(tmp),cases,stack,'netns-restore')
            b=Batch(rt,cases,['undefended'],header(rt));self.assertEqual(b.execute(),1)
            self.assertIn('restoration',b.error['message']);self.assertIn('not-started',b.rows[1]['invalid_reason'])
