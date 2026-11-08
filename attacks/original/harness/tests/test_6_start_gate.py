"""这是 1.1 隔离论证的验证测试：跨批门禁的临时文件/mock回归，不启动批次。"""
from contextlib import ExitStack
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
from common import json_bytes
from run_boot import stage, NREL


class HistoryGate(unittest.TestCase):
    def test_failed_history_is_refused_before_snapshot_mutation(self):
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            repo=Path(tmp);runs=repo/NREL/'runs';prior=runs/'20260101T010101Z-bad';prior.mkdir(parents=True)
            (prior/'LAUNCHER-FAILED.json').write_bytes(b'{}')
            args=NS(repo=repo,engine_path='ExperimentLab/engine-v3',label='offline')
            stack.enter_context(patch('run_boot.os',NS(name='posix',geteuid=lambda:0)))
            create=stack.enter_context(patch('run_boot.tempfile.mkdtemp',side_effect=AssertionError('snapshot reached')))
            with self.assertRaisesRegex(RuntimeError,'prior cleanup'):stage(args,[],{},time.monotonic()+600)
            create.assert_not_called()

    def test_empty_history_does_not_create_directory(self):
        from run_gate import check_history
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'runs';self.assertEqual(check_history(path),[]);self.assertFalse(path.exists())

    def test_cleanup_failures_retained_or_missing_never_pass(self):
        from run_gate import check_history
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);(path/'20260101T010101Z-old').mkdir()
            for cleanup in ({},{'ok':False},{'ok':True,'retained':['owned']},{'ok':True,'failures':['failed']}):
                with self.subTest(cleanup=cleanup),patch('run_gate.load_run',return_value=({'cleanup':cleanup,'cleanup_ok':True},[])):
                    with self.assertRaisesRegex(RuntimeError,'prior cleanup'):check_history(path)

    def test_complete_marker_alone_is_not_cleanup_proof(self):
        from run_gate import check_history
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);old=path/'20260101T010101Z-old';old.mkdir();(old/'COMPLETE.json').write_bytes(b'{}')
            with self.assertRaisesRegex(RuntimeError,'prior cleanup'):check_history(path)

    def test_valid_old_quality_failure_with_verified_cleanup_may_pass(self):
        from run_gate import check_history
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);old=path/'20260101T010101Z-old';old.mkdir();(old/'COMPLETE.json').write_bytes(b'{}')
            with patch('run_gate.load_run',return_value=({'cleanup':{'ok':True},'cleanup_ok':True,'controller_error':{'error':'quality'}},[])):
                self.assertEqual(len(check_history(path)),1)

    def test_unknown_directory_is_not_silently_ignored(self):
        from run_gate import check_history
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);(path/'unknown').mkdir()
            with self.assertRaisesRegex(RuntimeError,'unrecognized'):check_history(path)


@unittest.skipUnless(os.name=='posix','Linux advisory lock/fsync gate in temporary files only')
class PersistentGate(unittest.TestCase):
    def setUp(self):
        import run_gate
        self.g=run_gate;self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.state=self.root/'state'
        p=patch.object(run_gate,'STATE',self.state);p.start();self.addCleanup(p.stop)
        self.bundle={'repo':str(self.root/'repo'),'run':'20260101T010101Z-offline',
                     'root':str(self.root/'snapshot'),'root_identity':[1,2],'output':str(self.root/'output')}
        Path(self.bundle['output']).mkdir();(Path(self.bundle['output'])/'COMPLETE.json').write_bytes(b'{}')
        (Path(self.bundle['output'])/'run.json').write_bytes(b'{}')  # every archive has one; the receipt reads it

    def claim(self):
        b=self.bundle;b['gate']=self.g.claim(b['repo'],b['run']);self.g.bind(b);return b

    def clean(self):return patch.object(self.g,'load_run',return_value=({'run':self.bundle['run'],'cleanup_ok':True,'cleanup':{'ok':True}},[]))

    def test_bound_claim_blocks_new_repo_and_label_across_calls(self):
        self.claim()
        with self.assertRaisesRegex(RuntimeError,'active/unverified'):self.g.claim('/other','other')
        self.g.verify(self.bundle)

    def test_unbound_crashed_claim_also_blocks(self):
        self.g.claim('/repo','name')
        with self.assertRaises(RuntimeError):self.g.claim('/repo','next')

    def test_successful_cleanup_release_is_receipted(self):
        self.claim()
        with self.clean():self.g.release(self.bundle)
        self.assertFalse((self.state/'active.json').exists())
        receipt=json.loads((self.state/'last-clean.json').read_bytes());self.assertTrue(receipt['snapshot_removed'])
        self.assertIn('completion',receipt);self.g.claim('/next','next')
        # a 1.1 bundle (no 'unit') now also leaves its history receipt (2026-11-06)
        self.assertEqual(len(list((self.state/'verified').rglob('*.json'))),1)

    def test_unclean_batch_retains_gate(self):
        self.claim()
        with patch.object(self.g,'load_run',return_value=({'cleanup_ok':False,'cleanup':{'ok':False}},[])):
            with self.assertRaisesRegex(RuntimeError,'unverified'):self.g.release(self.bundle)
        self.assertTrue((self.state/'active.json').exists())

    def test_still_existing_snapshot_prevents_release(self):
        self.claim();Path(self.bundle['root']).mkdir()
        with self.clean(),self.assertRaisesRegex(RuntimeError,'snapshot'):self.g.release(self.bundle)
        self.assertTrue((self.state/'active.json').exists())

    def test_stale_token_cannot_release_another_claim(self):
        self.claim();stale=deepcopy(self.bundle);stale['gate']['token']='0'*64
        with self.clean(),self.assertRaisesRegex(RuntimeError,'stale'):self.g.release(stale)
        self.g.verify(self.bundle)

    def test_changed_frozen_output_or_root_is_rejected(self):
        self.claim()
        for field in ('root','output'):
            wrong=deepcopy(self.bundle);wrong[field]+='-different'
            with self.subTest(field=field),self.assertRaises(RuntimeError):self.g.verify(wrong)

    def test_failure_marker_or_corrupt_archive_keeps_gate(self):
        self.claim()
        with patch.object(self.g,'load_run',side_effect=ValueError('outer launcher failed')):
            with self.assertRaises(ValueError):self.g.release(self.bundle)
        self.assertTrue((self.state/'active.json').exists())

    def test_symlink_state_is_rejected_without_touching_target(self):
        target=self.root/'other';target.mkdir();self.state.symlink_to(target,target_is_directory=True)
        with self.assertRaises(ValueError):self.g.claim('/repo','run')
        self.assertEqual(list(target.iterdir()),[])

    def test_world_writable_state_is_rejected(self):
        self.state.mkdir(mode=0o777);self.state.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError,'unsafe'):self.g.claim('/repo','run')

    def test_hardlinked_active_record_cannot_be_rebound(self):
        b=self.bundle;b['gate']=self.g.claim(b['repo'],b['run'])
        os.link(self.state/'active.json',self.root/'alias')
        with self.assertRaisesRegex(RuntimeError,'unsafe'):self.g.bind(b)

    def test_mutex_busy_refuses_without_altering_active(self):
        import fcntl
        self.claim();before=(self.state/'active.json').read_bytes()
        fd=os.open(self.state/'mutex',os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.g.verify(self.bundle)
        finally:os.close(fd)
        self.assertEqual((self.state/'active.json').read_bytes(),before)


class LauncherGateWiring(unittest.TestCase):
    def frozen(self, result=None, discard_error=None, release_error=None):
        import run
        events=[]
        bundle={'root':'/tmp/nb-decoy-boot-mock','output':'/offline/output','cap':{},
                'crash_directory':'/offline/crashes','deadline':time.monotonic()+600}
        def discard(b):
            events.append('discard')
            if discard_error: raise discard_error
        def release(b):
            events.append('release')
            if release_error: raise release_error
        with ExitStack() as stack:
            stack.enter_context(patch.object(run,'HERE',Path(bundle['root'])/'harness'))
            stack.enter_context(patch.object(run,'load_bundle',return_value=bundle))
            stack.enter_context(patch('launch.run_controller',return_value=result or {'forced':False,'exit_code':0}))
            stack.enter_context(patch.object(Path,'exists',side_effect=lambda:True))
            stack.enter_context(patch.object(run,'discard',side_effect=discard))
            stack.enter_context(patch.object(run,'release_gate',side_effect=release))
            stack.enter_context(patch.object(run,'failure_marker',side_effect=lambda *a:events.append('failure')))
            from contextlib import nullcontext
            stack.enter_context(patch.object(run,'alarm',return_value=nullcontext()))
            try: code=run.main(['--frozen','/offline/bundle.json'])
            except Exception as exc: code=exc
        return events,code

    def test_release_only_after_snapshot_removal(self):
        events,code=self.frozen();self.assertEqual(events,['discard','release']);self.assertEqual(code,0)

    def test_snapshot_failure_never_calls_release(self):
        events,code=self.frozen(discard_error=RuntimeError('remove failed'))
        self.assertEqual(events,['discard']);self.assertIsInstance(code,RuntimeError)

    def test_release_failure_is_not_reported_as_success(self):
        events,code=self.frozen(release_error=RuntimeError('cleanup not verified'))
        self.assertEqual(events,['discard','release']);self.assertIsInstance(code,RuntimeError)

    def test_active_gate_refused_before_any_snapshot(self):
        import run_boot
        with ExitStack() as stack:
            stack.enter_context(patch('run_boot.os',NS(name='posix',geteuid=lambda:0)))
            stack.enter_context(patch('run_boot.check_history',return_value=[]))
            stack.enter_context(patch('run_boot.claim',side_effect=RuntimeError('active gate')))
            mkdir=stack.enter_context(patch('run_boot.tempfile.mkdtemp'))
            with self.assertRaisesRegex(RuntimeError,'active gate'):
                stage(NS(repo=Path('/repo'),label='offline'),[],{},time.monotonic()+600)
            mkdir.assert_not_called()
