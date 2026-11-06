"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import ExitStack, nullcontext
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from common import identity, json_bytes
from record import load_run
from run_baseline import verify
from run_batch import Batch
from run_boot import failure_marker, run_frozen
from run_evidence import Evidence, RESERVE
from run_limits import until
from run_rows import Row
from batch_fixtures import FakeRuntime, cases, header, patches

class BoundaryTests(unittest.TestCase):
    def test_past_deadline_no_extension(self):
        with self.assertRaises(TimeoutError): until(10,clock=lambda:11)
    def test_deadline_is_shared_absolute(self):
        self.assertEqual(until(20,clock=lambda:10).end,20)
    def test_deadline_cannot_be_extended_over_600(self):
        with self.assertRaises(TimeoutError): until(900,clock=lambda:10)
    def test_540_cutoff_no_new_arm(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen=cases(); rt=FakeRuntime(Path(tmp),chosen); patches(rt,stack)
            rt.work_end=time.monotonic()-1
            code=Batch(rt,chosen,['engine','undefended'],header(rt)).execute()
            self.assertEqual(code,1); self.assertNotIn('arm-engine',rt.events)
    def test_raw_budget_keeps_metadata_reserve(self):
        directory=Mock(limit=10*1024*1024); evidence=Evidence(directory)
        evidence.raw(b'data')
        self.assertEqual(directory.write.call_args.kwargs['reserve'],RESERVE)
    def test_output_exhaustion_cleanup_and_final_metadata(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen=cases(); rt=FakeRuntime(Path(tmp),chosen); patches(rt,stack)
            rt.evidence.raw=lambda *a,**k: (_ for _ in ()).throw(ValueError('output budget exhausted'))
            code=Batch(rt,chosen,['engine','undefended'],header(rt)).execute()
            meta,rows=load_run(rt.evidence.directory.path)
            self.assertEqual(code,1); self.assertTrue(meta['cleanup_ok'])
            self.assertEqual(rows[0]['outcome'],'invalid')
    def test_launcher_failure_rejected_even_with_complete(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen=cases(); rt=FakeRuntime(Path(tmp),chosen); patches(rt,stack)
            Batch(rt,chosen,['engine','undefended'],header(rt)).execute()
            failure_marker({'output':str(rt.evidence.directory.path)},'forced exit')
            with self.assertRaisesRegex(ValueError,'launcher'): load_run(rt.evidence.directory.path)
    def test_bootstrap_replaces_not_spawns_unwatched_launcher(self):
        bundle={'root':'/tmp/nb-decoy-boot-test','deadline':time.monotonic()+600}
        with patch('run_boot.os.execve',side_effect=InterruptedError) as execute:
            with self.assertRaises(InterruptedError): run_frozen(bundle)
            self.assertEqual(execute.call_args.args[1][4],'--frozen')
    def test_unregistered_v2_only_trial(self):
        versions={'v1':{'engine_path':'ExperimentLab/engine'}}
        cmd=Mock(return_value={'stdout':'fixture','exit_code':0})
        with patch('run_baseline.read_owned',return_value=json_bytes(versions)):
            result=verify(Path('/repo'),{'files':{'a':identity(b'a')}},{},cmd)
        self.assertIsNone(result['baseline']); self.assertFalse(result['baseline_check']['executed'])
        self.assertEqual(cmd.call_count,2)
    def test_registered_baseline_failure_stops(self):
        versions={'v4':{'engine_path':'ExperimentLab/engine-v3'}}
        source={'files':{'a':identity(b'a')}}
        def read(path,*a): return json_bytes(versions) if path.name=='versions.json' else b'checker'
        cmd=Mock(side_effect=[{'stdout':'head'},{'stdout':'dirty'}, {'exit_code':1}])
        with patch('run_baseline.read_owned',side_effect=read), patch('run_baseline.inventory',return_value=source):
            with self.assertRaisesRegex(ValueError,'baseline check failed'): verify(Path('/repo'),source,{},cmd)
    def test_missing_registered_host_profile_stops(self):
        versions={'v4':{'engine_path':'ExperimentLab/engine-v3'}}; source={'files':{'a':identity(b'a')}}
        def read(path,*a):
            if path.name=='versions.json': return json_bytes(versions)
            if path.name=='baseline.py': return b'checker'
            raise FileNotFoundError('no approved profile')
        cmd=Mock(side_effect=[{'stdout':'head'},{'stdout':'dirty'},{'exit_code':0}])
        with patch('run_baseline.read_owned',side_effect=read),patch('run_baseline.inventory',return_value=source):
            with self.assertRaises(FileNotFoundError): verify(Path('/repo'),source,{},cmd)

class RowTreeTests(unittest.TestCase):
    def runtime(self):
        return SimpleNamespace(command=Mock(), deployment=Mock(), rows=[], cap={'first':70000,'last':70005},
                               cgroup=SimpleNamespace(path=Path('/sys/fs/cgroup/nb-decoy-fixture')))
    def test_undefended_leader_exit_not_tree_exit(self):
        rt=self.runtime(); row=Row(rt,'undefended','work0','a',30)
        row.child=Mock(); row.child.proc.poll.return_value=0
        row.group=Mock(); row.group.empty.return_value=False
        self.assertFalse(row.poll())
        with self.assertRaises(RuntimeError): row.finish()
    def test_undefended_nonzero_not_complete(self):
        rt=self.runtime(); row=Row(rt,'undefended','work0','a',30)
        row.child=Mock(); row.child.proc.poll.return_value=2
        row.group=Mock(); row.group.empty.return_value=True
        rt.command.wait.return_value={'exit_code':2}
        self.assertFalse(row.finish()['runner_ok'])
    def test_engine_admin_retired_but_kernel_task_alive(self):
        rt=self.runtime(); rt.deployment.admin.rows.return_value='(none)'
        row=Row(rt,'engine','work0','a',30); row.execution='abc:1'; row.uid=70001; rt.rows=[row]
        with patch('run_rows.Path.read_text',return_value='90'), patch('run_rows.process_info',return_value={'uids':[70001]*4}):
            self.assertFalse(row.poll())
    def test_engine_both_barriers_clear(self):
        rt=self.runtime(); rt.deployment.admin.rows.return_value='(none)'
        row=Row(rt,'engine','work0','a',30); row.execution='abc:1'; row.uid=70001; rt.rows=[row]
        with patch('run_rows.Path.read_text',return_value=''):
            self.assertTrue(row.finish()['tree_empty'])
