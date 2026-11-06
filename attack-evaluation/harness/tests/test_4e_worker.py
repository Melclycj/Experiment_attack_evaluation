"""Fresh worker entry and host procfs identity tests with injected streams/syscalls only."""
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import nb26_worker as worker
from nb_contract import decode, encoded, stem
from foure_fixtures import req, report
from foura_fixtures import load
from netns_witness import worker_ref


class WorkerTests(unittest.TestCase):
    def entry(self,host=False,release='valid'):
        q=req();r=report(q);release_value={'attempt':stem(q),'nonce':q['sync']['nonce'],'state':'release'}
        if release=='foreign':release_value['nonce']='foreign'
        incoming=encoded(q)+(encoded(release_value) if host else b'')
        stdin=SimpleNamespace(buffer=io.BytesIO(incoming));stdout=SimpleNamespace(buffer=io.BytesIO())
        return q,r,stdin,stdout

    def test_cell_report_written_before_sync_and_stdout_after_release(self):
        q,r,stdin,stdout=self.entry();events=[];files=Mock();ctx=Mock()
        files.write.side_effect=lambda *a:events.append('live-written')
        ctx.synchronize.side_effect=lambda *a,**k:events.append('host-release')
        with patch.object(worker.sys,'argv',['worker']),patch.object(worker.sys,'stdin',stdin), \
             patch.object(worker.sys,'stdout',stdout),patch.object(worker,'report',return_value=r), \
             patch.object(worker,'Files',return_value=files),patch('runner.Context',return_value=ctx):
            self.assertEqual(worker.main(),0)
        self.assertEqual(events,['live-written','host-release'])
        files.absent.assert_called_once_with(worker.live_name(q));files.close.assert_called_once()
        ctx.synchronize.assert_called_once_with('done',timeout=10)
        self.assertEqual(decode(stdout.buffer.getvalue()),r)

    def test_cell_sync_error_closes_files_and_emits_no_final_success_capture(self):
        q,r,stdin,stdout=self.entry();files=Mock();ctx=Mock();ctx.synchronize.side_effect=TimeoutError('no release')
        with patch.object(worker.sys,'argv',['worker']),patch.object(worker.sys,'stdin',stdin), \
             patch.object(worker.sys,'stdout',stdout),patch.object(worker,'report',return_value=r), \
             patch.object(worker,'Files',return_value=files),patch('runner.Context',return_value=ctx), \
             self.assertRaises(TimeoutError):worker.main()
        files.close.assert_called_once();self.assertEqual(stdout.buffer.getvalue(),b'')

    def test_outside_mode_reuses_report_without_opening_workspace_and_bounded_release(self):
        for release in ('valid','foreign','timeout'):
            q,r,stdin,stdout=self.entry(True,release)
            with patch.object(worker.sys,'argv',['worker','--host-control']),patch.object(worker.sys,'stdin',stdin), \
                 patch.object(worker.sys,'stdout',stdout),patch.object(worker,'report',return_value=r), \
                 patch.object(worker,'Files',side_effect=AssertionError('host control cannot open work0')), \
                 patch.object(worker.select,'select',return_value=([] if release=='timeout' else [stdin.buffer],[],[])) as select:
                if release=='valid':self.assertEqual(worker.main(),0)
                else:
                    with self.assertRaises((ValueError,TimeoutError)):worker.main()
                select.assert_called_once_with([stdin.buffer],[],[],10)
            self.assertEqual(decode(stdout.buffer.getvalue()),r)

    def test_action_launches_explicit_fresh_interpreter_and_checks_report(self):
        q=req();r=report(q);ctx=Mock(request=q,payload=Path('/runtime/nb'))
        ctx.remaining.return_value=25
        ctx.command.return_value={'returncode':0,'signal':None,'stdout':encoded(r)}
        module=load('NB-26');self.assertTrue(module['control'](ctx));module['action'](ctx)
        args=ctx.command.call_args.args[1]
        self.assertEqual(args[1:3],['-I','-B']);self.assertTrue(args[-1].endswith('nb26_worker.py'))
        self.assertEqual(decode(ctx.command.call_args.kwargs['data']),q)
        self.assertEqual(ctx.command.call_args.kwargs['timeout'],25)
        ctx.command.return_value['returncode']=2
        with self.assertRaises(RuntimeError):module['action'](ctx)

    def test_report_original_uid_saved_before_namespace_calls(self):
        q=req();r=report(q);order=[]
        with patch.object(worker.os,'getuid',side_effect=lambda:order.append('uid') or 70001,create=True), \
             patch.object(worker,'perform',side_effect=lambda *a:order.append('perform') or dict(r)), \
             patch.object(worker.os,'getpid',return_value=3), \
             patch.object(worker.os,'readlink',return_value='net:[444]'):
            value=worker.report(q)
        self.assertEqual(order,['uid','perform']);self.assertEqual(value['original_uid'],70001)


class ProcPath:
    def __init__(self,value,threads):self.value=str(value);self.threads=threads
    def __truediv__(self,part):return ProcPath(self.value+'/'+str(part),self.threads)
    def read_text(self):return 'NSpid: 17 3\n'
    def iterdir(self):return iter(range(self.threads))


class WorkerWitnessTests(unittest.TestCase):
    def witness(self, *, uid=70001, argv=True, threads=1, expected=70001, duplicates=False):
        q=req();r=report(q);rt=Mock()
        with tempfile.TemporaryDirectory() as tmp:
            group=SimpleNamespace(path=Path(tmp));(group.path/'cgroup.procs').write_text('17 18' if duplicates else '17')
            rt.cgroup=group
            info={'uids':[uid]*4,'argv':['python','/runtime/nb/nb26_worker.py' if argv else 'other.py']}
            with patch('netns_witness.process_info',return_value=info), \
                 patch('netns_witness.Path',side_effect=lambda p:ProcPath(p,threads)), \
                 patch('netns_witness.ns',return_value='net:[444]'), \
                 patch('netns_witness.ProcessRef',return_value='pinned') as pin:
                result=worker_ref(rt,expected,r)
                pin.assert_called_once_with(17,expected,group)
                return result

    def test_match_requires_group_uid_argv_namespace_pid_and_single_thread(self):
        self.assertEqual(self.witness(),'pinned')
        for kwargs in ({'uid':1},{'argv':False},{'threads':2},{'duplicates':True},{'expected':1000}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.witness(**kwargs)
