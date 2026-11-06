"""这是 1.1 隔离论证的验证测试：第 5 步身份、路径和进程树的纯函数/mock 回归。"""
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from listener_witness import pin_row
from run_rows import Row, as_host
from run_runtime import Runtime
from undefended import check_directories, credentials, directory_facts, launch_context, main


STATUS = ('Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n'
          'Groups:\t4 27 1000\nNoNewPrivs:\t1\n' +
          ''.join(k + ':\t0000000000000000\n' for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')))


class IdentityTests(unittest.TestCase):
    def test_actual_four_ids_and_groups_pass(self):
        self.assertTrue(credentials(STATUS, [1000, 27, 4])['ok'])

    def test_any_uid_gid_capability_or_nnp_mismatch_fails(self):
        for old, new in [('Uid:\t1000 1000 1000 1000', 'Uid:\t1000 1000 0 1000'),
                         ('Gid:\t1000 1000 1000 1000', 'Gid:\t1000 1000 1000 0'),
                         ('NoNewPrivs:\t1', 'NoNewPrivs:\t0'), ('Groups:\t4 27 1000', 'Groups:\t1000')]:
            with self.subTest(field=old):
                self.assertFalse(credentials(STATUS.replace(old, new), [4, 27, 1000])['ok'])
        for cap in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
            with self.subTest(cap=cap):
                self.assertFalse(credentials(STATUS.replace(cap + ':\t0000000000000000', cap + ':\t1'), [4,27,1000])['ok'])

    def test_missing_malformed_identity_is_not_a_pass(self):
        for text in ('', STATUS.replace('NoNewPrivs:', 'Absent:'), STATUS.replace('CapEff:\t0', 'CapEff:\tnot-hex')):
            with self.subTest(text=text), self.assertRaises((KeyError, ValueError)):
                credentials(text, [4,27,1000])

    def test_setpriv_keeps_explicit_groups_and_drops_all_capabilities(self):
        args = as_host([4,27,1000])
        for flag in ('--reuid=1000', '--regid=1000', '--groups=4,27,1000',
                     '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs'):
            self.assertIn(flag, args)
        self.assertNotIn('--init-groups', args)
        for groups in ([], [True], [-1], ['1000']):
            with self.assertRaises(ValueError): as_host(groups)


class PathTests(unittest.TestCase):
    def test_every_ancestor_checked_but_no_target_open(self):
        p = Path(tempfile.gettempdir()).absolute() / 'nb-decoy-parent' / 'child'
        with patch('undefended.Path.stat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,
                   st_uid=1000, st_gid=1000, st_dev=1, st_ino=2)), \
             patch('undefended.os.access', return_value=True) as access, patch('builtins.open') as opened:
            facts = directory_facts([str(p), str(p.parent)])
        self.assertEqual({f['path'] for f in facts}, {str(q) for q in [p,*p.parents]})
        self.assertEqual(access.call_count, len(facts)); opened.assert_not_called()
        self.assertTrue(all(f['searchable'] for f in facts))

    def test_denied_missing_and_nondirectory_are_distinct(self):
        p = Path(tempfile.gettempdir()).absolute() / 'nb-decoy-parent'
        good = SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=1000,st_gid=1000,st_dev=1,st_ino=2)
        with patch('undefended.Path.stat', return_value=good), patch('undefended.os.access', return_value=False):
            self.assertTrue(all(not v['searchable'] and v['errno'] is None for v in directory_facts([str(p)])))
        with patch('undefended.Path.stat', side_effect=FileNotFoundError(2, 'missing')):
            self.assertTrue(all(v['errno']==2 and not v['searchable'] for v in directory_facts([str(p)])))
        good.st_mode=stat.S_IFREG|0o755
        with patch('undefended.Path.stat', return_value=good), patch('undefended.os.access') as access:
            self.assertTrue(all(not v['directory'] for v in directory_facts([str(p)])))
            access.assert_not_called()

    def test_metadata_helper_runs_as_host_and_keeps_raw_command_record(self):
        rt=SimpleNamespace(host={'host_user':{'groups':[4,27,1000]}}, command=Mock())
        check_directories(rt, ['/tmp/nb-decoy-a', '/tmp/nb-decoy-a'])
        argv=rt.command.call_args.args[0]
        self.assertIn('--groups=4,27,1000',argv); self.assertIn('/usr/bin/python3.12',argv)
        self.assertEqual(argv[-2:],['4,27,1000','/tmp/nb-decoy-a'])
        self.assertEqual(rt.command.call_args.kwargs,{'timeout':5})

    def test_runtime_checks_each_host_path_not_work_control_or_target_bytes(self):
        rt=SimpleNamespace(host={'host_user':{'groups':[1000]}},command=Mock())
        targets={'a':{'kind':'path','scope':'host','path':'/tmp/nb-decoy-a/secret'},
                 'b':{'kind':'path','scope':'host','path':'/tmp/nb-decoy-b/socket'},
                 'local':{'kind':'path','scope':'work','path':'nb-decoy-control'},
                 'abstract':{'kind':'abstract','name':'nb-decoy-abstract'}}
        Runtime.paths_accessible(rt, targets)
        argv=rt.command.call_args.args[0]
        self.assertEqual(argv[-2:], [str(Path('/tmp/nb-decoy-a')),str(Path('/tmp/nb-decoy-b'))])
        self.assertNotIn('/tmp/nb-decoy-a/secret',argv)
        rt.command.side_effect=RuntimeError('preflight failed')
        with self.assertRaises(RuntimeError): Runtime.paths_accessible(rt, targets)

    def test_cli_publishes_success_and_failure_identity_without_launch(self):
        for status, paths, code in [(STATUS,[{'path':'/a','searchable':True}],0),
                (STATUS,[{'path':'/a','searchable':False,'errno':13}],1),('',[],1)]:
            with patch('undefended.Path.read_text',return_value=status), \
                 patch('undefended.directory_facts',return_value=paths), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['4,27,1000','/a']),code)
                report=json.loads(output.getvalue())
                self.assertEqual(report['ok'],code==0); self.assertEqual(report['kind'],'undefended-preflight')


class LaunchTests(unittest.TestCase):
    def fixture(self, stack, root):
        home=root/'host'; work=root/'work'; payload=root/'payload'/'runner.py'
        home.mkdir(); work.mkdir(); payload.parent.mkdir(); payload.write_text('# fixture')
        rt=SimpleNamespace(home=home,resources=SimpleNamespace(roots={root}),
            payload={'runner.py':payload},host={'host_user':{'groups':[4,1000]}}, command=Mock(),
            cgroup=Mock(),deployment=SimpleNamespace(scratch=root,workspaces={'work0':{'mount':work},'work1':{'mount':work}},
                                                   host_workspaces={'work0':{'mount':work},'work1':{'mount':work}}))
        stack.enter_context(patch('undefended.check_directories'))
        # Ownership only is mocked; containment and no-symlink checks use temp files.
        real_stat=Path.stat
        def owner(p,*a,**kw):
            s=real_stat(p,*a,**kw)
            if p==home:
                return SimpleNamespace(st_mode=s.st_mode,st_uid=1000,st_gid=1000,st_dev=s.st_dev,st_ino=s.st_ino)
            return s
        stack.enter_context(patch('pathlib.Path.stat',owner))
        return rt

    def test_owned_home_work_payload_and_identical_runner_launch(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt=self.fixture(stack,Path(tmp)); group=Mock()
            with patch('run_rows.AttemptGroup',return_value=group):
                row=Row(rt,'undefended','work0','row-1',17).start()
            argv=rt.command.start.call_args.args[0]; kw=rt.command.start.call_args.kwargs
            self.assertEqual(argv[-4:],['/usr/bin/python3.12','-I','-B',str(rt.payload['runner.py'])])
            self.assertIn('--groups=4,1000',argv)
            self.assertEqual(kw['env'],{'HOME':str(rt.home)})
            self.assertEqual(kw['cwd'],rt.deployment.workspaces['work0']['mount'])
            self.assertEqual(kw['timeout'],17); self.assertIs(kw['group'],group)
            self.assertIs(row.group,group); group.create.assert_called_once()

    def test_home_outside_decoy_tree_never_creates_group_or_process(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt=self.fixture(stack,Path(tmp));rt.home=Path(tmp)/'work'
            with patch('run_rows.AttemptGroup') as group, self.assertRaisesRegex(ValueError,'HOME'):
                Row(rt,'undefended','work0','row-1',30).start()
            group.assert_not_called();rt.command.start.assert_not_called()

    def test_payload_outside_owned_roots_is_not_executed(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt=self.fixture(stack,Path(tmp));rt.payload['runner.py']=Path(tmp).parent/'other.py'
            with self.assertRaisesRegex(ValueError,'outside owned'):launch_context(rt,'work0')

    def test_wrong_home_owner_fails_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt=self.fixture(stack,Path(tmp))
            original=Path.stat
            def root_owner(p,*a,**kw):
                s=original(p,*a,**kw)
                if p==rt.home:return SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_gid=0)
                return s
            with patch('pathlib.Path.stat',root_owner),self.assertRaisesRegex(ValueError,'uid/gid'):
                launch_context(rt,'work0')

    def test_unknown_config_auxiliary_undefended_and_second_start_rejected(self):
        rt=SimpleNamespace(command=Mock())
        for cfg,work in [('typo','work0'),('undefended','work2'),('engine','other')]:
            with self.subTest(cfg=cfg,work=work),self.assertRaises(ValueError):Row(rt,cfg,work,'x',30).start()
        row=Row(rt,'undefended','work0','x',30);row.closed=True
        with self.assertRaisesRegex(ValueError,'single-use'):row.start()
        rt.command.start.assert_not_called()


class LifecycleTests(unittest.TestCase):
    def fixture(self):
        rt=SimpleNamespace(command=Mock(),deployment=SimpleNamespace(refs={}))
        rt.command.deadline.left.return_value=5
        row=Row(rt,'undefended','work1','support',30);row.child=Mock();row.child.proc.pid=22
        row.child.proc.poll.return_value=None;row.group=Mock()
        return rt,row

    def test_pin_waits_through_root_and_mixed_ids_before_setpriv_finishes(self):
        rt,row=self.fixture(); seen=[]
        def probe(pid):
            value=([0]*4 if not seen else [1000,1000,0,1000] if len(seen)==1 else [1000]*4)
            seen.append(value);return {'uids':value}
        def pin(*args):
            self.assertEqual(seen[-1],[1000]*4);return Mock()
        with patch('listener_witness.process_info',side_effect=probe),patch('listener_witness.ProcessRef',side_effect=pin) as ref:
            pin_row(rt,row,'victim')
        self.assertEqual(len(seen),3);ref.assert_called_once_with(22,1000,row.group)

    def test_exited_child_never_gets_pinned(self):
        rt,row=self.fixture();row.child.proc.poll.return_value=1
        with patch('listener_witness.ProcessRef') as ref,self.assertRaises(RuntimeError):pin_row(rt,row,'victim')
        ref.assert_not_called();self.assertEqual(rt.deployment.refs,{})

    def test_timeout_does_not_pin_or_claim_close(self):
        rt,row=self.fixture()
        with patch('listener_witness.wait_for',side_effect=TimeoutError), \
             patch('listener_witness.ProcessRef') as ref,self.assertRaises(TimeoutError):pin_row(rt,row,'victim')
        ref.assert_not_called();self.assertFalse(row.closed)

    def test_leader_exit_descendant_live_cannot_finish_or_remove_group(self):
        rt,row=self.fixture();row.child.proc.poll.return_value=0;row.group.empty.return_value=False
        with self.assertRaises(RuntimeError):row.finish()
        self.assertFalse(row.closed);row.group.remove.assert_not_called();rt.command.wait.assert_not_called()

    def test_start_failure_retains_group_for_global_recovery(self):
        rt,row=self.fixture();rt.host={'host_user':{'groups':[1000]}};rt.payload={'runner.py':Path('/owned/runner.py')};rt.cgroup=Mock()
        row.child=None;row.group=None;rt.command.start.side_effect=RuntimeError('exec failed')
        group=Mock()
        with patch('undefended.launch_context',return_value=(Path('/owned/work'),{'HOME':'/owned/home'})), \
             patch('run_rows.AttemptGroup',return_value=group),self.assertRaises(RuntimeError):row.start()
        self.assertIs(row.group,group);self.assertFalse(row.closed);group.remove.assert_not_called()
