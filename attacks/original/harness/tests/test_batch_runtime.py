"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from build import capacity
from common import identity
from run_runtime import Runtime

class RuntimeWiringTests(unittest.TestCase):
    def fixture(self, stack, path, failure=None):
        bundle={'root':str(path),'cap':capacity(10),'cgroup_parent':'/sys/fs/cgroup',
                'label':'offline','repo':str(path),'engine_identity':{'files':{'a':identity(b'a')}},
                'modules':{'NB-01':'NB-01.py'},'cert_python':'/offline/python','support_modules':{}}
        host={'crashes':{},'crash_directory':str(path)}
        group=Mock(created=False); group.path=Path('/sys/fs/cgroup/nb-decoy-offline')
        def create():
            group.created=True
            if failure=='cgroup': raise RuntimeError('injected cgroup')
        group.create.side_effect=create
        resources=Mock(roots={})
        resources.cleanup.return_value={'ok':True,'failures':[],'retained':[]}
        stack.enter_context(patch('run_runtime.RunCgroup',return_value=group))
        stack.enter_context(patch('run_runtime.Resources',return_value=resources))
        commands=[]
        def command_factory(cgroup,deadline,**kw):
            cmd=Mock(cgroup=cgroup,deadline=deadline)
            commands.append(cmd); return cmd
        stack.enter_context(patch('run_runtime.Commands',side_effect=command_factory))
        verified=stack.enter_context(patch('run_runtime.verify',return_value=bundle['engine_identity']))
        stack.enter_context(patch('run_runtime.fresh_root',return_value=path))
        stack.enter_context(patch('run_runtime.os.chown', create=True))
        def build(source,directory,cmd):
            if failure=='build': raise RuntimeError('injected build')
            directory.mkdir(); (directory/'product').write_bytes(b'offline-not-executable')
            return {'product':identity(b'offline-not-executable')}
        compiler=stack.enter_context(patch('run_runtime.compile_engine',side_effect=build))
        argv=stack.enter_context(patch('run_runtime.compile_argv',return_value=['/offline/cc','source.c']))
        payload={'runner.py':path/'runner.py','nb_probe':path/'nb_probe'}
        payload_fn=stack.enter_context(patch('run_runtime.prepare_payload',return_value=payload))
        if failure=='payload': payload_fn.side_effect=RuntimeError('injected payload')
        if failure=='baseline': verified.side_effect=RuntimeError('injected baseline')
        network=Mock(); stack.enter_context(patch('run_runtime.PrivateNetwork',return_value=network))
        deployment=Mock(scratch=path,workspaces={'work0':{'mount':path/'work'}},
                        host_workspaces={'work0':{'mount':path/'work'}})
        deployment.close.return_value={'ok':True,'failures':[],'retained':[]}
        if failure=='deployment': deployment.prepare.side_effect=RuntimeError('injected deployment')
        deploy_class=stack.enter_context(patch('run_runtime.Deployment',return_value=deployment))
        rt=Runtime(bundle,host,time.monotonic()+590,Mock())
        return rt,commands,compiler,argv,deploy_class,resources,group

    def test_production_pipeline_same_cgroup_independent_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt,cmds,compiler,argv,deploy,_,group=self.fixture(stack,Path(tmp))
            rt.prepare()
            self.assertEqual(rt.stage,'ready'); compiler.assert_called_once(); argv.assert_called_once()
            self.assertEqual(len(cmds),2); self.assertIsNot(cmds[0],cmds[1])
            self.assertIs(cmds[0].cgroup,cmds[1].cgroup)
            self.assertEqual(cmds[1].deadline.end,rt.end)
            self.assertEqual(cmds[0].deadline.end,rt.end-60)
            kw=deploy.call_args.kwargs
            self.assertIs(kw['cleanup_command'],cmds[1]); self.assertIs(kw['command'],cmds[0])
            rt.close(); self.assertTrue(rt.cleanup_result['ok'])
            cmds[0].close.assert_called_once(); cmds[1].close.assert_called_once()

    def test_current_missing_support_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt,*_=self.fixture(stack,Path(tmp)); rt.prepare()
            with self.assertRaisesRegex(ValueError,'not implemented'): rt.arm('engine')
            rt.close()

    def test_close_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt,*_=self.fixture(stack,Path(tmp)); rt.prepare()
            first=rt.close(); self.assertIs(first,rt.close())
            rt.deployment.close.assert_called_once()

    def test_engine_stop_precedes_attempt_group_recovery(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt,*_=self.fixture(stack,Path(tmp)); rt.prepare(); events=[]
            rt.deployment.stop_engine.side_effect=lambda: events.append('engine')
            group=Mock(created=True); group.kill_and_wait.side_effect=lambda **kw: events.append('tree')
            rt.rows=[SimpleNamespace(group=group)]
            rt.close(); self.assertEqual(events[:2],['engine','tree'])

    def test_path_checks_use_host_groups_not_root(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt,*_=self.fixture(stack,Path(tmp)); rt.prepare()
            rt.host['host_user']={'groups':[1000,27]}
            rt.paths_accessible({'x':{'kind':'path','scope':'host','path':'/tmp/nb-decoy-file/a'}})
            argv=rt.command.call_args.args[0]
            self.assertIn('--reuid=1000',argv); self.assertIn('--groups=1000,27',argv)
            rt.close()

def failed_stage(name):
    def test(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt,*_=self.fixture(stack,Path(tmp),name)
            with self.assertRaises(RuntimeError): rt.prepare()
            result=rt.close(); self.assertTrue(result['ok'])
    return test
for name in ('cgroup','baseline','build','payload','deployment'):
    setattr(RuntimeWiringTests,'test_partial_'+name+'_recovers',failed_stage(name))
