"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import ExitStack, nullcontext
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from batch_fixtures import FakeRuntime, header
from cell_payload import CELL, prepare_payload
from common import identity
from foura_fixtures import SCRIPTS, window
from nb_io import Files
from runner import run
from run_batch import Batch
from run_registry import CASES, SUPPORT_MODULES
from run_runtime import Runtime
from run_transport import OwnedTargets
from support_rows import SupportRows
from test_cell_payload import elf_fixture


class OfflineRuntime(FakeRuntime):
    """Real adapters + frozen payload + temporary files; all deployment/I/O mocked."""
    def __init__(self, root, cases, stack):
        super().__init__(root,cases)
        workspaces={}
        deployment_root=root/'nb-decoy-offline';deployment_root.mkdir()
        for name in ('work0','work1','work2'):
            p=deployment_root/name;p.mkdir();workspaces[name]={'mount':p,'source':p}
        self.work=workspaces['work0']['mount'];self.resources=SimpleNamespace(roots={deployment_root:(1,2)})
        self.deployment.workspaces=workspaces;self.deployment.host_workspaces=workspaces
        self.deployment.refs={};self.deployment.admin=Mock()
        self.deployment.upstream.child=Mock()
        self.targets=OwnedTargets(self);self.req=None;self.code=None
        probe=root/'structural-probe';probe.write_bytes(elf_fixture())
        selected={c.attack:SCRIPTS/c.module for c in cases}
        prepare_payload(CELL,probe,selected,root/'payload')
        self.payload_root=root/'payload'
        self.deployment.upstream.begin=lambda nonce:None
        self.deployment.upstream.end=self.window
        stack.enter_context(patch('run_transport.os.fchown'))
        stack.enter_context(patch('run_batch.alarm',lambda end:nullcontext()))
        stack.enter_context(patch('subprocess.Popen',side_effect=AssertionError('no subprocess')))
        stack.enter_context(patch('socket.socket',side_effect=AssertionError('no real socket')))
        stack.enter_context(patch('nb_wire.exchange',side_effect=lambda *a,**k: {'category':1,'status':200,
              'body':b'{"token":"offline-server-token"}','complete':True}))
        self.ref=Mock();self.ref.read.return_value={'pid':2,'start_time':3,'uids':[0]*4,'cgroup':'owned'}
        def pin(rt,key,child,uid):rt.deployment.refs[key]=self.ref;return self.ref
        stack.enter_context(patch('positive_controls.pin_child',side_effect=pin))
        stack.enter_context(patch('positive_controls.inspect_listener',side_effect=lambda ref,target:{
             'listening':True,'target':dict(target),'inode':17}))

    def start(self,config,**kwargs):
        self.req=json.loads((self.work/'nb-request.json').read_bytes())
        self.code=None
        def poll():
            if self.code is None:
                work,payload=Files(self.work),Files(self.payload_root)
                try:self.code=run(work,payload,cwd=str(self.work))
                finally:work.close();payload.close()
            return True
        return SimpleNamespace(poll=poll,finish=lambda:{'tree_empty':True,'runner_ok':self.code==0})

    def window(self):
        requests=[]
        if self.req['attack']=='PC-PROXY':
            requests=[{'method':'GET','host':self.req['parameters']['host'],
                       'path':'/'+self.req['parameters']['sentinel'],'reply_token':'offline-server-token'}]
        w=window(requests);nonce=self.req['sync']['nonce'];w['end']['attempt']=nonce
        for x in w['requests']:x['attempt']=nonce
        return w


@unittest.skipUnless(os.name=='posix','temporary pinned Linux file transport, no processes or listeners')
class EndToEndOfflineTests(unittest.TestCase):
    def test_real_case_to_payload_runner_collect_judge_restore_twice(self):
        cases=[replace(CASES[x],repeats=2) for x in ('PC-FILE','PC-PROXY')]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt=OfflineRuntime(Path(tmp),cases,stack)
            batch=Batch(rt,cases,['engine'],header(rt))
            self.assertEqual(batch.execute(),0, batch.error)
            self.assertEqual([r['outcome'] for r in batch.rows],['succeeded','succeeded'])
            self.assertEqual([r['successes'] for r in batch.rows],[2,2])
            files=[p for p in rt.evidence.directory.path.iterdir() if p.suffix=='.capture']
            self.assertEqual(len(files),4)
            self.assertFalse((rt.work/'nb-decoy-pc-output').exists())
            self.assertFalse((rt.work/'nb-decoy-pc-input').exists())

    def test_wrong_upstream_reply_is_invalid_and_stops_following_attempt(self):
        cases=[CASES['PC-PROXY'],CASES['PC-FILE']]
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            rt=OfflineRuntime(Path(tmp),cases,stack)
            stack.enter_context(patch('nb_wire.exchange',return_value={'category':1,'status':200,'body':b'wrong','complete':True}))
            batch=Batch(rt,cases,['engine'],header(rt));self.assertEqual(batch.execute(),1)
            self.assertEqual(batch.rows[0]['outcome'],'invalid')
            self.assertIn('not-started',batch.rows[1]['invalid_reason'])
            self.assertTrue(list(rt.evidence.directory.path.glob('*.capture')))


class LifecycleWiringTests(unittest.TestCase):
    def test_start_helper_uses_remaining_batch_budget_and_retains_request(self):
        rt=Runtime.__new__(Runtime)
        rt.bundle={'support_modules':SUPPORT_MODULES,'run':'offline'};rt.serial=0
        rt.targets=Mock();rt.deployment=SimpleNamespace(workspaces={'work1':{'mount':Path('/offline')}},
                                                       host_workspaces={'work1':{'mount':Path('/offline')}})
        rt.command=Mock();rt.command.deadline.left.return_value=370
        row=Mock();rt.start=Mock(return_value=row)
        value={'kind':'path','scope':'work','path':'nb-decoy-support'}
        with patch('run_runtime.prepare_request'):
            self.assertIs(rt.start_helper('work1','undefended','SUP-VICTIM',{'victim':value},{}),row)
        rt.start.assert_called_once_with('undefended',workspace='work1',seconds=370)
        self.assertEqual(row.request['attack'],'SUP-VICTIM')

    def test_cannot_start_support_in_work0_or_swap_roles(self):
        rt=Runtime.__new__(Runtime);rt.bundle={'support_modules':SUPPORT_MODULES}
        for workspace,config,module in [('work0','engine','SUP-VICTIM'),('work2','undefended','SUP-AUXILIARY'),
                                      ('work1','engine','SUP-AUXILIARY'),('work1','foreign','SUP-VICTIM')]:
            with self.assertRaises(ValueError):rt.start_helper(workspace,config,module,{}, {})

    def support(self):
        s=SupportRows.__new__(SupportRows);s.rt=Mock();s.config='engine';s.closed=False;s.current=s.question_pending=None
        s.items={role:{'row':Mock(workspace=ws,request={'v':1}), 'root':Path('/offline/nb-decoy-'+role),
                      'files':Mock()} for role,ws in [('victim','work1'),('auxiliary','work2')]}
        s.items['victim']['target']={'kind':'abstract','name':'nb-decoy-listener'}
        s._send=Mock();s.dispose=Mock()
        s.rt.deployment.workspaces={w:{'mount':Path('/offline')/w} for w in ('work1','work2')}
        s.rt.deployment.host_workspaces=s.rt.deployment.workspaces
        for i in s.items.values():i['row'].config='engine'
        for i in s.items.values():i['row'].finish.return_value={'tree_empty':True,'runner_ok':True}
        return s

    def test_orderly_support_close_collects_both_rows_before_release(self):
        s=self.support()
        with patch('support_rows.wait_for'),patch('support_rows.collect',return_value=({'control_ok':True},{})) as collect:
            s.close();s.close()
        self.assertEqual(collect.call_count,2);self.assertTrue(s.closed);s.dispose.assert_called_once()
        self.assertEqual(s.rt.targets.release.call_count,3)

    def test_one_close_failure_still_attempts_other_row_and_disposes(self):
        s=self.support();s.items['auxiliary']['row'].finish.side_effect=RuntimeError('offline tree still alive')
        with patch('support_rows.wait_for'),patch('support_rows.collect',return_value=({'control_ok':True},{})),\
             self.assertRaisesRegex(RuntimeError,'support close failed'):s.close()
        s.items['victim']['row'].finish.assert_called_once();s.dispose.assert_called_once()
        s.rt.targets.release.assert_not_called();self.assertFalse(s.closed)

    def test_support_nonzero_exit_is_not_normal_close(self):
        s=self.support();s.items['victim']['row'].finish.return_value={'tree_empty':True,'runner_ok':False}
        with patch('support_rows.wait_for'),patch('support_rows.collect',return_value=({'control_ok':True},{})),self.assertRaises(RuntimeError):s.close()
        self.assertFalse(s.closed)
