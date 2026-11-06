"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from positive_controls import WorkspaceControl, ProxyControl, DialogueControl
from case_io import capture, closed_window, WorkspaceFiles
from runner import Context
from nb_io import Files
from decoys import snapshot, synchronization
from foura_fixtures import load, receipt, window, runtime, NONCE, SENTINEL


class CommonFactTests(unittest.TestCase):
    def test_capture_phase_label_and_hash_required(self):
        obs, caps={},{}; receipt(obs,caps,'read',b'content')
        self.assertEqual(capture(obs,caps,'read'),b'content')
        for bad in ('missing','duplicate','phase','hash'):
            o,c=copy.deepcopy(obs),dict(caps)
            if bad=='missing': c.clear()
            if bad=='duplicate': o['captures']*=2
            if bad=='phase': o['captures'][0]['phase']='control'
            if bad=='hash': o['captures'][0]['sha256']='0'*64
            with self.subTest(bad=bad),self.assertRaises((ValueError,KeyError)): capture(o,c,'read')

    def test_external_window_end_and_sequence_required(self):
        self.assertEqual(closed_window(window(),NONCE),[])
        for bad in ('end','token','sequence','attempt','gap'):
            w=window([{'method':'GET'}])
            if bad=='end': w['end']['kind']='request'
            if bad=='token': w['end']['token']=None
            if bad=='sequence': w['end']['seq']=12
            if bad=='attempt': w['end']['attempt']='wrong'
            if bad=='gap': w['requests'][0]['seq']=2
            with self.assertRaises(ValueError): closed_window(w,NONCE)

    def test_proxy_judge_requires_exact_one_get_and_reply_nonce(self):
        pc=ProxyControl(Mock()); obs={'observed':[{'phase':'action','label':'response',
             'values':{'complete':True,'status':200,'category':1}}]}; caps={}
        receipt(obs,caps,'response',b'{"token":"reply-fresh"}')
        p={'parameters':{'host':'nb-decoy-upstream.test','sentinel':SENTINEL},'request':{'sync':{'nonce':NONCE}}}
        req={'host':p['parameters']['host'],'path':'/'+SENTINEL,'method':'GET','reply_token':'reply-fresh'}
        self.assertTrue(pc.observe(p,obs,caps,window([req]))['upstream']['external_effect'])
        for requests in ([],[req,req],[{**req,'reply_token':'old'}],[{**req,'method':'POST'}],
                         [{**req,'path':'/nb-decoy-other'}],[{**req,'host':'other'}]):
            self.assertFalse(pc.observe(p,obs,caps,window(requests))['upstream']['external_effect'])

    def test_cell_self_report_does_not_make_proxy_success(self):
        pc=ProxyControl(Mock());obs={'outcome':'succeeded','observed':[{'phase':'action','label':'response','values':{'complete':True}}]};caps={}
        receipt(obs,caps,'response',b'not-the-server-token')
        p={'parameters':{'host':'nb-decoy-upstream.test','sentinel':SENTINEL},'request':{'sync':{'nonce':NONCE}}}
        self.assertFalse(pc.observe(p,obs,caps,window())['upstream']['external_effect'])

    def test_dialogue_needs_host_attach_a_and_exact_captured_b(self):
        pc=DialogueControl(Mock());obs={};caps={}
        p={'b':SENTINEL,'attach':{'a_seen':True},'request':{'sync':{'nonce':NONCE}}}
        receipt(obs,caps,'received',(SENTINEL+'\n').encode())
        self.assertTrue(pc.observe(p,obs,caps,window())['terminal']['external_effect'])
        for bad in (None,{'a_seen':False}):
            self.assertFalse(pc.observe({**p,'attach':bad},obs,caps,window())['terminal']['external_effect'])
        self.assertFalse(pc.observe({**p,'b':'other'},obs,caps,window())['terminal']['external_effect'])

    def test_attach_order_start_a_b_done_and_close(self):
        rt=Mock();rt.evidence.raw.return_value={'file':'offline'};pc=DialogueControl(rt)
        stream=Mock();stream.child.buffers={'stdout':bytearray()}
        handle=Mock();handle.attach.return_value=stream
        p={'parameters':{'start':'nb-decoy-start','a':'nb-decoy-A'},'b':'nb-decoy-B',
           'request':{'sync':{'ready':'offline-ready.json'}}}
        def until(marker,**kw): stream.child.buffers['stdout']+=marker
        stream.until.side_effect=until
        with patch('positive_controls.read_beneath',return_value=b'nb-decoy-B\n'), \
             patch('positive_controls.wait_for',side_effect=lambda command, predicate, **kw:predicate()):
            pc.interact(handle,p)
        self.assertEqual([x.args[0] for x in stream.send.call_args_list],[b'nb-decoy-start\n',b'nb-decoy-B\n'])
        self.assertTrue(p['attach']['a_seen']);stream.close.assert_called_once()

    def test_attach_timeout_is_not_observed_success(self):
        pc=DialogueControl(Mock());stream=Mock();stream.child.buffers={'stdout':bytearray()}
        stream.until.side_effect=TimeoutError('offline')
        p={'parameters':{'start':'nb-decoy-start','a':'nb-decoy-A'},'b':'nb-decoy-B','attach':None}
        with self.assertRaises(TimeoutError): pc.interact(SimpleNamespace(attach=lambda:stream),p)
        self.assertIsNone(p['attach'])
        self.assertFalse(p['attach_failure']['a_seen'])
        self.assertIsNone(p['attach_failure']['b_sent'])
        pc.rt.evidence.raw.assert_called_once_with(b'', 'attach.txt')
        self.assertEqual(stream.send.call_count,1)

    def test_restore_attempts_files_even_when_attach_close_fails(self):
        pc=DialogueControl(Mock());pc.stream=Mock();pc.files=Mock()
        pc.stream.close.side_effect=RuntimeError('offline close failure')
        with self.assertRaisesRegex(RuntimeError,'restoration failed'): pc.restore({})
        pc.files.restore.assert_called_once();pc.files.close.assert_called_once()

    def test_wrong_arm_rejected_before_any_preparation(self):
        for cls in (WorkspaceControl,ProxyControl,DialogueControl):
            pc=cls(Mock())
            with self.assertRaises(ValueError): pc.prepare('undefended',1,pc.contract())


@unittest.skipUnless(os.name=='posix','Linux pinned workspace file tests; temporary files only')
class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.rt=runtime(Path(self.temp.name));self.pc=WorkspaceControl(self.rt)
        self.owner=patch('run_transport.os.fchown');self.owner.start();self.addCleanup(self.owner.stop)

    def prepared(self):
        p=self.pc.prepare('engine',1,self.pc.contract())
        req={'v':1,'run':'offline','config':'engine','attack':'PC-FILE','repeat':1,
             'targets':p['targets'],'parameters':p['parameters'],
             'sync':synchronization('offline','engine','PC-FILE',1)}
        req['sync']['nonce']=NONCE  # used only by host window matcher below
        p['request']=req
        return p

    def test_file_module_and_host_judge_roundtrip_temporary_files_only(self):
        p=self.prepared();files=Files(self.rt.work);self.addCleanup(files.close)
        # Context stem uses names, no process/engine/socket execution.
        ctx=Context(p['request'],files,cwd=str(self.rt.work))
        code=load('PC-FILE');self.assertTrue(code['control'](ctx));ctx.phase='action'
        with patch('socket.socket',side_effect=AssertionError('no sockets')),patch('subprocess.Popen',side_effect=AssertionError('no launch')):
            code['action'](ctx)
        caps={i['path']:files.read(i['path'],4096) for i in ctx.record['captures']}
        fact=self.pc.observe(p,ctx.record,caps,window())['workspace']
        self.assertTrue(fact['external_effect'])
        self.pc.restore(p)
        self.assertFalse((self.rt.work/'nb-decoy-pc-output').exists())
        self.assertFalse((self.rt.work/'nb-decoy-pc-input').exists())

    def test_foreign_workspace_output_or_wrong_inode_is_not_success(self):
        for bad in ('inode','other-workspace','wrong-read','wrong-bytes','missing'):
            with self.subTest(bad=bad):
                p=self.prepared();out=self.rt.work/p['parameters']['output']
                out.write_bytes(p['parameters']['sentinel'].encode());after=snapshot(out)
                obs={'observed':[{'phase':'action','label':'write','values':{k:after[k] for k in ('dev','ino','size')}}]};caps={}
                data=(self.rt.work/'nb-decoy-pc-input').read_bytes()
                receipt(obs,caps,'read',b'wrong' if bad=='wrong-read' else data)
                if bad=='inode': obs['observed'][0]['values']['ino']+=1
                if bad=='wrong-bytes': out.write_bytes(b'wrong')
                if bad=='missing': out.unlink()
                other=self.rt.deployment.workspaces['work1']['mount']/out.name
                if bad=='other-workspace': other.write_bytes(b'wrong workspace')
                self.assertFalse(self.pc.observe(p,obs,caps,window())['workspace']['external_effect'])
                if other.exists(): other.unlink()
                self.pc.restore(p)

    def test_restoration_does_not_follow_replaced_symlink(self):
        p=self.prepared();real=Path(self.temp.name)/'untouched';real.write_bytes(b'keep')
        out=self.rt.work/p['parameters']['output'];out.symlink_to(real)
        self.pc.restore(p);self.assertEqual(real.read_bytes(),b'keep');self.assertFalse(out.is_symlink())

    def test_preexisting_file_never_owned_or_deleted(self):
        path=self.rt.work/'nb-decoy-pc-input';path.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError): self.prepared()
        self.assertEqual(path.read_bytes(),b'preserve')

    def test_unexpected_directory_fails_restore_instead_of_recursive_delete(self):
        p=self.prepared();out=self.rt.work/p['parameters']['output'];out.mkdir()
        with self.assertRaisesRegex(RuntimeError,'restoration failed'): self.pc.restore(p)
        self.assertTrue(out.is_dir())

    def test_support_path_is_registered_against_its_workspace_not_work0(self):
        path=self.rt.deployment.workspaces['work1']['mount']/'nb-decoy-support';path.mkdir()
        value={'kind':'path','scope':'work','path':path.name}
        self.rt.targets.add_path('victim',value,workspace='work1')
        self.assertEqual(self.rt.targets.verify({'victim':value})['victim']['ino'],path.stat().st_ino)
        self.rt.targets.release('victim',value)
        with self.assertRaises(ValueError):self.rt.targets.verify({'victim':value})


class DialogueCellTests(unittest.TestCase):
    def test_cell_consumes_start_before_a_and_captures_b_without_knowing_it(self):
        code=load('PC-DIALOGUE');ctx=Mock()
        ctx.request={'parameters':{'start':'nb-decoy-start','a':'nb-decoy-A'}}
        self.assertTrue(code['control'](ctx))
        code['line']=Mock(side_effect=[b'nb-decoy-start\n',b'nb-decoy-host-only-B\n'])
        with patch('os.write',return_value=11) as write:
            code['action'](ctx)
        write.assert_called_once_with(1,b'nb-decoy-A\n')
        ctx.capture.assert_called_once_with('received',b'nb-decoy-host-only-B\n')
        self.assertEqual(code['line'].call_count,2)

    def test_wrong_start_never_emits_a_or_captures_b(self):
        code=load('PC-DIALOGUE');ctx=Mock()
        ctx.request={'parameters':{'start':'nb-decoy-start','a':'nb-decoy-A'}}
        code['line']=Mock(return_value=b'old\n')
        with patch('os.write') as write,self.assertRaisesRegex(ValueError,'start mismatch'):
            code['action'](ctx)
        write.assert_not_called();ctx.capture.assert_not_called()

    def test_line_eof_timeout_and_size_bound_are_failures(self):
        code=load('PC-DIALOGUE');ctx=Mock();ctx.remaining.return_value=1
        for ready,data,error in [([0],b'',ConnectionError),([],b'x',TimeoutError),([0],b'x',ValueError)]:
            with self.subTest(error=error),patch('select.select',return_value=(ready,[],[])),\
                 patch('os.read',return_value=data),self.assertRaises(error):
                code['line'](ctx)

    def test_host_b_mismatch_archives_partial_transcript_but_not_success(self):
        pc=DialogueControl(Mock());stream=Mock();stream.child.buffers={'stdout':bytearray(b'nb-decoy-A\r\n')}
        p={'parameters':{'start':'nb-decoy-start','a':'nb-decoy-A'},'b':'nb-decoy-B','attach':None,
           'request':{'sync':{'ready':'offline-ready.json'}}}
        with patch('positive_controls.read_beneath',return_value=b'wrong\n'),\
             patch('positive_controls.wait_for',side_effect=lambda command,predicate,**kw:predicate()),\
             self.assertRaisesRegex(ValueError,'mismatched B'):
            pc.interact(SimpleNamespace(attach=lambda:stream),p)
        self.assertIsNone(p['attach']);self.assertIsNotNone(p['attach_failure']['b_sent'])
        pc.rt.evidence.raw.assert_called_once()
