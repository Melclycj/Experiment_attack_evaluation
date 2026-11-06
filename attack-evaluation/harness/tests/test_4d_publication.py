"""这是 1.1 隔离论证的验证测试：ready/release 双链接发布窗口的离线回归，不读取未完成发布。"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from cell.nb_io import Files as HostFiles, PublicationPending as HostPending
from nb_io import PublicationPending as CellPending
from nb_contract import encoded, stem
from decoys import synchronization
from run_transport import synchronize
from runner import Context
from test_cell_contract import request
from test_cell_runner import Clock,MemoryFiles


def req21():
    req=request();req['attack']='NB-21';req['sync']=synchronization(req['run'],req['config'],'NB-21',1)
    return req


def message(req,state):return {'attempt':stem(req),'nonce':req['sync']['nonce'],'state':state}


class Publication(unittest.TestCase):
    def test_host_pending_retries_without_observation_or_release(self):
        req=req21();files=Mock();files.read.side_effect=[HostPending('publishing'),encoded(message(req,'sent'))]
        observe=Mock(return_value={'question':{'qid':9}})
        with patch('run_transport.Files',return_value=files),patch('run_transport.publish') as publish:
            self.assertIsNone(synchronize('/owned',req,'sent',observe))
            observe.assert_not_called();publish.assert_not_called()
            self.assertEqual(synchronize('/owned',req,'sent',observe),{'question':{'qid':9}})
            value=publish.call_args.args[2]
            self.assertEqual(value,encoded({**message(req,'release'),'question':9}))
        self.assertEqual(files.close.call_count,2)

    def test_host_other_invalid_file_never_retried(self):
        req=req21();files=Mock();files.read.side_effect=ValueError('not regular')
        with patch('run_transport.Files',return_value=files),patch('run_transport.publish') as publish, self.assertRaisesRegex(ValueError,'not regular'):
            synchronize('/owned',req,'sent',Mock())
        publish.assert_not_called();files.close.assert_called_once()

    def test_cell_pending_release_retries_under_same_deadline(self):
        req=req21();files=MemoryFiles();clock=Clock()
        files.read=Mock(side_effect=[CellPending('publishing'),encoded({**message(req,'release'),'question':7})])
        ctx=Context(req,files,clock=clock,sleep=clock.sleep)
        self.assertEqual(ctx.synchronize('sent'),7)
        self.assertEqual(files.read.call_count,2);self.assertLess(clock(),1)

    def test_persistent_two_link_release_times_out_not_success(self):
        req=req21();files=MemoryFiles();clock=Clock();files.read=Mock(side_effect=CellPending('persistent'))
        ctx=Context(req,files,clock=clock,sleep=clock.sleep)
        with self.assertRaisesRegex(TimeoutError,'synchronization'):ctx.synchronize('sent',timeout=.05)
        self.assertEqual(ctx.record['synchronization'],[]);self.assertLessEqual(clock(),.06)

    def test_cell_other_invalid_content_fails_immediately(self):
        req=req21();files=MemoryFiles();clock=Clock();files.read=Mock(side_effect=ValueError('unsafe'))
        with self.assertRaisesRegex(ValueError,'unsafe'):
            Context(req,files,clock=clock,sleep=clock.sleep).synchronize('sent')
        self.assertEqual(files.read.call_count,1);self.assertEqual(clock(),0)

    @unittest.skipUnless(os.name=='posix','temporary Linux hardlinks, no engine')
    def test_real_two_link_ready_is_unread_until_publisher_unlinks(self):
        req=req21()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'publisher-temp';source.write_bytes(encoded(message(req,'sent')))
            os.link(source,root/req['sync']['ready']);observe=Mock(return_value={'question':{'qid':7}})
            self.assertIsNone(synchronize(root,req,'sent',observe));observe.assert_not_called()
            source.unlink()
            with patch('run_transport.os.fchown'):synchronize(root,req,'sent',observe)
            self.assertEqual(observe.call_count,1)
            files=HostFiles(root)
            try:self.assertEqual(files.read(req['sync']['release'],4096),encoded({**message(req,'release'),'question':7}))
            finally:files.close()
