"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import base64
import copy
import json
import os
from pathlib import Path
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from nb_support import Mailbox, victim, auxiliary
from support_rows import SupportRows
from listener_witness import table_witness, socket_inodes
from listener_client import exchange
from foura_fixtures import NONCE, SENTINEL, MemoryFiles, Clock


def context(role):
    clock=Clock();ctx=Mock()
    ctx.request={'targets':{role:{}},'parameters':{'role':role,'nonce':NONCE,'name':'nb-decoy-listener'}}
    ctx.path.return_value='/offline';ctx.remaining.side_effect=lambda n=30:n
    ctx.sleep=clock.sleep; ctx.clock=clock
    return ctx


def command(seq,op,**kw):
    return json.dumps({'seq':seq,'nonce':NONCE,'op':op,**kw}).encode()


class WitnessTests(unittest.TestCase):
    def test_unix_abstract_requires_owned_listening_inode(self):
        text='Num RefCount Protocol Flags Type St Inode Path\n0: 2 0 00010000 0001 01 42 @nb-decoy-listener\n'
        target={'kind':'abstract','name':'nb-decoy-listener'}
        self.assertEqual(table_witness(text,target,{42})['inode'],42)
        for data,owners in [(text,{43}),(text.replace('00010000','00000000'),{42}),
                            (text.replace('nb-decoy-listener','nb-decoy-other'),{42}),
                            (text+text.splitlines()[1]+'\n',{42})]:
            with self.assertRaises(ValueError):table_witness(data,target,owners)

    def test_tcp_endpoint_and_inode_are_both_required(self):
        target={'kind':'inet','address':'127.0.0.1','port':443}
        text='header\n0: 0100007F:01BB 00000000:0000 0A 0 0 0 0 0 101\n'
        self.assertTrue(table_witness(text,target,{101})['listening'])
        with self.assertRaises(ValueError):table_witness(text,{**target,'port':444},{101})
        self.assertEqual(socket_inodes(['socket:[101]','pipe:[102]','/file']),{101})

    def test_path_socket_is_not_just_a_filesystem_inode(self):
        value={'kind':'path','scope':'host','path':'/tmp/nb-decoy-x/socket'}
        text='header\n0: 2 0 00010000 0001 01 82 /tmp/nb-decoy-x/socket\n'
        self.assertEqual(table_witness(text,value,{82})['inode'],82)
        with self.assertRaises(ValueError):table_witness(text,value,{99})


class CellSupportTests(unittest.TestCase):
    def setUp(self):
        for name, value in [('AF_UNIX', 1), ('SO_PEERCRED', 17)]:
            guard = patch('socket.' + name, value, create=True)
            guard.start(); self.addCleanup(guard.stop)

    def test_mailbox_stale_nonce_and_sequence_rejected(self):
        for bad in ({'nonce':'wrong','seq':0,'op':'stop'}, {'nonce':NONCE,'seq':2,'op':'stop'}):
            files=MemoryFiles({'command-0000.json':json.dumps(bad).encode()})
            with patch('nb_support.Files',return_value=files):box=Mailbox(context('victim'),'victim')
            with self.assertRaises(ValueError):box.next()

    def test_victim_ready_and_stop_close_without_real_listener(self):
        files=MemoryFiles({'command-0000.json':command(0,'stop')});files.close=Mock()
        listener=Mock()
        with patch('nb_support.Files',return_value=files),patch('nb_support.socket.socket',return_value=listener):
            victim(context('victim'))
        self.assertEqual(json.loads(files.values['ready.json'])['role'],'victim')
        listener.bind.assert_called_once_with('\0nb-decoy-listener');listener.close.assert_called_once();files.close.assert_called_once()

    def test_victim_records_peer_and_end_not_request(self):
        secret='f'*48
        files=MemoryFiles({'command-0000.json':command(0,'begin',attempt='attempt',secret=secret),
                           'command-0001.json':command(1,'stop')});files.close=Mock()
        conn=Mock();conn.__enter__=Mock(return_value=conn);conn.__exit__=Mock(return_value=False)
        conn.getsockopt.return_value=struct.pack('3i',44,1000,1000)
        conn.recv.side_effect=[b'\0NB-END:'+secret.encode()+b'\n',b'']
        listener=Mock();listener.accept.return_value=(conn,'')
        with patch('nb_support.Files',return_value=files),patch('nb_support.socket.socket',return_value=listener),\
             patch('nb_support.select.select',return_value=([listener],[],[])):
            victim(context('victim'))
        data=json.loads(files.values['event-000000.json'])
        self.assertEqual(data['kind'],'end');self.assertEqual(data['peer'],{'pid':44,'uid':1000,'gid':1000})
        self.assertEqual(json.loads(files.values['window-0000.json'])['cursor'],0)

    def test_victim_unclosed_window_is_error_and_closes_socket(self):
        files=MemoryFiles({'command-0000.json':command(0,'begin',attempt='a',secret='c'*48),
                           'command-0001.json':command(1,'stop')});files.close=Mock()
        listener=Mock()
        with patch('nb_support.Files',return_value=files),patch('nb_support.socket.socket',return_value=listener),\
             patch('nb_support.select.select',return_value=([],[],[])),self.assertRaises(ValueError):
            victim(context('victim'))
        listener.close.assert_called_once();files.close.assert_called_once()

    def test_victim_timeout_closes_listener(self):
        files=MemoryFiles();files.close=Mock();ctx=context('victim');ctx.remaining.side_effect=TimeoutError('offline')
        listener=Mock()
        with patch('nb_support.Files',return_value=files),patch('nb_support.socket.socket',return_value=listener),self.assertRaises(TimeoutError):
            victim(ctx)
        listener.close.assert_called_once()

    def test_auxiliary_idle_never_opens_proxy(self):
        files=MemoryFiles({'command-0000.json':command(0,'stop')});files.close=Mock()
        with patch('nb_support.Files',return_value=files),patch('nb_support.open_request') as op:
            auxiliary(context('auxiliary'))
        op.assert_not_called();files.close.assert_called_once()

    def test_auxiliary_final_result_written_and_connection_closed(self):
        files=MemoryFiles({'command-0000.json':command(0,'question',path='/nb-decoy-test'),
                           'command-0001.json':command(1,'stop')});files.close=Mock();conn=Mock()
        def thread(*,target,daemon):
            return SimpleNamespace(start=target,join=lambda **kw:None,is_alive=lambda:False)
        with patch('nb_support.Files',return_value=files),patch('nb_support.open_request',return_value=conn),\
             patch('nb_support.response',return_value={'category':1,'status':200,'body':b'yes','complete':True}),\
             patch('nb_support.threading.Thread',side_effect=thread):
            auxiliary(context('auxiliary'))
        result=json.loads(files.values['result-0000.json'])
        self.assertTrue(result['complete']);self.assertEqual(base64.b64decode(result['body_base64']),b'yes')
        conn.close.assert_called_once()

    def test_auxiliary_failed_response_is_recorded_not_success(self):
        files=MemoryFiles({'command-0000.json':command(0,'question',path='/nb-decoy-test'),
                           'command-0001.json':command(1,'stop')});files.close=Mock()
        def thread(*,target,daemon):return SimpleNamespace(start=target,join=lambda **kw:None,is_alive=lambda:False)
        with patch('nb_support.Files',return_value=files),patch('nb_support.open_request',return_value=Mock()),\
             patch('nb_support.response',side_effect=TimeoutError('offline')),patch('nb_support.threading.Thread',side_effect=thread):
            auxiliary(context('auxiliary'))
        self.assertFalse(json.loads(files.values['result-0000.json'])['complete'])


class HostSupportTests(unittest.TestCase):
    def make(self):
        s=SupportRows.__new__(SupportRows);s.rt=Mock();s.current=s.question_pending=None;s.closed=False;s.netfd=11;s.config='engine'
        s.signal_victim=False
        s.items={role:{'ref':Mock(),'row':Mock(execution='epoch:1'), 'files':Mock(), 'nonce':NONCE,
                      'sequence':0,'records':[],'root':Path('/offline/nb-decoy-'+role)} for role in ('victim','auxiliary')}
        s.items['victim']['target']={'kind':'abstract','name':'nb-decoy-listener'}
        s.rt.command.deadline.left.side_effect=lambda n:n
        s.rt.deployment.admin.watcher=None
        return s

    def test_two_arms_always_put_auxiliary_inside_engine(self):
        for config in ('engine','undefended'):
            with patch.object(SupportRows,'_start') as start: SupportRows(Mock(),config)
            self.assertEqual(start.call_args_list[0].args,('victim','work1',config,'SUP-VICTIM'))
            self.assertEqual(start.call_args_list[1].args,('auxiliary','work2','engine','SUP-AUXILIARY'))

    def test_partial_constructor_disposes_without_claiming_stopped(self):
        with patch.object(SupportRows,'_start',side_effect=ValueError('start')),patch.object(SupportRows,'dispose') as dispose,\
             self.assertRaises(ValueError): SupportRows(Mock(),'engine')
        dispose.assert_called_once()

    def test_window_checks_listener_before_begin_and_rejects_bad_ack(self):
        s=self.make();s._send=Mock(return_value=0);s._wait=Mock(return_value={'attempt':'wrong','cursor':0})
        with patch('support_rows.inspect_listener',return_value={'listening':True}) as inspect,self.assertRaises(ValueError):
            s.begin_window('attempt')
        inspect.assert_called_once();self.assertIsNotNone(s.current)

    def test_window_requires_tree_exit(self):
        s=self.make();s.current={'cursor':0,'attempt':'a','secret':'d'*48}
        with self.assertRaises(ValueError):s.end_window(tree_empty=False)
        s.rt.command.assert_not_called()

    def test_window_end_marker_is_actual_supervised_exchange(self):
        s=self.make();s.current={'cursor':0,'attempt':'a','secret':'d'*48}
        s._wait=Mock(return_value={'seq':0,'kind':'end','attempt':'a','token':'d'*48})
        s.rt.command.return_value={'stdout':'{"echo":true}'}
        with patch('support_rows.inspect_listener',return_value={'listening':True}),\
             patch('support_rows.time.monotonic',side_effect=[0,2]):
            value=s.end_window(tree_empty=True)
        self.assertEqual(value['requests'],[]);self.assertIsNone(s.current)
        argv=s.rt.command.call_args.args[0]
        self.assertIn('/usr/bin/nsenter',argv);self.assertTrue(any('/fd/11' in x for x in argv))

    def test_missing_or_wrong_end_stays_open(self):
        for fail in ('wrong','timeout'):
            s=self.make();s.current={'cursor':0,'attempt':'a','secret':'d'*48}
            s._wait=Mock(return_value={'seq':0,'kind':'end','attempt':'a','token':'wrong'})
            if fail=='timeout':s._wait.side_effect=TimeoutError('offline')
            s.rt.command.return_value={'stdout':'{"echo":true}'}
            with patch('support_rows.inspect_listener'),patch('support_rows.time.monotonic',side_effect=[0,2]),\
                 self.assertRaises((ValueError,TimeoutError)):s.end_window(tree_empty=True)
            self.assertIsNotNone(s.current)

    def test_question_watch_precedes_command_and_confirmation(self):
        s=self.make();events=[]
        s.rt.deployment.admin.watch.side_effect=lambda:events.append('watch')
        s._send=Mock(side_effect=lambda *a,**k:events.append('send') or 0)
        s._wait=Mock(return_value={'path':'/nb-decoy-test'})
        s.rt.deployment.admin.question.side_effect=lambda **k:events.append('confirm') or {'qid':1}
        self.assertEqual(s.begin_question('/nb-decoy-test'),{'qid':1})
        self.assertEqual(events,['watch','send','confirm'])

    def test_question_requires_confirmation_and_final_matching_result(self):
        s=self.make();s.question_pending={'sequence':0,'path':'/nb-decoy-test'}
        with self.assertRaises(ValueError):s.question_result()
        s.question_pending['question']={'qid':1};s._wait=Mock(return_value={'path':'wrong','complete':True})
        with self.assertRaises(ValueError):s.question_result()
        s._wait.return_value={'path':'/nb-decoy-test','complete':True}
        self.assertTrue(s.question_result()['complete']);self.assertIsNone(s.question_pending)

    def test_process_exit_not_hidden_by_ready_file(self):
        s=self.make();s.items['victim']['ref'].read.side_effect=RuntimeError('pinned process exited')
        with self.assertRaisesRegex(RuntimeError,'exited'):s._read('victim','ready.json')
        s.items['victim']['files'].read.assert_not_called()

    def test_dispose_releases_netns_and_files_idempotently(self):
        s=self.make()
        with patch('support_rows.os.close') as close:
            s.dispose();s.dispose()
        close.assert_called_once_with(11);self.assertIsNone(s.netfd)

    def test_close_refuses_unfinished_window(self):
        s=self.make();s.current={'attempt':'a'}
        with self.assertRaises(ValueError):s.close()

    def test_support_read_wrong_nonce_is_invalid(self):
        s=self.make();s.items['victim']['files'].read.return_value=b'{"nonce":"wrong"}'
        with self.assertRaisesRegex(ValueError,'nonce'):s._read('victim','ready.json')


class MarkerTests(unittest.TestCase):
    def setUp(self):
        for name, value in [('AF_UNIX', 1), ('SO_PEERCRED', 17)]:
            guard = patch('socket.' + name, value, create=True)
            guard.start(); self.addCleanup(guard.stop)

    def test_marker_client_echo_mismatch_closes_socket(self):
        conn=Mock();conn.__enter__=Mock(return_value=conn);conn.__exit__=Mock(return_value=False)
        conn.recv.side_effect=[b'wrong',b'']
        with patch('listener_client.socket.socket',return_value=conn),self.assertRaises(ValueError):exchange('nb-decoy-only','f'*48)
        conn.__exit__.assert_called_once()
