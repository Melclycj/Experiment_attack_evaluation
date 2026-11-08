"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from connection_endpoint import Endpoint
from cell.nb_io import PublicationPending
from support_rows import SupportRows
from connection_service import bind_endpoint, run as serve_run
from connection_end import end_exchange
from connection_cases import ConnectionCase
from listener_witness import inspect_listener, table_witness
from foura_fixtures import NONCE


class WitnessTests(unittest.TestCase):
    def test_udp_bound_endpoint_not_tcp_listen_or_connected_udp(self):
        value={'kind':'inet','address':'127.0.0.1','port':53000}
        text='header\n0: 0100007F:CF08 00000000:0000 07 0 0 0 0 0 43\n'
        self.assertTrue(table_witness(text,value,{43},'udp')['listening'])
        for source,owned in [(text,{44}),(text.replace(' 07 ',' 0A '),{43}),
                             (text.replace('00000000:0000','0100007F:1234'),{43}),
                             (text+text.splitlines()[1]+'\n',{43})]:
            with self.assertRaises(ValueError):table_witness(source,value,owned,'udp')
        with self.assertRaises(ValueError):table_witness(text,value,{43},'tcp')

    def test_inspection_reads_udp_table_and_double_checks_pinned_process(self):
        ref=Mock();ref.read.return_value={'pid':22}
        value={'kind':'inet','address':'127.0.0.1','port':53000}
        text='header\n0: 0100007F:CF08 00000000:0000 07 0 0 0 0 0 43\n'
        with patch('pathlib.Path.iterdir',return_value=[Path('/proc/22/fd/3')]),\
             patch('listener_witness.os.readlink',return_value='socket:[43]'),\
             patch('pathlib.Path.read_text',return_value=text) as read:
            self.assertTrue(inspect_listener(ref,value,'udp')['listening'])
        self.assertEqual(ref.read.call_count,2)


class EndpointTests(unittest.TestCase):
    def endpoint(self, wire='tcp', netfd=None):
        rt=Mock();rt.network=SimpleNamespace(prepared=True,closed=False,fds=[77])
        rt.command.deadline.left.side_effect=lambda n:n
        rt.deployment.refs={}
        e=Endpoint(rt,'nb-decoy-offline',{'kind':'inet','address':'127.0.0.1','port':42000},wire,'attempt',netfd=netfd)
        return rt,e

    def start_fixture(self, e):
        store=Mock(root=Path('/tmp/nb-decoy-offline'))
        child=Mock();child.proc.pid=22;child.proc.poll.return_value=None
        e.rt.command.start.return_value=child
        store.read.return_value=json.dumps({'target':e.value,'nonce':e.nonce,'pid':22,'wire':e.wire}).encode()
        return store, child

    def test_start_pins_registered_process_and_reads_table_before_use(self):
        rt,e=self.endpoint(netfd=77);store,child=self.start_fixture(e)
        witness={'target':e.value,'listening':True,'inode':44}
        with patch('connection_endpoint.ConnectionStore',return_value=store),\
             patch('connection_endpoint.wait_for',side_effect=lambda c,p,**kw:p()),\
             patch('connection_endpoint.pin_child',return_value=Mock()) as pin,patch.object(e,'witness',return_value=witness):
            self.assertEqual(e.start('relay'),e.value)
        argv=rt.command.start.call_args.args[0]
        self.assertEqual(argv[0],'/usr/bin/nsenter');self.assertIn('/fd/77',argv[1])
        pin.assert_called_once_with(rt,e.name,child,0);rt.targets.add_listener.assert_called_once()
        self.assertNotIn(e.secret,json.dumps(e.value))

    def test_readiness_wrong_nonce_pid_or_wire_is_not_listener_proof(self):
        for field,value in [('nonce','wrong'),('pid',23),('wire','udp')]:
            rt,e=self.endpoint();store,child=self.start_fixture(e)
            info=json.loads(store.read.return_value);info[field]=value;store.read.return_value=json.dumps(info).encode()
            with patch('connection_endpoint.ConnectionStore',return_value=store),\
                 patch('connection_endpoint.wait_for',side_effect=lambda c,p,**kw:p()),\
                 patch('connection_endpoint.pin_child') as pin,self.assertRaises(ValueError):e.start('relay')
            pin.assert_not_called();self.assertIs(e.child,child)

    def test_readiness_retries_publication_only_under_existing_deadline(self):
        rt,e=self.endpoint();store,child=self.start_fixture(e)
        good=store.read.return_value
        store.read.side_effect=[FileNotFoundError(),PublicationPending('link window'),good]
        def poll(command, check, **kw):
            self.assertEqual(kw['timeout'],5);self.assertIs(kw['child'],child)
            self.assertIsNone(check());self.assertIsNone(check());return check()
        with patch('connection_endpoint.ConnectionStore',return_value=store),\
             patch('connection_endpoint.wait_for',side_effect=poll),\
             patch('connection_endpoint.pin_child',return_value=Mock()),patch.object(e,'witness',return_value={}):
            self.assertEqual(e.start('relay'),e.value)
        self.assertEqual(store.read.call_count,3)
        rt.evidence.raw.assert_called_once_with(good,'listener-ready.json')

    def test_malformed_readiness_is_archived_not_retried(self):
        rt,e=self.endpoint();store,child=self.start_fixture(e);store.read.return_value=b'{malformed'
        with patch('connection_endpoint.ConnectionStore',return_value=store),\
             patch('connection_endpoint.wait_for',side_effect=lambda c,p,**kw:p()),self.assertRaises(ValueError):
            e.start('relay')
        self.assertEqual(store.read.call_count,1)
        rt.evidence.raw.assert_called_once_with(b'{malformed','listener-ready.json')

    def test_network_namespace_must_be_owned_and_live(self):
        for closed,prepared,fd in [(True,True,77),(False,False,77),(False,True,78)]:
            rt,e=self.endpoint(netfd=fd);rt.network.closed=closed;rt.network.prepared=prepared
            with self.assertRaises(ValueError):e.prefix()

    def test_end_checks_tree_and_same_listener_then_real_supervised_marker(self):
        rt,e=self.endpoint();e.child=Mock();e.child.proc.poll.return_value=0
        e.before={'target':e.value,'listening':True,'inode':44};e.witness=Mock(return_value=e.before)
        rt.command.return_value={'stdout':'{"echo":true}'}
        e.sample=Mock(return_value={'entries':[{'kind':'end'}],'markers':{}})
        with self.assertRaises(ValueError):e.finish(tree_empty=False)
        result=e.finish(tree_empty=True)
        self.assertTrue(e.ended);rt.command.wait.assert_called_once_with(e.child)
        self.assertEqual(rt.command.call_args.kwargs['env']['NB_END_SECRET'],e.secret)
        self.assertEqual(result['expected_secret'],e.secret)

    def test_wrong_identity_echo_and_exit_cannot_close_window(self):
        for fault in ('identity','echo','exit'):
            rt,e=self.endpoint();e.child=Mock();e.child.proc.poll.return_value=1 if fault=='exit' else 0
            e.before={'inode':1};e.witness=Mock(return_value={'inode':2 if fault=='identity' else 1})
            rt.command.return_value={'stdout':'{"echo":false}' if fault=='echo' else '{"echo":true}'}
            with self.assertRaises(ValueError):e.finish(tree_empty=True)
            self.assertFalse(e.ended)

    def test_restore_cannot_delete_a_live_service_and_dispose_is_readonly(self):
        rt,e=self.endpoint();e.child=Mock();e.child.proc.poll.return_value=None;e.store=Mock()
        with self.assertRaises(ValueError):e.restore()
        e.store.restore.assert_not_called();e.dispose();e.store.close.assert_called_once()

    def test_failed_restore_is_not_hidden_and_refs_not_released(self):
        rt,e=self.endpoint();rt.rows=[];e.restore=Mock(side_effect=ValueError('retained'))
        a=ConnectionCase(rt,'NB-16');a.sessions={'relay':e};a.registered={'relay':e.value}
        with self.assertRaisesRegex(RuntimeError,'retained'):a.restore({})
        rt.targets.release.assert_not_called();self.assertTrue(a.sessions)

    def test_live_attack_defers_all_deletion_but_samples_evidence(self):
        rt,e=self.endpoint();rt.rows=[SimpleNamespace(workspace='work0',closed=False)]
        e.sample=Mock();e.restore=Mock()
        a=ConnectionCase(rt,'NB-16');a.sessions={'relay':e};a.files=Mock()
        with self.assertRaisesRegex(RuntimeError,'still live'):a.restore({})
        e.sample.assert_called_once();e.restore.assert_not_called();a.files.restore.assert_not_called()


class PartialVictimTests(unittest.TestCase):
    def make(self):
        s=SupportRows.__new__(SupportRows);s.rt=Mock()
        s.current={'cursor':3,'attempt':'attempt','secret':NONCE}
        s.items={'victim':{'nonce':NONCE,'files':Mock(),'ref':Mock()}}
        s.items['victim']['ref'].read.side_effect=RuntimeError('exited')
        return s

    def test_dead_listener_missing_end_keeps_receipt_without_claiming_closure(self):
        s=self.make();item={'nonce':NONCE,'seq':3,'attempt':'attempt','kind':'request'}
        raw=json.dumps(item).encode()
        s.items['victim']['files'].read.side_effect=[raw,FileNotFoundError()]
        result=s.sample_window()
        self.assertEqual(result['entries'],[item]);self.assertNotIn('end',result)
        s.rt.evidence.raw.assert_called_once_with(raw,'support-partial.json')
        s.items['victim']['ref'].read.assert_not_called();self.assertIsNotNone(s.current)

    def test_bad_nonce_and_json_archived_without_becoming_verified_receipt(self):
        for raw in (b'{bad',b'{"nonce":"wrong"}'):
            s=self.make();s.items['victim']['files'].read.return_value=raw
            result=s.sample_window()
            self.assertEqual(result['entries'],[]);self.assertIn('error',result)
            s.rt.evidence.raw.assert_called_once_with(raw,'support-partial.json')

    def test_record_count_is_bounded_without_end_or_actual_socket(self):
        s=self.make()
        s.items['victim']['files'].read.side_effect=[json.dumps(
            {'nonce':NONCE,'seq':i,'attempt':'attempt','kind':'request'}).encode() for i in range(3,67)]
        result=s.sample_window()
        self.assertEqual(len(result['entries']),64);self.assertNotIn('end',result)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        guard = patch("socket.AF_UNIX", 1, create=True)
        guard.start(); self.addCleanup(guard.stop)

    def test_only_private_run_addresses_can_bind(self):
        for value in ({'kind':'inet','address':'8.8.8.8','port':80},
                      {'kind':'inet','address':'127.0.0.1','port':3128}):
            with patch('socket.socket') as sock,self.assertRaises(ValueError):bind_endpoint(value,'tcp')
            sock.assert_not_called()

    def test_bind_failure_closes_socket_and_never_unlinks_existing_path(self):
        sock=Mock();sock.bind.side_effect=OSError('occupied')
        with patch('socket.socket',return_value=sock),patch('os.unlink') as unlink,\
             self.assertRaises(OSError):bind_endpoint({'kind':'abstract','name':'nb-decoy-a'},'unix')
        sock.close.assert_called_once();unlink.assert_not_called()

    def test_udp_does_not_listen_and_uses_allocated_port(self):
        sock=Mock();sock.getsockname.return_value=('127.0.0.1',40000)
        with patch('socket.socket',return_value=sock):
            _,value=bind_endpoint({'kind':'inet','address':'127.0.0.1','port':0},'udp')
        self.assertEqual(value['port'],40000);sock.listen.assert_not_called()

    def test_marker_exchange_requires_exact_echo(self):
        value={'kind':'abstract','name':'nb-decoy-only'}
        with patch('connection_end.exchange',return_value=(b'wrong',{'errno':0})),self.assertRaises(ValueError):
            end_exchange(value,'unix',NONCE)

    def test_marker_success_is_not_forwarding_or_process_creation(self):
        value={'kind':'abstract','name':'nb-decoy-only'}
        frame=b'\0NB-END:'+NONCE.encode()+b'\n'
        with patch('connection_end.exchange',return_value=(frame,{'errno':0})) as ex:
            self.assertEqual(end_exchange(value,'unix',NONCE),{'echo':True})
        self.assertEqual(ex.call_args.args[3],frame)
