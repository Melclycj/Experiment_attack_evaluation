"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import errno
from pathlib import Path
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from foura_fixtures import load
from fourc_fixtures import prepared, probe_events
from nb_conn_actions import exchange, operation, control, action
from nb_conn_control import local_control
from nb_conn_probe import probe_result
from nb_conn_spec import SPECS, DIRECT, parameters, address, payload


class CellTests(unittest.TestCase):
    def ctx(self, attack='NB-16'):
        ctx=Mock(cwd='/work',payload=Path('/runtime/nb'))
        ctx.request=prepared(attack)['request'];ctx.remaining.side_effect=lambda n=30:n
        return ctx

    def test_all_explicit_modules_delegate_their_exact_id(self):
        for attack in SPECS:
            ns=load(attack);ctx=self.ctx(attack)
            with patch('nb_conn_actions.control',return_value=True) as ctl, patch('nb_conn_actions.action') as act:
                # Reload after patch so imported bindings are mocked, not executed.
                ns=load(attack);self.assertTrue(ns['control'](ctx));ns['action'](ctx)
                ctl.assert_called_once_with(ctx,attack);act.assert_called_once_with(ctx,attack)

    def test_each_address_uses_own_control_and_action(self):
        for attack in SPECS:
            ctx=self.ctx(attack)
            with patch('nb_conn_control.local_control',return_value=True) as ctl,patch('nb_conn_actions.operation') as op:
                self.assertTrue(control(ctx,attack));action(ctx,attack)
                self.assertEqual([c.args[2] for c in ctl.call_args_list],list(SPECS[attack]))
                self.assertEqual([c.args[2] for c in op.call_args_list],list(SPECS[attack]))
                self.assertEqual(len({c.args[4] for c in op.call_args_list}),len(SPECS[attack]))

    def test_parameters_reject_wrong_scope_id_missing_address_and_reused_nonce(self):
        ctx=self.ctx('NB-19');self.assertTrue(parameters(ctx,'NB-19'))
        for mutation in (lambda c:c.request.update(attack='NB-27'),
                         lambda c:c.request['targets'].pop('daemon-path'),
                         lambda c:c.request['parameters'].update(control_daemon='fake'),
                         lambda c:c.request['targets']['daemon-path'].update(scope='work')):
            c=self.ctx('NB-19');mutation(c)
            with self.assertRaises(ValueError):parameters(c,'NB-19')
        c=self.ctx('NB-19');p=c.request['parameters'];p['control_daemon-path']=p['sentinel_daemon-path']
        with self.assertRaises(ValueError):parameters(c,'NB-19')

    def test_python_socket_uses_direct_target_eof_and_captures_echo(self):
        ctx=self.ctx();conn=Mock();conn.recv.side_effect=[b'abc',b'']
        with patch('nb_conn_actions.socket.socket',return_value=conn):
            data,result=exchange(ctx,'tcp',ctx.request['targets']['relay'],b'abc')
        self.assertEqual(data,b'abc');self.assertEqual(result['errno'],0)
        conn.connect.assert_called_once_with(('127.0.0.1',42000))
        conn.shutdown.assert_called_once_with(socket.SHUT_WR);conn.close.assert_called_once()

    def test_python_denial_is_connect_observation_and_empty_capture(self):
        ctx=self.ctx();conn=Mock();conn.connect.side_effect=OSError(errno.ECONNREFUSED,'denied')
        with patch('nb_conn_actions.socket.socket',return_value=conn):
            data,result=exchange(ctx,'tcp',ctx.request['targets']['relay'],b'abc')
        self.assertEqual((data,result['step'],result['errno']),(b'','connect',111 if errno.ECONNREFUSED==111 else errno.ECONNREFUSED))
        conn.sendall.assert_not_called();conn.close.assert_called_once()

    def test_timeout_never_converted_to_expected_errno(self):
        ctx=self.ctx();conn=Mock();conn.connect.side_effect=TimeoutError('offline')
        with patch('nb_conn_actions.socket.socket',return_value=conn),self.assertRaises(TimeoutError):
            exchange(ctx,'tcp',ctx.request['targets']['relay'],b'abc')
        conn.close.assert_called_once()

    def test_abstract_same_constructor_for_control_and_target(self):
        self.assertEqual(address({'kind':'abstract','name':'nb-decoy-test'}),'\0nb-decoy-test')
        with self.assertRaises(ValueError):address({'kind':'path','scope':'host','path':'/'+('x'*108)})

    def test_c_probe_arguments_and_input_are_not_python_network_io(self):
        for attack in DIRECT:
            ctx=self.ctx(attack);wire=SPECS[attack]['global'][0];data=b'marker'
            ctx.command.return_value={'returncode':0,'signal':None,'error':None,'stdout':data,
                                      'stderr':probe_events(wire,data)}
            with patch('socket.socket',side_effect=AssertionError('no socket in probe wrapper')):
                out,result=operation(ctx,attack,'global',ctx.request['targets']['global'],data)
            argv=ctx.command.call_args.args[1]
            self.assertEqual(argv[1:],[wire,'93.184.216.2','42000'])
            self.assertEqual(ctx.command.call_args.kwargs['data'],data);self.assertEqual(out,data)
            self.assertEqual(result['errno'],0)

    def test_c_probe_failure_steps_distinguish_udp_connect_and_recv(self):
        for wire,where,code in [('tcp','connect',111),('udp','connect',101),('udp','recv',111)]:
            raw={'returncode':0,'signal':None,'error':None,'stdout':b'',
                 'stderr':probe_events(wire,b'marker',(where,code))}
            self.assertEqual(probe_result(raw,wire,6),{'step':where,'errno':code,'rc':-1})

    def test_c_probe_rejects_signal_missing_complete_wrong_sequence_and_bad_count(self):
        base={'returncode':0,'signal':None,'error':None,'stdout':b'abc','stderr':probe_events('tcp',b'abc')}
        for diff in ({'signal':9},{'returncode':2},{'stderr':b''},{'stdout':b'x'},
                     {'stderr':base['stderr'].replace(b'"connect"',b'"bogus"')}):
            with self.assertRaises(ValueError):probe_result({**base,**diff},'tcp',3)

    def test_local_control_closes_listener_before_action(self):
        ctx=self.ctx();conn=Mock();listener=Mock();listener.getsockname.return_value=('127.0.0.1',12345)
        data=payload('NB-16',ctx.request['parameters']['control_relay'])
        conn.__enter__=Mock(return_value=conn);conn.__exit__=Mock(return_value=False)
        conn.recv.side_effect=[data,b''];listener.accept.return_value=(conn,('127.0.0.1',1))
        def thread(*,target,daemon):
            return SimpleNamespace(start=target,join=lambda **kw:None,is_alive=lambda:False)
        op=Mock(return_value=(data,{'errno':0}))
        with patch('nb_conn_control.socket.socket',return_value=listener),patch('nb_conn_control.threading.Thread',side_effect=thread):
            self.assertTrue(local_control(ctx,'NB-16','relay',op))
        listener.bind.assert_called_once_with(('127.0.0.1',0));listener.close.assert_called_once()
        self.assertEqual(op.call_args.args[3]['port'],12345)
        ctx.capture.assert_called_once_with('relay-received',data)

    def test_local_path_collision_does_not_delete_or_connect(self):
        ctx=self.ctx('NB-19')
        with patch('nb_conn_control.os.path.lexists',return_value=True),patch('socket.socket') as sock,\
             patch('nb_conn_control.os.unlink') as unlink,self.assertRaises(FileExistsError):
            local_control(ctx,'NB-19','daemon-path',Mock())
        sock.assert_not_called();unlink.assert_not_called()
