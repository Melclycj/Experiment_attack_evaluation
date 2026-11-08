"""这是 1.1 隔离论证的验证测试：NB-21 套接字/线程全 mock，核对最终结果与关闭路径。"""
from contextlib import ExitStack
import errno
import socket
import unittest
from unittest.mock import Mock, MagicMock, patch
from cell.nb_engine_question import PendingRequest, answer, answer_bytes, control


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('socket.AF_UNIX',getattr(socket,'AF_UNIX',1),create=True))
        self.ctx=Mock();self.ctx.remaining.return_value=3
        self.ctx.cwd='/work';self.ctx.request={'parameters':{'controls':{'admin':'nb-decoy-control'}}}
        self.sock=MagicMock();self.thread=Mock();self.thread.is_alive.return_value=False
        self.stack.enter_context(patch('cell.nb_engine_question.socket.socket',return_value=self.sock))
        self.stack.enter_context(patch('cell.nb_engine_question.threading.Thread',return_value=self.thread))

    def pending(self):return PendingRequest(self.ctx,'/nb-decoy-request')

    def test_complete_response_is_captured_before_finish_returns(self):
        p=self.pending();value={'complete':True,'body':b'answer','category':1,'status':200}
        with patch('cell.nb_engine_question.response',return_value=value):p._read()
        self.assertTrue(p.done.is_set());self.assertTrue(p.sent.is_set())
        result=p.finish();self.assertTrue(result['complete']);self.assertFalse(result['cancelled'])
        self.ctx.capture.assert_called_once_with('response',b'answer')
        self.thread.join.assert_called_once();p.close();self.sock.close.assert_called_once()

    def test_connect_failure_is_not_a_final_response(self):
        p=self.pending();self.sock.connect.side_effect=FileNotFoundError(errno.ENOENT,'absent')
        p._read();self.assertFalse(p.sent.is_set());self.assertTrue(p.done.is_set())
        with self.assertRaisesRegex(RuntimeError,'before send'):p.wait_sent()
        with self.assertRaisesRegex(RuntimeError,'valid final result'):p.finish()
        p.close();self.sock.close.assert_called_once()

    def test_cancel_shutdown_unblocks_reader_and_records_local_final(self):
        p=self.pending()
        self.sock.shutdown.side_effect=lambda how:p._read()
        with patch('cell.nb_engine_question.response',side_effect=ConnectionError('closed')):
            result=p.finish(cancel=True)
        self.assertTrue(result['cancelled']);self.assertTrue(result['complete'])
        self.sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        self.sock.shutdown.side_effect=None;p.close()
        self.thread.join.assert_called();self.sock.close.assert_called_once()

    def test_completed_request_cannot_pass_pending_witness_gate(self):
        p=self.pending();p.sent.set();p.done.set()
        with self.assertRaisesRegex(RuntimeError,'before pending witness'):p.wait_sent()
        p.close()

    def test_send_wait_has_own_ten_second_bound(self):
        p=self.pending();p.sent=Mock();p.sent.wait.return_value=False
        with patch('cell.nb_engine_question.time.monotonic',side_effect=[0,11]),self.assertRaises(TimeoutError):p.wait_sent()
        p.close()

    def test_surviving_thread_is_cleanup_failure_not_success(self):
        p=self.pending();self.thread.is_alive.return_value=True
        with self.assertRaisesRegex(RuntimeError,'survived cleanup'):p.close()
        self.sock.close.assert_called_once()

    def test_answer_sends_exact_allow_once_frame_and_closes(self):
        with patch('cell.nb_engine_question.answer_reply') as reply:
            value=answer(self.ctx,'/owned/admin.sock',9)
        reply.assert_called_once()
        self.assertEqual(value,{'path':'/owned/admin.sock','qid':9,'errno':0,'step':'sent'})
        self.sock.sendall.assert_called_once_with(answer_bytes(9))
        self.sock.shutdown.assert_called_once_with(socket.SHUT_WR);self.sock.close.assert_called_once()

    def test_send_failure_has_no_success_capture(self):
        self.sock.sendall.side_effect=BrokenPipeError(errno.EPIPE,'closed')
        value=answer(self.ctx,'/owned/admin.sock',9)
        self.assertEqual(value['errno'],errno.EPIPE);self.assertEqual(value['step'],'send')
        self.ctx.capture.assert_called_once_with('admin',b'');self.sock.close.assert_called_once()

    def test_socket_control_roundtrip_uses_same_answer_and_unlinks_owned_name(self):
        peer=MagicMock();peer.__enter__.return_value=peer;peer.recv.side_effect=[answer_bytes(1),b'']
        self.sock.accept.return_value=(peer,None)
        # answer() gets its own connection; the listener stays owned until finally.
        sending=MagicMock()
        with patch('cell.nb_engine_question.socket.socket',side_effect=[self.sock,sending]), \
             patch('cell.nb_engine_question.os.path.lexists',return_value=False), \
             patch('cell.nb_engine_question.os.unlink') as unlink:
            self.assertTrue(control(self.ctx))
        sending.sendall.assert_called_once_with(answer_bytes(1))
        self.sock.close.assert_called_once();sending.close.assert_called_once()
        unlink.assert_called_once_with('/work/nb-decoy-control')

    def test_control_accept_failure_still_closes_and_unlinks(self):
        self.sock.accept.side_effect=TimeoutError('no client')
        with patch('cell.nb_engine_question.answer',return_value={'errno':0}), \
             patch('cell.nb_engine_question.os.path.lexists',return_value=False), \
             patch('cell.nb_engine_question.os.unlink') as unlink,self.assertRaises(TimeoutError):control(self.ctx)
        self.sock.close.assert_called_once();unlink.assert_called_once()

    def test_control_existing_path_is_not_deleted(self):
        with patch('cell.nb_engine_question.os.path.lexists',return_value=True), \
             patch('cell.nb_engine_question.os.unlink') as unlink,self.assertRaises(FileExistsError):control(self.ctx)
        unlink.assert_not_called();self.sock.bind.assert_not_called()
