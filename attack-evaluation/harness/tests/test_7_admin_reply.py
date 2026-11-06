"""这是 1.1 隔离论证的验证测试：NB-21 管理连接生命周期；所有 socket/fd 为 mock，不启动部署。"""
from contextlib import ExitStack
import errno
import importlib
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import Mock, patch
from cell import nb_engine_question as q
from nb_wire import frame

OK = frame(0x51, [b'\x43', b'\0' * 4])
QUESTION = frame(0x41, [(9).to_bytes(8, 'big')] + [b''] * 23)  # 24 fields since v4 (six host-file fields)


class Reply(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.ctx = Mock(); self.ctx.remaining.return_value = 3
        self.conn = Mock()
        self.stack.enter_context(patch.object(socket, 'AF_UNIX', 1, create=True))
        self.stack.enter_context(patch.object(socket, 'MSG_CTRUNC', 8, create=True))
        self.stack.enter_context(patch.object(q.socket, 'socket', return_value=self.conn))
        self.recv = self.stack.enter_context(patch.object(q.socket, 'recv_fds', create=True,
            return_value=(OK, [], 0, None)))
        self.close = self.stack.enter_context(patch.object(q.os, 'close'))

    def call(self):
        return q.answer(self.ctx, '/owned/admin.sock', 9)

    def test_one_answer_waits_for_reply_before_close(self):
        def receive(*args):
            self.conn.close.assert_not_called()
            return OK, [], 0, None
        self.recv.side_effect = receive
        result = self.call()
        self.recv.assert_called_once()
        self.conn.sendall.assert_called_once_with(q.answer_bytes(9))
        self.conn.close.assert_called_once()
        self.assertEqual(result['errno'], 0)

    def test_fragmented_question_and_ack_release_all_received_fds(self):
        raw = QUESTION + OK
        self.recv.side_effect = [(raw[:2], [91], 0, None), (raw[2:17], [], 0, None),
                                 (raw[17:], [92, 93], 0, None)]
        self.assertEqual(self.call()['errno'], 0)
        self.assertEqual(self.recv.call_count, 3)
        self.assertEqual([c.args[0] for c in self.close.call_args_list], [91, 92, 93])

    def test_withdrawal_push_may_precede_reply(self):
        self.recv.return_value = (frame(0x42, [(3).to_bytes(8, 'big'), b'\x01']) + OK, [], 0, None)
        self.call(); self.recv.assert_called_once()

    def test_eof_is_not_send_success(self):
        self.recv.return_value = (b'', [], 0, None)
        with self.assertRaises(ConnectionError): self.call()
        self.conn.close.assert_called_once()

    def test_truncated_frame_then_eof_is_not_success(self):
        self.recv.side_effect = [(OK[:-1], [], 0, None), (b'', [], 0, None)]
        with self.assertRaises(ConnectionError): self.call()

    def test_wrong_reply_verb_rejected(self):
        self.recv.return_value = (frame(0x51, [b'\x44', b'\0' * 4]), [], 0, None)
        with self.assertRaises(ValueError): self.call()

    def test_engine_error_is_quality_failure_not_blocked(self):
        self.recv.return_value = (frame(0x52, [b'\x43', b'\x05', b'unknown_question']), [], 0, None)
        with self.assertRaises(ValueError): self.call()

    def test_malformed_kinds_lengths_and_ack_payload_rejected(self):
        values = [b'\0' * 4, (65537).to_bytes(4, 'big'), frame(0x13, []),
                  frame(0x51, [b'\x43']), frame(0x51, [b'\x43', b'']),
                  frame(0x51, [b'\x43', b'\0' * 4, b'extra'])]
        for raw in values:
            self.recv.return_value = (raw, [], 0, None)
            with self.subTest(raw=raw), self.assertRaises(ValueError): self.call()

    def test_descriptor_truncation_closes_delivered_fds_and_rejects(self):
        self.recv.return_value = (OK, [91, 92], 8, None)
        with self.assertRaises(ValueError): self.call()
        self.assertEqual([c.args[0] for c in self.close.call_args_list], [91, 92])

    def test_one_fd_close_failure_still_releases_other_fds(self):
        self.recv.return_value = (OK, [91, 92], 0, None)
        self.close.side_effect = [OSError(errno.EBADF, 'bad fd'), None]
        with self.assertRaises(OSError): self.call()
        self.assertEqual([c.args[0] for c in self.close.call_args_list], [91, 92])

    def test_reply_arriving_after_deadline_is_rejected(self):
        clock = [0.0]
        def receive(*args):
            clock[0] = 4
            return OK, [91], 0, None
        self.recv.side_effect = receive
        with patch.object(q.time, 'monotonic', side_effect=lambda: clock[0]), self.assertRaises(TimeoutError):
            self.call()
        self.close.assert_called_once_with(91)

    def test_timeout_does_not_return_sent_success(self):
        self.recv.side_effect = TimeoutError('read deadline')
        with self.assertRaises(TimeoutError): self.call()
        self.conn.close.assert_called_once()

    def test_receive_budget_is_not_renewed_for_each_fragment(self):
        clock = [0.0]
        def receive(*args):
            clock[0] += 2
            return b'\0', [], 0, None
        self.recv.side_effect = receive
        with patch.object(q.time, 'monotonic', side_effect=lambda: clock[0]), self.assertRaises(TimeoutError):
            self.call()
        self.assertEqual(self.recv.call_count, 2)

    def test_push_flood_has_finite_aggregate_bound(self):
        self.recv.return_value = (QUESTION, [], 0, None)
        with patch.object(q.time, 'monotonic', return_value=0), self.assertRaises(ValueError): self.call()
        self.assertLessEqual(self.recv.call_count, 129)

    def test_connect_denial_keeps_original_file_view_diagnostic(self):
        self.conn.connect.side_effect = FileNotFoundError(errno.ENOENT, 'not visible')
        result = self.call()
        self.assertEqual((result['errno'], result['step']), (errno.ENOENT, 'connect'))
        self.recv.assert_not_called(); self.conn.close.assert_called_once()

    def test_transport_reset_is_quality_failure(self):
        self.recv.side_effect = ConnectionResetError(errno.ECONNRESET, 'reset')
        with self.assertRaises(ConnectionError): self.call()
        self.conn.close.assert_called_once()

    def test_control_send_only_mode_does_not_wait_for_a_nonprotocol_sink(self):
        result = q.answer(self.ctx, '/owned/control.sock', 1, wait_reply=False)
        self.assertEqual(result['errno'], 0); self.recv.assert_not_called()


@unittest.skipUnless(os.name == 'posix', 'production admin imports Linux modules; sockets remain mocked')
class ProductionSchedule(unittest.TestCase):
    def test_delayed_accept_pending_push_cannot_drop_unread_answer(self):
        source = Path(__file__).resolve().parents[6] / 'ExperimentLab/engine-v3'  # registered baseline v4
        for name in [n for n in sys.modules if n.split('.')[0] in ('engine', 'connector')]:
            del sys.modules[name]
        sys.path.insert(0, str(source))
        try:
            admin = importlib.import_module('engine.admin')
        finally:
            sys.path.pop(0)
        port = admin.AdminPort.__new__(admin.AdminPort)
        port.loop, port.listener, port.hook = Mock(), Mock(), Mock()
        port.hook.answer.return_value = (None, b'')  # engine-v3 hook.answer: (error name, reply note)
        port.clients, port.pending_questions, port.pending_fds = [], {9: QUESTION}, {9: 40}
        port.holds = {}  # v4: workspace holds, released when their connection closes (K-55)
        client, peer = Mock(), Mock()
        state = dict(closed=False, accepted=False, wire=b'')
        output = bytearray()
        client.close.side_effect = lambda: state.update(closed=True)
        client.sendall.side_effect = lambda data: state.update(wire=data)
        port.listener.accept.return_value = (peer, None)
        peer.recv.side_effect = lambda count: state['wire']
        def send(data):
            if state['closed']: raise BrokenPipeError(errno.EPIPE, 'peer already closed')
            output.extend(data)
        peer.sendall.side_effect = send
        # v4's admin port queues frames and sends with send/send_fds plus MSG_DONTWAIT, returning the count (K-28).
        peer.send.side_effect = lambda view, *flags: send(bytes(view)) or len(view)
        def push(sock, buffers, fds, *flags):
            data = b''.join(bytes(b) for b in buffers)
            send(data)
            return len(data)
        def drive():
            if not state['accepted']:
                state['accepted'] = True
                port._accept()
                if port.clients: port._readable(port.clients[0])
        def receive(*args):
            drive()
            data = bytes(output); output.clear()
            return data, [91], 0, None
        ctx = Mock(); ctx.remaining.return_value = 3
        with patch.object(q.socket, 'socket', return_value=client), \
             patch.object(q.socket, 'send_fds', side_effect=push), \
             patch.object(q.socket, 'recv_fds', side_effect=receive), patch.object(q.os, 'close'),              patch.object(admin.os, 'dup', side_effect=lambda fd: fd):
            q.answer(ctx, '/owned/admin.sock', 9)
            drive()  # old code closed before this schedule could deliver the push
        port.hook.answer.assert_called_once_with(9, 1)
        self.assertNotIn(9, port.pending_questions)
        self.assertTrue(state['closed'])
