"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from run_rows import Row


class AttachReadinessTests(unittest.TestCase):
    def fixture(self):
        rt = SimpleNamespace(command=Mock(), cap={'first': 70000, 'last': 70010},
            deployment=SimpleNamespace(root=Path('/var/lib/nb-decoy-offline'), admin=Mock(), engine=Mock()))
        rt.command.deadline.left.side_effect = lambda limit: limit
        rt.deployment.engine.proc.poll.return_value = None
        row = Row(rt, 'engine', 'work0', 'offline', 30)
        row.execution, row.uid = 'test:5', 70004
        rt.deployment.admin.rows.return_value = self.status('ACTIVE')
        return rt, row

    def status(self, state, uid=70004):
        return f'execution=test:5 workspace=work0 state={state} uid={uid}\n'

    def socket(self, *, uid=1000, mode=stat.S_IFSOCK | 0o600):
        return SimpleNamespace(st_uid=uid, st_mode=mode)

    def test_preparing_then_active_then_socket_ready(self):
        rt, row = self.fixture()
        rt.deployment.admin.rows.side_effect = [self.status('PREPARING'), self.status('ACTIVE'), self.status('ACTIVE')]
        with patch('run_rows.Path.lstat', side_effect=[FileNotFoundError(), self.socket()]), \
             patch('run_rows.plain_path'):
            stream = row.attach()
        self.assertIs(stream, rt.deployment.admin.attach.return_value)
        self.assertEqual(rt.deployment.admin.rows.call_count, 3)
        rt.deployment.admin.attach.assert_called_once_with('test:5', timeout=30)
        self.assertGreaterEqual(rt.command.pump.call_count, 3)

    def test_row_disappeared_does_not_launch_attach(self):
        rt, row = self.fixture()
        rt.deployment.admin.rows.return_value = '(none)'
        with self.assertRaisesRegex(RuntimeError, 'disappeared'):
            row.attach()
        rt.deployment.admin.attach.assert_not_called()

    def test_wrong_uid_does_not_launch_attach(self):
        rt, row = self.fixture()
        rt.deployment.admin.rows.return_value = self.status('ACTIVE', 70005)
        with self.assertRaisesRegex(ValueError, 'uid changed'):
            row.attach()
        rt.deployment.admin.attach.assert_not_called()

    def test_wrong_endpoint_owner_type_or_mode_rejected(self):
        for value in (self.socket(uid=70004), self.socket(mode=stat.S_IFREG | 0o600),
                      self.socket(mode=stat.S_IFSOCK | 0o666)):
            with self.subTest(value=value):
                rt, row = self.fixture()
                with patch('run_rows.Path.lstat', return_value=value), patch('run_rows.plain_path'):
                    with self.assertRaisesRegex(ValueError, 'endpoint'):
                        row.attach()
                rt.deployment.admin.attach.assert_not_called()

    def test_expired_attempt_never_launches_attach(self):
        rt, row = self.fixture()
        rt.command.deadline.left.side_effect = TimeoutError('attempt deadline')
        with self.assertRaises(TimeoutError):
            row.attach()
        rt.deployment.admin.attach.assert_not_called()

    def test_stopping_row_does_not_launch_attach(self):
        rt, row = self.fixture()
        rt.deployment.admin.rows.return_value = self.status('STOPPING')
        with self.assertRaisesRegex(RuntimeError, 'not attachable'):
            row.attach()
        rt.deployment.admin.attach.assert_not_called()

    def test_same_attempt_budget_bounds_client(self):
        rt, row = self.fixture()
        rt.command.deadline.left.side_effect = [4.0, 2.5]
        with patch('run_rows.Path.lstat', return_value=self.socket()), patch('run_rows.plain_path'):
            row.attach()
        rt.deployment.admin.attach.assert_called_once_with('test:5', timeout=2.5)
