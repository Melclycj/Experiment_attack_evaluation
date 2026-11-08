"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from pathlib import Path
import signal
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from process_identity import ProcessRef


class ProcessIdentityTests(unittest.TestCase):
    def test_pidfd_snapshot_and_signal_never_use_numeric_pid_for_signal(self):
        info = {"pid": 123, "start_time": 888, "uids": [1000] * 4, "state": "S",
                "cgroup": "0::/nb-decoy-test\n", "argv": ["/fixture"]}
        group = SimpleNamespace(path=Path("/sys/fs/cgroup/nb-decoy-test"))
        with patch("process_identity.process_info", return_value=info), \
                patch("process_identity.os.pidfd_open", create=True, return_value=99), \
                patch("process_identity.select.poll", return_value=SimpleNamespace(register=lambda *a: None, poll=lambda t: [])), \
                patch("process_identity.os.close") as close, \
                patch("process_identity.signal.pidfd_send_signal", create=True) as send:
            ref = ProcessRef(123, 1000, group)
            ref.send(signal.SIGTERM)
            send.assert_called_once_with(99, signal.SIGTERM)
            self.assertEqual(ref.read()["start_time"], 888)
            ref.close()
            ref.close()
            close.assert_called_once_with(99)

    def test_recycled_pid_or_changed_uid_closes_fd(self):
        info = {"pid": 123, "start_time": 888, "uids": [1000] * 4, "state": "S",
                "cgroup": "0::/nb-decoy-test\n", "argv": []}
        for updated in ({**info, "start_time": 889}, {**info, "uids": [70999] * 4}):
            with patch("process_identity.process_info", side_effect=[info, updated]), \
                    patch("process_identity.os.pidfd_open", create=True, return_value=99), \
                    patch("process_identity.select.poll", return_value=SimpleNamespace(register=lambda *a: None, poll=lambda t: [])), \
                    patch("process_identity.os.close") as close, self.assertRaises(RuntimeError):
                ProcessRef(123, 1000, SimpleNamespace(path=Path("/sys/fs/cgroup/nb-decoy-test")))
            close.assert_called_once_with(99)

    def test_foreign_group_and_stopped_processes_rejected_before_pidfd(self):
        base = {"pid": 123, "start_time": 888, "uids": [1000] * 4, "state": "S", "cgroup": "0::/other\n"}
        for info in (base, {**base, "cgroup": "0::/nb-decoy-test\n", "state": "T"}):
            with patch("process_identity.process_info", return_value=info), \
                    patch("process_identity.os.pidfd_open", create=True) as pin, self.assertRaises(RuntimeError):
                ProcessRef(123, 1000, SimpleNamespace(path=Path("/sys/fs/cgroup/nb-decoy-test")))
            pin.assert_not_called()
