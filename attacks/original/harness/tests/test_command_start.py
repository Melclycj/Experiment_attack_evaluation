"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from commands import Commands
from env import Deadline


@unittest.skipUnless(os.name == "posix", "Linux pipe selector; Popen remains mocked")
class StartProtocolTests(unittest.TestCase):
    def exercise(self, ack=b"J", *, fail_exec=False):
        with tempfile.TemporaryDirectory() as temp:
            fake_procs = Path(temp) / "cgroup.procs.fixture"
            fake_procs.write_bytes(b"")
            # These are ordinary temporary-file descriptors, NOT kernel cgroups.
            membership = os.open(fake_procs, os.O_WRONLY)
            pidfd = os.open(fake_procs, os.O_RDONLY)
            manager = Commands(Mock(created=False), Deadline(10))
            launched = []

            def popen(argv, **kwargs):
                launched.append((argv, kwargs))
                self.assertEqual(argv[:3], ["/usr/bin/python3", "-I", "-B"])
                self.assertTrue(argv[3].endswith("process_child.py"))
                group_fd, ready_fd = map(int, argv[4:6])
                self.assertEqual(kwargs["pass_fds"], (group_fd, ready_fd))
                self.assertEqual(group_fd, membership)
                if fail_exec:
                    raise OSError("Popen fixture failure")
                os.write(ready_fd, ack)
                proc = Mock(pid=999999)
                proc.poll.return_value = 0
                proc.wait.return_value = 0
                # Only local anonymous pipes, closed at the writer immediately.
                for name in ("stdout", "stderr"):
                    read, write = os.pipe()
                    os.close(write)
                    setattr(proc, name, os.fdopen(read, "rb"))
                return proc

            try:
                with patch.object(manager, "_membership_fd", return_value=membership), \
                        patch("commands.os.pidfd_open", return_value=pidfd), \
                        patch("commands.subprocess.Popen", side_effect=popen), \
                        patch.dict(os.environ, {"SECRET_TEST_VALUE": "must-not-inherit"}):
                    if ack != b"J" or fail_exec:
                        with self.assertRaises((OSError, RuntimeError)):
                            manager.start(["/fake/target", "literal;data"], env={"EXPLICIT": "fixture"})
                    else:
                        child = manager.start(["/fake/target", "literal;data"], env={"EXPLICIT": "fixture"})
                        self.assertTrue(child.joined)
                        self.assertEqual(manager.wait(child)["exit_code"], 0)
                        self.assertTrue(manager.records[0]["joined"])
                kwargs = launched[0][1]
                self.assertNotIn("SECRET_TEST_VALUE", kwargs["env"])
                self.assertEqual(kwargs["env"]["EXPLICIT"], "fixture")
                self.assertTrue(kwargs["close_fds"])
                self.assertTrue(kwargs["start_new_session"])
                self.assertNotIn("preexec_fn", kwargs)
                self.assertNotIn("shell", kwargs)
                with self.assertRaises(OSError):
                    os.fstat(membership)  # launch closed its cgroup fd
            finally:
                manager.close()
                if fail_exec:
                    os.close(pidfd)  # fake pidfd_open was never called

    def test_target_is_launched_only_via_membership_trampoline(self):
        self.exercise()

    def test_missing_acknowledgement_aborts(self):
        self.exercise(ack=b"")

    def test_wrong_acknowledgement_aborts(self):
        self.exercise(ack=b"N")

    def test_popen_failure_closes_membership_and_pipes(self):
        self.exercise(fail_exec=True)
