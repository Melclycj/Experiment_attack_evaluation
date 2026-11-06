"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import selectors
import tempfile
import unittest
from unittest.mock import Mock, patch

from commands import Commands, ManagedProcess
from env import Deadline


@unittest.skipUnless(os.name == "posix", "Linux anonymous pipe selector; no processes launched")
class InteractivePipeTests(unittest.TestCase):
    def make(self):
        manager = Commands(Mock(created=False), Deadline(10))
        read, write = os.pipe()
        os.set_blocking(write, False)
        proc = Mock(stdin=os.fdopen(write, "wb", buffering=0))
        proc.poll.return_value = None
        child = ManagedProcess(proc, None, {}, manager.deadline.end)
        child.input_open = True
        child.streams = 0
        manager.children.append(child)
        self.addCleanup(os.close, read)
        def finish():
            proc.poll.return_value = 0
            manager.close()
        self.addCleanup(finish)
        return manager, child, read

    def test_partial_writes_are_drained_without_logging_input(self):
        manager, child, read = self.make()
        original = os.write
        with patch("commands.os.write", side_effect=lambda fd, data: original(fd, data[:2])):
            manager.send_input(child, b"secret\n")
        self.assertEqual(os.read(read, 100), b"secret\n")
        self.assertNotIn("secret", str(child.item))
        manager.close_input(child)
        self.assertEqual(os.read(read, 1), b"")

    def test_overlarge_input_rejected_before_write(self):
        manager, child, _ = self.make()
        with self.assertRaises(ValueError):
            manager.send_input(child, b"a" * 65537)
        child.input_total = 1048576
        with self.assertRaises(ValueError):
            manager.send_input(child, b"a")

    def test_input_to_exited_child_fails(self):
        manager, child, _ = self.make()
        child.proc.poll.return_value = 1
        with self.assertRaises(BrokenPipeError):
            manager.send_input(child, b"x")

    def test_stuck_input_times_out_and_aborts(self):
        manager, child, _ = self.make()
        with patch.object(manager, "pump"), patch.object(manager, "abort") as abort, \
                patch("commands.time.monotonic", side_effect=[0, 9]), self.assertRaises(TimeoutError):
            manager.send_input(child, b"x", timeout=1)
        abort.assert_called_once()

    def test_input_eof_closes_and_unregisters_pending_fd(self):
        manager, child, read = self.make()
        manager.selector.register(child.proc.stdin, selectors.EVENT_WRITE, (child, "stdin"))
        child.input_pending.extend(b"pending")
        manager.close_input(child)
        manager.close_input(child)
        self.assertFalse(child.input_open)
        self.assertEqual(os.read(read, 1), b"")
        self.assertFalse(child.input_pending)

    def test_start_interactive_preserves_join_handshake(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "ordinary-file"
            p.write_bytes(b"")
            member, pidfd = os.open(p, os.O_WRONLY), os.open(p, os.O_RDONLY)
            manager = Commands(Mock(created=False), Deadline(10))
            input_reader = []
            def popen(argv, **kw):
                self.assertEqual(kw["stdin"], -1)  # subprocess.PIPE
                os.write(int(argv[5]), b"J")
                proc = Mock(pid=9001)
                proc.poll.return_value = None
                r, w = os.pipe()
                input_reader.append(r)
                proc.stdin = os.fdopen(w, "wb", buffering=0)
                for name in ("stdout", "stderr"):
                    r, w = os.pipe()
                    os.close(w)
                    setattr(proc, name, os.fdopen(r, "rb"))
                return proc
            try:
                with patch.object(manager, "_membership_fd", return_value=member), \
                        patch("commands.os.pidfd_open", return_value=pidfd), \
                        patch("commands.subprocess.Popen", side_effect=popen):
                    child = manager.start(["/fixture/not-executed"], interactive=True)
                    manager.send_input(child, b"fixture")
                    self.assertEqual(os.read(input_reader[0], 100), b"fixture")
                    manager.close_input(child)
                    child.proc.poll.return_value = 0
                    manager.wait(child)
            finally:
                manager.close()
                for fd in input_reader:
                    os.close(fd)
