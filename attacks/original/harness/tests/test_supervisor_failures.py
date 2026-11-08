"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from commands import Commands, ManagedProcess
from env import Deadline
from launch import await_release, verify_child, verify_inside
from common import identity


class LaunchFailureTests(unittest.TestCase):
    def test_no_outer_release_means_no_progress(self):
        with patch("launch.select.select", return_value=([], [], [])), patch("launch.os.read") as read:
            with self.assertRaises(RuntimeError):
                await_release(8)
            read.assert_not_called()

    def test_closed_or_wrong_release_is_not_permission(self):
        for value in (b"", b"NO", b"GG"):
            with self.subTest(value=value), patch("launch.select.select", return_value=([8], [], [])), \
                    patch("launch.os.read", return_value=value):
                with self.assertRaises(RuntimeError):
                    await_release(8)

    def test_verified_release(self):
        with patch("launch.select.select", return_value=([8], [], [])), patch("launch.os.read", return_value=b"G"):
            await_release(8)

    def test_inner_checks_real_kernel_namespace_fds_and_entry_bytes(self):
        before = {k: f"{k}:[1]" for k in ("mnt", "net", "pid")}
        after = {k: f"{k}:[2]" for k in before}
        boot = {"host": {"namespaces": before}, "namespace_fds": dict(mnt=10, net=11, pid=12),
                "entry": "/fake/run.py", "entry_identity": identity(b"frozen")}
        mounts = "1 0 8:1 / / rw - ext4 /dev/x rw\n2 1 0:1 / /proc rw - proc proc rw\n"
        with patch("launch.os.geteuid", return_value=0, create=True), patch("launch.os.getpid", return_value=1), \
                patch("launch.os.readlink", side_effect=lambda p: {"10": "mnt:[1]", "11": "net:[1]", "12": "pid:[1]"}[p.rsplit('/', 1)[1]]), \
                patch("launch.namespaces", return_value=after), patch.object(Path, "read_text", return_value=mounts), \
                patch("launch.read_owned", return_value=b"frozen"):
            self.assertEqual(verify_inside(boot), after)
            boot["entry_identity"] = identity(b"changed")
            with self.assertRaisesRegex(RuntimeError, "changed"):
                verify_inside(boot)

    def test_parent_accepts_actual_child_namespace_identity(self):
        before = {k: f"{k}:[1]" for k in ("mnt", "net", "pid")}
        after = {k: f"{k}:[2]" for k in before}
        report = {"pid": 123, "namespaces": after}
        fake_stat = "123 (worker) S " + " ".join(["0"] * 18 + ["987"])
        read = lambda p: "PPid:\t456\n" if p.name == "status" else fake_stat
        with patch("launch.os.pidfd_open", return_value=20, create=True), \
                patch.object(Path, "read_text", new=read), \
                patch("launch.os.readlink", side_effect=lambda p: after[p.name]), patch("launch.os.close") as close:
            self.assertEqual(verify_child(report, 456, before), 20)
            close.assert_not_called()
            bad_report = dict(report, namespaces=dict(after, net="net:[3]"))
            with self.assertRaises(RuntimeError):
                verify_child(bad_report, 456, before)
            close.assert_called_once_with(20)


class CommandRecoveryTests(unittest.TestCase):
    def make(self):
        manager = Commands(Mock(created=True), Deadline(10))
        self.addCleanup(manager.selector.close)
        kill_patch = patch("commands.signal.SIGKILL", 9, create=True)
        kill_patch.start()
        self.addCleanup(kill_patch.stop)
        children = []
        for pid in (123, 124):
            proc = Mock()
            proc.poll.return_value = None
            child = ManagedProcess(proc, pid, {"argv": ["/fake"]}, float("inf"))
            children.append(child)
        manager.children = children
        return manager, children

    def test_failed_signal_still_kills_cgroup_and_reaps_all(self):
        manager, children = self.make()
        with patch.object(manager, "send_signal", side_effect=[PermissionError("fixture"), None]) as send:
            with self.assertRaisesRegex(RuntimeError, "recovery incomplete"):
                manager.abort()
            self.assertEqual(send.call_count, 2)
        manager.cgroup.kill_and_wait.assert_called_once()
        for child in children:
            child.proc.wait.assert_called_once()

    def test_failed_reap_still_attempts_remaining_children(self):
        manager, children = self.make()
        children[0].proc.wait.side_effect = TimeoutError("fixture")
        with patch.object(manager, "send_signal"), self.assertRaises(RuntimeError):
            manager.abort()
        children[1].proc.wait.assert_called_once()

    def test_wait_rejects_foreign_process(self):
        manager, _ = self.make()
        with self.assertRaises(ValueError):
            manager.wait(Mock())

    def test_all_live_output_pipes_are_drained_in_same_pump(self):
        manager, children = self.make()
        keys = [SimpleNamespace(fileobj=Mock(), data=(child, "stdout")) for child in children]
        with patch.object(manager.selector, "select", return_value=[(key, 1) for key in keys]), \
                patch("commands.os.read", side_effect=[b"one", b"two"]):
            manager.pump(0)
        self.assertEqual([bytes(c.buffers["stdout"]) for c in children], [b"one", b"two"])
        self.assertEqual(manager.budget.used, 6)

    def test_eof_closes_pipe_and_updates_count(self):
        manager, children = self.make()
        stream = Mock()
        key = SimpleNamespace(fileobj=stream, data=(children[0], "stdout"))
        with patch.object(manager.selector, "select", return_value=[(key, 1)]), \
                patch.object(manager.selector, "unregister") as unregister, patch("commands.os.read", return_value=b""):
            manager.pump(0)
        unregister.assert_called_once_with(stream)
        stream.close.assert_called_once()
        self.assertEqual(children[0].streams, 1)

    def test_global_deadline_not_just_per_child_deadline(self):
        manager, _ = self.make()
        manager.deadline = Mock()
        manager.deadline.left.side_effect = TimeoutError("batch time exhausted")
        with patch.object(manager, "send_signal"), self.assertRaises(TimeoutError):
            manager.pump(0)
        manager.cgroup.kill_and_wait.assert_called_once()

    def test_closing_releases_pidfds_and_selector_after_abort_error(self):
        manager, children = self.make()
        with patch.object(manager, "abort", side_effect=RuntimeError("fixture")), \
                patch("commands.os.close") as close, self.assertRaises(RuntimeError):
            manager.close()
        self.assertEqual([c.args[0] for c in close.call_args_list], [123, 124])
        self.assertTrue(all(c.pidfd is None for c in children))
