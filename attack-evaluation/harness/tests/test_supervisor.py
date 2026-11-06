"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from commands import BASE_ENV, CaptureBudget, Commands, ManagedProcess, command_argv
from env import Deadline
from host import compare_crashes, crash_inventory, host_process_uids, socket_metadata, status_uids
from launch import read_boot, sealed_boot, unshare_argv, verify_child, verify_inside
from process_child import enter_and_exec, main


class ArgumentTests(unittest.TestCase):
    def test_no_shell_strings_or_relative_executable(self):
        for argv in ("echo hi", [], ["echo", "hi"], ["/bin/echo", "a\0b"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                command_argv(argv)

    def test_argv_preserves_spaces_and_metacharacters_as_data(self):
        self.assertEqual(command_argv(["/bin/echo", "a b; touch x"]), ["/bin/echo", "a b; touch x"])

    def test_argument_bound(self):
        with self.assertRaises(ValueError):
            command_argv(["/bin/echo", "x" * 65536])

    def test_global_budget_includes_multiple_children(self):
        budget = CaptureBudget(5)
        budget.consume(b"123")
        budget.consume(b"45")
        with self.assertRaises(ValueError):
            budget.consume(b"6")
        self.assertEqual(budget.used, 5)

    def test_base_environment_does_not_inherit_secrets(self):
        self.assertEqual(set(BASE_ENV), {"PATH", "LC_ALL", "HOME"})

    def test_budget_cannot_be_disabled(self):
        for value in (0, -1, 20 * 1024 * 1024):
            with self.assertRaises(ValueError):
                CaptureBudget(value)


class TrampolineTests(unittest.TestCase):
    def test_join_and_close_before_exec(self):
        events = []
        with patch("process_child.os.getpid", return_value=123), \
                patch("process_child.os.write", side_effect=lambda fd, b: events.append(("write", fd, b)) or len(b)), \
                patch("process_child.os.close", side_effect=lambda fd: events.append(("close", fd))), \
                patch("process_child.os.execve", side_effect=lambda *args: events.append(("exec", args[0]))):
            enter_and_exec(10, 11, ["/bin/true"])
        self.assertEqual(events, [("write", 10, b"123"), ("close", 10), ("write", 11, b"J"),
                                  ("close", 11), ("exec", "/bin/true")])

    def test_failed_join_never_acknowledges_or_executes(self):
        with patch("process_child.os.write", side_effect=PermissionError), patch("process_child.os.execve") as execute:
            with self.assertRaises(PermissionError):
                enter_and_exec(10, 11, ["/bin/true"])
            execute.assert_not_called()

    def test_short_join_write_never_executes(self):
        with patch("process_child.os.getpid", return_value=123), patch("process_child.os.write", return_value=1), \
                patch("process_child.os.execve") as execute:
            with self.assertRaises(RuntimeError):
                enter_and_exec(10, 11, ["/bin/true"])
            execute.assert_not_called()

    def test_bad_cli_fails_before_execution(self):
        with self.assertRaises(ValueError):
            main(["10", "11", "/bin/true"])

    def test_exec_failure_has_nonzero_exit(self):
        with patch("process_child.enter_and_exec", side_effect=OSError("test")), patch("builtins.print"):
            self.assertEqual(main(["10", "11", "--", "/missing"]), 126)


class HostTests(unittest.TestCase):
    def test_all_four_uid_fields(self):
        self.assertEqual(status_uids("Name:\tfixture\nUid:\t1\t2\t3\t4\n"), [1, 2, 3, 4])
        with self.assertRaises(ValueError):
            status_uids("Uid: 1 2 3\n")

    def test_host_scan_includes_threads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for tid, ids in (("100", "0 0 0 0"), ("101", "1000 70005 1000 1000")):
                path = root / "100/task" / tid
                path.mkdir(parents=True)
                (path / "status").write_text("Uid: " + ids + "\n")
            (root / "self").mkdir()
            self.assertEqual(host_process_uids(root), [0, 1000, 70005])

    def test_disappeared_task_is_not_permission_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "100/task/100").mkdir(parents=True)
            self.assertEqual(host_process_uids(root), [])
            with patch.object(Path, "read_text", side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    host_process_uids(root)

    def test_socket_check_only_reads_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nb-decoy-socket"
            self.assertFalse(socket_metadata(path)["exists"])
            path.write_bytes(b"not a socket")
            value = socket_metadata(path)
            self.assertTrue(value["exists"])
            self.assertFalse(value["socket"])

    def test_crash_check_detects_new_and_changed_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            before = crash_inventory(root)
            (root / "new.dmp").write_bytes(b"fixture")
            with self.assertRaises(RuntimeError):
                compare_crashes(before, crash_inventory(root))
            before = crash_inventory(root)
            (root / "new.dmp").write_bytes(b"changed fixture")
            with self.assertRaises(RuntimeError):
                compare_crashes(before, crash_inventory(root))

    def test_missing_crash_directory_is_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            value = crash_inventory(Path(temp) / "absent")
            self.assertEqual(value, {"exists": False, "entries": {}})
            self.assertEqual(compare_crashes(value, value), {"new": [], "changed": []})


class NamespaceTests(unittest.TestCase):
    def test_launch_always_has_three_namespaces_new_proc_private_propagation(self):
        argv = unshare_argv(10, 11)
        for flag in ("--mount", "--net", "--pid", "--fork", "--mount-proc", "--kill-child=KILL"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--propagation") + 1], "private")
        self.assertEqual(argv[-3:], ["--inside", "10", "11"])

    @unittest.skipUnless(hasattr(os, "memfd_create"), "Linux sealed memfd")
    def test_boot_cannot_be_changed_after_creation(self):
        fd = sealed_boot({"test": "fixture"})
        try:
            self.assertEqual(read_boot(fd), {"test": "fixture"})
            with self.assertRaises(OSError):
                os.pwrite(fd, b"x", 0)
        finally:
            os.close(fd)

    @unittest.skipUnless(hasattr(os, "memfd_create"), "Linux sealed memfd")
    def test_unsealed_context_rejected(self):
        fd = os.memfd_create("nb-unit", os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, b"{}")
            with self.assertRaises(RuntimeError):
                read_boot(fd)
        finally:
            os.close(fd)

    def test_child_cannot_supply_fake_host_namespace_values(self):
        boot = {"host": {"namespaces": {"mnt": "mnt:[1]"}}, "namespace_fds": {"mnt": 10}}
        with patch("launch.os.geteuid", return_value=0, create=True), \
                patch("launch.os.getpid", return_value=1), patch("launch.os.readlink", return_value="mnt:[2]"):
            with self.assertRaisesRegex(RuntimeError, "reference"):
                verify_inside(boot)

    def test_inner_refuses_non_pid_one(self):
        with patch("launch.os.geteuid", return_value=0, create=True), patch("launch.os.getpid", return_value=5):
            with self.assertRaises(RuntimeError):
                verify_inside({})

    def test_parent_rejects_unrelated_child_and_closes_pidfd(self):
        with patch("launch.os.pidfd_open", return_value=20, create=True), \
                patch.object(Path, "read_text", return_value="PPid:\t999\n"), patch("launch.os.close") as close:
            with self.assertRaises(RuntimeError):
                verify_child({"pid": 123}, 456, {})
            close.assert_called_once_with(20)


class CommandLifecycleTests(unittest.TestCase):
    def make(self):
        kill_patch = patch("commands.signal.SIGKILL", 9, create=True)
        kill_patch.start()
        self.addCleanup(kill_patch.stop)
        group = Mock(created=True)
        manager = Commands(group, Deadline(10))
        self.addCleanup(manager.selector.close)
        proc = Mock()
        proc.poll.return_value = None
        item = {"argv": ["/test"], "exit_code": None}
        child = ManagedProcess(proc, 123, item, float("inf"))
        manager.children.append(child)
        return manager, child, group

    def test_timeout_kills_entire_cgroup_and_reaps(self):
        manager, child, group = self.make()
        child.end = -1
        with patch.object(manager, "send_signal") as send:
            with self.assertRaises(TimeoutError):
                manager.pump(0)
            send.assert_called_once()
        group.kill_and_wait.assert_called_once_with(timeout=5)
        child.proc.wait.assert_called_once_with(timeout=5)
        self.assertTrue(manager.failed)

    def test_output_overflow_aborts_not_truncates_success(self):
        manager, child, group = self.make()
        manager.budget = CaptureBudget(2)
        stream = Mock()
        key = SimpleNamespace(fileobj=stream, data=(child, "stdout"))
        with patch.object(manager.selector, "select", return_value=[(key, 1)]), \
                patch("commands.os.read", return_value=b"123"), patch.object(manager, "send_signal"):
            with self.assertRaises(ValueError):
                manager.pump(0)
        group.kill_and_wait.assert_called_once()

    def test_wait_pumps_background_children_too(self):
        manager, child, _ = self.make()
        child.proc.poll.return_value = 0
        child.streams = 0
        self.assertEqual(manager.wait(child)["exit_code"], 0)

    def test_disallowed_exit_not_reported_as_success(self):
        manager, child, _ = self.make()
        child.proc.poll.return_value = 126
        child.streams = 0
        with self.assertRaises(RuntimeError):
            manager.wait(child)

    def test_unowned_process_cannot_be_signalled(self):
        manager, _, _ = self.make()
        with self.assertRaises(ValueError):
            manager.send_signal(object(), 9)

    def test_abort_does_not_skip_reap_when_cgroup_cleanup_fails(self):
        manager, child, group = self.make()
        group.kill_and_wait.side_effect = RuntimeError("fixture failure")
        with patch.object(manager, "send_signal"), self.assertRaises(RuntimeError):
            manager.abort()
        child.proc.wait.assert_called_once()
