"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from build import capacity, inventory, snapshot as source_snapshot, storage_reservation
from cleanup import Resources, beneath
from decoy_services import Journal, end_frame, observation
from decoys import changed, log_window, prefix_changed, snapshot, synchronization
from env import Deadline, check_namespaces, check_reserved_uids, mount_rows, process_stat
from safeio import atomic_write, read_beneath, relative_parts

MOUNTS = "1 0 8:1 / / rw - ext4 /dev/x rw\n2 1 0:1 / /proc rw - proc proc rw\n"


class InfrastructureTests(unittest.TestCase):
    def test_mountinfo_and_escaped_spaces(self):
        rows = mount_rows(MOUNTS + "3 1 8:2 / /tmp/a\\040b rw - btrfs /dev/y rw\n")
        self.assertEqual(rows[2]["target"], "/tmp/a b")

    def test_host_namespace_baseline_not_inside_pid_one(self):
        before = {k: f"{k}:[1]" for k in ("mnt", "pid", "net")}
        inside = {k: f"{k}:[2]" for k in before}
        check_namespaces(before, inside, MOUNTS)
        for kind in before:
            bad = dict(inside, **{kind: before[kind]})
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                check_namespaces(before, bad, MOUNTS)

    def test_mount_propagation_rejected(self):
        before = {k: f"{k}:[1]" for k in ("mnt", "pid", "net")}
        inside = {k: f"{k}:[2]" for k in before}
        with self.assertRaises(ValueError):
            check_namespaces(before, inside, MOUNTS.replace("rw - ext4", "rw shared:4 - ext4"))

    def test_process_name_with_parentheses(self):
        text = "123 (a tricky ) comm) S " + " ".join(["0"] * 18 + ["987"])
        self.assertEqual(process_stat(text), {"pid": 123, "comm": "a tricky ) comm", "state": "S", "start_time": 987})

    def test_reserved_uids_checks_whole_range_and_connector(self):
        check_reserved_uids(70000, 70100, [1000], [0, 1000])
        for accounts, procs in (([70050], []), ([], [70099]), ([70999], []), ([], [70999])):
            with self.subTest(accounts=accounts, procs=procs), self.assertRaises(ValueError):
                check_reserved_uids(70000, 70100, accounts, procs)

    def test_deadline_caps_and_expires(self):
        now = [10.0]
        clock = lambda: now[0]
        deadline = Deadline(30, clock)
        self.assertEqual(deadline.left(2), 2)
        now[0] = 40
        with self.assertRaises(TimeoutError):
            deadline.left()

    def test_capacity_ca_and_spare_control_uid(self):
        got = capacity(100)
        self.assertEqual(got["ca_count"], 101)
        self.assertEqual(got["spare_uid"], 70100)
        self.assertEqual(got["simultaneous_copies"], 3)
        for n in (0, 1000, 65537):
            with self.subTest(n=n), self.assertRaises(ValueError):
                capacity(n)

    def test_storage_reserves_three_live_rows(self):
        manifest = {"files": [{"type": "file", "size": 4097}, {"type": "directory", "size": 0}]}
        got = storage_reservation(manifest)
        self.assertEqual(got["max_reserved_nodes"], "9")
        self.assertEqual(int(got["max_reserved_bytes"]), 3 * (3 * 4096 + 8192))
        with self.assertRaises(ValueError):
            storage_reservation(manifest, 2)

    def test_source_snapshot_preserves_identity_and_untracked_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "engine"
            source.mkdir()
            (source / "one.py").write_bytes(b"one\r\n")
            (source / "not-in-git.py").write_bytes(b"untracked\n")
            (source / "runs").mkdir()
            (source / "runs/log.txt").write_bytes(b"excluded")
            (source / "__pycache__").mkdir()
            (source / "__pycache__/x.pyc").write_bytes(b"excluded")
            before = inventory(source)
            got = source_snapshot(source, root / "snapshot")
            self.assertEqual(got, before)
            self.assertEqual(len(got["files"]), 2)
            self.assertEqual((root / "snapshot/one.py").read_bytes(), b"one\r\n")
            # Restore write permission only on this test's copied files for Windows cleanup.
            for path in (root / "snapshot").iterdir():
                path.chmod(0o600)

    def test_snapshot_cannot_be_nested_in_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a").write_bytes(b"a")
            with self.assertRaises(ValueError):
                source_snapshot(root, root / "child")

    def test_relative_path_traversal(self):
        for name in ("../x", "/tmp/x", "a//b", "a/./b", "C:\\x", "a:b", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                relative_parts(name)

    def test_atomic_exclusive_write(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "file"
            atomic_write(path, b"a")
            with self.assertRaises(FileExistsError):
                atomic_write(path, b"b")
            self.assertEqual(path.read_bytes(), b"a")
            atomic_write(path, b"c", replace=True)
            self.assertEqual(path.read_bytes(), b"c")

    def test_changed_decoy_checks_identity(self):
        before = dict(verified=True, exists=True, dev=1, ino=2, sha256="a")
        self.assertFalse(changed(before, dict(before)))
        self.assertTrue(changed(before, dict(before, ino=3)))
        self.assertTrue(changed(before, dict(verified=True, exists=False)))
        with self.assertRaises(ValueError):
            changed(before, {})

    def test_audit_append_not_attack(self):
        self.assertFalse(prefix_changed(b"old\n", b"old\nnew\n"))
        self.assertTrue(prefix_changed(b"old\n", b"fake"))
        self.assertTrue(prefix_changed(b"old\n", b"old"))
        with self.assertRaises(ValueError):
            prefix_changed(b"", b"new")

    def test_sync_names_are_fresh_and_bound(self):
        a = synchronization("run", "engine", "NB-26", 1)
        b = synchronization("run", "engine", "NB-26", 1)
        self.assertNotEqual(a["ready"], b["ready"])
        self.assertIn("NB-26-r1", a["ready"])
        self.assertNotEqual(a["ready"], a["release"])

    def test_end_marker_is_not_a_success_or_marker_file(self):
        secret = "a" * 48
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            journal = Journal(path / "log.jsonl", path / "nb-decoy-marks", "attempt1", secret)
            try:
                journal.receive(b"attack", {"uid": 1000})
                journal.receive(end_frame(secret), {"uid": 0})
            finally:
                journal.close()
            files = list((path / "nb-decoy-marks").iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), b"attack")
            entries = [json.loads(x) for x in (path / "log.jsonl").read_text().splitlines()]
            self.assertEqual(len(log_window(entries, 0, secret, "attempt1")), 1)

    def test_prefix_or_fragment_of_end_marker_is_not_end(self):
        secret = "b" * 48
        for data in (end_frame(secret)[:-1], end_frame(secret) + b"payload"):
            got = observation(data, attempt="a", end_secret=secret, seq=0, peer={})
            self.assertEqual(got["kind"], "request")

    def test_missing_or_gapped_end_marker_invalidates_window(self):
        with self.assertRaises(ValueError):
            log_window([], 0, "end", "a")
        with self.assertRaises(ValueError):
            log_window([{"seq": 1, "kind": "end", "token": "end"}], 0, "end", "a")

    def test_old_attempt_excluded(self):
        entries = [{"seq": 0, "kind": "request", "attempt": "old"},
                   {"seq": 1, "kind": "request", "attempt": "new"},
                   {"seq": 2, "kind": "end", "token": "end"}]
        self.assertEqual([e["seq"] for e in log_window(entries, 1, "end", "new")], [1])

    def test_cleanup_prefix_is_component_aware(self):
        self.assertTrue(beneath("/tmp/nb-decoy-a/x", "/tmp/nb-decoy-a"))
        self.assertFalse(beneath("/tmp/nb-decoy-attacker", "/tmp/nb-decoy-a"))

    def test_cleanup_cgroup_failure_never_unmounts_or_removes(self):
        class BrokenGroup:
            created = True
            def kill_and_wait(self):
                raise RuntimeError("still populated")
        calls = []
        resources = Resources()
        resources.mounts = [(Path("/tmp/nb-decoy-x"), 4)]
        result = resources.cleanup(stop_engine=lambda: calls.append("stop"), cgroup=BrokenGroup(),
                                   command=lambda *a, **k: calls.append("command"), mountinfo=lambda: MOUNTS,
                                   crash_check=lambda: calls.append("crash"))
        self.assertFalse(result["ok"])
        self.assertEqual(calls, ["stop", "crash"])


@unittest.skipUnless(os.name == "posix", "Linux no-follow/openat contract")
class LinuxFileTests(unittest.TestCase):
    def test_capture_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "real").write_bytes(b"sentinel")
            (root / "link").symlink_to(root / "real")
            with self.assertRaises(OSError):
                read_beneath(root, "link")
            os.link(root / "real", root / "hard")
            with self.assertRaises(ValueError):
                read_beneath(root, "hard")

    def test_capture_rejects_parent_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "dir").mkdir()
            (root / "dir/file").write_bytes(b"ok")
            (root / "alias").symlink_to(root / "dir", target_is_directory=True)
            with self.assertRaises(OSError):
                read_beneath(root, "alias/file")
            os.mkfifo(root / "fifo")
            with self.assertRaises(ValueError):
                read_beneath(root, "fifo")

    def test_capture_bound_and_normal_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "file").write_bytes(b"abcd")
            self.assertEqual(read_beneath(root, "file", 4), b"abcd")
            with self.assertRaises(ValueError):
                read_beneath(root, "file", 3)

    def test_decoy_snapshot_identity_and_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "nb-decoy-file"
            path.write_bytes(b"original")
            before = snapshot(path)
            self.assertTrue(before["verified"])
            path.unlink()
            path.symlink_to("/does-not-exist")
            after = snapshot(path)
            self.assertTrue(changed(before, after))
            self.assertEqual(after["kind"], "nonregular")


if __name__ == "__main__":
    unittest.main()
