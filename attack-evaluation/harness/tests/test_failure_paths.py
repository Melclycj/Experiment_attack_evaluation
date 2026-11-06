"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import copy
import os
from pathlib import Path
import tempfile
import unittest

from cleanup import Resources
from fixtures import header, row, target
from judge import aggregate_attempts, aggregate_targets, finalize_pairing
from record import RunDirectory, validate_row
from summarize import history


class PairingFailureTests(unittest.TestCase):
    def test_every_repeat_needs_corresponding_peer(self):
        a, b = row(), row("undefended")
        second = copy.deepcopy(a["attempts"][0])
        second["repeat"] = 2
        a["attempts"].append(second)
        a.update(aggregate_attempts(a["attempts"], 2))
        # The undefended arm planned two attempts, but only produced the first.
        b.update(aggregate_attempts(b["attempts"], 2))
        got = finalize_pairing([a, b])[0]
        self.assertEqual(got["attempts"][0]["outcome"], "blocked")
        self.assertEqual(got["attempts"][1]["outcome"], "invalid")
        self.assertIsNone(got["upper_bound"])

    def test_verified_success_is_not_changed_by_missing_peer(self):
        got = finalize_pairing([row(branches=[target(effect=True)])])[0]
        self.assertEqual(got["outcome"], "succeeded")

    def test_duplicate_target_ids_rejected(self):
        bad = row(branches=[target("same"), target("same")])
        with self.assertRaises(ValueError):
            validate_row(bad)

    def test_duplicate_repetition_rejected(self):
        bad = row()
        bad["attempts"].append(copy.deepcopy(bad["attempts"][0]))
        with self.assertRaises(ValueError):
            validate_row(bad)

    def test_failed_control_with_candidate_effect_remains_visible(self):
        effect = target(effect=True, control_ok=False)
        self.assertTrue(effect["external_effect"])
        self.assertEqual(aggregate_targets([effect])[0], "invalid")

    def test_hidden_older_trials_still_report_nondeterminism(self):
        a, b, c = header(name="a"), header(name="b"), header(name="c")
        c["harness"] = {"different": "harness"}
        text = history([(a, [row()]), (b, [row(branches=[target(effect=True)])]), (c, [row()])])
        self.assertIn("全部见证", text)
        self.assertIn("a=预期机制挡住", text)
        self.assertIn("b=成功", text)

    def test_resummarize_does_not_modify_inputs(self):
        data = [(header(), [row()])]
        before = copy.deepcopy(data)
        history(data)
        self.assertEqual(data, before)

    def test_invalid_trial_cannot_create_confidence_bound(self):
        a = row(branches=[target(complete=False)])
        a["upper_bound"] = .95
        with self.assertRaises(ValueError):
            validate_row(a)


class CleanupFailureTests(unittest.TestCase):
    def test_engine_stop_error_retains_roots(self):
        class Group:
            created = True
            def kill_and_wait(self):
                pass
            def remove(self):
                self.created = False
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            keep = root / "keep"
            keep.write_text("do not delete")
            resources = Resources()
            info = root.stat()
            resources.roots[root] = (info.st_dev, info.st_ino)  # fake registered root for failure-path testing
            def broken_stop():
                raise RuntimeError("engine did not stop")
            result = resources.cleanup(stop_engine=broken_stop, cgroup=Group(), command=None,
                                       mountinfo=lambda: "", crash_check=lambda: None)
            self.assertFalse(result["ok"])
            self.assertTrue(keep.exists())
            self.assertEqual(result["retained"], [str(root)])

    def test_changed_mount_identity_is_not_unmounted(self):
        resources = Resources(top_mount_id=lambda _: 6)
        resources.mounts = [(Path("/etc/hosts"), 5)]
        commands = []
        result = resources.cleanup(stop_engine=lambda: None, cgroup=None,
                    command=lambda *a, **k: commands.append(a),
                    mountinfo=lambda: "6 1 8:1 / /etc/hosts rw - ext4 /dev/x rw\n", crash_check=lambda: None)
        self.assertFalse(result["ok"])
        self.assertEqual(commands, [])

    @unittest.skipUnless(os.name == "posix", "Linux mount path semantics")
    def test_stacked_hosts_bind_only_removes_our_visible_mount(self):
        original = "4 1 8:1 / /etc/hosts rw - ext4 /dev/x rw\n"
        owned = "5 1 8:1 / /etc/hosts rw - ext4 /dev/y rw\n"
        state = {"mounts": original + owned, "top": 5}
        resources = Resources(top_mount_id=lambda _: state["top"])
        resources.add_mount(Path("/etc/hosts"), state["mounts"])
        commands = []
        def command(argv, **kwargs):
            commands.append(argv)
            state.update(mounts=original, top=4)
        result = resources.cleanup(stop_engine=lambda: None, cgroup=None, command=command,
                                   mountinfo=lambda: state["mounts"], crash_check=lambda: None)
        self.assertTrue(result["ok"])
        self.assertEqual(commands, [["/usr/bin/umount", "/etc/hosts"]])
        self.assertEqual(state["mounts"], original)

    def test_crash_check_failure_is_not_clean_success(self):
        def crash():
            raise RuntimeError("new crash file")
        result = Resources().cleanup(stop_engine=lambda: None, cgroup=None, command=None,
                                     mountinfo=lambda: "", crash_check=crash)
        self.assertFalse(result["ok"])

    def test_bad_output_directory_not_used(self):
        with tempfile.TemporaryDirectory() as temp:
            for name in ("trial", "20261031T030000Z-../x", "20261031T030000Z-a/b"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    RunDirectory(Path(temp), name)

    @unittest.skipUnless(os.name == "posix", "Linux symlink test")
    def test_output_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = RunDirectory(root, "20261031T030000Z-test")
            (run.path / "escape").symlink_to(root / "elsewhere")
            with self.assertRaises(ValueError):
                run.write("safe.txt", b"content")


if __name__ == "__main__":
    unittest.main()
