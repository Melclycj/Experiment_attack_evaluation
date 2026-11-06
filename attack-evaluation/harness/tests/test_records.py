"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import copy
from pathlib import Path
import tempfile
import unittest

from common import identity, run_name, timestamp
from fixtures import header, row, target
from record import RunDirectory, formal_status, load_run, validate_row
from summarize import history, render_results


class RecordTests(unittest.TestCase):
    def test_utc_required(self):
        for value in ("2026-10-31T01:00:00", "2026-10-31T01:00:00+11:00"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                timestamp(value)
        self.assertEqual(run_name("test", "2026-10-31T03:00:00Z"), "20261031T030000Z-test")

    def test_formal_needs_all_evidence(self):
        self.assertFalse(formal_status(header()))
        good = header(baseline="v2")
        self.assertTrue(formal_status(good))
        for path, value in ((["engine", "baseline_files"], {}), (["engine", "baseline_check", "executed"], False),
                            (["engine", "baseline_check", "exit_code"], 1), (["host", "kernel_match"], False),
                            (["host", "readings_match"], None), (["engine", "baseline_check", "version"], "v1")):
            changed = copy.deepcopy(good)
            here = changed
            for key in path[:-1]:
                here = here[key]
            here[path[-1]] = value
            with self.subTest(path=path):
                self.assertFalse(formal_status(changed))

    def test_result_validation(self):
        validate_row(row())
        for field, value in (("successes", 1), ("repeats", True), ("outcome", "allowed"),
                             ("config", "../escape"), ("upper_bound", .8), ("script", {})):
            changed = row()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_row(changed)

    def test_false_aggregate_rejected(self):
        value = row()
        value["attempts"][0]["targets"] = []
        with self.assertRaises(ValueError):
            validate_row(value)

    def test_round_trip_and_final_pairing(self):
        with tempfile.TemporaryDirectory() as temp:
            run = RunDirectory(Path(temp), "20261031T030000Z-test")
            final = run.finalize(header(), [row(), row("undefended")])
            h, rows = load_run(run.path)
            self.assertFalse(h["formal"])
            self.assertEqual(rows, final)
            self.assertIn("试跑，不算数", (run.path / "README.md").read_text(encoding="utf-8"))
            self.assertLess(run.size(), 10 * 1024 * 1024)
            with self.assertRaises(RuntimeError):
                run.write("extra.txt", b"no")

    def test_cannot_force_formal(self):
        with tempfile.TemporaryDirectory() as temp:
            run = RunDirectory(Path(temp), "20261031T030000Z-test")
            run.finalize(header(formal=True), [row()])
            h, rows = load_run(run.path)
            self.assertFalse(h["formal"])
            self.assertEqual(rows[0]["outcome"], "invalid")

    def test_flat_names_and_exclusive_runs(self):
        with tempfile.TemporaryDirectory() as temp:
            run = RunDirectory(Path(temp), "20261031T030000Z-test")
            for name in ("../x", "sub/x", "a\\b", "/tmp/x", "x:y", ".hidden"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    run.write(name, b"x")
            with self.assertRaises(FileExistsError):
                RunDirectory(Path(temp), run.path.name)

    def test_output_budget_is_enforced_before_write(self):
        with tempfile.TemporaryDirectory() as temp:
            run = RunDirectory(Path(temp), "20261031T030000Z-test", limit=10)
            run.write("one.txt", b"12345")
            with self.assertRaises(ValueError):
                run.write("two.txt", b"123456")
            self.assertFalse((run.path / "two.txt").exists())

    def test_finalize_budget_includes_completion_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            run = RunDirectory(Path(temp), "20261031T030000Z-test", limit=100)
            with self.assertRaises(ValueError):
                run.finalize(header(), [row()])
            self.assertEqual(list(run.path.iterdir()), [])

    def test_partial_run_is_not_loaded(self):
        with tempfile.TemporaryDirectory() as temp:
            run = RunDirectory(Path(temp), "20261031T030000Z-test")
            with self.assertRaises(FileNotFoundError):
                load_run(run.path)

    def test_completed_metadata_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            run = RunDirectory(Path(temp), "20261031T030000Z-test")
            run.finalize(header(), [row(), row("undefended")])
            (run.path / "results.md").write_text("edited", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "modified"):
                load_run(run.path)

    def test_generated_table_escapes_injected_markup(self):
        value = row(branches=[target(complete=False)])
        value["invalid_reason"] = "<script>|\nhello"
        rendered = render_results([value])
        self.assertIn("&lt;script&gt;&#124; hello", rendered)

    def test_history_detects_same_code_across_fresh_paths(self):
        a, b = header(name="first"), header(name="second")
        first, second = row(), row(branches=[target(effect=True)])
        first["request_contract"], second["request_contract"] = "run1paths", "run2paths"
        rendered = history([(a, [first]), (b, [second])])
        self.assertIn("同码异果", rendered)
        self.assertNotIn("（first）", rendered)  # only latest trial is displayed

    def test_history_flags_regression(self):
        a, b = header(name="first", baseline="v2"), header(name="second", baseline="v3")
        b["engine"]["digest"] = "different-version"
        rendered = history([(a, [row()]), (b, [row(branches=[target(effect=True)])])])
        self.assertIn("挡住→成功", rendered)

    def test_history_never_carries_old_trial_subset_forward(self):
        a, b = header(name="first"), header(name="second")
        rendered = history([(a, [row(attack="NB-01")]), (b, [row(attack="NB-02")])])
        self.assertNotIn("NB-01", rendered.split("## 批次状态")[0])
        self.assertIn("NB-02", rendered)

    def test_identity_is_git_blob_not_plain_sha1(self):
        self.assertEqual(identity(b"")["blob"], "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")


if __name__ == "__main__":
    unittest.main()
