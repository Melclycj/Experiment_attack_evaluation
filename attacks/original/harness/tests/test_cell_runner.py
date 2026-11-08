"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import copy
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cell"))
from nb_contract import ERROR, LIMIT, REQUEST, decode, encoded, stem
from runner import Context, inherited_fds, run
from nb_process import execute
from test_cell_contract import request


class MemoryFiles:
    def __init__(self, values=None):
        self.values = dict(values or {})
    def read(self, name, limit):
        if name not in self.values:
            raise FileNotFoundError(name)
        value = self.values[name]
        if len(value) > limit:
            raise ValueError("read limit")
        return value
    def absent(self, name):
        if name in self.values:
            raise FileExistsError(name)
    def write(self, name, data):
        self.absent(name)
        self.values[name] = data


class Clock:
    def __init__(self):
        self.now = 0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


def fixture(script=b"def control(ctx): return True\ndef action(ctx): ctx.observe('unit', rc=0)\n"):
    req = request()
    reg = {"v": 1, "modules": {"NB-06": {"path": "modules/unit.py", "sha256": hashlib.sha256(script).hexdigest()}}}
    return req, MemoryFiles({REQUEST: encoded(req)}), MemoryFiles({"modules.json": encoded(reg), "modules/unit.py": script})


class RunnerTests(unittest.TestCase):
    def observed(self, req, work):
        return decode(work.values[stem(req) + "-observed.json"])

    def test_normal_complete_not_external_verdict(self):
        req, work, payload = fixture()
        self.assertEqual(run(work, payload, inherited=[{"fd": 3, "type": 0o140000}]), 0)
        out = self.observed(req, work)
        self.assertTrue(out["complete"])
        self.assertTrue(out["control_ok"])
        self.assertEqual(out["observed"][0]["phase"], "action")
        self.assertEqual(out["inherited_fds"][0]["fd"], 3)
        self.assertNotIn("outcome", out)

    def test_request_invalid_records_bootstrap_error(self):
        work = MemoryFiles({REQUEST: b"{}"})
        self.assertEqual(run(work, MemoryFiles()), 2)
        self.assertFalse(decode(work.values[ERROR])["complete"])

    def test_missing_request(self):
        work = MemoryFiles()
        self.assertEqual(run(work, MemoryFiles()), 2)
        self.assertEqual(decode(work.values[ERROR])["error"]["type"], "FileNotFoundError")

    def test_unknown_module_rejected(self):
        req, work, payload = fixture()
        payload.values["modules.json"] = encoded({"v": 1, "modules": {}})
        self.assertEqual(run(work, payload), 2)
        self.assertIn("unknown", self.observed(req, work)["error"]["message"])

    def test_module_hash_mismatch_not_executed(self):
        req, work, payload = fixture()
        payload.values["modules/unit.py"] = b"raise AssertionError('must not execute')"
        self.assertEqual(run(work, payload), 2)
        self.assertIn("digest", self.observed(req, work)["error"]["message"])

    def test_module_path_traversal(self):
        req, work, payload = fixture()
        reg = decode(payload.values["modules.json"])
        reg["modules"]["NB-06"]["path"] = "../unsafe.py"
        payload.values["modules.json"] = encoded(reg)
        self.assertEqual(run(work, payload), 2)
        self.assertFalse(self.observed(req, work)["complete"])

    def test_missing_module_functions(self):
        req, work, payload = fixture(b"def action(ctx): pass\n")
        self.assertEqual(run(work, payload), 2)
        self.assertIn("control(ctx)", self.observed(req, work)["error"]["message"])

    def test_control_false_prevents_action(self):
        req, work, payload = fixture(b"def control(ctx): return False\ndef action(ctx): raise AssertionError('action')")
        self.assertEqual(run(work, payload), 2)
        out = self.observed(req, work)
        self.assertFalse(out["control_ok"])
        self.assertEqual(out["error"]["message"], "control_failed")

    def test_control_requires_bool_true_not_truthy(self):
        req, work, payload = fixture(b"def control(ctx): return 1\ndef action(ctx): pass")
        self.assertEqual(run(work, payload), 2)
        self.assertFalse(self.observed(req, work)["control_ok"])

    def test_failed_action_records_previous_observation(self):
        req, work, payload = fixture(b"def control(ctx): return True\ndef action(ctx):\n ctx.observe('first', errno=1)\n raise ValueError('unit failure')")
        self.assertEqual(run(work, payload), 2)
        out = self.observed(req, work)
        self.assertFalse(out["complete"])
        self.assertEqual(out["observed"][0]["values"]["errno"], 1)

    def test_module_system_exit_is_failure(self):
        req, work, payload = fixture(b"def control(ctx): raise SystemExit(0)\ndef action(ctx): pass")
        self.assertEqual(run(work, payload), 2)
        self.assertEqual(self.observed(req, work)["error"]["type"], "SystemExit")

    def test_captures_separate_and_phased(self):
        req, work, payload = fixture(b"def control(ctx):\n ctx.capture('read', b'control-bytes')\n return True\ndef action(ctx): ctx.capture('read', b'only-capture-sentinel')")
        self.assertEqual(run(work, payload), 0)
        data = work.values[stem(req) + "-observed.json"]
        self.assertNotIn(b"only-capture-sentinel", data)
        captures = decode(data)["captures"]
        self.assertEqual([x["phase"] for x in captures], ["control", "action"])
        self.assertEqual(work.values[captures[1]["path"]], b"only-capture-sentinel")

    def test_existing_observation_not_overwritten(self):
        req, work, payload = fixture()
        name = stem(req) + "-observed.json"
        work.values[name] = b"keep"
        self.assertEqual(run(work, payload), 3)
        self.assertEqual(work.values[name], b"keep")

    def test_existing_release_invalid_before_module(self):
        req, work, payload = fixture()
        work.values[req["sync"]["release"]] = b"old"
        self.assertEqual(run(work, payload), 2)
        self.assertEqual(self.observed(req, work)["error"]["type"], "FileExistsError")

    def test_write_failure_never_success(self):
        req, work, payload = fixture()
        work.write = Mock(side_effect=OSError("disk fixture"))
        self.assertEqual(run(work, payload), 3)

    def test_post_action_deadline(self):
        req, work, payload = fixture(b"def control(ctx): return True\ndef action(ctx): ctx.sleep(31)")
        clock = Clock()
        factory = lambda *a, **k: Context(*a, **k, clock=clock, sleep=clock.sleep)
        self.assertEqual(run(work, payload, context_factory=factory), 2)
        self.assertEqual(self.observed(req, work)["error"]["type"], "TimeoutError")

    def test_boot_fd_snapshot_excludes_enumeration_descriptor(self):
        info = Mock(st_mode=0o140777, st_dev=2, st_ino=3)
        with patch("runner.os.listdir", return_value=["0", "3", "4"]), \
             patch("runner.os.fstat", side_effect=[info, info, OSError(9, "closed")]), \
             patch("runner.os.readlink", return_value="socket:[3]"):
            self.assertEqual([x["fd"] for x in inherited_fds()], [0, 3])


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.req, self.work, _ = fixture()
        self.clock = Clock()
        self.ctx = Context(self.req, self.work, clock=self.clock, sleep=self.clock.sleep, cwd="/work")

    def test_target_path_uses_cwd_without_resolving_symlink(self):
        self.assertEqual(self.ctx.path("control"), "/work/nb-decoy-control")
        self.assertEqual(self.ctx.path("host"), "/tmp/nb-decoy-unit/host/key")

    def test_unknown_target_rejected(self):
        with self.assertRaises(KeyError):
            self.ctx.path("unregistered")

    def test_kind_mismatch_never_calls_probe(self):
        self.ctx.executor = Mock()
        with self.assertRaises(ValueError):
            self.ctx.probe("bad", "tcp", "host")
        self.ctx.executor.assert_not_called()

    def test_command_timeout_preserves_partial_capture_and_reason(self):
        self.ctx.executor = Mock(return_value={"stdout": b"partial", "stderr": b"fixture", "returncode": -9,
                                               "signal": 9, "error": "timeout"})
        with self.assertRaisesRegex(RuntimeError, "timeout"):
            self.ctx.command("unit", ["/fixture"])
        self.assertEqual(self.ctx.record["observed"][0]["values"]["error"], "timeout")
        self.assertEqual(self.work.values[self.ctx.record["captures"][0]["path"]], b"partial")

    def test_observation_budget_rejects_large_data(self):
        with self.assertRaises(ValueError):
            self.ctx.observe("large", data="x" * 65536)
        self.ctx.finish({"type": "budget"})

    def test_stderr_is_diagnostic_not_stdout_capture(self):
        self.ctx.executor = Mock(return_value={"stdout": b"read-data", "stderr": b"target: ENOENT", "returncode": 1,
                                               "signal": None, "error": None})
        self.ctx.command("read", ["/fixture"])
        record = self.ctx.record
        self.assertEqual(record["observed"][0]["values"]["stderr"], "target: ENOENT")
        self.assertEqual(self.work.values[record["captures"][0]["path"]], b"read-data")

    def test_capture_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.capture("../escape", b"data")

    def test_capture_budget_leaves_failure_record_room(self):
        with self.assertRaises(ValueError):
            self.ctx.capture("huge", b"x" * LIMIT)
        self.ctx.finish({"type": "limit"})
        self.assertFalse(decode(self.work.values[self.ctx.observation])["complete"])

    def test_duplicate_capture_rejected(self):
        self.ctx.capture("one", b"data")
        with self.assertRaises(FileExistsError):
            self.ctx.capture("one", b"overwrite")

    def test_sync_roundtrip_uses_existing_decoy_names(self):
        def release(seconds):
            self.clock.sleep(seconds)
            value = decode(self.work.values[self.req["sync"]["ready"]])
            self.work.write(self.req["sync"]["release"], encoded({**value, "state": "release"}))
        self.ctx.sleep = release
        self.ctx.synchronize("sent")
        self.assertEqual(self.ctx.record["synchronization"][0]["nonce"], self.req["sync"]["nonce"])

    def test_sync_timeout_at_ten_seconds(self):
        with self.assertRaises(TimeoutError):
            self.ctx.synchronize("done")
        self.assertAlmostEqual(self.clock.now, 10)

    def test_sync_rejects_wrong_nonce(self):
        def bad(seconds):
            self.clock.sleep(seconds)
            self.work.write(self.req["sync"]["release"], encoded({"nonce": "other"}))
        self.ctx.sleep = bad
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.ctx.synchronize("done")

    def test_sync_rejects_preexisting_ready_and_release(self):
        for key in ("ready", "release"):
            with self.subTest(key=key):
                self.work.values[self.req["sync"][key]] = b"stale"
                with self.assertRaises(FileExistsError):
                    self.ctx.synchronize("sent")
                del self.work.values[self.req["sync"][key]]

    def test_sync_single_use(self):
        self.ctx.synced = True
        with self.assertRaises(ValueError):
            self.ctx.synchronize("done")

    def test_sync_read_finishes_after_deadline(self):
        original = self.work.read
        def late_read(name, limit):
            self.clock.now = 11
            return encoded({"attempt": stem(self.req), "nonce": self.req["sync"]["nonce"], "state": "release"})
        self.work.read = late_read
        with self.assertRaises(TimeoutError):
            self.ctx.synchronize("done")
        self.work.read = original

    def test_sync_cannot_enlarge_budget(self):
        with self.assertRaises(ValueError):
            self.ctx.synchronize("done", timeout=11)

    def test_sync_obeys_remaining_attempt_time(self):
        self.clock.now = 29
        with self.assertRaises(TimeoutError):
            self.ctx.synchronize("done")
        self.assertAlmostEqual(self.clock.now, 30)

    def test_probe_uses_registered_target_only(self):
        mock = Mock(return_value={"stdout": b"bytes", "stderr": b'{"step":"complete","rc":0,"errno":0}\n',
                                  "returncode": 0, "signal": None, "error": None})
        self.ctx.executor = mock
        result = self.ctx.probe("read", "read", "host")
        self.assertEqual(mock.call_args.args[0][-2:], ["read", "/tmp/nb-decoy-unit/host/key"])
        self.assertEqual(result["events"][-1]["step"], "complete")

    def test_signal_observation_not_false_success(self):
        self.ctx.executor = Mock(return_value={"stdout": b"", "stderr": b"", "returncode": -31,
                                               "signal": 31, "error": None})
        self.assertEqual(self.ctx.probe("read", "read", "host")["signal"], 31)
        self.assertEqual(self.ctx.record["observed"][0]["values"]["signal"], 31)

    def test_probe_missing_completion_invalid(self):
        self.ctx.executor = Mock(return_value={"stdout": b"partial", "stderr": b"", "returncode": 0,
                                               "signal": None, "error": None})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.ctx.probe("read", "read", "host")
        self.assertEqual(len(self.ctx.record["captures"]), 1)


class ProcessTests(unittest.TestCase):
    def fake(self, *, chunks=(b"out", b""), err=(b"",), rc=0, limit=100, timeout=False, input_error=False):
        proc = Mock(pid=1234, returncode=None)
        proc.wait.side_effect = lambda **kw: setattr(proc, "returncode", rc)
        streams = {}
        for i, name in enumerate(("stdin", "stdout", "stderr"), 10):
            stream = Mock(closed=False)
            stream.fileno.return_value = i
            stream.close.side_effect = lambda s=stream: setattr(s, "closed", True)
            setattr(proc, name, stream)
            streams[i] = name
        mapping = {}
        selector = Mock()
        selector.register.side_effect = lambda f, ev, data: mapping.update({f: Mock(fileobj=f, data=data)})
        selector.unregister.side_effect = lambda f: mapping.pop(f)
        selector.get_map.side_effect = lambda: mapping
        selector.select.side_effect = lambda _t: [(key, 1) for key in list(mapping.values())]
        proc.poll.return_value = rc
        outputs = {11: iter(chunks), 12: iter(err)}
        def read(fd, size):
            return next(outputs[fd])
        clock = Clock()
        def now():
            clock.now += 40 if timeout else .001
            return clock.now
        with patch("nb_process.subprocess.Popen", return_value=proc) as popen, \
             patch("nb_process.selectors.DefaultSelector", return_value=selector), \
             patch("nb_process.os.set_blocking"), patch("nb_process.os.read", side_effect=read), \
             patch("nb_process.os.write", side_effect=BrokenPipeError() if input_error else lambda fd, d: len(d)), \
             patch("nb_process.os.killpg", create=True) as kill, patch("nb_process.signal.SIGKILL", 9, create=True), \
             patch("nb_process.time.monotonic", side_effect=now):
            result = execute(["/fixture/never-run"], cwd="/work", env={}, data=b"x" if input_error else b"", limit=limit)
        self.assertTrue(popen.call_args.kwargs["close_fds"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        if result["error"]:
            kill.assert_called_once()
        else:
            kill.assert_not_called()
        selector.close.assert_called_once()
        return result

    def test_mock_process_captures_and_exit(self):
        result = self.fake()
        self.assertEqual(result["stdout"], b"out")
        self.assertEqual(result["returncode"], 0)
        self.assertIsNone(result["error"])

    def test_mock_process_signal(self):
        self.assertEqual(self.fake(rc=-31)["signal"], 31)

    def test_mock_timeout(self):
        self.assertEqual(self.fake(timeout=True)["error"], "timeout")

    def test_mock_output_limit(self):
        result = self.fake(chunks=(b"abcdef",), limit=3)
        self.assertEqual(result["error"], "output_limit")
        self.assertEqual(result["stdout"], b"abc")

    def test_mock_broken_input(self):
        self.assertEqual(self.fake(input_error=True)["error"], "input_not_consumed")

    def test_spawn_failure_record(self):
        with patch("nb_process.subprocess.Popen", side_effect=OSError(2, "fixture")):
            result = execute(["/fixture"], cwd="/work", env={})
        self.assertEqual(result["errno"], 2)
        self.assertIsNone(result["returncode"])

    def test_invalid_argv_never_spawns(self):
        with patch("nb_process.subprocess.Popen") as popen:
            for argv in (["relative"], [], ["/absolute", "bad\0arg"]):
                with self.subTest(argv=argv), self.assertRaises(ValueError):
                    execute(argv, cwd="/work", env={})
            popen.assert_not_called()
