"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from deploy_fixtures import FakeCommands, QUESTION
from management import Interaction, Management, current_question, execution_id
from net import QUESTION_HOST


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.command = FakeCommands(Path("/fixture"))
        self.engine = self.command.start(["/fixture/engine"])
        self.admin = Management(Path("/fixture/source"), Path("/fixture/root"), self.command, self.engine)

    def test_production_execution_id_contains_colon(self):
        self.assertEqual(execution_id("abcdef:1"), "abcdef:1")
        for value in ("../../pid", "x", "x:0", "a:1/b", "a:1\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                execution_id(value)

    def test_question_metadata_comes_only_from_rendered_admin_stream(self):
        q = current_question(QUESTION)
        self.assertEqual(q["execution"], "abcdef:1")
        self.assertEqual(q["host"], QUESTION_HOST)
        for text in (QUESTION + "question 7 withdrawn: gone\n", QUESTION + "question 7 answered\n",
                     QUESTION.split("answer question")[0], "agent says question 7"):
            self.assertIsNone(current_question(text))

    def test_one_answer_requires_matching_current_question_and_ack(self):
        child = self.command.start(["/fixture/questions"], interactive=True)
        child.buffers["stdout"].extend(QUESTION.encode())
        self.admin.watcher = Interaction(self.command, child)
        q = self.admin.question(execution="abcdef:1", path="/nb-request")
        self.admin.allow_once(q)
        self.assertEqual(self.command.inputs, [b"allow-once\n"])
        with self.assertRaises(RuntimeError):
            self.admin.allow_once(q)

    def test_withdrawn_question_cannot_be_answered(self):
        child = self.command.start(["/fixture/questions"], interactive=True)
        child.buffers["stdout"].extend(QUESTION.encode())
        self.admin.watcher = Interaction(self.command, child)
        q = current_question(QUESTION)
        child.buffers["stdout"].extend(b"question 7 withdrawn: gone\n")
        with self.assertRaises(RuntimeError):
            self.admin.allow_once(q)
        self.assertFalse(self.command.inputs)

    def test_credential_truth_is_environment_only_not_argv(self):
        self.admin.credential("nb-decoy-secret", "nb-decoy-placeholder")
        argv, kw = self.command.calls[-1]
        self.assertNotIn("nb-decoy-secret", str(argv))
        self.assertEqual(kw["env"], {"NB_DECOY_TRUTH": "nb-decoy-secret"})
        self.assertIn("--truth-env", argv)
        self.assertIn("--reuid=1000", argv)
        self.assertIn(str(Path("/fixture/source/bin/engine-client")), argv)

    def test_no_unregistered_question_host_entry_is_added(self):
        self.admin.entry()
        self.assertNotIn(QUESTION_HOST, str(self.command.calls))
        self.assertIn("GET", self.command.calls[-1][0])

    def test_control_not_ready_is_retried_but_other_refusals_are_not(self):
        for message, okay in (("control not ready", True), ("uid range exhausted", False)):
            with patch.object(self.admin, "call", side_effect=[
                    {"exit_code": 1, "stderr": message}, {"exit_code": 0, "stdout": "execution=abc:1\n"}]):
                if okay:
                    self.assertEqual(self.admin.start_row("work0"), "abc:1")
                else:
                    with self.assertRaises(RuntimeError):
                        self.admin.start_row("work0")

    def test_attach_pipe_and_input_eof(self):
        original = self.command.start
        def start(argv, **kw):
            child = original(argv, **kw)
            child.buffers["stderr"].extend(b"attached to abcdef:1; Ctrl-] detaches\n")
            return child
        self.command.start = start
        stream = self.admin.attach("abcdef:1")
        stream.send(b"start\n")
        stream.close()
        stream.close()
        self.assertEqual(self.command.inputs, [b"start\n"])
        self.assertEqual(len(self.command.closures), 1)
        self.assertTrue(self.command.starts[-1][1]["interactive"])
        with self.assertRaises(ValueError):
            stream.send(b"after EOF")

    def test_engine_exit_is_setup_failure_not_test_outcome(self):
        self.engine.proc.poll.return_value = 2
        with self.assertRaisesRegex(RuntimeError, "engine exited"):
            self.admin.workspaces()
