"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from common import identity, json_bytes
from run_baseline import ENGINE, verify
from run_boot import stage
from run_config import parser
from run_runtime import Runtime
import test_batch_runtime as runtime_tests

GO = 'ExperimentLab/engine-v3'      # registered baseline v4 (the name GO is historical: the selected main line)
FROZEN = 'ExperimentLab/engine-v2-go'  # frozen since v4; its archived runs stay readable, new runs are refused


class EngineSelectionTests(unittest.TestCase):
    def test_cli_defaults_to_go_and_refuses_the_frozen_tree(self):
        argv = ['--repo', '/repo', '--attacks', 'PC-FILE', '--configs', 'engine',
                '--label', 'offline', '--crash-directory', '/tmp/crashes']
        self.assertEqual(ENGINE, GO)
        self.assertEqual(parser().parse_args(argv).engine_path, GO)
        self.assertEqual(parser().parse_args([*argv, '--engine-path', GO]).engine_path, GO)
        with patch('sys.stderr'), self.assertRaises(SystemExit):
            parser().parse_args([*argv, '--engine-path', FROZEN])
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            verify(Path('/repo'), {}, {}, Mock(), engine_path=FROZEN)

    def test_stage_freezes_selected_source_and_path(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            repo = root / 'repo'
            runs = repo / 'Thesis/Work/Submission/attack_evaluation/no-bypass/runs'
            runs.mkdir(parents=True)
            frozen = root / 'frozen'
            frozen.mkdir()
            # Mock this module's guard, not shared os.name used by pathlib.
            stack.enter_context(patch('run_boot.os', SimpleNamespace(name='posix', geteuid=lambda: 0)))
            stack.enter_context(patch('run_boot.tempfile.mkdtemp', return_value=str(frozen)))
            stack.enter_context(patch('run_boot.claim', return_value={'mock': True}))
            stack.enter_context(patch('run_boot.bind'))
            snap = stack.enter_context(patch('run_boot.snapshot', return_value={'digest': 'offline'}))
            stack.enter_context(patch('run_boot.read_owned', return_value=b'x = 1\n'))
            args = SimpleNamespace(repo=repo, engine_path=GO, label='offline', cap={},
                configs=['engine'], crash_directory=root, cgroup_parent=root, cert_python='/offline/python')
            bundle = stage(args, [], {}, time.monotonic() + 600)
            self.assertEqual(bundle['engine_path'], GO)
            self.assertEqual(snap.call_args_list[1].args[0], repo / GO)

    def test_invalid_source_fails_before_snapshot_mutation(self):
        args = SimpleNamespace(engine_path='../outside')
        with patch('run_boot.os.geteuid', create=True, return_value=0), \
             patch('run_boot.os.name', 'posix'), patch('run_boot.tempfile.mkdtemp') as mkdir:
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                stage(args, [], {}, time.monotonic() + 600)
            mkdir.assert_not_called()

    def test_go_does_not_match_old_engine_registration(self):
        versions = {'v2': {'engine_path': 'ExperimentLab/engine-v2'}, 'v2-go': {'engine_path': FROZEN}}
        command = Mock(return_value={'stdout': 'offline', 'exit_code': 0})
        with patch('run_baseline.read_owned', return_value=json_bytes(versions)), \
             patch('run_baseline.inventory') as inventory:
            result = verify(Path('/repo'), {'files': {'a': identity(b'a')}}, {}, command, engine_path=GO)
        self.assertEqual(result['source_path'], GO)
        self.assertIsNone(result['baseline'])
        self.assertFalse(result['baseline_check']['executed'])
        inventory.assert_not_called()
        self.assertIn('--reuid=1000', command.call_args.args[0])
        self.assertIn('core.fsmonitor=false', command.call_args.args[0])
        self.assertIn(GO, command.call_args.args[0])
        self.assertIn(':(exclude)' + GO + '/runs', command.call_args.args[0])

    def test_registered_go_still_requires_actual_checker(self):
        versions = {'v2-go': {'engine_path': GO}}
        source = {'files': {'a': identity(b'a')}}
        def read(path, *args):
            return json_bytes(versions) if path.name == 'versions.json' else b'checker'
        command = Mock(side_effect=[{'stdout': 'head'}, {'stdout': ''}, {'exit_code': 1}])
        with patch('run_baseline.read_owned', side_effect=read), \
             patch('run_baseline.inventory', return_value=source):
            with self.assertRaisesRegex(ValueError, 'baseline check failed'):
                verify(Path('/repo'), source, {}, command, engine_path=GO)

    def test_runtime_passes_selected_path_to_verification(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt, *_ = runtime_tests.RuntimeWiringTests().fixture(stack, Path(tmp))
            rt.bundle['engine_path'] = GO
            with patch('run_runtime.verify', return_value=rt.engine_identity) as verified:
                rt.prepare()
                self.assertEqual(verified.call_args.kwargs['engine_path'], GO)
                rt.close()

    def test_verify_rejects_unapproved_path_before_commands(self):
        command = Mock()
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            verify(Path('/repo'), {}, {}, command, engine_path='/elsewhere')
        command.assert_not_called()

    def test_preparation_failure_still_identifies_selected_engine(self):
        bundle = {'root': '/tmp/offline', 'cap': {}, 'cgroup_parent': '/sys/fs/cgroup',
                  'label': 'offline', 'engine_path': GO, 'engine_identity': {'digest': 'offline'}}
        rt = Runtime(bundle, {}, time.monotonic() + 600, Mock())
        self.assertEqual(rt.engine_identity['source_path'], GO)
        self.assertNotIn('source_path', bundle['engine_identity'])
