"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import ExitStack
import tempfile
import unittest
from pathlib import Path
from record import load_run
from run_batch import Batch
from batch_fixtures import FakeRuntime, cases, header, patches

class BatchTests(unittest.TestCase):
    def exercise(self, fail=None, error=RuntimeError, sync=None):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            chosen = cases(sync); rt = FakeRuntime(Path(temp), chosen, fail, error)
            patches(rt, stack)
            result = Batch(rt, chosen, ['engine', 'undefended'], header(rt)).execute()
            meta, rows = load_run(rt.evidence.directory.path)
            self.assertLessEqual(rt.evidence.directory.size(), 10 * 1024 * 1024)
            self.assertIn('close', rt.events); self.assertFalse(meta['formal'])
            return result, meta, rows, rt.events

    def test_normal_two_arm_chain(self):
        code, meta, rows, events = self.exercise()
        self.assertEqual(code, 0); self.assertTrue(meta['cleanup_ok']); self.assertEqual(len(rows), 5)
        self.assertEqual([r['outcome'] for r in rows], ['blocked', 'succeeded', 'blocked', 'succeeded', 'succeeded'])
        self.assertLess(events.index('tree-empty'), events.index('window'))
        self.assertLess(events.index('window'), events.index('judge'))
        self.assertLess(events.index('arm-engine'), events.index('arm-undefended'))
    def test_required_sync_missing_invalid(self):
        code, meta, rows, _ = self.exercise('sync-missing', sync='sent')
        self.assertEqual(code, 1); self.assertIn('synchronization', rows[0]['invalid_reason'])
    def test_host_observed_sync_succeeds(self):
        code, _, _, events = self.exercise(sync='sent')
        self.assertEqual(code, 0); self.assertIn('sync', events)
    def test_sync_failure_never_judges(self):
        code, _, rows, events = self.exercise('sync', sync='done')
        self.assertEqual(code, 1); self.assertNotIn('judge', events)
    def test_cleanup_failure_recorded(self):
        code, meta, _, _ = self.exercise('close')
        self.assertEqual(code, 1); self.assertFalse(meta['cleanup_ok'])
        self.assertIn('controller-cleanup', str(meta['cleanup']))
    def test_no_window_before_tree_empty(self):
        _, _, _, events = self.exercise('tree-empty')
        self.assertNotIn('window', events); self.assertNotIn('judge', events)
    def test_request_failure_starts_no_row(self):
        _, _, rows, events = self.exercise('request')
        self.assertNotIn('start-engine', events); self.assertEqual(rows[0]['outcome'], 'invalid')
    def test_missing_observation_not_success(self):
        _, _, rows, events = self.exercise('collect', FileNotFoundError)
        self.assertIn('judge', events); self.assertEqual(rows[0]['outcome'], 'invalid')
    def test_output_limit_failure_finalizes_invalid(self):
        _, meta, rows, _ = self.exercise('collect', ValueError)
        self.assertEqual(rows[0]['outcome'], 'invalid'); self.assertTrue(meta['cleanup_ok'])

def failure_test(stage, error):
    def test(self):
        code, meta, rows, events = self.exercise(stage, error)
        self.assertEqual(code, 1); self.assertEqual(meta['controller_error']['type'], error.__name__)
        self.assertTrue(any(r['outcome'] == 'invalid' for r in rows))
        if stage not in ('access', 'arm-undefended', 'start-undefended'):
            self.assertNotIn('arm-undefended', events)
    return test

for stage in ('cgroup','baseline-host','build','payload','deployment','arm-engine','prepare-attempt',
              'verify','request','begin','start-engine','interact','pump','tree-empty','window',
              'collect','judge','restore','arm-undefended','access','start-undefended'):
    setattr(BatchTests, 'test_failure_' + stage.replace('-', '_'), failure_test(stage, RuntimeError))
for error in (TimeoutError, InterruptedError, KeyboardInterrupt, SystemExit):
    setattr(BatchTests, 'test_interrupted_' + error.__name__, failure_test('pump', error))
