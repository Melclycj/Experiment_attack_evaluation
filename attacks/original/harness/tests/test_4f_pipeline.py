"""这是 1.1 隔离论证的验证测试：全量编排、配对、失败归档与恢复的离线合约。"""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from batch_fixtures import header
from common import MAX_OUTPUT
from fourf_fixtures import MergedRuntime, ORDER, selected
from record import load_run
from run_batch import Batch
from run_config import schedule
from run_registry import CASES


class FullPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Two read-only assertion sets share one costly full 59-row archive.
        cls.full_result = cls().exercise()

    def exercise(self, names=ORDER, *, alter=None, **kwargs):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = selected(names)
            rt = MergedRuntime(Path(tmp), chosen, stack, **kwargs)
            if alter:
                alter(rt, stack)
            batch = Batch(rt, chosen, ['engine', 'undefended'], header(rt))
            code = batch.execute()
            meta, rows = load_run(rt.evidence.directory.path)
            files = {p.name: p.read_bytes() for p in rt.evidence.directory.path.iterdir()}
            self.assertLessEqual(sum(map(len, files.values())), MAX_OUTPUT)
            self.assertTrue(all(row.closed for row in rt.rows))
            return code, meta, rows, rt.trace, files

    def test_all_31_cases_two_arms_59_rows_four_support_starts(self):
        code, meta, rows, trace, files = self.full_result
        self.assertEqual(code, 0)  # New four/four contract; legacy omission tested separately.
        self.assertIsNone(meta['controller_error'])
        self.assertFalse(meta['formal'])
        self.assertTrue(meta['cleanup_ok'])
        self.assertEqual(len(rows), 59)
        self.assertEqual([(r['config'], r['attack']) for r in rows],
                         [(cfg, c.attack) for cfg, c in schedule([CASES[k] for k in ORDER], ['engine', 'undefended'])])
        self.assertEqual([d for s, _, d in trace if s == 'support-start'],
                         [('victim', 'work1', 'engine', 'SUP-VICTIM'),
                          ('auxiliary', 'work2', 'engine', 'SUP-AUXILIARY'),
                          ('victim', 'work1', 'undefended', 'SUP-VICTIM'),
                          ('auxiliary', 'work2', 'engine', 'SUP-AUXILIARY'),
                          ('victim', 'work1', 'engine', 'SUP-VICTIM')])
        self.assertEqual([d for s, _, d in trace if s == 'support-close'], ['engine', 'undefended'])
        for row in rows:
            with self.subTest(attack=row['attack'], config=row['config']):
                expected = ('blocked' if row['kind'] == 'attack' and row['config'] == 'engine' else 'succeeded')
                self.assertEqual(row['outcome'], expected)
                self.assertEqual(row['expected'], CASES[row['attack']].expectation(row['config']))
                self.assertEqual(len(row['attempts']), 1)
                self.assertIn('evidence', row['attempts'][0])
                self.assertEqual({t['id'] for t in row['attempts'][0]['targets']}, set(row['applicable_targets']))
        self.assertEqual(meta['report']['batch']['state'], 'completed')
        self.assertIn('COMPLETE.json', files)  # completeness is not experimental success

    def test_nb15_independent_rows_and_sync_cases_ordered(self):
        _, _, rows, trace, _ = self.full_result
        requests = [d for s, _, d in trace if s == 'request' and d['attack'] == 'NB-15']
        self.assertEqual([list(r['targets']) for r in requests], [['source'], ['mount']] * 2)
        self.assertEqual(len({r['sync']['nonce'] for r in requests}), 4)
        for cfg in ('engine', 'undefended'):
            for attack in ('NB-21', 'NB-26'):
                stages = [s for s, current, _ in trace if current == (cfg, attack)]
                self.assertLess(stages.index('sync'), stages.index('tree-empty'))
                self.assertLess(stages.index('tree-empty'), stages.index('after-tree'))
                self.assertLess(stages.index('after-tree'), stages.index('window'))
                self.assertLess(stages.index('judge'), stages.index('restore'))
        for attack in ORDER:
            paired = [r for r in rows if r['attack'] == attack]
            if len(paired) == 2:
                self.assertEqual(paired[0]['script'], paired[1]['script'])
                self.assertEqual(paired[0]['request_contract'], paired[1]['request_contract'])

    def test_successful_target_does_not_hide_other_targets_pairing_failure_in_exit_code(self):
        code, meta, rows, _, _ = self.exercise(['NB-23', 'PC-FILE'], effect=('engine', 'NB-23', 'core'), missing_peer=('NB-23', 'victim'))
        self.assertEqual(rows[0]['outcome'], 'succeeded')  # Retain a genuine modeled effect.
        targets = {t['id']: t for t in rows[0]['attempts'][0]['targets']}
        self.assertEqual(targets['core']['outcome'], 'succeeded')
        self.assertEqual(targets['victim']['outcome'], 'invalid')
        self.assertIsNone(rows[0]['upper_bound'])
        self.assertEqual(meta['report']['batch']['state'], 'failed')
        self.assertEqual(code, 1, 'batch exit must not contradict the failed quality report')

    def test_actual_attack_success_without_quality_failure_is_not_execution_failure(self):
        code, meta, rows, _, _ = self.exercise(['NB-01', 'PC-FILE'], effect=('engine', 'NB-01', 'file'))
        self.assertEqual(rows[0]['outcome'], 'succeeded')
        self.assertEqual(code, 0)
        self.assertEqual(meta['report']['batch']['state'], 'completed')

    def test_failed_peer_target_cannot_borrow_sibling_success(self):
        code, meta, rows, _, _ = self.exercise(['NB-20', 'PC-FILE'], missing_peer=('NB-20', 'metadata'))
        self.assertEqual(code, 1)
        targets = {t['id']: t for t in rows[0]['attempts'][0]['targets']}
        self.assertEqual(targets['metadata']['outcome'], 'invalid')
        self.assertIsNone(rows[0]['upper_bound'])

    def test_incomplete_capture_with_candidate_effect_never_becomes_success(self):
        code, meta, rows, _, _ = self.exercise(['NB-01', 'PC-FILE'],
            fault=(('engine', 'NB-01'), 'incomplete'), effect=('engine', 'NB-01', 'file'))
        self.assertEqual(code, 1)
        self.assertEqual(rows[0]['outcome'], 'invalid')
        self.assertTrue(rows[0]['attempts'][0]['targets'][0]['external_effect'])
        self.assertTrue(all('not-started' in r['invalid_reason'] for r in rows[1:]))

    def test_late_restore_failure_preserves_receipt_and_accounts_unstarted_rows(self):
        code, meta, rows, trace, files = self.exercise(fault=(('engine', 'NB-26'), 'restore'))
        self.assertEqual(code, 1)
        self.assertIn('restore', meta['controller_error']['message'])
        self.assertEqual(len(rows), 59)
        failed = next(r for r in rows if r['attack'] == 'NB-26' and r['config'] == 'engine')
        self.assertEqual(failed['outcome'], 'invalid')
        self.assertTrue(all('not-started' in r['invalid_reason'] for r in rows if r['config'] == 'undefended'))
        raw = [json.loads(data) for name, data in files.items() if name.startswith('raw-') and name.endswith('.json')]
        self.assertTrue(any(v.get('request', {}).get('attack') == 'NB-26' for v in raw if isinstance(v, dict)))
        self.assertEqual(sum(s == 'close' for s, _, _ in trace), 1)

    def test_synchronization_failure_stops_before_judge_and_preserves_remaining_rows(self):
        code, meta, rows, trace, _ = self.exercise(['NB-21', 'PC-FILE'],
                                                fault=(('engine', 'NB-21'), 'sync'))
        self.assertEqual(code, 1)
        self.assertEqual(rows[0]['outcome'], 'invalid')
        self.assertTrue(all('not-started' in r['invalid_reason'] for r in rows[1:]))
        self.assertFalse(any(s == 'judge' for s, _, _ in trace))
        self.assertTrue(any(s == 'restore' for s, _, _ in trace))

    def test_nonzero_runner_exit_with_candidate_effect_is_invalid(self):
        code, meta, rows, _, _ = self.exercise(['NB-26', 'PC-FILE'],
            fault=(('engine', 'NB-26'), 'runner-exit'), effect=('engine', 'NB-26', 'netns'))
        self.assertEqual(code, 1)
        target = rows[0]['attempts'][0]['targets'][0]
        self.assertTrue(target['external_effect'])
        self.assertEqual(target['outcome'], 'invalid')
        self.assertEqual(target['invalid_reason'], 'nonzero-runner-exit')

    def test_cleanup_failure_keeps_archive_but_fails_batch(self):
        def alter(rt, stack):
            stack.enter_context(patch.object(rt, 'close', return_value={
                'ok': False, 'failures': [{'step': 'offline-cleanup'}], 'retained': []}))
        code, meta, rows, _, files = self.exercise(['NB-01', 'PC-FILE'], alter=alter)
        self.assertEqual(code, 1)
        self.assertFalse(meta['cleanup_ok'])
        self.assertEqual(meta['report']['batch']['state'], 'failed')
        self.assertIn('COMPLETE.json', files)
        self.assertEqual(rows[0]['outcome'], 'blocked')

    def test_failure_before_attempt_is_archived_for_every_selected_row(self):
        def alter(rt, stack):
            stack.enter_context(patch.object(rt, 'prepare', side_effect=RuntimeError('payload setup failed')))
        code, meta, rows, trace, _ = self.exercise(alter=alter)
        self.assertEqual(code, 1)
        self.assertEqual(len(rows), 59)
        self.assertTrue(all(r['outcome'] == 'invalid' for r in rows))
        self.assertFalse(any(s == 'start' for s, _, _ in trace))
        self.assertTrue(meta['cleanup_ok'])
