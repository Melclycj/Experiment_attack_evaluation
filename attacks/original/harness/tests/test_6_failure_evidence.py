"""离线回归：窗口/观察/恢复失败及NB-23停止反例，恢复前留证，不启动真实进程。"""
from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch
from batch_fixtures import Adapter, FakeRuntime, cases, header, patches
from common import identity
from engine_cases import EngineCase
from file_cases import FileCase
from record import load_run
from run_batch import Batch
from run_registry import CASES, Case
from run_rows import Row
from test_6_lifecycle import registry_fixture


class ChangedFile(Adapter):
    def prepare(self, config, repeat, contract):
        p = super().prepare(config, repeat, contract)
        self.rt.object = self.rt.work / 'nb-decoy-object'
        self.rt.object.write_bytes(b'before')
        p.update(before={'targets': {'file': self.snapshot()}}, tokens={'file': 'nb-decoy-token'})
        return p

    def snapshot(self):
        return {'verified': True, 'exists': True, 'dev': 1, 'ino': 2, **identity(self.rt.object.read_bytes())}

    def interact(self, handle, prepared):
        self.rt.object.write_bytes(b'forbidden change')
        self.rt.events.append('changed')

    def after_tree(self, prepared, tree):
        if self.rt.failure == 'after-tree':
            raise ValueError('final response missing')

    def observe(self, *args):
        if self.rt.failure == 'judge':
            raise ValueError('scan failed')
        result = super().observe(*args)
        result['file'].update(external_effect=True, external_fact={'after': self.snapshot()})
        return result

    def failure_facts(self, *args):
        self.rt.events.append('fallback')
        with patch('file_cases.snapshot', side_effect=lambda path: self.snapshot()):
            return FileCase.failure_facts(self, *args)

    def restore(self, prepared):
        self.rt.events.append('restore')
        self.rt.object.write_bytes(b'before')
        if self.rt.failure == 'restore':
            raise ValueError('restore report failed')


class FailureCollection(unittest.TestCase):
    def exercise(self, failure, *, live=False, collect_fail=False):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = [Case('NB-07', 'NB-07.py', lambda rt: ChangedFile(rt, 'NB-07'),
                           {'mechanism': 'file-view'})]
            rt = FakeRuntime(Path(tmp), chosen, fail='window' if failure == 'window' else None,
                             error=ValueError)
            rt.failure = failure
            patches(rt, stack)
            if collect_fail:
                stack.enter_context(patch('run_batch.collect', side_effect=ValueError('bad capture')))
            if live:
                rt.finish = lambda: (_ for _ in ()).throw(TimeoutError('tree still live'))
            batch = Batch(rt, chosen, ['engine'], header(rt))
            code = batch.execute()
            meta, rows = load_run(rt.evidence.directory.path)
            raw = {p.name: p.read_bytes() for p in rt.evidence.directory.path.iterdir()}
            return code, meta, rows[0]['attempts'][0], raw, rt.events, rt.object.read_bytes()

    def check_retained(self, failure, **kw):
        code, meta, attempt, raw, events, restored = self.exercise(failure, **kw)
        self.assertEqual(code, 1)
        self.assertTrue(meta['cleanup_ok'])
        self.assertEqual(attempt['outcome'], 'invalid')
        target = attempt['targets'][0]
        self.assertTrue(target['external_effect'])
        self.assertTrue(target['target_verified'])
        self.assertEqual(target['external_fact']['after']['sha256'], identity(b'forbidden change')['sha256'])
        self.assertEqual(restored, b'before')
        self.assertIn(attempt['evidence']['file'], raw)
        self.assertEqual(events.count('restore'), 1)
        return events

    def test_window_failure_collects_then_snapshots_before_restore(self):
        events = self.check_retained('window')
        self.assertLess(events.index('collect'), events.index('restore'))
        self.assertLess(events.index('fallback'), events.index('restore'))

    def test_final_response_failure_still_preserves_modified_file(self):
        self.check_retained('after-tree')

    def test_judge_exception_preserves_modified_file(self):
        self.check_retained('judge')

    def test_bad_capture_does_not_hide_external_file_write(self):
        self.check_retained('window', collect_fail=True)

    def test_restore_exception_retains_prior_normal_receipt(self):
        self.check_retained('restore')

    def test_no_snapshot_or_capture_of_live_writer(self):
        _, _, attempt, _, events, _ = self.exercise('window', live=True)
        self.assertNotIn('collect', events)
        self.assertIsNone(attempt['targets'][0]['external_effect'])
        # The generic fallback is called, but its real FileCase gate returns
        # before reading any target. This test's restoration is only a temp mock.
        self.assertEqual(attempt['targets'][0]['external_fact'], {})


class SignalBatch(unittest.TestCase):
    def exercise(self, key, *, timeout=False):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = [CASES['NB-23']]
            rt = FakeRuntime(Path(tmp), chosen)
            owned, _ = registry_fixture('engine')
            rt.deployment.refs = owned.deployment.refs
            rt.targets = owned.targets
            rt.support, rt.rows = owned.support, []
            rt.cap = {'first': 70000, 'last': 70005}
            rt.cgroup = NS(path=Path('/offline/nb-decoy-group'))
            rt.deployment.admin = Mock()
            rt.deployment.admin.rows.side_effect = TimeoutError('stopped control plane')
            patches(rt, stack)
            stack.enter_context(patch('run_rows.Path.read_text', return_value='201' if timeout else ''))
            stack.enter_context(patch('run_rows.process_info', return_value={'uids': [70001] * 4}))
            count = [0]
            def pump():
                count[0] += 1
                if timeout and count[0] == 2:
                    # Model the supervisor's abort, without any actual signals.
                    rt.deployment.refs[key].value['state'] = 'Z'
                    raise TimeoutError('mock supervisor deadline')
                rt.deployment.refs[key].value['state'] = 'T'
            rt.pump = pump
            def start(config, **kw):
                row = Row(rt, config, 'work0', 'row', 30)
                row.execution, row.uid = 'attack:1', 70001
                rt.rows.append(row)
                return row
            rt.start = start
            code = Batch(rt, chosen, ['engine'], header(rt)).execute()
            meta, rows = load_run(rt.evidence.directory.path)
            attempt = rows[0]['attempts'][0]
            targets = {t['id']: t for t in attempt['targets']}
            raw = [json.loads(p.read_bytes()) for p in rt.evidence.directory.path.glob('raw-*.signal-stopped.json')]
            self.assertEqual(code, 1)
            self.assertEqual(attempt['outcome'], 'invalid')
            self.assertTrue(targets[key]['external_effect'])
            self.assertEqual(targets[key]['external_fact']['stopped_witness']['state'], 'T')
            self.assertTrue(any(x['target'] == key and x['stopped']['state'] == 'T' for x in raw))
            rt.deployment.admin.rows.assert_not_called()
            return meta, attempt

    def test_core_stop_is_preserved_without_control_plane_poll(self):
        self.exercise('core')

    def test_spawner_stop_is_preserved_without_control_plane_poll(self):
        self.exercise('spawner')

    def test_core_witness_survives_mock_timeout_and_recovery_failure(self):
        meta, _ = self.exercise('core', timeout=True)
        self.assertIn('mock supervisor deadline', meta['controller_error']['message'])

    def test_spawner_witness_survives_mock_timeout(self):
        self.exercise('spawner', timeout=True)


@unittest.skipUnless(os.name == 'posix', 'Linux pinned temporary files only; all process/network effects mocked')
class PinnedFilePipelines(unittest.TestCase):
    def test_real_file_adapter_retains_nb07_after_window_failure(self):
        from fourb_fixtures import FileRuntime
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = [CASES['NB-07']]
            rt = FileRuntime(Path(tmp), chosen, stack)
            rt.deployment.upstream.end = Mock(side_effect=ValueError('end marker lost'))
            self.assertEqual(Batch(rt, chosen, ['undefended'], header(rt)).execute(), 1)
            _, rows = load_run(rt.evidence.directory.path)
            target = rows[0]['attempts'][0]['targets'][0]
            self.assertTrue(target['external_effect'])
            self.assertNotEqual(target['external_fact']['before']['sha256'],
                                target['external_fact']['after']['sha256'])
            self.assertFalse(list(rt.work.glob('nb-decoy-file-*')))

    def test_real_nb21_mirror_retained_before_failed_final_response_restore(self):
        from fourd_fixtures import ObjectRuntime
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = [CASES['NB-21']]
            rt = ObjectRuntime(Path(tmp), chosen, stack)
            original_arm = rt.arm
            def arm(config):
                original_arm(config)
                rt.support.question_result = Mock(side_effect=ValueError('final result absent'))
            rt.arm = arm
            before = rt.paths['mirror'].read_bytes()
            self.assertEqual(Batch(rt, chosen, ['undefended'], header(rt)).execute(), 1)
            _, rows = load_run(rt.evidence.directory.path)
            target = next(t for t in rows[0]['attempts'][0]['targets'] if t['id'] == 'mirror')
            self.assertTrue(target['external_effect'])
            self.assertEqual(target['outcome'], 'invalid')
            ref = target['external_fact']['raw_after']
            after = (rt.evidence.directory.path / ref['file']).read_bytes()
            self.assertNotEqual(after, before)
            self.assertEqual(rt.paths['mirror'].read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
