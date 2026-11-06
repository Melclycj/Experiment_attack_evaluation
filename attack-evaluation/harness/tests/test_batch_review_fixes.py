"""离线回归：失败记录先留证再中止批次；只用临时文件和 mock，不运行 engine 或攻击。"""
from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from batch_fixtures import Adapter, FakeRuntime, cases, header, patches
from cell.nb_contract import REQUEST, stem
from common import identity, json_bytes
from record import load_run
from run_batch import Batch
from run_transport import collect, request


class FailureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.req = request('20261031T000000Z-test', 'engine', cases()[0], 1,
            {'targets': {'x': {'kind': 'path', 'scope': 'work', 'path': 'nb-decoy-file'}},
             'parameters': {}})
        self.name = stem(self.req) + '-action-partial.capture'
        self.data = b'partial output before failure'
        self.record = {'v': 1, 'attempt': stem(self.req), 'complete': False,
            'error': {'type': 'TimeoutError', 'message': 'failed after capture'},
            'control_ok': True, 'observed': [{'phase': 'action', 'step': 'started'}],
            'captures': [{'path': self.name, 'phase': 'action', 'bytes': len(self.data),
                          'sha256': identity(self.data)['sha256']}]}
        self.evidence = Mock()
        self.evidence.raw.side_effect = lambda data, suffix='json': {
            'file': 'raw-offline.' + suffix, **identity(data)}

    def read(self, work, name, limit):
        values = {REQUEST: json_bytes(self.req), self.name: self.data,
                  stem(self.req) + '-observed.json': json_bytes(self.record)}
        return values[name]

    def failed_collect(self):
        with patch('run_transport.read_beneath', side_effect=self.read):
            with self.assertRaises(ValueError) as caught:
                collect(Path('/offline'), self.req, self.evidence)
        return caught.exception

    def test_incomplete_archives_record_and_valid_capture(self):
        error = self.failed_collect()
        archived = [c.args[0] for c in self.evidence.raw.call_args_list]
        self.assertIn(self.data, archived)
        self.assertIn(json_bytes(self.record), archived)
        self.assertEqual(error.observation, self.record)
        self.assertEqual(error.captures, {self.name: self.data})

    def test_complete_with_error_still_archives_and_rejects(self):
        self.record['complete'] = True
        error = self.failed_collect()
        self.assertIn(self.data, [c.args[0] for c in self.evidence.raw.call_args_list])
        self.assertEqual(error.observation['error'], self.record['error'])

    def test_corrupt_capture_retains_observation_not_verified_bytes(self):
        self.record['captures'][0]['sha256'] = '0' * 64
        error = self.failed_collect()
        self.assertIn(json_bytes(self.record), [c.args[0] for c in self.evidence.raw.call_args_list])
        self.assertEqual(error.captures, {})

    def test_wrong_envelope_never_exposes_capture_as_verified(self):
        self.record['attempt'] = 'wrong-attempt'
        error = self.failed_collect()
        self.assertIsNone(error.observation)
        self.assertEqual(error.captures, {})
        self.assertNotIn(self.data, [c.args[0] for c in self.evidence.raw.call_args_list])

    def test_nonobject_observation_rejected_with_raw_preserved(self):
        self.record = ['bad envelope']
        self.failed_collect()
        self.assertIn(json_bytes(self.record), [c.args[0] for c in self.evidence.raw.call_args_list])

    def test_archive_index_links_source_capture_to_output(self):
        self.failed_collect()
        indexes = [json.loads(c.args[0]) for c in self.evidence.raw.call_args_list
                   if c.kwargs.get('suffix') == 'collection.json']
        self.assertEqual(len(indexes), 1)
        ref = indexes[0]['captures'][self.name]
        self.assertEqual(ref['sha256'], identity(self.data)['sha256'])


class AbortTests(unittest.TestCase):
    def exercise(self, *, fail=None, error=ValueError, observation=None, runner_ok=None, adapter=None):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = cases()
            chosen[0] = replace(chosen[0], repeats=2)
            rt = FakeRuntime(Path(tmp), chosen, fail, error)
            patches(rt, stack)
            if observation is not None:
                stack.enter_context(patch('run_batch.collect', return_value=(observation, {})))
            if runner_ok is not None:
                rt.finish = lambda: {'tree_empty': True, 'runner_ok': runner_ok}
            if adapter is not None:
                stack.enter_context(patch.object(Adapter, 'observe', adapter))
            code = Batch(rt, chosen, ['engine', 'undefended'], header(rt)).execute()
            meta, rows = load_run(rt.evidence.directory.path)
            return code, meta, rows, rt.events

    def check_stopped(self, result):
        code, meta, rows, events = result
        self.assertEqual(code, 1)
        self.assertTrue(meta['cleanup_ok'])
        self.assertIsNotNone(meta['controller_error'])
        self.assertEqual(events.count('start-engine'), 1)
        self.assertNotIn('arm-undefended', events)
        self.assertEqual(len(rows[0]['attempts']), 1)
        self.assertIn('evidence', rows[0]['attempts'][0])
        for value in rows[1:]:
            self.assertEqual(value['outcome'], 'invalid')
            self.assertIn('not-started', value['attempts'][0]['invalid_reason'])

    def test_missing_observation_stops_remaining_repeats_and_cases(self):
        self.check_stopped(self.exercise(fail='collect', error=FileNotFoundError))

    def test_malformed_observation_stops_batch(self):
        self.check_stopped(self.exercise(fail='collect', error=ValueError))

    def test_nonzero_runner_stops_batch(self):
        self.check_stopped(self.exercise(runner_ok=False))

    def test_incomplete_observation_stops_batch(self):
        self.check_stopped(self.exercise(observation={'complete': False, 'control_ok': True,
                                                     'error': 'injected incomplete'}))

    def test_failed_control_stops_batch(self):
        self.check_stopped(self.exercise(observation={'complete': True, 'control_ok': False}))

    def test_external_fact_failure_stops_batch(self):
        original = Adapter.observe
        def missing(adapter, *args):
            result = original(adapter, *args)
            result['file']['external_fact'] = {}
            return result
        self.check_stopped(self.exercise(adapter=missing))

    def test_failure_record_survives_full_batch_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            chosen = cases(); rt = FakeRuntime(Path(tmp), chosen); patches(rt, stack)
            data = b'captured before timeout'
            def read(work, name, limit):
                if name == REQUEST:
                    return json_bytes(current['req'])
                if name.endswith('.capture'):
                    return data
                req = current['req']; capture = stem(req) + '-action-partial.capture'
                return json_bytes({'v': 1, 'attempt': stem(req), 'complete': False,
                    'error': {'type': 'TimeoutError', 'message': 'injected timeout'},
                    'control_ok': True, 'captures': [{'path': capture, 'phase': 'action',
                    'bytes': len(data), 'sha256': identity(data)['sha256']}]})
            current = {}
            def actual_collect(work, req, evidence):
                current['req'] = req
                return collect(work, req, evidence)
            stack.enter_context(patch('run_batch.collect', side_effect=actual_collect))
            stack.enter_context(patch('run_transport.read_beneath', side_effect=read))
            code = Batch(rt, chosen, ['engine', 'undefended'], header(rt)).execute()
            meta, rows = load_run(rt.evidence.directory.path)
            self.assertEqual(code, 1); self.assertTrue(meta['cleanup_ok'])
            self.assertEqual(rt.events.count('start-engine'), 1)
            receipt = json.loads((rt.evidence.directory.path / rows[0]['attempts'][0]['evidence']['file']).read_bytes())
            self.assertEqual(receipt['observation']['error']['message'], 'injected timeout')
            self.assertEqual(len(list(rt.evidence.directory.path.glob('raw-*.capture'))), 1)
            self.assertTrue(receipt['targets'][0]['external_fact'])
            self.assertEqual(receipt['targets'][0]['outcome'], 'invalid')
