"""离线回归：NB-20有效捕获先于诊断质量；无真实凭据、进程或网络。"""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
from case_io import capture
from common import identity
from engine_observe import file_fact
from foura_fixtures import receipt
from judge import classify_target


class CaptureQuality(unittest.TestCase):
    def fixture(self, key='truth', data=None):
        marker = 'nb-decoy-' + 'x' * 48
        data = marker.encode() if data is None else data
        before = {'dev': 1, 'ino': 2, **identity(marker.encode())}
        obj = NS(path=Path('/offline/nb-decoy/' + key), before=before,
                 read=lambda: (marker.encode(), dict(before)))
        adapter = NS(attack='NB-20', files={key: obj},
                     rt=NS(work=Path('/offline/nb-decoy-work'),
                           evidence=NS(raw=lambda *a, **k: {'file': 'mock-only'})))
        p = {'config': 'engine', 'tokens': {key: marker},
             'parameters': {'controls': {key: 'nb-decoy-control'},
                            'control_sentinel': 'nb-decoy-control'}}
        obs, caps = {'observed': []}, {}
        receipt(obs, caps, key, data)
        return adapter, p, obs, caps

    def result(self, fixture, key='truth'):
        a, p, obs, caps = fixture
        return file_fact(a, p, obs, caps, [], key)

    def test_missing_action_diagnostic_preserves_truth_and_metadata(self):
        for key in ('truth', 'metadata'):
            with self.subTest(key=key):
                fixture = self.fixture(key)
                self.assertIn(fixture[1]['tokens'][key].encode(), capture(fixture[2], fixture[3], key))
                fact = self.result(fixture, key)
                self.assertTrue(fact['external_effect'])
                self.assertTrue(fact['external_fact']['capture_sentinel'])
                self.assertIn('missing/duplicate observation', fact['invalid_reason'])

    def test_missing_control_diagnostic_cannot_hide_verified_action(self):
        f = self.fixture()
        with patch('engine_observe.file_call', side_effect=[{'errno': 0}, ValueError('bad control')]):
            fact = self.result(f)
        self.assertTrue(fact['external_effect'])
        self.assertEqual(fact['invalid_reason'], 'bad control')

    def test_malformed_native_stream_cannot_hide_verified_action(self):
        f = self.fixture()
        with patch('engine_observe.file_call', side_effect=ValueError('incomplete diagnostic')):
            self.assertTrue(self.result(f)['external_effect'])

    def test_invalid_quality_is_not_promoted_to_success(self):
        fact = self.result(self.fixture())
        fact.pop('prerequisite_ok')
        value = classify_target(**fact, target_verified=True, complete=False)
        self.assertEqual(value['outcome'], 'invalid')
        self.assertTrue(value['external_effect'])

    def test_bad_digest_never_proves_leak(self):
        f = self.fixture(); f[2]['captures'][0]['sha256'] = '0' * 64
        self.assertFalse(self.result(f)['external_effect'])

    def test_bad_length_never_proves_leak(self):
        f = self.fixture(); f[2]['captures'][0]['bytes'] += 1
        self.assertFalse(self.result(f)['external_effect'])

    def test_wrong_phase_never_proves_action_leak(self):
        f = self.fixture(); f[2]['captures'][0]['phase'] = 'control'
        self.assertFalse(self.result(f)['external_effect'])

    def test_wrong_label_never_proves_target_leak(self):
        f = self.fixture(); f[2]['captures'][0]['label'] = 'metadata'
        self.assertFalse(self.result(f)['external_effect'])

    def test_duplicate_receipt_never_proves_leak(self):
        f = self.fixture(); f[2]['captures'].append(deepcopy(f[2]['captures'][0]))
        self.assertFalse(self.result(f)['external_effect'])

    def test_missing_receipt_cannot_borrow_unbound_bytes(self):
        f = self.fixture(); f[2]['captures'] = []
        self.assertFalse(self.result(f)['external_effect'])

    def test_missing_archived_bytes_never_proves_leak(self):
        f = self.fixture(); f[3].clear()
        self.assertFalse(self.result(f)['external_effect'])

    def test_host_read_of_sentinel_is_not_itself_a_leak(self):
        self.assertFalse(self.result(self.fixture(data=b''))['external_effect'])

    def test_no_sentinel_in_valid_capture_is_no_candidate(self):
        self.assertFalse(self.result(self.fixture(data=b'unrelated data'))['external_effect'])

    def test_failed_host_snapshot_does_not_erase_verified_capture(self):
        f = self.fixture()
        f[0].files['truth'].read = lambda: (_ for _ in ()).throw(ValueError('pin gone'))
        with patch('engine_observe.snapshot', return_value={'exists': False}):
            self.assertTrue(self.result(f)['external_effect'])


if __name__ == '__main__':
    unittest.main()
