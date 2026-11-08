"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Cold-audit findings 7 and 8 (2026-11-04): a history receipt binds every file of the
# archive, and a recovery record is accepted only with the full residue check set about
# the run's own objects (or, for a record older than that set, a later global check).
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from common import identity, json_bytes
import test_6b_gate_recovery as gate

LABEL_CGROUP = [{**c, 'object': '/sys/fs/cgroup/nb-decoy-cb10-selfcheck'} if c['check'] == 'cgroup-absent' else c
                for c in gate.CHECKS]
LEGACY = [c for c in LABEL_CGROUP if c['check'] not in ('no-nb-decoy-cgroup', 'no-nb-decoy-directory')]


class Acceptance(unittest.TestCase):
    def setUp(self):
        import run_gate
        self.g = run_gate;self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'runs' / '20261103T000000Z-offline';self.path.mkdir(parents=True)
        (self.path / 'COMPLETE.json').write_bytes(b'{}')
        self.header = {'run': self.path.name, 'cleanup': gate.FAILED, 'cleanup_ok': False}

    def record(self, checks, run=None):
        return {'schema': self.g.RECOVERY, 'run': run or self.path.name, 'approved_by_user': '2026-11-03',
                'cleanup': identity(json_bytes(gate.FAILED)), 'completion': identity(b'{}'), 'checks': checks}

    def test_any_all_ok_list_is_not_enough(self):
        self.assertTrue(self.g.recovered(self.record(gate.CHECKS), self.path, self.header))
        for name, checks in {'bare': [{'ok': True}], 'label-cgroup': LABEL_CGROUP,
                             'no-global': [c for c in gate.CHECKS if c['check'] != 'no-nb-decoy-directory'],
                             'root-unchecked': [c for c in gate.CHECKS if c['object'] != '/var/lib/nb-decoy-offline']}.items():
            with self.subTest(name=name):
                self.assertFalse(self.g.recovered(self.record(checks), self.path, self.header))

    def test_images_are_checked_but_never_mistaken_for_the_token(self):
        image = '/tmp/nb-decoy-offline/nb-decoy-runtime.btrfs'
        cleanup = {**gate.FAILED, 'steps': [*gate.FAILED['steps'], {'step': 'verify-loop:' + image, 'ok': True}]}
        header = {**self.header, 'cleanup': cleanup}
        record = {**self.record(gate.CHECKS), 'cleanup': identity(json_bytes(cleanup))}
        self.assertFalse(self.g.recovered(record, self.path, header))  # the image was never checked absent
        record['checks'] = [*gate.CHECKS, {'object': image, 'check': 'path-absent', 'ok': True}]
        self.assertTrue(self.g.recovered(record, self.path, header))

    def test_old_record_is_covered_only_by_a_later_global_check(self):
        folder = self.g.recovery_path(self.path).parent;folder.mkdir()
        earlier = folder / '20261102T000000Z-earlier.json'
        earlier.write_bytes(json_bytes(self.record(gate.CHECKS, run='20261102T000000Z-earlier')))
        self.assertFalse(self.g.recovered(self.record(LEGACY), self.path, self.header))
        later = folder / '20261104T000000Z-later.json'
        later.write_bytes(json_bytes(self.record([{**c, 'ok': False} if c['check'] == 'no-nb-decoy-cgroup' else c
                                                  for c in gate.CHECKS], run='20261104T000000Z-later')))
        self.assertFalse(self.g.recovered(self.record(LEGACY), self.path, self.header))
        later.write_bytes(json_bytes(self.record(gate.CHECKS, run='20261104T000000Z-later')))
        self.assertTrue(self.g.recovered(self.record(LEGACY), self.path, self.header))
        self.assertEqual(self.g.superseded(self.path), '20261104T000000Z-later')


@unittest.skipUnless(os.name == 'posix', 'Linux advisory lock/fsync gate in temporary files only')
class Receipt(unittest.TestCase):
    def setUp(self):
        import run_gate
        self.g = run_gate;self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        p = patch.object(run_gate, 'STATE', self.root / 'state');p.start();self.addCleanup(p.stop)

    def test_changed_evidence_file_voids_the_receipt(self):
        path = gate.archive(self.root, cleanup=gate.CLEAN, marker=False);runs = path.parent
        self.g.check_history(runs, receipts=True)
        (entry,) = self.g.check_history(runs, receipts=True);self.assertTrue(entry['receipt'])
        raw = sorted(path.glob('raw-*'))[0];data = raw.read_bytes()
        raw.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))  # same size, new content and mtime
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(runs, receipts=True)

    def test_added_file_voids_the_receipt_and_full_check_runs(self):
        path = gate.archive(self.root, cleanup=gate.CLEAN, marker=False);runs = path.parent
        self.g.check_history(runs, receipts=True)
        (path / 'results.md.bak').write_bytes(b'x')
        with patch.object(self.g, 'load_run', wraps=self.g.load_run) as full:
            try:self.g.check_history(runs, receipts=True)
            except RuntimeError:pass
        self.assertEqual(full.call_count, 1)


class Killed(gate.GateCase):
    """2026-11-04 cbfix-b1: a WSL instance restart killed controller and outer launcher
    together; the run has neither archive header nor launcher marker."""
    def setUp(self):
        super().setUp()
        self.path = self.root / 'runs' / '20261103T175513Z-killed';self.path.mkdir(parents=True)
        (self.path / 'raw-0001.json').write_bytes(b'{}')
        self.lease = self.lock(self.path)

    def test_marked_then_recovered_like_a_forced_run(self):
        from run_recover import mark_killed
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(self.path.parent)
        mark_killed(self.path)
        marker = json.loads((self.path / 'LAUNCHER-FAILED.json').read_bytes())
        self.assertFalse(marker['cleanup_verified']);self.assertIn('killed', marker['error'])
        record = self.record(self.path, self.lease)
        self.assertEqual(record['kind'], self.g.FORCED)
        self.g.release_recovered(self.path, record)
        self.assertFalse((self.state / 'active.json').exists())
        (entry,) = self.g.check_history(self.path.parent);self.assertIsNone(entry['archive'])

    def test_never_marks_a_run_with_header_completion_or_marker(self):
        from run_recover import mark_killed
        for name in ('run.json', 'COMPLETE.json', 'LAUNCHER-FAILED.json'):
            (self.path / name).write_bytes(b'{}')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'not the killed-unmarked case'):
                mark_killed(self.path)
            (self.path / name).unlink()


if __name__ == '__main__':
    unittest.main()
