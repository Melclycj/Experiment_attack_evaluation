"""这是 1.1 隔离论证的验证测试：启动门人工恢复的临时文件/mock回归，不启动批次。"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from common import identity, json_bytes

FAILED = {'ok': False, 'retained': [], 'steps': [
    {'step': 'stop-engine-and-wait-spawner', 'ok': True, 'detail': None},
    {'step': 'remove:/var/lib/nb-decoy-offline', 'ok': True, 'detail': None}],
    'failures': [{'step': 'controller-handles', 'error': 'spawner reported failed shutdown: wait status 9'}]}
CLEAN = {'ok': True, 'retained': [], 'failures': [], 'steps': []}
MARKER = b'{"cleanup_verified":false,"error":"snapshot cleanup: batch cleanup still unverified; gate retained"}'
FORCED_MARKER = b'{"cleanup_verified":false,"error":"forced/incomplete controller; cleanup unverified"}'
# run_recover.residue's full check set for the run whose snapshot token is 'offline'.
CHECKS = [{'object': '/var/lib/nb-decoy-offline', 'check': 'path-absent', 'ok': True},
          {'object': '/tmp/nb-decoy-boot-offline', 'check': 'path-absent', 'ok': True},
          {'object': '/sys/fs/cgroup/nb-decoy-offline', 'check': 'cgroup-absent', 'ok': True},
          *[{'object': 'host', 'check': name, 'ok': True} for name in (
              'no-nb-decoy-cgroup', 'no-nb-decoy-directory', 'no-mount-beneath-run-roots',
              'no-backing-file-from-run', 'no-task-with-run-uids', 'no-new-crash-entries')]]


def archive(root, cleanup=FAILED, marker=True):
    """A real finalized offline CB archive, with the launcher marker when cleanup failed."""
    from cb_batch import CredentialBatch
    from cb_pipeline_fixtures import Runtime, cases, header, patches
    found = cases(['CB-10:api-key-302']);chosen = [found['CB-10'], found['PC-CREDENTIAL']]
    with ExitStack() as stack:
        rt = Runtime(root, chosen);patches(rt, stack)
        rt.close = lambda: dict(cleanup)
        CredentialBatch(rt, chosen, ['engine', 'undefended'], header(rt)).execute()
    path = rt.evidence.directory.path
    if marker:(path / 'LAUNCHER-FAILED.json').write_bytes(MARKER)
    return path


def forced_run(runs, name='20261103T000500Z-forced'):
    path = runs / name;path.mkdir(parents=True)
    (path / 'raw-0001.json').write_bytes(b'{}');(path / 'LAUNCHER-FAILED.json').write_bytes(FORCED_MARKER)
    return path


class LoadRunPin(unittest.TestCase):
    def test_marker_blocks_unless_its_exact_bytes_are_pinned(self):
        from record import load_run
        with tempfile.TemporaryDirectory() as tmp:
            path = archive(Path(tmp))
            with self.assertRaisesRegex(ValueError, 'outer launcher'):load_run(path)
            with self.assertRaisesRegex(ValueError, 'outer launcher'):load_run(path, launcher_failed=identity(b'other'))
            header, _ = load_run(path, launcher_failed=identity(MARKER))
            self.assertFalse(header['cleanup_ok'])
            (path / 'results.md').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'modified'):load_run(path, launcher_failed=identity(MARKER))


class Accepted(unittest.TestCase):
    def setUp(self):
        import run_gate
        self.g = run_gate;self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'runs' / '20261103T000000Z-offline';self.path.mkdir(parents=True)
        (self.path / 'COMPLETE.json').write_bytes(b'{}')
        self.header = {'run': self.path.name, 'cleanup': FAILED, 'cleanup_ok': False}

    def record(self, **change):
        return {'schema': self.g.RECOVERY, 'run': self.path.name, 'approved_by_user': '2026-11-03',
                'cleanup': identity(json_bytes(FAILED)), 'completion': identity(b'{}'), 'checks': CHECKS, **change}

    def test_rule_needs_this_cleanup_archive_approval_and_clean_checks(self):
        self.assertTrue(self.g.recovered(self.record(), self.path, self.header))
        for change in ({'approved_by_user': ''}, {'approved_by_user': 'yes'}, {'checks': []},
                       {'checks': [{**CHECKS[0], 'ok': False}]}, {'completion': identity(b'x')},
                       {'cleanup': identity(b'x')}):
            with self.subTest(change=change):self.assertFalse(self.g.recovered(self.record(**change), self.path, self.header))
        retained = {**self.header, 'cleanup': {**FAILED, 'retained': ['/var/lib/nb-decoy-offline']}}
        self.assertFalse(self.g.recovered(self.record(cleanup=identity(json_bytes(retained['cleanup']))), self.path, retained))
        self.assertFalse(self.g.recovered(self.record(), self.path, {**self.header, 'run': 'other'}))

    def test_record_lives_beside_runs_and_must_name_its_run(self):
        target = self.g.recovery_path(self.path)
        self.assertEqual(target, Path(self.tmp.name) / 'recoveries' / (self.path.name + '.json'))
        self.assertIsNone(self.g.recovery(self.path))
        target.parent.mkdir();target.write_bytes(json_bytes(self.record(run='other')))
        with self.assertRaisesRegex(ValueError, 'malformed'):self.g.recovery(self.path)


@unittest.skipUnless(os.name == 'posix', 'Linux advisory lock/fsync gate in temporary files only')
class GateCase(unittest.TestCase):
    def setUp(self):
        import run_gate
        self.g = run_gate;self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name);self.state = self.root / 'state'
        p = patch.object(run_gate, 'STATE', self.state);p.start();self.addCleanup(p.stop)

    def lock(self, path):
        bundle = {'repo': str(self.root / 'repo'), 'run': path.name, 'root': str(self.root / 'nb-decoy-boot-offline'),
                  'root_identity': [1, 2], 'output': str(path)}
        bundle['gate'] = self.g.claim(bundle['repo'], bundle['run']);self.g.bind(bundle)
        self.bundle = bundle
        return json.loads((self.state / 'active.json').read_bytes())

    def record(self, path, lease, header=None, checks=CHECKS, token=None):
        from run_recover import build_record
        return build_record(path, 'credential-binding', header, {**lease, 'token': token or lease['token']},
                            checks, '2026-11-03')


class Release(GateCase):
    def setUp(self):
        super().setUp();self.path = archive(self.root);self.lease = self.lock(self.path)
        self.header = json.loads((self.path / 'run.json').read_bytes())

    def test_failed_cleanup_history_refused_until_recovered(self):
        runs = self.path.parent
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(runs)
        self.g.release_recovered(self.path, self.record(self.path, self.lease, self.header))
        self.assertFalse((self.state / 'active.json').exists())
        receipt = json.loads((self.state / 'last-clean.json').read_bytes())
        self.assertEqual(receipt['run'], self.path.name);self.assertIn('recovery', receipt)
        (entry,) = self.g.check_history(runs);self.assertIn('recovery', entry)
        self.g.claim('/next', 'next')  # the latch is open again

    def test_refusals_keep_the_latch_and_write_no_record(self):
        target = self.g.recovery_path(self.path)
        for record in (self.record(self.path, self.lease, self.header, token='0' * 64),
                       self.record(self.path, self.lease, self.header, checks=[{**CHECKS[0], 'ok': False}]),
                       {**self.record(self.path, self.lease, self.header), 'approved_by_user': ''}):
            with self.subTest(record=record['gate']['token'][:4]):
                with self.assertRaises(RuntimeError):self.g.release_recovered(self.path, record)
                self.assertTrue((self.state / 'active.json').exists());self.assertFalse(target.exists())
        Path(self.bundle['root']).mkdir()
        with self.assertRaisesRegex(RuntimeError, 'snapshot'):
            self.g.release_recovered(self.path, self.record(self.path, self.lease, self.header))
        self.assertTrue((self.state / 'active.json').exists())

    def test_tampered_record_or_archive_refused_by_history(self):
        self.g.release_recovered(self.path, self.record(self.path, self.lease, self.header))
        target = self.g.recovery_path(self.path);data = json.loads(target.read_bytes())
        target.write_bytes(json_bytes({**data, 'checks': [{**CHECKS[0], 'ok': False}]}))
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(self.path.parent)
        target.write_bytes(json_bytes(data));self.g.check_history(self.path.parent)
        (self.path / 'LAUNCHER-FAILED.json').write_bytes(b'{}')
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(self.path.parent)


class Forced(GateCase):
    def setUp(self):
        super().setUp();self.path = forced_run(self.root / 'runs');self.lease = self.lock(self.path)

    def test_forced_run_recovers_without_an_archive(self):
        runs = self.path.parent
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(runs)
        record = self.record(self.path, self.lease)
        self.assertEqual(record['kind'], self.g.FORCED);self.assertNotIn('completion', record)
        self.g.release_recovered(self.path, record)
        self.assertFalse((self.state / 'active.json').exists())
        (entry,) = self.g.check_history(runs);self.assertIsNone(entry['archive'])

    def test_forced_record_needs_its_marker_and_no_archive(self):
        self.g.release_recovered(self.path, self.record(self.path, self.lease))
        (self.path / 'LAUNCHER-FAILED.json').write_bytes(b'{}')
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(self.path.parent)
        (self.path / 'LAUNCHER-FAILED.json').write_bytes(FORCED_MARKER);self.g.check_history(self.path.parent)
        (self.path / 'COMPLETE.json').write_bytes(b'{}')
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(self.path.parent)


class Receipts(GateCase):
    def test_second_check_reads_only_deciding_files_and_any_change_reverifies(self):
        path = archive(self.root, cleanup=CLEAN, marker=False);runs = path.parent
        with patch.object(self.g, 'load_run', wraps=self.g.load_run) as full:
            self.g.check_history(runs, receipts=True);self.assertEqual(full.call_count, 1)
            (entry,) = self.g.check_history(runs, receipts=True);self.assertEqual(full.call_count, 1)
            self.assertTrue(entry['receipt'])
            self.g.check_history(runs);self.assertEqual(full.call_count, 2)  # receipts off: always full
        saved = self.state / 'verified' / path.parent.parent.name / (path.name + '.json')
        self.assertEqual(oct(saved.stat().st_mode & 0o777), '0o600')
        header = json.loads((path / 'run.json').read_bytes())
        (path / 'run.json').write_bytes(json_bytes({**header, 'cleanup_ok': True, 'extra': 1}))
        with self.assertRaisesRegex(RuntimeError, 'prior cleanup'):self.g.check_history(runs, receipts=True)


class ReleaseReceipt(GateCase):
    def test_outer_release_of_a_2_3_batch_leaves_a_receipt(self):
        path = archive(self.root, cleanup=CLEAN, marker=False);self.lock(path)
        self.bundle['unit'] = 'credential-binding';Path(self.bundle['root']).mkdir(exist_ok=True);Path(self.bundle['root']).rmdir()
        self.g.release(self.bundle)
        self.assertFalse((self.state / 'active.json').exists())
        with patch.object(self.g, 'load_run', wraps=self.g.load_run) as full:
            (entry,) = self.g.check_history(path.parent, receipts=True)
        self.assertEqual(full.call_count, 0);self.assertTrue(entry['receipt'])

    def test_1_1_release_leaves_a_receipt_too(self):
        # 2026-11-06: 1.1 checks history by receipt as 2.3 does; its bundle carries no 'unit' key.
        path = archive(self.root, cleanup=CLEAN, marker=False);self.lock(path)
        self.assertNotIn('unit', self.bundle)
        self.g.release(self.bundle)
        with patch.object(self.g, 'load_run', wraps=self.g.load_run) as full:
            (entry,) = self.g.check_history(path.parent, receipts=True)
        self.assertEqual(full.call_count, 0);self.assertTrue(entry['receipt'])


class Residue(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name);self.root = root;crash = root / 'crash';crash.mkdir()
        from host import crash_inventory
        self.header = {'cleanup': {'steps': [{'step': 'remove:' + str(root / 'deploy')},
                                             {'step': 'verify-loop:' + str(root / 'deploy' / 'a.btrfs')}]},
                       'host': {'capacity': {'first': 70000, 'last': 70014}, 'crash_directory': str(crash),
                                'crashes': crash_inventory(crash)}}
        self.lease = {'root': str(root / 'nb-decoy-boot-tok1'), 'started_at': '2026-11-03T00:00:00+00:00'}
        self.kw = {'cgroup_parent': root / 'cg', 'mounts': ['/', '/mnt/d', '/var/lib/nb-decoy-harness-gate'],
                   'loops': ['/var/lib/other.img'], 'uids': [0, 1000, 70998 - 1000], 'listing': [], 'cgroups': []}

    def failing(self, objects=None, **change):
        from run_recover import archived_objects, residue
        objects = objects or archived_objects(self.header, self.lease)
        return [c['check'] for c in residue(objects, **{**self.kw, **change}) if not c['ok']]

    def test_all_absent_is_clean(self):
        self.assertEqual(self.failing(), [])

    def test_each_residue_is_reported(self):
        self.assertEqual(self.failing(mounts=[str(self.root / 'deploy' / 'work0')]), ['no-mount-beneath-run-roots'])
        self.assertEqual(self.failing(mounts=['/var/lib/nb-decoy-xyz/work0']), ['no-mount-beneath-run-roots'])
        self.assertEqual(self.failing(loops=['/tmp/nb-decoy-xyz/a.btrfs']), ['no-backing-file-from-run'])
        for uid in (70000, 70014, 70998, 70999):
            self.assertEqual(self.failing(uids=[uid]), ['no-task-with-run-uids'])
        self.assertEqual(self.failing(cgroups=['nb-decoy-other']), ['no-nb-decoy-cgroup'])
        self.assertEqual(self.failing(listing=['/tmp/nb-decoy-other']), ['no-nb-decoy-directory'])
        (self.root / 'cg' / 'nb-decoy-tok1').mkdir(parents=True)
        self.assertEqual(self.failing(), ['cgroup-absent'])
        (self.root / 'nb-decoy-boot-tok1').mkdir();(self.root / 'deploy').mkdir()
        self.assertEqual(self.failing().count('path-absent'), 2)
        (Path(self.header['host']['crash_directory']) / 'wsl-crash-1.dmp').write_bytes(b'core')
        self.assertIn('no-new-crash-entries', self.failing())

    def test_cgroup_is_named_by_the_snapshot_token_not_the_label(self):
        from run_recover import archived_objects
        self.assertEqual(archived_objects(self.header, self.lease)['token'], 'tok1')
        (self.root / 'cg' / 'nb-decoy-offline').mkdir(parents=True)  # a label-named path is not the run cgroup
        self.assertEqual(self.failing(cgroups=[]), [])

    def test_forced_objects_from_token_and_crash_entries_since_start(self):
        from run_recover import forced_objects
        objects = forced_objects(self.lease, self.header['host']['crash_directory'])
        self.assertEqual(objects['roots'], ['/var/lib/nb-decoy-tok1', '/tmp/nb-decoy-tok1', '/tmp/nb-decoy-build-tok1'])
        old = Path(self.header['host']['crash_directory']) / 'old.dmp';old.write_bytes(b'x')
        os.utime(old, (1_700_000_000, 1_700_000_000))  # before the batch start
        self.assertEqual(self.failing(objects), [])
        (Path(self.header['host']['crash_directory']) / 'new.dmp').write_bytes(b'x')
        self.assertEqual(self.failing(objects), ['no-new-crash-entries'])

    def test_unknown_roots_or_snapshot_stop_instead_of_guessing(self):
        from run_recover import archived_objects, run_token
        with self.assertRaisesRegex(ValueError, 'inspect by hand'):
            archived_objects({**self.header, 'cleanup': {'steps': []}}, self.lease)
        with self.assertRaisesRegex(ValueError, 'inspect by hand'):run_token('/tmp/other')


class Command(unittest.TestCase):
    def test_writing_needs_root_a_valid_run_and_an_approval_date(self):
        from run_recover import main
        with patch('run_recover.os.geteuid', return_value=0), patch('run_recover.os.name', 'posix'):
            with self.assertRaisesRegex(ValueError, 'invalid run'):
                main(['--repo', '/r', '--unit', 'credential-binding', '--run', '../x', '--approved-by-user', '2026-11-03'])
            with self.assertRaisesRegex(ValueError, 'approved-by-user'):
                main(['--repo', '/r', '--unit', 'credential-binding', '--run', '20261103T000000Z-offline'])
        with patch('run_recover.os.geteuid', return_value=1000), patch('run_recover.os.name', 'posix'):
            with self.assertRaisesRegex(RuntimeError, 'WSL root'):
                main(['--repo', '/r', '--unit', 'credential-binding', '--run', '20261103T000000Z-offline', '--check-only'])


if __name__ == '__main__':unittest.main()
