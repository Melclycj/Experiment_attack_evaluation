"""离线回归：完整运行必须绑定所有原始证据及元数据引用，不启动任何被测程序。"""
import json
from pathlib import Path
import tempfile
import unittest

from common import identity, json_bytes
from fixtures import header, row
from record import RunDirectory, load_run
from run_evidence import Evidence


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = RunDirectory(Path(temp.name), '20261031T030000Z-test')
        self.ref = Evidence(self.directory).raw(b'original capture', 'capture')
        self.header = header(commands=[{'stdout': self.ref}])

    def finish(self):
        return self.directory.finalize(self.header, [row(), row('undefended')])

    def test_manifest_covers_raw_and_metadata(self):
        self.finish()
        manifest = json.loads((self.directory.path / 'COMPLETE.json').read_bytes())
        self.assertEqual(manifest['files'][self.ref['file']], identity(b'original capture'))
        self.assertEqual(set(manifest['files']),
                         {p.name for p in self.directory.path.iterdir()} - {'COMPLETE.json'})
        load_run(self.directory.path)

    def test_deleted_raw_rejected(self):
        self.finish()
        (self.directory.path / self.ref['file']).unlink()
        with self.assertRaises((ValueError, FileNotFoundError)):
            load_run(self.directory.path)

    def test_same_size_raw_tamper_rejected(self):
        self.finish()
        (self.directory.path / self.ref['file']).write_bytes(b'modified capture')
        with self.assertRaises(ValueError):
            load_run(self.directory.path)

    def test_raw_missing_before_finalize_rejected(self):
        (self.directory.path / self.ref['file']).unlink()
        with self.assertRaises(ValueError):
            self.finish()
        self.assertFalse((self.directory.path / 'COMPLETE.json').exists())

    def test_reference_digest_must_match_archived_bytes(self):
        self.header['commands'][0]['stdout'] = {**self.ref, **identity(b'wrong bytes')}
        with self.assertRaises(ValueError):
            self.finish()

    def test_attempt_reference_checked_too(self):
        value = row()
        value['attempts'][0]['evidence'] = {**self.ref, 'file': 'raw-missing.json'}
        with self.assertRaises(ValueError):
            self.directory.finalize(header(), [value])

    def test_unreferenced_raw_is_bound_too(self):
        self.header['commands'] = []
        self.finish()
        (self.directory.path / self.ref['file']).write_bytes(b'changed')
        with self.assertRaises(ValueError):
            load_run(self.directory.path)

    def test_unlisted_file_rejected(self):
        self.finish()
        (self.directory.path / 'extra.txt').write_bytes(b'extra')
        with self.assertRaises(ValueError):
            load_run(self.directory.path)

    def test_old_metadata_only_manifest_is_not_verified(self):
        self.finish()
        path = self.directory.path / 'COMPLETE.json'
        manifest = json.loads(path.read_bytes())
        manifest.pop('coverage', None)
        manifest['files'].pop(self.ref['file'], None)
        path.write_bytes(json_bytes(manifest))
        (self.directory.path / self.ref['file']).unlink()
        with self.assertRaises(ValueError):
            load_run(self.directory.path)

    def test_manifest_cannot_read_outside_run(self):
        self.finish()
        path = self.directory.path / 'COMPLETE.json'
        manifest = json.loads(path.read_bytes())
        manifest['files']['../outside'] = identity(b'outside')
        path.write_bytes(json_bytes(manifest))
        with self.assertRaises(ValueError):
            load_run(self.directory.path)
