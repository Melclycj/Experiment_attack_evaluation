"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cb_output import CountedRunDirectory, directory_class
from record import RunDirectory


class Counted(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name);self.run = CountedRunDirectory(self.root, '20261103T000000Z-counted')

    def test_total_tracks_writes_and_replacements_with_one_scan(self):
        with patch.object(self.run, 'size', wraps=self.run.size) as scans:
            for i in range(50):self.run.write(f'raw-{i:04}.json', b'123')
            self.run.write('raw-0000.json', b'1', replace=True)
        self.assertEqual(scans.call_count, 1)
        self.assertEqual(self.run.total, 148);self.assertEqual(self.run.size(), 148)

    def test_budget_is_still_enforced_on_every_write(self):
        self.run.limit = 10;self.run.write('a.json', b'123')
        for name, data, opts in [('b.json', b'12345678', {}), ('b.json', b'1', {'reserve': 7})]:
            with self.subTest(opts=opts), self.assertRaisesRegex(ValueError, 'budget'):
                self.run.write(name, data, **opts)
        self.run.write('b.json', b'1234567');self.assertEqual(self.run.total, 10)

    def test_foreign_entries_surface_at_the_next_rescan(self):
        self.run.write('a.json', b'1');(self.run.path / 'foreign.json').write_bytes(b'xyz')
        self.run.write('b.json', b'1');self.assertEqual(self.run.total, 2)
        self.assertEqual(self.run.rescan(), 5)
        (self.run.path / 'nested').mkdir()
        with self.assertRaises(ValueError):self.run.rescan()

    def test_unit_selects_the_class_and_the_base_scans_per_write(self):
        self.assertIs(directory_class('credential-binding'), CountedRunDirectory)
        self.assertIs(directory_class('no-bypass'), RunDirectory)
        base = RunDirectory(self.root, '20261103T000001Z-base')
        with patch.object(base, 'size', wraps=base.size) as scans:
            for i in range(5):base.write(f'r{i}.json', b'1')
        self.assertEqual(scans.call_count, 5)


if __name__ == '__main__':unittest.main()
