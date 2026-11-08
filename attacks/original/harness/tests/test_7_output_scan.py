"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import record


class OutputScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = record.RunDirectory(self.root, '20261101T070000Z-scan')

    def test_shared_ancestor_walk_is_constant_not_per_file(self):
        for i in range(303):
            (self.run.path / f'raw-{i:04}.json').write_bytes(b'123')
        with patch('record.plain_path', wraps=record.plain_path) as checked:
            self.assertEqual(self.run.size(), 909)
        self.assertEqual(checked.call_count, 2)
        self.assertTrue(all(c.args == (self.run.path,) for c in checked.call_args_list))

    def test_fresh_scan_counts_growth_addition_and_removal(self):
        f = self.run.path / 'raw.json'
        f.write_bytes(b'a')
        self.assertEqual(self.run.size(), 1)
        f.write_bytes(b'abcde')
        (self.run.path / 'more.json').write_bytes(b'ab')
        self.assertEqual(self.run.size(), 7)
        f.unlink()
        self.assertEqual(self.run.size(), 2)

    def test_budget_includes_actual_growth_reserve_and_replacement_temporary(self):
        self.run.limit = 10
        self.run.write('a.json', b'123')
        (self.run.path / 'a.json').write_bytes(b'1234567')
        for name, data, opts in [('b.json', b'1234', {}),
                                 ('b.json', b'1', {'reserve': 3}),
                                 ('a.json', b'1234', {'replace': True})]:
            with self.subTest(opts=opts), self.assertRaisesRegex(ValueError, 'budget'):
                self.run.write(name, data, **opts)
        self.assertEqual(list(self.run.path.iterdir()), [self.run.path / 'a.json'])
        self.assertEqual((self.run.path / 'a.json').read_bytes(), b'1234567')

    def test_directory_is_rejected(self):
        (self.run.path / 'nested').mkdir()
        with self.assertRaises(ValueError):
            self.run.size()

    def test_reparse_regular_entry_is_rejected_and_iterator_closed(self):
        entry = MagicMock()
        entry.stat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
            st_nlink=1, st_size=4, st_file_attributes=0x400)
        scan = MagicMock()
        scan.__enter__.return_value = iter([entry])
        with patch('record.os.scandir', return_value=scan), self.assertRaises(ValueError):
            self.run.size()
        entry.stat.assert_called_once_with(follow_symlinks=False)
        scan.__exit__.assert_called_once()

    def test_stat_failure_is_not_silently_skipped(self):
        entry = MagicMock()
        entry.stat.side_effect = FileNotFoundError('disappeared')
        scan = MagicMock()
        scan.__enter__.return_value = iter([entry])
        with patch('record.os.scandir', return_value=scan), self.assertRaises(FileNotFoundError):
            self.run.size()
        scan.__exit__.assert_called_once()

    def test_root_replacement_during_scan_fails_closed(self):
        original = record.os.scandir
        def replaced(path):
            path.rename(self.root / 'old-run')
            path.mkdir()
            return original(path)
        with patch('record.os.scandir', side_effect=replaced), self.assertRaises(ValueError):
            self.run.size()

    @unittest.skipUnless(os.name == 'posix', 'Linux link/FIFO semantics')
    def test_symlink_hardlink_and_fifo_entries_are_rejected(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'decoy')
        leaf = self.run.path / 'bad'
        for kind in ('symlink', 'hardlink', 'fifo'):
            if kind == 'symlink':
                leaf.symlink_to(outside)
            elif kind == 'hardlink':
                os.link(outside, leaf)
            else:
                os.mkfifo(leaf)
            try:
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    self.run.size()
            finally:
                leaf.unlink()

    @unittest.skipUnless(os.name == 'posix', 'Linux symlink semantics')
    def test_empty_root_and_ancestor_symlinks_are_rejected(self):
        original = self.run.path
        target = self.root / 'target'
        target.mkdir()
        original.rmdir()
        original.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.run.size()
        original.unlink()
        alias = self.root / 'alias'
        alias.symlink_to(target, target_is_directory=True)
        (target / 'run').mkdir()
        self.run.path = alias / 'run'
        with self.assertRaises(ValueError):
            self.run.size()


if __name__ == '__main__':
    unittest.main()
