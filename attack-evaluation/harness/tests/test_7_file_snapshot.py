"""Offline NB-12 regression: complete seeded snapshots, pinned fresh enumeration.

Only temporary files; no engine, attack process, socket, namespace or mount.
"""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from file_cases import FileCase
from file_tree import FileTree
from fourb_fixtures import temporary_runtime, prepare


@unittest.skipUnless(os.name == 'posix', 'Linux pinned-directory semantics')
class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nb-decoy-snapshot-')
        self.addCleanup(self.temp.cleanup)
        self.rt = temporary_runtime(Path(self.temp.name))
        for name in ('file_tree.os.fchown', 'file_tree.os.chown'):
            p = patch(name); p.start(); self.addCleanup(p.stop)
        for name in ('subprocess.Popen', 'socket.socket', 'os.system'):
            p = patch(name, side_effect=AssertionError('offline only'))
            p.start(); self.addCleanup(p.stop)

    def tree(self):
        tree = FileTree(self.rt, self.rt.work, 'nb-decoy-snapshot')
        self.addCleanup(tree.close)
        tree.write('nested/key', b'owned')
        return tree

    def test_scan_uses_fresh_descriptor_not_persistent_directory_stream(self):
        tree = self.tree()
        pinned = {f.fd for f in tree.dirs.values()}
        original = os.listdir
        seen = []
        def listdir(fd):
            seen.append(fd)
            # Fault model for the observed stale stream, not a kernel diagnosis.
            return [] if fd in pinned else original(fd)
        with patch('file_tree.os.listdir', side_effect=listdir):
            result = tree.scan()
        self.assertIn('nested/key', result)
        self.assertEqual(result['.']['names'], ['nested'])
        self.assertFalse(pinned.intersection(seen))
        for fd in set(seen):
            with self.assertRaises(OSError): os.fstat(fd)

    def test_repeated_scans_include_newly_created_entries(self):
        tree = self.tree()
        for number in range(8):
            tree.scan()
            tree.write('nested/key-' + str(number), b'fresh')
            result = tree.scan()
            tree.validate_seeded(result)
            self.assertIn('nested/key-' + str(number), result)

    def test_seed_validation_rejects_missing_snapshot_or_name(self):
        tree = self.tree()
        original = tree.scan()
        for kind in ('entry', 'name', 'exists', 'extra'):
            with self.subTest(kind=kind):
                result = copy.deepcopy(original)
                if kind == 'entry': del result['nested/key']
                if kind == 'name': result['nested']['names'] = []
                if kind == 'exists': result['nested/key']['exists'] = False
                if kind == 'extra': result['unexpected'] = {'exists': True}
                with self.assertRaisesRegex(ValueError, 'seeded snapshot'):
                    tree.validate_seeded(result)

    def test_scan_still_reports_unknown_addition_and_restore_retains_it(self):
        tree = self.tree()
        extra = tree.root / 'unknown'; extra.write_bytes(b'not ours')
        self.assertIn('unknown', tree.scan())
        with self.assertRaisesRegex(ValueError, 'unowned addition'): tree.restore()
        self.assertTrue(extra.exists())

    def test_scan_rejects_directory_identity_replacement(self):
        tree = self.tree()
        (tree.root / 'nested').rename(tree.root / 'original')
        (tree.root / 'nested').mkdir()
        with self.assertRaisesRegex(ValueError, 'replaced'): tree.scan()

    def test_prepare_rejects_incomplete_before_and_cleans_exact_owned_tree(self):
        adapter = FileCase(self.rt, 'NB-12')
        scan = FileTree.scan
        def incomplete(tree):
            result = scan(tree)
            if 'nb-decoy-key' in result:
                del result['nb-decoy-key']
                result['.']['names'] = []
            return result
        # Only the first two scans are preparation; restore must see real data.
        count = 0
        def once(tree):
            nonlocal count
            count += 1
            return incomplete(tree) if count <= 2 else scan(tree)
        try:
            with patch.object(FileTree, 'scan', once):
                with self.assertRaisesRegex(ValueError, 'seeded snapshot'):
                    prepare(adapter)
            self.assertFalse(adapter.trees)
            self.assertFalse(adapter.registered)
        finally:
            if adapter.trees: adapter.restore(None)

    def test_prepare_complete_alias_snapshot_matches_both_targets(self):
        adapter = FileCase(self.rt, 'NB-12')
        prepared = prepare(adapter)
        try:
            outer = prepared['before']['trees'][1]
            self.assertEqual(outer['.']['names'], ['nb-decoy-key'])
            for target in prepared['before']['targets'].values():
                self.assertEqual(outer['nb-decoy-key'], target)
        finally:
            adapter.restore(prepared)
