"""纯临时文件与 mock：确定性截住 link/unlink 窗口，不运行 engine 或建立监听。"""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nb_io import Files as CellFiles, PublicationPending as CellPending
from cell.nb_io import Files as HostFiles, PublicationPending as HostPending
from nb_support import Mailbox, auxiliary
from support_rows import SupportRows
from run_transport import publish
from test_4a_support import context, command
from foura_fixtures import NONCE, Clock


def box_with(files):
    with patch('nb_support.Files', return_value=files):
        return Mailbox(context('auxiliary'), 'auxiliary')


def host_with(files):
    support = SupportRows.__new__(SupportRows)
    support.rt = Mock()
    support.items = {'auxiliary': {'files': files, 'nonce': NONCE, 'records': [], 'ref': Mock()}}
    clock = Clock()
    support.rt.command.deadline.left.side_effect = lambda timeout: timeout
    support.rt.command.pump.side_effect = clock.sleep
    return support, clock


class MailboxRetryTests(unittest.TestCase):
    def test_pending_does_not_advance_sequence_or_decode_content(self):
        files = Mock()
        files.read.side_effect = [CellPending('pending'), command(0, 'stop')]
        box = box_with(files)
        self.assertIsNone(box.next())
        self.assertEqual(box.seq, 0)
        self.assertEqual(box.next()['op'], 'stop')
        self.assertEqual(box.seq, 1)
        self.assertEqual([c.args[0] for c in files.read.call_args_list], ['command-0000.json'] * 2)

    def test_other_value_errors_are_not_retried(self):
        files = Mock()
        files.read.side_effect = ValueError('wrong type or size')
        with self.assertRaisesRegex(ValueError, 'wrong type'):
            box_with(files).next()

    def test_auxiliary_pending_stop_completes_without_request(self):
        files = Mock()
        files.read.side_effect = [CellPending('pending'), command(0, 'stop')]
        ctx = context('auxiliary')
        with patch('nb_support.Files', return_value=files), patch('nb_support.open_request') as request:
            auxiliary(ctx)
        request.assert_not_called()
        self.assertEqual(files.read.call_count, 2)
        files.close.assert_called_once()

    def test_persistent_pending_obeys_cell_deadline(self):
        files = Mock()
        files.read.side_effect = CellPending('persistent two links')
        ctx = context('auxiliary')
        clock = Clock()
        def remaining(cap):
            if clock() >= .05:
                raise TimeoutError('original deadline')
            return min(cap, .05 - clock())
        ctx.remaining.side_effect = remaining
        ctx.sleep = clock.sleep
        with patch('nb_support.Files', return_value=files), self.assertRaisesRegex(TimeoutError, 'original'):
            auxiliary(ctx)
        self.assertLessEqual(files.read.call_count, 3)
        files.close.assert_called_once()

    def test_host_only_archives_complete_single_link_receipt(self):
        files = Mock()
        files.read.side_effect = [HostPending('pending'), json.dumps({'nonce': NONCE}).encode()]
        support, clock = host_with(files)
        with patch('upstream.time.monotonic', clock):
            self.assertEqual(support._wait('auxiliary', 'ready.json'), {'nonce': NONCE})
        self.assertEqual(len(support.items['auxiliary']['records']), 1)
        support.rt.evidence.raw.assert_called_once()

    def test_host_persistent_pending_has_original_timeout(self):
        files = Mock()
        files.read.side_effect = HostPending('pending')
        support, clock = host_with(files)
        with patch('upstream.time.monotonic', clock), self.assertRaises(TimeoutError):
            support._wait('auxiliary', 'ready.json', timeout=.05)
        self.assertLessEqual(files.read.call_count, 5)
        support.rt.evidence.raw.assert_not_called()

    def test_host_bad_nonce_or_other_errors_still_fail_immediately(self):
        for fault in (ValueError('not regular'), json.dumps({'nonce': 'wrong'}).encode()):
            files = Mock()
            if isinstance(fault, Exception):
                files.read.side_effect = fault
            else:
                files.read.return_value = fault
            support, clock = host_with(files)
            with patch('upstream.time.monotonic', clock), self.assertRaises(ValueError):
                support._wait('auxiliary', 'ready.json')
            self.assertEqual(files.read.call_count, 1)


@unittest.skipUnless(os.name == 'posix', 'Linux no-follow file transport')
class PublicationWindowTests(unittest.TestCase):
    def test_actual_host_publisher_window_retries_then_accepts_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, writer = CellFiles(tmp), HostFiles(tmp)
            self.addCleanup(files.close)
            self.addCleanup(writer.close)
            box, link = box_with(files), os.link
            def paused(*args, **kwargs):
                link(*args, **kwargs)
                self.assertEqual((Path(tmp) / 'command-0000.json').stat().st_nlink, 2)
                self.assertIsNone(box.next())
                self.assertEqual(box.seq, 0)
            with patch('run_transport.os.link', side_effect=paused), patch('run_transport.os.fchown'):
                publish(writer, 'command-0000.json', command(0, 'stop'))
            self.assertEqual(box.next()['op'], 'stop')
            self.assertEqual(box.seq, 1)

    def test_actual_cell_publisher_is_pending_to_host_until_unlinked(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, writer = HostFiles(tmp), CellFiles(tmp)
            self.addCleanup(files.close)
            self.addCleanup(writer.close)
            support, clock = host_with(files)
            link = os.link
            def paused(*args, **kwargs):
                link(*args, **kwargs)
                with self.assertRaises(HostPending):
                    support._read('auxiliary', 'ready.json')
                support.rt.evidence.raw.assert_not_called()
            with patch('nb_io.os.link', side_effect=paused):
                writer.write('ready.json', json.dumps({'nonce': NONCE}).encode())
            with patch('upstream.time.monotonic', clock):
                self.assertEqual(support._wait('auxiliary', 'ready.json')['nonce'], NONCE)

    def test_regular_evidence_still_rejects_two_links_without_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'file'
            path.write_bytes(b'evidence')
            os.link(path, Path(tmp) / 'second')
            files = HostFiles(tmp)
            self.addCleanup(files.close)
            with patch('cell.nb_io.os.read') as read, self.assertRaises(HostPending):
                files.read('file', 4096)
            read.assert_not_called()
            (Path(tmp) / 'second').unlink()
            self.assertEqual(files.read('file', 4096), b'evidence')

    def test_oversized_or_three_link_files_are_not_publication_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'file'
            path.write_bytes(b'long')
            os.link(path, Path(tmp) / 'second')
            files = HostFiles(tmp)
            self.addCleanup(files.close)
            for name, limit in [('file', 1), ('file', 10)]:
                if limit == 10:
                    os.link(path, Path(tmp) / 'third')
                with self.assertRaises(ValueError) as caught:
                    files.read(name, limit)
                self.assertNotIsInstance(caught.exception, HostPending)

    def test_nonregular_and_symlink_remain_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'dir').mkdir()
            (root / 'file').write_bytes(b'data')
            (root / 'link').symlink_to(root / 'file')
            os.mkfifo(root / 'fifo')
            files = HostFiles(tmp)
            self.addCleanup(files.close)
            for name in ('dir', 'link', 'fifo'):
                with self.assertRaises((OSError, ValueError)) as caught:
                    files.read(name, 4096)
                self.assertNotIsInstance(caught.exception, HostPending)
