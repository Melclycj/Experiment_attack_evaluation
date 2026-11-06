"""NB-26 regression: reuse only a proven retired control UID, with mocked OS actions."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import test_4e_userns_host as fixtures
from common import json_bytes
from foure_fixtures import req, report
from userns_control import SameUidControl


class RetiredControlTests(unittest.TestCase):
    def prepare(self, runtime=None, config='engine-control', repeat=1):
        rt, _, group, ref, candidate = fixtures.OutsideControlTests().fixture()
        child = rt.command.start.return_value
        if runtime is not None:
            rt = runtime
        q = req(config, repeat)
        child.buffers = {'stdout': bytearray(json_bytes(report(q, True, uid=70010)))}
        child.joined, child.streams, child.proc.returncode = True, 2, None
        group.created = False
        group.create.side_effect = lambda: setattr(group, 'created', True)
        group.remove.side_effect = lambda: setattr(group, 'created', False)
        rt.command.start.return_value = child
        def finish(owned):
            self.assertIs(owned, child)
            child.proc.returncode, child.streams = 0, 0
            return {'exit_code': 0}
        rt.command.wait.side_effect = finish
        ctl = SameUidControl(rt, candidate, q)
        return SimpleNamespace(rt=rt, ctl=ctl, group=group, ref=ref, child=child,
                               candidate=candidate, catalog_last=70009)

    def execute(self, d):
        with patch('userns_control.read_owned', return_value=json_bytes(
                {'uid_range': {'first': 70000, 'last': d.catalog_last}})), \
             patch('userns_control.AttemptGroup', return_value=d.group), \
             patch('userns_control.worker_ref', return_value=d.ref):
            return d.ctl.run()

    def reject_next(self, old):
        later = self.prepare(old.rt, 'undefended-control')
        starts = old.rt.command.start.call_count
        with self.assertRaisesRegex(ValueError, 'excluded'):
            self.execute(later)
        self.assertEqual(old.rt.command.start.call_count, starts)
        self.assertFalse(later.group.created)
        return later

    def test_both_arms_share_runtime_and_reuse_only_retired_control(self):
        first = self.prepare()
        self.assertTrue(self.execute(first)['ok'])
        self.assertTrue(first.ctl.closed)
        self.assertFalse(first.group.created)
        second = self.prepare(first.rt, 'undefended-control')
        self.assertTrue(self.execute(second)['ok'])
        self.assertEqual(first.rt.rows, [first.ctl, second.ctl])
        self.assertIsNot(first.group, second.group)
        self.assertEqual(first.ctl.uid, second.ctl.uid)
        self.assertEqual(first.rt.serial, 2)
        self.assertNotEqual(first.ctl.fact['report']['attempt'], second.ctl.fact['report']['attempt'])
        for d in (first, second):
            d.ref.close.assert_called_once()
            d.group.remove.assert_called_once()
            self.assertIsNone(d.ctl.ref)

    def test_multiple_repeats_keep_all_retired_ownership_records(self):
        rt, controls = None, []
        for config in ('engine-control', 'undefended-control'):
            for repeat in (1, 2):
                d = self.prepare(rt, config, repeat)
                self.assertTrue(self.execute(d)['ok'])
                rt = d.rt
                controls.append(d.ctl)
        self.assertEqual(rt.rows, controls)
        self.assertEqual(rt.serial, 4)

    def test_real_row_uid_conflict_still_rejected_even_when_closed(self):
        for closed in (False, True):
            with self.subTest(closed=closed):
                d = self.prepare()
                d.rt.rows.append(SimpleNamespace(uid=70010, closed=closed))
                with self.assertRaisesRegex(ValueError, 'excluded'):
                    self.execute(d)
                d.rt.command.start.assert_not_called()

    def test_active_control_is_not_reusable(self):
        first = self.prepare()
        self.execute(first)
        first.ctl.closed = False
        self.reject_next(first)

    def test_unclean_group_is_not_reusable(self):
        first = self.prepare()
        self.execute(first)
        first.group.created = True
        self.reject_next(first)

    def test_worker_exit_and_drained_streams_are_required(self):
        for mode in ('live', 'bad_exit', 'undrained', 'not_joined'):
            with self.subTest(mode=mode):
                first = self.prepare()
                self.execute(first)
                if mode == 'live': first.child.proc.returncode = None
                if mode == 'bad_exit': first.child.proc.returncode = 1
                if mode == 'undrained': first.child.streams = 1
                if mode == 'not_joined': first.child.joined = False
                self.reject_next(first)

    def test_failed_control_or_remaining_pin_is_not_reusable(self):
        for mode in ('failed', 'error', 'pin'):
            with self.subTest(mode=mode):
                first = self.prepare()
                self.execute(first)
                if mode == 'failed': first.ctl.fact['ok'] = False
                if mode == 'error': first.ctl.fact['error'] = 'failure after observation'
                if mode == 'pin': first.ctl.ref = first.ref
                self.reject_next(first)

    def test_foreign_runtime_control_is_not_reusable(self):
        first = self.prepare()
        self.execute(first)
        second = self.prepare()
        second.rt.rows.append(first.ctl)
        with self.assertRaisesRegex(ValueError, 'excluded'):
            self.execute(second)
        second.rt.command.start.assert_not_called()

    def test_same_control_object_cannot_be_restarted(self):
        first = self.prepare()
        self.execute(first)
        starts = first.rt.command.start.call_count
        with self.assertRaises(ValueError):
            self.execute(first)
        self.assertEqual(first.rt.command.start.call_count, starts)
        self.assertEqual(first.rt.rows, [first.ctl])

    def test_allocator_overlap_and_outside_reserved_range_still_fail(self):
        for mode in ('allocator', 'outside'):
            with self.subTest(mode=mode):
                first = self.prepare()
                self.execute(first)
                second = self.prepare(first.rt, 'undefended-control')
                if mode == 'allocator': second.catalog_last = 70010
                else: second.rt.cap['last'] = 70009
                with self.assertRaisesRegex(ValueError, 'excluded'):
                    self.execute(second)
                self.assertEqual(first.rt.command.start.call_count, 1)

    def test_group_removal_failure_never_retires_control(self):
        first = self.prepare()
        first.group.remove.side_effect = RuntimeError('remove failed')
        with self.assertRaisesRegex(RuntimeError, 'remove failed'):
            self.execute(first)
        self.assertFalse(first.ctl.closed)
        self.reject_next(first)

    def test_process_exit_or_namespace_restore_failure_never_retires(self):
        for mode in ('exit', 'restore'):
            with self.subTest(mode=mode):
                first = self.prepare()
                if mode == 'exit': first.ref.exited.return_value = False
                else: first.candidate.read.side_effect = [first.candidate.before, {'links': []}]
                with self.assertRaises(ValueError):
                    self.execute(first)
                self.assertFalse(first.ctl.fact['ok'])
                self.reject_next(first)

    def test_pin_close_failure_never_retires_control(self):
        first = self.prepare()
        first.ref.close.side_effect = OSError('pin close failed')
        with self.assertRaisesRegex(OSError, 'pin close failed'):
            self.execute(first)
        self.reject_next(first)

    def test_final_evidence_failure_is_not_reusable_despite_cleanup(self):
        first = self.prepare()
        def evidence(raw, label):
            if label == 'nb26-control.json':
                raise OSError('evidence write failed')
            return {'file': 'offline.json'}
        first.rt.evidence.raw.side_effect = evidence
        with self.assertRaisesRegex(OSError, 'evidence write failed'):
            self.execute(first)
        self.assertTrue(first.ctl.closed)
        self.assertFalse(first.group.created)
        first.rt.evidence.raw.side_effect = None
        self.reject_next(first)
