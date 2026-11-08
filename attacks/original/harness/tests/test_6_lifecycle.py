"""离线回归：登记所有权、watcher寿命与NB-23内核屏障；OS边界全mock。"""
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch
from commands import Commands
from engine_cases import EngineCase
from engine_observe import signal_fact
from engine_signals import sample_signals
from env import Deadline
from fourd_fixtures import Ref
from management import Management
from run_rows import Row
from run_runtime import Runtime
from run_transport import OwnedTargets
from support_rows import SupportRows


def registry_fixture(config):
    root = Path('/tmp/nb-decoy-own')
    refs = {'core': Ref(101, 1000), 'spawner': Ref(102, 0),
            'connector:v:1': Ref(103, 70999), 'connector:a:1': Ref(104, 70999),
            'file-worker:v:1': Ref(105, 70996), 'file-worker:a:1': Ref(106, 70996)}
    workspaces = {k: {'mount': root / k} for k in ('work0', 'work1', 'work2')}
    rt = NS(work=root / 'work0', resources=NS(roots={root}), command=Mock(),
            deployment=NS(refs=refs, workspaces=workspaces, host_workspaces=workspaces),
            evidence=NS(raw=Mock(return_value={'file': 'mock-receipt'})), rows=[])
    rt.targets = OwnedTargets(rt)
    support = object.__new__(SupportRows)
    support.rt, support.config = rt, config
    support.closed, support.current, support.question_pending, support.netfd = False, None, None, None
    support.items, support._send = {}, Mock()
    # This ownership fixture begins AFTER the separately tested host-to-cell transition.
    support.signal_victim = config == 'undefended'
    rt.support = support
    for role, ws, ex in [('victim', 'work1', 'v:1'),
                         ('auxiliary', 'work2', 'a:1')]:
        row = NS(workspace=ws, config='engine', execution=ex, closed=False, request={}, poll=lambda: True)
        def finish(row=row):
            row.closed = True
            return {'tree_empty': True, 'runner_ok': True}
        row.finish = finish
        rt.rows.append(row)
        name = 'nb-decoy-' + role
        value = {'kind': 'path', 'scope': 'work', 'path': name}
        support.items[role] = {'root': root / ws / name, 'row': row, 'files': Mock()}
        with patch('run_transport.snapshot', return_value={'exists': True, 'dev': 1, 'ino': 2,
                                                           'uid': 1000, 'mode': 0o700}):
            rt.targets.add_path(role, value, workspace=ws, owner='support')
    target = {'kind': 'abstract', 'name': 'nb-decoy-victim-listener'}
    support.items['victim']['target'] = target
    rt.targets._add('victim-listener-' + config, target, {}, lambda: {}, ())
    return rt, support


class RegistryOwnership(unittest.TestCase):
    def test_two_arms_nb23_then_real_support_close_keeps_ownership(self):
        for config in ('engine', 'undefended'):
            with self.subTest(config=config):
                rt, support = registry_fixture(config)
                adapter = EngineCase(rt, 'NB-23')
                prepared = adapter.prepare(config, 1, adapter.contract())
                self.assertIn(('support', 'auxiliary'), rt.targets.items)
                self.assertIn('auxiliary', rt.targets.items)
                adapter.restore(prepared)
                self.assertIn(('support', 'auxiliary'), rt.targets.items)
                self.assertNotIn('auxiliary', rt.targets.items)
                with patch('support_rows.wait_for', side_effect=lambda cmd, pred, **kw: pred()), \
                     patch('support_rows.collect', return_value=({'control_ok': True}, {})):
                    support.close()
                self.assertTrue(support.closed)
                self.assertTrue(all(r.closed for r in rt.rows))
                self.assertEqual(rt.targets.items, {})

    def test_process_must_not_rebind_existing_attack_path(self):
        rt, _ = registry_fixture('engine')
        value = {'kind': 'path', 'scope': 'work', 'path': 'nb-decoy-own'}
        rt.targets._add('auxiliary', value, {}, lambda: {}, ())
        with self.assertRaisesRegex(ValueError, 'cannot rebind'):
            rt.targets.add_process('auxiliary', rt.deployment.refs['connector:a:1'])
        self.assertEqual(rt.targets.items['auxiliary'][0], value)

    def test_support_registration_is_invisible_to_default_attack_verify(self):
        rt, _ = registry_fixture('engine')
        value = {'kind': 'path', 'scope': 'work', 'path': 'nb-decoy-victim'}
        with self.assertRaisesRegex(ValueError, 'not registered'):
            rt.targets.verify({'victim': value})
        with patch('run_transport.snapshot', return_value={'exists': True, 'dev': 1, 'ino': 2,
                                                          'uid': 1000, 'mode': 0o700}):
            self.assertIn('victim', rt.targets.verify({'victim': value}, owner='support'))

    def test_wrong_owner_cannot_release_support(self):
        rt, _ = registry_fixture('engine')
        value = {'kind': 'path', 'scope': 'work', 'path': 'nb-decoy-victim'}
        with self.assertRaises(ValueError):
            rt.targets.release('victim', value)
        self.assertIn(('support', 'victim'), rt.targets.items)

    def test_unknown_owner_is_rejected(self):
        rt, _ = registry_fixture('engine')
        with self.assertRaises(ValueError):
            rt.targets.verify({'victim': {}}, owner='typo')


class WatchLifetime(unittest.TestCase):
    def fixture(self):
        clock = [100.0]
        cmd = object.__new__(Commands)
        cmd.deadline = Deadline(540, clock=lambda: clock[0])
        cmd.children, cmd.selector, cmd.abort = [], Mock(), Mock()
        cmd.selector.select.return_value = []
        admin = Management(Path('/offline'), Path('/offline/nb-decoy'), cmd, None)
        def start(*args, timeout):
            child = NS(end=clock[0] + cmd.deadline.left(timeout), proc=Mock(), streams=1)
            child.proc.poll.return_value = None
            cmd.children.append(child)
            return NS(child=child, until=Mock())
        admin._interactive = Mock(side_effect=start)
        rt = NS(bundle={'attacks': ['NB-21']}, command=cmd, work_end=640,
                deployment=NS(admin=admin))
        return rt, cmd, clock

    def test_batch_watcher_survives_first_attempt_deadline(self):
        rt, cmd, clock = self.fixture()
        Runtime.prepare_watcher(rt)
        child = rt.deployment.admin.watcher.child
        self.assertEqual(child.end, 640)
        rt.deployment.admin._interactive.assert_called_once_with('admin', 'questions', timeout=540)
        cmd.deadline = Deadline(30, clock=lambda: clock[0])
        clock[0] = 131
        cmd.deadline = Deadline(30, clock=lambda: clock[0])
        with patch('commands.time.monotonic', return_value=clock[0]):
            Commands.pump(cmd, 0)
        cmd.abort.assert_not_called()
        self.assertEqual(child.end, 640)

    def test_batch_deadline_still_aborts(self):
        rt, cmd, clock = self.fixture()
        Runtime.prepare_watcher(rt)
        clock[0] = 641
        with self.assertRaises(TimeoutError):
            Commands.pump(cmd, 0)
        cmd.abort.assert_called_once()

    def test_cannot_start_batch_watcher_inside_attempt_budget(self):
        rt, cmd, clock = self.fixture()
        cmd.deadline = Deadline(30, clock=lambda: clock[0])
        with self.assertRaisesRegex(ValueError, 'batch work deadline'):
            Runtime.prepare_watcher(rt)
        rt.deployment.admin._interactive.assert_not_called()

    def test_other_selections_need_no_watcher(self):
        rt, _, _ = self.fixture(); rt.bundle['attacks'] = ['NB-20']
        Runtime.prepare_watcher(rt)
        rt.deployment.admin._interactive.assert_not_called()

    def test_watcher_start_failure_propagates_to_batch_cleanup(self):
        rt, _, _ = self.fixture()
        rt.deployment.admin._interactive.side_effect = ValueError('watch failed')
        with self.assertRaisesRegex(ValueError, 'watch failed'):
            Runtime.prepare_watcher(rt)


class KernelBarrier(unittest.TestCase):
    def fixture(self):
        rt = NS(command=Mock(), deployment=NS(admin=Mock()), rows=[],
                cap={'first': 70000, 'last': 70005}, cgroup=NS(path=Path('/offline/nb-decoy-group')))
        row = Row(rt, 'engine', 'work0', 'row', 30)
        row.execution, row.uid, row.kernel_only = 'attack:1', 70001, True
        rt.rows = [row]
        rt.deployment.admin.rows.side_effect = TimeoutError('stopped core')
        return rt, row

    def test_kernel_barrier_does_not_rpc_stopped_core(self):
        rt, row = self.fixture()
        with patch('run_rows.Path.read_text', return_value=''):
            tree = row.finish()
        self.assertTrue(tree['tree_empty'])
        self.assertEqual(tree['source'], 'kernel-only')
        rt.deployment.admin.rows.assert_not_called()

    def test_live_uid_prevents_kernel_exit_claim(self):
        _, row = self.fixture()
        with patch('run_rows.Path.read_text', return_value='201'), \
             patch('run_rows.process_info', return_value={'uids': [70001] * 4}):
            self.assertFalse(row.poll())
            with self.assertRaises(RuntimeError): row.finish()
        self.assertFalse(row.closed)

    def test_missing_or_foreign_uid_cannot_use_kernel_only_fallback(self):
        for uid in (None, 1000, 70999):
            _, row = self.fixture(); row.uid = uid
            with self.subTest(uid=uid), self.assertRaises(ValueError): row.poll()


class SignalSampling(unittest.TestCase):
    def fixture(self):
        rt, _ = registry_fixture('engine')
        a = EngineCase(rt, 'NB-23'); p = a.prepare('engine', 1, a.contract())
        rt.evidence.raw.reset_mock()
        return a, p

    def test_first_stop_saved_once_and_survives_later_exit(self):
        a, p = self.fixture(); ref = a.processes['core']; ref.value['state'] = 'T'
        sample_signals(a, p); sample_signals(a, p)
        a.rt.evidence.raw.assert_called_once()
        ref.value['state'] = 'Z'
        fact = signal_fact(a, p, {}, {}, 'core')
        self.assertTrue(fact['external_effect'])
        self.assertEqual(fact['external_fact']['stopped_witness']['state'], 'T')
        self.assertIn('exited', fact['invalid_reason'])

    def test_identity_mismatch_cannot_become_stop_witness(self):
        a, p = self.fixture(); a.processes['core'].value.update(state='T', start_time=999)
        with self.assertRaisesRegex(ValueError, 'identity changed'): sample_signals(a, p)
        self.assertFalse(p['signal_witnesses'])

    def test_archive_failure_keeps_in_memory_stop_fact(self):
        a, p = self.fixture(); a.processes['core'].value['state'] = 'T'
        a.rt.evidence.raw.side_effect = OSError('full')
        with self.assertRaises(OSError): sample_signals(a, p)
        self.assertEqual(p['signal_witnesses']['core']['state'], 'T')


if __name__ == '__main__':
    unittest.main()
