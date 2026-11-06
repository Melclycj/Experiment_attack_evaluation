"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from cb_dumps import lifecycle
from cb_sentinels import new_credential
from host import crash_inventory
from record import RunDirectory
from run_evidence import Evidence

PIPE = {'kernel/core_pattern': '|/wsl-capture-crash %t %E %p %s', 'kernel/core_uses_pid': '0', 'fs/suid_dumpable': '0'}
CORE = {'role': 'core', 'alive_verified': True, 'identity_unchanged': True}
EXITED = [{'role': 'row-tree', 'exit_verified': True}, CORE]


def point(collector, configuration=PIPE):
    return {'configuration': dict(configuration), 'collector': collector}


class Lifecycle(unittest.TestCase):
    def test_quiet_wsl_collector_meeting_every_condition_is_not_produced(self):
        empty = {'exists': True, 'entries': {}}
        r = lifecycle(point(empty), point(empty), EXITED, reader=lambda n: self.fail('nothing to read'))
        self.assertTrue(r['complete']);self.assertEqual(r['state'], 'not-produced');self.assertEqual(r['reason'], '')
        self.assertEqual(r['dumps'], []);self.assertEqual(r['witness']['rule'], 'wsl-pipe-declared-directory')

    def test_other_pipe_or_inexact_wsl_pattern_stays_a_gap(self):
        empty = {'exists': True, 'entries': {}}
        for pattern in ('|/usr/lib/systemd/systemd-coredump %P %u %g %s', '|/wsl-capture-crash %t %E %p',
                        '|/wsl-capture-crash %t %E %p %s ', '|/tmp/wsl-capture-crash %t %E %p %s'):
            with self.subTest(pattern=pattern):
                c = {**PIPE, 'kernel/core_pattern': pattern}
                r = lifecycle(point(empty, c), point(empty, c), EXITED, None)
                self.assertFalse(r['complete']);self.assertEqual(r['reason'], 'pipe-core-collector-not-accounted')

    def test_missing_collector_directory_is_not_zero(self):
        empty, missing = {'exists': True, 'entries': {}}, {'exists': False, 'entries': {}}
        for before, after in ((missing, missing), (empty, missing), (missing, empty)):
            r = lifecycle(point(before), point(after), EXITED, None)
            self.assertFalse(r['complete']);self.assertEqual(r['reason'], 'core-collector-directory-unreadable')

    def test_every_process_condition_is_required(self):
        empty = {'exists': True, 'entries': {}}
        tree = {'role': 'row-tree', 'exit_verified': True}
        cases = {'process-exit-coverage-incomplete': ([CORE], [tree], [tree, CORE, CORE], [],
                                                       [tree, CORE, {'role': 'connector', 'alive_verified': True}],
                                                       [tree, CORE, {'role': 'runner', 'exit_verified': False}]),
                 'core-liveness-or-identity-unverified': ([tree, {'role': 'core', 'alive_verified': True}],
                                                          [tree, {**CORE, 'alive_verified': False}],
                                                          [tree, {'role': 'core', 'exit_verified': True}])}
        for reason, variants in cases.items():
            for processes in variants:
                with self.subTest(processes=processes):
                    r = lifecycle(point(empty), point(empty), processes, None)
                    self.assertFalse(r['complete']);self.assertIn(reason, r['reason'])

    def test_new_or_changed_collector_entry_is_read_even_without_completeness(self):
        old = {'exists': True, 'entries': {'old.dmp': {'size': 3, 'mtime_ns': 1, 'mode': stat.S_IFREG}}}
        new = {'exists': True, 'entries': {'old.dmp': {'size': 4, 'mtime_ns': 2, 'mode': stat.S_IFREG},
                                           'new.dmp': {'size': 4, 'mtime_ns': 2, 'mode': stat.S_IFREG}}}
        calls = []
        r = lifecycle(point(old), point(new), EXITED, reader=lambda n: calls.append(n) or b'core')
        self.assertEqual(sorted(calls), ['new.dmp', 'old.dmp']);self.assertEqual(len(r['dumps']), 2)
        self.assertFalse(r['complete']);self.assertEqual(r['reason'], 'core-collector-new-or-changed')

    def test_drift_live_process_unreadable_and_file_pattern_reasons(self):
        empty = {'exists': True, 'entries': {}}
        r = lifecycle(point(empty), point(empty, {**PIPE, 'fs/suid_dumpable': '1'}), [{'role': 'x'}], None)
        self.assertIn('core-configuration-changed', r['reason'])
        self.assertIn('process-exit-coverage-incomplete', r['reason'])
        big = {'exists': True, 'entries': {'a': {'size': 3 * 1024 * 1024, 'mtime_ns': 1, 'mode': stat.S_IFREG},
                                           'b': {'size': 1, 'mtime_ns': 1, 'mode': stat.S_IFLNK}}}
        r = lifecycle(point(empty), point(big), EXITED, reader=lambda n: self.fail('must not read'))
        self.assertIn('core-type-or-size-incomplete', r['reason'])
        flat = {**PIPE, 'kernel/core_pattern': 'core'}
        r = lifecycle(point(empty, flat), point(empty, flat), EXITED, None)
        self.assertEqual(r['reason'], 'core-file-landing-not-declared')
        grown = {'exists': True, 'entries': {'c': {'size': 4, 'mtime_ns': 1, 'mode': stat.S_IFREG}}}
        with self.assertRaises(ValueError):lifecycle(point(empty), point(grown), EXITED, reader=lambda n: b'xx')


class Ref:
    def __init__(self, exited=True):self.done = exited
    def exited(self):return self.done


TERMINAL = {'data': b'nb-decoy-terminal-x\r\n', 'complete': True, 'reason': '', 'provenance': {'source': 'offline'}}


@unittest.skipUnless(os.name == 'posix', 'openat evidence reads')
class Collect(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();root = Path(self.temp.name)
        (root / 'runs').mkdir();self.scratch = root / 'scratch';self.scratch.mkdir()
        self.crash = root / 'crashes';self.crash.mkdir()
        self.e09 = self.scratch / 'e09.jsonl';self.e09.write_bytes(b'{"n":1}\n')
        self.accounts = [new_credential('nb-decoy-' + k, 'nb-decoy-cb-x.test', 443, 'api-key') for k in 'ABC']
        self.connector = {'ready': {'pid': 9, 'execution': 'work0:1'}, 'ref': Ref(),
                          'environment': {'role': 'connector'}, 'environment_bytes': b'A=1\0',
                          'logs': {'stdout': {'data': b'', 'complete': True}, 'stderr': {'data': b'', 'complete': True}}}
        measure = SimpleNamespace(collect=lambda execution: [self.connector])
        self.engine = SimpleNamespace(buffers={'stdout': bytearray(), 'stderr': bytearray()})
        self.rt = SimpleNamespace(evidence=Evidence(RunDirectory(root / 'runs', '20261103T000000Z-cbcollect')),
            deployment=SimpleNamespace(scratch=self.scratch, evidence=self.e09, engine=self.engine,
                                       refs={'core': SimpleNamespace(initial={'pid': 7}, read=lambda: {'pid': 7})},
                                       cb_measure=measure),
            host={'crash_directory': str(self.crash)}, cb_e09_seen=b'')
        self.items = [{'receipt': {'role': 'runner', 'process': {'pid': 12}, 'stage': 'initial'}, 'raw': b'X=1\0', 'ref': Ref()}]

    def tearDown(self):
        self.temp.cleanup()

    def collect(self, *, handle=None, prior=b'{"n":1}\n', after=None, items=None, terminal=TERMINAL,
                worker=True):
        from cb_outlets import collect
        prepared = {'all_accounts': self.accounts, 'e09_before': prior,
                    'dump_before': point(crash_inventory(self.crash))}
        if worker:  # v4: cb_row samples the row's file worker environment at the row gate
            prepared['file_worker_environ'] = ({'role': 'file-worker', 'stage': 'row-gate',
                                                'process': {'pid': 8}}, b'W=1\0')
        process = SimpleNamespace(items=self.items if items is None else items, finish=lambda: True)
        handle = handle or SimpleNamespace(execution='work0:1')
        witness = after or (lambda crash: point(crash_inventory(crash)))
        with patch('cb_outlets.environment', lambda ref: ({'process': {'pid': 7}, 'pidfd_pinned': True}, b'C=1\0')), \
             patch('cb_outlets.dump_witness', witness):
            return collect(self.rt, prepared, {'complete': True}, {'nb-decoy-x': b'reply'},
                           {'requests': []}, process, handle, tree={'tree_empty': True, 'source': 'kernel-only'},
                           terminal=terminal)

    def test_file_worker_environment_is_scanned_and_its_absence_is_a_gap(self):
        r = self.collect()
        worker = [i for i in r['items'] if i['outlet'] == 'environ' and i['provenance'].get('role') == 'file-worker']
        self.assertEqual(len(worker), 1)
        r = self.collect(worker=False)
        self.assertIn('environ:file worker environment not sampled', r['gaps'])
        self.assertFalse(r['complete'])

    def test_every_declared_outlet_is_inventoried_and_quiet_collector_is_not_produced(self):
        r = self.collect()
        self.assertEqual({i['outlet'] for i in r['items']},
                         {'upstream', 'responses', 'trace', 'e09', 'core-connector-output', 'environ', 'core-dump'})
        self.assertEqual(r['gaps'], []);self.assertTrue(r['complete']);self.assertEqual(r['forbidden'], [])
        dump = next(i for i in r['items'] if i['outlet'] == 'core-dump')
        self.assertEqual(dump['state'], 'not-produced');self.assertEqual(dump['witness']['rule'], 'wsl-pipe-declared-directory')
        self.assertEqual([p['role'] for p in dump['witness']['processes']], ['row-tree', 'connector', 'runner', 'core'])
        self.assertEqual(dump['witness']['processes'][-1]['checked'], 'after-closing-witness')
        self.assertEqual(self.rt.cb_e09_seen, self.e09.read_bytes())

    def test_core_lost_after_the_closing_witness_keeps_the_dump_a_gap(self):
        def lost():
            raise RuntimeError('pinned process exited')
        self.rt.deployment.refs['core'].read = lost
        r = self.collect()
        self.assertFalse(r['complete']);self.assertEqual(r['gaps'], ['core-dump:core-liveness-or-identity-unverified'])

    def test_truth_in_e09_increment_core_and_connector_output_is_forbidden(self):
        truth = self.accounts[1].truth
        self.e09.write_bytes(b'{"n":1}\n' + json.dumps({'v': truth.decode()}).encode() + b'\n')
        self.engine.buffers['stderr'].extend(b'core ' + truth)
        self.connector['logs']['stderr'] = {'data': b'x' + truth, 'complete': True}
        outlets = {h['outlet'] for h in self.collect()['forbidden']}
        self.assertEqual(outlets, {'e09', 'core-connector-output'})

    def test_new_collector_dump_with_truth_is_a_proven_leak(self):
        def after(crash):
            (crash / 'wsl-crash-1.dmp').write_bytes(b'dump ' + self.accounts[0].truth)
            return point(crash_inventory(crash))
        r = self.collect(after=after)
        self.assertTrue(any(h['outlet'] == 'core-dump' for h in r['forbidden']));self.assertFalse(r['complete'])
        self.assertIn('core-dump:core-collector-new-or-changed', r['gaps'])

    def test_undefended_initial_parent_is_preset_but_child_output_is_not(self):
        truth = self.accounts[0].truth
        child = SimpleNamespace(buffers={'stdout': bytearray(b'out ' + truth), 'stderr': bytearray()}, proc=SimpleNamespace(pid=11))
        items = [{'receipt': {'role': 'undefended-parent', 'process': {'pid': 13}, 'stage': 'initial'},
                  'raw': b'NB_DECOY_CREDENTIAL=' + truth + b'\0', 'ref': Ref()}]
        r = self.collect(handle=SimpleNamespace(execution=None, child=child), items=items)
        self.assertEqual({h['outlet'] for h in r['forbidden']}, {'trace'})

    def test_rewritten_e09_and_live_connector_fail_closed(self):
        with self.assertRaises(ValueError):self.collect(prior=b'{"n":0}\n')
        self.connector['ref'] = Ref(False)
        self.assertIn('process-exit-coverage-incomplete', ' '.join(self.collect()['gaps']))


class Handle:
    def __init__(self, polls=1):
        self.polls, self.execution, self.config = polls, 'work0:1', 'engine'
    def poll(self):
        self.polls -= 1;return self.polls < 0
    def finish(self):
        return {'tree_empty': True, 'source': 'kernel-only'}


class RowDriver(unittest.TestCase):
    def drive(self, *, sync=lambda w, req, state, ready: ready({'state': state}), worker=False, items=1, collect=None,
              seen=b''):
        import cb_row
        events = []
        class Measure:
            def __init__(self, rt, files, prepared):self.items = [object()] * items;self.handle = None
            def pump(self):events.append('pump')
            def close(self):events.append('measure-close')
        rt = SimpleNamespace(bundle={'run': '20261103T000000Z-cbrow'}, host={'crash_directory': '/offline'},
            deployment=SimpleNamespace(upstream=SimpleNamespace(begin=lambda n: events.append('begin'),
                                                                 end=lambda: events.append('end') or {'requests': []})),
            command=SimpleNamespace(observers=['base'], deadline=SimpleNamespace(left=lambda n: n)),
            evidence=SimpleNamespace(raw=lambda data, *a: {'file': 'raw-0001.json'}), work='old',
            pump=lambda: events.append('rt-pump'), cb_e09_seen=seen)
        rt.start = lambda config, workspace, seconds: events.append('start') or Handle()
        files = SimpleNamespace(root='/offline-work', reserve=lambda name: name)
        parameters = {'worker_ready': 'nb-decoy-worker-ready'} if worker else {}
        prepared = {'targets': {'b': {'kind': 'inet', 'address': '192.0.2.1', 'port': 443}}, 'parameters': parameters}
        case = SimpleNamespace(attack='CB-05', sync='sent')
        sample = lambda rt, execution: events.append(('file-worker-environ', execution)) or (
            {'role': 'file-worker', 'stage': 'row-gate'}, b'W=1\0')
        with patch('cb_row.ProcessMeasurement', Measure), patch('cb_row.prepare_request', lambda *a: None), \
             patch('cb_row.file_worker_environ', sample), \
             patch('cb_row.e09_read', lambda d, prior=b'': events.append(('e09', prior)) or b''), \
             patch('cb_row.synchronize', sync), \
             patch('cb_row.open_terminal', lambda h, g: events.append(('terminal-open', g)) or SimpleNamespace(closed=True)), \
             patch('cb_row.finish_terminal', lambda rt, t, g: events.append('terminal-finish') or
                   {'data': b'', 'complete': True, 'reason': '', 'provenance': {}}), \
             patch('cb_row.dump_witness', lambda p: events.append('dump-before') or 'witness'), \
             patch('cb_row.collect', collect or (lambda *a: ({'complete': True}, {}))), \
             patch('cb_row.outlets', lambda *a, **k: events.append(('outlets', k['tree']['tree_empty']))
                   or {'complete': True, 'gaps': [], 'forbidden': []}):
            try:
                result = cb_row.run_row(rt, case, prepared, files, config='engine', on_sync=lambda p, item: {'ok': item})
                return result, events, rt, prepared
            except ValueError as exc:
                return exc, events, rt, prepared

    def test_witness_window_and_collection_order(self):
        result, events, rt, prepared = self.drive()
        self.assertLess(events.index('dump-before'), events.index('start'))
        self.assertLess(events.index('begin'), events.index('start'))
        self.assertLess(events.index('start'), events.index('end'));self.assertEqual(events[-2:][-1], 'measure-close')
        self.assertIn(('outlets', True), events);self.assertEqual(prepared['dump_before'], 'witness')
        self.assertEqual(rt.command.observers, ['base']);self.assertEqual(rt.work, 'old')
        self.assertEqual(prepared['parameters']['attempt_nonce'], prepared['request']['sync']['nonce'])
        # v4: the row's file worker environment is sampled after the row starts and before its gate opens
        sampled = next(e for e in events if isinstance(e, tuple) and e[0] == 'file-worker-environ')
        opened = next(e for e in events if isinstance(e, tuple) and e[0] == 'terminal-open')
        self.assertLess(events.index('start'), events.index(sampled))
        self.assertLess(events.index(sampled), events.index(opened))
        self.assertEqual(prepared['file_worker_environ'][1], b'W=1\0')

    def test_missing_handshake_or_unpinned_child_never_releases(self):
        exc, events, rt, _ = self.drive(sync=lambda *a: None)
        self.assertIn('handshake absent', str(exc));self.assertIn('measure-close', events)
        self.assertEqual(rt.command.observers, ['base'])
        exc, _, _, _ = self.drive(worker=True, items=1)
        self.assertIn('pinned environment', str(exc))

    def test_absent_handshake_still_closes_the_window_and_keeps_the_cell_error(self):
        archived = []
        def observed(*a):
            return ({'complete': False, 'error': 'TimeoutError: environment handshake timeout'}, {})
        import cb_row
        with patch.object(cb_row, 'json_bytes', lambda v: archived.append(v) or b'{}'):
            exc, events, _, _ = self.drive(sync=lambda *a: None, collect=observed)
        self.assertIn('handshake absent', str(exc));self.assertIn('environment handshake timeout', str(exc))
        self.assertIn('end', events);self.assertIn('measure-close', events)
        self.assertTrue(any(isinstance(v, dict) and 'observation' in v and 'window' in v for v in archived))

    def test_collection_error_is_a_coverage_gap(self):
        from run_transport import CollectionError
        def broken(*a):
            raise CollectionError(ValueError('truncated'), {'complete': False}, {})
        result, _, _, _ = self.drive(collect=broken)
        self.assertFalse(result['coverage']['complete']);self.assertIn('truncated', result['coverage']['gaps'][-1])


if __name__ == '__main__':unittest.main()
