"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import json
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from cb_batch import CredentialBatch
from cb_profile import HOSTS
from cell.cb_spec import BRANCHES
from cb_pipeline_fixtures import Runtime, cases, header, patches
from record import load_run

ATTACKS = ['CB-%02d' % i for i in range(1, 13)]


def order(names):
    """Positive controls interspersed, as selection() requires for engine batches."""
    result = []
    controls = ['PC-CREDENTIAL', 'PC-FILE', 'PC-PROXY', 'PC-DIALOGUE']
    for i, name in enumerate(names):
        result.append(name)
        if i % 3 == 0 and controls:result.append(controls.pop(0))
    return result + controls


class Pipeline(unittest.TestCase):
    def run_batch(self, names=None, configs=('engine', 'undefended'), targets=(), **options):
        names = order(names or ATTACKS)
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            found = cases(targets);chosen = [found[n] for n in names]
            rt = Runtime(Path(temp), chosen, **{k: v for k, v in options.items() if k not in ('before', 'after')})
            if options.get('before'):options['before'](rt)
            patches(rt, stack)
            code = CredentialBatch(rt, chosen, list(configs), header(rt)).execute()
            meta, rows = load_run(rt.evidence.directory.path)
            directory = rt.evidence.directory.path
            if options.get('after'):options['after'](rows, directory)
            files = {p.name for p in directory.iterdir()}
            readme = (directory / 'README.md').read_text(encoding='utf-8')
            leftovers = [p for w in rt.deployment.workspaces.values() for p in Path(w['mount']).iterdir()]
            credentials = [p for p in (rt.deployment.root / 'state/credentials').rglob('*') if p.is_file()] \
                if (rt.deployment.root / 'state/credentials').exists() else []
            self.assertLessEqual(rt.evidence.directory.size(), 10 * 1024 * 1024)
            return {'code': code, 'meta': meta, 'rows': {(r['attack'], r['config']): r for r in rows},
                    'rt': rt, 'files': files, 'readme': readme, 'leftovers': leftovers, 'credentials': credentials}

    def targets(self, result, attack, config):
        return {t['id']: t for a in result['rows'][(attack, config)]['attempts'] for t in a['targets']}

    def test_every_target_both_arms_pairs_and_restores(self):
        first = [a + ':' + b for a in ('CB-07', 'CB-09', 'CB-10') for b in BRANCHES[a][:8]]
        rest = [a + ':' + b for a in ('CB-07', 'CB-09', 'CB-10') for b in BRANCHES[a][8:]]
        self.check_complete(self.run_batch(targets=first), first)
        self.check_complete(self.run_batch(['CB-07', 'CB-09', 'CB-10'], targets=rest), rest)

    def check_complete(self, r, selected):
        chosen = {s.split(':')[0]: [] for s in selected}
        for s in selected:chosen[s.split(':')[0]].append(s.split(':')[1])
        expected = {a: chosen.get(a, list(BRANCHES[a])) for a in ATTACKS if (a, 'engine') in r['rows']}
        self.assertEqual(r['meta']['controller_error'], None, r['meta'].get('controller_error'))
        self.assertEqual(r['code'], 0, r['meta']['report'])
        for attack in expected:
            engine, peer = self.targets(r, attack, 'engine'), self.targets(r, attack, 'undefended')
            self.assertEqual(list(engine), expected[attack]);self.assertEqual(list(peer), expected[attack])
            for key, t in engine.items():
                with self.subTest(attack=attack, target=key):
                    self.assertEqual(t['outcome'], 'blocked', t.get('invalid_reason'))
                    self.assertTrue(t['pairing']['satisfied'])
                    self.assertEqual(peer[key]['outcome'], 'succeeded');self.assertTrue(peer[key]['prerequisite_ok'])
            self.assertEqual(r['rows'][(attack, 'engine')]['outcome'], 'blocked')
        for name in ('PC-CREDENTIAL', 'PC-FILE', 'PC-PROXY', 'PC-DIALOGUE'):
            self.assertEqual(r['rows'][(name, 'engine')]['outcome'], 'succeeded')
            self.assertNotIn((name, 'undefended'), r['rows'])
        # Real restoration: no account, truth file, decoy file or row selection left.
        self.assertEqual(r['credentials'], []);self.assertEqual(r['leftovers'], [])
        rt = r['rt'];self.assertEqual(rt.row_accounts, {});self.assertEqual(rt.undefended_environment, {})
        self.assertEqual(rt.targets.live, {})
        self.assertEqual(set(rt.cb_owners), {c.account for c in rt.cb_accounts})
        self.assertTrue(r['meta']['late_scan']['complete']);self.assertEqual(r['meta']['late_scan']['findings'], 0)
        self.assertTrue({'run.json', 'README.md', 'results.jsonl', 'results.md', 'COMPLETE.json'} <= r['files'])
        self.assertIn('2.3 凭据使用绑定', r['readme'])

    def test_unaccounted_dump_collector_makes_targets_invalid_without_losing_effects(self):
        # When the collector cannot be accounted (any tests.md 1.3 condition fails), the
        # first CB attempt is a quality failure and the batch stops there, as every batch
        # does on a quality failure.
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], dump='pipe')
        engine = self.targets(r, 'CB-10', 'engine')['api-key-302']
        self.assertEqual(engine['outcome'], 'invalid');self.assertIn('pipe-core-collector-not-accounted', engine['quality_issue'])
        self.assertIn('not-started', r['rows'][('CB-10', 'undefended')]['attempts'][0]['invalid_reason'])
        self.assertEqual(r['code'], 1)
        r = self.run_batch(['CB-10'], configs=('undefended',), targets=['CB-10:api-key-302'], dump='pipe')
        peer = self.targets(r, 'CB-10', 'undefended')['api-key-302']
        self.assertEqual(peer['outcome'], 'succeeded');self.assertFalse(peer['prerequisite_ok'])

    def leak_into(self, attack, config, outlet='core-connector-output'):
        def leak(prepared, scan):
            spec = prepared.get('spec') or {}
            if spec.get('attack') == attack and prepared['config'] == config and not prepared['parameters'].get('reference'):
                scan.add(outlet, 'injected', prepared['accounts']['A'].truth, complete=True, provenance={'test': 1})
        return leak

    def test_engine_leak_is_success_and_positive_control_leak_is_failure(self):
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], leak=self.leak_into('CB-10', 'engine'))
        self.assertEqual(self.targets(r, 'CB-10', 'engine')['api-key-302']['outcome'], 'succeeded')
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], leak=self.leak_into('PC-CREDENTIAL', 'engine', 'responses'))
        control = self.targets(r, 'PC-CREDENTIAL', 'engine')['api-key-valid']
        self.assertEqual(control['outcome'], 'invalid')
        self.assertEqual(control['invalid_reason'], 'positive-control-forbidden-outlet-hit');self.assertEqual(r['code'], 1)

    def test_generic_control_upstream_requests_are_scanned_and_accounts_archived(self):
        # Re-audit R3: PC-FILE/PROXY/DIALOGUE get the same per-request upstream scan as the
        # attacks, and their registered accounts' receipts are archived with the fact.
        def traffic(secret):
            def send(up, prepared):
                body = prepared['all_accounts'][0].truth if secret else b'nonsecret control body'
                up.request(HOSTS['sink'], '/nb-decoy-cb/collect/control-probe', body=body, method='POST')
            return send
        seen = {}
        def archived(rows, directory):
            row = next(x for x in rows if (x['attack'], x['config']) == ('PC-FILE', 'engine'))
            evidence = row['attempts'][0]['targets'][0]['external_fact']['evidence']
            seen['fact'] = json.loads((directory / evidence['file']).read_bytes())['external_fact']
        def clean(rt):rt.control_traffic = traffic(False)
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=clean, after=archived)
        self.assertEqual(r['rows'][('PC-FILE', 'engine')]['outcome'], 'succeeded')
        fact = seen['fact']
        self.assertEqual(len(fact['scans']), 1);self.assertEqual(fact['scans'][0]['forbidden'], [])
        self.assertEqual(len(fact['accounts']), 3)
        def leaky(rt):rt.control_traffic = traffic(True)
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=leaky)
        control = self.targets(r, 'PC-FILE', 'engine')['control']
        self.assertEqual(control['outcome'], 'invalid')
        self.assertEqual(control['invalid_reason'], 'positive-control-forbidden-outlet-hit');self.assertEqual(r['code'], 1)
        def bare(rt):rt.control_metadata = False
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=bare)
        control = self.targets(r, 'PC-FILE', 'engine')['control']
        self.assertEqual(control['outcome'], 'invalid');self.assertIn('control-account-metadata-missing', control['quality_issue'])

    def test_late_e09_hit_back_labels_the_owning_target(self):
        def before(rt):
            original = rt.own
            def own(credentials, attack, config, branch=None):
                credentials = list(credentials);original(credentials, attack, config, branch)
                if (attack, config, branch) == ('CB-10', 'engine', 'api-key-302') and not rt.late_e09:
                    rt.late_e09 = json.dumps({'line': credentials[0].truth.decode()}).encode() + b'\n'
            rt.own = own
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=before)
        target = self.targets(r, 'CB-10', 'engine')['api-key-302']
        self.assertEqual(target['outcome'], 'succeeded');self.assertEqual(target['late_findings'][0]['outlet'], 'e09')
        self.assertTrue(r['meta']['late_scan']['complete']);self.assertGreaterEqual(r['meta']['late_scan']['findings'], 1)

    def test_batch_exit_collector_file_overturns_not_produced(self):
        def before(rt):
            rt.late_dump = b'core without any sentinel'
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=before)
        engine = self.targets(r, 'CB-10', 'engine')['api-key-302']
        self.assertEqual(engine['outcome'], 'invalid');self.assertFalse(engine['complete'])
        self.assertEqual(engine['invalid_reason'], 'core-dump-not-produced-overturned')
        peer = self.targets(r, 'CB-10', 'undefended')['api-key-302']
        self.assertEqual(peer['outcome'], 'succeeded');self.assertFalse(peer['prerequisite_ok'])
        for name in ('PC-CREDENTIAL', 'PC-FILE', 'PC-PROXY', 'PC-DIALOGUE'):
            self.assertEqual(r['rows'][(name, 'engine')]['outcome'], 'invalid', name)
        late = r['meta']['late_scan']
        self.assertFalse(late['complete']);self.assertIn('core-dump:collector-new-at-batch-end', late['gaps'])
        self.assertEqual(late['collector']['changed'], ['wsl-crash-late.dmp']);self.assertEqual(late['findings'], 0)
        self.assertGreaterEqual(late['collector']['overturned'], 6)
        self.assertEqual(r['meta']['controller_error']['stage'], 'late-scan');self.assertEqual(r['code'], 1)

    def test_batch_exit_dump_with_truth_back_labels_and_still_fails(self):
        def before(rt):
            original = rt.own
            def own(credentials, attack, config, branch=None):
                credentials = list(credentials);original(credentials, attack, config, branch)
                if (attack, config, branch) == ('CB-10', 'engine', 'api-key-302') and not rt.late_dump:
                    rt.late_dump = b'core ' + credentials[0].truth
            rt.own = own
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=before)
        target = self.targets(r, 'CB-10', 'engine')['api-key-302']
        self.assertEqual(target['outcome'], 'succeeded');self.assertFalse(target['complete'])
        self.assertEqual(target['late_findings'][0]['outlet'], 'core-dump')
        self.assertGreaterEqual(r['meta']['late_scan']['findings'], 1);self.assertEqual(r['code'], 1)

    def test_collector_is_rechecked_without_any_account(self):
        from cb_late import late_scan
        from host import crash_inventory
        from record import RunDirectory
        from run_evidence import Evidence
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);(root / 'runs').mkdir();crash = root / 'crashes';crash.mkdir()
            rt = type('RT', (), {})()
            rt.cb_accounts, rt.host = [], {'crash_directory': str(crash), 'crashes': crash_inventory(crash)}
            rt.evidence = Evidence(RunDirectory(root / 'runs', '20261103T000000Z-cblate'))
            self.assertTrue(late_scan(rt, [])['complete'])
            (crash / 'wsl-crash-1.dmp').write_bytes(b'core')
            r = late_scan(rt, [])
            self.assertFalse(r['complete']);self.assertIn('core-dump:collector-new-at-batch-end', r['gaps'])

    def test_unattributed_or_missing_final_copy_fails_the_batch(self):
        from cb_sentinels import new_credential
        stray = new_credential('nb-decoy-stray', 'nb-decoy-cb-x.test', 443, 'api-key')
        def before(rt):
            rt.cb_accounts.append(stray);rt.late_e09 = stray.truth + b'\n'
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=before)
        self.assertEqual(r['meta']['controller_error']['stage'], 'late-scan');self.assertEqual(r['code'], 1)
        def missing(rt):
            rt.deployment.evidence_bytes = None
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=missing)
        self.assertIn('e09:final-copy-missing', r['meta']['late_scan']['gaps']);self.assertEqual(r['code'], 1)

    def test_restore_failure_stops_later_targets_and_rows(self):
        def fail(name):
            return name == 'admin-cred-del'
        r = self.run_batch(['CB-09', 'CB-10'], targets=['CB-09:api-key-unique', 'CB-09:api-key-selected'], fail=fail)
        engine = self.targets(r, 'CB-09', 'engine')
        self.assertIn('credential restoration', r['rows'][('CB-09', 'engine')]['attempts'][0]['fatal_error'])
        self.assertEqual(engine['api-key-unique']['outcome'], 'invalid')
        self.assertTrue(engine['api-key-selected']['invalid_reason'].startswith('not-started'))
        self.assertTrue(all(a['targets'][0]['invalid_reason'].startswith('not-started')
                            for a in r['rows'][('CB-10', 'engine')]['attempts']))
        self.assertEqual(r['code'], 1);self.assertIn('close', r['rt'].events)

    def test_eight_target_row_with_a_long_failure_still_finalizes(self):
        selected = ['CB-07:' + b for b in BRANCHES['CB-07'][:8]]
        def fail(name):
            if name == 'row-traffic-CB-07-engine' and fail.seen == 3:raise_long()
            fail.seen += name == 'row-traffic-CB-07-engine'
            return False
        def raise_long():
            raise RuntimeError('x' * 3000)
        fail.seen = 0
        r = self.run_batch(['CB-07'], targets=selected, fail=fail)
        engine = self.targets(r, 'CB-07', 'engine')
        self.assertEqual(list(engine), list(BRANCHES['CB-07'][:8]))
        failed = [k for k, t in engine.items() if t['invalid_reason'].startswith('RuntimeError')]
        self.assertEqual(len(failed), 1);self.assertLessEqual(len(engine[failed[0]]['invalid_reason']), 160)
        order = list(engine);after = order[order.index(failed[0]) + 1:]
        self.assertTrue(after)
        self.assertTrue(all(engine[k]['invalid_reason'] == 'not-started: after ' + failed[0] for k in after))
        # Earlier blocked targets lost their undefended pair when the batch stopped.
        self.assertTrue(all(engine[k]['invalid_reason'] == 'undefended-target-prerequisite-unsatisfied'
                            for k in order[:order.index(failed[0])]))
        self.assertIn('COMPLETE.json', r['files'])

    def test_row_failure_keeps_target_and_still_restores(self):
        def fail(name):
            return name == 'row-traffic-CB-07-engine'
        r = self.run_batch(['CB-07'], targets=['CB-07:basic-body', 'CB-07:basic-query'], fail=fail)
        engine = self.targets(r, 'CB-07', 'engine')
        self.assertIn('injected', engine['basic-body']['invalid_reason'])
        self.assertTrue(engine['basic-query']['invalid_reason'].startswith('not-started'))
        self.assertEqual(r['credentials'], []);self.assertEqual(r['leftovers'], [])

    def test_cb09_branches_are_only_attacker_reachable_ones(self):
        self.assertEqual(sorted({b.split('-')[-1] for b in BRANCHES['CB-09']}), ['selected', 'unique'])
        r = self.run_batch(['CB-09'], targets=['CB-09:token-unique', 'CB-09:token-selected'])
        engine = self.targets(r, 'CB-09', 'engine')
        self.assertEqual({k: t['outcome'] for k, t in engine.items()}, {'token-unique': 'blocked', 'token-selected': 'blocked'})

    def test_each_target_gets_its_own_deadline(self):
        import cb_batch
        from unittest.mock import patch
        ends, untils = [], []
        real_end, real_until = cb_batch.target_end, cb_batch.until
        def target_end(rt):
            ends.append(real_end(rt));return ends[-1]
        def until(end):
            untils.append(end);return real_until(end)
        with patch('cb_batch.target_end', target_end), patch('cb_batch.until', until):
            r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302', 'CB-10:token-307', 'CB-10:basic-308'])
        self.assertEqual(r['code'], 0, r['meta'].get('controller_error'))
        branched = lambda attack: attack.startswith('CB-') or attack == 'PC-CREDENTIAL'
        per_target = sum(len(a['targets']) for (attack, _), row in r['rows'].items() if branched(attack)
                         for a in row['attempts'])
        rows = sum(1 for attack, _ in r['rows'] if not branched(attack))
        self.assertEqual(per_target, 3 + 3 + 4);self.assertEqual(len(ends), per_target + rows)
        self.assertEqual([u for u in untils if u in ends], ends)
        self.assertEqual(len(set(ends)), len(ends))

    def test_output_is_fully_rescanned_at_each_target_start(self):
        from cb_output import CountedRunDirectory
        from unittest.mock import patch
        calls, real = [], CountedRunDirectory.rescan
        def rescan(directory):
            calls.append(directory.total);return real(directory)
        with patch.object(CountedRunDirectory, 'rescan', rescan):
            r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302', 'CB-10:token-307', 'CB-10:basic-308'])
        self.assertEqual(r['code'], 0, r['meta'].get('controller_error'))
        # One per sub-target: 3 + 3 CB-10, 4 PC-CREDENTIAL, 3 single-row controls; the first sets the total.
        self.assertEqual(len(calls), 3 + 3 + 4 + 3);self.assertIsNone(calls[0])

    def test_work_budget_exhaustion_marks_unstarted_rows(self):
        def before(rt):
            original = rt.event
            def event(name):
                original(name)
                if name == 'row-traffic-CB-10-engine':rt.work_end = time.monotonic() - 1
            rt.event = event
        r = self.run_batch(['CB-10', 'CB-11'], targets=['CB-10:api-key-302', 'CB-11:api-key-http'], before=before)
        self.assertIn('540-second', r['meta']['controller_error']['message'])
        self.assertTrue(r['rows'][('CB-11', 'undefended')]['attempts'][0]['invalid_reason'].startswith('not-started'))
        self.assertEqual(r['code'], 1)


if __name__ == '__main__':unittest.main()
