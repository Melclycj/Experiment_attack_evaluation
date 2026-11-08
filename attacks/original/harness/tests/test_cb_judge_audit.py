"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Cold-audit findings 3, 5 and 6 (2026-11-04): the observed mechanism comes from the
# engine's diagnostics, never the expectation; each undefended target needs its own
# effect; every target delivers its declared capture inventory.
import base64
import json
import unittest
from cb_case_plan import plan
from cb_judge import verdict
from cb_judge_fixtures import fixture
from cell.cb_spec import BRANCHES
from test_cb_judge import evaluate


def outcome(args, config='engine', **changes):
    s = args[0]
    return verdict(evaluate(args, config, **changes), key=s['branch'], expected=s['mechanism'],
                   positive=s['attack'] == 'PC-CREDENTIAL')


def without_capture(args, label):
    obs = args[3]
    obs['captures'] = [c for c in obs['captures'] if c['label'] != label]


class Mechanism(unittest.TestCase):
    def test_every_engine_target_names_its_mechanism_from_diagnostics(self):
        for attack, branches in BRANCHES.items():
            if attack in ('PC-CREDENTIAL', 'CB-14'):  # CB-14 条款 8: separate keep path, see test_cb14_clause8
                continue
            for branch in branches:
                with self.subTest(attack=attack, branch=branch):
                    t = outcome(fixture(attack, branch))
                    self.assertEqual(t['outcome'], 'blocked', t['invalid_reason'])
                    self.assertEqual(t['observed_mechanism'], plan(attack, branch)['mechanism'])
                    self.assertTrue(t['external_fact']['diagnosis'])

    def test_no_diagnostics_is_unattributed_not_blocked(self):
        t = outcome(fixture('CB-10', 'api-key-302'), diagnostics=None)
        self.assertEqual(t['outcome'], 'invalid');self.assertEqual(t['invalid_reason'], 'mechanism-unattributed')

    def test_cb12_other_canonical_rejection_is_not_host_protection(self):
        args = fixture('CB-12', 'api-key-host')
        args[6]['connector'] = json.dumps({'event': 'connection_closed',
                                           'reason': 'request does not read: header name not lowercase'}).encode()
        t = outcome(args)
        self.assertEqual(t['outcome'], 'invalid');self.assertIsNone(t['observed_mechanism'])

    def test_cb12_host_reading_is_bound_to_one_record_of_this_row(self):
        # Re-audit R4: an unrelated event carrying the words, a second refusal, a repeated
        # record or an E-09 slice without this row's control admission is no Host attribution.
        host = 'request does not read: forbidden header host (条款 3)'
        def log(*items):
            return b''.join(json.dumps(i).encode() + b'\n' for i in items)
        cases = {
            'other-event': log({'event': 'judgment_port_fatal', 'reason': 'core protocol: ' + host}),
            'repeated': log({'event': 'connection_closed', 'reason': host}, {'event': 'connection_closed', 'reason': host}),
            'second-refusal': log({'event': 'connection_closed', 'reason': host},
                                  {'event': 'connection_closed', 'reason': 'IP literal refused at validation (条款 7)'}),
            'refused-request': log({'event': 'connection_closed', 'reason': host},
                                   {'event': 'request_refused', 'why': 'address'}),
        }
        for name, connector in cases.items():
            with self.subTest(case=name):
                args = fixture('CB-12', 'api-key-host');args[6]['connector'] = connector
                t = outcome(args)
                self.assertEqual(t['outcome'], 'invalid');self.assertIsNone(t['observed_mechanism'])
        args = fixture('CB-12', 'api-key-host');args[6]['e09'] = b''
        t = outcome(args)
        self.assertEqual(t['outcome'], 'invalid');self.assertIsNone(t['observed_mechanism'])
        # The normal per-connection closes beside the one refusal still attribute (real archives show them).
        args = fixture('CB-12', 'api-key-host')
        args[6]['connector'] = log({'event': 'connector_started', 'uid': 1}, {'event': 'connection_closed', 'reason': 'reader refused a fragment'},
                                   {'event': 'connection_closed', 'reason': host}, {'event': 'judgment_port_fatal', 'reason': 'judgment port closed'})
        self.assertEqual(outcome(args)['observed_mechanism'], 'canonical-host-rejection')

    def test_other_refusal_or_wrong_account_is_not_account_selection(self):
        args = fixture('CB-06', 'api-key-empty')
        records = [json.loads(l) for l in args[6]['e09'].splitlines()]
        records[-1].update(reason_code='not_authorized');records[-1]['detail']['deny_reason'] = 3
        args[6]['e09'] = b''.join(json.dumps(r).encode() + b'\n' for r in records)
        self.assertEqual(outcome(args)['invalid_reason'], 'mechanism-unattributed')
        args = fixture('CB-07', 'basic-body')
        records = [json.loads(l) for l in args[6]['e09'].splitlines()]
        records[-1]['detail'].update(credential='placed', account=args[2]['A'].account)
        args[6]['e09'] = b''.join(json.dumps(r).encode() + b'\n' for r in records)
        self.assertEqual(outcome(args)['outcome'], 'invalid')


class Prerequisite(unittest.TestCase):
    def strip_header(self, row, name, replacement=None):
        head = base64.b64decode(row['head_base64']).split(b'\r\n')
        kept = [l for l in head if not l.lower().startswith(name.encode() + b':')]
        if replacement is not None:
            kept.append(name.encode() + b': ' + replacement)
        row['head_base64'] = base64.b64encode(b'\r\n'.join(kept)).decode()

    def test_audit_counterexamples_fail_the_premise(self):
        # A leak elsewhere stays a leak (effect), but is not the attack's own effect (premise).
        args = fixture('CB-10', 'api-key-302', 'undefended')
        target = next(r for r in args[5]['requests'] if r['path'] == '/nb-decoy-cb/collect/' + 'a' * 48)
        self.strip_header(target, 'x-api-key')
        f = evaluate(args, 'undefended')
        self.assertTrue(f['effect']);self.assertFalse(f['prerequisite_ok'])
        args = fixture('CB-07', 'api-key-dual', 'undefended')
        row = next(r for r in args[5]['requests'] if r['path'] == args[1]['path'])
        self.strip_header(row, 'authorization', b'nb-decoy-placeholder')
        f = evaluate(args, 'undefended')
        self.assertTrue(f['effect']);self.assertFalse(f['prerequisite_ok'])
        args = fixture('CB-12', 'api-key-host', 'undefended')
        row = next(r for r in args[5]['requests'] if r['path'] == args[1]['path'])
        self.strip_header(row, 'x-api-key')
        config_hit = {'complete': True, 'gaps': [], 'forbidden': [{'account': args[2]['A'].account, 'outlet': 'responses'}]}
        f = evaluate(args, 'undefended', coverage=config_hit)
        self.assertTrue(f['effect']);self.assertFalse(f['prerequisite_ok'])

    def test_every_undefended_target_meets_its_own_effect(self):
        for attack, branches in BRANCHES.items():
            if attack in ('PC-CREDENTIAL', 'CB-14'):  # CB-14 条款 8: separate keep path, see test_cb14_clause8
                continue
            for branch in branches:
                with self.subTest(attack=attack, branch=branch):
                    self.assertTrue(evaluate(fixture(attack, branch, 'undefended'), 'undefended')['prerequisite_ok'])


class Inventory(unittest.TestCase):
    def test_positive_control_needs_its_missing_and_failure_captures(self):
        for label in ('missing', 'failure-body'):
            args = fixture('PC-CREDENTIAL', 'api-key-valid')
            without_capture(args, label)
            with self.subTest(label=label):
                t = outcome(args)
                self.assertEqual(t['outcome'], 'invalid');self.assertIn('missing-capture:action/' + label, t['quality_issue'])

    def test_cb03_must_show_installation_triggered_postinstall(self):
        args = fixture('CB-03', 'api-key-npm')
        without_capture(args, 'package')
        self.assertEqual(outcome(args)['outcome'], 'invalid')
        args = fixture('CB-03', 'api-key-npm')
        stdout = next(c for c in args[3]['captures'] if c['label'] == 'child-stdout')
        data = json.loads(args[4][stdout['path']]);data['lifecycle'] = None
        raw = json.dumps(data).encode();args[4][stdout['path']] = raw
        import hashlib
        stdout.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(outcome(args)['outcome'], 'invalid')


if __name__ == '__main__':
    unittest.main()
