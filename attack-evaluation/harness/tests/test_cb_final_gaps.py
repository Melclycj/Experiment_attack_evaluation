"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Cold-audit finding 4 (2026-11-04): a batch-exit gap on any outlet, not only the
# core-dump collector, voids every target whose coverage rested on that outlet.
import unittest
import test_cb_pipeline as pipeline
from cb_sentinels import new_credential


class FinalGaps(unittest.TestCase):
    run_batch = pipeline.Pipeline.run_batch
    targets = pipeline.Pipeline.targets

    def check_voided(self, r):
        engine = self.targets(r, 'CB-10', 'engine')['api-key-302']
        self.assertEqual(engine['outcome'], 'invalid');self.assertFalse(engine['complete'])
        self.assertEqual(engine['invalid_reason'], 'final-coverage-incomplete')
        peer = self.targets(r, 'CB-10', 'undefended')['api-key-302']
        self.assertEqual(peer['outcome'], 'succeeded');self.assertFalse(peer['prerequisite_ok'])
        self.assertEqual(r['rows'][('PC-CREDENTIAL', 'engine')]['outcome'], 'invalid')
        self.assertGreaterEqual(r['meta']['late_scan']['collector']['overturned'], 6);self.assertEqual(r['code'], 1)

    def test_missing_final_e09_voids_every_complete_target(self):
        def missing(rt):
            rt.deployment.evidence_bytes = None
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=missing)
        self.assertIn('e09:final-copy-missing', r['meta']['late_scan']['gaps'])
        self.check_voided(r)

    def test_unattributed_late_hit_voids_every_complete_target(self):
        stray = new_credential('nb-decoy-stray', 'nb-decoy-cb-x.test', 443, 'api-key')
        def before(rt):
            rt.cb_accounts.append(stray);rt.late_e09 = stray.truth + b'\n'
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], before=before)
        self.assertIn('late-hit-unattributed:e09', r['meta']['late_scan']['gaps'])
        self.check_voided(r)


class ReferenceCoverage(unittest.TestCase):
    run_batch = pipeline.Pipeline.run_batch
    targets = pipeline.Pipeline.targets

    def test_reference_row_with_an_outlet_gap_cannot_qualify(self):
        # Cold-audit finding 3: a reference row's own coverage must be complete.
        def gap(prepared, scan):
            if prepared['parameters'].get('reference'):
                scan.unavailable('trace', 'offline-reference', 'reference outlet gap')
        r = self.run_batch(['CB-10'], targets=['CB-10:api-key-302'], leak=gap)
        engine = self.targets(r, 'CB-10', 'engine')['api-key-302']
        self.assertEqual(engine['outcome'], 'invalid');self.assertFalse(engine['control']['ok'])
        self.assertIn('credential-control-or-reference-failed', engine['quality_issue'])


if __name__ == '__main__':
    unittest.main()
