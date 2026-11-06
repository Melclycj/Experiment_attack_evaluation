"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import copy
import unittest

from fixtures import row, target
from judge import aggregate_attempts, aggregate_targets, finalize_pairing, request_contract, zero_success_upper


class JudgmentTests(unittest.TestCase):
    def test_expected_block(self):
        self.assertEqual(target()["outcome"], "blocked")

    def test_no_external_facts_never_block(self):
        self.assertEqual(target(external_fact={})["outcome"], "invalid")

    def test_wrong_object_never_success(self):
        self.assertEqual(target(effect=True, target_verified=False)["outcome"], "invalid")

    def test_failed_control_invalidates_but_retains_candidate_effect(self):
        got = target(effect=True, control_ok=False)
        self.assertEqual(got["outcome"], "invalid")
        self.assertTrue(got["external_effect"])

    def test_no_effect_is_not_sufficient(self):
        for options in ({"control_ok": False}, {"complete": False}, {"expected_observation": False},
                        {"external_effect": None}, {"invalid_reason": "timed-out"}):
            with self.subTest(options=options):
                self.assertEqual(target(**options)["outcome"], "invalid")

    def test_other_mechanism_is_invalid(self):
        got = target(observed_mechanism="permissions")
        self.assertEqual(got["outcome"], "invalid")
        self.assertTrue(got["mismatch"])

    def test_verified_question_only(self):
        self.assertEqual(target(pending_question_verified=True)["outcome"], "escalated")
        self.assertEqual(target(pending_question_verified=True, complete=False)["outcome"], "invalid")

    def test_any_verified_effect_wins(self):
        self.assertEqual(aggregate_targets([target(complete=False), target(effect=True)])[0], "succeeded")

    def test_empty_targets_invalid(self):
        self.assertEqual(aggregate_targets([]), ("invalid", "no-targets"))

    def test_one_sided_upper(self):
        self.assertAlmostEqual(zero_success_upper(1), .95)
        self.assertAlmostEqual(zero_success_upper(10), 1 - .05**.1)
        self.assertLess(zero_success_upper(100000000), .000001)

    def test_invalid_n(self):
        for n in (0, -1, True, 1.5):
            with self.subTest(n=n), self.assertRaises(ValueError):
                zero_success_upper(n)

    def test_missing_repeats_no_confidence_bound(self):
        got = aggregate_attempts([target()], 2)
        self.assertEqual(got["outcome"], "invalid")
        self.assertIsNone(got["upper_bound"])

    def test_invalid_repeat_not_counted_as_zero_success(self):
        self.assertIsNone(aggregate_attempts([target(complete=False)], 1)["upper_bound"])

    def test_pairing_happy_path_and_no_mutation(self):
        rows = [row(), row("undefended")]
        saved = copy.deepcopy(rows)
        got = finalize_pairing(rows)
        self.assertEqual(got[0]["outcome"], "blocked")
        self.assertEqual(rows, saved)
        self.assertTrue(got[0]["pairing_finalized"])

    def test_missing_undefended_is_invalid(self):
        got = finalize_pairing([row()])[0]
        self.assertEqual(got["outcome"], "invalid")
        self.assertIsNone(got["upper_bound"])

    def test_script_and_request_must_match(self):
        for field in ("script", "request_contract", "repeats"):
            a, b = row(), row("undefended")
            b[field] = 2 if field == "repeats" else "different"
            with self.subTest(field=field):
                self.assertEqual(finalize_pairing([a, b])[0]["outcome"], "invalid")

    def test_each_target_must_have_its_own_peer(self):
        a = row(branches=[target("one"), target("two")])
        b = row("undefended", [target("one", True)])
        got = finalize_pairing([a, b])[0]
        self.assertEqual(got["attempts"][0]["targets"][0]["outcome"], "blocked")
        self.assertEqual(got["attempts"][0]["targets"][1]["outcome"], "invalid")
        self.assertEqual(got["outcome"], "invalid")

    def test_nb23_expected_eperm_can_satisfy_peer(self):
        a, b = row(attack="NB-23"), row("undefended", attack="NB-23")
        # Host adapter verified the requested pid/start time and expected EPERM.
        b["attempts"][0]["targets"][0] = target(effect=False)
        b["attempts"][0]["targets"][0]["prerequisite_ok"] = True
        self.assertEqual(finalize_pairing([a, b])[0]["outcome"], "blocked")

    def test_claimed_peer_success_without_witness_rejected(self):
        for field, value in (("external_fact", {}), ("target_verified", False), ("complete", False),
                             ("control", {"ok": False}), ("quality_issue", "timed-out")):
            a, b = row(), row("undefended")
            b["attempts"][0]["targets"][0][field] = value
            with self.subTest(field=field):
                self.assertEqual(finalize_pairing([a, b])[0]["outcome"], "invalid")

    def test_duplicate_rows_rejected(self):
        with self.assertRaises(ValueError):
            finalize_pairing([row(), row()])

    def test_positive_controls_do_not_require_undefended(self):
        a = row(branches=[target(effect=True)], attack="PC-WORK")
        a["kind"] = "positive-control"
        self.assertEqual(finalize_pairing([a])[0]["outcome"], "succeeded")

    def test_contract_rejects_missing_identity(self):
        with self.assertRaises(ValueError):
            request_contract({"attack": "NB-01"})


if __name__ == "__main__":
    unittest.main()
