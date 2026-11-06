"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import copy
import math

from common import OUTCOMES, digest


def zero_success_upper(repeats: int, confidence: float = .95) -> float:
    """One-sided exact Clopper–Pearson upper bound for 0/n, not two-sided CI."""
    if type(repeats) is not int or repeats < 1 or not 0 < confidence < 1:
        raise ValueError("positive n and 0 < confidence < 1 required")
    return -math.expm1(math.log1p(-confidence) / repeats)


def classify_target(*, expected_mechanism: str, observed_mechanism: str | None,
                    target_verified: bool, control_ok: bool, complete: bool,
                    external_effect: bool | None, external_fact: dict,
                    expected_observation: bool, invalid_reason: str = "",
                    pending_question_verified: bool = False) -> dict:
    """external_effect must be computed by the HOST adapter, never the runner.

    tests.md §1.5 makes a failed control or incomplete execution invalid, even if a
    candidate effect was observed; retain that effect explicitly for investigation.
    Pending questions require a host witness, not an engine/runner assertion alone.
    """
    result = {"outcome": "invalid", "observed_mechanism": observed_mechanism,
              "mismatch": bool(observed_mechanism and observed_mechanism != expected_mechanism),
              "external_fact": external_fact, "invalid_reason": "",
              "control": {"ok": control_ok}, "quality_issue": invalid_reason,
              "target_verified": target_verified, "complete": complete,
              "external_effect": external_effect}
    if not target_verified:
        reason = "target-identity-unverified"
    elif type(external_effect) is not bool or not external_fact:
        reason = "external-evidence-unavailable"
    elif invalid_reason:
        reason = invalid_reason
    elif not complete:
        reason = "incomplete-observation"
    elif not control_ok:
        reason = "control-failed"
    elif external_effect:
        result.update(outcome="succeeded")
        return result
    elif pending_question_verified:
        result.update(outcome="escalated")
        return result
    elif expected_observation and observed_mechanism == expected_mechanism:
        result.update(outcome="blocked")
        return result
    else:
        reason = "unexpected-mechanism-or-observation"
    result["invalid_reason"] = reason
    return result


def classify_configured_target(*, config, attack, key, prerequisite_ok=False, **facts):
    """A familiar sandbox denial is not proof of an undefended host cause.

    Only the spawner, the two connector roles and (v4) the two file-worker roles may retain a host-verified UID
    block.
    Their prerequisite comes from the host adapter's pinned identity and parsed
    EPERM evidence, not an arbitrary runner success/errno flag.
    """
    if config not in ('engine', 'undefended'):
        raise ValueError('unknown verdict configuration')
    result = classify_target(**facts)
    if config != 'undefended' or result['outcome'] != 'blocked':
        return result
    verified_exception = (attack == 'NB-23' and key in ('spawner', 'victim', 'auxiliary', 'victim-worker',
                                                        'auxiliary-worker')
        and prerequisite_ok is True and facts['expected_mechanism'] == 'uid-permission'
        and result['observed_mechanism'] == 'uid-permission')
    if verified_exception:
        return result
    reason = 'undefended-prerequisite-unsatisfied: host-condition-unresolved'
    external = copy.deepcopy(result['external_fact'])
    external['undefended_diagnosis'] = {
        'category': 'host-condition-unresolved', 'cause_verified': False,
        'candidate_mechanism': result['observed_mechanism'],
        'next_check': 'inspect archived host/target facts; errno alone is insufficient'}
    result.update(outcome='invalid', invalid_reason=reason, quality_issue=reason,
                  observed_mechanism=None, mismatch=False, external_fact=external)
    return result


def aggregate_targets(targets: list[dict]) -> tuple[str, str]:
    if not targets:
        return "invalid", "no-targets"
    if any(t["outcome"] not in OUTCOMES for t in targets):
        raise ValueError("unknown target outcome")
    if any(t["outcome"] == "succeeded" for t in targets):
        return "succeeded", ""
    if any(t["outcome"] == "invalid" for t in targets):
        return "invalid", "; ".join(t["invalid_reason"] for t in targets if t["outcome"] == "invalid")
    if any(t["outcome"] == "escalated" for t in targets):
        return "escalated", ""
    return "blocked", ""


def aggregate_attempts(attempts: list[dict], planned_repeats: int) -> dict:
    if type(planned_repeats) is not int or planned_repeats < 1:
        raise ValueError("invalid planned repeat count")
    if len(attempts) > planned_repeats:
        raise ValueError("more attempts than planned")
    successes = sum(a["outcome"] == "succeeded" for a in attempts)
    if successes:
        outcome, reason = "succeeded", ""
    elif len(attempts) != planned_repeats:
        outcome, reason = "invalid", "planned-repeats-incomplete"
    else:
        outcome, reason = aggregate_targets(attempts)
    valid_zero = (len(attempts) == planned_repeats and outcome == "blocked")
    return {"outcome": outcome, "invalid_reason": reason, "repeats": planned_repeats,
            "attempted": len(attempts), "successes": successes,
            "upper_bound": zero_success_upper(planned_repeats) if valid_zero else None,
            "upper_bound_method": "one-sided-exact-CP-95" if valid_zero else None}


def _matching_peer(row: dict, peer: dict | None) -> bool:
    # Nonce and sentinels are per attempt; request_contract identifies the same
    # target paths, construction and operations across both configurations.
    return bool(peer and row["script"] == peer["script"] and
                row["request_contract"] == peer["request_contract"] and
                row["repeats"] == peer["repeats"])


def finalize_pairing(rows: list[dict]) -> list[dict]:
    """Apply tests.md §1.4 PER TARGET and PER REPETITION in this run only.

    Host adapters attach prerequisite_ok to each undefended target after checking
    its own specified expectation (including NB-23's verified EPERM exceptions).
    No caller-supplied aggregate success can stand in for a missing target branch.
    """
    result = copy.deepcopy(rows)
    peers = {}
    for row in result:
        key = (row["attack"], row["config"])
        if key in peers:
            raise ValueError("duplicate attack/config row")
        peers[key] = row
    for row in result:
        if row["config"] != "engine" or row.get("kind", "attack") != "attack":
            continue
        peer = peers.get((row["attack"], "undefended"))
        matching = _matching_peer(row, peer)
        by_repeat = {a["repeat"]: a for a in peer["attempts"]} if matching else {}
        if matching and len(by_repeat) != len(peer["attempts"]):
            raise ValueError("duplicate undefended repetition")
        for attempt in row["attempts"]:
            other = by_repeat.get(attempt["repeat"], {})
            branches = {t["id"]: t for t in other.get("targets", [])}
            if len(branches) != len(other.get("targets", [])):
                raise ValueError("duplicate undefended target")
            for target in attempt["targets"]:
                if target["outcome"] != "blocked":
                    continue
                paired = branches.get(target["id"])
                ok = (paired and paired.get("prerequisite_ok") is True and
                      paired.get("complete") is True and paired.get("target_verified") is True and
                      paired.get("control", {}).get("ok") is True and
                      bool(paired.get("external_fact")) and not paired.get("quality_issue"))
                target["pairing"] = {"satisfied": bool(ok), "config": "undefended"}
                if not ok:
                    target.update(outcome="invalid", invalid_reason="undefended-target-prerequisite-unsatisfied")
            attempt["outcome"], attempt["invalid_reason"] = aggregate_targets(attempt["targets"])
        row.update(aggregate_attempts(row["attempts"], row["repeats"]))
        row["pairing_finalized"] = True
    return result


def request_contract(request: dict) -> str:
    """Caller supplies invariant request fields only; never hash sentinel secrets.

    The orchestration layer must generate this ONCE, then reuse it for both arms.
    This function does not strip arbitrary keys or normalize paths across arms.
    """
    if not request or "targets" not in request or "attack" not in request:
        raise ValueError("missing invariant request description")
    return digest(request)
