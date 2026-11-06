"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from common import digest, identity
from judge import aggregate_attempts, aggregate_targets, classify_target

WHEN = "2026-10-31T03:00:00+00:00"


def target(name="file", effect=False, **overrides):
    values = dict(expected_mechanism="file-view", observed_mechanism="file-view", target_verified=True,
                  control_ok=True, complete=True, external_effect=effect,
                  external_fact={"before": "test-only", "after": "test-only"}, expected_observation=True)
    values.update(overrides)
    result = classify_target(**values)
    result.update(id=name, prerequisite_ok=effect)
    return result


def row(config="engine", branches=None, attack="NB-01"):
    branches = branches if branches is not None else [target(effect=config == "undefended")]
    outcome, reason = aggregate_targets(branches)
    attempts = [{"repeat": 1, "targets": branches, "outcome": outcome, "invalid_reason": reason}]
    return dict(attack=attack, config=config, script=identity(b"test-only script"), expected={"mechanism": "file-view"},
                observed=[], observed_mechanism="file-view", mismatch=False, control={"ok": True},
                external_fact={"fixture": True}, started_at=WHEN, finished_at=WHEN, attempts=attempts,
                request_contract=digest({"fixture": True}), **aggregate_attempts(attempts, 1))


def header(name="20261031T030000Z-test", baseline=None, **overrides):
    files = {"engine.py": identity(b"test-only engine")}
    result = dict(run=name, engine={"files": files, "digest": digest(files), "baseline": baseline,
                  "baseline_files": files if baseline else None,
                  "baseline_check": {"executed": bool(baseline), "exit_code": 0 if baseline else None,
                                     "version": baseline}},
                  harness={"digest": digest("test-only harness")}, spec=identity(b"test-only spec"),
                  configs=["engine", "undefended"], host={"kernel_match": True, "readings_match": True},
                  policy={}, deployment={}, commands=[], started_at=WHEN, finished_at=WHEN,
                  cleanup={"ok": True}, cleanup_ok=True, formal=bool(baseline))
    result.update(overrides)
    return result
