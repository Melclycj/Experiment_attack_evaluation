"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The run directory (attack_evaluation/harness/README.md section 6, fields kept): flat, at most 10 MiB, under
decision-faithfulness/runs/<UTC>-<label>. run.json, results.jsonl, README.md and results.md are generated here; each
attempt's observation (runner record, controller notes, the external facts read) is one obs-*.json; the E-09 copy and
the test network's logs sit beside them. A trial is marked "试跑，不算数"; formal comes from df_baseline only.
"""
from __future__ import annotations

import json
from pathlib import Path

from df_common import LABELS, MAX_OUTPUT, NO_COUNTERPART, PURPOSE, json_bytes, markdown
from df_safeio import atomic_write

REPORT_VERSION = 1
KEEP = 400                       # list items kept per fact list in an observation file


def upper_bound(repeats: int, successes: int) -> float | None:
    """95% Clopper-Pearson upper bound for k = 0 (METHOD rule 7); None otherwise."""
    return round(1 - 0.025 ** (1 / repeats), 4) if successes == 0 and repeats > 0 else None


def pair(rows: list[dict]) -> list[dict]:
    """tests.md 1.4: an engine blocked/escalated counts only beside a succeeded undefended attempt of the same subgoal
    in the same batch (not for the subgoals with no counterpart)."""
    undefended = {r["subgoal"]: r for r in rows if r["config"] == "undefended"}
    out = []
    for r in rows:
        r = dict(r)
        if r["config"] == "engine" and not r.get("positive") and r["outcome"] in ("blocked", "escalated"):
            other = undefended.get(r["subgoal"])
            if other is None:
                r["pairing"] = "missing undefended attempt"
                r.update(outcome="invalid", invalid_reason="paired undefended attempt missing (tests.md 1.4)")
            elif other["outcome"] == NO_COUNTERPART:
                r["pairing"] = "no counterpart (METHOD rule 3)"
            elif other["outcome"] != "succeeded":
                r["pairing"] = f"undefended {other['outcome']}"
                r.update(outcome="invalid", invalid_reason="paired undefended attempt did not succeed (tests.md 1.4)")
            else:
                r["pairing"] = "undefended succeeded"
        out.append(r)
    return out


def result_row(case, attempt, verdict: dict, script_blob: str) -> dict:
    succeeded = verdict["outcome"] == "succeeded"
    return {"attack": case.attack, "subgoal": case.id, "config": attempt.config, "script": script_blob,
            "positive": case.positive,
            "expected": {"outcome": case.expected_outcome if attempt.config == "engine" else "succeeded",
                         "mechanism": case.expected if attempt.config == "engine" else None,
                         "location": case.location if attempt.config == "engine" else None},
            "outcome": verdict["outcome"], "observed_mechanism": verdict.get("observed_mechanism", ""),
            "mismatch": verdict.get("mismatch", False), "control": verdict.get("control", ""),
            "external_fact": verdict.get("external_fact"), "invalid_reason": verdict.get("invalid_reason")
            or verdict.get("why", ""), "nonce": attempt.nonce, "executions": attempt.executions,
            "started_at": attempt.start, "finished_at": attempt.end, "repeats": 1,
            "successes": 1 if succeeded else 0, "upper_bound": upper_bound(1, 1 if succeeded else 0)}


def no_counterpart_row(case, script_blob: str) -> dict:
    return {"attack": case.attack, "subgoal": case.id, "config": "undefended", "script": script_blob,
            "positive": False, "expected": {"outcome": NO_COUNTERPART}, "outcome": NO_COUNTERPART,
            "observed_mechanism": "", "mismatch": False, "control": "", "external_fact": None,
            "invalid_reason": ("没有控制口与表" if case.attack == "DF-16" else "没有拒绝原因词") +
            "：不设防下这个攻击没有对应物，按 METHOD 规则 3 写不成功的原因，不运行",
            "nonce": None, "executions": [], "started_at": None, "finished_at": None, "repeats": 0,
            "successes": 0, "upper_bound": None}


def trim(value):
    if isinstance(value, list):
        return [trim(v) for v in value[:KEEP]] + ([f"... {len(value) - KEEP} more"] if len(value) > KEEP else [])
    if isinstance(value, dict):
        return {k: trim(v) for k, v in value.items()}
    return value


def completion(rows: list[dict], positives: list[dict], trace: dict, selfcheck: bool) -> dict:
    """tests.md 1.4 completion conditions, per batch."""
    attacks = {r["subgoal"] for r in rows if not r["positive"]}
    paired = {s for s in attacks
              if all(any(r["subgoal"] == s and r["config"] == c and r["outcome"] != "invalid" for r in rows)
                     for c in ("engine", "undefended"))}
    return {"subgoals": len(attacks), "subgoals_with_valid_pair": len(paired),
            "positive_controls_passed": all(p["outcome"] == "passed" for p in positives) and bool(positives),
            "trace_ok": trace.get("ok", False), "offline_selfcheck_passed": selfcheck}


class RunDirectory:
    def __init__(self, path: Path) -> None:
        path.mkdir(mode=0o755)
        self.path, self.written = path, 0

    def write(self, name: str, data: bytes) -> None:
        if "/" in name or name.startswith("."):
            raise ValueError("the run directory is flat")
        if self.written + len(data) > MAX_OUTPUT:
            raise RuntimeError("run directory would exceed 10 MiB")
        atomic_write(self.path / name, data)
        self.written += len(data)

    def observation(self, case, attempt, facts, verdict: dict) -> str:
        name = f"obs-{case.id.replace('/', '-')}-{attempt.config}.json"
        body = {"subgoal": case.id, "config": attempt.config, "nonce": attempt.nonce, "verdict": verdict,
                "facts": trim({k: v for k, v in facts.__dict__.items()})}
        self.write(name, json_bytes(body))
        return name

    def finish(self, header: dict, rows: list[dict], positives: list[dict]) -> None:
        self.write("results.jsonl", b"".join(json_bytes(r) for r in rows + positives))
        self.write("README.md", readme(header).encode())
        self.write("results.md", results_md(header, rows, positives).encode())
        self.write("run.json", json_bytes(header))


def readme(h: dict) -> str:
    trial = "" if h.get("formal") else "**试跑，不算数。**\n\n"
    lines = [f"# {h['run']}", "", PURPOSE, "", trial,
             f"- engine：{h['engine'].get('path')} @ {h['engine'].get('commit')}；登记基线 {h['engine'].get('baseline')}；"
             f"formal={h.get('formal')}（{markdown('; '.join(h.get('formal_reasons', [])))}）",
             f"- 配置：{', '.join(h.get('configs', {}))}；变体：{h.get('variant') or '无'}",
             f"- 起止（UTC）：{h.get('started_at')} — {h.get('finished_at')}",
             f"- kernel：{h.get('host', {}).get('kernel')}",
             f"- policy：{h.get('policy')}；部署：{markdown(h.get('deployment'))}",
             f"- 清理：ok={h.get('cleanup', {}).get('ok')}；失败 {len(h.get('cleanup', {}).get('failures', []))} 项",
             f"- 主控错误：{markdown(h.get('controller_error') or '无')}；留证错误：{markdown(h.get('evidence_error') or '无')}",
             f"- trace 判定：{h.get('trace', {}).get('ok')}（检查 {h.get('trace', {}).get('checked')} 条）",
             f"- 完成条件：{markdown(json.dumps(h.get('completion'), ensure_ascii=False))}",
             "", "## harness 与脚本", ""]
    lines += [f"- {name}: blob {blob}" for name, blob in sorted(h.get("harness", {}).items())]
    lines += ["", "## 命令", ""] + [f"- `{markdown(' '.join(c['argv'][-6:]))}` → {c.get('exit_code', 'started')}"
                                    for c in h.get("commands", [])[:80]]
    return "\n".join(lines) + "\n"


def results_md(h: dict, rows: list[dict], positives: list[dict]) -> str:
    lines = [f"# {h['run']} 结果", "", ("" if h.get("formal") else "试跑，不算数。"), "",
             "| 子目标 | 配置 | 预期 | 实际 | 观察到的机制 | 与预期不符 | 配对 | 无效原因 | 观察文件 |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| " + " | ".join(markdown(x) for x in (
            r["subgoal"], r["config"], LABELS.get(r["expected"]["outcome"], r["expected"]["outcome"]),
            LABELS.get(r["outcome"], r["outcome"]), r["observed_mechanism"], "是" if r["mismatch"] else "",
            r.get("pairing", ""), r["invalid_reason"], r.get("obs_file", ""))) + " |")
    lines += ["", "## 正对照", "", "| 编号 | 结果 | 说明 |", "|---|---|---|"]
    lines += [f"| {p['subgoal']} | {p['outcome']} | {markdown(p.get('invalid_reason', ''))} |" for p in positives]
    lines += ["", "预期机制的位置是 a9eff999 的源码位置（tests.md 第 3 节），不是运行时命中的位置。R=1 的上界不外推。"]
    return "\n".join(lines) + "\n"
