"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import LABELS, PURPOSE, digest, markdown, timestamp
from safeio import atomic_write, plain_path
from run_units import report_purpose
from report_view import batch_status, detail_lines, evidence_links, expectation, status_lines, STATES


def render_results(rows: list[dict], header: dict | None = None) -> str:
    lines = [report_purpose(header), "", "# 本次结果", "", *status_lines(header or {}, rows),
             "| 攻击 | 配置 | 记录的预期 | 实际结果 | 成功/计划次数 | 零成功上界（单侧 95% CP） | 核对/说明 | 证据 |",
             "|---|---|---|---|---|---|---|---|"]
    for row in rows:
        bound = "—" if row["upper_bound"] is None else f"{row['upper_bound']:.8g}"
        reason = row["invalid_reason"] or expectation(row)
        expected = LABELS.get(row.get('expected', {}).get('outcome'), '未记录')
        lines.append("| " + " | ".join(map(markdown, [row["attack"], row["config"], expected,
                     LABELS[row["outcome"]], f"{row['successes']}/{row['repeats']}", bound, reason])) +
                     " | " + evidence_links(row['attempts']) + " |")
    lines += ["", "无效/缺失的尝试不进入零成功置信上界。跨配置前提见下表逐目标配对状态。",
              "上界仅描述本项有效重复；R=1 时 0/1 的上界为 0.95，不能外推为广义安全保证。",
              "试跑及未完整结束的批次不作正式通过；不因批级失败抹去已有局部观察。", ""]
    for row in rows:
        lines.extend(detail_lines(row))
    return "\n".join(lines)


def same_code_key(header: dict, row: dict) -> tuple:
    return (row["attack"], row["config"], header["engine"]["digest"], digest(header["harness"]),
            digest(header["spec"]), digest(row["script"]))


def history(runs: list[tuple[dict, list[dict]]]) -> str:
    """Keep all formal versions, latest trial; scan ALL runs for inconsistent outcomes.

    No document mutation: repeat escalation and regressions are reported, never
    silently change tests.md's preregistered R or attacks.md's expected column.
    """
    runs = sorted(runs, key=lambda x: (timestamp(x[0]["started_at"]), x[0]["run"]))
    columns, outcomes, signatures, witnesses = {}, defaultdict(set), {}, defaultdict(list)
    rows_by_run = {header["run"]: rows for header, rows in runs}
    for header, rows in runs:
        version = header["engine"]["baseline"] if header["formal"] else "trial"
        columns.setdefault(version, {})
        if version == "trial":
            columns[version] = {}  # only the latest trial, even if its subset is smaller
        for row in rows:
            key = same_code_key(header, row)
            outcomes[key].add(row["outcome"])
            witnesses[key].append((header["run"], row["outcome"]))
            signatures[(header["run"], row["attack"], row["config"])] = key
            columns[version][(row["attack"], row["config"])] = (header, row)
    # Trial always last, independent of the order a formal baseline first appeared.
    order = [v for v in columns if v != "trial"] + (["trial"] if "trial" in columns else [])
    attacks = sorted({attack for col in columns.values() for attack, _ in col})
    units = {h.get('unit', 'no-bypass') for h, _ in runs}
    if len(units) > 1: raise ValueError('cannot merge histories from different units')
    lines = [report_purpose(runs[-1][0] if runs else None), "", "# 运行历史（只汇总 COMPLETE.json 完整的运行）", "",
             "| 攻击 | " + " | ".join(markdown("最近试跑（不算数）" if v == "trial" else v) for v in order) + " |",
             "|---|" + "---|" * len(order)]
    for attack in attacks:
        cells, previous = [], {}
        for version in order:
            parts = []
            for (aid, config), (header, row) in sorted(columns[version].items()):
                if aid != attack:
                    continue
                flags = []
                key = signatures[(header["run"], aid, config)]
                if len(outcomes[key]) > 1:
                    flags.append("同码异果：需预定重复 R")
                old = previous.get(config)
                if old and old != row["outcome"]:
                    flags.append("**挡住→成功**" if old == "blocked" and row["outcome"] == "succeeded" else "结果变化")
                previous[config] = row["outcome"]
                state = batch_status(header, rows_by_run[header['run']])
                if state['state'] != 'completed':
                    flags.append('批次' + STATES[state['state']])
                if expectation(row) != '符合记录的预期':
                    flags.append(expectation(row))
                if not header.get("cleanup_ok"):
                    flags.append("清理未通过")
                parts.append(f"{markdown(config)}：{LABELS[row['outcome']]}（{markdown(header['run'])}）" +
                             ("；" + "；".join(flags) if flags else ""))
            cells.append("<br>".join(parts) or "—")
        lines.append("| " + markdown(attack) + " | " + " | ".join(cells) + " |")
    lines += ["", "## 批次状态（包括无结果的失败运行）", ""]
    for header, rows in runs:
        state = batch_status(header, rows)
        lines.append('- ' + markdown(header['run']) + '：' + STATES[state['state']] +
                     ('；' + markdown('；'.join(state['reasons'])) if state['reasons'] else ''))
    lines += ["", "同码比较包含 engine、harness、规格与脚本；每次运行的新诱饵路径与随机串不拆散比较。"
              "不将未测、试跑或清理失败当作正式通过。", ""]
    inconsistent = [key for key in outcomes if len(outcomes[key]) > 1]
    if inconsistent:
        lines += ["## 同码异果的全部见证（包括历史列里隐藏的旧试跑）", ""]
        for key in sorted(inconsistent):
            entries = "；".join(f"{markdown(run)}={LABELS[outcome]}" for run, outcome in witnesses[key])
            lines.append(f"- {markdown(key[0])} / {markdown(key[1])} / {markdown(key[2])}：{entries}；需预定重复 R。")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline only: summarize completed harness runs; never starts engine")
    parser.add_argument("runs", type=Path)
    parser.add_argument("--write-history", action="store_true", help="explicitly replace derived history.md, saving a backup")
    args = parser.parse_args()
    from record import load_run
    parent, collected, errors = plain_path(args.runs), [], []
    for path in sorted(parent.iterdir()):
        if path.name == "history.md" or path.name.startswith("history.md."):
            continue
        try:
            plain_path(path)
            if not path.is_dir():
                raise ValueError("unexpected file in runs directory")
            collected.append(load_run(path))
        except (ValueError, OSError, KeyError) as error:
            errors.append(f"{path.name}: {error}")
    if errors:
        print("拒绝生成不完整的历史表：\n" + "\n".join(errors), file=sys.stderr)
        return 2
    rendered = history(collected)
    if args.write_history:
        target = parent / "history.md"
        if target.exists():
            from safeio import read_owned
            old = read_owned(target)
            backup = parent / ("history.md." + digest(old.hex()).split(":")[1][:16] + ".bak")
            if not backup.exists():
                atomic_write(backup, old)
        atomic_write(target, rendered.encode("utf-8"), replace=True)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
