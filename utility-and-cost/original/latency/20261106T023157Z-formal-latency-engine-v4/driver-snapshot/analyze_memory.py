"""Memory-column analysis of one run directory (protocol.md 3.1). Reads memory-records.jsonl (read-only) and writes
memory-analysis.json and memory-analysis.md next to it.

Per object, tier and state:
- non-shared extra memory per agent: the unit group's PSS / N minus the bare reference's unit PSS / N at the same
  tier and state;
- shared fixed cost: baseline 2 minus baseline 1 (host used memory), and the shared group's own PSS per tier;
- overall marginal cost: slope of host used memory over N (relative to baseline 1) minus the bare slope on the same
  tiers; a second fit uses "this tier's reading - its pre-build reading + the shared fixed cost", and the two are
  flagged when they differ by more than 20 %.
Repetitions are numbered across passes (pass 1's reps first) and paired by that number; the range over the pairs is
reported. Of the attempts of one repetition, the last one counts. A reading is flagged when it is unstable, timed
out settling, interfered, has incomplete PSS or (resident) a unit not at its prompt; flagged readings are left out of
the clean numbers and of the bare reference. An object whose resident readings are less than half clean gets
"未证" for the main comparison.

    python3 -m driver.analyze_memory runs/<run dir>
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

BARE = "bare"
FIT_GAP = 0.20


def load(run: Path) -> list[dict]:
    return [json.loads(line) for line in (run / "memory-records.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()]


def slope(points: list[tuple[int, float]]) -> float | None:
    if len({n for n, _ in points}) < 2:
        return None
    xs, ys = [n for n, _ in points], [v for _, v in points]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)


def flags(s: dict) -> list[str]:
    out = [f for f in ("unstable", "settle_timed_out", "interfered", "pss_incomplete") if s.get(f)]
    if s.get("not_at_prompt"):
        out.append("not_at_prompt")
    return out


def readings(records: list[dict], reps_pass1: int) -> tuple[dict, dict, dict]:
    """(rows by (object, state), baseline 1 by (object, pass), baseline 2 by (object, pass)). One row per
    repetition: its last attempt."""
    base1, base2, pre, last = {}, {}, {}, {}
    for r in records:
        obj = r.get("object")
        if r["kind"] == "baseline1":
            base1[(obj, r["pass_no"])] = r["reading"]["host"]
        elif r["kind"] == "baseline2":
            base2[(obj, r["pass_no"])] = r["reading"]["host"]
        elif r["kind"] == "prebuild":
            pre[(obj, r["pass_no"], r["n"], r["rep"], r["attempt"])] = r["reading"]["host"]
        elif r["kind"] == "rep":
            k = (obj, r["pass_no"], r["n"], r["rep"])
            if k not in last or r["attempt"] >= last[k]["attempt"]:
                last[k] = r
    rows = defaultdict(list)
    for (obj, pass_no, n, rep), r in last.items():
        b1, b2 = base1[(obj, pass_no)], base2[(obj, pass_no)]
        p = pre.get((obj, pass_no, n, rep, r["attempt"]))
        for state, s in r["states"].items():
            h = s["host"]
            rows[(obj, state)].append({
                "n": n, "seq": rep + reps_pass1 * (pass_no - 1), "pass_no": pass_no, "attempt": r["attempt"],
                "per_unit_mib": h["groups"]["unit"]["pss_mib"] / n,
                "shared_mib": h["groups"].get("shared", {}).get("pss_mib", 0.0),
                "used_delta_mib": h["used_mib"] - b1["used_mib"],
                "fit2_mib": h["used_mib"] - p["used_mib"] + (b2["used_mib"] - b1["used_mib"]) if p else None,
                "committed_delta_mib": h["Committed_AS"] - b1["Committed_AS"],
                "flags": flags(s)})
    return rows, base1, base2


def bare_reference(bare: list[dict], n: int, seq: int) -> tuple[float | None, str]:
    """The bare per-unit PSS for repetition seq at tier n: its paired repetition if that one is clean, else the mean
    of the clean bare repetitions at n."""
    clean = [b for b in bare if b["n"] == n and not b["flags"]]
    paired = [b for b in clean if b["seq"] == seq]
    if paired:
        return paired[0]["per_unit_mib"], "paired"
    if clean:
        return statistics.fmean(b["per_unit_mib"] for b in clean), "mean of clean"
    return None, "none clean"


def _range(vals: list[float]) -> list[float] | None:
    return [round(min(vals), 1), round(max(vals), 1)] if vals else None


def _slopes(rows: list[dict], bare: list[dict], key: str) -> dict[int, float]:
    """Per repetition number: object slope minus bare slope over the tiers both have clean readings for."""
    out = {}
    for seq in sorted({x["seq"] for x in rows}):
        mine = {x["n"]: x[key] for x in rows if x["seq"] == seq and not x["flags"] and x[key] is not None}
        ref = {b["n"]: b[key] for b in bare if b["seq"] == seq and not b["flags"] and b[key] is not None}
        tiers = sorted(set(mine) & set(ref))
        s, s0 = slope([(n, mine[n]) for n in tiers]), slope([(n, ref[n]) for n in tiers])
        if s is not None and s0 is not None:
            out[seq] = s - s0
    return out


def analyse(records: list[dict], reps_pass1: int, bare_name: str = BARE) -> dict:
    rows_by, base1, base2 = readings(records, reps_pass1)
    out = {}
    for (obj, state), rows in rows_by.items():
        bare = rows_by.get((bare_name, state), [])
        tiers = {}
        for n in sorted({x["n"] for x in rows}):
            at = sorted((x for x in rows if x["n"] == n), key=lambda x: x["seq"])
            extra_all, extra_clean, refs = [], [], []
            for x in at:
                ref, how = bare_reference(bare, n, x["seq"])
                refs.append(how)
                if ref is None:
                    continue
                extra_all.append(x["per_unit_mib"] - ref)
                if not x["flags"]:
                    extra_clean.append(x["per_unit_mib"] - ref)
            tiers[n] = {"readings": len(at), "flagged": sum(1 for x in at if x["flags"]),
                        "flags": [x["flags"] for x in at], "seq": [x["seq"] for x in at],
                        "per_unit_mib": [round(x["per_unit_mib"], 1) for x in at],
                        "bare_reference": refs,
                        "extra_mib_all": [round(v, 1) for v in extra_all], "extra_range_all": _range(extra_all),
                        "extra_mib_clean": [round(v, 1) for v in extra_clean],
                        "extra_range_clean": _range(extra_clean),
                        "shared_mib": [round(x["shared_mib"], 1) for x in at],
                        "host_used_delta_mib": [round(x["used_delta_mib"], 1) for x in at]}
        fit1, fit2 = _slopes(rows, bare, "used_delta_mib"), _slopes(rows, bare, "fit2_mib")
        gaps = {seq: abs(fit1[seq] - fit2[seq]) / abs(fit1[seq]) > FIT_GAP
                for seq in fit1 if seq in fit2 and fit1[seq] != 0}
        clean = sum(1 for x in rows if not x["flags"])
        fixed = [b2["used_mib"] - base1[k]["used_mib"] for k, b2 in base2.items() if k[0] == obj]
        out[f"{obj}/{state}"] = {
            "object": obj, "state": state, "tiers": tiers,
            "marginal_extra_fit1_mib": {s: round(v, 1) for s, v in fit1.items()},
            "marginal_extra_fit1_range": _range(list(fit1.values())),
            "marginal_extra_fit2_mib": {s: round(v, 1) for s, v in fit2.items()},
            "marginal_extra_fit2_range": _range(list(fit2.values())),
            "fits_differ_over_20pct": sorted(s for s, g in gaps.items() if g),
            "shared_fixed_used_mib": [round(v, 1) for v in fixed],
            "clean_readings": clean, "readings": len(rows),
            "main_comparison": "未证" if state == "resident" and clean * 2 < len(rows) else "ok"}
    return out


def markdown(result: dict) -> str:
    lines = ["| 对象 | 状态 | 档 | 读数（有标记） | 每单位独占（MiB） | 非共享额外，剔除后（范围，MiB） | 共用部件那组（MiB） |",
             "|---|---|---|---|---|---|---|"]
    for key in sorted(result):
        r = result[key]
        for n, t in r["tiers"].items():
            lines.append(f"| {r['object']} | {r['state']} | {n} | {t['readings']}（{t['flagged']}） | "
                         f"{t['per_unit_mib']} | {t['extra_range_clean']} | {t['shared_mib']} |")
    lines += ["", "| 对象 | 状态 | 整体边际成本，拟合一（范围，MiB） | 拟合二（范围，MiB） | 相差超 20% 的重复 | "
                  "共用部件固定成本（MiB） | 主比较 |", "|---|---|---|---|---|---|---|"]
    for key in sorted(result):
        r = result[key]
        lines.append(f"| {r['object']} | {r['state']} | {r['marginal_extra_fit1_range']} | "
                     f"{r['marginal_extra_fit2_range']} | {r['fits_differ_over_20pct']} | "
                     f"{r['shared_fixed_used_mib']} | {r['main_comparison']} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    """One run: results go next to it. Several runs (e.g. a follow-up run of one object, whose bare reference is in
    the main run) with --out DIR: their records are analysed together and the results go to DIR. --bare NAME picks
    the reference object (default "bare")."""
    args = sys.argv[1:]
    out, bare_name = None, BARE
    if "--bare" in args:
        i = args.index("--bare")
        bare_name, args = args[i + 1], args[:i] + args[i + 2:]
    if "--out" in args:
        i = args.index("--out")
        out, args = Path(args[i + 1]), args[:i] + args[i + 2:]
    runs = [Path(a) for a in args]
    if len(runs) > 1 and out is None:
        sys.exit("several runs need --out DIR")
    cfgs = [json.loads((r / "config.json").read_text(encoding="utf-8")) for r in runs]
    if len({c["reps_pass1"] for c in cfgs}) != 1:
        sys.exit("runs differ in reps_pass1")
    records = []
    for i, r in enumerate(runs):
        # an object a later run measures again (a follow-up) is taken from that later run only
        later = {o for c in cfgs[i + 1:] for o in c["objects"]}
        records += [x for x in load(r) if x.get("object") not in later]
    result = analyse(records, cfgs[0]["reps_pass1"], bare_name)
    out = out or runs[0]
    out.mkdir(exist_ok=True)
    (out / "memory-analysis.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    (out / "memory-analysis.md").write_text(markdown(result), encoding="utf-8")
    (out / "sources.json").write_text(json.dumps({"runs": [str(r) for r in runs], "bare": bare_name}, indent=1),
                                      encoding="utf-8")
    print(markdown(result))


if __name__ == "__main__":
    main()
