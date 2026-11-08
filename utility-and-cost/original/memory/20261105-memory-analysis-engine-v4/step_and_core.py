"""Two read-only checks on the v4 round, from its 1 Hz host samples and records.
1. Did each resident reading come after Claude Code's ~2-minute memory step? The same reading as
   runs/20261101-checks-resident-step-and-model-api/step_check.py: unit PSS per agent from the start of the wait to the
   end of the window; the last moment before the window it differed from the window's mean by more than 5 MiB.
2. How the shared group's PSS grows inside one core run: its PSS just before each repetition is built (no row online)
   against the rows started so far in that core run, per core run; the rows counted from the rep records' notes.
Usage: python -X utf8 step_and_core.py <run dir>"""
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

THRESH = 5.0
run = Path(sys.argv[1])
rows = []
for f in sorted(run.glob("host-*/host-samples.jsonl")):
    for line in f.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        u = r.get("groups", {}).get("unit")
        if u:
            rows.append((r["t"], u["pss_mib"]))
recs = [json.loads(x) for x in (run / "memory-records.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]

summary = defaultdict(list)
for rec in recs:
    if rec["kind"] != "rep":
        continue
    res, n = rec["states"]["resident"], rec["n"]
    start, t0, t1 = res["t0"] - res["settle_s"], res["t0"], res["t1"]
    seg = [(t - start, p / n) for t, p in rows if start <= t <= t1]
    win = [p for dt, p in seg if dt >= t0 - start]
    if not win or len(seg) < 30:
        summary[rec["object"]].append(None)
        continue
    ref = statistics.fmean(win)
    before = [(dt, p) for dt, p in seg if 20 <= dt < t0 - start]
    last_off = max((dt for dt, p in before if abs(p - ref) > THRESH), default=None)
    early = [p for dt, p in seg if 20 <= dt <= 60]
    summary[rec["object"]].append({"wait": round(res["settle_s"]), "last_off": last_off,
                                   "step": ref - (statistics.fmean(early) if early else ref)})
print("## resident step: window minus 20-60 s (MiB per agent); last >5 MiB off before the window (s after the wait began)")
for obj, items in summary.items():
    ok = [x for x in items if x]
    offs = [x["last_off"] for x in ok if x["last_off"] is not None]
    waits = [x["wait"] for x in ok]
    steps = [x["step"] for x in ok]
    print(f"{obj:18s} reps {len(ok):2d}  wait {min(waits)}-{max(waits)} s  step {min(steps):6.1f} .. {max(steps):6.1f}  "
          f"off-plateau {len(offs)}/{len(ok)}" + (f", last at {min(offs):.0f}-{max(offs):.0f} s" if offs else "")
          + (f"  missing {len(items) - len(ok)}" if len(items) != len(ok) else ""))

print("\n## shared group's PSS just before each build, against the rows started so far in that core run (one per pass)")
rows_so_far: dict = {}
points: dict = defaultdict(list)
for rec in recs:
    key = (rec.get("object"), rec.get("pass_no"))
    if rec["kind"] == "baseline2":
        rows_so_far[key] = 1                                  # the model check's row
    elif rec["kind"] == "prebuild" and rec.get("object", "").startswith("engine"):
        reading = rec["reading"]
        shared = reading.get("first", reading).get("groups", {}).get("shared", {}).get("pss_mib")
        points[key].append((rows_so_far.get(key, 1), shared))
    elif rec["kind"] == "rep":
        rows_so_far[key] = rows_so_far.get(key, 1) + 2 * rec["n"]    # one probe and one claude row per unit
for key, pts in sorted(points.items(), key=str):
    xs, ys = [x for x, y in pts if y is not None], [y for x, y in pts if y is not None]
    if len(xs) >= 2:
        mx, my = statistics.fmean(xs), statistics.fmean(ys)
        b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
        print(f"{key[0]} pass {key[1]}: slope {b:.2f} MiB per row started, intercept {my - b * mx:.1f}; "
              + " ".join(f"{x}:{y:.0f}" for x, y in zip(xs, ys)))
