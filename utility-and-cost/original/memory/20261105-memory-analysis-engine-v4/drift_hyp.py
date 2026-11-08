"""Cross-round drift of the anchors and hypothesis A (protocol.md 7) for the v4 round. Resident state, MiB per agent.
Usage: drift_hyp.py <this round's memory-analysis.json>

Drift: bare-api-only's unit PSS per agent and Docker Sandboxes' non-shared extra per tier in this round next to the
earlier rounds (10-30 bare-api-only run, 10-31 Go rerun, 10-31 evening VM round; Docker Sandboxes 10-30 and 10-31
evening). Hypothesis A: per tier, the largest of this paper's three repetitions against min(250, a quarter of each VM
object's smallest repetition): Docker Sandboxes from this round, Gondolin and Kairos from the 10-31 evening round
(the only round that has them, so that comparison crosses rounds). Clean readings; all readings next to them."""
import json
import sys
from pathlib import Path

RUNS = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "INDEX.md").exists() else \
    Path("D:/Thesis/ExperimentLab/sota-memory-measurement/runs")
TIERS = (1, 2, 4, 8, 16)
ROUNDS = {"10-30": RUNS / "20261030-memory-analysis-api-only-bare/memory-analysis.json",
          "10-31": RUNS / "20261031-memory-analysis-engine-go-rerun/memory-analysis.json",
          "10-31 evening": RUNS / "20261101-memory-analysis-vm/memory-analysis.json"}


def tier(src: dict, obj: str, n: int) -> dict | None:
    return (src.get(f"{obj}/resident") or {}).get("tiers", {}).get(str(n))


def vals(t: dict | None, key: str) -> list[float]:
    if not t:
        return []
    return [v for v in (t.get(f"{key}_clean") or []) if v is not None] if key == "extra_mib" else \
        [v for v in (t.get(key) or []) if v is not None]


def rng(xs: list[float]) -> str:
    return f"{min(xs):.1f}–{max(xs):.1f}" if xs else "—"


def main() -> None:
    now = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    old = {k: json.loads(p.read_text(encoding="utf-8")) for k, p in ROUNDS.items() if p.exists()}
    print("## bare-api-only, unit PSS per agent (resident)")
    for n in TIERS:
        cells = [f"{k} {rng(vals(tier(src, 'bare-api-only', n), 'per_unit_mib'))}" for k, src in old.items()]
        print(f"N={n:2d}  this round {rng(vals(tier(now, 'bare-api-only', n), 'per_unit_mib'))}   " + "   ".join(cells))
    print("\n## docker-sandboxes, non-shared extra per agent (resident, each round against its own bare-api-only)")
    for n in TIERS:
        cells = [f"{k} {rng(vals(tier(src, 'docker-sandboxes', n), 'extra_mib'))}" for k, src in old.items()
                 if tier(src, 'docker-sandboxes', n)]
        print(f"N={n:2d}  this round {rng(vals(tier(now, 'docker-sandboxes', n), 'extra_mib'))}   " + "   ".join(cells))
    vm = old.get("10-31 evening", {})
    print("\n## hypothesis A: this paper's largest repetition against min(250, VM smallest / 4)")
    for obj in ("engine-v4-shared", "engine-v4-copy"):
        verdicts = []
        for n in TIERS:
            mine = vals(tier(now, obj, n), "extra_mib")
            mine_all = [v for v in (tier(now, obj, n) or {}).get("extra_mib_all", []) if v is not None]
            lines = {"docker-sandboxes": vals(tier(now, "docker-sandboxes", n), "extra_mib"),
                     "gondolin": vals(tier(vm, "gondolin", n), "extra_mib"),
                     "kairos": vals(tier(vm, "kairos", n), "extra_mib")}
            parts = []
            for name, xs in lines.items():
                if not xs or not mine:
                    parts.append(f"{name} 不可检验")
                    continue
                line = min(250.0, min(xs) / 4)
                ok = max(mine) < line
                verdicts.append(ok)
                parts.append(f"{name} {max(mine):.1f} 对 {line:.1f} {'满足' if ok else '不满足'}")
            print(f"{obj} N={n:2d} (clean {rng(mine)}, all {rng(mine_all)}): " + "; ".join(parts))
        print(f"{obj}: {'每档都满足' if verdicts and all(verdicts) else '有档不满足或不可检验'}\n")


if __name__ == "__main__":
    main()
