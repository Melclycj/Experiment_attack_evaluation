"""Expected v4 values per tier (resident, MiB per agent, non-shared PSS relative to the same round's bare-api-only):
the 10-31 Go rows plus what the 2-unit breakdown (runs/20261105T121513Z-v4-chain) adds per unit. Inference, written
before the formal run. Also the hypothesis-A lines (a quarter of each VM object's smallest value per tier)."""
import json
from pathlib import Path

RUNS = Path("D:/Thesis/ExperimentLab/sota-memory-measurement/runs")
go = json.loads((RUNS / "20261031-memory-analysis-engine-go-rerun/memory-analysis.json").read_text(encoding="utf-8"))
vm = json.loads((RUNS / "20261101-memory-analysis-vm/memory-analysis.json").read_text(encoding="utf-8"))
base = json.loads((RUNS / "20261030-memory-analysis-api-only-bare/memory-analysis.json").read_text(encoding="utf-8"))

FW_PRIV, PY_FILE_TOTAL = 12.2, 6.0      # file worker private; python file pages shared by connectors, workers, core, PDP
MCP_PRIV, MCP_FILE = 1.05, 4.8          # MCP server private; its file pages (all of them in copy mode)


def extra(src: dict, obj: str, n: int) -> tuple[float, float]:
    t = src[f"{obj}/resident"]["tiers"][str(n)]
    vals = t["extra_mib_clean"] or t["extra_mib_all"]
    return min(vals), max(vals)


for n in (1, 2, 4, 8, 16):
    fw = FW_PRIV + PY_FILE_TOTAL / (2 * n + 2)
    lo_s, hi_s = extra(go, "engine-go-shared-runtime", n)
    lo_c, hi_c = extra(go, "engine-go", n)
    add_s, add_c = fw + MCP_PRIV + MCP_FILE / n, fw + MCP_PRIV + MCP_FILE
    lines = {}
    for name, src in (("docker-sandboxes", base), ("gondolin", vm), ("kairos", vm)):
        key = f"{name}/resident"
        if key in src and str(n) in src[key]["tiers"]:
            lines[name] = round(extra(src, name, n)[0] / 4, 1)
    print(f"N={n:2d}  shared 10-31 {lo_s:6.1f}-{hi_s:6.1f} +{add_s:5.1f} -> {lo_s + add_s:6.1f}-{hi_s + add_s:6.1f}   "
          f"copy 10-31 {lo_c:6.1f}-{hi_c:6.1f} +{add_c:5.1f} -> {lo_c + add_c:6.1f}-{hi_c + add_c:6.1f}   lines {lines}")
