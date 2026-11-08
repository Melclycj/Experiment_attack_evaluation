"""Reads a latency run (driver/latency.py, protocol.md 3.3) and computes what the engine adds to one request.

    python3 -m driver.analyze_latency <run dir>      # writes latency-analysis.json and latency-analysis.md beside it

For each block and pass: the difference between the engine arm and the same pass's direct arm, at the median and at
p99, by the nearest-rank method on the raw samples after the warm-up. A difference of p99s is not the p99 of the added
time. The three passes are reported as a range, with no statistical test; samples within a pass are correlated and
are not pooled. Blocks that failed their checks are reported and left out of the range.

The core's own segments come from the engine's records and are for scale only (protocol.md 3.3): they are not added up
and are not a breakdown of the client's time.
"""
from __future__ import annotations

import gzip
import json
import math
import sys
from pathlib import Path

ITER, REQ, TLS, CONNECTING, FAILED = ("iteration_duration", "http_req_duration", "http_req_tls_handshaking",
                                      "http_req_connecting", "http_req_failed")
SEGMENTS = (("admitted to decided", "request_admitted", "request_decided"),
            ("PDP round trip", "pdp_requested", "pdp_answered"))
LOG_FIELDS = ("msec", "request_time", "connection", "connection_requests", "session_reused", "protocol", "method",
              "uri", "status", "request_length", "bytes_sent", "host")
KEEPALIVE_SHARE = 0.99          # of measured requests on a connection already used, when reuse is claimed
BIG_BODY, BIG_RESPONSE = 64 * 1024, 1024 * 1024


def nearest_rank(values: list[float], q: float) -> float:
    """protocol.md 2.3: the smallest sample with at least q of the samples at or below it."""
    if not values or not 0 < q <= 1:
        raise ValueError("nearest_rank needs samples and 0 < q <= 1")
    ordered = sorted(values)
    return ordered[math.ceil(q * len(ordered)) - 1]


def read_k6(lines) -> list[dict]:
    """One row per iteration of the block's scenario, in order, from k6's JSON output. Setup's iteration and any other
    scenario's metrics are left out. One VU makes one request per iteration, so the n-th of each metric belongs to
    the n-th iteration."""
    series: dict[str, list] = {ITER: [], REQ: [], TLS: [], CONNECTING: [], FAILED: []}
    statuses, protos = [], []
    for line in lines:
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("type") != "Point" or e.get("metric") not in series:
            continue
        tags = e["data"].get("tags") or {}
        if tags.get("scenario") != "block" or tags.get("group", "") == "::setup":
            continue
        series[e["metric"]].append(e["data"]["value"])
        if e["metric"] == REQ:
            statuses.append(tags.get("status"))
            protos.append(tags.get("proto"))
    n = len(series[ITER])
    for name, values in series.items():
        if len(values) != n:
            raise ValueError(f"{len(values)} {name} points against {n} iterations")
    return [{"iter_ms": series[ITER][i], "req_ms": series[REQ][i], "tls_ms": series[TLS][i],
             "connecting_ms": series[CONNECTING][i], "failed": series[FAILED][i], "status": statuses[i],
             "proto": protos[i]} for i in range(n)]


def read_upstream(lines) -> list[dict]:
    rows = []
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        if len(parts) != len(LOG_FIELDS):
            raise ValueError(f"upstream log line has {len(parts)} fields: {line!r}")
        rows.append(dict(zip(LOG_FIELDS, parts)))
    return rows


def check_block(block: dict, k6: list[dict], upstream: list[dict], warmup: int, total: int) -> list[str]:
    """What must hold for a block to count: every request made, answered 200 and seen once upstream, and the
    connection behaviour the block is named for."""
    bad = []
    if len(k6) != total:
        bad.append(f"k6 made {len(k6)} requests, expected {total}")
    wrong = [r["status"] for r in k6 if r["status"] != "200"]
    if wrong:
        bad.append(f"k6 saw {len(wrong)} responses other than 200, first {wrong[0]}")
    if len(upstream) != total:
        bad.append(f"upstream logged {len(upstream)} requests, expected {total}")
    if len({r["uri"] for r in upstream}) != len(upstream):
        bad.append("upstream saw a path twice")
    wrong = [r["status"] for r in upstream if r["status"] != "200"]
    if wrong:
        bad.append(f"upstream answered {len(wrong)} requests other than 200, first {wrong[0]}")
    measured = upstream[warmup:]
    reused = sum(int(r["connection_requests"]) > 1 for r in measured)
    if block["conn"] == "keepalive" and measured and reused / len(measured) < KEEPALIVE_SHARE:
        bad.append(f"keepalive: only {reused} of {len(measured)} requests upstream reused a connection")
    if block["conn"] == "bothcold" and reused:
        bad.append(f"bothcold: {reused} requests upstream reused a connection")
    if block["size"] == "big":
        small = [r for r in measured if int(r["request_length"]) < BIG_BODY or int(r["bytes_sent"]) < BIG_RESPONSE
                 or r["method"] != "POST"]
        if small:
            bad.append(f"big: {len(small)} requests not a POST, or smaller than the 64 KiB body or the 1 MiB response")
    return bad


def connection_facts(k6: list[dict], upstream: list[dict], warmup: int) -> dict:
    """Which handshakes happened, as the client and the upstream saw them (protocol.md 3.3 asks for them per hop)."""
    measured_k6, measured_up = k6[warmup:], upstream[warmup:]
    return {"client_tls_handshakes": sum(r["tls_ms"] > 0 for r in measured_k6),
            "client_new_connections": sum(r["connecting_ms"] > 0 for r in measured_k6),
            "upstream_new_connections": sum(int(r["connection_requests"]) == 1 for r in measured_up),
            "upstream_session_reused": sum(r["session_reused"] == "r" for r in measured_up),
            "protocols": sorted({r["proto"] or "" for r in measured_k6}),
            "upstream_protocols": sorted({r["protocol"] for r in measured_up})}


def differences(blocks: list[dict]) -> dict[str, dict]:
    """Per block id, per pass: engine minus direct at the median and at p99, and the range over clean passes."""
    out: dict[str, dict] = {}
    for b in blocks:
        out.setdefault(b["block"], {"passes": {}}).setdefault("passes", {}).setdefault(b["pass"], {})[b["arm"]] = b
    for block, entry in out.items():
        diffs = {"median": [], "p99": []}
        rows = []
        for number, arms in sorted(entry["passes"].items()):
            row = {"pass": number, "problems": sum((a.get("problems", []) for a in arms.values()), [])}
            if {"engine", "direct"} <= arms.keys():
                for name in diffs:
                    row[name] = {"engine_ms": arms["engine"][name], "direct_ms": arms["direct"][name],
                                 "diff_ms": arms["engine"][name] - arms["direct"][name]}
                    if not row["problems"]:
                        diffs[name].append(row[name]["diff_ms"])
            rows.append(row)
        entry["passes"] = rows
        for name, values in diffs.items():
            entry[f"{name}_diff_range_ms"] = [min(values), max(values)] if values else None
        entry["clean_passes"] = len(diffs["median"])
    return out


def core_segments(events: list[dict], executions: dict[str, str]) -> dict:
    """Per block: counts of the engine's decisions and, for scale, the core's own segments over allowed requests."""
    per: dict[str, dict] = {}
    files: dict[tuple, dict] = {}
    for e in events:
        binding = e.get("control_binding") or {}
        block = executions.get(binding.get("execution_id"))
        admission = (e.get("detail") or {}).get("admission")
        if block is None or admission is None:
            continue
        files.setdefault((block, binding["execution_id"], admission), {})[e["kind"]] = e
    for (block, _, _), kinds in files.items():
        decided = kinds.get("request_decided")
        entry = per.setdefault(block, {"decided": 0, "allowed": 0, "placed": 0, "samples": {n: [] for n, _, _ in SEGMENTS}})
        if decided is None:
            continue
        entry["decided"] += 1
        if decided.get("outcome") != "allow":
            continue
        entry["allowed"] += 1
        entry["placed"] += (decided.get("detail") or {}).get("credential") == "placed"
        for name, first, last in SEGMENTS:
            if first in kinds and last in kinds:
                entry["samples"][name].append((int(kinds[last]["monotonic_time"]) - int(kinds[first]["monotonic_time"])) / 1e6)
    for entry in per.values():
        samples = entry.pop("samples")
        entry["segments_ms"] = {name: {"n": len(v), "median": nearest_rank(v, 0.5), "p99": nearest_rank(v, 0.99)}
                                for name, v in samples.items() if v}
    return per


def _open(path: Path):
    return gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz" else path.open(encoding="utf-8")


def analyse(run_dir: Path) -> dict:
    config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    warmup, total = config["warmup"], config["warmup"] + config["measured"]
    records = [json.loads(x) for x in (run_dir / "blocks.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    blocks = []
    for rec in records:
        with _open(run_dir / rec["k6_file"]) as fh:
            k6 = read_k6(fh)
        with _open(run_dir / rec["upstream_file"]) as fh:
            upstream = read_upstream(fh)
        measured = [r["iter_ms"] for r in k6[warmup:]]
        problems = check_block(rec, k6, upstream, warmup, total) + list(rec.get("run_problems", []))
        if rec.get("throttled_periods"):
            problems.append(f"cgroup throttled {rec['throttled_periods']} periods")
        blocks.append({**rec, "problems": problems, "connections": connection_facts(k6, upstream, warmup),
                       "median": nearest_rank(measured, 0.5) if measured else None,
                       "p99": nearest_rank(measured, 0.99) if measured else None,
                       "n": len(measured)})
    result = {"config": config, "blocks": blocks, "differences": differences(blocks), "core": {}}
    for path in sorted((run_dir / "engine").glob("*/events-*.jsonl*")):
        with _open(path) as fh:
            events = [json.loads(x) for x in fh if x.strip()]
        executions = {b["execution"]: b["block"] for b in blocks if b.get("execution")}
        result["core"][path.parent.name] = core_segments(events, executions)
    passes = run_dir / "passes.jsonl"
    result["passes"] = [json.loads(x) for x in passes.read_text(encoding="utf-8").splitlines() if x.strip()] if passes.exists() else []
    return result


def _ms(value: float | None) -> str:
    return "—" if value is None else f"{value:.2f}"


def report(result: dict) -> str:
    lines = ["# 每请求开销：分析结果", "",
             "由 driver/analyze_latency.py 生成。单位 ms。差 = 经 engine − 同遍直连，最近秩法，范围取核对都过的遍，没有统计检验。"
             "p99 的差是分位点之差，不是新增耗时的 p99。", "",
             "| 组 | 遍数 | 中位差（范围） | p99 差（范围） | 逐遍中位：engine / 直连 |", "|---|---|---|---|---|"]
    for block, d in sorted(result["differences"].items()):
        per = "；".join(f"{_ms(p['median']['engine_ms'])} / {_ms(p['median']['direct_ms'])}" for p in d["passes"] if "median" in p)
        med, p99 = d["median_diff_range_ms"], d["p99_diff_range_ms"]
        lines.append(f"| {block} | {d['clean_passes']} | {_ms(med[0]) + '–' + _ms(med[1]) if med else '—'} "
                     f"| {_ms(p99[0]) + '–' + _ms(p99[1]) if p99 else '—'} | {per} |")
    lines += ["", "## 连接（每块测量段的次数）", "",
              "| 遍 | 组 | 臂 | 客户端 TLS 握手 | 客户端新连接 | 上游新连接 | 上游会话复用 | 客户端协议 | 上游协议 |",
              "|---|---|---|---|---|---|---|---|---|"]
    for b in sorted(result["blocks"], key=lambda x: (x["pass"], x["block"], x["arm"])):
        c = b["connections"]
        lines.append(f"| {b['pass']} | {b['block']} | {b['arm']} | {c['client_tls_handshakes']} | {c['client_new_connections']} "
                     f"| {c['upstream_new_connections']} | {c['upstream_session_reused']} | {','.join(c['protocols'])} "
                     f"| {','.join(c['upstream_protocols'])} |")
    problems = [(b["pass"], b["block"], b["arm"], p) for b in result["blocks"] for p in b["problems"]]
    lines += ["", "## 核对没过的块", ""] + ([f"- 第 {n} 遍 {block} {arm}：{p}" for n, block, arm, p in problems] or ["没有。"])
    lines += ["", "## 核心自己的分段（engine 记录，只看量级，不相加）", "",
              "| 核心运行 | 组 | 判定 | 放行 | 凭据已放 | 接收到判定 中位 / p99 | PDP 往返 中位 / p99 |", "|---|---|---|---|---|---|---|"]
    for run, per in sorted(result["core"].items()):
        for block, e in sorted(per.items()):
            seg = e["segments_ms"]
            first, second = seg.get(SEGMENTS[0][0], {}), seg.get(SEGMENTS[1][0], {})
            lines.append(f"| {run} | {block} | {e['decided']} | {e['allowed']} | {e['placed']} "
                         f"| {_ms(first.get('median'))} / {_ms(first.get('p99'))} | {_ms(second.get('median'))} / {_ms(second.get('p99'))} |")
    lines += ["", "## 每遍开始前的环境读数", "", "| 遍 | CPU 校准（秒） | fsync 中位 / p99（ms） |", "|---|---|---|"]
    for p in result["passes"]:
        lines.append(f"| {p['pass']} | {p['calibration_s']:.3f} | {_ms(p['fsync_ms']['median'])} / {_ms(p['fsync_ms']['p99'])} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    run_dir = Path(argv[0])
    result = analyse(run_dir)
    (run_dir / "latency-analysis.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    (run_dir / "latency-analysis.md").write_text(report(result), encoding="utf-8")
    print(report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
