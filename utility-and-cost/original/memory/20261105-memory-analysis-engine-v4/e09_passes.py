"""Per core run of an engine object (one pass), from the records archived in <run>/engine/<object>-<stamp>/: the
registration (fallback deleted or absent, entries per workspace), the model check, every request decision by host,
method, outcome and reason, the refused requests to other hosts, and the questions. Also, per resident row, the
requests its Claude Code made. Usage: e09_passes.py <run dir> [<run dir>...] > out.json"""
import collections
import json
import sys
from pathlib import Path


def events_of(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    return [json.loads(x) for x in (lines if text.endswith("\n") else lines[:-1]) if x.strip()]


def requests(events: list[dict]) -> dict:
    """Network requests by (execution, seq): admission, decision and completion (run_gate.requests_of's pairing)."""
    files = {(e.get("detail") or {}).get("admission") for e in events if e["kind"] == "request_admitted"
             and (e.get("detail") or {}).get("request_kind") == "file"}
    out = collections.defaultdict(dict)
    for e in events:
        d = e.get("detail") or {}
        if e["kind"] == "diagnostic" and e.get("name") == "request_completed":
            out[(d.get("execution_id"), d.get("seq"))]["completed"] = d
            continue
        ex = (e.get("control_binding") or {}).get("execution_id")
        if e["kind"] in ("request_admitted", "request_decided") and "seq" in d and d.get("admission") not in files:
            out[(ex, d["seq"])][e["kind"]] = {"outcome": e.get("outcome"), "reason": e.get("reason_code"), **d}
    return out


def main() -> None:
    report = []
    for run in map(Path, sys.argv[1:]):
        rows_by_exec = {}
        for line in (run / "memory-records.jsonl").read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            for r in (rec.get("notes") or {}).get("rows", []):
                rows_by_exec[r["execution"]] = (rec.get("object"), rec.get("n"), rec.get("rep"), r["unit"], r["runtime"])
        for d in sorted((run / "engine").iterdir()):
            evs = events_of(next(d.glob("events-*.jsonl")))
            rules = json.loads(next(d.glob("rules-*.txt")).read_text(encoding="utf-8"))
            reqs = requests(evs)
            by = collections.Counter()
            refused_other = collections.Counter()
            per_kind = collections.Counter()
            for (ex, seq), r in reqs.items():
                a, dec, done = r.get("request_admitted", {}), r.get("request_decided", {}), r.get("completed", {})
                key = (a.get("host"), a.get("method"), dec.get("outcome"), dec.get("reason"), dec.get("key_kind"),
                       done.get("status"))
                by[key] += 1
                if dec.get("reason") in ("no_entry", "not_covered"):
                    refused_other[(a.get("host"), a.get("method"), dec.get("reason"))] += 1
                kind = rows_by_exec.get(ex, (None, None, None, None, "check" if ex == rules.get("model_check", {})
                                             .get("execution") else "?"))[4]
                per_kind[(kind, a.get("host"), a.get("method"), (a.get("path") or "").split("?")[0], dec.get("outcome"),
                          done.get("status"))] += 1
            entries = sorted({ln.split("entries=")[1] for ln in rules.get("ws_list", "").splitlines() if "entries=" in ln})
            report.append({
                "run": run.name, "core_run": d.name,
                "fallback": sorted(set((rules.get("fallback") or {}).values())), "entries": entries,
                "model_check": [(x["request"], x["decision"], x["credential"], x["status"])
                                for x in rules.get("model_check", {}).get("requests", [])],
                "questions": (d / "questions.jsonl").exists(),
                "decisions": [[*k, v] for k, v in sorted(by.items(), key=lambda kv: -kv[1])],
                "refused_other_hosts": [[*k, v] for k, v in refused_other.items()],
                "by_runtime": [[*k, v] for k, v in sorted(per_kind.items(), key=lambda kv: (str(kv[0][0]), -kv[1]))],
                "rows": sum(1 for e in evs if e["kind"] == "spawn_requested"),
            })
    json.dump(report, sys.stdout, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
