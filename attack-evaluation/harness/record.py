"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat

from common import MAX_OUTPUT, OUTCOMES, PURPOSE, identity, json_bytes, markdown, timestamp
from judge import aggregate_attempts, aggregate_targets, finalize_pairing
from safeio import atomic_write, plain_path, read_owned
from run_units import report_purpose
from report_view import REPORT_VERSION, batch_status, status_lines

HEADER_FIELDS = {"run", "engine", "harness", "spec", "configs", "host", "policy", "deployment",
                 "commands", "started_at", "finished_at", "cleanup"}
ROW_FIELDS = {"attack", "config", "script", "expected", "outcome", "observed", "observed_mechanism",
              "mismatch", "control", "external_fact", "invalid_reason", "started_at", "finished_at",
              "repeats", "successes", "upper_bound", "attempts", "request_contract"}


def formal_status(header: dict) -> bool:
    """Fail closed: source identity + executed baseline check + actual host comparison.

    Evidence here is produced by the host build/verification layer, not by a CLI
    '--formal' flag. An unregistered version, a missing check or a mismatch is trial.
    """
    if header.get("variant") or header["engine"].get("variant"):
        return False
    engine, host = header["engine"], header["host"]
    baseline = engine.get("baseline_check", {})
    return bool(engine.get("baseline") and engine.get("files") and
                engine.get("files") == engine.get("baseline_files") and
                baseline.get("executed") is True and type(baseline.get("exit_code")) is int and
                baseline.get("exit_code") == 0 and
                baseline.get("version") == engine["baseline"] and
                host.get("kernel_match") is True and host.get("readings_match") is True)


def validate_row(row: dict) -> None:
    from run_evidence import ROW_LIMIT  # one bound for writing and reading back (16 KiB since v4)
    if len(json_bytes(row)) > ROW_LIMIT:
        raise ValueError('result metadata budget exceeded')
    missing = ROW_FIELDS - row.keys()
    if missing:
        raise ValueError(f"missing result fields: {sorted(missing)}")
    if not re.fullmatch(r"(?:NB-\d{2}|CB-(?:0[1-9]|1[0-2]|14)|PC-[A-Z0-9-]+|BD-[A-Z0-9-]+)", row["attack"]):
        raise ValueError("invalid attack ID")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", row["config"]):
        raise ValueError("invalid configuration")
    if row["outcome"] not in OUTCOMES or type(row["mismatch"]) is not bool:
        raise ValueError("invalid outcome or mismatch flag")
    if type(row["repeats"]) is not int or row["repeats"] < 1:
        raise ValueError("invalid repeat count")
    if type(row["successes"]) is not int or not 0 <= row["successes"] <= row["repeats"]:
        raise ValueError("invalid success count")
    if row["outcome"] == "invalid" and not row["invalid_reason"]:
        raise ValueError("invalid result needs a reason")
    if row["outcome"] != "invalid" and row["invalid_reason"]:
        raise ValueError("reason on non-invalid outcome")
    if row["upper_bound"] is not None:
        if row["outcome"] != "blocked" or row["successes"] != 0 or not 0 <= row["upper_bound"] <= 1:
            raise ValueError("upper bound requires a valid zero-success sample")
    if (row["successes"] > 0) != (row["outcome"] == "succeeded"):
        raise ValueError("outcome disagrees with success count")
    if timestamp(row["finished_at"]) < timestamp(row["started_at"]):
        raise ValueError("negative result duration")
    if not row["script"] or not row["request_contract"]:
        raise ValueError("missing code/request identity")
    script = row["script"]
    if not isinstance(script, dict) or not re.fullmatch(r"[0-9a-f]{40}", script.get("blob", "")) or not re.fullmatch(
            r"[0-9a-f]{64}", script.get("sha256", "")):
        raise ValueError("script needs both git blob and sha256 identity")
    seen = set()
    for attempt in row["attempts"]:
        number = attempt["repeat"]
        if type(number) is not int or not 1 <= number <= row["repeats"] or number in seen:
            raise ValueError("invalid/duplicate repetition")
        seen.add(number)
        ids = [t["id"] for t in attempt["targets"]]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate target")
        for target in attempt["targets"]:
            if target["outcome"] not in OUTCOMES:
                raise ValueError("unknown target outcome")
            if target["outcome"] == "invalid" and not target["invalid_reason"]:
                raise ValueError("invalid target needs a reason")
        if (attempt["outcome"], attempt["invalid_reason"]) != aggregate_targets(attempt["targets"]):
            raise ValueError("attempt disagrees with target results")
    derived = aggregate_attempts(row["attempts"], row["repeats"])
    for field in ("outcome", "invalid_reason", "successes", "upper_bound"):
        if row[field] != derived[field]:
            raise ValueError(f"result disagrees with attempts: {field}")
    json_bytes(row)  # Reject NaN, unserializable values.


def validate_references(value, files):
    """Evidence references bind names AND identities, including nested receipts."""
    if isinstance(value, dict):
        if 'file' in value and any(k in value for k in ('blob', 'sha256', 'bytes')):
            name = value['file']
            if (not isinstance(name, str) or name not in files
                    or {k: value.get(k) for k in ('blob', 'sha256', 'bytes')} != files[name]):
                raise ValueError('missing/mismatched evidence reference: ' + str(name))
        for item in value.values():
            validate_references(item, files)
    elif isinstance(value, list):
        for item in value:
            validate_references(item, files)


def render_readme(header: dict, rows=()) -> str:
    state = "正式运行" if header["formal"] else "试跑，不算数"
    sections = [("engine 与基线", "engine"), ("harness 与规格身份", "harness"),
                ("tests.md 身份", "spec"), ("配置身份", "configs"), ("kernel 与宿主核对", "host"),
                ("policy 与 BPF", "policy"), ("部署 digest", "deployment"),
                ("编译与运行命令", "commands"), ("清理结果", "cleanup")]
    lines = [report_purpose(header), "", f"# {markdown(header['run'])}", "", f"**{state}**", "",
             f"UTC：{header['started_at']} → {header['finished_at']}", "", *status_lines(header, rows)]
    for title, field in sections:
        lines += [f"## {title}", "", "````json", json.dumps(header[field], ensure_ascii=False,
                  indent=2, sort_keys=True).replace("````", "\\u0060" * 4), "````", ""]
    return "\n".join(lines)


class RunDirectory:
    """Flat, exclusive, controller-owned output; never follow capture symlinks.

    Creates no engine processes. Writes are limited including temporary replacement
    bytes; reserve enough room for run.json/README/cleanup before copying raw logs.
    """
    def __init__(self, parent: Path, name: str, limit: int = MAX_OUTPUT):
        if not re.fullmatch(r"\d{8}T\d{6}Z-[A-Za-z0-9][A-Za-z0-9_-]{0,79}", name):
            raise ValueError("run directory needs UTC timestamp + label")
        if not 1 <= limit <= MAX_OUTPUT:
            raise ValueError("output limit may only be lowered")
        self.path = plain_path(parent) / name
        self.path.mkdir(mode=0o700)
        self.limit = limit
        self.finalized = False

    def size(self) -> int:
        """Fresh bounded-output inventory; share only the ancestor validation.

        This is a controller-owned tree (as required by atomic_write), not a
        mutable attack capture tree. A new scandir/stat snapshot is taken for
        EVERY call; no entry, size or successful path check survives the call.
        Validate common ancestors at both boundaries and every leaf without
        following links, including Windows reparse points. Reject root swaps.
        """
        path = plain_path(self.path)
        before = path.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("run output root is not a directory")
        total = 0
        with os.scandir(path) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                # Windows enumeration omits link count; obtain real metadata.
                if os.name == "nt" and info.st_nlink == 0:
                    info = os.stat(entry.path, follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or getattr(info, "st_file_attributes", 0) & 0x400):
                    raise ValueError("run directory contains directory/link/nonregular file")
                total += info.st_size
        after = plain_path(path).lstat()
        if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or not stat.S_ISDIR(after.st_mode)):
            raise ValueError("run output root changed during scan")
        return total

    def used(self) -> int:
        """Bytes counted against the budget before a write: a fresh full scan."""
        return self.size()

    def write(self, name: str, data: bytes, *, replace: bool = False, reserve: int = 0) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", name):
            raise ValueError("output must have a flat safe filename")
        if self.finalized:
            raise RuntimeError("run already finalized")
        if reserve < 0 or self.used() + len(data) + reserve > self.limit:
            raise ValueError("10 MiB output budget exceeded")
        atomic_write(self.path / name, data, replace=replace)

    def finalize(self, header: dict, rows: list[dict]) -> list[dict]:
        if HEADER_FIELDS - header.keys():
            raise ValueError(f"missing run fields: {sorted(HEADER_FIELDS - header.keys())}")
        if header["run"] != self.path.name:
            raise ValueError("run name disagrees with directory")
        if timestamp(header["finished_at"]) < timestamp(header["started_at"]):
            raise ValueError("negative run duration")
        for row in rows:
            validate_row(row)
        final_rows = finalize_pairing(rows)
        for row in final_rows:
            validate_row(row)
        actual = dict(header, formal=formal_status(header), schema="nb-harness/1")
        # Do not count results from incomplete cleanup as clean verified evidence.
        actual["cleanup_ok"] = actual["cleanup"].get("ok") is True
        actual["report"] = {"version": REPORT_VERSION, "batch": batch_status(actual, final_rows)}
        from summarize import render_results
        payloads = {"results.jsonl": b"".join(json_bytes(row) for row in final_rows),
                    "results.md": render_results(final_rows, actual).encode("utf-8"),
                    "run.json": json_bytes(actual),
                    "README.md": render_readme(actual, final_rows).encode("utf-8")}
        size = self.size()  # Reject links/non-flat contents before inventory.
        files = {p.name: identity(read_owned(p, MAX_OUTPUT)) for p in self.path.iterdir()}
        if set(files) & (set(payloads) | {'COMPLETE.json'}):
            raise ValueError('preexisting completion metadata')
        validate_references([actual, final_rows], files)
        files.update({name: identity(data) for name, data in payloads.items()})
        completion = json_bytes({"schema": "nb-harness/1", "run": self.path.name,
                                 "coverage": "all-files", "files": files})
        if size + sum(map(len, payloads.values())) + len(completion) > self.limit:
            raise ValueError("insufficient reserved output space for final metadata")
        for name, data in payloads.items():
            self.write(name, data)
        # Completion marker is deliberately the last write; readers reject partial runs.
        self.write("COMPLETE.json", completion)
        self.finalized = True
        return final_rows


def load_run(path: Path, *, launcher_failed: dict | None = None) -> tuple[dict, list[dict]]:
    """launcher_failed: identity pinned by a user-approved recovery record (run_gate)."""
    path = plain_path(path)
    failed = path / "LAUNCHER-FAILED.json"
    pinned = failed.exists() and launcher_failed is not None
    if failed.exists() and (not pinned or identity(read_owned(failed)) != launcher_failed):
        raise ValueError("outer launcher/cleanup failed; run is not verified")
    total = 0
    for item in path.iterdir():
        plain_path(item)
        info = item.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("non-flat run")
        total += info.st_size
    if total > MAX_OUTPUT:
        raise ValueError("oversized run")
    complete = json.loads(read_owned(path / "COMPLETE.json", MAX_OUTPUT))
    header = json.loads(read_owned(path / "run.json", MAX_OUTPUT))
    if complete.get("run") != path.name or header.get("run") != path.name:
        raise ValueError("run identity mismatch")
    required = {"run.json", "results.jsonl", "results.md", "README.md"}
    files = complete.get('files', {})
    if (complete.get("schema") != "nb-harness/1" or complete.get('coverage') != 'all-files'
            or not isinstance(files, dict) or not required <= set(files)
            or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", n) for n in files)
            or set(files) != {p.name for p in path.iterdir()} - {'COMPLETE.json'}
            - ({'LAUNCHER-FAILED.json'} if pinned else set())):
        raise ValueError("invalid/incomplete all-files completion manifest")
    for name in files:
        if identity(read_owned(path / name, MAX_OUTPUT)) != files[name]:
            raise ValueError("completed run evidence/metadata modified: " + name)
    if HEADER_FIELDS - header.keys() or header.get("formal") != formal_status(header):
        raise ValueError("invalid run header/formal classification")
    rows = [json.loads(line) for line in read_owned(path / "results.jsonl", MAX_OUTPUT).splitlines() if line]
    validate_references([header, rows], files)
    for row in rows:
        validate_row(row)
    keys = [(r["attack"], r["config"]) for r in rows]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate result rows")
    for row in rows:
        if row["config"] == "engine" and row.get("kind", "attack") == "attack" and not row.get("pairing_finalized"):
            raise ValueError("unfinalized cross-configuration pairing")
    if 'report' in header:
        from summarize import render_results
        if header['report'] != {'version': REPORT_VERSION, 'batch': batch_status(header, rows)}:
            raise ValueError('report summary disagrees with batch evidence')
        for name, rendered in (('results.md', render_results(rows, header)),
                               ('README.md', render_readme(header, rows))):
            if read_owned(path / name, MAX_OUTPUT) != rendered.encode('utf-8'):
                raise ValueError('derived report disagrees with evidence: ' + name)
    return header, rows
