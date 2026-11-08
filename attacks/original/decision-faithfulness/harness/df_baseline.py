"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Whether a run is formal (tests.md section 6; harness README section 6 "formal"): the compiled source equals the
registered baseline v4 file by file, the baseline's own checker passes, and the baseline has an approved host-readings
profile that holds for this host. The profile conditions are those of attack_evaluation/harness/run_baseline.py, so one
profile means the same in every unit: its version is the baseline's, it is approved and names its sources, its
required set equals its readings' keys, every reading is an explicit /proc/sys value equal to this host's, its kernel is
this kernel, and its config_sha256 is the sha256 of the decompressed /proc/config.gz. Any reason against makes the run a
trial; nothing here raises for a trial: an evidence file or reading that is missing, unreadable, not JSON or not of the
expected shape is one more reason. Decided by the harness, never by a flag.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
import re
import zlib

from df_common import BASELINE, ENGINE_COMMIT, ENGINE_PATH
from df_deploy import inventory
from df_proc import AS_HOST

BASE = Path("Thesis/Work/Submission/prove/baseline")
CONFIG_GZ = Path("/proc/config.gz")
CONFIG_MAX = 2 * 1024 * 1024
SYSCTL_PATH = re.compile(r"/proc/sys(/[A-Za-z0-9_.-]+)+")          # an explicit sysctl file; no NUL, no other byte
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")                 # ASCII digits only


def read_json(path: Path, what: str, reasons: list[str]) -> dict | None:
    """An evidence file as a JSON object; None, with the reason added, when it is missing, unreadable or not one."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        reasons.append(f"{what} unreadable or not JSON: {type(error).__name__}")
        return None
    if not isinstance(data, dict):
        reasons.append(f"{what} is not a JSON object")
        return None
    return data


def approved_date(value: object) -> bool:
    """approved_by_user is the user's approval as a YYYY-MM-DD date string, nothing else."""
    if not isinstance(value, str) or not DATE.fullmatch(value):
        return False
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def profile_reasons(data: dict, kernel: str, config_gz: Path = CONFIG_GZ) -> list[str]:
    """What keeps a host-readings profile from holding for this host; empty when it holds."""
    reasons: list[str] = []
    readings = data.get("readings")
    if not isinstance(readings, dict) or not all(isinstance(v, dict) for v in readings.values()):
        reasons.append("host-readings profile's readings are not an object of reading objects")
        readings = {}
    sources = data.get("sources")
    missing = [name for name, bad in (
        ("version", data.get("version") != BASELINE), ("readings", not readings),
        ("approved_by_user as YYYY-MM-DD", not approved_date(data.get("approved_by_user"))),
        ("sources as a non-empty list of non-empty strings",
         not isinstance(sources, list) or not sources or not all(isinstance(s, str) and s.strip() for s in sources)),
    ) if bad]
    if missing:
        reasons.append(f"host-readings profile not a complete approved profile for {BASELINE}: " + ", ".join(missing))
    required = data.get("required")
    if not isinstance(required, list) or not all(isinstance(x, str) for x in required) \
            or set(required) != set(readings):
        reasons.append("host-readings profile's required set differs from its readings")
    if data.get("kernel") != kernel:
        reasons.append("host-readings profile is for another kernel")
    for key, item in readings.items():
        path = item.get("path", "")
        if not isinstance(path, str) or not SYSCTL_PATH.fullmatch(path) or ".." in Path(path).parts:
            reasons.append(f"host reading {key} is not a /proc/sys value")
            continue
        try:
            value = Path(path).read_text().strip()
        except (OSError, UnicodeDecodeError, ValueError) as error:
            reasons.append(f"host reading {key} unreadable: {type(error).__name__}")
            continue
        if value != item.get("value"):
            reasons.append(f"host reading {key} differs")
    try:
        with gzip.open(config_gz) as f:
            config = f.read(CONFIG_MAX + 1)
    except (OSError, EOFError, zlib.error) as error:              # zlib.error: a gzip whose deflate data is corrupt
        reasons.append(f"kernel CONFIG unreadable: {type(error).__name__}")
    else:
        if not data.get("config_sha256") or len(config) > CONFIG_MAX \
                or hashlib.sha256(config).hexdigest() != data["config_sha256"]:
            reasons.append("kernel CONFIG differs from the profile's config_sha256")
    return reasons


def verify(repo: Path, snapshot: dict, kernel: str, command, *, variant: str | None,
           config_gz: Path = CONFIG_GZ) -> dict:
    reasons: list[str] = []
    base = repo / BASE
    versions = read_json(base / "versions.json", "registered versions file", reasons) or {}
    entry = versions.get(BASELINE) if isinstance(versions.get(BASELINE), dict) else {}
    if variant:
        reasons.append(f"deliberately wrong engine ({variant}): never formal")
    if entry.get("engine_path") != ENGINE_PATH or entry.get("engine_commit") != ENGINE_COMMIT:
        reasons.append(f"registered baseline {BASELINE} names another engine path or commit")
    exported = base / "artifacts" / BASELINE / "engine"
    try:
        registered = inventory(exported) if exported.is_dir() else {"files": None}
    except OSError as error:
        reasons.append(f"registered {BASELINE} export unreadable: {type(error).__name__}")
        registered = {"files": None}
    if registered["files"] != snapshot["files"]:
        reasons.append(f"compiled source differs from the registered {BASELINE} export, file by file")
    profile = base / "host-readings" / f"{BASELINE}.json"
    if not profile.exists():
        reasons.append(f"no approved host-readings profile for {BASELINE}")
    else:
        data = read_json(profile, "host-readings profile", reasons)
        if data is not None:
            reasons += profile_reasons(data, kernel, config_gz)
    # The baseline's own checker reads the whole registered export on /mnt/d and takes minutes (S1, 2026-11-05: over
    # 60 s); like attack_evaluation/harness/run_baseline.py it runs only when nothing cheaper has made the run a trial.
    exit_code = None
    if not reasons:
        check = command(AS_HOST + ["/usr/bin/env", "-C", repo, "/usr/bin/python3", "-I", "-B", base / "baseline.py",
                                   "check", BASELINE], timeout=240, allowed=tuple(range(256)))
        exit_code = check["exit_code"]
        if exit_code != 0:
            reasons.append(f"baseline.py check {BASELINE} exited {exit_code}")
    return {"baseline": BASELINE if not reasons else None, "formal": not reasons, "reasons": reasons,
            "registered_files": None if registered["files"] is None else len(registered["files"]),
            "snapshot_files": snapshot["count"],
            "baseline_check_exit": exit_code if exit_code is not None else "not run: already a trial"}
