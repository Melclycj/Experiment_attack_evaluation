"""Entry point for the memory column (protocol.md 3.1, 4, 6, 8) on the Linux measurement server. One run directory
per run; one command starts it, as root, detached from the SSH session:

    cd /opt/sota-measurement && setsid nohup python3 -m driver.run_memory --config config/server-memory.json \
        --mode formal --approval "<user's words>" > runs/last-start.log 2>&1 &

Trial mode runs the same code with a trial config; its preflight reports instead of blocking.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import client, engine_object, memory, objects, vm_objects

EXP = Path(__file__).resolve().parents[1]


def schedule(names: list[str], seed: int, reps_pass1: int, reps_pass2: int) -> list[dict]:
    """protocol.md 4: two passes over every object; pass 1 in seeded random order, pass 2 reversed."""
    order = list(names)
    random.Random(seed).shuffle(order)
    plan = [{"pass_no": 1, "object": o, "reps": reps_pass1} for o in order]
    if reps_pass2:
        plan += [{"pass_no": 2, "object": o, "reps": reps_pass2} for o in reversed(order)]
    return plan


def _out(argv: list[str], timeout: float = 60) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return (r.stdout + r.stderr).strip()[:400]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"<{type(exc).__name__}: {exc}>"


def instance_type() -> str:
    """From the EC2 instance metadata service (IMDSv2)."""
    try:
        tok = urllib.request.urlopen(urllib.request.Request(
            "http://169.254.169.254/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"}), timeout=5).read().decode()
        return urllib.request.urlopen(urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-type",
            headers={"X-aws-ec2-metadata-token": tok}), timeout=5).read().decode()
    except OSError as exc:
        return f"<{exc}>"


def versions() -> dict:
    claude_bin = os.path.realpath("/usr/local/bin/claude")
    return {"platform": platform.platform(), "python": platform.python_version(),
            "os_release": _out(["sh", "-c", "grep PRETTY_NAME /etc/os-release"]),
            "instance_type": instance_type(), "cpu": _out(["sh", "-c", "grep -m1 'model name' /proc/cpuinfo"]),
            "nproc": _out(["nproc"]), "thp": _out(["cat", "/sys/kernel/mm/transparent_hugepage/enabled"]),
            "ksm": _out(["cat", "/sys/kernel/mm/ksm/run"]),
            "claude": _out(["claude", "--version"]), "claude_sha256": _out(["sha256sum", claude_bin]),
            "k6": _out(["k6", "version"]), "docker": _out(["dpkg-query", "-W", "docker-ce", "containerd.io"]),
            "nono": _out(["nono", "--version"]), "openshell": _out(["openshell", "--version"]),
            "escrow_commit": _out(["git", "-C", "/home/jerry/sota-src/benign-attach-gateway", "rev-parse", "HEAD"])}


def _cpu_busy(seconds: float) -> float:
    """Share of all CPUs busy over `seconds`, from /proc/stat (the driver itself is idle while it waits)."""
    def snap() -> tuple[int, int]:
        f = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
        return sum(f), f[3] + f[4]  # total, idle + iowait
    t0, i0 = snap()
    time.sleep(seconds)
    t1, i1 = snap()
    return 100.0 * (1 - (i1 - i0) / max(1, t1 - t0))


def api_key_ok(key: str) -> str:
    req = urllib.request.Request("https://api.anthropic.com/v1/models",
                                 headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return str(resp.status)
    except urllib.error.HTTPError as exc:
        return str(exc.code)
    except OSError as exc:
        return f"error: {exc}"


def preflight(mode: str, limits: memory.Limits, key: str, cpu_seconds: float, names: list[str]) -> list[dict]:
    m = memory_now()
    claudes = _out(["pgrep", "-x", "claude"]).split()
    docker = subprocess.run(["systemctl", "is-active", "--quiet", "docker.service"]).returncode == 0
    tools = {"k6": "/usr/local/bin/k6", "claude": "/usr/local/bin/claude", "nono": "/usr/local/bin/nono",
             "openshell": "/usr/local/bin/openshell"}
    missing = [t for t, p in tools.items() if not os.path.exists(p)]
    checks = [
        ("running as root", os.geteuid() == 0, ""),
        ("Claude Code " + objects.CLAUDE_VERSION, _out(["claude", "--version"]).startswith(objects.CLAUDE_VERSION),
         _out(["claude", "--version"])),
        ("Docker not running", not docker, ""),
        ("available memory", m["MemAvailable"] > limits.min_available_mib + 4096, f"{m['MemAvailable']:.0f} MiB"),
        ("no swap in use", m["swap_used_mib"] == 0, f"{m['swap_used_mib']:.0f} MiB"),
        ("disk free", m["disk_free_gib"] > limits.min_disk_free_gib + 5, f"{m['disk_free_gib']:.1f} GiB"),
        ("other CPU", (cpu := _cpu_busy(cpu_seconds)) < 5.0, f"{cpu:.1f}% over {cpu_seconds:.0f}s"),
        ("no Claude Code running", not claudes, f"pids {claudes}"),
        ("/dev/kvm", os.path.exists("/dev/kvm"), ""),
        # a VM left by an earlier run would be counted with this run's units (the VMs' Claude Code is not a host
        # process, so the check above cannot see it)
        ("no VM processes", not (vms := _vm_processes()), f"pids {vms}"),
        ("no unit or holder processes", not (units := _cgroup_pids(Path(memory.CGBASE, "units"))
                                              + _cgroup_pids(Path(memory.CGBASE, "holders"))), f"pids {units}"),
        # what a killed driver leaves of the engine: the core and the PDP in the shared group, rows at their uids,
        # and the deployments mounted under the work root (their credential stores hold the key)
        ("no shared-group processes", not (shared := _cgroup_pids(Path(memory.CGBASE, "shared"))), f"pids {shared}"),
        ("no engine row or PDP processes", not (rowp := _engine_uid_pids()), f"pids {rowp}"),
        ("nothing mounted under the work root", not (mnt := _work_mounts()), json.dumps(mnt)),
        ("no Kairos namespaces", "sotakai" not in _out(["ip", "netns", "list"]), ""),
        ("tools", not missing, f"missing {missing}"),
        ("objects known", all(n in objects.ADAPTERS for n in names), json.dumps(names)),
        ("model API key", (code := api_key_ok(key)) == "200", code),
    ]
    return [{"check": c, "ok": ok, "detail": d, "blocking": mode == "formal"} for c, ok, d in checks]


def _vm_processes() -> list[int]:
    marks = ("qemu-system-x86_64", "cloud-hypervisor", "containerd-shim-nerdbox")
    out = []
    for d in Path("/proc").iterdir():
        if d.name.isdigit():
            try:
                cmd = (d / "cmdline").read_bytes().split(b"\0")[0].decode("utf-8", "replace")
            except OSError:
                continue
            if any(m in cmd for m in marks):
                out.append(int(d.name))
    return out


def _cgroup_pids(path: Path) -> list[int]:
    if not path.is_dir():
        return []
    return [int(x) for f in path.rglob("cgroup.procs") for x in f.read_text().split()]


def _engine_uid_pids() -> list[int]:
    """Processes at the engine's execution uids or at its dedicated uids (connector, file worker, workspace owner,
    PDP)."""
    from .agent import uid_procs
    e = engine_object
    uids = [*range(e.UID_FIRST, e.UID_FIRST + e.UID_COUNT), e.CONNECTOR_UID, e.FILE_WORKER_UID, e.OWNER_UID, e.PDP_UID]
    return [p["pid"] for p in uid_procs(uids)]


def _work_mounts() -> list[str]:
    return [ln.split()[1] for ln in Path("/proc/mounts").read_text().splitlines()
            if ln.split()[1].startswith(objects.WORK + "/")]


def memory_now() -> dict:
    from .agent import meminfo
    return meminfo()


def _sweep_secrets(ctx: memory.Ctx) -> list[str]:
    """Remove every temporary file that can hold the key or its last 20 characters, also after a crash: the bare
    units' work and config dirs, every object's unit dirs under the work root, and the Gondolin and Kairos units
    (vm_objects.sweep; the Kairos base image stays until the end of the measurement, protocol.md 8). The engine's
    deployments live under the work root on mounted images: they are torn down first, and the work root is not removed
    while anything is still mounted under it (rmtree would descend into the mounts). A SIGKILL or an out-of-memory kill
    of the driver skips this; the next run's preflight then finds the leftovers (blocking in formal mode)."""
    left = engine_object.teardown_deployments()
    try:   # each step inside is caught too; this guard keeps the rmtree below certain
        left += vm_objects.sweep()
    except Exception as exc:
        left.append(f"vm sweep: {type(exc).__name__}: {exc}")
    mounted = _work_mounts()
    if left or mounted:
        ctx.log("sweep_incomplete", engine_left=left, mounted=mounted)
    shutil.rmtree(objects.Bare.UNITS, ignore_errors=True)
    if not mounted:
        shutil.rmtree(objects.WORK, ignore_errors=True)
    return left + [f"still mounted: {m}" for m in mounted]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--mode", choices=("trial", "formal"), required=True)
    ap.add_argument("--approval", default="", help="the user's start approval, verbatim (formal runs)")
    args = ap.parse_args(argv)
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    if args.mode == "formal" and not args.approval:
        sys.exit("a formal run needs --approval with the user's words")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = EXP / "runs" / f"{stamp}-{args.mode}-{cfg['label']}"
    run_dir.mkdir(parents=True)
    shutil.copy2(args.config, run_dir / "config.json")
    shutil.copytree(Path(__file__).resolve().parent, run_dir / "driver-snapshot",
                    ignore=shutil.ignore_patterns("__pycache__"))   # the driver exactly as run
    timing = memory.Timing(**cfg.get("timing", {}))
    limits = memory.Limits(**cfg.get("limits", {}))
    key = objects.api_key()
    plan = schedule(cfg["objects"], cfg["seed"], cfg["reps_pass1"], cfg["reps_pass2"])
    meta = {"started_utc": stamp, "mode": args.mode, "approval": args.approval, "argv": sys.argv,
            "config": cfg, "timing": asdict(timing), "limits": asdict(limits), "schedule": plan,
            "versions": versions(), "driver_pid": os.getpid()}
    checks = preflight(args.mode, limits, key, cfg.get("preflight_cpu_seconds", 60), cfg["objects"])
    meta["preflight"] = checks
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    failed = [c for c in checks if not c["ok"]]
    if failed and args.mode == "formal":
        print("preflight failed:", json.dumps(failed, indent=1))
        return 2

    def _on_term(_signum, _frame):   # SIGTERM ends the run like Ctrl-C: cleanup, sweep and summary still run
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _on_term)
    ctx = memory.Ctx(run_dir, timing, limits)
    ctx.agent = client.Agent(run_dir, timing.interval)
    ctx.watch = memory.Watch(ctx)
    ctx.watch.start()
    results, status = [], "completed"
    errored: set[str] = set()  # protocol.md 5: an object that errored skips the rest of the night
    night_end = time.monotonic() + cfg.get("night_deadline_s", 6.5 * 3600)
    try:
        for item in plan:
            if time.monotonic() > night_end:  # no new object pass after the night's cut-off
                ctx.log("object_skipped", reason="night deadline", **item)
                results.append({**item, "skipped": "night deadline"})
                continue
            if item["object"] in errored:
                ctx.log("object_skipped", reason="errored in an earlier pass", **item)
                results.append({**item, "skipped": "errored in an earlier pass"})
                continue
            obj = objects.ADAPTERS[item["object"]](lambda: ctx.agent, key)
            cap = cfg.get("object_time_cap_s", {}).get(item["object"], cfg.get("default_time_cap_s", 5400))
            ctx.log("object_start", **item)
            try:
                res = memory.ObjectPass(ctx, obj, cfg["tiers"], item["reps"], item["pass_no"], cap).run()
            except memory.StopNight:
                raise
            except Exception as exc:  # ObjectPass.run cleans up itself; this is a failure of its cleanup path
                res = {"object": item["object"], "pass_no": item["pass_no"], "error": f"{type(exc).__name__}: {exc}"}
            if res.get("error") or str(res.get("stop_reason", "")).startswith("error"):
                errored.add(item["object"])
            results.append(res)
            ctx.log("object_end", **res)
    except memory.StopNight as exc:
        status = f"stopped: {exc}"
    except KeyboardInterrupt:
        status = "interrupted (SIGINT or SIGTERM)"
    finally:
        try:
            sweep = _sweep_secrets(ctx)
        except Exception as exc:  # the facilities still close and the summary is still written
            sweep = [f"sweep failed: {type(exc).__name__}: {exc}"]
        try:
            ctx.watch.stop()
        finally:
            ctx.agent.close()
        summary = {"status": status, "finished_utc": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                   "results": results, "sweep_left": sweep}
        (run_dir / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(run_dir)
    return 0 if status == "completed" and not sweep else 3


if __name__ == "__main__":
    raise SystemExit(main())
