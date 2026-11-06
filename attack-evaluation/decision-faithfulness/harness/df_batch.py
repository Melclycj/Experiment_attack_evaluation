"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

One batch (TESTING section 1 rules 1-8; tests.md sections 1 and 6). Started by the user's "开始" only, as root in WSL:

    python3 -I -B df_batch.py --label L --cases DF-03/post-unlisted,DF-05/302 --repo /mnt/d/Thesis \
        --crash-directory /mnt/c/Users/<user>/AppData/Local/Temp/wsl-crashes [--variant follow-3xx]

It re-executes itself under unshare (private mount and net namespaces), refuses while the 1.1/2.3 apparatus's start
gate or a previous 3.1 batch's gate is present, builds the pinned engine, runs each subgoal under the engine and then
undefended, judges, checks the trace, copies the evidence and cleans up in the fixed order. Exit 0 only when the
batch ran to its end and cleaned up; the outcomes themselves are in the run directory.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import pwd
import secrets
import shutil
import signal
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I keeps the script's directory off sys.path
from df_common import (ATTEMPT_SECONDS, DF_GATE, H_GATE, HOST_UID, LONG_RUN_SECONDS, RUN_SECONDS,  # noqa: E402
                       UID_FIRST, CONNECTOR_UID, ENGINE_COMMIT, ENGINE_PATH, identity, run_name, token, utc)

UNIT = Path(__file__).resolve().parents[1]


def outer(args: argparse.Namespace) -> int:
    if os.geteuid() != 0 or platform.system() != "Linux":
        raise SystemExit("run as root inside WSL")
    before = {kind: os.readlink(f"/proc/self/ns/{kind}") for kind in ("mnt", "net", "pid")}
    limit = LONG_RUN_SECONDS if "DF-06/no-answer" in args.cases.split(",") else RUN_SECONDS
    argv = ["/usr/bin/unshare", "--mount", "--propagation", "private", "--net", "--", "/usr/bin/python3", "-I", "-B",
            str(Path(__file__).resolve()), *sys.argv[1:], "--inside", "--before", json.dumps(before)]
    proc = subprocess.Popen(argv)
    try:
        return proc.wait(timeout=limit + 120)            # the independent watchdog over the inner deadline
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGTERM)                 # the inner controller cleans up on SIGTERM
        return proc.wait(timeout=120) or 3


def claim_gate() -> Path:
    if Path(H_GATE).exists():
        raise RuntimeError("the 1.1/2.3 apparatus's start gate is present: another batch owns the machine")
    gate = Path(DF_GATE)
    gate.mkdir(mode=0o700, exist_ok=True)
    path = gate / "active.json"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)   # a leftover gate means a failed cleanup
    os.write(fd, json.dumps({"pid": os.getpid(), "started_at": utc()}).encode())
    os.close(fd)
    return path


def snapshot_tree(source: Path, dest: Path) -> dict:
    dest.mkdir(mode=0o755)
    blobs = {}
    for p in sorted(source.glob("*.py")):
        shutil.copyfile(p, dest / p.name)
        os.chmod(dest / p.name, 0o644)
        blobs[p.name] = identity(p.read_bytes())["blob"]
    return blobs


def inside(args: argparse.Namespace) -> int:
    import df_admin
    import df_baseline
    import df_cleanup
    import df_control
    import df_deploy
    import df_env
    import df_judge
    import df_net
    import df_proc
    import df_record
    import df_registry
    import df_tls
    import df_variants

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:                  # PR_SET_CHILD_SUBREAPER: orphaned spawner comes back here
        raise RuntimeError("cannot become a subreaper")
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit("SIGTERM")))
    ids = [c for c in args.cases.split(",") if c] or (df_variants.flips(args.variant) if args.variant else [])
    if args.variant and set(ids) != set(df_variants.flips(args.variant)):
        raise SystemExit("a self-check batch runs exactly the subgoals its variants must flip")
    cases = df_registry.batch_cases(ids, controls=not args.variant)
    limit = LONG_RUN_SECONDS if any(c.limit > ATTEMPT_SECONDS for c in cases) else RUN_SECONDS
    deadline = df_cleanup.Deadline(limit)
    (UNIT / "runs").mkdir(exist_ok=True)
    run = df_record.RunDirectory(UNIT / "runs" / run_name(args.label))
    header: dict = {"run": run.path.name, "started_at": utc(), "variant": args.variant, "cases": [c.id for c in cases],
                    "engine": {"path": ENGINE_PATH, "commit": ENGINE_COMMIT}, "configs": {}, "commands": [],
                    "limits": {"batch_seconds": limit}}
    command = df_proc.Commands()
    resources = df_cleanup.Resources()
    cgroup = df_cleanup.RunCgroup(Path("/sys/fs/cgroup"), "df-" + token(args.label))
    env = df_env.Env()
    env.watch, env.admin, env.net = None, None, None
    engine_proc, gate, crash_before = None, None, None
    rows, positives, attempts, evidence = [], [], [], None
    try:
        df_cleanup.check_namespaces(json.loads(args.before), df_proc.namespaces(),
                                    Path("/proc/self/mountinfo").read_text())
        gate = claim_gate()
        capacity = sum(len(c.rows) for c in cases) + 2
        df_cleanup.check_reserved_uids(UID_FIRST, UID_FIRST + capacity - 1, df_proc.host_accounts(),
                                       df_proc.process_uids())
        crash_before = crash_inventory(args.crash_directory)
        header["host"] = {"kernel": platform.release(), "namespaces_before": json.loads(args.before)}
        root = Path(f"/var/lib/nb-decoy-df-{args.label}")
        scratch = Path(f"/tmp/nb-decoy-df-{args.label}-{secrets.token_hex(4)}")
        for d in (root, scratch):
            d.mkdir(mode=0o755)
            resources.add_root(d)
        cgroup.create()
        command.procs = cgroup.procs_path()
        env.root, env.scratch, env.command = root, scratch, command
        env.harness = scratch / "harness"
        env.scripts = scratch / "scripts"
        header["harness"] = snapshot_tree(Path(__file__).resolve().parent, env.harness)
        header["scripts"] = snapshot_tree(UNIT / "scripts", env.scripts)
        header["spec"] = identity((UNIT / "tests.md").read_bytes())["blob"]
        (scratch / "src").mkdir(mode=0o755)
        env.engine, snapshot = df_deploy.snapshot_engine(args.repo, scratch / "src", command)
        if args.variant:
            header["variant_patch"] = df_variants.apply_all(env.engine, args.variant)
            snapshot = df_deploy.inventory(env.engine)
        header["engine"].update(files=snapshot["count"], digest=identity(json.dumps(snapshot["files"],
                                                                                    sort_keys=True).encode())["blob"])
        formal = df_baseline.verify(args.repo, snapshot, platform.release(), command, variant=args.variant)
        header.update(formal=formal["formal"], formal_reasons=formal["reasons"])
        header["engine"]["baseline"] = formal["baseline"]
        build = scratch / "build"
        build.mkdir(mode=0o755)
        os.chown(build, HOST_UID, HOST_UID)
        df_deploy.compile_engine(env.engine, build, command, pwd.getpwuid(HOST_UID).pw_dir)
        images = {"runtime": (scratch / "runtime.btrfs", 1024), "workspace": (scratch / "workspace.btrfs", 256)}
        for path, mib in images.values():
            with path.open("xb") as out:
                out.truncate(mib * 1024 * 1024)
            resources.add_image(path)
            command(["/usr/sbin/mkfs.btrfs", "-q", path])
        workspaces = scratch / "workspaces"
        workspaces.mkdir(mode=0o700)
        for image, target in ((images["runtime"][0], root), (images["workspace"][0], workspaces)):
            command(["/usr/bin/mount", "-o", "loop,nosuid,nodev", image, target])
            resources.add_mount(target, Path("/proc/self/mountinfo").read_text())
        os.chmod(root, 0o755)
        tls = df_tls.make(scratch)
        env.ca_file = tls["ca"]
        env.connector_logs = scratch / "nb-decoy-connector-logs"
        env.connector_logs.mkdir(mode=0o700)
        os.chown(env.connector_logs, CONNECTOR_UID, CONNECTOR_UID)
        env.uwork = df_control.host_work(scratch / "nb-decoy-uwork")
        (scratch / "net").mkdir(mode=0o700)
        env.net = df_net.BatchNetwork(command, resources, scratch / "net", env.harness, tls)
        header["network"] = env.net.prepare(deadline.left())
        env.net.start_servers()
        env.targets = df_net.targets()
        binds: list[Path] = []
        header["deployment"] = df_deploy.deploy(root, env.engine, build, env.scripts, workspaces, binds, command,
                                                capacity=capacity, harness=env.harness,
                                                connector_logs=env.connector_logs, ca_file=tls["ca"])
        for target in binds:
            resources.add_mount(target, Path("/proc/self/mountinfo").read_text())
        header["policy"] = header["deployment"]["policy_digest"]
        command([build / "w2-catalog", root, "catalog.json"], timeout=120)
        evidence_dir = scratch / "nb-decoy-evidence"
        evidence_dir.mkdir()
        evidence = df_deploy.evidence_file(evidence_dir)
        env.events = df_env.EventsFile(evidence)
        env.pdp = df_env.Pdp(env)
        engine_out = (scratch / "nb-decoy-engine.stdout").open("wb")
        engine_err = (scratch / "nb-decoy-engine.stderr").open("wb")
        engine_proc = df_deploy.start_engine(env.engine, build, root, evidence, command, engine_out, engine_err)
        env.admin = df_admin.Admin(root, env.engine)
        wait_admin(env.admin, engine_proc, min(120, deadline.left()))
        wait_control_ready(env.events, engine_proc, min(120, deadline.left()))
        env.watch = df_admin.Watch(env.admin)
        env.watch.start()
        env.pdp.use("simple")
        header["configs"] = {"engine": {"engine": ENGINE_COMMIT, "variant": args.variant},
                             "undefended": {"uid": HOST_UID, "kernel": platform.release(), "cgroup": True,
                                            "no_new_privs": True, "network": "batch run namespace, direct"}}
        for case in cases:
            if deadline.left() < case.limit * 2 + 15:
                header.setdefault("not_run", []).append(case.id)
                continue
            for config in ("engine", "undefended"):
                if config == "undefended" and (case.positive or not case.undefended):
                    if not case.positive:
                        rows.append(df_record.no_counterpart_row(case, script_blob(header, case)))
                    continue
                runner = df_control.run_engine if config == "engine" else df_control.run_undefended
                attempt, facts = runner(env, case)
                verdict = case.judge(facts)
                row = df_record.result_row(case, attempt, verdict, script_blob(header, case))
                row["obs_file"] = run.observation(case, attempt, facts, verdict)
                (positives if case.positive else rows).append(row)
                attempts.append({"nonce": attempt.nonce, "config": config, "executions": attempt.executions,
                                 "start": attempt.start, "end": attempt.end or time.time()})
    except BaseException as error:
        header["controller_error"] = f"{type(error).__name__}: {error}"
        header["controller_traceback"] = traceback.format_exc()[-6000:]
    try:
        header["trace"] = df_judge.trace_check([a for a in attempts if a["config"] == "engine"],
                                               env.net.read("test") if env.net else [],
                                               (env.net.read("test") + env.net.read("run")) if env.net else [],
                                               env.events.read_from(0) if evidence else [])
        copy_evidence(run, env, evidence)
    except BaseException as error:
        header["evidence_error"] = f"{type(error).__name__}: {error}"
    header["cleanup"] = cleanup(env, engine_proc, resources, cgroup, command, args.crash_directory, crash_before)
    if gate is not None and header["cleanup"]["ok"]:
        gate.unlink()                                    # a failed cleanup keeps the gate: later batches refuse
    header["finished_at"] = utc()
    header["commands"] = command.records
    rows = df_record.pair(rows)
    if args.variant:
        header["selfcheck"] = df_variants.selfcheck(args.variant, rows)
    header["completion"] = df_record.completion(rows, positives, header.get("trace", {}), args.selfcheck_passed)
    run.finish(header, rows, positives)
    ok = not header.get("controller_error") and not header.get("evidence_error") and header["cleanup"]["ok"]
    print(json.dumps({"run": str(run.path), "ok": ok}), flush=True)
    return 0 if ok else 1


def script_blob(header: dict, case) -> str:
    return header.get("scripts", {}).get(case.attack + ".py", "")


def wait_admin(admin, engine_proc, limit: float) -> None:
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if engine_proc.poll() is not None:
            raise RuntimeError("the engine exited before the management port came up")
        try:
            if admin.row_list()["ok"]:
                return
        except OSError:
            pass
        time.sleep(1)
    raise TimeoutError("the management port never came up")


def wait_control_ready(events, engine_proc, limit: float) -> None:
    """The spawner checks the runtime seed before it is ready; rows start only after its control_ready (run_gate.py
    start_row at a9eff999 retries ROW_START for the same reason)."""
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if engine_proc.poll() is not None:
            raise RuntimeError("the engine exited before the spawner was ready")
        if any(e.get("name") == "control_received" and
               ((e.get("detail") or {}).get("record") or {}).get("type") == "control_ready"
               for e in events.read_from(0)):
            return
        time.sleep(0.5)
    raise TimeoutError("the spawner never reported control_ready")


def copy_evidence(run, env, evidence: Path | None) -> None:
    if evidence is not None and evidence.exists():
        run.write("events.jsonl", evidence.read_bytes())
    if env.net is not None:
        for side, path in env.net.logs.items():
            if path.exists():
                run.write(f"testnet-{side}.jsonl", path.read_bytes())
    if env.admin is not None:
        run.write("admin.json", json.dumps(env.admin.log, ensure_ascii=False).encode())
    if getattr(env, "pdp", None) is not None:
        run.write("pdp.json", json.dumps({"swaps": env.pdp.swaps, "events": env.pdp.events}).encode())


def crash_inventory(directory: Path) -> dict:
    if not directory.exists():
        return {"exists": False, "entries": {}}
    return {"exists": True, "entries": {p.name: [p.lstat().st_size, p.lstat().st_mtime_ns] for p in directory.iterdir()}}


def cleanup(env, engine_proc, resources, cgroup, command, crash_directory: Path, crash_before) -> dict:
    import df_proc

    def stop_engine():
        for closer in (getattr(env, "watch", None),):
            if closer is not None:
                closer.close()
        if engine_proc is not None and engine_proc.poll() is None:
            engine_proc.send_signal(signal.SIGTERM)
            engine_proc.wait(timeout=20)
        if getattr(env, "pdp", None) is not None:
            env.pdp.close()
        end = time.monotonic() + 20                      # the orphaned spawner sees control EOF and exits by itself
        while time.monotonic() < end and Path(f"/proc/self/task/{os.getpid()}/children").read_text().split():
            os.waitpid(-1, os.WNOHANG)
            time.sleep(0.05)
        if env.net is not None:
            env.net.close()
        return {"engine_exit": None if engine_proc is None else engine_proc.returncode}

    def crash_check():
        after = crash_inventory(crash_directory)
        if crash_before is not None and after != crash_before:
            raise RuntimeError("the Windows crash directory changed during the batch")
        return {"unchanged": True}
    return resources.cleanup(stop_engine=stop_engine, cgroup=cgroup, command=command,
                             mountinfo=lambda: Path("/proc/self/mountinfo").read_text(), crash_check=crash_check)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--label", required=True, type=token)
    p.add_argument("--cases", default="", help="comma-separated subgoal ids; a self-check batch may leave it empty")
    p.add_argument("--repo", type=Path, default=Path("/mnt/d/Thesis"))
    p.add_argument("--crash-directory", type=Path, required=True)
    p.add_argument("--variant", default=None)
    p.add_argument("--selfcheck-passed", action="store_true",
                   help="the offline judge self-check (harness/tests) passed for this harness blob set")
    p.add_argument("--inside", action="store_true")
    p.add_argument("--before", default="{}")
    args = p.parse_args()
    if args.variant is not None:
        from df_variants import names
        names(args.variant)                              # raises on an unknown or repeated variant
    elif not args.cases:
        raise SystemExit("--cases is required outside a self-check batch")
    return inside(args) if args.inside else outer(args)


if __name__ == "__main__":
    raise SystemExit(main())
