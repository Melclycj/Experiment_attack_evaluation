"""Deployment of this thesis's engine for the memory column on the measurement server (protocol.md 1, "本论文"): the
archived version v4, ExperimentLab/engine-v3 @ a9eff999 (prove/baseline v4). Run as root on the server, from the
driver directory:

    python3 -m driver.engine_deploy build <base> <mode> <engine dir> <frontend>
        # mode: copy or shared, written into the catalog either way (v4's default is shared, S-23); frontend: go
    python3 -m driver.engine_deploy capool <base> <count>    # top the CA pool up to count entries
    python3 -m driver.engine_deploy teardown <base>

The deployment follows the engine's block 7 gate (engine-v3/checks/run_gate.py deploy()) with what the measurement
needs instead of the gate's single row: 16 workspaces (one per unit), three runtimes ("probe": the k6 idle script;
"claude": interactive Claude Code at its prompt; "check": one model call in print mode) and one launch plan per runtime
and workspace. As in the gate, every row has a connector (uid 70999) and a file worker (uid 70996) outside the cell and
the MCP server inside it (the seed's mcp/engine-mcp on the cell's port 3129); the workspace storage belongs to the
dedicated owner (uid 70997) with the content in its fixed subdirectory; the hook directory belongs to the engine uid
with the PDP's group (70998), mode 2750. The runtime seed is the gate's 7.1 seed of the engine directory (Claude Code,
bash, the frontend, the MCP server, the pty relay, ldd closure) plus k6.

<base> holds the two btrfs images, their mount points, the native, frontend and MCP builds and the engine's evidence
directory (the engine uid's with the PDP's group, 0750, as the gate makes it); <base>/deploy is the deployment root
(root-owned btrfs, as the catalog requires).
"""
from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .engine_object import (CONNECTOR_UID, ENGINE_UID, FILE_WORKER_UID, OWNER_UID, PDP_UID, PLACEHOLDER, UID_COUNT,
                            UID_FIRST, UNITS)
from .objects import CLAUDE_VERSION, IDLE_JS

K6 = Path("/usr/local/bin/k6")               # v2.3.0, statically linked; the same binary every other object runs
IMAGES = {"runtime": 8, "workspace": 2}      # GiB, sparse
BASE_ENV = {"PATH": "/bin:/usr/bin", "SHELL": "/bin/bash", "TERM": "xterm-256color", "LANG": "C.UTF-8",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"}
# The cell's HOME is its own /tmp (child.c); Claude Code's state file is written there from the read-only cell file
# before Claude Code starts, with bash builtins only (the seed has no coreutils).
RUNTIMES = {
    "probe": ["/runtime/bin/bash", "-c", "exec /runtime/bin/k6 run --no-usage-report --quiet /w2/idle.js"],
    "claude": ["/runtime/bin/bash", "-c",
               "printf '%s' \"$(</w2/claude.json)\" > /tmp/.claude.json && exec /runtime/bin/claude"],
    # the model-API check before each pass (protocol.md 2.2): one call in print mode through the engine
    "check": ["/runtime/bin/bash", "-c",
              "printf '%s' \"$(</w2/claude.json)\" > /tmp/.claude.json && "
              "exec /runtime/bin/claude -p 'Reply with the single word ok.' --model haiku"],
}


def claude_state() -> str:
    """Onboarding done, /work trusted, the placeholder key approved (as OpenShell's cc-start.sh does)."""
    return json.dumps({"hasCompletedOnboarding": True, "lastOnboardingVersion": CLAUDE_VERSION, "theme": "dark",
                       "autoUpdates": False,
                       "customApiKeyResponses": {"approved": [PLACEHOLDER[-20:]], "rejected": []},
                       "projects": {"/work": {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True,
                                              "allowedTools": []}}})


def run(argv: list, timeout: float = 600, env: dict | None = None) -> str:
    p = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout,
                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8", **(env or {})})
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(str(a) for a in argv[:6])} failed ({p.returncode}): {p.stderr[-1500:]}")
    return p.stdout


def command(argv: list, timeout: float = 600, env: dict | None = None) -> dict:
    """run() in the shape the engine's check helpers take (gate_seed.go_build, gate_seed.mcp_build)."""
    return {"stdout": run(argv, timeout, env)}


def load(engine: Path):
    """The engine directory's own seed builder and check constants (one engine directory per process); the dedicated
    ids this driver uses must be the ones the engine's own checks deploy with."""
    for sub in ("native/checks", "checks"):
        if str(engine / sub) not in sys.path:
            sys.path.insert(0, str(engine / sub))
    import gate_seed  # noqa: E402
    import run_engine_checks  # noqa: E402
    import run_sandbox_checks  # noqa: E402
    if Path(gate_seed.__file__).resolve().parents[1] != engine.resolve():
        raise RuntimeError(f"gate_seed came from {gate_seed.__file__}, not {engine}")
    ids = (run_sandbox_checks.WORKER_ID, run_sandbox_checks.OWNER_ID, run_sandbox_checks.PDP_ID)
    if ids != (FILE_WORKER_UID, OWNER_UID, PDP_UID):
        raise RuntimeError(f"{engine}'s dedicated ids {ids} differ from the driver's")
    return gate_seed, run_engine_checks, run_sandbox_checks


def paths(base: Path) -> dict[str, Path]:
    return {"deploy": base / "deploy", "workspaces": base / "workspaces", "build": base / "build",
            "evidence": base / "evidence", "images": base / "images", "state": base / "deployment.json"}


def build(base: Path, mode: str, engine: Path, frontend: str) -> dict:
    gate_seed, checks, _ = load(engine)
    if mode not in ("copy", "shared") or frontend not in gate_seed.FRONTENDS:
        raise ValueError(f"mode {mode!r} frontend {frontend!r}")
    p = paths(base)
    if p["state"].exists():
        raise RuntimeError(f"{base} is already deployed; tear it down first")
    for uid in (*range(UID_FIRST, UID_FIRST + UID_COUNT), CONNECTOR_UID, FILE_WORKER_UID, OWNER_UID, PDP_UID):
        try:
            pwd.getpwuid(uid)
        except KeyError:
            continue
        raise RuntimeError(f"uid {uid} is a host account")
    for gid in (CONNECTOR_UID, FILE_WORKER_UID, OWNER_UID, PDP_UID):     # each dedicated id is its own group too
        try:
            grp.getgrgid(gid)
        except KeyError:
            continue
        raise RuntimeError(f"gid {gid} is a host group")
    base.mkdir(mode=0o755, parents=True)
    try:
        for d in ("images", "deploy", "workspaces"):
            p[d].mkdir(mode=0o755)
        p["build"].mkdir(mode=0o755)
        os.chown(p["build"], ENGINE_UID, ENGINE_UID)
        # the trace is readable by the PDP's group, never writable by it; the engine uid writes it (run_gate.py)
        p["evidence"].mkdir(mode=0o750)
        os.chown(p["evidence"], ENGINE_UID, PDP_UID)
        os.chmod(p["evidence"], 0o750)
        started = time.time()
        home = pwd.getpwuid(ENGINE_UID).pw_dir
        run(checks.AS_USER + ["/usr/bin/make", "-s", "-C", engine / "native", "sandbox", f"BUILD_DIR={p['build']}"],
            timeout=600)
        if frontend == "go":
            gate_seed.go_build(p["build"], command, checks.AS_USER, home)
        gate_seed.mcp_build(p["build"], command, checks.AS_USER, home)      # every seed has the MCP server (H-23)
        for name, gib in IMAGES.items():
            image = p["images"] / f"{name}.btrfs"
            with image.open("xb") as out:
                out.truncate(gib * 1024 ** 3)
            run(["/usr/sbin/mkfs.btrfs", "-q", image])
        run(["/usr/bin/mount", "-o", "loop,nosuid,nodev", p["images"] / "runtime.btrfs", p["deploy"]])
        run(["/usr/bin/mount", "-o", "loop,nosuid,nodev", p["images"] / "workspace.btrfs", p["workspaces"]])
        record = deploy(p, mode, engine, frontend)
        record.update(mode=mode, base=str(base), engine=str(engine), frontend=frontend,
                      engine_files=engine_digests(engine), build_seconds=round(time.time() - started, 1),
                      built_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        p["state"].write_text(json.dumps(record, indent=1) + "\n")
    except BaseException:
        # no deployment.json yet, so neither the object's teardown nor the end-of-run sweep would find this half-built
        # deployment: undo the mounts and remove base now (the credential store is filled only once the core runs)
        left = teardown(base)
        if left:
            print(json.dumps({"rollback_left": left}), file=sys.stderr)
        raise
    return record


def engine_digests(engine: Path) -> dict[str, str]:
    """sha256 of every file of the engine directory but runs/ and bytecode caches: the code this deployment runs
    (prove/baseline v4 is 188 files, compared with its export after the run)."""
    out = {}
    for f in sorted(engine.rglob("*")):
        rel = f.relative_to(engine).as_posix()
        if f.is_file() and not rel.startswith("runs/") and "__pycache__" not in f.parts:
            out[rel] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def deploy(p: dict[str, Path], mode: str, engine: Path, frontend: str) -> dict:
    gate_seed, checks, sandbox_checks = load(engine)
    save_json, python = sandbox_checks.save_json, checks.PYTHON
    root = p["deploy"]
    (root / "store").mkdir(mode=0o700)
    (root / "store/objects").mkdir(mode=0o700)
    (root / "store/store.lock").touch(mode=0o600)
    (root / "sandbox-root").mkdir(mode=0o755)
    for d in ("w2", "w2/ca"):
        (root / d).mkdir(mode=0o755)
    for name, text in (("idle.js", IDLE_JS), ("claude.json", claude_state())):
        (root / "w2" / name).write_text(text)
        os.chmod(root / "w2" / name, 0o444)
    capool(root, 2 * UNITS + 2, engine)
    seed, versions = gate_seed.build_seed(root / "seed", p["build"], False, frontend=frontend)
    seed.file(K6, "bin/k6")                             # the probe; static, so the ldd pass below adds nothing
    versions["k6"] = {"digest": seed.entries["bin/k6"]["digest"], "libraries_added": seed.libraries()}
    components = seed.manifest()
    component_digest = save_json(root / "components.json", components)
    lock_digest = seed.entries["dependency-lock.json"]["digest"]
    policy_digest = save_json(root / "policy.json", {"v": 1, "target_arch": "x86_64", "default_action": "errno",
                                                     "default_errno": 1, "allow": gate_seed.WORKLOAD_ALLOW})
    profile_digest = save_json(root / "isolation.json", {"isolation_profile_id": "sandbox-native",
                               "target_arch": "x86_64", "layout": "runtime-root-v1", "construction": "SB-01-SB-09"})
    fs = os.statvfs(root)
    identity = run(["/usr/bin/btrfs", "filesystem", "show", "--raw", root])
    nodes = len(components["files"]) + 1
    charge = 4096 * nodes + sum(((e["size"] + 4095) // 4096) * 4096 for e in components["files"] if e["type"] == "file")
    # Every unit holds one copy (copy mode); the gate's deployment allows two.
    storage_digest = save_json(root / "storage.json", {
        "storage_profile_id": "measure-store", "store_id": "e" * 32,
        "filesystem_uuid": re.search(r"uuid:\s*([0-9a-f-]{36})", identity).group(1),
        "store_root_ref": "store", "objects_ref": "store/objects", "lock_ref": "store/store.lock",
        "owner_uid": 0, "owner_gid": 0, "filesystem_kind": "btrfs",
        "filesystem_capacity_bytes": str(fs.f_blocks * fs.f_frsize), "max_copies": UNITS,
        "max_reserved_bytes": str(UNITS * charge), "max_reserved_nodes": str(UNITS * nodes), "max_tree_nodes": 65536,
        "min_free_bytes": str(64 * 1024 * 1024), "cleanup_timeout_ms": 10000})
    frontend_argv = gate_seed.FRONTEND_ARGV[frontend]
    catalog: dict = {
        "v": 1, "runtimes": [],
        "storage_profile": {"artifact_ref": "storage.json", "artifact_digest": storage_digest},
        "policies": [{"policy_id": "workload", "artifact_ref": "policy.json", "artifact_digest": policy_digest,
                      "target_arch": "x86_64", "format": "w2-seccomp-json/1", "compiler_identity": "libseccomp-2.5.5"}],
        "workspaces": [], "profiles": [{"artifact_ref": "isolation.json", "artifact_digest": profile_digest}],
        "plans": [], "uid_range": {"first": UID_FIRST, "last": UID_FIRST + UID_COUNT - 1},
        "connector": {"uid": CONNECTOR_UID, "gid": CONNECTOR_UID, "executable": python[0],
                      "argv": [*python, str(engine / "bin/connector"), "--library", str(root / "libw2sandbox.so")]},
        # the row's file worker (validation.md H-14), its own dedicated uid, as the gate deploys it
        "file_worker": {"uid": FILE_WORKER_UID, "gid": FILE_WORKER_UID, "executable": python[0],
                        "argv": [*python, str(engine / "bin/file-worker"), "--library",
                                 str(root / "libw2sandbox.so")]},
        "relay": {"executable": "/runtime/bin/w2-relay", "argv": ["/runtime/bin/w2-relay"]},
        "frontend": {"executable": frontend_argv[0], "argv": list(frontend_argv)},
        "proxy_port": 3128, "cell_files_ref": "w2", "ca_pool_ref": "ca-pool",
        # the in-cell MCP server from the seed (validation.md H-23); no file object is registered here
        "mcp_server": {"executable": gate_seed.MCP_ARGV[0], "argv": list(gate_seed.MCP_ARGV)}, "mcp_port": 3129,
        "pdp": {"uid": PDP_UID, "gid": PDP_UID},
        "runtime_mode": mode}                           # written explicitly: the catalog's default is shared (S-23)
    (root / "hook").mkdir()                             # the hook port's directory, as the deployment makes it (K-48)
    os.chown(root / "hook", ENGINE_UID, PDP_UID)
    os.chmod(root / "hook", 0o2750)
    shutil.copy(p["build"] / "libw2sandbox.so", root / "libw2sandbox.so")
    os.chmod(root / "libw2sandbox.so", 0o644)
    rds = {}
    for runtime, argv in RUNTIMES.items():
        env = {**BASE_ENV, **({"ANTHROPIC_API_KEY": PLACEHOLDER} if runtime in ("claude", "check") else {})}
        descriptor = dict(runtime_id=runtime, artifact_digest=component_digest, dependency_digest=lock_digest,
                          layout_id="runtime-root-v1", storage_profile_id="measure-store",
                          executable="/runtime/bin/bash", argv=argv, cwd="/work", env=env, protocol="w2-local/2",
                          component_manifest_ref="components.json", component_manifest_digest=component_digest)
        rds[runtime] = save_json(root / f"{runtime}.json", descriptor)
        catalog["runtimes"].append({"descriptor_ref": f"{runtime}.json", "descriptor_digest": rds[runtime],
                                    "seed_ref": "seed", "dependency_lock_ref": "dependency-lock.json"})
    # the workspace storage belongs to the dedicated owner, root of it 0700, the content in the fixed subdirectory
    # the cell mounts (agent-rm-model 3.1; D-17, S-25), as the gate deploys it
    for i in range(1, UNITS + 1):
        ws = f"work{i}"
        source = p["workspaces"] / ws
        run(["/usr/bin/btrfs", "subvolume", "create", source])
        os.chown(source, OWNER_UID, OWNER_UID)
        source.chmod(0o700)
        (source / sandbox_checks.TREE).mkdir(mode=0o700)
        os.chown(source / sandbox_checks.TREE, OWNER_UID, OWNER_UID)
        (root / ws).mkdir()
        run(["/usr/bin/mount", "--bind", source, root / ws])
        catalog["workspaces"].append({"workspace_id": ws, "workspace_layout_id": "private-work-v1", "source_ref": ws,
                                      "workspace_uid": OWNER_UID, "workspace_gid": OWNER_UID})
        for runtime in RUNTIMES:
            plan = dict(launch_plan_id=f"{runtime}-{i}", runtime_id=runtime, runtime_descriptor_digest=rds[runtime],
                        workspace_id=ws, workspace_layout_id="private-work-v1", policy_id="workload",
                        policy_digest=policy_digest, isolation_profile_id="sandbox-native",
                        isolation_profile_digest=profile_digest)
            catalog["plans"].append({"artifact_ref": f"plan-{runtime}-{i}.json",
                                     "artifact_digest": save_json(root / f"plan-{runtime}-{i}.json", plan)})
    return {"seed": {"entries": len(seed.entries), "bytes": sum(e["size"] for e in seed.entries.values()),
                     "versions": versions}, "charge_bytes": charge, "nodes": nodes,
            "catalog_digest": save_json(root / "catalog.json", catalog)}


def capool(root: Path, want: int, engine: Path) -> int:
    """Top the CA pool up to `want` entries (the spawner consumes one per row); returns how many were added."""
    gate_seed, _, _ = load(engine)
    pool = root / "ca-pool"
    have = len([d for d in pool.iterdir() if d.is_dir()]) if pool.is_dir() else 0
    add = max(0, want - have)
    if add:
        run([gate_seed.VENV / "bin/python", engine / "frontend/make_ca_pool.py", pool, str(add)], timeout=300)
    return add


def teardown(base: Path) -> list[str]:
    """Unmount the workspace binds and both images and remove base. Returns what could not be undone."""
    p = paths(base)
    users = []
    for d in Path("/proc").iterdir():                  # the core, the PDP or a row still running from this deployment
        try:
            if d.name.isdigit() and int(d.name) != os.getpid() and str(base).encode() in (d / "cmdline").read_bytes():
                users.append(int(d.name))
        except OSError:
            continue
    if users:
        return [f"processes still use {base}: {users[:8]}"]
    left = []
    mounts = [line.split()[1] for line in Path("/proc/mounts").read_text().splitlines()]
    for target in sorted((m for m in mounts if m.startswith(str(base) + "/")), key=len, reverse=True):
        r = subprocess.run(["/usr/bin/umount", target], capture_output=True, text=True)
        if r.returncode != 0:
            left.append(f"umount {target}: {r.stderr.strip()}")
    if not left:
        shutil.rmtree(base)
    elif p["state"].exists():
        left.append("deployment kept")
    return left


def main(argv: list[str]) -> int:
    op, base = argv[0], Path(argv[1])
    if op == "build":
        print(json.dumps(build(base, argv[2], Path(argv[3]), argv[4])))
    elif op == "capool":
        engine = Path(json.loads(paths(base)["state"].read_text())["engine"])
        print(json.dumps({"added": capool(paths(base)["deploy"], int(argv[2]), engine)}))
    elif op == "teardown":
        left = teardown(base)
        print(json.dumps({"left": left}))
        return 1 if left else 0
    else:
        raise SystemExit(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
