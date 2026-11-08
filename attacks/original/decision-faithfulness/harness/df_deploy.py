"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The batch's engine-v3 deployment, built from the pinned commit (registered baseline v4; never the working tree): git
archive of a9eff999 into the batch root, compiled as the host user, a runtime seed of Python 3.12, the attack scripts
and the real in-cell MCP server, and a catalog written the way the engine's own checks/run_gate.py deploy() writes it
(a9eff999). That function is not called: it fixes the uid range to 70000-70015 and the CA pool to 16, too few for one
batch, and gives the connector no CA for the test upstream. What differs here: the uid range and the CA pool are sized
to the batch; the connector argv adds --ca-file (the batch CA) and runs through df_connector_log.py (stderr kept); the
seed holds Python and the scripts instead of an agent; two workspaces, one runner plan each. As there, every row has
its file worker (uid 70996, validation.md H-14) and the seed's MCP server on the cell's port 3129 (H-23); this unit
registers no host file object, so neither is asked anything. Helpers come from the snapshot.
"""
from __future__ import annotations

import importlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

from df_common import (CONNECTOR_UID, ENGINE_COMMIT, ENGINE_PATH, HOST_UID, MCP_PORT, OWNER_UID, PDP_UID,
                       UID_FIRST, WORKER_UID, identity)
from df_proc import AS_HOST, AS_PDP

GO = "/usr/local/go/bin/go"
PYTHON = ["/usr/bin/python3", "-I", "-B"]
SPAWNER_CAPS = ["/usr/bin/setpriv",
                "--bounding-set=-all,+sys_admin,+setuid,+setgid,+setpcap,+net_admin,+kill,+chown",
                "--inh-caps=-all", "--ambient-caps=-all"]
RUNTIME = "df-runner"
WORKSPACES = ("work0", "work1")
PLANS = {"work0": "df-runner-0", "work1": "df-runner-1"}
RUNNER = "/runtime/usr/bin/python3.12"
RUNNER_ARGV = [RUNNER, "-I", "-B", "/runtime/df/df_runner.py"]
RUNNER_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
TREE = "tree"                         # catalog.h W2_WORKSPACE_TREE; run_sandbox_checks.TREE at a9eff999
# the MCP server as checks/gate_seed.py builds and places it at a9eff999 (MCP_BUILD, MCP_SEED, MCP_ARGV); checks_modules
# holds the snapshot to these, so the build here and the seed and catalog below cannot drift from the gate's
MCP_BUILD = ["build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w"]
MCP_SEED = "mcp/engine-mcp"
MCP_ARGV = ["/runtime/" + MCP_SEED]
# catalog.c catalog_load's keys apart from the program and identity keys services() writes
ARTIFACT_KEYS = ("v", "runtimes", "workspaces", "plans", "storage_profile", "policies", "profiles", "uid_range")
EXCLUDE = ("runs", "__pycache__")


def snapshot_engine(repo: Path, dest: Path, command) -> tuple[Path, dict]:
    """The pinned commit's engine tree, extracted root-owned and read-only to everyone else."""
    out = command(AS_HOST + ["/usr/bin/git", "-c", "core.fsmonitor=false", "-C", repo, "archive", "--format=tar",
                             ENGINE_COMMIT, ENGINE_PATH], raw=True, timeout=120)
    with tarfile.open(fileobj=io.BytesIO(out["stdout_bytes"])) as tar:
        tar.extractall(dest, filter="data")
    engine = dest / ENGINE_PATH
    for dirpath, dirnames, filenames in os.walk(dest):
        os.chmod(dirpath, 0o755)
        for name in filenames:
            p = Path(dirpath) / name
            os.chmod(p, 0o755 if p.stat().st_mode & 0o111 else 0o644)
    return engine, inventory(engine)


def inventory(root: Path) -> dict:
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(d for d in dirnames if not (rel_dir == Path(".") and d in EXCLUDE)
                             and d != "__pycache__")
        for name in sorted(filenames):
            rel = (rel_dir / name).as_posix()
            files[rel] = identity((Path(dirpath) / name).read_bytes())["blob"]
    return {"files": files, "count": len(files)}


def checks_modules(engine: Path):
    """gate_seed and run_sandbox_checks from the snapshot (Seed, STDLIB_SKIP, FRONTEND_ARGV, WORKLOAD_ALLOW,
    save_json); imported by path so nothing of the working tree can stand in for them."""
    for sub in ("checks", "native/checks"):
        if str(engine / sub) not in sys.path:
            sys.path.insert(0, str(engine / sub))
    gate_seed = importlib.import_module("gate_seed")
    sandbox = importlib.import_module("run_sandbox_checks")
    for module in (gate_seed, sandbox):
        if engine.resolve() not in Path(module.__file__).resolve().parents:
            raise RuntimeError(f"{module.__name__} did not come from the pinned snapshot")
    if sandbox.OWNER_ID != OWNER_UID or sandbox.TREE != TREE:
        raise RuntimeError("the snapshot's workspace owner or tree name differs from this harness")
    if sandbox.WORKER_ID != WORKER_UID or sandbox.MCP_PORT != MCP_PORT:
        raise RuntimeError("the snapshot's file worker uid or MCP port differs from this harness")
    if (gate_seed.MCP_BUILD, gate_seed.MCP_SEED, gate_seed.MCP_ARGV) != (MCP_BUILD, MCP_SEED, MCP_ARGV):
        raise RuntimeError("the snapshot builds or places the MCP server differently from this harness")
    return gate_seed, sandbox


def compile_engine(engine: Path, build: Path, command, home: str) -> None:
    command(AS_HOST + ["/usr/bin/make", "-s", "-C", engine / "native", "sandbox", f"BUILD_DIR={build}"],
            timeout=300, in_cgroup=True)
    command(AS_HOST + [GO, "-C", engine / "frontend-go", "build", "-trimpath", "-buildvcs=false",
                       "-o", build / "engine-frontend", "."],
            timeout=300, env={"HOME": home, "CGO_ENABLED": "0", "GOTOOLCHAIN": "local"}, in_cgroup=True)
    command(AS_HOST + [GO, "-C", engine / "mcp-go", *MCP_BUILD, "-o", build / "engine-mcp", "."],
            timeout=300, env={"HOME": home, "CGO_ENABLED": "0", "GOTOOLCHAIN": "local"}, in_cgroup=True)


def build_seed(gate_seed, seed_dir: Path, build: Path, scripts: Path):
    s = gate_seed.Seed(seed_dir)
    s.file(build / "w2-relay", "bin/w2-relay")
    s.file(build / "engine-frontend", "frontend/engine-frontend")
    s.file(build / "engine-mcp", MCP_SEED)                  # every seed has the MCP server (gate_seed.build_seed, H-23)
    s.file(Path("/usr/bin/python3.12"), "usr/bin/python3.12")
    s.tree(Path("/usr/lib/python3.12"), "usr/lib/python3.12", lambda n: n in gate_seed.STDLIB_SKIP)
    for p in sorted(scripts.glob("*.py")):
        s.file(p, f"df/{p.name}")
    added = s.libraries()
    versions = {"python": subprocess.run(["/usr/bin/python3.12", "--version"], capture_output=True,
                                         text=True).stdout.strip(),
                "libraries": sorted(added), "not_found": sorted(s.missing),
                "scripts": {p.name: identity(p.read_bytes())["blob"] for p in sorted(scripts.glob("*.py"))}}
    import json
    s.file(None, "dependency-lock.json", (json.dumps(versions, separators=(",", ":")) + "\n").encode())
    return s, versions


def deploy(root: Path, engine: Path, build: Path, scripts: Path, workspace_storage: Path, binds: list,
           command, *, capacity: int, harness: Path, connector_logs: Path, ca_file: str) -> dict:
    """The deployment root's content and catalog; returns what run.json records about it."""
    gate_seed, sandbox = checks_modules(engine)
    save_json = sandbox.save_json
    for d in ("store", "store/objects"):
        (root / d).mkdir(mode=0o700)
    (root / "store/store.lock").touch(mode=0o600)
    for d in ("sandbox-root", "w2", "w2/ca"):
        (root / d).mkdir(mode=0o755)
    command(PYTHON + [engine / "frontend/make_ca_pool.py", root / "ca-pool", str(capacity)], timeout=120)
    seed, versions = build_seed(gate_seed, root / "seed", build, scripts)
    components = seed.manifest()
    component_digest = save_json(root / "components.json", components)
    lock_digest = seed.entries["dependency-lock.json"]["digest"]
    policy_digest = save_json(root / "policy.json", {"v": 1, "target_arch": "x86_64", "default_action": "errno",
                                                     "default_errno": 1, "allow": gate_seed.WORKLOAD_ALLOW})
    profile_digest = save_json(root / "isolation.json", {"isolation_profile_id": "sandbox-native",
                               "target_arch": "x86_64", "layout": "runtime-root-v1", "construction": "SB-01-SB-09"})
    fs = os.statvfs(root)
    shown = command(["/usr/bin/btrfs", "filesystem", "show", "--raw", root])["stdout"]
    nodes = len(components["files"]) + 1
    charge = 4096 * nodes + sum(((e["size"] + 4095) // 4096) * 4096 for e in components["files"]
                                if e["type"] == "file")
    storage_digest = save_json(root / "storage.json", {
        "storage_profile_id": "df-store", "store_id": "d" * 32,
        "filesystem_uuid": re.search(r"uuid:\s*([0-9a-f-]{36})", shown).group(1),
        "store_root_ref": "store", "objects_ref": "store/objects", "lock_ref": "store/store.lock",
        "owner_uid": 0, "owner_gid": 0, "filesystem_kind": "btrfs",
        "filesystem_capacity_bytes": str(fs.f_blocks * fs.f_frsize), "max_copies": 16,
        "max_reserved_bytes": str(2 * charge), "max_reserved_nodes": str(2 * nodes), "max_tree_nodes": 65536,
        "min_free_bytes": str(64 * 1024 * 1024), "cleanup_timeout_ms": 10000})
    catalog: dict = {
        "v": 1, "runtimes": [], "workspaces": [], "plans": [],
        "storage_profile": {"artifact_ref": "storage.json", "artifact_digest": storage_digest},
        "policies": [{"policy_id": "workload", "artifact_ref": "policy.json", "artifact_digest": policy_digest,
                      "target_arch": "x86_64", "format": "w2-seccomp-json/1", "compiler_identity": "libseccomp-2.5.5"}],
        "profiles": [{"artifact_ref": "isolation.json", "artifact_digest": profile_digest}],
        "uid_range": {"first": UID_FIRST, "last": UID_FIRST + capacity - 1},
        **services(engine, root, harness, connector_logs, ca_file, gate_seed.FRONTEND_ARGV["go"])}
    connector_argv = catalog["connector"]["argv"]
    (root / "hook").mkdir()
    os.chown(root / "hook", HOST_UID, PDP_UID)
    os.chmod(root / "hook", 0o2750)
    shutil.copy(build / "libw2sandbox.so", root / "libw2sandbox.so")
    os.chmod(root / "libw2sandbox.so", 0o644)
    for wid in WORKSPACES:
        source = workspace_storage / wid
        command(["/usr/bin/btrfs", "subvolume", "create", source])
        os.chown(source, OWNER_UID, OWNER_UID)
        source.chmod(0o700)
        (source / TREE).mkdir(mode=0o700)
        os.chown(source / TREE, OWNER_UID, OWNER_UID)
        (root / wid).mkdir()
        command(["/usr/bin/mount", "--bind", source, root / wid])
        binds.append(root / wid)
        catalog["workspaces"].append({"workspace_id": wid, "workspace_layout_id": "private-work-v1",
                                      "source_ref": wid, "workspace_uid": OWNER_UID, "workspace_gid": OWNER_UID})
    descriptor = dict(runtime_id=RUNTIME, artifact_digest=component_digest, dependency_digest=lock_digest,
                      layout_id="runtime-root-v1", storage_profile_id="df-store", executable=RUNNER,
                      argv=RUNNER_ARGV, cwd="/work", env=RUNNER_ENV, protocol="w2-local/2",
                      component_manifest_ref="components.json", component_manifest_digest=component_digest)
    rd = save_json(root / f"{RUNTIME}.json", descriptor)
    catalog["runtimes"].append({"descriptor_ref": f"{RUNTIME}.json", "descriptor_digest": rd,
                                "seed_ref": "seed", "dependency_lock_ref": "dependency-lock.json"})
    for wid, plan_id in PLANS.items():
        plan = dict(launch_plan_id=plan_id, runtime_id=RUNTIME, runtime_descriptor_digest=rd, workspace_id=wid,
                    workspace_layout_id="private-work-v1", policy_id="workload", policy_digest=policy_digest,
                    isolation_profile_id="sandbox-native", isolation_profile_digest=profile_digest)
        catalog["plans"].append({"artifact_ref": f"plan-{plan_id}.json",
                                 "artifact_digest": save_json(root / f"plan-{plan_id}.json", plan)})
    catalog_digest = save_json(root / "catalog.json", catalog)
    return {"seed": versions, "policy_digest": policy_digest, "catalog_digest": catalog_digest,
            "components_digest": component_digest, "uid_range": catalog["uid_range"], "capacity": capacity,
            "connector_argv": connector_argv}


def services(engine: Path, root: Path, harness: Path, connector_logs: Path, ca_file: str, frontend_argv: list) -> dict:
    """The catalog's program and identity keys, as run_gate.py deploy() writes them at a9eff999: the connector (through
    df_connector_log.py, with the batch CA), the rows' file worker (H-14), the in-cell relay, frontend and MCP server
    (H-23) and their ports, the cell files, the CA pool, the PDP's identity and the runtime placement."""
    library = str(root / "libw2sandbox.so")
    connector_argv = [*PYTHON, str(harness / "df_connector_log.py"), str(connector_logs),
                      str(engine / "bin/connector"), "--library", library, "--ca-file", ca_file]
    return {
        "connector": {"uid": CONNECTOR_UID, "gid": CONNECTOR_UID, "executable": PYTHON[0], "argv": connector_argv},
        "file_worker": {"uid": WORKER_UID, "gid": WORKER_UID, "executable": PYTHON[0],
                        "argv": [*PYTHON, str(engine / "bin/file-worker"), "--library", library]},
        "relay": {"executable": "/runtime/bin/w2-relay", "argv": ["/runtime/bin/w2-relay"]},
        "frontend": {"executable": frontend_argv[0], "argv": list(frontend_argv)},
        "mcp_server": {"executable": MCP_ARGV[0], "argv": list(MCP_ARGV)}, "mcp_port": MCP_PORT,
        "proxy_port": 3128, "cell_files_ref": "w2", "ca_pool_ref": "ca-pool",
        "pdp": {"uid": PDP_UID, "gid": PDP_UID}, "runtime_mode": "shared"}


def evidence_file(directory: Path) -> Path:
    """E-09's file: written by the engine uid, readable by the PDP's group (run_gate.py at a9eff999)."""
    os.chown(directory, HOST_UID, PDP_UID)
    os.chmod(directory, 0o750)
    evidence = directory / "events.jsonl"
    evidence.touch(mode=0o640)
    os.chown(evidence, HOST_UID, PDP_UID)
    os.chmod(evidence, 0o640)
    return evidence


def start_simple_pdp(engine: Path, root: Path, command, log) -> subprocess.Popen:
    return command.start(AS_PDP + PYTHON + [engine / "bin/simple-pdp", root / "hook/pdp.sock"],
                         stdout=log, stderr=subprocess.STDOUT)


def start_hold_pdp(engine: Path, harness: Path, root: Path, command) -> subprocess.Popen:
    return command.start(AS_PDP + PYTHON + [harness / "df_pdp_hold.py", engine, root / "hook/pdp.sock"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def start_engine(engine: Path, build: Path, root: Path, evidence: Path, command, out, err) -> subprocess.Popen:
    """The production entry under w2-cell, as run_gate.py starts it (completion diagnostics on, as there)."""
    return command.start(SPAWNER_CAPS + [build / "w2-cell", root, "catalog.json", str(HOST_UID), str(HOST_UID),
                                         *PYTHON, engine / "bin/engine", build / "libw2sandbox.so", root,
                                         "catalog.json", evidence, "--measure-completion"],
                         stdout=out, stderr=err)
