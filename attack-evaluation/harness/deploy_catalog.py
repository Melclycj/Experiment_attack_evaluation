"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import json
from pathlib import Path

from build import capacity, storage_reservation
from common import digest, identity, json_bytes
from env import OWNER_UID, WORKER_UID
from safeio import atomic_write, read_owned

PYTHON = ["/usr/bin/python3", "-I", "-B"]
SPAWNER_CAPS = ["/usr/bin/setpriv",
               "--bounding-set=-all,+sys_admin,+setuid,+setgid,+setpcap,+net_admin,+kill,+chown",
               "--inh-caps=-all", "--ambient-caps=-all"]
# The PDP's dedicated uid and group, as engine-v3 checks/run_gate.py deploys it (648d60f2 4.2; validation.md D-13):
# no host account, outside the reserved range, not the connector's 70999.
PDP_UID = 70998
PDP_CAPS = ["/usr/bin/setpriv", f"--reuid={PDP_UID}", f"--regid={PDP_UID}", "--clear-groups", "--bounding-set=-all",
            "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]
HOOK_MODE = 0o2750  # owner the engine uid, group the PDP group, setgid (engine-v3 engine/pdp.py check_hook_dir)
# Base line v4 (engine-v3 @ a9eff999): the in-cell MCP server's port, apart from proxy_port (run_gate.py deploy()).
# The MCP process is the frontend stand-in, whose argv tail (<socket> <port> <ready file>) is the MCP server's:
# it connects the row's file port, listens and writes the ready file, as native/checks/run_sandbox_checks.py deploys it.
MCP_PORT = 3129


def save(path: Path, value: dict) -> str:
    data = json_bytes(value)
    atomic_write(path, data)
    path.chmod(0o444)
    return "sha256:" + identity(read_owned(path))["sha256"]


def catalog_files(source: Path, root: Path, cap: dict, *, fs_uuid: str, fs_bytes: int, cb_logs=None) -> dict:
    """Production v4 catalog (runtime_mode left to its default, shared), three workspaces owned by the dedicated
    workspace uid, the rows' file worker and the MCP stand-in, workload allowlist only."""
    if cap != capacity(cap["executions"], cap["first"], cap["last"] - cap["first"] + 1 - cap["executions"]):
        raise ValueError("capacity does not match the build contract")
    if cap["ca_count"] > 1024:  # current production engine/startup.py RANGE_MAX
        raise ValueError("production core startup verifies at most 1024 reserved uids")
    manifest = json.loads(read_owned(root / "components.json"))
    component = "sha256:" + identity(read_owned(root / "components.json"))["sha256"]
    lock = "sha256:" + identity(read_owned(root / "seed/dependency-lock.json"))["sha256"]
    receipt = json.loads(read_owned(root / "seed-receipt.json"))
    if component != receipt["components_digest"] or lock != receipt["dependency_digest"]:
        raise ValueError("seed receipt digest mismatch")
    reservation = storage_reservation(manifest, cap["simultaneous_copies"])
    if fs_bytes < 4 * reservation["charge_per_copy"] + int(reservation["min_free_bytes"]):
        raise RuntimeError("fixed image cannot hold seed plus three copies; do not enlarge without approval")
    allow = sorted({line.strip() for line in read_owned(source / "checks/workload-allow.txt").decode().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")})
    if not allow:
        raise ValueError("empty production workload policy")
    policy = save(root / "policy.json", {"v": 1, "target_arch": "x86_64", "default_action": "errno",
                                         "default_errno": 1, "allow": allow})
    profile = save(root / "isolation.json", {"isolation_profile_id": "sandbox-native", "target_arch": "x86_64",
                                           "layout": "runtime-root-v1", "construction": "SB-01-SB-09"})
    storage = save(root / "storage.json", {
        "storage_profile_id": "nb-store", "store_id": "e" * 32, "filesystem_uuid": fs_uuid,
        "store_root_ref": "store", "objects_ref": "store/objects", "lock_ref": "store/store.lock",
        "owner_uid": 0, "owner_gid": 0, "filesystem_kind": "btrfs", "filesystem_capacity_bytes": str(fs_bytes),
        **{k: v for k, v in reservation.items() if k != "charge_per_copy"},
        "max_copies": 16,  # storage.c requires 16 slots; byte/node reservations still charge only three copies
        "max_tree_nodes": 65536, "cleanup_timeout_ms": 10000})
    descriptor = {"runtime_id": "nb", "artifact_digest": component, "dependency_digest": lock,
                  "layout_id": "runtime-root-v1", "storage_profile_id": "nb-store",
                  "executable": "/runtime/usr/bin/python3.12",
                  "argv": ["/runtime/usr/bin/python3.12", "-I", "-B", "/runtime/nb/runner.py"],
                  "cwd": "/work", "env": {"PATH": "/usr/bin:/bin", "HOME": "/work", "LANG": "C.UTF-8",
                                            "GIT_CONFIG_NOSYSTEM": "1"},
                  "protocol": "w2-local/2", "component_manifest_ref": "components.json",
                  "component_manifest_digest": component}
    rd = save(root / "runtime.json", descriptor)
    catalog = {"v": 1, "runtimes": [{"descriptor_ref": "runtime.json", "descriptor_digest": rd,
                                     "seed_ref": "seed", "dependency_lock_ref": "dependency-lock.json"}],
               "storage_profile": {"artifact_ref": "storage.json", "artifact_digest": storage},
               "policies": [{"policy_id": "workload", "artifact_ref": "policy.json", "artifact_digest": policy,
                             "target_arch": "x86_64", "format": "w2-seccomp-json/1", "compiler_identity": "libseccomp-2.5.5"}],
               "profiles": [{"artifact_ref": "isolation.json", "artifact_digest": profile}],
               "workspaces": [], "plans": [], "uid_range": {"first": cap["first"], "last": cap["spare_uid"] - 1},
               "connector": {"uid": 70999, "gid": 70999, "executable": PYTHON[0],
                             "argv": [*PYTHON, str(source / "bin/connector"), "--library",
                                      str(root / "libw2sandbox.so"), "--ca-file", str(root / "tls/ca.pem")]},
               "relay": {"executable": "/runtime/bin/w2-relay", "argv": ["/runtime/bin/w2-relay"]},
               "frontend": {"executable": "/runtime/bin/w2-frontend-stub", "argv": ["/runtime/bin/w2-frontend-stub"]},
               "proxy_port": 3128, "cell_files_ref": "w2", "ca_pool_ref": "ca-pool",
               "pdp": {"uid": PDP_UID, "gid": PDP_UID},
               # v4 required keys (catalog.c): the row's file worker under its own dedicated uid (H-14) and the
               # in-cell MCP server (H-23), here the frontend stand-in (MCP_PORT comment above).
               "file_worker": {"uid": WORKER_UID, "gid": WORKER_UID, "executable": PYTHON[0],
                               "argv": [*PYTHON, str(source / "bin/file-worker"), "--library",
                                        str(root / "libw2sandbox.so")]},
               "mcp_server": {"executable": "/runtime/bin/w2-frontend-stub", "argv": ["/runtime/bin/w2-frontend-stub"]},
               "mcp_port": MCP_PORT}
    for i in range(3):
        workspace = f"work{i}"
        catalog["workspaces"].append({"workspace_id": workspace, "workspace_layout_id": "private-work-v1",
                                      "source_ref": workspace, "workspace_uid": OWNER_UID,
                                      "workspace_gid": OWNER_UID})  # v4: never the engine uid (cell.c, S-22)
        plan = {"launch_plan_id": f"nb-{i}", "runtime_id": "nb", "runtime_descriptor_digest": rd,
                "workspace_id": workspace, "workspace_layout_id": "private-work-v1", "policy_id": "workload",
                "policy_digest": policy, "isolation_profile_id": "sandbox-native", "isolation_profile_digest": profile}
        name = f"plan-nb-{i}.json"
        catalog["plans"].append({"artifact_ref": name, "artifact_digest": save(root / name, plan)})
    if cb_logs is not None:
        wrapper = Path(__file__).with_name('cb_connector_boot.py')
        original = catalog['connector']['argv']
        catalog['connector']['argv'] = [*PYTHON, str(wrapper), str(cb_logs), *original[len(PYTHON):]]
    cd = save(root / "catalog.json", catalog)
    result = {"catalog": catalog, "catalog_digest": cd, "policy_digest": policy,
            "components_digest": component, "reservation": reservation}
    if cb_logs is not None:
        result['measurement'] = {'unit':'credential-binding','approved_by_user':'2026-11-03',
            'wrapper': identity(read_owned(wrapper)),
            'host_collector': identity(read_owned(Path(__file__).with_name('cb_measure.py'))),
            'original_connector_argv': original,'environment_handshake':'pidfd-before-exec',
            'stdout_stderr':'exclusive-files-before-exec-until-pidfd-exit',
            'log_limit_per_stream':262144,'source_modified':False,'formal':False}
    return result
