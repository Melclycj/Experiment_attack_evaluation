"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import time

from build import inventory
from common import digest, identity, json_bytes, token
from deploy_catalog import HOOK_MODE, PDP_CAPS, PDP_UID, PYTHON, SPAWNER_CAPS, catalog_files
from deploy_seed import FILE_LIMIT, PRODUCTS, payload_manifest
from env import OWNER_UID, WORKER_UID
from management import Management
from net import QUESTION_HOST, UPSTREAM_HOST, mount_owned
from process_identity import ProcessRef, direct_children, process_info
from safeio import atomic_write, plain_path, read_beneath, read_owned
from upstream import Upstream, wait_for

IMAGE_BYTES = 256 * 1024 * 1024  # TESTING §1: never silently inherit run_gate's larger images
TREE = "tree"  # v4: the fixed subdirectory a cell mounts (catalog.h W2_WORKSPACE_TREE; child.c; S-25)
HOST_WORKSPACES = ("work0", "work1")  # the undefended arm's own host-user workspaces (tests.md 1.7)


def require_platform():
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("production deployment requires the authorized private WSL root controller")


def fresh_root(path: Path, resources):
    path = plain_path(path, missing_leaf=True)
    if path.parent not in (Path("/tmp"), Path("/var/lib")) or not path.name.startswith("nb-decoy-"):
        raise ValueError("deployment roots must be fresh nb-decoy roots in /tmp or /var/lib")
    path.mkdir(mode=0o755)
    resources.add_root(path)  # before any later chmod/population can fail
    path.chmod(0o755)
    return path


class Deployment:
    """3c lifecycle. Caller supplies snapshots/products and a separate bounded
    cleanup Commands instance (reserved time, same cgroup) to survive failed setup.
    This class never authorizes a run: 3e must enforce the user's 开始 gate first.
    Inputs/outputs are interfaces, not test outcomes or baseline registration.
    """
    def __init__(self, *, source: Path, source_identity: dict, build: Path, products: dict,
                 cap: dict, payload: dict, command, resources, network, cleanup_command,
                 crash_check, label: str, cert_python="/home/jerry/.venvs/engine-v2-frontend/bin/python", unit="no-bypass"):
        self.source, self.build, self.cap = Path(source), Path(build), cap
        self.source_identity, self.products, self.payload = source_identity, products, payload
        self.command, self.resources, self.network = command, resources, network
        self.cleanup_command, self.crash_check, self.cert_python = cleanup_command, crash_check, cert_python
        self.root = Path("/var/lib") / ("nb-decoy-" + token(label))
        self.scratch = Path("/tmp") / ("nb-decoy-" + label)
        self.storage, self.evidence = self.scratch / "workspaces", self.scratch / "nb-decoy-e09.jsonl"
        self.engine = self.admin = self.upstream = self.pdp = None
        # engine arm: the deployment's v4 workspaces; undefended arm: the host user's own (tests.md 1.7)
        self.refs, self.manifest, self.workspaces, self.host_workspaces = {}, {}, {}, {}
        self.stage, self.started, self.cleanup_result = "new", False, None
        self.evidence_bytes = None
        self.unit = unit
        self.cb_logs = None
        self.cb_measure = None

    def prepare(self):
        if self.started:
            raise RuntimeError("deployment lifecycle is single-use")
        self.started = True
        try:
            require_platform()
            if (self.network.command is not self.command or self.network.resources is not self.resources
                    or self.cleanup_command is self.command
                    or self.cleanup_command.cgroup is not self.command.cgroup):
                raise ValueError("deployment supervision/resource owners do not match")
            self.stage = "inputs"
            self.source, self.build = plain_path(self.source), plain_path(self.build)
            if inventory(self.source) != self.source_identity:
                raise ValueError("source snapshot changed")
            for name in PRODUCTS:
                if identity(read_owned(self.build / name, FILE_LIMIT)) != self.products.get(name):
                    raise ValueError("compiled artifact digest mismatch: " + name)
            payload = payload_manifest(self.payload)
            self.stage = "images"
            fresh_root(self.scratch, self.resources)
            fresh_root(self.root, self.resources)
            self.storage.mkdir(mode=0o755)
            for name, target in (("runtime", self.root), ("workspace", self.storage)):
                path = self.scratch / ("nb-decoy-" + name + ".btrfs")
                with path.open("xb") as handle:
                    self.resources.add_image(path)
                    handle.truncate(IMAGE_BYTES)
                self.command(["/usr/sbin/mkfs.btrfs", "-q", str(path)], timeout=20)
                mount_owned(self.resources, self.command, ["/usr/bin/mount", "-o", "loop,nosuid,nodev",
                            str(path), str(target)], target)
            self.stage = "seed"
            for rel, mode in (("store", 0o700), ("store/objects", 0o700), ("sandbox-root", 0o755),
                              ("w2", 0o755), ("w2/ca", 0o755)):
                (self.root / rel).mkdir(mode=mode)
                (self.root / rel).chmod(mode)
            # The hook port's directory, made once by the deployment as root (648d60f2 4.2; validation.md K-48).
            hook = self.root / "hook"
            hook.mkdir(mode=0o700)
            os.chown(hook, 1000, PDP_UID)
            os.chmod(hook, HOOK_MODE)
            atomic_write(self.root / "store/store.lock", b"")
            atomic_write(self.root / "libw2sandbox.so", read_owned(self.build / "libw2sandbox.so", FILE_LIMIT))
            (self.root / "libw2sandbox.so").chmod(0o644)
            payload_path = self.scratch / "nb-decoy-payload.json"
            atomic_write(payload_path, json_bytes(payload))
            self.command([*PYTHON, str(Path(__file__).with_name("deploy_seed.py")), str(self.source),
                          str(self.build), str(self.root), str(payload_path)], timeout=120)
            self.stage = "tls"
            self.command([self.cert_python, "-I", "-B", str(Path(__file__).with_name("tls_material.py")),
                          str(self.source), str(self.root), str(self.cap["ca_count"]),
                          *([self.unit] if self.unit != "no-bypass" else [])], timeout=60)
            pool = self.root / "ca-pool"
            entries = list(pool.iterdir())
            if len(entries) != self.cap["ca_count"]:
                raise RuntimeError("wrong CA pool count")
            for entry in entries:
                for file in ("ca.pem", "ca.key"):
                    read_owned(entry / file, 65536)
            self.stage = "workspaces"
            # v4 (engine-v3 @ a9eff999): the subvolume root belongs to the dedicated workspace owner, 0700, and a cell
            # gets only its fixed tree subdirectory through the idmapped mount (cell.c refuses the engine uid; S-22,
            # S-25). Decoys and requests go into tree/, owned by that owner, so they map to the row's uid in the cell.
            for i in range(3):
                name, source = f"work{i}", self.storage / f"work{i}"
                self.command(["/usr/bin/btrfs", "subvolume", "create", str(source)], timeout=10)
                os.chown(source, OWNER_UID, OWNER_UID)
                source.chmod(0o700)
                (source / TREE).mkdir(mode=0o700)
                os.chown(source / TREE, OWNER_UID, OWNER_UID)
                (source / TREE).chmod(0o700)
                target = self.root / name
                target.mkdir(mode=0o755)
                mount_owned(self.resources, self.command, ["/usr/bin/mount", "--bind", str(source), str(target)], target)
                self.workspaces[name] = {"source": source / TREE, "mount": target / TREE, "plan": f"nb-{i}",
                                         "owner": OWNER_UID}
            # The undefended arm is the status quo with no engine: the agent's workspace is a host-user directory.
            # Same two-path shape as the engine arm (storage subvolume and a bind mount), outside the deployment root.
            host_mounts = self.scratch / "host-work"
            host_mounts.mkdir(mode=0o755)
            for name in HOST_WORKSPACES:
                source = self.storage / ("u-" + name)
                self.command(["/usr/bin/btrfs", "subvolume", "create", str(source)], timeout=10)
                os.chown(source, 1000, 1000)
                source.chmod(0o700)
                target = host_mounts / name
                target.mkdir(mode=0o755)
                mount_owned(self.resources, self.command, ["/usr/bin/mount", "--bind", str(source), str(target)], target)
                self.host_workspaces[name] = {"source": source, "mount": target, "owner": 1000}
            self.stage = "catalog"
            if self.unit == 'credential-binding':
                self.cb_logs = self.scratch / 'nb-decoy-connector-logs'
                self.cb_logs.mkdir(mode=0o700)
                os.chown(self.cb_logs,70999,70999)
            fs = os.statvfs(self.root)
            filesystem = self.command(["/usr/bin/btrfs", "filesystem", "show", "--raw", str(self.root)])["stdout"]
            match = re.search(r"uuid:\s*([0-9a-f-]{36})", filesystem)
            if not match:
                raise RuntimeError("cannot identify owned btrfs filesystem")
            self.manifest = catalog_files(self.source, self.root, self.cap,
                                          fs_uuid=match[1], fs_bytes=fs.f_blocks * fs.f_frsize,
                                          **({'cb_logs': self.cb_logs} if self.cb_logs else {}))
            self.manifest["compiled_policy"] = json.loads(self.command(
                [str(self.build / "w2-catalog"), str(self.root), "catalog.json"], timeout=30)["stdout"])
            if self.manifest["compiled_policy"]["catalog_digest"] != self.manifest["catalog_digest"]:
                raise RuntimeError("native catalog digest mismatch")
            self.manifest["artifacts"] = {
                path.relative_to(self.root).as_posix(): identity(read_owned(path, FILE_LIMIT))
                for path in [*self.root.glob("*.json"), self.root / "libw2sandbox.so",
                             *self.root.glob("tls/*"), *self.root.glob("ca-pool/*/*")]}
            self.manifest.update(source=self.source_identity, products=self.products)
            self.manifest["digest"] = digest(self.manifest)
            self.stage = "network"
            self.network_info = self.network.prepare()
            names = (UPSTREAM_HOST, QUESTION_HOST)
            if self.unit == 'credential-binding':
                from cb_profile import NAMES
                names = NAMES
            self.network.bind_hosts(self.scratch / "nb-decoy-hosts", names=names)
            self.stage = "https"
            upstream_type = Upstream
            if self.unit == 'credential-binding':
                from cb_upstream import CredentialUpstream
                upstream_type = CredentialUpstream
            self.upstream = upstream_type(self.root, self.command, self.network, self.network_info)
            self.upstream.start()
            self.stage = "engine"
            atomic_write(self.evidence, b"")
            self.evidence.chmod(0o600)
            os.chown(self.evidence, 1000, 1000)
            # The simple PDP (validation.md P-01) as its dedicated uid, in the run cgroup, started first: it retries
            # until the hook port is up, and a request that reaches the PDP stage before it connects waits (K-47).
            self.pdp = self.command.start([*PDP_CAPS, *PYTHON, str(self.source / "bin/simple-pdp"),
                                           str(self.root / "hook/pdp.sock")], timeout=self.command.deadline.left(540))
            self.engine = self.command.start([*SPAWNER_CAPS, str(self.build / "w2-cell"), str(self.root),
                "catalog.json", "1000", "1000", *PYTHON, str(self.source / "bin/engine"),
                str(self.root / "libw2sandbox.so"), str(self.root), "catalog.json", str(self.evidence)],
                timeout=self.command.deadline.left(540))
            self.admin = Management(self.source, self.root, self.command, self.engine)
            self.admin.ready()
            self._pdp_ready()
            self.refs["core"] = ProcessRef(self.engine.proc.pid, 1000, self.command.cgroup)
            self.refs["spawner"] = self._spawner()
            if self.unit == 'credential-binding':
                from cb_measure import ConnectorMeasurement
                self.cb_measure = ConnectorMeasurement(self)
                self.command.observers = [*getattr(self.command,'observers',()),self.cb_measure.pump]
            self.stage = "management"
            # Random values belong to this deployment only, never real credentials.
            self.admin.credential(secrets.token_hex(24), "nb-decoy-" + secrets.token_hex(16))
            self.admin.entry()
            for workspace in ("work0", "work2"):  # NB-21's question: the attack row (work0), the auxiliary row (work2)
                self.admin.question_entry(workspace)
            self.stage = "ready"
            return self
        except BaseException:
            self.close()
            raise

    def _pdp_ready(self):
        """Setup readiness only: the engine's own E-09 record of the hook port accepting the PDP (engine/pdp.py)."""
        def connected():
            lines = read_beneath(self.scratch, self.evidence.name).split(b"\n")[:-1]  # complete lines only
            for line in lines:
                try:
                    if json.loads(line).get("kind") == "pdp_connected":
                        return True
                except (ValueError, AttributeError):
                    continue
            return False
        return wait_for(self.command, connected, child=self.pdp)

    def _spawner(self):
        def find():
            children = direct_children(self.engine.proc.pid)
            for pid in children:
                try:
                    info = process_info(pid)
                except FileNotFoundError:
                    continue
                if info["uids"] == [0] * 4 and info["argv"][:1] == [str(self.build / "w2-cell")]:
                    return ProcessRef(pid, 0, self.command.cgroup)
        return wait_for(self.command, find, child=self.engine)

    def connector(self, execution):
        """Pin the exact row connector by production argv, parent and cgroup."""
        def find():
            self.refs["spawner"].read()
            for pid in direct_children(self.refs["spawner"].initial["pid"]):
                try:
                    info = process_info(pid)
                except FileNotFoundError:
                    continue
                if (info["uids"] == [70999] * 4 and info["argv"][-1:] == [execution]
                        and str(self.source / "bin/connector") in info["argv"]):
                    return ProcessRef(pid, 70999, self.command.cgroup)
        ref = wait_for(self.command, find, child=self.engine)
        key = "connector:" + execution
        if key in self.refs:
            ref.close()
            raise ValueError("connector already pinned")
        self.refs[key] = ref
        return ref

    def file_worker(self, execution):
        """Pin the row's file worker (v4, spawner.c start_worker) by production argv, parent, uid and cgroup."""
        def find():
            self.refs["spawner"].read()
            for pid in direct_children(self.refs["spawner"].initial["pid"]):
                try:
                    info = process_info(pid)
                except FileNotFoundError:
                    continue
                if (info["uids"] == [WORKER_UID] * 4 and info["argv"][-1:] == [execution]
                        and str(self.source / "bin/file-worker") in info["argv"]):
                    return ProcessRef(pid, WORKER_UID, self.command.cgroup)
        key = "file-worker:" + execution
        if key in self.refs:
            raise ValueError("file worker already pinned")
        ref = wait_for(self.command, find, child=self.engine)
        self.refs[key] = ref
        return ref

    def state_paths(self):
        return {"admin": self.root / "state/admin.sock", "e09": self.evidence,
                "mirror": self.root / "state/workspaces/work0.json",
                "credentials": self.root / "state/credentials" / (UPSTREAM_HOST + ":443")}

    def stop_engine(self):
        """Stop by owned pidfd, then wait for spawner EOF exit before netns close.
        During cleanup, drain existing pipes with the separately reserved supervisor.
        No start/attack is permitted on the failed original Commands object.
        """
        if self.engine is None:
            return
        core = self.refs.get("core")
        if core and not core.exited():
            core.send(signal.SIGCONT)
        self.command.send_signal(self.engine, signal.SIGTERM)
        end = time.monotonic() + self.cleanup_command.deadline.left(15)
        while self.engine.proc.poll() is None or self.engine.streams:
            # Drain with cleanup's deadline/budget without re-enabling original start().
            old = self.command.deadline
            deadlines = [(p, p.end) for p in self.command.children]
            try:
                self.command.deadline = self.cleanup_command.deadline
                for p, _ in deadlines:
                    p.end = end
                self.command.pump(.02)
            finally:
                self.command.deadline = old
                for p, previous in deadlines:
                    p.end = previous
            if time.monotonic() >= end:
                raise TimeoutError("engine/spawner did not exit before cleanup deadline")
        spawner = self.refs.get("spawner")
        if spawner and not spawner.exited():
            raise RuntimeError("spawner survived engine shutdown")
        if self.cb_measure is not None and not self.cb_measure.finished:
            self.cb_measure.finalize()
        if spawner:
            try:
                reaped, status = os.waitpid(spawner.initial["pid"], os.WNOHANG)
                if reaped and status != 0:
                    raise RuntimeError(f"spawner reported failed shutdown: wait status {status}")
            except ChildProcessError:
                pass

    def close(self):
        if self.cleanup_result is not None:
            return self.cleanup_result
        def stop():
            try:
                self.stop_engine()
                if self.evidence.exists():
                    self.evidence_bytes = read_beneath(self.scratch, self.evidence.name)
            finally:
                self.network.close()  # MUST release pinned fds even on stop failure
        self.cleanup_result = self.resources.cleanup(stop_engine=stop, cgroup=self.command.cgroup,
            command=self.cleanup_command, mountinfo=lambda: Path("/proc/self/mountinfo").read_text(),
            crash_check=self.crash_check)
        if self.cb_measure is not None:
            self.cb_measure.close()
        for ref in self.refs.values():
            ref.close()
        return self.cleanup_result

    def __enter__(self):
        return self.prepare()

    def __exit__(self, *_):
        result = self.close()
        if not result["ok"]:
            raise RuntimeError("deployment cleanup incomplete; retained objects: " + repr(result))
