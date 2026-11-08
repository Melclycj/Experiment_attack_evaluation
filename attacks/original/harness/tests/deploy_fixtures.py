"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from build import capacity, inventory
from common import digest, identity, json_bytes
from deploy import Deployment
from deploy_seed import PRODUCTS
from net import QUESTION_HOST, UPSTREAM_HOST

ENGINE_SOURCE = Path(__file__).resolve().parents[6] / "ExperimentLab/engine-v3"  # registered baseline v4


def mini_seed(root):
    """Disposable file assembly input, NOT an engine implementation or a runnable probe."""
    seed = root / "seed"
    seed.mkdir()
    lock = {"fixture": "offline-only"}
    (seed / "dependency-lock.json").write_bytes(json_bytes(lock))
    data = json_bytes(lock)
    files = [{"path": "dependency-lock.json", "type": "file", "mode": 0o444,
              "size": len(data), "digest": digest(lock)}]
    manifest = {"v": 1, "files": files}
    (root / "components.json").write_bytes(json_bytes(manifest))
    (root / "seed-receipt.json").write_bytes(json_bytes({"components_digest": digest(manifest),
         "dependency_digest": digest(lock), "entries": len(files)}))
    return manifest


def mini_tls(root, count):
    (root / "ca-pool").mkdir()
    for i in range(count):
        entry = root / "ca-pool" / str(i)
        entry.mkdir()
        for name in ("ca.pem", "ca.key"):
            (entry / name).write_bytes(b"offline-mock-certificate")
    (root / "tls").mkdir()
    for name in ("ca.pem", "ca.key", "server.pem", "server.key"):
        (root / "tls" / name).write_bytes(b"offline-mock-certificate")


class FakeCommands:
    """No subprocess, socket or mount. Only fixture directories and dispatch traces."""
    def __init__(self, root, fail=None):
        self.root, self.fail = root, fail
        self.cgroup = Mock(created=True, path=Path("/sys/fs/cgroup/nb-decoy-fixture"))
        self.deadline = SimpleNamespace(left=lambda cap=600: min(cap, 20))
        self.calls, self.starts, self.inputs, self.closures = [], [], [], []
        self.children = []

    def __call__(self, argv, **kw):
        argv = list(map(str, argv))
        self.calls.append((argv, kw))
        text = " ".join(argv)
        if self.fail and self.fail in text:
            raise RuntimeError("fixture setup failure: " + self.fail)
        result = {"exit_code": 0, "stdout": "", "stderr": ""}
        if "deploy_seed.py" in text:
            mini_seed(Path(argv[-2]))
        elif "tls_material.py" in text:
            mini_tls(Path(argv[-2]), int(argv[-1]))
        elif "subvolume" in argv:
            Path(argv[-1]).mkdir()
        elif "filesystem" in argv:
            result["stdout"] = "uuid: 12345678-1234-1234-1234-123456789abc"
        elif argv[0].endswith("w2-catalog"):
            data = (Path(argv[1]) / "catalog.json").read_bytes()
            result["stdout"] = json.dumps({"catalog_digest": "sha256:" + identity(data)["sha256"],
                 "policies": [{"policy_id": "workload", "bpf_digest": digest("offline-bpf")}]})
        elif argv[-2:] == ["ws", "list"]:
            result["stdout"] = "workspace=work0 root=fixture state=ready entries=1\n"
        elif "start" in argv and "row" in argv:
            result["stdout"] = "execution=abcdef:1\n"
        elif argv[-2:] == ["row", "list"]:
            result["stdout"] = "(none)\n"
        return result

    def start(self, argv, **kwargs):
        if self.fail and self.fail in " ".join(map(str, argv)):
            raise RuntimeError("fixture start failure")
        self.starts.append((argv, kwargs))
        if any(Path(str(a)).parts[-2:] == ("bin", "engine") for a in argv):
            # The engine's E-09 record of the hook port accepting the PDP (engine/pdp.py), as deploy._pdp_ready reads it.
            with Path(argv[-1]).open("ab") as evidence:
                evidence.write(b'{"kind":"pdp_connected","outcome":"observed"}\n')
        child = SimpleNamespace(proc=Mock(pid=901), streams=0,
                                buffers={"stdout": bytearray(), "stderr": bytearray()}, end=99999)
        child.proc.poll.return_value = None
        self.children.append(child)
        return child

    def pump(self, seconds=0):
        pass

    def send_input(self, child, data, **kw):
        self.inputs.append(data)
        if data == b"allow-once\n":
            child.buffers["stdout"].extend(b"question 7 answered\n")

    def close_input(self, child):
        self.closures.append(child)
        child.proc.poll.return_value = 0

    def wait(self, child, **kwargs):
        return {"exit_code": 0}

    def send_signal(self, child, signum):
        child.proc.poll.return_value = -signum


def make_deployment(temp, fail=None):
    top = Path(temp)
    source, build, payload = (top / name for name in ("source", "build", "payload"))
    for path in (source, build, payload):
        path.mkdir()
    (source / "checks").mkdir()
    (source / "checks/workload-allow.txt").write_text("# fixture policy\nread\nwrite\nexit\n")
    for name in PRODUCTS:
        (build / name).write_bytes(b"offline-build-identity-" + name.encode())
    (payload / "runner.py").write_bytes(b"# offline payload fixture; not executed\n")
    # A valid x86-64 ELF header (e_machine 0x3e at offset 18): the stock Seed drops prebuilt binaries of another
    # architecture (gate_seed.py, 1b7efb82), and a real run compiles an x86-64 nb_probe.
    (payload / "nb_probe").write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00"
                                       b"offline-payload-fixture-not-executable")
    command = FakeCommands(top, fail)
    cleanup = FakeCommands(top)
    cleanup.cgroup = command.cgroup
    resources = Mock(roots={})
    network = Mock(command=command, resources=resources, prepared=True, closed=False, fds=[99])
    network.prepare.return_value = {"upstream": {"fd": 99}, "hostname": UPSTREAM_HOST}
    deployment = Deployment(source=source, source_identity=inventory(source), build=build,
        products={name: identity((build / name).read_bytes()) for name in PRODUCTS}, cap=capacity(4),
        payload={name: payload / name for name in ("runner.py", "nb_probe")}, command=command,
        resources=resources, network=network, cleanup_command=cleanup, crash_check=Mock(), label="fixture")
    deployment.root, deployment.scratch = top / "nb-decoy-deploy", top / "nb-decoy-scratch"
    deployment.storage = deployment.scratch / "workspaces"
    deployment.evidence = deployment.scratch / "nb-decoy-e09.jsonl"
    return deployment


_QUESTION_BODY = ("── question 7 ── row abcdef:1 ── workspace work2 ──\n"
                  "  matched      exact " + QUESTION_HOST + ":443\n"
                  "  method       POST\n  scheme       https\n  host         " + QUESTION_HOST
                  + "\n  port         443\n  path         /nb-request\n")
# The production client's prompt (engine-v2-go client/admin.py, 648d60f2 3.2) and the pre-648d60f2 one.
QUESTION = _QUESTION_BODY + ("answer question 7 [allow-once | deny-once | allow-always (allow, never ask on this cell "
                             "again) | deny-always (deny on this cell from now on) | show]: ")
OLD_QUESTION = _QUESTION_BODY + "answer question 7 [allow-once | allow-record | deny-once | deny-record | show]: "
