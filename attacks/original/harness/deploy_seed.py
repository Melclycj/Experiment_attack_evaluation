"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import digest, identity, json_bytes
from safeio import atomic_write, plain_path, read_owned, relative_parts

PRODUCTS = ("w2-cell", "libw2sandbox.so", "w2-relay", "w2-frontend-stub", "w2-catalog")
FILE_LIMIT = 64 * 1024 * 1024


def payload_manifest(payload: dict[str, Path]) -> dict:
    """Explicit payload only: 3d supplies these files; never substitute an engine fixture."""
    if not {"runner.py", "nb_probe"} <= payload.keys():
        raise ValueError("3d payload requires runner.py and compiled nb_probe")
    if len(payload) > 256:
        raise ValueError("too many payload files")
    result = {}
    for rel, path in sorted(payload.items()):
        relative_parts(rel)
        path = plain_path(path)
        data = read_owned(path, FILE_LIMIT)
        if not data:
            raise ValueError("empty payload")
        if rel == "nb_probe" and not data.startswith(b"\x7fELF"):
            raise ValueError("nb_probe must be a compiled Linux ELF")
        result[rel] = {"source": str(path), "identity": identity(data),
                       "executable": rel == "nb_probe" or bool(path.stat().st_mode & 0o111)}
    return result


def load_seed_class(source: Path):
    """Load the snapshotted production Seed unchanged, including its policy input."""
    spec = importlib.util.spec_from_file_location("nb_production_gate_seed", source / "checks/gate_seed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Seed, module.STDLIB_SKIP


def assemble_seed(source: Path, build: Path, root: Path, payload: dict) -> dict:
    """ONLY in a Commands child. Seed.libraries and every ldd descendant inherit
    that child's cgroup, hard deadline and parent kill-on-failure supervision.
    No gate build_seed(), downloads, diagnostic whitelist or version execution.
    """
    Seed, skip = load_seed_class(source)
    s = Seed(root / "seed")
    for product in ("w2-relay", "w2-frontend-stub"):
        s.file(build / product, "bin/" + product)
    for origin, rel in (("/usr/bin/bash", "bin/bash"), ("/usr/bin/python3.12", "usr/bin/python3.12"),
                        ("/usr/bin/git", "usr/bin/git")):
        s.file(Path(origin), rel)
    s.link("bin/sh", "bash")
    s.tree(Path("/usr/lib/python3.12"), "usr/lib/python3.12", lambda n: n in skip)
    s.tree(Path("/usr/share/git-core/templates"), "usr/share/git-core/templates", lambda n: False)
    if not {"runner.py", "nb_probe"} <= payload.keys():
        raise ValueError("missing runtime payload")
    for rel, item in sorted(payload.items()):
        relative_parts(rel)
        data = read_owned(Path(item["source"]), FILE_LIMIT)
        if identity(data) != item["identity"]:
            raise ValueError("payload changed after validation")
        target = "nb/" + rel
        s.file(None, target, data)
        mode = 0o555 if item["executable"] else 0o444
        (s.root / target).chmod(mode)
        s.entries[target]["mode"] = mode
    # The *whole* assembly, including this stock dependency scanner, runs in the
    # run cgroup. Its subprocess calls are never invoked from the controller.
    added = s.libraries()
    if s.missing:
        raise RuntimeError("unresolved seed libraries: " + ",".join(sorted(s.missing)))
    lock = {"v": 1, "libraries": sorted(added), "inputs": s.manifest()}
    s.file(None, "dependency-lock.json", json_bytes(lock))
    manifest = s.manifest()
    atomic_write(root / "components.json", json_bytes(manifest))
    receipt = {"components_digest": digest(manifest), "dependency_digest": digest(lock),
               "entries": len(manifest["files"])}
    atomic_write(root / "seed-receipt.json", json_bytes(receipt))
    return receipt


def main(argv):
    if len(argv) != 4 or os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("internal root/cgroup seed worker: SOURCE BUILD ROOT PAYLOAD_JSON")
    source, build, root, payload = map(Path, argv)
    assemble_seed(plain_path(source), plain_path(build), plain_path(root),
                  json.loads(read_owned(payload)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
