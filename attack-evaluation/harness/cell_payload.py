"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from pathlib import Path
import struct
import sys

from common import identity, json_bytes, token
from deploy_seed import payload_manifest
from safeio import atomic_write, plain_path, read_owned

CELL = Path(__file__).absolute().parent / "cell"
CORE = ("runner.py", "nb_contract.py", "nb_io.py", "nb_process.py", "nb_wire.py", "nb_support.py",
        "nb_file_spec.py", "nb_file_diag.py", "nb_file_actions.py",
        "nb_conn_spec.py", "nb_conn_probe.py", "nb_conn_actions.py", "nb_conn_control.py",
        "nb_engine_spec.py", "nb_engine_probe.py", "nb_engine_actions.py", "nb_engine_question.py")


CORE += ("nb_fd.py", "nb_netlink.py", "nb_userns.py", "nb26_worker.py")


def static_probe(path):
    """Offline ELF64/x86_64 structural check; never execute the binary or ldd.

    A compiler/source receipt is still required by the authorized build controller.
    This check is not a substitute for actually compiling and testing the probe.
    """
    data = read_owned(path, 16 * 1024 * 1024)
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected little-endian ELF64")
    if struct.unpack_from("<HHI", data, 16) != (2, 62, 1):
        raise ValueError("expected static x86_64 executable")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, entsize, count = struct.unpack_from("<HHH", data, 52)
    if size != 64 or entsize != 56 or not 1 <= count <= 128 or offset < 64 or offset + count * 56 > len(data):
        raise ValueError("malformed ELF program table")
    types = []
    for i in range(count):
        kind, flags, start, _va, _pa, filesz, memsz, _align = struct.unpack_from("<IIQQQQQQ", data, offset + 56 * i)
        if start + filesz > len(data) or (kind == 1 and filesz > memsz):
            raise ValueError("ELF segment outside file")
        types.append(kind)
    if 1 not in types or 2 in types or 3 in types:
        raise ValueError("probe must be static, no PT_DYNAMIC/PT_INTERP")
    return identity(data)


def prepare_payload(cell_source: Path, compiled_probe: Path, modules: dict, output: Path, *, support_modules=(), unit='no-bypass'):
    """Only explicit reviewed modules; no globbing of no-bypass/scripts or /work.

    Copies selected bytes into an exclusive controller-owned staging directory,
    closing the manifest-versus-source race before deploy_seed computes identities.
    Empty modules is allowed for preparation but cannot run any attack. Production
    callers must pass immutable snapshots, not this checkout's live files.
    """
    cell_source, compiled_probe = plain_path(cell_source), plain_path(compiled_probe)
    if type(modules) is not dict or len(modules) > 128:
        raise ValueError("explicit bounded module map required")
    supports = set(support_modules)
    if supports - {'SUP-VICTIM', 'SUP-AUXILIARY'} or supports - set(modules):
        raise ValueError("unknown/unselected persistent support module")
    if set(modules).intersection({'SUP-VICTIM', 'SUP-AUXILIARY'}) != supports:
        raise ValueError("support requires explicit trusted lifecycle registration")
    from run_units import unit as selected_unit
    selected_unit(unit)
    core=CORE
    if unit=='credential-binding':
        core+=('cb_spec.py','cb_wire.py','cb_actions.py','cb_worker.py','cb_handshake.py','cb_install.py')
    selected = {name: read_owned(cell_source / name, 65536) for name in core}
    probe_identity = static_probe(compiled_probe)
    selected["nb_probe"] = read_owned(compiled_probe, 16 * 1024 * 1024)
    if identity(selected["nb_probe"]) != probe_identity:
        raise ValueError("probe changed while reading")
    registry = {"v": 1, "modules": {}}
    for attack, source in sorted(modules.items()):
        token(attack)
        data = read_owned(plain_path(source), 65536)
        compile(data, str(source), "exec")  # parse only; never import/execute a module
        name = "modules/" + attack + ".py"
        selected[name] = data
        registry["modules"][attack] = {"path": name, "sha256": identity(data)["sha256"]}
        if attack in supports:
            registry["modules"][attack]["lifetime"] = 540
    selected["modules.json"] = json_bytes(registry)
    output = plain_path(output, missing_leaf=True)
    output.mkdir(mode=0o755)
    result = {}
    for name, data in selected.items():
        path = output / name
        path.parent.mkdir(mode=0o755, exist_ok=True)
        atomic_write(path, data)
        path.chmod(0o555 if name == "nb_probe" else 0o444)
        result[name] = path
    payload_manifest(result)  # exactly the mapping accepted by Deployment
    return result


def compile_argv(source: Path, output: Path):
    """Plan only. Later run through AS_BUILDER + Commands in the run cgroup.
    It returns argv and performs no compilation, process launch or filesystem write.
    """
    source = plain_path(source)
    output = plain_path(output, missing_leaf=True)
    if output.exists():
        raise FileExistsError(output)
    return ["/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-no-pie",
            "-o", str(output), str(source / "nb_probe.c")]
