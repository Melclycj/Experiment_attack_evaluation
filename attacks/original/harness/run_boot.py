"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from build import inventory, snapshot
from common import MAX_OUTPUT, identity, json_bytes, run_name, utc
from env import mount_rows
from record import RunDirectory
from run_gate import check_history, claim, bind, verify as verify_gate
from run_baseline import ENGINE, ENGINE_PATHS
from run_units import unit
from safeio import atomic_write, plain_path, read_owned

HREL = Path('Thesis/Work/Submission/attack_evaluation/harness')
NREL = HREL.parent / 'no-bypass'
OUTER_RESERVE = 65536


def stage(args, cases, support_modules, deadline):
    """Only called past --start 开始. No compilation or deployment here."""
    if os.name != 'posix' or os.geteuid() != 0:
        raise RuntimeError('real batches require Linux/WSL root')
    engine_path = getattr(args, 'engine_path', ENGINE)
    if engine_path not in ENGINE_PATHS:
        raise ValueError('unsupported engine source path')
    run_id = run_name(args.label)
    selected = unit(getattr(args, 'unit', 'no-bypass'))
    # Both units check history by receipt (2.3: user 2026-11-03; 1.1: 2026-11-06, so the full archive check runs once
    # outside the batch clock instead of inside every batch). Any change to a run's deciding files re-verifies it.
    check_history(args.repo / selected.runs, receipts=True)
    lease = claim(args.repo, run_id)
    root = Path(tempfile.mkdtemp(prefix='nb-decoy-boot-', dir='/tmp'))
    root.chmod(0o755)
    info = root.stat()
    bundle = {'root': str(root), 'root_identity': [info.st_dev, info.st_ino],
              'repo': str(args.repo), 'engine_path': engine_path, 'label': root.name[len('nb-decoy-boot-'):],
              'run': run_id, 'deadline': deadline, 'cap': args.cap, 'gate': lease,
              'output': str(args.repo / selected.runs / run_id),
              'configs': args.configs, 'attacks': [c.attack for c in cases],
              'crash_directory': str(args.crash_directory), 'cgroup_parent': str(args.cgroup_parent),
              'cert_python': args.cert_python, 'started_at': utc(), 'authorized': '开始'}
    if selected.name != 'no-bypass':
        bundle['unit'] = selected.name
        bundle['targets'] = list(getattr(args,'target',()))
    if getattr(args, 'variant', None):
        bundle['variant'] = args.variant
    bind(bundle)  # Crash after here retains the exact root/output ownership record.
    try:
        bundle['harness_identity'] = snapshot(args.repo / HREL, root / 'harness', exclude=('tests', '__pycache__'))
        bundle['engine_identity'] = snapshot(args.repo / engine_path, root / 'engine')
        if bundle.get('variant'):
            if selected.name != 'credential-binding' or engine_path != ENGINE:
                raise ValueError('self-check patch is restricted to credential-binding on the registered engine')
            if bundle['variant'] == 'connection-ignore-account':
                from cb_keep_variant import patch_snapshot  # CB-14 条款 8 self-check
            else:
                from cb_variant import patch_snapshot       # CB-10 redirect self-check
            bundle['variant_provenance'] = patch_snapshot(root / 'engine',bundle['engine_identity'])
            bundle['engine_identity'] = bundle['variant_provenance']['patched']
        spec = read_owned(args.repo / selected.spec)
        atomic_write(root / 'tests.md', spec)
        bundle['spec_identity'] = identity(spec)
        (root / 'modules').mkdir(mode=0o755)
        mapping = {c.attack: c.module for c in cases}
        if set(mapping) & set(support_modules):
            raise ValueError('support and case IDs overlap')
        mapping.update(support_modules)
        bundle['modules'], bundle['support_modules'], bundle['script_identities'] = mapping, support_modules, {}
        for key, name in mapping.items():
            if Path(name).name != name or not name.endswith('.py'):
                raise ValueError('explicit module must be a flat Python filename')
            source = args.repo / selected.script(key, name)
            data = read_owned(source, 65536)
            compile(data, str(source), 'exec')
            dest = root / 'modules' / name
            if not dest.exists():
                atomic_write(dest, data); dest.chmod(0o444)
            elif read_owned(dest, 65536) != data:
                raise ValueError('conflicting module source')
            bundle['script_identities'][key] = identity(data)
        if time.monotonic() >= deadline - 60:
            raise TimeoutError('snapshot exhausted work budget')
        runs = args.repo / selected.runs
        if not runs.exists():
            runs.mkdir(mode=0o755)
        directory = RunDirectory(runs, bundle['run'], limit=MAX_OUTPUT - OUTER_RESERVE)
        bundle['output'] = str(directory.path)
        atomic_write(root / 'bundle.json', json_bytes(bundle))
        (root / 'bundle.json').chmod(0o444)
        return bundle
    except BaseException:
        discard(bundle)
        raise


def discard(bundle):
    root = plain_path(Path(bundle['root']))
    if root.parent != Path('/tmp') or not root.name.startswith('nb-decoy-boot-'):
        raise ValueError('snapshot cleanup scope mismatch')
    now = root.stat()
    if [now.st_dev, now.st_ino] != bundle['root_identity']:
        raise ValueError('snapshot identity changed')
    if any(r['target'] == str(root) or r['target'].startswith(str(root) + '/')
           for r in mount_rows(Path('/proc/self/mountinfo').read_text())):
        raise RuntimeError('snapshot contains a mount; retaining it')
    if not shutil.rmtree.avoids_symlink_attacks:
        raise RuntimeError('safe snapshot removal unavailable')
    shutil.rmtree(root)


def load_bundle(path):
    path = plain_path(path)
    root = path.parent
    data = json.loads(read_owned(path, 2 * 1024 * 1024))
    selected = unit(data.get('unit', 'no-bypass'))
    if selected.name != 'no-bypass' and (not data.get('repo') or not data.get('run') or
            Path(data.get('output', '')) != Path(data['repo']) / selected.runs / data['run']):
        raise ValueError('frozen output differs from evaluation unit')
    if data.get('engine_path') not in ENGINE_PATHS:
        raise ValueError('unsupported frozen engine source path')
    if path.name != 'bundle.json' or Path(data['root']) != root or data.get('authorized') != '开始':
        raise ValueError('invalid frozen launch context')
    if root.parent != Path('/tmp') or not root.name.startswith('nb-decoy-boot-'):
        raise ValueError('not a native Linux snapshot')
    info = root.stat()
    if info.st_uid != 0 or info.st_mode & 0o022 or [info.st_dev, info.st_ino] != data['root_identity']:
        raise ValueError('snapshot ownership/identity changed')
    if inventory(root / 'harness', ('tests', '__pycache__')) != data['harness_identity']:
        raise ValueError('frozen harness changed')
    if inventory(root / 'engine') != data['engine_identity']:
        raise ValueError('frozen engine changed')
    if identity(read_owned(root / 'tests.md')) != data['spec_identity']:
        raise ValueError('frozen spec changed')
    for key, name in data['modules'].items():
        if identity(read_owned(root / 'modules' / name, 65536)) != data['script_identities'][key]:
            raise ValueError('frozen module changed')
    verify_gate(data)
    return data


def run_frozen(bundle):
    path = Path(bundle['root']) / 'bundle.json'
    command = ['/usr/bin/python3', '-I', '-B', str(path.parent / 'harness/run.py'), '--frozen', str(path)]
    if time.monotonic() >= bundle['deadline'] - 60:
        raise TimeoutError('bootstrap exhausted work deadline')
    # Replace bootstrap rather than create an unmonitored launcher grandchild.
    # Frozen branch owns snapshot cleanup. The unshare watchdog stays alive.
    os.execve(command[0], command, {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'})
    raise RuntimeError('exec unexpectedly returned')


def failure_marker(bundle, error):
    # COMPLETE alone does not override a forced bootstrap/outer-cleanup failure.
    path = Path(bundle['output'])
    data = json_bytes({'cleanup_verified': False, 'error': str(error)[:2048]})
    if sum(p.stat().st_size for p in path.iterdir()) + len(data) > MAX_OUTPUT:
        raise RuntimeError('outer failure evidence exceeds reserved budget')
    atomic_write(path / 'LAUNCHER-FAILED.json', data)
