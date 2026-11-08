"""Engine integration (build steps 1–3): real engine (Python, uid 1000) ↔ real spawner, disposable deployment.

Run as root inside a private mount namespace:
  unshare --mount --propagation private python3 checks/run_engine_checks.py --run-dir ../runs/<dir> --label <l>
Only newly created images are formatted; every mount, loop device and deployment file belongs to this run.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
from typing import Any

ENGINE = Path(__file__).resolve().parents[1]
NATIVE = ENGINE / 'native'
REPO = ENGINE.parents[1]
DESIGN = REPO / 'ExperimentLab/lab/experiments/w2/implementation/engine-design'
sys.path.insert(0, str(NATIVE / 'checks'))
from run_sandbox_checks import OWNER_ID, PDP_ID, TREE, check_report, deployment, digest, save_json  # noqa: E402
from gate_seed import MCP_SEED, WORKLOAD_ALLOW, mcp_build  # noqa: E402
from file_read_cases import check_mcp, host_files, kill_worker_when_running, real_mcp, write_requests  # noqa: E402

SPAWNER_CAPS = ['/usr/bin/setpriv', '--bounding-set=-all,+sys_admin,+setuid,+setgid,+setpcap,+net_admin,+kill,+chown',
                '--inh-caps=-all', '--ambient-caps=-all']
AS_USER = ['/usr/bin/setpriv', '--reuid=1000', '--regid=1000', '--clear-groups', '--bounding-set=-all',
           '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']
PYTHON = ['/usr/bin/python3', '-I', '-B']
# P-02: the run's simple PDP denies a row registered with this policy context and answers every other row as usual
DENY_CONTEXT = 'engine-checks-deny'
# (scenario, fault, argument, production build, spawner left for the supervisor)
CASES = [
    ('normal', '', '', False, False),
    ('parallel', '', '', False, False),
    ('close-preparing', '', '', False, False),
    ('startup-fault', 'validate', 'stage=validate', False, False),
    ('startup-fault', 'clone', 'stage=clone', False, False),
    ('startup-fault', 'uid.reread', 'stage=uid', False, False),
    ('startup-fault', 'policy', 'stage=policy', False, False),
    ('startup-fault', 'handoff', 'stage=handoff', False, False),
    ('startup-fault', 'exec', 'post-commit', False, False),
    ('kill-error', 'kill', '', False, True),
    ('kill-no-fact', 'kill.no-effect', '', False, True),
    ('control-loss', 'reap.echild', 'linger-0', False, True),
    ('control-loss', 'worker.exit', '', False, True),
    ('normal', '', '', True, False),
] + [('agent-fault', '', mode, False, False) for mode in
     ('partial', 'oversize', 'rights', 'oob', 'fork-sender')] + [
    ('proxy', '', '', False, False),      # block 4: the real connector (bin/connector) instead of the stub for this case
    ('transfer-proxy', '', '', False, False),   # S-24: the same request from a transfer row, refused before the PDP
    ('context-proxy', '', DENY_CONTEXT, False, False),  # P-02: the PDP denies by the row's context, and only by it
    # 2.3c: H-17 on the whole machine (the runner kills the running real file worker); then the end-to-end read through
    # the real MCP server and worker (H-23, H-24), its argument the registered directory, set when the run makes it.
    # Both after the proxy cases, which expect work0 to have no object.
    ('worker-kill', '', '', False, False),
    ('mcp', '', '', False, False),
]
INPUTS = ['engine/**/*.py', 'connector/*.py', 'fileworker/*.py', 'pdp/*.py', 'bin/*', 'tests/*.py', 'checks/*.py', 'native/Makefile', 'native/sandbox/*',
          'native/checks/*', 'frontend-go/*.go', 'frontend-go/go.mod', 'mcp-go/*.go', 'mcp-go/go.mod',
          'checks/workload-allow.txt', 'README.md', 'validation.md']
AGENT_MODES = ('basic', 'partial', 'oversize', 'rights', 'oob', 'fork-sender', 'proxy', 'mcp')


# D-13 as deployed: run as one uid against one record file; what it may do with the file and its directory.
ACCESS_PROBE = '''
import json, os, sys
out = {}
for name, action in (('list', lambda: os.listdir(os.path.dirname(sys.argv[1]))),
                     ('read', lambda: os.close(os.open(sys.argv[1], os.O_RDONLY))),
                     ('append', lambda: os.close(os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND)))):
    try:
        action()
        out[name] = 0
    except OSError as error:
        out[name] = error.errno
print(json.dumps(out))
'''
RECORD_ACCESS = {'pdp': {'list': 0, 'read': 0, 'append': errno.EACCES},
                 'pool': {'list': errno.EACCES, 'read': errno.EACCES, 'append': errno.EACCES}}


def record_access(records: list[Path], command) -> dict[str, Any]:
    """The record directory and files as the deployment made them (D-13; user 2026-11-01: the PDP reads its history
    there): owner, group and mode, and what the PDP's uid and a pool uid may do. ok: directory 0750 and files 0640, all
    the engine uid's and the PDP's group; the PDP lists and reads but cannot append; the pool uid gets nothing."""
    shape = {p.name: {'uid': st.st_uid, 'gid': st.st_gid, 'mode': oct(st.st_mode & 0o7777)}
             for p in (records[0].parent, *records) for st in (p.stat(),)}
    tried = {who: json.loads(command(['/usr/bin/setpriv', f'--reuid={uid}', f'--regid={uid}', '--clear-groups',
                                      '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                                      '--no-new-privs', *PYTHON, '-c', ACCESS_PROBE, records[0]])['stdout'])
             for who, uid in (('pdp', PDP_ID), ('pool', 70000))}
    expected = {records[0].parent.name: {'uid': 1000, 'gid': PDP_ID, 'mode': '0o750'},
                **{p.name: {'uid': 1000, 'gid': PDP_ID, 'mode': '0o640'} for p in records}}
    return {'shape': shape, 'tried': tried, 'ok': shape == expected and tried == RECORD_ACCESS}


def answer_note(reply_to: str) -> str:
    """The engine's answer to any well-formed control message, as the fixture logs it (validation.md K-04)."""
    return 'frame={"v":2,"type":"error","reply_to":"%s","code":"unsupported_kind"}' % reply_to



DOC_TEXT = 'grüße, ✓ engine-local document line\n' * 600     # ≈ 22 KB, multi-byte, several chunks
OTHER_TEXT = 'the other document\n'
STUB_TEXT = 'stub reply'


def add_agent_plans(root: Path) -> None:
    """Fixture "agent <mode>" runtimes and plans, each a copy of the deployment's observe runtime and plan
    with only runtime_id, argv and the plan's runtime reference changed."""
    catalog = json.loads((root / 'catalog.json').read_text())
    observe = json.loads((root / 'observe.json').read_text())
    # 2.3c (validation.md H-23): the mcp plan runs under the deployment's workload policy (checks/workload-allow.txt,
    # the gate's), so the real MCP server is seen to start under the list a deployment has, not the diagnostic one
    workload = save_json(root / 'workload-policy.json', {'v': 1, 'target_arch': 'x86_64', 'default_action': 'errno',
                                                         'default_errno': 1, 'allow': WORKLOAD_ALLOW})
    catalog['policies'].append({'policy_id': 'workload', 'artifact_ref': 'workload-policy.json',
                                'artifact_digest': workload, 'target_arch': 'x86_64', 'format': 'w2-seccomp-json/1',
                                'compiler_identity': 'libseccomp-2.5.5'})
    for mode in AGENT_MODES:
        name = 'agent-' + mode
        rd = save_json(root / f'{name}.json',
                       dict(observe, runtime_id=name, argv=[observe['executable'], 'agent', mode]))
        catalog['runtimes'].append({'descriptor_ref': f'{name}.json', 'descriptor_digest': rd,
                                    'seed_ref': 'seed', 'dependency_lock_ref': 'dependency-lock.json'})
        for i in ((0, 1) if mode == 'basic' else (0,)):
            template = json.loads((root / f'plan-observe-{i}.json').read_text())
            plan = dict(template, launch_plan_id=f'{name}-{i}', runtime_id=name, runtime_descriptor_digest=rd)
            if mode == 'mcp':
                plan.update(policy_id='workload', policy_digest=workload)
            ref = f'plan-{name}-{i}.json'
            catalog['plans'].append({'artifact_ref': ref, 'artifact_digest': save_json(root / ref, plan)})
    # S-24 in the integration: the proxy fixture again, under the reserved transfer runtime id, as work0's push plan
    rd = save_json(root / 'w2-transfer-push.json',
                   dict(observe, runtime_id='w2-transfer-push', argv=[observe['executable'], 'agent', 'proxy']))
    catalog['runtimes'].append({'descriptor_ref': 'w2-transfer-push.json', 'descriptor_digest': rd,
                                'seed_ref': 'seed', 'dependency_lock_ref': 'dependency-lock.json'})
    plan = dict(json.loads((root / 'plan-observe-0.json').read_text()), launch_plan_id='work0.push',
                runtime_id='w2-transfer-push', runtime_descriptor_digest=rd)
    catalog['plans'].append({'artifact_ref': 'plan-work0.push.json',
                             'artifact_digest': save_json(root / 'plan-work0.push.json', plan)})
    save_json(root / 'catalog.json', catalog)




def real_connector(root: Path, library: Path) -> None:
    """Block 4: point the deployment's connector entry at bin/connector (python3 -I -B, the connector uid, the library
    copied beside the catalog because the build directory is 0700). The stub stays for every other case."""
    shutil.copy(library, root / 'libw2sandbox.so')
    os.chmod(root / 'libw2sandbox.so', 0o644)
    catalog = json.loads((root / 'catalog.json').read_text())
    catalog['connector'] = {'uid': catalog['connector']['uid'], 'gid': catalog['connector']['gid'],
                            'executable': PYTHON[0],
                            'argv': [*PYTHON, str(ENGINE / 'bin/connector'), '--library', str(root / 'libw2sandbox.so')]}
    # the real file worker beside it (validation.md H-14): started, dropped to its uid and serving the row's file port
    catalog['file_worker'] = {'uid': catalog['file_worker']['uid'], 'gid': catalog['file_worker']['gid'],
                              'executable': PYTHON[0],
                              'argv': [*PYTHON, str(ENGINE / 'bin/file-worker'), '--library',
                                       str(root / 'libw2sandbox.so')]}
    save_json(root / 'catalog.json', catalog)


def agent_frames(note: str) -> list[dict[str, Any]]:
    return [json.loads(line[len('frame='):]) for line in note.splitlines() if line.startswith('frame=')]


def replies(frames: list[dict[str, Any]], rid: str) -> list[dict[str, Any]]:
    return [f for f in frames if f.get('reply_to') == rid and f['type'] in ('chunk', 'result', 'error')]





def blob(path: Path) -> str:
    """git blob id of the on-disk bytes (first 16 hex), as BUILD-PLAN §2 cites them."""
    data = path.read_bytes()
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + bytes(1) + data).hexdigest()[:16]


# ---- two-epoch run (R-GX-04): the cell in one cgroup, released by a stand-in for the host-init supervisor ----------
def populated(cg: Path) -> int:
    return int(dict(line.split() for line in (cg / 'cgroup.events').read_text().splitlines())['populated'])


def release_gate(cg: Path, deadline_s: float = 10) -> list[str]:
    """Test stand-in for the deployment's release gate (conn E-04; engine-requirements row 218, a deployment item): it
    reads only the cell cgroup's cgroup.events, keeps no state, writes cgroup.kill if the cell is populated and
    releases only once populated reads 0. Never a self-report of the engine or spawner, never a /proc uid scan."""
    steps = [f'seen {populated(cg)}']
    if steps[0] == 'seen 1':
        (cg / 'cgroup.kill').write_text('1')
        steps.append('kill')
        until = time.monotonic() + deadline_s
        while populated(cg):
            assert time.monotonic() < until, 'gate: the cell never read populated 0'
            time.sleep(0.005)
        steps.append('seen 0')
    return steps + ['release']


def cell_tasks(cg: Path) -> list[dict[str, Any]]:
    """Members of the cell cgroup with their uid and state (an observation of this test, not used by the gate)."""
    out = []
    for pid in (cg / 'cgroup.procs').read_text().split():
        try:
            status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines())
        except FileNotFoundError:
            continue
        out.append({'pid': int(pid), 'name': status['Name'].strip(), 'uid': int(status['Uid'].split()[0]),
                    'state': status['State'].split()[0]})
    return out


def running(pid: int) -> bool:
    """True while the task exists and is not a zombie."""
    try:
        state = next(line for line in Path(f'/proc/{pid}/status').read_text().splitlines() if line.startswith('State:'))
    except FileNotFoundError:
        return False
    return state.split()[1] != 'Z'


def utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--runtime-mode', choices=('shared', 'copy', 'default'), default='shared',
                        help="the catalog's runtime_mode, written explicitly: shared (the default, S-23) or copy; "
                             "'default' leaves the key out to test the catalog's own default (S-23)")
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == 'Linux'
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER: this run supervises its descendants
    run = args.run_dir.resolve(strict=True)
    assert run.parent == ENGINE / 'runs' and args.label.replace('-', '').isalnum()
    record_path = run / f'{args.label}.json'
    assert not record_path.exists()
    pdp_proc = None
    for uid in (70000, 70001, 70002, 70998, 70996):    # the pool's test uids, the PDP's and the file worker's
        try:
            pwd.getpwuid(uid)
        except KeyError:
            continue
        raise RuntimeError(f'test uid {uid} is a host account')
    build = Path(tempfile.mkdtemp(prefix='engine-check-build-', dir='/tmp'))
    build.chmod(0o755)
    os.chown(build, 1000, 1000)
    root = Path('/var/lib') / ('engine-check-' + args.label)
    root.mkdir(mode=0o755)
    cell_cgroup = Path('/sys/fs/cgroup') / ('engine-check-' + args.label + '-cell')
    assert not cell_cgroup.exists()
    scratch = Path(tempfile.mkdtemp(prefix='engine-check-', dir='/tmp')).resolve()
    images = {name: scratch / f'{name}.btrfs' for name in ('runtime', 'workspace')}
    for image in images.values():
        with image.open('xb') as out:
            out.truncate(256 * 1024 * 1024)
    workspace_storage = scratch / 'workspaces'
    evidence_dir = Path(tempfile.mkdtemp(prefix='engine-evidence-', dir='/tmp'))
    # the records as the gate deploys them (D-13): the engine uid writes, the PDP's group reads, nobody else enters
    os.chown(evidence_dir, 1000, PDP_ID)
    os.chmod(evidence_dir, 0o750)

    def evidence_file(name: str) -> Path:
        path = evidence_dir / name
        path.touch(mode=0o640)
        os.chown(path, 1000, PDP_ID)
        os.chmod(path, 0o640)
        return path

    def evidence_events(path: Path) -> list[dict[str, Any]]:
        lines = path.read_text().splitlines() if path.exists() else []
        shutil.copyfile(path, run / f'{args.label}-{path.name}')
        return [json.loads(line) for line in lines]

    def diagnostic(events_: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
        return next((e['detail'] for e in events_ if e['kind'] == 'diagnostic' and e['name'] == name), None)
    workspace_storage.mkdir()
    record: dict[str, Any] = {
        'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'engine build steps 1-3 (launch, reclaim, receive pipeline, phase rules, request admission, '
                 'authorization, dispatch to the document handler and the model stub connector, E-09 records) '
                 'against the real spawner; agent is the native fixture; no real model connector or runtime',
        'kernel': platform.release(), 'commands': [], 'cases': [], 'result': 'not-run',
        'design_blobs': {p: blob(DESIGN / p) for p in ('connections.md', 'resources-routing.md',
                                                        'supporting-interfaces.md')}}
    sources = sorted({p for pattern in INPUTS for p in ENGINE.glob(pattern) if p.is_file()})
    record['inputs'] = [{'path': p.relative_to(REPO).as_posix(), 'digest': digest(p)} for p in sources]
    with tarfile.open(run / f'{args.label}-inputs.tar', 'x') as out:
        for p in sources:
            out.add(p, arcname=p.relative_to(REPO).as_posix(), recursive=False)

    def command(argv: list[Any], *, timeout: float = 60, fault: str = '', allowed=(0,)) -> dict[str, Any]:
        env = dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C.UTF-8', W2_TEST_FAULT=fault)
        started = time.monotonic()
        p = subprocess.run([str(v) for v in argv], env=env, capture_output=True, text=True, timeout=timeout)
        item = {'argv': [str(v) for v in argv], 'fault': fault, 'exit_code': p.returncode, 'stdout': p.stdout,
                'stderr': p.stderr, 'elapsed_seconds': round(time.monotonic() - started, 3)}
        record['commands'].append(item)
        print(json.dumps({'command': len(record['commands']) - 1, 'exit_code': p.returncode, 'fault': fault,
                          'last_arg': str(argv[-1])}), flush=True)
        if p.returncode not in allowed:
            raise RuntimeError('command failed: ' + json.dumps(item)[:4000])
        return item

    def events(stdout: str) -> list[dict[str, Any]]:
        return [json.loads(line) for line in stdout.splitlines() if line.startswith('{"event"')]

    def own_children() -> list[int]:
        """This run's direct children, the simple PDP left out: it lives for the whole run (P-01)."""
        return [int(p) for p in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()
                if pdp_proc is None or int(p) != pdp_proc.pid]

    def supervise(case: dict[str, Any], recover: bool) -> None:
        """Kill and reap what the spawner left behind; record it. Then clear the store if asked."""
        adopted, until = [], time.monotonic() + 10
        while True:
            children = own_children()
            if not children:
                break
            assert time.monotonic() < until, 'supervisor reap deadline'
            for pid in children:
                try:
                    status = Path(f'/proc/{pid}/status').read_text()
                    uid = next(line.split()[1] for line in status.splitlines() if line.startswith('Uid:'))
                    name = next(line.split(None, 1)[1].strip() for line in status.splitlines() if line.startswith('Name:'))
                    os.kill(pid, signal.SIGKILL)
                except (FileNotFoundError, ProcessLookupError):
                    uid = name = None
                got, wait_status = os.waitpid(pid, os.WNOHANG)
                if got:
                    adopted.append({'pid': got, 'uid': uid, 'name': name, 'wait_status': wait_status})
            time.sleep(0.02)
        case['supervisor_reaped'] = adopted
        if recover:
            case['supervisor_recovery'] = command(
                SPAWNER_CAPS + [build / 'w2-recover', root, 'catalog.json',
                                '--supervisor-confirmed-old-domain-empty'])['stdout']

    mounted: list[Path] = []
    workspace_binds: list[Path] = []
    mcp_top: Path | None = None
    try:
        command(AS_USER + ['/usr/bin/make', '-s', '-C', NATIVE, 'sandbox', 'BUILD_DIR=' + str(build)], timeout=120)
        record['build_artifacts'] = []
        for name in ('w2-cell', 'w2-cell-test', 'w2-recover', 'libw2sandbox.so', 'agent-fixture'):
            destination = run / f'{args.label}-{name}'
            shutil.copyfile(build / name, destination)
            record['build_artifacts'].append({'path': destination.name, 'digest': digest(destination)})
        # 2.3c (validation.md H-23): the real MCP server, built as the gate builds it, into the seed at mcp/engine-mcp;
        # its digest is recorded, the 6 MiB binary is not copied here
        mcp_binary = mcp_build(build, command, AS_USER, pwd.getpwuid(1000).pw_dir)
        record['mcp_binary'] = {'seed_path': MCP_SEED, 'digest': digest(mcp_binary), 'size': mcp_binary.stat().st_size}
        library = build / 'libw2sandbox.so'
        # Unit suite as uid 1000 against this very build.
        unit = command(AS_USER + ['/usr/bin/env', f'HOME={pwd.getpwuid(1000).pw_dir}',  # user-site pytest
                                  f'ENGINE_TEST_LIB={library}', 'PYTHONDONTWRITEBYTECODE=1',
                                  '/usr/bin/python3', '-m', 'pytest', '-p', 'no:cacheprovider', '-q',
                                  ENGINE / 'tests'], timeout=300)
        record['unit_summary'] = unit['stdout'].strip().splitlines()[-1]
        # Senders at chosen uids (0, the overflow uid, other pool uids) need root; same build.
        root_unit = command(['/usr/bin/env', f'HOME={pwd.getpwuid(1000).pw_dir}', f'ENGINE_TEST_LIB={library}',
                             'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3', '-m', 'pytest', '-p',
                             'no:cacheprovider', '-q', '-rs', f'--basetemp={scratch}/root-tests',
                             ENGINE / 'tests/test_receive_root.py', ENGINE / 'tests/test_connector_root.py',
                             ENGINE / 'tests/test_fileworker_root.py', ENGINE / 'tests/test_fileport_root.py',
                             ENGINE / 'tests/test_pdp_root.py', ENGINE / 'tests/test_client_workspace_root.py',
                             ENGINE / 'tests/test_connector_named_root.py'], timeout=180)
        record['root_unit_summary'] = root_unit['stdout'].strip().splitlines()[-1]
        assert 'skipped' not in record['root_unit_summary'], record['root_unit_summary']
        command(['/usr/sbin/mkfs.btrfs', '-q', images['runtime']])
        command(['/usr/bin/mount', '-o', 'loop,nosuid,nodev', images['runtime'], root])
        mounted.append(root)
        command(['/usr/sbin/mkfs.btrfs', '-q', images['workspace']])
        command(['/usr/bin/mount', '-o', 'loop,nosuid,nodev', images['workspace'], workspace_storage])
        mounted.append(workspace_storage)
        deployment(root, build, command, workspace_storage, workspace_binds,
                   runtime_mode=None if args.runtime_mode == 'default' else args.runtime_mode,
                   extra_seed={MCP_SEED: mcp_binary})
        add_agent_plans(root)
        mcp_top = Path(tempfile.mkdtemp(prefix='engine-mcp-', dir='/tmp'))
        files = host_files(mcp_top)
        record['mcp_host_files'] = {'notes': files['notes'], 'sizes': {p.name: p.lstat().st_size for p in
                                                                      (mcp_top / 'notes/notes.txt', mcp_top / 'outside.txt')}}
        # S-23: what a row's /runtime must show, the seed itself when shared (written or by default), else a copy of it
        record['seed_inodes'] = {name: {'device': (root / 'seed' / name).lstat().st_dev,
                                        'inode': (root / 'seed' / name).lstat().st_ino}
                                 for name in ('bin', 'bin/agent-fixture', 'link')}
        # the simple PDP (P-01), as the PDP's dedicated uid; it reconnects to each engine the cases start. Its test
        # variant denies by one policy context (P-02); rows without that context get the plain answer.
        pdp_log = (run / f'{args.label}-pdp.log').open('xb')
        pdp_proc = subprocess.Popen(['/usr/bin/setpriv', f'--reuid={PDP_ID}', f'--regid={PDP_ID}', '--clear-groups',
                                     '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
                                     *PYTHON, str(ENGINE / 'bin/simple-pdp'), '--deny-context', DENY_CONTEXT,
                                     str(root / 'hook/pdp.sock')],
                                    stdout=pdp_log, stderr=subprocess.STDOUT)
        with tarfile.open(run / f'{args.label}-deployment.tar', 'x') as out:
            for p in sorted(root.glob('*.json')):
                out.add(p, arcname=p.name, recursive=False)

        for number, (scenario, fault, argument, production, leftover) in enumerate(CASES):
            for work in ('work0', 'work1', 'work2'):
                for name in ('report.txt', 'linger.txt', 'persistent', 'agent.txt', 'mcp-request.txt'):
                    (root / work / TREE / name).unlink(missing_ok=True)
            if scenario == 'mcp':                  # the registered directory, and what the fixture is to POST
                argument = files['notes']
                write_requests(root / 'work0' / TREE / 'mcp-request.txt', argument, OWNER_ID)
            cell = build / ('w2-cell' if production else 'w2-cell-test')
            evidence = evidence_file(f'case{number:02d}-events.jsonl')
            argv = SPAWNER_CAPS + [cell, root, 'catalog.json', '1000', '1000', *PYTHON,
                                   ENGINE / 'bin/engine-scenario', library, root, 'catalog.json',
                                   evidence, scenario]
            if argument:
                argv.append(argument)
            stub_catalog = (root / 'catalog.json').read_text()
            if scenario in ('proxy', 'transfer-proxy', 'context-proxy', 'worker-kill', 'mcp'):
                real_connector(root, library)
            if scenario == 'mcp':
                real_mcp(root)
            killed: dict[str, Any] = {}
            killer = None
            if scenario == 'worker-kill':
                killer = threading.Thread(target=kill_worker_when_running, daemon=True,
                                          args=(root / 'work0' / TREE / 'agent.txt', killed))
                killer.start()
            try:
                item = command(argv, fault=fault, timeout=120, allowed=(0, 1))
            finally:
                (root / 'catalog.json').write_text(stub_catalog)
                if killer is not None:
                    killer.join(70)
            trace = events(item['stdout'])
            result = next((e for e in trace if e['event'] == 'scenario_result'), {'result': 'missing'})
            recorded = evidence_events(evidence)
            case = {'scenario': scenario, 'fault': fault, 'argument': argument, 'production_build': production,
                    'command': len(record['commands']) - 1, 'result': result['result'],
                    'checks': result.get('checks'), 'spawner_exit': result.get('spawner_exit'),
                    'error': result.get('error'), 'receipt': result.get('receipt'),
                    'evidence': f'{args.label}-{evidence.name}', 'events': len(recorded),
                    'startup': diagnostic(recorded, 'startup_checked')}
            # The receipt covers every event, and the file holds exactly what the receipt names.
            assert result.get('receipt', {}).get('evidence_complete') is True, result.get('receipt')
            assert [e['producer_seq'] for e in recorded] == [str(i) for i in range(1, len(recorded) + 1)]
            assert result['receipt']['last_durable_seq'] == str(len(recorded))
            assert all('event_id' in e and (e['kind'] == 'diagnostic' or isinstance(e.get('source_ref'), dict))
                       for e in recorded), 'an E-09 event without event_id or source_ref'
            # Post-exec evidence: the report the fixture writes only after execve (checked as in the
            # sandbox regression), independent of channel readability.
            case['reports'] = {w: (root / w / TREE / 'report.txt').read_text() for w in ('work0', 'work1', 'work2')
                               if (root / w / TREE / 'report.txt').exists()}
            # v2 (agent-rm-model 3.1): the uid is leased per execution from the reserved range in launch order, not
            # bound to the workspace; each report names its own uid, inside the range, and no two share one.
            leased = []
            for w, report in case['reports'].items():
                marker = re.search(r'^EXEC_MARKER pid=1 uid=(\d+) gid=(\d+)$', report, re.M)
                assert marker and marker.group(1) == marker.group(2) and 70000 <= int(marker.group(1)) <= 70015, (w, report[:200])
                leased.append(int(marker.group(1)))
                check_report(report, leased[-1])
            assert len(set(leased)) == len(leased), leased
            case['leased_uids'] = dict(zip(case['reports'], leased))
            # S-23: under shared placement, written or the catalog's default, every row's /runtime is the seed itself
            # (same device and inode); under copy, a copy on the same file system (same device, another inode)
            for w, report in case['reports'].items():
                for name, seed in record['seed_inodes'].items():
                    seen = re.search(rf'^runtime\.{re.escape(name)} dev=(\d+) inode=(\d+)\b', report, re.M)
                    assert seen and int(seen[1]) == seed['device'] and \
                        (int(seen[2]) == seed['inode']) == (args.runtime_mode != 'copy'), (w, name, seed, report[:200])
            case['runtime_is_seed'] = bool(case['reports']) and args.runtime_mode != 'copy'
            # What the fixture itself sent and received, written inside the sandbox.
            case['agent_notes'] = {w: (root / w / TREE / 'agent.txt').read_text() for w in ('work0', 'work1', 'work2')
                                   if (root / w / TREE / 'agent.txt').exists()}
            if killer is not None:
                case['killed'] = killed
            supervise(case, leftover)
            record['cases'].append(case)
            assert result['result'] == 'passed' and item['exit_code'] == 0, case
            if scenario == 'worker-kill':
                # H-17: the process the runner killed is the row's worker as the core knows it
                assert killed.get('pid') == result['checks']['worker_pid'], (killed, result['checks'])
            if scenario == 'mcp':
                # H-23, H-24 from the agent's side; H-20: neither marker string is in the records of this case
                case['mcp'] = check_mcp(case['agent_notes'].get('work0', ''), argument, files['markers'])
                records = (run / case['evidence']).read_text()
                case['markers_in_records'] = [k for k, m in files['markers'].items() if m in records]
                assert not case['markers_in_records'], case['markers_in_records']
            # The fixture's own record of the engine's answers: one per message it sent on the control channel.
            answered = {'normal': {'work0': ['1']}, 'parallel': {'work0': ['1'], 'work1': ['1']},
                        'worker-kill': {'work0': ['1']}}.get(scenario, {})
            if scenario == 'agent-fault' and argument == 'fork-sender':
                answered = {'work0': ['1', '2']}
            if scenario == 'proxy':
                # the fixture's own account of the proxy exchange: the request went out on the row's path and came back
                # as a refusal (category 2) with an error body and an end frame (validation.md C-24, C-32)
                note = case['agent_notes'].get('work0', '')
                assert 'proxy=sent' in note and 'proxy=head category=2 status=0' in note and 'proxy=end' in note, note
                assert 'proxy=chunk' in note and 'proxy=eof' not in note, note
            if scenario in ('proxy', 'transfer-proxy', 'context-proxy'):
                # 2.3b (validation.md H-04, H-05, H-06): the fixture's FILE_LIST_OBJECTS on /run/w2/file.sock came back
                # through the row's real file worker as FILE_OBJECTS with the empty list (no object is registered)
                note = case['agent_notes'].get('work0', '')
                assert 'file=reply 00 00 00 09 74 00 00 00 04 00 00 00 00\n' in note, note
            if scenario in ('transfer-proxy', 'context-proxy'):
                # S-24, P-02: the fixture's request (for context-proxy, its last row's, the one the PDP denied) came back
                # refused (category 2) with a body and an end frame
                note = case['agent_notes'].get('work0', '')
                assert 'proxy=sent' in note and 'proxy=head category=2 status=0' in note and 'proxy=end' in note, note
            if argument == 'rights':
                sent = re.search(r'sent=request\+rights rc=(-?\d+) ', case['agent_notes']['work0'])
                assert sent and int(sent.group(1)) > 0, 'the fd-carrying frame was not sent'
            if argument == 'oob':
                assert 'sent=oob rc=1 ' in case['agent_notes']['work0'], 'the out-of-band byte was not sent'
            for w, ids in answered.items():
                for rid in ids:
                    assert answer_note(rid) in case['agent_notes'].get(w, ''), ('no answer at the agent', w, rid)
            expected = {'normal': {'work0'}, 'parallel': {'work0', 'work1'}, 'proxy': {'work0'},
                        'transfer-proxy': {'work0'}, 'context-proxy': {'work0'}, 'worker-kill': {'work0'}}.get(scenario, set())
            assert expected <= set(case['reports']), ('no post-exec report', case['reports'].keys())
            if scenario == 'normal':
                # Each exec creates /work/persistent with O_EXCL and reports whether it already existed;
                # the final report says 1 only if the first exec made it and the second exec wrote the report.
                assert 'persistent_existed=1' in case['reports']['work0'], 'one of the two executions did not exec'
            if not leftover:
                assert case['spawner_exit'] == 0 and not case['supervisor_reaped'], case

        # Two-epoch run (R-GX-04): agent A alive in the cell's cgroup when spawner 1 is SIGKILLed; engine 2 on the same
        # pool starts only after the stand-in gate read populated 0.
        cell_cgroup.mkdir()
        two: dict[str, Any] = {'scenario': 'two-epoch', 'cgroup': str(cell_cgroup), 'timeline': []}
        record['cases'].append(two)

        def mark(what: str, **detail: Any) -> None:
            two['timeline'].append({'at_utc': utc(), 'what': what, **detail})

        def start_in_cell(scenario: str, evidence: Path) -> subprocess.Popen:
            for work in ('work0', 'work1', 'work2'):
                for name in ('report.txt', 'linger.txt', 'persistent', 'agent.txt'):
                    (root / work / TREE / name).unlink(missing_ok=True)
            argv = SPAWNER_CAPS + [build / 'w2-cell-test', root, 'catalog.json', '1000', '1000', *PYTHON,
                                   ENGINE / 'bin/engine-scenario', library, root, 'catalog.json',
                                   evidence, scenario]
            return subprocess.Popen([str(v) for v in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'},
                                    preexec_fn=lambda: (cell_cgroup / 'cgroup.procs').write_text('0'))

        def finish_epoch(proc: subprocess.Popen, evidence: Path, name: str) -> dict[str, Any]:
            stdout, stderr = proc.communicate(timeout=120)
            result = next((e for e in events(stdout) if e['event'] == 'scenario_result'), {'result': 'missing'})
            recorded = evidence_events(evidence)
            assert result.get('receipt', {}).get('evidence_complete') is True, result.get('receipt')
            assert [e['producer_seq'] for e in recorded] == [str(i) for i in range(1, len(recorded) + 1)]
            epoch = {'exit_code': proc.returncode, 'result': result['result'], 'checks': result.get('checks'),
                     'error': result.get('error'), 'spawner_exit': result.get('spawner_exit'),
                     'evidence': f'{args.label}-{evidence.name}', 'events': len(recorded), 'stderr': stderr[-4000:]}
            two[name] = epoch
            return epoch

        evidence_1 = evidence_file('two-epoch-1-events.jsonl')
        engine_1 = start_in_cell('two-epoch-first', evidence_1)
        mark('engine 1 started', pid=engine_1.pid)
        until = time.monotonic() + 30
        while not ('"message_received"' in evidence_1.read_text()
                   and len([t for t in cell_tasks(cell_cgroup) if t['uid'] == 70000]) >= 2):
            assert time.monotonic() < until and engine_1.poll() is None, 'agent A did not become active'
            time.sleep(0.05)
        spawner_1 = int(Path(f'/proc/{engine_1.pid}/task/{engine_1.pid}/children').read_text().split()[0])
        two['cell_before_kill'] = cell_tasks(cell_cgroup)
        a_tasks = [t['pid'] for t in two['cell_before_kill'] if t['uid'] == 70000]
        os.kill(spawner_1, signal.SIGKILL)
        mark('spawner 1 SIGKILLed', pid=spawner_1, a_tasks=a_tasks)
        first = finish_epoch(engine_1, evidence_1, 'epoch_1')
        mark('engine 1 exited', exit_code=engine_1.returncode)
        two['after_engine_1'] = {'populated': populated(cell_cgroup), 'cell': cell_tasks(cell_cgroup),
                                 'a_running': [pid for pid in a_tasks if running(pid)]}
        two['gate'] = release_gate(cell_cgroup)
        mark('gate released', steps=two['gate'])
        two['a_running_at_release'] = [pid for pid in a_tasks if running(pid)]
        reaped, until = [], time.monotonic() + 10       # the killed members were reparented to this run (subreaper)
        while own_children():
            assert time.monotonic() < until, 'reap of the killed cell members'
            got, wait_status = os.waitpid(-1, os.WNOHANG)
            if got:
                reaped.append({'pid': got, 'exit': os.waitstatus_to_exitcode(wait_status)})
            else:
                time.sleep(0.01)
        two['reaped_after_gate'] = reaped
        two['a_present_before_engine_2'] = [pid for pid in a_tasks if Path(f'/proc/{pid}').exists()]
        two['recovery'] = command(SPAWNER_CAPS + [build / 'w2-recover', root, 'catalog.json',
                                                  '--supervisor-confirmed-old-domain-empty'])['stdout']
        evidence_2 = evidence_file('two-epoch-2-events.jsonl')
        engine_2 = start_in_cell('two-epoch-second', evidence_2)
        mark('engine 2 started', pid=engine_2.pid)
        second = finish_epoch(engine_2, evidence_2, 'epoch_2')
        mark('engine 2 exited', exit_code=engine_2.returncode)
        two['reports'] = {w: (root / w / TREE / 'report.txt').read_text() for w in ('work0',)
                          if (root / w / TREE / 'report.txt').exists()}
        check_report(two['reports']['work0'], 70000)
        two['agent_notes'] = {'work0': (root / 'work0' / TREE / 'agent.txt').read_text()}
        supervise(two, False)
        two['populated_after_engine_2'] = populated(cell_cgroup)
        cell_cgroup.rmdir()
        assert first['result'] == 'passed' and first['exit_code'] == 0 and first['spawner_exit'] == -9, first
        assert two['after_engine_1']['populated'] == 1 and len(two['after_engine_1']['a_running']) >= 2, two
        assert two['gate'] == ['seen 1', 'kill', 'seen 0', 'release'], two['gate']
        assert not two['a_running_at_release'] and not two['a_present_before_engine_2'], two
        # A's PID 1 comes back to this run; its namespace's other tasks are reaped by the kernel when that init dies
        # (zap_pid_ns_processes), so for them only their absence is observable.
        a_reaped = [r for r in reaped if r['pid'] in a_tasks]
        assert a_reaped and all(r['exit'] == -signal.SIGKILL for r in a_reaped), reaped
        assert second['result'] == 'passed' and second['exit_code'] == 0 and second['spawner_exit'] == 0, second
        assert second['checks']['b']['uid'] == first['checks']['a']['uid'] == 70000, (first['checks'], second['checks'])
        assert answer_note('1') in two['agent_notes']['work0'] and not two['supervisor_reaped'], two
        assert two['populated_after_engine_2'] == 0

        # Production entry: start, self-check, control_ready, then terminated by this supervisor.
        evidence = evidence_file('production-events.jsonl')
        argv = SPAWNER_CAPS + [build / 'w2-cell', root, 'catalog.json', '1000', '1000', *PYTHON,
                               ENGINE / 'bin/engine', library, root, 'catalog.json', evidence]
        proc = subprocess.Popen([str(v) for v in argv], stdout=subprocess.PIPE, text=True,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
        until = time.monotonic() + 30
        while time.monotonic() < until and '"control_ready"' not in evidence.read_text() and proc.poll() is None:
            time.sleep(0.05)
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        # The orphaned spawner sees control EOF and exits by itself; wait for that before supervising.
        natural, until = [], time.monotonic() + 10
        while time.monotonic() < until and own_children():
            got, wait_status = os.waitpid(-1, os.WNOHANG)
            if got:
                natural.append({'pid': got, 'exit': os.waitstatus_to_exitcode(wait_status)})
            time.sleep(0.02)
        recorded = evidence_events(evidence)
        case = {'scenario': 'production-entry', 'exit_code': proc.returncode, 'spawner_natural_exits': natural,
                'startup': diagnostic(recorded, 'startup_checked'),
                'control_ready': any(e['kind'] == 'diagnostic' and e['name'] == 'control_received'
                                     and e['detail']['record']['type'] == 'control_ready' for e in recorded),
                'events': recorded, 'stdout': proc.stdout.read() if proc.stdout else ''}
        supervise(case, False)
        record['cases'].append(case)
        assert case['startup'] and case['control_ready'] and not case['supervisor_reaped'], case

        # Self-check refusal: same production entry in a user namespace whose uid_map is not the identity.
        item = command(['/usr/bin/unshare', '--user', '--map-root-user', *PYTHON, ENGINE / 'bin/engine', library,
                        root, 'catalog.json', evidence_dir / 'refusal-unused.jsonl'], allowed=(3,))
        refusal = next(e for e in events(item['stdout']) if e['event'] == 'startup_refused')
        record['cases'].append({'scenario': 'userns-self-check-refusal', 'exit_code': item['exit_code'],
                                'refusal': refusal})
        assert 'uid_map' in refusal['reason'] and '4294967295' not in refusal['reason']
        record['record_access'] = record_access(sorted(evidence_dir.iterdir()), command)
        assert record['record_access']['ok'], record['record_access']
        record['result'] = 'passed'
    except BaseException as error:
        record['error'] = repr(error)
        record['traceback'] = traceback.format_exc()
        record['result'] = 'failed'
    finally:
        if pdp_proc is not None:
            pdp_proc.terminate()
            pdp_proc.wait(10)
            pdp_log.close()
        try:
            if cell_cgroup.exists():                    # a failed two-epoch run: empty and remove the cell cgroup
                release_gate(cell_cgroup)
                cell_cgroup.rmdir()
                record['result'] = 'failed'
            leftover: dict[str, Any] = {}
            supervise(leftover, False)
            if leftover['supervisor_reaped']:
                record['emergency_supervisor_reaps'] = leftover['supervisor_reaped']
                record['result'] = 'failed'
            for target in reversed(workspace_binds):
                command(['/usr/bin/umount', target])
            for target in reversed(mounted):
                command(['/usr/bin/umount', target])
            for image in images.values():
                loops = command(['/usr/sbin/losetup', '--list', '--json', '--associated', image])
                assert not json.loads(loops['stdout'] or '{}').get('loopdevices')
            assert root.parent == Path('/var/lib') and root.name == 'engine-check-' + args.label
            root.rmdir()
            assert not any(line.split()[4].startswith(str(scratch))
                           for line in Path('/proc/self/mountinfo').read_text().splitlines())
            shutil.rmtree(scratch)
            shutil.rmtree(build)
            shutil.rmtree(evidence_dir)
            if mcp_top is not None:
                assert mcp_top.parent == Path('/tmp') and mcp_top.name.startswith('engine-mcp-')
                shutil.rmtree(mcp_top)
            record['cleanup'] = {'deployment_removed': not root.exists(), 'scratch_removed': not scratch.exists(),
                                 'cell_cgroup_removed': not cell_cgroup.exists(),
                                 'loop_detached': True, 'build_removed': not build.exists(),
                                 'evidence_dir_removed': not evidence_dir.exists()}
        except BaseException as error:
            record['cleanup_error'] = repr(error)
            record['result'] = 'failed'
        record['finished_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with record_path.open('x') as out:
            json.dump(record, out, ensure_ascii=False, indent=2)
            out.write('\n')
    print(json.dumps({'record': str(record_path), 'result': record['result']}), flush=True)
    return 0 if record['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
