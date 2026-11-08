"""Record local C17 contract checks; run as an unprivileged Linux user.

No mount, namespace, privilege change, policy installation or runtime launch.
Each label is immutable and records the exact consumed source bytes.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', required=True, type=Path)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or os.geteuid() == 0:
        raise SystemExit('Use a non-root Linux account')
    posture = {}
    for line in Path('/proc/self/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in {'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb',
                   'NoNewPrivs', 'Seccomp'}:
            posture[key] = value.strip()
    if any(int(posture[key], 16) for key in ('CapPrm', 'CapEff', 'CapAmb')):
        raise SystemExit('Use a process without permitted/effective/ambient capabilities')
    if not re.fullmatch(r'[a-z0-9-]+', args.label):
        raise SystemExit('Invalid observation label')
    implementation = Path(__file__).resolve().parents[1]
    root = implementation.parents[2]  # ExperimentLab/engine/native -> repository root
    w2_impl = root / 'ExperimentLab/lab/experiments/w2/implementation'  # design documents stay in W2
    run = args.run_dir.resolve(strict=True)
    if run.parent != implementation.parent / 'runs':
        raise SystemExit('Run directory must be under ExperimentLab/engine/runs')
    record_path = run / (args.label + '.json')
    archive_path = run / (args.label + '-inputs.tar')
    if record_path.exists() or archive_path.exists():
        raise SystemExit('Refusing to overwrite observation or input archive')
    inputs = [
        '.goals/plans/w2-execution.plan.md',
        'ExperimentLab/lab/experiments/w2/selection-protocol.md',
        'ExperimentLab/lab/experiments/w2/p2a-plan.md',
        'ExperimentLab/lab/experiments/w2/environment-manifest.json',
        'ExperimentLab/lab/experiments/w2/workload-validation.md',
        'Thesis/Work/Design/sandbox-mediated-agent-execution/option-b-workload-per-engine.md',
        'Thesis/Work/Design/sandbox-mediated-agent-execution/mechanism.md',
        'Thesis/Work/Design/sandbox-mediated-agent-execution/scope-and-boundary.md',
        'Thesis/Work/Design/sandbox-mediated-agent-execution/kernel/kernel-uid-binding.md',
    ]
    for name in ['engine-design.md', 'sandbox-design.md', 'verification-plan.md',
                 'engine-design/connections.md', 'engine-design/resources-routing.md',
                 'engine-design/supporting-interfaces.md']:
        inputs.append((w2_impl / name).relative_to(root).as_posix())
    for name in ['Makefile',
                 'sandbox/contract.h', 'sandbox/contract.c', 'checks/check_contract.c',
                 'checks/probe_handoff.c', 'checks/check_sources.py', 'checks/run_checks.py']:
        inputs.append((implementation / name).relative_to(root).as_posix())
    identities = [{'path': name, 'sha256': digest(root / name)} for name in inputs]
    with tarfile.open(archive_path, 'x') as archive:
        for name in inputs:
            archive.add(root / name, arcname=name, recursive=False)
    record = {
        'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'Stage-2 C17 types/bootstrap codec and trusted unprivileged handoff API probe only',
        'environment': {'kernel_release': platform.release(), 'architecture': platform.machine(),
                        'uid': os.getuid(), 'gid': os.getgid(),
                        'python': platform.python_version(), 'process_posture': posture},
        'inputs': identities,
        'input_archive': {'path': archive_path.name, 'sha256': digest(archive_path)},
        'commands': [], 'artifacts': [], 'result': 'not-run',
    }
    build = Path(tempfile.mkdtemp(prefix='w2-p2a-contracts-', dir='/tmp'))
    record['build_directory'] = str(build)
    env = dict(os.environ)
    env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
    env['LC_ALL'] = 'C.UTF-8'

    def command(argv, timeout=40):
        started = time.monotonic()
        try:
            result = subprocess.run(argv, cwd=implementation, env=env,
                                    capture_output=True, text=True, timeout=timeout)
            entry = {'argv': argv, 'exit_code': result.returncode,
                     'stdout': result.stdout, 'stderr': result.stderr}
        except subprocess.TimeoutExpired as exc:
            entry = {'argv': argv, 'exit_code': None, 'timed_out': True,
                     'stdout': (exc.stdout or b'').decode('utf-8', errors='replace'),
                     'stderr': (exc.stderr or b'').decode('utf-8', errors='replace')}
        entry['elapsed_seconds'] = time.monotonic() - started
        record['commands'].append(entry)
        if entry['exit_code'] != 0:
            raise RuntimeError('Command failed: ' + repr(argv))

    try:
        command(['/usr/bin/gcc', '--version'])
        command(['/usr/bin/make', '--version'])
        record['tool_identities'] = [
            {'path': p, 'sha256': digest(Path(p))}
            for p in ['/usr/bin/gcc', '/usr/bin/ld', '/usr/bin/make']
        ]
        command(['/usr/bin/make', 'check', 'BUILD_DIR=' + str(build)])
        for name in ['check-contract', 'probe-handoff']:
            destination = run / (args.label + '-' + name + '.elf')
            with destination.open('xb') as output:
                output.write((build / name).read_bytes())
            record['artifacts'].append({'path': destination.name, 'sha256': digest(destination)})
        changed = [i['path'] for i in identities if digest(root / i['path']) != i['sha256']]
        record['inputs_changed_during_run'] = changed
        if changed:
            raise RuntimeError('Inputs changed during check')
        record['result'] = 'passed'
    except Exception as exc:
        record['result'] = 'failed'
        record['error'] = str(exc)
    finally:
        try:
            resolved = build.resolve(strict=True)
            if resolved.parent != Path('/tmp') or not resolved.name.startswith('w2-p2a-contracts-'):
                raise RuntimeError('Unexpected build cleanup target')
            shutil.rmtree(resolved)
            record['build_directory_removed'] = not build.exists()
        except Exception as exc:
            record['cleanup_error'] = str(exc)
            record['result'] = 'failed'
        record['finished_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with record_path.open('x', encoding='utf-8') as output:
            json.dump(record, output, ensure_ascii=False, indent=2)
            output.write('\n')
    print(json.dumps({'record': str(record_path), 'result': record['result'],
                      'build_directory_removed': record.get('build_directory_removed', False)}))
    return 0 if record['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
