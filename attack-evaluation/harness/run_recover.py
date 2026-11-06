"""这是 1.1 隔离论证的验证测试：启动门的人工恢复；只读核对失败批次的对象都已不在，全部干净且经用户批准才写核验记录并解锁，不删除任何运行对象。"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).absolute().parent
sys.path[:0] = [str(HERE), str(HERE / 'cell')]
from common import MAX_OUTPUT, identity, json_bytes, token, utc
from env import mount_rows
from host import compare_crashes, crash_inventory, host_process_uids
from run_gate import FORCED, RECOVERY, release_recovered
from run_units import unit
from safeio import plain_path, read_owned

FIXED_UIDS = (70996, 70997, 70998, 70999)  # file worker, workspace owner, PDP, connector (outside build.capacity)
RESERVED = (70000, 70995)    # build.capacity starts at 70000 and never reaches 70996
GATE = 'nb-decoy-harness-gate'
RUN = r'\d{8}T\d{6}Z-[A-Za-z0-9][A-Za-z0-9_-]{0,79}'


def _beneath(target, roots):
    return any(target == r or target.startswith(r.rstrip('/') + '/') for r in roots)


def run_token(snapshot_root):
    """Deployment roots and the run cgroup carry the snapshot's token (run_boot.stage)."""
    name = Path(snapshot_root or '').name
    if not name.startswith('nb-decoy-boot-'):
        raise ValueError('snapshot root unknown; inspect by hand')
    return token(name[len('nb-decoy-boot-'):])


def archived_objects(header, lease):
    """Objects named by the archive's own cleanup record."""
    steps = [s['step'] for s in header['cleanup']['steps']]
    roots = [s.split(':', 1)[1] for s in steps if s.startswith('remove:')]
    if not roots:
        raise ValueError('run roots unknown; inspect by hand')
    host = header['host']
    def crash():
        compare_crashes(host['crashes'], crash_inventory(Path(host['crash_directory'])))
    return {'roots': roots, 'images': [s.split(':', 1)[1] for s in steps if s.startswith('verify-loop:')],
            'snapshot': lease.get('root'), 'token': run_token(lease.get('root')),
            'uids': (host['capacity']['first'], host['capacity']['last']),
            'crash_directory': host['crash_directory'], 'crash': crash}


def forced_objects(lease, crash_directory):
    """No cleanup record survives a controller forced before archiving: its roots are
    named from the snapshot token, and any crash entry since the batch start is new."""
    tok = run_token(lease.get('root'))
    started = datetime.datetime.fromisoformat(lease['started_at']).timestamp() * 1e9
    def crash():
        found = crash_inventory(Path(crash_directory))
        if found.get('exists') is not True:
            raise ValueError('crash directory missing')
        new = sorted(n for n, e in found['entries'].items() if e['mtime_ns'] >= started)
        if new:
            raise RuntimeError(f'crash entries since the batch start: {new}')
    return {'roots': ['/var/lib/nb-decoy-' + tok, '/tmp/nb-decoy-' + tok, '/tmp/nb-decoy-build-' + tok],
            'images': [], 'snapshot': lease['root'], 'token': tok, 'uids': RESERVED,
            'crash_directory': str(crash_directory), 'crash': crash}


def residue(objects, *, cgroup_parent, mounts, loops, uids, listing, cgroups):
    """Read-only facts about the failed batch's objects plus any nb-decoy leftover; nothing is removed."""
    named = [*objects['roots'], *objects['images'], objects['snapshot']]
    checks = [{'object': p, 'check': 'path-absent', 'ok': not os.path.lexists(p)} for p in named]
    group = str(Path(cgroup_parent) / ('nb-decoy-' + objects['token']))
    checks.append({'object': group, 'check': 'cgroup-absent', 'ok': not os.path.lexists(group)})
    checks.append({'object': str(cgroup_parent), 'check': 'no-nb-decoy-cgroup', 'ok': not cgroups,
                   'found': sorted(cgroups)})
    checks.append({'object': '/tmp, /var/lib', 'check': 'no-nb-decoy-directory', 'ok': not listing,
                   'found': sorted(listing)})
    found = sorted(t for t in mounts if _beneath(t, named) or ('/nb-decoy-' in t and GATE not in t))
    checks.append({'object': 'mountinfo', 'check': 'no-mount-beneath-run-roots', 'ok': not found, 'found': found})
    found = sorted(f for f in loops if 'nb-decoy-' in f)
    checks.append({'object': 'loop-devices', 'check': 'no-backing-file-from-run', 'ok': not found, 'found': found})
    first, last = objects['uids']
    found = sorted(u for u in uids if first <= u <= last or u in FIXED_UIDS)
    checks.append({'object': 'processes', 'check': 'no-task-with-run-uids', 'ok': not found, 'found': found})
    try:
        objects['crash']()
        ok, detail = True, ''
    except (RuntimeError, ValueError, OSError) as exc:
        ok, detail = False, str(exc)[:200]
    checks.append({'object': objects['crash_directory'], 'check': 'no-new-crash-entries', 'ok': ok, 'detail': detail})
    return checks


def host_facts(cgroup_parent):
    loops = json.loads(subprocess.run(['/usr/sbin/losetup', '--list', '--json'], check=True,
                                      capture_output=True, text=True, timeout=10).stdout or '{}')
    return {'mounts': [r['target'] for r in mount_rows(Path('/proc/self/mountinfo').read_text())],
            'loops': [d.get('back-file') or '' for d in loops.get('loopdevices', [])],
            'uids': host_process_uids(),
            'listing': [str(Path(d) / n) for d in ('/tmp', '/var/lib') for n in os.listdir(d)
                        if n.startswith('nb-decoy-') and not n.endswith('-gate')],  # per-unit gate dirs are persistent infra, not run residue
            'cgroups': [n for n in os.listdir(cgroup_parent) if n.startswith('nb-decoy-')]}


KILLED = 'controller and outer launcher killed together without a marker (e.g. WSL instance restart); marked by run_recover'


def mark_killed(path):
    """A run whose controller and outer launcher died together leaves neither an archive
    header nor a launcher marker. Write the marker the outer launcher would have written
    (run_boot.failure_marker's format), only when none of the three exists, so the run is
    then handled exactly like a controller forced before archiving."""
    path = Path(path)
    if any(os.path.lexists(path / n) for n in ('run.json', 'COMPLETE.json', 'LAUNCHER-FAILED.json')):
        raise ValueError('run has a header, completion or marker; not the killed-unmarked case')
    from run_boot import failure_marker
    failure_marker({'output': str(path)}, KILLED)


def build_record(path, unit_name, header, lease, checks, approved):
    """header None: the controller was forced before archiving (kind FORCED)."""
    failed = path / 'LAUNCHER-FAILED.json'
    record = {'schema': RECOVERY, 'run': path.name, 'unit': unit_name, 'approved_by_user': approved,
              'recorded_at': utc(), 'launcher_failed': identity(read_owned(failed)) if failed.exists() else None,
              'gate': {'token': lease['token'], 'run': lease['run']}, 'checks': checks}
    if header is None:
        return {**record, 'kind': FORCED}
    return {**record, 'cleanup': identity(json_bytes(header['cleanup'])),
            'cleanup_failures': header['cleanup'].get('failures', []),
            'completion': identity(read_owned(path / 'COMPLETE.json', MAX_OUTPUT))}


def main(argv=None):
    p = argparse.ArgumentParser(description='Manual start-gate recovery of one failed batch; '
                                            '--check-only writes nothing')
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--unit', choices=('no-bypass', 'credential-binding'), required=True)
    p.add_argument('--run', required=True)
    p.add_argument('--approved-by-user', help='YYYY-MM-DD of the user approval; required to write')
    p.add_argument('--cgroup-parent', type=Path, default=Path('/sys/fs/cgroup'))
    p.add_argument('--crash-directory', type=Path, help='required when the controller was forced before archiving')
    p.add_argument('--check-only', action='store_true')
    p.add_argument('--killed-unmarked', action='store_true',
                   help='the run has neither header nor marker: controller and outer launcher died together')
    a = p.parse_args(argv)
    if os.name != 'posix' or os.geteuid() != 0:
        raise RuntimeError('recovery requires WSL root')
    if not re.fullmatch(RUN, a.run):
        raise ValueError('invalid run id')
    if not a.check_only and not re.fullmatch(r'\d{4}-\d{2}-\d{2}', a.approved_by_user or ''):
        raise ValueError('--approved-by-user YYYY-MM-DD required to write a recovery record')
    path = plain_path(a.repo / unit(a.unit).runs / a.run)
    import run_gate
    with run_gate._locked() as directory:
        lease = run_gate._active(directory)
    if lease.get('run') != a.run or lease.get('output') != str(path):
        raise RuntimeError('active cleanup gate does not name this run')
    if (path / 'run.json').exists():
        header = json.loads(read_owned(path / 'run.json', MAX_OUTPUT))
        if header.get('cleanup', {}).get('retained'):
            raise RuntimeError('retained objects need object-by-object handling; not this path')
        objects = archived_objects(header, lease)
    elif (path / 'LAUNCHER-FAILED.json').exists() and not (path / 'COMPLETE.json').exists():
        if a.crash_directory is None:
            raise ValueError('--crash-directory required for a run forced before archiving')
        header, objects = None, forced_objects(lease, a.crash_directory)
    elif a.killed_unmarked and not (path / 'COMPLETE.json').exists():
        if a.crash_directory is None:
            raise ValueError('--crash-directory required for a run killed before archiving')
        header, objects = None, forced_objects(lease, a.crash_directory)
    else:
        raise RuntimeError('run has neither an archive header nor a launcher failure marker; inspect by hand '
                           '(--killed-unmarked if controller and outer launcher died together)')
    checks = residue(objects, cgroup_parent=a.cgroup_parent, **host_facts(a.cgroup_parent))
    print(json.dumps({'run': a.run, 'checks': checks}, ensure_ascii=False, indent=1))
    clean = all(c['ok'] for c in checks)
    if a.check_only:
        return 0 if clean else 1
    if not clean:
        raise RuntimeError('residue found; gate stays locked and no record is written')
    if header is None and not (path / 'LAUNCHER-FAILED.json').exists():
        mark_killed(path)  # only after the read-only checks are clean and approved
    record = release_recovered(path, build_record(path, a.unit, header, lease, checks, a.approved_by_user))
    print('recovered: ' + record['run'])
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
