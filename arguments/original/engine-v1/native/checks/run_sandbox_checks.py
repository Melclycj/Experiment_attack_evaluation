"""Build-identity-bound, disposable Linux sandbox integration checks.

Run as root inside a private mount namespace. Only a newly created image is
formatted; all deployment mounts and files are owned by this invocation.
"""
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
import subprocess
import tarfile
import tempfile
import time
import traceback

HERE = Path(__file__).resolve().parent
IMPL = HERE.parent
REPO = IMPL.parents[2]  # ExperimentLab/engine/native -> repository root
W2 = REPO / 'ExperimentLab/lab/experiments/w2'  # design and plan documents stay in W2


def digest(path):
    return 'sha256:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n')
    path.chmod(0o644)
    return digest(path)


def process_creation_entries(raw):
    """Count every syscall entry, retaining failed and unfinished calls too."""
    entries, pending = [], {}
    for line in raw.splitlines():
        match = re.match(r'^(\d+)\s+(clone3|clone|fork|vfork)\(', line)
        if match:
            pid, operation = int(match[1]), match[2]
            assert pid not in pending, ('overlapping traced calls', line)
            entry = {'pid': pid, 'syscall': operation, 'entry': line, 'return_pid': None}
            entries.append(entry)
            if '<unfinished ...>' in line:
                pending[pid] = entry
            else:
                returned = re.search(r'\s=\s(-?\d+)\b', line)
                if returned:
                    entry['return_pid'] = int(returned[1])
        else:
            match = re.match(r'^(\d+)\s+<\.\.\. (clone3|clone|fork|vfork) resumed>', line)
            if match:
                entry = pending.pop(int(match[1]))
                assert entry['syscall'] == match[2]
                entry['resumed'] = line
                returned = re.search(r'\s=\s(-?\d+)\b', line)
                if returned:
                    entry['return_pid'] = int(returned[1])
    assert not pending, ('incomplete process trace', pending)
    return entries


def passcred_before_clone(raw, spawner):
    """engine-requirements §2: SO_PASSCRED is set on the engine end at socketpair creation, before the clone of
    the execution (engine build acceptance observes the order). Spawner lines only; returns the three lines."""
    lines = [line for line in raw.splitlines() if line.startswith(f'{spawner} ')]
    for i, line in enumerate(lines):
        pair = re.search(r'socketpair\(AF_UNIX, SOCK_STREAM[^,]*, 0, \[(\d+), (\d+)\]\) = 0', line)
        if not pair:
            continue
        rest = lines[i + 1:]
        clone = next((j for j, l in enumerate(rest) if 'clone(' in l and 'CLONE_NEWPID' in l), len(rest))
        passcred = [j for j, l in enumerate(rest)
                    if re.search(rf'setsockopt\({pair[1]}, SOL_SOCKET, SO_PASSCRED, \[1\], 4\) = 0', l)]
        if not passcred:
            continue                       # another socketpair (not the execution's)
        assert passcred[0] < clone < len(rest), ('SO_PASSCRED not before the clone', rest[:clone + 1])
        return [line, rest[passcred[0]], rest[clone]]
    raise AssertionError('no execution socketpair in the spawner trace')


def deployment(root, build, command, workspace_storage, workspace_binds):
    (root / 'store').mkdir(mode=0o700)
    (root / 'store/objects').mkdir(mode=0o700)
    (root / 'store/store.lock').touch(mode=0o600)
    (root / 'sandbox-root').mkdir(mode=0o755)
    (root / 'seed').mkdir(mode=0o755)
    (root / 'seed/bin').mkdir(mode=0o755)
    shutil.copyfile(build / 'agent-fixture', root / 'seed/bin/agent-fixture')
    (root / 'seed/bin/agent-fixture').chmod(0o555)
    lock_digest = save_json(root / 'seed/dependency-lock.json', {
        'fixture': 'native-observer', 'linkage': 'static',
        'compiler': command(['/usr/bin/gcc', '-dumpfullversion'])['stdout'].strip(),
        'libc_development_package': command(['/usr/bin/dpkg-query', '-W', '-f=${Version}', 'libc6-dev'])['stdout']})
    (root / 'seed/dependency-lock.json').chmod(0o444)
    (root / 'seed/link').symlink_to('bin/agent-fixture')
    components = {'v': 1, 'files': [
        {'path': 'bin', 'type': 'directory', 'size': 0, 'mode': 0o755},
        {'path': 'bin/agent-fixture', 'type': 'file', 'size': (build / 'agent-fixture').stat().st_size,
         'mode': 0o555, 'digest': digest(build / 'agent-fixture')},
        {'path': 'dependency-lock.json', 'type': 'file', 'size': (root / 'seed/dependency-lock.json').stat().st_size,
         'mode': 0o444, 'digest': lock_digest},
        {'path': 'link', 'type': 'symlink', 'size': len('bin/agent-fixture'), 'mode': 0o777,
         'target': 'bin/agent-fixture'},
    ]}
    component_digest = save_json(root / 'components.json', components)
    config_digest = save_json(root / 'adapter.json', {'v': 1, 'model_resource_ids': [], 'document_resource_ids': [],
        'tools': [], 'limits': {'max_frame_bytes': 65536, 'max_tool_result_bytes': 16384, 'max_output_tokens': 4096}, 'encoding': 'utf-8'})
    # Explicit diagnostic workload policy. Forbidden names cannot be inserted
    # by a catalog; the compiler owns native ABI and S1 treatment.
    policy = {'v': 1, 'target_arch': 'x86_64', 'default_action': 'errno', 'default_errno': 1,
              'allow': ['read', 'write', 'readv', 'writev', 'close', 'fstat', 'newfstatat',
                        'statx', 'lseek', 'mmap', 'mprotect', 'munmap', 'brk', 'madvise',
                        'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'sigaltstack',
                        'access', 'faccessat2', 'openat', 'getdents64', 'readlink', 'readlinkat',
                        'arch_prctl', 'set_tid_address', 'set_robust_list', 'rseq', 'futex',
                        'getrandom', 'clock_gettime', 'clock_nanosleep', 'nanosleep',
                        'getpid', 'getppid', 'gettid', 'getuid', 'geteuid', 'getgid', 'getegid',
                        'getresuid', 'getresgid', 'getgroups', 'prlimit64', 'prctl',
                        'sendmsg', 'recvmsg', 'sendto', 'recvfrom', 'poll', 'ppoll',
                        'fcntl', 'getsockname', 'getpeername', 'getsockopt', 'shutdown',
                        'chdir', 'getcwd', 'execve', 'exit', 'exit_group', 'wait4', 'waitid',
                        'clone', 'unshare', 'kill', 'tgkill', 'setsid', 'pause', 'restart_syscall',
                        'fsync', 'fdatasync', 'uname', 'setuid']}
    policy_digest = save_json(root / 'policy.json', policy)
    profile = {'isolation_profile_id': 'sandbox-native', 'target_arch': 'x86_64',
               'layout': 'runtime-root-v1', 'construction': 'SB-01-SB-09'}
    profile_digest = save_json(root / 'isolation.json', profile)
    fs = os.statvfs(root)
    identity = command(['/usr/bin/btrfs', 'filesystem', 'show', '--raw', root])['stdout']
    storage = {'storage_profile_id': 'diagnostic-store', 'store_id': 'd'*32,
        'filesystem_uuid': re.search(r'uuid:\s*([0-9a-f-]{36})', identity).group(1),
        'store_root_ref': 'store', 'objects_ref': 'store/objects', 'lock_ref': 'store/store.lock',
        'owner_uid': 0, 'owner_gid': 0, 'filesystem_kind': 'btrfs',
        'filesystem_capacity_bytes': str(fs.f_blocks*fs.f_frsize), 'max_copies': 16,
        'max_reserved_bytes': str(128*1024*1024), 'max_reserved_nodes': '1024', 'max_tree_nodes': 1024,
        'min_free_bytes': str(64*1024*1024), 'cleanup_timeout_ms': 1000}
    nodes = len(components['files'])+1
    charge = 4096*nodes+sum(((e['size']+4095)//4096)*4096 for e in components['files'] if e['type'] == 'file')
    storage.update(max_reserved_bytes=str(2*charge), max_reserved_nodes=str(2*nodes))
    storage_digest = save_json(root / 'storage.json', storage)
    catalog = {'v': 1, 'runtimes': [],
        'adapters': [{'adapter_id': 'fixture', 'compatibility_profile': 'diagnostic-native',
                      'config_ref': 'adapter.json', 'config_digest': config_digest}],
        'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage_digest},
        'policies': [
        {'policy_id': 'diagnostic', 'artifact_ref': 'policy.json', 'artifact_digest': policy_digest,
         'target_arch': 'x86_64', 'format': 'w2-seccomp-json/1', 'compiler_identity': 'libseccomp-2.5.5'}],
        'workspaces': [], 'profiles': [{'artifact_ref': 'isolation.json', 'artifact_digest': profile_digest}], 'plans': []}
    for i in range(3):
        source = workspace_storage / f'work{i}'
        command(['/usr/bin/btrfs', 'subvolume', 'create', source])
        os.chown(source, 70000+i, 70000+i)
        source.chmod(0o700)
        (root / f'work{i}').mkdir()
        command(['/usr/bin/mount', '--bind', source, root / f'work{i}'])
        workspace_binds.append(root / f'work{i}')
        catalog['workspaces'].append({'workspace_id': f'work{i}', 'workspace_layout_id': 'private-work-v1',
                                      'source_ref': f'work{i}', 'workspace_uid': 70000+i, 'workspace_gid': 70000+i})
    for name in ('observe', 'linger'):
        descriptor = dict(runtime_id=name, adapter_id='fixture', artifact_digest=component_digest,
                          dependency_digest=lock_digest, layout_id='runtime-root-v1', storage_profile_id='diagnostic-store',
                          executable='/runtime/bin/agent-fixture',
                          argv=['/runtime/bin/agent-fixture'] + (['linger'] if name == 'linger' else []),
                          cwd='/work', env={}, protocol='w2-local/2', adapter_config_ref='adapter.json',
                          adapter_config_digest=config_digest, compatibility_profile='diagnostic-native',
                          component_manifest_ref='components.json', component_manifest_digest=component_digest)
        rd = save_json(root / f'{name}.json', descriptor)
        catalog['runtimes'].append({'descriptor_ref': f'{name}.json', 'descriptor_digest': rd,
                                   'seed_ref': 'seed', 'dependency_lock_ref': 'dependency-lock.json'})
        for i in (range(3) if name == 'observe' else [0]):
            plan = dict(launch_plan_id=f'{name}-{i}', runtime_id=name, runtime_descriptor_digest=rd,
                        workspace_id=f'work{i}', workspace_layout_id='private-work-v1', policy_id='diagnostic',
                        policy_digest=policy_digest, isolation_profile_id='sandbox-native', isolation_profile_digest=profile_digest)
            ref = f'plan-{name}-{i}.json'
            catalog['plans'].append({'artifact_ref': ref, 'artifact_digest': save_json(root / ref, plan)})
    save_json(root / 'catalog.json', catalog)
    slow = dict(storage, cleanup_timeout_ms=10000)
    slow_digest = save_json(root / 'slow-storage.json', slow)
    slow_catalog = dict(catalog, storage_profile={'artifact_ref': 'slow-storage.json', 'artifact_digest': slow_digest})
    save_json(root / 'slow-catalog.json', slow_catalog)


def check_report(report, uid):
    assert f'EXEC_MARKER pid=1 uid={uid} gid={uid}' in report, report
    assert re.findall(r'inherited_fd=(\d+)', report) == ['0', '1', '2', '3']
    assert all(f'fd{i}=/dev/null' in report for i in range(3))
    assert 'inherited_fd=3 flags=0' in report
    assert f'uids={uid},{uid},{uid} gids={uid},{uid},{uid} groups=0' in report
    for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        assert re.search(rf'{name}:\s+0+\b', report), name
    assert re.search(r'NoNewPrivs:\s+1', report) and re.search(r'Seccomp:\s+2', report)
    for name in ('runtime_write', 'outside_visible', 'oldroot_visible', 'setuid_zero',
                 'unshare_user', 'clone_user', 'bind', 'connect', 'io_uring_setup',
                 'io_uring_enter', 'io_uring_register'):
        assert re.search(rf'^{name}=-1 errno=', report, re.M), name
    # With a root-owned 0755 artifact, DAC may reject before the VFS readonly
    # check. Observe both the denied write and the independent mountinfo ro flag.
    assert re.search(r'runtime_write=-1 errno=(13|30)\b', report)
    for name in ('setuid_zero', 'unshare_user', 'clone_user', 'bind', 'connect',
                 'io_uring_setup', 'io_uring_enter', 'io_uring_register', 'sysinfo', 'sync', 'syncfs'):
        assert re.search(rf'^{name}=-1 errno={errno.EPERM}\b', report, re.M), name
    assert 'clone3=-1 errno=38' in report and 'pthread=0 errno=0' in report and 'proc_meminfo=-1 errno=2' in report and re.search(r'^Max core file size\s+1\s+1\s+bytes', report, re.M)
    assert 'abi.ia32.signal=31 exit=-1' in report and 'abi.x32.signal=31 exit=-1' in report
    assert 'work_exec=37' in report
    assert 'socket.local.rc=0 size=2' in report and 'socket.peer.rc=0 size=2' in report
    buffers = re.search(r'socket.sndbuf=(\d+) rcvbuf=(\d+)', report)
    assert buffers and all(65536 <= int(value) <= 131072 for value in buffers.groups())
    mounts = report.split('BEGIN mountinfo\n')[1].split('END mountinfo')[0].splitlines()
    by_target = {line.split()[4]: line for line in mounts if line.strip()}
    runtime = by_target['/runtime'].split()
    assert all(x in runtime[5].split(',') for x in ['ro', 'nosuid', 'nodev', 'noatime'])
    work = by_target['/work'].split()
    assert all(x in work[5].split(',') for x in ['rw', 'nosuid', 'nodev']) and 'noexec' not in work[5]
    assert ' - proc ' in by_target['/proc'] and 'subset=pid' in by_target['/proc'].split()[-1].split(',')
    for path in ('/tmp', '/dev', '/dev/shm'):
        assert ' - tmpfs ' in by_target[path]
    assert not any(' shared:' in line or ' master:' in line for line in mounts)
    net = report.split('BEGIN net\n')[1].split('END net')[0]
    assert re.findall(r'^\s*(\w+):', net, re.M) == ['lo']


FAULTS = [('validate', 'validate'), ('reflink', 'validate'), ('socketpair', 'socketpair'),
          ('passcred', 'passcred'), ('clone', 'clone'), ('mount_private', 'mount_private'),
          ('root.mount', 'root'), ('root.chdir', 'root')]
FAULTS += [(f'root.mkdir.{x}', 'root') for x in ('runtime', 'work', 'proc', 'dev', 'tmp', '.oldroot')]
FAULTS += [(f'root.link.{x}', 'root') for x in ('bin', 'lib', 'lib64', 'usr')]
FAULTS += [(x, s) for s, xs in [('runtime_mount', ['runtime.bind', 'runtime.remount']),
                               ('work_mount', ['work.open', 'work.bind', 'work.remount', 'work.close']),
                               ('runtime_mount', ['runtime.open', 'runtime.identity']),
                               ('proc', ['proc']), ('dev_tmp', ['dev.mount', 'dev.close', 'tmp', 'shm.mkdir', 'shm']),
                               ('pivot', ['pivot', 'pivot.chdir', 'pivot.detach', 'pivot.rmdir']),
                               ('loopback', ['loopback.socket', 'loopback.get', 'loopback.set', 'loopback.close']),
                               ('stdio', ['stdio.open', 'stdio.dup.0', 'stdio.dup.1', 'stdio.dup.2', 'stdio.close']),
                               ('fd_cleanup', ['fd.dup', 'fd.get', 'fd.cloexec', 'fd.close_range', 'core.limit']),
                               ('no_new_privs', ['no_new_privs']), ('bounding', ['bounding']),
                               ('groups_gid', ['groups', 'gid']), ('uid', ['uid', 'uid.reread']),
                               ('caps', ['ambient', 'caps']), ('policy', ['policy']),
                               ('sealed', ['sealed']), ('handoff', ['handoff']),
                               ('commit', ['commit']), ('exec', ['exec.cwd', 'exec'])] for x in xs]
FAULTS += [(f'dev.{op}.{dev}', 'dev_tmp') for dev in ('null', 'zero', 'random', 'urandom')
           for op in ('create', 'bind', 'remount')]
FAULTS += [(f'bounding.{i}', 'bounding') for i in range(41)]
FAULTS += [(f'buffer.{side}.{direction}.{operation}', 'socketpair')
           for side in range(2) for direction in range(2) for operation in ('set', 'get')]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--storage-only', action='store_true')
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == 'Linux'
    # The external test supervisor adopts only descendants of this invocation.
    # Its facts are recorded separately from spawner control notifications.
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
    assert re.fullmatch('[a-z0-9-]+', args.label)
    run = args.run_dir.resolve(strict=True)
    own_build = args.build is None
    build = (Path(tempfile.mkdtemp(prefix='w2-p2a-build-', dir='/tmp')) if own_build
             else args.build.resolve(strict=True))
    if own_build:
        build.chmod(0o755)
        os.chown(build, 1000, 1000)
    assert run.parent == IMPL.parent / 'runs'
    record_path = run / f'{args.label}.json'
    assert not record_path.exists()
    for uid in (70000, 70001, 70002):
        try:
            pwd.getpwuid(uid)
        except KeyError:
            pass
        else:
            raise RuntimeError(f'Test uid {uid} is registered to a host account')
    root = Path('/var/lib') / ('w2-sandbox-' + args.label)
    root.mkdir(mode=0o755)  # exclusive creation; never reuse a deployment
    scratch = Path(tempfile.mkdtemp(prefix='w2-p2a-sandbox-', dir='/tmp')).resolve()
    image = scratch / 'runtime.btrfs'
    with image.open('xb') as output:
        output.truncate(256 * 1024 * 1024)
    workspace_image = scratch / 'workspace.btrfs'
    with workspace_image.open('xb') as output:
        output.truncate(256 * 1024 * 1024)
    workspace_storage = scratch / 'workspaces'
    workspace_storage.mkdir()
    record = {'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'sandbox/spawner product paths with diagnostic native fixtures; not real agent/engine utility',
              'kernel': platform.release(), 'commands': [], 'cases': [], 'result': 'not-run',
              'scratch': str(scratch), 'deployment': str(root), 'mount_namespace_private': True}
    record['preconditions'] = {path: Path(path).read_text() for path in
        ('/proc/self/uid_map', '/proc/self/gid_map', '/proc/sys/kernel/overflowuid',
         '/proc/sys/kernel/overflowgid', '/proc/sys/kernel/yama/ptrace_scope', '/sys/kernel/mm/ksm/run')}
    sources = sorted(p for p in IMPL.rglob('*') if p.is_file() and p.suffix in {'.c', '.h', '.py', '.md'}) + [IMPL / 'Makefile']
    sources += [REPO / '.goals/plans/w2-execution.plan.md', W2 / 'selection-protocol.md',
                W2 / 'p2a-plan.md', W2 / 'environment-manifest.json', W2 / 'workload-validation.md']
    sources += [REPO / 'Thesis/Work/Design/sandbox-mediated-agent-execution' / p for p in
                ('option-b-workload-per-engine.md', 'mechanism.md', 'scope-and-boundary.md', 'kernel/kernel-uid-binding.md')]
    record['inputs'] = [{'path': p.relative_to(REPO).as_posix(), 'digest': digest(p)} for p in sources]
    archive = run / f'{args.label}-inputs.tar'
    with tarfile.open(archive, 'x') as out:
        for p in sources:
            out.add(p, arcname=p.relative_to(REPO).as_posix(), recursive=False)
    record['source_archive'] = {'path': archive.name, 'digest': digest(archive)}
    record['build_artifacts'] = []
    def command(argv, *, timeout=25, fault='', allowed=(0,)):
        env = dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C.UTF-8', W2_TEST_FAULT=fault)
        started = time.monotonic()
        p = subprocess.run([str(v) for v in argv], env=env, capture_output=True, text=True, timeout=timeout)
        item = {'argv': [str(v) for v in argv], 'fault': fault, 'exit_code': p.returncode,
                'stdout': p.stdout, 'stderr': p.stderr, 'elapsed_seconds': time.monotonic()-started}
        record['commands'].append(item)
        print(json.dumps({'command': len(record['commands'])-1, 'exit_code': p.returncode,
                          'fault': fault, 'last_arg': str(argv[-1])}), flush=True)
        if p.returncode not in allowed:
            raise RuntimeError('Command failed: ' + json.dumps(item))
        return item

    mounted = False
    workspace_mounted = False
    workspace_binds = []
    try:
        command(['/usr/bin/gcc', '--version'])
        command(['/usr/bin/dpkg-query', '-W', '-f=${Package} ${Version}\n',
                 'gcc', 'libc6-dev', 'libjansson-dev', 'libmd-dev',
                 'libseccomp-dev', 'libcap-dev', 'btrfs-progs', 'linux-libc-dev', 'strace'])
        if own_build:
            command(['/usr/bin/setpriv', '--reuid=1000', '--regid=1000', '--clear-groups',
                     '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
                     '/usr/bin/make', '-C', IMPL, 'sandbox', 'check', 'BUILD_DIR=' + str(build)], timeout=60)
        for name in ('w2-cell', 'w2-cell-test', 'w2-catalog', 'w2-recover', 'libw2sandbox.so', 'agent-fixture', 'check-transport', 'check-kill', 'check-storage', 'check-spawner-state', 'check-recovery', 'check-workspace', 'check-create-cancel'):
            destination = run / f'{args.label}-{name}'
            with destination.open('xb') as out:
                out.write((build / name).read_bytes())
            record['build_artifacts'].append({'path': destination.name, 'digest': digest(destination)})
        linked = command(['/usr/bin/ldd', build / 'w2-cell'])['stdout']
        dependency_paths = {Path(p).resolve() for p in re.findall(r'(/[^\s()]+)', linked)}
        dependency_paths.update(Path(p).resolve() for p in ('/usr/bin/gcc', '/usr/bin/make', '/usr/bin/python3', '/usr/bin/strace'))
        record['dependency_binary_identities'] = [{'path': str(p), 'digest': digest(p)} for p in sorted(dependency_paths)]
        command(['/usr/bin/setpriv', '--reuid=1000', '--regid=1000', '--clear-groups',
                 '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
                 build / 'check-transport'])
        command([build / 'check-kill'])
        command([build / 'check-spawner-state'])
        command(['/usr/bin/setpriv', '--reuid=1000', '--regid=1000', '--clear-groups',
                 '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
                 '/usr/bin/python3', HERE / 'check_wire.py', build / 'libw2sandbox.so'])
        command(['/usr/bin/python3', HERE / 'check_wire.py', build / 'libw2sandbox.so', '--mixed'])
        invalid_environment = command(['/usr/bin/unshare', '--user', '--map-root-user',
                                       build / 'check-transport', '--environment'], allowed=(1,))
        assert 'environment_check rejected=1' in invalid_environment['stdout']
        command(['/usr/sbin/mkfs.btrfs', '-q', image])
        command(['/usr/bin/mount', '-o', 'loop,nosuid,nodev', image, root])
        mounted = True
        command(['/usr/sbin/mkfs.btrfs', '-q', workspace_image])
        command(['/usr/bin/mount', '-o', 'loop,nosuid,nodev', workspace_image, workspace_storage])
        workspace_mounted = True
        command(['/usr/bin/findmnt', '--json', '--target', root])
        deployment(root, build, command, workspace_storage, workspace_binds)
        command(['/usr/bin/btrfs', 'subvolume', 'create', workspace_storage / 'counterfeit'])
        os.chown(workspace_storage / 'counterfeit', 70000, 70000)
        (workspace_storage / 'counterfeit').chmod(0o700)
        record['seed_inodes'] = {name: {'device': (root / 'seed' / name).lstat().st_dev,
                                      'inode': (root / 'seed' / name).lstat().st_ino}
                                 for name in ('bin', 'bin/agent-fixture', 'link')}
        record['store_anchors'] = {name: {'device': (root / name).stat().st_dev, 'inode': (root / name).stat().st_ino,
                                        'uid': (root / name).stat().st_uid, 'gid': (root / name).stat().st_gid,
                                        'mode': oct((root / name).stat().st_mode & 0o7777)}
                                   for name in ('store', 'store/objects', 'store/store.lock')}
        policy_dir = run / (args.label + '-policy')
        policy_dir.mkdir()
        policy_build = command([build / 'w2-catalog', root, 'catalog.json', policy_dir])
        record['policy_build'] = json.loads(policy_build['stdout'])
        for item in record['policy_build']['policies']:
            assert digest(policy_dir / (item['policy_id'] + '.bpf')) == item['bpf_digest']
        if not args.smoke and not args.storage_only:
            command(['/usr/bin/python3', HERE / 'check_catalogs.py', root, build / 'w2-cell'], timeout=60)
        with tarfile.open(run / f'{args.label}-deployment.tar', 'x') as out:
            for p in sorted(root.glob('*.json')):
                out.add(p, arcname=p.name, recursive=False)
        prefix = ['/usr/bin/setpriv', '--bounding-set=-all,+sys_admin,+setuid,+setgid,+setpcap,+net_admin,+kill',
                  '--inh-caps=-all', '--ambient-caps=-all']
        command(prefix + [build / 'check-storage', root, 'catalog.json'])
        record['create_cancellation_checks'] = []
        for mode in ('normal', 'deadline', 'cancel', 'eof', 'store-deadline', 'store-io-error'):
            checked = command(prefix + [build / 'check-create-cancel', root, 'catalog.json', mode])
            record['create_cancellation_checks'].append(json.loads(checked['stdout']))
        record['recovery_deadline_checks'] = []
        for point, edge in [('normal', 0)] + [(point, edge) for point in ('fsync', 'fstatvfs') for edge in (-1, 0, 1)]:
            checked = command(prefix + [build / 'check-recovery', root, 'catalog.json', point, str(edge)])
            record['recovery_deadline_checks'].append(json.loads(checked['stdout']))
        workspace_check = command([build / 'check-workspace', root, 'catalog.json', HERE / 'engine_fixture.py',
                                   build / 'libw2sandbox.so', workspace_storage])
        record['workspace_reference_checks'] = json.loads(workspace_check['stdout'])
        check_report((root / 'work0/report.txt').read_text(), 70000)

        def filesystem_failures():
            observations = []
            record['real_filesystem_failure_checks'] = observations
            for kind in ('readonly', 'metadata-enospc'):
                argv = [str(a) for a in prefix+[build / 'check-storage', root, 'catalog.json', '--probe-failure']]
                p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                pressure = root / 'metadata-pressure'
                names, readonly, triggered = [], False, False
                detail = {'kind': kind, 'argv': argv, 'available_before': os.statvfs(root).f_bavail*os.statvfs(root).f_frsize}
                observations.append(detail)
                try:
                    detail['ready'] = p.stdout.readline().strip()
                    assert detail['ready'] == 'READY'
                    if kind == 'readonly':
                        command(['/usr/bin/mount', '-o', 'remount,bind,ro,nosuid,nodev', root])
                        readonly = True
                    else:
                        pressure.mkdir(mode=0o700)
                        until = time.monotonic()+45
                        for index in range(100000):
                            assert time.monotonic() < until, 'finite metadata-pressure deadline'
                            path = pressure / str(index)
                            try:
                                fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
                                names.append(path)
                                try:
                                    try:
                                        os.setxattr(fd, 'user.w2-pressure', b'x'*3000)
                                    except OSError as error:
                                        if error.errno != errno.ENOSPC:
                                            raise
                                        detail['actual_xattr_enospc'] = True
                                finally:
                                    os.close(fd)
                            except OSError as error:
                                assert error.errno == errno.ENOSPC, error
                                detail.update(actual_pressure_errno=error.errno, empty_files=len(names), regular_data_bytes=0)
                                break
                        else:
                            raise AssertionError('metadata pressure did not reach real ENOSPC within the fixed bound')
                    detail['available_under_failure'] = os.statvfs(root).f_bavail*os.statvfs(root).f_frsize
                    detail['filesystem_usage_command'] = len(record['commands'])
                    command(['/usr/bin/btrfs', 'filesystem', 'usage', '--raw', root])
                    p.stdin.write('G\n')
                    p.stdin.flush()
                    triggered = True
                    stdout, stderr = p.communicate(timeout=15)
                    detail.update(actual_wait_returncode=p.returncode, stdout=stdout, stderr=stderr)
                    assert p.returncode == 0, detail
                    outcome = json.loads(stdout)
                    assert outcome['runtime_create_result'] != 0
                    assert outcome['os_errno'] == (errno.EROFS if kind == 'readonly' else errno.ENOSPC), outcome
                finally:
                    if p.poll() is None:
                        p.kill()
                        p.wait(timeout=5)
                    if not triggered:
                        stdout, stderr = p.communicate()
                        detail.update(actual_wait_returncode=p.returncode, stdout=stdout, stderr=stderr)
                    if readonly:
                        command(['/usr/bin/mount', '-o', 'remount,bind,rw,nosuid,nodev', root])
                    for path in reversed(names):
                        assert path.parent == pressure and path.name.isdecimal()
                        path.unlink()
                    if pressure.exists():
                        pressure.rmdir()
                assert triggered
                if kind == 'metadata-enospc':
                    detail['available_after_unlink_pressure'] = os.statvfs(root).f_bavail*os.statvfs(root).f_frsize
                    command(['/usr/bin/btrfs', 'filesystem', 'sync', root])
                    command(['/usr/bin/btrfs', 'balance', 'start', '-musage=0', '-dusage=0', root])
                    detail['available_after_empty_block_group_reclaim'] = os.statvfs(root).f_bavail*os.statvfs(root).f_frsize
                recovery = command(prefix+[build / 'w2-recover', root, 'catalog.json', '--supervisor-confirmed-old-domain-empty'])
                detail['recovery_after_probe_actual_exit_and_fault_repair'] = recovery['stdout']
                detail['available_after_repair'] = os.statvfs(root).f_bavail*os.statvfs(root).f_frsize
                detail['result'] = 'passed'

        def case(mode, fault='', stage='', production=False):
            for work in ('work0', 'work1', 'work2'):
                for name in ('report.txt', 'linger.txt'):
                    (root / work / name).unlink(missing_ok=True)
            catalog_name = 'slow-catalog.json' if mode == 'slow-eof' else 'catalog.json'
            argv = prefix + [build / ('w2-cell' if production else 'w2-cell-test'), root, catalog_name,
                             '1000', '1000', '/usr/bin/python3', HERE / 'engine_fixture.py', root, catalog_name,
                             mode, build / 'libw2sandbox.so', stage]
            live_trace = None
            if mode in {'busy', 'bad-uid', 'bad-gid'}:
                live_trace = run / f'{args.label}-{mode}-process.trace'
                assert not live_trace.exists()
                argv = ['/usr/bin/strace', '-f', '-qq', '-s', '256', '-e',
                        'trace=clone,clone3,fork,vfork,socketpair,setsockopt', '-o', live_trace, *argv]
            item = command(argv, fault=fault)
            observations = {'mode': mode, 'fault': fault, 'command': len(record['commands'])-1, 'reports': {}}
            if live_trace:
                peer = json.loads(item['stdout'])
                waits = [e['spawner_waitpid'] for e in peer['events'] if 'spawner_waitpid' in e]
                workers = [e['worker_pid'] for e in peer['events'] if 'worker_pid' in e]
                prepared = [e['receive'] for e in peer['events'] if e.get('receive', {}).get('type') == 'spawn_prepared']
                assert len(waits) == len(workers) == 1
                entries = [entry for entry in process_creation_entries(live_trace.read_text()) if entry['pid'] == waits[0]]
                assert len(entries) == (2 if mode == 'busy' else 1), entries
                worker_entry = [entry for entry in entries if entry['return_pid'] == workers[0]]
                assert len(worker_entry) == 1 and 'CLONE_NEWNS' not in worker_entry[0]['entry'], entries
                assert len(prepared) == (1 if mode == 'busy' else 0), prepared
                if mode == 'busy':
                    observations['passcred_before_clone'] = passcred_before_clone(live_trace.read_text(), waits[0])
                if prepared:
                    agent_entry = [entry for entry in entries if entry['return_pid'] == prepared[0]['child_pid']]
                    assert len(agent_entry) == 1 and all(flag in agent_entry[0]['entry'] for flag in
                        ('CLONE_NEWNS', 'CLONE_NEWPID', 'CLONE_NEWNET', 'CLONE_NEWIPC')), entries
                observations['live_rejection_process_trace'] = {'path': live_trace.name, 'digest': digest(live_trace),
                    'spawner_pid': waits[0], 'worker_pid': workers[0], 'creation_entries': entries,
                    'legitimate_prepared': prepared,
                    'qualification': 'All spawner process creation entries accounted for by worker and, for busy only, the one legitimate first agent; rejected request adds zero calls'}
            if mode == 'slow-eof':
                assert item['elapsed_seconds'] >= 6
                assert re.search(r'W2_JOB_DONE copy=\S+:1:r job=\d+ op=delete attempt=1 result=removed removed=1', item['stderr'])
                observations['healthy_cleanup_crossed_five_seconds_without_supervisor_recovery'] = True
            if mode == 'storage-retained':
                completed = re.findall(r'W2_JOB_DONE copy=\S+:1:r job=\d+ op=delete attempt=(\d+) result=failed removed=[01]', item['stderr'])
                assert completed == ['1', '2', '3'], completed
                submitted = re.findall(r'W2_JOB_SUBMIT copy=\S+:1:r job=\d+ op=delete attempt=(\d+)', item['stderr'])
                assert submitted == completed
                observations['actual_delete_results_three_attempts'] = completed
            if mode in {'kill-error', 'reap-error', 'kill-no-fact', 'reap-parallel',
                        'reap-control-loss', 'cleanup-progress', 'worker-loss', 'storage-retained'}:
                children = [int(p) for p in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()]
                if mode in {'cleanup-progress', 'worker-loss', 'storage-retained'}:
                    assert not children, 'all PID1 and cleanup workers should be reaped'
                else:
                    assert children, 'expected retained process/reap obligation'
                observations['supervisor_only'] = []
                for pid in children:
                    status_before = Path(f'/proc/{pid}/status').read_text()
                    expected_uid = 70001 if mode == 'reap-parallel' else 70000
                    assert re.search(rf'^Uid:\s+{expected_uid}\b', status_before, re.M), status_before
                    try:
                        os.kill(pid, 9)
                        killed = 'sent'
                    except ProcessLookupError:
                        killed = 'ESRCH; wait still required'
                    until = time.monotonic() + 3
                    while True:
                        got, status = os.waitpid(pid, os.WNOHANG)
                        if got == pid:
                            break
                        assert time.monotonic() < until, 'supervisor reap deadline'
                        time.sleep(.01)
                    observations['supervisor_only'].append({'pid': pid, 'status_before': status_before,
                        'kill': killed, 'actual_waitpid': got, 'wait_status': status})
                if mode in {'reap-error', 'reap-control-loss', 'reap-parallel'}:
                    uncertain = set()
                    for action, pid in re.findall(r'W2_TEST_TRACE (kill|wait_error) pid=(\d+)', item['stderr']):
                        if action == 'wait_error':
                            uncertain.add(pid)
                        else:
                            assert pid not in uncertain, 'numeric PID signalled after loss of ownership'
                    assert uncertain
                    observations['no_signal_after_wait_error'] = True
                # No live child remains. Remove only this test epoch's anchored
                # instance trees; the failing spawner did not claim this work.
                recovery = command(prefix + [build / 'w2-recover', root, 'catalog.json',
                                      '--supervisor-confirmed-old-domain-empty'])
                observations['supervisor_filesystem_recovery'] = recovery['stdout']
            for i in range(3):
                report = root / f'work{i}/report.txt'
                if report.exists():
                    observations['reports'][f'work{i}'] = report.read_text()
            record['cases'].append(observations)
            if mode == 'stall-first':
                assert set(observations['reports']) == {'work1'}
                check_report(observations['reports']['work1'], 70001)
            elif mode in {'reap-parallel', 'reap-control-loss', 'cleanup-progress', 'storage-retry', 'storage-retained', 'budget', 'slow-eof'}:
                for workspace, report in observations['reports'].items():
                    check_report(report, 70000+int(workspace[-1]))
                assert observations['reports']
            elif mode in {'normal', 'parallel', 'repeated'}:
                check_report(observations['reports']['work0'], 70000)
                for name, source in record['seed_inodes'].items():
                    match = re.search(rf'^runtime\.{re.escape(name)} dev=(\d+) inode=(\d+)', observations['reports']['work0'], re.M)
                    assert match and int(match[1]) == source['device'] and int(match[2]) != source['inode']
                assert (root / 'work0/persistent').read_bytes() == b'preserved'
                if mode == 'repeated':
                    assert 'persistent_existed=1' in observations['reports']['work0']
                if mode == 'parallel':
                    check_report(observations['reports']['work1'], 70001)
                    for ns in ('mnt', 'pid', 'net', 'ipc'):
                        a = re.search(rf'ns\.{ns}=(\S+)', observations['reports']['work0']).group(1)
                        b = re.search(rf'ns\.{ns}=(\S+)', observations['reports']['work1']).group(1)
                        assert a != b, (ns, a, b)
                    for name in record['seed_inodes']:
                        a = re.search(rf'^runtime\.{re.escape(name)} dev=(\d+) inode=(\d+)', observations['reports']['work0'], re.M)
                        b = re.search(rf'^runtime\.{re.escape(name)} dev=(\d+) inode=(\d+)', observations['reports']['work1'], re.M)
                        assert a and b and a[1] == b[1] and a[2] != b[2]
            else:
                assert not observations['reports'], ('unexpected exec', mode, fault)
            assert not list((root / 'store/objects').iterdir()), 'runtime/root scratch not reclaimed'
            for event in json.loads(item['stdout'])['events']:
                if 'receive' in event and event['receive']['type'] == 'spawn_prepared':
                    pid = event['receive']['child_pid']
                    assert not Path(f'/proc/{pid}').exists(), ('unreaped child', pid)
            observations['checks'] = 'passed'

        case('normal', production=True)
        if not args.smoke and not args.storage_only:
            case('parallel', production=True)
            case('budget', production=True)
            case('repeated', production=True)
            case('stop', production=True)
            case('control-loss', production=True)
            case('busy', production=True)
            case('bad-uid', production=True)
            case('bad-gid', production=True)
            case('invalid-control', production=True)
            case('wrong-commit', production=True)
            case('no-commit', production=True)
            case('normal', fault='channel_at_three')
            case('stall-first', fault='stall.copy')
            case('kill-error', fault='kill')
            case('reap-error', fault='reap.echild')
            case('reap-control-loss', fault='reap.echild')
            case('reap-parallel', fault='reap.second.echild')
            case('cleanup-progress', fault='stall.cleanup')
            case('worker-loss', fault='worker.exit')
            case('worker-loss', fault='worker.result')
            case('storage-retry', fault='delete.once')
            case('storage-retry', fault='delete.fsync.once')
            case('normal', fault='delete.fsync.late')
            case('stop-create', fault='worker.ready.late')
            case('storage-retained', fault='delete.unlink')
            case('storage-retained', fault='delete.fsync')
            for point in ('no_new_privs', 'bounding', 'groups', 'gid', 'uid', 'uid.reread', 'caps', 'ambient'):
                case('worker-init', fault='worker.drop.'+point)
            for point in ('mkdir', 'directory', 'open', 'verify', 'chmod', 'symlink', 'tree_verify', 'statvfs'):
                case('fault', fault='create.'+point, stage='validate')
            case('kill-no-fact', fault='kill.esrch')
            case('kill-no-fact', fault='kill.no-effect')
            for fault, stage in FAULTS:
                case('fault', fault, stage)
        if not args.smoke:
            case('slow-eof', fault='delete.slow')
            filesystem_failures()
            case('normal', production=True)
        record['result'] = 'passed'
    except BaseException as exc:
        record['error'] = repr(exc)
        record['traceback'] = traceback.format_exc()
        record['result'] = 'failed'
        print(json.dumps({'error': repr(exc)}), flush=True)
    finally:
        try:
            adopted = []
            until = time.monotonic() + 4
            while True:
                children = [int(p) for p in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()]
                if not children:
                    break
                assert time.monotonic() < until, 'external supervisor cleanup deadline'
                for pid in children:
                    try:
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        pass
                    got, status = os.waitpid(pid, os.WNOHANG)
                    if got:
                        adopted.append({'pid': got, 'wait_status': status})
                time.sleep(.01)
            if adopted:
                record['emergency_supervisor_reaps'] = adopted
                record['result'] = 'failed'
            for target in reversed(workspace_binds):
                command(['/usr/bin/umount', target])
            if workspace_mounted:
                command(['/usr/bin/umount', workspace_storage])
            if mounted:
                command(['/usr/bin/umount', root])
            loops = command(['/usr/sbin/losetup', '--list', '--json', '--associated', image])
            assert not json.loads(loops['stdout']).get('loopdevices')
            workspace_loops = command(['/usr/sbin/losetup', '--list', '--json', '--associated', workspace_image])
            assert not json.loads(workspace_loops['stdout']).get('loopdevices')
            assert root.parent == Path('/var/lib') and root.name == 'w2-sandbox-' + args.label
            root.rmdir()
            assert scratch.parent == Path('/tmp') and scratch.name.startswith('w2-p2a-sandbox-')
            assert not any(line.split()[4] == str(scratch) or line.split()[4].startswith(str(scratch)+'/')
                           for line in Path('/proc/self/mountinfo').read_text().splitlines())
            shutil.rmtree(scratch)
            if own_build:
                assert build.parent == Path('/tmp') and build.name.startswith('w2-p2a-build-')
                shutil.rmtree(build)
            record['cleanup'] = {'deployment_removed': not root.exists(), 'scratch_removed': not scratch.exists(), 'loop_detached': True}
        except BaseException as exc:
            record['cleanup_error'] = repr(exc)
            record['result'] = 'failed'
        record['finished_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with record_path.open('x') as out:
            json.dump(record, out, ensure_ascii=False, indent=2)
            out.write('\n')
    print(json.dumps({'record': str(record_path), 'result': record['result']}), flush=True)
    return 0 if record['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
