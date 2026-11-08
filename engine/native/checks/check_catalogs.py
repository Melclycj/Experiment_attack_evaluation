"""Independent malformed deployment inputs against the actual cell preflight.

The caller owns this disposable deployment and runs this only between epochs.
Each variant is restored; these mutations are not a model/task interface.
"""
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def main():
    root, cell = Path(sys.argv[1]), sys.argv[2]
    # The short-lived positive-control engine leaves its spawner to the test
    # supervisor. Keep that real wait here, before returning to the outer suite.
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
    original = {p.name: p.read_bytes() for p in root.glob('*.json')}
    results = []

    def traced(argv):
        with tempfile.NamedTemporaryFile(prefix='w2-preflight-trace-', mode='r+') as trace:
            p = subprocess.run(['/usr/bin/strace', '-f', '-qq', '-s', '256',
                                '-e', 'trace=clone,clone3,fork,vfork,execve',
                                '-o', trace.name, *argv], capture_output=True, text=True, timeout=8)
            trace.seek(0)
            raw = trace.read()
        assert 'execve(' in raw, ('tracer did not observe target exec', p.stderr, raw)
        # Match syscall entries after the traced PID, never text in exec argv.
        attempts = re.findall(r'(?m)^\d+\s+(?:clone|clone3|fork|vfork)\(', raw)
        waited = []
        deadline = time.monotonic() + 5
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid:
                assert os.WIFEXITED(status) or os.WIFSIGNALED(status), (pid, status)
                waited.append({'pid': pid, 'wait_status': status})
            else:
                assert time.monotonic() < deadline, 'traced descendant not terminated'
                time.sleep(.01)
        return p, {'process_creation_attempts': len(attempts), 'raw': raw,
                   'test_supervisor_waits': waited}

    # Positive control: the same observer must see an actual child creation.
    control, trace = traced(['/usr/bin/python3', '-c',
        'import os; p=os.fork(); os._exit(0) if p==0 else os.waitpid(p,0)'])
    assert control.returncode == 0 and trace['process_creation_attempts'] >= 1, trace
    tracer_control = {'exit_code': control.returncode, **trace}
    # A valid catalog must still pass with this tracer attached: reaching the
    # unprivileged engine exec prevents a tracer-induced universal rejection
    # from making every malformed-input test pass for the wrong reason.
    control, trace = traced([cell, str(root), 'catalog.json', '1000', '1000', '/usr/bin/true'])
    assert control.returncode == 0 and trace['process_creation_attempts'] >= 2, (control.stderr, trace)
    assert 'execve("/usr/bin/true"' in trace['raw'], trace
    assert not list((root / 'store/objects').iterdir())
    valid_catalog_control = {'exit_code': control.returncode, 'stdout': control.stdout,
                             'stderr': control.stderr, **trace}

    def load(name):
        return json.loads((root / name).read_bytes())

    def write(name, obj):
        (root / name).write_text(json.dumps(obj, separators=(',', ':')) + '\n')

    def relink():
        catalog = load('catalog.json')
        catalog['storage_profile']['artifact_digest'] = sha((root / catalog['storage_profile']['artifact_ref']).read_bytes())
        for runtime in catalog['runtimes']:
            descriptor = load(runtime['descriptor_ref'])
            component = sha((root / descriptor['component_manifest_ref']).read_bytes())
            descriptor['component_manifest_digest'] = descriptor['artifact_digest'] = component
            write(runtime['descriptor_ref'], descriptor)
            runtime['descriptor_digest'] = sha((root / runtime['descriptor_ref']).read_bytes())
        for policy in catalog['policies']:
            policy['artifact_digest'] = sha((root / policy['artifact_ref']).read_bytes())
        for profile in catalog['profiles']:
            profile['artifact_digest'] = sha((root / profile['artifact_ref']).read_bytes())
        for entry in catalog['plans']:
            p = load(entry['artifact_ref'])
            runtime = next(r for r in catalog['runtimes'] if load(r['descriptor_ref'])['runtime_id'] == p['runtime_id'])
            p['runtime_descriptor_digest'] = runtime['descriptor_digest']
            p['policy_digest'] = catalog['policies'][0]['artifact_digest']
            p['isolation_profile_digest'] = catalog['profiles'][0]['artifact_digest']
            write(entry['artifact_ref'], p)
            entry['artifact_digest'] = sha((root / entry['artifact_ref']).read_bytes())
        write('catalog.json', catalog)

    def variant(name, change, fix_references=True, cleanup=None):
        try:
            change()
            if fix_references:
                relink()
            p, trace = traced([cell, str(root), 'catalog.json', '1000', '1000', '/usr/bin/true'])
            results.append({'case': name, 'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr,
                            'process_trace': trace,
                            'input_digests': {f.name: sha(f.read_bytes()) for f in root.glob('*.json')}})
            assert p.returncode == 2, (name, p.returncode, p.stdout, p.stderr)
            assert trace['process_creation_attempts'] == 0, (name, trace)
            assert not list((root / 'store/objects').iterdir()), name
        finally:
            if cleanup:
                cleanup()
            for filename, data in original.items():
                (root / filename).write_bytes(data)
                (root / filename).chmod(0o644)

    def mutate(name, fn):
        value = load(name)
        fn(value)
        write(name, value)

    variant('duplicate-json-key', lambda: (root / 'catalog.json').write_bytes(original['catalog.json'].replace(b'"v":1', b'"v":1,"v":1', 1)), False)
    variant('invalid-utf8', lambda: (root / 'catalog.json').write_bytes(b'{"v":"\xff"}'), False)
    variant('trailing-json', lambda: (root / 'catalog.json').write_bytes(original['catalog.json'] + b'{}'), False)
    variant('unknown-catalog-field', lambda: mutate('catalog.json', lambda d: d.update(secret='forbidden')), False)
    variant('duplicate-runtime-id', lambda: mutate('catalog.json', lambda d: d['runtimes'].append(copy.deepcopy(d['runtimes'][0]))), False)
    variant('catalog-item-limit', lambda: mutate('catalog.json', lambda d: d.update(runtimes=d['runtimes'][:1] * 65)), False)
    for name, fields in [
        ('wrong-executable-root', {'executable': '/bin/agent-fixture'}),
        ('wrong-cwd', {'cwd': '/tmp'}),
        ('wrong-protocol', {'protocol': 'w2-local/1'}),
        ('wrong-argv-zero', {'argv': ['/runtime/bin/other']}),
        ('argv-limit', {'argv': ['/runtime/bin/agent-fixture'] * 65}),
        ('string-limit', {'argv': ['/runtime/bin/agent-fixture', 'x' * 4097]}),
        ('total-argument-limit', {'argv': ['/runtime/bin/agent-fixture'] + ['x' * 4096] * 4}),
        ('nul-string', {'argv': ['/runtime/bin/agent-fixture', 'a\x00b']}),
        ('invalid-env-key', {'env': {'1BAD': 'value'}}),
        ('inline-flags', {'clone_flags': 0}),
        ('null-executable', {'executable': None}),
        ('v1-adapter-field', {'adapter_id': 'fixture'}),   # removed in v2 (build plan 7.3): now an unknown field
        ('dependency-mismatch', {'dependency_digest': 'sha256:'+'0'*64}),
        ('unknown-storage-profile', {'storage_profile_id': 'unregistered'}),
    ]:
        variant(name, lambda fields=fields: mutate('observe.json', lambda d: d.update(fields)))
    for name in ('bind', 'connect', 'io_uring_setup', 'io_uring_enter', 'io_uring_register', 'clone3', 'sysinfo', 'sync', 'syncfs'):
        variant('forbidden-policy-' + name, lambda name=name: mutate('policy.json', lambda d: d['allow'].append(name)))
    variant('default-allow-policy', lambda: mutate('policy.json', lambda d: d.update(default_action='allow')))
    variant('policy-wrong-abi', lambda: mutate('policy.json', lambda d: d.update(target_arch='i386')))
    variant('policy-empty', lambda: (root / 'policy.json').write_bytes(b''))
    variant('policy-digest-mismatch', lambda: (root / 'policy.json').write_bytes(original['policy.json'] + b' '), False)
    variant('unknown-plan-field', lambda: mutate('plan-observe-0.json', lambda d: d.update(workspace_path='/etc')))
    variant('workspace-uid-mismatch', lambda: mutate('catalog.json', lambda d: d['workspaces'][0].update(workspace_uid=70002)), False)
    variant('workspace-overflow-uid', lambda: mutate('catalog.json', lambda d: d['workspaces'][0].update(workspace_uid=65534)), False)
    variant('workspace-reused-uid', lambda: mutate('catalog.json', lambda d: d['workspaces'][1].update(workspace_uid=70000)), False)
    # the workspace rework (validation.md S-22): the owner is a dedicated uid, never the engine's (cell.c, 1000 here),
    # the connector's or the PDP's (catalog.c). The storage is chowned to match, so only the new check can refuse it.
    work0 = root / 'work0'
    owner = os.stat(work0)

    def owned_by(uid, gid):
        def change():
            os.chown(work0, uid, gid)
            mutate('catalog.json', lambda d: d['workspaces'][0].update(workspace_uid=uid, workspace_gid=gid))
        return change

    def restore_owner():
        os.chown(work0, owner.st_uid, owner.st_gid)
    connector, pdp = load('catalog.json')['connector'], load('catalog.json')['pdp']
    for name, uid, gid in (('workspace-owned-by-engine-uid', 1000, owner.st_gid),
                           ('workspace-owned-by-engine-gid', owner.st_uid, 1000),
                           ('workspace-owned-by-connector', connector['uid'], owner.st_gid),
                           ('workspace-owned-by-pdp', pdp['uid'], owner.st_gid)):
        variant(name, owned_by(uid, gid), False, cleanup=restore_owner)
    # phase 2 (validation.md K-48, D-13): the PDP identity outside the range and apart from the connector's
    variant('pdp-missing', lambda: mutate('catalog.json', lambda d: d.pop('pdp')), False)
    variant('pdp-in-range', lambda: mutate('catalog.json', lambda d: d['pdp'].update(uid=70003)), False)
    variant('pdp-is-connector', lambda: mutate('catalog.json', lambda d: d['pdp'].update(uid=d['connector']['uid'])), False)
    variant('pdp-zero', lambda: mutate('catalog.json', lambda d: d['pdp'].update(uid=0)), False)
    variant('pdp-extra-field', lambda: mutate('catalog.json', lambda d: d['pdp'].update(path='/x')), False)
    # validation.md H-14: the file worker's identity outside the range, apart from the connector's, the PDP's, every
    # workspace owner's (catalog.c) and the engine's (cell.c, 1000 here)
    variant('file-worker-missing', lambda: mutate('catalog.json', lambda d: d.pop('file_worker')), False)
    for name, change in (('in-range', {'uid': 70003}), ('gid-in-range', {'gid': 70003}), ('is-connector', {'uid': 70999}),
                         ('is-pdp', {'uid': 70998}), ('zero', {'uid': 0}), ('gid-zero', {'gid': 0}),
                         ('overflow', {'uid': 65534}), ('is-engine', {'uid': 1000}), ('gid-is-engine', {'gid': 1000}),
                         ('extra-field', {'path': '/x'}), ('relative-executable', {'executable': 'stub'})):
        variant('file-worker-' + name, lambda change=change: mutate('catalog.json', lambda d: d['file_worker'].update(change)),
                False)
    variant('workspace-owned-by-file-worker', owned_by(load('catalog.json')['file_worker']['uid'], owner.st_gid), False,
            cleanup=restore_owner)
    # validation.md H-23: the in-cell MCP server, a program in the frontend's form, and its port in 1-65535 and apart
    # from the proxy port (catalog.c)
    variant('mcp-server-missing', lambda: mutate('catalog.json', lambda d: d.pop('mcp_server')), False)
    variant('mcp-port-missing', lambda: mutate('catalog.json', lambda d: d.pop('mcp_port')), False)
    for name, value in (('zero', 0), ('is-proxy-port', 3128), ('over-65535', 65536), ('negative', -1), ('text', '3129')):
        variant('mcp-port-' + name, lambda value=value: mutate('catalog.json', lambda d: d.update(mcp_port=value)), False)
    for name, change in (('relative-executable', {'executable': 'engine-mcp', 'argv': ['engine-mcp']}),
                         ('argv-zero-differs', {'argv': ['/runtime/bin/other']}), ('empty-argv', {'argv': []}),
                         ('extra-field', {'uid': 70996})):
        variant('mcp-server-' + name, lambda change=change: mutate('catalog.json', lambda d: d['mcp_server'].update(change)),
                False)

    def nested_cell_files():                    # cold review 2026-11-01 (S-20): child.c mounts the reference by path
        (root / 'nest').mkdir(mode=0o755)
        shutil.copytree(root / 'w2', root / 'nest/w2', symlinks=True)
        mutate('catalog.json', lambda d: d.update(cell_files_ref='nest/w2'))

    variant('nested-cell-files-ref', nested_cell_files, False, lambda: shutil.rmtree(root / 'nest'))
    variant('mutable-policy-leaf', lambda: (root / 'policy.json').chmod(0o666), False)
    variant('unlisted-runtime-file', lambda: (root / 'seed/extra').write_text('extra'), False,
            lambda: (root / 'seed/extra').unlink())
    variant('cross-artifact-hardlink', lambda: os.link(root / 'seed/bin/agent-fixture', root / 'extra-link'), False,
            lambda: (root / 'extra-link').unlink())

    def symlink_escape():
        (root / 'seed/link').unlink()
        (root / 'seed/link').symlink_to('/etc/passwd')
        mutate('components.json', lambda d: d['files'][-1].update(target='/etc/passwd', size=len('/etc/passwd')))

    def restore_link():
        (root / 'seed/link').unlink()
        (root / 'seed/link').symlink_to('bin/agent-fixture')

    variant('symlink-escape', symlink_escape, True, restore_link)

    def mutable_parent():
        (root / 'mutable').mkdir(mode=0o777)
        (root / 'mutable').chmod(0o777)
        (root / 'mutable/policy.json').write_bytes(original['policy.json'])
        (root / 'mutable/policy.json').chmod(0o644)
        mutate('catalog.json', lambda d: d['policies'][0].update(artifact_ref='mutable/policy.json'))

    def remove_mutable():
        (root / 'mutable/policy.json').unlink()
        (root / 'mutable').rmdir()

    variant('replaceable-policy-parent', mutable_parent, True, remove_mutable)
    variant('unordered-manifest-parent', lambda: mutate('components.json', lambda d: d['files'].reverse()))
    # phase 2 (validation.md U-03): the two other manifest shapes the path table must judge as the loops did
    variant('duplicate-manifest-path', lambda: mutate('components.json', lambda d: d['files'].append(copy.deepcopy(d['files'][-1]))))
    variant('missing-manifest-parent', lambda: mutate('components.json',
            lambda d: d.update(files=[f for f in d['files'] if f['path'] != 'bin'])))
    for name, fields in (
        ('wrong-uuid', {'filesystem_uuid': '0'*36}),
        ('wrong-capacity', {'filesystem_capacity_bytes': '1'}),
        ('too-small-reserve', {'max_reserved_bytes': '1'}),
        ('too-small-free-floor', {'min_free_bytes': '1'}),
        ('too-small-node-budget', {'max_reserved_nodes': '1'}),
        ('overflow-budget', {'max_reserved_bytes': '18446744073709551615'}),
        ('wrong-owner', {'owner_uid': 70000}),
        ('wrong-objects-ref', {'objects_ref': 'seed'}),
        ('wrong-copy-count', {'max_copies': 17}),
        ('wrong-timeout', {'cleanup_timeout_ms': 999}),
    ):
        variant('storage-'+name, lambda fields=fields: mutate('storage.json', lambda d: d.update(fields)))
    variant('directory-0555-rejected-by-new-manifest', lambda: ((root / 'seed/bin').chmod(0o555),
            mutate('components.json', lambda d: d['files'][0].update(mode=0o555))), True,
            lambda: (root / 'seed/bin').chmod(0o755))
    variant('seed-file-capability-rejected', lambda: os.setxattr(root / 'seed/bin/agent-fixture', 'security.capability',
            bytes.fromhex('0100000201000000000000000000000000000000')), False,
            lambda: os.removexattr(root / 'seed/bin/agent-fixture', 'security.capability'))
    capabilities = ('sys_admin', 'setuid', 'setgid', 'setpcap', 'net_admin', 'kill')
    for missing in capabilities:
        admitted = ','.join('+'+name for name in capabilities if name != missing)
        argv = ['/usr/bin/setpriv', '--bounding-set=-all,'+admitted,
                '--inh-caps=-all', '--ambient-caps=-all', cell, str(root),
                'catalog.json', '1000', '1000', '/usr/bin/true']
        p, trace = traced(argv)
        assert p.returncode == 2 and not list((root / 'store/objects').iterdir()), missing
        assert trace['process_creation_attempts'] == 0, (missing, trace)
        results.append({'case': 'withdraw-cap-'+missing, 'argv': argv, 'exit_code': p.returncode,
                        'stdout': p.stdout, 'stderr': p.stderr, 'process_trace': trace})
    print(json.dumps({'tracer_positive_control': tracer_control, 'valid_catalog_control': valid_catalog_control,
                      'catalog_negative_checks': results, 'result': 'passed'}), flush=True)


if __name__ == '__main__':
    main()
