"""这是 1.1 隔离论证的验证测试：不设防身份与目录搜索预检；只读元数据，不连接服务。"""
import json
import os
from pathlib import Path
import stat
import sys


def credentials(text, groups):
    """Check actual post-setpriv credentials, not the controller's uid."""
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    result = {key: [int(v) for v in fields[key].split()] for key in ('Uid', 'Gid', 'Groups')}
    result.update({key: int(fields[key], 16) for key in
                   ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')})
    result['NoNewPrivs'] = int(fields['NoNewPrivs'])
    result['ok'] = (result['Uid'] == [1000] * 4 and result['Gid'] == [1000] * 4
                    and sorted(set(result['Groups'])) == sorted(set(groups))
                    and all(result[k] == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
                    and result['NoNewPrivs'] == 1)
    return result


def directory_facts(directories):
    """Inspect every lexical ancestor; never open a target's content or socket."""
    paths = set()
    for name in directories:
        p = Path(name)
        if not p.is_absolute() or '..' in p.parts:
            raise ValueError('absolute normalized directory required')
        paths.update([p, *p.parents])
    result = []
    for p in sorted(paths):
        item = {'path': str(p), 'searchable': False, 'errno': None}
        try:
            s = p.stat()
            item.update(directory=stat.S_ISDIR(s.st_mode), uid=s.st_uid, gid=s.st_gid,
                        mode=stat.S_IMODE(s.st_mode), dev=s.st_dev, ino=s.st_ino,
                        searchable=stat.S_ISDIR(s.st_mode) and os.access(p, os.X_OK))
        except OSError as exc:
            item['errno'] = exc.errno
        result.append(item)
    return result


def check_directories(runtime, directories):
    """Authorized runtime only; the supervisor archives raw stdout on failure too."""
    from run_rows import as_host
    groups = runtime.host['host_user']['groups']
    names = sorted({str(p) for p in directories})
    runtime.command([*as_host(groups), '/usr/bin/python3.12', '-I', '-B',
                     str(Path(__file__).absolute()), ','.join(map(str, groups)), *names], timeout=5)


def launch_context(runtime, workspace):
    """Bind HOME/cwd/payload to this run before creating an undefended process."""
    from safeio import plain_path
    home = Path(runtime.home)
    from run_transport import workspace_entry
    work = Path(workspace_entry(runtime, workspace, 'undefended')['mount'])  # the host user's own (tests.md 1.7)
    payload = Path(runtime.payload['runner.py'])
    base = Path(runtime.deployment.scratch) / 'host'
    if home != base and base not in home.parents:
        raise ValueError('undefended HOME is not this run\'s decoy home')
    for p in (home, work, payload):
        if not any(p == root or root in p.parents for root in runtime.resources.roots):
            raise ValueError('undefended HOME/cwd/payload outside owned run roots')
        plain_path(p)
    if not home.is_dir() or not work.is_dir() or not payload.is_file():
        raise ValueError('undefended HOME/cwd/payload type mismatch')
    owner = home.stat()
    if (owner.st_uid, owner.st_gid) != (1000, 1000):
        raise ValueError('undefended HOME must belong to uid/gid 1000')
    check_directories(runtime, [home, work, payload.parent])
    environment={'HOME':str(home)}
    extra=getattr(runtime,'undefended_environment',{})
    if extra:
        if runtime.bundle.get('unit')!='credential-binding' or set(extra)!={'NB_DECOY_CREDENTIAL','NB_DECOY_MARKER'}:
            raise ValueError('unregistered undefended environment keys')
        if any(not isinstance(v,str) or len(v)>4096 or '\x00' in v for v in extra.values()):
            raise ValueError('invalid bounded synthetic environment')
        environment.update(extra)
    return work, environment


def main(argv):
    if len(argv) < 2 or len(argv) > 128:
        raise ValueError('expected groups and bounded directory list')
    groups = [int(v) for v in argv[0].split(',')]
    if not groups or any(v < 0 for v in groups):
        raise ValueError('explicit nonnegative groups required')
    report = {'kind': 'undefended-preflight', 'identity': None, 'directories': [], 'error': None}
    try:
        report['identity'] = credentials(Path('/proc/self/status').read_text(), groups)
        report['directories'] = directory_facts(argv[1:])
    except (OSError, ValueError, KeyError) as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)[:512]
    report['ok'] = (not report['error'] and report['identity']['ok']
                    and all(p['searchable'] for p in report['directories']))
    print(json.dumps(report, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
