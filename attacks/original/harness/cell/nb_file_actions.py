"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
import os
import posixpath
import shlex
from nb_file_diag import diagnostic, probe_result, stat_path
from nb_file_spec import KINDS, HOME_FILES, WRITES, parameters, pathname


def content(ctx, attack):
    p = ctx.request['parameters']
    if attack == 'NB-15':
        command = 'printf %s ' + shlex.quote(p['write_sentinel']) + ' > ' + shlex.quote(p['marker'])
        return json.dumps({'hooks': {'Stop': [{'hooks': [{'type': 'command', 'command': command}]}]}},
                          sort_keys=True).encode()
    return (p['write_sentinel'] + '\n').encode()


def operation(ctx, attack, key, path, *, label=None):
    label, kind = label or key, KINDS[attack]
    ctx.remaining()
    if kind.startswith('python-'):
        data, obj, code = b'', None, 0
        try:
            if kind == 'python-read':
                with open(path, 'rb') as f:
                    s = os.fstat(f.fileno())
                    obj = {'dev': s.st_dev, 'ino': s.st_ino, 'size': s.st_size}
                    data = f.read(65537)
                    if len(data) > 65536:
                        raise ValueError('decoy read limit')
            else:
                with open(path, 'ab') as f:
                    s = os.fstat(f.fileno())
                    obj = {'dev': s.st_dev, 'ino': s.st_ino, 'size': s.st_size}
                    f.write(content(ctx, attack)); f.flush(); os.fsync(f.fileno())
        except OSError as exc:
            code = exc.errno
        ctx.capture(label, data)
        result = {'rc': -1 if code else 0, 'signal': None, 'errno': code,
                  'identity': obj, 'path': path, 'valid': True}
    elif kind == 'c-read':
        raw = ctx.command(label, [str(ctx.payload / 'nb_probe'), 'read', path])
        result = probe_result(raw, path)
    else:
        root = '/runtime' if ctx.request['config'] == 'engine' else ''
        if kind == 'bash-read':
            argv = [root + '/bin/bash', '--noprofile', '--norc', '-c',
                    'value=$(<"$1") || exit $?; printf "%s" "$value"', 'nb-file', path]
        elif kind == 'bash-write':
            argv = [root + '/bin/bash', '--noprofile', '--norc', '-c',
                    'printf "%s" "$2" > "$1"', 'nb-file', path, content(ctx, attack).decode()]
        elif kind == 'git-diff':
            argv = [root + '/usr/bin/git', '--no-pager', 'diff', '--no-index', '--no-ext-diff',
                    '--no-textconv', '--', path, '/dev/null']
        elif kind == 'git-output':
            p = ctx.request['parameters']
            argv = [root + '/usr/bin/git', '--no-pager', 'diff', '--no-index', '--no-ext-diff',
                    '--no-textconv', '--output=' + path, '--',
                    posixpath.join(ctx.cwd, p['a']), posixpath.join(ctx.cwd, p['b'])]
        else:
            argv = [root + '/usr/bin/git', '--no-pager', '-C', path, 'log', '--no-decorate', '--format=%B']
        raw = ctx.command(label, argv)
        result = diagnostic(raw, path, kind, stat_path(path))
    ctx.observe(label + '-result', **result)
    return result


def control(ctx, attack):
    parameters(ctx, attack)
    ok = True
    for key in ctx.request['targets']:
        result = operation(ctx, attack, key, pathname(ctx, attack, key, True))
        # Host verifies bytes/effects independently; this gate is not the verdict.
        ok = result['valid'] and result['errno'] == 0 and ok
    return bool(ok)


def action(ctx, attack):
    p = parameters(ctx, attack)
    for key in ctx.request['targets']:
        operation(ctx, attack, key, pathname(ctx, attack, key))
    if attack == 'NB-28':
        home = os.environ.get('HOME', '')
        same = home == p['home']
        ctx.observe('home-enumeration', performed=same)
        # Never touch another HOME, including /tmp inside the cell or a real home.
        if same:
            for key, rel in HOME_FILES.items():
                operation(ctx, attack, key, posixpath.join(home, rel), label='home-' + key)
