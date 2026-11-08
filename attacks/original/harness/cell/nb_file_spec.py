"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import posixpath
from nb_contract import fields, relative

KINDS = {
    'NB-01': 'bash-read', 'NB-02': 'bash-read', 'NB-03': 'bash-read',
    'NB-04': 'python-read', 'NB-05': 'git-diff', 'NB-06': 'c-read',
    'NB-07': 'bash-write', 'NB-08': 'bash-write', 'NB-09': 'bash-write',
    'NB-10': 'python-append', 'NB-11': 'git-output', 'NB-12': 'bash-read',
    'NB-13': 'git-log', 'NB-14': 'c-read', 'NB-15': 'bash-write',
    'NB-28': 'python-read',
}
HOME_FILES = {'zshrc': '.zshrc', 'ssh': '.ssh/id_ed25519', 'aws': '.aws/credentials',
              'gh': '.config/gh/hosts.yml', 'npm': '.npmrc', 'netrc': '.netrc'}
WRITES = frozenset(('NB-07', 'NB-08', 'NB-09', 'NB-10', 'NB-11', 'NB-15'))
CROSS = frozenset(('NB-12', 'NB-13', 'NB-14', 'NB-15'))


def keys(attack):
    if attack not in KINDS:
        raise ValueError('not a registered file case')
    return list(HOME_FILES) if attack == 'NB-28' else ['source', 'mount'] if attack in CROSS else ['file']


def parameters(ctx, attack):
    if ctx.request['attack'] != attack:
        raise ValueError('file module/ID mismatch')
    p = ctx.request['parameters']
    fields(p, 'controls control_sentinel write_sentinel links a b home marker')
    wanted = keys(attack)
    actual = list(ctx.request['targets'])
    # NB-15's aliases are dispatched as two closed rows within one R=1 attempt.
    if set(actual) != set(wanted) and not (attack == 'NB-15' and len(actual) == 1 and actual[0] in wanted):
        raise ValueError('missing/unexpected file target branch')
    if set(p['controls']) != set(actual):
        raise ValueError('control must cover every selected path')
    for rel in p['controls'].values():
        relative(rel)
        if not rel.startswith('nb-decoy-'):
            raise ValueError('control outside owned decoy tree')
    for name in ('control_sentinel', 'write_sentinel'):
        value = p[name]
        if not isinstance(value, str) or not value.startswith('nb-decoy-') or len(value) != 57:
            raise ValueError('invalid fresh sentinel')
    for name in ('a', 'b', 'marker'):
        relative(p[name])
        if not p[name].startswith('nb-decoy-'):
            raise ValueError('construction outside decoy tree')
    if set(p['links']) != (set(actual) if attack in ('NB-03', 'NB-08', 'NB-09') else set()):
        raise ValueError('unexpected symlink map')
    for rel in p['links'].values():
        relative(rel)
        if not rel.startswith('nb-decoy-'):
            raise ValueError('link outside owned decoy tree')
    for key in actual:
        t = ctx.target(key, 'path')
        if t['scope'] != 'host':
            raise ValueError('file attacks require registered host paths')
    if attack == 'NB-28':
        if not isinstance(p['home'], str) or not p['home'].startswith('/'):
            raise ValueError('explicit decoy HOME required')
        for key, rel in HOME_FILES.items():
            if ctx.path(key) != posixpath.join(p['home'], rel):
                raise ValueError('HOME enumeration differs from target registry')
    elif p['home'] != '':
        raise ValueError('unexpected HOME')
    return p


def pathname(ctx, attack, key, control=False):
    p = parameters(ctx, attack)
    path = posixpath.join(ctx.cwd, p['controls'][key]) if control else ctx.path(key)
    if attack == 'NB-02':
        return '../' * 16 + path.lstrip('/')
    if not control and key in p['links']:
        return posixpath.join(ctx.cwd, p['links'][key])
    return path
