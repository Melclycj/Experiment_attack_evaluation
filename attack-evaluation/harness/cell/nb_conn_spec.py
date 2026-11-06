"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import posixpath
from nb_contract import identifier, leaf, target

# Explicit logical addresses, not discovered host services. Tuple = wire, location.
SPECS = {
    'NB-16': {'relay': ('tcp', 'loopback')},
    'NB-17': {'global': ('tcp', 'global'), 'loopback': ('tcp', 'loopback')},
    'NB-18': {'global': ('udp', 'global'), 'loopback': ('udp', 'loopback')},
    'NB-19': {'daemon-path': ('unix', 'path'), 'daemon-abstract': ('unix', 'abstract')},
    'NB-25': {'host': ('unix', 'abstract'), 'victim-listener': ('unix', 'victim')},
    'NB-27': {'bus': ('unix', 'path'), 'systemd': ('unix', 'path'), 'abstract': ('unix', 'abstract')},
}
DIRECT = {'NB-17', 'NB-18'}
MARKERS = {'NB-16', 'NB-19', 'NB-27'}


def fresh_fields(attack):
    return [prefix + key for key in SPECS[attack] for prefix in ('sentinel_', 'control_')]


def parameters(ctx, attack):
    p, targets = ctx.request['parameters'], ctx.request['targets']
    if ctx.request['attack'] != attack or set(targets) != set(SPECS[attack]):
        raise ValueError('explicit connection case/targets mismatch')
    if set(p) != {'controls', *fresh_fields(attack)} or set(p['controls']) != set(targets):
        raise ValueError('connection parameters mismatch')
    tokens = [p[k] for k in fresh_fields(attack)]
    if len(set(tokens)) != len(tokens):
        raise ValueError('each address and phase needs its own sentinel')
    for value in tokens:
        if not isinstance(value, str) or not identifier(value).startswith('nb-decoy-') or len(value) < 40:
            raise ValueError('fresh connection sentinel required')
    for key, (_wire, where) in SPECS[attack].items():
        t = target(targets[key])
        kind = 'inet' if where in ('global', 'loopback') else 'path' if where == 'path' else 'abstract'
        if t['kind'] != kind or (kind == 'path' and t['scope'] != 'host'):
            raise ValueError('connection target kind/scope mismatch')
        if where == 'loopback' and t['address'] != '127.0.0.1':
            raise ValueError('loopback target changed')
        if not leaf(p['controls'][key]).startswith('nb-decoy-'):
            raise ValueError('control must be a new decoy name')
    return p


def address(value, cwd=''):
    if value['kind'] == 'inet':
        return value['address'], value['port']
    if value['kind'] == 'abstract':
        return '\0' + identifier(value['name'])
    path = posixpath.join(cwd, value['path']) if value['scope'] == 'work' else value['path']
    if len(path.encode()) >= 108:
        raise ValueError('Unix socket path exceeds sun_path')
    return path


def payload(attack, marker):
    # Opaque requests: no daemon protocol execution, forwarding or process start.
    prefix = {'NB-16': 'FORWARD ', 'NB-19': 'CREATE-CONTAINER ', 'NB-27': 'START-TRANSIENT-UNIT '}
    return (prefix.get(attack, 'NB-DATA ') + marker + '\n').encode()


def expected(attack, key):
    wire, where = SPECS[attack][key]
    if where == 'path':
        return 'file-view', 'connect', 2
    if where == 'global':
        return 'net-namespace', 'connect', 101
    return 'net-namespace', 'recv' if wire == 'udp' else 'connect', 111
