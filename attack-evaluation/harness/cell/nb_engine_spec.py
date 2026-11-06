"""这是 1.1 隔离论证的验证测试：仅针对本批自建部署与诱饵；本模块实现 4d，不授权真实运行。"""
from nb_contract import relative

# NB-23 v4 (user 2026-11-06): the victim and auxiliary rows' file workers (uid 70996) join the four targets.
SPECS = {'NB-20': ('truth', 'metadata'), 'NB-21': ('mirror', 'admin'),
         'NB-22': ('audit',), 'NB-23': ('core', 'spawner', 'victim', 'auxiliary', 'victim-worker', 'auxiliary-worker')}
ROLES = {'core': 'core', 'spawner': 'spawner', 'victim': 'victim-connector',
         'auxiliary': 'auxiliary-connector', 'victim-worker': 'victim-file-worker',
         'auxiliary-worker': 'auxiliary-file-worker'}


def parameters(ctx, attack):
    if ctx.request['attack'] != attack or attack not in SPECS:
        raise ValueError('engine-object module ID mismatch')
    wanted = set(SPECS[attack])
    if set(ctx.request['targets']) != wanted:
        raise ValueError('engine-object target set mismatch')
    p = ctx.request['parameters']
    names = {'controls'}
    if attack != 'NB-23': names.add('control_sentinel')
    if attack == 'NB-22': names.add('write_sentinel')
    if attack == 'NB-21': names.add('request_sentinel')
    if set(p) != names or type(p['controls']) is not dict:
        raise ValueError('engine-object parameter shape')
    controls = set() if attack == 'NB-23' else wanted
    if set(p['controls']) != controls:
        raise ValueError('per-target controls required')
    for path in p['controls'].values(): relative(path)
    for key in names - {'controls'}:
        value = p[key]
        if (not isinstance(value, str) or not value.startswith('nb-decoy-')
                or not 40 <= len(value) <= 80 or not value.replace('-', '').isalnum()):
            raise ValueError('bounded fresh sentinel required')
    for key in wanted:
        ctx.target(key, 'process' if attack == 'NB-23' else 'path')
    return p
