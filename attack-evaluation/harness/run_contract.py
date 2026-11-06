"""逐配置目标适用性校验：只表达已批准的 NB-23 差异，不豁免逐目标不设防前提。"""
from common import token


def validate_contract(contract, attack):
    if (not isinstance(contract, dict) or contract.get('attack') != attack
            or not contract.get('construction') or not contract.get('operations')
            or any(k in contract for k in ('config', 'sync', 'nonce'))):
        raise ValueError('missing/shared action contract or contains envelope fields')
    targets = contract.get('targets')
    if not isinstance(targets, list) or not 1 <= len(targets) <= 64:
        raise ValueError('contract needs bounded logical target IDs')
    for key in targets:
        token(key)
    if len(set(targets)) != len(targets):
        raise ValueError('duplicate contract target')
    roles = contract.get('process_roles', {})
    if not isinstance(roles, dict) or set(roles) - set(targets):
        raise ValueError('process role not in contract target set')
    if any(role not in ('core', 'spawner', 'victim-connector', 'auxiliary-connector', 'victim-file-worker',
                        'auxiliary-file-worker')
           for role in roles.values()) or len(set(roles.values())) != len(roles):
        raise ValueError('unknown/duplicate process role')
    matrix = contract.get('targets_by_config', {'engine': targets, 'undefended': targets})
    if not isinstance(matrix, dict) or set(matrix) != {'engine', 'undefended'}:
        raise ValueError('target applicability must explicitly cover both configurations')
    for branch in matrix.values():
        if not isinstance(branch, list) or not branch:
            raise ValueError('empty/non-list applicable targets')
        for key in branch:
            token(key)
        if len(set(branch)) != len(branch) or set(branch) - set(targets):
            raise ValueError('duplicate/unknown applicable target')
    engine, peer = set(matrix['engine']), set(matrix['undefended'])
    if engine != set(targets):
        raise ValueError('engine must retain every contract target')
    if peer != engine:
        missing = engine - peer
        if (attack != 'NB-23' or len(missing) != 1
                or roles.get(next(iter(missing))) != 'victim-connector'):
            raise ValueError('only NB-23 undefended victim connector is inapplicable')
    return matrix


def targets_for(contract, config):
    matrix = validate_contract(contract, contract.get('attack'))
    if config not in matrix:
        raise ValueError('unknown target configuration')
    return list(matrix[config])
