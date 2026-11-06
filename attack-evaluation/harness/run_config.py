"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import argparse
from pathlib import Path
from build import capacity
from run_baseline import ENGINE, ENGINE_PATHS
from common import token
from run_units import unit, cases_for
from safeio import plain_path, read_owned


def selection(attacks, configs, registry):
    if not attacks or len(attacks) > 64 or len(set(attacks)) != len(attacks):
        raise ValueError('explicit nonempty unique attack list (max 64) required')
    if configs not in (['engine'], ['undefended'], ['engine', 'undefended']):
        raise ValueError('configs must be engine, undefended, or engine,undefended in that order')
    missing = [name for name in attacks if name not in registry]
    if missing:
        raise ValueError('step-4 modules not implemented: ' + ', '.join(missing))
    cases = [registry[name].validate() for name in attacks]
    if any(c.kind in ('control', 'boundary') for c in cases) and 'engine' not in configs:
        raise ValueError('positive controls and boundary demonstrations run only with engine')
    if any(c.kind == 'attack' for c in cases) and 'engine' in configs and not any(c.kind == 'control' for c in cases):
        raise ValueError('engine batch must explicitly include an interspersed positive control')
    if len(cases) > 2 and any(c.kind == 'attack' for c in cases) and 'engine' in configs:
        if not any(c.kind == 'control' for c in cases[1:-1]):
            raise ValueError('positive control must be mixed between attacks')
    return cases


def schedule(cases, configs):
    result = []
    for config in configs:
        ordered = [c for c in cases if config == 'engine' or c.kind not in ('control', 'boundary')]
        if config == 'undefended':
            ordered = [c for c in ordered if c.attack not in ('NB-23', 'NB-22')] + [
                c for name in ('NB-23', 'NB-22') for c in ordered if c.attack == name]
        result.extend((config, case) for case in ordered)
    return result


def batch_capacity(cases, configs):
    # Two persistent engine support rows per arm, plus attack rows; reserve one
    # uid for each restartable helper/attempt. Overreservation is safe, not reuse.
    count = sum(c.repeats * max(1, len(c.branches)) for cfg, c in schedule(cases, configs) if cfg == 'engine')
    count += 2 * len(configs) + sum(c.repeats * max(1, len(c.branches)) for cfg, c in schedule(cases, configs))
    cap = capacity(count)
    if cap['ca_count'] > 1024:
        raise ValueError('batch exceeds current production capacity')
    return cap


def parser():
    p = argparse.ArgumentParser(description='Offline by default; --start 开始 is required for a real batch')
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--engine-path', choices=ENGINE_PATHS, default=ENGINE,
                   help='repository-relative engine source; recorded in frozen context and run header')
    p.add_argument('--unit', choices=('no-bypass', 'credential-binding'), default='no-bypass')
    p.add_argument('--variant', choices=('redirect-credentials','connection-ignore-account'),
                   help='isolated judge self-check: redirect-credentials=CB-10, connection-ignore-account=CB-14')
    p.add_argument('--target',action='append',default=[],help='CB only: ID:subtarget, repeat to select a bounded batch; omissions are not coverage')
    p.add_argument('--attacks', required=True, help='explicit comma-separated implemented case IDs')
    p.add_argument('--configs', required=True)
    p.add_argument('--label', required=True)
    p.add_argument('--crash-directory', type=Path, required=True)
    p.add_argument('--cgroup-parent', type=Path, default=Path('/sys/fs/cgroup'))
    p.add_argument('--cert-python', default='/home/jerry/.venvs/engine-v2-frontend/bin/python')
    p.add_argument('--start', choices=['开始'])
    return p


def options(argv, registry):
    args = parser().parse_args(argv)
    selected = unit(args.unit)
    registry = cases_for(args.unit, registry, args.target)
    if any(t.partition(':')[0] not in args.attacks.split(',') for t in args.target):
        raise ValueError('target selector names an unselected case')
    cases = selection(args.attacks.split(','), args.configs.split(','), registry)
    variant_attack = {'redirect-credentials': 'CB-10', 'connection-ignore-account': 'CB-14'}
    if args.variant and (args.unit != 'credential-binding' or args.configs != 'engine'
                         or not any(c.attack == variant_attack[args.variant] for c in cases)
                         or any(c.kind == 'attack' and c.attack != variant_attack[args.variant] for c in cases)):
        raise ValueError('variant is restricted to its own engine-only judge self-check')
    token(args.label)
    if len(args.label) > 24:
        raise ValueError('label max 24 characters (bounded transport filenames)')
    args.repo = plain_path(args.repo)
    args.configs = args.configs.split(',')
    if args.unit=='credential-binding':
        from cb_registry import capacity_for
        args.cap=capacity_for(cases,args.configs)
    else:args.cap = batch_capacity(cases, args.configs)
    for c in cases:
        read_owned(args.repo / selected.script(c.attack, c.module), 65536)
    return args, cases
