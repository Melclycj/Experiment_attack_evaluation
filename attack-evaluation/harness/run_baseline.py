"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
from pathlib import Path
from build import AS_BUILDER, inventory
from common import identity
from safeio import read_owned

BASE = Path('Thesis/Work/Submission/prove/baseline')
# The engine's frozen version: registered baseline v4 = ExperimentLab/engine-v3 @ a9eff999 (user 2026-11-05). The
# harness speaks its interfaces (dedicated workspace owner and tree, the rows' file worker, the MCP server, the
# 24-field QUESTION); runs archived from ExperimentLab/engine-v2-go stay readable, they name their own source path.
ENGINE = 'ExperimentLab/engine-v3'
ENGINE_PATHS = (ENGINE,)
# baseline.py check reads the whole registered export on /mnt/d: 155 s for v4 as uid 1000 (measured 2026-11-05).
# It runs as the host user, never root: git refuses a root caller in the user's repository ("dubious ownership").
BASELINE_CHECK_SECONDS = 240


def verify(repo, source_identity, host, command, *, engine_path=ENGINE):
    """No CLI formal flag. Source matching no registered export is trial; a matching registered
    build MUST pass the actual baseline checker and complete registered host
    readings. Missing host profile fails closed, never silently downgrades it.
    host-readings/<version>.json is an integration input, NOT created here.
    Its approval/source references and required keys are owned by baseline work.
    """
    if engine_path not in ENGINE_PATHS:
        raise ValueError("unsupported engine source path")
    base = repo / BASE
    versions = json.loads(read_owned(base / 'versions.json', 65536))
    result = dict(source_identity, source_path=engine_path, baseline=None, baseline_check={'executed': False})
    git = lambda *a: command([*AS_BUILDER, '/usr/bin/git', '-c', 'core.fsmonitor=false', '-C', str(repo), *a], timeout=10)['stdout'].strip()
    result['commit'] = git('rev-parse', 'HEAD')
    result['working_tree'] = git('status', '--porcelain', '--untracked-files=all', '--', engine_path,
                                ':(exclude)' + engine_path + '/runs')
    for version, entry in versions.items():
        if entry.get('engine_path') != engine_path:
            continue
        # Exported bytes must also agree with committed blob IDs (checker below).
        exported = base / 'artifacts' / version / 'engine'
        registered = inventory(exported)
        if registered['files'] != source_identity['files']:
            continue
        before = identity(read_owned(base / 'baseline.py'))
        check = command([*AS_BUILDER, '/usr/bin/env', '-C', str(repo), '/usr/bin/python3', '-I', '-B',
                         str(base / 'baseline.py'), 'check', version], timeout=BASELINE_CHECK_SECONDS)
        if identity(read_owned(base / 'baseline.py')) != before:
            raise ValueError('baseline checker changed during verification')
        if check['exit_code'] != 0:
            raise ValueError('registered baseline check failed')
        profile_path = base / 'host-readings' / (version + '.json')
        profile = json.loads(read_owned(profile_path, 65536))
        if (profile.get('version') != version or not profile.get('approved_by_user')
                or not profile.get('sources') or not profile.get('readings')
                or set(profile.get('required', [])) != set(profile['readings'])):
            raise ValueError('missing complete approved registered host-readings profile')
        actual = {}
        for key, item in profile['readings'].items():
            path = item['path']
            if not path.startswith('/proc/sys/') or '..' in Path(path).parts:
                raise ValueError('host reader permits only explicit read-only /proc/sys values')
            actual[key] = Path(path).read_text().strip()
            if actual[key] != item['value']:
                raise ValueError('registered host reading differs: ' + key)
        # CONFIG and other non-sysctl assertions must be included in evidence by
        # baseline owner before registration; this controller never invents them.
        if profile.get('kernel') != host['kernel'] or not profile.get('config_sha256'):
            raise ValueError('registered kernel/CONFIG evidence missing or mismatched')
        import gzip
        config = gzip.decompress(read_owned(Path('/proc/config.gz'), 2 * 1024 * 1024))
        if identity(config)['sha256'] != profile['config_sha256']:
            raise ValueError('kernel CONFIG mismatch')
        host.update(kernel_match=True, readings_match=True, registered_readings=actual,
                    profile=identity(read_owned(profile_path)))
        result.update(baseline=version, baseline_files=registered['files'],
                      baseline_check={'executed': True, 'exit_code': 0, 'version': version})
        break
    return result
