"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from common import identity
from test_cell_runner import Clock, MemoryFiles

H = Path(__file__).resolve().parents[1]
SCRIPTS = H.parent / 'no-bypass/scripts'
NONCE = 'a' * 48
SENTINEL = 'nb-decoy-' + 'b' * 48


def load(name):
    ns = {'__name__': 'offline_module'}
    exec(compile((SCRIPTS / (name + '.py')).read_bytes(), name, 'exec'), ns)
    return ns


def receipt(observation, captures, label, data, phase='action'):
    name = 'offline-' + phase + '-' + label + '.capture'
    observation.setdefault('captures', []).append({'label': label, 'phase': phase, 'path': name,
        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    captures[name] = data


def window(requests=()):
    requests = [{'seq': i, 'kind': 'request', 'attempt': NONCE, **v} for i, v in enumerate(requests)]
    return {'cursor': 0, 'end': {'kind': 'end', 'seq': len(requests), 'token': 'end-secret', 'attempt': NONCE},
            'requests': requests}


def runtime(root):
    workspaces = {}
    for name in ('work0', 'work1', 'work2'):
        path = root / name; path.mkdir()
        workspaces[name] = {'mount': path, 'source': path}
    rt = SimpleNamespace(work=workspaces['work0']['mount'], resources=SimpleNamespace(roots={root: (1, 2)}),
        # Offline: both arms share these directories; the v4 split is tested in test_9_engine_v4.
        deployment=SimpleNamespace(workspaces=workspaces, host_workspaces=workspaces, refs={}, admin=Mock(),
                                   upstream=Mock()),
        evidence=Mock(), command=Mock(), rows=[])
    rt.evidence.raw.side_effect = lambda data, suffix='json': {'file': 'offline.' + suffix, **identity(data)}
    from run_transport import OwnedTargets
    rt.targets = OwnedTargets(rt)
    return rt
