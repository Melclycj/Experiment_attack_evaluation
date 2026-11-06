"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import errno
import json
import os
from pathlib import Path
import zlib
from unittest.mock import patch
from foura_fixtures import runtime, receipt, NONCE, window
from run_registry import CASES
from run_transport import request
from cell.nb_file_spec import KINDS, WRITES
from cell.nb_file_actions import content
from test_4a_integration import OfflineRuntime
from runner import Context, run
from nb_io import Files
from types import SimpleNamespace


def temporary_runtime(root):
    rt = runtime(root)
    rt.home = root / 'host'; rt.home.mkdir()
    return rt


def prepare(adapter, config='engine', branch=None):
    c = adapter.contract()
    p = adapter.prepare_branch(config, 1, c, branch) if branch else adapter.prepare(config, 1, c)
    p['request'] = request('offline-file', config, CASES[adapter.attack], 1, p)
    return p


def closed(prepared, requests=()):
    w = window(requests)
    w['end']['attempt'] = prepared['request']['sync']['nonce']
    for item in w['requests']:
        item['attempt'] = w['end']['attempt']
    return w


def git_message(path):
    oid = (path / '.git/refs/heads/main').read_text().strip()
    raw = zlib.decompress((path / '.git/objects' / oid[:2] / oid[2:]).read_bytes())
    return raw.split(b'\0', 1)[1].split(b'\n\n', 1)[1]


def simulated_operation(ctx, attack, key, path, *, label=None):
    """Mocked boundary: manipulate temporary fixture bytes only, never launch.
    Production syscall/shell code is replaced, not used to claim an attack ran.
    """
    label = label or key
    raw_path = path
    # Translate only the offline cell's modeled /work into the fixture workspace.
    if path.startswith('../'):
        path = '/' + path.lstrip('./')
    if path.startswith('/work/'):
        path = str(ctx.offline_work) + path[len('/work'):]
    obj, data, code = None, b'', 0
    if ctx.phase == 'action' and ctx.request['config'] == 'engine':
        code = errno.ENOENT
    else:
        target = Path(path)
        # Engine control symlinks point into the modeled /work, not the real FS.
        if target.is_symlink():
            text = os.readlink(target)
            target = Path(str(ctx.offline_work) + text[len('/work'):]) if text.startswith('/work/') else Path(text)
        elif target.parent.is_symlink():
            text = os.readlink(target.parent)
            target = (Path(str(ctx.offline_work) + text[len('/work'):]) if text.startswith('/work/') else Path(text)) / target.name
        st = target.stat()
        obj = {'dev': st.st_dev, 'ino': st.st_ino, 'size': st.st_size}
        if attack in WRITES:
            blob = content(ctx, attack)
            if attack == 'NB-11': blob = b'diff --git a b\n-a\n+b\n'
            if attack == 'NB-10': blob = target.read_bytes() + blob
            target.write_bytes(blob)
        else:
            data = git_message(target) if attack == 'NB-13' else target.read_bytes()
    ctx.capture(label, data)
    value = {'path': raw_path, 'valid': True, 'rc': -1 if code else 0, 'signal': None,
             'errno': code, 'identity': obj}
    ctx.observe(label + '-result', **value)
    return value


class FileRuntime(OfflineRuntime):
    def __init__(self, root, cases, stack, operation=simulated_operation):
        super().__init__(root, cases, stack)
        own = next(iter(self.resources.roots))
        self.home = own / 'host'; self.home.mkdir()
        self.branch_requests, self.rows = [], []
        stack.enter_context(patch('file_tree.os.fchown'))
        stack.enter_context(patch('file_tree.os.chown'))
        stack.enter_context(patch('nb_file_actions.operation', side_effect=operation))

    def start(self, config, **kwargs):
        self.req = json.loads((self.work / 'nb-request.json').read_bytes())
        self.branch_requests.append(self.req)
        self.code = None
        def factory(*args, **kwargs):
            ctx = Context(*args, **kwargs)
            ctx.offline_work = self.work
            return ctx
        def poll():
            if self.code is None:
                work, payload = Files(self.work), Files(self.payload_root)
                try:
                    with patch.dict(os.environ, {'HOME': str(self.home) if config == 'undefended' else '/tmp'}):
                        self.code = run(work, payload, cwd='/work' if config == 'engine' else str(self.work),
                                        context_factory=factory)
                finally:
                    work.close(); payload.close()
            return True
        return SimpleNamespace(poll=poll, finish=lambda: {'tree_empty':True, 'runner_ok':self.code == 0})
