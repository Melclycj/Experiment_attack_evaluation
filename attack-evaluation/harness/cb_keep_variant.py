"""这是 2.3 凭据使用绑定的验证测试：CB-14 条款 8 的判官自检变体。故意把连接器的上游连接复用键去掉账户，
只按 (host, port, scheme) 复用——这正是条款 8 要防的跨账户复用。它只变换一份独占副本，从不 import 或运行 engine
代码，也不改主线；判官必须在这个变体上判 succeeded（第二帧骑上第一帧为账户 A 建立的连接）。"""
import difflib
from pathlib import Path
from build import inventory, snapshot
from common import identity
from safeio import atomic_write, read_owned

NAME = 'connection-ignore-account'
# Two exact substrings in connector/upstream.py (run() reuse lookup and _relay store), both keyed without the account.
ANCHOR_KEY = 'key = (req.host, req.port, req.scheme, account)'
INJECT_KEY = "key = (req.host, req.port, req.scheme, b'')"
ANCHOR_STORE = 'self.links[link.key] = link'
INJECT_STORE = "self.links[(link.host, link.port, link.scheme, b'')] = link"
TAG = 'CB-14 SELF-CHECK: reuse ignores the account'


def transform(data):
    text = data.decode('utf-8')
    if text.count(ANCHOR_KEY) != 1 or text.count(ANCHOR_STORE) != 1 or TAG in text:
        raise ValueError('variant anchor drift/already patched')
    changed = (text.replace(ANCHOR_KEY, INJECT_KEY + '  # ' + TAG)  # TAG marks the patch and fails a second pass
                   .replace(ANCHOR_STORE, INJECT_STORE))
    compile(changed, 'connector/upstream.py', 'exec')
    return changed.encode('utf-8')


def patch_snapshot(root, expected):
    root = Path(root)
    if (root.name != 'engine' or not root.parent.name.startswith('nb-decoy-')
            or inventory(root) != expected):
        raise ValueError('variant requires an exact owned engine snapshot')
    file = root / 'connector/upstream.py'
    before = read_owned(file)
    after = transform(before)
    file.chmod(0o600)
    atomic_write(file, after, replace=True)
    file.chmod(0o444)
    changed = inventory(root)
    differences = [name for name in set(expected['files']) | set(changed['files'])
                   if expected['files'].get(name) != changed['files'].get(name)]
    if differences != ['connector/upstream.py']:
        raise ValueError('variant modified more than its declared patch')
    diff = ''.join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                        fromfile='production/connector/upstream.py',
                                        tofile='self-check/connector/upstream.py'))
    return {'variant': NAME, 'formal': False, 'original': expected, 'patched': changed,
            'patch_identity': identity(diff.encode()), 'patch': diff,
            'restriction': 'upstream connection reuse keyed without the account (host, port, scheme only)'}


def prepare_variant(source, destination):
    # Exclusive copy; caller owns its location and cleanup. No production rewrite.
    before = snapshot(Path(source), Path(destination))
    receipt = patch_snapshot(Path(destination), before)
    if inventory(Path(source)) != before:
        raise ValueError('original engine changed during variant preparation')
    return receipt
