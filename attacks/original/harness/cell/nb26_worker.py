"""这是 1.1 隔离论证的验证测试：仅针对本次自建诱饵，不操作外部目标。
NB-26 fresh single-thread worker; publish live diagnostics before host release."""
import os
from pathlib import Path
import select
import sys

sys.path.insert(0, str(Path(__file__).absolute().parent))
from nb_contract import decode, encoded, stem, validate_request
from nb_io import Files
from nb_userns import perform


def live_name(req):
    return stem(req) + '-live.json'


def report(req):
    uid = os.getuid()
    p = req['parameters']
    result = perform(req['targets']['netns'], p['local_if'], p['peer_if'])
    result.update(attempt=stem(req), nonce=req['sync']['nonce'], pid=os.getpid(),
                  original_uid=uid, netns=os.readlink('/proc/self/ns/net'))
    return result


def main():
    host = sys.argv[1:] == ['--host-control']
    if sys.argv[1:] and not host:
        raise ValueError('explicit worker mode required')
    raw = sys.stdin.buffer.readline(65537) if host else sys.stdin.buffer.read(65537)
    req = validate_request(decode(raw))
    if req['attack'] != 'NB-26' or set(req['targets']) != {'netns'}:
        raise ValueError('explicit NB-26 request required')
    if host:
        # The same perform() code, outside the cell. A pipe handshake avoids
        # granting the reserved control uid access to work0 or a shared HOME.
        data = encoded(report(req))
        sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
        if not select.select([sys.stdin.buffer], [], [], 10)[0]:
            raise TimeoutError('host control release timeout')
        release = decode(sys.stdin.buffer.readline(4097))
        if release != {'attempt': stem(req), 'nonce': req['sync']['nonce'], 'state': 'release'}:
            raise ValueError('host control release mismatch')
        return 0
    from runner import Context
    work = Files(os.getcwd())
    try:
        ctx = Context(req, work)
        ctx.preflight(); work.absent(live_name(req))
        data = encoded(report(req))
        work.write(live_name(req), data)
        ctx.synchronize('done', timeout=10)
        sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
        return 0
    finally:
        work.close()


if __name__ == '__main__':
    raise SystemExit(main())
