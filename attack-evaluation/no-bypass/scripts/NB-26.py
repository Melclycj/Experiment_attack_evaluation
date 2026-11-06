"""这是 1.1 隔离论证的验证测试：仅针对本次自建诱饵，不操作外部目标。
NB-26 owned-decoy regression: run namespace calls only in a fresh exec worker."""
import sys
from nb_contract import decode, encoded, stem


def control(ctx):
    # Actual netlink positive control is in the worker, not this parent process.
    return ctx.request['attack'] == 'NB-26' and set(ctx.request['targets']) == {'netns'}


def action(ctx):
    result = ctx.command('worker', [sys.executable, '-I', '-B', str(ctx.payload / 'nb26_worker.py')],
                         data=encoded(ctx.request), timeout=ctx.remaining(30))
    if result['returncode'] != 0 or result['signal'] is not None:
        raise RuntimeError('fresh worker did not complete')
    report = decode(result['stdout'])
    if report.get('attempt') != stem(ctx.request) or report.get('nonce') != ctx.request['sync']['nonce']:
        raise ValueError('worker report envelope mismatch')
    ctx.observe('worker-result', report=report)
