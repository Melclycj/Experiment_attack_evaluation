"""这是 2.3 凭据使用绑定的验证测试：CB-14 条款 8 的判官。只读 keep 上游的按连接记录判外部事实——无凭据的第二帧
是否骑在第一帧（账户 A）认证过的那条上游连接上并被按先前账户接受；不消费 cell 自报的成功标志，不使用真实凭据。

正确的 engine 给无账户的第二帧一个不同的复用键，会另开一条连接（isolated）→ blocked；只有按 (host,port) 复用、
忽略账户的连接器才会把第二帧放到 A 的连接上（crossed）→ succeeded。不设防一条直连连接自然 crossed → 作配对前提。"""
import base64
from cb_sentinels import hits


def keep_judge(spec, parameters, accounts, observation, captures, window, *, config, coverage):
    """Return a fact for cb_judge.verdict (expected mechanism 'connection-account-isolation')."""
    a = accounts[spec['source']]
    records = window.get('keep_requests', [])
    auth = [r for r in records if r.get('path') == parameters['path']]
    probe = [r for r in records if r.get('path') == parameters['probe_path']]
    quality = []
    if coverage.get('complete') is not True:
        quality.extend(coverage.get('gaps') or ['incomplete-outlet-coverage'])
    if observation.get('complete') is not True:
        quality.append('incomplete-runner-observation')
    if len(auth) != 1 or len(probe) != 1:
        quality.append('keep-frame-count:%d-auth/%d-probe' % (len(auth), len(probe)))
    effect = expected = control_ok = False
    mechanism = None
    forbidden = []
    if len(auth) == 1 and len(probe) == 1:
        first, second = auth[0], probe[0]
        # The within-attack control: frame 1 is account A using the keep endpoint (it authenticates the connection).
        control_ok = bool(first.get('had_auth'))
        if not first.get('had_auth'):
            quality.append('keep-auth-frame-unauthenticated')
        if second.get('had_auth'):
            quality.append('keep-probe-frame-carried-credential')
        # Account A's secret belongs only in the authed frame, never in the header-less probe frame.
        probe_head = base64.b64decode(second.get('head_base64', ''), validate=True)
        forbidden = hits(probe_head, [a])
        same_connection = second.get('conn_id') == first.get('conn_id')
        rode_authed_connection = second.get('conn_authed') is True
        crossed = (same_connection and rode_authed_connection) or bool(forbidden)
        isolated = (not same_connection) and second.get('conn_authed') is False and not forbidden
        effect = crossed
        if config == 'undefended':
            expected = crossed  # one direct keep-alive connection: the second frame rides it (pre-agreed effect)
        else:
            expected = isolated
            mechanism = 'connection-account-isolation' if isolated else 'connection-reused-across-account'
    prerequisite_ok = config == 'undefended' and effect is True and not quality
    return {'effect': bool(effect), 'expected': bool(expected), 'control_ok': control_ok,
            'complete': not quality, 'quality_issue': '; '.join(quality), 'mechanism': mechanism,
            'forbidden': forbidden, 'prerequisite_ok': prerequisite_ok, 'keep_records': records}
