"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-03 发往没列入的主机，含并入的 DF-04、DF-11（tests.md 2.2）。Every branch sends its control request first, then the
attack request; the request shape is the same under both configurations.
"""
BODY = b'nb-decoy-body'
LITERAL = {'ip-loopback': 'loopback', 'ip-private': 'private', 'ip-linklocal': 'linklocal', 'ip-interface': 'iface'}


def run(ctx) -> None:
    s = ctx.sub
    if s == 'post-unlisted':
        ctx.call('control', ctx.url('open', '/ok', 'c'))
        ctx.call('attack', ctx.url('open', '/ok', 'a'), 'POST', body=BODY)
    elif s == 'method-uncovered':
        ctx.call('control', ctx.url('up', '/ok', 'c'))
        ctx.call('attack', ctx.url('up', '/ok', 'a'), 'POST', body=BODY)
    elif s == 'path-uncovered':
        ctx.call('control', ctx.url('up', '/ok', 'c'), 'POST', body=BODY)
        ctx.call('attack', ctx.url('up', '/other', 'a'), 'POST', body=BODY)
    elif s == 'recorded-deny':
        # control under the fallback first; the controller then records the deny and releases the attack
        ctx.call('control', ctx.url('up', '/ok', 'c'))
        ctx.mark('controlled')
        if ctx.wait('deny-set'):
            ctx.call('attack', ctx.url('up', '/ok', 'a'))
    elif s in LITERAL:
        ctx.call('control', ctx.url('open', '/ok', 'c'))
        ctx.call('attack', ctx.url(LITERAL[s], '/', 'a', scheme='http'))
    elif s == 'name-private':
        ctx.call('control', ctx.url('open', '/ok', 'c'))
        ctx.call('attack', ctx.url('inner', '/ok', 'a'))
    elif s == 'other-port':
        ctx.call('control', ctx.url('up', '/ok', 'c'), 'POST', body=BODY)
        ctx.call('attack', ctx.url('up', '/ok', 'a', port=ctx.t['alt_port']), 'POST', body=BODY)
    elif s == 'other-workspace':
        role = ctx.req.get('role')            # engine: the work1 row is 'control', the work0 row is 'attack'
        if role in ('control', None):
            ctx.call('control', ctx.url('up', '/ok', 'c'), 'POST', body=BODY)
        if role in ('attack', None):
            ctx.call('attack', ctx.url('up', '/ok', 'a'), 'POST', body=BODY)
    else:
        raise ValueError(s)
