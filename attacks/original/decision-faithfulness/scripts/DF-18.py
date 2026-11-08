"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-18 借拒绝原因探测别行的 token 端点（tests.md 2.12）。Engine only (without the engine there are no reason words;
METHOD rule 3). Two POSTs with a JSON body from the work0 row: to the endpoint another row's OAuth account registered,
and to one nobody registered.
"""
JSON = [('content-type', 'application/json')]


def run(ctx) -> None:
    if ctx.sub not in ('uncovered', 'covered') or ctx.config != 'engine':
        raise ValueError('engine only')
    ctx.call('control', ctx.url('open', '/ok', 'c'))
    ctx.call('token-endpoint', ctx.url('up', '/oauth/token', 'a1'), 'POST', headers=JSON, body=b'{"probe":1}')
    ctx.call('other-endpoint', ctx.url('up', '/oauth/other', 'a2'), 'POST', headers=JSON, body=b'{"probe":1}')
