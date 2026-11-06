"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-10 换账户后复用连接（tests.md 2.8）。On one connection: a request carrying the authorization header (the engine
places account a's truth), the same again (control: a same-key request reuses the upstream connection), then one
without the header.
"""


def run(ctx) -> None:
    if ctx.sub != 'account-then-none':
        raise ValueError(ctx.sub)
    auth = [('authorization', ctx.bearer())]
    conn = ctx.open(ctx.url('up', '/ok', 'a1'))
    ctx.call('with-account', ctx.url('up', '/ok', 'a1'), headers=auth, conn=conn)
    ctx.call('with-account-again', ctx.url('up', '/ok', 'c2'), headers=auth, conn=conn)
    ctx.call('without-account', ctx.url('up', '/ok', 'a2'), conn=conn)
    conn.close()
