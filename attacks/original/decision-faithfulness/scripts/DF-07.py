"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-07 "允许一次"用两次（tests.md 2.5）。The controller answers the first request allow-once; the same request goes again
at once on the same connection. The controller never answers a second question; the script gives up after second_wait.
"""
BODY = b'nb-decoy-once'


def run(ctx) -> None:
    if ctx.sub != 'once-twice':
        raise ValueError(ctx.sub)
    conn = ctx.open(ctx.url('up', '/ok', 'a'))
    ctx.call('first', ctx.url('up', '/ok', 'a'), 'POST', body=BODY, conn=conn, timeout=20)
    ctx.call('second', ctx.url('up', '/ok', 'a'), 'POST', body=BODY, conn=conn, timeout=ctx.req['second_wait'])
    conn.close()
