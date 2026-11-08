"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-08 问用户到发出之间换请求（tests.md 2.6）。Request A raises a question; once the controller has seen it, the script
closes A's connection (the connector withdraws A) and sends request B on a new connection. The controller then answers
A's question allow-once.
"""
import time


def run(ctx) -> None:
    if ctx.sub != 'withdraw-swap':
        raise ValueError(ctx.sub)
    ctx.call('control', ctx.url('up', '/ok', 'c'), 'POST', body=b'nb-decoy-c', timeout=20)
    a = ctx.send('request-a', ctx.url('up', '/ok', 'a'), 'POST', body=b'nb-decoy-A')
    ctx.mark('sent-a')
    released = ctx.wait('asked-a', 15)
    if a is not None:
        a.close()
    ctx.note('a_closed_at', time.time())
    if released:
        ctx.call('request-b', ctx.url('up', '/ok', 'b'), 'POST', body=b'nb-decoy-B', timeout=ctx.req['b_wait'])
