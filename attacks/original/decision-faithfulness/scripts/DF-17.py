"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-17 并发改表（tests.md 2.11）。The script only sends; the test side holds the window open (the question left
unanswered, or the PDP stand-in holding its answer) while the controller changes the table.
"""
BODY = b'nb-decoy-body'


def run(ctx) -> None:
    if ctx.sub not in ('ask-then-narrow', 'pdp-narrow', 'pdp-deny'):
        raise ValueError(ctx.sub)
    ctx.call('control', ctx.url('up', '/ok', 'c'), 'POST', body=BODY, timeout=20)
    ctx.call('attack', ctx.url('up', '/ok', 'a'), 'POST', body=BODY, timeout=25)
