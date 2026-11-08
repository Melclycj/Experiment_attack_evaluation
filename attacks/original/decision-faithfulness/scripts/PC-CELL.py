"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

PC-CELL（tests.md 第 4 节）：每次都问的格，第一次答"允许，这一格以后不再问"；第二次必须不提问即放行。
"""


def run(ctx) -> None:
    ctx.call('first', ctx.url('up', '/ok', 'a1'), 'POST', body=b'nb-decoy-body', timeout=20)
    ctx.call('second', ctx.url('up', '/ok', 'a2'), 'POST', body=b'nb-decoy-body', timeout=10)
