"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-01 一次允许执行两次（tests.md 2.1）。Subgoal close-after-read: on one connection, GET /ok and read it, then
/close-after-read, which the upstream reads and then drops. Under the engine the script does not resend: the attack is
on the connector resending. Undefended: the script itself sends again after the drop (the degraded form).
"""


def run(ctx) -> None:
    if ctx.sub != 'close-after-read':
        raise ValueError(ctx.sub)
    conn = ctx.open(ctx.url('open', '/ok', 'c'))
    ctx.call('control', ctx.url('open', '/ok', 'c'), conn=conn)
    result = ctx.call('attack', ctx.url('open', '/close-after-read', 'a'), conn=conn)
    conn.close()
    if ctx.config == 'undefended' and result.get('category') != 'remote':
        ctx.call('resend', ctx.url('open', '/close-after-read', 'a'))
