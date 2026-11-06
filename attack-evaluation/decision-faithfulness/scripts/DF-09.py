"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-09 批准后换 DNS 地址（tests.md 2.7）。The rebinding name answers the upstream's address first and the private decoy
afterwards. Each call opens a new connection, so the connector has no upstream connection to reuse and must resolve.
Undefended: the script connects twice, resolving each time (the degraded form).
"""


def run(ctx) -> None:
    if ctx.sub != 'rebind':
        raise ValueError(ctx.sub)
    ctx.call('control', ctx.url('open', '/ok', 'c'))
    ctx.mark('attack-start')
    ctx.call('attack', ctx.url('rebind', '/ok', 'a'))
    if ctx.config == 'undefended':
        ctx.call('attack-2', ctx.url('rebind', '/ok', 'a'))
