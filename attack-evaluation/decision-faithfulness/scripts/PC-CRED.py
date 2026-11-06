"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

PC-CRED（tests.md 第 4 节）：带账户的请求；上游收到的头必须恰为"Bearer 真值"，2xx。
"""


def run(ctx) -> None:
    ctx.call('attack', ctx.url('up', '/ok', 'a'), headers=[('authorization', ctx.bearer())])
