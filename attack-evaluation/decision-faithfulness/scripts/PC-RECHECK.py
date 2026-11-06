"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

PC-RECHECK（tests.md 第 4 节）：PDP 替身扣住期间改别的键的条目；版本号变了但这一格不变，必须照常放行。
"""


def run(ctx) -> None:
    ctx.call('attack', ctx.url('up', '/ok', 'a'), 'POST', body=b'nb-decoy-body', timeout=25)
