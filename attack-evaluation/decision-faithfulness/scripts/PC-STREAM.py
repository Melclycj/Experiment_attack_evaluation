"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

PC-STREAM（tests.md 第 4 节）：GET /stream，不撤销；两块都必须到，并有 RESP_END。
"""


def run(ctx) -> None:
    first = ctx.call('attack', ctx.url('open', '/stream', 'a'), first_chunk_only=True)
    if first.get('chunks'):
        ctx.mark('first')
        ctx.resume('attack-rest', first, 20)
    if first.get('conn') is not None:
        first['conn'].close()
