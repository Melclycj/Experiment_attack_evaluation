"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-12 撤销后继续用已开的连接（tests.md 2.9）。The script reads the first block of /stream, marks it, then keeps reading.
The controller revokes in the subgoal's way, waits for the engine's revocation record, then lets the upstream send the
marked second block.
"""
SUBS = ('entry-del', 'entry-narrow-account', 'entry-deny', 'cred-del', 'cred-put')


def run(ctx) -> None:
    if ctx.sub not in SUBS:
        raise ValueError(ctx.sub)
    auth = [('authorization', ctx.bearer())]
    ctx.call('control', ctx.url('up', '/ok', 'c'), headers=auth)
    first = ctx.call('attack', ctx.url('up', '/stream', 'a'), headers=auth, first_chunk_only=True)
    if first.get('chunks'):
        ctx.mark('first')
        ctx.resume('attack-rest', first, 20)
    if first.get('conn') is not None:
        first['conn'].close()
