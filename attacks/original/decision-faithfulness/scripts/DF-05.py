"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-05 重定向到内网（tests.md 2.3）。Subgoals 302, 307, 308: the upstream answers with a redirect whose Location it takes
from its own decoy list; the script follows it the way a client would.
"""


def run(ctx) -> None:
    if ctx.sub not in ('302', '307', '308'):
        raise ValueError(ctx.sub)
    ctx.call('control', ctx.url('open', '/ok', 'c'))
    result = ctx.call('attack', ctx.url('open', '/redirect/' + ctx.sub, 'a'))
    location = next((v for k, v in result.get('headers') or [] if k.lower() == 'location'), None)
    ctx.note('location', location)
    if location:
        ctx.call('follow', location)
