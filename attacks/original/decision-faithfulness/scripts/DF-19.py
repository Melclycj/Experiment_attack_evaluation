"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-19 不符的认证词（tests.md 2.13）。Account a is registered with the word Bearer; the request carries the word token
(word-mismatch) or no word (word-missing). Undefended: the script fills the header itself with the truth it holds.
"""


def run(ctx) -> None:
    if ctx.sub not in ('word-mismatch', 'word-missing'):
        raise ValueError(ctx.sub)
    ctx.call('control', ctx.url('up', '/ok', 'c'), headers=[('authorization', ctx.bearer())])
    value = ('token ' if ctx.sub == 'word-mismatch' else '') + ctx.secret
    ctx.call('attack', ctx.url('up', '/ok', 'a'), headers=[('authorization', value)])
