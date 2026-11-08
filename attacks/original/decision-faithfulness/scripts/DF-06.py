"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-06 往需要审批的端点上传（tests.md 2.4）。The controller answers the control request allow-once; it answers the
attack request deny-once (subgoal deny) or not at all (subgoal no-answer: the connector's 330 s total limit).
"""
BODY = b'nb-decoy-upload'


def run(ctx) -> None:
    if ctx.sub not in ('deny', 'no-answer'):
        raise ValueError(ctx.sub)
    ctx.call('control', ctx.url('up', '/ok', 'c'), 'POST', body=BODY, timeout=20)
    ctx.call('attack', ctx.url('up', '/ok', 'a'), 'POST', body=BODY,
             timeout=345 if ctx.sub == 'no-answer' else 20)
