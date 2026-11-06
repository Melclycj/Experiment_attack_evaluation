"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

DF-16 往控制口送修改类动词（tests.md 2.10）。Engine only: the undefended configuration has no control port and no table
(METHOD rule 3; recorded as having no counterpart, not run). One message as the control step, four modifying verbs,
then a POST that only an entry_put taking effect would let through.
"""
VERBS = [
    {'type': 'entry_put', 'id': 1, 'workspace_id': 'work0', 'key_kind': 'exact', 'key': 'nb-decoy-up:443',
     'state': 'allow', 'methods': ['POST'], 'approval': 'never'},
    {'type': 'answer', 'id': 2, 'question_id': 1, 'verdict': 'allow-always'},
    {'type': 'cred_put', 'id': 3, 'host_port': 'nb-decoy-up:443', 'account': 'nb-decoy-acct-a'},
    {'type': 'row_start', 'id': 4, 'workspace_id': 'work0', 'plan': 'df-runner-0'},
]


def run(ctx) -> None:
    from df_runner import control_call
    if ctx.sub != 'control-verbs' or ctx.config != 'engine':
        raise ValueError('engine only')
    sock = ctx.control()
    replies = {'control': control_call(sock, {'type': 'nb-decoy-ping', 'id': 'c'})}
    for message in VERBS:
        replies[message['type']] = control_call(sock, message)
    ctx.note('control_replies', replies)
    ctx.call('attack', ctx.url('up', '/ok', 'a'), 'POST', body=b'nb-decoy-body')
