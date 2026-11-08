"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from cb_actions import control, action as run_action

def action(ctx):
    return run_action(ctx, 'CB-02')
