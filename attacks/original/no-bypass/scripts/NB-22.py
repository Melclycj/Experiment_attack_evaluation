"""这是 1.1 隔离论证的验证测试：仅针对本批自建部署与诱饵；本模块实现 4d，不授权真实运行。"""
from nb_engine_actions import control as run_control, action as run_action


def control(ctx):
    return run_control(ctx, 'NB-22')


def action(ctx):
    return run_action(ctx, 'NB-22')
