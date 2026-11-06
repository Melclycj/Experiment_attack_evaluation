"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from nb_conn_actions import control as _control, action as _action


def control(ctx):
    return _control(ctx, 'NB-17')


def action(ctx):
    return _action(ctx, 'NB-17')
