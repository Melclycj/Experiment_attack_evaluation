"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from nb_file_actions import control as file_control, action as file_action


def control(ctx):
    return file_control(ctx, "NB-06")


def action(ctx):
    return file_action(ctx, "NB-06")
