"""这是 1.1 隔离论证的验证测试：NB-19/27 逐目标失败分流，不凭 errno 虚构宿主根因。"""


def diagnose(*, effect, control_ok, error, step, errno):
    """Only a closed, quality-checked no-effect observation can be a host lead.

    Permission errno is not proof of DAC/LSM, and a real daemon's absence says
    nothing about these owned decoys. Preserve uncertainty until a permitted run.
    """
    if error or not control_ok:
        category = 'script-or-evidence-error'
        next_check = 'repair control/request/capture/window evidence before host attribution'
    elif effect:
        category = 'succeeded'
        next_check = None
    else:
        category = 'host-condition-unresolved'
        next_check = 'inspect archived uid/groups/path/listener facts in an authorized trial; errno alone is insufficient'
    return {'category': category, 'step': step, 'errno': errno,
            'cause_verified': False, 'candidate_effect': bool(effect),
            'real_socket_metadata_used': False, 'next_check': next_check}
