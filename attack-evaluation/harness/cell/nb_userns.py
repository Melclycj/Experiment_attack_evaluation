"""这是 1.1 隔离论证的验证测试：仅针对本次自建诱饵，不操作外部目标。
NB-26 单线程子进程中的调用序列；仅本批诱饵 peer，所有结果保留原始 errno。"""
import ctypes
import os
import platform
import signal
from pathlib import Path
from nb_netlink import dump, exchange, veth

NEWUSER, NEWNET = 0x10000000, 0x40000000


class Syscalls:
    def __init__(self):
        if platform.machine() not in ('x86_64', 'AMD64'):
            raise RuntimeError('registered x86_64 fixture only')
        self.lib = ctypes.CDLL(None, use_errno=True)
        self.lib.syscall.restype = ctypes.c_long

    def call(self, number, *args):
        ctypes.set_errno(0)
        rc = self.lib.syscall(ctypes.c_long(number), *args)
        return {'rc': int(rc), 'errno': ctypes.get_errno() if rc == -1 else 0}

    def clone(self, modern):
        if modern:
            args = (ctypes.c_ulonglong * 11)()
            args[0], args[4] = NEWUSER, signal.SIGCHLD
            result = self.call(435, ctypes.byref(args), ctypes.c_size_t(ctypes.sizeof(args)))
        else:
            result = self.call(56, ctypes.c_ulong(NEWUSER | signal.SIGCHLD),
                               ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_ulong(0))
        if result['rc'] == 0:
            os._exit(0)  # no child action or Python teardown
        if result['rc'] > 0:
            pid, status = os.waitpid(result['rc'], 0)
            result.update(reaped=pid == result['rc'], status=status)
            if pid != result['rc'] or status != 0:
                raise RuntimeError('namespace child not reaped normally')
        return result

    def unshare(self, flags):
        return self.call(272, ctypes.c_ulong(flags))

    def map_uid(self, uid):
        try:
            Path('/proc/self/uid_map').write_text(f'0 {uid} 1\n')
            return {'rc': 0, 'errno': 0}
        except OSError as exc:
            return {'rc': -1, 'errno': exc.errno}


def perform(target, local, peer, *, syscalls=None, transact=exchange, task_count=None):
    count = len(os.listdir('/proc/self/task')) if task_count is None else task_count
    if count != 1:
        raise ValueError('NB-26 requires a fresh single-thread process')
    ops = syscalls or Syscalls()
    uid = os.getuid()
    # (a) Same encoder/socket/decoder before the namespace-changing actions.
    control = transact(dump(1), listing=True)
    calls = {'unshare0': ops.unshare(0), 'clone3': ops.clone(True),
             'clone': ops.clone(False), 'unshare_user': ops.unshare(NEWUSER)}
    if calls['unshare_user']['rc'] == 0:
        calls['uid_map'] = ops.map_uid(uid)
        if calls['uid_map']['rc'] == 0:
            calls['unshare_net'] = ops.unshare(NEWNET)
    # Required even when NEWUSER, mapping or NEWNET failed. Never use sendmsg.
    attempt = transact(veth(target['pid'], local, peer, 2))
    return {'task_count': count, 'control': control, 'calls': calls, 'netlink': attempt}
