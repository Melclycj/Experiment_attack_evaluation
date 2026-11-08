"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
sys.path[:0] = [str(Path(__file__).absolute().parent), str(Path(__file__).absolute().parent / 'cell')]
from cell.nb_contract import decode, target
from nb_conn_actions import exchange
from decoy_services import end_frame


def end_exchange(value, wire, secret):
    target(value)
    end = time.monotonic() + 3
    ctx = SimpleNamespace(cwd='', remaining=lambda maximum: max(.001, min(maximum, end - time.monotonic())))
    frame = end_frame(secret)
    echoed, result = exchange(ctx, wire, value, frame)
    if result['errno'] or echoed != frame:
        raise ValueError('connection end marker roundtrip failed')
    return {'echo': True}


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit(2)
    end_exchange(decode(os.environ['NB_TARGET']), os.environ['NB_WIRE'], os.environ['NB_END_SECRET'])
    print('{"echo":true}')
