"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
import socket
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).absolute().parent))
from common import token
from decoy_services import end_frame


def exchange(name, secret):
    if not token(name).startswith('nb-decoy-'):
        raise ValueError('only registered decoy abstract endpoint')
    data = end_frame(secret)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(3)
        conn.connect('\0' + name)
        conn.sendall(data); conn.shutdown(socket.SHUT_WR)
        output = bytearray()
        while len(output) <= len(data):
            part = conn.recv(len(data) + 1 - len(output))
            if not part:
                break
            output.extend(part)
        if bytes(output) != data:
            raise ValueError('listener end echo mismatch')
    return True


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(2)
    exchange(sys.argv[1], os.environ['NB_END_SECRET'])
    print('{"echo":true}')
