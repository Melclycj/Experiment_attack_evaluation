"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
import select
from nb_contract import fields

def line(ctx):
    data = bytearray()
    while len(data) < 256:
        if not select.select([0], [], [], ctx.remaining(10))[0]:
            raise TimeoutError('dialogue line timeout')
        b = os.read(0, 1)
        if not b:
            raise ConnectionError('dialogue input EOF')
        data += b
        if b == b'\n':
            return bytes(data)
    raise ValueError('dialogue line bound')

def control(ctx):
    fields(ctx.request['parameters'], 'start a')
    for value in ctx.request['parameters'].values():
        if not isinstance(value, str) or not value.startswith('nb-decoy-') or not value.isascii() or not value.replace('-', '').isalnum():
            raise ValueError('dialogue nonce syntax')
    return True

def action(ctx):
    p = ctx.request['parameters']
    if line(ctx) != (p['start'] + '\n').encode():
        raise ValueError('dialogue start mismatch')
    os.write(1, (p['a'] + '\n').encode())
    ctx.capture('received', line(ctx))
