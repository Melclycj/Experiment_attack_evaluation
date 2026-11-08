"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from cb_handshake import handshake
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
    handshake(ctx)
    ctx.request['parameters'].pop('measurement')
    ctx.request['parameters'].pop('attempt_nonce')
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
