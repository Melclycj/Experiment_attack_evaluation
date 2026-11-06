"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，演示机制/策略分离的边界；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from nb_contract import fields
from nb_wire import exchange, request_bytes

def control(ctx):
    fields(ctx.request['parameters'], 'sentinel host key')
    p = ctx.request['parameters']
    request_bytes('GET', p['host'], '/' + p['sentinel'], headers=[(b'x-nb-decoy-key', p['key'].encode())])
    ctx.target('upstream', 'inet')
    return True

def action(ctx):
    p = ctx.request['parameters']
    reply = exchange('GET', p['host'], '/' + p['sentinel'],
                     lambda: ctx.remaining(10), headers=[(b'x-nb-decoy-key', p['key'].encode())])
    ctx.capture('response', reply.pop('body'))
    ctx.observe('response', **reply)
