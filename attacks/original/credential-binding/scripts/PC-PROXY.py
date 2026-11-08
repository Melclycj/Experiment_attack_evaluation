"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from cb_handshake import handshake
from nb_contract import fields
from nb_wire import open_request, response, request_bytes
from cb_wire import Tap

def control(ctx):
    handshake(ctx)
    ctx.request['parameters'].pop('measurement')
    ctx.request['parameters'].pop('attempt_nonce')
    fields(ctx.request['parameters'], 'sentinel host')
    p = ctx.request['parameters']
    request_bytes('GET', p['host'], '/' + p['sentinel'])
    ctx.target('upstream', 'inet')
    return True

def action(ctx):
    p = ctx.request['parameters']
    with open_request('GET', p['host'], '/' + p['sentinel'], lambda: ctx.remaining(10)) as conn:
        tap=Tap(conn)
        reply=response(tap,lambda:ctx.remaining(10))
        ctx.capture('raw-response',bytes(tap.raw))
    ctx.capture('response', reply.pop('body'))
    ctx.observe('response', **reply)
