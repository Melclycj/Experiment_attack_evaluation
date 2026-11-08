"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from cb_handshake import handshake
import os
from nb_contract import fields, leaf

def control(ctx):
    handshake(ctx)
    ctx.request['parameters'].pop('measurement')
    ctx.request['parameters'].pop('attempt_nonce')
    fields(ctx.request['parameters'], 'output sentinel')
    leaf(ctx.request['parameters']['output'])
    ctx.target('workspace', 'path')
    return True

def action(ctx):
    item = ctx.target('workspace', 'path')
    if item['scope'] != 'work':
        raise ValueError('workspace control must use work-relative input')
    ctx.capture('read', ctx.files.read(item['path'], 4096))
    p = ctx.request['parameters']
    ctx.files.write(p['output'], p['sentinel'].encode())
    fd = os.open(p['output'], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=ctx.files.fd)
    try:
        info = os.fstat(fd)
        ctx.observe('write', dev=info.st_dev, ino=info.st_ino, size=info.st_size)
    finally:
        os.close(fd)
