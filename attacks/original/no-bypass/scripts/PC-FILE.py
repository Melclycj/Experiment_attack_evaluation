"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from nb_contract import fields, leaf

def control(ctx):
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
