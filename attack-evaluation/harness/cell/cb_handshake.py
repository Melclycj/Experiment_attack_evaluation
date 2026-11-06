"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import json
import os
import select
import time
from nb_contract import leaf
from nb_io import PublicationPending

GATE_LIMIT=128


def terminal_gate(ctx):
    """Engine rows block here until the host's attach client delivers the gate line, so the
    captured terminal stream starts before any action (tests.md 1.3, trace row). The line's
    echo in the capture witnesses that order. Undefended rows carry no gate: their stdout and
    stderr are host pipes from process start."""
    gate=ctx.request['parameters'].pop('terminal',None)
    if ctx.request['config']!='engine':
        if gate is not None:raise ValueError('terminal gate outside an engine row')
        return
    if not isinstance(gate,str) or not gate.startswith('nb-decoy-terminal-') or len(gate)>=GATE_LIMIT:
        raise ValueError('engine row without a terminal gate')
    data=bytearray();end=ctx.clock()+ctx.remaining(10)
    while not data.endswith(b'\n'):
        left=end-ctx.clock()
        if left<=0 or len(data)>GATE_LIMIT:raise TimeoutError('terminal gate timeout or bound')
        if not select.select([0],[],[],left)[0]:raise TimeoutError('terminal gate timeout')
        b=os.read(0,1)
        if not b:raise ConnectionError('terminal gate EOF')
        data+=b
    if bytes(data)!=(gate+'\n').encode():raise ValueError('terminal gate mismatch')


def handshake(ctx):
    terminal_gate(ctx)
    p=ctx.request['parameters']['measurement']
    ready,release=leaf(p['ready']),leaf(p['release'])
    item={'pid':os.getpid(),'ppid':os.getppid(),'marker':p['marker']}
    ctx.files.write(ready,json.dumps(item).encode())
    end=ctx.clock()+ctx.remaining(10)
    while ctx.clock()<end:
        # The host publishes by hard link (run_transport.publish): a two-link window is
        # "not yet", exactly as runner.Context.synchronize treats it (2026-11-04 cbfix-b4).
        try:data=ctx.files.read(release,4096)
        except (FileNotFoundError,PublicationPending):ctx.sleep(.01);continue
        if json.loads(data)!=item:raise ValueError('environment handshake mismatch')
        return
    raise TimeoutError('environment handshake timeout')
