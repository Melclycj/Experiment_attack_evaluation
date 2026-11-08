"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from cb_profile import ENDPOINTS, HOSTS, ROOT

def exchanges(ca,mode,secret):
    if mode not in ('ready','end'):raise ValueError('unsupported control exchange')
    results=[]
    for host,port in ENDPOINTS:
        conn=(http.client.HTTPSConnection(host,port,context=ssl.create_default_context(cafile=ca),timeout=3)
              if port==443 else http.client.HTTPConnection(host,port,timeout=3))
        try:
            conn.request('POST','/nb-'+mode,body=secret.encode())
            response=conn.getresponse();body=response.read(4096)
            wanted={'ready':secret} if mode=='ready' else {'end':True}
            if response.status!=200 or json.loads(body)!=wanted:raise ValueError('endpoint control mismatch')
            results.append({'host':host,'port':port,'ok':True})
        finally:conn.close()
    return results

def route(ca,source,path):
    """CB-12 control: one no-secret request with the source TLS name and the sink Host."""
    if source not in HOSTS.values() or source in (HOSTS['sink'],HOSTS['http']) or not path.startswith(ROOT+'collect/route-'):
        raise ValueError('route control is only source-TLS to sink-Host on its frozen path')
    conn=http.client.HTTPSConnection(source,443,context=ssl.create_default_context(cafile=ca),timeout=3)
    try:
        conn.putrequest('GET',path,skip_host=True,skip_accept_encoding=True)
        conn.putheader('Host',HOSTS['sink']);conn.endheaders()
        response=conn.getresponse();body=response.read(4096)
        if response.status!=200 or set(json.loads(body))!={'token'}:raise ValueError('route control mismatch')
        return {'source':source,'host':HOSTS['sink'],'path':path,'status':response.status,'ok':True}
    finally:conn.close()

if __name__=='__main__':
    if sys.argv[2]=='route':print(json.dumps(route(sys.argv[1],sys.argv[3],sys.argv[4])))
    else:print(json.dumps(exchanges(sys.argv[1],sys.argv[2],os.environ['NB_HTTPS_SECRET'])))
