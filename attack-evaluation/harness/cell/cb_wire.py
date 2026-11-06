"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import http.client
import json
import socket
import ssl
import struct
import urllib.parse
from cb_spec import HOSTS
from nb_wire import frame,response

KEEP_PORT=8443  # CB-14 条款 8 的保持连接上游旁路端口；不进 ENDPOINTS


def validate(host,port,scheme,path,headers,body):
    if host not in HOSTS.values() or (scheme,port) not in (('https',443),('http',80),('https',KEEP_PORT)):
        raise ValueError('only frozen local credential endpoints')
    if not path.startswith('/nb-decoy-cb/') or len(path)>8192 or len(body)>16384:
        raise ValueError('credential path/body bound')
    for name,value in headers:
        if name not in ('x-api-key','authorization','host','x-nb-decoy-other','x-nb-decoy-marker'):
            raise ValueError('undeclared test header')
        if not value or len(value)>4096 or any(ord(c)<32 or ord(c)>126 for c in value):
            raise ValueError('bounded printable test header required')


def canonical(method,host,port,scheme,path,headers,body):
    validate(host,port,scheme,path,headers,body)
    path,sep,query=path.partition('?')
    fields=[x.encode() for pair in headers for x in pair]
    packed=struct.pack('>I',len(fields))+b''.join(struct.pack('>I',len(x))+x for x in fields)
    return frame(1,[method.encode(),scheme.encode(),host.encode(),struct.pack('>H',port),
                    path.encode(),query.encode(),packed,body])


class Tap:
    def __init__(self,conn):self.conn=conn;self.raw=bytearray()
    def settimeout(self,n):self.conn.settimeout(n)
    def recv(self,n):
        data=self.conn.recv(n);self.raw.extend(data)
        if len(self.raw)>131072:raise ValueError('response tap bound')
        return data


def exchange(params,method,host,path,headers=(),body=b'',*,remaining,follow=False,port=443,scheme='https'):
    validate(host,port,scheme,path,headers,body)
    if params['config']=='engine':
        raw=b''
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            tap=Tap(conn)
            try:
                conn.settimeout(remaining());conn.connect('/run/w2/proxy.sock')
                conn.sendall(canonical(method,host,port,scheme,path,headers,body))
                result=response(tap,remaining)
                return {**result,'raw':bytes(tap.raw),'error':None}
            except (OSError,ValueError,ConnectionError) as exc:
                return {'complete':False,'category':None,'status':None,'body':b'',
                        'raw':bytes(tap.raw),'error':type(exc).__name__}
    if params['config']!='undefended':raise ValueError('unknown credential configuration')
    context=ssl.create_default_context(cafile=params['ca'])
    all_raw=bytearray()
    for hop in range(2):
        conn=(http.client.HTTPSConnection(host,port,context=context,timeout=remaining()) if scheme=='https'
              else http.client.HTTPConnection(host,port,timeout=remaining()))
        try:
            conn.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
            if not any(k=='host' for k,v in headers):conn.putheader('Host',host)
            for name,value in headers:conn.putheader(name,value)
            if body or method=='POST':conn.putheader('Content-Length',str(len(body)))
            conn.endheaders(body)
            r=conn.getresponse();data=r.read(65537)
            if len(data)>65536:raise ValueError('direct response bound')
            raw=json.dumps({'status':r.status,'headers':r.getheaders()}).encode()+b'\n'+data
            all_raw.extend(raw)
            if follow and hop==0 and r.status in (302,307,308):
                location=urllib.parse.urlsplit(r.getheader('Location',''))
                if (location.scheme!='https' or location.hostname!=HOSTS['sink'] or location.port not in (None,443)
                        or not location.path.startswith('/nb-decoy-cb/collect/') or location.query or location.fragment):
                    raise ValueError('redirect leaves frozen decoy scope')
                host,port,scheme,path=location.hostname,443,'https',location.path
                continue # Deliberately preserve authentication in this explicit undefended client.
            return {'complete':True,'category':1,'status':r.status,'body':data,'raw':bytes(all_raw),'error':None}
        except (OSError,http.client.HTTPException) as exc:
            return {'complete':False,'category':None,'status':None,'body':b'',
                    'raw':bytes(all_raw),'error':type(exc).__name__}
        finally:conn.close()
    raise ValueError('redirect hop bound')


def exchange_pair(params,frames,*,remaining,port=KEEP_PORT,scheme='https'):
    """CB-14 条款 8: send the frames on ONE connection in turn, each read to its end — one proxy connection for the
    engine arm (so the connector keeps one fd thread and may reuse an idle upstream link), one keep-alive TLS
    connection for the undefended arm. frames: list of (method, host, path, headers, body). Returns per-frame results."""
    for method,host,path,headers,body in frames:
        validate(host,port,scheme,path,headers,body)
    results=[]
    if params['config']=='engine':
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(remaining());conn.connect('/run/w2/proxy.sock')
            for method,host,path,headers,body in frames:
                tap=Tap(conn)
                try:
                    conn.sendall(canonical(method,host,port,scheme,path,headers,body))
                    result=response(tap,remaining)
                    results.append({**result,'raw':bytes(tap.raw),'error':None})
                except (OSError,ValueError,ConnectionError) as exc:
                    results.append({'complete':False,'category':None,'status':None,'body':b'',
                                    'raw':bytes(tap.raw),'error':type(exc).__name__})
                    break
        return results
    if params['config']!='undefended':raise ValueError('unknown credential configuration')
    context=ssl.create_default_context(cafile=params['ca'])
    conn=None
    try:
        for method,host,path,headers,body in frames:
            if conn is None:
                conn=http.client.HTTPSConnection(host,port,context=context,timeout=remaining())
            try:
                conn.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
                if not any(k=='host' for k,v in headers):conn.putheader('Host',host)
                for name,value in headers:conn.putheader(name,value)
                if body or method=='POST':conn.putheader('Content-Length',str(len(body)))
                conn.endheaders(body)
                r=conn.getresponse();data=r.read(65537)
                if len(data)>65536:raise ValueError('direct response bound')
                raw=json.dumps({'status':r.status,'headers':r.getheaders()}).encode()+b'\n'+data
                results.append({'complete':True,'category':1,'status':r.status,'body':data,'raw':raw,'error':None})
            except (OSError,http.client.HTTPException) as exc:
                results.append({'complete':False,'category':None,'status':None,'body':b'',
                                'raw':b'','error':type(exc).__name__})
                break
    finally:
        if conn is not None:conn.close()
    return results
