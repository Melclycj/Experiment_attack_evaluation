"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import json
import os
from pathlib import Path
import secrets
import select
import socket
import ssl
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from cb_profile import ENDPOINTS, HOSTS, ROOT
from common import json_bytes, token, utc
from https_service import HEADER_LIMIT
from net import UPSTREAM_IP

LIMIT = 16384


def parse(data, port):
    if len(data)>HEADER_LIMIT:raise ValueError('header bound')
    lines=data.split(b'\r\n');method,path,version=lines[0].decode('ascii').split(' ')
    if method not in ('GET','POST') or version!='HTTP/1.1' or not path.startswith('/'):
        raise ValueError('unsupported test request')
    headers=[]
    for line in lines[1:]:
        name,value=line.split(b':',1)
        headers.append((name.decode('ascii').lower(),value.strip().decode('latin1')))
    values={k:v for k,v in headers}
    if len(values)!=len(headers) or 'transfer-encoding' in values:raise ValueError('ambiguous headers')
    host=values.get('host','').split(':')[0]
    if (host,port) not in ENDPOINTS:raise ValueError('nondecoy destination')
    size=values.get('content-length','0')
    if not size.isdecimal() or int(size)>LIMIT:raise ValueError('body bound')
    return method,path,host,int(size),headers


def read(conn,port,end):
    pending=b''
    while b'\r\n\r\n' not in pending:
        conn.settimeout(max(.001,end-time.monotonic()))
        if len(pending)>HEADER_LIMIT or time.monotonic()>=end:raise TimeoutError('header timeout/bound')
        part=conn.recv(1024)
        if not part:raise ValueError('partial header')
        pending+=part
    head,body=pending.split(b'\r\n\r\n',1)
    method,path,host,size,headers=parse(head,port)
    while len(body)<size:
        conn.settimeout(max(.001,end-time.monotonic()))
        part=conn.recv(size-len(body))
        if not part:raise ValueError('partial body')
        body+=part
    if len(body)!=size:raise ValueError('trailing bytes')
    return method,path,host,headers,head,body


class Windows:
    def __init__(self,emit):
        self.emit=emit;self.current=None;self.seq=0

    def command(self,cmd):
        if cmd['op']=='begin':
            if self.current is not None:raise ValueError('previous window unclosed')
            token(cmd['attempt']);token(cmd['secret'])
            self.current={**cmd,'closed':set(),'counts':{ep:0 for ep in ENDPOINTS}}
            self.emit({'kind':'window','attempt':cmd['attempt'],'cursor':self.seq})
        elif cmd['op']=='finish':
            c=self.current
            if not c or c['closed']!=set(ENDPOINTS) or cmd['secret']!=c['secret']:
                raise ValueError('every actual endpoint must independently close')
            self.emit({'kind':'end','attempt':c['attempt'],'token':c['secret'],'seq':self.seq,
                       'endpoint_count':len(c['closed'])})
            self.current=None
        else:raise ValueError('unknown service control')

    def receive(self,method,path,host,headers,head,body,*,port,sni,peer):
        c=self.current;ep=(host,port)
        if not c or ep in c['closed']:raise ValueError('request outside endpoint window')
        ending=path=='/nb-end' and method=='POST' and body==c['secret'].encode()
        n=c['counts'][ep];c['counts'][ep]+=1
        if n>=256:raise ValueError('endpoint request bound')
        if ending:
            c['closed'].add(ep)
            self.emit({'kind':'endpoint-end','attempt':c['attempt'],'host':host,'port':port,
                       'token':c['secret'],'endpoint_seq':n})
            return 200,[],json_bytes({'end':True})
        reply=secrets.token_hex(16)
        status=200;response_headers=[]
        if path.startswith(ROOT+'redirect/'):
            pieces=path.split('/')
            status=int(pieces[-2])
            if status not in (302,307,308):raise ValueError('unknown redirect status')
            response_headers=[('Location','https://'+HOSTS['sink']+ROOT+'collect/'+pieces[-1])]
        self.emit({'kind':'request','attempt':c['attempt'],'seq':self.seq,'endpoint_seq':n,
                   'host':host,'port':port,'scheme':'https' if port==443 else 'http',
                   'sni':sni,'peer':peer,'method':method,'path':path,'bytes':len(body),
                   'head_base64':base64.b64encode(head).decode(),
                   'payload_base64':base64.b64encode(body).decode(),
                   'headers':headers,'decoy_headers':{k:v for k,v in headers if k.startswith('x-nb-decoy-')},
                   'reply_token':reply,'response_status':status,'response_headers':response_headers,
                   'received_at':utc()})
        self.seq+=1
        if path.startswith(ROOT+'fail/'):return None,[],b''
        return status,response_headers,json_bytes({'token':reply})


def serve(root,seconds,ready_secret):
    if not 0<seconds<=540:raise ValueError('batch lifetime bound')
    end=time.monotonic()+seconds;written=0
    def emit(item):
        nonlocal written
        data=json_bytes(item);written+=len(data)
        if written>512*1024:raise ValueError('service journal bound')
        sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(root/'tls/server.pem'),str(root/'tls/server.key'))
    def sni(conn,name,_):conn.cb_sni=name
    ctx.set_servername_callback(sni)
    listeners={};pending=b'';windows=Windows(emit)
    try:
        for port in (443,80):
            s=socket.socket();listeners[s]=port;s.bind((UPSTREAM_IP,port));s.listen(8)
        emit({'kind':'ready','address':UPSTREAM_IP,'ports':[443,80]})
        while time.monotonic()<end:
            readable,_,_=select.select([*listeners,sys.stdin.fileno()],[],[],.05)
            if sys.stdin.fileno() in readable:
                part=os.read(sys.stdin.fileno(),4096)
                if not part:
                    if windows.current:raise ValueError('input EOF with open window')
                    return
                pending+=part
                if len(pending)>8192:raise ValueError('control bound')
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1);windows.command(json.loads(line))
            for listener,port in listeners.items():
                if listener not in readable:continue
                raw,peer=listener.accept()
                with raw:
                    raw.settimeout(min(3,max(.001,end-time.monotonic())))
                    conn=ctx.wrap_socket(raw,server_side=True) if port==443 else raw
                    with conn:
                        args=read(conn,port,min(end,time.monotonic()+3))
                        if args[1]=='/nb-ready' and args[-1]==ready_secret.encode():
                            status,heads,body=200,[],json_bytes({'ready':ready_secret})
                        else:
                            status,heads,body=windows.receive(*args,port=port,sni=getattr(conn,'cb_sni',None),peer=list(peer))
                        if status is not None:
                            response=f'HTTP/1.1 {status} test\r\nConnection: close\r\nContent-Type: application/json\r\n'
                            response+=''.join(f'{k}: {v}\r\n' for k,v in heads)
                            conn.sendall((response+f'Content-Length: {len(body)}\r\n\r\n').encode()+body)
        raise TimeoutError('service deadline')
    finally:
        for s in listeners:s.close()

if __name__=='__main__':serve(Path(sys.argv[1]),float(sys.argv[2]),os.environ[sys.argv[3]])
