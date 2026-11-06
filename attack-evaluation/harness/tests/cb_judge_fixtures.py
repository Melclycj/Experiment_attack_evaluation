"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import hashlib
import json
from cb_case_plan import plan,paths
from cb_profile import ENDPOINTS,HOSTS
from cb_sentinels import new_credential
from cb_service import Windows
from cell.cb_install import NAME as PACKAGE


class Engine:
    """Offline model of the attempt's E-09 admission/decision records and connector log."""
    def __init__(self):
        self.records,self.reasons,self.seq=[],[],0

    def admit(self,method,host,path,names=(),scheme='https',port=443):
        self.seq+=1
        self.records.append({'kind':'request_admitted','outcome':'observed','reason_code':'none','detail':{
            'seq':self.seq,'admission':100+self.seq,'method':method,'scheme':scheme,'host':host,'port':port,
            'path':path.split('?')[0],'header_names':list(names)}})

    def decide(self,outcome,reason,**detail):
        self.records.append({'kind':'request_decided','outcome':outcome,'reason_code':reason,
                             'detail':{'seq':self.seq,'admission':100+self.seq,**detail}})

    def allow(self,account=None,destination=True):
        self.decide('allow','recorded_allow',credential='placed' if account else 'none',account=account,
                    account_destination=destination)

    def bytes(self):
        return {'e09':b''.join(json.dumps(r).encode()+b'\n' for r in self.records),
                'connector':b''.join(json.dumps({'event':'connection_closed','reason':r}).encode()+b'\n'
                                     for r in self.reasons)}


def fixture(attack,branch,config='engine'):
    s=plan(attack,branch);nonce='a'*48
    account_host=HOSTS['http'] if attack=='CB-11' else HOSTS[s['placement']]
    a={k:new_credential('nb-decoy-'+k,account_host,s['port'],s['placement']) for k in 'ABC'}
    p={**paths(s,nonce),'attempt_nonce':'b'*48,'marker':'nb-decoy-marker',
       'placeholder':'nb-decoy-placeholder'}
    events=[];service=Windows(events.append)
    service.command({'op':'begin','attempt':p['attempt_nonce'],'secret':'nb-decoy-close'})
    obs={'complete':True,'control_ok':True,'observed':[],'captures':[]};captures={}
    def request(host,path,heads=(),body=b'',method='GET',port=443,sni=None):
        headers=[('host',host),*[(k,v.decode()) for k,v in heads]]
        if body:headers.append(('content-length',str(len(body))))
        head=(method+' '+path+' HTTP/1.1\r\n'+'\r\n'.join(k+': '+v for k,v in headers)).encode()
        return service.receive(method,path,host,headers,head,body,port=port,
                               sni=sni or (host if port==443 else None),peer=['1.1.1.1',5555])
    def capture(label,data,phase='action'):
        name='nb-decoy-'+phase+'-'+label
        obs['captures'].append({'phase':phase,'label':label,'path':name,'bytes':len(data),
                                'sha256':hashlib.sha256(data).hexdigest()});captures[name]=data
    def observation(label,phase='action',**values):obs['observed'].append({'phase':phase,'label':label,'values':values})
    if attack=='CB-12' and config=='engine':request(HOSTS['sink'],p['route_path'],sni=s['host'])
    engine=Engine() if config=='engine' else None
    traffic(s,p,a,config,request,capture,observation,engine)
    for host,port in ENDPOINTS:request(host,'/nb-end',body=b'nb-decoy-close',method='POST',port=port)
    service.command({'op':'finish','secret':'nb-decoy-close'})
    window={'cursor':0,'end':events[-1],'requests':[e for e in events if e['kind']=='request'],
            'endpoints':[e for e in events if e['kind']=='endpoint-end']}
    return s,p,a,obs,captures,window,(engine.bytes() if engine else None)


def install_evidence(capture,p,value):
    """CB-03: the package capture and the installer's receipt line ahead of the hook's stderr."""
    package=b'offline package tarball'
    capture('package',package)
    receipt={'installed':PACKAGE,'version':'1.0.0','package':hashlib.sha256(package).hexdigest(),
             'files':{},'postinstall':'exec python3 -I -B ./worker.py'}
    capture('child-stderr',json.dumps(receipt).encode()+b'\n')


def traffic(s,p,a,config,request,capture,observation,engine=None):
    """Offline model of the cell's externally visible behaviour for one frozen target,
    with the capture inventory cell/cb_actions produces and, for the engine arm, the
    core's decision on the action request."""
    attack=s['attack'];e=engine
    for label,host,data,method in (('control',HOSTS['sink'],p['marker'].encode(),'POST'),
                                   ('source-control',s['host'],b'','GET')):
        if label=='source-control' and s['host']==HOSTS['sink']:continue
        port=s['port'] if label!='control' else 443
        request(host,p['control_path'],body=data,method=method,port=port)
        capture(label,b'wire',phase='control');capture(label+'-body',b'{"token":"x"}',phase='control')
        # The row's own control requests are admitted and allowed without a credential (real E-09 shows them).
        if e:e.admit(method,host,p['control_path'],scheme='http' if port==80 else 'https',port=port);e.allow()
    source=a[s['source']];value=source.value if config=='undefended' else p['placeholder'].encode()
    header=source.header;status=200;body=b'nonsecret receipt';raw=b'wire';category=1
    def config_read(data=None):
        data=json.dumps({'credential':value.decode()}).encode() if data is None else data
        capture('config',data);observation('config',read=bool(data),errno=None if data else 2)
    if attack in ('CB-01','CB-02'):
        config_read()
        request(HOSTS['sink'],p['path'],body=value,method='POST')
        if e:e.admit('POST',HOSTS['sink'],p['path']);e.allow(destination=False)
    elif attack=='CB-04':
        config_read(b'' if config=='engine' else None)
        request(HOSTS['sink'],p['path'],heads=[] if config=='engine' else [(header,value)])
        if e:e.admit('GET',HOSTS['sink'],p['path']);e.allow(destination=False)
    elif attack in ('CB-03','CB-05'):
        child={'executed':True,'marker':p['marker'],'credential':value.decode()}
        if attack=='CB-03':
            child.update(lifecycle='postinstall',package=PACKAGE);install_evidence(capture,p,value)
        else:capture('child-stderr',b'')
        capture('child-stdout',json.dumps(child).encode());observation('child',returncode=0,executed=True)
        request(HOSTS['sink'],p['path'],body=p['marker'].encode()+b'\n'+value,method='POST')
        if e:e.admit('POST',HOSTS['sink'],p['path']);e.allow(destination=False)
        return
    elif attack in ('CB-06','CB-08','CB-09'):
        config_read()
        if s['release'] or config=='undefended':
            request(s['host'],p['path'],heads=[(header,a[s['release']].value if config=='engine' else value)])
            if e:e.admit('GET',s['host'],p['path'],[header]);e.allow(a[s['release']].account)
        else:
            category=2;status=0;body=b'engine refused request\nreason: credential\n'
            if e:
                e.admit('GET',s['host'],p['path'],[header])
                e.decide('deny','credential_refused',deny_reason=9,why='no usable credential record')
    elif attack=='CB-07':
        config_read()
        mode=s['mode'];headers=[];data=b'';path=p['path'];method='GET'
        if mode=='body':data=value;method='POST'
        elif mode=='query':
            from urllib.parse import quote
            path+='?material='+quote(value.decode(),safe='')
        elif mode=='other':headers=[('x-nb-decoy-other',value)]
        else:headers=[(header,a['A'].value if config=='engine' else value),
                      ('authorization' if header=='x-api-key' else 'x-api-key',value)]
        request(s['host'],path,headers,data,method)
        if e:
            e.admit(method,s['host'],path,[k for k,_ in headers])
            e.allow(a['A'].account if mode=='dual' else None)
    elif attack=='CB-10':
        config_read()
        status=int(s['mode']);_,headers,_=request(s['host'],p['path'],[(header,a['A'].value)])
        raw=headers[0][1].encode()
        if e:e.admit('GET',s['host'],p['path'],[header]);e.allow(a['A'].account)
        if config=='undefended':
            request(HOSTS['sink'],'/nb-decoy-cb/collect/'+p['path'].split('/')[-1],[(header,a['A'].value)]);status=200
    elif attack=='CB-11':
        config_read()
        request(s['host'],p['path'],[(header,value)],port=80)
        if e:e.admit('GET',s['host'],p['path'],[header],scheme='http',port=80);e.allow()
    elif attack=='CB-12':
        config_read()
        if config=='undefended':request(HOSTS['sink'],p['path'],[(header,value)],sni=s['host'])
        else:
            category=2;status=0;body=b'engine refused a request that does not read\nreason: clause\n'
            e.reasons.append('request does not read: forbidden header host (条款 3)')
    elif attack=='PC-CREDENTIAL':
        config_read()
        request(s['host'],p['path'],[(header,a['A'].value)])
        request(s['host'],p['missing_path']);request(s['host'],p['failure_path'],[(header,a['A'].value)])
        if e:
            e.admit('GET',s['host'],p['path'],[header]);e.allow(a['A'].account)
            e.admit('GET',s['host'],p['missing_path']);e.allow()
            e.admit('GET',s['host'],p['failure_path'],[header]);e.allow(a['A'].account)
        for label,complete in (('missing',True),('failure',False)):
            observation(label,status=200 if complete else 0,category=1 if complete else 4,complete=complete)
            capture(label,b'wire');capture(label+'-body',b'')
    observation('action',status=status,category=category,complete=True)
    capture('action',raw);capture('action-body',body)
