"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import json
import os
from pathlib import Path
import secrets
import time
from common import json_bytes
from deploy_catalog import PYTHON
from upstream import Upstream,wait_for
from cb_profile import ENDPOINTS

class CredentialUpstream(Upstream):
    def __init__(self,*a,**k):
        super().__init__(*a,**k)
        # CB-14 条款 8: a second service on the bypass port 8443, its own stdout stream. CB-01–12 never touch it.
        self.keep_child=None;self.keep_cursor=0;self.keep_pending=b'';self.keep_events=[];self.keep_mark=0

    def keep_poll(self):
        if self.keep_child is None:return self.keep_events
        data=bytes(self.keep_child.buffers["stdout"])
        self.keep_pending+=data[self.keep_cursor:]
        self.keep_cursor=len(data)
        while b"\n" in self.keep_pending:
            line,self.keep_pending=self.keep_pending.split(b"\n",1)
            self.keep_events.append(json.loads(line))
        return self.keep_events

    def exchange(self,mode,secret):
        result=self.command([*PYTHON,str(Path(__file__).with_name('cb_service_client.py')),
                             str(self.root/'tls/ca.pem'),mode],timeout=5,env={'NB_HTTPS_SECRET':secret})
        rows=json.loads(result['stdout'])
        if {(x['host'],x['port']) for x in rows}!=set(ENDPOINTS) or not all(x['ok'] for x in rows):
            raise ValueError('endpoint exchange coverage incomplete')
        return rows

    def route(self,source,path):
        """Inside an open window only; the judge reads the request from the service record."""
        if self.current is None:raise RuntimeError('route control outside an attempt window')
        result=self.command([*PYTHON,str(Path(__file__).with_name('cb_service_client.py')),
                             str(self.root/'tls/ca.pem'),'route',source,path],timeout=5)
        receipt=json.loads(result['stdout'])
        if receipt.get('ok') is not True or receipt.get('path')!=path:raise ValueError('route control receipt mismatch')
        return receipt

    def start(self):
        fd=self.info['upstream']['fd']
        if not self.network.prepared or self.network.closed or fd not in self.network.fds or self.child:
            raise RuntimeError('no owned network for credential service')
        secret=secrets.token_hex(24);seconds=self.command.deadline.left(540)
        self.child=self.command.start(['/usr/bin/nsenter',f'--net=/proc/{os.getpid()}/fd/{fd}','--',
            *PYTHON,str(Path(__file__).with_name('cb_service.py')),str(self.root),str(seconds),'NB_READY_SECRET'],
            timeout=seconds,interactive=True,env={'NB_READY_SECRET':secret})
        wait_for(self.command,lambda:any(x.get('kind')=='ready' for x in self.poll()),child=self.child)
        self.readiness=self.exchange('ready',secret)
        # CB-14 条款 8: start the keep-alive upstream on 8443 in the same decoy netns (additive; CB-01–12 do not use it).
        keep_secret=secrets.token_hex(24)
        self.keep_child=self.command.start(['/usr/bin/nsenter',f'--net=/proc/{os.getpid()}/fd/{fd}','--',
            *PYTHON,str(Path(__file__).with_name('cb_keep_service.py')),str(self.root),str(seconds),'NB_KEEP_SECRET'],
            timeout=seconds,interactive=True,env={'NB_KEEP_SECRET':keep_secret})
        wait_for(self.command,lambda:any(x.get('kind')=='keep-ready' and x.get('secret')==keep_secret
                                         for x in self.keep_poll()),child=self.keep_child)
        return self

    def begin(self,attempt):
        if self.current or self.closed or not self.child:raise RuntimeError('invalid window start')
        self.keep_mark=len(self.keep_poll())  # CB-14: keep records from here to end() belong to this attempt
        secret=secrets.token_hex(24);start=len(self.poll())
        self.command.send_input(self.child,json_bytes({'op':'begin','attempt':attempt,'secret':secret}))
        row=wait_for(self.command,lambda:next((x for x in self.poll()[start:] if x.get('kind')=='window'
                                              and x['attempt']==attempt),None),child=self.child)
        self.current=(attempt,secret,row['cursor'],start)
        return row['cursor']

    def end(self):
        if self.current is None:raise RuntimeError('no open credential window')
        attempt,secret,cursor,start=self.current
        end=time.monotonic()+1
        while time.monotonic()<end:self.command.pump(.02)
        self.exchange('end',secret)
        self.command.send_input(self.child,json_bytes({'op':'finish','secret':secret}))
        marker=wait_for(self.command,lambda:next((e for e in self.poll()[start:] if e.get('kind')=='end'
                                                and e.get('token')==secret),None),child=self.child)
        events=self.poll()[start:]
        endpoints=[e for e in events if e.get('kind')=='endpoint-end']
        if (len(endpoints)!=len(ENDPOINTS) or {(x['host'],x['port']) for x in endpoints}!=set(ENDPOINTS)
                or any(x.get('token')!=secret or x.get('attempt')!=attempt for x in endpoints)):
            raise ValueError('endpoint closure witness incomplete')
        requests=[e for e in events if e.get('kind')=='request']
        for e in endpoints:
            local=[x for x in requests if (x['host'],x['port'])==(e['host'],e['port'])]
            if [x['endpoint_seq'] for x in local]!=list(range(e['endpoint_seq'])):
                raise ValueError('endpoint sequence gap')
        self.current=None
        keep_requests=[e for e in self.keep_poll()[self.keep_mark:] if e.get('kind')=='keep-request']
        return {'cursor':cursor,'end':marker,'requests':requests,'endpoints':endpoints,'keep_requests':keep_requests}

    def close(self):
        if not self.closed and self.keep_child is not None:
            try:
                self.command.close_input(self.keep_child)
                self.command.wait(self.keep_child)
                self.keep_poll()
            except Exception:
                pass  # keep stream is best-effort for 试跑; cb_service closure below is the strict one
        super().close()
