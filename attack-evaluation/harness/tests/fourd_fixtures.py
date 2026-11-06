"""这是 1.1 隔离论证的验证测试：4d 离线夹具；只用临时文件、线程信箱与 mock，无真实攻击。"""
import errno
import json
import os
from pathlib import Path
import signal
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch
from foura_fixtures import window
from test_4a_integration import OfflineRuntime
from runner import Context, run
from nb_io import Files
from nb_engine_question import answer_bytes
from run_runtime import Runtime
from common import json_bytes


def event(step, rc=0, error=0): return {'step':step,'rc':rc,'errno':error}


def raw_events(items, stdout=b''):
    return {'stdout':stdout,'stderr':b''.join(json_bytes(e) for e in items+[event('complete')]),
            'returncode':0,'signal':None,'error':None}


def control_events():
    return [event(name,777 if name in ('control_fork','control_wait_stop','control_reap') else 0)
            for name in ('control_fork','control_stop','control_wait_stop','control_state',
                         'control_resume','control_kill','control_reap')]


class Ref:
    def __init__(self,pid,uid):
        self.value={'pid':pid,'start_time':pid*10,'uids':[uid]*4,'state':'S','cgroup':'0::/offline'}
        self.signals=[]
    def read(self): return dict(self.value)
    def send(self,sig):
        assert sig == signal.SIGCONT
        self.signals.append(sig); self.value['state']='S'


def seed(rt, root):
    rt.deployment.root=root
    state=root/'state';(state/'workspaces').mkdir(parents=True)
    credentials=state/'credentials'/'nb-decoy-upstream.test:443';credentials.mkdir(parents=True)
    paths={'mirror':state/'workspaces/work0.json','e09':root/'nb-decoy-e09.jsonl',
           'credentials':credentials,'admin':state/'admin.sock'}
    # The v4 mirror as engine/workspaces.py at a9eff999 writes it (MIRROR_VERSION 3): "objects" on the table,
    # "addresses" on every entry; read back from a formal run's raw mirror.
    mirror={'v':3,'workspace_id':'work0','root':str(rt.work),'device':1,'inode':2,'objects':[],
            'entries':[{'key_kind':3,'key':'','state':1,'methods':['GET'],'prefixes':[],'accounts':[],'approval':1,
                        'addresses':[]}]}
    def put(path,data):
        path.write_bytes(data);path.chmod(0o600);os.chown(path,1000,1000)
    put(paths['mirror'],json_bytes(mirror));put(paths['e09'],b'{"offline":"original audit"}\n')
    generations=[0]
    def credential(truth, witness):
        # engine-v2-go layout (648d60f2): every registration writes the next generation's truth file, then the
        # metadata naming it, then removes the older generation; a number is never reused within a run
        generations[0]+=1;gen=generations[0]
        put(credentials/f'nb-decoy-account.{gen}.truth_a',truth.encode())
        put(credentials/'nb-decoy-account.json',json_bytes({'generation':gen,'has_truth_b':False,
            'token_endpoint':'https://nb-decoy-upstream.test/'+witness}))
        old=credentials/f'nb-decoy-account.{gen-1}.truth_a'
        if old.exists():old.unlink()
    rt.deployment.state_paths=lambda:paths
    rt.deployment.admin.credential.side_effect=credential
    rt.deployment.admin.watcher=Mock()  # batch-prepared watcher, not an attempt child
    rt.deployment.admin.watch.side_effect=lambda:setattr(rt.deployment.admin,'watcher',Mock())
    rt.deployment.refs.update(core=Ref(100,1000),spawner=Ref(101,0))
    return paths


class ObjectRuntime(OfflineRuntime):
    def __init__(self,root,cases,stack):
        super().__init__(root,cases,stack)
        own=next(iter(self.resources.roots))
        self.paths=seed(self,own);self.home=own
        self.rows=[];self.threads=[];self.arrivals=[];self.requests=[];self.qid=7
        self.command.pump=lambda *args:None
        self.cancel=threading.Event()
        self.paired_targets=lambda t,c:Runtime.paired_targets(self,t,c)
        self.deployment.admin.question.side_effect=self.question
        stack.enter_context(patch('engine_cases.inspect_listener', side_effect=lambda ref,target:{
            'listening':True,'target':dict(target),'inode':901}))
        import nb_engine_actions as actions
        rewrite=actions.rewrite
        def modeled_rewrite(ctx,path):
            if ctx.phase=='action' and ctx.request['config']=='engine':
                ctx.capture('mirror',b'');value={'path':path,'errno':errno.ENOENT,'identity':None,'step':'open','valid':True}
                ctx.observe('mirror-result',**value);return value
            path= self.translate(path)
            # Real Python rewrite touches only the temporary fixture. Keep the
            # reported cell-visible path, not this offline translation.
            orig=ctx.observe
            def observe(label,**value):
                if label=='mirror-result': value['path']=self.cell_path(path,ctx)
                return orig(label,**value)
            ctx.observe=observe
            try:return rewrite(ctx,path)
            finally:ctx.observe=orig
        stack.enter_context(patch('nb_engine_actions.rewrite',side_effect=modeled_rewrite))
        stack.enter_context(patch('nb_engine_actions.socket_control',side_effect=self.socket_control))
        stack.enter_context(patch('nb_engine_actions.answer',side_effect=self.answer))
        runtime=self
        class Pending:
            def __init__(self,ctx,path):self.ctx,self.path=ctx,path
            def wait_sent(self):pass
            def finish(self,cancel=False):
                self.ctx.capture('response',b'')
                self.ctx.observe('response-result',path=self.path,complete=True,cancelled=cancel,category=1,status=200)
            def close(self):pass
        stack.enter_context(patch('nb_engine_actions.PendingRequest',Pending))

    def translate(self,path):return str(self.work)+path[len('/work'):] if path.startswith('/work/') else path
    def cell_path(self,path,ctx):
        return '/work'+path[len(str(self.work)):] if ctx.phase=='control' and ctx.request['config']=='engine' else path

    def arm(self,config):
        self.active=config;self.support=SimpleNamespace(items={})
        for role,ws in [('victim','work1'),('auxiliary','work2')]:
            execution=role+':1' if config=='engine' or role=='auxiliary' else None
            row=SimpleNamespace(workspace=ws,execution=execution,closed=False)
            self.rows.append(row);self.support.items[role]={'row':row}
            if execution:
                self.deployment.refs['connector:'+execution]=Ref(102 if role=='victim' else 103,70999)
                self.deployment.refs['file-worker:'+execution]=Ref(104 if role=='victim' else 105,70996)  # v4
        def signal_victim():
            row=self.support.items['victim']['row']
            row.execution='victim:1'
            self.deployment.refs['connector:victim:1']=Ref(102,70999)
            self.deployment.refs['file-worker:victim:1']=Ref(104,70996)
        self.support.ensure_signal_victim=signal_victim
        self.support.begin_question=lambda path:self.question(execution='auxiliary:1',path=path)
        self.support.question_result=lambda:{'path':'/'+self.req['parameters']['request_sentinel'],'complete':True,'status':200}
        # Previous support rows belong to the old arm, not additional live rows.
        for row in self.rows[:-2]:row.closed=True

    def question(self,execution,path,timeout=10):
        return {'qid':self.qid,'execution':execution,'workspace':'work0' if execution=='attack:1' else 'work2',
                'method':'POST','host':'nb-decoy-question.test','path':path,'scheme':'https','port':'443'}

    def socket_control(self,ctx):
        p=ctx.request['parameters'];path=ctx.cwd+'/'+p['controls']['admin'];data=answer_bytes(1)
        ctx.capture('admin',data);ctx.capture('admin-received',data)
        ctx.observe('admin-result',path=path,qid=1,errno=0,step='sent');return True

    def answer(self,ctx,path,qid):
        code=errno.ENOENT if ctx.request['config']=='engine' else 0
        ctx.capture('admin',b'' if code else answer_bytes(qid))
        value={'path':path,'qid':qid,'errno':code,'step':'connect' if code else 'sent'}
        ctx.observe('admin-result',**value)
        if not code:self.arrivals.append({'method':'POST','host':'nb-decoy-question.test',
                                         'path':'/'+ctx.request['parameters']['request_sentinel']})
        return value

    def execute_command(self,ctx,argv,**kwargs):
        op=argv[1]
        if op=='stop-control':return raw_events(control_events())
        denied=ctx.phase=='action' and ctx.request['config']=='engine'
        if op=='stop':
            if denied:return raw_events([event('proc_open',-1,errno.ENOENT),event('kill',-1,errno.ESRCH)])
            ref=next(r for r in self.deployment.refs.values() if r.read()['pid']==int(argv[2]))
            code=0 if ref.read()['uids']==[1000]*4 else errno.EPERM
            if not code:ref.value['state']='T'
            return raw_events([event('proc_open',3),event('proc_read',80),event('proc_close'),
                               event('process_identity_match'),event('kill',-1 if code else 0,code)])
        if denied:return raw_events([event('open',-1,errno.ENOENT)])
        path=Path(self.translate(argv[2]));s=path.stat();data=path.read_bytes() if op=='read' else b''
        if op=='truncate':path.write_bytes(kwargs['data'])
        items=[event('open',3),event('fstat'),dict(event('identity'),dev=s.st_dev,ino=s.st_ino,size=s.st_size)]
        items += ([event('read',len(data)),event('read')] if op=='read' else [event('write',len(kwargs['data'])),event('fsync')])
        return raw_events(items+[event('close')],data)

    def start(self,config,**kwargs):
        self.req=json.loads((self.work/'nb-request.json').read_bytes());self.requests.append(self.req)
        self.arrivals=[];state={'code':None,'thread':None}
        row=SimpleNamespace(execution='attack:1' if config=='engine' else None,workspace='work0',closed=False)
        self.rows.append(row)
        def factory(*args,**kw):
            def sleep(delay):
                if self.cancel.wait(delay): raise RuntimeError('offline fixture cancelled')
            ctx=Context(*args,sleep=sleep,**kw)
            ctx.executor=lambda argv,**k:self.execute_command(ctx,argv,**k)
            return ctx
        def work():
            files,payload=Files(self.work),Files(self.payload_root)
            try:
                state['code']=run(files,payload,cwd='/work' if config=='engine' else str(self.work),context_factory=factory)
            finally:files.close();payload.close()
        def poll():
            if state['thread'] is None:
                state['thread']=threading.Thread(target=work);self.threads.append(state['thread']);state['thread'].start()
            return not state['thread'].is_alive()
        def finish():
            state['thread'].join(1);row.closed=True
            return {'tree_empty':True,'runner_ok':state['code']==0}
        row.poll,row.finish=poll,finish
        return row

    def pump(self):time.sleep(.001)
    def window(self):
        w=window(self.arrivals);nonce=self.req['sync']['nonce'];w['end']['attempt']=nonce
        for item in w['requests']:item['attempt']=nonce
        return w
    def close(self):
        self.cancel.set()
        for thread in self.threads:thread.join(2)
        if any(thread.is_alive() for thread in self.threads):raise RuntimeError('offline thread leaked')
        return {'ok':True,'failures':[],'retained':[],'steps':[]}
