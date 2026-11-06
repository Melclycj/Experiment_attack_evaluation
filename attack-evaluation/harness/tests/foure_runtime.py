"""4e full offline pipeline: production adapters/transport with mocked cell/OS boundaries."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from cell.nb26_worker import live_name
from common import json_bytes
from foure_fixtures import FakeCandidate, boot, fd_observation, report, candidate_rows
from nb_contract import decode, stem
from nb_io import Files
from runner import Context, run
from test_4a_integration import OfflineRuntime


class SpecialRuntime(OfflineRuntime):
    def __init__(self, root, cases, stack, failure=None):
        super().__init__(root,cases,stack)
        owned=next(iter(self.resources.roots))
        self.home=owned/'host';self.home.mkdir()
        self.rows=[];self.failure=failure;self.requests=[]
        self.cap={'first':70000,'last':70010,'spare_uid':70010}
        stack.enter_context(patch('file_tree.os.fchown'))
        stack.enter_context(patch('file_tree.os.chown'))
        stack.enter_context(patch('userns_case.Candidate',side_effect=FakeCandidate))
        stack.enter_context(patch('userns_case.SameUidControl.run',return_value={'ok':True,'source':'offline mock control'}))
        stack.enter_context(patch('userns_case.worker_ref',side_effect=lambda *a,**k:self.worker))
        stack.enter_context(patch('nb_fd.control',side_effect=self.fd_control))
        stack.enter_context(patch('nb_fd.action',side_effect=self.fd_action))

    def fd_record(self,ctx):
        adapter=self.adapter
        p=self.prepared
        p['cwd']=self.work
        return fd_observation(p,self.active=='undefended')

    def fd_control(self,ctx):
        obs,caps=self.fd_record(ctx)
        for item in obs['observed']:
            if item['phase']=='control':ctx.observe(item['label'],**item['values'])
        for item in obs['captures']:
            if item['phase']=='control':ctx.capture(item['label'],caps[item['path']])
        return True

    def fd_action(self,ctx):
        obs,caps=self.fd_record(ctx)
        for item in obs['observed']:
            if item['phase']=='action':ctx.observe(item['label'],**item['values'])
        for item in obs['captures']:
            if item['phase']=='action':ctx.capture(item['label'],caps[item['path']])
        if self.failure=='fd-missing-capture':ctx.record['captures']=ctx.record['captures'][:-1]

    def start(self,config,**kwargs):
        self.req=json.loads((self.work/'nb-request.json').read_bytes());self.requests.append(self.req)
        if self.req['attack'] not in ('NB-24','NB-26'):return super().start(config,**kwargs)
        self.code=None
        handle=SimpleNamespace(uid=70001 if config=='engine' else None,group=None,closed=False,
                               workspace='work0',attach=lambda:None)
        self.rows.append(handle)
        self.worker=Mock(initial={'pid':17,'start_time':88});self.worker.exited.return_value=False
        if self.req['attack']=='NB-26':
            self.live_report=report(self.req,config=='undefended')
            self.candidate.current['links']=candidate_rows(config=='undefended')
            if self.failure=='live-nonce':self.live_report['nonce']='foreign'
            if self.failure=='worker-exit':self.worker.read.side_effect=RuntimeError('worker exited during observation')
            files=Files(self.work)
            try:
                files.write(live_name(self.req),json_bytes(self.live_report))
                files.write(self.req['sync']['ready'],json_bytes({'attempt':stem(self.req),
                            'nonce':self.req['sync']['nonce'],'state':'done'}))
            finally:files.close()
        def execute(argv,**kw):
            assert argv[-1].endswith('/nb26_worker.py')
            assert decode(kw['data'])==self.req
            assert decode((self.work/self.req['sync']['release']).read_bytes())['state']=='release'
            return {'stdout':json_bytes(self.live_report),'stderr':b'','returncode':0,'signal':None,'error':None}
        def factory(*args,**kwargs):
            ctx=Context(*args,**kwargs,executor=execute)
            # The worker owns NB-26 ready/release; runner preflight happened
            # before this mock published them in start(). No OS worker is run.
            if self.req['attack']=='NB-26':ctx.preflight=lambda:None
            return ctx
        def poll():
            if self.code is None:
                files,payload=Files(self.work),Files(self.payload_root)
                try:
                    self.code=run(files,payload,inherited=boot(),cwd='/work' if config=='engine' else str(self.work),
                                  context_factory=factory)
                    if self.failure=='worker-capture' and self.req['attack']=='NB-26':
                        path=self.work/(stem(self.req)+'-observed.json')
                        value=json.loads(path.read_bytes());value['captures']=[];path.write_bytes(json_bytes(value))
                finally:files.close();payload.close()
            return True
        def finish():
            handle.closed=True;self.worker.exited.return_value=True
            if self.req['attack']=='NB-26' and self.failure!='netns-restore':
                self.candidate.current=copy.deepcopy(self.candidate.before)
            return {'tree_empty':True,'runner_ok':self.code==0}
        handle.poll,handle.finish=poll,finish
        return handle
