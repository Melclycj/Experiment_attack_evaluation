"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import json
import secrets
from pathlib import Path
from cb_accounts import Accounts, host_port
from cb_case_plan import plan, paths
from cb_profile import HOSTS, ROOT
from cell.cb_spec import BRANCHES, mechanism
from case_io import WorkspaceFiles
from common import identity, json_bytes
from listener_witness import inspect_listener, pin_child
from net import UPSTREAM_IP
from safeio import read_beneath


class CredentialCase:
    """A host adapter. Accounts, releases and expectations never come from the cell."""
    def __init__(self, runtime, attack, branches=None):
        self.rt,self.attack=runtime,attack
        self.branches=tuple(branches or BRANCHES[attack])
        self.accounts=None;self.files=None;self.current=None

    def contract(self):
        return {'attack':self.attack,'targets':list(self.branches),
                'construction':{key:plan(self.attack,key) for key in self.branches},
                'operations':['declare-accounts','reference-rows','controlled-action','scan-all-outlets','restore'],
                'baseline':'engine-placeholder / undefended-preseeded-synthetic-truth'}

    def prepare_branch(self, config, repeat, contract, branch):
        if config not in ('engine','undefended') or contract!=self.contract():
            raise ValueError('credential contract/config changed')
        if self.accounts is not None:raise ValueError('previous credential target not restored')
        spec=plan(self.attack,branch);rt=self.rt
        self.accounts=Accounts(rt.deployment)
        account_host=HOSTS['http'] if self.attack=='CB-11' else HOSTS[spec['placement']]
        values=self.accounts.create(account_host,spec['port'],spec['placement'])
        rt.own(values.values(),self.attack,config,branch)
        self.current={'spec':spec,'accounts':values,'config':config,'branch':branch,'entries':[],'references':[]}
        try:
            for c in values.values():self.accounts.register(c)
            # :80 truth is independent of the corresponding HTTPS reference truth.
            references=values
            if self.attack=='CB-11':
                references=self.accounts.create(HOSTS[spec['placement']],443,spec['placement'])
                rt.own(references.values(),self.attack,config,branch)
                for c in references.values():self.accounts.register(c)
            self.current['reference_accounts']=references
            self.current['metadata']=list(self.accounts.receipts)
            self.current['all_accounts']=list(self.accounts.credentials)
            self.entry('work0',HOSTS['sink'],443,())
            self.entry('work1',HOSTS['sink'],443,())
            self.entry('work0',spec['host'],spec['port'],[values[x].account for x in spec['accounts']])
            selected=spec['selected']
            rt.row_accounts={'work0':[(host_port(spec['host'],spec['port']),values[selected].account)] if selected else []}
            self.files=WorkspaceFiles(rt,'work0')
            nonce=secrets.token_hex(24);marker='nb-decoy-marker-'+secrets.token_hex(24)
            placeholder='nb-decoy-placeholder-'+secrets.token_hex(24)
            p={**paths(spec,nonce),'host':spec['host'],'port':spec['port'],'scheme':spec['scheme'],
               'header':values[spec['source']].header,'branch_mode':spec['mode'],'marker':marker,
               'placeholder':placeholder,'ca':str(rt.deployment.root/'tls/ca.pem'),
               'config_path':'nb-decoy-cb-input-'+nonce,'config':config}
            value=values[spec['source']].value.decode() if config=='undefended' else placeholder
            if not (config=='engine' and self.attack=='CB-04'):
                before=self.files.write(p['config_path'],json_bytes({'credential':value,'marker':marker}))
            else:
                self.files.reserve(p['config_path']);before={'exists':False,'reason':'no-service-account-material-in-cell'}
            if self.attack in ('CB-03','CB-05'):
                for field in ('worker_name','package_name','worker_request','worker_ready','worker_release'):
                    p[field]=self.files.reserve('nb-decoy-'+field.replace('_','-')+'-'+nonce)
            rt.undefended_environment=({'NB_DECOY_CREDENTIAL':value,'NB_DECOY_MARKER':marker}
                                      if config=='undefended' else {})
            ref=pin_child(rt,'upstream-service',rt.deployment.upstream.child,0)
            target={'kind':'inet','address':UPSTREAM_IP,'port':spec['port']}
            rt.targets.add_listener(branch,target,ref,lambda:inspect_listener(ref,target))
            self.current.update(targets={branch:target},parameters=p,
                before={'config':before,'accounts':self.current['metadata'],'spec':spec})
            return self.current
        except BaseException:
            # Keep exact ownership for finally/dispose; no lost partially persisted accounts.
            raise

    def entry(self, workspace, host, port, accounts):
        result=self.accounts.set_entry(workspace,host,port,accounts,(ROOT,))
        key=(workspace,host,port)
        if key not in self.current['entries']:self.current['entries'].append(key)
        mirror=read_beneath(self.rt.deployment.root,'state/workspaces/'+workspace+'.json')
        receipt={'workspace':workspace,'host':host,'port':port,'accounts':list(accounts),
                 'reply':result,'mirror':json.loads(mirror),'mirror_identity':identity(mirror)}
        self.current.setdefault('entry_receipts',[]).append(receipt)
        return receipt

    def synchronize(self, prepared, ready):
        if prepared['spec']['attack']=='CB-12' and prepared['config']=='engine':
            s=prepared['spec'];prepared['route']=self.rt.deployment.upstream.route(s['host'],prepared['parameters']['route_path'])
            return {'handshake':ready,'route_control':prepared['route']}
        return {'handshake':ready,'action':'continue-frozen-request'}

    def restore(self, prepared):
        if any(not r.closed for r in self.rt.rows):
            raise ValueError('cannot restore credential material while a row is live')
        errors=[]
        if self.files:
            try:self.files.restore()
            except Exception as exc:errors.append(str(exc))
        for workspace,host,port in reversed(prepared.get('entries',[])):
            try:self.rt.deployment.admin.call('entry','del',workspace,'exact',host_port(host,port))
            except Exception as exc:errors.append(str(exc))
        if self.accounts:
            try:self.accounts.close()
            except Exception as exc:errors.append(str(exc))
        self.rt.undefended_environment={};self.rt.row_accounts={}
        if errors:raise RuntimeError('credential restore failed: '+'; '.join(errors))
        for key,value in prepared.get('targets',{}).items():self.rt.targets.release(key,value)
        self.accounts=self.files=self.current=None

    def dispose(self):
        if self.files:self.files.close()
