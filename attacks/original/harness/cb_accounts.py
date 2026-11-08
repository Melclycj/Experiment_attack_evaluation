"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Controller-only synthetic accounts. Truth goes through private files, never argv/env.
import json
import os
from pathlib import Path
import secrets
from cb_profile import ENDPOINTS, KEEP_ENDPOINTS, ROOT
from cb_sentinels import new_credential
from common import identity, json_bytes, token
from safeio import atomic_write, plain_path, read_owned


def host_port(host, port):
    # KEEP_ENDPOINTS (CB-14 条款 8 的 8443 保持连接端点) is a valid account/entry destination though it never
    # joins the window-closure ENDPOINTS. CB-01–12 only ever pass ENDPOINTS destinations, so this branch is theirs alone.
    if (host,port) not in ENDPOINTS and (host,port) not in KEEP_ENDPOINTS:
        raise ValueError('account destination is not an explicit test endpoint')
    return host + ':' + str(port)


def entry_arguments(workspace, host, port, accounts, prefixes):
    if workspace not in ('work0','work1','work2'):
        raise ValueError('unknown test workspace')
    accounts = tuple(accounts)
    if len(accounts)>3 or len(set(accounts))!=len(accounts):
        raise ValueError('bounded distinct test accounts required')
    prefixes = tuple(prefixes)
    if not prefixes or any(not p.startswith(ROOT) or '?' in p or '#' in p or '..' in p.split('/') for p in prefixes):
        raise ValueError('entry paths must be frozen credential decoys')
    args = ['entry','put',workspace,'exact','allow',host_port(host,port),
            '--method','GET','--method','POST','--approval','never']
    for account in accounts:
        if not token(account).startswith('nb-decoy-'):
            raise ValueError('synthetic accounts only')
        args += ['--account',account]
    for prefix in prefixes:
        args += ['--prefix',prefix]
    return args


def validate_metadata(meta, credential):
    expected = {'v':2,'account':credential.account,'host_port':host_port(credential.host,credential.port),
                'placement':{'api-key':1,'bearer':2,'token':2,'basic':3}[credential.placement],
                'word':{'bearer':'Bearer','token':'token'}.get(credential.placement,''),
                'has_truth_b':credential.placement=='basic','token_endpoint':'',
                'registration_endpoint':'','device_authorization_endpoint':''}
    if (set(meta) != {*expected,'generation'} or type(meta.get('generation')) is not int
            or meta['generation']<1 or any(meta.get(k)!=v for k,v in expected.items())):
        raise ValueError('registered credential metadata differs from frozen account')
    return meta


class Accounts:
    def __init__(self, deployment):
        self.d = deployment
        self.credentials, self.sources, self.registered, self.receipts = [], [], [], []
        self.directory = None

    def create(self, host, port, placement, labels=('A','B','C')):
        host_port(host,port)
        if tuple(labels) != ('A','B','C'):
            raise ValueError('each placement needs independent A/B/C accounts')
        result={label:new_credential('nb-decoy-'+label+'-'+secrets.token_hex(12),host,port,placement)
                for label in labels}
        self.credentials.extend(result.values())
        return result

    def _source(self, credential, part, data):
        if self.directory is None:
            path = self.d.scratch / ('nb-decoy-truths-'+secrets.token_hex(12))
            path.mkdir(mode=0o700);os.chown(path,1000,1000)
            self.directory = path
        path=self.directory/(credential.account+'-'+part)
        atomic_write(path,data);path.chmod(0o600);os.chown(path,1000,1000)
        self.sources.append(path)
        return path

    def register(self, credential):
        if credential not in self.credentials or credential in self.registered:
            raise ValueError('unowned or repeated test credential')
        key=host_port(credential.host,credential.port)
        base=self.d.root/'state/credentials'/key
        meta_path=base/(credential.account+'.json')
        if meta_path.exists():
            raise ValueError('refusing to overwrite an existing credential')
        a=self._source(credential,'a',credential.truth)
        argv=['cred','put',key,credential.account,credential.placement,'--truth-file',str(a)]
        if credential.placement=='basic':
            b=self._source(credential,'b',credential.password)
            argv+=['--truth-b-file',str(b)]
        # Track attempted ownership before an ambiguous reply: never forget a
        # partially persisted registration when preparing the next attempt.
        self.registered.append(credential)
        result=self.d.admin.call(*argv)
        meta=validate_metadata(json.loads(read_owned(meta_path,16384)),credential)
        generation=meta['generation']
        truth_files=[]
        for part,data in [('a',credential.truth)]+([('b',credential.password)] if credential.password else []):
            path=base/f'{credential.account}.{generation}.truth_{part}'
            raw=read_owned(path,4096)
            if raw!=data:
                raise ValueError('registered truth differs from the private input')
            truth_files.append({'path':str(path),'identity':identity(raw),'trusted_source':True})
        receipt={'credential':credential.metadata(),'metadata':meta,'registration':result,
                 'truth_files':truth_files,'source_files':[str(p) for p in self.sources
                                                        if p.name.startswith(credential.account+'-')]}
        self.receipts.append(receipt)
        return receipt

    def set_entry(self, workspace, host, port, accounts, prefixes):
        allowed={c.account for c in self.credentials if (c.host,c.port)==(host,port)}
        if set(accounts)-allowed:
            raise ValueError('entry uses an unowned/mismatched credential')
        return self.d.admin.call(*entry_arguments(workspace,host,port,accounts,prefixes))

    def close(self):
        errors=[]
        for c in reversed(self.registered):
            base=self.d.root/'state/credentials'/host_port(c.host,c.port)
            try:
                self.d.admin.call('cred','del',host_port(c.host,c.port),c.account)
                if any(p.name==c.account+'.json' or p.name.startswith(c.account+'.') for p in base.iterdir()):
                    raise ValueError('credential files remain after deletion')
            except Exception as exc:
                errors.append(type(exc).__name__+': '+str(exc)[:256])
        if errors:
            raise RuntimeError('account recovery incomplete: '+'; '.join(errors))
        self.registered.clear()
        for path in reversed(self.sources):
            plain_path(path)
            if path.parent != self.directory:
                raise ValueError('private source left its owned directory')
            path.unlink()
        self.sources.clear()
        if self.directory:
            self.directory.rmdir();self.directory=None
