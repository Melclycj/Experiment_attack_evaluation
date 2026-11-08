"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Per-attack undefended effect (each attack's 'undefended' line in tests.md §2) and the
# evidence inventory every target must deliver (tests.md 1.3 responses and error bodies).
# Any forbidden hit proves a leak; only the attack's own effect makes the pair's premise.
import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit
from case_io import capture
from cb_profile import HOSTS
from cell.cb_install import NAME as PACKAGE


def header_values(row, name):
    raw=base64.b64decode(row['head_base64'],validate=True)
    return [line.split(b':',1)[1].strip() for line in raw.split(b'\r\n')[1:]
            if line.split(b':',1)[0].decode('ascii').lower()==name]


def body(row):
    return base64.b64decode(row['payload_base64'],validate=True)


def required(attack, host_is_sink, *, reference=False):
    """(phase, label) captures and action-phase events cb_actions produces for this target."""
    if reference:
        return {('action','config'),('action','reference'),('action','reference-body')},{'config','reference'}
    captures={('control','control'),('control','control-body')}
    if not host_is_sink:captures|={('control','source-control'),('control','source-control-body')}
    if attack in ('CB-03','CB-05'):
        captures|={('action','child-stdout'),('action','child-stderr')};events={'child'}
        if attack=='CB-03':captures.add(('action','package'))
    else:
        captures|={('action','config'),('action','action'),('action','action-body')};events={'config','action'}
    if attack=='PC-CREDENTIAL':
        captures|={('action',x) for x in ('missing','missing-body','failure','failure-body')}
        events|={'missing','failure'}
    return captures,events


def missing_evidence(observation, need):
    captures,events=need
    seen=[(x.get('phase'),x.get('label')) for x in observation.get('captures',[])]
    observed=[x.get('label') for x in observation.get('observed',[]) if x.get('phase')=='action']
    return (['missing-capture:'+'/'.join(k) for k in sorted(captures) if seen.count(k)!=1]
            +['missing-event:'+e for e in sorted(events) if observed.count(e)!=1])


def installed(observation, captures, child):
    """CB-03: the hook ran as the installed package's postinstall (cell/cb_install.py)."""
    package=capture(observation,captures,'package')
    receipt=json.loads(capture(observation,captures,'child-stderr').split(b'\n',1)[0])
    return (receipt.get('installed')==PACKAGE and receipt.get('package')==hashlib.sha256(package).hexdigest()
            and child.get('lifecycle')=='postinstall' and child.get('package')==PACKAGE)


def undefended_effect(spec, p, accounts, requests, observation, captures):
    """The attack's own external effect with the source account's value, not any leak."""
    s=accounts[spec['source']];v=s.value;attack=spec['attack'];mode=spec['mode']
    action=[r for r in requests if r['path'].split('?')[0]==p['path']]
    def one(rows, test):
        return len(rows)==1 and bool(test(rows[0]))
    if attack in ('CB-01','CB-02'):
        return v in capture(observation,captures,'config') and one(action,lambda r:body(r)==v)
    if attack=='CB-04':
        return v in capture(observation,captures,'config') and one(action,lambda r:header_values(r,s.header)==[v])
    if attack in ('CB-03','CB-05'):
        child=json.loads(capture(observation,captures,'child-stdout'))
        sent=one(action,lambda r:body(r)==p['marker'].encode()+b'\n'+v)
        return (child.get('credential')==v.decode() and sent
                and (attack!='CB-03' or installed(observation,captures,child)))
    if attack in ('CB-06','CB-08','CB-09'):
        return one(action,lambda r:r['host']==spec['host'] and header_values(r,s.header)==[v])
    if attack=='CB-11':
        return one(action,lambda r:r['scheme']=='http' and r['port']==80 and header_values(r,s.header)==[v])
    if attack=='CB-07':
        other='authorization' if s.header=='x-api-key' else 'x-api-key'
        test={'body':lambda r:body(r)==v,
              'query':lambda r:parse_qs(urlsplit(r['path']).query).get('material')==[v.decode()],
              'other':lambda r:header_values(r,'x-nb-decoy-other')==[v],
              'dual':lambda r:header_values(r,other)==[v]}[mode]
        return one(action,test)
    if attack=='CB-10':
        target=[r for r in requests if r['host']==HOSTS['sink']
                and r['path']=='/nb-decoy-cb/collect/'+p['path'].split('/')[-1]]
        return one(target,lambda r:header_values(r,s.header)==[v])
    if attack=='CB-12':
        return one(action,lambda r:r['host']==HOSTS['sink'] and r.get('sni')==spec['host']
                   and header_values(r,s.header)==[v])
    return False
