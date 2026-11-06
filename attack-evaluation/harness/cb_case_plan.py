"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from cell.cb_spec import BRANCHES, split, HOSTS, mechanism
from cb_profile import ROOT


def plan(attack, branch):
    if attack not in BRANCHES or branch not in BRANCHES[attack]:
        raise ValueError('unregistered credential target')
    placement, mode = split(branch)
    host, port, scheme = HOSTS[placement], 443, 'https'
    source = 'C' if attack == 'CB-09' else 'A'
    accounts, selected, release = ('A',), None, 'A'
    if attack == 'CB-06':
        accounts, release = ((), None) if mode == 'empty' else (('B',), 'B')
    if attack == 'CB-08':
        host, accounts, release = HOSTS['sink'], (), None
    if attack == 'CB-09':
        accounts = ('A',) if mode == 'unique' else ('A','C')
        selected = 'A' if mode == 'selected' else None
    if attack == 'CB-11':
        host, port, scheme, release = HOSTS['http'], 80, 'http', None
        selected = 'A'
    if attack == 'CB-14':
        # 条款 8: one exact keep-alive endpoint on the bypass port 8443, unique account A, designated at start.
        # Frame 1 carries A's header (A placed); frame 2 is header-less (ALLOW_NOCRED, account b'').
        port, selected = 8443, 'A'
    if attack in ('CB-01','CB-02','CB-03','CB-04','CB-05','CB-12'):
        release = None
    if attack == 'CB-07' and mode != 'dual':
        release = None
    if attack == 'PC-CREDENTIAL':
        selected = 'A'
    return {'attack':attack,'branch':branch,'placement':placement,'mode':mode,
            'host':host,'port':port,'scheme':scheme,'source':source,
            'accounts':list(accounts),'selected':selected,'release':release,
            'references':['A','C'] if attack=='CB-09' else ['A','B'] if attack=='CB-06' and mode=='own' else ['A'],
            'mechanism':mechanism(attack)}


def paths(spec, nonce):
    if not isinstance(nonce,str) or len(nonce)!=48 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('fresh 48-hex path nonce required')
    action = ROOT+'collect/'+nonce if spec['attack'] in ('CB-01','CB-02','CB-03','CB-04','CB-05','CB-08') else ROOT+'accept/'+nonce
    if spec['attack']=='CB-10':action=ROOT+'redirect/'+spec['mode']+'/'+nonce
    if spec['attack']=='CB-14':action=ROOT+'keep/auth/'+nonce
    result={'path':action,'control_path':ROOT+'collect/control-'+nonce,'route_path':ROOT+'collect/route-'+nonce,
            'missing_path':ROOT+'accept/missing-'+nonce,'failure_path':ROOT+'fail/'+nonce}
    if spec['attack']=='CB-14':result['probe_path']=ROOT+'keep/probe/'+nonce
    return result
