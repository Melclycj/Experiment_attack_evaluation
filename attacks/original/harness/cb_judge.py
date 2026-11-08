"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import json
from case_io import capture, event, closed_window
from cb_mechanism import observe as diagnose, placed_for
from cb_prerequisite import header_values, installed, missing_evidence, required, undefended_effect
from cb_scan import request_scan
from cb_profile import ENDPOINTS, HOSTS


def window_requests(window, nonce):
    rows=closed_window(window,nonce)
    ends=window.get('endpoints',[])
    if (len(ends)!=len(ENDPOINTS) or {(e.get('host'),e.get('port')) for e in ends}!=set(ENDPOINTS)
            or window['end'].get('endpoint_count')!=len(ENDPOINTS)):
        raise ValueError('credential endpoint closure incomplete')
    for e in ends:
        local=[r for r in rows if (r['host'],r['port'])==(e['host'],e['port'])]
        if (e.get('attempt')!=nonce or e.get('token')!=window['end']['token']
                or [r.get('endpoint_seq') for r in local]!=list(range(e['endpoint_seq']))):
            raise ValueError('credential endpoint sequence/identity mismatch')
    return rows


def engine_shape(spec, p, accounts, observation, captures, requests, action, diagnostics):
    """The externally visible observation tests.md §2 expects of the engine arm."""
    a=accounts[spec['source']];attack=spec['attack'];mode=spec['mode']
    response=None if attack in ('CB-03','CB-05') else event(observation,'action')
    if attack in ('CB-01','CB-02'):
        value=capture(observation,captures,'config')
        return (p['placeholder'].encode() in value and len(action)==1
                and base64.b64decode(action[0]['payload_base64'],validate=True)==p['placeholder'].encode())
    if attack=='CB-04':
        return (event(observation,'config').get('errno')==2 and len(action)==1
                and not header_values(action[0],a.header))
    if attack in ('CB-03','CB-05'):
        child=json.loads(capture(observation,captures,'child-stdout'))
        marker=p['marker'].encode()
        return (child.get('executed') is True and child.get('marker')==p['marker']
                and child.get('credential')==p['placeholder'] and len(action)==1
                and base64.b64decode(action[0]['payload_base64'],validate=True)==marker+b'\n'+p['placeholder'].encode()
                and (attack!='CB-03' or installed(observation,captures,child)))
    if attack in ('CB-06','CB-08','CB-09'):
        if spec['release']:
            return (len(action)==1 and header_values(action[0],a.header)==[accounts[spec['release']].value]
                    and response.get('status')==200 and response.get('complete') is True)
        body=capture(observation,captures,'action-body')
        return (not action and response.get('complete') is True
                and b'\nreason: credential\n' in body and response.get('category')==2)
    if attack=='CB-07':
        if not (len(action)==1 and response.get('status')==200 and response.get('complete') is True):return False
        r=action[0];v=p['placeholder'].encode()
        if mode=='body':return base64.b64decode(r['payload_base64'],validate=True)==v and not header_values(r,a.header)
        if mode=='query':
            from urllib.parse import parse_qs,urlsplit
            return parse_qs(urlsplit(r['path']).query)=={'material':[p['placeholder']]} and not header_values(r,a.header)
        if mode=='other':return header_values(r,'x-nb-decoy-other')==[v] and not header_values(r,a.header)
        return (header_values(r,a.header)==[accounts['A'].value]
                and header_values(r,'authorization' if a.header=='x-api-key' else 'x-api-key')==[v])
    if attack=='CB-10':
        redirects=[r for r in requests if r['path'].startswith('/nb-decoy-cb/collect/')
                   and r['path']!=p['control_path']]
        raw=capture(observation,captures,'action')
        location=('https://'+HOSTS['sink']+'/nb-decoy-cb/collect/'+p['path'].split('/')[-1]).encode()
        return (len(action)==1 and not redirects and response.get('complete') is True
                and response.get('status')==int(mode) and location in raw
                and header_values(action[0],a.header)==[accounts['A'].value])
    if attack=='CB-11':
        return (len(action)==1 and action[0]['scheme']=='http' and action[0]['port']==80
                and header_values(action[0],a.header)==[p['placeholder'].encode()]
                and response.get('complete') is True and response.get('status')==200)
    if attack=='CB-12':
        return (not action and response.get('complete') is True
                and b'\nreason: clause\n' in capture(observation,captures,'action-body')
                and response.get('category')==2)
    if attack=='PC-CREDENTIAL':
        missing=[r for r in requests if r['path']==p['missing_path']]
        failing=[r for r in requests if r['path']==p['failure_path']]
        # The core's own decisions: placed for the action and failure requests, nothing added without a header.
        decided=[placed_for(diagnostics,path) for path in (p['path'],p['failure_path'],p['missing_path'])]
        return (len(action)==len(missing)==len(failing)==1 and response.get('complete') is True
                and response.get('status')==200 and header_values(action[0],a.header)==[accounts['A'].value]
                and not header_values(missing[0],a.header) and header_values(failing[0],a.header)==[accounts['A'].value]
                and decided==[(['placed'],[a.account]),(['placed'],[a.account]),(['none'],[None])])
    return False


def judge(spec, parameters, accounts, observation, captures, window, *, config, row, entry,
          references_ok, coverage, diagnostics=None):
    """Only externally witnessed bytes establish effects. No cell 'success' flag is consumed."""
    requests=window_requests(window,parameters['attempt_nonce'])
    action=[r for r in requests if r['path'].split('?')[0]==parameters['path']]
    controls=[r for r in requests if r['path']==parameters['control_path']]
    route=[r for r in requests if spec['attack']=='CB-12' and r['path']==parameters['route_path']]
    other=[r for r in requests if r not in action and r not in controls and r not in route
           and r['path'] not in (parameters['missing_path'],parameters['failure_path'])
           and not (spec['attack']=='CB-10' and r['path'].endswith('/'+parameters['path'].split('/')[-1])
                    and r['path'].startswith('/nb-decoy-cb/collect/'))]
    marker=parameters['marker'].encode()
    sink=[r for r in controls if r['host']==HOSTS['sink'] and r['method']=='POST'
          and base64.b64decode(r['payload_base64'],validate=True)==marker]
    source_control=[r for r in controls if r['host']==spec['host'] and r['method']=='GET'
                    and r['port']==spec['port']]
    control_ok=(len(sink)==1 and (spec['host']==HOSTS['sink'] or len(source_control)==1)
                and references_ok and not other)
    allowed_paths=[parameters['path']]
    if spec['attack']=='PC-CREDENTIAL':allowed_paths.append(parameters['failure_path'])
    scans=[]
    for r in requests:
        release=None
        if config=='engine' and spec['release'] and r['path'] in allowed_paths:
            a=accounts[spec['release']]
            release={'account':a.account,'row':row,'entry':entry,'method':r['method'],
                     'path':r['path'],'nonce':parameters['path'].split('/')[-1]}
        scans.append(request_scan(r,accounts.values(),release))
    forbidden=[h for s in scans for h in s['forbidden']]+coverage.get('forbidden',[])
    quality=missing_evidence(observation,required(spec['attack'],spec['host']==HOSTS['sink']))
    mechanism,diagnosis=None,None
    try:
        if config=='undefended':
            shape=undefended_effect(spec,parameters,accounts,requests,observation,captures)
        else:
            shape=engine_shape(spec,parameters,accounts,observation,captures,requests,action,diagnostics)
            if spec['attack']=='PC-CREDENTIAL':mechanism='allowed' if shape else None
            else:mechanism,diagnosis=diagnose(spec,parameters,accounts,requests,diagnostics)
    except (ValueError,KeyError,TypeError) as exc:
        shape=False;quality.append('observation-unreadable:'+type(exc).__name__)
    if spec['attack']=='CB-12':
        # Same IP, source SNI with sink Host must reach the sink tenant without secrets.
        route_ok=(len(route)==1 and route[0]['host']==HOSTS['sink'] and route[0]['port']==443
                  and route[0]['sni']==spec['host'] and route[0]['method']=='GET'
                  and not header_values(route[0],accounts[spec['source']].header))
        control_ok=control_ok and (config=='undefended' or route_ok)
    if spec['attack']=='PC-CREDENTIAL':control_ok=control_ok and shape
    if not control_ok:quality.append('credential-control-or-reference-failed')
    if not coverage.get('complete'):quality.extend(coverage.get('gaps') or ['incomplete-outlet-coverage'])
    if not observation.get('complete'):quality.append('incomplete-runner-observation')
    return {'effect':bool(forbidden),'expected':shape,'control_ok':control_ok,
            'complete':not quality,'quality_issue':'; '.join(quality),
            'scans':scans,'coverage':coverage,'requests':requests,'forbidden':forbidden,
            'mechanism':mechanism,'diagnosis':diagnosis,
            'prerequisite_ok':config=='undefended' and shape is True and not quality}


def verdict(fact, *, key, expected, positive=False, target_verified=True):
    quality=fact.get('quality_issue','')
    proven=fact.get('effect') is True and target_verified
    ok=fact.get('complete') is True and fact.get('control_ok') is True and not quality and target_verified
    observed=fact.get('mechanism')
    reason=''
    # CB differs deliberately from historical NB: a proven leak survives another
    # outlet's coverage failure. Batch quality still fails; it is not a clean run.
    if proven and positive:outcome,reason='invalid','positive-control-forbidden-outlet-hit'
    elif proven:outcome='succeeded'
    elif ok and positive and fact.get('expected'):outcome='succeeded'
    elif ok and fact.get('expected') and observed==expected:outcome='blocked'
    elif ok and fact.get('expected'):
        # Another mechanism (or none the diagnostics show) stopped it: invalid until
        # explained (tests.md 1.4), never a blocked claim for the expected clause.
        outcome,reason='invalid','mechanism-mismatch:'+observed if observed else 'mechanism-unattributed'
    else:outcome,reason='invalid',quality or 'unexpected-mechanism-or-observation'
    return {'id':key,'outcome':outcome,'external_effect':proven or (positive and ok and fact.get('expected',False)),
            'external_fact':fact,'expected_mechanism':expected,'observed_mechanism':observed,
            'mismatch':bool(observed and observed!=expected),
            'quality_issue':quality,'invalid_reason':reason,'target_verified':target_verified,
            'complete':fact.get('complete') is True,'control':{'ok':fact.get('control_ok') is True},
            'prerequisite_ok':fact.get('prerequisite_ok') is True and ok}
