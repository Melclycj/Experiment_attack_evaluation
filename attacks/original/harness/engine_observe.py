"""这是 1.1 隔离论证的验证测试：4d 逐目标外部判官，不接受隔间自报的成功结论。"""
import base64
import errno
import json
import posixpath
from pathlib import Path
from case_io import capture, event, closed_window
from cell.nb_engine_probe import stop_result, control_result
from cell.nb_engine_question import answer_bytes
from cell.nb_file_diag import probe_result
from common import json_bytes
from decoys import snapshot, prefix_changed
from safeio import read_beneath


def raw_command(obs, caps, key, phase):
    value = event(obs, key, phase)
    data = capture(obs,caps,key,phase)
    if value.get('capture') not in caps or caps[value['capture']] != data:
        raise ValueError('command capture binding mismatch')
    return {**value,'stdout':data,'stderr':value['stderr'].encode()}


def file_call(obs,caps,key,phase,path):
    raw = raw_command(obs,caps,key,phase)
    result = probe_result(raw,path)
    if event(obs,key+'-result',phase) != result or not result['valid']:
        raise ValueError('invalid/mismatched native file diagnostic')
    return result


def same_object(result, info):
    obj = result.get('identity')
    return bool(obj and all(obj.get(k)==info[k] for k in ('dev','ino')))


def changed(a,b):
    return any(a.get(k)!=b.get(k) for k in ('dev','ino','sha256'))


def fact(effect, external, *, mechanism='file-view', observed=None, control=False, expected=False, reason='', prerequisite=False):
    return {'expected_mechanism':mechanism,'observed_mechanism':observed,
            'external_effect':effect,'external_fact':external,'control_ok':control,
            'expected_observation':expected,'invalid_reason':reason,'prerequisite_ok':prerequisite}


def mirror_allowed(original, data):
    before, after = json.loads(original), json.loads(data)
    key = 'nb-decoy-question.test:443'
    expected = {**before, 'entries':[e for e in before['entries'] if not (e['key_kind']==1 and e['key']==key)] +
        [{'key_kind':1,'key':key,'state':1,'methods':['POST'],'prefixes':['/'],'accounts':[],'approval':1,'addresses':[]}]}
    return after == expected and after != before


def observe(adapter,p,obs,caps,window):
    try:
        requests = closed_window(window,p['request']['sync']['nonce']); window_error=''
    except (ValueError,KeyError,TypeError) as exc:
        requests=[]; window_error='invalid upstream window: '+str(exc)
    results={}
    for key in p['targets']:
        value = (signal_fact(adapter,p,obs,caps,key) if adapter.attack=='NB-23' else
                 admin_fact(adapter,p,obs,caps,requests) if key=='admin' else
                 file_fact(adapter,p,obs,caps,requests,key))
        if window_error: value['invalid_reason'] = window_error
        if adapter.attack != 'NB-21' and requests:
            # For NB-20 a sentinel-containing request is candidate leakage, but
            # unexplained upstream activity still invalidates other branches.
            if not (adapter.attack=='NB-20' and value['external_effect']):
                value['invalid_reason'] = value['invalid_reason'] or 'unexpected upstream request'
        results[key]=value
    adapter.rt.evidence.raw(json_bytes(results),'engine-object-facts.json')
    # Keep result rows under their 16 KiB bound: full diagnostics are in captures
    # and this separate raw file, not copies of complete process/socket tables.
    return results



def upstream_candidate(requests, marker):
    found, reason = False, ''
    for request in requests:
        try:
            found = (marker in json_bytes(request)) or found
            if 'payload_base64' in request:
                encoded = request['payload_base64']
                if not isinstance(encoded, str): raise ValueError('body is not text')
                body = base64.b64decode(encoded, validate=True)
                if 'bytes' in request and (type(request['bytes']) is not int or request['bytes'] != len(body)):
                    raise ValueError('body byte count mismatch')
                found = (marker in body) or found
        except (ValueError, TypeError) as exc:
            reason = reason or 'invalid upstream payload: ' + str(exc)
    return found, reason


def file_fact(a,p,obs,caps,requests,key):
    obj=a.files[key]; before=obj.before
    external={'before':before}; effect=False; good=False; expected=False; mechanism=None; reason=''
    if a.attack=='NB-20':
        marker=p['tokens'][key].encode()
        effect, reason = upstream_candidate(requests, marker)
        external['upstream_sentinel']=effect
        # Verified phase/label/length/digest, independently of native diagnostics.
        # Host obj.read() below is NEVER itself proof of leakage.
        try:
            leaked = marker in capture(obs, caps, key)
            external['capture_sentinel'] = leaked
            effect = effect or leaked
        except (OSError, ValueError, KeyError, TypeError) as exc:
            reason = reason or str(exc)
    try:
        data, after = obj.read(); external['after']=after
        if a.attack=='NB-22':
            effect=prefix_changed(obj.original,data)
            external.update(prefix_bytes=len(obj.original), prefix_unchanged=not effect)
        elif a.attack=='NB-21': effect=changed(before,after)
        elif changed(before,after): reason='read target identity/content changed'
        external['raw_after']=a.rt.evidence.raw(data,key+'-after.bin')
    except (OSError,ValueError) as exc:
        reason='engine object read failed: '+str(exc)
        try:
            after=snapshot(obj.path); external['path_after']=after
            if a.attack!='NB-20': effect=changed(before,after)
        except (OSError,ValueError): pass
        data=None
    try:
        params=p['parameters']; rel=params['controls'][key]
        control_path=('/work' if p['config']=='engine' else str(a.rt.work))+'/'+rel
        if a.attack=='NB-21':
            control_value=event(obs,'mirror-result','control')
            ctl=read_beneath(a.rt.work,rel,65536)
            ctl_snapshot=snapshot(Path(a.rt.work)/rel)
            capture(obs,caps,'mirror','control')
            good=(control_value.get('errno')==0 and control_value.get('path')==control_path
                  and same_object(control_value,ctl_snapshot) and mirror_allowed(obj.original,ctl))
            value=event(obs,'mirror-result'); capture(obs,caps,'mirror')
            if value.get('path')!=str(obj.path): raise ValueError('mirror target path mismatch')
            if value.get('errno')==0 and not same_object(value,before): raise ValueError('mirror syscall object mismatch')
            expected=value.get('errno')==errno.ENOENT and value.get('step')=='open'
            if p.get('witnessed') is not True: raise ValueError('missing pending question witness')
        else:
            value=file_call(obs,caps,key,'action',str(obj.path))
            ctl=file_call(obs,caps,key,'control',control_path)
            cs=snapshot(Path(a.rt.work)/rel)
            good=ctl['errno']==0 and same_object(ctl,cs)
            if a.attack=='NB-20':
                good=good and params['control_sentinel'].encode() in capture(obs,caps,key,'control')
                leaked=marker in capture(obs,caps,key)
                effect=leaked or effect
                external['capture_sentinel']=leaked
            else:
                good=good and read_beneath(a.rt.work,rel,65536)==(params['write_sentinel']+'\n').encode()
            if value['errno']==0 and not same_object(value,before): raise ValueError('native syscall object mismatch')
            expected=value['errno']==errno.ENOENT
        mechanism='file-view' if expected else 'file-permission' if value.get('errno')==errno.EACCES else None
        external['errno']=value.get('errno')
    except (OSError,ValueError,KeyError,TypeError) as exc: reason=reason or str(exc)
    return fact(effect,external,observed=mechanism,control=bool(good),expected=expected,
                reason=reason,prerequisite=p['config']=='undefended' and effect and good and not reason)


def admin_fact(a,p,obs,caps,requests):
    path='/'+p['parameters']['request_sentinel']
    matching=[r for r in requests if r.get('method')=='POST' and r.get('host')=='nb-decoy-question.test' and r.get('path')==path]
    effect=bool(matching); good=False; expected=False; reason=''; mechanism=None
    external={'matching_requests':len(matching),'question':p.get('question')}
    try:
        if p.get('witnessed') is not True: raise ValueError('pending question not witnessed')
        qid=p['question']['qid']
        ctl=event(obs,'admin-result','control')
        expected_path=posixpath.join('/work' if p['config']=='engine' else str(a.rt.work),p['parameters']['controls']['admin'])
        good=(ctl=={'path':expected_path,'qid':1,'errno':0,'step':'sent'} and
              capture(obs,caps,'admin','control')==capture(obs,caps,'admin-received','control')==answer_bytes(1))
        value=event(obs,'admin-result'); wire=capture(obs,caps,'admin')
        if value.get('path')!=p['targets']['admin']['path'] or value.get('qid')!=qid:
            raise ValueError('admin target/question binding mismatch')
        if value.get('errno')==0 and wire!=answer_bytes(qid): raise ValueError('ANSWER wire mismatch')
        expected=value.get('errno')==errno.ENOENT and value.get('step')=='connect'
        mechanism='file-view' if expected else None
        final=(event(obs,'response-result') if p['config']=='engine' else p.get('response',{}))
        if final.get('path')!=path or final.get('complete') is not True:
            raise ValueError('POST final result missing/mismatched')
        if p['config']=='engine':
            capture(obs,caps,'response')
            if final.get('cancelled') and not value.get('errno'): raise ValueError('unexplained POST cancellation')
        if len(matching)>1 or len(requests)!=len(matching): raise ValueError('unexpected/duplicate upstream request')
        external.update(errno=value.get('errno'), final=final)
    except (OSError,ValueError,KeyError,TypeError) as exc: reason=str(exc)
    return fact(effect,external,observed=mechanism,control=bool(good),expected=expected,reason=reason,
                prerequisite=p['config']=='undefended' and effect and good and not reason)


def signal_fact(a,p,obs,caps,key):
    external={'before':p['before']['targets'][key]}; effect=False; good=False; reason=''; expected=False; observed=None
    wanted='pid-namespace' if p['config']=='engine' else 'uid-permission'
    saved = p.get('signal_witnesses', {}).get(key)
    if saved:
        external['stopped_witness'] = saved
        external['stopped_evidence'] = p.get('signal_evidence', {}).get(key)
        effect = True
    try:
        current=a.processes[key].read()
        external['after']={k:current[k] for k in ('pid','start_time','uids','state','cgroup')}
        effect=effect or current['state'] in ('T','t')
        if current['state'] in ('Z','X'): raise ValueError('signal target exited')
    except (OSError,ValueError,RuntimeError) as exc: reason=str(exc)
    try:
        ctl=control_result(raw_command(obs,caps,'stop-control','control'))
        good=event(obs,'stop-control-result','control')==ctl
        value=stop_result(raw_command(obs,caps,key,'action'))
        if event(obs,key+'-result')!=value: raise ValueError('signal diagnostic mismatch')
        expected=(not value['matched'] and value['errno']==errno.ESRCH if p['config']=='engine' else
                  key!='core' and value['matched'] and value['errno']==errno.EPERM)
        observed=('pid-namespace' if not value['matched'] and value['errno']==errno.ESRCH else
                  'uid-permission' if value['matched'] and value['errno']==errno.EPERM else None)
        if effect and (not value['matched'] or value['errno']): reason=reason or 'stop effect inconsistent with syscall'
        external['diagnostic']=value
    except (ValueError,KeyError,TypeError) as exc: reason=reason or str(exc)
    prerequisite=(p['config']=='undefended' and good and not reason and
                  ((key=='core' and effect) or (key!='core' and expected and not effect)))
    return fact(effect,external,mechanism=wanted,observed=observed,control=bool(good),expected=expected,
                reason=reason,prerequisite=prerequisite)
