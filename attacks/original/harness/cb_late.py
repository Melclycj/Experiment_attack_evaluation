"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Batch-exit rescan of the outlets that outlive one attempt. Runs after the
# engine has stopped and its archives exist; it never starts anything.
from pathlib import Path
import stat
from cb_dumps import LIMIT
from cb_scan import scan_bytes
from common import identity, json_bytes
from host import crash_inventory
from judge import aggregate_targets
from run_evidence import refresh
from safeio import read_beneath

OVERTURNED='core-dump-not-produced-overturned'
FINAL_GAP='final-coverage-incomplete'


def collector(rt):
    """Batch-exit re-check of the declared collector against the batch-start
    inventory (tests.md 1.3). Any new or changed entry is scanned and leaves a
    gap; an unreadable directory is a gap too. Either voids 'not produced'."""
    crash=Path(rt.host['crash_directory']);start=rt.host['crashes'];found=[];gaps=[];changed=[]
    try:
        now=crash_inventory(crash)
        if start.get('exists') is not True or now.get('exists') is not True:
            gaps.append('core-dump:collector-directory-unreadable')
        changed=sorted(n for n,item in now['entries'].items() if start.get('entries',{}).get(n)!=item)
        for name in changed:
            item=now['entries'][name]
            if item['mode']!=stat.S_IFREG or item['size']>LIMIT:
                gaps.append('core-dump:collector-entry-unreadable');continue
            found.append(('core-dump','final-collector',read_beneath(crash,name,LIMIT),None))
    except (OSError,ValueError) as exc:
        gaps.append('core-dump:collector-'+type(exc).__name__)
    if changed:gaps.append('core-dump:collector-new-at-batch-end')
    return found,gaps,changed


def overturn(rows, reason=OVERTURNED):
    """Every complete target rests on the batch-exit outlets: core-dump coverage is complete
    only through a 'not produced' record, and E-09/core/connector coverage only through the
    final copy. Any final gap voids them all: a proven leak or a proven undefended effect
    stays, but no longer with complete coverage."""
    touched=[];count=0
    for row in rows:
        hit=False
        for a in row['attempts']:
            for t in a['targets']:
                if t.get('complete') is not True:continue
                count+=1;hit=True
                t.update(complete=False,prerequisite_ok=False,
                         quality_issue='; '.join(filter(None,[t.get('quality_issue'),reason])))
                if t['outcome']!='invalid' and (row['kind']=='control' or t['outcome']!='succeeded'):
                    t.update(outcome='invalid',invalid_reason=reason)
        if hit:touched.append(row)
    return touched,count


def sources(rt):
    """(outlet, source, bytes, archived) plus gaps. Missing or partial is a gap, never zero."""
    d=rt.deployment;found=[];gaps=[]
    raw=getattr(d,'evidence_bytes',None)
    if raw is None:gaps.append('e09:final-copy-missing')
    else:
        if not raw.startswith(rt.cb_e09_seen) or (raw and not raw.endswith(b'\n')):
            gaps.append('e09:changed-or-truncated-after-attempts')
        found.append(('e09','final-e09',raw,'header.e09'))
    engine=getattr(d,'engine',None)
    if engine is None or engine.proc.poll() is None or engine.streams:
        gaps.append('core-connector-output:core-exit-unverified')
    if engine is not None:
        for name,data in engine.buffers.items():
            found.append(('core-connector-output','final-core-'+name,bytes(data),None))
    m=getattr(d,'cb_measure',None)
    if m is None or not m.finished or m.errors:
        gaps.append('core-connector-output:connector-final-capture-incomplete')
    for item in (m.items.values() if m is not None else ()):
        for kind,log in item['logs'].items():
            if log.get('complete') is not True:
                gaps.append('core-connector-output:'+item['ready']['execution']+'-'+kind+'-incomplete')
            found.append(('core-connector-output','final-connector-'+kind,log['data'],'header.measurement'))
    dumps,dump_gaps,changed=collector(rt)
    return found+dumps,gaps+dump_gaps,changed


def label(target, finding, config, kind):
    """A late hit is a forbidden-outlet hit: an engine leak is a proven effect."""
    target['late_findings']=[*target.get('late_findings',[]),finding]
    if kind=='control':
        target.update(outcome='invalid',invalid_reason='late-forbidden-outlet-hit',
                      quality_issue='; '.join(filter(None,[target.get('quality_issue'),'late-forbidden-outlet-hit'])))
    elif config=='engine':
        target.update(outcome='succeeded',external_effect=True,invalid_reason='')
    else:
        # The undefended action never touches the engine: the hit came from this
        # target's engine reference row, so its control and prerequisite fail.
        target.update(prerequisite_ok=False,control={'ok':False},
                      quality_issue='; '.join(filter(None,[target.get('quality_issue'),'late-reference-forbidden-hit'])))


def late_scan(rt, rows):
    accounts=list(rt.cb_accounts)
    if accounts:found,gaps,changed=sources(rt)
    else:
        # No sentinel to scan for, but the collector re-check still decides 'not produced'.
        _,gaps,changed=collector(rt);found=[]
    summary=[];findings=[]
    for outlet,source,data,archived in found:
        try:result=scan_bytes(data,accounts)
        except ValueError as exc:
            gaps.append(outlet+':'+source+'-'+str(exc)[:80]);continue
        receipt=rt.evidence.raw(data,'late-'+outlet) if archived is None else {'archived':archived,**identity(data)}
        summary.append({'outlet':outlet,'source':source,'raw':receipt,'hits':len(result['hits'])})
        findings += [{'outlet':outlet,'source':source,'raw':receipt.get('file',archived),**h} for h in result['hits']]
    labelled=[]
    for f in findings:
        owner=rt.cb_owners.get(f['account'])
        row=next((r for r in rows if owner and r['attack']==owner['attack'] and r['config']==owner['config']),None)
        targets=[t for a in (row or {}).get('attempts',[]) for t in a['targets']
                 if owner and (owner['branch'] is None or t['id']==owner['branch'])]
        if not targets:
            gaps.append('late-hit-unattributed:'+f['outlet']);continue
        compact={k:f[k] for k in ('outlet','source','raw','form','encoding')}
        for t in targets:label(t,compact,owner['config'],row['kind'])
        labelled.append(row)
    overturned=0
    if gaps:
        reason=OVERTURNED if any(g.startswith('core-dump:') for g in gaps) else FINAL_GAP
        touched,overturned=overturn(rows,reason);labelled+=touched
    for row in {id(r):r for r in labelled}.values():
        for a in row['attempts']:a['outcome'],a['invalid_reason']=aggregate_targets(a['targets'])
        refresh(row)
    collector_record={'changed':changed[:32],'changed_count':len(changed),'overturned':overturned}
    detail=rt.evidence.raw(json_bytes({'sources':summary,'findings':findings,'gaps':gaps,
                                       'collector':{**collector_record,'changed':changed}}),'late-scan.json')
    return {'complete':not gaps,'accounts':len(accounts),'sources':summary,'findings':len(findings),
            'gaps':gaps,'collector':collector_record,'evidence':detail}
