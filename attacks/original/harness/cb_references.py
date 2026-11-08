"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import secrets
from dataclasses import replace
from cb_accounts import host_port
from cb_profile import ROOT
from cb_judge import window_requests, header_values
from cb_prerequisite import missing_evidence, required
from cb_scan import request_scan
from cb_row import run_row
from case_io import WorkspaceFiles, event
from common import json_bytes


def reference_rows(rt, case, adapter, prepared):
    receipts=[]
    for label in prepared['spec']['references']:
        c=prepared['reference_accounts'][label]
        entry=adapter.entry('work1',c.host,c.port,[c.account])
        rt.row_accounts['work1']=[(host_port(c.host,c.port),c.account)]
        files=WorkspaceFiles(rt,'work1','engine')
        nonce=secrets.token_hex(24);placeholder='nb-decoy-reference-'+nonce
        name='nb-decoy-reference-'+nonce
        try:
            files.write(name,json_bytes({'credential':placeholder,'marker':placeholder}))
            p={'reference':True,'host':c.host,'port':c.port,'scheme':'https','header':c.header,
               'config_path':name,'path':ROOT+'accept/'+nonce,'marker':placeholder,
               'placeholder':placeholder,'config':'engine','ca':str(rt.deployment.root/'tls/ca.pem')}
            ref={'targets':prepared['targets'],'parameters':p,'all_accounts':prepared['all_accounts']}
            result=run_row(rt,replace(case,sync='sent'),ref,files,config='engine',workspace='work1')
            rows=window_requests(result['window'],p['attempt_nonce'])
            release={'account':c.account,'row':result['row'],'entry':entry,'nonce':nonce,'method':'GET','path':p['path']}
            scans=[request_scan(row,prepared['all_accounts'],release) for row in rows]
            response=event(result['observation'],'reference')
            missing=missing_evidence(result['observation'],required(case.attack,False,reference=True))
            # A reference qualifies only with every declared outlet completely scanned (cold audit, finding 3).
            ok=(len(rows)==1 and rows[0]['host']==c.host and rows[0]['path']==p['path']
                and header_values(rows[0],c.header)==[c.value] and response.get('status')==200
                and response.get('complete') is True and not any(s['forbidden'] for s in scans)
                and not result['coverage']['forbidden'] and result['coverage']['complete'] is True
                and not missing)
            receipts.append({'account':label,'ok':ok,'scan':scans,'coverage':result['coverage'],
                             'missing':missing,'evidence':result['evidence']})
        finally:
            if not any(not r.closed for r in rt.rows):files.restore()
            files.close()
    prepared['references']=receipts
    return all(r['ok'] for r in receipts) and len(receipts)==len(prepared['spec']['references'])
