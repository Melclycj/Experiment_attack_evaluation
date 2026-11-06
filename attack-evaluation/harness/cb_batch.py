"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import time
from cb_judge import judge, verdict, window_requests
from cb_late import late_scan
from cb_scan import request_scan
from cb_references import reference_rows
from cb_row import run_row
from common import json_bytes
from judge import aggregate_targets
from run_batch import Batch
from run_evidence import failed_attempt
from run_limits import alarm, until

REASON=160  # full exception text is archived; rows carry a bounded reason
TARGET_SECONDS=30  # tests.md 1.1: one sub-target, all its rows from start to verdict


def target_end(rt):
    """One sub-target's deadline (user 2026-11-03), never past the batch work end."""
    return min(rt.work_end,time.monotonic()+TARGET_SECONDS)


class CredentialBatch(Batch):
    def after_cleanup(self):
        self.header['late_scan']=late_scan(self.rt,self.rows)
        if not self.header['late_scan']['complete']:
            self.error=self.error or {'stage':'late-scan','type':'IncompleteCoverage',
                'message':'; '.join(self.header['late_scan']['gaps'])[:512]}
            self.header['controller_error']=self.error

    def attempt(self,case,config,repeat):
        if not case.attack.startswith('CB-') and case.attack!='PC-CREDENTIAL':
            return self.control_attempt(case,config,repeat)
        if case.attack=='CB-14':
            return self.keep_attempt(case,config,repeat)  # 条款 8: separate keep-connection judge
        adapter=self.adapters[case.attack];rt=self.rt
        old=rt.command.deadline
        results=[];receipts=[];fatal='';first=''
        try:
            for branch in self.contracts[case.attack]['targets']:
                if fatal:
                    results.extend(failed_attempt(repeat,'not-started: after '+first,[branch])['targets']);continue
                end=target_end(rt);rt.command.deadline=until(end)
                prepared=None
                try:
                    with alarm(end):
                        rt.evidence.directory.rescan()  # full output scan per sub-target (cb_output)
                        prepared=adapter.prepare_branch(config,repeat,self.contracts[case.attack],branch)
                        rt.targets.verify(prepared['targets'])
                        references_ok=reference_rows(rt,case,adapter,prepared)
                        result=run_row(rt,case,prepared,adapter.files,config=config,on_sync=adapter.synchronize)
                        fact=judge(prepared['spec'],prepared['parameters'],prepared['accounts'],
                            result['observation'],result['captures'],result['window'],config=config,
                            row=result['row'],entry=prepared['entry_receipts'][-1],references_ok=references_ok,
                            coverage=result['coverage'],diagnostics=result.get('diagnostics'))
                        target=verdict(fact,key=branch,expected=prepared['spec']['mechanism'],positive=case.kind=='control')
                        raw=rt.evidence.raw(json_bytes({'branch':branch,'result':target,'row_evidence':result['evidence'],
                            'references':prepared['references'],'baseline':prepared['before']}))
                        rt.cb_attempts.append({'attack':case.attack,'config':config,'branch':branch,
                            'accounts':list(prepared['all_accounts']),'evidence':raw})
                        # Keep bounded row metadata; detailed observations live in raw files.
                        target['external_fact']={'evidence':raw,'forbidden_count':len(fact['forbidden'])}
                        results.append(target);receipts.append(raw)
                        fatal=(target['quality_issue'] or target['invalid_reason'])[:REASON]
                except BaseException as exc:
                    detail=type(exc).__name__+': '+str(exc)
                    fatal=detail[:REASON]
                    try:receipts.append(rt.evidence.raw(json_bytes({'branch':branch,'error':detail[:4096]}),'failure.json'))
                    except BaseException:pass  # the bounded reason still names the failure
                    if not any(t['id']==branch for t in results):
                        results.extend(failed_attempt(repeat,fatal,[branch])['targets'])
                finally:
                    if prepared is not None:
                        try:
                            with alarm(end):adapter.restore(prepared)
                        except BaseException as exc:
                            reason=('credential restoration: '+str(exc))[:REASON];fatal=fatal or reason
                            for t in results:
                                if t['id']==branch and t['outcome']!='succeeded':
                                    t.update(outcome='invalid',invalid_reason=reason,
                                             quality_issue='; '.join(filter(None,[t.get('quality_issue'),reason])))
                    first=first or (branch if fatal else '')
            outcome,reason=aggregate_targets(results)
            return {'repeat':repeat,'targets':results,'outcome':outcome,'invalid_reason':reason,
                    'fatal_error':fatal,'evidence':rt.evidence.raw(json_bytes({'branches':receipts}))}
        finally:rt.command.deadline=old


    def keep_attempt(self,case,config,repeat):
        """CB-14 条款 8. Same per-branch shape as attempt(), but the keep-connection judge and no separate reference
        row (frame 1, account A on the keep endpoint, is the within-attack control). targets are empty for CB-14."""
        from cb_keep_judge import keep_judge
        adapter=self.adapters[case.attack];rt=self.rt
        old=rt.command.deadline
        results=[];receipts=[];fatal='';first=''
        try:
            for branch in self.contracts[case.attack]['targets']:
                if fatal:
                    results.extend(failed_attempt(repeat,'not-started: after '+first,[branch])['targets']);continue
                end=target_end(rt);rt.command.deadline=until(end)
                prepared=None
                try:
                    with alarm(end):
                        rt.evidence.directory.rescan()
                        prepared=adapter.prepare_branch(config,repeat,self.contracts[case.attack],branch)
                        result=run_row(rt,case,prepared,adapter.files,config=config,on_sync=adapter.synchronize)
                        fact=keep_judge(prepared['spec'],prepared['parameters'],prepared['accounts'],
                            result['observation'],result['captures'],result['window'],config=config,
                            coverage=result['coverage'])
                        target=verdict(fact,key=branch,expected=prepared['spec']['mechanism'])
                        raw=rt.evidence.raw(json_bytes({'branch':branch,'result':target,'row_evidence':result['evidence'],
                            'references':prepared['references'],'baseline':prepared['before']}))
                        rt.cb_attempts.append({'attack':case.attack,'config':config,'branch':branch,
                            'accounts':list(prepared['all_accounts']),'evidence':raw})
                        target['external_fact']={'evidence':raw,'forbidden_count':len(fact['forbidden'])}
                        results.append(target);receipts.append(raw)
                        fatal=(target['quality_issue'] or target['invalid_reason'])[:REASON]
                except BaseException as exc:
                    detail=type(exc).__name__+': '+str(exc)
                    fatal=detail[:REASON]
                    try:receipts.append(rt.evidence.raw(json_bytes({'branch':branch,'error':detail[:4096]}),'failure.json'))
                    except BaseException:pass
                    if not any(t['id']==branch for t in results):
                        results.extend(failed_attempt(repeat,fatal,[branch])['targets'])
                finally:
                    if prepared is not None:
                        try:
                            with alarm(end):adapter.restore(prepared)
                        except BaseException as exc:
                            reason=('credential restoration: '+str(exc))[:REASON];fatal=fatal or reason
                            for t in results:
                                if t['id']==branch and t['outcome']!='succeeded':
                                    t.update(outcome='invalid',invalid_reason=reason,
                                             quality_issue='; '.join(filter(None,[t.get('quality_issue'),reason])))
                    first=first or (branch if fatal else '')
            outcome,reason=aggregate_targets(results)
            return {'repeat':repeat,'targets':results,'outcome':outcome,'invalid_reason':reason,
                    'fatal_error':fatal,'evidence':rt.evidence.raw(json_bytes({'branches':receipts}))}
        finally:rt.command.deadline=old


    def control_attempt(self,case,config,repeat):
        rt=self.rt;adapter=self.adapters[case.attack];prepared=None
        end=target_end(rt);old=rt.command.deadline;rt.command.deadline=until(end)
        try:
            with alarm(end):
                rt.evidence.directory.rescan()  # full output scan per sub-target (cb_output)
                prepared=adapter.prepare(config,repeat,self.contracts[case.attack])
                rt.targets.verify(prepared['targets'])
                result=run_row(rt,case,prepared,adapter.files,config=config,interact=adapter.interact)
                facts=adapter.observe(prepared,result['observation'],result['captures'],result['window'])
                # The upstream outlet's per-request scan (tests.md 1.3, 4), as cb_judge does for attacks.
                # These rows hold no account and no entry names one, so no release applies.
                requests=window_requests(result['window'],prepared['parameters']['attempt_nonce'])
                scans=[request_scan(r,prepared['all_accounts']) for r in requests]
                upstream=[h for s in scans for h in s['forbidden']]
                metadata=prepared.get('metadata')
                targets=[]
                for key,fact in facts.items():
                    coverage=result['coverage'];gaps=list(coverage['gaps'])
                    if not metadata:gaps.append('control-account-metadata-missing')
                    quality='; '.join(gaps)
                    measured={'effect':bool(coverage['forbidden'] or upstream),'expected':fact['external_effect'] is True,
                        'control_ok':fact['control_ok'],'complete':coverage['complete'] and not gaps,
                        'quality_issue':quality,'mechanism':'allowed','coverage':coverage,
                        'scans':scans,'forbidden':upstream+coverage['forbidden'],'accounts':metadata,
                        'positive_fact':fact}
                    target=verdict(measured,key=key,expected='allowed',positive=True)
                    receipt=rt.evidence.raw(json_bytes(target));target['external_fact']={'evidence':receipt}
                    targets.append(target)
                    rt.cb_attempts.append({'attack':case.attack,'config':config,'branch':key,
                        'accounts':prepared['all_accounts'],'evidence':receipt})
                outcome,reason=aggregate_targets(targets)
                return {'repeat':repeat,'targets':targets,'outcome':outcome,'invalid_reason':reason,
                        'fatal_error':next((t['quality_issue'] or t['invalid_reason'] for t in targets
                                           if t['quality_issue'] or t['invalid_reason']),''),
                        'evidence':result['evidence']}
        finally:
            try:
                if prepared is not None:
                    with alarm(end):adapter.restore(prepared)
            finally:rt.command.deadline=old
