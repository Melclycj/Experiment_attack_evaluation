"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from dataclasses import replace
from functools import partial
from run_registry import Case
from cb_adapter import CredentialCase
from cb_keep_adapter import KeepCase
from cb_controls import MeasuredFile, MeasuredProxy, MeasuredDialogue
from cb_case_plan import plan
from cell.cb_spec import BRANCHES, mechanism

def registry(targets=()):
    selected={}
    for item in targets:
        attack,sep,branch=item.partition(':')
        if not sep or attack not in BRANCHES or branch not in BRANCHES[attack]:
            raise ValueError('unknown credential target selector')
        if branch in selected.setdefault(attack,[]):raise ValueError('duplicate credential target')
        selected[attack].append(branch)
    result={}
    for attack,all_branches in BRANCHES.items():
        branches=tuple(b for b in all_branches if b in selected.get(attack,all_branches))
        case_cls=KeepCase if attack=='CB-14' else CredentialCase  # CB-14 条款 8 is a separate keep-connection path
        result[attack]=Case(attack,attack+'.py',partial(case_cls,attack=attack,branches=branches),
            {'outcome':'succeeded' if attack=='PC-CREDENTIAL' else 'blocked',
             'mechanism':mechanism(attack),'location':'credential-binding/tests.md §2.13' if attack=='CB-14'
             else 'credential-binding/tests.md §3'},
            kind='control' if attack=='PC-CREDENTIAL' else 'attack',sync='sent',branches=branches)
    result.update({c.attack:Case(c.attack,c.attack+'.py',c,{'outcome':'succeeded'},kind='control')
                   for c in (MeasuredFile,MeasuredProxy,MeasuredDialogue)})
    return result

# MAX_TARGETS keeps a result row within its 16 KiB bound, with room left for one failed
# target's reasons; larger selections are split with --target (tests.md 1.1).
MAX_TARGETS=8

def capacity_for(cases,configs):
    from build import capacity
    for case in cases:
        if len(case.branches)>MAX_TARGETS:
            raise ValueError(f'{case.attack} selects {len(case.branches)} targets; at most {MAX_TARGETS} '
                             'per batch, split the rest into further batches with --target')
    count=0
    for config in configs:
        for case in cases:
            if config!='engine' and case.kind=='control':continue
            if case.attack not in BRANCHES:
                count+=case.repeats;continue
            for branch in case.branches:
                spec=plan(case.attack,branch)
                # Real engine reference rows in either arm, plus the action row.
                count+=case.repeats*(len(spec['references'])+1)
    cap=capacity(count)
    if cap['ca_count']>1024:raise ValueError('credential batch exceeds production capacity')
    return cap
