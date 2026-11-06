"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import stat
from pathlib import Path
from common import identity
from host import crash_inventory

LIMIT=2*1024*1024
WSL_PIPE='|/wsl-capture-crash %t %E %p %s'
RULE='wsl-pipe-declared-directory'

KEYS=('kernel/core_pattern','kernel/core_uses_pid','fs/suid_dumpable')

def configuration(proc=Path('/proc')):
    return {key:(proc/'sys'/key).read_text().strip() for key in KEYS}

def witness(crash_directory, *, proc=Path('/proc')):
    """Read-only point witness: kernel core settings and the collector landing inventory."""
    return {'configuration':configuration(proc),'collector':crash_inventory(Path(crash_directory))}

def process_reasons(processes):
    """Row tree, declared children and connector exited; the one batch core alive and unchanged."""
    reasons=[]
    roles=[p.get('role') for p in processes]
    if 'row-tree' not in roles or roles.count('core')!=1:reasons.append('process-exit-coverage-incomplete')
    for p in processes:
        if p.get('role')=='core':
            if p.get('alive_verified') is not True or p.get('identity_unchanged') is not True:
                reasons.append('core-liveness-or-identity-unverified')
        elif p.get('exit_verified') is not True:reasons.append('process-exit-coverage-incomplete')
    return reasons

def lifecycle(before, after, processes, reader):
    """Per-attempt core-dump coverage between two point witnesses (tests.md 1.3).

    The WSL pipe collector is accounted only under the user's 2026-11-03 rule:
    core settings unchanged and the pattern exactly WSL_PIPE; the declared
    directory present with nothing new or changed; every attempt process exited
    and the batch core alive with its identity unchanged. Only then is the
    record 'not-produced', and only for the declared directory: the WSL
    configuration is not read, so a disabled or late collector stays a residual,
    and cb_late re-checks the directory at batch exit. Any new or changed entry
    is read (bounded) and scanned but never makes coverage complete. Other
    collectors stay incomplete. Nothing here induces a crash or changes host
    core settings.
    """
    reasons=[]
    if before['configuration']!=after['configuration']:reasons.append('core-configuration-changed')
    pattern=before['configuration'].get('kernel/core_pattern','')
    if pattern!=WSL_PIPE:
        reasons.append('pipe-core-collector-not-accounted' if pattern.startswith('|')
                       else 'core-file-landing-not-declared')
    reasons+=process_reasons(processes)
    old,new=before['collector'],after['collector']
    if old.get('exists') is not True or new.get('exists') is not True:
        reasons.append('core-collector-directory-unreadable')
    entries=new.get('entries',{})
    changed=sorted(n for n,item in entries.items() if old.get('entries',{}).get(n)!=item)
    if changed:reasons.append('core-collector-new-or-changed')
    dumps=[]
    for name in changed:
        item=entries[name]
        if item['mode']!=stat.S_IFREG or item['size']>LIMIT:
            reasons.append('core-type-or-size-incomplete');continue
        raw=reader(name)
        if len(raw)!=item['size']:raise ValueError('core bytes changed during read')
        dumps.append({'name':name,'data':raw,'identity':identity(raw)})
    witness={'rule':RULE,'configuration':before['configuration'],'configuration_after':after['configuration'],
             'processes':processes,'collector_new_or_changed':changed,
             'collector_exists':[old.get('exists'),new.get('exists')]}
    if reasons:
        return {'complete':False,'reason':'; '.join(dict.fromkeys(reasons)),'dumps':dumps,'witness':witness}
    return {'complete':True,'state':'not-produced','reason':'','dumps':[],'witness':witness}
