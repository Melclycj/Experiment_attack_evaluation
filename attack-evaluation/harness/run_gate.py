"""这是 1.1 隔离论证的验证测试：持久启动门；不清扫历史对象，不自动解锁失败。"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import stat
from common import MAX_OUTPUT, identity, json_bytes, utc
from record import load_run
import summarize  # Load report renderer before the outer launcher removes its snapshot.
from safeio import atomic_write, plain_path, read_owned

STATE = Path('/var/lib/nb-decoy-harness-gate')
LIMIT = 16384
RECOVERY = 'nb-cleanup-recovery/1'
RECORD_LIMIT = 65536
FORCED = 'forced-incomplete'
DATE = r'\d{4}-\d{2}-\d{2}'


def recovery_path(path):
    """Beside the unit's runs directory, never inside an archive (user 2026-11-03)."""
    return Path(path).parent.parent/'recoveries'/(Path(path).name+'.json')


def recovery(path):
    target=recovery_path(path)
    if not os.path.lexists(target): return None
    record=json.loads(read_owned(target,RECORD_LIMIT))
    if not isinstance(record,dict) or record.get('schema')!=RECOVERY or record.get('run')!=Path(path).name:
        raise ValueError('malformed recovery record')
    return record


# run_recover.residue's check names. A record is accepted only with all of them (cold audit, finding 8).
REQUIRED_CHECKS = frozenset({'path-absent', 'cgroup-absent', 'no-nb-decoy-cgroup', 'no-nb-decoy-directory',
                             'no-mount-beneath-run-roots', 'no-backing-file-from-run', 'no-task-with-run-uids',
                             'no-new-crash-entries'})
GLOBAL_CHECKS = frozenset({'no-nb-decoy-cgroup', 'no-nb-decoy-directory'})


def _all_ok(checks):
    return bool(isinstance(checks,list) and checks
                and all(isinstance(c,dict) and c.get('ok') is True for c in checks))


def checks_cover(checks, roots):
    """The full residue check set, all ok, about this run's own objects: every root and
    image its archive names checked absent, and its snapshot and run cgroup named by the
    same snapshot token (a label-named cgroup is a different, nonexistent path)."""
    if not _all_ok(checks) or {c.get('check') for c in checks}!=REQUIRED_CHECKS:return False
    # The deployment root /var/lib/nb-decoy-<token> carries the snapshot token (run_boot.stage).
    tokens={Path(r).name[len('nb-decoy-'):] for r in roots
            if Path(r).parent==Path('/var/lib') and Path(r).name.startswith('nb-decoy-')}
    if len(tokens)!=1:return False
    token=tokens.pop()
    absent={str(c.get('object')) for c in checks if c['check']=='path-absent'}
    group=[str(c.get('object')) for c in checks if c['check']=='cgroup-absent']
    return bool(set(roots)<=absent and any(Path(p).name=='nb-decoy-boot-'+token for p in absent)
                and len(group)==1 and Path(group[0]).name=='nb-decoy-'+token)


def superseded(path):
    """A record without the run-cgroup and global checks is covered by a LATER recovery
    record of the same unit whose global checks (no nb-decoy cgroup, no nb-decoy directory
    in /tmp or /var/lib at all) were all ok: this run's objects were gone by then. Returns
    that record's run name, or None."""
    folder=recovery_path(path).parent
    if not folder.is_dir():return None
    for later in sorted(folder.iterdir()):
        if later.suffix!='.json' or later.stem<=Path(path).name:continue
        record=json.loads(read_owned(later,RECORD_LIMIT))
        checks=record.get('checks') if isinstance(record,dict) else None
        if (record.get('schema')==RECOVERY and re.fullmatch(DATE,str(record.get('approved_by_user','')))
                and _all_ok(checks) and GLOBAL_CHECKS<={c.get('check') for c in checks}):
            return later.stem
    return None


def archive_roots(header):
    steps=[s.get('step','') for s in header.get('cleanup',{}).get('steps',[])]
    return [s.split(':',1)[1] for s in steps if s.startswith(('remove:','verify-loop:'))]


def recovered(record, path, header):
    """Same rule for history and release: this run's cleanup and archive, a user
    approval date, the full residue check set about this run's objects all ok (or, for
    a record made before that set existed, a later global check), no retained object."""
    cleanup=header.get('cleanup',{});checks=record.get('checks')
    covered=checks_cover(checks,archive_roots(header)) or (_all_ok(checks) and superseded(path) is not None)
    return bool(not cleanup.get('retained') and header.get('run')==Path(path).name
                and record.get('cleanup')==identity(json_bytes(cleanup))
                and record.get('completion')==identity(read_owned(Path(path)/'COMPLETE.json'))
                and re.fullmatch(DATE,str(record.get('approved_by_user','')))
                and covered)


def recovered_forced(record, path):
    """A controller forced before archiving: no completion manifest exists, so the
    record pins the launcher marker; the run never counts as results. Its roots come
    from the record itself (run_recover.forced_objects); the token must still agree."""
    path=Path(path);marker=path/'LAUNCHER-FAILED.json';checks=record.get('checks')
    roots=[str(c.get('object')) for c in (checks if isinstance(checks,list) else []) if isinstance(c,dict)
           and c.get('check')=='path-absent' and not Path(str(c.get('object'))).name.startswith('nb-decoy-boot-')]
    return bool(record.get('kind')==FORCED and not os.path.lexists(path/'COMPLETE.json')
                and marker.exists() and record.get('launcher_failed')==identity(read_owned(marker))
                and re.fullmatch(DATE,str(record.get('approved_by_user','')))
                and checks_cover(checks,roots))


RECEIPT_RULE = '2026-11-04'  # acceptance rules a receipt vouches for; a change re-verifies every run in full.
# Raising the result-row bound from 8 to 16 KiB (2026-11-06) only relaxes acceptance, so it does not change the rule.


def _inventory(path):
    """Every entry of the run directory by name, type, size and mtime, in one scandir:
    a changed, added or removed evidence or results file voids the receipt (cold audit,
    finding 7). The manifest alone cannot show that the files it names still match it."""
    rows=[]
    with os.scandir(path) as entries:
        for entry in entries:
            info=entry.stat(follow_symlinks=False)
            rows.append([entry.name,stat.S_IFMT(info.st_mode),info.st_size,info.st_mtime_ns])
    rows.sort()
    return {'entries':len(rows),**identity(json_bytes(rows))}


def _deciding(path, record):
    """Identities of the small files whose bytes decide a history verdict, plus the
    whole directory's inventory and the acceptance rule version."""
    path=Path(path);marker=path/'LAUNCHER-FAILED.json'
    return {'completion':identity(read_owned(path/'COMPLETE.json',MAX_OUTPUT)),
            'header':identity(read_owned(path/'run.json',MAX_OUTPUT)),
            'launcher_failed':identity(read_owned(marker)) if marker.exists() else None,
            'recovery':identity(read_owned(recovery_path(path),RECORD_LIMIT)) if record else None,
            'inventory':_inventory(path),'rule':RECEIPT_RULE}


def _receipt_path(directory, path):
    return directory/'verified'/Path(path).parent.parent.name/(Path(path).name+'.json')


def _receipt_matches(path, record):
    with _locked() as directory:
        target=_receipt_path(directory,path)
        if not os.path.lexists(target): return False
        _owned(target.stat());saved=json.loads(read_owned(target,LIMIT))
    return saved.get('run')==Path(path).name and saved.get('files')==_deciding(path,record)


def _put_receipt(directory, path, record):
    """Caller holds the gate lock and has just verified the archive in full."""
    target=_receipt_path(directory,path)
    for folder in (target.parent.parent,target.parent):
        try: folder.mkdir(mode=0o700)
        except FileExistsError: pass
    atomic_write(target,json_bytes({'run':Path(path).name,'files':_deciding(path,record),'verified_at':utc()}),
                 replace=True)
    _sync(target.parent)


def _write_receipt(path, record):
    with _locked() as directory:_put_receipt(directory,path,record)


def check_history(runs, *, receipts=False):
    """Historical failed/incomplete cleanup is a stop, not a deletion request.

    receipts (2.3: user 2026-11-03; 1.1 too since 2026-11-06): a run fully verified once
    (load_run) gets a root-only receipt in the gate directory, kept per unit; later checks
    read only the small files that decide the verdict and fall back to full verification
    on any change.
    Full archive verification still runs whenever results are loaded or audited."""
    runs=plain_path(runs,missing_leaf=True)
    if not runs.exists(): return []
    checked=[]
    for path in sorted(runs.iterdir()):
        plain_path(path)
        if path.is_file(): continue  # history.md and other derived summaries
        if not path.is_dir() or not re.fullmatch(r'\d{8}T\d{6}Z-[A-Za-z0-9][A-Za-z0-9_-]{0,79}',path.name):
            raise RuntimeError('prior run directory unrecognized; inspect '+str(path))
        try:
            record=recovery(path)
            if record and record.get('kind')==FORCED:
                if not recovered_forced(record,path):raise ValueError('forced-run recovery record not acceptable')
                checked.append({'run':path.name,'archive':None,
                                'recovery':identity(read_owned(recovery_path(path),RECORD_LIMIT))})
                continue
            if receipts and _receipt_matches(path,record):
                checked.append({'run':path.name,'completion':identity(read_owned(path/'COMPLETE.json')),'receipt':True})
                continue
            header,_=load_run(path,launcher_failed=(record or {}).get('launcher_failed'))
            cleanup=header.get('cleanup',{})
            clean=(header.get('cleanup_ok') is True and cleanup.get('ok') is True
                   and not cleanup.get('failures') and not cleanup.get('retained'))
            if not clean and not (record and recovered(record,path,header)):
                raise ValueError('cleanup unverified or retained objects')
        except (OSError,ValueError,KeyError,TypeError) as exc:
            raise RuntimeError('prior cleanup gate refused '+str(path)+': '+str(exc)) from exc
        entry={'run':path.name,'completion':identity(read_owned(path/'COMPLETE.json'))}
        if not clean:entry['recovery']=identity(read_owned(recovery_path(path),RECORD_LIMIT))
        if receipts:_write_receipt(path,record)
        checked.append(entry)
    return checked


def _owned(info, *, directory=False):
    valid=stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1
    if not valid or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=(0o700 if directory else 0o600):
        raise RuntimeError('unsafe cleanup gate ownership/type/mode')


@contextmanager
def _locked():
    if os.name!='posix': raise RuntimeError('cleanup gate requires Linux')
    import fcntl
    parent=plain_path(STATE.parent)
    try: STATE.mkdir(mode=0o700)
    except FileExistsError: pass
    directory=plain_path(STATE);_owned(directory.stat(),directory=True)
    fd=os.open(directory/'mutex',os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        _owned(os.fstat(fd))
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield directory
    finally: os.close(fd)


def _sync(directory):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _active(directory):
    path=plain_path(directory/'active.json')
    _owned(path.stat())
    value=json.loads(read_owned(path,LIMIT))
    if not isinstance(value,dict) or value.get('schema')!='nb-cleanup-gate/1':
        raise RuntimeError('malformed cleanup gate; manual investigation required')
    return value


def claim(repo, run):
    """Root-only stage calls this before creating any snapshot/deployment.

    No PID/age/reboot expiry and no force flag: a crash leaves active.json intact.
    The fixed native-Linux location is shared even when repo or label changes.
    """
    with _locked() as directory:
        if os.path.lexists(directory/'active.json'):
            raise RuntimeError('cleanup gate active/unverified; inspect '+str(directory/'active.json'))
        lease={'schema':'nb-cleanup-gate/1','token':secrets.token_hex(32),
               'repo':str(repo),'run':run,'started_at':utc()}
        atomic_write(directory/'active.json',json_bytes(lease));_sync(directory)
        return lease


def _bound(bundle):
    lease=bundle.get('gate')
    if (not isinstance(lease,dict) or lease.get('repo')!=bundle.get('repo')
            or lease.get('run')!=bundle.get('run')
            or not re.fullmatch('[0-9a-f]{64}',lease.get('token',''))):
        raise ValueError('frozen cleanup gate binding missing/mismatched')
    return {**lease,'root':bundle['root'],'root_identity':bundle['root_identity'],'output':bundle['output']}


def bind(bundle):
    expected=_bound(bundle)
    with _locked() as directory:
        if _active(directory)!=bundle['gate']: raise RuntimeError('stale cleanup gate claim')
        atomic_write(directory/'active.json',json_bytes(expected),replace=True);_sync(directory)


def verify(bundle):
    with _locked() as directory:
        if _active(directory)!=_bound(bundle): raise RuntimeError('cleanup gate bundle identity changed')


def release(bundle):
    """Only the outer frozen launcher, AFTER verified archive and snapshot removal.

    Quality failures may release if cleanup is sound. Missing/corrupt completion,
    forced launcher, retained resources, or surviving snapshot keep the latch set.
    No recovery/force path is provided here; never infer cleanup from PID absence.
    """
    with _locked() as directory:
        if _active(directory)!=_bound(bundle): raise RuntimeError('stale cleanup gate release')
        if os.path.lexists(bundle['root']): raise RuntimeError('snapshot cleanup still unverified')
        path=Path(bundle['output']);header,_=load_run(path)
        cleanup=header.get('cleanup',{})
        if (header.get('run')!=bundle['run'] or header.get('cleanup_ok') is not True
                or cleanup.get('ok') is not True or cleanup.get('failures') or cleanup.get('retained')):
            raise RuntimeError('batch cleanup still unverified; gate retained')
        # This full verification is the one the next history check would repeat (both units).
        _put_receipt(directory,path,None)
        receipt={**_bound(bundle),'released_at':utc(),'cleanup':identity(json_bytes(cleanup)),
                 'completion':identity(read_owned(path/'COMPLETE.json')),'snapshot_removed':True}
        atomic_write(directory/'last-clean.json',json_bytes(receipt),replace=True)
        _sync(directory)
        os.unlink(directory/'active.json');_sync(directory)


def release_recovered(path, record):
    """Manual recovery of one failed-cleanup batch, called only by run_recover after
    its residue checks and the user's approval. Opens the latch only for the run the
    active lease names, once its snapshot is gone, its archive verifies with the
    launcher marker pinned, and the record passes the rule history applies. An
    existing record for the run is reused (an interrupted recovery), never replaced."""
    path=Path(path)
    with _locked() as directory:
        lease=_active(directory)
        if (lease.get('run')!=path.name or lease.get('output')!=str(path)
                or (record.get('gate') or {}).get('token')!=lease.get('token')):
            raise RuntimeError('active cleanup gate does not name this run')
        if not lease.get('root') or os.path.lexists(lease['root']):
            raise RuntimeError('snapshot cleanup still unverified')
        record=recovery(path) or record
        if record.get('kind')==FORCED:ok=recovered_forced(record,path)
        else:
            header,_=load_run(path,launcher_failed=record.get('launcher_failed'))
            ok=recovered(record,path,header)
        if not ok or (record.get('gate') or {}).get('token')!=lease.get('token'):
            raise RuntimeError('recovery record not acceptable; gate retained')
        target=recovery_path(path);data=json_bytes(record)
        if not os.path.lexists(target):
            plain_path(target.parent.parent)
            try: target.parent.mkdir()
            except FileExistsError: pass
            atomic_write(target,data)
        if record.get('kind')!=FORCED:
            _put_receipt(directory,path,record)
        receipt={**lease,'released_at':utc(),'recovery':identity(read_owned(target,RECORD_LIMIT)),
                 'completion':record.get('completion'),'snapshot_removed':True}
        atomic_write(directory/'last-clean.json',json_bytes(receipt),replace=True)
        _sync(directory)
        os.unlink(directory/'active.json');_sync(directory)
        return record
