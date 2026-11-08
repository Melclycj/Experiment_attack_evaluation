"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import secrets
import time
from pathlib import Path
from cb_measure import environment
from cb_processes import ProcessMeasurement
from cb_dumps import witness as dump_witness
from cb_outlets import e09_read, collect as outlets
from cb_terminal import gate, open_terminal, finish_terminal
from common import json_bytes
from run_transport import prepare_request, request, synchronize, collect, CollectionError


def file_worker_environ(rt, execution):
    """v4 (user 2026-11-06): the row's file worker's /proc/PID/environ, read once while the row waits at its gate.
    The pin is released at once: the worker is a scan source here, not an NB-23 signal target."""
    key='file-worker:'+execution
    ref=rt.deployment.file_worker(execution)
    try:
        receipt,raw=environment(ref)
        rt.command.budget.consume(raw)
    finally:
        rt.deployment.refs.pop(key,None);ref.close()
    return {**receipt,'role':'file-worker','stage':'row-gate'},raw


def run_row(rt, case, prepared, files, *, config, workspace='work0', interact=None, on_sync=None):
    """A bounded real row, called only by the authorized CB batch, never offline tests."""
    old_work=rt.work;rt.work=files.root
    measure=ProcessMeasurement(rt,files,prepared);handle=None
    nonce=secrets.token_hex(24)
    p=prepared['parameters']
    p['measurement']={k:files.reserve('nb-decoy-measure-'+nonce+'-'+k) for k in ('ready','release')}
    p['measurement']['marker']=nonce
    if config=='engine':p['terminal']=gate()
    # The batch's verified E-09 prefix carries across rows: truncation or rewrite between rows fails here.
    prepared['e09_before']=e09_read(rt.deployment,rt.cb_e09_seen)
    req=request(rt.bundle['run'],config,case,1,prepared);prepared['request']=req
    p['attempt_nonce']=req['sync']['nonce']
    # request() returns the same parameter object, so freeze after the generated nonce.
    prepare_request(files.root,req)
    prepared['dump_before']=dump_witness(Path(rt.host['crash_directory']))
    rt.deployment.upstream.begin(req['sync']['nonce'])
    old_observers=list(getattr(rt.command,'observers',()))
    rt.command.observers=[*old_observers,measure.pump]
    synced=None;observation={};captures={};tree={};terminal=None
    try:
        handle=rt.start(config,workspace=workspace,seconds=rt.command.deadline.left(30))
        measure.handle=handle
        if config=='engine':
            prepared['file_worker_environ']=file_worker_environ(rt,handle.execution)
            terminal=open_terminal(handle,p['terminal'])
        if interact:interact(handle,prepared)
        while True:
            measure.pump()
            if case.sync and synced is None:
                def ready(item):
                    if p.get('worker_ready') and len(measure.items)!=2:
                        raise ValueError('child cannot be released without its pinned environment')
                    return on_sync(prepared,item) if on_sync else {'ready':item}
                synced=synchronize(files.root,req,case.sync,ready)
            rt.pump()
            if handle.poll():break
        tree=handle.finish()
        screen=finish_terminal(rt,terminal,p['terminal']) if terminal else None
        window=rt.deployment.upstream.end()
        error=None
        try:observation,captures=collect(files.root,req,rt.evidence)
        except CollectionError as exc:
            observation,captures=exc.observation or {},exc.captures;error=str(exc)
        if case.sync and synced is None:
            # Diagnosis only: keep the cell's own account of why it never signalled.
            rt.evidence.raw(json_bytes({'observation':observation,'collection_error':error,'window':window,
                                        'terminal':screen and screen['data'].decode('utf-8','replace')[-4096:]}),
                            'handshake-absent.json')
            raise ValueError('required row handshake absent; cell error: '
                             +str(observation.get('error') or error)[:120])
        coverage=outlets(rt,prepared,observation,captures,window,measure,handle,tree=tree,terminal=screen)
        if error:
            coverage['complete']=False;coverage['gaps'].append(error)
        result={'observation':observation,'captures':captures,'window':window,'coverage':coverage,
                'tree':tree,'row':handle.execution or 'undefended:'+str(handle.child.proc.pid),
                'synchronization':synced}
        # All returned bytes are separately archived; this is an attributable receipt.
        result['evidence']=rt.evidence.raw(json_bytes({k:v for k,v in result.items() if k!='captures'}))
        result['diagnostics']=prepared.pop('diagnostics',None)  # bytes already archived as E-09/connector items
        return result
    finally:
        try:
            if terminal is not None and not terminal.closed:terminal.close()
        except Exception:pass  # the row already failed; Commands still owns and reaps the client
        measure.close();rt.command.observers=old_observers;rt.work=old_work
