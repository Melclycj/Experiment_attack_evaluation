"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import json
from pathlib import Path
from cb_scan import Scan
from cb_dumps import LIMIT as DUMP_LIMIT, lifecycle, witness as dump_witness
from cb_measure import environment
from common import json_bytes
from safeio import read_beneath


def e09_read(deployment, prior=b''):
    raw=read_beneath(deployment.scratch,deployment.evidence.name)
    if not raw.startswith(prior) or (raw and not raw.endswith(b'\n')):
        raise ValueError('E09 truncated, changed or incomplete')
    for line in raw.splitlines():
        if not isinstance(json.loads(line),dict):raise ValueError('E09 nonobject record')
    return raw


def collect(rt, prepared, observation, captures, window, process_measure, handle, tree=None, terminal=None):
    scan=Scan(prepared['all_accounts']);evidence=rt.evidence
    processes=[{'role':'row-tree','exit_verified':(tree or {}).get('tree_empty') is True,
                'source':(tree or {}).get('source')}]
    def add(outlet,name,data,complete=True,provenance=None,preset=False):
        source=evidence.raw(data,name)
        return scan.add(outlet,source['file'],data,complete=complete,
                        provenance={**(provenance or {}),'raw':source},preset=preset)
    # Upstream authorization exceptions are applied by cb_judge per raw request.
    add('upstream','upstream-index',b'',provenance={'window':evidence.raw(json_bytes(window)),
        'scan_owner':'cb_judge.request_scan','requests':len(window.get('requests',[]))})
    if not captures:scan.unavailable('responses','runner','no verified captures')
    for name,raw in captures.items():add('responses','capture',raw,provenance={'workspace_name':name})
    add('trace','runner-observation',json_bytes(observation),complete=observation.get('complete') is True)
    if handle.execution:
        # The row's pty stream, read through one attach client from before the cell's gate to relay EOF.
        if terminal is None:scan.unavailable('trace','runner-terminal','engine row terminal not captured')
        else:
            add('trace','runner-terminal',terminal['data'],complete=terminal['complete'],
                provenance={**terminal['provenance'],'reason':terminal['reason']})
            if not terminal['complete']:scan.unavailable('trace','runner-terminal',terminal['reason'])
    prior=prepared['e09_before']
    raw=e09_read(rt.deployment,prior);rt.cb_e09_seen=raw;attempt_e09=raw[len(prior):]
    add('e09','attempt-e09',attempt_e09,provenance={'cursor':len(prior),'total_bytes':len(raw)})
    # Core stays alive for the batch. Its cumulative prefix is checked again at
    # finalization; this item only claims the attempt's current prefix.
    core=rt.deployment.engine
    for name,raw in core.buffers.items():
        add('core-connector-output','core-'+name,bytes(raw),provenance={'process':rt.deployment.refs['core'].initial,
            'scope':'prefix; batch exit scan required'})
    if handle.execution:
        worker=prepared.pop('file_worker_environ',None)  # v4: the row's file worker, sampled at the row gate (cb_row)
        if worker is None:scan.unavailable('environ','file-worker-environ','file worker environment not sampled')
        else:add('environ','file-worker-environ',worker[1],provenance=worker[0])
        connector=b''
        for item in rt.deployment.cb_measure.collect(handle.execution):
            processes.append({'role':'connector','pid':item['ready']['pid'],'exit_verified':item['ref'].exited()})
            add('environ','connector-environ',item['environment_bytes'],provenance=item['environment'])
            for name,log in item['logs'].items():
                add('core-connector-output','connector-'+name,log['data'],complete=log['complete'],
                    provenance={'ready':item['ready']})
                if name=='stderr':connector+=log['data']
        # Mechanism diagnosis input (cb_mechanism): the same verified bytes, never a cell report.
        prepared['diagnostics']={'e09':attempt_e09,'connector':connector}
    else:
        for name,raw in handle.child.buffers.items():
            add('trace','undefended-'+name,bytes(raw),provenance={'process':handle.child.proc.pid})
    complete=process_measure.finish()
    for item in process_measure.items:
        p=item['receipt'];preset=p['role']=='undefended-parent'
        processes.append({'role':p['role'],'pid':p['process']['pid'],'exit_verified':item['ref'].exited()})
        add('environ','process-environ',item['raw'],complete=complete,provenance=p,preset=preset)
    if not complete:scan.unavailable('environ','declared-processes','missing handshake or live process')
    core_receipt,core_env=environment(rt.deployment.refs['core'])
    add('environ','core-environ',core_env,provenance={**core_receipt,'role':'core','stage':'attempt-end'})
    crash=Path(rt.host['crash_directory'])
    closing=dump_witness(crash)
    # Core liveness and identity are confirmed after the closing witness, so a
    # core crash inside the window cannot pass as 'not produced'. A later crash
    # is caught by the batch-exit collector re-check and the cleanup crash check.
    try:
        rt.deployment.refs['core'].read();alive=True
    except (RuntimeError,OSError,ValueError):
        alive=False
    processes.append({'role':'core','pid':core_receipt['process']['pid'],'alive_verified':alive,
                      'identity_unchanged':alive,'checked':'after-closing-witness'})
    dump=lifecycle(prepared['dump_before'],closing,processes,
                   lambda name:read_beneath(crash,name,DUMP_LIMIT))
    for item in dump['dumps']:
        add('core-dump','core-dump',item['data'],complete=False,
            provenance={'collector':str(crash),'name':item['name']})
    if dump['complete']:scan.not_produced('core-dump','lifecycle',dump['witness'])
    else:scan.unavailable('core-dump','lifecycle',dump['reason'],witness=dump['witness'])
    return scan.result()
