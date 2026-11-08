"""这是 1.1 隔离论证的验证测试：4d 宿主准备与外部事实，只接受本批拥有的对象。"""
import signal
from common import json_bytes
from env import WORKER_UID
from cell.nb_engine_spec import ROLES

# Each target's expected uid: the core runs as the host user, the spawner as root, the row connectors as 70999 and
# (v4) the row file workers as the dedicated file-worker uid.
UIDS = {'core': 1000, 'spawner': 0, 'victim-connector': 70999, 'auxiliary-connector': 70999,
        'victim-file-worker': WORKER_UID, 'auxiliary-file-worker': WORKER_UID}


def prepare_signals(adapter, config):
    rt, targets, before = adapter.rt, {}, {}
    if config == 'undefended':
        rt.support.ensure_signal_victim()
    for key, role in ROLES.items():
        if role in ('core', 'spawner'):
            ref = rt.deployment.refs[role]
        else:
            item = rt.support.items['victim' if role.startswith('victim-') else 'auxiliary']
            row = item['row']
            if row.closed or not row.execution: raise ValueError('support connector is not live')
            kind = 'connector:' if role.endswith('-connector') else 'file-worker:'
            ref = rt.deployment.refs[kind + row.execution]
        value = ref.read()
        uid = UIDS[role]
        if value['state'] in ('T', 't', 'Z', 'X') or value['uids'] != [uid]*4:
            raise ValueError('signal target initially stopped/exited/wrong uid')
        rt.targets.add_process(key, ref)
        targets[key] = {'kind': 'process', 'pid': value['pid'], 'starttime': value['start_time']}
        adapter.registered[key] = targets[key]
        adapter.processes[key] = ref
        before[key] = {k: value[k] for k in ('pid', 'start_time', 'uids', 'state', 'cgroup')}
    return targets, before


def sample_signals(adapter, prepared):
    '''Pin identity before every pump/poll; save each first stopped state once.'''
    saved = prepared.setdefault('signal_witnesses', {})
    refs = prepared.setdefault('signal_evidence', {})
    for key, ref in adapter.processes.items():
        current = ref.read()
        before = prepared['before']['targets'][key]
        if any(current[k] != before[k] for k in ('pid', 'start_time', 'uids', 'cgroup')):
            raise ValueError('signal witness identity changed: ' + key)
        if current['state'] in ('T', 't') and key not in saved:
            saved[key] = {k: current[k] for k in ('pid', 'start_time', 'uids', 'state', 'cgroup')}
            # Keep in-memory fact even if archive budget/I/O fails at this point.
            refs[key] = adapter.rt.evidence.raw(json_bytes({'target': key, 'stopped': saved[key]}),
                                               'signal-stopped.json')


def resume_processes(adapter, *, wait=True):
    """Attempt EVERY pinned target, even if another died or evidence writing failed.
    Never use os.kill/numeric PID. Timeout disposal still resumes before teardown.
    """
    from upstream import wait_for
    results, errors = {}, []
    for key, ref in adapter.processes.items():
        try:
            fact = ref.read()
            if fact['state'] in ('Z', 'X'): raise ValueError('target died before recovery')
            stopped = fact['state'] in ('T', 't')
            if stopped:
                ref.send(signal.SIGCONT)
                if wait:
                    wait_for(adapter.rt.command, lambda: ref.read()['state'] not in ('T', 't'), timeout=2)
            final = ref.read()
            results[key] = {'was_stopped': stopped, 'state': final['state'], 'pid': final['pid']}
            if final['state'] in ('T', 't', 'Z', 'X'):
                raise ValueError('target not restored to live running state')
        except Exception as exc:
            errors.append(key + ': ' + str(exc))
    return {'restored': not errors, 'processes': results, 'errors': errors}
