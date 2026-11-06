"""这是 1.1 隔离论证的验证测试：4d 的 C 探针记录校验；不执行系统调用。"""
import errno
from nb_contract import decode


def events(raw):
    if raw.get('error') or raw.get('signal') is not None or raw.get('returncode') != 0 or raw.get('stdout'):
        raise ValueError('signal probe incomplete/nonempty capture')
    items = [decode(line) for line in raw['stderr'].splitlines()]
    if not items or items.pop() != {'step': 'complete', 'rc': 0, 'errno': 0}:
        raise ValueError('signal probe completion missing')
    for item in items:
        if (set(item) != {'step', 'rc', 'errno'} or type(item['rc']) is not int
                or type(item['errno']) is not int or item['errno'] < 0
                or (item['rc'] < 0) != (item['errno'] > 0)):
            raise ValueError('malformed signal event')
    return items


def stop_result(raw):
    items = events(raw)
    if len(items) not in (2, 5) or items[0]['step'] != 'proc_open' or items[-1]['step'] != 'kill':
        raise ValueError('signal probe event order')
    matched = len(items) == 5
    if matched:
        if ([e['step'] for e in items[1:4]] != ['proc_read', 'proc_close', 'process_identity_match']
                or items[0]['rc'] < 0 or items[1]['rc'] <= 0 or items[2]['rc'] != 0 or items[3]['rc'] != 0):
            raise ValueError('signal process identity not verified')
    elif items[0]['rc'] >= 0 or items[0]['errno'] != errno.ENOENT:
        raise ValueError('unexpected proc visibility error')
    last = items[-1]
    if last['rc'] not in (-1, 0): raise ValueError('invalid kill result')
    return {'valid': True, 'matched': matched, 'errno': last['errno'], 'rc': last['rc']}


def control_result(raw):
    items = events(raw)
    expected = ['control_fork', 'control_stop', 'control_wait_stop', 'control_state',
                'control_resume', 'control_kill', 'control_reap']
    if [e['step'] for e in items] != expected or any(e['errno'] for e in items):
        raise ValueError('stop control failed or incomplete restoration')
    pid = items[0]['rc']
    if (pid <= 1 or items[2]['rc'] != pid or items[6]['rc'] != pid
            or any(items[i]['rc'] != 0 for i in (1,3,4,5))):
        raise ValueError('stop control child identity/wait mismatch')
    return {'valid': True, 'child': pid, 'stopped': True, 'resumed': True, 'reaped': True}
