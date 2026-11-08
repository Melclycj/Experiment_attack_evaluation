"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from nb_contract import decode


def probe_result(raw, wire, size):
    """Validate the existing static C network probe, including the first failure.
    Host repeats this parsing from the archived stderr; cell booleans are not proof.
    """
    if raw['returncode'] != 0 or raw.get('signal') is not None or raw.get('error'):
        raise ValueError('network probe did not finish')
    events = [decode(line) for line in raw['stderr'].splitlines()]
    if not events or events.pop() != {'step': 'complete', 'rc': 0, 'errno': 0}:
        raise ValueError('incomplete network probe events')
    for item in events:
        if (set(item) != {'step', 'rc', 'errno'} or type(item['rc']) is not int
                or type(item['errno']) is not int or item['errno'] < 0
                or (item['rc'] < 0) != (item['errno'] > 0)):
            raise ValueError('malformed network probe event')
    pos, failed = 0, None

    def take(step):
        nonlocal pos, failed
        if pos >= len(events) or events[pos]['step'] != step:
            raise ValueError('network probe order: expected ' + step)
        item = events[pos]; pos += 1
        if item['rc'] < 0:
            failed = item
        return item['rc']

    opened = take('socket') >= 0
    if opened:
        for step in ('send_timeout', 'recv_timeout', 'connect'):
            if failed is None:
                take(step)
        sent = 0
        while failed is None and sent < size:
            n = take('send')
            if n == 0 or n > size - sent or (wire == 'udp' and n >= 0 and n != size):
                raise ValueError('invalid send count')
            if n > 0:
                sent += n
        if failed is None and wire == 'tcp':
            take('shutdown')
        received = 0
        while failed is None:
            n = take('recv')
            if n > 0:
                received += n
            if n <= 0 or wire == 'udp':
                break
        if received != len(raw['stdout']):
            raise ValueError('probe receive count differs from capture')
        prior = failed
        take('close')
        failed = prior or failed
    elif raw['stdout']:
        raise ValueError('capture without network socket')
    if pos != len(events):
        raise ValueError('unexpected trailing network probe events')
    return {'step': failed['step'] if failed else 'complete',
            'errno': failed['errno'] if failed else 0, 'rc': -1 if failed else 0}
