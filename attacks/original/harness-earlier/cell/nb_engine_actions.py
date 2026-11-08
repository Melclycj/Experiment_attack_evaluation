"""这是 1.1 隔离论证的验证测试：仅针对本批自建部署与诱饵；本模块实现 4d，不授权真实运行。"""
import json
import os
import posixpath
from nb_engine_spec import parameters
from nb_file_diag import probe_result
from nb_engine_question import PendingRequest, answer, control as socket_control
from nb_engine_probe import stop_result, control_result


def native_file(ctx, key, path, op='read', data=b''):
    raw = ctx.command(key, [str(ctx.payload / 'nb_probe'), op, path], data=data)
    value = probe_result(raw, path)
    ctx.observe(key + '-result', **value)
    return value


def rewrite(ctx, path):
    """Existing mirror only: no mkdir/O_CREAT, retain its identity fields/schema."""
    code, obj, step = 0, None, 'open'
    try:
        with open(path, 'r+b') as stream:
            s = os.fstat(stream.fileno())
            obj = {'dev': s.st_dev, 'ino': s.st_ino, 'size': s.st_size}
            data = stream.read(65537)
            if len(data) > 65536: raise ValueError('mirror read bound')
            value = json.loads(data)
            if (not isinstance(value, dict) or value.get('v') != 1
                    or value.get('workspace_id') != 'work0' or not isinstance(value.get('entries'), list)):
                raise ValueError('unexpected workspace mirror schema')
            key = 'nb-decoy-question.test:443'
            value['entries'] = [e for e in value['entries'] if not (e['key_kind'] == 1 and e['key'] == key)]
            value['entries'].append({'key_kind': 1, 'key': key, 'state': 1, 'methods': ['POST'],
                                    'prefixes': ['/'], 'accounts': [], 'approval': 1})
            data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            if len(data) > 65536: raise ValueError('mirror write bound')
            step = 'write'; stream.seek(0); stream.write(data); stream.truncate()
            stream.flush(); os.fsync(stream.fileno())
    except OSError as exc:
        code = exc.errno
        if not code: raise
    ctx.capture('mirror', b'')
    fact = {'path': path, 'errno': code, 'identity': obj, 'step': step, 'valid': True}
    ctx.observe('mirror-result', **fact)
    return fact


def control(ctx, attack):
    p = parameters(ctx, attack)
    if attack == 'NB-23':
        raw = ctx.command('stop-control', [str(ctx.payload / 'nb_probe'), 'stop-control', 'self'])
        value = control_result(raw)
        ctx.observe('stop-control-result', **value)
        return value['valid']
    ok = True
    for key, rel in p['controls'].items():
        path = posixpath.join(ctx.cwd, rel)
        if attack == 'NB-21':
            value = rewrite(ctx, path) if key == 'mirror' else None
            good = value['errno'] == 0 if value else socket_control(ctx)
        else:
            value = native_file(ctx, key, path, 'truncate' if attack == 'NB-22' else 'read',
                (p['write_sentinel'] + '\n').encode() if attack == 'NB-22' else b'')
            good = value['valid'] and value['errno'] == 0
        ok = bool(good and ok)
    return ok


def action(ctx, attack):
    p = parameters(ctx, attack)
    if attack == 'NB-21':
        pending = None
        try:
            if ctx.request['config'] == 'engine':
                pending = PendingRequest(ctx, '/' + p['request_sentinel']); pending.wait_sent()
            qid = ctx.synchronize('sent')
            rewrite(ctx, ctx.path('mirror'))
            value = answer(ctx, ctx.path('admin'), qid)
            if pending is not None: pending.finish(cancel=value['errno'] != 0)
        finally:
            if pending is not None: pending.close()
    elif attack == 'NB-23':
        for key in ctx.request['targets']:
            item = ctx.target(key, 'process')
            raw = ctx.command(key, [str(ctx.payload / 'nb_probe'), 'stop', str(item['pid']), str(item['starttime'])])
            ctx.observe(key + '-result', **stop_result(raw))
    else:
        for key in ctx.request['targets']:
            native_file(ctx, key, ctx.path(key), 'truncate' if attack == 'NB-22' else 'read',
                (p['write_sentinel'] + '\n').encode() if attack == 'NB-22' else b'')
