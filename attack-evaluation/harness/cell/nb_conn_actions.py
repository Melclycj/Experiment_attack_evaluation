"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import socket
from nb_conn_probe import probe_result
from nb_conn_spec import DIRECT, SPECS, address, parameters, payload


def exchange(ctx, wire, value, data):
    """Ordinary sockets only; never consult proxy environment variables."""
    conn, output, step, code = None, bytearray(), 'socket', 0
    try:
        family = socket.AF_INET if value['kind'] == 'inet' else socket.AF_UNIX
        conn = socket.socket(family, socket.SOCK_DGRAM if wire == 'udp' else socket.SOCK_STREAM)
        conn.settimeout(ctx.remaining(1))
        step = 'connect'; conn.connect(address(value, ctx.cwd))
        step = 'send'; conn.sendall(data)
        if wire != 'udp':
            step = 'shutdown'; conn.shutdown(socket.SHUT_WR)
        step = 'recv'
        while True:
            conn.settimeout(ctx.remaining(1))
            part = conn.recv(16385 - len(output))
            if not part:
                break
            output.extend(part)
            if len(output) > 16384:
                raise ValueError('connection echo bound')
            if wire == 'udp':
                break
        step = 'complete'
    except OSError as exc:
        # Socket timeouts are quality failures, not evidence of isolation.
        if isinstance(exc, TimeoutError) or exc.errno is None:
            raise TimeoutError('connection exchange timed out') from exc
        code = exc.errno
    finally:
        if conn is not None:
            conn.close()
    return bytes(output), {'step': step, 'errno': code, 'rc': -1 if code else 0}


def operation(ctx, attack, key, value, data):
    wire = SPECS[attack][key][0]
    if attack in DIRECT:
        raw = ctx.command(key, [str(ctx.payload / 'nb_probe'), wire,
                               value['address'], str(value['port'])], data=data)
        result = probe_result(raw, wire, len(data))
        output = raw['stdout']
    else:
        output, result = exchange(ctx, wire, value, data)
        ctx.capture(key, output)
    ctx.observe(key + '-result', **result, target=value)
    return output, result


def control(ctx, attack):
    from nb_conn_control import local_control
    parameters(ctx, attack)
    ok = True
    for key in SPECS[attack]:
        # Each address gets an independent control and capture, even for one wire.
        ok = local_control(ctx, attack, key, operation) and ok
    return ok


def action(ctx, attack):
    p = parameters(ctx, attack)
    for key, value in ctx.request['targets'].items():
        operation(ctx, attack, key, value, payload(attack, p['sentinel_' + key]))
