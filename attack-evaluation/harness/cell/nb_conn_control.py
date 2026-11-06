"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
import socket
import threading
from nb_conn_spec import SPECS, address, payload


def local_control(ctx, attack, key, operation):
    """Same exchange/probe as action, with a fresh local listener, closed first.
    Only called inside an authorized row. Offline tests mock socket and thread.
    """
    wire, where = SPECS[attack][key]
    name = ctx.request['parameters']['controls'][key]
    kind = 'inet' if wire != 'unix' else 'path' if where == 'path' else 'abstract'
    value = ({'kind': 'inet', 'address': '127.0.0.1', 'port': 0} if kind == 'inet' else
             {'kind': 'path', 'scope': 'work', 'path': name} if kind == 'path' else
             {'kind': 'abstract', 'name': name})
    location = address(value, ctx.cwd)
    if kind == 'path' and os.path.lexists(location):
        raise FileExistsError('local control path already exists')
    listener, thread, bound, result = None, None, False, {}
    data = payload(attack, ctx.request['parameters']['control_' + key])

    def serve():
        try:
            if wire == 'udp':
                received, peer = listener.recvfrom(16385)
                listener.sendto(received, peer)
            else:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(ctx.remaining(2))
                    chunks = bytearray()
                    while len(chunks) <= 16384:
                        part = conn.recv(16385 - len(chunks))
                        if not part:
                            break
                        chunks.extend(part)
                    received = bytes(chunks)
                    if len(received) > 16384:
                        raise ValueError('control receive bound')
                    conn.sendall(received)
            result['received'] = received
        except Exception as exc:
            result['error'] = type(exc).__name__ + ': ' + str(exc)

    try:
        family = socket.AF_INET if kind == 'inet' else socket.AF_UNIX
        listener = socket.socket(family, socket.SOCK_DGRAM if wire == 'udp' else socket.SOCK_STREAM)
        listener.settimeout(ctx.remaining(2)); listener.bind(location); bound = True
        if kind == 'inet':
            value['port'] = listener.getsockname()[1]
        if wire != 'udp':
            listener.listen(1)
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        echoed, result_call = operation(ctx, attack, key, value, data)
        thread.join(timeout=ctx.remaining(3))
        if thread.is_alive() or 'error' in result or 'received' not in result:
            raise ValueError('local control service failed: ' + str(result.get('error')))
        ctx.capture(key + '-received', result['received'])
        return result_call['errno'] == 0 and echoed == result['received'] == data
    finally:
        if listener is not None:
            listener.close()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)
            if thread.is_alive():
                raise RuntimeError('control thread not stopped')
        if bound and kind == 'path':
            os.unlink(location)
