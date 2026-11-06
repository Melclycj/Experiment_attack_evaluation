"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import socket
import sys
sys.path.insert(0, str(Path(__file__).absolute().parent))
sys.path.insert(0, str(Path(__file__).absolute().parent / 'cell'))
from nb_conn_spec import address
from cell.nb_contract import decode, target
from common import json_bytes
from decoy_services import Journal, serve
from net import UPSTREAM_IP
from safeio import atomic_write, plain_path, read_owned


def bind_endpoint(value, wire):
    """Only the two private-run IPv4 addresses, or newly owned Unix endpoints."""
    value = dict(value)
    if wire not in ('tcp', 'udp', 'unix'):
        raise ValueError('unknown connection wire')
    if value['kind'] == 'inet':
        if wire == 'unix' or value['address'] not in ('127.0.0.1', UPSTREAM_IP):
            raise ValueError('not a private-run address')
        if type(value['port']) is not int or not 0 <= value['port'] <= 65535 or value['port'] == 3128:
            raise ValueError('invalid/reserved listener port')
    else:
        target(value)
        if wire != 'unix':
            raise ValueError('wrong Unix wire')
    conn = socket.socket(socket.AF_INET if value['kind'] == 'inet' else socket.AF_UNIX,
                         socket.SOCK_DGRAM if wire == 'udp' else socket.SOCK_STREAM)
    try:
        if value['kind'] == 'inet':
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        conn.bind(address(value))
        if value['kind'] == 'inet':
            value['port'] = conn.getsockname()[1]
            if value['port'] == 3128:
                raise ValueError('allocated frontend port; invalid preparation')
        if wire != 'udp':
            conn.listen(8)
        target(value)
        return conn, value
    except BaseException:
        conn.close()
        raise


def run(root, seconds):
    root = plain_path(Path(root))
    if not root.name.startswith('nb-decoy-') or root.stat().st_uid != 0 or not 0 < seconds <= 30:
        raise ValueError('invalid owned service directory/time limit')
    config = decode(read_owned(root / 'config.json', 16384))
    value = config['target']
    if value['kind'] == 'path' and value != {'kind': 'path', 'scope': 'host', 'path': str(root / 'socket')}:
        raise ValueError('path listener outside exact new store')
    listener, journal = None, None
    try:
        listener, value = bind_endpoint(value, config['wire'])
        if value['kind'] == 'path':
            if config['owner'] not in ('daemon', 'user'):
                raise ValueError('unknown socket ownership')
            os.chown(value['path'], 0 if config['owner'] == 'daemon' else 1000, 1000)
            os.chmod(value['path'], 0o660 if config['owner'] == 'daemon' else 0o600)
        journal = Journal(root / 'journal.jsonl', root / 'nb-decoy-markers' if config['markers'] else None,
                          config['attempt'], config['secret'])
        atomic_write(root / 'ready.json', json_bytes({'target': value, 'nonce': config['nonce'],
                     'pid': os.getpid(), 'wire': config['wire']}))
        serve(listener, journal, seconds=seconds)
    finally:
        if listener is not None:
            listener.close()
        if journal is not None:
            journal.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit(2)
    run(sys.argv[1], float(sys.argv[2]))
