"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import socket
import struct
from process_identity import ProcessRef, direct_children, process_info
from upstream import wait_for


def socket_inodes(entries):
    return {int(x[8:-1]) for x in entries if x.startswith('socket:[') and x.endswith(']')}


def table_witness(text, target, owned, protocol="tcp"):
    """Pure /proc socket-table parser; endpoint AND owning fd inode must match."""
    matches = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if target['kind'] == 'abstract':
            if len(parts) >= 8 and parts[3:6] == ['00010000', '0001', '01'] and parts[7] == '@' + target['name']:
                matches.append(int(parts[6]))
        elif target['kind'] == 'inet':
            endpoint = socket.inet_aton(target['address'])[::-1].hex().upper() + f':{target["port"]:04X}'
            if len(parts) >= 10 and parts[1] == endpoint and parts[3] == ('07' if protocol == 'udp' else '0A') and (protocol != 'udp' or parts[2] == '00000000:0000'):
                matches.append(int(parts[9]))
        elif target['kind'] == 'path':
            if len(parts) >= 8 and parts[3:6] == ['00010000', '0001', '01'] and parts[7] == target['path']:
                matches.append(int(parts[6]))
        else:
            raise ValueError('unsupported listener witness kind')
    if len(matches) != 1 or matches[0] not in owned:
        raise ValueError('listener absent/ambiguous or not owned by pinned process')
    return {'listening': True, 'target': dict(target), 'inode': matches[0]}


def inspect_listener(ref, target, protocol="tcp"):
    before = ref.read()
    root = Path('/proc') / str(before['pid'])
    entries = []
    for p in (root / 'fd').iterdir():
        try:
            entries.append(os.readlink(p))
        except FileNotFoundError:
            continue
    text = (root / 'net' / (('udp' if protocol == 'udp' else 'tcp') if target['kind'] == 'inet' else 'unix')).read_text()
    fact = table_witness(text, target, socket_inodes(entries), protocol)
    ref.read()
    return fact


def pin_child(rt, key, child, uid):
    if key in rt.deployment.refs:
        return rt.deployment.refs[key]
    if child not in rt.command.children or child.proc.poll() is not None:
        raise ValueError('cannot pin a foreign/exited supervisor child')
    ref = ProcessRef(child.proc.pid, uid, child.group if hasattr(child, 'group') else rt.cgroup)
    rt.deployment.refs[key] = ref
    return ref


def pin_row(rt, row, key):
    if key in rt.deployment.refs:
        raise ValueError('support process key already pinned')
    if row.config == 'undefended':
        # AttemptGroup membership is deliberately narrower than the batch group.
        # Commands.start acknowledges cgroup entry BEFORE setpriv/exec.
        # Wait for the owned live child to drop uid; do not pin root by timing.
        def host_ready():
            try:
                return process_info(row.child.proc.pid)['uids'] == [1000] * 4
            except FileNotFoundError:
                return False
        wait_for(rt.command, host_ready, timeout=5, child=row.child)
        ref = ProcessRef(row.child.proc.pid, 1000, row.group)
    else:
        if row.uid is None:
            raise ValueError('support row uid unavailable')
        spawner = rt.deployment.refs['spawner']
        def find():
            spawner.read()
            found = []
            for pid in direct_children(spawner.initial['pid']):
                try:
                    info = process_info(pid)
                except FileNotFoundError:
                    continue
                if info['uids'] == [row.uid] * 4:
                    found.append(pid)
            if len(found) > 1:
                raise ValueError('ambiguous row leader')
            return found[0] if found else None
        pid = wait_for(rt.command, find, timeout=5)
        ref = ProcessRef(pid, row.uid, rt.cgroup)
    rt.deployment.refs[key] = ref
    return ref
