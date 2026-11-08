"""Exercise the exported C receiver with real Linux sockets and credentials.

The privileged mixed-uid mode is a test supervisor, never an agent/engine path.
It supplies kernel-generated credentials; synthetic malformed cmsghdr cases
are separately labelled in check_transport.c.
"""
import array
import ctypes as C
import json
import os
import socket
import struct
import sys


lib = C.CDLL(sys.argv[1], use_errno=True)
lib.w2_recv_control.argtypes = [C.c_int, C.c_void_p, C.c_size_t, C.POINTER(C.c_int)]
lib.w2_recv_control.restype = C.c_ssize_t
lib.w2_reader_new.restype = C.c_void_p
lib.w2_reader_free.argtypes = [C.c_void_p]
lib.w2_frame_receive.argtypes = [C.c_void_p, C.c_int, C.c_uint, C.c_uint,
                               C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
results = []


def read_frame(reader, endpoint, uid):
    buf, length = C.create_string_buffer(65536), C.c_size_t()
    got = lib.w2_frame_receive(reader, endpoint.fileno(), uid, 65534,
                               buf, len(buf), C.byref(length))
    return got, buf.raw[:length.value]


def stream(credentials=True):
    a, b = socket.socketpair()
    if credentials:
        a.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    return a, b


def controls():
    epoch = 'a' * 32
    digest = 'sha256:' + 'b' * 64
    prepared = dict(v=1, type='spawn_prepared', engine_epoch=epoch, seq='1', connector_pid=4243, worker_pid=4244,
                    execution_id=epoch+':1', lease_id=epoch+':1:u',
                    launch_plan_digest=digest, policy_digest=digest,
                    isolation_profile_digest=digest, child_pid=1, sealed=True)
    prepared['copy_id'] = epoch+':1:r'
    ready = dict(v=1, type='control_ready', engine_epoch=epoch, seq='1',
                 catalog_digest=digest, protocol='w2-local/2')
    ready.update(runtime_storage_protocol='w2-runtime-store/1', storage_profile_digest=digest)
    for kind in ('valid', 'ready', 'missing', 'extra', 'unexpected', 'regular',
                 'no-passcred', 'seqpacket', 'unconnected', 'named',
                 'control-credentials', 'truncated', 'unknown-field'):
        with _resources() as owned:
            left, right = socket.socketpair(type=socket.SOCK_SEQPACKET)
            owned.extend([left, right])
            target, peer = stream(kind != 'no-passcred')
            owned.extend([target, peer])
            if kind == 'regular':
                target = open('/dev/null', 'rb')
                owned.append(target)
            elif kind == 'seqpacket':
                target, peer = socket.socketpair(type=socket.SOCK_SEQPACKET)
                owned.extend([target, peer])
                target.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            elif kind == 'unconnected':
                target = socket.socket(socket.AF_UNIX)
                owned.append(target)
                target.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            elif kind == 'named':
                server, client = socket.socket(socket.AF_UNIX), socket.socket(socket.AF_UNIX)
                owned.extend([server, client])
                server.bind('\0w2-check-'+str(os.getpid()))
                server.listen(1)
                client.connect(server.getsockname())
                target, _ = server.accept()
                owned.append(target)
                target.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            body = dict(ready if kind in {'ready', 'unexpected'} else prepared)
            if kind == 'unknown-field':
                body['flags'] = 0
            wire = json.dumps(body).encode()
            if kind == 'truncated':
                wire += b' ' * 16384
            fds = [] if kind in {'ready', 'missing'} else [target.fileno()]
            if kind == 'extra':
                fds *= 2
            if kind == 'control-credentials':
                left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
            before = len(os.listdir('/proc/self/fd'))
            assert right.sendmsg([wire], ancillary) == len(wire)
            buf, fd = C.create_string_buffer(16384), C.c_int(-1)
            n = lib.w2_recv_control(left.fileno(), buf, len(buf), C.byref(fd))
            if kind in {'valid', 'ready'}:
                assert n > 0, (kind, n, C.get_errno())
                if kind == 'valid':
                    assert fd.value >= 0 and not os.get_inheritable(fd.value)
                    os.close(fd.value)
                else:
                    assert fd.value == -1
            else:
                assert n == -1 and fd.value == -1, (kind, n, fd.value)
            assert len(os.listdir('/proc/self/fd')) == before, kind
            results.append('control:'+kind)


def controls3():
    """validation.md H-06: the engine's receiver of spawn_prepared takes exactly three fds, each an unnamed connected
    AF_UNIX stream with PASSCRED=1; two, four, a third without PASSCRED, a prepared without worker_pid, a
    worker_exited, and a fd on another record type are each refused with every received fd closed. The spawner's
    sender takes at most three."""
    lib.w2_recv_control3.argtypes = [C.c_int, C.c_void_p, C.c_size_t, C.POINTER(C.c_int * 3)]
    lib.w2_recv_control3.restype = C.c_ssize_t
    lib.w2_send_control_fds.argtypes = [C.c_int, C.c_char_p, C.c_size_t, C.POINTER(C.c_int), C.c_size_t]
    lib.w2_send_control_fds.restype = C.c_int
    epoch = 'a' * 32
    digest = 'sha256:' + 'b' * 64
    prepared = dict(v=1, type='spawn_prepared', engine_epoch=epoch, seq='1', connector_pid=4243, worker_pid=4244,
                    execution_id=epoch+':1', lease_id=epoch+':1:u', launch_plan_digest=digest, policy_digest=digest,
                    isolation_profile_digest=digest, child_pid=1, sealed=True, copy_id=epoch+':1:r')
    exited = dict(v=1, type='worker_exited', engine_epoch=epoch, seq='1', execution_id=epoch+':1',
                  lease_id=epoch+':1:u', exit_code=None, signal=9)
    for kind in ('valid', 'two', 'four', 'third-no-passcred', 'no-worker-pid', 'worker-exited', 'worker-exited-fd'):
        with _resources() as owned:
            left, right = socket.socketpair(type=socket.SOCK_SEQPACKET)
            owned.extend([left, right])
            ends = []
            for i in range(4):
                target, peer = stream(not (kind == 'third-no-passcred' and i == 2))
                owned.extend([target, peer])
                ends.append(target.fileno())
            body = dict(prepared)
            if kind == 'no-worker-pid':
                del body['worker_pid']
            if kind.startswith('worker-exited'):
                body = exited
            n_fds = {'two': 2, 'four': 4, 'worker-exited': 0, 'worker-exited-fd': 1}.get(kind, 3)
            wire = json.dumps(body).encode()
            before = len(os.listdir('/proc/self/fd'))
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', ends[:n_fds]))] if n_fds else []
            assert right.sendmsg([wire], ancillary) == len(wire)
            buf, fds = C.create_string_buffer(16384), (C.c_int * 3)(-1, -1, -1)
            n = lib.w2_recv_control3(left.fileno(), buf, len(buf), C.byref(fds))
            if kind in ('valid', 'worker-exited'):
                assert n > 0, (kind, n, C.get_errno())
                got = [v for v in fds if v >= 0]
                assert len(got) == (3 if kind == 'valid' else 0), (kind, list(fds))
                assert all(not os.get_inheritable(v) for v in got)
                for v in got:
                    os.close(v)
            else:
                assert n == -1 and list(fds) == [-1, -1, -1], (kind, n, list(fds))
            assert len(os.listdir('/proc/self/fd')) == before, kind
            results.append('control3:' + kind)
    with _resources() as owned:                                # the sender: three go, four are refused
        left, right = socket.socketpair(type=socket.SOCK_SEQPACKET)
        owned.extend([left, right])
        wire = json.dumps(prepared).encode()
        four = (C.c_int * 4)(*[left.fileno()] * 4)
        assert lib.w2_send_control_fds(right.fileno(), wire, len(wire), four, 3) == 1
        assert lib.w2_send_control_fds(right.fileno(), wire, len(wire), four, 4) == -1
        results.append('control3:sender-cap')


class _resources(list):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        for resource in reversed(self):
            resource.close()


def data_frames():
    uid = os.getuid()
    for change in ('uid', 'fd-reuse'):
        with _resources() as owned:
            receiver, sender = stream()
            owned.extend([receiver, sender])
            reader = lib.w2_reader_new()
            try:
                sender.sendall(b'\0')
                assert read_frame(reader, receiver, uid)[0] == 0
                if change == 'fd-reuse':
                    replacement, peer = stream()
                    owned.extend([replacement, peer])
                    os.dup2(replacement.fileno(), receiver.fileno(), inheritable=False)
                    peer.sendall(b'\0\0\2{}')
                else:
                    sender.sendall(b'\0\0\2{}')
                assert read_frame(reader, receiver, uid+1 if change == 'uid' else uid)[0] == -1
                results.append('frame:immutable-binding-'+change)
            finally:
                lib.w2_reader_free(reader)
    maximum = b'{"text":"' + b'x' * (65536-11) + b'"}'
    assert len(maximum) == 65536
    with _resources() as owned:
        receiver, sender = stream()
        owned.extend([receiver, sender])
        reader = lib.w2_reader_new()
        try:
            for body in (maximum, b'{}', b'{"next":true}'):
                sender.sendall(struct.pack('>I', len(body))+body)
                assert read_frame(reader, receiver, uid)[0] == 0  # exact header
                got, actual = read_frame(reader, receiver, uid)
                assert got == 1 and actual == body
            results.append('frame:maximum-and-contiguous')
        finally:
            lib.w2_reader_free(reader)
    # Since 2026-10-19 the C reader frames and compares only; it hands every credential-checked body over
    # unchanged, and the body's content (integer range, element and depth limits, duplicate keys, UTF-8) is
    # judged by the engine's Python parse (engine/receive.py parse_body; tests/test_receive.py). These cases
    # check the hand-over: content the parse rejects is not rejected, altered or truncated here.
    for kind, body in (
        ('safe-int', b'{"n":9007199254740991}'),
        ('unsafe-int', b'{"n":9007199254740992}'),
        ('unsafe-negative-int', b'{"n":-9007199254740992}'),
        ('element-limit', json.dumps({'a': [0]*4095}, separators=(',', ':')).encode()),
        ('element-overflow', json.dumps({'a': [0]*4096}, separators=(',', ':')).encode()),
        ('depth-limit', b'{"a":'*16+b'0'+b'}'*16),
        ('depth-overflow', b'{"a":'*17+b'0'+b'}'*17),
        ('duplicate-key', b'{"x":1,"x":2}'),
        ('bad-utf8', b'{"x":"\xff"}'),
        ('not-json', b'not json'),
    ):
        receiver, sender = stream()
        reader = lib.w2_reader_new()
        try:
            sender.sendall(struct.pack('>I', len(body))+body)
            assert read_frame(reader, receiver, uid)[0] == 0
            got, data = read_frame(reader, receiver, uid)
            assert got == 1 and data == body, kind
            results.append('frame-handover:'+kind)
        finally:
            lib.w2_reader_free(reader)
            receiver.close()
            sender.close()
    for kind, wire in (
        ('zero', b'\0'*4), ('oversize', struct.pack('>I', 65537)),
        ('rights', b'\0\0\0\2{}'), ('urgent', b'\0\0\0\2{}'),
    ):
        receiver, sender = stream()
        reader = lib.w2_reader_new()
        try:
            if kind == 'rights':
                before = len(os.listdir('/proc/self/fd'))
                sender.sendmsg([wire], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                         array.array('i', [sender.fileno()]))])
            else:
                sender.sendall(wire)
            if kind == 'urgent':
                assert sender.send(b'!', socket.MSG_OOB) == 1
            got, _ = read_frame(reader, receiver, uid)
            if got == 0:
                got, _ = read_frame(reader, receiver, uid)
            assert got == -1, kind
            if kind == 'rights':
                assert len(os.listdir('/proc/self/fd')) == before
            assert read_frame(reader, receiver, uid)[0] == -1
            results.append('frame:'+kind)
        finally:
            lib.w2_reader_free(reader)
            receiver.close()
            sender.close()


def mixed_credentials():
    assert os.getuid() == 0
    wire = b'\0\0\0\2{}'
    # Every byte position, including both ends of the header/body boundary.
    for bad_at in range(-1, len(wire)):
        receiver, sender = stream()
        reader = lib.w2_reader_new()
        try:
            for position, byte in enumerate(wire):
                child = os.fork()
                if child == 0:
                    receiver.close()
                    uid = 70001 if position == bad_at else 70000
                    os.setgroups([])
                    os.setresgid(uid, uid, uid)
                    os.setresuid(uid, uid, uid)
                    os._exit(0 if sender.send(bytes([byte])) == 1 else 1)
                pid, status = os.waitpid(child, 0)
                assert pid == child and status == 0
                got, _ = read_frame(reader, receiver, 70000)
                expected = -1 if 0 <= bad_at <= position else int(position == len(wire)-1)
                assert got == expected, (bad_at, position, got, expected)
            results.append({'kernel_credentials_bad_byte': bad_at,
                            'outcome': 'accepted same-uid children' if bad_at == -1 else 'permanently rejected'})
        finally:
            lib.w2_reader_free(reader)
            receiver.close()
            sender.close()


def storage_records():
    epoch = 'a'*32
    base = dict(v=1, type='runtime_status', seq='1', engine_epoch=epoch, execution_id=epoch+':1',
                lease_id=epoch+':1:u', copy_id=epoch+':1:r', state='released', basis='not_materialized',
                reason='none', attempt=0, os_errno=None)
    for fields, valid in [({}, True), ({'attempt': 1}, False), ({'basis': 'tree_removed', 'attempt': 1}, True),
            ({'basis': 'tree_removed'}, False), ({'state': 'retained', 'basis': 'unconfirmed', 'reason': 'delete_failed', 'attempt': 3}, True),
            ({'state': 'retained', 'basis': 'unconfirmed'}, False), ({'attempt': 4}, False),
            ({'copy_id': epoch+':2:r'}, False), ({'os_errno': 5}, False), ({'extra': 0}, False)]:
        with _resources() as owned:
            left, right = socket.socketpair(type=socket.SOCK_SEQPACKET)
            owned.extend([left, right])
            right.send(json.dumps(dict(base, **fields)).encode())
            buf, fd = C.create_string_buffer(16384), C.c_int(-1)
            got = lib.w2_recv_control(left.fileno(), buf, len(buf), C.byref(fd))
            assert (got > 0) == valid and fd.value == -1, (fields, got)
    lib.w2_job_parse.argtypes = [C.c_char_p, C.c_size_t]
    lib.w2_job_parse.restype = C.c_void_p
    lib.json_delete.argtypes = [C.c_void_p]
    done = dict(v=1, type='job_done', seq='1', job_id='1', copy_id=epoch+':1:r', result='ready',
                root_dev='1', root_ino='2', root_removed=False, reason='none', os_errno=None)
    for fields, valid in [({}, True), ({'root_removed': True}, False), ({'result': 'removed', 'root_removed': True}, True),
            ({'result': 'removed'}, False), ({'result': 'failed'}, False),
            ({'result': 'failed', 'reason': 'delete_failed', 'os_errno': 5, 'root_removed': True}, True),
            ({'result': 'not_materialized', 'root_dev': None, 'root_ino': None, 'reason': 'create_failed', 'os_errno': 28}, True),
            ({'root_ino': '0'}, False), ({'extra': 1}, False), ({'root_removed': 1}, False)]:
        wire = json.dumps(dict(done, **fields)).encode()
        got = lib.w2_job_parse(wire, len(wire))
        assert bool(got) == valid, fields
        if got:
            lib.json_delete(got)
    results.append('storage:public-status-and-private-result-causal-schema')


if len(sys.argv) == 3 and sys.argv[2] == '--mixed':
    mixed_credentials()
else:
    assert os.getuid() != 0
    controls()
    controls3()
    storage_records()
    data_frames()
print(json.dumps({'checks': results, 'result': 'passed'}))
