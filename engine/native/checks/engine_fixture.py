"""Trusted unprivileged test peer for the production spawner.

Uses the compiled C control/credential/frame receiver. It is not the engine's
business schema, grant evaluator or a replacement for real-runtime validation.
"""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import socket
import struct
import subprocess
import sys
import time


def main():
    root, catalog_name, mode, library, argument = sys.argv[1:]
    root = Path(root)
    lib = C.CDLL(library, use_errno=True)
    lib.w2_recv_control.argtypes = [C.c_int, C.c_void_p, C.c_size_t, C.POINTER(C.c_int)]
    lib.w2_recv_control.restype = C.c_ssize_t
    lib.w2_recv_control3.argtypes = [C.c_int, C.c_void_p, C.c_size_t, C.POINTER(C.c_int * 3)]
    lib.w2_recv_control3.restype = C.c_ssize_t
    lib.w2_send_fixed.argtypes = [C.c_int, C.c_void_p, C.c_size_t, C.c_uint64]
    lib.w2_reader_new.restype = C.c_void_p
    lib.w2_reader_free.argtypes = [C.c_void_p]
    lib.w2_frame_receive.argtypes = [C.c_void_p, C.c_int, C.c_uint, C.c_uint,
                                   C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
    lib.w2_recv_credential.argtypes = [C.c_int, C.c_void_p, C.c_size_t, C.c_uint, C.c_int, C.c_uint]
    lib.w2_recv_credential.restype = C.c_ssize_t
    control = socket.socket(fileno=3)
    deadline = time.monotonic() + 24
    epoch = secrets.token_hex(16)
    seq = 0
    incoming = 1
    events = []
    channels = {}
    runtime_views = {}
    runtime_status = {}
    judgments, connector_posture, started_connectors, exited_connectors = {}, {}, {}, {}
    file_judgments, worker_posture_of, started_workers, exited_workers = {}, {}, {}, {}

    def connector_status(pid, uid='70999'):
        """S-11 evidence: the connector runs as the dedicated uid with no capability, no_new_privs, and holds only
        stdio plus fds 3 and 4 (the proxy listener and its judgment end); H-14 the same for the file worker, as its
        own uid (fd 3 the file-port listener, fd 4 its file judgment end)."""
        status = {k: v.strip() for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                  if ':' in line for k, v in [line.split(':', 1)]}
        assert status['Uid'].split() == [uid] * 4 and status['Gid'].split() == [uid] * 4, status
        assert all(int(status[k], 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')), status
        assert status['NoNewPrivs'] == '1', status
        try:   # the fd table of another uid's process is readable only by a privileged observer; the unprivileged
               # engine relies on the connector stub's own check instead (it exits 5 on any extra descriptor)
            fd_targets = {int(p.name): os.readlink(p) for p in Path(f'/proc/{pid}/fd').iterdir()}
        except PermissionError:
            fd_targets = None
        if fd_targets is not None:
            assert sorted(fd_targets) == [0, 1, 2, 3, 4], fd_targets
            assert all(fd_targets[i] == '/dev/null' for i in range(3)) and fd_targets[3].startswith('socket:') and fd_targets[4].startswith('socket:')
        return {'uid': status['Uid'], 'caps': status['CapEff'], 'fds': fd_targets}
    # These exist only after the trusted launcher pre-forked the spawner.
    secret = os.memfd_create('engine-secret-after-prefork')
    os.write(secret, b'ENGINE_PRIVATE_SENTINEL')
    sibling = socket.socketpair()
    catalog_bytes = (root / catalog_name).read_bytes()
    catalog = json.loads(catalog_bytes)
    plans = [(json.loads((root / e['artifact_ref']).read_bytes()), e['artifact_digest'])
             for e in catalog['plans']]
    posture = {k: v.strip() for line in Path('/proc/self/status').read_text().splitlines()
               if ':' in line for k, v in [line.split(':', 1)]
               if k in {'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp'}}
    if mode == 'workspace-lifecycle':
        assert os.getuid() == 0, 'dedicated root observer, not the product engine'
        events.append({'observer_role': 'privileged workspace fd/identity test peer; not unprivileged engine evidence'})
    else:
        assert os.getuid() == 1000 and all(int(posture[k], 16) == 0 for k in
                  ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')), posture
        assert posture['NoNewPrivs'] == '1'
    spawner_pid = int(Path(f'/proc/self/task/{os.getpid()}/children').read_text().strip())
    spawner_posture = {k: v.strip() for line in Path(f'/proc/{spawner_pid}/status').read_text().splitlines()
                       if ':' in line for k, v in [line.split(':', 1)]
                       if k in {'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp'}}
    expected_caps = sum(1 << i for i in (5, 6, 7, 8, 12, 21)) | (1 << 0)   # v2: CAP_CHOWN kept for the row sockets (S-08)
    assert all(int(spawner_posture[k], 16) == expected_caps for k in ('CapPrm', 'CapEff', 'CapBnd'))
    assert all(int(spawner_posture[k], 16) == 0 for k in ('CapInh', 'CapAmb'))

    def send(kind, index=None, **fields):
        nonlocal seq
        seq += 1
        body = dict(v=1, type=kind, engine_epoch=epoch, seq=str(seq))
        if index is not None:
            body.update(execution_id=f'{epoch}:{index}', lease_id=f'{epoch}:{index}:u')
        body.update(fields)
        wire = json.dumps(body, separators=(',', ':')).encode()
        while True:
            try:
                assert control.send(wire) == len(wire)
                break
            except BlockingIOError:
                assert time.monotonic() < deadline
                select.select([], [control], [], .1)
            except BrokenPipeError:
                assert mode == 'worker-init'
                events.append({'worker_failure_closed_before_init_send': True})
                break
        events.append({'send': body})
        return wire

    def receive(include_runtime=False):
        nonlocal incoming
        while True:
            assert time.monotonic() < deadline, ('control deadline', events)
            buf = C.create_string_buffer(16384)
            fds = (C.c_int * 3)(-1, -1, -1)
            n = lib.w2_recv_control3(control.fileno(), buf, len(buf), C.byref(fds))
            if n == -2:
                select.select([control], [], [], .05)
                continue
            assert n > 0, ('control failure', n, C.get_errno(), events)
            body = json.loads(buf.raw[:n])
            assert body['seq'] == str(incoming) and body['engine_epoch'] == epoch
            incoming += 1
            fd = C.c_int(fds[0])
            if fd.value >= 0:
                index = int(body['execution_id'].split(':')[-1])
                assert index not in channels and fds[1] >= 0 and fds[2] >= 0 and body['type'] == 'spawn_prepared'
                channels[index] = socket.socket(fileno=fd.value)
                judgments[index] = socket.socket(fileno=fds[1])
                file_judgments[index] = socket.socket(fileno=fds[2])      # validation.md H-06: the third fd
                assert judgments[index].getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
                assert file_judgments[index].getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
                connector_pid, worker_pid = body['connector_pid'], body['worker_pid']
                assert connector_pid != worker_pid, body
                connector_posture[index] = connector_status(connector_pid)
                worker_posture_of[index] = connector_status(worker_pid, '70996')
                started_connectors[body['execution_id']] = connector_pid
                started_workers[body['execution_id']] = worker_pid
                buffers = {str(option): channels[index].getsockopt(socket.SOL_SOCKET, option)
                           for option in (socket.SO_SNDBUF, socket.SO_RCVBUF)}
                assert all(65536 <= value <= 131072 for value in buffers.values())
                events.append({'kernel_buffers': buffers, 'execution': index})
            events.append({'receive': body, 'received_fd': fd.value, 'received_fd2': fds[1], 'received_fd3': fds[2]})
            if body['type'] == 'execution_empty':     # a started connector's and worker's exits come first (K-22, H-17)
                assert body['execution_id'] not in started_connectors or body['execution_id'] in exited_connectors, \
                    ('execution_empty before its connector_exited', body, events)
                assert body['execution_id'] not in started_workers or body['execution_id'] in exited_workers, \
                    ('execution_empty before its worker_exited', body, events)
            if body['type'] in ('connector_exited', 'worker_exited'):
                (exited_connectors if body['type'] == 'connector_exited' else exited_workers)[body['execution_id']] = body
                if not include_runtime:
                    continue
            if body['type'] == 'runtime_status':
                identity = body['execution_id']
                assert body['copy_id'] == identity+':r' and identity in runtime_views
                assert runtime_views[identity] != 'released' or body['state'] == 'released'
                runtime_views[identity] = body['state']
                runtime_status[identity] = body
                if not include_runtime:
                    continue
            return body

    def runtime_notice():
        """The next runtime_status or other notice, past any connector_exited: a row's connector may exit before or
        after its runtime notices arrive (the spawner's timing, not the protocol's); receive() has recorded it."""
        while (body := receive(True))['type'] in ('connector_exited', 'worker_exited'):
            pass
        return body

    def spawn(index, plan_index=0, budget=7000, **overrides):
        runtime_views[f'{epoch}:{index}'] = 'pending'
        plan, digest = plans[plan_index]
        workspace = next(w for w in catalog['workspaces'] if w['workspace_id'] == plan['workspace_id'])
        # v2: the engine allocates the uid from the reserved range; this fixture takes 70000 + workspace index so
        # that the report checks keyed by workspace keep their expected uid.
        uid = 70000 + int(workspace['workspace_id'][-1])
        fields = dict(uid=uid, gid=uid,
                      launch_plan_id=plan['launch_plan_id'], launch_plan_digest=digest,
                      startup_deadline_ns=str(time.monotonic_ns() + budget * 1000000))
        fields.update(overrides)
        return send('spawn', index, **fields)

    def commit(index, wrong=False):
        data = struct.pack('>4sHHII', b'W2BP', 1, 2, 0, 0)
        if wrong:
            data = b'bad!' + data[4:]
        # Exercise fragmented COMMIT through the actual child receiver.
        for part in data:
            byte = bytes([part])
            assert lib.w2_send_fixed(channels[index].fileno(), byte, 1,
                                     time.monotonic_ns() + 2000000000) == 0
        events.append({'commit': index, 'valid': not wrong})

    def first_frame(index, uid):
        """The fixture's first frame after exec, read through the C reader under the row's uid (v2 has no hello; the
        frame is only a carrier for the identity check)."""
        reader = lib.w2_reader_new()
        assert reader
        try:
            while True:
                assert time.monotonic() < deadline, ('first frame deadline', index, events)
                buf = C.create_string_buffer(65536)
                size = C.c_size_t()
                n = lib.w2_frame_receive(reader, channels[index].fileno(), uid, 65534,
                                         buf, len(buf), C.byref(size))
                assert n >= 0, ('frame failure', n, C.get_errno(), events)
                if n:
                    body = json.loads(buf.raw[:size.value])
                    assert body == dict(v=2, type='request', id='1')
                    assert channels[index].getsockname() == '' and channels[index].getpeername() == ''
                    events.append({'fixture_first_frame': index, 'body': body, 'unnamed': True})
                    return
                select.select([channels[index]], [], [], .01)
        finally:
            lib.w2_reader_free(reader)

    def stop(index):
        send('stop', index, reason='normal')

    try:
        send('control_init', catalog_digest='sha256:' + hashlib.sha256(catalog_bytes).hexdigest(), protocol='w2-local/2',
             runtime_storage_protocol='w2-runtime-store/1', storage_profile_digest=catalog['storage_profile']['artifact_digest'])
        if mode == 'worker-init':
            while True:
                ready, _, _ = select.select([control], [], [], .1)
                assert time.monotonic() < deadline
                if ready:
                    assert control.recv(16384) == b''
                    break
            events.append({'worker_init_failed_without_ready_or_clone': True})
        else:
            assert receive()['type'] == 'control_ready'
            workers = Path(f'/proc/{spawner_pid}/task/{spawner_pid}/children').read_text().split()
            assert len(workers) == 1, workers
            worker_posture = {k: v.strip() for line in Path(f'/proc/{workers[0]}/status').read_text().splitlines()
                              if ':' in line for k, v in [line.split(':', 1)]
                              if k in {'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs'}}
            assert worker_posture['Uid'].split() == ['0']*4 and worker_posture['Gid'].split() == ['0']*4
            assert all(int(worker_posture[k], 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
            assert worker_posture['NoNewPrivs'] == '1'
            events.append({'worker_posture': worker_posture, 'worker_pid': int(workers[0])})
        if mode == 'worker-init':
            pass
        elif mode == 'workspace-lifecycle':
            source = Path(argument)
            workspace_devices = {os.stat(root / w['source_ref']).st_dev for w in catalog['workspaces']}
            workspace_devices.add(os.stat(source / 'counterfeit').st_dev)

            def workspace_references(phase):
                observations = []
                for role, pid in [('spawner', spawner_pid), ('worker', int(workers[0]))]:
                    refs = []
                    for entry in Path(f'/proc/{pid}/fd').iterdir():
                        try:
                            st = entry.stat()
                            target = os.readlink(entry)
                        except FileNotFoundError:
                            continue  # fd was closed while taking the snapshot
                        refs.append({'fd': int(entry.name), 'target': target, 'device': st.st_dev, 'inode': st.st_ino})
                    assert all(ref['device'] not in workspace_devices for ref in refs), (phase, role, refs)
                    observations.append({'role': role, 'pid': pid, 'fds': refs})
                events.append({'workspace_reference_observation': phase, 'processes': observations})

            def released(index):
                while runtime_views[f'{epoch}:{index}'] != 'released':
                    receive(include_runtime=True)

            def normal_execution(index):
                spawn(index)
                assert receive()['type'] == 'spawn_prepared'
                workspace_references(f'prepared-{index}')
                commit(index)
                first_frame(index, 70000)
                channels[index].send(b'F')
                assert receive()['basis'] == 'pid1_reaped'
                released(index)
                channels[index].close()
                workspace_references(f'finished-{index}')

            workspace_references('control-ready')
            normal_execution(1)
            original = os.stat(root / 'work0')
            counterfeit = os.stat(source / 'counterfeit')
            assert original.st_uid == counterfeit.st_uid and original.st_gid == counterfeit.st_gid
            assert original.st_ino == counterfeit.st_ino and original.st_dev != counterfeit.st_dev
            subprocess.run(['/usr/bin/mount', '--bind', str(source / 'counterfeit'), str(root / 'work0')], check=True)
            try:
                # Same name/owner/mode/inode number, different Btrfs source identity.
                spawn(2)
                failure = receive()
                assert failure['type'] == 'spawn_failed' and failure['stage'] == 'work_mount', failure
                assert receive()['basis'] == 'pid1_reaped'
                released(2)
                workspace_references('failed-replaced-source')
                assert not (root / 'work0/tree/report.txt').exists(), 'replacement reached agent exec'
                events.append({'replacement_rejected': failure, 'original_device': original.st_dev,
                               'counterfeit_device': counterfeit.st_dev})
            finally:
                subprocess.run(['/usr/bin/umount', str(root / 'work0')], check=True)
            assert os.stat(root / 'work0').st_dev == original.st_dev
            normal_execution(3)
            assert 'persistent_existed=1' in (root / 'work0/tree/report.txt').read_text()
        elif mode == 'budget':
            spawn(1, plan_index=0)
            spawn(2, plan_index=1)
            assert receive()['type'] == 'spawn_prepared'
            assert receive()['type'] == 'spawn_prepared'
            commit(1)
            commit(2)
            first_frame(1, 70000)
            first_frame(2, 70001)
            spawn(3, plan_index=2)
            assert receive()['error_code'] == 'resource_exhausted'
            assert receive()['basis'] == 'never_created'
            channels[1].send(b'F')
            assert receive()['basis'] == 'pid1_reaped'
            while runtime_views[f'{epoch}:1'] != 'released':
                assert runtime_notice()['type'] == 'runtime_status'
            spawn(4, plan_index=2)
            assert receive()['type'] == 'spawn_prepared'
            commit(4)
            first_frame(4, 70002)
            channels[2].send(b'F')
            channels[4].send(b'F')
            assert receive()['basis'] == 'pid1_reaped'
            assert receive()['basis'] == 'pid1_reaped'
            events.append({'two_copy_budget_rejects_third_then_released_charge_reused': True})
        elif mode == 'stop-create':
            spawn(1)
            time.sleep(.05)
            stop(1)
            notice = receive()
            assert notice['type'] == 'execution_empty' and notice['basis'] == 'never_created'
            events.append({'stop_before_late_ready_forbids_clone': True})
        elif mode == 'storage-retry' or mode == 'storage-retained':
            spawn(1)
            assert receive()['type'] == 'spawn_prepared'
            commit(1)
            first_frame(1, 70000)
            channels[1].send(b'F')
            assert receive()['basis'] == 'pid1_reaped'
            notice = runtime_notice()
            assert notice['type'] == 'runtime_status' and notice['state'] == 'retained' and notice['attempt'] == 1
            spawn(2, plan_index=1)
            assert receive()['error_code'] == 'resource_exhausted'
            assert receive()['basis'] == 'never_created'
            while runtime_views[f'{epoch}:2'] != 'released':
                assert runtime_notice()['type'] == 'runtime_status'
            if mode == 'storage-retry':
                while runtime_views[f'{epoch}:1'] != 'released':
                    notice = runtime_notice()
                    assert notice['type'] == 'runtime_status'
                original_status = runtime_status[f'{epoch}:1']
                assert original_status['attempt'] == 2 and original_status['basis'] == 'tree_removed'
                spawn(3, plan_index=1)
                assert receive()['type'] == 'spawn_prepared'
                commit(3)
                first_frame(3, 70001)
                channels[3].send(b'F')
                assert receive()['basis'] == 'pid1_reaped'
                events.append({'retained_blocks_admission_then_retry_reopens': True})
            else:
                while runtime_status[f'{epoch}:1']['attempt'] < 3:
                    notice = runtime_notice()
                    assert notice['type'] == 'runtime_status'
                assert runtime_views[f'{epoch}:1'] == 'retained'
                events.append({'third_attempt_registered_retained': True})
                control.close()
        elif mode == 'invalid-control':
            body = dict(v=1, type='spawn', engine_epoch=epoch, seq='9', execution_id=f'{epoch}:1',
                        lease_id=f'{epoch}:1:u', uid=70000, gid=70000,
                        launch_plan_id=plans[0][0]['launch_plan_id'], launch_plan_digest=plans[0][1],
                        startup_deadline_ns=str(time.monotonic_ns()+2000000000))
            control.send(json.dumps(body).encode())
            while True:
                ready, _, _ = select.select([control], [], [], .1)
                assert time.monotonic() < deadline
                if ready:
                    assert control.recv(16384) == b''
                    break
            events.append({'invalid_sequence_closed': True})
        elif mode == 'stall-first':
            spawn(1, plan_index=1)
            assert receive()['type'] == 'spawn_prepared'
            commit(1)
            first_frame(1, 70001)
            spawn(2, plan_index=0, budget=1100)
            time.sleep(.05)
            started = time.monotonic()
            stop(1)
            first = receive()
            assert first['type'] == 'execution_empty' and first['execution_id'].endswith(':1')
            assert first['basis'] == 'pid1_reaped' and time.monotonic()-started < .8
            events.append({'active_execution_stopped_during_other_create': True})
            empty = False
            failed = False
            while not (failed and empty):
                notice = receive()
                assert notice['execution_id'].endswith(':2')
                if notice['type'] == 'spawn_failed':
                    failed = True
                else:
                    assert notice['type'] == 'execution_empty' and notice['basis'] == 'never_created'
                    empty = True
        elif mode == 'worker-loss':
            spawn(1)
            while True:
                assert time.monotonic() < deadline
                buf, fd = C.create_string_buffer(16384), C.c_int(-1)
                n = lib.w2_recv_control(control.fileno(), buf, len(buf), C.byref(fd))
                assert fd.value == -1, 'worker loss must not hand off an agent'
                if n == -2:
                    select.select([control], [], [], .05)
                    continue
                assert n >= 0
                if n == 0:
                    break
                body = json.loads(buf.raw[:n])
                assert body['type'] != 'spawn_prepared'
                events.append({'receive': body})
            events.append({'worker_loss_closes_control_no_empty_inferred': True})
            control.close()
        elif mode in {'normal', 'parallel', 'stop', 'control-loss', 'repeated', 'slow-eof',
                      'kill-error', 'reap-error', 'kill-no-fact', 'reap-parallel',
                      'reap-control-loss', 'cleanup-progress'}:
            indices = [1, 2] if mode in {'parallel', 'reap-parallel', 'cleanup-progress'} else [1]
            for index in indices:
                spawn(index, next(i for i, (p, _) in enumerate(plans) if p['launch_plan_id'] == 'linger-0')
                      if mode in {'stop', 'control-loss', 'kill-error', 'reap-error', 'kill-no-fact'} else index-1)
            for _ in indices:
                assert receive()['type'] == 'spawn_prepared'
            for index in indices:
                commit(index)
            for index in indices:
                first_frame(index, 70000 + (index-1))
            if mode == 'slow-eof':
                channels[1].send(b'F')
                assert receive()['basis'] == 'pid1_reaped'
                events.append({'eof_before_six_second_delete_completion_ns': time.monotonic_ns()})
                control.close()
            elif mode in {'control-loss', 'reap-control-loss'}:
                control.close()
            elif mode == 'cleanup-progress':
                channels[1].send(b'F')
                assert receive()['basis'] == 'pid1_reaped'
                started = time.monotonic()
                stop(2)
                assert receive()['basis'] == 'pid1_reaped'
                assert time.monotonic()-started < 1, 'cleanup blocked another stop/reap'
                events.append({'second_stopped_while_cleanup_stalled': True})
                control.close()
            elif mode in {'kill-error', 'reap-error', 'kill-no-fact', 'reap-parallel'}:
                stop(2 if mode == 'reap-parallel' else 1)
                if mode in {'reap-error', 'reap-parallel'}:
                    # A failed wait invalidates the control epoch immediately.
                    # Diagnostics are best effort; EOF must never become empty.
                    while True:
                        ready, _, _ = select.select([control], [], [], .1)
                        assert time.monotonic() < deadline
                        if ready:
                            assert control.recv(16384) == b''
                            break
                    events.append({'reap_failure_closed_control': True})
                elif mode == 'kill-error':
                    failure = receive()
                    assert failure['type'] == 'spawn_failed' and failure['stage'] == 'reap'
                else:
                    # v2: stop kills the row's connector and file worker, so their exits arrive first; after them,
                    # nothing (H-17)
                    exited = sorted(receive(True)['type'] for _ in range(2))
                    assert exited == ['connector_exited', 'worker_exited'], exited
                    readable, _, _ = select.select([control], [], [], .25)
                    assert not readable, 'kill result was mistaken for empty'
                assert not any(e.get('receive', {}).get('type') == 'execution_empty' for e in events)
                events.append({'lease_evidence': 'unconfirmed; test peer quarantines, no reuse'})
                control.close()
            else:
                for index in indices:
                    if mode == 'stop':
                        stop(index)
                        stop(index)
                    else:
                        channels[index].send(b'F')
                empties = [receive() for _ in indices]
                assert all(e['type'] == 'execution_empty' and e['basis'] == 'pid1_reaped' for e in empties)
                if mode != 'stop':
                    assert all(e['exit_code'] == 0 for e in empties)
                else:
                    assert all(e['signal'] == 9 for e in empties)
                if mode == 'repeated':
                    channels[1].close()
                    spawn(3)
                    assert receive()['type'] == 'spawn_prepared'
                    commit(3)
                    first_frame(3, 70000)
                    channels[3].send(b'F')
                    assert receive()['basis'] == 'pid1_reaped'
        elif mode in {'fault', 'wrong-commit', 'no-commit', 'bad-uid', 'bad-gid', 'busy'}:
            spawn(1, budget=1200 if mode == 'no-commit' else 7000,
                  **({'uid': 69999} if mode == 'bad-uid' else {'gid': 70002} if mode == 'bad-gid' else {}))
            first = receive()
            if mode == 'busy':
                assert first['type'] == 'spawn_prepared'
                spawn(2)
                failure, empty = receive(), receive()
                assert failure['error_code'] == 'resource_exhausted' and empty['basis'] == 'never_created'
                stop(1)
                assert receive()['basis'] == 'pid1_reaped'
            elif first['type'] == 'spawn_prepared':
                if mode != 'no-commit' and not (mode == 'fault' and argument == 'commit'):
                    commit(1, mode == 'wrong-commit')
                # A FAIL after handoff belongs on fd3 and must not look like an agent frame.
                data = bytearray()
                while len(data) < 16:
                    buf = C.create_string_buffer(16-len(data))
                    n = lib.w2_recv_credential(channels[1].fileno(), buf, len(buf), 70000, 0, 65534)
                    if n == -2:
                        select.select([channels[1]], [], [], .05)
                        assert time.monotonic() < deadline
                        continue
                    assert n > 0, ('post-handoff FAIL missing', n)
                    data.extend(buf.raw[:n])
                magic, version, kind, stage, number = struct.unpack('>4sHHII', data)
                assert (magic, version, kind) == (b'W2BP', 1, 3)
                events.append({'post_handoff_fail': {'stage': stage, 'errno': number}})
                terminal = receive()
                assert terminal['basis'] == 'pid1_reaped'
            elif first['type'] == 'execution_empty' and mode == 'fault' and argument == 'commit':
                # Injected pre-recv failure may be reaped before the already
                # queued SEALED is handed off. Empty closes admission too.
                assert first['basis'] == 'pid1_reaped' and first['exit_code'] == 125
            else:
                assert first['type'] == 'spawn_failed', first
                terminal = receive()
                assert terminal['type'] == 'execution_empty'
                if mode in {'bad-uid', 'bad-gid'}:
                    assert terminal['basis'] == 'never_created'
                if argument:
                    assert first['stage'] == argument, (first, argument)
        else:
            raise AssertionError('Unknown test case ' + mode)
        if control.fileno() >= 0 and mode not in {'invalid-control', 'kill-error', 'reap-error', 'kill-no-fact',
                'reap-parallel', 'reap-control-loss', 'cleanup-progress', 'worker-loss', 'storage-retained', 'worker-init'}:
            while (any(view != 'released' for view in runtime_views.values())
                   or any(e not in exited_connectors for e in started_connectors)
                   or any(e not in exited_workers for e in started_workers)):
                assert receive(True)['type'] in ('runtime_status', 'connector_exited', 'worker_exited')
            # the stub exits 3-6 on a broken inheritance contract, for the connector and the file worker alike
            for eid, exit_record in [*exited_connectors.items(), *exited_workers.items()]:
                assert (exit_record['exit_code'], exit_record['signal']) in ((None, 9), (0, None)), (eid, exit_record)
            events.append({'connectors': {'started': started_connectors, 'exited': exited_connectors,
                                          'posture': connector_posture},
                           'file_workers': {'started': started_workers, 'exited': exited_workers,
                                            'posture': worker_posture_of}})
        if control.fileno() >= 0:
            control.close()
        # Test engine is also the spawner's direct parent. Actual wait, not EOF,
        # confirms this trusted process has returned from its cleanup loop.
        while True:
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid:
                events.append({'spawner_waitpid': pid, 'status': status})
                assert os.WIFEXITED(status)
                assert os.WEXITSTATUS(status) == (1 if mode in {'kill-error', 'reap-error', 'kill-no-fact',
                    'reap-parallel', 'reap-control-loss', 'cleanup-progress', 'worker-loss', 'storage-retained', 'worker-init'} else 0)
                break
            assert time.monotonic() < deadline
            time.sleep(.02)
        print(json.dumps({'case': mode, 'posture': posture, 'spawner_posture': spawner_posture, 'events': events, 'result': 'passed'}), flush=True)
    except BaseException:
        print(json.dumps({'case': mode, 'posture': posture, 'events': events, 'result': 'failed'}), flush=True)
        raise
    finally:
        for channel in [*channels.values(), *judgments.values(), *file_judgments.values()]:
            channel.close()
        if control.fileno() >= 0:
            control.close()
        os.close(secret)
        for side in sibling:
            side.close()


if __name__ == '__main__':
    main()
