"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
import hashlib
from pathlib import Path
import secrets
import time
from cell.nb_contract import decode
from cell.nb_io import Files, PublicationPending
from common import json_bytes
from decoys import log_window
from listener_witness import pin_row, inspect_listener
from run_transport import collect, directory_owner, publish, workspace_entry
from upstream import wait_for


class SupportRows:
    """Two live rows, host-owned command sequence, bounded immutable receipts.
    Victim follows the arm until the approved NB-23 signal-target switch;
    auxiliary ALWAYS runs inside the real engine.
    Row readiness, pidfd identity and socket-table ownership are separate gates.
    """
    def __init__(self, rt, config):
        if config not in ('engine', 'undefended'):
            raise ValueError('unknown support arm')
        self.rt, self.config, self.items = rt, config, {}
        self.current, self.question_pending = None, None
        self.closed, self.netfd = False, None
        self.signal_victim = False
        try:
            self._start('victim', 'work1', config, 'SUP-VICTIM')
            self._start('auxiliary', 'work2', 'engine', 'SUP-AUXILIARY')
        except BaseException:
            # Runtime owns rows from BEFORE start; global cleanup will stop even
            # partial starts. Only release host descriptors here, do not claim done.
            self.dispose()
            raise

    def _start(self, role, workspace, config, module, *, suffix=""):
        rt = self.rt
        root = Path(workspace_entry(rt, workspace, config)['mount'])
        if not any(p == root or p in root.parents for p in rt.resources.roots):
            raise ValueError('support workspace not owned')
        name = f'nb-decoy-{self.config}-{role}' + suffix
        parent = Files(root)
        try:
            parent.absent(name)
            owner = directory_owner(parent.fd)  # v4 workspace owner (engine arm) or host user (undefended)
            os.mkdir(name, 0o700, dir_fd=parent.fd)
            os.chown(name, *owner, dir_fd=parent.fd, follow_symlinks=False)
        finally:
            parent.close()
        item = {'root': root / name, 'files': Files(root / name), 'sequence': 0,
                'nonce': secrets.token_hex(24), 'row': None, 'ref': None, 'records': []}
        self.items[role] = item
        value = {'kind': 'path', 'scope': 'work', 'path': name}
        rt.targets.add_path(role, value, workspace=workspace, owner='support', config=config)
        # Same logical victim address in both arms; old support is closed first.
        stable = hashlib.sha256((rt.bundle['run'] + ':' + role).encode()).hexdigest()[:24]
        params = {'role': role, 'nonce': item['nonce'], 'name': 'nb-decoy-' + stable}
        row = rt.start_helper(workspace, config, module, {role: value}, params)
        item['row'] = row
        if row.execution:
            rt.deployment.connector(row.execution)
            rt.deployment.file_worker(row.execution)  # v4: the row's file worker, an NB-23 signal target
        item['ref'] = pin_row(rt, row, self.config + '-' + role + suffix)
        ready = self._wait(role, 'ready.json')
        if ready.get('role') != role:
            raise ValueError('support readiness role mismatch')
        if role == 'victim':
            if ready.get('name') != params['name']:
                raise ValueError('victim endpoint readiness mismatch')
            target = {'kind': 'abstract', 'name': params['name']}
            item['target'] = target
            rt.targets.add_listener('victim-listener-' + self.config, target, item['ref'],
                                    lambda: inspect_listener(item['ref'], target))
            pid = item['ref'].read()['pid']
            self.netfd = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY | os.O_CLOEXEC)
            item['ref'].read()

    def _stop(self, role):
        """Verify the old tree and archive its receipt BEFORE replacing a request."""
        item = self.items[role]
        self._send(role, 'stop')
        row = item['row']
        wait_for(self.rt.command, row.poll, timeout=10)
        tree = row.finish()
        observation, _ = collect(workspace_entry(self.rt, row.workspace, row.config)['mount'],
                                 row.request, self.rt.evidence)
        if tree.get('tree_empty') is not True or tree.get('runner_ok') is False or observation.get('control_ok') is not True:
            raise ValueError('support runner failed')
        return tree

    def ensure_signal_victim(self):
        """NB-23 only: retire host victim, then own a real work1 connector.
        The attacker remains undefended. NB-25 has already run; never move its
        listener into a cell during a connection attempt. No new budget or uid
        reuse: setup consumes the current attempt; helper dies at batch teardown.
        Partial starts remain in Runtime.rows for the normal cleanup path.
        """
        if self.config != 'undefended' or self.closed or self.current is not None or self.question_pending is not None:
            raise ValueError('signal peer requires idle, open undefended support')
        item = self.items['victim']; row = item['row']
        if self.signal_victim:
            if row.closed or row.config != 'engine' or row.workspace != 'work1' or not row.execution:
                raise ValueError('signal victim role/lifecycle mismatch')
            self.rt.deployment.refs['connector:' + row.execution].read()
            return
        if row.closed or row.config != 'undefended' or row.workspace != 'work1' or row.execution:
            raise ValueError('old host victim role/lifecycle mismatch')
        before = item['ref'].read()
        tree = self._stop('victim')
        self.rt.targets.release('victim-listener-' + self.config, item['target'])
        self.rt.targets.release('victim', {'kind':'path', 'scope':'work', 'path':item['root'].name}, owner='support')
        if self.netfd is not None:
            os.close(self.netfd); self.netfd = None
        item['files'].close(); item['ref'].close()
        self._start('victim', 'work1', 'engine', 'SUP-VICTIM', suffix='-signal')
        peer = self.items['victim']['row']
        self.rt.evidence.raw(json_bytes({'transition':'NB-23-victim-connector',
            'from':before, 'old_tree':tree, 'execution':peer.execution,
            'connector':self.rt.deployment.refs['connector:' + peer.execution].read()}),
            'support-transition.json')
        self.signal_victim = True

    def _read(self, role, name):
        item = self.items[role]
        item['ref'].read()
        raw = item['files'].read(name, 65536)
        item['records'].append(self.rt.evidence.raw(raw, 'support.json'))
        data = decode(raw)
        if not isinstance(data, dict) or data.get('nonce') != item['nonce']:
            raise ValueError('support receipt nonce mismatch')
        return data

    def _wait(self, role, name, timeout=10):
        def check():
            try:
                return self._read(role, name)
            except (FileNotFoundError, PublicationPending):
                return None
        return wait_for(self.rt.command, check, timeout=timeout)

    def _send(self, role, op, **values):
        item = self.items[role]
        item['ref'].read()
        seq = item['sequence']
        if seq >= 128:
            raise ValueError('support mailbox command limit')
        publish(item['files'], f'command-{seq:04d}.json', json_bytes(
            {'nonce': item['nonce'], 'seq': seq, 'op': op, **values}))
        item['sequence'] += 1
        return seq

    def begin_window(self, attempt):
        if self.current is not None or self.closed or self.signal_victim:
            raise ValueError('victim window already open/closed or changed to signal peer')
        victim = self.items['victim']
        inspect_listener(victim['ref'], victim['target'])
        secret = secrets.token_hex(24)
        seq = self._send('victim', 'begin', attempt=attempt, secret=secret)
        # Install state before waiting: failure cannot silently abandon a window.
        self.current = {'attempt': attempt, 'secret': secret, 'sequence': seq, 'cursor': None}
        ack = self._wait('victim', f'window-{seq:04d}.json')
        if ack.get('attempt') != attempt or type(ack.get('cursor')) is not int or ack['cursor'] < 0:
            raise ValueError('victim window acknowledgement mismatch')
        self.current['cursor'] = ack['cursor']
        return dict(self.current, secret='<controller-only>')

    def end_window(self, *, tree_empty):
        if tree_empty is not True or self.current is None or self.current['cursor'] is None:
            raise ValueError('victim end requires verified attack tree exit and window')
        rt, current, victim = self.rt, self.current, self.items['victim']
        if rt.command.deadline.left(1) < 1:
            raise TimeoutError('insufficient budget for full listener effect window')
        end = time.monotonic() + 1
        while time.monotonic() < end:
            rt.pump()
        inspect_listener(victim['ref'], victim['target'])
        if self.netfd is None:
            raise ValueError('victim namespace handle missing')
        command = ['/usr/bin/nsenter', f'--net=/proc/{os.getpid()}/fd/{self.netfd}', '--',
                   '/usr/bin/python3', '-I', '-B', str(Path(__file__).with_name('listener_client.py')),
                   victim['target']['name']]
        result = rt.command(command, timeout=5, env={'NB_END_SECRET': current['secret']})
        if decode(result['stdout']) != {'echo': True}:
            raise ValueError('victim end roundtrip missing')
        entries = []
        current['entries'] = entries  # keep verified partial records if closure fails
        for seq in range(current['cursor'], current['cursor'] + 64):
            item = self._wait('victim', f'event-{seq:06d}.json', timeout=3)
            entries.append(item)
            if item.get('seq') != seq or item.get('attempt') != current['attempt']:
                raise ValueError('victim journal sequence/attempt mismatch')
            if item.get('kind') == 'end':
                requests = log_window(entries, current['cursor'], current['secret'], current['attempt'])
                window = {'cursor': current['cursor'], 'end': item, 'requests': requests,
                          'listener': inspect_listener(victim['ref'], victim['target'])}
                self.current = None
                return window
        raise ValueError('victim end marker absent')

    def sample_window(self):
        """Failure evidence only: bounded reads do not require a still-live row.
        Never closes a window or treats a missing marker as a successful block.
        """
        result = {'entries': [], 'raw': []}
        current, victim = self.current, self.items['victim']
        if current is None or type(current.get('cursor')) is not int:
            return result
        for seq in range(current['cursor'], current['cursor'] + 64):
            try:
                raw = victim['files'].read(f'event-{seq:06d}.json', 65536)
            except FileNotFoundError:
                break
            except (ValueError, OSError) as exc:
                result['error'] = str(exc); break
            result['raw'].append(self.rt.evidence.raw(raw, 'support-partial.json'))
            try:
                item = decode(raw)
                if not isinstance(item, dict) or item.get('nonce') != victim['nonce']:
                    raise ValueError('partial support receipt nonce mismatch')
                result['entries'].append(item)
                if item.get('seq') != seq or item.get('attempt') != current['attempt']:
                    raise ValueError('partial support receipt sequence/attempt mismatch')
                if item.get('kind') == 'end':
                    break
            except (ValueError, TypeError) as exc:
                result['error'] = str(exc); break
        return result

    def begin_question(self, path):
        if self.question_pending is not None:
            raise ValueError('auxiliary question already active')
        admin, item = self.rt.deployment.admin, self.items['auxiliary']
        if admin.watcher is None:
            admin.watch()
        seq = self._send('auxiliary', 'question', path=path)
        self.question_pending = {'sequence': seq, 'path': path}
        sent = self._wait('auxiliary', f'sent-{seq:04d}.json')
        if sent.get('path') != path:
            raise ValueError('auxiliary sent path mismatch')
        question = admin.question(execution=item['row'].execution, path=path)
        self.question_pending['question'] = question
        return question

    def question_result(self):
        pending = self.question_pending
        if pending is None or 'question' not in pending:
            raise ValueError('no externally verified pending question')
        result = self._wait('auxiliary', f'result-{pending["sequence"]:04d}.json', timeout=10)
        if result.get('path') != pending['path'] or result.get('complete') is not True:
            raise ValueError('auxiliary request did not reach final result')
        self.question_pending = None
        return result

    def close(self):
        if self.closed:
            return
        if self.current is not None or self.question_pending is not None:
            raise ValueError('support cannot close an unfinished window/question')
        errors = []
        for role, item in reversed(list(self.items.items())):
            try:
                self._stop(role)
            except Exception as exc:
                errors.append(role + ': ' + str(exc))
        self.dispose()
        if not errors:
            for role, item in self.items.items():
                self.rt.targets.release(role, {'kind': 'path', 'scope': 'work', 'path': item['root'].name}, owner='support')
            self.rt.targets.release('victim-listener-' + self.config, self.items['victim']['target'])
        if errors:
            raise RuntimeError('support close failed: ' + '; '.join(errors))
        self.closed = True

    def dispose(self):
        """Release pinned host descriptors after shutdown, including partial starts.
        Never equate this with the orderly stop/observation gate in close().
        """
        if self.netfd is not None:
            os.close(self.netfd); self.netfd = None
        for item in self.items.values():
            item['files'].close()
