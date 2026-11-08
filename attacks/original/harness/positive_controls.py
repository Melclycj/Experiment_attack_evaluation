"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from pathlib import Path
from case_io import WorkspaceFiles, capture, event, closed_window, positive_fact, record_restore
from common import identity, json_bytes
from decoys import sentinel, snapshot
from listener_witness import pin_child, inspect_listener
from net import UPSTREAM_HOST, UPSTREAM_IP
from safeio import read_beneath
from cell.nb_contract import stem
from upstream import wait_for


class Positive:
    def __init__(self, runtime):
        self.rt, self.files, self.stream = runtime, None, None

    def contract(self):
        return {'attack': self.attack, 'targets': [self.target], 'construction': self.attack,
                'operations': self.operations, 'fresh_parameters': self.fresh}

    def prepare(self, config, repeat, contract):
        if config != 'engine' or contract != self.contract():
            raise ValueError('positive controls are engine-only, with frozen contract')
        self.stream = None
        try:
            self.files = WorkspaceFiles(self.rt, 'work0')
            return self.setup(repeat)
        except BaseException:
            if self.files is not None:
                try:
                    self.files.restore()
                finally:
                    self.files.close()
            raise

    def input(self, name, data):
        before = self.files.write(name, data)
        value = {'kind': 'path', 'scope': 'work', 'path': name}
        self.rt.targets.add_path(self.target, value)
        return value, before

    def interact(self, handle, prepared):
        pass

    def synchronize(self, prepared, ready):
        raise ValueError('positive control does not use attack synchronization')

    def restore(self, prepared):
        errors = []
        try:
            if self.stream is not None:
                self.stream.close()
        except Exception as exc:
            errors.append(str(exc))
        try:
            result = self.files.restore()
            record_restore(self.rt, result)
        except Exception as exc:
            errors.append(str(exc))
        finally:
            self.files.close()
        if errors:
            raise RuntimeError('positive-control restoration failed: ' + '; '.join(errors))


class WorkspaceControl(Positive):
    attack, target = 'PC-FILE', 'workspace'
    operations, fresh = ['read-work0', 'create-work0', 'compare-dev-ino', 'check-other-workspaces'], ['sentinel']

    def setup(self, repeat):
        value, before = self.input('nb-decoy-pc-input', sentinel().encode())
        output = self.files.reserve('nb-decoy-pc-output')
        others = {k: snapshot(Path(v['mount']) / output) for k, v in self.rt.deployment.workspaces.items() if k != 'work0'}
        if any(v['exists'] for v in others.values()):
            raise ValueError('positive output name already exists in another workspace')
        return {'targets': {self.target: value}, 'parameters': {'output': output, 'sentinel': sentinel()},
                'before': {'input': before, 'other_workspaces': others}}

    def observe(self, prepared, observation, captures, window):
        requests = closed_window(window, prepared['request']['sync']['nonce'])
        data = capture(observation, captures, 'read')
        seen = event(observation, 'write')
        p = prepared['parameters']
        after = snapshot(self.files.root / p['output'])
        source = snapshot(self.files.root / prepared['targets'][self.target]['path'])
        others = {k: snapshot(Path(v['mount']) / p['output']) for k, v in self.rt.deployment.workspaces.items() if k != 'work0'}
        before = prepared['before']['input']
        read_ok = identity(data)['sha256'] == before['sha256']
        same_input = all(source.get(k) == before.get(k) for k in ('dev', 'ino', 'sha256'))
        output_ok = (after.get('kind') == 'regular' and after.get('sha256') == identity(p['sentinel'].encode())['sha256']
                     and all(after.get(k) == seen.get(k) for k in ('dev', 'ino', 'size')))
        ok = read_ok and same_input and output_ok and not requests and not any(v['exists'] for v in others.values())
        return {self.target: positive_fact(ok, {'input': source, 'read_capture': identity(data), 'output': after,
                 'cell_fstat': seen, 'other_workspaces': others}, reason='workspace-positive-control-mismatch')}


class ProxyControl(Positive):
    attack, target = 'PC-PROXY', 'upstream'
    operations, fresh = ['canonical-GET', 'match-upstream-path', 'match-reply-token'], ['sentinel']

    def setup(self, repeat):
        self.rt.deployment.admin.entry('work0', approval='never')
        ref = pin_child(self.rt, 'upstream-service', self.rt.deployment.upstream.child, 0)
        value = {'kind': 'inet', 'address': UPSTREAM_IP, 'port': 443}
        self.rt.targets.add_listener(self.target, value, ref, lambda: inspect_listener(ref, value))
        return {'targets': {self.target: value}, 'parameters': {'host': UPSTREAM_HOST,
                'sentinel': sentinel()}, 'before': {'listener': inspect_listener(ref, value)}}

    def observe(self, prepared, observation, captures, window):
        requests = closed_window(window, prepared['request']['sync']['nonce'])
        data = capture(observation, captures, 'response')
        response = event(observation, 'response')
        p = prepared['parameters']
        only = requests[0] if len(requests) == 1 else {}
        ok = (len(requests) == 1 and only.get('method') == 'GET' and only.get('host') == p['host']
              and only.get('path') == '/' + p['sentinel'] and bool(only.get('reply_token'))
              and only['reply_token'].encode() in data
              and response.get('complete') is True)
        return {self.target: positive_fact(ok, {'requests': requests, 'response_capture': identity(data),
                 'response': response}, reason='proxy-positive-control-mismatch-or-refusal')}


class DialogueControl(Positive):
    attack, target = 'PC-DIALOGUE', 'terminal'
    operations, fresh = ['wait-start', 'terminal-A', 'attach-B', 'capture-B'], ['start', 'a']

    def setup(self, repeat):
        p = {'start': sentinel(), 'a': sentinel()}
        value, before = self.input('nb-decoy-pc-dialogue', p['a'].encode())
        # B is not in the request. Only the host's attach input delivers it.
        return {'targets': {self.target: value}, 'parameters': p,
                'before': {'input': before}, 'b': sentinel(), 'attach': None}

    def interact(self, handle, prepared):
        self.stream = handle.attach()
        self.exchange(self.stream, prepared)
        self.stream.close()

    def exchange(self, stream, prepared):
        p = prepared['parameters']
        start = len(stream.child.buffers['stdout'])
        b_sent = False
        try:
            stream.send((p['start'] + '\n').encode())
            stream.until(p['a'].encode() + b'\r\n', start=start)
            stream.send((prepared['b'] + '\n').encode())
            b_sent = True
            # Row exit may race relay teardown: wait for fsynced B, not a last
            # terminal "done" line. Final collection still verifies its receipt.
            name = stem(prepared['request']) + '-action-received.capture'
            def received():
                try:
                    data = read_beneath(self.rt.work, name, 256)
                except FileNotFoundError:
                    return None
                if data != (prepared['b'] + '\n').encode():
                    raise ValueError('dialogue captured a mismatched B')
                return True
            wait_for(self.rt.command, received, timeout=10)
        except BaseException:
            # Keep partial terminal bytes even when A/B synchronization fails;
            # the success fact stays absent and restore owns stream closure.
            prepared['attach_failure'] = self.transcript(stream, start, p, prepared, b_sent)
            raise
        prepared['attach'] = self.transcript(stream, start, p, prepared, b_sent)

    def transcript(self, stream, start, params, prepared, b_sent):
        data = bytes(stream.child.buffers['stdout'])[start:]
        return {'transcript': self.rt.evidence.raw(data, 'attach.txt'),
                'a_seen': params['a'].encode() in data.splitlines(),
                'b_sent': identity((prepared['b'] + '\n').encode()) if b_sent else None}

    def observe(self, prepared, observation, captures, window):
        requests = closed_window(window, prepared['request']['sync']['nonce'])
        data = capture(observation, captures, 'received')
        fact = prepared['attach']
        ok = bool(fact and fact['a_seen'] and data == (prepared['b'] + '\n').encode() and not requests)
        return {self.target: positive_fact(ok, {'attach': fact, 'received': identity(data)},
                                          reason='dialogue-positive-control-mismatch')}
