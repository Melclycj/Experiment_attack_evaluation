"""NB-26 outside-cell positive control: reserved uid, owned cgroup, observe before release."""
from cell.nb_contract import decode, stem
from common import json_bytes
from netns_witness import effect, worker_ref
from run_rows import AttemptGroup
from safeio import read_owned
from userns_report import validate


class SameUidControl:
    workspace, execution = 'nb26-control', None

    def __init__(self, rt, candidate, req):
        self.rt, self.candidate, self.req = rt, candidate, req
        self.uid, self.group, self.child = rt.cap['spare_uid'], None, None
        self.closed, self.ref = False, None
        self.fact = {'ok': False, 'error': ''}
        self.retired = False

    def _uid_reusable(self, runtime):
        # rows retains cleanup ownership across arms. Only our successful,
        # fully finalized controls may reuse the spare uid, never real rows.
        # joined witnesses cgroup entry, not exit; returncode/streams and the
        # earlier pidfd exit + namespace restoration checks establish exit.
        return (self.rt is runtime and self.retired is True and self.closed is True
                and self.fact.get('ok') is True and not self.fact.get('error')
                and self.group is not None and self.group.created is False
                and self.child is not None and self.child.joined is True
                and self.child.proc.returncode == 0 and self.child.streams == 0
                and self.ref is None)

    def run(self):
        if self.closed or self.group is not None:
            raise ValueError('control object cannot be restarted')
        rt, req = self.rt, self.req
        try:
            catalog = decode(read_owned(rt.deployment.root / 'catalog.json'))
            limits = catalog['uid_range']
            if (not rt.cap['first'] <= self.uid <= rt.cap['last']
                    or limits['first'] <= self.uid <= limits['last']
                    or any(r.uid == self.uid and not (
                        type(r) is SameUidControl and r is not self and r._uid_reusable(rt))
                        for r in rt.rows)):
                raise ValueError('control uid must be reserved and excluded from every row')
            rt.serial += 1
            self.group = AttemptGroup(rt.cgroup, 'nb26-control-' + str(rt.serial))
            rt.rows.append(self)  # global cleanup owns even a partially created group
            self.group.create()
            argv = ['/usr/bin/setpriv', '--reuid=' + str(self.uid), '--regid=' + str(self.uid),
                    '--clear-groups', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                    '--no-new-privs', '/usr/bin/python3.12', '-I', '-B',
                    str(rt.payload['nb26_worker.py']), '--host-control']
            self.child = rt.command.start(argv, group=self.group, interactive=True,
                cwd=rt.deployment.scratch, env={'HOME': '/nonexistent'}, timeout=rt.command.deadline.left(20))
            rt.command.send_input(self.child, json_bytes(req), timeout=2)
            while True:
                rt.pump()
                raw = bytes(self.child.buffers['stdout'])
                if len(raw) > 65536:
                    raise ValueError('oversized outside-cell control')
                if b'\n' in raw:
                    break
                if self.child.proc.poll() is not None:
                    raise ValueError('outside-cell control exited before observation')
            self.fact['raw'] = rt.evidence.raw(raw, 'nb26-control-live.json')
            report = validate(decode(raw), req, self.uid)
            self.ref = worker_ref(rt, self.uid, report, group=self.group, pid=self.child.proc.pid)
            self.ref.read()
            live = self.candidate.read()
            self.ref.read()
            success = effect(self.candidate.before, live, req['parameters']['peer_if'])
            self.fact.update(report=report, live=live, effect=success)
            rt.evidence.raw(json_bytes(self.fact), 'nb26-control-before-release.json')
            rt.command.send_input(self.child, json_bytes({'attempt': stem(req),
                'nonce': req['sync']['nonce'], 'state': 'release'}), timeout=2)
            rt.command.close_input(self.child)
            rt.command.wait(self.child)
            while not self.group.empty():
                rt.pump()
            if not self.ref.exited():
                raise ValueError('outside control process still live')
            after = self.candidate.read()
            self.fact['after'] = after
            if after != self.candidate.before:
                raise ValueError('outside control did not restore candidate netns')
            if not success:
                raise ValueError('same-uid outside-cell positive control failed')
            self.fact['ok'] = True
            return self.fact
        except BaseException as exc:
            self.fact['error'] = type(exc).__name__ + ': ' + str(exc)[:512]
            raise
        finally:
            try:
                self.stop()
            finally:
                if self.ref is not None:
                    self.ref.close(); self.ref = None
                rt.evidence.raw(json_bytes(self.fact), 'nb26-control.json')
            # A stop, pin-close or final evidence failure must not retire it.
            self.retired = self.fact['ok'] is True and not self.fact['error']

    def stop(self):
        if self.group is not None and self.group.created:
            if not self.group.empty():
                self.group.kill_and_wait(timeout=self.rt.command.deadline.left(5))
            self.group.remove()
        self.closed = True
