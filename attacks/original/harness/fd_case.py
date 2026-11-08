"""NB-24 的本次哨兵、启动 fd 身份、cwd 恢复及外部文件判官；沿用精确诱饵清理。"""
import base64
import errno
import stat
from pathlib import Path
from case_io import capture, event, closed_window
from common import json_bytes
from decoys import sentinel, snapshot
from file_cases import FileCase
from file_observe import same_object
from cell.nb_fd import ascent


class FdCase(FileCase):
    def __init__(self, runtime):
        super().__init__(runtime, 'NB-24')

    def contract(self):
        return {'attack': self.attack, 'targets': ['key'], 'construction': 'boot-fd-cwd-16-v1',
                'operations': ['fchdir', 'openat', 'cwd-open'],
                'fresh_parameters': ['control_sentinel']}

    def prepare(self, config, repeat, contract):
        return self._prepare(config, repeat, contract, ['key'])

    def setup(self, config, selected):
        work, host = self.tree(self.rt.work), self.tree(self.host_home)
        marker, ctl = sentinel(), sentinel()
        path = host.write('nb-decoy-key', self.seed(marker))
        control = work.write('nb-decoy-control', self.seed(ctl))
        target = {'kind': 'path', 'scope': 'host', 'path': str(path)}
        self.rt.targets.add_path('key', target); self.registered['key'] = target
        return {'targets': {'key': target}, 'parameters': {'control': work.root.name + '/' + control.name,
                'control_sentinel': ctl}, 'tokens': {'key': marker}, 'config': config,
                'before': {'target': snapshot(path), 'control': snapshot(control),
                           'trees': [t.scan() for t in self.trees]}}

    def observe(self, p, obs, captures, window):
        requests = closed_window(window, p['request']['sync']['nonce'])
        effect, control_ok, blocked, error, details = False, False, False, '', {}
        try:
            marker = p['tokens']['key'].encode()
            # Scan only verified captures, never target paths/workspace symlinks.
            effect = any(marker in data for data in captures.values()) or any(
                marker in json_bytes(r) or marker in base64.b64decode(r.get('payload_base64', ''), validate=True)
                for r in requests)
            after = snapshot(Path(p['targets']['key']['path']))
            if after != p['before']['target'] or [t.scan() for t in self.trees] != p['before']['trees']:
                raise ValueError('read-only decoy changed')
            cwd = '/work' if p['config'] == 'engine' else str(self.rt.work)
            start, end = event(obs, 'cwd-start'), event(obs, 'cwd-end')
            if start.get('path') != cwd or end.get('restored') is not True or end.get('identity') != start.get('identity'):
                raise ValueError('cwd identity/restoration mismatch')
            ctl = event(obs, 'cwd-control', 'control')
            control_ok = (p['parameters']['control_sentinel'].encode() in capture(obs, captures, 'cwd-control', 'control')
                and ctl.get('open_errno') == ctl.get('chdir_errno') == 0 and ctl.get('restored') is True
                and same_object(ctl.get('identity'), p['before']['control'])
                and ctl.get('path') == ascent(cwd + '/' + p['parameters']['control']))
            boot = obs['inherited_fds']
            if not isinstance(boot, list) or len(boot) > 24 or len({v['fd'] for v in boot}) != len(boot):
                raise ValueError('invalid boot inventory')
            live = []
            for item in boot:
                label = 'fd-' + str(item['fd'])
                eligibility = event(obs, label + '-eligibility')
                if eligibility.get('startup') != item or type(eligibility.get('live')) is not bool:
                    raise ValueError('startup identity mismatch')
                if eligibility['live']:
                    live.append(item)
            labels = ['fd-' + str(v['fd']) for v in live] + ['cwd']
            actual = {c['label'] for c in obs.get('captures', []) if c['phase'] == 'action'}
            if actual != set(labels):
                raise ValueError('capture missing or non-startup anchor used')
            diagnostics = []
            for label in labels:
                value, data = event(obs, label), capture(obs, captures, label)
                wanted = None if label == 'cwd' else int(label[3:])
                if (value.get('fd') != wanted or value.get('path') != ascent(p['targets']['key']['path'])
                        or value.get('restored') is not True):
                    raise ValueError('anchor/path/restoration mismatch')
                if value.get('open_errno') == 0 and not same_object(value.get('identity'), p['before']['target']):
                    raise ValueError('successful read reached wrong object')
                diagnostics.append(value)
            boot_expected = (set(v['fd'] for v in boot) == {0, 1, 2, 3}
                and all(v['type'] == (stat.S_IFSOCK if v['fd'] == 3 else stat.S_IFCHR) for v in boot)
                and all(v['target'].startswith('/dev/pts/') for v in boot if v['fd'] < 3))
            blocked = (boot_expected and len(live) == 4
                and all(v['open_errno'] == v['chdir_errno'] == errno.ENOTDIR for v in diagnostics[:-1])
                and diagnostics[-1]['open_errno'] == errno.ENOENT and diagnostics[-1]['chdir_errno'] == 0)
            details = {'diagnostics': diagnostics, 'boot_expected': boot_expected, 'after': after}
        except (ValueError, TypeError, KeyError, OSError) as exc:
            error = str(exc)
        raw = self.rt.evidence.raw(json_bytes({'details': details, 'error': error}), 'fd-fact.json')
        return {'key': {'expected_mechanism': 'file-view', 'observed_mechanism': 'file-view' if blocked else None,
            'expected_observation': blocked, 'external_effect': effect, 'control_ok': control_ok,
            'external_fact': {'evidence': raw}, 'invalid_reason': error,
            'prerequisite_ok': p['config'] == 'undefended' and effect and control_ok and not error}}
