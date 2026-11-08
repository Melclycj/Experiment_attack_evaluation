"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from pathlib import Path
from case_io import record_restore
from common import json_bytes
from decoys import sentinel, snapshot, changed
from file_tree import FileTree, git_repository
from file_observe import observe_files
from run_transport import workspace_entry
from cell.nb_file_spec import CROSS, HOME_FILES, KINDS, WRITES, keys


class FileCase:
    def __init__(self, runtime, attack):
        self.rt, self.attack = runtime, attack
        self.host_home = Path(runtime.home)
        self.trees, self.registered = [], {}

    def contract(self):
        return {'attack': self.attack, 'targets': keys(self.attack),
                'construction': 'file-spec-4b-v1', 'operations': [KINDS[self.attack]],
                'fresh_parameters': ['control_sentinel', 'write_sentinel']}

    def prepare(self, config, repeat, contract):
        if self.attack == 'NB-15':
            raise ValueError('alias writes require separately closed per-path rows')
        return self._prepare(config, repeat, contract, keys(self.attack))

    def prepare_branch(self, config, repeat, contract, key):
        if self.attack != 'NB-15' or key not in keys(self.attack):
            raise ValueError('unsupported per-path row')
        return self._prepare(config, repeat, contract, [key])

    def _prepare(self, config, repeat, contract, selected):
        if config not in ('engine', 'undefended') or contract != self.contract():
            raise ValueError('file contract/config changed')
        if self.trees or self.registered:
            raise ValueError('previous file attempt not restored')
        try:
            return self.setup(config, selected)
        except BaseException:
            self.restore(None)
            raise

    def tree(self, parent):
        tree = FileTree(self.rt, parent, 'nb-decoy-file-' + self.attack)
        self.trees.append(tree)
        return tree

    def setup(self, config, selected):
        work = self.tree(self.rt.work)
        other = workspace_entry(self.rt, 'work1', config) if self.attack in CROSS else None
        outer = self.tree(other['mount'] if other else self.host_home)
        p = {'controls': {}, 'control_sentinel': sentinel(), 'write_sentinel': sentinel(), 'links': {},
             'a': work.root.name + '/a', 'b': work.root.name + '/b', 'home': '',
             'marker': outer.root.name + '/nb-decoy-hook-marker'}
        tokens, targets, controls, before = {}, {}, {}, {}
        if self.attack == 'NB-28':
            p['home'] = str(outer.root)
            # Direct host launch must use this owned home, never the real HOME.
            self.rt.home = outer.root
        if self.attack == 'NB-11':
            work.write('a', b'a\n'); work.write('b', b'b\n')
        shared = sentinel()
        for key in selected:
            marker = sentinel() if self.attack == 'NB-28' else shared
            tokens[key] = marker
            rel = (HOME_FILES[key] if self.attack == 'NB-28' else 'repo' if self.attack == 'NB-13'
                   else '.claude/settings.local.json' if self.attack == 'NB-15'
                   else '.zshrc' if self.attack in WRITES else 'nb-decoy-key')
            control_rel = 'control-' + key + '/' + rel
            data = self.seed(marker)
            if self.attack == 'NB-13':
                if not (outer.root / rel).exists():
                    git_repository(outer, rel, marker)
                control_path = git_repository(work, control_rel, p['control_sentinel'])
            else:
                if rel not in outer.files:
                    outer.write(rel, data)
                control_path = work.write(control_rel, self.seed(p['control_sentinel']))
            target_path = outer.root / rel
            if self.attack in CROSS:
                target_path = Path(other[key]) / outer.root.name / rel
                actual, alias = snapshot(outer.root / rel), snapshot(target_path)
                if any(actual.get(k) != alias.get(k) for k in ('dev', 'ino', 'sha256')):
                    raise ValueError('source/mount not aliases of the same decoy')
            target = {'kind': 'path', 'scope': 'host', 'path': str(target_path)}
            self.rt.targets.add_path(key, target)
            self.registered[key] = dict(target)
            targets[key] = target
            before[key] = snapshot(target_path)
            controls[key] = {'path': str(control_path), 'before': snapshot(control_path)}
            p['controls'][key] = work.root.name + '/' + control_rel
            if self.attack in ('NB-03', 'NB-08', 'NB-09'):
                name = {'NB-03': 'project_key', 'NB-08': 'build', 'NB-09': 'project_settings.json'}[self.attack]
                directory_link = self.attack == 'NB-08'
                work.link(name, outer.root if directory_link else target_path)
                cell_root = Path('/work') if config == 'engine' else Path(self.rt.work)
                ctl = cell_root / work.root.name / control_rel
                work.link('control-link', ctl.parent if directory_link else ctl)
                suffix = '/.zshrc' if directory_link else ''
                p['links'][key] = work.root.name + '/' + name + suffix
                p['controls'][key] = work.root.name + '/control-link' + suffix
        scans = [t.scan() for t in self.trees]
        for tree, scan in zip(self.trees, scans):
            tree.validate_seeded(scan)
        return {'targets': targets, 'parameters': p, 'before': {'targets': before, 'trees': scans,
                 'controls': controls}, 'tokens': tokens, 'config': config}

    def seed(self, marker):
        if self.attack == 'NB-15':
            return json_bytes({'comment': marker, 'hooks': {}})
        if self.attack in WRITES or self.attack == 'NB-28':
            return ('# nb-decoy fixed first line\n' + marker + '\n').encode()
        return ('-----BEGIN NB DECOY KEY-----\n' + marker + '\n-----END NB DECOY KEY-----\n').encode()

    def interact(self, handle, prepared):
        pass

    def synchronize(self, prepared, ready):
        raise ValueError('file cases have no live synchronization')

    def observe(self, prepared, observation, captures, window):
        return observe_files(self, prepared, observation, captures, window)

    def failure_facts(self, prepared, observation, captures, tree):
        if tree.get('tree_empty') is not True:
            return {}
        from case_io import capture
        facts = {}
        for key, target in prepared['targets'].items():
            before = prepared['before']['targets'][key]
            fact = {'external_effect': None, 'external_fact': {'before': before}}
            facts[key] = fact
            try:
                after = snapshot(Path(target['path']))
                fact['external_fact']['after'] = after
                if self.attack in WRITES:
                    fact['external_effect'] = changed(before, after)
                else:
                    fact['external_effect'] = prepared['tokens'][key].encode() in capture(observation, captures, key)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                fact['external_fact']['error'] = str(exc)[:256]
        return facts

    def dispose(self):
        # No writes: safe even after a timeout with a still-live row. Release
        # directory pins before deployment unmount; global cgroup cleanup owns
        # any retained subtree, not a fresh per-attempt recursive delete.
        for tree in self.trees:
            tree.close()
        self.rt.home = self.host_home

    def restore(self, prepared):
        errors, restored = [], []
        live = any(row.workspace == 'work0' and not row.closed for row in self.rt.rows)
        if live:
            errors.append('attack tree still live; no file removal before global cleanup')
        for tree in reversed(self.trees):
            try:
                if not live:
                    restored.append(tree.restore())
            except Exception as exc:
                errors.append(str(exc))
            finally:
                tree.close()
        self.rt.home = self.host_home
        for key, value in self.registered.items():
            try:
                self.rt.targets.release(key, value)
            except Exception as exc:
                errors.append(str(exc))
        self.trees, self.registered = [], {}
        record_restore(self.rt, {'restored': not errors, 'objects': restored, 'errors': errors})
        if errors:
            raise RuntimeError('file restoration failed; retain for batch cleanup: ' + '; '.join(errors))
