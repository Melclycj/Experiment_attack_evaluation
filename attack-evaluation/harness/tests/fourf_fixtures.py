"""这是 1.1 隔离论证的验证测试：4f 全注册编排夹具；OS 效果为 mock，不是实测。"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from batch_fixtures import FakeRuntime, patches
from common import identity
from foura_fixtures import SCRIPTS
from run_contract import targets_for
from run_registry import CASES, SUPPORT_MODULES
from run_runtime import Runtime
from support_rows import SupportRows

ORDER = ([f'NB-{n:02}' for n in range(1, 10)] + ['PC-FILE'] +
         [f'NB-{n:02}' for n in range(10, 20)] + ['PC-PROXY'] +
         [f'NB-{n:02}' for n in range(20, 29)] + ['PC-DIALOGUE'])


class ContractAdapter:
    """Use each real adapter's contract; replace host/device facts, not the judge."""
    def __init__(self, rt, original):
        self.rt, self.original, self.attack = rt, original, original.attack
        self.spec = original.factory(rt).contract()

    def contract(self):
        return deepcopy(self.spec)

    def prepare(self, config, repeat, contract):
        return self._prepare(config, targets_for(contract, config))

    def prepare_branch(self, config, repeat, contract, branch):
        return self._prepare(config, [branch])

    def _prepare(self, config, keys):
        rt = self.rt
        rt.current = (config, self.attack)
        rt.mark('prepare', tuple(keys))
        if self.attack == 'NB-23' and config == 'undefended':
            rt.support.ensure_signal_victim()
        targets = {}
        for key in keys:
            role = self.spec.get('process_roles', {}).get(key)
            if role:
                refkey = role
                if role.endswith(('-connector', '-file-worker')):
                    work = 'work1' if role.startswith('victim-') else 'work2'
                    row = next(r for r in rt.rows if r.workspace == work and not r.closed)
                    refkey = ('connector:' if role.endswith('-connector') else 'file-worker:') + row.execution
                info = rt.deployment.refs[refkey].read()
                targets[key] = dict(kind='process', pid=info['pid'], starttime=info['start_time'])
            else:
                targets[key] = dict(kind='path', scope='host', path=f'/tmp/nb-decoy-4f/{self.attack}/{key}')
        params = {'operation': self.spec['operations']}
        params.update({key: 'nb-decoy-' + ('a' if config == 'engine' else 'b') * 48
                       for key in self.spec.get('fresh_parameters', [])})
        return dict(targets=targets, parameters=params, before={'mock': True}, config=config)

    def interact(self, handle, prepared):
        self.rt.mark('interact')

    def synchronize(self, prepared, ready):
        self.rt.mark('sync')
        return {'mock_host_witness': True, 'state': ready['state']}

    def after_tree(self, prepared, tree):
        self.rt.mark('after-tree')

    def observe(self, prepared, observed, captures, window):
        rt = self.rt
        rt.mark('judge')
        facts = {}
        for key in prepared['targets']:
            success = prepared['config'] == 'undefended' or self.original.kind == 'control'
            mechanism = self.original.expected.get('mechanism', '')
            if self.attack == 'NB-23' and prepared['config'] == 'undefended' and key != 'core':
                success, mechanism = False, 'uid-permission'
            if rt.effect == (prepared['config'], self.attack, key):
                success = True
            prerequisite = prepared['config'] == 'undefended'
            if rt.missing_peer == (self.attack, key):
                prerequisite = False
            facts[key] = dict(expected_mechanism=mechanism, observed_mechanism=mechanism,
                              control_ok=True, external_effect=success, expected_observation=True,
                              external_fact={'mock_host_effect': success, 'target': key},
                              prerequisite_ok=prerequisite)
        return facts

    def restore(self, prepared):
        self.rt.mark('restore')

    def dispose(self):
        self.rt.mark('dispose', self.attack)


class SupportFixture(SupportRows):
    """Keep production constructor role dispatch; mock persistent row OS boundaries."""
    def _start(self, role, workspace, config, module):
        self.rt.mark('support-start', (role, workspace, config, module))
        row = self.rt.start_helper(workspace, config, module,
                                  {role: dict(kind='path', scope='work', path='nb-decoy-' + role)}, {})
        self.items[role] = {'row': row}

    def ensure_signal_victim(self):
        # Model OS lifecycle only; keep the real role binding and pairing code.
        if self.signal_victim: return
        self.items['victim']['row'].closed = True
        self._start('victim', 'work1', 'engine', 'SUP-VICTIM')
        self.signal_victim = True

    def close(self):
        if self.closed:
            return
        self.rt.mark('support-close', self.config)
        for item in self.items.values():
            item['row'].closed = True
        self.closed = True

    def dispose(self):
        self.rt.mark('support-dispose', self.config)


def selected(names=ORDER):
    return [replace(CASES[key], factory=lambda rt, c=CASES[key]: ContractAdapter(rt, c)) for key in names]


class MergedRuntime(FakeRuntime):
    """Production Batch/arm/helpers/contracts/record; no process, socket or syscall."""
    arm = Runtime.arm
    use, workspace = Runtime.use, Runtime.workspace  # v4: each arm's own work0
    start_helper = Runtime.start_helper
    paired_targets = Runtime.paired_targets
    finish_work = Runtime.finish_work

    def __init__(self, root, chosen, stack, *, fault=None, effect=None, missing_peer=None):
        super().__init__(root, chosen)
        self.home, self.rows, self.serial = root, [], 0
        from run_limits import until
        self.command.deadline = until(self.work_end)
        self.support, self.support_factory = None, SupportFixture
        self.current, self.trace = None, []
        self.fault, self.effect, self.missing_peer = fault, effect, missing_peer
        self.bundle['support_modules'] = dict(SUPPORT_MODULES)
        self.bundle['script_identities'] = {c.attack: identity((SCRIPTS / c.module).read_bytes()) for c in chosen}
        self.deployment.workspaces = {k: {'mount': root / k} for k in ('work0', 'work1', 'work2')}
        self.deployment.host_workspaces = self.deployment.workspaces  # offline: arms share; v4 split in test_9
        self.deployment.refs = {k: Mock(read=Mock(return_value={'pid': i, 'start_time': i * 10}))
                                for k, i in (('core', 20), ('spawner', 21))}
        self.deployment.upstream.begin = lambda nonce: self.mark('begin')
        self.deployment.upstream.end = self.window
        def verify(targets, *, owner='attack'):
            if owner not in ('attack', 'support'):
                raise ValueError('unknown mock registration owner')
            return {key: {'mock_identity': True} for key in targets}
        self.targets.verify = verify
        patches(self, stack)
        stack.enter_context(patch('run_batch.prepare_request', side_effect=self.publish))
        stack.enter_context(patch('run_runtime.prepare_request', side_effect=self.publish))
        stack.enter_context(patch('run_batch.collect', side_effect=self.collect))

    def mark(self, stage, detail=None):
        self.trace.append((stage, self.current, detail))
        if self.fault == (self.current, stage):
            raise RuntimeError('injected ' + stage)

    def publish(self, work, req):
        self.mark('request', deepcopy(req))

    def start(self, config, workspace='work0', seconds=30):
        self.serial += 1
        execution = 'mock-' + str(self.serial) if config == 'engine' else None
        row = SimpleNamespace(workspace=workspace, config=config, closed=False, execution=execution)
        if execution:
            value = {'pid': 100 + self.serial, 'start_time': 1000 + self.serial}
            self.deployment.refs['connector:' + execution] = Mock(read=Mock(return_value=value))
            worker = {'pid': 500 + self.serial, 'start_time': 5000 + self.serial}  # v4: the row's file worker
            self.deployment.refs['file-worker:' + execution] = Mock(read=Mock(return_value=worker))
        row.stop = lambda: setattr(row, 'closed', True)
        def finish():
            self.mark('tree-empty')
            row.closed = True
            return {'tree_empty': True, 'runner_ok': self.fault != (self.current, 'runner-exit')}
        row.poll, row.finish = lambda: True, finish
        self.rows.append(row)
        self.mark('start', (workspace, config, seconds))
        return row

    def collect(self, *args):
        self.mark('collect')
        complete = self.fault != (self.current, 'incomplete')
        return {'complete': complete, 'control_ok': True, 'captures': []}, {}

    def window(self):
        self.mark('window')
        return {'requests': [], 'end': {'kind': 'end'}}

    def close(self):
        for row in self.rows:
            row.closed = True
        self.mark('close')
        return {'ok': True, 'failures': [], 'retained': [], 'steps': []}
