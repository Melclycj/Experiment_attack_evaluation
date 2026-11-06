"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import time
from types import SimpleNamespace
from build import AS_BUILDER, compile_engine, inventory
from cell_payload import compile_argv, prepare_payload
from cleanup import Resources
from commands import CaptureBudget, Commands
from common import identity, json_bytes
from deploy import Deployment, fresh_root
from env import RunCgroup
from host import compare_crashes, crash_inventory
from net import PrivateNetwork
from run_baseline import ENGINE, verify
from run_limits import until
from run_rows import Row
from run_contract import targets_for
from run_transport import OwnedTargets, logical_target, prepare_request, request, workspace_entry
from safeio import read_owned


class Runtime:
    """Production wiring only. Tests replace this boundary, not engine code.
    Construction is read-only; all mutations occur under execute()'s finally.
    """
    def __init__(self, bundle, host, absolute_deadline, evidence, support=None):
        self.bundle, self.host, self.end, self.evidence = bundle, host, absolute_deadline, evidence
        self.work_end, self.cap = absolute_deadline - 60, bundle['cap']
        self.source = Path(bundle['root']) / 'engine'
        self.root = Path(bundle['root'])
        self.resources, self.rows = Resources(), []
        self.cgroup = RunCgroup(Path(bundle['cgroup_parent']), bundle['label'])
        self.command = self.cleanup_command = self.deployment = self.network = None
        self.records, self.support, self.support_factory = [], None, support
        self.targets, self.stage, self.cleanup_result = OwnedTargets(self), 'new', None
        self.engine_identity = dict(bundle['engine_identity'],
                                    source_path=bundle.get('engine_path', ENGINE))
        self.payload, self.modules, self.serial = {}, {}, 0
        self.active, self.config = None, None
        if bundle.get('variant'):
            receipt = bundle['variant_provenance']
            self.engine_identity.update(variant=bundle['variant'],
                original_digest=receipt['original']['digest'],patch_identity=receipt['patch_identity'])

    def prepare(self):
        self.stage = 'cgroup'
        self.cgroup.create()
        self.command = Commands(self.cgroup, until(self.work_end), budget=CaptureBudget(512 * 1024), records=self.records)
        self.cleanup_command = Commands(self.cgroup, until(self.end), budget=CaptureBudget(128 * 1024), records=self.records)
        self.stage = 'baseline-host'
        self.engine_identity = verify(Path(self.bundle['repo']), self.engine_identity, self.host, self.command,
                                      engine_path=self.bundle.get('engine_path', ENGINE))
        self.stage = 'build'
        scratch = fresh_root(Path('/tmp') / ('nb-decoy-build-' + self.bundle['label']), self.resources)
        build = scratch / 'build'
        products = compile_engine(self.source, build, self.command)
        cell = Path(__file__).parent / 'cell'
        self.command([*AS_BUILDER, *compile_argv(cell, build / 'nb_probe')], timeout=60)
        for path in build.iterdir():
            if path.is_file():
                os.chown(path, 0, 0); path.chmod(0o555)
        os.chown(build, 0, 0); build.chmod(0o755)
        self.stage = 'payload'
        self.modules = {name: self.root / 'modules' / rel for name, rel in self.bundle['modules'].items()}
        self.payload = prepare_payload(cell, build / 'nb_probe', self.modules, scratch / 'payload',
                                       support_modules=self.bundle['support_modules'],
                                       **({'unit':self.bundle['unit']} if self.bundle.get('unit') else {}))
        self.stage = 'deployment'
        self.network = PrivateNetwork(self.command, self.resources, self.host)
        self.deployment = Deployment(source=self.source, source_identity=self.bundle['engine_identity'],
            build=build, products=products, cap=self.cap, payload=self.payload, command=self.command,
            resources=self.resources, network=self.network, cleanup_command=self.cleanup_command,
            crash_check=self.crash_check, label=self.bundle['label'], cert_python=self.bundle['cert_python'],
            **({'unit':self.bundle['unit']} if self.bundle.get('unit') else {}))
        self.deployment.prepare()
        self.prepare_watcher()
        self.use('engine')
        self.home = self.deployment.scratch / 'host'
        self.home.mkdir(mode=0o700)
        os.chown(self.home, 1000, 1000)
        self.stage = 'ready'

    def prepare_watcher(self):
        # Batch resource: start before Batch installs a 30-second attempt limit.
        if 'NB-21' in self.bundle.get('attacks', []):
            if self.command.deadline.end != self.work_end:
                raise ValueError('approval watcher requires batch work deadline')
            self.deployment.admin.watch()

    def use(self, config):
        """The arm's own workspaces: the deployment's v4 ones for engine, the host user's for undefended."""
        self.workspace('work0', config)
        self.config = config
        self.work = self.workspace('work0', config)['mount']

    def workspace(self, name, config=None):
        return workspace_entry(self, name, config)

    def crash_check(self):
        return compare_crashes(self.host['crashes'], crash_inventory(Path(self.host['crash_directory'])))

    def arm(self, config):
        if self.support is not None:
            self.support.close()
            for row in self.rows:
                if not row.closed:
                    row.stop()
            self.support = None
        if self.support_factory is None:
            raise ValueError('step-4 victim/auxiliary programs are not implemented')
        self.use(config)
        self.support = self.support_factory(self, config)
        live = [r for r in self.rows if not r.closed]
        wanted = {('work1', config), ('work2', 'engine')}
        if {(r.workspace, r.config) for r in live} != wanted or len(live) != 2:
            raise ValueError('support must own exactly victim work1 and auxiliary work2')
        self.active = config

    def start_helper(self, workspace, config, module_id, targets, parameters):
        if workspace not in ('work1', 'work2') or (workspace == 'work2' and config != 'engine'):
            raise ValueError('invalid support workspace/configuration')
        if config not in ('engine', 'undefended') or module_id != {
                'work1': 'SUP-VICTIM', 'work2': 'SUP-AUXILIARY'}[workspace]:
            raise ValueError('support role/lifecycle not bound to its workspace')
        if module_id not in self.bundle['support_modules']:
            raise ValueError('helper module not explicitly selected')
        self.targets.verify(targets, owner='support')
        self.serial += 1
        req = request(self.bundle['run'], config, SimpleNamespace(attack=module_id), self.serial,
                      {'targets': targets, 'parameters': parameters})
        prepare_request(self.workspace(workspace, config)['mount'], req)
        row = self.start(config, workspace=workspace, seconds=self.command.deadline.left(540))
        row.request = req
        return row

    def start(self, config, workspace='work0', seconds=30):
        self.serial += 1
        row = Row(self, config, workspace, 'row-' + str(self.serial), seconds)
        self.rows.append(row)  # ownership registered before any start can fail
        return row.start()

    def paired_targets(self, targets, contract):
        result = {}
        roles = contract.get('process_roles', {})
        if set(targets) != set(targets_for(contract, self.active)):
            raise ValueError('process/target set differs from declared applicability')
        for key, value in targets.items():
            if key not in roles:
                result[key] = logical_target(self, value)
                continue
            role = roles[key]
            if value['kind'] != 'process':
                raise ValueError('process role used for nonprocess target')
            if role in ('core', 'spawner'):
                ref = self.deployment.refs[role]
            elif role in ('victim-connector', 'auxiliary-connector', 'victim-file-worker', 'auxiliary-file-worker'):
                workspace = 'work1' if role.startswith('victim-') else 'work2'
                rows = [r for r in self.rows if r.workspace == workspace and not r.closed and r.execution]
                if len(rows) != 1:
                    raise ValueError('named support connector is not a live owned row')
                kind = 'connector:' if role.endswith('-connector') else 'file-worker:'
                ref = self.deployment.refs[kind + rows[0].execution]
            else:
                raise ValueError('unknown process role')
            fact = ref.read()
            if value != {'kind': 'process', 'pid': fact['pid'], 'starttime': fact['start_time']}:
                raise ValueError('process target does not match its pinned role')
            result[key] = {'kind': 'process', 'role': role}
        return result

    def paths_accessible(self, targets):
        # No read of target bytes; only directory search access with actual uid/
        # supplementary groups. Don't follow target symlinks (intentional cases).
        from undefended import check_directories
        parents = sorted({str(Path(v['path']).parent) for v in targets.values()
                          if v['kind'] == 'path' and v['scope'] == 'host'})
        if parents:
            check_directories(self, parents)

    def finish_work(self):
        if self.support is not None:
            self.support.close()

    def pump(self):
        self.command.pump(.02)

    def close(self):
        if self.cleanup_result is not None:
            return self.cleanup_result
        errors = []
        if self.deployment:
            try:
                self.deployment.stop_engine()
            except Exception as exc:
                errors.append(str(exc))
        if self.support is not None:
            try:
                self.support.dispose()
            except Exception as exc:
                errors.append(str(exc))
        # Close owned per-attempt cgroups before Resources removes the batch.
        # Even if work supervisor failed, use same cgroup with total deadline.
        for row in self.rows:
            if row.group and row.group.created:
                try:
                    row.group.kill_and_wait(timeout=until(self.end).left(5))
                    row.group.remove()
                except Exception as exc:
                    errors.append(str(exc))
        try:
            if self.deployment:
                result = self.deployment.close()
            else:
                command = self.cleanup_command
                if command is None and self.cgroup.created:
                    command = Commands(self.cgroup, until(self.end), records=self.records,
                                       budget=CaptureBudget(128 * 1024))
                    self.cleanup_command = command
                result = self.resources.cleanup(stop_engine=lambda: self.network.close() if self.network else None,
                    cgroup=self.cgroup, command=command,
                    mountinfo=lambda: Path('/proc/self/mountinfo').read_text(), crash_check=self.crash_check)
        finally:
            for cmd in (self.command, self.cleanup_command):
                if cmd:
                    try:
                        cmd.close()
                    except Exception as exc:
                        errors.append(str(exc))
        if errors:
            result['ok'] = False
            result['failures'].extend({'step': 'controller-handles', 'error': e} for e in errors)
        self.cleanup_result = result
        return result
