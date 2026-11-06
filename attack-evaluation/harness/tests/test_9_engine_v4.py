"""这是 1.1 隔离论证的验证测试：harness 对登记基线 v4（engine-v3 @ a9eff999）的适配；全部离线，不启动部署。"""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

from build import capacity
from common import identity, json_bytes
from env import check_reserved_uids

# v4's dedicated ids, as the tests expect them; env.py must carry the same values (Catalog checks it).
OWNER_UID, WORKER_UID = 70997, 70996

HOST_PROFILE = Path(__file__).resolve().parent / 'host_profile_fixture.json'


def runtime(root):
    """Two arms' workspaces, as deploy.Deployment lays them out on v4 (offline paths only)."""
    engine = {w: {'source': root / 'workspaces' / w / 'tree', 'mount': root / 'deploy' / w / 'tree'}
              for w in ('work0', 'work1', 'work2')}
    host = {w: {'source': root / 'workspaces' / ('u-' + w), 'mount': root / 'host-work' / w}
            for w in ('work0', 'work1')}
    return NS(deployment=NS(workspaces=engine, host_workspaces=host), config=None)


class Catalog(unittest.TestCase):
    def catalog(self):
        from deploy_catalog import catalog_files
        from deploy_fixtures import make_deployment, mini_seed
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            d.root.mkdir()
            mini_seed(d.root)
            return d, catalog_files(d.source, d.root, d.cap, fs_uuid='12345678-1234-1234-1234-123456789abc',
                                    fs_bytes=256 * 1024**2)['catalog']

    def test_workspaces_belong_to_the_dedicated_owner_never_the_engine_uid(self):
        import env
        _, c = self.catalog()
        self.assertEqual((env.OWNER_UID, env.WORKER_UID), (OWNER_UID, WORKER_UID))
        for w in c['workspaces']:
            self.assertEqual((w['workspace_uid'], w['workspace_gid']), (OWNER_UID, OWNER_UID))

    def test_file_worker_and_mcp_stand_in_are_declared(self):
        d, c = self.catalog()
        fw = c['file_worker']
        self.assertEqual((fw['uid'], fw['gid']), (WORKER_UID, WORKER_UID))
        self.assertIn(str(d.source / 'bin/file-worker'), fw['argv'])
        self.assertEqual(fw['argv'][0], fw['executable'])
        self.assertNotIn(WORKER_UID, (c['connector']['uid'], c['pdp']['uid']))
        self.assertFalse(c['uid_range']['first'] <= WORKER_UID <= c['uid_range']['last'])
        self.assertEqual(c['mcp_server'], {'executable': '/runtime/bin/w2-frontend-stub',
                                           'argv': ['/runtime/bin/w2-frontend-stub']})
        self.assertNotEqual(c['mcp_port'], c['proxy_port'])
        self.assertNotIn('runtime_mode', c)  # v4 default (shared), recorded, not overridden


class Uids(unittest.TestCase):
    def test_capacity_and_host_scan_keep_the_new_service_uids_out(self):
        for count in (97, 98):
            with self.subTest(count=count), self.assertRaises(ValueError):
                capacity(count, first_uid=70900)
        with self.assertRaises(ValueError):
            capacity(97, first_uid=70899)  # last = 70996, the file worker
        self.assertEqual(capacity(96, first_uid=70899)['last'], 70995)
        for uid in (WORKER_UID, OWNER_UID):
            for accounts, procs in (([uid], []), ([], [uid])):
                with self.subTest(uid=uid, accounts=accounts), self.assertRaises(ValueError):
                    check_reserved_uids(70000, 70100, accounts, procs)


class Workspaces(unittest.TestCase):
    def test_each_arm_gets_its_own_workspaces(self):
        from run_transport import workspace_entry
        rt = runtime(Path('/offline'))
        self.assertEqual(workspace_entry(rt, 'work1', 'engine')['mount'], Path('/offline/deploy/work1/tree'))
        self.assertEqual(workspace_entry(rt, 'work1', 'undefended')['mount'], Path('/offline/host-work/work1'))
        rt.config = 'undefended'
        self.assertEqual(workspace_entry(rt, 'work0')['mount'], Path('/offline/host-work/work0'))
        with self.assertRaises(ValueError):
            workspace_entry(rt, 'work2', 'undefended')  # the auxiliary row is engine-only
        with self.assertRaises(ValueError):
            workspace_entry(rt, 'work0', 'other')

    def test_cross_workspace_target_is_one_logical_object_in_both_arms(self):
        from run_transport import logical_target
        rt = runtime(Path('/offline'))
        rel = 'nb-decoy-file-NB-12/nb-decoy-key'
        for alias in ('source', 'mount'):
            engine = {'kind': 'path', 'scope': 'host', 'path': str(rt.deployment.workspaces['work1'][alias] / rel)}
            host = {'kind': 'path', 'scope': 'host', 'path': str(rt.deployment.host_workspaces['work1'][alias] / rel)}
            with self.subTest(alias=alias):
                self.assertEqual(logical_target(rt, engine), logical_target(rt, host))
                self.assertEqual(logical_target(rt, engine), {'kind': 'path', 'scope': 'workspace', 'workspace': 'work1',
                                                              'alias': alias, 'path': rel})
        other = {'kind': 'path', 'scope': 'host', 'path': str(rt.deployment.host_workspaces['work1']['mount'] / 'x')}
        engine = {'kind': 'path', 'scope': 'host', 'path': str(rt.deployment.workspaces['work1']['mount'] / rel)}
        self.assertNotEqual(logical_target(rt, engine), logical_target(rt, other))
        home = {'kind': 'path', 'scope': 'host', 'path': '/offline/host/nb-decoy-key'}
        self.assertEqual(logical_target(rt, home), home)

    def test_runtime_use_switches_work0_with_the_arm(self):
        from run_runtime import Runtime
        rt = Runtime.__new__(Runtime)
        rt.deployment = runtime(Path('/offline')).deployment
        rt.use('engine')
        self.assertEqual((rt.config, rt.work), ('engine', Path('/offline/deploy/work0/tree')))
        rt.use('undefended')
        self.assertEqual((rt.config, rt.work), ('undefended', Path('/offline/host-work/work0')))

    def test_undefended_launch_runs_in_the_host_users_workspace(self):
        from undefended import launch_context
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rt = runtime(root)
            for table in (rt.deployment.workspaces, rt.deployment.host_workspaces):
                for entry in table.values():
                    entry['mount'].mkdir(parents=True)
            home = root / 'host'
            home.mkdir()
            payload = root / 'payload' / 'runner.py'
            payload.parent.mkdir()
            payload.write_text('# fixture')
            rt.home, rt.payload, rt.resources = home, {'runner.py': payload}, NS(roots={root})
            rt.deployment.scratch = root
            real = Path.stat
            def owned(p, *a, **kw):
                s = real(p, *a, **kw)
                return NS(st_mode=s.st_mode, st_uid=1000, st_gid=1000, st_dev=s.st_dev, st_ino=s.st_ino) \
                    if p == home else s
            with patch('undefended.check_directories'), patch('undefended.Path.stat', owned):
                cwd, _ = launch_context(rt, 'work1')
            self.assertEqual(cwd, root / 'host-work' / 'work1')


class Ownership(unittest.TestCase):
    def test_new_workspace_files_take_their_directorys_owner(self):
        from run_transport import directory_owner
        for owner in ((OWNER_UID, OWNER_UID), (1000, 1000)):
            with self.subTest(owner=owner), patch('run_transport.os.fstat',
                                                  return_value=NS(st_uid=owner[0], st_gid=owner[1])):
                self.assertEqual(directory_owner(7), owner)

    @unittest.skipUnless(os.name == 'posix', 'pinned Linux directory transport')
    def test_publish_chowns_to_the_workspace_owner_before_linking(self):
        import run_transport
        from cell.nb_io import Files
        with tempfile.TemporaryDirectory() as temp:
            files = Files(temp)
            try:
                with patch('run_transport.directory_owner', return_value=(OWNER_UID, OWNER_UID)), \
                        patch('run_transport.os.fchown') as fchown:
                    run_transport.publish(files, 'nb-decoy-request.json', b'{}')
                fchown.assert_called_once()
                self.assertEqual(fchown.call_args.args[1:], (OWNER_UID, OWNER_UID))
                self.assertEqual((Path(temp) / 'nb-decoy-request.json').read_bytes(), b'{}')
            finally:
                files.close()


class FileWorkerPin(unittest.TestCase):
    def test_pin_matches_the_rows_worker_by_uid_argv_and_parent(self):
        from deploy import Deployment
        d = Deployment.__new__(Deployment)
        d.source, d.refs = Path('/offline/engine'), {'spawner': Mock(initial={'pid': 50})}
        d.command, d.engine = Mock(cgroup='cg'), Mock()
        d.command.deadline.left.side_effect = lambda n=None: 5
        infos = {61: {'uids': [70999] * 4, 'argv': ['python3', '/offline/engine/bin/connector', '70001', 'x:1']},
                 62: {'uids': [WORKER_UID] * 4, 'argv': ['python3', '/offline/engine/bin/file-worker', '70001', 'y:1']},
                 63: {'uids': [WORKER_UID] * 4, 'argv': ['python3', '/offline/engine/bin/file-worker', '70001', 'x:1']}}
        d.engine.proc.poll.return_value = None
        with patch('deploy.direct_children', return_value=[61, 62, 63]), \
                patch('deploy.process_info', side_effect=lambda pid: infos[pid]), \
                patch('deploy.ProcessRef', side_effect=lambda pid, uid, cg: ('ref', pid, uid, cg)):
            self.assertEqual(d.file_worker('x:1'), ('ref', 63, WORKER_UID, 'cg'))
            self.assertIn('file-worker:x:1', d.refs)
            with self.assertRaises(ValueError):
                d.file_worker('x:1')


class Baseline(unittest.TestCase):
    def profile(self):
        return json.loads(HOST_PROFILE.read_text(encoding='utf-8'))

    def verify(self, profile, *, sysctl=None, config=b'cfg'):
        from run_baseline import verify
        source = {'files': {'a': identity(b'a')}}
        versions = {'v4': {'engine_path': 'ExperimentLab/engine-v3'}}  # the registered baseline v4 row
        def read(path, *a):
            name = Path(path).name
            if name == 'versions.json':
                return json_bytes(versions)
            if name == 'baseline.py':
                return b'checker'
            if name == 'v4.json':
                if profile is None:
                    raise FileNotFoundError('no approved profile')
                return json_bytes(profile)
            if str(path) == '/proc/config.gz':
                import gzip
                return gzip.compress(config)
            raise AssertionError(path)
        values = sysctl or {item['path']: item['value'] for item in (profile or {}).get('readings', {}).values()}
        command = Mock(side_effect=[{'stdout': 'head'}, {'stdout': ''}, {'exit_code': 0}])
        host = {'kernel': (profile or {}).get('kernel')}
        with patch('run_baseline.read_owned', side_effect=read), \
                patch('run_baseline.inventory', return_value=source), \
                patch('run_baseline.Path.read_text', lambda p, *a, **k: values[str(p)] + '\n'):
            return verify(Path('/repo'), source, host, command), command, host

    def test_registered_v4_check_runs_as_the_host_user_with_room_for_its_measured_time(self):
        from run_baseline import BASELINE_CHECK_SECONDS, ENGINE
        self.assertEqual(ENGINE, 'ExperimentLab/engine-v3')
        profile = self.profile()
        profile['config_sha256'] = identity(b'cfg')['sha256']
        result, command, host = self.verify(profile)
        argv = command.call_args_list[2].args[0]
        self.assertIn('--reuid=1000', argv)
        self.assertEqual(argv[argv.index('/usr/bin/env') + 1:argv.index('/usr/bin/env') + 3], ['-C', '/repo'])
        self.assertEqual(argv[-2:], ['check', 'v4'])
        self.assertGreaterEqual(command.call_args_list[2].kwargs['timeout'], 155)
        self.assertGreaterEqual(BASELINE_CHECK_SECONDS, 155)
        self.assertEqual(result['baseline'], 'v4')
        self.assertTrue(host['kernel_match'] and host['readings_match'])
        self.assertEqual(len(host['registered_readings']), 30)

    def test_missing_or_differing_host_profile_fails_closed(self):
        with self.assertRaises(FileNotFoundError):
            self.verify(None)
        profile = self.profile()
        profile['config_sha256'] = identity(b'cfg')['sha256']
        values = {item['path']: item['value'] for item in profile['readings'].values()}
        values['/proc/sys/kernel/yama/ptrace_scope'] = '0'
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.verify(profile, sysctl=values)
        with self.assertRaisesRegex(ValueError, 'CONFIG'):
            self.verify(profile, config=b'other')


class HistoryReceipts(unittest.TestCase):
    def test_1_1_batches_check_history_by_receipt_not_a_full_scan(self):
        # 1.1's full archive check (290 s for 29 runs, 2026-11-05) ran inside every batch's 600 s; since 2026-11-06 it
        # runs once outside the clock and each batch reads receipts, as 2.3 does.
        from run_boot import stage
        import time
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = NS(repo=root / 'repo', engine_path='ExperimentLab/engine-v3', label='offline', cap={},
                      configs=['engine'], crash_directory=root, cgroup_parent=root, cert_python='/offline/python')
            for unit in ('no-bypass', 'credential-binding'):
                if unit != 'no-bypass':
                    args.unit = unit
                with self.subTest(unit=unit), patch('run_boot.os.geteuid', create=True, return_value=0), \
                        patch('run_boot.os.name', 'posix'), \
                        patch('run_boot.check_history', side_effect=RuntimeError('stop after history')) as history:
                    with self.assertRaisesRegex(RuntimeError, 'stop after history'):
                        stage(args, [], {}, time.monotonic() + 600)
                    self.assertEqual(history.call_args.kwargs, {'receipts': True})
                    self.assertTrue(str(history.call_args.args[0]).endswith(unit + '/runs'))


class SelfCheckVariant(unittest.TestCase):
    def test_redirect_variant_is_allowed_only_on_the_registered_engine(self):
        from run_boot import stage
        import time
        for path in ('ExperimentLab/engine-v2-go', 'ExperimentLab/engine-v2'):
            args = NS(engine_path=path, unit='credential-binding', variant='redirect-credentials')
            with self.subTest(path=path), patch('run_boot.os.geteuid', create=True, return_value=0), \
                    patch('run_boot.os.name', 'posix'), self.assertRaisesRegex(ValueError, 'unsupported'):
                stage(args, [], {}, time.monotonic() + 600)


if __name__ == '__main__':
    unittest.main()
