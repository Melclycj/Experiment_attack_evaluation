"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zlib
from unittest.mock import patch
from file_cases import FileCase
from file_tree import FileTree, git_repository
from judge import classify_target
from runner import Context
from test_cell_runner import MemoryFiles
from nb_file_actions import action, control
from nb_file_spec import KINDS, keys
from fourb_fixtures import temporary_runtime, prepare, closed, simulated_operation


@unittest.skipUnless(os.name=='posix','Linux pinned temporary decoys only; all execution mocked')
class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='nb-decoy-4b-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.rt=temporary_runtime(self.root)
        for name in ('file_tree.os.fchown','file_tree.os.chown'):
            p=patch(name);p.start();self.addCleanup(p.stop)
        for name in ('subprocess.Popen','socket.socket','os.system'):
            p=patch(name,side_effect=AssertionError('no processes/listeners'));p.start();self.addCleanup(p.stop)

    def adapter(self,attack='NB-04',config='engine',branch=None):
        a=FileCase(self.rt,attack);p=prepare(a,config,branch)
        self.addCleanup(lambda:a.restore(p) if a.trees else None)
        return a,p

    def observations(self,a,p):
        files=MemoryFiles()
        ctx=Context(p['request'],files,cwd='/work' if p['config']=='engine' else str(self.rt.work))
        ctx.offline_work=self.rt.work
        with patch('nb_file_actions.operation',side_effect=simulated_operation),patch.dict(os.environ,
             {'HOME':str(self.rt.home) if p['config']=='undefended' else '/tmp'}):
            self.assertTrue(control(ctx,a.attack));ctx.phase='action';action(ctx,a.attack)
        ctx.record.update(complete=True,control_ok=True)
        return ctx.record,files.values

    def facts(self,a,p,obs,caps,w=None):
        return a.observe(p,obs,caps,w or closed(p))

    def verdict(self,fact):
        copy=dict(fact);copy.pop('prerequisite_ok')
        return classify_target(target_verified=True,complete=True,**copy)['outcome']

    def test_every_file_case_host_judge_both_configs_and_restoration(self):
        for attack in KINDS:
            for cfg in ('engine','undefended'):
                for branch in (('source','mount') if attack=='NB-15' else (None,)):
                    with self.subTest(attack=attack,config=cfg,branch=branch):
                        a,p=self.adapter(attack,cfg,branch);obs,caps=self.observations(a,p)
                        facts=self.facts(a,p,obs,caps)
                        self.assertEqual(set(facts),{branch} if branch else set(keys(attack)))
                        self.assertEqual({self.verdict(f) for f in facts.values()},
                                         {'blocked' if cfg=='engine' else 'succeeded'},facts)
                        self.assertEqual({f['prerequisite_ok'] for f in facts.values()},{cfg=='undefended'})
                        a.restore(p);self.assertFalse(self.rt.targets.items)
                        self.assertFalse(list(self.rt.work.glob('nb-decoy-file-*')))

    def test_attack_sentinels_are_not_disclosed_in_cell_request(self):
        a,p=self.adapter('NB-28')
        raw=json.dumps(p['request'])
        self.assertTrue(all(value not in raw for value in p['tokens'].values()))
        self.assertEqual(len(set(p['tokens'].values())),6)

    def test_fresh_markers_repeat_without_changing_paths_or_action(self):
        a,p=self.adapter();tokens=p['tokens'];targets=p['targets'];a.restore(p)
        second=prepare(a)
        self.assertNotEqual(tokens,second['tokens']);self.assertEqual(targets,second['targets'])

    def test_missing_any_target_is_rejected_before_cell(self):
        a,p=self.adapter('NB-12');p['targets']['source']['path']+='/wrong'
        with self.assertRaises(ValueError):self.rt.targets.verify(p['targets'])

    def test_other_successful_path_cannot_mask_missing_capture(self):
        a,p=self.adapter('NB-12','undefended');obs,caps=self.observations(a,p)
        obs['captures']=[c for c in obs['captures'] if not(c['phase']=='action' and c['label']=='mount')]
        f=self.facts(a,p,obs,caps)
        self.assertEqual(self.verdict(f['source']),'succeeded');self.assertEqual(self.verdict(f['mount']),'invalid')

    def test_old_marker_or_forged_success_boolean_never_proves_read(self):
        a,p=self.adapter();obs,caps=self.observations(a,p);obs['outcome']='succeeded'
        f=self.facts(a,p,obs,caps)['file'];self.assertFalse(f['external_effect'])
        self.assertEqual(self.verdict(f),'blocked')

    def test_broken_control_cannot_become_blocked(self):
        a,p=self.adapter();obs,caps=self.observations(a,p)
        obs['observed']=[x for x in obs['observed'] if x['phase']!='control']
        self.assertEqual(self.verdict(self.facts(a,p,obs,caps)['file']),'invalid')

    def test_capture_receipt_tampering_invalid(self):
        a,p=self.adapter();obs,caps=self.observations(a,p);obs['captures'][0]['sha256']='0'*64
        self.assertEqual(self.verdict(self.facts(a,p,obs,caps)['file']),'invalid')

    def test_permission_barrier_not_counted_as_expected_file_view(self):
        a,p=self.adapter();obs,caps=self.observations(a,p)
        next(x for x in obs['observed'] if x['phase']=='action')['values']['errno']=errno.EACCES
        f=self.facts(a,p,obs,caps)['file']
        self.assertEqual(self.verdict(f),'invalid');self.assertEqual(f['observed_mechanism'],'file-permissions')

    def test_success_with_wrong_object_invalid(self):
        a,p=self.adapter('NB-04','undefended');obs,caps=self.observations(a,p)
        next(x for x in obs['observed'] if x['phase']=='action')['values']['identity']['ino']+=1
        f=self.facts(a,p,obs,caps)['file'];self.assertTrue(f['external_effect'])
        self.assertEqual(self.verdict(f),'invalid')

    def test_upstream_body_scanned_as_bytes_not_base64_text(self):
        a,p=self.adapter();obs,caps=self.observations(a,p)
        w=closed(p,[{'payload_base64':base64.b64encode(p['tokens']['file'].encode()).decode()}])
        f=self.facts(a,p,obs,caps,w)['file']
        self.assertTrue(f['external_effect']);self.assertEqual(self.verdict(f),'succeeded')

    def test_shared_alias_token_upstream_hit_does_not_prove_both_paths(self):
        a,p=self.adapter('NB-12');obs,caps=self.observations(a,p)
        w=closed(p,[{'payload_base64':base64.b64encode(p['tokens']['source'].encode()).decode()}])
        facts=self.facts(a,p,obs,caps,w)
        self.assertEqual({self.verdict(f) for f in facts.values()},{'invalid'})
        self.assertTrue(all(f['external_effect'] for f in facts.values()))
        self.assertTrue(all('not-attributable' in f['invalid_reason'] for f in facts.values()))

    def test_read_target_changed_is_invalid_not_a_read_success(self):
        a,p=self.adapter();obs,caps=self.observations(a,p)
        Path(p['targets']['file']['path']).write_bytes(b'changed')
        self.assertEqual(self.verdict(self.facts(a,p,obs,caps)['file']),'invalid')

    def test_write_external_effect_retained_if_diagnostic_missing(self):
        a,p=self.adapter('NB-10','undefended');obs,caps=self.observations(a,p)
        obs['observed']=[x for x in obs['observed'] if x['phase']!='action']
        f=self.facts(a,p,obs,caps)['file'];self.assertTrue(f['external_effect'])
        self.assertEqual(self.verdict(f),'invalid')

    def test_new_file_in_decoy_home_invalidates_and_cleanup_retains_unknown(self):
        a,p=self.adapter('NB-07');obs,caps=self.observations(a,p)
        unexpected=a.trees[1].root/'unexpected';unexpected.write_bytes(b'fixture')
        self.assertEqual(self.verdict(self.facts(a,p,obs,caps)['file']),'invalid')
        with self.assertRaisesRegex(RuntimeError,'restoration failed'):a.restore(p)
        self.assertTrue(unexpected.exists())

    def test_capture_scanner_never_follows_preseeded_symlink(self):
        a,p=self.adapter('NB-03');obs,caps=self.observations(a,p)
        self.assertEqual(self.verdict(self.facts(a,p,obs,caps)['file']),'blocked')

    def test_home_guard_mismatch_is_invalid_per_path(self):
        a,p=self.adapter('NB-28','undefended');obs,caps=self.observations(a,p)
        next(x for x in obs['observed'] if x['label']=='home-enumeration')['values']['performed']=False
        self.assertEqual({self.verdict(f) for f in self.facts(a,p,obs,caps).values()},{'invalid'})

    def test_unclosed_or_wrong_nonce_window_is_rejected(self):
        a,p=self.adapter();obs,caps=self.observations(a,p);w=closed(p);w['end']['attempt']='wrong'
        with self.assertRaises(ValueError):self.facts(a,p,obs,caps,w)

    def test_prepare_failure_restores_created_subtrees(self):
        a=FileCase(self.rt,'NB-04')
        with patch.object(self.rt.targets,'add_path',side_effect=ValueError('registry failure')):
            with self.assertRaisesRegex(ValueError,'registry failure'):prepare(a)
        self.assertFalse(a.trees);self.assertFalse(list(self.rt.work.glob('nb-decoy-file-*')))

    def test_nb15_cannot_collapse_alias_writes_into_one_row(self):
        a=FileCase(self.rt,'NB-15')
        with self.assertRaisesRegex(ValueError,'separately closed'):prepare(a)

    def test_source_mount_mismatch_is_preparation_failure(self):
        alternate=self.root/'different-source';alternate.mkdir()
        self.rt.deployment.workspaces['work1']['source']=alternate
        a=FileCase(self.rt,'NB-12')
        with self.assertRaisesRegex(ValueError,'not aliases'):prepare(a)

    def test_existing_tree_never_overwritten_or_adopted(self):
        path=self.rt.work/'nb-decoy-file-NB-04';path.mkdir();(path/'keep').write_bytes(b'original')
        a=FileCase(self.rt,'NB-04')
        with self.assertRaises(FileExistsError):prepare(a)
        self.assertEqual((path/'keep').read_bytes(),b'original')

    def test_owned_leaf_replaced_by_symlink_unlinks_link_not_victim(self):
        tree=FileTree(self.rt,self.rt.work,'nb-decoy-tree');target=tree.write('owned',b'x')
        victim=self.root/'victim';victim.write_bytes(b'keep');target.unlink();target.symlink_to(victim)
        tree.restore();self.assertEqual(victim.read_bytes(),b'keep')

    def test_replaced_owned_directory_is_retained(self):
        tree=FileTree(self.rt,self.rt.work,'nb-decoy-tree');tree.directory('child')
        (tree.root/'child').rename(tree.root/'old-child');(tree.root/'child').mkdir()
        try:
            with self.assertRaisesRegex(ValueError,'replaced'):tree.restore()
        finally:tree.close()

    def test_live_row_prevents_removal_and_releases_pins(self):
        from types import SimpleNamespace
        a,p=self.adapter();trees=list(a.trees)
        self.rt.rows=[SimpleNamespace(workspace='work0',closed=False)]
        with self.assertRaisesRegex(RuntimeError,'still live'):a.restore(p)
        self.assertTrue(all(t.root.exists() and t.closed for t in trees))
        self.assertTrue(Path(p['targets']['file']['path']).exists())

    def test_dispose_is_read_only_not_a_restoration_claim(self):
        a,p=self.adapter();trees=list(a.trees)
        a.dispose();a.dispose()
        self.assertTrue(all(t.root.exists() and t.closed for t in trees))
        with self.assertRaisesRegex(RuntimeError,'closed pins'):a.restore(p)

    def test_partial_constructor_failure_removes_only_new_empty_directory(self):
        with patch('file_tree.os.fchown',side_effect=OSError('injected chown failure')):
            with self.assertRaisesRegex(OSError,'chown failure'):
                FileTree(self.rt,self.rt.work,'nb-decoy-partial')
        self.assertFalse((self.rt.work/'nb-decoy-partial').exists())

    def test_read_effect_retained_when_control_capture_is_missing(self):
        a,p=self.adapter('NB-04','undefended');obs,caps=self.observations(a,p)
        obs['captures']=[c for c in obs['captures'] if c['phase']!='control']
        f=self.facts(a,p,obs,caps)['file'];self.assertTrue(f['external_effect'])
        self.assertEqual(self.verdict(f),'invalid')

    def test_git_fixture_commit_message_object_hash_and_owner_model(self):
        tree=FileTree(self.rt,self.rt.work,'nb-decoy-git')
        try:
            path=git_repository(tree,'repo','nb-decoy-test-marker')
            oid=(path/'.git/refs/heads/main').read_text().strip()
            raw=zlib.decompress((path/'.git/objects'/oid[:2]/oid[2:]).read_bytes())
            self.assertEqual(hashlib.sha1(raw).hexdigest(),oid)
            self.assertIn(b'\n\nnb-decoy-test-marker\n',raw)
            self.assertEqual((path/'.git/HEAD').read_bytes(),b'ref: refs/heads/main\n')
        finally:tree.restore()
