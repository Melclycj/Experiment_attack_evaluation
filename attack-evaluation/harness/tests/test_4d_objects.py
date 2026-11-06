"""这是 1.1 隔离论证的验证测试：4d 临时文件判官及故障恢复；不启动外部进程。"""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from types import SimpleNamespace
from engine_cases import EngineCase
from engine_objects import EngineFile
from engine_observe import mirror_allowed
from foura_fixtures import runtime
from fourd_fixtures import seed,Ref
from decoys import prefix_changed


@unittest.skipUnless(os.name=='posix','pinned Linux temporary file metadata; no engine')
class ObjectTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='nb-decoy-4d-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.rt=runtime(self.root);self.paths=seed(self.rt,self.root)
        self.rt.support=Mock();self.rt.rows=[]
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('run_transport.os.fchown'))
        self.stack.enter_context(patch('engine_cases.inspect_listener',side_effect=lambda ref,t:{'listening':True,'target':t,'inode':901}))
    def adapter(self,key,config='engine'):
        a=EngineCase(self.rt,key);p=a.prepare(config,1,a.contract());return a,p

    def test_dual_credential_registered_with_different_fresh_sentinels(self):
        a,p=self.adapter('NB-20')
        try:
            self.assertNotEqual(p['tokens']['truth'],p['tokens']['metadata'])
            for key in ('truth','metadata'):
                self.assertIn(p['tokens'][key].encode(),a.files[key].original)
                self.assertNotIn(p['tokens'][key],json.dumps(p['parameters']))
                self.assertEqual(p['before']['targets'][key]['uid'],1000)
                self.assertEqual(p['before']['targets'][key]['mode'],0o600)
        finally:a.restore(p)
        self.assertEqual(self.rt.targets.items,{})

    def test_one_credential_record_shared_by_both_configurations(self):
        # engine-v2-go names the truth file by a generation it never reuses within a run, so a second registration
        # would move the target; both configurations of the pair use the batch's single registration
        a,p=self.adapter('NB-20');one=p['tokens'];targets=p['targets'];a.restore(p)
        calls=self.rt.deployment.admin.credential.call_count
        q=a.prepare('undefended',1,a.contract())
        try:
            self.assertEqual(q['tokens'],one);self.assertEqual(q['targets'],targets)
            self.assertEqual(self.rt.deployment.admin.credential.call_count,calls)
            for key in ('truth','metadata'):self.assertIn(one[key].encode(),a.files[key].original)
        finally:a.restore(q)

    def test_registration_failure_restores_temporary_controls(self):
        self.rt.deployment.admin.credential.side_effect=ValueError('registration refused')
        a=EngineCase(self.rt,'NB-20')
        with self.assertRaises(ValueError):a.prepare('engine',1,a.contract())
        self.assertFalse(list(self.rt.work.glob('nb-decoy-*')));self.assertFalse(a.files)

    def test_missing_second_credential_closes_first_pin(self):
        original=self.rt.deployment.admin.credential.side_effect
        def broken(*args):original(*args);(self.paths['credentials']/'nb-decoy-account.json').unlink()
        self.rt.deployment.admin.credential.side_effect=broken
        a=EngineCase(self.rt,'NB-20')
        with self.assertRaises(FileNotFoundError):a.prepare('engine',1,a.contract())
        self.assertEqual(self.rt.targets.items,{});self.assertFalse(a.files)

    def test_e09_prefix_archive_before_any_attack_and_append_not_effect(self):
        a,p=self.adapter('NB-22')
        try:
            before=a.files['audit'].original
            self.assertIn('audit',p['before']['backups'])
            with self.paths['e09'].open('ab') as f:f.write(b'new audit event\n')
            after,_=a.files['audit'].read();self.assertFalse(prefix_changed(before,after))
        finally:a.restore(p)
        self.assertTrue(self.paths['e09'].read_bytes().endswith(b'new audit event\n'))

    def test_truncated_audit_is_not_rewritten_by_restore(self):
        a,p=self.adapter('NB-22');before=a.files['audit'].original
        self.paths['e09'].write_bytes(b'fake\n')
        self.assertTrue(prefix_changed(before,a.files['audit'].read()[0]))
        a.restore(p);self.assertEqual(self.paths['e09'].read_bytes(),b'fake\n')

    def test_empty_audit_is_invalid_before_start(self):
        self.paths['e09'].write_bytes(b'')
        with self.assertRaisesRegex(ValueError,'empty E-09'):self.adapter('NB-22')
        self.assertEqual(self.rt.targets.items,{})

    def test_audit_preservation_failure_prevents_returning_prepared(self):
        self.rt.evidence.raw.side_effect=OSError('out of evidence budget')
        a=EngineCase(self.rt,'NB-22')
        with self.assertRaisesRegex(RuntimeError,'out of evidence budget; recovery:') as raised:
            a.prepare('undefended',1,a.contract())
        self.assertIsInstance(raised.exception.__cause__,OSError)
        self.assertFalse(a.files)

    def test_mirror_restore_retains_original_inode_and_bytes(self):
        a,p=self.adapter('NB-21');original=a.files['mirror'].original;s=self.paths['mirror'].stat()
        self.paths['mirror'].write_bytes(b'changed')
        a.restore(p)
        self.assertEqual(self.paths['mirror'].read_bytes(),original)
        self.assertEqual(self.paths['mirror'].stat().st_ino,s.st_ino)

    def test_replaced_mirror_is_not_followed_or_restored(self):
        a,p=self.adapter('NB-21');foreign=self.root/'unrelated';foreign.write_bytes(b'keep')
        self.paths['mirror'].unlink();self.paths['mirror'].symlink_to(foreign)
        with self.assertRaisesRegex(RuntimeError,'recovery failed'):a.restore(p)
        self.assertEqual(foreign.read_bytes(),b'keep')

    def test_file_pin_rejects_wrong_owner_mode_and_symlink(self):
        for mode in (0o644,0o666,0o400):
            self.paths['e09'].chmod(mode)
            # An unprivileged O_RDWR open of 0400 fails in the kernel before
            # fstat validates mode; root reaches the explicit ValueError instead.
            expected = (ValueError, PermissionError) if mode == 0o400 else ValueError
            with self.subTest(mode=mode),self.assertRaises(expected) as rejected:
                self.reject_pin()
            if isinstance(rejected.exception, PermissionError):
                self.assertEqual(rejected.exception.errno, errno.EACCES)
        self.paths['e09'].chmod(0o600);self.paths['e09'].unlink();self.paths['e09'].symlink_to(self.paths['mirror'])
        with self.assertRaises(OSError):EngineFile(self.rt,self.paths['e09'])

    def reject_pin(self):
        # Failed acquisition must close both the file and parent directory pins.
        close = EngineFile.close
        with patch.object(EngineFile, 'close', autospec=True, side_effect=close) as called:
            try:
                EngineFile(self.rt, self.paths['e09'])
            finally:
                called.assert_called_once()
                obj = called.call_args.args[0]
                self.assertIsNone(obj.fd)
                if obj.parent is not None:
                    self.assertIsNone(obj.parent.fd)

    def test_wrong_uid_is_rejected_without_changing_fixture_ownership(self):
        # Simulate the metadata only; do not chown a fixture to a foreign user.
        real_fstat = os.fstat
        inode = self.paths['e09'].stat().st_ino
        def wrong_uid(fd):
            value = real_fstat(fd)
            if value.st_ino == inode:
                fields = list(value); fields[4] = 1001
                return os.stat_result(fields)
            return value
        before = self.paths['e09'].read_bytes()
        with patch('engine_objects.os.fstat', side_effect=wrong_uid), self.assertRaisesRegex(ValueError, 'uid 1000'):
            self.reject_pin()
        self.assertEqual(self.paths['e09'].stat().st_uid, 1000)
        self.assertEqual(self.paths['e09'].read_bytes(), before)

    def test_hardlinked_engine_file_is_rejected_and_pins_closed(self):
        os.link(self.paths['e09'], self.root / 'nb-decoy-e09-alias')
        with self.assertRaisesRegex(ValueError, 'single-link'):
            self.reject_pin()

    def test_kernel_permission_denial_closes_parent_pin_even_as_root(self):
        real_open = os.open
        def denied(name, flags, *args, **kwargs):
            if name == self.paths['e09'].name:
                raise PermissionError(errno.EACCES, 'offline injected denial', name)
            return real_open(name, flags, *args, **kwargs)
        with patch('engine_objects.os.open', side_effect=denied), self.assertRaises(PermissionError):
            self.reject_pin()

    def test_live_row_defers_file_mutation_but_pidfd_recovery_still_runs(self):
        a,p=self.adapter('NB-21');original=a.files['mirror'].original
        self.paths['mirror'].write_bytes(b'changed');ref=Ref(99,1000);ref.value['state']='T';a.processes={'core':ref}
        self.rt.rows=[SimpleNamespace(workspace='work0',closed=False)]
        with patch('upstream.wait_for',side_effect=lambda cmd,predicate,**kw:predicate()),self.assertRaises(RuntimeError):a.restore(p)
        self.assertEqual(ref.read()['state'],'S');self.assertEqual(self.paths['mirror'].read_bytes(),b'changed')

    def test_evidence_failure_does_not_prevent_process_recovery(self):
        a=EngineCase(self.rt,'NB-23');ref=Ref(99,1000);ref.value['state']='T';a.processes={'core':ref}
        self.rt.evidence.raw.side_effect=OSError('no room')
        with patch('upstream.wait_for',side_effect=lambda cmd,predicate,**kw:predicate()),self.assertRaises(OSError):a.restore({})
        self.assertEqual(ref.read()['state'],'S')

    def test_dispose_recovers_after_expired_attempt_skipped_restore(self):
        a=EngineCase(self.rt,'NB-23');ref=Ref(99,1000);ref.value['state']='T';a.processes={'core':ref}
        with patch('upstream.wait_for',side_effect=lambda cmd,predicate,**kw:predicate()):a.dispose()
        self.assertEqual(ref.read()['state'],'S');self.assertEqual(a.processes,{})
