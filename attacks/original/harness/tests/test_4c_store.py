"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from connection_store import ConnectionStore
from connection_endpoint import Endpoint
from connection_service import run
from common import json_bytes
from decoy_services import Journal
from foura_fixtures import NONCE


@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:1)()==0,
                     'Linux root-owned temporary evidence only; no listener/process')
class StoreTests(unittest.TestCase):
    def make(self, root):
        rt=SimpleNamespace(deployment=SimpleNamespace(scratch=root),resources=SimpleNamespace(roots={root}),evidence=Mock())
        return rt,ConnectionStore(rt,'nb-decoy-store')

    def test_exact_files_markers_cleaned_and_existing_directory_never_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);rt,s=self.make(root)
            try:
                s.write_config({'nonce':NONCE})
                with self.assertRaises(FileExistsError):ConnectionStore(rt,'nb-decoy-store')
                journal=Journal(s.root/'journal.jsonl',s.root/'nb-decoy-markers','attempt',NONCE)
                journal.receive(b'owned-request',{'uid':1000});journal.close()
                self.assertEqual(s.markers(),{'nb-decoy-0000':b'owned-request'})
                self.assertTrue(s.restore()['restored']);self.assertTrue(s.restore()['restored'])
                self.assertFalse(s.root.exists())
            finally:s.close()

    def test_marker_end_writes_no_file_and_restore_removes_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,s=self.make(Path(tmp))
            try:
                journal=Journal(s.root/'journal.jsonl',s.root/'nb-decoy-markers','attempt',NONCE)
                journal.receive(b'\0NB-END:'+NONCE.encode()+b'\n',{'uid':0});journal.close()
                self.assertEqual(s.markers(),{});self.assertTrue(s.restore()['restored'])
            finally:s.close()

    def test_unknown_child_retained_not_recursively_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,s=self.make(Path(tmp))
            try:
                (s.root/'foreign').write_bytes(b'keep')
                with self.assertRaisesRegex(ValueError,'unknown'):s.restore()
                self.assertEqual((s.root/'foreign').read_bytes(),b'keep')
            finally:s.close()

    def test_marker_symlink_never_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,s=self.make(Path(tmp));outside=Path(tmp)/'outside';outside.mkdir()
            try:
                (s.root/'nb-decoy-markers').symlink_to(outside,target_is_directory=True)
                with self.assertRaises(ValueError):s.markers()
                with self.assertRaises(ValueError):s.restore()
                self.assertTrue(outside.is_dir())
            finally:s.close()

    def test_closed_pins_cannot_claim_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,s=self.make(Path(tmp));s.close()
            with self.assertRaises(ValueError):s.restore()

    def test_malformed_truncated_journal_keeps_valid_candidate_and_raw_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            rt,s=self.make(Path(tmp));rt.evidence.raw.return_value={'file':'offline-raw'}
            try:
                row={'kind':'request','seq':0,'payload_base64':'bWFya2Vy','bytes':6}
                blob=json_bytes(row)+b'{partial'
                (s.root/'journal.jsonl').write_bytes(blob)
                e=Endpoint(rt,'nb-decoy-store',{'kind':'abstract','name':'nb-decoy-test'},'unix','attempt');e.store=s
                value=e.sample()
                self.assertEqual(value['entries'],[row]);self.assertIn('malformed',value['error'])
                rt.evidence.raw.assert_any_call(blob,'connections.jsonl')
            finally:s.close()

    def test_service_permissions_and_marker_only_behavior_without_socket(self):
        for owner,uid,mode in [('daemon',0,0o660),('user',1000,0o600)]:
            with tempfile.TemporaryDirectory() as tmp:
                _,s=self.make(Path(tmp));value={'kind':'path','scope':'host','path':str(s.root/'socket')}
                try:
                    s.write_config({'target':value,'wire':'unix','attempt':'attempt','secret':NONCE,
                                    'nonce':NONCE,'owner':owner,'markers':True})
                    listener=Mock();journal=Mock()
                    with patch('connection_service.bind_endpoint',return_value=(listener,value)),\
                         patch('connection_service.os.chown') as chown,patch('connection_service.os.chmod') as chmod,\
                         patch('connection_service.Journal',return_value=journal) as create,\
                         patch('connection_service.serve') as serve:
                        run(s.root,12)
                    chown.assert_called_once_with(value['path'],uid,1000)
                    chmod.assert_called_once_with(value['path'],mode)
                    serve.assert_called_once_with(listener,journal,seconds=12)
                    self.assertEqual(create.call_args.args[1],s.root/'nb-decoy-markers')
                    listener.close.assert_called_once();journal.close.assert_called_once()
                finally:s.close()

    def test_service_rejects_real_daemon_path_before_socket_bind(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,s=self.make(Path(tmp))
            try:
                s.write_config({'target':{'kind':'path','scope':'host','path':'/var/run/docker.sock'}})
                with patch('connection_service.bind_endpoint') as bind,self.assertRaises(ValueError):run(s.root,10)
                bind.assert_not_called()
            finally:s.close()
