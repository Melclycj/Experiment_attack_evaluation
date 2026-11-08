"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from common import identity, json_bytes
from run_transport import CollectionError, collect, prepare_request, request, synchronize, OwnedTargets
from cell.nb_contract import stem
from batch_fixtures import cases

@unittest.skipUnless(os.name == 'posix', 'Linux pinned workspace transport')
class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.req = request('20261031T000000Z-test','engine',cases()[0],1,
                           {'targets': {'x': {'kind':'path','scope':'work','path':'nb-decoy-file'}},'parameters':{}})
        self.chown = patch('run_transport.os.fchown'); self.chown.start(); self.addCleanup(self.chown.stop)
        self.evidence = Mock()
        self.evidence.raw.side_effect = lambda data, suffix='json': {
            'file': 'raw-offline.' + suffix, **identity(data)}
    def record(self, **changes):
        data = {'v':1,'attempt':stem(self.req),'complete':True,'error':None,
                'control_ok':True,'captures':[], 'observed':[]}
        data.update(changes)
        (self.work/(stem(self.req)+'-observed.json')).write_bytes(json_bytes(data))
    def ready(self, nonce=None):
        data={'attempt':stem(self.req),'nonce':nonce or self.req['sync']['nonce'],'state':'sent'}
        (self.work/self.req['sync']['ready']).write_bytes(json_bytes(data))
    def test_roundtrip(self):
        prepare_request(self.work,self.req); self.record()
        observed,captures=collect(self.work,self.req,self.evidence)
        self.assertTrue(observed['complete']); self.assertEqual(captures,{})
    def test_missing_request(self):
        self.record()
        with self.assertRaisesRegex(CollectionError, 'FileNotFoundError'): collect(self.work,self.req,self.evidence)
    def test_missing_observation(self):
        prepare_request(self.work,self.req)
        with self.assertRaisesRegex(CollectionError, 'FileNotFoundError'): collect(self.work,self.req,self.evidence)
    def test_request_tamper(self):
        prepare_request(self.work,self.req); self.record()
        (self.work/'nb-request.json').write_bytes(json_bytes({**self.req,'repeat':2}))
        with self.assertRaises(ValueError): collect(self.work,self.req,self.evidence)
    def test_incomplete(self):
        prepare_request(self.work,self.req); self.record(complete=False)
        with self.assertRaises(ValueError): collect(self.work,self.req,self.evidence)
    def test_capture_digest(self):
        prepare_request(self.work,self.req)
        name=stem(self.req)+'-action-x.capture'; data=b'decoy-only'; (self.work/name).write_bytes(data)
        self.record(captures=[{'path':name,'phase':'action','bytes':len(data),'sha256':identity(data)['sha256']}])
        self.assertEqual(collect(self.work,self.req,self.evidence)[1][name], data)
    def test_wrong_capture_digest(self):
        prepare_request(self.work,self.req)
        name=stem(self.req)+'-action-x.capture'; (self.work/name).write_bytes(b'actual')
        self.record(captures=[{'path':name,'phase':'action','bytes':6,'sha256':'0'*64}])
        with self.assertRaises(ValueError): collect(self.work,self.req,self.evidence)
    def test_capture_symlink_rejected(self):
        prepare_request(self.work,self.req)
        name=stem(self.req)+'-action-x.capture'; (self.work/'source').write_bytes(b'decoy')
        (self.work/name).symlink_to(self.work/'source')
        self.record(captures=[{'path':name,'phase':'action','bytes':5,'sha256':identity(b'decoy')['sha256']}])
        with self.assertRaises(CollectionError): collect(self.work,self.req,self.evidence)
    def test_sync_missing(self):
        observe=Mock()
        self.assertIsNone(synchronize(self.work,self.req,'sent',observe)); observe.assert_not_called()
    def test_no_observation_no_release(self):
        self.ready()
        with self.assertRaises(ValueError): synchronize(self.work,self.req,'sent',lambda _: {})
        self.assertFalse((self.work/self.req['sync']['release']).exists())
    def test_wrong_nonce_no_release(self):
        self.ready('0'*48); observe=Mock()
        with self.assertRaises(ValueError): synchronize(self.work,self.req,'sent',observe)
        observe.assert_not_called()
    def test_observed_then_release(self):
        self.ready()
        fact=synchronize(self.work,self.req,'sent',lambda _: {'socket_table':'observed'})
        self.assertEqual(fact,{'socket_table':'observed'})
        self.assertTrue((self.work/self.req['sync']['release']).is_file())
    def test_preexisting_release_refused(self):
        (self.work/self.req['sync']['release']).write_bytes(b'old')
        with self.assertRaises(FileExistsError): prepare_request(self.work,self.req)

class TargetRegistryTests(unittest.TestCase):
    def runtime(self):
        return SimpleNamespace(work=Path('/tmp/nb-decoy-own/work'),
            resources=SimpleNamespace(roots={Path('/tmp/nb-decoy-own'):(1,2)}),
            deployment=SimpleNamespace(refs={}))
    def test_prefix_not_ownership(self):
        targets=OwnedTargets(self.runtime())
        with self.assertRaises(ValueError): targets.add_path('x',{'kind':'path','scope':'host','path':'/tmp/nb-decoy-other/a'})
    def test_exact_identity_checked_again(self):
        targets=OwnedTargets(self.runtime()); value={'kind':'path','scope':'host','path':'/tmp/nb-decoy-own/a'}
        first={'exists':True,'dev':1,'ino':2,'uid':1000,'mode':384}
        with patch('run_transport.snapshot', side_effect=[first,{**first,'ino':3}]):
            targets.add_path('x',value)
            with self.assertRaises(ValueError): targets.verify({'x':value})
    def test_unregistered_target(self):
        with self.assertRaises(ValueError): OwnedTargets(self.runtime()).verify({'x':{}})
    def test_foreign_process_ref(self):
        with self.assertRaises(ValueError): OwnedTargets(self.runtime()).add_process('x',Mock())
    def test_foreign_listener_ref(self):
        with self.assertRaises(ValueError):
            OwnedTargets(self.runtime()).add_listener('x',{'kind':'inet','address':'127.0.0.1','port':23456},Mock(),Mock())
