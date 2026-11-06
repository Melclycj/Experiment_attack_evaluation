"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from cb_connector_boot import invocation, file_identity, LOG_LIMIT
from cb_measure import (ConnectorMeasurement, validate_ready, environment,
                        bounded_log, LIMIT)
from common import json_bytes
from commands import CaptureBudget


def fixture():
    source = Path('/tmp/nb-decoy-test/engine')
    target = str(source / 'bin/connector')
    ready = {'v':1,'pid':42,'ppid':40,'execution':'work0:1','row_uid':70000,
             'nonce':'a'*48,'uid':70999,'target':target,
             'argv':[target,'--library','/tmp/nb-decoy-test/library.so','70000','work0:1'],
             'logs':{k:{'name':'nb-decoy-work0-1-'+k,'dev':1,'ino':i,'mode':stat.S_IFREG}
                     for i,k in enumerate(('stdout','stderr'),1)},
             'production_fds':{str(i):{'dev':1,'ino':i+10,'mode':stat.S_IFSOCK} for i in (3,4)},
             'log_limit':LOG_LIMIT}
    info = {'pid':42,'ppid':40,'start_time':99,'uids':[70999]*4,'cgroup':'0::/nb-decoy-test\n',
            'argv':['/usr/bin/python3','-I','-B','/tmp/wrapper.py','/tmp/nb-decoy-logs',*ready['argv']]}
    return source, ready, info


class WrapperContract(unittest.TestCase):
    def test_original_arguments_not_rewritten(self):
        s,r,_ = fixture()
        root,target,args = invocation(['/tmp/nb-decoy-logs',*r['argv']])
        self.assertEqual(root,Path('/tmp/nb-decoy-logs'))
        self.assertEqual(target,s/'bin/connector')
        self.assertEqual(args,r['argv'][1:])

    def test_nondecoy_traversal_wrong_target_wrong_uid_rejected(self):
        _,r,_ = fixture()
        argv=['/tmp/nb-decoy-logs',*r['argv']]
        for index,value in ((0,'/tmp/real'),(0,'/tmp/../nb-decoy-logs'),(1,'/tmp/not-connector'),
                            (-1,'../bad'),(-2,'1000'),(-2,'wrong')):
            bad=argv.copy();bad[index]=value
            with self.subTest(value=value),self.assertRaises(ValueError):invocation(bad)

    def test_complete_ready_binds_parent_cgroup_reserved_uid_and_log_names(self):
        s,r,i=fixture()
        validate_ready(r,'nb-decoy-work0-1.ready',s,'0::/nb-decoy-test',40,i)
        for field,value in (('ppid',50),('pid',1),('uid',1000),('row_uid',1000),
                            ('execution','work0:2'),('target','/real/connector'),('nonce','x'),
                            ('log_limit',LOG_LIMIT+1)):
            bad=copy.deepcopy(r);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                validate_ready(bad,'nb-decoy-work0-1.ready',s,'0::/nb-decoy-test',40,i)

    def test_wrong_host_identity_or_descriptor_cannot_release(self):
        s,r,i=fixture()
        for field,value in (('ppid',50),('pid',43),('uids',[1000]*4),('cgroup','0::/other'),('argv',[])):
            bad={**i,field:value}
            with self.subTest(field=field),self.assertRaises(ValueError):
                validate_ready(r,'nb-decoy-work0-1.ready',s,'0::/nb-decoy-test',40,bad)
        for mutation in ('missing','alias','bad-fd','bad-name'):
            bad=copy.deepcopy(r)
            if mutation=='missing':del bad['logs']['stderr']
            if mutation=='alias':bad['logs']['stderr']['ino']=1
            if mutation=='bad-fd':bad['production_fds']['4']['mode']=stat.S_IFREG
            if mutation=='bad-name':bad['logs']['stdout']['name']='../outside'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                validate_ready(bad,'nb-decoy-work0-1.ready',s,'0::/nb-decoy-test',40,i)


class EnvironmentCapture(unittest.TestCase):
    def exercise(self,data,change=False):
        _,_,info=fixture()
        ref=Mock();ref.read.side_effect=[info,{**info,'start_time':100} if change else info]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'42').mkdir();(root/'42/environ').write_bytes(data)
            return environment(ref,proc=root)

    def test_pins_both_sides_and_preserves_raw_bytes(self):
        receipt,data=self.exercise(b'KEY=nb-decoy-value\0OTHER=ok\0')
        self.assertTrue(receipt['pidfd_pinned']);self.assertEqual(data,b'KEY=nb-decoy-value\0OTHER=ok\0')

    def test_truncation_size_or_identity_change_not_negative_scan(self):
        for data,change in ((b'KEY=value',False),(b'x'*(LIMIT+1),False),(b'A=B\0',True)):
            with self.subTest(change=change,size=len(data)),self.assertRaises(ValueError):
                self.exercise(data,change)


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux owner checks')
class LogCapture(unittest.TestCase):
    def test_empty_live_is_not_complete_and_late_exit_bytes_are_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'nb-decoy-output';p.write_bytes(b'');p.chmod(0o600);os.chown(p,70999,70999)
            s=p.stat();d={'name':p.name,'dev':s.st_dev,'ino':s.st_ino,'mode':stat.S_IFREG}
            raw,fact=bounded_log(root,d,32,final=False)
            self.assertFalse(fact['complete'])
            p.write_bytes(b'exit traceback')
            raw,fact=bounded_log(root,d,32,final=True,prior=raw)
            self.assertEqual(raw,b'exit traceback');self.assertTrue(fact['complete'])
            p.write_bytes(b'x'*32)
            _,fact=bounded_log(root,d,32,final=True)
            self.assertFalse(fact['complete']);self.assertEqual(fact['reason'],'output-cap-reached')

    def test_truncate_replace_owner_mode_symlink_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'nb-decoy-output';p.write_bytes(b'ok');p.chmod(0o600);os.chown(p,70999,70999)
            s=p.stat();d={'name':p.name,'dev':s.st_dev,'ino':s.st_ino,'mode':stat.S_IFREG}
            with self.assertRaises(ValueError):bounded_log(root,d,32,final=True,prior=b'old-data')
            with self.assertRaises(ValueError):bounded_log(root,{**d,'ino':s.st_ino+1},32,final=True)
            p.chmod(0o644)
            with self.assertRaises(ValueError):bounded_log(root,d,32,final=True)
            p.unlink();p.symlink_to(root/'missing')
            with self.assertRaises(ValueError):bounded_log(root,d,32,final=True)


class HostHandshake(unittest.TestCase):
    def exercise(self, *, wrong_parent=False, orphan=False, cap=False):
        source,ready,info=fixture()
        if wrong_parent:info['ppid']=41
        with tempfile.TemporaryDirectory() as tmp:
            logs=Path(tmp);(logs/'nb-decoy-work0-1.ready').write_bytes(json_bytes(ready))
            for d in ready['logs'].values():(logs/d['name']).write_bytes(b'')
            if orphan:(logs/'nb-decoy-orphan.pending').write_bytes(b'{}')
            spawner=Mock();spawner.read.return_value={'pid':40}
            ref=Mock();ref.exited.return_value=True
            command=SimpleNamespace(cgroup=SimpleNamespace(path=Path('/sys/fs/cgroup/nb-decoy-test')),
                                    budget=CaptureBudget(524288))
            deployment=SimpleNamespace(source=source,cb_logs=logs,refs={'spawner':spawner},command=command,
                                       cap={'first':70000,'last':70010})
            measure=ConnectorMeasurement(deployment)
            def log(root,desc,bound,*,final,prior=b''):
                return b'late' if final else b'',{'complete':final and not cap,'identity':{},'reason':''}
            def fd(pid,n):return ready['production_fds'][str(n)]
            with patch('cb_measure.wrapper_process',return_value=info),patch('cb_measure.ProcessRef',return_value=ref),\
                 patch('cb_measure.environment',return_value=({'role':'connector'},b'A=B\0')),\
                 patch('cb_measure.bounded_log',side_effect=log),patch('cb_measure.descriptor_identity',side_effect=fd):
                if wrong_parent:
                    with self.assertRaises(ValueError):measure.pump()
                    self.assertFalse((logs/'nb-decoy-work0-1.release').exists());return
                measure.pump();measure.pump()
                self.assertEqual(len(measure.items),1)
                self.assertEqual(json.loads((logs/'nb-decoy-work0-1.release').read_bytes()),ready)
                with self.assertRaises(ValueError):measure.collect('wrong:1')
                result=measure.finalize();measure.close()
                ref.close.assert_called_once()
                self.assertEqual(result[0]['logs']['stderr']['data'],b'late')
                self.assertEqual(bool(measure.errors),orphan or cap)
                self.assertTrue(measure.finished)

    def test_handshake_releases_once_and_collects_exit(self):self.exercise()
    def test_foreign_parent_never_released(self):self.exercise(wrong_parent=True)
    def test_missing_ready_startup_failure_retained(self):self.exercise(orphan=True)
    def test_cap_reached_not_complete(self):self.exercise(cap=True)


if __name__=='__main__':unittest.main()
