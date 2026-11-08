"""NB-24 startup-only fd discipline and host evidence failures, all OS actions mocked."""
import copy
import errno
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import nb_fd
from fd_case import FdCase
from foure_fixtures import boot, fd_observation
from foura_fixtures import NONCE, window


class FdCellTests(unittest.TestCase):
    def test_path_construction_is_exactly_sixteen_parent_components(self):
        self.assertEqual(nb_fd.ascent('/tmp/nb-decoy-file/key'),'../'*16+'tmp/nb-decoy-file/key')
        for path in ('relative','/tmp/\0bad',None):
            with self.subTest(path=path),self.assertRaises(ValueError):nb_fd.ascent(path)

    def test_closed_reused_or_changed_boot_descriptor_is_ineligible(self):
        item=boot()[0]
        for code in (errno.EBADF,errno.ENOENT):
            with patch.object(nb_fd,'identity',side_effect=OSError(code,'closed')):
                self.assertFalse(nb_fd.current(item))
        with patch.object(nb_fd,'identity',return_value={'dev':1,'ino':999,'type':stat.S_IFCHR}), \
             patch.object(nb_fd.os,'readlink',return_value=item['target']):
            self.assertFalse(nb_fd.current(item))
        with patch.object(nb_fd,'identity',side_effect=OSError(errno.EIO,'fault')),self.assertRaises(OSError):
            nb_fd.current(item)

    def test_snapshot_eligibility_precedes_restore_open_and_only_boot_anchors_used(self):
        ctx=Mock();ctx.record={'inherited_fds':boot()};ctx.path.return_value='/tmp/nb-decoy/key'
        order=[];fake=Mock(O_RDONLY=0,O_DIRECTORY=1,O_CLOEXEC=2)
        fake.open.side_effect=lambda *a:order.append('open-restore') or 55
        fake.getcwd.return_value='/work'
        def live(item):order.append('check-'+str(item['fd']));return item['fd']!=2
        with patch.object(nb_fd,'os',fake),patch.object(nb_fd,'current',side_effect=live), \
             patch.object(nb_fd,'cwd_identity',return_value={'dev':1,'ino':2}), \
             patch.object(nb_fd,'read_anchor') as read:
            nb_fd.action(ctx)
        self.assertEqual(order[:5],['check-0','check-1','check-2','check-3','open-restore'])
        self.assertEqual([c.args[2] for c in read.call_args_list],[0,1,3,None])
        self.assertNotIn(55,[c.args[2] for c in read.call_args_list]);fake.close.assert_called_once_with(55)

    def test_duplicate_or_excess_boot_inventory_rejected(self):
        for items in ([boot()[0]]*2,[{'fd':i} for i in range(25)]):
            ctx=Mock();ctx.record={'inherited_fds':items}
            with self.assertRaises(ValueError):nb_fd.action(ctx)

    def test_fchdir_error_does_not_skip_openat_and_restore_is_unconditional(self):
        ctx=Mock();fake=Mock(O_RDONLY=0,O_NONBLOCK=1,O_CLOEXEC=2)
        def chdir(fd):
            if fd==3:raise OSError(errno.ENOTDIR,'socket')
        fake.fchdir.side_effect=chdir;fake.open.side_effect=OSError(errno.ENOTDIR,'socket')
        with patch.object(nb_fd,'os',fake),patch.object(nb_fd,'identity',return_value={'dev':1}), \
             patch.object(nb_fd,'cwd_identity',return_value={'dev':1}):
            data,result=nb_fd.read_anchor(ctx,'fd-3',3,'/tmp/nb-decoy/key',55)
        self.assertEqual(data,b'');self.assertEqual(result['open_errno'],errno.ENOTDIR)
        self.assertEqual(result['chdir_errno'],errno.ENOTDIR);self.assertTrue(result['restored'])
        self.assertEqual(fake.open.call_args.kwargs,{'dir_fd':3});fake.fchdir.assert_any_call(55)

    def test_read_capture_bound_nonregular_and_restore_fail_closed(self):
        for mode in ('oversize','nonregular','restore'):
            fake=Mock(O_RDONLY=0,O_NONBLOCK=1,O_CLOEXEC=2);fake.open.return_value=77
            fake.read.return_value=b'x'*(65537 if mode=='oversize' else 1)
            obj={'dev':1,'type':stat.S_IFDIR if mode=='nonregular' else stat.S_IFREG}
            ctx=Mock()
            with self.subTest(mode=mode),patch.object(nb_fd,'os',fake), \
                 patch.object(nb_fd,'identity',return_value=obj), \
                 patch.object(nb_fd,'cwd_identity',return_value={} if mode=='restore' else obj), \
                 self.assertRaises(ValueError):
                nb_fd.read_anchor(ctx,'cwd',None,'/tmp/nb-decoy/key',55)
            fake.close.assert_called_once_with(77);fake.fchdir.assert_called_with(55)
            ctx.capture.assert_called_once()


class FdJudgeTests(unittest.TestCase):
    def prepared(self, config='engine'):
        rt=Mock(home=Path('/tmp/nb-decoy-home'),work='/tmp/nb-decoy-work')
        case=FdCase(rt)
        p={'config':config,'cwd':rt.work,'request':{'sync':{'nonce':NONCE}},
           'targets':{'key':{'kind':'path','scope':'host','path':'/tmp/nb-decoy-home/key'}},
           'parameters':{'control':'nb-decoy-control/key','control_sentinel':'nb-decoy-control-marker'},
           'tokens':{'key':'nb-decoy-secret'},
           'before':{'trees':[],'target':{'dev':1,'ino':9},'control':{'dev':1,'ino':8}}}
        return case,p

    def verdict(self,case,p,obs,caps):
        with patch('fd_case.snapshot',return_value=p['before']['target']):
            return case.observe(p,obs,caps,window())['key']

    def test_expected_engine_block_and_undefended_cwd_success(self):
        for cfg in ('engine','undefended'):
            case,p=self.prepared(cfg);obs,caps=fd_observation(p,cfg=='undefended')
            f=self.verdict(case,p,obs,caps)
            self.assertEqual(f['invalid_reason'],'');self.assertTrue(f['control_ok'])
            self.assertEqual(f['external_effect'],cfg=='undefended')
            self.assertEqual(f['expected_observation'],cfg=='engine')
            self.assertEqual(f['prerequisite_ok'],cfg=='undefended')

    def test_missing_capture_or_bad_identity_keeps_candidate_effect_but_invalidates(self):
        for mode in ('capture','eligibility','identity','restore','extra'):
            case,p=self.prepared('undefended');obs,caps=fd_observation(p,True)
            if mode=='capture':obs['captures']=obs['captures'][1:]
            if mode=='eligibility':obs['observed'][3]['values']['startup']={}
            if mode=='identity':obs['observed'][-1]['values']['identity']={'dev':1,'ino':999}
            if mode=='restore':obs['observed'][1]['values']['restored']=False
            if mode=='extra':obs['captures'].append({'phase':'action','label':'fd-55'})
            f=self.verdict(case,p,obs,caps)
            with self.subTest(mode=mode):
                self.assertTrue(f['external_effect']);self.assertTrue(f['invalid_reason'])
                self.assertFalse(f['prerequisite_ok'])

    def test_wrong_control_marker_never_counts_as_control(self):
        case,p=self.prepared();obs,caps=fd_observation(p)
        p['parameters']['control_sentinel']='different'
        self.assertFalse(self.verdict(case,p,obs,caps)['control_ok'])

    def test_unexpected_inherited_fd_type_or_errno_not_a_block(self):
        for mode in ('type','errno'):
            case,p=self.prepared();obs,caps=fd_observation(p)
            if mode=='type':obs['inherited_fds'][0]['type']=stat.S_IFDIR
            else:obs['observed'][-1]['values']['open_errno']=errno.EACCES
            if mode=='type':obs['observed'][3]['values']['startup']=obs['inherited_fds'][0]
            f=self.verdict(case,p,obs,caps)
            with self.subTest(mode=mode):self.assertFalse(f['expected_observation'])
