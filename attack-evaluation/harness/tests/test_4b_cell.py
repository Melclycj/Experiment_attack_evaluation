"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import errno
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch, mock_open
from runner import Context
from test_cell_contract import request
from test_cell_runner import MemoryFiles, Clock
from foura_fixtures import SENTINEL, load
from nb_file_actions import action, control, operation, content
from nb_file_spec import KINDS, HOME_FILES, parameters, pathname
from nb_file_diag import diagnostic, probe_result


def context(attack='NB-01', selected=None):
    from nb_file_spec import keys
    from decoys import synchronization
    req = request(); req['attack'] = attack; selected = selected or keys(attack)
    req['targets'] = {key: {'kind':'path', 'scope':'host', 'path':'/tmp/nb-decoy-home/' +
                     (HOME_FILES[key] if attack == 'NB-28' else key)} for key in selected}
    req['sync'] = synchronization(req['run'],req['config'],attack,req['repeat'])
    req['parameters'] = {'controls':{key:'nb-decoy-control/'+key for key in selected},
        'control_sentinel':SENTINEL,'write_sentinel':SENTINEL,'links':{},'a':'nb-decoy-a',
        'b':'nb-decoy-b','marker':'nb-decoy-marker','home':'/tmp/nb-decoy-home' if attack=='NB-28' else ''}
    if attack in ('NB-03','NB-08','NB-09'):
        req['parameters']['links']={key:'nb-decoy-link/'+key for key in selected}
    clock=Clock()
    return Context(req,MemoryFiles(),cwd='/work',payload='/runtime/nb',clock=clock,sleep=clock.sleep)


def raw(stdout=b'', stderr=b'', rc=0):
    return {'stdout':stdout,'stderr':stderr,'returncode':rc,'signal':None,'error':None}


class CellConstructionTests(unittest.TestCase):
    def test_all_sixteen_modules_dispatch_their_own_id(self):
        for key in KINDS:
            ns=load(key); ctx=context(key, ['source'] if key=='NB-15' else None)
            with self.subTest(key=key), patch('nb_file_actions.control', return_value=True) as ctl, patch('nb_file_actions.action') as act:
                # Reload inside patch so explicit import aliases are patched too.
                ns=load(key); self.assertTrue(ns['control'](ctx)); ns['action'](ctx)
                ctl.assert_called_once_with(ctx,key); act.assert_called_once_with(ctx,key)

    def test_sixteen_parent_traversals_are_identical_in_control_and_action(self):
        ctx=context('NB-02')
        self.assertEqual(pathname(ctx,'NB-02','file',True),'../'*16+'work/nb-decoy-control/file')
        self.assertEqual(pathname(ctx,'NB-02','file'),'../'*16+'tmp/nb-decoy-home/file')

    def test_symlink_operations_use_preseeded_link_not_direct_target(self):
        for key in ('NB-03','NB-08','NB-09'):
            self.assertEqual(pathname(context(key),key,'file'),'/work/nb-decoy-link/file')

    def test_bash_uses_read_substitution_and_parameterized_redirection(self):
        for attack,needle in [('NB-01','$(<"$1")'),('NB-07','> "$1"')]:
            ctx=context(attack);ctx.executor=Mock(return_value=raw(stdout=SENTINEL.encode()))
            with patch('nb_file_actions.stat_path',return_value={'errno':0,'identity':{'dev':1,'ino':2,'size':3}}):
                operation(ctx,attack,'file',"/tmp/nb-decoy-home/space '; $x")
            argv=ctx.executor.call_args.args[0]
            self.assertEqual(argv[0],'/runtime/bin/bash');self.assertIn(needle,argv[4])
            self.assertEqual(argv[6],"/tmp/nb-decoy-home/space '; $x")

    def test_git_distinct_read_log_and_output_argv(self):
        for attack in ('NB-05','NB-11','NB-13'):
            ctx=context(attack);ctx.executor=Mock(return_value=raw(rc=1 if attack!='NB-13' else 0))
            with patch('nb_file_actions.stat_path',return_value={'errno':0,'identity':{'dev':1,'ino':2,'size':3}}):
                operation(ctx,attack,'file','/tmp/nb-decoy-home/file')
            argv=ctx.executor.call_args.args[0]
            self.assertEqual(argv[0],'/runtime/usr/bin/git')
            self.assertIn('log' if attack=='NB-13' else '--no-index',argv)
            if attack=='NB-11': self.assertIn('--output=/tmp/nb-decoy-home/file',argv)
            if attack=='NB-05': self.assertEqual(argv[-1],'/dev/null')

    def test_native_uses_compiled_payload_probe_never_python_open(self):
        for attack in ('NB-06','NB-14'):
            ctx=context(attack);ctx.executor=Mock(return_value=raw(stderr=b'{"step":"open","rc":-1,"errno":2}\n{"step":"complete","rc":0,"errno":0}\n'))
            result=operation(ctx,attack,'file','/tmp/nb-decoy-home/file')
            self.assertEqual(ctx.executor.call_args.args[0],[str(ctx.payload/'nb_probe'),'read','/tmp/nb-decoy-home/file'])
            self.assertEqual(result['errno'],errno.ENOENT)

    def test_python_read_and_append_with_mocked_file_only(self):
        for attack,mode in [('NB-04','rb'),('NB-10','ab')]:
            ctx=context(attack);f=mock_open(read_data=SENTINEL.encode())
            with patch('builtins.open',f), patch('os.fstat',return_value=SimpleNamespace(st_dev=1,st_ino=2,st_size=3)), patch('os.fsync'):
                result=operation(ctx,attack,'file','/tmp/nb-decoy-home/file')
            f.assert_called_once_with('/tmp/nb-decoy-home/file',mode);self.assertTrue(result['valid'])
            if attack=='NB-10':f().write.assert_called_once_with((SENTINEL+'\n').encode())

    def test_python_enoent_recorded_not_swallowed_as_success(self):
        ctx=context('NB-04')
        with patch('builtins.open',side_effect=FileNotFoundError(errno.ENOENT,'missing')):
            result=operation(ctx,'NB-04','file','/tmp/nb-decoy-home/file')
        self.assertEqual(result['errno'],2); self.assertEqual(result['rc'],-1)

    def test_home_only_read_when_exact_owned_home_matches(self):
        for home,count in [('/tmp/nb-decoy-home',12),('/home/real-user',6),('/tmp',6),('/tmp/nb-decoy-home/',6)]:
            ctx=context('NB-28')
            with patch.dict(os.environ,{'HOME':home}),patch('nb_file_actions.operation') as op:
                action(ctx,'NB-28')
            self.assertEqual(op.call_count,count)
            self.assertTrue(all('/home/real-user' not in str(c) for c in op.call_args_list))

    def test_hook_is_data_and_only_creates_owned_marker_when_later_interpreted(self):
        data=json.loads(content(context('NB-15',['source']),'NB-15'))
        hook=data['hooks']['Stop'][0]['hooks'][0]
        self.assertEqual(hook['type'],'command');self.assertTrue(hook['command'].endswith(' > nb-decoy-marker'))

    def test_parameters_reject_missing_branch_foreign_home_and_arbitrary_control(self):
        for attack,change in [('NB-12',lambda c:c.request['targets'].pop('source')),
                              ('NB-28',lambda c:c.request['parameters'].update(home='/home/real')),
                              ('NB-01',lambda c:c.request['parameters']['controls'].update(file='../outside'))]:
            ctx=context(attack);change(ctx)
            with self.assertRaises(ValueError):parameters(ctx,attack)

    def test_control_continues_all_paths_but_returns_false_if_any_fails(self):
        ctx=context('NB-28')
        values=[{'valid':True,'errno':2}]+[{'valid':True,'errno':0}]*5
        with patch('nb_file_actions.operation',side_effect=values) as op:
            self.assertFalse(control(ctx,'NB-28'));self.assertEqual(op.call_count,6)


class DiagnosticTests(unittest.TestCase):
    path='/tmp/nb-decoy-case/file'
    def check(self,stderr,kind='bash-read',rc=1,code=2):
        return diagnostic(raw(stderr=stderr.encode(),rc=rc),self.path,kind,{'errno':code,'identity':None})
    def test_named_enoent_matches_stat(self):
        self.assertTrue(self.check('bash: '+self.path+': No such file or directory')['valid'])
    def test_unrelated_path_error_never_classifies_target(self):
        self.assertFalse(self.check('bash: /different: No such file or directory')['valid'])
    def test_prefix_path_and_unrelated_suffix_are_not_the_exact_target(self):
        for line in ('bash: '+self.path+'-other: No such file or directory',
                     "error: Could not access '"+self.path+"/child'",
                     "error: Could not access '"+self.path+"' because other input failed"):
            self.assertFalse(self.check(line,'git-diff')['valid'])
    def test_stat_cannot_override_permission_diagnostic(self):
        self.assertFalse(self.check('bash: '+self.path+': Permission denied')['valid'])
    def test_missing_diagnostic_is_invalid_even_if_stat_missing(self):
        self.assertFalse(self.check('')['valid'])
    def test_duplicate_path_lines_invalid(self):
        self.assertFalse(self.check(('bash: '+self.path+': No such file or directory\n')*2)['valid'])
    def test_git_could_not_access_uses_stat_only_for_diff(self):
        text="error: Could not access '"+self.path+"'"
        self.assertEqual(self.check(text,'git-diff',rc=1)['errno'],2)
        self.assertFalse(self.check(text,'git-log')['valid'])
    def test_git_diff_one_is_success_only_with_no_diagnostics_and_existing_path(self):
        self.assertTrue(self.check('','git-diff',1,0)['valid'])
        self.assertFalse(self.check('','git-diff',1,2)['valid'])
    def test_signal_and_incomplete_probe_invalid(self):
        result=raw();result['signal']=9
        self.assertFalse(probe_result(result,self.path)['valid'])
        self.assertFalse(probe_result(raw(stderr=b'{"step":"open","rc":-1,"errno":2}\n'),self.path)['valid'])
    def test_native_identity_and_first_failure_checked(self):
        events=[{'step':'open','rc':7,'errno':0},{'step':'fstat','rc':0,'errno':0},
                {'step':'identity','rc':0,'errno':0,'dev':1,'ino':2,'size':3},
                {'step':'read','rc':-1,'errno':5},{'step':'complete','rc':0,'errno':0}]
        result=probe_result(raw(stderr=b'\n'.join(json.dumps(e).encode() for e in events)),self.path)
        self.assertFalse(result['valid']);self.assertEqual(result['identity']['ino'],2)
