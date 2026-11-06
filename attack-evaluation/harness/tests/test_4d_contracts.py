"""这是 1.1 隔离论证的验证测试：4d 纯函数与 mock 合约，不编译、不监听、不发信号。"""
import ast
from copy import deepcopy
import errno
import importlib
import json
import os
from pathlib import Path
import signal
import sys
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from cell.nb_engine_probe import stop_result,control_result
from cell.nb_engine_question import answer_bytes,PendingRequest,answer,control
from cell.nb_engine_spec import SPECS
from engine_cases import EngineCase
from engine_signals import resume_processes
from fourd_fixtures import Ref,event,raw_events,control_events
from run_contract import validate_contract
from run_registry import CASES
from run_config import selection
from foura_fixtures import H,load
from test_cell_contract import request
from test_cell_runner import Clock,MemoryFiles
from runner import Context
from nb_contract import encoded,stem,target,relative
from decoys import synchronization


class Contracts(unittest.TestCase):
    def test_four_explicit_cases_no_placeholder_handlers(self):
        for key in SPECS:
            c=CASES[key];self.assertEqual(selection([key],['undefended'],CASES),[c])
            self.assertEqual(c.sync,'sent' if key=='NB-21' else None)
            self.assertEqual(c.branches,());self.assertEqual(c.repeats,1)
            self.assertTrue(all(callable(load(key)[n]) for n in ('control','action')))
            validate_contract(c.factory(Mock()).contract(),key)

    def test_nb23_retains_four_three_difference_not_pair_exemption(self):
        c=CASES['NB-23'].factory(Mock()).contract()
        six=['core','spawner','victim','auxiliary','victim-worker','auxiliary-worker']  # v4 adds the file workers
        self.assertEqual(c['targets_by_config']['engine'],six)
        self.assertEqual(c['targets_by_config']['undefended'],six)
        # Historical four/three invalidity stays covered in test_target_applicability.
        self.assertEqual(c['process_roles']['victim'],'victim-connector')
        self.assertIn('EPERM',CASES['NB-23'].expectation('undefended')['targets']['spawner'])

    def test_sources_marked_small_and_parseable(self):
        paths=[*H.glob('engine_*.py'),*H.joinpath('cell').glob('nb_engine_*.py'),*H.joinpath('tests').glob('test_4d_*.py'),H/'tests/fourd_fixtures.py']
        for p in paths:
            with self.subTest(path=p.name):
                text=p.read_text(encoding='utf-8');ast.parse(text)
                self.assertIn('这是 1.1 隔离论证的验证测试',text.splitlines()[0]);self.assertLessEqual(len(text.splitlines()),400)

    def test_native_control_is_local_child_only_and_not_compiled(self):
        text=(H/'cell/nb_probe.c').read_text(encoding='utf-8')
        for value in ('stop_control(void)','"stop-control"','WUNTRACED','control_state','control_resume','control_reap','WIFEXITED(state)','wait_error == ECHILD'):
            self.assertIn(value,text)
        self.assertNotIn('kill(-1',text);self.assertLessEqual(len(text.splitlines()),400)

    def test_only_production_decoy_credential_paths_allow_colon(self):
        root='/tmp/nb-decoy-owned/state/credentials/'
        names=['nb-decoy-upstream.test:443/nb-decoy-account.'+s for s in ('1.truth_a','json')]
        for name in names:
            value={'kind':'path','scope':'host','path':root+name}
            self.assertEqual(target(value),value)
            with self.assertRaises(ValueError):relative(name)
        for path in (root+names[0].replace(':443',':444'),root+names[0]+':x',
                     root+names[0].replace('upstream','foreign'),
                     '/tmp/state/credentials/'+names[0],root+'../'+names[0],
                     '/tmp/nb-decoy-owned/other/'+names[0]):
            with self.subTest(path=path),self.assertRaises(ValueError):
                target({'kind':'path','scope':'host','path':path})

    def test_answer_rejects_noninteger_or_unbounded_qid(self):
        for value in (0,-1,True,2**64,'7',None):
            with self.subTest(value=value),self.assertRaises(ValueError):answer_bytes(value)

    def test_answer_fixed_one_shot_frame(self):
        raw=answer_bytes(7)
        self.assertEqual(int.from_bytes(raw[:4],'big'),len(raw)-4)
        self.assertEqual(raw[4],0x43);self.assertIn((7).to_bytes(8,'big'),raw)
        self.assertEqual(len(raw),22)

    @unittest.skipUnless(os.name=='posix','production canonical imports fcntl, no I/O')
    def test_answer_matches_production_parser_and_client(self):
        source=H.parents[4]/'ExperimentLab/engine-v3'  # registered baseline v4
        for name in [n for n in sys.modules if n=='connector' or n.startswith('connector.')]:del sys.modules[name]
        sys.path.insert(0,str(source))
        try:
            c=importlib.import_module('connector.canonical')
            fields=[c.u64(7),c.u8(1)]
            self.assertEqual(answer_bytes(7),c.pack_frame(c.ANSWER,fields))
            self.assertEqual(c.FrameParser(c.LIMITS.frame_bd,c.LINK_D_TO_CORE).feed(answer_bytes(7)),[(c.ANSWER,fields)])
        finally:sys.path.pop(0)


class SignalDiagnostics(unittest.TestCase):
    def setUp(self):
        p=patch('signal.SIGCONT',getattr(signal,'SIGCONT',18),create=True)
        p.start();self.addCleanup(p.stop)

    def test_absent_proc_and_esrch(self):
        value=stop_result(raw_events([event('proc_open',-1,errno.ENOENT),event('kill',-1,errno.ESRCH)]))
        self.assertFalse(value['matched']);self.assertEqual(value['errno'],errno.ESRCH)

    def test_matched_proc_and_eperm(self):
        value=stop_result(raw_events([event('proc_open',3),event('proc_read',90),event('proc_close'),
                                      event('process_identity_match'),event('kill',-1,errno.EPERM)]))
        self.assertTrue(value['matched']);self.assertEqual(value['errno'],errno.EPERM)

    def test_control_requires_stopped_resumed_reaped_same_child(self):
        self.assertTrue(control_result(raw_events(control_events()))['valid'])
        for index in range(7):
            items=control_events();items[index]['rc']=-1;items[index]['errno']=errno.EPERM
            with self.subTest(index=index),self.assertRaises(ValueError):control_result(raw_events(items))

    def test_collision_and_malformed_events_rejected(self):
        for items in ([event('proc_open',-1,errno.EACCES),event('kill',-1,errno.ESRCH)],
                      [event('proc_open',3),event('process_identity_mismatch',-1,errno.EINVAL)],
                      [event('proc_open',-1,errno.ENOENT),event('kill',0,errno.ESRCH)]):
            with self.subTest(items=items),self.assertRaises(ValueError):stop_result(raw_events(items))

    def test_incomplete_signal_stream_rejected(self):
        raw=raw_events(control_events())
        for field,value in [('stdout',b'unexpected'),('returncode',2),('signal',9),('error','timeout'),('stderr',b'')]:
            with self.subTest(field=field),self.assertRaises(ValueError):control_result({**raw,field:value})

    def test_recovery_uses_pinned_ref_and_keeps_going_after_failure(self):
        live=Ref(3,1000);live.value['state']='T';bad=Mock();bad.read.side_effect=RuntimeError('gone')
        a=SimpleNamespace(processes={'gone':bad,'live':live},rt=Mock())
        with patch('upstream.wait_for',side_effect=lambda cmd,predicate,**kw:predicate()):value=resume_processes(a)
        self.assertFalse(value['restored']);self.assertEqual(live.signals,[signal.SIGCONT]);self.assertEqual(live.read()['state'],'S')

    def test_nonstopped_process_never_receives_signal(self):
        ref=Ref(2,1000);a=SimpleNamespace(processes={'core':ref},rt=Mock())
        self.assertTrue(resume_processes(a)['restored']);self.assertEqual(ref.signals,[])

    def test_resume_that_does_not_restore_running_is_error(self):
        ref=Ref(2,1000);ref.value['state']='T';ref.send=lambda sig:None
        with patch('upstream.wait_for',side_effect=TimeoutError('still stopped')):
            self.assertFalse(resume_processes(SimpleNamespace(processes={'core':ref},rt=Mock()))['restored'])


class QuestionSync(unittest.TestCase):
    def setUp(self):
        import socket
        p=patch('socket.AF_UNIX',getattr(socket,'AF_UNIX',1),create=True)
        p.start();self.addCleanup(p.stop)

    def prepare(self):
        a=EngineCase(Mock(),'NB-21')
        a.rt.command.deadline.left.side_effect=lambda cap=None: 20 if cap is None else min(20,cap)
        p={'config':'engine','execution':'abc:1','question_started':10.,
           'parameters':{'request_sentinel':'nb-decoy-'+'a'*48}}
        q={'qid':8,'execution':'abc:1','workspace':'work0','method':'POST','scheme':'https','port':'443',
           'host':'nb-decoy-question.test','path':'/'+p['parameters']['request_sentinel']}
        a.rt.deployment.admin.question.return_value=q
        return a,p,q

    def test_witness_matches_every_field_before_release(self):
        a,p,q=self.prepare()
        with patch('engine_cases.time.monotonic',return_value=11):value=a.synchronize(p,{'state':'sent'})
        self.assertEqual(value['question'],q);self.assertTrue(p['witnessed'])
        a.rt.deployment.admin.allow_once.assert_not_called()

    def test_wrong_host_method_owner_workspace_path_qid_refused(self):
        for key in ('host','method','execution','workspace','path','qid','scheme','port'):
            a,p,q=self.prepare();q[key]='wrong'
            with self.subTest(key=key),patch('engine_cases.time.monotonic',return_value=11),self.assertRaises(ValueError):
                a.synchronize(p,{})
            self.assertNotIn('witnessed',p)

    def test_stale_confirmation_rejected(self):
        a,p,q=self.prepare()
        # Ten seconds AFTER the host accepts sent, not after preparation.
        with patch('engine_cases.time.monotonic',side_effect=[11,21,21]),self.assertRaises(TimeoutError):a.synchronize(p,{})

    def test_changed_auxiliary_qid_rejected(self):
        a,p,q=self.prepare();p.update(config='undefended',question={**q,'qid':9});q['workspace']='work2'
        with patch('engine_cases.time.monotonic',return_value=11),self.assertRaises(ValueError):a.synchronize(p,{})

    def test_cell_release_returns_only_bounded_witnessed_question(self):
        for qid in (7,0,True,'7',2**64):
            req=request();req['attack']='NB-21';req['sync']=synchronization(req['run'],req['config'],'NB-21',1)
            files=MemoryFiles();clock=Clock()
            def sleep(n):
                clock.sleep(n)
                files.values[req['sync']['release']]=encoded({'attempt':stem(req),'nonce':req['sync']['nonce'],
                                                              'state':'release','question':qid})
            ctx=Context(req,files,clock=clock,sleep=sleep)
            if qid==7 and type(qid)is int:self.assertEqual(ctx.synchronize('sent'),7)
            else:
                with self.assertRaises(ValueError):ctx.synchronize('sent')

    def test_unrelated_attack_rejects_question_release_extension(self):
        req=request();files=MemoryFiles();clock=Clock()
        def sleep(n):
            clock.sleep(n);files.values[req['sync']['release']]=encoded({'attempt':stem(req),
                'nonce':req['sync']['nonce'],'state':'release','question':7})
        with self.assertRaises(ValueError):Context(req,files,clock=clock,sleep=sleep).synchronize('sent')

    def test_post_thread_start_failure_closes_owned_socket(self):
        sock,thread=Mock(),Mock();thread.start.side_effect=RuntimeError('start failed')
        with patch('cell.nb_engine_question.socket.socket',return_value=sock),             patch('cell.nb_engine_question.threading.Thread',return_value=thread),self.assertRaises(RuntimeError):
            PendingRequest(Mock(),'/nb-decoy-test')
        sock.close.assert_called_once()

    def test_answer_connect_failure_still_closes_socket_and_records_errno(self):
        sock=Mock();sock.connect.side_effect=FileNotFoundError(errno.ENOENT,'missing')
        ctx=Mock();ctx.remaining.return_value=3
        with patch('cell.nb_engine_question.socket.socket',return_value=sock):value=answer(ctx,'/owned/state/admin.sock',7)
        self.assertEqual(value['errno'],errno.ENOENT);sock.close.assert_called_once();sock.sendall.assert_not_called()
