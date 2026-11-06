"""这是 1.1 隔离论证的验证测试：NB-23 四目标与受害行切换，全部 OS 动作为 mock。"""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from engine_cases import EngineCase
from engine_signals import prepare_signals
from fourd_fixtures import Ref
from run_config import batch_capacity, schedule
from run_contract import validate_contract
from run_registry import CASES
from support_rows import SupportRows
import test_target_applicability as applicability
from test_target_applicability import SignalAdapter, ROLES
from cell.nb_engine_spec import ROLES as ENGINE_ROLES  # v4: the four targets plus two row file workers


class Transition(unittest.TestCase):
    def make(self):
        s = SupportRows.__new__(SupportRows)
        s.rt = Mock(); s.rt.active = 'undefended'
        s.config = 'undefended'; s.current = s.question_pending = None
        s.closed = s.signal_victim = False; s.netfd = 11
        old = dict(row=SimpleNamespace(config='undefended', workspace='work1',
                   execution=None, closed=False), ref=Mock(), files=Mock(),
                   root=Path('/offline/nb-decoy-undefended-victim'),
                   target={'kind':'abstract', 'name':'nb-decoy-victim'})
        aux = dict(row=SimpleNamespace(config='engine', workspace='work2',
                   execution='aux:1', closed=False))
        s.items = {'victim':old, 'auxiliary':aux}
        s.rt.rows = [old['row'], aux['row']]
        s.rt.deployment.refs = {}
        s.rt.deployment.workspaces = {'work1':{'mount':Path('/offline/work1')}}
        s.rt.deployment.host_workspaces = s.rt.deployment.workspaces
        old['ref'].read.return_value={'pid':201,'start_time':100,'uids':[1000]*4}
        s._send = Mock(); s._wait = Mock()
        old['row'].poll = Mock(return_value=True)
        old['row'].finish = Mock(side_effect=lambda: self.finish(old['row']))
        s.rt.command.deadline.left.side_effect = lambda n=None: 20 if n is None else min(n,20)
        events = []
        def start(*args, **kwargs):
            self.assertTrue(old['row'].closed)
            self.assertEqual(args, ('victim','work1','engine','SUP-VICTIM'))
            self.assertEqual(kwargs, {'suffix':'-signal'})
            events.append('start')
            row = SimpleNamespace(config='engine', workspace='work1', execution='peer:1', closed=False)
            s.rt.rows.append(row)
            s.items['victim'] = dict(row=row, ref=Mock(), files=Mock(), root=Path('/offline/nb-decoy-undefended-victim-signal'))
            s.rt.deployment.refs['connector:peer:1'] = Ref(202,70999)
            s.items['victim']['ref'].read.return_value={'pid':203,'start_time':101,'uids':[70000]*4}
        s._start = Mock(side_effect=start)
        return s, old, aux, events

    @staticmethod
    def finish(row):
        row.closed = True
        return {'tree_empty':True, 'runner_ok':True}

    def guards(self, stack):
        stack.enter_context(patch('support_rows.wait_for', side_effect=lambda cmd,fn,**kw:fn()))
        stack.enter_context(patch('support_rows.collect', return_value=({'control_ok':True},{})))
        close = stack.enter_context(patch('support_rows.os.close'))
        return close

    def test_real_work1_peer_after_verified_host_stop(self):
        s,old,aux,events = self.make()
        old['row'].request = {}
        with ExitStack() as st:
            close = self.guards(st)
            s.ensure_signal_victim()
        self.assertEqual(events,['start'])
        self.assertTrue(s.signal_victim); self.assertIs(s.items['auxiliary'],aux)
        old['files'].close.assert_called_once(); old['ref'].close.assert_called_once()
        close.assert_called_once_with(11)
        self.assertEqual(len([r for r in s.rt.rows if not r.closed]),2)
        self.assertEqual(s.items['victim']['row'].execution,'peer:1')
        s.rt.targets.release.assert_any_call('victim-listener-undefended',old['target'])
        self.assertTrue(s.rt.evidence.raw.called)

    def test_transition_reentry_does_not_start_second_peer(self):
        s,old,_,_ = self.make(); old['row'].request = {}
        with ExitStack() as st:
            self.guards(st); s.ensure_signal_victim(); s.ensure_signal_victim()
        s._start.assert_called_once()

    def test_refuse_open_window_pending_question_closed_or_wrong_arm(self):
        for field,value in [('current',{}),('question_pending',{}),('closed',True),('config','engine')]:
            s,_,_,_ = self.make(); setattr(s,field,value)
            with self.subTest(field=field),self.assertRaises(ValueError):s.ensure_signal_victim()
            s._send.assert_not_called(); s._start.assert_not_called()

    def test_failed_old_stop_never_starts_peer(self):
        s,old,_,_ = self.make(); old['row'].request={}
        with ExitStack() as st:
            self.guards(st)
            old['row'].finish.side_effect=RuntimeError('not retired')
            with self.assertRaises(RuntimeError):s.ensure_signal_victim()
        s._start.assert_not_called(); s.rt.targets.release.assert_not_called()

    def test_bad_old_receipt_never_starts_peer(self):
        s,old,_,_ = self.make(); old['row'].request={}
        with ExitStack() as st:
            self.guards(st)
            st.enter_context(patch('support_rows.collect',return_value=({'control_ok':False},{})))
            with self.assertRaises(ValueError):s.ensure_signal_victim()
        s._start.assert_not_called()

    def test_start_failure_keeps_partial_new_row_for_batch_cleanup(self):
        s,old,_,_ = self.make(); old['row'].request={}; start=s._start.side_effect
        def fail(*a,**k):start(*a,**k);raise RuntimeError('readiness failed')
        s._start.side_effect=fail
        with ExitStack() as st:
            self.guards(st)
            with self.assertRaises(RuntimeError):s.ensure_signal_victim()
        self.assertFalse(s.signal_victim)
        self.assertFalse(s.items['victim']['row'].closed)
        self.assertIn(s.items['victim']['row'],s.rt.rows)

    def test_transition_evidence_failure_is_not_success(self):
        s,old,_,_ = self.make(); old['row'].request={}
        s.rt.evidence.raw.side_effect=OSError('evidence full')
        with ExitStack() as st:
            self.guards(st)
            with self.assertRaises(OSError):s.ensure_signal_victim()

    def test_signal_peer_cannot_be_reused_for_nb25_host_window(self):
        s,_,_,_ = self.make(); s.signal_victim=True
        with patch('support_rows.inspect_listener') as inspect,self.assertRaises(ValueError):s.begin_window('later')
        inspect.assert_not_called()

    def test_wrong_existing_peer_role_is_not_silently_reused(self):
        for attribute,value in [('execution',None),('closed',True),('workspace','work2'),('config','undefended')]:
            s,old,_,_ = self.make(); s.signal_victim=True
            old['row'].config='engine';old['row'].execution='peer:1'
            setattr(old['row'],attribute,value)
            with self.subTest(attribute=attribute),self.assertRaises(ValueError):s.ensure_signal_victim()
            s._start.assert_not_called()


class FourTargets(unittest.TestCase):
    def test_new_contract_has_four_targets_in_both_arms(self):
        c=EngineCase(Mock(),'NB-23').contract()
        m=validate_contract(c,'NB-23')
        self.assertEqual(m['engine'],list(ENGINE_ROLES));self.assertEqual(m['undefended'],list(ENGINE_ROLES))
        self.assertNotEqual(c['construction'],'engine-objects-4d-v1')
        self.assertEqual(CASES['NB-23'].expectation('undefended')['targets']['victim'],'identity-matched EPERM')

    def adapter(self):
        rt=Mock();rt.deployment.refs={'core':Ref(100,1000),'spawner':Ref(101,0),
            'connector:peer':Ref(102,70999),'connector:aux':Ref(103,70999),
            'file-worker:peer':Ref(104,70996),'file-worker:aux':Ref(105,70996)}
        rt.support.items={'victim':{'row':SimpleNamespace(closed=False,execution='peer')},
                          'auxiliary':{'row':SimpleNamespace(closed=False,execution='aux')}}
        return SimpleNamespace(rt=rt,registered={},processes={})

    def test_prepare_pins_distinct_real_connector_and_all_four_targets(self):
        a=self.adapter();targets,before=prepare_signals(a,'undefended')
        a.rt.support.ensure_signal_victim.assert_called_once()
        self.assertEqual(set(targets),set(ENGINE_ROLES))
        self.assertEqual(before['victim']['uids'],[70999]*4)
        self.assertEqual(before['victim-worker']['uids'],[70996]*4)
        self.assertEqual(targets['victim-worker']['pid'],104)
        self.assertNotEqual(targets['victim'],targets['auxiliary'])

    def test_wrong_uid_stopped_or_dead_peer_is_invalid(self):
        for field,value in [('uids',[1000]*4),('state','T'),('state','Z')]:
            a=self.adapter();a.rt.deployment.refs['connector:peer'].value[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):prepare_signals(a,'undefended')

    def test_missing_peer_cannot_fallback_to_auxiliary(self):
        a=self.adapter();a.rt.support.items['victim']['row'].execution=None
        with self.assertRaises(ValueError):prepare_signals(a,'undefended')

    def test_host_connections_remain_before_signal_transition_and_capacity_is_sufficient(self):
        cases=[CASES[x] for x in ('NB-23','PC-FILE','NB-25','PC-PROXY','NB-22','PC-DIALOGUE')]
        seq=[c.attack for cfg,c in schedule(cases,['engine','undefended']) if cfg=='undefended']
        self.assertEqual(seq,['NB-25','NB-23','NB-22'])
        # Engine attack/control rows plus two engine supports per arm; the new
        # work1 peer consumes the already reserved undefended victim allocation.
        cap=batch_capacity(cases,['engine','undefended'])
        self.assertGreaterEqual(cap['executions'],len(cases)+4)
        self.assertEqual(cap['simultaneous_copies'],3)

    def test_four_four_pipeline_pairs_each_target_with_own_peer(self):
        class Paired(SignalAdapter):
            def contract(self):
                value=super().contract();value['targets_by_config']['undefended']=list(ROLES)
                return value
            def prepare(self,*args):
                value=super().prepare(*args)
                self.rt.rows[0].execution='victim'
                return value
        code,meta,rows,_=applicability.ApplicabilityTests().exercise(Paired)
        self.assertEqual(code,0,meta.get('controller_error'))
        self.assertEqual(rows[0]['outcome'],'blocked')
        targets=rows[0]['attempts'][0]['targets']
        self.assertEqual(len(targets),4)
        self.assertTrue(all(t['pairing']['satisfied'] for t in targets))
