"""这是 1.1 隔离论证的验证测试：M06 假时钟与辅助提问准备门；所有请求为 mock。"""
from contextlib import ExitStack
from dataclasses import replace
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch
from engine_cases import EngineCase
from env import Deadline


class QuestionTiming(unittest.TestCase):
    def fixture(self, config='engine', now=25, started=10, end=40, delay=0):
        clock = [float(now)]
        deadline = Deadline(end-now, clock=lambda: clock[0])
        rt = NS(command=NS(deadline=deadline), deployment=NS(admin=Mock()))
        a = EngineCase(rt, 'NB-21')
        p = dict(config=config, execution='attack:1' if config=='engine' else 'auxiliary:1',
                 question_started=started, parameters={'request_sentinel':'nb-decoy-'+'a'*48})
        q = dict(qid=7, execution=p['execution'], workspace='work0' if config=='engine' else 'work2',
                 method='POST', host='nb-decoy-question.test', path='/'+p['parameters']['request_sentinel'],
                 scheme='https', port='443')
        if config=='undefended': p['question'] = dict(q)
        def query(**kw): clock[0] += delay; return dict(q)
        rt.deployment.admin.question.side_effect = query
        return a, p, q, clock

    def sync(self, a, p, clock, ready=None):
        with patch('engine_cases.time.monotonic', side_effect=lambda: clock[0]):
            return a.synchronize(p, ready or {'state':'sent'})

    def test_slow_setup_does_not_consume_engine_sent_confirmation_window(self):
        a, p, q, clock = self.fixture(delay=2)
        result = self.sync(a,p,clock)
        self.assertEqual(result['question'],q); self.assertTrue(p['witnessed'])
        self.assertEqual(result['confirmation_seconds'],2)
        self.assertEqual(result['age_seconds'],17)
        self.assertTrue(result['age_is_upper_bound'])
        a.rt.deployment.admin.question.assert_called_once_with(execution=p['execution'],path=q['path'],timeout=10)
        self.assertEqual(a.rt.command.deadline.end,40)

    def test_engine_exact_ten_second_confirmation_is_rejected(self):
        for query_time, validation_time in ((10,0),(9,1)):
            a,p,_,clock=self.fixture(now=10,started=10,end=40,delay=query_time)
            original=a.question_witness
            def check(*args):
                clock[0]+=validation_time
                return original(*args)
            a.question_witness=check
            with self.subTest(query=query_time,validation=validation_time), self.assertRaisesRegex(TimeoutError,'confirmation'):
                self.sync(a,p,clock)
            self.assertNotIn('witnessed',p)

    def test_engine_below_ten_second_confirmation_passes(self):
        a,p,_,clock=self.fixture(now=10,started=10,end=40,delay=9.9)
        self.assertTrue(self.sync(a,p,clock)['confirmation_seconds']<10)

    def test_confirmation_query_is_capped_by_remaining_attempt(self):
        a,p,q,clock=self.fixture(now=38,started=10,end=40,delay=1)
        result=self.sync(a,p,clock)
        self.assertEqual(result['confirmation_seconds'],1)
        self.assertEqual(a.rt.deployment.admin.question.call_args.kwargs['timeout'],2)
        self.assertEqual(a.rt.command.deadline.end,40)

    def test_attempt_deadline_still_wins_under_ten_seconds(self):
        a,p,_,clock=self.fixture(now=38,started=10,end=40,delay=3)
        with self.assertRaises(TimeoutError):self.sync(a,p,clock)
        self.assertNotIn('witnessed',p)

    def test_expired_attempt_does_not_query_or_release(self):
        a,p,_,clock=self.fixture();clock[0]=41
        with self.assertRaises(TimeoutError):self.sync(a,p,clock)
        a.rt.deployment.admin.question.assert_not_called()
        self.assertNotIn('witnessed',p)

    def test_undefended_question_older_than_ten_seconds_is_allowed(self):
        a,p,_,clock=self.fixture(config='undefended',delay=1)
        result=self.sync(a,p,clock)
        self.assertEqual(result['age_seconds'],16)
        self.assertEqual(result['core_timeout_margin_seconds'],284)
        self.assertIsNone(result['confirmation_limit_seconds'])
        self.assertEqual(a.rt.deployment.admin.question.call_args.kwargs['timeout'],15)

    def test_undefended_query_itself_may_exceed_ten_within_attempt(self):
        a,p,_,clock=self.fixture(config='undefended',now=10,delay=11)
        self.assertEqual(self.sync(a,p,clock)['confirmation_seconds'],11)

    def test_core_expiry_must_leave_room_for_remaining_attempt(self):
        a,p,_,clock=self.fixture(config='undefended',now=299,started=0,end=310)
        with self.assertRaisesRegex(TimeoutError,'300-second'):self.sync(a,p,clock)
        self.assertNotIn('witnessed',p)

    def test_negative_question_age_is_rejected(self):
        a,p,_,clock=self.fixture(started=26)
        with self.assertRaises(TimeoutError):self.sync(a,p,clock)

    def test_cell_timestamp_cannot_extend_host_confirmation_limit(self):
        a,p,_,clock=self.fixture(now=10,started=10,delay=10)
        with self.assertRaises(TimeoutError):self.sync(a,p,clock,{'state':'sent','sent_at':10**12})

    def test_changed_auxiliary_question_still_prevents_release(self):
        a,p,_,clock=self.fixture(config='undefended');p['question']['qid']=99
        with self.assertRaisesRegex(ValueError,'auxiliary question changed'):self.sync(a,p,clock)
        a.rt.deployment.admin.allow_once.assert_not_called()
        self.assertNotIn('witnessed',p)

    @unittest.skipUnless(os.name=='posix','Linux pinned auxiliary preflight fixture; process/network mocked')
    def test_undefended_wrong_question_is_rejected_before_attack_start(self):
        from batch_fixtures import header
        from fourd_fixtures import ObjectRuntime
        from record import load_run
        from run_batch import Batch
        from run_registry import CASES
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            chosen=[CASES['NB-21']];rt=ObjectRuntime(Path(tmp),chosen,stack)
            real_arm=rt.arm
            def arm(config):
                real_arm(config)
                original=rt.support.begin_question
                rt.support.begin_question=lambda path:{**original(path),'workspace':'foreign'}
            rt.arm=arm
            start=Mock(wraps=rt.start);rt.start=start
            self.assertEqual(Batch(rt,chosen,['undefended'],header(rt)).execute(),1)
            meta,_=load_run(rt.evidence.directory.path)
            self.assertIn('witness mismatch',meta['controller_error']['message'])
            start.assert_not_called()


if __name__=='__main__':
    unittest.main()
