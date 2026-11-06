"""NB-26 live observation/release/restore and same-uid control tests using only mocks."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from common import json_bytes
from cell.nb_contract import stem
from foure_fixtures import req, report, FakeCandidate, candidate_rows
from foura_fixtures import receipt, window
from userns_case import UsernsCase
from userns_control import SameUidControl
from netns_witness import effect, links


class WitnessTests(unittest.TestCase):
    def test_effect_requires_same_namespace_identity_and_only_named_new_peer(self):
        c=FakeCandidate(Mock());base=c.before
        self.assertFalse(effect(base,copy.deepcopy(base),'nbdp1'))
        live={**base,'links':candidate_rows(True)};self.assertTrue(effect(base,live,'nbdp1'))
        for field in ('pid','starttime','net','user'):
            with self.subTest(field=field),self.assertRaises(ValueError):effect(base,{**live,field:'other'},'nbdp1')
        for rows in ([{'ifindex':2,'ifname':'nbdp1'}],candidate_rows()+[{'ifindex':2,'ifname':'eth0'}],
                     candidate_rows(True)+[{'ifindex':3,'ifname':'nbdp1'}]):
            with self.subTest(rows=rows),self.assertRaises(ValueError):effect(base,{**base,'links':rows},'nbdp1')

    def test_invalid_duplicate_or_unbounded_link_lists(self):
        for rows in ([{'ifindex':0,'ifname':'lo'}],candidate_rows()*2,[],[{}],None):
            if rows==[]:self.assertEqual(links(rows),[]);continue
            with self.subTest(rows=rows),self.assertRaises((ValueError,KeyError,TypeError)):links(rows)


class HostCaseTests(unittest.TestCase):
    def setup_case(self, cfg='engine'):
        rt=Mock(work=Path('/tmp/nb-decoy-work'));rt.deployment.refs={};rt.rows=[]
        rt.evidence.raw.return_value={'file':'offline.json'}
        case=UsernsCase(rt);case.candidate=FakeCandidate(rt)
        q=req(cfg);p={'config':cfg,'request':q,'parameters':q['parameters'],
                    'targets':q['targets'],'before':{'candidate':case.candidate.before}}
        case.control={'ok':True};case.handle=Mock(uid=70001,group=None,closed=True)
        case.worker=Mock(initial={'pid':17,'start_time':88});case.worker.exited.return_value=True
        return case,p

    def sync(self,case,p,r):
        ready={'attempt':stem(p['request']),'nonce':p['request']['sync']['nonce'],'state':'done'}
        worker=case.worker
        with patch('userns_case.read_beneath',return_value=json_bytes(r)), \
             patch('userns_case.worker_ref',return_value=worker):
            return case.synchronize(p,ready)

    def final(self,case,p,r):
        obs={'observed':[{'phase':'action','label':'worker-result','values':{'report':r}}]};caps={}
        receipt(obs,caps,'worker',json_bytes(r))
        w=window();w['end']['attempt']=p['request']['sync']['nonce']
        return obs,caps,w

    def test_live_witness_before_release_and_exit_restoration_before_verdict(self):
        for cfg in ('engine','undefended'):
            case,p=self.setup_case(cfg);r=report(p['request'],cfg=='undefended')
            case.candidate.current['links']=candidate_rows(cfg=='undefended')
            fact=self.sync(case,p,r);self.assertEqual(fact['effect'],cfg=='undefended')
            self.assertEqual(case.worker.read.call_count,2)
            case.candidate.current=copy.deepcopy(case.candidate.before)
            f=case.observe(p,*self.final(case,p,r))['netns']
            self.assertEqual(f['invalid_reason'],'');self.assertTrue(f['control_ok'])
            self.assertEqual(f['expected_observation'],cfg=='engine')
            self.assertEqual(f['prerequisite_ok'],cfg=='undefended')

    def test_wrong_nonce_repeated_sync_or_unwitnessed_uid_fails_before_release(self):
        case,p=self.setup_case();r=report(p['request'])
        with self.assertRaises(ValueError):case.synchronize(p,{'state':'done'})
        r['original_uid']=123
        with self.assertRaises(ValueError):self.sync(case,p,r)
        self.sync(case,p,report(p['request']))
        with self.assertRaises(ValueError):self.sync(case,p,report(p['request']))

    def test_worker_exit_during_observation_rejects_sync(self):
        case,p=self.setup_case();case.worker.read.side_effect=[{},RuntimeError('exited')]
        with self.assertRaisesRegex(RuntimeError,'exited'):self.sync(case,p,report(p['request']))
        self.assertIsNone(case.live)

    def test_no_live_witness_or_no_exit_never_blocks(self):
        for mode in ('missing','alive'):
            case,p=self.setup_case();r=report(p['request'])
            if mode=='alive':self.sync(case,p,r);case.worker.exited.return_value=False
            f=case.observe(p,*self.final(case,p,r))['netns']
            self.assertTrue(f['invalid_reason']);self.assertFalse(f['expected_observation'])

    def test_capture_restore_control_and_end_failures_preserve_candidate_effect(self):
        for mode in ('capture','restore','control','end'):
            case,p=self.setup_case('undefended');r=report(p['request'],True)
            case.candidate.current['links']=candidate_rows(True);self.sync(case,p,r)
            case.candidate.current=copy.deepcopy(case.candidate.before)
            obs,caps,w=self.final(case,p,r)
            if mode=='capture':obs['captures']=[]
            if mode=='restore':case.candidate.current['links']=candidate_rows(True)
            if mode=='control':case.control['ok']=False
            if mode=='end':w['end']={}
            f=case.observe(p,obs,caps,w)['netns']
            with self.subTest(mode=mode):
                self.assertTrue(f['external_effect']);self.assertFalse(f['prerequisite_ok'])
                self.assertTrue(f['invalid_reason'] or not f['control_ok'])

    def test_restore_releases_pins_even_with_live_row_but_is_not_success(self):
        case,p=self.setup_case();case.handle.closed=False;candidate=case.candidate;worker=case.worker
        case.target=p['targets']['netns'];case.rt.deployment.refs['nb26-candidate']=candidate.ref
        with self.assertRaisesRegex(RuntimeError,'attack tree live'):case.restore(p)
        worker.close.assert_called_once();candidate.ref.close.assert_called_once()
        self.assertNotIn('nb26-candidate',case.rt.deployment.refs)
        case.rt.targets.release.assert_called_once_with('netns',p['targets']['netns'])

    def test_prepare_failure_unwinds_registered_candidate(self):
        rt=Mock(bundle={'run':'offline'},rows=[]);rt.deployment.refs={}
        case=UsernsCase(rt)
        with patch('userns_case.Candidate',side_effect=FakeCandidate), \
             patch('userns_case.SameUidControl') as control:
            control.return_value.run.side_effect=ValueError('control failed')
            with self.assertRaisesRegex(ValueError,'control failed'):case.prepare('engine',1,case.contract())
        rt.targets.release.assert_called_once();self.assertIsNone(case.candidate)
        self.assertNotIn('nb26-candidate',rt.deployment.refs)


class OutsideControlTests(unittest.TestCase):
    def fixture(self, success=True):
        rt=Mock(cap={'first':70000,'last':70010,'spare_uid':70010},rows=[],serial=0)
        rt.deployment.root=Path('/tmp/nb-decoy-root');rt.deployment.scratch=Path('/tmp/nb-decoy-scratch')
        rt.payload={'nb26_worker.py':Path('/tmp/nb-decoy-payload/nb26_worker.py')}
        rt.evidence.raw.return_value={'file':'offline.json'}
        rt.command.deadline.left.side_effect=lambda n:n
        q=req('engine-control');r=report(q,True,uid=70010)
        child=Mock(buffers={'stdout':bytearray(json_bytes(r))});child.proc.pid=17;child.proc.poll.return_value=None
        rt.command.start.return_value=child
        group=Mock(created=True);group.empty.return_value=True
        ref=Mock(initial={'pid':17});ref.exited.return_value=True
        candidate=FakeCandidate(rt);live=copy.deepcopy(candidate.before);live['links']=candidate_rows(success)
        candidate.read=Mock(side_effect=[live,copy.deepcopy(candidate.before)])
        return rt,q,group,ref,candidate

    def execute(self, data, catalog_last=70009):
        rt,q,group,ref,candidate=data
        with patch('userns_control.read_owned',return_value=json_bytes({'uid_range':{'first':70000,'last':catalog_last}})), \
             patch('userns_control.AttemptGroup',return_value=group),patch('userns_control.worker_ref',return_value=ref):
            ctl=SameUidControl(rt,candidate,q);value=ctl.run()
        return ctl,value

    def test_reserved_uid_group_bounded_argv_and_two_phase_release(self):
        data=self.fixture();rt,q,group,ref,candidate=data
        ctl,fact=self.execute(data)
        self.assertTrue(fact['ok']);self.assertTrue(ctl.closed)
        argv=rt.command.start.call_args.args[0]
        self.assertIn('--reuid=70010',argv);self.assertIn('--no-new-privs',argv)
        self.assertEqual(argv[-1],'--host-control')
        self.assertIs(rt.command.start.call_args.kwargs['group'],group)
        self.assertEqual(rt.command.send_input.call_count,2)
        self.assertIn(b'"state":"release"',rt.command.send_input.call_args.args[1])
        rt.command.wait.assert_called_once();group.remove.assert_called_once();ref.close.assert_called_once()
        self.assertEqual(ref.read.call_count,2)

    def test_control_uid_must_not_be_in_allocator(self):
        data=self.fixture()
        with self.assertRaisesRegex(ValueError,'excluded'):self.execute(data,70010)
        data[0].command.start.assert_not_called()

    def test_no_effect_releases_and_restores_but_fails_positive_control(self):
        data=self.fixture(False)
        with self.assertRaisesRegex(ValueError,'positive control failed'):self.execute(data)
        data[0].command.wait.assert_called_once();data[2].remove.assert_called_once()

    def test_bad_nonce_does_not_release_and_cleanup_kills_owned_group(self):
        data=self.fixture();rt,q,group,ref,candidate=data
        rt.command.start.return_value.buffers={'stdout':bytearray(b'{"nonce":"foreign"}\n')}
        group.empty.return_value=False
        with self.assertRaises(ValueError):self.execute(data)
        self.assertEqual(rt.command.send_input.call_count,1)
        group.kill_and_wait.assert_called_once();group.remove.assert_called_once()

    def test_restore_failure_cannot_be_accepted(self):
        data=self.fixture();candidate=data[-1]
        candidate.read.side_effect=[{**candidate.before,'links':candidate_rows(True)}]*2
        with self.assertRaisesRegex(ValueError,'restore'):self.execute(data)
        data[2].remove.assert_called_once()
