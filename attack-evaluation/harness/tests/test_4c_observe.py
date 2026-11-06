"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import base64
import copy
import unittest
from connection_observe import observe_target
from fourc_fixtures import prepared, observations, service_window
from nb_conn_spec import SPECS, DIRECT


def judge(attack, key, config='engine', success=False, mutation=None):
    p = prepared(attack, config)
    obs, caps = observations(attack, p, success)
    win = service_window(attack, key, p, success)
    if mutation:
        mutation(p, obs, caps, win)
    return observe_target(attack, key, p, obs, caps, win, {'file': 'offline-window.json'})


class AddressJudges(unittest.TestCase):
    pass


def test_matrix(attack, key, mode):
    def test(self):
        mutations = {
            'missing-capture': lambda p,o,c,w: c.clear(),
            'wrong-end': lambda p,o,c,w: w['end'].update(token='wrong'),
            'missing-end': lambda p,o,c,w: w.update(end={}),
            'wrong-listener': lambda p,o,c,w: w['listener'].update(target={'kind':'abstract','name':'nb-decoy-wrong'}),
            'gap': lambda p,o,c,w: w.update(cursor=5),
            'wrong-attempt': lambda p,o,c,w: w['end'].update(attempt='other'),
        }
        success = mode != 'blocked'
        result = judge(attack, key, 'undefended' if success else 'engine', success, mutations.get(mode))
        self.assertEqual(result['external_effect'], success)
        if mode in ('blocked','succeeded'):
            self.assertEqual(result['invalid_reason'], '')
            self.assertTrue(result['control_ok'])
            self.assertEqual(result['expected_observation'], not success)
            self.assertEqual(result['prerequisite_ok'], success)
        else:
            self.assertTrue(result['invalid_reason'])
            self.assertFalse(result['prerequisite_ok'])
    return test


for attack in SPECS:
    for key in SPECS[attack]:
        for mode in ('blocked','succeeded','missing-capture','wrong-end','missing-end','wrong-listener','gap','wrong-attempt'):
            setattr(AddressJudges, 'test_' + '_'.join((attack,key,mode)).replace('-','_'), test_matrix(attack,key,mode))


class QualityTests(unittest.TestCase):
    def test_one_addresses_marker_cannot_prove_another_address(self):
        for attack, key in (('NB-19','daemon-path'),('NB-27','bus'),('NB-25','host'),('NB-17','global')):
            def mutate(p,o,c,w):
                data = b'wrong-nonce'
                w['requests'][0].update(payload_base64=base64.b64encode(data).decode(), bytes=len(data))
                w['markers'] = {}
            result = judge(attack,key,'undefended',True,mutate)
            self.assertFalse(result['external_effect']); self.assertTrue(result['invalid_reason'])

    def test_wrong_unix_credentials_keep_candidate_but_invalidate(self):
        result=judge('NB-25','host','undefended',True,
                     lambda p,o,c,w:w['requests'][0]['peer'].update(uid=0))
        self.assertTrue(result['external_effect']); self.assertIn('credentials',result['invalid_reason'])

    def test_end_generated_marker_is_not_an_attack_effect(self):
        def mutate(p,o,c,w):
            w['markers']['nb-decoy-0000']={'payload_base64':w['end']['payload_base64']}
        result=judge('NB-27','bus',mutation=mutate)
        self.assertFalse(result['external_effect']);self.assertIn('marker',result['invalid_reason'])

    def test_duplicate_records_are_quality_failure(self):
        def mutate(p,o,c,w):
            w['requests'].append({**w['requests'][0],'seq':1});w['end']['seq']=2
        result=judge('NB-17','global','undefended',True,mutate)
        self.assertTrue(result['external_effect']);self.assertIn('duplicate',result['invalid_reason'])

    def test_control_failure_keeps_external_effect(self):
        def mutate(p,o,c,w):
            row=next(r for r in o['observed'] if r['phase']=='control' and r['label']=='relay-result')
            row['values'].update(step='connect',errno=111,rc=-1)
        result=judge('NB-16','relay','undefended',True,mutate)
        self.assertFalse(result['control_ok']);self.assertTrue(result['external_effect'])
        self.assertFalse(result['prerequisite_ok'])

    def test_changed_action_endpoint_rejected(self):
        def mutate(p,o,c,w):
            row=next(r for r in o['observed'] if r['phase']=='action' and r['label']=='relay-result')
            row['values']['target']={**row['values']['target'],'port':1}
        self.assertIn('different endpoint',judge('NB-16','relay',mutation=mutate)['invalid_reason'])

    def test_c_report_must_agree_with_raw_stderr(self):
        for attack in DIRECT:
            def mutate(p,o,c,w):
                row=next(r for r in o['observed'] if r['phase']=='action' and r['label']=='global')
                row['values']['stderr']='{"step":"complete","rc":0,"errno":0}\n'
            self.assertTrue(judge(attack,'global',mutation=mutate)['invalid_reason'])

    def test_udp_recv_timeout_never_counts_as_isolation(self):
        def mutate(p,o,c,w):
            for row in o['observed']:
                if row['phase']=='action' and row['label']=='loopback':
                    row['values']['stderr']=row['values']['stderr'].replace('111','11')
                if row['phase']=='action' and row['label']=='loopback-result':
                    row['values']['errno']=11
        self.assertIn('timeout',judge('NB-18','loopback',mutation=mutate)['invalid_reason'])
