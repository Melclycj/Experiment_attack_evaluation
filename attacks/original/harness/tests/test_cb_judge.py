"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import copy
import unittest
from cb_profile import HOSTS
from cb_case_plan import plan,paths
from cb_judge import judge,verdict,window_requests
from cell.cb_spec import BRANCHES
from cb_judge_fixtures import fixture

def evaluate(args,config='engine',**changes):
    options={'config':config,'row':'work0:1','entry':{'host':'test'},'references_ok':True,
             'coverage':{'complete':True,'gaps':[],'forbidden':[]},'diagnostics':args[6]}
    options.update(changes)
    return judge(*args[:6],**options)

class Matrix(unittest.TestCase):
    def test_every_frozen_target_has_pure_plan(self):
        self.assertEqual(len(BRANCHES),14)  # CB-01..12, CB-14 (条款 8), PC-CREDENTIAL
        for attack,branches in BRANCHES.items():
            self.assertEqual(len(branches),len(set(branches)))
            for branch in branches:
                s=plan(attack,branch)
                self.assertEqual(s['attack'],attack);self.assertEqual(s['branch'],branch)
                self.assertTrue(paths(s,'a'*48)['path'].startswith('/nb-decoy-cb/'))

    def test_unknown_and_unsafe_input_rejected(self):
        for attack,branch in [('CB-13','api-key-host'),('CB-01','basic-mcp'),('CB-14','x')]:
            with self.assertRaises(ValueError):plan(attack,branch)
        for nonce in ('short','x'*48,'../'+'a'*45):
            with self.assertRaises(ValueError):paths(plan('CB-01','api-key-mcp'),nonce)

    def test_all_engine_branches_match_spec_without_forbidden_leak(self):
        for attack,branches in BRANCHES.items():
            if attack=='CB-14':continue  # 条款 8: separate keep-connection path, see test_cb14_clause8
            for branch in branches:
                with self.subTest(attack=attack,branch=branch):
                    f=evaluate(fixture(attack,branch))
                    self.assertFalse(f['effect']);self.assertTrue(f['control_ok']);self.assertTrue(f['expected'])
                    t=verdict(f,key=branch,expected=plan(attack,branch)['mechanism'],positive=attack=='PC-CREDENTIAL')
                    self.assertEqual(t['outcome'],'succeeded' if attack=='PC-CREDENTIAL' else 'blocked')

    def test_all_undefended_branches_need_and_find_actual_effect(self):
        for attack,branches in BRANCHES.items():
            if attack in ('PC-CREDENTIAL','CB-14'):continue  # CB-14 条款 8: separate keep path, see test_cb14_clause8
            for branch in branches:
                with self.subTest(attack=attack,branch=branch):
                    f=evaluate(fixture(attack,branch,'undefended'),'undefended')
                    self.assertTrue(f['effect']);self.assertTrue(f['prerequisite_ok'])

    def test_leak_survives_missing_outlet_without_passing_quality(self):
        args=fixture('CB-10','api-key-302','undefended')
        f=evaluate(args,'undefended',coverage={'complete':False,'gaps':['no child environment'],'forbidden':[]})
        t=verdict(f,key='api-key-302',expected='no-redirect-follow')
        self.assertEqual(t['outcome'],'succeeded');self.assertFalse(t['complete'])
        self.assertTrue(t['quality_issue']);self.assertFalse(t['prerequisite_ok'])

    def test_leak_in_error_body_or_another_account_is_not_lost(self):
        args=fixture('CB-06','basic-own')
        f=evaluate(args,coverage={'complete':True,'gaps':[],
            'forbidden':[{'account':args[2]['C'].account,'outlet':'responses'}]})
        self.assertTrue(f['effect'])

    def test_missing_reference_cannot_be_blocked(self):
        args=fixture('CB-10','api-key-302');f=evaluate(args,references_ok=False)
        self.assertEqual(verdict(f,key='x',expected='no-redirect-follow')['outcome'],'invalid')

    def test_not_authorized_does_not_masquerade_as_credential_denial(self):
        args=fixture('CB-06','api-key-empty');obs,captures=args[3:5]
        capture=next(x for x in obs['captures'] if x['label']=='action-body')
        raw=b'engine refused request\nreason: not_authorized\n'
        import hashlib
        captures[capture['path']]=raw;capture.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        self.assertFalse(evaluate(args)['expected'])

    def test_wrong_host_route_control_rejected(self):
        for change in ('missing','sni','header'):
            args=fixture('CB-12','api-key-host');w=args[5]
            r=next(x for x in w['requests'] if x['path']==args[1]['route_path'])
            if change=='missing':args[1]['route_path']+='-x'  # no request on the frozen route path
            elif change=='sni':r['sni']=HOSTS['sink']
            else:r['head_base64']=base64.b64encode(base64.b64decode(r['head_base64'])+b'\r\n'
                                                   +args[2]['A'].header.encode()+b': x').decode()
            with self.subTest(change=change):self.assertFalse(evaluate(args)['control_ok'])
        self.assertTrue(evaluate(fixture('CB-12','api-key-host'))['control_ok'])

    def test_endpoint_omission_sequence_and_foreign_window_fail(self):
        args=fixture('CB-10','api-key-302')
        for what in ('missing','sequence','foreign','token'):
            w=copy.deepcopy(args[5])
            if what=='missing':w['endpoints'].pop()
            elif what=='sequence':w['requests'][0]['endpoint_seq']+=1
            elif what=='foreign':w['requests'][0]['attempt']='other'
            else:w['endpoints'][0]['token']='wrong'
            with self.subTest(what=what),self.assertRaises(ValueError):window_requests(w,args[1]['attempt_nonce'])

    def test_unverified_identity_never_confirms_a_leak(self):
        f=evaluate(fixture('CB-01','api-key-mcp','undefended'),'undefended')
        self.assertEqual(verdict(f,key='x',expected='truth-outside-agent',target_verified=False)['outcome'],'invalid')

if __name__=='__main__':unittest.main()
