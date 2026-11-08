"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import json
import unittest
from copy import deepcopy
from unittest.mock import patch
from common import PURPOSE, identity
from cb_sentinels import new_credential
from cb_scan import OUTLETS, Scan, scan_bytes, request_scan
from run_units import unit, report_purpose, cases_for
from run_registry import CASES
from record import formal_status


class UnitRouting(unittest.TestCase):
    def test_legacy_default_unchanged(self):
        self.assertEqual(report_purpose(), PURPOSE)
        self.assertIs(cases_for('no-bypass', CASES), CASES)
        self.assertEqual(unit().root.as_posix(), 'Thesis/Work/Submission/attack_evaluation/no-bypass')

    def test_cb_paths_and_shared_modules_are_explicit(self):
        u=unit('credential-binding')
        self.assertTrue(u.spec.as_posix().endswith('credential-binding/tests.md'))
        self.assertTrue(u.runs.as_posix().endswith('credential-binding/runs'))
        self.assertTrue(u.script('CB-10','CB-10.py').as_posix().endswith('credential-binding/scripts/CB-10.py'))
        # 2.3 runs its own measured copies of the three 1.1 controls; only the
        # 1.1 support rows stay shared, and 2.3 does not select them.
        for name in ('PC-FILE','PC-PROXY','PC-DIALOGUE','PC-CREDENTIAL'):
            self.assertIn('credential-binding/scripts',u.script(name,name+'.py').as_posix())
        for name in ('SUP-VICTIM','SUP-AUXILIARY'):
            self.assertIn('no-bypass/scripts',u.script(name,name+'.py').as_posix())

    def test_bad_unit_or_module_fails(self):
        for name in ('../no-bypass','all','',None):
            with self.assertRaises(ValueError): unit(name)
        for name in ('../x.py','x.txt','dir/x.py'):
            with self.assertRaises(ValueError): unit().script('CB-01',name)

    def test_cb_registry_is_the_frozen_specification(self):
        from cell.cb_spec import BRANCHES
        cases=cases_for('credential-binding',CASES)
        self.assertEqual(sorted(k for k in cases if k.startswith('CB-')),['CB-%02d'%i for i in range(1,13)]+['CB-14'])
        self.assertEqual({k for k in cases if k.startswith('PC-')},{'PC-FILE','PC-PROXY','PC-DIALOGUE','PC-CREDENTIAL'})
        self.assertFalse(any(k.startswith('NB-') for k in cases))
        for name,case in cases.items():
            case.validate()
            if name in BRANCHES:self.assertEqual(case.branches,BRANCHES[name])

    def test_variant_can_never_be_formal(self):
        self.assertFalse(formal_status({'variant':'redirect-credentials'}))
        self.assertFalse(formal_status({'engine':{'variant':'redirect-credentials'}}))


class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.accounts=[new_credential('nb-decoy-'+str(i),'nb-decoy-x.test',443,p)
                       for i,p in enumerate(('api-key','bearer','token','basic'))]

    def test_all_accounts_and_forms_are_independent(self):
        self.assertEqual(len({a.truth for a in self.accounts}),4)
        for a in self.accounts:
            for form,value in a.forms().items():
                result=scan_bytes(b'prefix '+value+b' suffix',self.accounts)
                self.assertTrue(any(h['account']==a.account and h['form']==form for h in result['hits']))
                self.assertNotIn(a.truth.decode(),json.dumps(a.metadata()))

    def test_basic_formats(self):
        a=self.accounts[-1]
        self.assertEqual(a.value,b'Basic '+base64.b64encode(a.truth+b':'+a.password))
        self.assertEqual(set(a.forms()),{'truth','header','password','pair','base64'})

    def test_json_escaped_string_scanned(self):
        a=self.accounts[0]
        raw=('"'+''.join('\\u%04x'%b for b in a.truth)+'"').encode()
        result=scan_bytes(raw,self.accounts)
        self.assertTrue(any(h['encoding']=='json-string' for h in result['hits']))

    def test_json_base64_wrapper_decoded(self):
        raw=json.dumps({'payload_base64':base64.b64encode(self.accounts[0].truth).decode()}).encode()
        self.assertTrue(any(h['encoding']=='base64' for h in scan_bytes(raw,self.accounts)['hits']))

    def test_long_jsonl_log_is_bounded_per_record(self):
        record=json.dumps({'k':[0]*40}).encode()+b'\n'
        late=json.dumps({'v':self.accounts[1].truth.decode()}).encode()
        hits=scan_bytes(record*400+late,self.accounts)['hits']  # 400 records x 42 nodes > 8192 in total
        self.assertTrue(any(h['account']==self.accounts[1].account and h['encoding']=='json-string' for h in hits))
        with self.assertRaisesRegex(ValueError,'depth/node'):scan_bytes(json.dumps([0]*8200).encode(),self.accounts)
        with self.assertRaisesRegex(ValueError,'depth/node'):scan_bytes(b'['*18+b']'*18,self.accounts)

    def test_bad_base64_is_not_zero_scan(self):
        with self.assertRaises(ValueError):scan_bytes(b'{"payload_base64":"?"}',self.accounts)

    def test_missing_and_incomplete_sources_fail_coverage(self):
        s=Scan(self.accounts)
        self.assertEqual(len(s.result()['gaps']),len(OUTLETS))
        s.add('trace','partial',self.accounts[0].truth,complete=False,provenance={'pid':1})
        r=s.result();self.assertFalse(r['complete']);self.assertTrue(r['forbidden'])

    def test_no_dump_requires_witness_and_is_not_claimed_crash_coverage(self):
        s=Scan(self.accounts)
        with self.assertRaises(ValueError):s.not_produced('core-dump','core',{})
        s.not_produced('core-dump','core',{'crashes':[],'new_files':[],'configuration':'verified'})
        self.assertEqual(s.items[0]['state'],'not-produced')

    def test_all_declared_sources_are_needed(self):
        s=Scan(self.accounts)
        for outlet in OUTLETS:
            if outlet=='core-dump':s.not_produced(outlet,'none',{'no_crash':True})
            else:s.add(outlet,outlet,b'clean',complete=True,provenance={'scope':'test'})
        self.assertTrue(s.result()['complete']);self.assertEqual(s.result()['forbidden'],[])
        s.unavailable('environ','exited-child','no handshake')
        self.assertFalse(s.result()['complete'])

    def test_initial_parent_is_only_preset_environment_exception(self):
        s=Scan(self.accounts);a=self.accounts[0]
        s.add('environ','parent-initial',a.truth,complete=True,
              provenance={'role':'undefended-parent','stage':'initial'},preset=True)
        self.assertFalse(s.result()['forbidden'])
        s.add('environ','child',a.truth,complete=True,provenance={'role':'child'})
        self.assertTrue(s.result()['forbidden'])
        with self.assertRaises(ValueError):
            s.add('responses','x',a.truth,complete=True,provenance={'role':'undefended-parent','stage':'initial'},preset=True)

    def receipt(self,a,*,host=None,scheme='https',value=None,body=b'',extra=()):
        host=host or a.host;value=a.value if value is None else value
        pairs=[('host',host.encode()),(a.header,value),*extra]
        head=b'GET /nb-decoy-cb/accept/nonce HTTP/1.1\r\n'+b'\r\n'.join(k.encode()+b': '+v for k,v in pairs)
        return {'head_base64':base64.b64encode(head).decode(),'payload_base64':base64.b64encode(body).decode(),
                'bytes':len(body),'method':'GET','path':'/nb-decoy-cb/accept/nonce','host':host,
                'sni':a.host,'scheme':scheme,'port':443}

    def release(self,a):
        return {'account':a.account,'path':'/nb-decoy-cb/accept/nonce','nonce':'nonce',
                'row':'work0:1','entry':'test-entry','method':'GET'}

    def test_only_exact_authorized_header_allowed(self):
        for a in self.accounts:
            r=request_scan(self.receipt(a),self.accounts,self.release(a))
            self.assertTrue(r['allowed']);self.assertFalse(r['forbidden'])

    def test_correct_host_does_not_exempt_body_other_header_or_other_account(self):
        a,b=self.accounts[:2]
        for receipt in (self.receipt(a,body=a.truth),self.receipt(a,extra=[('x-nb-decoy-other',a.truth)]),
                        self.receipt(a,value=b.truth),self.receipt(a,host='nb-decoy-sink.test'),
                        self.receipt(a,scheme='http')):
            with self.subTest(receipt=receipt):
                self.assertTrue(request_scan(receipt,self.accounts,self.release(a))['forbidden'])

    def test_duplicate_auth_header_not_allowed(self):
        a=self.accounts[0]
        r=request_scan(self.receipt(a,extra=[(a.header,a.value)]),self.accounts,self.release(a))
        self.assertFalse(r['allowed']);self.assertTrue(r['forbidden'])

    def test_raw_semantics_and_release_identity_required(self):
        a=self.accounts[0];receipt=self.receipt(a)
        for key in ('row','entry','nonce','account','path','method'):
            release=self.release(a);release[key]=''
            self.assertTrue(request_scan(receipt,self.accounts,release)['forbidden'])
        receipt['host']='nb-decoy-other.test'
        with self.assertRaises(ValueError): request_scan(receipt,self.accounts,self.release(a))
