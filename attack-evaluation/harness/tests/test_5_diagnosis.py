"""这是 1.1 隔离论证的验证测试：NB-19/27 逐目标归因；全部外部效果为显式 mock。"""
import copy
import unittest
from connection_observe import observe_target
from fourc_fixtures import prepared, observations, service_window
from judge import classify_target
from nb_conn_spec import SPECS


def fact(attack, key, success=False, change=None, config='undefended'):
    p=prepared(attack,config);obs,caps=observations(attack,p,success)
    window=service_window(attack,key,p,success)
    if change:change(p,obs,caps,window)
    value=observe_target(attack,key,p,obs,caps,window,{'file':'offline-window.json'})
    prerequisite=value.pop('prerequisite_ok')
    result=classify_target(**value,target_verified=True,complete=True)
    return result,prerequisite


class TargetDiagnosisTests(unittest.TestCase):
    pass


def make_test(attack,key,mode):
    def test(self):
        success=mode in ('success','wrong-end','wrong-target','failed-control')
        def mutate(p,obs,caps,window):
            action=next(v['values'] for v in obs['observed'] if v['phase']=='action' and v['label']==key+'-result')
            if mode=='wrong-end':window['end']['token']='wrong'
            if mode=='wrong-target':action['target']={'kind':'abstract','name':'nb-decoy-wrong'}
            if mode=='failed-control':
                control=next(v['values'] for v in obs['observed'] if v['phase']=='control' and v['label']==key+'-result')
                control.update(errno=13,rc=-1,step='connect')
            if mode=='permission':action.update(errno=13,rc=-1,step='connect')
            if mode=='timeout':action.update(errno=110,rc=-1,step='recv')
            if mode=='invalid-step':action.update(errno=13,rc=-1,step='not-a-syscall')
            if mode=='invalid-complete':action.update(errno=13,rc=-1,step='complete')
        result,prerequisite=fact(attack,key,success,mutate)
        diagnosis=result['external_fact']['undefended_diagnosis']
        category=('succeeded' if mode=='success' else 'host-condition-unresolved' if mode in ('no-effect','permission')
                  else 'script-or-evidence-error')
        self.assertEqual(diagnosis['category'],category)
        self.assertFalse(diagnosis['cause_verified']);self.assertFalse(diagnosis['real_socket_metadata_used'])
        self.assertEqual(result['outcome'],'succeeded' if mode=='success' else 'invalid')
        self.assertEqual(result['external_effect'],success)
        self.assertEqual(prerequisite,mode=='success')
        if mode=='permission':self.assertEqual(diagnosis['errno'],13)
        if mode in ('no-effect','permission'):self.assertIn('host-condition-unresolved',result['invalid_reason'])
    return test


for attack in ('NB-19','NB-27'):
    for key in SPECS[attack]:
        for mode in ('success','no-effect','permission','wrong-end','wrong-target','failed-control','timeout','invalid-step','invalid-complete'):
            setattr(TargetDiagnosisTests,'test_'+(attack+'_'+key+'_'+mode).replace('-','_'),make_test(attack,key,mode))


class NoAttributionLeakTests(unittest.TestCase):
    def test_engine_errno_remains_expected_mechanism_not_host_attribution(self):
        for attack in ('NB-19','NB-27'):
            for key in SPECS[attack]:
                result,_=fact(attack,key,config='engine')
                self.assertEqual(result['outcome'],'blocked')
                self.assertNotIn('undefended_diagnosis',result['external_fact'])

    def test_real_daemon_absence_cannot_explain_owned_decoy_failure(self):
        def mutate(p,o,c,w):
            p['real_sockets']=[{'path':'/var/run/docker.sock','exists':False}]
        result,_=fact('NB-19','daemon-path',change=mutate)
        self.assertEqual(result['external_fact']['undefended_diagnosis']['category'],'host-condition-unresolved')
        self.assertFalse(result['external_fact']['undefended_diagnosis']['real_socket_metadata_used'])
