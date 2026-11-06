"""这是 1.1 隔离论证的验证测试：真实判官/配对/归档结合 mock 外部窗口，非试跑。"""
from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from batch_fixtures import Adapter, FakeRuntime, cases, header, patches
from connection_cases import ConnectionCase
from connection_observe import observe_target
from fourc_fixtures import prepared, observations, service_window
from record import load_run
from run_batch import Batch
from run_registry import CASES


class SocketAdapter(Adapter):
    """Use production contracts/judges with generated, explicitly mock facts."""
    def contract(self):
        return ConnectionCase(self.rt,self.attack).contract()

    def prepare(self,config,repeat,contract):
        return prepared(self.attack,config)

    def observe(self,p,obs,caps,window):
        result={}
        for key in p['targets']:
            success=p['config']=='undefended' and key!=self.rt.missing
            observed,captured=observations(self.attack,p,success)
            external=service_window(self.attack,key,p,success)
            evidence=self.rt.evidence.raw(json.dumps(external).encode(),'mock-window.json')
            result[key]=observe_target(self.attack,key,p,observed,captured,external,evidence)
        return result


class PairingAndArchiveTests(unittest.TestCase):
    def exercise(self,attack,missing=None):
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            chosen=[replace(CASES[attack],factory=lambda rt:SocketAdapter(rt,attack)),cases()[1]]
            rt=FakeRuntime(Path(tmp),chosen);rt.missing=missing;patches(rt,stack)
            code=Batch(rt,chosen,['engine','undefended'],header(rt)).execute()
            meta,rows=load_run(rt.evidence.directory.path)
            return code,meta,rows

    def test_each_target_needs_its_own_success_and_diagnostic_survives_archive(self):
        for attack,missing in [('NB-19','daemon-path'),('NB-27','bus'),('NB-27','systemd'),('NB-27','abstract')]:
            with self.subTest(attack=attack,missing=missing):
                code,meta,rows=self.exercise(attack,missing)
                self.assertEqual(code,1);self.assertTrue(meta['cleanup_ok'])
                self.assertEqual(meta['report']['batch']['state'],'failed')
                engine={t['id']:t for t in rows[0]['attempts'][0]['targets']}
                peer={t['id']:t for t in rows[2]['attempts'][0]['targets']}
                self.assertEqual(engine[missing]['outcome'],'invalid')
                self.assertEqual(peer[missing]['outcome'],'invalid')
                self.assertEqual(peer[missing]['external_fact']['undefended_diagnosis']['category'],'host-condition-unresolved')
                for key in set(peer)-{missing}:
                    self.assertEqual(engine[key]['outcome'],'blocked');self.assertEqual(peer[key]['outcome'],'succeeded')
                self.assertEqual(rows[2]['outcome'],'succeeded')  # Retain sibling effects, NOT batch pass.
                self.assertIsNone(rows[0]['upper_bound'])

    def test_complete_own_successes_allow_pairing(self):
        for attack in ('NB-19','NB-27'):
            code,meta,rows=self.exercise(attack)
            self.assertEqual(code,0);self.assertIsNone(meta['controller_error'])
            self.assertTrue(all(t['pairing']['satisfied'] for t in rows[0]['attempts'][0]['targets']))
            self.assertEqual(rows[0]['script'],rows[2]['script'])
            self.assertEqual(rows[0]['request_contract'],rows[2]['request_contract'])

    def test_target_parent_preflight_failure_stops_before_any_undefended_start(self):
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            chosen=cases();rt=FakeRuntime(Path(tmp),chosen,fail='access');patches(rt,stack)
            code=Batch(rt,chosen,['engine','undefended'],header(rt)).execute()
            meta,rows=load_run(rt.evidence.directory.path)
            self.assertEqual(code,1);self.assertNotIn('start-undefended',rt.events)
            self.assertIn('access',meta['controller_error']['message']);self.assertTrue(meta['cleanup_ok'])
            self.assertTrue(all(r['outcome']=='invalid' for r in rows if r['kind']=='attack'))
