"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from cell_payload import CELL, CORE, prepare_payload
from nb_contract import manifest, encoded, REQUEST, stem
from runner import Context, run
from test_cell_contract import request
from test_cell_runner import MemoryFiles, Clock
from test_cell_payload import elf_fixture
from run_registry import CASES, SUPPORT_MODULES, SUPPORT
from run_config import selection, schedule
from foura_fixtures import H, SCRIPTS


class AssemblyTests(unittest.TestCase):
    def test_all_five_explicit_modules_in_readonly_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); probe = root / 'probe'; probe.write_bytes(elf_fixture())
            modules = {**{k: SCRIPTS / c.module for k,c in CASES.items() if c.kind == 'control'},
                       **{k: SCRIPTS / name for k,name in SUPPORT_MODULES.items()}}
            with patch('subprocess.Popen', side_effect=AssertionError('no launch')):
                result = prepare_payload(CELL, probe, modules, root/'stage', support_modules=SUPPORT_MODULES)
            reg = manifest(json.loads(result['modules.json'].read_bytes()))
            self.assertEqual(len(reg['modules']), 5)
            for key, item in reg['modules'].items():
                self.assertEqual(item.get('lifetime', 30), 540 if key in SUPPORT_MODULES else 30)
                self.assertEqual(hashlib.sha256(result[item['path']].read_bytes()).hexdigest(), item['sha256'])
            for shared in ('nb_wire.py', 'nb_support.py'):
                self.assertIn(shared, CORE)
                self.assertEqual(result[shared].read_bytes(), (CELL/shared).read_bytes())

    def test_support_cannot_silently_get_attack_lifetime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); probe=root/'probe'; probe.write_bytes(elf_fixture())
            with self.assertRaisesRegex(ValueError, 'explicit trusted'):
                prepare_payload(CELL, probe, {'SUP-VICTIM':SCRIPTS/'SUP-VICTIM.py'}, root/'stage')

    def test_non_support_cannot_get_extended_lifetime(self):
        for key, life in [('PC-FILE',540), ('NB-01',540), ('SUP-VICTIM',30), ('SUP-OTHER',540), ('PC-FILE',True)]:
            with self.subTest(key=key,life=life), self.assertRaises(ValueError):
                manifest({'v':1,'modules':{key:{'path':'modules/x.py','sha256':'a'*64,'lifetime':life}}})

    def _run_clock(self, key, lifetime=None, parameters=None):
        req=request(); req['attack']=key
        from decoys import synchronization
        req['sync']=synchronization(req['run'],req['config'],key,req['repeat'])
        req['parameters']=parameters or {}
        code=b'def control(ctx): return True\ndef action(ctx): ctx.sleep(31)\n'
        item={'path':'modules/x.py','sha256':hashlib.sha256(code).hexdigest()}
        if lifetime is not None: item['lifetime']=lifetime
        work=MemoryFiles({REQUEST:encoded(req)})
        payload=MemoryFiles({'modules.json':encoded({'v':1,'modules':{key:item}}),'modules/x.py':code})
        clock=Clock()
        factory=lambda *a,**k: Context(*a,**k,clock=clock,sleep=clock.sleep)
        return run(work,payload,context_factory=factory), json.loads(work.values[stem(req)+'-observed.json'])

    def test_support_survives_thirty_seconds_offline_clock(self):
        code, obs=self._run_clock('SUP-VICTIM',540)
        self.assertEqual(code,0); self.assertTrue(obs['complete'])

    def test_request_cannot_extend_attack_deadline(self):
        code, obs=self._run_clock('NB-06',parameters={'lifetime':540,'timeout':540})
        self.assertEqual(code,2); self.assertEqual(obs['error']['type'],'TimeoutError')

    def test_only_three_controls_registered_no_attack_fixtures(self):
        controls = {k: c for k, c in CASES.items() if c.kind == 'control'}
        self.assertEqual(set(controls),{'PC-FILE','PC-PROXY','PC-DIALOGUE'})
        self.assertTrue(callable(SUPPORT))
        chosen=selection(list(controls),['engine','undefended'],CASES)
        self.assertEqual(len(schedule(chosen,['engine','undefended'])),3)
        for i in range(1,29):
            with self.assertRaises(ValueError): selection([f'NB-{i:02}'],['engine'],CASES)

    def test_all_source_is_small_and_purpose_marked(self):
        paths=[*SCRIPTS.glob('*.py'),*(H/x for x in ('case_io.py','listener_witness.py','listener_client.py',
              'support_rows.py','positive_controls.py')),*(CELL/x for x in CORE)]
        for p in paths:
            with self.subTest(path=p.name):
                text=p.read_text(encoding='utf-8'); ast.parse(text)
                self.assertIn('这是 1.1 隔离论证的验证测试',text.splitlines()[0])
                self.assertLessEqual(len(text.splitlines()),400)

    def test_helpers_use_only_shared_snapshotted_imports(self):
        for name in SUPPORT_MODULES.values():
            tree=ast.parse((SCRIPTS/name).read_text(encoding='utf-8'))
            self.assertEqual({n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)}, {'nb_support'})
        self.assertIn('support_modules=self.bundle[\'support_modules\']',(H/'run_runtime.py').read_text(encoding='utf-8'))
