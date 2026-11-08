"""这是 1.1 隔离论证的验证测试：31 项及两常开程序的快照与 payload 完整性，纯离线。"""
import ast
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from build import inventory
from cell_payload import CELL, CORE, prepare_payload
from common import identity, json_bytes
from foura_fixtures import H, SCRIPTS
from fourf_fixtures import ORDER
from nb_contract import manifest, module_code
from run_boot import HREL, NREL, stage, load_bundle
from run_config import batch_capacity, schedule, selection
from run_contract import validate_contract
from run_registry import CASES, SUPPORT, SUPPORT_MODULES
from support_rows import SupportRows
from test_cell_payload import elf_fixture
from test_cell_runner import MemoryFiles

ATTACKS = {f'NB-{i:02}' for i in range(1, 29)}
CONTROLS = {'PC-FILE', 'PC-PROXY', 'PC-DIALOGUE'}
BOUNDARY = {'BD-01', 'BD-02'}


class RegistryTests(unittest.TestCase):
    def test_exact_set_unique_modules_and_production_contracts(self):
        self.assertEqual(set(CASES), ATTACKS | CONTROLS | BOUNDARY)
        self.assertEqual(len({c.module for c in CASES.values()}), 33)
        self.assertEqual(SUPPORT_MODULES, {'SUP-VICTIM': 'SUP-VICTIM.py', 'SUP-AUXILIARY': 'SUP-AUXILIARY.py'})
        self.assertIs(SUPPORT, SupportRows)
        for key, case in CASES.items():
            with self.subTest(attack=key):
                self.assertEqual(case.validate().attack, key)
                self.assertEqual(case.module, key + '.py')
                self.assertEqual(case.repeats, 1)
                rt = SimpleNamespace(home=Path('/tmp/nb-decoy-offline'))
                adapter = case.factory(rt)
                validate_contract(adapter.contract(), key)
                for method in ('prepare', 'interact', 'synchronize', 'observe', 'restore'):
                    self.assertTrue(callable(getattr(adapter, method)))
                self.assertEqual(case.sync, {'NB-21': 'sent', 'NB-26': 'done'}.get(key))
                self.assertEqual(case.branches, ('source', 'mount') if key == 'NB-15' else ())

    def test_selection_capacity_and_destructive_tail_keep_all_cases(self):
        chosen = selection(ORDER, ['engine', 'undefended'], CASES)
        plan = schedule(chosen, ['engine', 'undefended'])
        self.assertEqual(len(plan), 59)
        self.assertEqual([c.attack for cfg, c in plan[-2:]], ['NB-23', 'NB-22'])
        self.assertEqual({c.attack for cfg, c in plan if cfg == 'undefended'}, ATTACKS)
        self.assertEqual({c.attack for cfg, c in plan if cfg == 'engine'}, ATTACKS | CONTROLS)
        cap = batch_capacity(chosen, ['engine', 'undefended'])
        self.assertEqual(cap['executions'], 97)  # 32 engine + 61 row reserve + 4 support reserve
        self.assertEqual(cap['simultaneous_copies'], 3)
        self.assertLess(cap['last'], 70999)

    def test_local_import_closure_including_exec_worker_is_fully_packaged(self):
        local = {p.stem for p in CELL.glob('*.py')}
        included = {Path(name).stem for name in CORE}
        self.assertEqual(len(CORE), len(set(CORE)))
        self.assertIn('nb26_worker', included)
        for path in [*(CELL / name for name in CORE), *(SCRIPTS / c.module for c in CASES.values()),
                     *(SCRIPTS / name for name in SUPPORT_MODULES.values())]:
            tree = ast.parse(path.read_text(encoding='utf-8'))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split('.')[0])
                elif isinstance(node, ast.Import):
                    imports.update(n.name.split('.')[0] for n in node.names)
            self.assertFalse((imports & local) - included, (path.name, imports - included))
            self.assertFalse(imports - local - sys.stdlib_module_names, (path.name, imports - local))


class FrozenPayloadTests(unittest.TestCase):
    def test_runtime_passes_all_frozen_modules_supports_and_payload_to_deployment(self):
        from test_batch_runtime import RuntimeWiringTests
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            rt, commands, compiler, argv, deploy, *_ = RuntimeWiringTests().fixture(stack, Path(tmp))
            modules = {**{k: c.module for k, c in CASES.items()}, **SUPPORT_MODULES}
            rt.bundle['modules'] = modules
            rt.bundle['support_modules'] = dict(SUPPORT_MODULES)
            with patch('run_runtime.prepare_payload', return_value={'offline': Path(tmp) / 'payload'}) as payload:
                rt.prepare()
                self.assertEqual(payload.call_args.args[2],
                                 {k: Path(tmp) / 'modules' / name for k, name in modules.items()})
                self.assertEqual(payload.call_args.kwargs['support_modules'], SUPPORT_MODULES)
                self.assertIs(deploy.call_args.kwargs['payload'], rt.payload)
                self.assertIs(deploy.call_args.kwargs['command'], commands[0])
                self.assertEqual(commands[0].deadline.end, rt.end - 60)
                self.assertEqual(commands[1].deadline.end, rt.end)
                rt.close()

    def test_boot_snapshot_to_payload_all_33_modules_without_compiler_or_import_execution(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            repo, frozen = root / 'repo', root / 'nb-decoy-boot-offline'
            frozen.mkdir()
            harness, scripts = repo / HREL, repo / NREL / 'scripts'
            harness.mkdir(parents=True); scripts.mkdir(parents=True)
            for p in H.rglob('*'):
                if p.is_file() and p.suffix in ('.py', '.c') and 'tests' not in p.relative_to(H).parts:
                    dest = harness / p.relative_to(H)
                    dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(p.read_bytes())
            for name in [*(c.module for c in CASES.values()), *SUPPORT_MODULES.values()]:
                (scripts / name).write_bytes((SCRIPTS / name).read_bytes())
            spec = (SCRIPTS.parent / 'tests.md').read_bytes()
            (repo / NREL / 'tests.md').write_bytes(spec)
            engine = repo / 'ExperimentLab/engine-v3'; engine.mkdir(parents=True)
            (engine / 'offline.txt').write_bytes(b'Not an engine; snapshot I/O fixture only.')
            stack.enter_context(patch('run_boot.os', SimpleNamespace(name='posix', geteuid=lambda: 0)))
            stack.enter_context(patch('run_boot.tempfile.mkdtemp', return_value=str(frozen)))
            stack.enter_context(patch('run_boot.claim', return_value={'mock': True}))
            stack.enter_context(patch('run_boot.bind'))
            chosen = selection(ORDER, ['engine', 'undefended'], CASES)
            args = SimpleNamespace(repo=repo, label='offline', cap=batch_capacity(chosen, ['engine', 'undefended']),
                                   configs=['engine', 'undefended'], crash_directory=root, cgroup_parent=root,
                                   cert_python='/offline/python')
            bundle = stage(args, chosen, SUPPORT_MODULES, time.monotonic() + 600)
            self.assertEqual(set(bundle['modules']), ATTACKS | CONTROLS | set(SUPPORT_MODULES))
            self.assertEqual(bundle['spec_identity'], identity(spec))
            self.assertEqual(bundle['harness_identity'], inventory(frozen / 'harness', ('tests', '__pycache__')))
            # Live source drift must not alter already captured bytes.
            (scripts / 'NB-01.py').write_bytes(b'raise AssertionError("live tree must not run")\n')
            (harness / 'cell/nb26_worker.py').write_bytes(b'raise AssertionError("not frozen")\n')
            probe = root / 'structural-only'; probe.write_bytes(elf_fixture())
            mapping = {key: frozen / 'modules' / name for key, name in bundle['modules'].items()}
            result = prepare_payload(frozen / 'harness/cell', probe, mapping, root / 'payload',
                                     support_modules=bundle['support_modules'])
            self.assertEqual(set(result), set(CORE) | {'nb_probe', 'modules.json'} |
                             {'modules/' + key + '.py' for key in mapping})
            contents = {name: path.read_bytes() for name, path in result.items()}
            reg = manifest(json.loads(contents['modules.json']))
            for key, entry in reg['modules'].items():
                self.assertEqual(identity(contents[entry['path']]), bundle['script_identities'][key])
                self.assertEqual(entry.get('lifetime', 30), 540 if key in SUPPORT_MODULES else 30)
                self.assertIsInstance(module_code(MemoryFiles(contents), reg, key), type(compile('', '', 'exec')))
            contents['modules/NB-01.py'] = b'# changed\n'
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                module_code(MemoryFiles(contents), reg, 'NB-01')
            self.assertEqual(result['nb26_worker.py'].read_bytes(), (CELL / 'nb26_worker.py').read_bytes())


class BundleIdentityTests(unittest.TestCase):
    def exercise(self, *, changed_spec=False):
        root = Path('/tmp/nb-decoy-boot-offline')
        original = b'offline specification\n'
        bundle = dict(engine_path='ExperimentLab/engine-v3', root=str(root), authorized='开始',
                      root_identity=[1, 2], harness_identity={'digest': 'h'}, engine_identity={'digest': 'e'},
                      modules={'NB-01': 'NB-01.py'}, script_identities={'NB-01': identity(b'# module\n')},
                      spec_identity=identity(original))
        def read(path, *args):
            if path.name == 'bundle.json': return json_bytes(bundle)
            if path.name == 'tests.md': return b'changed spec' if changed_spec else original
            return b'# module\n'
        info = SimpleNamespace(st_uid=0, st_mode=0o755, st_dev=1, st_ino=2)
        with patch('run_boot.plain_path', side_effect=lambda p: p), patch('run_boot.read_owned', side_effect=read), \
             patch.object(Path, 'stat', return_value=info), \
             patch('run_boot.inventory', side_effect=lambda p, *args: bundle[p.name + '_identity']), \
             patch('run_boot.verify_gate'):
            return load_bundle(root / 'bundle.json')

    def test_intact_frozen_bundle_loads(self):
        self.assertEqual(self.exercise()['modules'], {'NB-01': 'NB-01.py'})

    def test_changed_frozen_spec_cannot_keep_old_spec_identity(self):
        with self.assertRaisesRegex(ValueError, 'spec'):
            self.exercise(changed_spec=True)
