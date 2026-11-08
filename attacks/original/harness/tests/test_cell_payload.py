"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import ast
import json
import os
import sys
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from cell_payload import CELL, CORE, compile_argv, prepare_payload, static_probe
from deploy_seed import payload_manifest


def elf_fixture(kind=1):
    """Non-executable test bytes; structural validation ONLY, never launched."""
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 62, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, kind, 5, 0, 0, 0, 120, 120, 1)
    return data


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.probe = self.root / "structural-fixture"
        self.probe.write_bytes(elf_fixture())

    def test_explicit_payload_matches_3c_contract(self):
        module = self.root / "unit.py"
        module.write_text("def control(ctx): return True\ndef action(ctx): pass\n")
        with patch("subprocess.Popen", side_effect=AssertionError("no process in payload assembly")):
            payload = prepare_payload(CELL, self.probe, {"NB-06": module}, self.root / "stage")
        self.assertEqual(set(payload), {*CORE, "nb_probe", "modules.json", "modules/NB-06.py"})
        registry = json.loads(payload["modules.json"].read_bytes())
        checked = payload_manifest(payload)
        self.assertEqual(registry["modules"]["NB-06"]["sha256"], checked["modules/NB-06.py"]["identity"]["sha256"])

    @unittest.skipUnless(os.name == "posix", "Linux real file transport; module is pure fixture, no probe")
    def test_staged_payload_to_runner_offline_file_roundtrip(self):
        sys.path.insert(0, str(CELL))
        from nb_io import Files
        from nb_contract import REQUEST, decode, encoded, stem
        from runner import run
        from test_cell_contract import request
        module = self.root / "unit.py"
        module.write_bytes(b"def control(ctx): return True\ndef action(ctx): ctx.capture('unit', b'fixture-data')\n")
        stage = self.root / "stage"
        prepare_payload(CELL, self.probe, {"NB-06": module}, stage)
        workspace = self.root / "work"
        workspace.mkdir()
        req = request()
        work, payload = Files(workspace), Files(stage)
        try:
            work.write(REQUEST, encoded(req))
            with patch("subprocess.Popen", side_effect=AssertionError("offline fixture must not launch")):
                self.assertEqual(run(work, payload, cwd=str(workspace)), 0)
            record = decode(work.read(stem(req) + "-observed.json", 65536))
            self.assertTrue(record["complete"])
            self.assertEqual(work.read(record["captures"][0]["path"], 100), b"fixture-data")
        finally:
            work.close()
            payload.close()

    def test_empty_manifest_does_not_fake_implemented_attacks(self):
        payload = prepare_payload(CELL, self.probe, {}, self.root / "stage")
        self.assertEqual(json.loads(payload["modules.json"].read_bytes())["modules"], {})

    def test_stage_is_exclusive(self):
        output = self.root / "stage"
        prepare_payload(CELL, self.probe, {}, output)
        with self.assertRaises(FileExistsError):
            prepare_payload(CELL, self.probe, {}, output)

    def test_source_mutation_does_not_change_staged_payload(self):
        module = self.root / "unit.py"
        module.write_bytes(b"# original\n")
        payload = prepare_payload(CELL, self.probe, {"NB-06": module}, self.root / "stage")
        module.write_bytes(b"# changed\n")
        self.assertEqual(payload["modules/NB-06.py"].read_bytes(), b"# original\n")

    def test_no_automatic_module_discovery(self):
        (self.root / "unlisted.py").write_text("raise AssertionError('must not load')")
        payload = prepare_payload(CELL, self.probe, {}, self.root / "stage")
        self.assertFalse(any("unlisted" in name for name in payload))

    def test_module_key_traversal_rejected(self):
        with self.assertRaises(ValueError):
            prepare_payload(CELL, self.probe, {"../bad": self.probe}, self.root / "stage")
        self.assertFalse((self.root / "stage").exists())

    def test_bad_module_syntax_rejected_without_execution(self):
        module = self.root / "unit.py"
        module.write_bytes(b"def invalid(\n")
        with self.assertRaises(SyntaxError):
            prepare_payload(CELL, self.probe, {"NB-06": module}, self.root / "stage")

    def test_dynamic_or_interpreted_elf_rejected(self):
        for kind in (2, 3):
            self.probe.write_bytes(elf_fixture(kind))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                static_probe(self.probe)

    def test_fake_magic_alone_not_sufficient(self):
        self.probe.write_bytes(b"\x7fELFfake")
        with self.assertRaises(ValueError):
            static_probe(self.probe)

    def test_foreign_arch_rejected(self):
        data = elf_fixture()
        struct.pack_into("<H", data, 18, 183)
        self.probe.write_bytes(data)
        with self.assertRaises(ValueError):
            static_probe(self.probe)

    def test_out_of_file_segment_rejected(self):
        data = elf_fixture()
        struct.pack_into("<Q", data, 64 + 8, 999999)
        self.probe.write_bytes(data)
        with self.assertRaises(ValueError):
            static_probe(self.probe)

    def test_compile_plan_does_not_compile(self):
        with patch("subprocess.Popen", side_effect=AssertionError("must not compile")):
            argv = compile_argv(CELL, self.root / "nb_probe")
        self.assertIn("-static", argv)
        self.assertIn("-Werror", argv)
        self.assertFalse((self.root / "nb_probe").exists())

    def test_compile_output_cannot_overwrite(self):
        with self.assertRaises(FileExistsError):
            compile_argv(CELL, self.probe)


class SourceContractTests(unittest.TestCase):
    def test_all_new_source_size_purpose_and_python_syntax(self):
        paths = [*(CELL / name for name in CORE), CELL / "nb_probe.c", CELL.parent / "cell_payload.py"]
        for path in paths:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn("这是 1.1 隔离论证的验证测试", text.splitlines()[0])
                self.assertLessEqual(len(text.splitlines()), 400)
                if path.suffix == ".py":
                    ast.parse(text)

    def test_probe_static_contract_only_not_compilation(self):
        text = (CELL / "nb_probe.c").read_text(encoding="utf-8")
        for operation in ('"read"', '"truncate"', '"tcp"', '"udp"', '"stop"'):
            self.assertIn(operation, text)
        for syscall in ("SYS_openat", "SYS_read", "SYS_write", "SYS_connect", "SYS_sendto", "SYS_recvfrom", "SYS_kill"):
            self.assertIn(syscall, text)
        self.assertIn('event("complete", 0, 0)', text)
        self.assertIn("actual != expected", text)
        self.assertNotIn("system(", text)
        self.assertNotIn("SYS_mount", text)
        self.assertNotIn("SYS_unshare", text)
