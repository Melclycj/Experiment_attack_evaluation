"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from build import capacity
from common import digest, identity, json_bytes
from deploy_catalog import catalog_files
from deploy_seed import assemble_seed, load_seed_class, payload_manifest
from deploy_fixtures import ENGINE_SOURCE, make_deployment, mini_seed


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.d = make_deployment(self.temp.name)
        self.d.root.mkdir()
        mini_seed(self.d.root)

    def build_catalog(self, **kw):
        return catalog_files(self.d.source, self.d.root, self.d.cap,
                             fs_uuid="12345678-1234-1234-1234-123456789abc", fs_bytes=kw.get("size", 256 * 1024**2))

    def test_production_programs_ca_policy_and_three_workspaces(self):
        output = self.build_catalog()
        c = output["catalog"]
        self.assertEqual(c["uid_range"], {"first": 70000, "last": 70003})
        self.assertEqual(len(c["workspaces"]), 3)
        self.assertEqual(len(c["plans"]), 3)
        self.assertEqual(c["connector"]["uid"], 70999)
        self.assertIn(str(self.d.source / "bin/connector"), c["connector"]["argv"])
        self.assertEqual(c["connector"]["argv"][-2:], ["--ca-file", str(self.d.root / "tls/ca.pem")])
        self.assertEqual(c["frontend"]["argv"], ["/runtime/bin/w2-frontend-stub"])
        self.assertNotIn("engine_fixture", str(c))
        policy = json.loads((self.d.root / "policy.json").read_bytes())
        self.assertEqual(policy["allow"], ["exit", "read", "write"])
        self.assertEqual(policy["default_errno"], 1)

    def test_every_catalog_reference_hashes_the_actual_written_bytes(self):
        c = self.build_catalog()["catalog"]
        refs = [c["storage_profile"], *c["profiles"], *c["plans"], *c["policies"]]
        for ref in refs:
            actual = identity((self.d.root / ref["artifact_ref"]).read_bytes())["sha256"]
            self.assertEqual(ref["artifact_digest"], "sha256:" + actual)
        runtime = c["runtimes"][0]
        self.assertEqual(runtime["descriptor_digest"], "sha256:" + identity(
            (self.d.root / runtime["descriptor_ref"]).read_bytes())["sha256"])

    def test_three_copy_reservation_and_native_fixed_slot_count(self):
        result = self.build_catalog()
        storage = json.loads((self.d.root / "storage.json").read_bytes())
        self.assertEqual(storage["max_copies"], 16)  # production storage.c accepts exactly 16 slots
        self.assertEqual(int(storage["max_reserved_bytes"]), 3 * result["reservation"]["charge_per_copy"])
        self.assertEqual(int(storage["max_reserved_nodes"]), 3 * 2)

    def test_small_fixed_image_is_rejected_not_grown(self):
        with self.assertRaisesRegex(RuntimeError, "do not enlarge"):
            self.build_catalog(size=64 * 1024**2)

    def test_seed_receipt_tampering_is_rejected(self):
        (self.d.root / "seed/dependency-lock.json").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.build_catalog()

    def test_capacity_cannot_drop_unused_uid(self):
        self.d.cap["last"] = 70003
        with self.assertRaises(ValueError):
            self.build_catalog()

    def test_reject_missing_or_non_elf_payload(self):
        with self.assertRaises(ValueError):
            payload_manifest({"runner.py": self.d.payload["runner.py"]})
        self.d.payload["nb_probe"].write_bytes(b"not compiled")
        with self.assertRaisesRegex(ValueError, "ELF"):
            payload_manifest(self.d.payload)

    def test_payload_digest_and_path_checks(self):
        result = payload_manifest(self.d.payload)
        self.assertEqual(result["runner.py"]["identity"], identity(self.d.payload["runner.py"].read_bytes()))
        for rel in ("../bad", "/bad", "x\\y"):
            with self.subTest(rel=rel), self.assertRaises(ValueError):
                payload_manifest({**self.d.payload, rel: self.d.payload["runner.py"]})


@unittest.skipUnless(os.name == "posix", "stock Seed creates Linux symlinks in temporary fixtures")
class SeedTests(unittest.TestCase):
    def assemble(self, temp, *, missing=False, mutate=False):
        d = make_deployment(temp)
        d.root.mkdir()
        payload = payload_manifest(d.payload)
        if mutate:
            d.payload["runner.py"].write_bytes(b"changed after approval")
        StockSeed, skip = load_seed_class(ENGINE_SOURCE)
        class FixtureSeed(StockSeed):
            def file(self, src, rel, data=None):
                if src and not str(src).startswith(str(d.build)):
                    src, data = None, b"offline-system-file"
                super().file(src, rel, data)
            def tree(self, src, rel, skip):
                self._dirs(rel)
            def libraries(self):
                if missing:
                    self.missing.add("fixture-missing.so")
                return []
        with patch("deploy_seed.load_seed_class", return_value=(FixtureSeed, skip)):
            result = assemble_seed(d.source, d.build, d.root, payload)
        return d, result

    def test_stock_seed_manifest_contains_real_payload_and_readonly_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            d, receipt = self.assemble(temp)
            manifest = json.loads((d.root / "components.json").read_bytes())
            entries = {e["path"]: e for e in manifest["files"]}
            self.assertEqual(entries["nb/nb_probe"]["mode"], 0o555)
            self.assertEqual(entries["nb/runner.py"]["mode"], 0o444)
            self.assertEqual(receipt["components_digest"], digest(manifest))
            for e in entries.values():
                if e["type"] == "file":
                    self.assertEqual(e["digest"], "sha256:" + identity((d.root / "seed" / e["path"]).read_bytes())["sha256"])

    def test_missing_library_fails(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(RuntimeError, "libraries"):
            self.assemble(temp, missing=True)

    def test_changed_payload_fails(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(ValueError, "payload changed"):
            self.assemble(temp, mutate=True)
