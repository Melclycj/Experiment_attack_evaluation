"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import importlib
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from build import capacity
from deploy_catalog import catalog_files
from deploy_fixtures import ENGINE_SOURCE, make_deployment, mini_seed


class CapacityContractTests(unittest.TestCase):
    def test_native_catalog_width_is_not_core_startup_capacity(self):
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            d.root.mkdir()
            mini_seed(d.root)
            with self.assertRaisesRegex(ValueError, "core startup"):
                catalog_files(d.source, d.root, capacity(1024, first_uid=80000),
                              fs_uuid="12345678-1234-1234-1234-123456789abc", fs_bytes=256 * 1024**2)


@unittest.skipUnless(os.name == "posix", "production startup imports Linux pwd; no engine or native library loaded")
class CoreCatalogContractTests(unittest.TestCase):
    def test_generated_catalog_reads_in_current_production_python_loader(self):
        for name in [n for n in sys.modules if n.split(".")[0] in ("engine", "connector")]:
            del sys.modules[name]
        sys.path.insert(0, str(ENGINE_SOURCE))
        try:
            startup = importlib.import_module("engine.startup")
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            d.root.mkdir()
            mini_seed(d.root)
            result = catalog_files(d.source, d.root, d.cap,
                                   fs_uuid="12345678-1234-1234-1234-123456789abc", fs_bytes=256 * 1024**2)
            with patch.object(startup.pwd, "getpwuid", side_effect=KeyError):
                catalog = startup.load_catalog(d.root, "catalog.json", startup.Environment(65534, 65534, {}), 1000)
            self.assertEqual(catalog.catalog_digest, result["catalog_digest"])
            self.assertEqual(set(catalog.plans), {"nb-0", "nb-1", "nb-2"})
            self.assertEqual(catalog.uid_range, (d.cap["first"], d.cap["spare_uid"] - 1))
            self.assertEqual(catalog.connector_uid, 70999)
            self.assertEqual((catalog.pdp_uid, catalog.pdp_gid), (70998, 70998))
