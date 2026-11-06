"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import copy
import errno
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cell"))
from nb_contract import decode, encoded, leaf, manifest, relative, target, validate_request
from nb_io import Files
from decoys import synchronization


def request():
    return {"v": 1, "run": "20261031T030000Z-unit", "config": "engine", "attack": "NB-06",
            "repeat": 1, "targets": {"control": {"kind": "path", "scope": "work", "path": "nb-decoy-control"},
                                    "host": {"kind": "path", "scope": "host", "path": "/tmp/nb-decoy-unit/host/key"}},
            "parameters": {}, "sync": synchronization("20261031T030000Z-unit", "engine", "NB-06", 1)}


class ContractTests(unittest.TestCase):
    def test_existing_decoy_sync_contract_accepted(self):
        value = request()
        self.assertEqual(validate_request(decode(encoded(value))), value)

    def test_duplicate_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            decode(b'{"v":1,"v":1}')

    def test_nonfinite_json_rejected(self):
        for value in (b'NaN', b'Infinity', b'-Infinity'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode(value)

    def test_missing_or_unknown_fields_rejected(self):
        for change in ("missing", "extra"):
            value = request()
            if change == "missing":
                del value["targets"]
            else:
                value["module_path"] = "/tmp/code.py"
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_request(value)

    def test_bool_version_and_repeat_rejected(self):
        for key in ("v", "repeat"):
            value = request()
            value[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_request(value)

    def test_cross_attempt_sync_rejected(self):
        for key in ("run", "config", "attack", "repeat"):
            value = request()
            value[key] = 2 if key == "repeat" else "another"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "mismatch"):
                validate_request(value)

    def test_nonce_malformed_or_replaced_rejected(self):
        for nonce in ("", "x" * 48, "a" * 48, 1):
            value = request()
            value["sync"]["nonce"] = nonce
            with self.subTest(nonce=nonce), self.assertRaises(ValueError):
                validate_request(value)

    def test_path_traversal_and_foreign_syntax_rejected(self):
        for value in ("", "/file", "../file", "a/../file", "a//file", "a/./file", "C:foo", "a\\b", "a\0b", "a\nb"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                relative(value)

    def test_flat_output_only(self):
        with self.assertRaises(ValueError):
            leaf("dir/file")

    def test_component_length_limit(self):
        with self.assertRaises(ValueError):
            relative("a" * 256)

    def test_empty_targets_rejected(self):
        value = request()
        value["targets"] = {}
        with self.assertRaises(ValueError):
            validate_request(value)

    def test_target_limit(self):
        value = request()
        value["targets"] = {f"t{i}": value["targets"]["host"] for i in range(65)}
        with self.assertRaises(ValueError):
            validate_request(value)

    def test_real_host_paths_not_accepted(self):
        for path in ("/etc/passwd", "/home/user/.ssh/id_ed25519", "/tmp/nb-decoy-x/../real"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                target({"kind": "path", "scope": "host", "path": path})

    def test_target_kinds(self):
        for value in ({"kind": "inet", "address": "127.0.0.1", "port": 12345},
                      {"kind": "process", "pid": 24, "starttime": 1},
                      {"kind": "abstract", "name": "nb-decoy-unit"}):
            self.assertEqual(target(value), value)

    def test_no_dns_or_broadcast_or_bad_port(self):
        for address, port in (("example.com", 443), ("0.0.0.0", 5), ("224.0.0.1", 5),
                              ("255.255.255.255", 5), ("127.0.0.1", 0), ("127.0.0.1", True)):
            with self.subTest(address=address, port=port), self.assertRaises(ValueError):
                target({"kind": "inet", "address": address, "port": port})

    def test_process_broadcast_pid_not_accepted(self):
        for pid in (-1, 0, 1, True, 2**31):
            with self.subTest(pid=pid), self.assertRaises(ValueError):
                target({"kind": "process", "pid": pid, "starttime": 1})

    def test_manifest_cannot_name_external_module(self):
        for path in ("../code.py", "/work/code.py", "modules/../../a.py", "modules/__pycache__/a.pyc", "runner.py"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                manifest({"v": 1, "modules": {"NB-06": {"path": path, "sha256": "a" * 64}}})

    def test_empty_allowlist_valid_but_authorizes_nothing(self):
        self.assertEqual(manifest({"v": 1, "modules": {}})["modules"], {})

    def test_parameters_and_request_size(self):
        for params in ([], {"large": "x" * 65536}):
            value = request()
            value["parameters"] = params
            with self.subTest(params_type=type(params)), self.assertRaises(ValueError):
                validate_request(value)

    def test_attempt_name_bound(self):
        value = request()
        value["run"] = "a" * 80
        value["config"] = "b" * 80
        value["sync"] = synchronization(value["run"], value["config"], value["attack"], 1)
        with self.assertRaisesRegex(ValueError, "too long"):
            validate_request(value)


@unittest.skipUnless(os.name == "posix", "Linux openat/no-follow/fsync transport")
class FileTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = Files(self.root)
        self.addCleanup(self.files.close)

    def test_atomic_roundtrip_and_no_overwrite(self):
        self.files.write("one", b"abc")
        self.assertEqual(self.files.read("one", 3), b"abc")
        with self.assertRaises(FileExistsError):
            self.files.write("one", b"changed")
        self.assertEqual(self.files.read("one", 3), b"abc")
        self.assertEqual(list(self.root.iterdir()), [self.root / "one"])

    def test_read_bound(self):
        self.files.write("one", b"abcd")
        with self.assertRaises(ValueError):
            self.files.read("one", 3)

    def test_symlink_capture_and_parent_refused(self):
        (self.root / "real").mkdir()
        (self.root / "real/file").write_bytes(b"secret")
        (self.root / "link").symlink_to("real", target_is_directory=True)
        (self.root / "capture").symlink_to("real/file")
        for name in ("link/file", "capture"):
            with self.subTest(name=name), self.assertRaises(OSError):
                self.files.read(name, 128)

    def test_symlink_output_is_not_followed(self):
        (self.root / "real").write_bytes(b"keep")
        (self.root / "capture").symlink_to("real")
        with self.assertRaises(FileExistsError):
            self.files.write("capture", b"replace")
        self.assertEqual((self.root / "real").read_bytes(), b"keep")

    def test_hardlink_refused(self):
        (self.root / "real").write_bytes(b"keep")
        os.link(self.root / "real", self.root / "capture")
        with self.assertRaises(ValueError):
            self.files.read("capture", 128)

    def test_fifo_refused_without_blocking(self):
        os.mkfifo(self.root / "pipe")
        with self.assertRaises(ValueError):
            self.files.read("pipe", 128)

    def test_root_symlink_refused(self):
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            Files(self.root / "link")

    def test_partial_file_not_published_on_fsync_failure(self):
        with patch("nb_io.os.fsync", side_effect=OSError(errno.EIO, "fixture")):
            with self.assertRaises(OSError):
                self.files.write("output", b"data")
        self.assertFalse((self.root / "output").exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_file_and_directory_synced(self):
        real_fsync = os.fsync
        with patch("nb_io.os.fsync", wraps=real_fsync) as sync:
            self.files.write("output", b"data")
        self.assertEqual(sync.call_count, 2)
        self.assertEqual(sync.call_args.args[0], self.files.fd)

    def test_nested_source_read(self):
        (self.root / "modules").mkdir()
        (self.root / "modules/unit.py").write_bytes(b"# unit")
        self.assertEqual(self.files.read("modules/unit.py", 100), b"# unit")
