"""这是 1.1 隔离论证的验证测试：harness 对 engine-v2-go 第二阶段接口（648d60f2）的适配，v4（engine-v3 @ a9eff999）仍沿用的部分；全部离线，不启动部署。"""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from build import capacity
from cell.nb_contract import target
from cell.nb_engine_question import answer_bytes
from deploy_catalog import PDP_UID, catalog_files
from deploy_fixtures import ENGINE_SOURCE, FakeCommands, OLD_QUESTION, QUESTION, make_deployment, mini_seed
from engine_cases import credential_files
from env import check_reserved_uids
from management import Management, current_question
from net import QUESTION_HOST, UPSTREAM_HOST

# The keys native/sandbox/catalog.c accepts without the optional runtime_mode (648d60f2 4.2; v4 adds the file
# worker, the MCP server and its port as required keys).
CATALOG_KEYS = {"v", "runtimes", "policies", "workspaces", "profiles", "plans", "storage_profile", "uid_range",
                "connector", "relay", "frontend", "proxy_port", "cell_files_ref", "ca_pool_ref", "pdp",
                "file_worker", "mcp_server", "mcp_port"}


class CatalogAndUids(unittest.TestCase):
    def test_catalog_names_the_pdp_identity_outside_range_and_connector(self):
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            d.root.mkdir()
            mini_seed(d.root)
            c = catalog_files(d.source, d.root, d.cap, fs_uuid="12345678-1234-1234-1234-123456789abc",
                              fs_bytes=256 * 1024**2)["catalog"]
        self.assertEqual(set(c), CATALOG_KEYS)
        self.assertEqual(c["pdp"], {"uid": PDP_UID, "gid": PDP_UID})
        self.assertEqual(PDP_UID, 70998)
        self.assertNotEqual(PDP_UID, c["connector"]["uid"])
        self.assertFalse(c["uid_range"]["first"] <= PDP_UID <= c["uid_range"]["last"])

    def test_reserved_uid_scan_covers_the_pdp_uid(self):
        check_reserved_uids(70000, 70100, [1000], [0, 1000])
        for accounts, procs in (([70998], []), ([], [70998])):
            with self.subTest(accounts=accounts, procs=procs), self.assertRaises(ValueError):
                check_reserved_uids(70000, 70100, accounts, procs)
        with self.assertRaises(ValueError):
            check_reserved_uids(70900, 70998, [], [])

    def test_capacity_range_never_reaches_the_pdp_uid(self):
        with self.assertRaises(ValueError):
            capacity(98, first_uid=70900)  # last = 70998
        with self.assertRaises(ValueError):
            capacity(97, first_uid=70900)  # last = 70997, v4's workspace owner
        self.assertEqual(capacity(95, first_uid=70900)["last"], 70995)


class ManagementGo(unittest.TestCase):
    def setUp(self):
        self.command = FakeCommands(Path("/fixture"))
        self.engine = self.command.start(["/fixture/engine"])
        self.admin = Management(Path("/fixture/source"), Path("/fixture/root"), self.command, self.engine)

    def test_credential_has_no_placeholder_argument_and_witness_rides_in_metadata(self):
        self.admin.credential("nb-decoy-secret", "nb-decoy-witness")
        argv, kw = self.command.calls[-1]
        tail = argv[argv.index("put"):]
        self.assertEqual(tail[:4], ["put", UPSTREAM_HOST + ":443", "nb-decoy-account", "api-key"])
        self.assertEqual(tail[4:], ["--truth-env", "NB_DECOY_TRUTH",
                                    "--token-endpoint", f"https://{UPSTREAM_HOST}/nb-decoy-witness"])
        self.assertNotIn("nb-decoy-secret", str(argv))
        self.assertEqual(kw["env"], {"NB_DECOY_TRUTH": "nb-decoy-secret"})
        for witness in ("", "a/b", "x?y", "nb-decoy-secret"):
            with self.subTest(witness=witness), self.assertRaises(ValueError):
                self.admin.credential("nb-decoy-secret", witness)

    def test_question_entry_is_an_every_time_cell_on_the_question_host_only(self):
        self.admin.question_entry("work2")
        argv = self.command.calls[-1][0]
        tail = argv[argv.index("put"):]
        self.assertEqual(tail, ["put", "work2", "exact", "allow", QUESTION_HOST + ":443", "--method", "POST",
                                "--prefix", "/", "--approval", "always"])
        for workspace in ("work3", "../work0", ""):
            with self.subTest(workspace=workspace), self.assertRaises(ValueError):
                self.admin.question_entry(workspace)

    def test_current_prompt_is_parsed_and_the_old_prompt_is_not(self):
        self.assertEqual(current_question(QUESTION)["qid"], 7)
        self.assertIsNone(current_question(OLD_QUESTION))


class CellGo(unittest.TestCase):
    def test_answer_is_the_two_field_frame(self):
        raw = answer_bytes(7)
        self.assertEqual(raw, bytes.fromhex("00000012") + bytes([0x43])
                         + bytes.fromhex("00000008") + (7).to_bytes(8, "big") + bytes.fromhex("00000001") + b"\x01")

    @unittest.skipUnless(os.name == "posix", "production canonical imports fcntl, no I/O")
    def test_answer_matches_engine_go_parser(self):
        for name in [n for n in sys.modules if n == "connector" or n.startswith("connector.")]:
            del sys.modules[name]
        sys.path.insert(0, str(ENGINE_SOURCE))
        try:
            c = importlib.import_module("connector.canonical")
            fields = [c.u64(7), c.u8(1)]
            self.assertEqual(answer_bytes(7), c.pack_frame(c.ANSWER, fields))
            self.assertEqual(c.FIELD_COUNT[c.QUESTION], 24)  # v4: six host-file fields (H-09)
        finally:
            sys.path.pop(0)
            for name in [n for n in sys.modules if n == "connector" or n.startswith("connector.")]:
                del sys.modules[name]

    def test_generation_named_truth_path_is_the_only_new_colon_target(self):
        root = "/tmp/nb-decoy-owned/state/credentials/nb-decoy-upstream.test:443/"
        for name in ("nb-decoy-account.1.truth_a", "nb-decoy-account.42.truth_a", "nb-decoy-account.json"):
            value = {"kind": "path", "scope": "host", "path": root + name}
            self.assertEqual(target(value), value)
        for name in ("nb-decoy-account.truth_a", "nb-decoy-account.0.truth_a", "nb-decoy-account.01.truth_a",
                     "nb-decoy-account.1.truth_b", "nb-decoy-account.1.truth_a/x", "other.1.truth_a"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                target({"kind": "path", "scope": "host", "path": root + name})


class CredentialFiles(unittest.TestCase):
    def test_truth_path_follows_the_metadata_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "nb-decoy-account.json").write_text(json.dumps({"generation": 3, "account": "nb-decoy-account"}))
            files = credential_files(directory)
            self.assertEqual(files, {"truth": directory / "nb-decoy-account.3.truth_a",
                                     "metadata": directory / "nb-decoy-account.json"})
            for bad in ({"generation": 0}, {"generation": "3"}, {"generation": True}, {}):
                (directory / "nb-decoy-account.json").write_text(json.dumps(bad))
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    credential_files(directory)


if __name__ == "__main__":
    unittest.main()
