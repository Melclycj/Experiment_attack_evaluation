"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from decoy_services import end_frame
from deploy_fixtures import ENGINE_SOURCE, FakeCommands
from https_service import Window, parse_head, read_request
from net import QUESTION_HOST, UPSTREAM_HOST, UPSTREAM_IP, hosts_bytes
from tls_material import generate
from upstream import Upstream, wait_for


class HttpsPureTests(unittest.TestCase):
    def test_both_decoy_hosts_and_no_external_hosts(self):
        for host in (UPSTREAM_HOST, QUESTION_HOST):
            result = parse_head(f"GET /random HTTP/1.1\r\nHost: {host}:443".encode())
            self.assertEqual(result, ("GET", "/random", host, 0, {}))
        with self.assertRaises(ValueError):
            parse_head(b"GET / HTTP/1.1\r\nHost: example.com")

    def test_decoy_headers_are_captured_for_the_receipt(self):
        head = f"GET /nb-decoy-x HTTP/1.1\r\nHost: {UPSTREAM_HOST}\r\nx-nb-decoy-key: nb-decoy-abc\r\nuser-agent: curl".encode()
        self.assertEqual(parse_head(head)[4], {"x-nb-decoy-key": "nb-decoy-abc"})

    def test_request_size_duplicate_and_transfer_encoding_fail_closed(self):
        base = f"POST / HTTP/1.1\r\nHost: {UPSTREAM_HOST}\r\n".encode()
        for bad in (b"Content-Length: 999999", b"Content-Length: -1", b"Transfer-Encoding: chunked",
                    b"Content-Length: 1\r\nContent-Length: 1", b"Host: duplicate", b"x: " + b"a" * 17000):
            with self.subTest(bad=bad[:30]), self.assertRaises(ValueError):
                parse_head(base + bad)

    def test_partial_body_eof_is_not_a_request(self):
        conn = Mock()
        conn.recv.side_effect = [f"POST / HTTP/1.1\r\nHost: {UPSTREAM_HOST}\r\nContent-Length: 3\r\n\r\nx".encode(), b""]
        with patch("https_service.time.monotonic", return_value=0), self.assertRaises(ConnectionError):
            read_request(conn, 10)

    def test_fragmented_request_and_absolute_deadline(self):
        conn = Mock()
        conn.recv.side_effect = [b"GET /", f" HTTP/1.1\r\nHost: {UPSTREAM_HOST}\r\n\r\n".encode()]
        with patch("https_service.time.monotonic", return_value=0):
            self.assertEqual(read_request(conn, 10)[:3], ("GET", "/", UPSTREAM_HOST))
        with patch("https_service.time.monotonic", return_value=11), self.assertRaises(TimeoutError):
            read_request(conn, 10)

    def test_real_marker_is_exact_and_excluded_from_requests(self):
        log, secret = [], "a" * 48
        window = Window(log.append)
        with self.assertRaises(ValueError):
            window.receive("GET", "/", UPSTREAM_HOST, b"", [])
        window.begin("attempt-1", secret)
        with self.assertRaises(ValueError):
            window.begin("attempt-2", secret)
        response = json.loads(window.receive("GET", "/nonce", UPSTREAM_HOST, b"", []))
        self.assertEqual(response["token"], log[-1]["reply_token"])
        window.receive("POST", "/nb-end", UPSTREAM_HOST, end_frame(secret) + b"wrong", [])
        self.assertEqual(log[-1]["kind"], "request")
        window.receive("POST", "/nb-end", UPSTREAM_HOST, end_frame(secret), [])
        self.assertEqual(log[-1]["kind"], "end")
        self.assertEqual(log[-1]["seq"], 2)
        self.assertIsNone(window.current)
        window.begin("attempt-2", "b" * 48)
        self.assertEqual(log[-1]["cursor"], 3)

    def test_window_connection_bound(self):
        window = Window(lambda _: None)
        window.begin("attempt-1", "a" * 48)
        window.count = 64
        with self.assertRaises(ValueError):
            window.receive("GET", "/", UPSTREAM_HOST, b"", [])

    def test_hosts_bind_contains_both_certificate_names(self):
        data = hosts_bytes(b"127.0.0.1 localhost\n", (UPSTREAM_HOST, QUESTION_HOST))
        for host in (UPSTREAM_HOST, QUESTION_HOST):
            self.assertIn(f"{UPSTREAM_IP} {host}\n".encode(), data)
        for names in (("example.com",), (UPSTREAM_HOST, UPSTREAM_HOST), ()):
            with self.assertRaises(ValueError):
                hosts_bytes(b"", names)
        with self.assertRaises(ValueError):
            hosts_bytes(f"1.2.3.4 {QUESTION_HOST}\n".encode(), (UPSTREAM_HOST, QUESTION_HOST))

    def test_service_early_exit_and_timeout_are_distinct_from_test_result(self):
        command = FakeCommands(Path("/fixture"))
        child = command.start(["/fixture/service"])
        child.proc.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, "not a test outcome"):
            wait_for(command, lambda: True, child=child)
        child.proc.poll.return_value = None
        with patch("upstream.time.monotonic", side_effect=[0, 100]), self.assertRaises(TimeoutError):
            wait_for(command, lambda: False, child=child)

    def test_upstream_uses_pinned_namespace_and_real_ca_roundtrip(self):
        command = FakeCommands(Path("/fixture"))
        network = SimpleNamespace(prepared=True, closed=False, fds=[19])
        service = Upstream(Path("/fixture/root"), command, network, {"upstream": {"fd": 19}})
        original = command.start
        def start(argv, **kw):
            child = original(argv, **kw)
            child.buffers["stdout"].extend(b'{"kind":"ready"}\n')
            return child
        command.start = start
        with patch.object(service, "exchange", side_effect=lambda mode, secret: {"ready": secret}) as exchange:
            service.start()
            exchange.assert_called_once()
        self.assertIn("/fd/19", command.starts[-1][0][1])
        self.assertTrue(command.starts[-1][1]["interactive"])

    def test_unpinned_or_closed_network_cannot_start_service(self):
        command = FakeCommands(Path("/fixture"))
        for network in (SimpleNamespace(prepared=False, closed=False, fds=[19]),
                        SimpleNamespace(prepared=True, closed=True, fds=[19]),
                        SimpleNamespace(prepared=True, closed=False, fds=[])):
            service = Upstream(Path("/fixture/root"), command, network, {"upstream": {"fd": 19}})
            with self.assertRaises(RuntimeError):
                service.start()
        self.assertEqual(command.starts, [])


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography not installed in this offline interpreter")
class CertificateTests(unittest.TestCase):
    def test_generated_pool_size_and_certificate_chain_sans(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtensionOID
        with tempfile.TemporaryDirectory() as temp, patch("builtins.print"):
            root = Path(temp)
            generate(ENGINE_SOURCE, root, 5)
            self.assertEqual(len(list((root / "ca-pool").iterdir())), 5)
            ca = x509.load_pem_x509_certificate((root / "tls/ca.pem").read_bytes())
            leaf = x509.load_pem_x509_certificate((root / "tls/server.pem").read_bytes())
            self.assertEqual(leaf.issuer, ca.subject)
            ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
            names = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            self.assertEqual(set(names.get_values_for_type(x509.DNSName)), {UPSTREAM_HOST, QUESTION_HOST})
            self.assertFalse(leaf.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
            self.assertEqual(len({p.read_bytes() for p in root.glob("ca-pool/*/ca.pem")}), 5)
