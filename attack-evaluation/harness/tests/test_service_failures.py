"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from common import json_bytes
from deploy_fixtures import FakeCommands
from https_client import request
from net import UPSTREAM_HOST
from upstream import Upstream


class UpstreamWindowTests(unittest.TestCase):
    def setup_service(self):
        command = FakeCommands(Path("/fixture"))
        service = Upstream(Path("/fixture/root"), command,
                           SimpleNamespace(prepared=True, closed=False, fds=[19]), {"upstream": {"fd": 19}})
        service.child = command.start(["/fixture/mock-service"], interactive=True)
        def control(child, data):
            value = json.loads(data)
            child.buffers["stdout"].extend(json_bytes({"kind": "window", "attempt": value["attempt"], "cursor": 7}))
        command.send_input = control
        return command, service

    def test_end_waits_effect_window_and_accepts_only_between_cursor_and_end(self):
        command, service = self.setup_service()
        self.assertEqual(service.begin("attempt-2"), 7)
        secret = service.current[1]
        stream = service.child.buffers["stdout"]
        for row in ({"kind": "request", "attempt": "attempt-1", "seq": 6},
                    {"kind": "request", "attempt": "attempt-2", "seq": 7}):
            stream.extend(json_bytes(row))
        def exchange(mode, value):
            self.assertEqual((mode, value), ("end", secret))
            stream.extend(json_bytes({"kind": "end", "token": secret, "seq": 8}))
            return {"token": "response"}
        with patch.object(service, "exchange", side_effect=exchange), \
                patch("upstream.time.monotonic", side_effect=[0, 2, 2]):
            result = service.end()
        self.assertEqual([r["seq"] for r in result["requests"]], [7])
        service.close()
        service.close()
        self.assertEqual(len(command.closures), 1)

    def test_no_fabricated_end_on_failed_https_exchange(self):
        _, service = self.setup_service()
        service.begin("attempt-1")
        with patch.object(service, "exchange", side_effect=ConnectionError("fixture TLS failure")), \
                patch("upstream.time.monotonic", side_effect=[0, 2]), self.assertRaises(ConnectionError):
            service.end()
        self.assertIsNotNone(service.current)
        with self.assertRaisesRegex(RuntimeError, "unclosed"):
            service.close()

    def test_journal_partial_final_line_is_not_success(self):
        _, service = self.setup_service()
        service.child.buffers["stdout"].extend(b'{"partial"')
        with self.assertRaisesRegex(RuntimeError, "truncated"):
            service.close()

    def test_journal_invalid_json_is_not_success(self):
        _, service = self.setup_service()
        service.child.buffers["stdout"].extend(b'bad\n')
        with self.assertRaises(ValueError):
            service.poll()

    def test_readiness_claim_without_matching_tls_roundtrip_fails(self):
        command, service = self.setup_service()
        service.child = None
        original = command.start
        def start(argv, **kw):
            child = original(argv, **kw)
            child.buffers["stdout"].extend(b'{"kind":"ready"}\n')
            return child
        command.start = start
        with patch.object(service, "exchange", return_value={"ready": "wrong"}), \
                self.assertRaisesRegex(RuntimeError, "roundtrip"):
            service.start()


class HttpsClientTests(unittest.TestCase):
    def test_client_uses_ca_verification_and_expected_hostname(self):
        conn = Mock()
        conn.getresponse.return_value = SimpleNamespace(status=200, read=lambda _: b'{"token":"reply"}')
        with patch("https_client.ssl.create_default_context") as ctx, \
                patch("https_client.http.client.HTTPSConnection", return_value=conn) as make:
            self.assertEqual(request(Path("/fixture/ca.pem"), "end", "a" * 48), {"token": "reply"})
            ctx.assert_called_once_with(cafile=str(Path("/fixture/ca.pem")))
            self.assertEqual(make.call_args.args, (UPSTREAM_HOST, 443))
            self.assertEqual(conn.request.call_args.args, ("POST", "/nb-end"))
            conn.close.assert_called_once()

    def test_oversized_and_wrong_status_replies_close_socket(self):
        for status, data in ((200, b"x" * 4097), (503, b"{}")):
            conn = Mock()
            conn.getresponse.return_value = SimpleNamespace(status=status, read=lambda _: data)
            with patch("https_client.ssl.create_default_context"), \
                    patch("https_client.http.client.HTTPSConnection", return_value=conn), self.assertRaises(RuntimeError):
                request(Path("/fixture/ca.pem"), "ready", "a" * 48)
            conn.close.assert_called_once()
