"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from net import IP, UPSTREAM_HOST, UPSTREAM_IP, PrivateNetwork, hosts_bytes, mount_owned, validate_links


class NetworkPureTests(unittest.TestCase):
    def test_only_loopback_is_an_acceptable_fresh_namespace(self):
        validate_links([{"ifname": "lo"}])
        for rows in ([], [{"ifname": "eth0"}], [{"ifname": "lo"}, {"ifname": "eth0"}]):
            with self.assertRaises(RuntimeError):
                validate_links(rows)

    def test_hosts_copy_preserves_input_and_adds_only_decoy(self):
        old = b"127.0.0.1 localhost\n# fixture\n"
        self.assertEqual(hosts_bytes(old), old + f"{UPSTREAM_IP} {UPSTREAM_HOST}\n".encode())

    def test_hosts_conflict_nul_and_oversize_rejected(self):
        for data in (f"1.2.3.4 alias {UPSTREAM_HOST}\n".encode(), b"x\0", b"x" * 65537):
            with self.assertRaises(ValueError):
                hosts_bytes(data)

    def test_hostname_in_comment_is_not_an_existing_mapping(self):
        self.assertIn(UPSTREAM_IP.encode(), hosts_bytes(f"# {UPSTREAM_HOST}\n".encode()))

    def test_unknown_namespace_is_not_entered(self):
        command = Mock()
        network = PrivateNetwork(command, Mock(), {})
        with self.assertRaises(ValueError):
            network.in_namespace(123, ["/bin/true"])
        command.assert_not_called()

    def test_pinned_namespace_not_name_or_holder_pid(self):
        command = Mock()
        network = PrivateNetwork(command, Mock(), {})
        network.fds = [12]
        with patch("net.os.getpid", return_value=1):
            network.in_namespace(12, [IP, "-j", "link", "show"])
        self.assertEqual(command.call_args.args[0][:3], ["/usr/bin/nsenter", "--net=/proc/1/fd/12", "--"])

    def test_close_releases_namespace_refs_before_holder_cleanup(self):
        network = PrivateNetwork(Mock(), Mock(), {})
        network.fds = [12, 13]
        with patch("net.os.close") as close:
            network.close()
            network.close()
        self.assertEqual([call.args[0] for call in close.call_args_list], [13, 12])
        with self.assertRaises(ValueError):
            network.in_namespace(12, [IP, "link"])

    def test_hosts_cannot_be_bound_before_network_setup(self):
        network = PrivateNetwork(Mock(), Mock(), {})
        with self.assertRaises(RuntimeError):
            network.bind_hosts(Path("/fake"))


class MountTransactionTests(unittest.TestCase):
    def check_mount(self, *, mids, error=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "mountpoint"
            target.mkdir()
            resources = Mock(roots={root: (1, 2)})
            command = Mock(side_effect=error)
            with patch("net.mounted_id", side_effect=mids), patch.object(Path, "read_text", return_value="fixture"):
                if error is not None or mids[0] == mids[1]:
                    with self.assertRaises(RuntimeError):
                        mount_owned(resources, command, ["/usr/bin/mount", "fixture"], target)
                else:
                    mount_owned(resources, command, ["/usr/bin/mount", "fixture"], target)
            return resources

    def test_successful_mount_registered(self):
        self.check_mount(mids=[10, 11]).add_mount.assert_called_once()

    def test_mount_registered_even_if_post_command_processing_failed(self):
        self.check_mount(mids=[10, 11], error=RuntimeError("output limit")).add_mount.assert_called_once()

    def test_failed_mount_does_not_register_original_layer(self):
        self.check_mount(mids=[10, 10], error=RuntimeError("mount failed")).add_mount.assert_not_called()

    def test_success_exit_without_new_mount_is_not_success(self):
        self.check_mount(mids=[10, 10]).add_mount.assert_not_called()

    def test_outside_target_rejected_before_command(self):
        with tempfile.TemporaryDirectory() as temp:
            command = Mock()
            resources = Mock(roots={})
            with self.assertRaises(ValueError):
                mount_owned(resources, command, ["/usr/bin/mount"], Path(temp))
            command.assert_not_called()


class NetworkPlanTests(unittest.TestCase):
    def plan(self, routes=None, links=None):
        calls = []

        def command(argv, **kwargs):
            calls.append(argv)
            if argv == [IP, "-j", "link", "show"]:
                return {"stdout": json.dumps(links if links is not None else [{"ifname": "lo"}])}
            if "route" in argv:
                return {"stdout": json.dumps(routes or [])}
            return {"stdout": ""}

        network = PrivateNetwork(command, Mock(), {"namespaces": {}})
        network.fds = [55, 56]
        holders = [(SimpleNamespace(proc=SimpleNamespace(pid=101)), 55),
                   (SimpleNamespace(proc=SimpleNamespace(pid=102)), 56)]
        with patch("net.check_namespaces"), patch("net.namespaces", return_value={}), \
                patch.object(Path, "read_text", return_value="fixture"), \
                patch.object(network, "_holder", side_effect=holders), patch("net.os.getpid", return_value=1):
            try:
                value = network.prepare()
            except RuntimeError:
                if routes or links:
                    return calls, network, None
                raise
        return calls, network, value

    def test_setup_has_no_host_default_route_or_named_netns(self):
        calls, network, result = self.plan()
        self.assertTrue(network.prepared)
        self.assertEqual(result["address"], UPSTREAM_IP)
        self.assertFalse(any("/var/run/netns" in str(argv) for argv in calls))
        self.assertFalse(any("sysctl" in str(argv) for argv in calls))
        self.assertFalse(any("default" in argv for argv in calls))
        veth = next(argv for argv in calls if "veth" in argv)
        self.assertIn("--net=/proc/1/fd/55", veth)
        self.assertEqual(veth[-2:], ["netns", "1"])
        self.assertNotIn("101", veth)

    def test_nonisolated_interface_rejected_before_any_mutating_command(self):
        calls, network, result = self.plan(links=[{"ifname": "eth0"}])
        self.assertIsNone(result)
        self.assertEqual(calls, [[IP, "-j", "link", "show"]])
        self.assertFalse(network.prepared)

    def test_unexpected_default_route_invalidates_setup(self):
        _, network, result = self.plan(routes=[{"dst": "default"}])
        self.assertIsNone(result)
        self.assertFalse(network.prepared)
        with self.assertRaises(RuntimeError):
            network.prepare()  # failed setup is not reused
