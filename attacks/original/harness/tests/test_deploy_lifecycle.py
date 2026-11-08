"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from contextlib import ExitStack
import os
from pathlib import Path
import signal
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from deploy import IMAGE_BYTES, fresh_root
from deploy_fixtures import make_deployment


class LifecycleTests(unittest.TestCase):
    def exercise(self, *, failure=None, interrupt=False, retain=False):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            d = make_deployment(temp, failure)
            order = []
            stack.enter_context(patch("deploy.require_platform"))
            chown = stack.enter_context(patch("deploy.os.chown", create=True))
            stack.enter_context(patch("deploy.read_beneath", side_effect=lambda root, rel: (root / rel).read_bytes()))
            stack.enter_context(patch("deploy.os.statvfs", create=True, return_value=SimpleNamespace(
                f_blocks=256 * 1024, f_frsize=1024)))
            def fresh(path, resources):
                path.mkdir()
                resources.roots[path] = (1, 2)
            stack.enter_context(patch("deploy.fresh_root", side_effect=fresh))
            mounted = []
            def mount(resources, command, argv, target):
                mounted.append(target)
                if failure == "partial-mount" and len(mounted) == 2:
                    raise TimeoutError("fixture mount completed before timeout")
            stack.enter_context(patch("deploy.mount_owned", side_effect=mount))
            upstream = Mock()
            if failure == "https-ready":
                upstream.start.side_effect = TimeoutError("fixture HTTPS readiness")
            stack.enter_context(patch("deploy.Upstream", return_value=upstream))
            refs = []
            def reference(*_):
                ref = Mock(initial={"pid": 902})
                ref.exited.return_value = True
                refs.append(ref)
                return ref
            stack.enter_context(patch("deploy.ProcessRef", side_effect=reference))
            stack.enter_context(patch.object(d, "_spawner", side_effect=reference))
            if interrupt:
                d.network.prepare.side_effect = KeyboardInterrupt
            d.network.close.side_effect = lambda: order.append("network-close")
            def cleanup(**kwargs):
                order.append("stop-engine")
                kwargs["stop_engine"]()
                order.extend(["kill-cgroup", "unmount", "loops", "retain" if retain else "remove", "crash"])
                return {"ok": not retain, "retained": [str(d.root)] if retain else [], "failures": []}
            d.resources.cleanup.side_effect = cleanup
            stack.enter_context(patch("deploy.os.waitpid", create=True, return_value=(902, 0)))
            stack.enter_context(patch("deploy.os.WNOHANG", create=True, new=1))
            if failure or interrupt:
                with self.assertRaises((RuntimeError, TimeoutError, KeyboardInterrupt)):
                    d.prepare()
            else:
                self.assertIs(d.prepare(), d)
                self.assertEqual(d.stage, "ready")
                self.assertEqual(d.admin.start_row("work0"), "abcdef:1")
                d.admin.stop_row("abcdef:1")
                self.assertEqual(set(d.workspaces), {"work0", "work1", "work2"})
                self.assertIn("digest", d.manifest)
                self.assertEqual(len(list((d.root / "ca-pool").iterdir())), d.cap["ca_count"])
                d.network.bind_hosts.assert_called_once_with(d.scratch / "nb-decoy-hosts",
                                                             names=("nb-decoy-upstream.test", "nb-decoy-question.test"))
                sizes = [p.stat().st_size for p in d.scratch.glob("*.btrfs")]
                self.assertEqual(sizes, [IMAGE_BYTES, IMAGE_BYTES])
                # two images, three engine workspace binds, two undefended host-workspace binds (v4, tests.md 1.7)
                self.assertEqual(len(mounted), 7)
                self.assertEqual(set(d.host_workspaces), {"work0", "work1"})
                self.assertTrue(all(w["mount"].name == "tree" for w in d.workspaces.values()))
                chown.assert_any_call(d.storage / "work0", 70997, 70997)
                chown.assert_any_call(d.storage / "u-work0", 1000, 1000)
                engine = d.command.starts[-1][0]
                self.assertIn(str(d.source / "bin/engine"), engine)
                self.assertIn(str(d.build / "w2-cell"), engine)
                self.assertNotIn("engine_fixture", str(engine))
                pdp = d.command.starts[-2][0]  # started before the engine, under its dedicated uid only
                self.assertEqual(pdp[:8], ["/usr/bin/setpriv", "--reuid=70998", "--regid=70998", "--clear-groups",
                                           "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                                           "--no-new-privs"])
                self.assertEqual(pdp[-2:], [str(d.source / "bin/simple-pdp"), str(d.root / "hook/pdp.sock")])
                chown.assert_any_call(d.root / "hook", 1000, 70998)
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE((d.root / "hook").stat().st_mode), 0o2750)
                asked = [argv for argv, _ in d.command.calls if "nb-decoy-question.test:443" in argv]
                self.assertEqual([argv[argv.index("put") + 1] for argv in asked], ["work0", "work2"])
                self.assertTrue(all(argv[-2:] == ["--approval", "always"] for argv in asked))
                d.close()
            d.close()  # idempotent, including partial failures
            d.resources.cleanup.assert_called_once()
            self.assertEqual(order, ["stop-engine", "network-close", "kill-cgroup", "unmount", "loops",
                                     "retain" if retain else "remove", "crash"])
            for ref in refs:
                ref.close.assert_called_once()
            return d.stage, d.cleanup_result

    def test_mock_full_assembly_admin_and_cleanup_chain(self):
        self.exercise()

    def test_each_command_stage_failure_uses_same_cleanup(self):
        for failure in ("mkfs.btrfs", "deploy_seed.py", "tls_material.py", "subvolume", "w2-catalog",
                        "https-ready", "simple-pdp", "w2-cell", "cred put", "nb-decoy-question.test"):
            with self.subTest(stage=failure):
                self.exercise(failure=failure)

    def test_partial_mount_timeout_still_cleans_registered_objects(self):
        self.exercise(failure="partial-mount")

    def test_interrupt_uses_same_cleanup(self):
        self.exercise(interrupt=True)

    def test_cleanup_failure_is_returned_not_success(self):
        _, result = self.exercise(retain=True)
        self.assertFalse(result["ok"])
        self.assertTrue(result["retained"])

    def test_wrong_product_fails_before_any_side_effect_command(self):
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            d.products["w2-cell"]["sha256"] = "wrong"
            with patch("deploy.require_platform"), patch.object(d, "close") as close:
                with self.assertRaisesRegex(ValueError, "artifact digest"):
                    d.prepare()
                close.assert_called_once()
            self.assertEqual(d.command.calls, [])
            self.assertFalse(d.root.exists())

    def test_changed_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            (d.source / "changed").write_text("fixture")
            with patch("deploy.require_platform"), patch.object(d, "close"), self.assertRaisesRegex(ValueError, "snapshot"):
                d.prepare()
            self.assertEqual(d.command.calls, [])

    def test_no_reuse_and_no_unowned_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            d.started = True
            with self.assertRaises(RuntimeError):
                d.prepare()
            with self.assertRaises(ValueError):
                fresh_root(Path(temp) / "outside", Mock())

    def test_network_closes_even_when_engine_stop_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            def cleanup(**kw):
                with self.assertRaises(RuntimeError):
                    kw["stop_engine"]()
                return {"ok": False, "retained": [str(d.root)]}
            d.resources.cleanup.side_effect = cleanup
            with patch.object(d, "stop_engine", side_effect=RuntimeError("fixture stuck engine")):
                self.assertFalse(d.close()["ok"])
            d.network.close.assert_called_once()

    def test_context_exit_surfaces_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            d = make_deployment(temp)
            with patch.object(d, "close", return_value={"ok": False, "retained": [str(d.root)]}):
                with self.assertRaisesRegex(RuntimeError, "cleanup incomplete"):
                    d.__exit__(None, None, None)
