"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Cold-audit finding 5 (CB-03, 2026-11-04): installing the local package is what runs its
# declared postinstall. Runs the real offline installer and /bin/sh in a temporary
# directory only; no network, namespace, engine or attack.
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

CELL = Path(__file__).resolve().parent.parent / 'cell'


def tarball(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name);info.size = len(data);info.type = kind
            archive.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


@unittest.skipUnless(os.name == 'posix', 'execve and /bin/sh')
class Install(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_postinstall_runs_from_the_installed_package_as_the_same_process(self):
        from cb_actions import package
        out = self.root / 'hook.txt'
        script = 'exec /bin/sh -c \'echo "$npm_lifecycle_event $npm_package_name $$ $PWD" > ' + str(out) + '\''
        ctx = SimpleNamespace(payload=CELL)
        data = package(ctx, script)
        (self.root / 'pkg.tgz').write_bytes(data)
        child = subprocess.Popen([sys.executable, '-I', '-B', str(CELL / 'cb_install.py'), str(self.root / 'pkg.tgz'),
                                  str(self.root / 'prefix')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = child.communicate(timeout=20)
        self.assertEqual(child.returncode, 0, stderr)
        receipt = json.loads(stderr.split(b'\n', 1)[0])
        self.assertEqual(receipt['installed'], 'nb-decoy-offline-package')
        self.assertEqual(receipt['package'], hashlib.sha256(data).hexdigest())
        self.assertEqual(receipt['files']['worker.py'], hashlib.sha256((CELL / 'cb_worker.py').read_bytes()).hexdigest())
        event, name, pid, cwd = out.read_text().split()
        self.assertEqual((event, name), ('postinstall', 'nb-decoy-offline-package'))
        # The hook replaced the installer: the runner's direct child keeps its PID.
        self.assertEqual(int(pid), child.pid)
        self.assertEqual(cwd, str(self.root / 'prefix' / 'node_modules' / 'nb-decoy-offline-package'))

    def test_links_escapes_and_hookless_packages_are_refused(self):
        from cb_install import install
        manifest = json.dumps({'name': 'nb-decoy-offline-package', 'scripts': {'postinstall': 'true'}}).encode()
        cases = {'link': [('package/package.json', manifest, tarfile.REGTYPE), ('package/x', b'', tarfile.SYMTYPE)],
                 'escape': [('package/package.json', manifest, tarfile.REGTYPE), ('package/../x', b'x', tarfile.REGTYPE)],
                 'nested': [('package/package.json', manifest, tarfile.REGTYPE), ('package/a/b', b'x', tarfile.REGTYPE)],
                 'no-hook': [('package/package.json', b'{"name":"nb-decoy-offline-package"}', tarfile.REGTYPE)]}
        for i, (name, members) in enumerate(cases.items()):
            path = self.root / (name + '.tgz');path.write_bytes(tarball(members))
            with self.subTest(name=name), self.assertRaises(ValueError):
                install(str(path), str(self.root / ('prefix-' + str(i))))


if __name__ == '__main__':
    unittest.main()
