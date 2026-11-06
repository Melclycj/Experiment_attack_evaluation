"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.name == 'posix', 'Linux dir-fd file transport')
class ReadyPublication(unittest.TestCase):
    def test_ready_name_appears_only_complete_and_exclusive(self):
        import nb_io
        from cb_worker import publish_ready
        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd();os.chdir(tmp)
            try:
                p = {'worker_ready': 'nb-decoy-worker-ready-1', 'marker': 'nb-decoy-m'}
                seen = []
                real = nb_io.os.fsync
                def fsync(fd):
                    seen.append(os.path.lexists(p['worker_ready']));return real(fd)
                with patch.object(nb_io.os, 'fsync', fsync):
                    publish_ready(p)
                # The data fsync happens before the final name exists; only then is it linked.
                self.assertFalse(seen[0])
                value = json.loads(Path(p['worker_ready']).read_bytes())
                self.assertEqual(value, {'pid': os.getpid(), 'ppid': os.getppid(), 'marker': 'nb-decoy-m'})
                self.assertEqual(os.stat(p['worker_ready']).st_nlink, 1)
                self.assertEqual([n for n in os.listdir('.') if n.startswith('.nb-write-')], [])
                with self.assertRaises(FileExistsError):publish_ready(p)
            finally:
                os.chdir(old)

    def test_host_poll_treats_the_two_link_window_as_pending(self):
        import nb_io
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'temp').write_bytes(b'{}');os.link(Path(tmp, 'temp'), Path(tmp, 'ready'))
            files = nb_io.Files(tmp)
            try:
                with self.assertRaises(nb_io.PublicationPending):files.read('ready', 4096)
            finally:
                files.close()


if __name__ == '__main__':unittest.main()
