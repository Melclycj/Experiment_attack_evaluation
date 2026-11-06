"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
import resource
import subprocess
import unittest


@unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfd')
class HighDescriptor(unittest.TestCase):
    def test_exited_works_for_a_pidfd_numbered_above_1024(self):
        from process_identity import ProcessRef
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if soft <= 1100:
            self.skipTest('descriptor limit too low to place a pidfd above 1024')
        child = subprocess.Popen(['/usr/bin/sleep', '30'])
        high = None
        try:
            fd = os.pidfd_open(child.pid)
            high = os.dup2(fd, 1100);os.close(fd)
            ref = object.__new__(ProcessRef);ref.fd = high
            self.assertFalse(ref.exited())
            child.kill();child.wait(timeout=5)
            self.assertTrue(ref.exited())
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
            if high is not None:os.close(high)


if __name__ == '__main__':unittest.main()
