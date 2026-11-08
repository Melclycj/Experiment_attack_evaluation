"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import os
from record import RunDirectory


class CountedRunDirectory(RunDirectory):
    """2.3 output (user 2026-11-03): the byte budget runs on a total, not a scan per write.

    A full scan of the run directory on /mnt/d costs about 0.7 ms per file, and a
    sub-target writes about 60 files, so a scan per write made each later
    sub-target slower. Every write still enforces the budget against the total and
    passes RunDirectory.write's flat-name and atomic_write's path checks. The full
    scan (size: links, non-regular entries, root swaps, real bytes) runs at each
    sub-target start (cb_batch) and in finalize; a foreign entry surfaces there,
    not at the next write. 1.1 keeps the base class.
    """
    total = None

    def rescan(self) -> int:
        self.total = self.size()
        return self.total

    def used(self) -> int:
        return self.rescan() if self.total is None else self.total

    def write(self, name, data, *, replace=False, reserve=0):
        target = self.path / name
        old = target.lstat().st_size if replace and os.path.lexists(target) else 0
        super().write(name, data, replace=replace, reserve=reserve)
        self.total += len(data) - old


def directory_class(unit):
    return CountedRunDirectory if unit == 'credential-binding' else RunDirectory
