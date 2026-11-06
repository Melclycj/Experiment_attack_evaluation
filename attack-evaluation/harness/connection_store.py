"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
from pathlib import Path
import stat
from cell.nb_io import Files
from common import json_bytes
from safeio import atomic_write


class ConnectionStore:
    """Root-owned per-address evidence; uid 1000 can search but not rewrite it.
    Exact children only. Never recursively delete an unexpected file/directory.
    The controller must prove service AND attack tree exit before restore().
    """
    NAMES = {'config.json', 'ready.json', 'journal.jsonl', 'socket', 'nb-decoy-markers'}

    def __init__(self, rt, name):
        from cell.nb_contract import leaf
        if not leaf(name).startswith('nb-decoy-'):
            raise ValueError('connection directory must be a decoy')
        parent = Path(rt.deployment.scratch)
        if not any(parent == r or r in parent.parents for r in rt.resources.roots):
            raise ValueError('connection store outside owned run roots')
        self.root, self.parent, self.files = parent / name, Files(parent), None
        self.restored, created = False, None
        try:
            self.parent.absent(name)
            os.mkdir(name, 0o755, dir_fd=self.parent.fd)
            created = os.stat(name, dir_fd=self.parent.fd, follow_symlinks=False)
            self.files = Files(self.root)
            self.pinned = os.fstat(self.files.fd)
            if self.pinned.st_uid != 0 or stat.S_IMODE(self.pinned.st_mode) != 0o755:
                raise ValueError('connection evidence requires root-owned 0755 directory')
        except BaseException:
            try:
                if created is not None:
                    now = os.stat(name, dir_fd=self.parent.fd, follow_symlinks=False)
                    if (now.st_dev, now.st_ino) != (created.st_dev, created.st_ino):
                        raise ValueError("partial store replaced; retain for cleanup")
                    os.rmdir(name, dir_fd=self.parent.fd)
            finally:
                self.close()
            raise

    def write_config(self, value):
        self.files.absent('config.json')
        atomic_write(self.root / 'config.json', json_bytes(value))

    def read(self, name, limit=512 * 1024):
        return self.files.read(name, limit)

    def markers(self):
        path = self.root / 'nb-decoy-markers'
        try:
            info = path.lstat()
        except FileNotFoundError:
            return {}
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('marker directory identity/permissions')
        with_files = Files(path)
        try:
            names = sorted(os.listdir(with_files.fd))
            if len(names) > 64:
                raise ValueError('marker count bound')
            result = {}
            for name in names:
                if len(name) != 13 or not name.startswith('nb-decoy-') or not name[9:].isdigit():
                    raise ValueError('unexpected marker name')
                result[name] = with_files.read(name, 16384)
            return result
        finally:
            with_files.close()

    def restore(self):
        if self.restored:
            return {'restored': True, 'root': str(self.root)}
        if self.files is None or self.files.fd is None:
            raise ValueError('closed store does not prove restoration')
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (self.pinned.st_dev, self.pinned.st_ino):
            raise ValueError('connection store replaced; retaining')
        names = set(os.listdir(self.files.fd))
        if names - self.NAMES:
            raise ValueError('unknown connection evidence child; retaining')
        markers = self.markers()
        if 'nb-decoy-markers' in names:
            m = Files(self.root / 'nb-decoy-markers')
            try:
                for name in markers:
                    os.unlink(name, dir_fd=m.fd)
            finally:
                m.close()
            os.rmdir('nb-decoy-markers', dir_fd=self.files.fd)
        for name in names - {'nb-decoy-markers'}:
            if stat.S_ISDIR(os.stat(name, dir_fd=self.files.fd, follow_symlinks=False).st_mode):
                raise ValueError('unexpected directory at connection file; retaining')
            os.unlink(name, dir_fd=self.files.fd)
        os.rmdir(self.root.name, dir_fd=self.parent.fd)
        self.parent.absent(self.root.name)
        self.restored = True
        self.close()
        return {'restored': True, 'root': str(self.root)}

    def close(self):
        if self.files is not None:
            self.files.close()
        self.parent.close()
