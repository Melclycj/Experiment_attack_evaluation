"""这是 1.1 隔离论证的验证测试：4d 宿主准备与外部事实，只接受本批拥有的对象。"""
import hashlib
import os
from pathlib import Path
import stat
from cell.nb_io import Files

LIMIT = 1024 * 1024


class EngineFile:
    """Pinned existing regular file. Append-safe E-09 reads retain a fixed prefix;
    foreign links/replacements are never followed or overwritten during recovery.
    """
    def __init__(self, rt, path):
        self.path, self.fd, self.parent = Path(path), None, None
        if not any(self.path == p or p in self.path.parents for p in rt.resources.roots):
            raise ValueError('engine object outside registered batch roots')
        try:
            self.parent = Files(self.path.parent)
            self.parent_identity = os.fstat(self.parent.fd)
            self.fd = os.open(self.path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                              dir_fd=self.parent.fd)
            s = os.fstat(self.fd)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != 1000 or stat.S_IMODE(s.st_mode) != 0o600:
                raise ValueError('engine file must be uid 1000, mode 0600, single-link regular')
            self.initial = self.identity(s)
            self.original, self.before = self.read()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def identity(s):
        return {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid, 'mode': stat.S_IMODE(s.st_mode)}

    def check(self):
        if self.fd is None: raise ValueError('closed engine file pin')
        # Re-walk all ancestors without following replacements/links.
        fresh = Files(self.path.parent)
        try:
            s = os.fstat(fresh.fd)
            if (s.st_dev, s.st_ino) != (self.parent_identity.st_dev, self.parent_identity.st_ino):
                raise ValueError('engine object parent replaced')
        finally:
            fresh.close()
        s = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
        f = os.fstat(self.fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or f.st_nlink != 1
                or self.identity(s) != self.initial or self.identity(f) != self.initial):
            raise ValueError('engine file identity/ownership changed')
        return f

    def read(self):
        s = self.check()
        if s.st_size > LIMIT: raise ValueError('engine evidence size bound')
        # One prefix only: legitimate audit append need not stop the engine.
        data = os.pread(self.fd, s.st_size, 0)
        if len(data) != s.st_size or os.pread(self.fd, s.st_size, 0) != data:
            raise ValueError('engine prefix changed during read')
        end = self.check()
        if end.st_size < len(data): raise ValueError('engine file truncated during read')
        return data, {**self.initial, 'size': len(data), 'observed_size': end.st_size,
                      'sha256': hashlib.sha256(data).hexdigest()}

    def restore(self):
        current, _ = self.read()
        if current != self.original:
            self.check()
            offset = 0
            while offset < len(self.original):
                n = os.pwrite(self.fd, self.original[offset:], offset)
                if n <= 0: raise OSError('short mirror restore')
                offset += n
            os.ftruncate(self.fd, len(self.original)); os.fsync(self.fd)
        data, info = self.read()
        if data != self.original: raise ValueError('mirror restoration mismatch')
        return info

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd = None
        if self.parent is not None: self.parent.close()
