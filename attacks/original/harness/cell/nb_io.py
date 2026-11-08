"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import os
import secrets
import stat

if __package__:
    from .nb_contract import leaf, relative
else:
    from nb_contract import leaf, relative


class PublicationPending(ValueError):
    """Two links may be the exclusive publisher before unlink; never read them.

    Only live mailbox polling may retry this under its existing deadline.
    Evidence collection and all other reads still fail closed.
    """


class Files:
    """Pinned Linux directory; no-follow reads and exclusive atomic flat writes.

    Used for harness transport only, not deliberately symlinked attack targets.
    The external judge must still verify the untrusted cell's observations.
    """
    def __init__(self, root):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise RuntimeError("cell file transport requires Linux")
        root = os.path.abspath(root)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        fd = os.open("/", flags)
        try:
            for part in root.split("/")[1:]:
                if part:
                    child = os.open(part, flags, dir_fd=fd)
                    os.close(fd)
                    fd = child
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def absent(self, name):
        leaf(name)
        try:
            os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise FileExistsError(name)

    def read(self, name, limit):
        relative(name)
        if type(limit) is not int or limit < 0:
            raise ValueError("invalid read limit")
        fds, parent = [], self.fd
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            for part in name.split("/")[:-1]:
                parent = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
                fds.append(parent)
            fd = os.open(name.split("/")[-1], flags | os.O_NONBLOCK, dir_fd=parent)
            fds.append(fd)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("not a bounded single-link regular file")
            if before.st_nlink == 2:
                raise PublicationPending("single-link publication pending")
            if before.st_nlink != 1:
                raise ValueError("not a bounded single-link regular file")
            data = bytearray()
            while True:
                chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ValueError("file grew beyond limit")
            after = os.fstat(fd)
            if any(getattr(before, k) != getattr(after, k) for k in
                   ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
                raise ValueError("file changed during read")
            return bytes(data)
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def write(self, name, data):
        leaf(name)
        self.absent(name)
        temp = ".nb-write-" + secrets.token_hex(16)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
        finally:
            os.unlink(temp, dir_fd=self.fd)
        os.fsync(self.fd)
