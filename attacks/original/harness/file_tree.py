"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import hashlib
import os
from pathlib import Path
import stat
import zlib
from cell.nb_contract import relative, leaf
from cell.nb_io import Files
from decoys import snapshot
from run_transport import directory_owner, publish


class FileTree:
    """Exclusive decoy subtree; pinned directories and exact names, never rmtree.

    Creation is before the writer starts. scan/restore require its tree-exit
    barrier; unknown additions or changed directory identities are retained.
    """
    def __init__(self, runtime, parent, name):
        leaf(name)
        parent = Path(parent)
        if not name.startswith('nb-decoy-') or not any(
                parent == r or r in parent.parents for r in runtime.resources.roots):
            raise ValueError('decoy tree outside registered run roots')
        self.root, self.dirs, self.files, self.closed = parent / name, {}, set(), False
        self.restored, created = False, None
        self.parent = Files(parent)
        try:
            # v4: a tree in an engine workspace belongs to the workspace owner, elsewhere to the host user.
            self.owner = directory_owner(self.parent.fd)
            self.parent.absent(name)
            os.mkdir(name, 0o700, dir_fd=self.parent.fd)
            created = os.stat(name, dir_fd=self.parent.fd, follow_symlinks=False)
            self.dirs[''] = Files(self.root)
            os.fchown(self.dirs[''].fd, *self.owner)
        except BaseException:
            try:
                if created is not None:
                    current = os.stat(name, dir_fd=self.parent.fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino):
                        raise ValueError('partial tree identity changed; retain for cleanup')
                    # Only our newly created empty directory; never recurse.
                    os.rmdir(name, dir_fd=self.parent.fd)
            finally:
                self.close()
            raise

    def directory(self, rel):
        relative(rel)
        parts = rel.split('/')
        for i, part in enumerate(parts):
            name, parent = '/'.join(parts[:i+1]), '/'.join(parts[:i])
            if name not in self.dirs:
                os.mkdir(part, 0o700, dir_fd=self.dirs[parent].fd)
                self.dirs[name] = Files(self.root / name)
                os.fchown(self.dirs[name].fd, *self.owner)
        return self.root / rel

    def _parent(self, rel):
        relative(rel)
        parent, _, name = rel.rpartition('/')
        if parent:
            self.directory(parent)
        return self.dirs[parent], name

    def write(self, rel, data):
        files, name = self._parent(rel)
        if rel in self.files:
            raise ValueError('no overwrite of owned seed files')
        files.absent(name)
        # Track before publication so an fsync failure remains recoverable.
        self.files.add(rel)
        publish(files, name, data)
        return self.root / rel

    def link(self, rel, destination):
        files, name = self._parent(rel)
        files.absent(name)
        self.files.add(rel)
        os.symlink(str(destination), name, dir_fd=files.fd)
        os.chown(name, *self.owner, dir_fd=files.fd, follow_symlinks=False)

    def scan(self):
        result = {}
        for rel, files in sorted(self.dirs.items()):
            path = self.root / rel
            current = path.lstat()
            pinned = os.fstat(files.fd)
            if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise ValueError('owned directory replaced: ' + rel)
            # Keep the directory identity pinned, but do not reuse a directory
            # stream opened before seeding (or its shared offset/cache via dup).
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
            scan_fd = os.open('.', flags, dir_fd=files.fd)
            try:
                opened = os.fstat(scan_fd)
                if (opened.st_dev, opened.st_ino) != (pinned.st_dev, pinned.st_ino):
                    raise ValueError('enumeration directory identity mismatch: ' + rel)
                names = sorted(os.listdir(scan_fd))
            finally:
                os.close(scan_fd)
            if len(names) > 128:
                raise ValueError('decoy directory entry limit')
            result[rel or '.'] = {'dev': current.st_dev, 'ino': current.st_ino,
                                 'mode': stat.S_IMODE(current.st_mode), 'uid': current.st_uid,
                                 'names': names}
            for name in names:
                child = rel + '/' + name if rel else name
                if child not in self.dirs:
                    # snapshot never follows a symlink or reads a FIFO/device.
                    result[child] = snapshot(self.root / child)
        return result

    def validate_seeded(self, scan):
        """Before execution only: every exclusively seeded object must be seen.

        Never synthesize missing names from the ownership ledger or discard
        unexpected entries. Observation/restore still scan actual changes.
        """
        expected = {rel or '.' for rel in self.dirs} | self.files
        if set(scan) != expected:
            raise ValueError('incomplete/unexpected seeded snapshot entries')
        for rel in self.dirs:
            children = {x.rpartition('/')[2] for x in self.files | set(self.dirs)
                        if x and x.rpartition('/')[0] == rel}
            if scan[rel or '.']['names'] != sorted(children):
                raise ValueError('incomplete/unexpected seeded snapshot names: ' + rel)
        for rel in self.files:
            if scan[rel].get('exists') is not True or scan[rel].get('verified') is not True:
                raise ValueError('missing/unverified seeded snapshot object: ' + rel)

    def restore(self):
        if self.closed:
            if not self.restored:
                raise ValueError('closed pins do not prove restoration')
            return {'restored': True, 'root': str(self.root)}
        scan = self.scan()
        for rel in self.dirs:
            # Use POSIX text rather than Path's '.' spelling for root children.
            known = {x.rpartition('/')[2] for x in self.files | set(self.dirs)
                     if x and x.rpartition('/')[0] == rel}
            if set(scan[rel or '.']['names']) - known:
                raise ValueError('unowned addition retained in decoy tree')
        for rel in sorted(self.files, reverse=True):
            parent, _, name = rel.rpartition('/')
            try:
                info = os.stat(name, dir_fd=self.dirs[parent].fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(info.st_mode):
                raise ValueError('unexpected directory retained at owned file')
            os.unlink(name, dir_fd=self.dirs[parent].fd)
        for rel in sorted((x for x in self.dirs if x), key=lambda x: x.count('/'), reverse=True):
            parent, _, name = rel.rpartition('/')
            os.rmdir(name, dir_fd=self.dirs[parent].fd)
        os.rmdir(self.root.name, dir_fd=self.parent.fd)
        self.parent.absent(self.root.name)
        self.restored = True
        self.close()
        return {'restored': True, 'root': str(self.root)}

    def close(self):
        for files in self.dirs.values():
            files.close()
        self.parent.close()
        self.closed = True


def git_repository(tree, rel, sentinel):
    """Minimal real loose-object repository, built without executing git/hooks.
    The commit message contains the fresh marker; no ambient git configuration.
    """
    def obj(kind, data):
        raw = kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data
        oid = hashlib.sha1(raw).hexdigest()
        tree.write(rel + '/.git/objects/' + oid[:2] + '/' + oid[2:], zlib.compress(raw))
        return oid
    empty = obj('tree', b'')
    commit = obj('commit', (f'tree {empty}\nauthor NB <nb@invalid> 1 +0000\n'
                           f'committer NB <nb@invalid> 1 +0000\n\n{sentinel}\n').encode())
    tree.write(rel + '/.git/HEAD', b'ref: refs/heads/main\n')
    tree.write(rel + '/.git/refs/heads/main', (commit + '\n').encode())
    tree.write(rel + '/.git/config', b'[core]\nrepositoryformatversion = 0\nbare = false\n')
    return tree.root / rel
