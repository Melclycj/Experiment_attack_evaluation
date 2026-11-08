"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Measurement deployment only; the original connector is exec'd with fd3/fd4 intact.
import json
import os
from pathlib import Path
import re
import resource
import secrets
import stat
import sys
import time

LOG_LIMIT = 262144


def invocation(argv):
    if len(argv) < 5:
        raise ValueError('measurement wrapper needs root, target and original arguments')
    root, target, *args = argv
    root, target = Path(root), Path(target)
    if (not root.is_absolute() or '..' in root.parts or not root.name.startswith('nb-decoy-')
            or not target.is_absolute() or '..' in target.parts or target.name != 'connector'
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}:[1-9][0-9]{0,19}', args[-1])
            or not args[-2].isdecimal()):
        raise ValueError('invalid measurement wrapper invocation')
    if int(args[-2]) < 65536:
        raise ValueError('connector row must use a reserved uid')
    return root, target, args


def file_identity(fd):
    s = os.fstat(fd)
    return {'dev': s.st_dev, 'ino': s.st_ino, 'mode': stat.S_IFMT(s.st_mode)}


def run(argv):
    root, target, args = invocation(argv)
    if os.getuid() != 70999 or root.is_symlink():
        raise ValueError('measurement wrapper must run as the connector uid')
    s = root.stat()
    if s.st_uid != 70999 or stat.S_IMODE(s.st_mode) != 0o700 or not stat.S_ISDIR(s.st_mode):
        raise ValueError('private connector log directory required')
    # Check these BEFORE opening files: a missing production descriptor must not
    # accidentally be reused as an output file and then survive an apparent pass.
    links = {str(fd): file_identity(fd) for fd in (3, 4)}
    if any(v['mode'] != stat.S_IFSOCK for v in links.values()):
        raise ValueError('production proxy/judgment descriptors are not sockets')
    execution = args[-1]
    stem = 'nb-decoy-' + execution.replace(':', '-')
    logs = {}
    for fd, kind in ((1, 'stdout'), (2, 'stderr')):
        name = stem + '-' + kind
        out = os.open(root / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            if out <= 4:
                raise ValueError('measurement output collided with production descriptors')
            os.dup2(out, fd, inheritable=True)
            logs[kind] = {'name': name, **file_identity(out)}
        finally:
            os.close(out)
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    bound = min([LOG_LIMIT] + [n for n in (soft, hard) if n != resource.RLIM_INFINITY])
    if bound <= 0:
        raise ValueError('inherited file limit does not allow complete measurement')
    # Lower only; leave core-dump configuration untouched and record the bound.
    resource.setrlimit(resource.RLIMIT_FSIZE, (bound, bound))
    ready = {'v': 1, 'pid': os.getpid(), 'ppid': os.getppid(), 'execution': execution,
             'row_uid': int(args[-2]), 'nonce': secrets.token_hex(24), 'uid': os.getuid(),
             'target': str(target), 'argv': [str(target), *args], 'logs': logs,
             'production_fds': links, 'log_limit': bound}
    temporary = root / (stem + '.pending')
    with temporary.open('x') as f:
        json.dump(ready, f); f.flush(); os.fsync(f.fileno())
    # Exclusive publication: never replace a peer's ready record.
    os.link(temporary, root / (stem + '.ready')); temporary.unlink()
    end = time.monotonic() + 10
    while time.monotonic() < end:
        try:
            release_path = root / (stem + '.release')
            fd = os.open(release_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            time.sleep(.01); continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_size > 16384:
                raise ValueError('release is not a bounded controller-owned record')
            release = json.loads(os.read(fd, 16385))
        finally:
            os.close(fd)
        if release != ready:
            raise ValueError('measurement release mismatch')
        if {str(fd): file_identity(fd) for fd in (3, 4)} != links:
            raise ValueError('production descriptors changed before exec')
        # execv preserves the sampled environment and pid/starttime. There is no
        # intervening shell, environment mutation or detached logging process.
        os.execv(sys.executable, [sys.executable, '-I', '-B', str(target), *args])
        raise RuntimeError('exec returned')
    raise TimeoutError('connector environment measurement handshake timeout')


if __name__ == '__main__':
    run(sys.argv[1:])
