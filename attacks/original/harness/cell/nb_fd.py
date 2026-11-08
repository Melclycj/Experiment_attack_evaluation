"""这是 1.1 隔离论证的验证测试：仅针对本次自建诱饵，不操作外部目标。
NB-24：只以启动清单中身份未变的 fd 与原 cwd 读本批诱饵；不借运行器新开的 fd。"""
import errno
import os
import stat


def ascent(path):
    if not isinstance(path, str) or not path.startswith('/') or '\0' in path:
        raise ValueError('absolute decoy path required')
    return '../' * 16 + path.lstrip('/')


def identity(fd):
    info = os.fstat(fd)
    return {'dev': info.st_dev, 'ino': info.st_ino, 'type': stat.S_IFMT(info.st_mode)}


def current(item):
    """A closed/reused number is not an inherited anchor. Never dup/open it anew."""
    try:
        now = identity(item['fd'])
        now['target'] = os.readlink('/proc/self/fd/' + str(item['fd']))
        return all(now[k] == item[k] for k in now)
    except OSError as exc:
        if exc.errno in (errno.EBADF, errno.ENOENT):
            return False
        raise


def read_anchor(ctx, label, fd, path, restore_fd):
    """The restore descriptor is never passed to openat as an attack anchor."""
    data, opened = b'', None
    result = {'fd': fd, 'path': ascent(path), 'chdir_errno': 0,
              'open_errno': 0, 'identity': None, 'restored': False}
    try:
        if fd is not None:
            try:
                os.fchdir(fd)
            except OSError as exc:
                result['chdir_errno'] = exc.errno
        try:
            opened = os.open(result['path'], os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC,
                             **({'dir_fd': fd} if fd is not None else {}))
            result['identity'] = identity(opened)
            if result['identity']['type'] != stat.S_IFREG:
                raise ValueError('decoy read reached a nonregular object')
            data = os.read(opened, 65537)
            if len(data) > 65536:
                raise ValueError('decoy capture limit')
        except OSError as exc:
            result['open_errno'] = exc.errno
    finally:
        if opened is not None:
            os.close(opened)
        os.fchdir(restore_fd)
        result['restored'] = identity(restore_fd) == cwd_identity()
        ctx.capture(label, data)
        ctx.observe(label, **result)
    if not result['restored']:
        raise ValueError('cwd restoration failed')
    return data, result


def cwd_identity():
    value = os.stat('.')
    return {'dev': value.st_dev, 'ino': value.st_ino, 'type': stat.S_IFMT(value.st_mode)}


def control(ctx):
    # Opening cwd is allowed ONLY for the specified positive control/restoration.
    fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        data, result = read_anchor(ctx, 'cwd-control', fd,
                                  os.path.join(ctx.cwd, ctx.request['parameters']['control']), fd)
        return (result['open_errno'] == result['chdir_errno'] == 0
                and ctx.request['parameters']['control_sentinel'].encode() in data)
    finally:
        os.close(fd)


def action(ctx):
    items = ctx.record['inherited_fds']
    if len(items) > 24 or len({v['fd'] for v in items}) != len(items):
        raise ValueError('invalid/big startup fd inventory')
    # Check liveness BEFORE opening the restoration fd: a closed boot number
    # must not become eligible because this open happens to recycle it.
    live = {item['fd']: current(item) for item in items}
    restore_fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    initial = cwd_identity()
    try:
        ctx.observe('cwd-start', path=os.getcwd(), identity=initial)
        for item in items:
            label = 'fd-' + str(item['fd'])
            valid = live[item['fd']] and current(item)
            ctx.observe(label + '-eligibility', startup=item, live=valid)
            if valid:
                read_anchor(ctx, label, item['fd'], ctx.path('key'), restore_fd)
        # cwd is its own ambient anchor, NOT restore_fd or Files.fd.
        read_anchor(ctx, 'cwd', None, ctx.path('key'), restore_fd)
    finally:
        os.fchdir(restore_fd)
        ctx.observe('cwd-end', identity=cwd_identity(), restored=cwd_identity() == initial)
        os.close(restore_fd)
