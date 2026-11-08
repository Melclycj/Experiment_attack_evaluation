"""w2_open_beneath through engine/ffi.py against the real library (validation.md H-10, H-11; plan engine-v3-n16-file-read
2.3a). The cases that need root (a bind mount under the prefix, /dev/null bound into it) are in the C check
native/checks/check_open_beneath.c, which the sandbox regression runs as root.
"""
from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
import socket
import stat
import time

import pytest

from conftest import settled_fds as open_fds

READ, LIST = 1, 2
O_PATH = getattr(os, 'O_PATH', 0o10000000)


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, int]:
    base = tmp_path / 'base'
    (base / 'sub').mkdir(parents=True)
    (base / 'f.txt').write_bytes(b'hello')
    (base / 'sub' / 'in.txt').write_bytes(b'inner')
    (tmp_path / 'outside').mkdir()
    (tmp_path / 'outside' / 'secret').write_bytes(b'SECRET')
    (base / 'mid').symlink_to('sub')
    (base / 'last').symlink_to('f.txt')
    (base / 'out').symlink_to(tmp_path / 'outside' / 'secret')
    (base / 'up').symlink_to('../outside/secret')
    os.mkfifo(base / 'fifo')
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(base / 'sock'))
    s.close()
    anchor = os.open(base, O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    yield base, anchor
    os.close(anchor)


def test_a_regular_file_is_reopened_read_only_as_the_same_inode(native, tree) -> None:
    base, anchor = tree
    fd = native.open_beneath(anchor, b'f.txt', READ)
    try:
        st, want = os.fstat(fd), os.stat(base / 'f.txt')
        assert stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) == (want.st_dev, want.st_ino)
        assert os.pread(fd, 16, 0) == b'hello'                         # a real descriptor, not an O_PATH one
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        assert flags & os.O_ACCMODE == os.O_RDONLY and not flags & O_PATH and flags & os.O_NONBLOCK
        assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        with pytest.raises(OSError):
            os.write(fd, b'x')
    finally:
        os.close(fd)
    fd = native.open_beneath(anchor, b'sub/in.txt', READ)
    assert os.pread(fd, 16, 0) == b'inner'
    os.close(fd)


def test_a_directory_is_reopened_for_listing(native, tree) -> None:
    base, anchor = tree
    for path, where in ((b'sub', base / 'sub'), (b'.', base)):
        fd = native.open_beneath(anchor, path, LIST)
        try:
            st = os.fstat(fd)
            assert stat.S_ISDIR(st.st_mode) and st.st_ino == os.stat(where).st_ino
            assert sorted(e.name for e in os.scandir(fd)) == sorted(os.listdir(where))
        finally:
            os.close(fd)


@pytest.mark.parametrize('path,want,expected', [
    (b'mid/in.txt', READ, errno.ELOOP),          # a symlink in the middle
    (b'last', READ, errno.ELOOP),                # the last segment a symlink, even to a file under the prefix
    (b'out', READ, errno.ELOOP),                 # an absolute symlink out of the prefix
    (b'up', READ, errno.ELOOP),                  # a relative symlink out of the prefix
    (b'../outside/secret', READ, errno.EXDEV),   # out of the prefix by ..
    (b'sub/../../outside/secret', READ, errno.EXDEV),
    (b'sub', READ, errno.EISDIR),                # read of a directory
    (b'fifo', READ, errno.EOPNOTSUPP),           # a FIFO with no writer: refused at once, never opened
    (b'sock', READ, errno.EOPNOTSUPP),           # a Unix socket
    (b'f.txt', LIST, errno.ENOTDIR),             # list of a file
    (b'fifo', LIST, errno.ENOTDIR),
    (b'nope', READ, errno.ENOENT),
    (b'f.txt/x', READ, errno.ENOTDIR),           # a file in the middle
    (b'mid', LIST, errno.ELOOP),
])
def test_what_the_open_refuses(native, tree, path: bytes, want: int, expected: int) -> None:
    base, anchor = tree
    fds = open_fds()
    started = time.monotonic()
    with pytest.raises(OSError) as e:
        native.open_beneath(anchor, path, want)
    assert e.value.errno == expected and time.monotonic() - started < 2
    assert open_fds() == fds


def test_an_absolute_path_is_refused(native, tree, tmp_path: Path) -> None:
    _, anchor = tree
    with pytest.raises(OSError) as e:
        native.open_beneath(anchor, str(tmp_path / 'outside' / 'secret').encode(), READ)
    assert e.value.errno == errno.EXDEV


def test_magic_links_are_refused(native, tmp_path: Path) -> None:
    """/proc/self/fd/N and /proc/self/cwd are magic links: with /proc/self as the anchor, neither resolves."""
    target = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    proc = os.open('/proc/self', O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for path, want in ((f'fd/{target}'.encode(), LIST), (b'cwd', LIST), (b'exe', READ)):
            with pytest.raises(OSError) as e:
                native.open_beneath(proc, path, want)
            assert e.value.errno == errno.ELOOP, path
    finally:
        os.close(proc)
        os.close(target)


def test_a_device_is_refused_without_being_opened(native) -> None:
    dev = os.open('/dev', O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in (b'null', b'zero', b'tty'):
            with pytest.raises(OSError) as e:
                native.open_beneath(dev, name, READ)
            assert e.value.errno == errno.EOPNOTSUPP, name
    finally:
        os.close(dev)


def test_bad_arguments(native, tree) -> None:
    _, anchor = tree
    for path, want in ((b'f.txt', 3), (b'f.txt', 0), (b'', READ)):
        with pytest.raises(OSError) as e:
            native.open_beneath(anchor, path, want)
        assert e.value.errno == errno.EINVAL
    with pytest.raises(ValueError):
        native.open_beneath(anchor, b'f.txt\x00../x', READ)            # never truncated at the NUL
    with pytest.raises(OSError):
        native.open_beneath(-1, b'f.txt', READ)
