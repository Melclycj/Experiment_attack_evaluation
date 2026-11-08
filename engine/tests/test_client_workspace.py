"""The management client's workspace side (validation.md A-09, A-10, A-12; agent-rm-model 6.2 工作区进出行): how it opens
paths in a workspace, what it takes, what an archive holds, how a directory push lands. Unprivileged: the test process
is the owner of a temporary workspace; the drops and the whole push and export run as root in the integration runs."""
from __future__ import annotations

import ctypes
import errno
import io
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import types

import pytest

from client import workspace as w
from connector import canonical as c

ENGINE = Path(__file__).resolve().parents[1]
PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER = 36, 37     # <linux/prctl.h>


def held(root: Path) -> w.Hold:
    st = os.stat(root)
    return w.Hold('work0', str(root), st.st_dev, st.st_ino, w.Ids(os.getuid(), os.getgid()))


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / 'work0'
    (root / w.TREE).mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    return root


def test_the_tree_is_reached_only_from_the_root_the_engine_holds(ws: Path, tmp_path: Path) -> None:
    """A-10: the root must be the held one (device, inode, owner); the subdirectory must be a plain directory."""
    hold = held(ws)
    tree = w.Tree(hold)
    assert os.fstat(tree.fd).st_ino == os.stat(ws / w.TREE).st_ino
    other = tmp_path / 'other'
    (other / w.TREE).mkdir(parents=True)
    with pytest.raises(w.Refused, match='not the one the engine holds'):
        w.Tree(w.Hold('work0', str(other), hold.device, hold.inode, hold.owner))
    with pytest.raises(w.Refused, match='not the one the engine holds'):
        w.Tree(w.Hold('work0', str(ws), hold.device, hold.inode, w.Ids(os.getuid() + 1, os.getgid())))
    (ws / w.TREE).rmdir()
    (ws / w.TREE).symlink_to(other / w.TREE)
    with pytest.raises(w.Refused, match='not a plain directory'):
        w.Tree(hold)


def test_directories_below_are_opened_one_component_at_a_time_never_through_a_symlink(ws: Path, tmp_path: Path) -> None:
    """A-10: the agent can plant a symlink or a FIFO where the client goes; each refuses, at once, and nothing outside
    the workspace is touched."""
    outside = tmp_path / 'elsewhere'
    outside.mkdir()
    tree = w.Tree(held(ws))
    (ws / w.TREE / w.ENGINE_DIR).symlink_to(outside)
    with pytest.raises(w.Refused, match='not a plain directory'):
        tree.dir(w.ENGINE_DIR, 'incoming', create=True)
    assert list(outside.iterdir()) == []
    (ws / w.TREE / w.ENGINE_DIR).unlink()
    (ws / w.TREE / w.ENGINE_DIR).mkdir()
    os.mkfifo(ws / w.TREE / w.ENGINE_DIR / 'incoming')
    started = time.monotonic()
    with pytest.raises(w.Refused, match='not a plain directory'):
        tree.dir(w.ENGINE_DIR, 'incoming', create=True)
    assert time.monotonic() - started < 1                     # a FIFO is never waited on
    os.unlink(ws / w.TREE / w.ENGINE_DIR / 'incoming')
    fd = tree.dir(w.ENGINE_DIR, 'incoming', create=True)
    assert stat.S_ISDIR(os.fstat(fd).st_mode)


def test_writes_are_exclusive_and_removal_never_follows(ws: Path, tmp_path: Path) -> None:
    """A-10: a name already there refuses a create; removing a planted symlink removes the link, not its target."""
    target = tmp_path / 'precious'
    target.write_text('keep')
    tree = w.Tree(held(ws))
    incoming = tree.dir(w.ENGINE_DIR, 'incoming', create=True)
    (ws / w.TREE / w.ENGINE_DIR / 'incoming' / 'push.bundle').symlink_to(target)
    with pytest.raises(w.Refused, match='exists'):
        w.create(incoming, 'push.bundle')
    w.remove(incoming, 'push.bundle')
    assert target.read_text() == 'keep' and not (ws / w.TREE / w.ENGINE_DIR / 'incoming' / 'push.bundle').is_symlink()
    os.close(w.create(incoming, 'push.bundle'))
    (ws / w.TREE / w.ENGINE_DIR / 'incoming' / 'sub').mkdir()
    with pytest.raises(w.Refused, match='is a directory'):
        w.remove(incoming, 'sub')


def test_a_single_file_is_taken_only_when_regular_and_within_the_limit(ws: Path, tmp_path: Path) -> None:
    """A-10, A-08: a FIFO (opened without waiting), a symlink, a directory or an oversized file is refused."""
    engine = w.Tree(held(ws)).dir(w.ENGINE_DIR, create=True)
    base = ws / w.TREE / w.ENGINE_DIR
    os.mkfifo(base / 'fifo')
    (base / 'link').symlink_to(tmp_path)
    (base / 'dir').mkdir()
    (base / 'big').write_bytes(b'x' * 11)
    (base / 'ok').write_bytes(b'x' * 10)
    for name in ('fifo', 'link', 'dir', 'big'):
        started = time.monotonic()
        with pytest.raises(w.Refused):
            w.open_regular(engine, name, 10)
        assert time.monotonic() - started < 1, name
    os.close(w.open_regular(engine, 'ok', 10))


def test_the_result_file_must_be_one_short_fixed_line(ws: Path) -> None:
    """A-10: the result is read only as 'ok <word>' or 'fail <word>'; anything longer or else is refused."""
    engine = w.Tree(held(ws)).dir(w.ENGINE_DIR, create=True)
    result = ws / w.TREE / w.ENGINE_DIR / 'result'
    result.write_text('ok push\n')
    assert w.result_line(engine) == 'ok push'
    for bad in ('ok push; rm -rf /\n', 'fine\n', '\x1b[2Jok push\n', 'ok ' + 'x' * 300 + '\n'):
        result.write_text(bad)
        with pytest.raises(w.Refused):
            w.result_line(engine)


def run_body(name: str, root: Path, stdin: bytes = b'', *args: str) -> subprocess.CompletedProcess:
    """One of the module's bodies in a fresh interpreter, with stdin and stdout as the pipes a real run would give it."""
    st = os.stat(root)
    code = ('import os, sys; from client import workspace as w; '
            f'h = w.Hold("work0", {str(root)!r}, {st.st_dev}, {st.st_ino}, w.Ids(os.getuid(), os.getgid())); '
            f'w.{name}(h, *sys.argv[1:])()')
    return subprocess.run([sys.executable, '-I', '-c', f'import sys; sys.path.insert(0, {str(ENGINE)!r}); ' + code, *args],
                          input=stdin, capture_output=True, timeout=30)


def test_an_archive_export_holds_regular_files_and_directories_only(ws: Path, tmp_path: Path) -> None:
    """A-09: no FIFO (never opened, the export does not hang), no symlink, no .git at any level whatever its case, no
    top-level .engine, no setuid, setgid or sticky bit, no owner ids."""
    tree = ws / w.TREE
    (tree / 'src').mkdir()
    (tree / 'src' / 'main.py').write_text('print(1)\n')
    (tree / 'src' / 'main.py').chmod(0o4755)
    (tree / 'shared').mkdir(mode=0o755)
    (tree / 'shared').chmod(0o3777)
    (tree / '.git').mkdir()
    (tree / '.git' / 'config').write_text('[core]\n')
    (tree / 'src' / '.GIT').mkdir()
    (tree / 'src' / '.GIT' / 'HEAD').write_text('ref')
    (tree / w.ENGINE_DIR).mkdir()
    (tree / w.ENGINE_DIR / 'result').write_text('ok push\n')
    (tree / 'src' / w.ENGINE_DIR).mkdir()                       # a nested one is the agent's content
    os.mkfifo(tree / 'pipe')
    (tree / 'out').symlink_to(tmp_path)
    done = run_body('pack', ws)
    assert done.returncode == 0, done.stderr
    with tarfile.open(fileobj=io.BytesIO(done.stdout), mode='r') as tar:
        members = {m.name: m for m in tar.getmembers()}
    assert set(members) == {'src', 'src/main.py', 'shared', 'src/.engine'}
    assert members['src/main.py'].mode == 0o755 and members['shared'].mode == 0o777
    assert all((m.uid, m.gid, m.uname, m.gname) == (0, 0, '', '') for m in members.values())


def tar_of(entries: list[tuple[str, bytes | None, int]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as tar:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if data is None:
                info.type = tarfile.FIFOTYPE
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_a_directory_push_lands_in_a_new_directory_through_the_data_filter(ws: Path) -> None:
    """A-07, A-12: into an empty workspace the import lands in the subdirectory itself; later pushes land in a new
    directory, refused if it exists; the data filter clears setuid and skips what it refuses (a FIFO, an escape)."""
    stream = tar_of([('a.txt', b'one', 0o4755), ('pipe', None, 0o644), ('../escape.txt', b'x', 0o644)])
    done = run_body('unpack', ws, stream, '')
    assert done.returncode == 0, done.stderr
    tree = ws / w.TREE
    assert (tree / 'a.txt').read_bytes() == b'one' and os.stat(tree / 'a.txt').st_mode & 0o7777 == 0o755
    assert not (tree / 'pipe').exists() and not (ws / 'escape.txt').exists()
    assert b'2 member(s) refused' in done.stderr
    done = run_body('unpack', ws, tar_of([('b.txt', b'two', 0o644)]), 'from-user-1')
    assert done.returncode == 0 and (tree / 'from-user-1' / 'b.txt').read_bytes() == b'two'
    done = run_body('unpack', ws, tar_of([('c.txt', b'three', 0o644)]), 'from-user-1')
    assert done.returncode != 0 and b'from-user-1 exists' in done.stderr


# ---- the hold covers the children's whole life (overall review 2026-11-03, #2; A-10, K-55) ----------------------------
def sleeper() -> int:
    pid = os.fork()
    if not pid:
        time.sleep(60)
        os._exit(0)
    return pid


def gone(pid: int) -> bool:
    """True when ``pid`` was already reaped (it did not outlive the call); else it is killed and reaped here."""
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    return False


def test_a_failure_while_waiting_kills_and_reaps_the_children_before_it_is_raised() -> None:
    """The hold ends with the management connection; a frame that does not read ends the parent's wait, and no child may
    go on touching the workspace after that."""
    near, far = socket.socketpair()
    far.sendall(b'x')                                                  # the port is readable

    def receive() -> None:
        raise c.Malformed('a frame that does not read')

    pid = sleeper()
    try:
        with pytest.raises(c.Malformed):
            w.wait(types.SimpleNamespace(sock=near, receive=receive), [pid])
    finally:
        near.close()
        far.close()
        assert gone(pid)


def test_a_second_fork_that_fails_leaves_no_first_child_behind(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[int] = []

    def fork(ids, body, stdin=None, stdout=None) -> int:
        if started:
            raise OSError(errno.EAGAIN, 'no more processes')
        started.append(sleeper())
        return started[0]

    monkeypatch.setattr(w, 'fork', fork)
    me = w.Ids(os.getuid(), os.getgid())
    with pytest.raises(OSError):
        w.run(None, (me, lambda: None, 'writing'), (me, lambda: None, 'reading'))
    assert gone(started[0])


def test_a_child_dies_with_the_client_that_started_it() -> None:
    """Even a client killed outright takes its children with it (PR_SET_PDEATHSIG, set after the drop, with the parent
    checked again so that a parent already gone is not missed). The test process is a subreaper meanwhile, so the
    orphaned child comes back to it and is reaped here, not by whichever process above is the subreaper."""
    libc = ctypes.CDLL(None, use_errno=True)
    was = ctypes.c_int(0)
    assert libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(was), 0, 0, 0) == 0
    assert libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    r, wr = os.pipe()
    client = child = None
    try:
        client = os.fork()
        if not client:                                                 # stands for the root client
            os.close(r)
            if not os.fork():
                w.die_with_parent(os.getppid())
                os.write(wr, b'%d\n' % os.getpid())
                time.sleep(60)
                os._exit(0)
            os.close(wr)
            time.sleep(60)
            os._exit(0)
        os.close(wr)
        wr = None
        ready, _, _ = select.select([r], [], [], 10)
        assert ready, 'the child never reported'
        child = int(os.read(r, 32))
        os.kill(client, signal.SIGKILL)
        os.waitpid(client, 0)
        client = None
        ready, _, _ = select.select([r], [], [], 10)
        assert ready and os.read(r, 1) == b''                          # the child's end closed: it is gone
        _, status = os.waitpid(child, 0)
        child = None
        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    finally:
        for pid in (client, child):                                    # a failure leaves nothing running behind
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except (ProcessLookupError, ChildProcessError):
                    pass
        os.close(r)
        if wr is not None:
            os.close(wr)
        libc.prctl(PR_SET_CHILD_SUBREAPER, was.value, 0, 0, 0)


@pytest.mark.parametrize('uid, gid', [(0, 70997), (70997, 0), (4242, 70997), (70997, 4242)])
def test_a_hold_naming_root_or_the_initiating_user_as_owner_is_refused(uid: int, gid: int) -> None:
    """The children drop to the owner the core names; root is never that owner (the catalog refuses it), nor is the
    initiating user (S-22). A reply naming either is refused before anything runs as it (overall review, #15)."""
    reply = c.pack_list([b'/srv/w', b'1', b'2', str(uid).encode(), str(gid).encode()])
    link = types.SimpleNamespace(call=lambda kind, fields: (c.OK, [c.u8(c.WS_HOLD), reply]))
    with pytest.raises(w.Refused):
        w.hold(link, 'work0', w.Ids(4242, 4242))
