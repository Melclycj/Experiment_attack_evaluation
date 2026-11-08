"""Workspace transfers: import, push and export (agent-rm-model 3.1 行的标识, 6.2 工作区内容经导入、推进、导出进出;
validation.md A-07–A-10, A-12, K-55, S-24).

Run as root, through its own entry bin/engine-workspace, which loads only this module and client/link.py of the client
(the part that is TCB; README TCB 模块清单, K-41). The root process holds the management connection, and with it the workspace's hold (K-55), and moves bytes
between pipes; it opens no path in the workspace or on the user's side. Two kinds of child process do that, each dropped
for good before it touches anything (real, effective and saved uid and gid, and the supplementary groups):

- as the workspace owner (the hold's OK names it): open the workspace root the hold names, check its device, inode and
  owner, open the fixed subdirectory beneath it, and below that go one component at a time, never following a symlink;
  create files exclusively; take a single file only when fstat says regular, the whole tree only as regular files and
  directories;
- as the initiating user (SUDO_UID, or --as-user): everything on the user's side, both git fetches of an agent bundle
  included (git's own parser is declared out of scope, N-20).

Git work inside the workspace repository runs as a transfer execution in a cell (S-24): the client puts one bundle file
in or takes one out, and reads the result file once every process of the transfer row is gone. If the management
connection closes, the hold is gone with it and the client stops at once.
"""
from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import datetime
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Callable

from connector import canonical as c
from .link import ERR_NAMES, Link

TREE = 'tree'                       # the fixed subdirectory a cell mounts (native/sandbox/catalog.h W2_WORKSPACE_TREE)
ENGINE_DIR = '.engine'              # the transfers' own directory in the subdirectory, left out of an archive export
BUNDLE_MAX = 1 << 30                # one bundle in or out (A-08); a larger one is refused, not cut
ARCHIVE_MAX = 1 << 30               # one tar stream in or out (A-09, A-12)
RESULT_MAX = 256                    # the transfer row's result file
TRANSFER_TIMEOUT_S, STOP_GRACE_S, POLL_S = 300.0, 60.0, 0.2
RESULT = re.compile(r'(ok|fail) [a-z-]+')
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
PR_SET_PDEATHSIG = 1                # <linux/prctl.h>


class Refused(Exception):
    """The operation stops; the message says why and names no secret."""


@dataclass(frozen=True)
class Ids:
    uid: int
    gid: int
    groups: tuple[int, ...] = ()
    home: str = '/'


@dataclass(frozen=True)
class Hold:
    """What WS_HOLD's OK says about the held workspace (SPEC §3.4)."""
    workspace: str
    root: str
    device: int
    inode: int
    owner: Ids


def transfer_plan(workspace: str, kind: str) -> str:
    """The deployment names each workspace's two transfer plans this way (deployment.md 第 5 节)."""
    return f'{workspace}.{kind}'


# ---- identities and children ----
def initiating_user(name: str | None) -> Ids:
    if name is None:
        uid = os.environ.get('SUDO_UID')
        if not uid:
            raise Refused('run under sudo, or name the user with --as-user')
        entry = pwd.getpwuid(int(uid))
    else:
        entry = pwd.getpwuid(int(name)) if name.isdigit() else pwd.getpwnam(name)
    if entry.pw_uid == 0:
        raise Refused('the initiating user cannot be root')
    return Ids(entry.pw_uid, entry.pw_gid, tuple(os.getgrouplist(entry.pw_name, entry.pw_gid)), entry.pw_dir)


def drop(ids: Ids) -> None:
    """For good: groups, then the three gids, then the three uids; checked afterwards (A-10)."""
    os.setgroups(list(ids.groups))
    os.setresgid(ids.gid, ids.gid, ids.gid)
    os.setresuid(ids.uid, ids.uid, ids.uid)
    if os.getresuid() != (ids.uid,) * 3 or os.getresgid() != (ids.gid,) * 3 or set(os.getgroups()) != set(ids.groups):
        raise Refused('could not drop privileges')
    os.umask(0o077)


def die_with_parent(parent: int) -> None:
    """The child dies with the client, even a client killed outright, so it never outlives the hold (A-10). Set after the
    drop, since a change of uid or gid clears it (prctl(2)); the parent is checked afterwards in case it was gone before."""
    if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise Refused('could not tie the child to the client')
    if os.getppid() != parent:
        raise Refused('the client is gone')


def fork(ids: Ids, body: Callable[[], None], stdin: int | None = None, stdout: int | None = None) -> int:
    """``body`` in a child dropped to ``ids``, with only stdio open (the pipes, when given, as 0 and 1)."""
    parent = os.getpid()
    pid = os.fork()
    if pid:
        return pid
    code = 70
    try:
        if stdin is not None:
            os.dup2(stdin, 0)
        if stdout is not None:
            os.dup2(stdout, 1)
        for name in os.listdir('/proc/self/fd'):
            if int(name) > 2:
                try:
                    os.close(int(name))
                except OSError:
                    pass
        drop(ids)
        die_with_parent(parent)
        body()
        code = 0
    except Refused as e:
        os.write(2, f'workspace: {e}\n'.encode())
        code = 1
    except BaseException as e:      # noqa: BLE001 - a child reports and exits, it never returns into the parent's code
        os.write(2, f'workspace: {type(e).__name__}: {e}\n'.encode())
    finally:
        os._exit(code)


def wait(link: Link, pids: list[int]) -> list[int]:
    """Exit codes in order. If the management connection closes or fails meanwhile, the hold is gone: the children are
    killed and reaped before anything is raised (A-10)."""
    codes: dict[int, int] = {}
    sel = selectors.DefaultSelector()
    sel.register(link.sock, selectors.EVENT_READ)
    try:
        while len(codes) < len(pids):
            for pid in pids:
                if pid not in codes:
                    done, status = os.waitpid(pid, os.WNOHANG)
                    if done:
                        codes[pid] = os.waitstatus_to_exitcode(status)
            if len(codes) < len(pids) and sel.select(POLL_S) and not drained(link):
                raise Refused('the management connection closed, and the hold with it; stopped')
    except BaseException:
        stop([pid for pid in pids if pid not in codes])
        raise
    finally:
        sel.close()
    return [codes[p] for p in pids]


def stop(pids: list[int]) -> None:
    """Kill and reap: a child of the client never outlives the hold."""
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass


def drained(link: Link) -> bool:
    """Read what the core sent (questions belong to ``admin questions``); False when the core closed the port."""
    frames = link.receive()
    if frames is None:
        return False
    for _, _, fd in frames:
        if fd is not None:
            os.close(fd)
    return True


def run(link: Link, *steps: tuple[Ids, Callable[[], None], str]) -> None:
    """Two children joined by a pipe (writer first, reader second), or one child alone; each must exit 0."""
    if len(steps) == 1:
        pids = [fork(steps[0][0], steps[0][1])]
    else:
        r, w = os.pipe2(os.O_CLOEXEC)
        pids = []
        try:
            pids.append(fork(steps[0][0], steps[0][1], stdout=w))
            pids.append(fork(steps[1][0], steps[1][1], stdin=r))
        except BaseException:
            stop(pids)                                     # the second did not start: the first goes too
            raise
        finally:
            os.close(r)
            os.close(w)
    for (_, _, what), code in zip(steps, wait(link, pids)):
        if code:
            raise Refused(f'{what} failed')


# ---- byte moves ----
def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def copy(src: int, dst: int, limit: int) -> int:
    total = 0
    while chunk := os.read(src, 1 << 20):
        total += len(chunk)
        if total > limit:
            raise Refused(f'more than {limit} bytes')
        write_all(dst, chunk)
    return total


# ---- the workspace side, as the owner (A-10) ----
def check_name(name: str) -> str:
    if not name or name in ('.', '..') or '/' in name or '\0' in name:
        raise Refused(f'not a single path component: {name!r}')
    return name


class Tree:
    """The workspace's fixed subdirectory, reached from the root the engine holds, checked by device, inode and owner."""

    def __init__(self, hold: Hold) -> None:
        try:
            root = os.open(hold.root, DIR_FLAGS)
        except OSError as e:
            raise Refused(f'cannot open the workspace root: {e.strerror}') from None
        try:
            st = os.fstat(root)
            if (st.st_dev, st.st_ino, st.st_uid) != (hold.device, hold.inode, hold.owner.uid):
                raise Refused('the workspace root is not the one the engine holds')
            try:
                self.fd = os.open(TREE, DIR_FLAGS, dir_fd=root)
            except OSError as e:
                raise Refused(f'the workspace subdirectory is not a plain directory ({e.strerror})') from None
        finally:
            os.close(root)

    def dir(self, *names: str, create: bool = False) -> int:
        """A directory below the subdirectory, one component at a time; a symlink or a non-directory anywhere refuses."""
        fd = os.dup(self.fd)
        for name in names:
            if create:
                try:
                    os.mkdir(check_name(name), 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            try:
                fd, old = os.open(check_name(name), DIR_FLAGS, dir_fd=fd), fd
            except OSError as e:
                raise Refused(f'{"/".join(names)} is not a plain directory ({e.strerror})') from None
            os.close(old)
        return fd


def remove(dir_fd: int, name: str) -> None:
    """Unlink whatever an earlier transfer or the agent left under this name; unlink never follows a symlink."""
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    except IsADirectoryError:
        raise Refused(f'{name} is a directory') from None


def create(dir_fd: int, name: str) -> int:
    try:
        return os.open(name, CREATE_FLAGS, 0o600, dir_fd=dir_fd)
    except FileExistsError:
        raise Refused(f'{name} exists') from None


def open_regular(dir_fd: int, name: str, limit: int) -> int:
    """A single file is taken only when fstat says regular and it fits the limit; a FIFO is opened non-blocking."""
    try:
        fd = os.open(name, READ_FLAGS, dir_fd=dir_fd)
    except OSError as e:
        raise Refused(f'{name}: {e.strerror}') from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        os.close(fd)
        raise Refused(f'{name} is not a regular file of at most {limit} bytes')
    return fd


def result_line(engine_dir: int) -> str:
    fd = open_regular(engine_dir, 'result', RESULT_MAX)
    try:
        data = os.read(fd, RESULT_MAX + 1)
    finally:
        os.close(fd)
    line = data.decode('ascii', 'replace').strip()
    if not RESULT.fullmatch(line):
        raise Refused('the transfer result does not read')
    return line


def prepare(hold: Hold, area: str, stale: tuple[str, ...]) -> Callable[[], None]:
    """Before a transfer row: the transfer directories exist, and the stale result and files are gone."""
    def body() -> None:
        tree = Tree(hold)
        engine, sub = tree.dir(ENGINE_DIR, create=True), tree.dir(ENGINE_DIR, area, create=True)
        remove(engine, 'result')
        for name in stale:
            remove(sub, name)
    return body


def put_push(hold: Hold, head: str) -> Callable[[], None]:
    """The user's bundle from stdin into .engine/incoming, created exclusively; the branch the first push checks out."""
    def body() -> None:
        incoming = Tree(hold).dir(ENGINE_DIR, 'incoming')
        fd = create(incoming, 'push.bundle')
        copy(0, fd, BUNDLE_MAX)
        os.fsync(fd)
        os.close(fd)
        fd = create(incoming, 'push.head')
        write_all(fd, head.encode())
        os.close(fd)
    return body


def check_result(hold: Hold, expected: str) -> Callable[[], None]:
    def body() -> None:
        line = result_line(Tree(hold).dir(ENGINE_DIR))
        sys.stderr.write(f'transfer: {line}\n')
        if line != expected:
            raise Refused(f'the transfer reported {line}')
    return body


def take_export(hold: Hold) -> Callable[[], None]:
    """The agent's bundle to stdout, once the transfer reported ok; then it is removed from the workspace."""
    def body() -> None:
        tree = Tree(hold)
        if result_line(tree.dir(ENGINE_DIR)) != 'ok export':
            raise Refused('the export transfer did not report ok')
        outgoing = tree.dir(ENGINE_DIR, 'outgoing')
        fd = open_regular(outgoing, 'export.bundle', BUNDLE_MAX)
        try:
            copy(fd, 1, BUNDLE_MAX)
        finally:
            os.close(fd)
        remove(outgoing, 'export.bundle')
    return body


def unpack(hold: Hold, into: str | None) -> Callable[[], None]:
    """A tar stream from stdin, extracted with tarfile's data filter: into the subdirectory itself when it holds nothing
    but .engine (the import, A-12), else into a new directory created here (A-07). Members the filter refuses are
    skipped and counted."""
    def body() -> None:
        tree = Tree(hold)
        present = set(os.listdir(tree.fd)) - {ENGINE_DIR}
        if present or into:
            name = check_name(into or 'from-user-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
            if name == ENGINE_DIR:
                raise Refused(f'{ENGINE_DIR} is the transfers\' own directory')
            try:
                os.mkdir(name, 0o700, dir_fd=tree.fd)
            except FileExistsError:
                raise Refused(f'{name} exists') from None
            target = tree.dir(name)
        else:
            target, name = tree.fd, '.'
        os.fchdir(target)
        skipped = 0
        with os.fdopen(0, 'rb', closefd=False) as stream, tarfile.open(fileobj=Limited(stream, ARCHIVE_MAX),
                                                                       mode='r|') as tar:
            for member in tar:
                try:
                    tar.extract(member, '.', filter='data')
                except tarfile.FilterError:
                    skipped += 1
        sys.stderr.write(f'pushed into {name}; {skipped} member(s) refused by the data filter\n')
    return body


def pack(hold: Hold) -> Callable[[], None]:
    """The whole subdirectory to stdout as a tar stream: regular files and directories only, never following a symlink;
    no .git at any level (case ignored), no top-level .engine, setuid, setgid and sticky bits cleared, owners blank
    (A-09). A FIFO is never opened: its type is known from lstat before any open."""
    def body() -> None:
        with os.fdopen(1, 'wb', closefd=False) as stream, tarfile.open(fileobj=Limited(stream, ARCHIVE_MAX), mode='w|',
                                                                        format=tarfile.PAX_FORMAT) as tar:
            walk(tar, Tree(hold).fd, '', top=True)
    return body


def walk(tar: tarfile.TarFile, dir_fd: int, prefix: str, top: bool) -> None:
    for name in sorted(os.listdir(dir_fd)):
        if name.lower() == '.git' or (top and name == ENGINE_DIR):
            continue
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        path = prefix + name
        if stat.S_ISDIR(st.st_mode):
            sub = os.open(name, DIR_FLAGS, dir_fd=dir_fd)
            try:
                info = tarfile.TarInfo(path)
                info.type, info.mode, info.mtime = tarfile.DIRTYPE, st.st_mode & 0o777, int(st.st_mtime)
                tar.addfile(info)
                walk(tar, sub, path + '/', top=False)
            finally:
                os.close(sub)
        elif stat.S_ISREG(st.st_mode):
            fd = os.open(name, READ_FLAGS, dir_fd=dir_fd)
            with os.fdopen(fd, 'rb') as f:
                now = os.fstat(fd)
                if not stat.S_ISREG(now.st_mode) or (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
                    continue
                info = tarfile.TarInfo(path)
                info.size, info.mode, info.mtime = now.st_size, now.st_mode & 0o777, int(now.st_mtime)
                tar.addfile(info, f)


class Limited:
    """A file object that refuses to pass more than ``limit`` bytes either way."""

    def __init__(self, f, limit: int) -> None:
        self.f, self.limit, self.count = f, limit, 0

    def _count(self, n: int) -> None:
        self.count += n
        if self.count > self.limit:
            raise Refused(f'more than {self.limit} bytes')

    def read(self, n: int = -1) -> bytes:
        data = self.f.read(n)
        self._count(len(data))
        return data

    def write(self, data: bytes) -> int:
        self._count(len(data))
        return self.f.write(data)

    def flush(self) -> None:
        self.f.flush()


# ---- the user's side, as the initiating user ----
def git(user: Ids, *args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
    env = {'PATH': '/usr/bin:/bin', 'HOME': user.home, 'LANG': 'C.UTF-8', 'GIT_TERMINAL_PROMPT': '0'}
    return subprocess.run(['git', *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          check=False)     # stdin is the pipe this child reads; git never gets it


def must(result: subprocess.CompletedProcess, what: str) -> None:
    if result.returncode:
        raise Refused(f'{what}: {result.stderr.strip()[:300]}')


def make_bundle(user: Ids, repo: str, branches: list[str]) -> Callable[[], None]:
    """Only the branches the user named, as refs/heads/*, from the user's own repository, to stdout."""
    def body() -> None:
        for branch in branches:
            must(git(user, 'check-ref-format', '--branch', branch), f'{branch} is not a branch name')
            must(git(user, '-C', repo, 'rev-parse', '--verify', '--quiet', f'refs/heads/{branch}'),
                 f'{branch} is not a local branch of {repo}')
        tmp = tempfile.mkdtemp(prefix='engine-push-')
        try:
            path = os.path.join(tmp, 'push.bundle')
            must(git(user, '-C', repo, 'bundle', 'create', '-q', path, *[f'refs/heads/{b}' for b in branches]),
                 'git bundle create')
            fd = os.open(path, READ_FLAGS)
            try:
                copy(fd, 1, BUNDLE_MAX)
            finally:
                os.close(fd)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return body


def fetch_export(user: Ids, repo: str, workspace: str) -> Callable[[], None]:
    """The agent's bundle from stdin into a new temporary repository, then from there, with fsck, into the user's
    refs/remotes/agent-<workspace>/*: no tags, no submodule recursion, only these refspecs (A-08)."""
    def body() -> None:
        must(git(user, 'check-ref-format', f'refs/remotes/agent-{workspace}/x'), f'agent-{workspace} is not a ref name')
        must(git(user, '-C', repo, 'rev-parse', '--git-dir'), f'{repo} is not a git repository')
        tmp = tempfile.mkdtemp(prefix='engine-export-')
        try:
            path = os.path.join(tmp, 'export.bundle')
            fd = os.open(path, CREATE_FLAGS, 0o600)
            try:
                received = copy(0, fd, BUNDLE_MAX)
            finally:
                os.close(fd)
            if not received:                     # the workspace side refused to hand a bundle out; it says why
                raise Refused('no bundle came out of the workspace')
            staging = os.path.join(tmp, 'staging.git')
            must(git(user, 'init', '--bare', '-q', staging), 'git init')
            must(git(user, '-C', staging, 'fetch', '-q', '--no-tags', '--no-recurse-submodules', path,
                     '+refs/heads/*:refs/heads/*'), 'fetch into the temporary repository')
            must(git(user, '-C', repo, '-c', 'transfer.fsckObjects=true', 'fetch', '-q', '--no-tags',
                     '--no-recurse-submodules', staging, f'+refs/heads/*:refs/remotes/agent-{workspace}/*'),
                 'fetch into the repository (with fsck)')
            sys.stderr.write(f'exported into refs/remotes/agent-{workspace}/* of {repo}\n')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return body


def make_tar(directory: str) -> Callable[[], None]:
    def body() -> None:
        with os.fdopen(1, 'wb', closefd=False) as stream, tarfile.open(fileobj=Limited(stream, ARCHIVE_MAX), mode='w|',
                                                                        format=tarfile.PAX_FORMAT) as tar:
            tar.add(directory, arcname='.')
    return body


def write_archive(out_dir: str, workspace: str) -> Callable[[], None]:
    def body() -> None:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        out = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)    # the user's own directory
        try:
            name = check_name(f'{workspace}-{stamp}.tar')
            fd = create(out, name)
            try:
                copy(0, fd, ARCHIVE_MAX)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(out)
        sys.stderr.write(f'archive: {os.path.join(out_dir, name)}\n')
    return body


# ---- the management port, as root ----
def call(link: Link, kind: int, fields: list[bytes]) -> list[bytes]:
    got, reply = link.call(kind, fields)
    if got != c.OK:
        code = c.read_uint(reply[1], 1)
        raise Refused(f'refused ({ERR_NAMES.get(code, code)}): {reply[2].decode("utf-8", "replace")}')
    return c.unpack_list(reply[1])


def hold(link: Link, workspace: str, user: Ids | None = None) -> Hold:
    """The children drop to the owner the core names; that is never root (the catalog refuses it) nor the initiating user
    (S-22), and a reply naming either is refused before anything runs as it."""
    root, device, inode, uid, gid = call(link, c.WS_HOLD, [workspace.encode()])
    owner = Ids(int(uid), int(gid))
    if 0 in (owner.uid, owner.gid) or user is not None and (owner.uid == user.uid or owner.gid == user.gid):
        raise Refused(f'the core named {owner.uid}:{owner.gid} as the workspace owner')
    return Hold(workspace, root.decode(), int(device), int(inode), owner)


def transfer(link: Link, h: Hold, kind: str, timeout: float) -> None:
    """Start the workspace's transfer plan under the hold and wait until every process of that row is gone (A-10): the
    row is out of ROW_LIST only once it is closed, its domain empty and its workspace released."""
    hold(link, h.workspace)                                              # still ours: the connection is alive
    [eid] = call(link, c.ROW_START, [h.workspace.encode(), transfer_plan(h.workspace, kind).encode(), c.pack_list([]), b''])
    deadline, stopped = time.monotonic() + timeout, False
    while eid in call(link, c.ROW_LIST, [])[0::4]:
        if time.monotonic() > deadline:
            if stopped:
                raise Refused(f'the {kind} row {eid.decode()} did not end')
            call(link, c.ROW_STOP, [eid])
            deadline, stopped = time.monotonic() + STOP_GRACE_S, True
        time.sleep(POLL_S)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog='engine-workspace', description='import, push and export a workspace (run as '
                                                                          'root, bin/engine-workspace)')
    parser.add_argument('--root', required=True, help='deployment root: <root>/state/admin.sock')
    actions = parser.add_subparsers(dest='action', required=True)
    push = actions.add_parser('push', help="the user's branches, or a directory, into the workspace; "
                                           'into an empty workspace this is the import')
    push.add_argument('workspace')
    push.add_argument('--repo', help="the user's git repository")
    push.add_argument('--branch', action='append', default=[], help='repeatable: a local branch to push')
    push.add_argument('--dir', help='a plain directory to push (non-git workspaces)')
    push.add_argument('--into', help='the new directory a directory push goes into (default from-user-<time>)')
    export = actions.add_parser('export', help="the agent's branches into refs/remotes/agent-<workspace>/*, "
                                               'or the whole tree as an archive file')
    export.add_argument('workspace')
    export.add_argument('--repo', help="the user's git repository to fetch into")
    export.add_argument('--archive-to', help='a directory for the archive file (non-git workspaces)')
    for q in (push, export):
        q.add_argument('--as-user', help='the initiating user (default: the user sudo names)')
        q.add_argument('--timeout', type=float, default=TRANSFER_TIMEOUT_S, help='seconds a transfer row may run')
    return run_command(parser.parse_args(argv))


def run_command(args) -> int:
    if os.geteuid() != 0:
        print('workspace: run as root (sudo), so the client can drop to the workspace owner', file=sys.stderr)
        return 2
    try:
        user = initiating_user(args.as_user)
        git_mode = bool(args.repo)
        if args.action == 'push' and git_mode == bool(args.dir) or args.action == 'export' and git_mode == bool(args.archive_to):
            raise Refused('give exactly one of --repo and --dir (push) or --repo and --archive-to (export)')
        if args.action == 'push' and git_mode and not args.branch:
            raise Refused('name at least one --branch')
        link = Link(Path(args.root) / 'state' / 'admin.sock')
    except (Refused, KeyError, OSError) as e:
        print(f'workspace: {e}', file=sys.stderr)
        return 2
    try:
        h = hold(link, args.workspace, user)
        if args.action == 'push' and git_mode:
            run(link, (h.owner, prepare(h, 'incoming', ('push.bundle', 'push.head')), 'preparing the workspace'))
            run(link, (user, make_bundle(user, args.repo, args.branch), 'bundling the branches'),
                (h.owner, put_push(h, args.branch[0]), 'writing the bundle into the workspace'))
            transfer(link, h, 'push', args.timeout)
            run(link, (h.owner, check_result(h, 'ok push'), 'the push'))
        elif args.action == 'push':
            run(link, (user, make_tar(args.dir), 'packing the directory'), (h.owner, unpack(h, args.into), 'unpacking'))
        elif git_mode:
            run(link, (h.owner, prepare(h, 'outgoing', ('export.bundle',)), 'preparing the workspace'))
            transfer(link, h, 'export', args.timeout)
            run(link, (h.owner, take_export(h), 'taking the bundle out'),
                (user, fetch_export(user, args.repo, args.workspace), 'fetching'))
        else:
            run(link, (h.owner, pack(h), 'packing the workspace'),
                (user, write_archive(args.archive_to, args.workspace), 'writing the archive'))
        call(link, c.WS_RELEASE, [args.workspace.encode()])
        return 0
    except (Refused, ConnectionError, c.Malformed) as e:
        print(f'workspace: {e}', file=sys.stderr)
        return 1
    finally:
        link.close()
