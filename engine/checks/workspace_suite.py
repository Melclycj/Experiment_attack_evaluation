"""The workspace rework measured end to end on the gate's deployment (plan engine-v2-workspace-owner step 5; validation.md
A-07–A-10, A-12, D-17, K-55, S-24, N-21; agent-rm-model 6.2 工作区内容经导入、推进、导出进出).

run_gate.py --suite workspace deploys the 7.2 seed (bash, git), a git workspace work0 and a plain one work1, each with
its two transfer plans, plus the agent-side runtimes below: fixed bash -c scripts, one row each, that do in the cell
what an agent would (commit, tag, install hooks, build a bad object). What the gate's workload allowlist does not let a
cell do (mknodat for a FIFO; symlinks) the runner places in the storage itself, as the workspace owner: the client under
test sees the same file system either way. The runner reads workspace state as root without running git there (refs
are parsed from the files), and runs git in the user's repository as the user.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable

USER = 1000
AGENT_ENV = {'PATH': '/bin:/usr/bin', 'LANG': 'C.UTF-8', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
             'GIT_AUTHOR_NAME': 'agent', 'GIT_AUTHOR_EMAIL': 'agent@cell', 'GIT_COMMITTER_NAME': 'agent',
             'GIT_COMMITTER_EMAIL': 'agent@cell'}
HOOKS = ('reference-transaction', 'post-checkout', 'post-merge')
SCRIPTS = {
    # after the import: what the agent sees, then its own branch and tag, and hooks it points git at
    'ws-agent-work': ('work0', r'''set -u; cd /work; exec > /work/agent-work.txt 2>&1
git for-each-ref --format='%(refname)'
git checkout -q -b agent-feature && echo agent > agent.txt && git add agent.txt && git commit -q -m 'agent change'
git tag agent-tag
git notes add -m 'agent note' HEAD
dangling=$(git commit-tree "$(git rev-parse 'HEAD^{tree}')" -m dangling) && git replace "$dangling" HEAD
git config core.hooksPath .git/hooks
echo done'''),
    # S-24's discriminating check: the same fetch fires the agent's hook without core.hooksPath=/dev/null, not with it
    # (bash builtins and git only: the 7.2 seed has no coreutils)
    'ws-hook-probe': ('work0', r'''set -u; cd /work; exec > /work/hook-probe.txt 2>&1
: > /work/hook-log
git bundle create -q /tmp/probe.bundle --branches
git fetch -q --no-tags /tmp/probe.bundle '+refs/heads/*:refs/remotes/probe-a/*'
mapfile -t a < /work/hook-log; echo "without ${#a[@]}"
git -c core.hooksPath=/dev/null fetch -q --no-tags /tmp/probe.bundle '+refs/heads/*:refs/remotes/probe-b/*'
mapfile -t b < /work/hook-log; echo "with $(( ${#b[@]} - ${#a[@]} ))"
echo done'''),
    # a commit whose tree holds a .git entry: the user side's fsck must refuse it (A-08)
    'ws-agent-evil': ('work0', r'''set -u; cd /work; exec > /work/agent-evil.txt 2>&1
blob=$(printf 'evil\n' | git hash-object -w --stdin)
tree=$(printf '100644 blob %s\t.git\n' "$blob" | git mktree)
commit=$(git commit-tree "$tree" -m evil)
git update-ref refs/heads/evil "$commit" && echo "evil=$commit"'''),
    'ws-agent-clean': ('work0', 'set -u; cd /work; git update-ref -d refs/heads/evil > /work/agent-clean.txt 2>&1; echo done'),
}


def runtimes() -> list[tuple[str, list[str], dict[str, str], str]]:
    """(runtime, argv, env, workspace) for run_gate.deploy's extra runtimes; plan <runtime>-0."""
    return [(name, ['/runtime/bin/bash', '-c', script], AGENT_ENV, ws) for name, (ws, script) in SCRIPTS.items()]


def refs_of(git_dir: Path) -> dict[str, str]:
    """Every ref of a repository from its files (loose refs over packed ones) and HEAD, without running git there."""
    out: dict[str, str] = {}
    packed = git_dir / 'packed-refs'
    if packed.exists():
        for line in packed.read_text().splitlines():
            if line and line[0] not in '#^':
                sha, name = line.split(' ', 1)
                out[name] = sha
    for path in (git_dir / 'refs').rglob('*'):
        if path.is_file():
            out[path.relative_to(git_dir).as_posix()] = path.read_text().strip()
    out['HEAD'] = (git_dir / 'HEAD').read_text().strip()
    return out


def tree_digest(top: Path, skip: tuple[str, ...] = ('.git', '.engine')) -> dict[str, str]:
    out = {}
    for path in sorted(top.rglob('*')):
        rel = path.relative_to(top)
        if rel.parts[0] in skip or path.is_symlink() or not path.is_file():
            continue
        out[rel.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


class Suite:
    def __init__(self, root: Path, run: Path, label: str, command: Callable[..., dict[str, Any]], admin: list[Any],
                 python: list[str], engine: Path, owner: int, tree: str, evidence: Path) -> None:
        self.root, self.run_dir, self.label, self.command, self.admin = root, run, label, command, admin
        self.evidence = evidence
        self.python, self.engine, self.owner, self.tree_name = python, engine, owner, tree
        self.checks: dict[str, Any] = {}
        self.home = Path(tempfile.mkdtemp(prefix='engine-ws-user-', dir='/tmp'))
        os.chown(self.home, USER, USER)
        self.home.chmod(0o700)
        self.repo, self.plain_dir, self.out = self.home / "repo", self.home / "plain", self.home / "archives"

    def tree(self, ws: str) -> Path:
        return self.root / ws / self.tree_name

    def as_user(self, argv: list[Any], **kw: Any) -> dict[str, Any]:
        return self.command(['/usr/bin/setpriv', f'--reuid={USER}', f'--regid={USER}', '--init-groups',
                             '/usr/bin/env', f'HOME={self.home}', 'GIT_CONFIG_NOSYSTEM=1', *argv], **kw)

    def git_user(self, *args: str, allowed=(0,)) -> dict[str, Any]:
        return self.as_user(['/usr/bin/git', '-c', 'user.name=user', '-c', 'user.email=user@host', '-C', self.repo, *args],
                            allowed=allowed)

    def user_refs(self) -> dict[str, str]:
        listing = self.git_user('for-each-ref', '--format=%(refname) %(objectname)')['stdout']
        out = dict(line.split(' ', 1) for line in listing.splitlines())
        out['HEAD'] = self.git_user('symbolic-ref', 'HEAD')['stdout'].strip()
        return out

    def workspace(self, *args: str, allowed=(0, 1, 2)) -> dict[str, Any]:
        started = time.monotonic()
        done = self.command([*self.python, self.engine / 'bin/engine-workspace', '--root', self.root, *args,
                             '--as-user', str(USER)], timeout=300, allowed=allowed)
        done['seconds'] = round(time.monotonic() - started, 2)
        return done

    def row(self, plan: str, workspace: str) -> str:
        """Start one agent-side row and wait until every process of it is gone (its execution leaves ROW_LIST)."""
        started = self.command(self.admin + ['admin', 'row', 'start', workspace, plan])
        eid = re.search(r'execution=(\S+)', started['stdout']).group(1)
        until = time.monotonic() + 120
        while eid in self.command(self.admin + ['admin', 'row', 'list'])['stdout']:
            assert time.monotonic() < until, f'row {plan} did not end'
            time.sleep(0.5)
        return eid

    def plant(self, path: Path, make: Callable[[Path], None]) -> None:
        """What the gate's allowlist keeps the cell from doing, done in the storage as the workspace owner."""
        make(path)
        os.lchown(path, self.owner, self.owner)

    def check(self, name: str, ok: bool, **observed: Any) -> None:
        self.checks[name] = {'ok': bool(ok), **observed}

    # ---- the scenario ----
    def setup(self) -> None:
        self.as_user(['/usr/bin/git', 'init', '-q', '-b', 'main', self.repo])
        (self.repo / 'README').write_text('user readme\n')
        os.chown(self.repo / 'README', USER, USER)
        self.git_user('add', 'README')
        self.git_user('commit', '-q', '-m', 'user one')
        self.git_user('checkout', '-q', '-b', 'feature')
        self.git_user('commit', '-q', '--allow-empty', '-m', 'user feature')
        self.git_user('checkout', '-q', 'main')
        self.git_user('tag', 'v1')
        self.git_user('branch', 'private')                  # never named: must never reach the workspace (A-07)
        self.git_user('notes', 'add', '-m', 'user note', 'main')        # must stay as it is after export (A-08)
        # a plain directory with a setuid file, a FIFO, an outward symlink and a hard link to a file outside it
        self.as_user(['/usr/bin/python3', '-I', '-c', PLAIN_SOURCE, self.plain_dir, self.home / 'outside.txt'])
        self.as_user(['/usr/bin/mkdir', self.out])

    def git_import_push_export(self) -> None:
        tree0 = self.tree('work0')
        done = self.workspace('push', 'work0', '--repo', str(self.repo), '--branch', 'main', '--branch', 'feature')
        refs = refs_of(tree0 / '.git') if (tree0 / '.git').exists() else {}
        user = self.user_refs()
        inodes = {(os.stat(p).st_dev, os.stat(p).st_ino) for p in self.repo.rglob('*') if p.is_file()}
        shared = [str(p) for p in tree0.rglob('*') if p.is_file() and not p.is_symlink()
                  and (os.stat(p).st_dev, os.stat(p).st_ino) in inodes]
        self.check('A-12 git import: named branches only, no tags, checked out, no shared inode', done['exit_code'] == 0
                   and set(refs) == {'refs/remotes/user/main', 'refs/remotes/user/feature', 'refs/heads/main', 'HEAD'}
                   and refs['refs/remotes/user/main'] == user['refs/heads/main'] and refs['HEAD'] == 'ref: refs/heads/main'
                   and (tree0 / 'README').read_text() == 'user readme\n' and not shared
                   and (tree0 / '.engine/result').read_text().strip() == 'ok push',
                   refs=refs, shared=shared, stderr=done['stderr'][-400:])
        eid = self.row('ws-agent-work-0', 'work0')
        saw = (tree0 / 'agent-work.txt').read_text()
        # the hooks the agent pointed core.hooksPath at, executable (the allowlist has no fchmodat for chmod(1))
        for hook in HOOKS:
            self.plant(tree0 / '.git' / 'hooks' / hook,
                       lambda p, h=hook: (p.parent.mkdir(exist_ok=True), p.write_text(f'#!/bin/sh\necho {h} >> /work/hook-log\n'),
                                          p.chmod(0o755)))
        os.chown(tree0 / '.git' / 'hooks', self.owner, self.owner)
        self.check('A-07 the agent sees refs/remotes/user/*', 'refs/remotes/user/main' in saw and 'refs/remotes/user/feature'
                   in saw and 'done' in saw, execution=eid, saw=saw)
        before = self.user_refs()
        worktree = tree_digest(self.repo)
        (tree0 / 'hook-log').unlink(missing_ok=True)
        head = (self.git_user('symbolic-ref', 'HEAD')['stdout'], self.git_user('rev-parse', 'HEAD')['stdout'])
        done = self.workspace('export', 'work0', '--repo', str(self.repo))
        after = self.user_refs()
        head_after = (self.git_user('symbolic-ref', 'HEAD')['stdout'], self.git_user('rev-parse', 'HEAD')['stdout'])
        added = {k: v for k, v in after.items() if k not in before}
        workspace_refs = refs_of(tree0 / '.git')
        # A-10: what the export wrote into the user's repository belongs to the user (the fetch ran after the drop)
        not_users = [str(p) for p in (self.repo / '.git').rglob('*') if os.lstat(p).st_uid != USER]
        self.check('A-10 the export writes into the user repository as the user', done['exit_code'] == 0 and not not_users,
                   not_users=not_users[:10])
        self.check('A-08 export: agent branches under refs/remotes/agent-work0/*, nothing else moves, no agent tag',
                   done['exit_code'] == 0 and set(added) == {'refs/remotes/agent-work0/main',
                                                             'refs/remotes/agent-work0/agent-feature'}
                   and all(after[k] == v for k, v in before.items()) and 'refs/tags/agent-tag' not in after
                   and added['refs/remotes/agent-work0/agent-feature'] == workspace_refs['refs/heads/agent-feature']
                   and tree_digest(self.repo) == worktree and not (tree0 / 'hook-log').exists()
                   and not [p for p in Path('/tmp').glob('engine-export-*')] and head_after == head
                   and {'refs/notes/commits', 'refs/heads/private'} <= set(before)
                   and any(r.startswith('refs/notes/') for r in workspace_refs)        # the agent's note and replace
                   and any(r.startswith('refs/replace/') for r in workspace_refs),     # ref exist, and did not come
                   added=added, head=head, stderr=done['stderr'][-400:], seconds=done['seconds'],
                   agent_notes_and_replace=sorted(r for r in workspace_refs if r.startswith(('refs/notes/', 'refs/replace/'))))
        # the user moves on, and pushes main again: only refs/remotes/user/main moves in the workspace
        (self.repo / 'README').write_text('user readme two\n')
        self.git_user('commit', '-q', '-am', 'user two')
        before_ws = {k: v for k, v in refs_of(tree0 / '.git').items() if not k.startswith('refs/remotes/user/')}
        files = tree_digest(tree0)
        (tree0 / 'hook-log').unlink(missing_ok=True)
        done = self.workspace('push', 'work0', '--repo', str(self.repo), '--branch', 'main')
        refs = refs_of(tree0 / '.git')
        self.check('A-07 second push: refs/remotes/user/main moves, the rest of the workspace does not, no hook runs',
                   done['exit_code'] == 0 and refs['refs/remotes/user/main'] == self.user_refs()['refs/heads/main']
                   and {k: v for k, v in refs.items() if not k.startswith('refs/remotes/user/')} == before_ws
                   and {k for k in refs if k.startswith('refs/remotes/user/')} == {'refs/remotes/user/main',
                                                                       'refs/remotes/user/feature'}
                   and tree_digest(tree0) == files and not (tree0 / 'hook-log').exists(),
                   stderr=done['stderr'][-400:])
        self.row('ws-hook-probe-0', 'work0')
        probe = (tree0 / 'hook-probe.txt').read_text()
        self.check('S-24 discriminating: the fetch fires the agent hook without core.hooksPath=/dev/null, not with it',
                   re.search(r'^without [1-9]', probe, re.M) is not None and re.search(r'^with 0$', probe, re.M) is not None
                   and 'done' in probe, probe=probe)

    def bad_object(self) -> None:
        tree0 = self.tree('work0')
        self.row('ws-agent-evil-0', 'work0')
        evil = (tree0 / 'agent-evil.txt').read_text()
        before = self.user_refs()
        done = self.workspace('export', 'work0', '--repo', str(self.repo))
        self.check('A-08 a bundle with a .git tree entry is refused by the user side fsck; the repository is untouched',
                   'evil=' in evil and done['exit_code'] != 0 and self.user_refs() == before
                   and re.search(r'dotgit|\.git', done['stderr'], re.I) is not None,
                   evil=evil, stderr=done['stderr'][-600:])
        self.row('ws-agent-clean-0', 'work0')

    def planted(self) -> None:
        tree0, tree1 = self.tree('work0'), self.tree('work1')
        engine = tree0 / '.engine'
        target = tree1 / 'made'
        guard = tree_digest(tree1, skip=())

        def reset() -> None:
            subprocess.run(['/usr/bin/rm', '-rf', str(engine)], check=True)

        reset()
        self.plant(engine, lambda p: p.symlink_to(target))
        a = self.workspace('push', 'work0', '--repo', str(self.repo), '--branch', 'main')
        b = self.workspace('export', 'work0', '--repo', str(self.repo))
        reset()
        self.plant(engine, lambda p: p.mkdir(mode=0o700))
        self.plant(engine / 'incoming', lambda p: p.symlink_to(target))
        c = self.workspace('push', 'work0', '--repo', str(self.repo), '--branch', 'main')
        reset()
        self.plant(engine, lambda p: p.mkdir(mode=0o700))
        self.plant(engine / 'outgoing', lambda p: os.mkfifo(p))
        d = self.workspace('export', 'work0', '--repo', str(self.repo))
        self.check('A-10 a symlinked .engine or .engine/incoming, a FIFO for .engine/outgoing: refused at once, the other '
                   'workspace untouched', all(x['exit_code'] != 0 and x['seconds'] < 60 for x in (a, b, c, d))
                   and tree_digest(tree1, skip=()) == guard,
                   stderr=[x['stderr'][-200:] for x in (a, b, c, d)], seconds=[x['seconds'] for x in (a, b, c, d)])
        reset()
        precious = tree1 / 'made' / 'hello.txt'
        self.plant(engine, lambda p: p.mkdir(mode=0o700))
        self.plant(engine / 'result', lambda p: p.symlink_to(precious))
        e = self.workspace('push', 'work0', '--repo', str(self.repo), '--branch', 'main')
        self.check('A-10 a stale result planted as a symlink is removed, never followed', e['exit_code'] == 0
                   and precious.read_text() == 'hi\n' and not (engine / 'result').is_symlink(), stderr=e['stderr'][-300:])
        reset()

    def plain(self) -> None:
        tree1 = self.tree('work1')
        done = self.workspace('push', 'work1', '--dir', str(self.plain_dir))
        source = os.stat(self.home / 'outside.txt')
        linked = tree1 / 'linked.txt'
        self.check('A-12 plain import: the data filter keeps files, clears setuid, drops the FIFO and the outward link',
                   done['exit_code'] == 0 and (tree1 / 'a.txt').read_text() == 'a\n'
                   and os.stat(tree1 / 'tool.sh').st_mode & 0o7777 == 0o755 and not (tree1 / 'pipe').exists()
                   and not (tree1 / 'out').is_symlink() and linked.read_text() == 'outside\n'
                   and os.stat(linked).st_ino != source.st_ino, stderr=done['stderr'][-400:])
        # what an agent leaves in a plain workspace, placed as the owner (the 7.2 seed has no mkdir): nested
        # repositories, the transfers' directory name, a setuid file of its own, a FIFO, an outward symlink
        for d in ('made/sub', 'nested/.git', 'nested/inner/.GIT', '.engine'):
            for part in [Path(*Path(d).parts[:i + 1]) for i in range(len(Path(d).parts))]:
                if not (tree1 / part).exists():
                    self.plant(tree1 / part, lambda p: p.mkdir(mode=0o755))
        for name, body in (('made/hello.txt', 'hi\n'), ('nested/.git/config', 'cfg\n'), ('nested/inner/.GIT/HEAD', 'ref\n'),
                           ('.engine/junk', 'junk\n'), ('made/setuid.sh', '#!/bin/sh\n')):
            self.plant(tree1 / name, lambda p, b=body: p.write_text(b))
        (tree1 / 'made' / 'setuid.sh').chmod(0o4755)
        self.plant(tree1 / 'made' / 'pipe', lambda p: os.mkfifo(p))
        self.plant(tree1 / 'made' / 'link', lambda p: p.symlink_to('/etc/passwd'))
        done = self.workspace('export', 'work1', '--archive-to', str(self.out))
        archives = sorted(self.out.glob('work1-*.tar'))
        members: dict[str, Any] = {}
        if archives:
            with tarfile.open(archives[-1]) as tar:
                members = {m.name: (m.type, m.mode) for m in tar.getmembers()}
        bad = [n for n, (t, mode) in members.items() if t not in (tarfile.REGTYPE, tarfile.DIRTYPE) or mode & 0o7000
               or any(part.lower() == '.git' for part in n.split('/')) or n.split('/')[0] == '.engine']
        self.check('A-09 archive export: regular files and directories only, no .git at any level, no top .engine, no '
                   'setuid; the FIFO was not waited on', done['exit_code'] == 0 and len(archives) == 1 and members
                   and 'made/hello.txt' in members and 'made/setuid.sh' in members and not bad and done['seconds'] < 60
                   and os.stat(archives[-1]).st_uid == USER, members=sorted(members), bad=bad, seconds=done['seconds'])
        clash = self.workspace('push', 'work1', '--dir', str(self.plain_dir), '--into', 'made')
        self.check('A-07 a plain push into a directory that exists is refused', clash['exit_code'] != 0
                   and 'exists' in clash['stderr'], stderr=clash['stderr'][-200:])

    def hold(self) -> None:
        sys.path.insert(0, str(self.engine))
        from client.link import Link
        from connector import canonical as c
        link = Link(self.root / 'state' / 'admin.sock')
        try:
            held, reply = link.call(c.WS_HOLD, [b'work0'])
            other = self.command(self.admin + ['admin', 'row', 'start', 'work0', 'ws-agent-clean-0'], allowed=(0, 1))
            own, own_reply = link.call(c.ROW_START, [b'work0', b'ws-agent-clean-0', c.pack_list([]), b''])
            released, _ = link.call(c.WS_RELEASE, [b'work0'])
        finally:
            link.close()
        after = self.row('ws-agent-clean-0', 'work0')
        self.check('K-55 during a hold another connection starts nothing and the holder only transfers; release frees it',
                   held == c.OK and other['exit_code'] == 1 and 'busy' in other['stderr'] and own == c.ERR
                   and released == c.OK and bool(after), other=other['stderr'][-200:])

    def host_cannot_enter(self) -> None:
        probe = self.command(['/usr/bin/setpriv', f'--reuid={USER}', f'--regid={USER}', '--clear-groups', '/usr/bin/python3',
                              '-I', '-c', HOST_PROBE, self.root / 'work0', self.tree('work0')], allowed=(0,))
        tried = json.loads(probe['stdout'])
        self.check('D-17 in the deployment: the host user makes nothing in the workspace', all(e == 13 for e in tried.values()),
                   tried=tried)

    def wait_ready(self, seconds: float = 300) -> float:
        """The management port is up before the spawner has checked the seed; rows start only after control_ready,
        which the engine traces as control_received (gate start_row retries for the same reason)."""
        started, until = time.monotonic(), time.monotonic() + seconds
        while True:
            text = self.evidence.read_text() if self.evidence.exists() else ''
            if re.search(r'"control_received".*"type": ?"control_ready"', text):
                return round(time.monotonic() - started, 1)
            assert time.monotonic() < until, 'the spawner never reported control_ready'
            time.sleep(1)

    def run(self) -> dict[str, Any]:
        self.setup()
        self.checks['spawner ready'] = {'ok': True, 'waited_seconds': self.wait_ready()}
        for step in (self.git_import_push_export, self.bad_object, self.plain, self.planted, self.hold,
                     self.host_cannot_enter):
            try:
                step()
            except BaseException as error:          # noqa: BLE001 - one step's failure is a recorded check, not the end
                self.check(f'{step.__name__} ran', False, error=repr(error))
        return {'checks': self.checks, 'ok': all(c['ok'] for c in self.checks.values()) and len(self.checks) >= 15}


PLAIN_SOURCE = r'''
import os, sys
d, outside = sys.argv[1], sys.argv[2]
os.mkdir(d)
open(os.path.join(d, 'a.txt'), 'w').write('a\n')
open(os.path.join(d, 'tool.sh'), 'w').write('#!/bin/sh\n')
os.chmod(os.path.join(d, 'tool.sh'), 0o4755)
os.mkfifo(os.path.join(d, 'pipe'))
os.symlink('/etc/passwd', os.path.join(d, 'out'))
open(outside, 'w').write('outside\n')
os.link(outside, os.path.join(d, 'linked.txt'))
'''
HOST_PROBE = r'''
import json, os, socket, sys
out = {}
for d in sys.argv[1:]:
    for name, action in (('file', lambda: os.close(os.open(d + '/host-file', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))),
                         ('fifo', lambda: os.mkfifo(d + '/host-fifo')),
                         ('socket', lambda: socket.socket(socket.AF_UNIX).bind(d + '/host-sock'))):
        try:
            action()
            out[d + ' ' + name] = 0
        except OSError as error:
            out[d + ' ' + name] = error.errno
print(json.dumps(out))
'''
