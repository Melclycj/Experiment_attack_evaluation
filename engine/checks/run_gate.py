"""Block 7 gate (build plan 7.1, 7.2): a real deployment driven only through the admin client.

The production engine (bin/engine) runs under w2-cell with the real connector; the runtime seed holds a real agent
(Claude Code, a single native binary), bash, the in-cell frontend (--frontend go, the default: the static binary built
from frontend-go/; --frontend python: Python 3.12 + mitmproxy from the frontend venv) and the pty relay. The runner then
does what a user does: registers the credential record and the destination entry over the management port, starts a
row, answers any question with deny-once, and watches the agent through the attach window (its asciinema record is
the evidence that the response streamed). Nothing is called in-process.

Suite 7.1 runs Claude Code once from a fixed script; suite 7.2 starts one execution per adaptation item (gate_items.py)
of an interactive shell runtime and types each item's command at its prompt through the attach window. Suite derive
does the same with the derivation set (derive_cell.py), one shell runtime per agent, on the experiment seed (--seed
experiment: all three agents and the work tools, gate_seed.py), which the other two suites can also take. Suite files
runs Claude Code once as 7.1 does, its MCP configuration the cell's MCP server, on a host directory registered over the
management port: one read of a registered file, three ways out of the prefix (file_suite.py; validation.md H-25).

Run as root inside a private mount namespace (the truth is read from ExperimentLab/.env and goes only to the admin
client's environment):
  unshare --mount --propagation private python3 checks/run_gate.py --run-dir runs/<dir> --label <l> [--suite 7.2]
      [--seed experiment] [--suite derive [--agents claude,pi,opencode]] [--frontend python] [--runtime-mode copy]
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pty
import pwd
import re
import secrets
import select
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import termios
import threading
import time
import traceback
from typing import Any, Callable

ENGINE = Path(__file__).resolve().parents[1]
NATIVE = ENGINE / 'native'
REPO = ENGINE.parents[1]
sys.path.insert(0, str(NATIVE / 'checks'))
sys.path.insert(0, str(ENGINE / 'checks'))
from run_engine_checks import AS_USER, PYTHON, SPAWNER_CAPS, record_access  # noqa: E402
from run_sandbox_checks import OWNER_ID, TREE, WORKER_ID, digest, save_json  # noqa: E402
import file_suite  # noqa: E402
import transfer_runtimes  # noqa: E402
import workspace_suite  # noqa: E402
from gate_items import (GH_PLACEHOLDER, GIT_PLACEHOLDER, GITHUB_USER, ITEM_EXIT, ITEMS,  # noqa: E402
                        NPM_PLACEHOLDER)
from gate_seed import (FRONTEND_ARGV, FRONTENDS, MCP_ARGV, VENV, WORKLOAD_ALLOW, build_seed, go_build,  # noqa: E402
                       mcp_build, preflight)

DOTENV = REPO / 'ExperimentLab/.env'
HOST, ACCOUNT = 'api.anthropic.com:443', 'gate'
PDP_ID = 70998          # the PDP uid and gid (D-13): no host account, outside the reserved range
PLACEHOLDER = 'sk-ant-api03-w2gate-placeholder-000000000000000000000000000000000000000000000000'
PROMPT = 'Write the English words for the numbers one to forty, one per line, and nothing else.'
# The agent: wait for the user's "go" on the pty (asking again after every other line: the relay drains what was
# printed before the user attached, see Terminal.await_prompt), run Claude Code once in print mode with partial
# messages (each delta is printed as it arrives), report its exit, wait for an Enter so the relay drains before pid 1
# exits.
AGENT_SCRIPT = ('until printf "w2-gate: type go and press Enter to start\\n"; IFS= read -r w || exit 1; '
                '[ "$w" = go ]; do :; done; '
                '/runtime/bin/claude -p "$W2_PROMPT" --model haiku --output-format stream-json --verbose '
                '--include-partial-messages --disallowedTools WebSearch; echo "W2_CLAUDE_EXIT=$?"; IFS= read -r _')
# validation.md N-14: the demonstration configuration keeps the provider's server-side search off (WebSearch disallowed
# above); every model-API request body the user's window shows must carry no server-tool block of these types.
SERVER_TOOL = re.compile(r'"type":"(web_search|web_fetch)[^"]*"')
AGENT_ENV = {'PATH': '/bin:/usr/bin', 'SHELL': '/bin/bash', 'TERM': 'xterm-256color', 'LANG': 'C.UTF-8',
             'ANTHROPIC_API_KEY': PLACEHOLDER, 'W2_PROMPT': PROMPT,
             # telemetry, error reporting and update checks off: the gate is about the model call (recorded in README)
             'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_AUTOUPDATER': '1'}
# 7.2: the interactive shell the runner types into, with the clients' own configuration pointed at the cell files
SHELL_ENV = {**{k: v for k, v in AGENT_ENV.items() if k != 'W2_PROMPT'}, 'PS1': 'w2$ ',
             'GIT_CONFIG_GLOBAL': '/w2/gitconfig', 'NPM_CONFIG_USERCONFIG': '/w2/npmrc', 'NPM_CONFIG_CACHE': '/tmp/npm-cache',
             'NPM_CONFIG_UPDATE_NOTIFIER': 'false', 'UV_CACHE_DIR': '/tmp/uv-cache', 'GH_TOKEN': GH_PLACEHOLDER,
             'GH_NO_UPDATE_NOTIFIER': '1', 'GH_PROMPT_DISABLED': '1', 'PIP_NO_INPUT': '1'}
PROMPT_MARK = b'w2$ '


def utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()



def cell_files(root: Path) -> None:
    """The deployment's read-only cell files for 7.2 (build plan 5.3): the git credential helper and its placeholder
    pair, the global git config naming it, and the .npmrc with the npm account's placeholder."""
    for d in ('bin', 'placeholders'):
        (root / 'w2' / d).mkdir(mode=0o755)
    helper = root / 'w2/bin/git-credential-placeholder'
    shutil.copyfile(ENGINE / 'frontend/git-credential-placeholder', helper)
    os.chmod(helper, 0o555)
    # GitHub takes the account's username with a token as the password (HTTPS); only the password position carries
    # the placeholder, so only it is replaced and the username goes out as written here
    (root / 'w2/placeholders/git').write_text(f'username={GITHUB_USER}\npassword={GIT_PLACEHOLDER}\n')
    (root / 'w2/gitconfig').write_text('[credential]\n\thelper = /w2/bin/git-credential-placeholder\n'
                                       '[init]\n\tdefaultBranch = main\n')
    template = (ENGINE / 'frontend/npmrc.template').read_text().replace('W2-PLACEHOLDER-npm-alice', NPM_PLACEHOLDER)
    (root / 'w2/npmrc').write_text(template)
    for f in ('placeholders/git', 'gitconfig', 'npmrc'):
        os.chmod(root / 'w2' / f, 0o444)


def deploy(root: Path, build: Path, command: Callable[..., dict[str, Any]], workspace_storage: Path,
           workspace_binds: list[Path], record: dict[str, Any], full: bool, frontend: str,
           runtime_mode: str = 'shared', experiment: bool = False,
           shells: dict[str, dict[str, str]] | None = None, workspaces: tuple[str, ...] = ('work0',),
           extra: list[tuple[str, list[str], dict[str, str], str]] | None = None) -> None:
    """shells: one interactive shell runtime per name (<name>-shell, plan <name>-shell-0), each with SHELL_ENV plus
    that name's own variables, instead of 7.2's single shell (the derivation set's agents). workspaces: the catalog's
    workspaces, each with its transfer plans when the seed has git; extra: (runtime, argv, env, workspace) more
    runtimes, plan <runtime>-0 on that workspace (the workspace suite's agent side)."""
    (root / 'store').mkdir(mode=0o700)
    (root / 'store/objects').mkdir(mode=0o700)
    (root / 'store/store.lock').touch(mode=0o600)
    (root / 'sandbox-root').mkdir(mode=0o755)
    (root / 'w2').mkdir(mode=0o755)
    (root / 'w2/ca').mkdir(mode=0o755)
    command([VENV / 'bin/python', ENGINE / 'frontend/make_ca_pool.py', root / 'ca-pool', '16'])  # one per execution: 16 = the uid range
    if full:
        cell_files(root)
    seed, versions = build_seed(root / 'seed', build, full, frontend, experiment)
    record['seed'] = {'entries': len(seed.entries), 'versions': versions,
                      'bytes': sum(e['size'] for e in seed.entries.values())}
    components = seed.manifest()
    component_digest = save_json(root / 'components.json', components)
    lock_digest = seed.entries['dependency-lock.json']['digest']
    policy_digest = save_json(root / 'policy.json', {'v': 1, 'target_arch': 'x86_64', 'default_action': 'errno',
                                                     'default_errno': 1, 'allow': WORKLOAD_ALLOW})
    profile_digest = save_json(root / 'isolation.json', {'isolation_profile_id': 'sandbox-native',
                               'target_arch': 'x86_64', 'layout': 'runtime-root-v1', 'construction': 'SB-01-SB-09'})
    fs = os.statvfs(root)
    identity = command(['/usr/bin/btrfs', 'filesystem', 'show', '--raw', root])['stdout']
    nodes = len(components['files']) + 1
    charge = 4096 * nodes + sum(((e['size'] + 4095) // 4096) * 4096 for e in components['files'] if e['type'] == 'file')
    storage_digest = save_json(root / 'storage.json', {
        'storage_profile_id': 'gate-store', 'store_id': 'e' * 32,
        'filesystem_uuid': re.search(r'uuid:\s*([0-9a-f-]{36})', identity).group(1),
        'store_root_ref': 'store', 'objects_ref': 'store/objects', 'lock_ref': 'store/store.lock',
        'owner_uid': 0, 'owner_gid': 0, 'filesystem_kind': 'btrfs',
        'filesystem_capacity_bytes': str(fs.f_blocks * fs.f_frsize), 'max_copies': 16,
        'max_reserved_bytes': str(2 * charge), 'max_reserved_nodes': str(2 * nodes), 'max_tree_nodes': 65536,
        'min_free_bytes': str(64 * 1024 * 1024), 'cleanup_timeout_ms': 10000})
    catalog: dict[str, Any] = {
        'v': 1, 'runtimes': [],
        'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage_digest},
        'policies': [{'policy_id': 'workload', 'artifact_ref': 'policy.json', 'artifact_digest': policy_digest,
                      'target_arch': 'x86_64', 'format': 'w2-seccomp-json/1', 'compiler_identity': 'libseccomp-2.5.5'}],
        'workspaces': [], 'profiles': [{'artifact_ref': 'isolation.json', 'artifact_digest': profile_digest}],
        'plans': [], 'uid_range': {'first': 70000, 'last': 70015},
        'connector': {'uid': 70999, 'gid': 70999, 'executable': PYTHON[0],
                      'argv': [*PYTHON, str(ENGINE / 'bin/connector'), '--library', str(root / 'libw2sandbox.so')]},
        # the row's file worker (validation.md H-14), its own dedicated uid; D-19 is the deployment that makes it
        'file_worker': {'uid': 70996, 'gid': 70996, 'executable': PYTHON[0],
                        'argv': [*PYTHON, str(ENGINE / 'bin/file-worker'), '--library', str(root / 'libw2sandbox.so')]},
        'relay': {'executable': '/runtime/bin/w2-relay', 'argv': ['/runtime/bin/w2-relay']},
        'frontend': {'executable': FRONTEND_ARGV[frontend][0], 'argv': FRONTEND_ARGV[frontend]},
        'proxy_port': 3128, 'cell_files_ref': 'w2', 'ca_pool_ref': 'ca-pool',
        # host file reads (validation.md H-23): the real in-cell MCP server from the seed, on the cell's 127.0.0.1:3129
        'mcp_server': {'executable': MCP_ARGV[0], 'argv': MCP_ARGV}, 'mcp_port': 3129,
        'pdp': {'uid': PDP_ID, 'gid': PDP_ID}}                      # 648d60f2 4.2; validation.md D-13
    (root / 'hook').mkdir()                          # the hook port's directory, as the deployment makes it (K-48)
    os.chown(root / 'hook', 1000, PDP_ID)
    os.chmod(root / 'hook', 0o2750)
    catalog['runtime_mode'] = runtime_mode           # written explicitly: the catalog's default is shared (S-23)
    shutil.copy(build / 'libw2sandbox.so', root / 'libw2sandbox.so')
    os.chmod(root / 'libw2sandbox.so', 0o644)
    # the workspace rework (agent-rm-model 3.1; D-17, S-25): the storage belongs to the dedicated owner, root 0700, the
    # content in the fixed subdirectory the cell mounts
    for wid in workspaces:
        source = workspace_storage / wid
        command(['/usr/bin/btrfs', 'subvolume', 'create', source])
        os.chown(source, OWNER_ID, OWNER_ID)
        source.chmod(0o700)
        (source / TREE).mkdir(mode=0o700)
        os.chown(source / TREE, OWNER_ID, OWNER_ID)
        (root / wid).mkdir()
        command(['/usr/bin/mount', '--bind', source, root / wid])
        workspace_binds.append(root / wid)
        catalog['workspaces'].append({'workspace_id': wid, 'workspace_layout_id': 'private-work-v1',
                                      'source_ref': wid, 'workspace_uid': OWNER_ID, 'workspace_gid': OWNER_ID})
    shell = ['/runtime/bin/bash', '--norc', '--noprofile', '-i']
    runtimes = ([(f'{name}-shell', shell, {**SHELL_ENV, **more}, 'work0') for name, more in shells.items()] if shells else
                [('shell', shell, SHELL_ENV, 'work0') if full else
                 ('claude-code', ['/runtime/bin/bash', '-c', AGENT_SCRIPT], AGENT_ENV, 'work0')]) + list(extra or [])
    for runtime, argv, env, wid in runtimes:
        descriptor = dict(runtime_id=runtime, artifact_digest=component_digest,
                          dependency_digest=lock_digest, layout_id='runtime-root-v1', storage_profile_id='gate-store',
                          executable='/runtime/bin/bash', argv=argv, cwd='/work', env=env, protocol='w2-local/2',
                          component_manifest_ref='components.json', component_manifest_digest=component_digest)
        rd = save_json(root / f'{runtime}.json', descriptor)
        catalog['runtimes'].append({'descriptor_ref': f'{runtime}.json', 'descriptor_digest': rd,
                                    'seed_ref': 'seed', 'dependency_lock_ref': 'dependency-lock.json'})
        plan = dict(launch_plan_id=f'{runtime}-0', runtime_id=runtime, runtime_descriptor_digest=rd,
                    workspace_id=wid, workspace_layout_id='private-work-v1', policy_id='workload',
                    policy_digest=policy_digest, isolation_profile_id='sandbox-native',
                    isolation_profile_digest=profile_digest)
        catalog['plans'].append({'artifact_ref': f'plan-{runtime}-0.json',
                                 'artifact_digest': save_json(root / f'plan-{runtime}-0.json', plan)})
    if full or experiment:                           # the seeds with bash and git: each workspace's two transfer plans (S-24)
        transfer_runtimes.register(root, catalog, save_json, list(workspaces), component_digest=component_digest,
                                   lock_digest=lock_digest, storage_profile_id='gate-store', policy_id='workload',
                                   policy_digest=policy_digest, profile_digest=profile_digest)
    save_json(root / 'catalog.json', catalog)


class Watcher:
    """``engine-client admin questions`` as the user's approval window, kept in the transcript. Mode 'recorded': every
    question is answered deny-once (a question means the entries did not cover a request the agent made). Mode 'ask':
    each question is first drawn in full ('show', the whole body from the question's memfd), then answered allow-once."""

    def __init__(self, argv: list[str], ask: bool) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.transcript, self.answered, self.ask, self.shown = b'', 0, ask, set()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        pending = b''
        while True:
            data = os.read(self.proc.stdout.fileno(), 65536)
            if not data:
                return
            self.transcript += data
            pending += data
            while (m := re.search(rb'answer question (\d+) \[[^\]]*\]: ', pending)):
                pending, qid = pending[m.end():], m.group(1)
                if self.ask and qid not in self.shown:
                    self.shown.add(qid)
                    reply = b'show\n'
                else:
                    reply = b'allow-once\n' if self.ask else b'deny-once\n'
                    self.answered += 1
                self.proc.stdin.write(reply)
                self.proc.stdin.flush()

    def stop(self) -> str:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()
        return self.transcript.decode('utf-8', 'replace')


class Terminal:
    """The user's terminal for ``engine-client attach``: a pty pair, the client on the slave, this runner on the master."""

    def __init__(self, argv: list[str]) -> None:
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 50, 200, 0, 0))
        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        self.output = b''

    def read_until(self, marker: bytes | re.Pattern, timeout: float, start: int = 0) -> bool:
        """Read until marker (bytes or a compiled pattern) appears in the output from offset start on."""
        until = time.monotonic() + timeout
        seen = (lambda: marker.search(self.output, start) is not None) if isinstance(marker, re.Pattern) else \
            (lambda: marker in self.output[start:])
        while not seen():
            left = until - time.monotonic()
            if left <= 0 or not select.select([self.master], [], [], left)[0]:
                return seen()
            try:
                data = os.read(self.master, 65536)
            except OSError:
                return seen()
            if not data:
                return seen()
            self.output += data
        return True

    def await_prompt(self, marker: bytes, timeout: float, every: float = 2.0) -> bool:
        """Wait for the program's prompt. With no client attached the relay drains the agent's output (relay.c), so a
        prompt printed before this client attached is gone: after every `every` seconds without it, type an empty
        line, at which the program (the interactive shell, AGENT_SCRIPT) prints its prompt again."""
        until = time.monotonic() + timeout
        while not self.read_until(marker, min(every, until - time.monotonic())):
            if time.monotonic() >= until:
                return False
            self.type(b'\r')
        return True

    def type(self, data: bytes) -> None:
        os.write(self.master, data)


def owner(e: dict[str, Any]) -> str | None:
    return (e.get('control_binding') or {}).get('execution_id')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--mode', choices=('recorded', 'ask'), default='recorded',
                        help='recorded: the entry allows without asking; ask: every request is a question the runner '
                             'reads in full and answers allow-once (N-14 body check)')
    parser.add_argument('--suite', choices=('7.1', '7.2', 'derive', 'workspace', 'files'), default='7.1',
                        help='derive: the derivation set in the cell, each agent on its own shell runtime '
                             '(derive_cell.py; needs --seed experiment); workspace: import, push and export end to end '
                             '(workspace_suite.py); files: Claude Code reads a registered host file through the MCP '
                             'server and tries three ways out (file_suite.py)')
    parser.add_argument('--items', default='', help='7.2, derive: comma-separated item names (default: all)')
    parser.add_argument('--seed', choices=('gate', 'experiment'), default='gate',
                        help="experiment: deployment.md section 8's seed with all three agents (gate_seed.build_seed)")
    parser.add_argument('--agents', default='claude,pi,opencode', help='derive: comma-separated agents')
    parser.add_argument('--frontend', choices=FRONTENDS, default='go', help='the in-cell frontend (gate_seed.py)')
    parser.add_argument('--runtime-mode', choices=('copy', 'shared'), default='shared',
                        help="the catalog's runtime_mode, written explicitly: shared (the default, S-23) or copy")
    args = parser.parse_args()
    full, experiment = args.suite in ('7.2', 'derive', 'workspace'), args.seed == 'experiment'
    assert experiment or args.suite != 'derive', 'the derivation set runs on the experiment seed'
    agents = tuple(a for a in args.agents.split(',') if a)
    items = [i for i in ITEMS if not args.items or i.name in args.items.split(',')]
    assert os.geteuid() == 0 and platform.system() == 'Linux'
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER: the orphaned spawner comes back to this run
    run = args.run_dir.resolve(strict=True)
    assert run.parent == ENGINE / 'runs' and args.label.replace('-', '').isalnum()
    record_path = run / f'{args.label}.json'
    assert not record_path.exists()
    dotenv = dict(line.split('=', 1) for line in DOTENV.read_text().splitlines() if '=' in line)
    truth = dotenv.get('ANTHROPIC_API_KEY', '').strip().strip('"').encode()
    assert truth and PLACEHOLDER.encode() != truth
    # 7.2: the npm account gets a sentinel truth (the npm registry does not check a bearer on public packages, measured
    # 2026-10-30); gh and git use the user's GitHub token when .env has one, else a sentinel (gh then ends at a 401).
    # Every truth is searched for like the model key.
    github = dotenv.get('GITHUB_TOKEN', '').strip().strip('"').encode()
    truths = {'anthropic': truth, 'npm': ('npm_W2SENTINEL' + secrets.token_hex(16)).encode(),
              'gh': github or ('ghp_W2SENTINEL' + secrets.token_hex(16)).encode()}
    build = Path(tempfile.mkdtemp(prefix='engine-gate-build-', dir='/tmp'))
    build.chmod(0o755)
    os.chown(build, 1000, 1000)
    root = Path('/var/lib') / ('engine-gate-' + args.label)
    root.mkdir(mode=0o755)
    scratch = Path(tempfile.mkdtemp(prefix='engine-gate-', dir='/tmp')).resolve()
    images = {'runtime': (scratch / 'runtime.btrfs', 6 if experiment else 3), 'workspace': (scratch / 'workspace.btrfs', 1)}
    if args.suite == 'derive':
        import derive_cell                           # imported here: it reads derive_host, which imports this file
        items = derive_cell.items(agents, root / 'work0', AS_USER, tuple(n for n in args.items.split(',') if n))
    for image, gib in images.values():
        with image.open('xb') as out:
            out.truncate(gib * 1024 ** 3)
    workspace_storage = scratch / 'workspaces'
    workspace_storage.mkdir()
    evidence_dir = Path(tempfile.mkdtemp(prefix='engine-gate-evidence-', dir='/tmp'))
    # the trace is readable by the PDP's group (user 2026-11-01: a PDP that connects reads its history there), never
    # writable by it; the engine uid writes it
    os.chown(evidence_dir, 1000, PDP_ID)
    os.chmod(evidence_dir, 0o750)
    evidence = evidence_dir / 'events.jsonl'
    evidence.touch(mode=0o640)
    os.chown(evidence, 1000, PDP_ID)
    os.chmod(evidence, 0o640)
    layout = watch = None
    if args.suite == 'files':      # a fresh host directory, outside every directory of the engine's (H-22)
        layout = file_suite.make_layout(Path(tempfile.mkdtemp(prefix='engine-gate-files-', dir='/tmp')))
        truths['file_outside'] = layout.outside.encode()      # searched for like a truth: it must reach no record
    record: dict[str, Any] = {'started_at_utc': utc(), 'kernel': platform.release(), 'commands': [], 'result': 'not-run',
                              'suite': args.suite, 'frontend': args.frontend, 'runtime_mode': args.runtime_mode,
                              'seed_kind': args.seed, 'agents': list(agents) if args.suite == 'derive' else None,
                              'scope': ('build plan 7.4 step 5: the derivation set, one execution per item and agent, '
                                        'typed at the cell shell' if args.suite == 'derive' else
                                        'build plan 7.2: adaptation items, one execution each, typed at the cell shell'
                                        if full else 'plan engine-v3-n16-file-read 2.3d: Claude Code in a cell reads a '
                                        'registered host file through the in-cell MCP server, then three paths out of '
                                        'the prefix' if layout else 'build plan 7.1: Claude Code in a cell, model API '
                                        'through the in-cell frontend, the real connector and the core') +
                                       ', driven only through the admin client'}
    inputs = sorted({p for pattern in ('engine/*.py', 'connector/*.py', 'pdp/*.py', 'client/*.py', 'frontend/*.py', 'relay/*.c',
                                       'frontend-go/*.go', 'frontend-go/go.mod', 'mcp-go/*.go', 'mcp-go/go.mod',
                                       'bin/*', 'checks/*.py',
                                       'checks/workload-allow.txt', 'native/Makefile', 'native/sandbox/*')
                     for p in ENGINE.glob(pattern) if p.is_file()})
    record['inputs'] = [{'path': p.relative_to(REPO).as_posix(), 'digest': digest(p)} for p in inputs]
    client = AS_USER + [*PYTHON, ENGINE / 'bin/engine-client', '--root', root]
    engine_proc = pdp_proc = None

    def command(argv: list[Any], *, timeout: float = 120, allowed=(0,), env: dict[str, str] | None = None) -> dict[str, Any]:
        started = time.monotonic()
        p = subprocess.run([str(v) for v in argv], capture_output=True, text=True, timeout=timeout,
                           env=dict({'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'}, **(env or {})))
        item = {'argv': [str(v) for v in argv], 'exit_code': p.returncode, 'stdout': p.stdout[-20000:],
                'stderr': p.stderr[-20000:], 'elapsed_seconds': round(time.monotonic() - started, 3)}
        record['commands'].append(item)
        print(json.dumps({'command': len(record['commands']) - 1, 'exit_code': p.returncode,
                          'argv': item['argv'][-3:]}), flush=True)
        if p.returncode not in allowed:
            raise RuntimeError('command failed: ' + json.dumps(item)[:4000])
        return item

    mounted: list[Path] = []
    workspace_binds: list[Path] = []
    try:
        command(AS_USER + ['/usr/bin/make', '-s', '-C', NATIVE, 'sandbox', 'BUILD_DIR=' + str(build)], timeout=300)
        if args.frontend == 'go':
            go_build(build, command, AS_USER, pwd.getpwuid(1000).pw_dir)
        mcp_build(build, command, AS_USER, pwd.getpwuid(1000).pw_dir)      # every seed has the MCP server (H-23)
        for path, _ in images.values():
            command(['/usr/sbin/mkfs.btrfs', '-q', path])
        command(['/usr/bin/mount', '-o', 'loop,nosuid,nodev', images['runtime'][0], root])
        mounted.append(root)
        command(['/usr/bin/mount', '-o', 'loop,nosuid,nodev', images['workspace'][0], workspace_storage])
        mounted.append(workspace_storage)
        deploy(root, build, command, workspace_storage, workspace_binds, record, full, args.frontend, args.runtime_mode,
               experiment, {a: derive_cell.AGENT_ENV[a] for a in agents} if args.suite == 'derive' else None,
               ('work0', 'work1') if args.suite == 'workspace' else ('work0',),
               workspace_suite.runtimes() if args.suite == 'workspace' else
               [file_suite.runtime(layout, AGENT_ENV)] if layout else None)
        record['preflight'] = preflight(root / 'seed', scratch, full, args.frontend, experiment)
        # U-03: the catalog load w2-cell runs before the engine starts (cell.c), the seed's full check included
        record['catalog_check_seconds'] = command([build / 'w2-catalog', root, 'catalog.json'])['elapsed_seconds']
        print(json.dumps({'preflight': record['preflight']})[:3000], flush=True)
        with tarfile.open(run / f'{args.label}-deployment.tar', 'x') as out:
            for p in sorted(root.glob('*.json')):
                out.add(p, arcname=p.name, recursive=False)
        # the simple PDP (P-01) as the PDP's dedicated uid, started first: it connects once the hook port is up
        pdp_proc = subprocess.Popen(['/usr/bin/setpriv', f'--reuid={PDP_ID}', f'--regid={PDP_ID}', '--clear-groups',
                                     '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
                                     *PYTHON, str(ENGINE / 'bin/simple-pdp'), str(root / 'hook/pdp.sock')],
                                    stdout=(run / f'{args.label}-pdp.log').open('xb'), stderr=subprocess.STDOUT)
        # The production entry under w2-cell; the spawner's and the connector's stdio land in these two files.
        out_path, err_path = run / f'{args.label}-engine.stdout', run / f'{args.label}-engine.stderr'
        with out_path.open('xb') as out, err_path.open('xb') as err:
            engine_proc = subprocess.Popen([str(v) for v in SPAWNER_CAPS + [
                build / 'w2-cell', root, 'catalog.json', '1000', '1000', *PYTHON, ENGINE / 'bin/engine',
                build / 'libw2sandbox.so', root, 'catalog.json', evidence, '--measure-completion']], stdout=out, stderr=err,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
        until = time.monotonic() + 120
        while command(client + ['admin', 'ws', 'list'], allowed=(0, 2))['exit_code']:
            assert time.monotonic() < until and engine_proc.poll() is None, 'the management port never came up'
            time.sleep(1)
        command(client + ['admin', 'cred', 'put', HOST, ACCOUNT, 'api-key', '--truth-env', 'W2_GATE_TRUTH'],
                env={'W2_GATE_TRUTH': truth.decode()})
        command(client + ['admin', 'entry', 'put', 'work0', 'exact', 'allow', HOST, '--method', 'POST', '--method', 'GET',
                          '--prefix', '/v1/', '--prefix', '/api/', '--account', ACCOUNT,
                          '--approval', 'always' if args.mode == 'ask' else 'never'])
        if layout:                                       # H-25: the directory object as a user registers it
            command(client + ['admin', 'object', 'put', 'work0', file_suite.ALIAS, layout.prefix, '--type', 'dir',
                              '--list', '--mode', 'allow'])
            watch = file_suite.Watch(layout, evidence)
        record['mode'] = args.mode
        record['workspaces'] = command(client + ['admin', 'ws', 'list'])['stdout']
        watcher = Watcher([str(v) for v in client + ['admin', 'questions']], args.mode == 'ask')
        if args.suite == 'workspace':                    # the workspace rework end to end; its verdict comes below
            record['workspace'] = workspace_suite.Suite(root, run, args.label, command, client, PYTHON, ENGINE, OWNER_ID,
                                                        TREE, evidence).run()
            record['question_transcript'] = watcher.stop()
            raise StopIteration
        if full:
            record['items'], plan = [], None
            for item in items:
                if args.suite == 'derive' and item.plan != plan:      # each agent starts on an empty workspace
                    plan = item.plan
                    derive_cell.clear_workspace(root / 'work0')
                record['items'].append(run_item(item, client, command, root, evidence_dir, run, args.label, truths))
            record['question_transcript'] = watcher.stop()
            record['questions_answered'] = watcher.answered
            raise StopIteration
        started = start_row(client, command, file_suite.PLAN if layout else 'claude-code-0')
        execution = re.search(r'execution=(\S+)', started['stdout']).group(1)
        record['execution'] = execution
        attach_sock = root / 'rows' / execution / 'attach.sock'
        until = time.monotonic() + 60
        while not attach_sock.exists():
            assert time.monotonic() < until, 'no attach socket'
            time.sleep(0.2)
        recording = evidence_dir / 'attach.cast'
        term = Terminal([str(v) for v in client + ['attach', execution, '--record', recording]])
        record['agent_ready'] = term.await_prompt(b'press Enter to start', 90)
        record['rows_after_start'] = command(client + ['admin', 'row', 'list'])['stdout']
        assert record['agent_ready'], term.output[-3000:].decode('utf-8', 'replace')
        record['enter_at_utc'] = utc()
        term.type(b'go\r')
        record['agent_finished'] = term.read_until(b'W2_CLAUDE_EXIT=', 240) and term.read_until(b'\n', 5)
        exit_line = re.search(rb'W2_CLAUDE_EXIT=(\d+)', term.output)
        record['claude_exit'] = int(exit_line.group(1)) if exit_line else None
        term.type(b'\r')                                 # the agent's last read: pid 1 exits, the row closes
        term.read_until(b'\x00never', 15)
        if term.proc.poll() is None:
            term.type(b'\x1d')                           # Ctrl-] detaches
        term.proc.wait(timeout=10)
        record['attach_exit'] = term.proc.returncode
        (run / f'{args.label}-terminal.txt').write_bytes(term.output)
        until = time.monotonic() + 30
        while execution in command(client + ['admin', 'row', 'list'])['stdout'] and time.monotonic() < until:
            time.sleep(1)
        record['question_transcript'] = watcher.stop()
        record['questions_answered'] = watcher.answered
        shutil.copyfile(recording, run / f'{args.label}-attach.cast')
    except StopIteration:                                # the 7.2 suite ends here; its verdicts come below
        pass
    except BaseException as error:
        record['error'] = repr(error)
        record['traceback'] = traceback.format_exc()
        record['result'] = 'failed'
    finally:
        try:
            watched = watch.stop() if watch else []     # files: the row is over; anything still waiting goes on
            if engine_proc is not None and engine_proc.poll() is None:
                engine_proc.send_signal(signal.SIGTERM)
                engine_proc.wait(timeout=20)
            if pdp_proc is not None:
                pdp_proc.terminate()
                pdp_proc.wait(timeout=10)
            until = time.monotonic() + 20                # the orphaned spawner sees control EOF and exits by itself
            while time.monotonic() < until and Path(f'/proc/self/task/{os.getpid()}/children').read_text().split():
                os.waitpid(-1, os.WNOHANG)
                time.sleep(0.05)
            leftover = Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()
            for pid in leftover:
                os.kill(int(pid), signal.SIGKILL)
                os.waitpid(int(pid), 0)
            record['supervisor_killed'] = leftover
            events = [json.loads(line) for line in evidence.read_text().splitlines()] if evidence.exists() else []
            shutil.copyfile(evidence, run / f'{args.label}-events.jsonl')
            record['record_access'] = record_access([evidence], command)      # D-13 as deployed; recorded only
            record['timings'] = timings(events)
            if full:
                for entry in record.get('items', []):
                    rs = requests_of(events, entry.get('execution'))
                    item = next(i for i in items if i.name == entry['name'])
                    entry['requests'] = rs
                    entry['ok'], entry['observed'] = item.judge(rs, entry.get('terminal_tail', ''))
                    entry['ok'] = entry['ok'] and entry.get('exit') == 0 and entry.get('drive', {}).get('ok', True)
                if args.suite == 'derive':
                    derive_cell.github_check(record.get('items', []), github.decode())
                record['port_faults'] = [e for e in events if e.get('kind') == 'diagnostic'
                                         and e.get('name') == 'judgment_port_fault']
            else:
                record['analysis'] = analyse(events, record.get('execution'), run / f'{args.label}-attach.cast')
            if args.mode == 'ask':
                record['n14'] = body_check(record.get('question_transcript', ''))
                (run / f'{args.label}-questions.txt').write_text(record.get('question_transcript', ''))
            # sentinel (build plan 4.5 at the gate): the truth appears nowhere but the credential store
            hits = []
            for top in (root, workspace_storage, evidence_dir, run):
                for dirpath, _, filenames in os.walk(top):
                    for name in filenames:
                        p = Path(dirpath) / name
                        if p.is_file() and not p.is_symlink() and p != record_path:
                            try:
                                data = p.read_bytes()
                                hits += [f'{name}:{p}' for name, value in truths.items() if value in data]
                            except OSError:
                                pass
            store = str(root / 'state/credentials')
            record['sentinel'] = {'hits': [h for h in hits if store not in h],
                                  'credential_store_hits': [h for h in hits if store in h],
                                  'searched': [str(root), str(workspace_storage), str(evidence_dir), str(run)]}
            if layout:                                   # H-25's criteria (file_suite.judge), the trace read in place
                terminal = run / f'{args.label}-terminal.txt'
                record['files'] = file_suite.judge(events, record.get('execution'),
                                                   terminal.read_bytes() if terminal.exists() else b'',
                                                   evidence.read_bytes(), layout, watched,
                                                   [h for h in hits if h.startswith('file_outside:')], WORKER_ID)
            if record['result'] != 'failed' and args.suite == 'workspace':
                record['result'] = ('passed' if record.get('workspace', {}).get('ok') and not record['sentinel']['hits']
                                    and not record['port_faults'] else 'failed')
            elif record['result'] != 'failed' and full:
                bad = [i['name'] for i in record.get('items', []) if not i['ok']]
                record['result'] = ('failed' if record['sentinel']['hits'] or record['port_faults'] or not record.get('items')
                                    else 'passed' if not bad else 'items-not-passed: ' + ','.join(bad))
            elif record['result'] != 'failed':
                a = record['analysis']
                n14_ok = args.mode != 'ask' or (record['n14']['model_bodies'] >= 1 and not record['n14']['server_tool_blocks'])
                # files: no partial messages asked for, so no stream to judge; its own criteria instead
                record['result'] = 'passed' if (a['model_call_ok'] and (a['streamed'] if not layout else
                                                                        record['files']['ok'])
                                                and record.get('claude_exit') == 0
                                                and not record['sentinel']['hits'] and not a['port_faults']
                                                and n14_ok) else 'failed'
            for target in reversed(workspace_binds):
                command(['/usr/bin/umount', target])
            for target in reversed(mounted):
                command(['/usr/bin/umount', target])
            root.rmdir()
            shutil.rmtree(scratch)
            shutil.rmtree(build)
            shutil.rmtree(evidence_dir)
            if layout:
                shutil.rmtree(layout.top)
            record['cleanup'] = {'deployment_removed': not root.exists(), 'scratch_removed': not scratch.exists()}
        except BaseException as error:
            record['cleanup_error'] = repr(error)
            record['cleanup_traceback'] = traceback.format_exc()
            record['result'] = 'failed'
        record['finished_at_utc'] = utc()
        with record_path.open('x') as out:
            json.dump(record, out, ensure_ascii=False, indent=2)
            out.write('\n')
    print(json.dumps({'record': str(record_path), 'result': record['result']}), flush=True)
    return 0 if record['result'] == 'passed' else 1


def run_item(item, client: list[Any], command: Callable[..., dict[str, Any]], root: Path, evidence_dir: Path,
             run: Path, label: str, truths: dict[str, bytes]) -> dict[str, Any]:
    """One adaptation item: its setup over the management port, a fresh execution of the shell runtime, the command
    typed at the prompt through the attach window, then exit. The verdict is drawn later from the trace."""
    entry: dict[str, Any] = {'name': item.name, 'goal': item.goal, 'command': item.command, 'started_at_utc': utc()}
    env = {'W2_NPM_TRUTH': truths['npm'].decode(), 'W2_GH_TRUTH': truths['gh'].decode(), 'W2_GIT_USER': GITHUB_USER}
    for tail in item.setup:
        command(client + ['admin', *tail], env=env if 'cred' in tail[:1] else None)
    started = start_row(client, command, item.plan)
    execution = entry['execution'] = re.search(r'execution=(\S+)', started['stdout']).group(1)
    attach_sock = root / 'rows' / execution / 'attach.sock'
    until = time.monotonic() + 60
    while not attach_sock.exists():
        assert time.monotonic() < until, 'no attach socket'
        time.sleep(0.2)
    recording = evidence_dir / f'{item.name}.cast'
    term = Terminal([str(v) for v in client + ['attach', execution, '--record', recording]])
    entry['ready'] = term.await_prompt(PROMPT_MARK, 90)
    if entry['ready']:
        mark = len(term.output)
        term.type(item.command.encode() + b'; echo W2_ITEM_EXIT=$?\r')
        if item.drive is not None:
            entry['drive'] = item.drive(term, mark)
        entry['finished'] = term.read_until(ITEM_EXIT, item.timeout, mark)
        found = ITEM_EXIT.search(term.output, mark)
        entry['exit'] = int(found.group(1)) if found else None
        entry['terminal_tail'] = term.output[mark:][-60000:].decode('utf-8', 'replace')
        term.type(b'exit\r')
    term.read_until(b'\x00never', 15)
    if term.proc.poll() is None:
        term.type(b'\x1d')
    term.proc.wait(timeout=10)
    (run / f'{label}-{item.name}-terminal.txt').write_bytes(term.output)
    if recording.exists():
        shutil.copyfile(recording, run / f'{label}-{item.name}.cast')
    until = time.monotonic() + 30
    while execution in command(client + ['admin', 'row', 'list'])['stdout'] and time.monotonic() < until:
        time.sleep(1)
    entry['finished_at_utc'] = utc()
    return entry


def start_row(client: list[Any], command: Callable[..., dict[str, Any]], plan: str) -> dict[str, Any]:
    """ROW_START, retried while the spawner has not reported control_ready yet (the management port is up first; the
    spawner verifies the runtime seed before it is ready, longer for a larger seed)."""
    until = time.monotonic() + 120
    while True:
        started = command(client + ['admin', 'row', 'start', 'work0', plan], allowed=(0, 1))
        if started['exit_code'] == 0:
            return started
        assert 'control not ready' in started['stderr'] and time.monotonic() < until, started['stderr']
        time.sleep(1)


def requests_of(events: list[dict[str, Any]], execution: str | None) -> list[dict[str, Any]]:
    """Per request of one row: admission, decision and completion, paired by seq. The engine does not record completion
    (648d60f2 4.3); the gate runs it with the measurement switch, which writes each one as a request_completed
    diagnostic (README 完成记录开关). Network requests only: a file request's seq is the file port's own (H-20), so
    its records are left out by their admission numbers."""
    files = {(e.get('detail') or {}).get('admission') for e in events if e['kind'] == 'request_admitted'
             and (e.get('detail') or {}).get('request_kind') == 'file'}
    by_seq: dict[int, dict[str, Any]] = {}
    for e in events:
        d = e.get('detail') or {}
        if e['kind'] == 'diagnostic' and e.get('name') == 'request_completed' and d.get('execution_id') == execution:
            by_seq.setdefault(d['seq'], {})['request_reported'] = dict(d)
        elif owner(e) == execution and e['kind'] in ('request_admitted', 'request_decided') and 'seq' in d \
                and d.get('admission') not in files:
            by_seq.setdefault(d['seq'], {})[e['kind']] = {'outcome': e.get('outcome'), 'reason': e.get('reason_code'), **d}
    out = []
    for seq, r in sorted(by_seq.items()):
        a, dec, rep = r.get('request_admitted', {}), r.get('request_decided', {}), r.get('request_reported', {})
        out.append({'seq': seq, 'method': a.get('method'), 'host': a.get('host'), 'port': a.get('port'),
                    'path': a.get('path'), 'header_names': a.get('header_names'), 'body_len': a.get('body_len'),
                    'decision': dec.get('outcome'), 'basis': dec.get('reason'), 'credential': dec.get('credential'),
                    'account': dec.get('account'), 'placement': dec.get('placement'),
                    'result': rep.get('result'), 'status': rep.get('status')})
    return out


def timings(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Seconds on the engine's monotonic clock: control_init sent to control_ready received, and per row (the gate
    starts one at a time) spawn_requested to spawn_prepared, the copy and its structure check included (S-21, U-03)."""
    def at(e: dict[str, Any]) -> int:
        return int(e['monotonic_time'])

    def control(name: str, kind: str) -> int | None:
        return next((at(e) for e in events if e.get('name') == name
                     and (e.get('detail') or {}).get('record', {}).get('type') == kind), None)
    sent, ready = control('control_sent', 'control_init'), control('control_received', 'control_ready')
    spawns, pending = [], None
    for e in events:
        if e['kind'] == 'spawn_requested':
            pending = at(e)
        elif e['kind'] == 'spawn_prepared' and pending is not None:
            spawns.append(round((at(e) - pending) / 1e9, 3))
            pending = None
    return {'control_ready_seconds': round((ready - sent) / 1e9, 3) if sent and ready else None,
            'spawn_seconds': spawns, 'spawn_max_seconds': max(spawns, default=None)}


def body_check(transcript: str) -> dict[str, Any]:
    """N-14 on what the user's window drew in full: for every model-API request (POST /v1/messages) the body line, its
    server-tool blocks (must be none) and the tool names it offers the model."""
    bodies, blocks, names = 0, [], set()
    for block in transcript.split('── question ')[1:]:
        if '  method       POST' not in block or '  path         /v1/messages' not in block:
            continue
        lines = block.splitlines()
        at = next((i for i, line in enumerate(lines) if line.startswith('  body ')), None)
        if at is None or at + 1 >= len(lines) or not lines[at + 1].startswith('    '):
            continue
        body = lines[at + 1].strip()
        if re.search(r' …\[first \d+ of \d+ bytes\]$', body):   # the clipped first drawing; the full one follows 'show'
            continue
        bodies += 1
        blocks += SERVER_TOOL.findall(body)
        names.update(re.findall(r'"name":"([A-Za-z0-9_]+)","description"', body))
    return {'model_bodies': bodies, 'server_tool_blocks': blocks, 'tool_names': sorted(names)}


def analyse(events: list[dict[str, Any]], execution: str | None, cast: Path) -> dict[str, Any]:
    """Per request of the row: admission, decision, report (paired by seq); and the stream as the user's terminal saw it."""
    mine = [e for e in events if owner(e) == execution]
    requests = requests_of(events, execution)
    model_calls = [r for r in requests if r['method'] == 'POST' and r['host'] == 'api.anthropic.com'
                   and (r['path'] or '').startswith('/v1/messages')]
    ok = [r for r in model_calls if r['decision'] == 'allow' and r['credential'] == 'placed' and r['account'] == ACCOUNT
          and r['result'] == 1 and r['status'] is not None and 200 <= r['status'] < 300]
    deltas, result_ok, times = 0, False, []
    if cast.exists():
        lines = cast.read_text(encoding='utf-8', errors='replace').splitlines()[1:]
        text = ''
        for line in lines:
            at, kind, data = json.loads(line)
            if kind != 'o':
                continue
            text += data
            n = data.count('"content_block_delta"')
            if n:
                deltas += n
                times.append(at)
        result_ok = '"type":"result"' in text and '"is_error":false' in text
    return {'requests': requests, 'model_calls': len(model_calls), 'model_call_ok': bool(ok),
            'delta_events': deltas, 'delta_output_times': [round(t, 3) for t in times][:200],
            'delta_span_seconds': round(times[-1] - times[0], 3) if len(times) > 1 else 0.0,
            'streamed': deltas >= 3 and len(set(round(t, 3) for t in times)) >= 3 and result_ok,
            'result_line_ok': result_ok,
            'port_faults': [e for e in events if e.get('kind') == 'diagnostic' and e.get('name') == 'judgment_port_fault'],
            'kinds': sorted({e['kind'] if e['kind'] != 'diagnostic' else 'diagnostic:' + e.get('name', '')
                             for e in mine})}


if __name__ == '__main__':
    raise SystemExit(main())
