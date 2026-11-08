"""Host measurement for the workload seccomp allowlist (build plan 7.4 steps 3-4; allowlist-derivation.md).

On the host and without the sandbox, every source the cell's workload policy must cover is run under ``strace -f``:
the three agents (Claude Code, Pi, OpenCode) on the derivation set, one-shot and once interactively; the gate's ten
commands (gate_items.ITEMS) typed into an interactive bash; the frontend and the pty relay as their own processes (out
of their host tests). The agents' environment is the cell's: the pty as stdio, a fresh empty HOME, the proxy and CA
variables, only placeholders; checks/derive_proxy.py on a plain mitmdump stands in for the connector. The startup
code between the filter and the agent's exec is read off native/sandbox/child.c, not measured.

Outputs in the run directory: results.json (per run: argv without secrets, exit, the expected-result judgement),
syscalls.json (per run, per source, the union), files/ (paths each run opened or executed, for the runtime notes of
plan 7.4 step 7), outputs/ (terminal output), proxy.jsonl (header names only, never values). Raw strace output stays
in the work root (gzip), not in the repository.

Run as the ordinary user inside WSL (not root):
  python3 checks/derive_host.py --run-dir runs/<dir> [--agents claude,pi,opencode] [--parts agents,gate,helpers]
      [--frontend python]
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Callable
import urllib.request

ENGINE = Path(__file__).resolve().parents[1]
REPO = ENGINE.parents[1]
sys.path.insert(0, str(ENGINE / 'checks'))
from gate_items import (FIRST_START, GH_PLACEHOLDER, GIT_PLACEHOLDER, GITHUB_USER, ITEM_EXIT, ITEMS,  # noqa: E402
                        MAIN_SCREEN, MCP_CONFIG, NPM_PLACEHOLDER, TEST_REPO, screen)
from gate_seed import CLAUDE, FRONTENDS, GO, VENV  # noqa: E402
from run_gate import DOTENV, PLACEHOLDER, PROMPT_MARK, SHELL_ENV, Terminal  # noqa: E402

USER_HOME = Path('/home/jerry')
NODE_BIN = USER_HOME / '.local/opt/node-v22.23.4-linux-x64/bin'      # Pi 1.4.0 needs node >= 22.19 (plan 7.4 step 2)
AGENTS = USER_HOME / '.local/agents'
TOOL_CACHE = Path('/var/cache/w2-gate-tools')                       # the gate seed's uv and gh release binaries
MODEL = 'claude-haiku-5-5'                                          # what Claude Code's "haiku" resolves to (7.2 runs)
STRACE = ['/usr/bin/strace', '-f', '-qq', '-s', '256']
SCRATCH = ('/tmp/hw', '/tmp/tb', '/tmp/pip-t', '/tmp/uvv', '/tmp/npm-t', '/tmp/models.json')
NPM_TRUTH = 'W2-SENTINEL-npm-host-derive'
# Read off native/sandbox/child.c 204-223 (filter installed, then SEALED/COMMIT over fd 3, chdir, the relay and frontend
# forked by start_helper, wait_ready, execve) and transport.c w2_send_fixed / w2_recv_fixed / wait_for, with glibc's
# mapping: send -> sendto, poll -> poll, nanosleep -> clock_nanosleep, waitpid -> wait4, _exit -> exit_group, fork ->
# clone (and set_robust_list in the child); clock_gettime is the vDSO and listed in case it falls back.
STARTUP_READ = sorted({'sendto', 'recvmsg', 'poll', 'clock_gettime', 'chdir', 'clone', 'set_robust_list', 'close',
                       'fcntl', 'execve', 'exit_group', 'access', 'wait4', 'clock_nanosleep'})
# The policy compiler refuses these whatever the list says (native/sandbox/policy.c forbidden[]); plan 7.4 step 4.
COMPILER_REFUSED = {'io_uring_setup', 'io_uring_enter', 'io_uring_register', 'clone3', 'sysinfo', 'sync', 'syncfs',
                    'keyctl', 'add_key', 'request_key'}
PRIVILEGED = re.compile(r'^(mount|umount2?|move_mount|open_tree|fsopen|fsmount|fsconfig|fspick|mount_setattr|'
                        r'pivot_root|ptrace|process_vm_readv|process_vm_writev|pidfd_getfd|bpf|perf_event_open|setns|'
                        r'userfaultfd|kexec_load|kexec_file_load|init_module|finit_module|delete_module)$')
LINE = re.compile(r'^(\d+)\s+(?:<\.\.\. (\w+) resumed>|(\w+)\()')
SPAWN = re.compile(r'^(\d+)\s+(?:<\.\.\. )?(clone3?|fork|vfork)\b.*= (\d+)(?: <|$)')
EXECVE = re.compile(r'^(\d+)\s+execve\("([^"]*)", \[(.*?)\]')
OPENED = re.compile(r'^\d+\s+(?:execve|open|openat)\((?:AT_FDCWD, )?"([^"]*)".* = \d+')
REPLY = re.compile(r'(?i)systemcall|syscall')
# (g)'s expected result (allowlist-derivation.md, user 2026-11-02): the reply agrees with the page, which has the title
# "Example Domain" and no h1, so it gives the title or says there is no h1; matched on screen() text (no whitespace)
NO_H1 = re.compile(r"(?i)no<?h1|n[o']thave(an)?<?h1|without(an)?<?h1|没有<?h1")


def page_matches(text: str) -> bool:
    return 'ExampleDomain' in text or NO_H1.search(text) is not None


def utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def derivation_set() -> dict[str, str]:
    """The prompts as the user confirmed them: read from the table in allowlist-derivation.md, the single copy."""
    ops: dict[str, str] = {}
    for line in (ENGINE / 'allowlist-derivation.md').read_text(encoding='utf-8').splitlines():
        m = re.match(r'^\| \(([a-h])\) [^|]* \| (.+?) \| [^|]+ \|$', line)
        if m:
            ops[m.group(1)] = m.group(2).replace('\\_', '_').replace('\\*', '*')
    assert sorted(ops) == list('abcdefgh'), sorted(ops)
    return ops


class Agent:
    def __init__(self, name: str, oneshot: Callable[[str], list[str]], interactive: list[str], env: dict[str, str],
                 not_applicable: frozenset[str] = frozenset()) -> None:
        self.name, self.oneshot, self.interactive, self.env = name, oneshot, interactive, env
        self.not_applicable = not_applicable


def agents(bin_dir: Path) -> dict[str, Agent]:
    claude, pi, oc = str(bin_dir / 'claude'), str(bin_dir / 'pi'), str(bin_dir / 'opencode')
    return {
        # the gate's display configuration (validation.md N-14; run_gate.AGENT_ENV)
        'claude': Agent('claude', lambda p: [claude, '-p', p, '--model', 'haiku', '--disallowedTools', 'WebSearch',
                                             '--permission-mode', 'bypassPermissions'],
                        [claude, '--model', 'haiku', '--disallowedTools', 'WebSearch'],
                        {'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_AUTOUPDATER': '1'}),
        # Pi's counterparts (docs/environment-variables.md): no version check, no install telemetry; no fetch tool
        'pi': Agent('pi', lambda p: [pi, '-p', p, '--model', f'anthropic/{MODEL}'], [pi, '--model', f'anthropic/{MODEL}'],
                    {'PI_SKIP_VERSION_CHECK': '1', 'PI_TELEMETRY': '0'}, frozenset({'g'})),
        # OpenCode's counterparts: no self-update, no language-server downloads; --auto answers its permission asks
        'opencode': Agent('opencode', lambda p: [oc, 'run', p, '-m', f'anthropic/{MODEL}', '--auto'],
                          [oc, '-m', f'anthropic/{MODEL}'],
                          {'OPENCODE_DISABLE_AUTOUPDATE': '1', 'OPENCODE_DISABLE_LSP_DOWNLOAD': '1'}),
    }


class Rig:
    """The work root (WSL ext4, outside the repository), the proxy standing in for the connector, the host's cell files."""

    def __init__(self, run: Path) -> None:
        self.run = run
        self.root = Path('/var/tmp/w2-derive') / run.name
        self.root.mkdir(parents=True, exist_ok=False)
        for d in ('strace', 'homes', 'work', 'w2/bin', 'w2/placeholders', 'bin', 'mitm'):
            (self.root / d).mkdir(parents=True)
        self.log, self.label = self.root / 'proxy.jsonl', self.root / 'label'
        self.label.write_text('')
        self._cell_files()
        self._bin()
        self.proxy = self._start_proxy()

    def _cell_files(self) -> None:
        w2 = self.root / 'w2'
        shutil.copyfile(ENGINE / 'frontend/git-credential-placeholder', w2 / 'bin/git-credential-placeholder')
        os.chmod(w2 / 'bin/git-credential-placeholder', 0o555)
        (w2 / 'placeholders/git').write_text(f'username={GITHUB_USER}\npassword={GIT_PLACEHOLDER}\n')
        (w2 / 'gitconfig').write_text(f'[credential]\n\thelper = {w2}/bin/git-credential-placeholder\n'
                                      '[init]\n\tdefaultBranch = main\n')
        template = (ENGINE / 'frontend/npmrc.template').read_text()
        (w2 / 'npmrc').write_text(template.replace('W2-PLACEHOLDER-npm-alice', NPM_PLACEHOLDER))

    def _bin(self) -> None:
        b = self.root / 'bin'
        links = {'node': NODE_BIN / 'node', 'npm': NODE_BIN / 'npm', 'npx': NODE_BIN / 'npx', 'claude': CLAUDE,
                 'pi': AGENTS / 'pi/node_modules/.bin/pi', 'opencode': AGENTS / 'opencode/node_modules/.bin/opencode',
                 'uv': next(TOOL_CACHE.glob('uv-*/**/uv')), 'gh': next(TOOL_CACHE.glob('gh-*/**/bin/gh'))}
        for name, target in links.items():
            os.symlink(target, b / name)

    def _start_proxy(self) -> subprocess.Popen[bytes]:
        dotenv = dict(line.split('=', 1) for line in DOTENV.read_text().splitlines() if '=' in line)
        subs = {'x-api-key': {PLACEHOLDER: {'truth': dotenv['ANTHROPIC_API_KEY'], 'account': 'gate'}},
                'bearer': {GH_PLACEHOLDER: {'truth': dotenv['GITHUB_TOKEN'], 'account': 'gh'},
                           NPM_PLACEHOLDER: {'truth': NPM_TRUTH, 'account': 'npm'}},
                'basic_password': {GIT_PLACEHOLDER: {'truth': dotenv['GITHUB_TOKEN'], 'account': 'git'}}}
        self.subs = self.root / 'subs.json'
        fd = os.open(self.subs, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(subs, f)
        self.github_token = dotenv['GITHUB_TOKEN']
        env = {**os.environ, 'W2_DERIVE_SUBS': str(self.subs), 'W2_DERIVE_LOG': str(self.log),
               'W2_DERIVE_LABEL': str(self.label)}
        # as the cell's frontend: HTTP/1.1 only, responses streamed through
        proc = subprocess.Popen([str(VENV / 'bin/mitmdump'), '-q', '--listen-host', '127.0.0.1', '--listen-port', '18080',
                                 '--set', f'confdir={self.root / "mitm"}', '--set', 'http2=false',
                                 '--set', 'stream_large_bodies=1', '-s', str(ENGINE / 'checks/derive_proxy.py')],
                                env=env, stdout=open(self.root / 'mitmdump.log', 'wb'), stderr=subprocess.STDOUT)
        self.ca = self.root / 'mitm/mitmproxy-ca-cert.pem'
        until = time.monotonic() + 30
        while not self.ca.exists():
            assert proc.poll() is None and time.monotonic() < until, 'mitmdump did not start'
            time.sleep(0.2)
        time.sleep(1)
        return proc

    def env(self, home: Path, extra: dict[str, str]) -> dict[str, str]:
        """The cell's agent environment (run_gate.SHELL_ENV and native/sandbox/child.c build_env) on host paths."""
        ca, w2 = str(self.ca), self.root / 'w2'
        env = {**SHELL_ENV, 'HOME': str(home), 'PATH': f'{self.root / "bin"}:/usr/bin:/bin',
               'GIT_CONFIG_GLOBAL': str(w2 / 'gitconfig'), 'W2_GIT_PLACEHOLDER_FILE': str(w2 / 'placeholders/git'),
               'NPM_CONFIG_USERCONFIG': str(w2 / 'npmrc'), 'NPM_CONFIG_CACHE': f'{home}/npm-cache',
               'UV_CACHE_DIR': f'{home}/uv-cache',
               'HTTPS_PROXY': 'http://127.0.0.1:18080', 'HTTP_PROXY': 'http://127.0.0.1:18080', 'NO_PROXY': 'localhost,127.0.0.1',
               'NODE_EXTRA_CA_CERTS': ca, 'SSL_CERT_FILE': ca, 'GIT_SSL_CAINFO': ca, 'PIP_CERT': ca,
               'REQUESTS_CA_BUNDLE': ca, 'CURL_CA_BUNDLE': ca,
               # host only: pytest is a user-site install, found through the real user's base, not the fresh HOME
               'PYTHONUSERBASE': str(USER_HOME / '.local')}
        env.update(extra)
        return env

    def flows(self, label: str) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        rows = [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]
        return [r for r in rows if r['op'] == label]

    def close(self) -> None:
        self.proxy.terminate()
        try:
            self.proxy.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proxy.kill()
        self.subs.unlink(missing_ok=True)
        shutil.copyfile(self.log, self.run / 'proxy.jsonl') if self.log.exists() else None


def run_traced(rig: Rig, label: str, argv: list[str], env: dict[str, str], cwd: Path, timeout: float,
               drive: Callable[[Terminal], dict[str, Any]] | None = None) -> dict[str, Any]:
    """One traced run on a pty: the label routes the proxy log, strace writes the label's file."""
    for path in SCRATCH:
        shutil.rmtree(path, ignore_errors=True) if os.path.isdir(path) else Path(path).unlink(missing_ok=True)
    rig.label.write_text(label)
    trace = rig.root / 'strace' / f'{label}.strace'
    start, t0 = utc(), time.monotonic()
    term = Terminal(['/usr/bin/env', '-i', '-C', str(cwd), *[f'{k}={v}' for k, v in env.items()],
                     *STRACE, '-o', str(trace), '--', *argv])
    entry: dict[str, Any] = {'label': label, 'argv': argv, 'started_utc': start}
    if drive is not None:
        entry['drive'] = drive(term)
    term.read_until(b'\x00never', max(1.0, timeout - (time.monotonic() - t0)))
    if term.proc.poll() is None:
        os.killpg(term.proc.pid, signal.SIGKILL)
        entry['killed'] = True
    entry['exit'] = term.proc.wait(timeout=30)
    entry['seconds'] = round(time.monotonic() - t0, 1)
    rig.label.write_text('')
    (rig.run / 'outputs').mkdir(exist_ok=True)
    (rig.run / 'outputs' / f'{label}.txt').write_bytes(term.output)
    entry['output'] = term.output.decode('utf-8', 'replace')
    return entry


def drive_tui(agent: str, prompt: str) -> Callable[[Terminal], dict[str, Any]]:
    """Interactive run as a user: Claude Code's first-start screens (gate_items.FIRST_START), the prompt, the reply,
    then the agent's own exit (Claude Code /exit, Pi Ctrl-D on an empty editor, OpenCode /exit then Ctrl-C twice)."""
    def drive(term: Terminal) -> dict[str, Any]:
        rec: dict[str, Any] = {'answered': [], 'reply_seen': False}
        pos, until = 0, time.monotonic() + 90
        while time.monotonic() < until:
            term.read_until(b'\x00never', 2.0, len(term.output))
            text = screen(term.output[pos:])
            hit = next(((p, k) for p, k in FIRST_START if p in text and p not in rec['answered']), None)
            if agent == 'claude' and hit is not None:
                rec['answered'].append(hit[0])
                for key in hit[1]:
                    time.sleep(0.5)
                    term.type(key)
                pos = len(term.output)
            elif agent != 'claude' or MAIN_SCREEN in text:
                break
        time.sleep(3)
        asked = len(term.output)
        term.type(prompt.encode())
        time.sleep(0.5)
        term.type(b'\r')
        until = time.monotonic() + 180
        while time.monotonic() < until and not rec['reply_seen']:
            term.read_until(b'\x00never', 2.0, len(term.output))
            rec['reply_seen'] = REPLY.search(screen(term.output[asked:])) is not None
        time.sleep(3)
        for keys in ([b'/exit', b'\r'] if agent == 'claude' else [b'\x04'] if agent == 'pi'
                     else [b'/exit', b'\r', b'\x03', b'\x03']):
            if term.proc.poll() is not None:
                break
            term.type(keys)
            time.sleep(1.5)
        return rec
    return drive


def judge(op: str, entry: dict[str, Any], flows: list[dict[str, Any]], work: Path) -> tuple[bool, str]:
    """The expected result of allowlist-derivation.md for op, read off the workspace, the output and the proxy log."""
    text, out = screen(entry['output'].encode()), entry['output']
    model = [f for f in flows if f['host'] == 'api.anthropic.com' and f['path'].startswith('/v1/messages')]
    model_ok = bool(model) and all(f['status'] and 200 <= f['status'] < 300 for f in model)
    if op == 'a':
        return model_ok and REPLY.search(text) is not None, f'model calls {len(model)}, all 2xx {model_ok}'
    if op == 'b':
        init, test = work / 'calc/__init__.py', work / 'tests/test_calc.py'
        ok = (init.exists() and test.exists() and re.search(r'def add\(\s*a\s*,\s*b\s*,\s*c', init.read_text()) is not None)
        return bool(ok), f'files {init.exists()}/{test.exists()}'
    if op == 'c':
        marks = ['defadd', 'tests/test_calc.py', 'calc/__init__.py']
        return all(m in text for m in marks), str({m: m in text for m in marks})
    if op == 'd':
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'PYTHONUSERBASE': str(USER_HOME / '.local')}
        done = subprocess.run(['python3', '-m', 'pytest', '-q', '-p', 'no:cacheprovider'], cwd=work, env=env,
                              capture_output=True, text=True, timeout=120)
        tail = done.stdout.strip().splitlines()[-1:] or ['']
        return done.returncode == 0 and 'passed' in text, f'host rerun: {tail[0]}'
    if op == 'e':
        head = subprocess.run(['git', '-C', str(work), 'rev-parse', 'HEAD'], capture_output=True, text=True)
        push = [f for f in flows if f['host'] == 'github.com' and f['path'].endswith('/git-receive-pack')
                and f['method'] == 'POST']
        pushed = bool(push) and all(f['status'] == 200 and f['credential'] == 'placed' for f in push)
        return head.returncode == 0 and Path('/tmp/hw/.git').is_dir() and pushed, \
            f'workspace commit {head.returncode == 0}, clone {Path("/tmp/hw/.git").is_dir()}, push {pushed}'
    if op == 'f':
        have = {'pip': Path('/tmp/pip-t/six.py').exists(), 'uv': any(Path('/tmp/uvv').glob('lib/python3*/site-packages/six.py')),
                'npm': Path('/tmp/npm-t/node_modules/is-number').is_dir()}
        return all(have.values()), str(have)
    if op == 'g':
        page = [f for f in flows if f['host'] == 'example.com']
        return page_matches(text) and any(f['status'] == 200 for f in page), f'example.com requests {len(page)}'
    mcp = [f for f in flows if f['host'] == 'mcp.deepwiki.com' and f['method'] == 'POST']
    ok2 = [f for f in mcp if f['status'] and 200 <= f['status'] < 300]
    return len(ok2) >= 2 and re.search(r'\d', out) is not None, f'MCP POST {len(mcp)}, 2xx {len(ok2)}'


def github_push_seen(rig: Rig, since: str) -> bool:
    """The (e) push checked independently on GitHub: the newest commit touching w2-derive-log.txt is ours and new."""
    req = urllib.request.Request(f'https://api.github.com/repos/{TEST_REPO}/commits?path=w2-derive-log.txt&per_page=1',
                                 headers={'Authorization': f'Bearer {rig.github_token}', 'User-Agent': 'w2-derive'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        commits = json.load(resp)
    return bool(commits) and commits[0]['commit']['author']['name'] == 'w2-derive' \
        and commits[0]['commit']['author']['date'] >= since[:19]


def agent_part(rig: Rig, agent: Agent, ops: dict[str, str]) -> list[dict[str, Any]]:
    home, work = rig.root / 'homes' / agent.name, rig.root / 'work' / agent.name
    home.mkdir()
    work.mkdir()
    entries = []
    for op, prompt in ops.items():
        label = f'{agent.name}-{op}'
        if op in agent.not_applicable:
            entries.append({'label': label, 'not_applicable': True})
            continue
        extra = dict(agent.env)
        if op == 'h' and agent.name == 'opencode':
            extra['OPENCODE_CONFIG_CONTENT'] = json.dumps(
                {'mcp': {'deepwiki': {'type': 'remote', 'url': 'https://mcp.deepwiki.com/mcp'}}})
        if agent.name == 'pi':
            config = home / '.pi/agent/mcp.json'
            config.parent.mkdir(parents=True, exist_ok=True)
            config.write_text(json.dumps({'mcpServers': {'deepwiki': {'url': 'https://mcp.deepwiki.com/mcp'}}})) \
                if op == 'h' else config.unlink(missing_ok=True)
        argv = agent.oneshot(prompt) + (['--mcp-config', MCP_CONFIG] if op == 'h' and agent.name == 'claude' else [])
        entry = run_traced(rig, label, argv, rig.env(home, extra), work, 600)
        entry['ok'], entry['observed'] = judge(op, entry, rig.flows(label), work)
        if op == 'e':
            entry['github_commit'] = github_push_seen(rig, entry['started_utc'])
            entry['ok'] = entry['ok'] and entry['github_commit']
        entries.append(entry)
        print(f"{label}: ok={entry['ok']} exit={entry['exit']} {entry['seconds']}s {entry['observed']}", flush=True)
    label = f'{agent.name}-a-interactive'
    (home / '.pi/agent/mcp.json').unlink(missing_ok=True)       # (h)'s MCP server is not part of the interactive run
    entry = run_traced(rig, label, agent.interactive, rig.env(home, dict(agent.env)), work, 420,
                       drive_tui(agent.name, ops['a']))
    model = [f for f in rig.flows(label) if f['host'] == 'api.anthropic.com' and f['path'].startswith('/v1/messages')]
    entry['ok'] = entry['drive']['reply_seen'] and bool(model) and all(200 <= (f['status'] or 0) < 300 for f in model)
    entry['observed'] = f"model calls {len(model)}, reply on screen {entry['drive']['reply_seen']}, exit {entry['exit']}"
    entries.append(entry)
    print(f"{label}: ok={entry['ok']} {entry['observed']}", flush=True)
    return entries


def gate_part(rig: Rig) -> list[dict[str, Any]]:
    """The gate's ten commands typed into an interactive bash as run_gate does; the npm command's npm-cli path is the
    seed's (/usr/lib/node_modules/npm), here the host node's own npm."""
    entries = []
    for item in ITEMS:
        label = f'gate-{item.name}'
        home = rig.root / 'homes' / label
        home.mkdir()
        command = item.command.replace('/usr/lib/node_modules/npm/bin/npm-cli.js',
                                       str(NODE_BIN.parent / 'lib/node_modules/npm/bin/npm-cli.js'))

        def drive(term: Terminal, command: str = command, item: Any = item) -> dict[str, Any]:
            rec: dict[str, Any] = {'ready': term.read_until(PROMPT_MARK, 60)}
            mark = len(term.output)
            term.type(command.encode() + b'; echo W2_ITEM_EXIT=$?\r')
            if item.drive is not None:
                rec['drive'] = item.drive(term, mark)
            rec['finished'] = term.read_until(ITEM_EXIT, item.timeout, mark)
            found = ITEM_EXIT.search(term.output, mark)
            rec['exit'] = int(found.group(1)) if found else None
            rec['tail'] = term.output[mark:][-12000:].decode('utf-8', 'replace')
            term.type(b'exit\r')
            return rec
        entry = run_traced(rig, label, ['/bin/bash', '--norc', '--noprofile', '-i'], rig.env(home, {}), home,
                           item.timeout + 120, drive)
        entry['ok'], entry['observed'] = item.judge(rig.flows(label), entry['drive'].get('tail', ''))
        entry['ok'] = entry['ok'] and entry['drive'].get('exit') == 0 and \
            (item.drive is None or entry['drive'].get('drive', {}).get('ok', False))
        entries.append(entry)
        print(f"{label}: ok={entry['ok']} {entry['observed']}", flush=True)
    return entries


def helper_part(rig: Rig, frontend: str) -> list[dict[str, Any]]:
    """The frontend and the relay as their own processes, out of their host tests under strace; only the process that
    executed the helper's binary and its descendants count (the test harness and pytest do not). The Go frontend is
    built before tracing (gate_seed.go_build's flags) and handed to the test by W2_FRONTEND_GO_BIN."""
    entries = []
    env = dict(os.environ, W2_FRONTEND_IMPL=frontend)
    if frontend == 'go':
        env['W2_FRONTEND_GO_BIN'] = str(rig.root / 'bin/engine-frontend')
        subprocess.run([str(GO), '-C', str(ENGINE / 'frontend-go'), 'build', '-trimpath', '-buildvcs=false', '-o',
                        env['W2_FRONTEND_GO_BIN'], '.'], env=dict(env, CGO_ENABLED='0', GOTOOLCHAIN='local'), check=True)
    # the Python frontend by its script in argv; the Go frontend and the relay by the executed path (the relay's name
    # is also in make's and cc's argv)
    for label, test, marker in (('helper-frontend', 'tests/test_frontend.py',
                                 'path:/engine-frontend' if frontend == 'go' else 'argv:/frontend/engine_frontend.py'),
                                ('helper-relay', 'tests/test_relay.py', 'path:/w2-relay')):
        trace = rig.root / 'strace' / f'{label}.strace'
        # the unit tests' own interpreter (pytest is not in the frontend venv; the tests start the venv's python
        # for the frontend themselves)
        done = subprocess.run([*STRACE, '-o', str(trace), '--', sys.executable, '-m', 'pytest', '-q',
                               '-p', 'no:cacheprovider', test], cwd=ENGINE, env=env, capture_output=True, text=True,
                              timeout=900)
        entries.append({'label': label, 'exit': done.returncode, 'marker': marker,
                        'tail': done.stdout.strip().splitlines()[-1:], 'ok': done.returncode == 0})
        print(f"{label}: exit={done.returncode} {entries[-1]['tail']}", flush=True)
    return entries


def syscalls(trace: Path, marker: str | None = None) -> tuple[set[str], set[str]]:
    """Syscall names in a trace and the files opened or executed; with marker ('argv:<text>' found in the argv, or
    'path:<suffix>' ending the executed path), only the processes that executed that binary, from that execve on,
    and their descendants. A multi-threaded tracee's execve is often split (<unfinished ...> then resumed), so the
    execve line counts unless it shows a failure itself."""
    names, files = set(), set()
    keep: set[str] | None = None if marker is None else set()
    field, _, needle = (marker or ':').partition(':')
    with open(trace, errors='replace') as f:
        for line in f:
            if keep is not None:
                m = EXECVE.match(line)
                if m and ') = -1' not in line and (needle in m.group(3) if field == 'argv'
                                                    else m.group(2).endswith(needle)):
                    keep.add(m.group(1))
                s = SPAWN.match(line)
                if s and s.group(1) in keep:
                    keep.add(s.group(3))
            m = LINE.match(line)
            if not m or (keep is not None and m.group(1) not in keep):
                continue
            names.add(m.group(2) or m.group(3))
            o = OPENED.match(line)
            if o:
                files.add(o.group(1))
    return names, files


def summarize(rig: Rig, entries: list[dict[str, Any]]) -> dict[str, Any]:
    per_run: dict[str, list[str]] = {}
    (rig.run / 'files').mkdir(exist_ok=True)
    for e in entries:
        trace = rig.root / 'strace' / f"{e['label']}.strace"
        if not trace.exists():
            continue
        names, files = syscalls(trace, e.get('marker'))
        per_run[e['label']] = sorted(names)
        (rig.run / 'files' / f"{e['label']}.txt").write_text('\n'.join(sorted(files)) + '\n')
        e['syscall_count'] = len(names)
    sources = {'agent-claude': 'claude-', 'agent-pi': 'pi-', 'agent-opencode': 'opencode-', 'gate-commands': 'gate-',
               'frontend': 'helper-frontend', 'relay': 'helper-relay'}
    by_source = {s: sorted(set().union(*[set(v) for k, v in per_run.items() if k.startswith(p)] or [set()]))
                 for s, p in sources.items()}
    by_source['startup-code (read)'] = STARTUP_READ
    union = set().union(*map(set, by_source.values()))
    return {'per_run': per_run, 'per_source': by_source, 'union': sorted(union),
            'compiler_refused_seen': sorted(union & COMPILER_REFUSED),
            'privileged_seen': sorted(n for n in union if PRIVILEGED.match(n)),
            'unnamed_seen': sorted(n for n in union if n.startswith('syscall_')),
            'candidate': sorted(n for n in union if n not in COMPILER_REFUSED and not PRIVILEGED.match(n))}


def versions() -> dict[str, str]:
    def out(argv: list[str]) -> str:
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=60).stdout.strip().splitlines()[0]
        except (OSError, IndexError, subprocess.TimeoutExpired):
            return 'unavailable'
    return {'kernel': os.uname().release, 'strace': out(['/usr/bin/strace', '-V']), 'node': out([str(NODE_BIN / 'node'), '--version']),
            'claude': out([str(CLAUDE), '--version']), 'pi': out([str(NODE_BIN / 'node'), str(AGENTS / 'pi/node_modules/.bin/pi'), '--version']),
            'opencode': out([str(AGENTS / 'opencode/node_modules/.bin/opencode'), '--version']),
            'mitmdump': out([str(VENV / 'bin/mitmdump'), '--version']), 'python3': out(['python3', '--version']),
            'go': out([str(GO), 'version'])}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--agents', default='claude,pi,opencode')
    parser.add_argument('--parts', default='agents,gate,helpers')
    parser.add_argument('--ops', default='abcdefgh')
    parser.add_argument('--frontend', choices=FRONTENDS, default='go', help='the frontend the helpers part measures')
    args = parser.parse_args()
    assert os.geteuid() != 0, 'run as the ordinary user: the agents run as they would for a user'
    run = args.run_dir.resolve()
    assert (run / 'README.md').exists(), 'write the run README (purpose, command, criteria) first'
    ops = {k: v for k, v in derivation_set().items() if k in args.ops}
    parts = args.parts.split(',')
    results: dict[str, Any] = {'started_utc': utc(), 'versions': versions(), 'parts': parts,
                               'frontend': args.frontend, 'entries': []}
    rig = Rig(run)
    try:
        if 'agents' in parts:
            table = agents(rig.root / 'bin')
            for name in args.agents.split(','):
                results['entries'] += agent_part(rig, table[name], ops)
        if 'gate' in parts:
            results['entries'] += gate_part(rig)
        if 'helpers' in parts:
            results['entries'] += helper_part(rig, args.frontend)
    finally:
        rig.close()
    results['syscalls'] = summarize(rig, results['entries'])
    for e in results['entries']:
        e.pop('output', None)
        if 'drive' in e and isinstance(e['drive'], dict):
            e['drive'].pop('tail', None)
    for trace in (rig.root / 'strace').glob('*.strace'):
        with open(trace, 'rb') as src, gzip.open(f'{trace}.gz', 'wb') as dst:
            shutil.copyfileobj(src, dst)
        trace.unlink()
    results['raw_strace'] = str(rig.root / 'strace')
    results['finished_utc'] = utc()
    (run / 'syscalls.json').write_text(json.dumps(results.pop('syscalls'), indent=1) + '\n')
    (run / 'results.json').write_text(json.dumps(results, indent=1) + '\n')
    bad = [e['label'] for e in results['entries'] if not e.get('not_applicable') and not e.get('ok')]
    print('not as expected:', bad or 'none')
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
