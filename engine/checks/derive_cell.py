"""The derivation set in the cell (build plan 7.4 step 5; allowlist-derivation.md): the evidence that the deployed
workload list is enough for this set. Each agent runs every item of the set once, one execution per item, typed at the
cell's shell through the attach window as the gate's 7.2 items are (run_gate.run_item); then once interactively for (a).
The agents, prompts and expected results are the host derivation's (checks/derive_host.py); here they are read off the
row's own trace, the shell's output after the command (and checks typed in the same row for what lands in the cell's
/tmp), the workspace on the host, and GitHub for the push.

Every agent starts on an empty workspace (cleared on the host before its first item); within an agent the items run in
order on the same workspace, as on the host.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
from typing import Any, Callable
import urllib.request

from derive_host import MODEL, REPLY, derivation_set, drive_tui, page_matches
from gate_items import ITEMS, MCP_CONFIG, TEST_REPO, Item, calls, describe, ok2xx, screen

AGENTS = ('claude', 'pi', 'opencode')
# each agent's own switches (derive_host.agents), registered in its runtime: the runtime notes' second section
AGENT_ENV = {'claude': {'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_AUTOUPDATER': '1'},
             'pi': {'PI_SKIP_VERSION_CHECK': '1', 'PI_TELEMETRY': '0'},
             'opencode': {'OPENCODE_DISABLE_AUTOUPDATE': '1', 'OPENCODE_DISABLE_LSP_DOWNLOAD': '1'}}
NOT_APPLICABLE = {'pi': {'g'}}          # Pi has no web fetch tool (allowlist-derivation.md)
INTERACTIVE = {'claude': 'claude --model haiku --disallowedTools WebSearch', 'pi': f'pi --model anthropic/{MODEL}',
               'opencode': f'opencode -m anthropic/{MODEL}'}
PI_MCP = json.dumps({'mcpServers': {'deepwiki': {'url': 'https://mcp.deepwiki.com/mcp'}}})
OPENCODE_MCP = json.dumps({'mcp': {'deepwiki': {'type': 'remote', 'url': 'https://mcp.deepwiki.com/mcp'}}})
# the entries and credential records of the 7.2 items the set also needs (git push, npm, MCP); run once, first
SETUP = [tail for item in ITEMS if item.name in ('git-push', 'npm', 'mcp') for tail in item.setup]
# what the shell checks in the cell after the agent, for what lands in the row's own /tmp; each prints W2_<NAME>
CHECKS = {'e': {'HW_CLONED': 'test -d /tmp/hw/.git'},
          'f': {'PIP_OK': 'test -f /tmp/pip-t/six.py',
                'UV_OK': 'ls /tmp/uvv/lib/python3*/site-packages/six.py',
                'NPM_OK': 'test -d /tmp/npm-t/node_modules/is-number'}}


def oneshot(agent: str, op: str, prompt: str) -> str:
    """The agent's one-shot run of one item at the cell's shell, as derive_host.agents runs it on the host."""
    q = shlex.quote(prompt)
    if agent == 'claude':
        mcp = f' --mcp-config {shlex.quote(MCP_CONFIG)}' if op == 'h' else ''
        return f'claude -p {q} --model haiku --disallowedTools WebSearch --permission-mode bypassPermissions{mcp}'
    if agent == 'pi':
        mcp = (f"mkdir -p ~/.pi/agent && printf '%s' {shlex.quote(PI_MCP)} > ~/.pi/agent/mcp.json && "
               if op == 'h' else '')
        return f'{mcp}pi -p {q} --model anthropic/{MODEL}'
    mcp = f'OPENCODE_CONFIG_CONTENT={shlex.quote(OPENCODE_MCP)} ' if op == 'h' else ''
    return f'{mcp}opencode run {q} -m anthropic/{MODEL} --auto'


def command(agent: str, op: str, prompt: str) -> str:
    """A marker the shell prints (so the judges read only what follows the echoed command line), the run, the checks;
    the item's exit is the agent's."""
    checks = ''.join(f"{test} >/dev/null 2>&1 && printf 'W2_%s\\n' {name}; " for name, test in CHECKS.get(op, {}).items())
    return f"printf 'W2_%s\\n' BEGIN; {oneshot(agent, op, prompt)}; s=$?; {checks}(exit $s)"


def after(out: str) -> str:
    at = out.find('W2_BEGIN')
    return out[at + len('W2_BEGIN'):] if at >= 0 else ''


def model_ok(rs: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
    """Every model request carried the gate account's key, placed by the engine; every one that completed returned 2xx,
    and at least one did. A request without a completion is one the client dropped (OpenCode's small parallel request
    when it exits after answering), not a refusal: refusals are decisions, and none of these is one."""
    m = calls(rs, 'api.anthropic.com', 'POST', '/v1/messages')
    done = [r for r in m if r['status'] is not None]
    return (bool(done) and ok2xx(done) and all(r['decision'] == 'allow' and r['credential'] == 'placed'
                                              and r['account'] == 'gate' for r in m)), m


def judge(op: str, work: Path, as_user: list[str]) -> Callable[[list[dict[str, Any]], str], tuple[bool, str]]:
    """allowlist-derivation.md's expected result of op (derive_host.judge), on the cell's evidence."""
    def j(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
        text, raw = screen(after(out).encode()), after(out)
        ok, m = model_ok(rs)
        if op == 'a':
            return ok and REPLY.search(text) is not None, f'model {describe(m)}'
        if op == 'b':
            init, test = work / 'calc/__init__.py', work / 'tests/test_calc.py'
            three = init.exists() and re.search(r'def add\(\s*a\s*,\s*b\s*,\s*c', init.read_text()) is not None
            return ok and init.exists() and test.exists() and three, f'files {init.exists()}/{test.exists()}, c {three}'
        if op == 'c':
            marks = {mark: mark in text for mark in ('defadd', 'tests/test_calc.py', 'calc/__init__.py')}
            return ok and all(marks.values()), str(marks)
        if op == 'd':
            rerun = subprocess.run(as_user + ['/usr/bin/env', 'PYTHONUSERBASE=/home/jerry/.local',
                                              'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3', '-m', 'pytest', '-q',
                                              '-p', 'no:cacheprovider'], cwd=work, capture_output=True, text=True,
                                   timeout=120)
            tail = (rerun.stdout.strip().splitlines() or [''])[-1]
            return ok and rerun.returncode == 0 and 'passed' in text, f'host rerun: {tail}'
        if op == 'e':
            head = subprocess.run(as_user + ['/usr/bin/git', '-C', str(work), 'rev-parse', 'HEAD'], capture_output=True,
                                  text=True)
            push = [r for r in calls(rs, 'github.com', 'POST', f'/{TEST_REPO}.git/')
                    if r['path'].endswith('/git-receive-pack')]
            pushed = ok2xx(push) and all(r['credential'] == 'placed' and r['account'] == 'git' for r in push)
            cloned = 'W2_HW_CLONED' in raw
            return ok and head.returncode == 0 and cloned and pushed, \
                f'workspace commit {head.returncode == 0}, clone {cloned}, push {describe(push)}'
        if op == 'f':
            have = {name: f'W2_{name}' in raw for name in CHECKS['f']}
            return ok and all(have.values()), str(have)
        if op == 'g':
            page = calls(rs, 'example.com', 'GET')
            return ok and page_matches(text) and ok2xx(page), f'example.com {describe(page)}'
        mcp = [r for r in calls(rs, 'mcp.deepwiki.com', 'POST', '/mcp')
               if r['status'] is not None and 200 <= r['status'] < 300]
        return ok and len(mcp) >= 2 and re.search(r'\d', raw) is not None, f'MCP POST 2xx {len(mcp)}'
    return j


def interactive_drive(agent: str, prompt: str) -> Callable[[Any, int], dict[str, Any]]:
    """derive_host.drive_tui after the program has drawn its first screen and gone quiet (a TUI that reads the terminal
    later would lose keys typed earlier); ok is the reply on screen."""
    def drive(term: Any, mark: int) -> dict[str, Any]:
        last, still = len(term.output), 0
        for _ in range(60):
            term.read_until(b'\x00never', 1.0, len(term.output))
            still = still + 1 if len(term.output) == last else 0
            last = len(term.output)
            if still >= 2 and last - mark > 200:
                break
        rec = drive_tui(agent, prompt)(term)
        return {**rec, 'ok': rec['reply_seen']}
    return drive


def items(agents: tuple[str, ...], work: Path, as_user: list[str], names: tuple[str, ...] = ()) -> list[Item]:
    """One plan per agent (<agent>-shell-0), only the named items if names are given; the set's setup rides on the
    first item that runs. One engine run starts at most as many rows as the deployment's uid range holds (uids are
    not reused within a run, 6.2 uid row): 16 in the gate's deployment, so one agent per run."""
    ops, out = derivation_set(), []
    for agent in agents:
        for op, prompt in ops.items():
            if op in NOT_APPLICABLE.get(agent, ()):
                continue
            out.append(Item(f'{agent}-{op}', f'derivation ({op}) for {agent}: allowlist-derivation.md',
                            command(agent, op, prompt), judge(op, work, as_user), timeout=600,
                            plan=f'{agent}-shell-0'))
        def j_tui(rs: list[dict[str, Any]], out_: str) -> tuple[bool, str]:
            ok, m = model_ok(rs)
            return ok, f'model {describe(m)}'
        out.append(Item(f'{agent}-a-interactive', f'derivation (a) interactively for {agent}',
                        f"{INTERACTIVE[agent]}; printf 'W2_TUI_EXIT=%s\\n' $?; true", j_tui, timeout=420,
                        drive=interactive_drive(agent, ops['a']), plan=f'{agent}-shell-0'))
    out = [i for i in out if not names or i.name in names]
    if out:
        out[0] = replace(out[0], setup=SETUP)
    return out


def clear_workspace(work: Path) -> None:
    """The host user empties the workspace before an agent's first item; the root directory stays (its identity is
    the workspace's, K-20)."""
    for child in work.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def github_check(entries: list[dict[str, Any]], token: str) -> None:
    """(e) on GitHub as well: a w2-derive commit on w2-derive-log.txt inside the item's run, on the test repository."""
    if not token:
        return
    req = urllib.request.Request(f'https://api.github.com/repos/{TEST_REPO}/commits?path=w2-derive-log.txt&per_page=20',
                                 headers={'Authorization': f'Bearer {token}', 'User-Agent': 'w2-derive'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        commits = json.load(resp)
    dates = [datetime.fromisoformat(c['commit']['author']['date'].replace('Z', '+00:00'))
             for c in commits if c['commit']['author']['name'] == 'w2-derive']
    for entry in entries:
        if entry['name'].endswith('-e'):
            start = datetime.fromisoformat(entry['started_at_utc']).replace(microsecond=0)
            end = datetime.fromisoformat(entry['finished_at_utc'])
            entry['github_commit'] = any(start <= d <= end for d in dates)
            entry['ok'] = entry['ok'] and entry['github_commit']
