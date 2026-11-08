"""The adaptation items of the block 7 gate (build plan 7.2; validation.md U-01): one execution per item, the command
typed by the runner at the cell's interactive shell through the attach window, after the entries and credential records
the item needs were set up over the management port, as a user would.

Each item's success flag is the plan's; it is read off the row's own trace (admission, decision and report per request)
and the terminal. A failure is classified as the plan says: refused by a clause, the client does not honour the proxy
variables or the CA, or an engine defect. An engine defect is never recorded as an adaptation failure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import time
from typing import Any, Callable

ANTHROPIC = 'api.anthropic.com:443'
NPM_PLACEHOLDER = 'W2-PLACEHOLDER-npm-gate'
GH_PLACEHOLDER = 'W2-PLACEHOLDER-github-gate'
GIT_PLACEHOLDER = 'W2-PLACEHOLDER-git-gate'
GITHUB_USER, TEST_REPO = 'Melclycj', 'Melclycj/Thesis-testbox'     # the user's test repository (user, 2026-10-30)
MCP_CONFIG = '{"mcpServers":{"deepwiki":{"type":"http","url":"https://mcp.deepwiki.com/mcp"}}}'
CLAUDE = "claude -p '{prompt}' --model haiku --disallowedTools WebSearch --output-format json {extra}"


@dataclass(frozen=True)
class Item:
    name: str
    goal: str
    command: str
    judge: Callable[[list[dict[str, Any]], str], tuple[bool, str]]
    setup: list[list[str]] = field(default_factory=list)     # admin argv tails, run before the row starts
    timeout: float = 180
    # An interactive program: called with the attach terminal and the output offset where the command was typed; it
    # does what a user does at that program's screens and returns its own record with an 'ok' flag.
    drive: Callable[[Any, int], dict[str, Any]] | None = None
    plan: str = 'shell-0'                                    # the launch plan of the row the item runs in


ANSI = re.compile(rb'\x1b\[[0-9;?<>=]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][0-9A-Za-z]|\x1b[=>78]')


def screen(output: bytes) -> str:
    """The terminal output as text without escape sequences or whitespace: the TUI places words by cursor moves, so
    the spaces between them are not reliably in the byte stream."""
    return re.sub(r'\s+', '', ANSI.sub(b'', output).decode('utf-8', 'replace'))


# Claude Code's first-start screens (2.1.312, read off a host probe on 2026-10-30), each with the answer a user gives:
# the theme as offered; "use this API key?" defaults to No, so Up then Enter; the security notes; "trust this
# folder?" defaults to No, so Down then Enter. Matched on screen() text; a screen that does not appear is skipped.
FIRST_START = (('Choosethetextstyle', (b'\r',)), ('usethisAPIkey', (b'\x1b[A', b'\r')),
               ('PressEntertocontinue', (b'\r',)), ('Itrustthisfolder', (b'\x1b[B', b'\r')))
MAIN_SCREEN = 'foragents'
SAY = 'Reply with the single word READY'
REPLY = re.compile(r'(?<!singleword)READY')


def drive_claude(term: Any, mark: int) -> dict[str, Any]:
    """Interactive Claude Code at the cell's shell, as a user: answer the first-start screens, send one prompt, wait
    for the reply, /exit back to the shell. The judge reads the model call off the trace; this record is the terminal."""
    record: dict[str, Any] = {'answered': [], 'main_screen': False, 'reply_seen': False, 'exited': False}
    pos, until = mark, time.monotonic() + 120
    while time.monotonic() < until and not record['main_screen']:
        term.read_until(b'\x00never', 1.0, len(term.output))
        text = screen(term.output[pos:])
        hit = next(((p, keys) for p, keys in FIRST_START if p in text and p not in record['answered']), None)
        if hit is not None:
            record['answered'].append(hit[0])
            for key in hit[1]:
                time.sleep(0.5)
                term.type(key)
            pos = len(term.output)
        elif MAIN_SCREEN in text:
            record['main_screen'] = True
    if not record['main_screen']:
        return {**record, 'ok': False}
    time.sleep(1)
    asked = len(term.output)
    term.type(SAY.encode())
    time.sleep(0.5)
    term.type(b'\r')
    until = time.monotonic() + 120
    while time.monotonic() < until and not record['reply_seen']:
        term.read_until(b'\x00never', 1.0, len(term.output))
        record['reply_seen'] = REPLY.search(screen(term.output[asked:])) is not None
    time.sleep(1)
    term.type(b'/exit')
    time.sleep(0.5)
    term.type(b'\r')
    record['exited'] = term.read_until(ITEM_EXIT, 60, asked)
    return {**record, 'ok': record['reply_seen'] and record['exited']}


def calls(requests: list[dict[str, Any]], host: str, method: str | None = None, path: str = '') -> list[dict[str, Any]]:
    return [r for r in requests if r['host'] == host and (method is None or r['method'] == method)
            and (r['path'] or '').startswith(path)]


def ok2xx(rs: list[dict[str, Any]]) -> bool:
    return bool(rs) and all(r['decision'] == 'allow' and r['result'] == 1 and r['status'] is not None
                            and 200 <= r['status'] < 300 for r in rs)


def describe(rs: list[dict[str, Any]]) -> str:
    return '; '.join(f"{r['method']} {r['host']}{r['path']} {r['decision']}/{r['credential']} -> {r['result']}:{r['status']}"
                     for r in rs) or 'no request'


def j_curl(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    m = calls(rs, 'api.anthropic.com', 'GET', '/v1/models')
    return (ok2xx(m) and all(r['credential'] == 'placed' for r in m) and 'W2_HTTP=200' in out), describe(m)


def j_git_clone(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    refs = calls(rs, 'github.com', 'GET', '/octocat/Hello-World.git/info/refs')
    pack = calls(rs, 'github.com', 'POST', '/octocat/Hello-World.git/git-upload-pack')
    return ok2xx(refs) and ok2xx(pack), describe(refs + pack)


def j_git_push(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    """git sends no credential first and takes GitHub's 401 as the challenge, then asks the credential helper (the
    placeholder pair) and retries; the engine writes the whole Basic value from the registered user and password
    (account git, 648d60f2 4.3). The push itself is the
    POST to git-receive-pack, which must be replaced and 2xx; every replaced request must be 2xx."""
    repo = calls(rs, 'github.com', path=f'/{TEST_REPO}.git/')
    push = [r for r in repo if r['method'] == 'POST' and r['path'].endswith('/git-receive-pack')]
    placed = [r for r in repo if r['credential'] == 'placed']
    challenges = [r for r in repo if r['status'] == 401]
    return (ok2xx(push) and all(r['credential'] == 'placed' and r['account'] == 'git' for r in push)
            and ok2xx(placed) and all(r['credential'] == 'none' for r in challenges)
            and 'rejected' not in out), describe(repo)


def j_pip(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    index, files = calls(rs, 'pypi.org', 'GET', '/simple/six'), calls(rs, 'files.pythonhosted.org', 'GET')
    return ok2xx(index) and ok2xx(files), describe(index + files)


def j_npm(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    reg = calls(rs, 'registry.npmjs.org', 'GET')
    placed = reg and all(r['credential'] == 'placed' and r['account'] == 'npm' for r in reg)
    return ok2xx(reg) and bool(placed) and NPM_PLACEHOLDER not in out, describe(reg)


def j_webfetch(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    page = calls(rs, 'example.com', 'GET')
    return ok2xx(page) and 'Example Domain' in out and '"is_error":false' in out.replace(' ', ''), describe(page)


def j_mcp(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    """The MCP session as the protocol runs it: Claude Code first tries the newer protocol (a POST carrying mcp-method).
    A server that does not speak it answers that one probe 400 (this server did, with or without the engine: host
    control through plain mitmproxy, 2026-10-30), and the client initializes on the legacy protocol, whose GET is the
    server-notification stream, cut when the row closes, so it has no report. A server that speaks it answers 2xx and the
    session stays on it (this server since 2026-11-03). Every other request must be an allowed remote 2xx, at least the
    initialize and one tool call."""
    mcp = calls(rs, 'mcp.deepwiki.com', path='/mcp')
    probe = [r for r in mcp if r['method'] == 'POST' and 'mcp-method' in (r['header_names'] or [])
             and r['decision'] == 'allow' and r['result'] == 1 and r['status'] == 400]
    stream = [r for r in mcp if r['method'] == 'GET' and r['decision'] == 'allow' and r['result'] is None]
    rest = [r for r in mcp if r not in probe and r not in stream]
    posts = [r for r in rest if r['method'] == 'POST']
    return (len(probe) <= 1 and len(stream) <= 1 and len(posts) >= 2 and ok2xx(rest)
            and '"is_error":false' in out.replace(' ', '')), describe(mcp)


def j_gh(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    user = calls(rs, 'api.github.com', 'GET', '/user')
    return ok2xx(user) and all(r['credential'] == 'placed' for r in user), describe(user)


def j_claude_interactive(rs: list[dict[str, Any]], out: str) -> tuple[bool, str]:
    """Every model call of the interactive session is replaced with the gate account's key and 2xx; the terminal half
    (the reply on screen, /exit back to the shell) is the drive record's 'ok'."""
    model = calls(rs, 'api.anthropic.com', 'POST', '/v1/messages')
    return ok2xx(model) and all(r['credential'] == 'placed' and r['account'] == 'gate' for r in model), describe(model)


ITEMS = [
    Item('curl', 'curl with the placeholder header to an account destination: replaced, 2xx',
         "curl -sS -o /tmp/models.json -w 'W2_HTTP=%{http_code}\\n' -H \"x-api-key: $ANTHROPIC_API_KEY\" "
         "-H 'anthropic-version: 2023-06-01' https://api.anthropic.com/v1/models", j_curl),
    Item('git-clone', 'git clone of a public repository: 2xx',
         'git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hw && git -C /tmp/hw log --oneline -1',
         j_git_clone,
         setup=[['entry', 'put', 'work0', 'exact', 'allow', 'github.com:443', '--method', 'GET', '--method', 'POST',
                 '--prefix', '/octocat/Hello-World.git/']]),
    Item('git-push', "git push to the user's test repository: the placeholder credential is replaced, 2xx",
         f'git clone https://github.com/{TEST_REPO}.git /tmp/tb && cd /tmp/tb '
         "&& printf 'w2 gate push %(%Y-%m-%dT%H:%M:%SZ)T\\n' -1 >> w2-gate-log.txt && git add w2-gate-log.txt "
         '&& git -c user.name=w2-gate -c user.email=w2-gate@users.noreply.github.com commit -q -m '
         "'w2 gate: push through the engine' && git push origin HEAD", j_git_push,
         setup=[['cred', 'put', 'github.com:443', 'git', 'basic', '--truth-env', 'W2_GIT_USER',
                 '--truth-b-env', 'W2_GH_TRUTH'],
                ['entry', 'put', 'work0', 'exact', 'allow', 'github.com:443', '--method', 'GET', '--method', 'POST',
                 '--prefix', '/octocat/Hello-World.git/', '--prefix', f'/{TEST_REPO}.git/', '--account', 'git']]),
    Item('pip', 'pip installs a small package: SSL_CERT_FILE/PIP_CERT honoured, 2xx',
         'python3.12 -m pip install --no-cache-dir --disable-pip-version-check --target /tmp/pip-t six && '
         'PYTHONPATH=/tmp/pip-t python3.12 -c "import six; print(six.__version__)"', j_pip),
    Item('uv', 'uv installs a small package: SSL_CERT_FILE honoured, 2xx',
         'uv venv /tmp/uvv --python /usr/bin/python3.12 && uv pip install --python /tmp/uvv/bin/python six', j_pip),
    Item('npm', 'npm installs a small package: the .npmrc placeholder token is replaced, never sent as is',
         'node /usr/lib/node_modules/npm/bin/npm-cli.js install --no-audit --no-fund --prefix /tmp/npm-t is-number '
         "&& node -e \"console.log(require('/tmp/npm-t/node_modules/is-number')(5))\"", j_npm,
         setup=[['cred', 'put', 'registry.npmjs.org:443', 'npm', 'bearer', '--truth-env', 'W2_NPM_TRUTH'],
                ['entry', 'put', 'work0', 'exact', 'allow', 'registry.npmjs.org:443', '--method', 'GET',
                 '--account', 'npm']]),
    Item('webfetch', "Claude Code's WebFetch fetches a public page: the fallback entry lets the GET through, 2xx",
         CLAUDE.format(prompt='Fetch https://example.com/ with the WebFetch tool and reply with the exact text of its '
                              'h1 heading and nothing else.', extra='--allowedTools WebFetch'), j_webfetch),
    Item('mcp', "Claude Code's MCP HTTP client reaches a test server through the proxy variables: 2xx",
         CLAUDE.format(prompt='Call the deepwiki read_wiki_structure tool for the repository facebook/react and reply '
                              'with how many top-level topics it lists, as a number only.',
                       extra=f"--mcp-config '{MCP_CONFIG}' --allowedTools mcp__deepwiki__read_wiki_structure"), j_mcp,
         setup=[['entry', 'put', 'work0', 'exact', 'allow', 'mcp.deepwiki.com:443', '--method', 'POST', '--method', 'GET',
                 '--method', 'DELETE', '--prefix', '/mcp']], timeout=300),
    Item('gh', '`gh api user`: the placeholder token is replaced, 2xx', 'gh api user --jq .login', j_gh,
         setup=[['cred', 'put', 'api.github.com:443', 'gh', 'bearer', '--truth-env', 'W2_GH_TRUTH'],
                ['entry', 'put', 'work0', 'exact', 'allow', 'api.github.com:443', '--method', 'GET', '--account', 'gh']]),
    Item('claude-interactive', 'interactive Claude Code: first-start screens answered in the attach window, one prompt, '
         'the model call replaced (account gate) and 2xx, READY on screen, /exit back to the shell',
         'claude --model haiku --disallowedTools WebSearch', j_claude_interactive, timeout=300, drive=drive_claude),
]
ITEM_EXIT = re.compile(rb'W2_ITEM_EXIT=(\d+)')
