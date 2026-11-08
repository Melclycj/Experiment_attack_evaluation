"""The runtime seed for the block 7 gate (build plan 7.1, 7.2) and the deployment's workload seccomp policy.

The seed is what the catalog requires (catalog.c tree_check): root-owned, directories 0755, files 0444 or 0555 with one
link each, symlinks resolving inside, every entry in the component manifest with its digest. Programs come from the
host (Claude Code, bash, Python and the frontend venv, git, curl, node and npm) or, for uv and gh, from their official
release archives fetched into a cache directory of their own; the libraries they need are added by ldd closure.

The frontend is one of FRONTENDS. 'go' (the default): the static binary built from frontend-go/ (go_build); Python
then enters the seed only for 7.2, whose pip and uv items run it, with pip as its one site package. 'python':
frontend/engine_frontend.py on Python 3.12 with the whole frontend venv as site packages, as in engine-v2.

The experiment seed (deployment.md section 8; build plan 7.4 step 5) is the 7.2 seed plus the other two agents and the
work tools of the derivation set: Pi as npm installed it (allowlist-derivation.md) on the node it needs, OpenCode's one
program, the programs of coreutils, grep, findutils, sed and diffutils as dpkg lists them, pytest, and the static
ripgrep and fd builds Pi would otherwise fetch on first start. An ELF that is not x86-64 (a prebuilt for another
architecture inside an npm package) stays out: the catalog refuses it (catalog.c validate_elf).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tarfile
import time
from typing import Any, Callable
import urllib.request

ENGINE = Path(__file__).resolve().parents[1]
VENV = Path('/home/jerry/.venvs/engine-v2-frontend')
VENV_SITE = VENV / 'lib/python3.12/site-packages'
NODE_HOME = Path('/opt/node-v22.18.0-linux-x64')
CLAUDE = NODE_HOME / 'lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe'
TOOL_CACHE = Path('/var/cache/w2-gate-tools')     # release archives of uv and gh, one directory per archive
LIB_DIR = 'lib/x86_64-linux-gnu'
STDLIB_SKIP = {'__pycache__', 'test', 'idlelib', 'tkinter', 'turtledemo', 'ensurepip', 'lib2to3', 'pydoc_data',
               'config-3.12-x86_64-linux-gnu', 'site-packages', 'dist-packages'}
GO = Path('/usr/local/go/bin/go')
FRONTENDS = ('go', 'python')
# the experiment seed's additions (build plan 7.4 steps 2 and 5)
NODE22 = Path('/home/jerry/.local/opt/node-v22.23.4-linux-x64')     # Pi 1.4.0 needs node >= 22.19
AGENTS = Path('/home/jerry/.local/agents')                          # Pi and OpenCode as npm installed them
PI_CLI = '@earendil-works/pi-coding-agent/dist/bundle/cli.js'
OPENCODE = AGENTS / 'opencode/node_modules/opencode-ai/bin/opencode.exe'    # the program the npm postinstall placed
WORK_PACKAGES = ('coreutils', 'grep', 'findutils', 'sed', 'diffutils')
PYTEST = ('pytest', 'pluggy', 'iniconfig', 'packaging', 'pygments')       # pytest and what it requires on 3.12
PYTHON_PATHS = ('/home/jerry/.local/lib/python3.12/site-packages', '/usr/lib/python3/dist-packages')
X86_64 = b'\x3e\x00'                                                # ELF e_machine, little-endian
# the frontend's program and argv in the cell; child.c start_helper appends <proxy socket> <port> <ready file>
FRONTEND_ARGV = {'go': ['/runtime/frontend/engine-frontend', '--ca-dir', '/w2/ca'],
                 'python': ['/runtime/usr/bin/python3.12', '-I', '-B', '/runtime/frontend/engine_frontend.py',
                            '--ca-dir', '/w2/ca']}
# host file reads (validation.md H-23): the in-cell MCP server, mcp-go/ built static into the seed at MCP_SEED; child.c
# appends <file socket> <port> <ready file> as for the frontend. Built with -ldflags='-s -w' (the frontend is not): that
# drops the symbol table and DWARF, which only a debugger reads (Go's panic traces come from pclntab, which stays), and
# takes the binary from 9.4 to 6.4 MiB of seed (runs/20261103T201435Z-mcp-go-unit).
MCP_SEED = 'mcp/engine-mcp'
MCP_ARGV = ['/runtime/' + MCP_SEED]
MCP_BUILD = ['build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w']

# The deployment's workload policy, one list for every runtime, default deny: the union of the calls measured on the
# host for the agents, the gate's commands, the frontend, the relay and the startup code (build plan 7.4,
# allowlist-derivation.md); the file's header names the runs. The compiler still refuses io_uring, clone3 (ENOSYS),
# sysinfo, sync and the key calls, and masks CLONE_NEWUSER on clone.
WORKLOAD_ALLOW = sorted({line.strip() for line in (ENGINE / 'checks/workload-allow.txt').read_text().splitlines()
                         if line.strip() and not line.startswith('#')})


class Seed:
    """The runtime seed as the catalog requires it (catalog.c tree_check): root-owned, directories 0755, files 0444 or
    0555 with one link each, symlinks resolving inside, every entry in the component manifest with its digest. Files
    are copied (symlinks followed); the shared libraries every ELF needs are added from the host by ldd closure."""

    def __init__(self, root: Path) -> None:
        self.root, self.entries, self.elves, self.missing, self.foreign = root, {}, [], set(), []
        root.mkdir(mode=0o755)
        os.chmod(root, 0o755)

    def _dirs(self, rel: str) -> None:
        parts = PurePosixPath(rel).parts
        for i in range(1, len(parts) + 1):
            path = '/'.join(parts[:i])
            if path not in self.entries:
                (self.root / path).mkdir(mode=0o755)
                os.chmod(self.root / path, 0o755)
                self.entries[path] = {'path': path, 'type': 'directory', 'size': 0, 'mode': 0o755}

    def file(self, src: Path | None, rel: str, data: bytes | None = None) -> None:
        """A file from the host (src) or, with src None, the given bytes (mode 0444)."""
        if rel in self.entries:
            return
        data = src.read_bytes() if data is None else data
        if data[:4] == b'\x7fELF' and data[18:20] != X86_64:      # another architecture's prebuilt: left out
            self.foreign.append(rel)
            return
        if '/' in rel:
            self._dirs(str(PurePosixPath(rel).parent))
        mode = 0o555 if src is not None and src.stat().st_mode & 0o111 else 0o444
        target = self.root / rel
        target.write_bytes(data)
        os.chmod(target, mode)
        self.entries[rel] = {'path': rel, 'type': 'file', 'size': len(data), 'mode': mode,
                             'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}
        if data[:4] == b'\x7fELF':
            self.elves.append(target)

    def link(self, rel: str, target: str) -> None:
        """A relative symlink inside the seed (the catalog resolves it beneath the seed root)."""
        self._dirs(str(PurePosixPath(rel).parent))
        os.symlink(target, self.root / rel)
        self.entries[rel] = {'path': rel, 'type': 'symlink', 'size': len(target.encode()), 'mode': 0o777,
                             'target': target}

    def tree(self, src: Path, rel: str, skip: Callable[[str], bool]) -> None:
        for dirpath, dirnames, filenames in os.walk(src):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames if not skip(d) and not (here / d).is_symlink())
            base = rel if here == src else f'{rel}/{here.relative_to(src).as_posix()}'
            self._dirs(base)
            for name in sorted(filenames):
                p = here / name
                if skip(name) or not p.exists():          # broken symlinks (e.g. Debian's sitecustomize) stay out
                    continue
                self.file(p, f'{base}/{name}')

    def libraries(self) -> list[str]:
        """ldd closure; each library lands at lib/x86_64-linux-gnu/<soname>, the loader at lib64."""
        added, pending = [], list(self.elves)
        while pending:
            out = subprocess.run(['/usr/bin/ldd', str(pending.pop())], capture_output=True, text=True).stdout
            for line in out.splitlines():
                if '=> not found' in line:
                    self.missing.add(line.split()[0])
                m = re.match(r'\s*(\S+) => (/\S+) \(0x', line)
                loader = re.match(r'\s*(/\S*ld-linux-x86-64\.so\.2) \(0x', line)
                if loader:
                    rel, src = 'lib64/ld-linux-x86-64.so.2', Path(loader.group(1))
                elif m and not m.group(2).startswith(str(self.root)):
                    rel, src = f'{LIB_DIR}/{m.group(1)}', Path(m.group(2))
                else:
                    continue
                if rel not in self.entries:
                    self.file(src, rel)
                    added.append(rel)
                    pending.append(self.root / rel)
        return added

    def manifest(self) -> dict[str, Any]:
        return {'v': 1, 'files': [self.entries[k] for k in sorted(self.entries)]}


def _fetch(url: str, into: Path) -> tuple[Path, str]:
    """One release archive into its own directory under the cache (kept across runs); returns the archive and the URL
    it finally came from (the release tag is in it)."""
    into.mkdir(parents=True, exist_ok=True)
    archive, origin = into / 'archive.tar.gz', into / 'origin.txt'
    if not archive.exists():
        with urllib.request.urlopen(url, timeout=120) as response:
            data, final = response.read(), response.geturl()
        archive.write_bytes(data)
        origin.write_text(final + '\n')
    return archive, origin.read_text().strip()


def _latest(repo: str) -> str:
    with urllib.request.urlopen(f'https://api.github.com/repos/{repo}/releases/latest', timeout=60) as response:
        return json.load(response)['tag_name']


def _release(into: Path, url: str, member: str) -> dict[str, Any]:
    """One release archive (cached in its own directory), extracted with tarfile's data filter; the member's path. The
    lock records the URL asked for (it names the release tag), not the expiring signed one the download ends at."""
    archive, _ = _fetch(url, into)
    out = into / 'extracted'
    if not out.exists():
        with tarfile.open(archive) as tar:
            tar.extractall(out, filter='data')
    binary = out / member
    return {'path': binary, 'url': url, 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}


def fetch_tools(cache: Path = TOOL_CACHE, experiment: bool = False) -> dict[str, dict[str, Any]]:
    """uv and gh are not on the host: their official release archives (uv's latest x86_64 glibc build; gh's latest
    linux_amd64 build, a static Go binary), extracted with tarfile's data filter. They run only inside the cell (and in
    the preflight chroot as an unmapped uid). The experiment seed adds ripgrep and fd the same way: the latest static
    musl builds, the assets Pi's own tools manager would fetch, cached by release tag."""
    gh_tag = _latest('cli/cli')
    gh_name = f'gh_{gh_tag.lstrip("v")}_linux_amd64'
    tools = {'uv': _release(cache / 'uv-latest', 'https://github.com/astral-sh/uv/releases/latest/download/'
                            'uv-x86_64-unknown-linux-gnu.tar.gz', 'uv-x86_64-unknown-linux-gnu/uv'),
             'gh': _release(cache / f'gh-{gh_tag}', f'https://github.com/cli/cli/releases/download/{gh_tag}/'
                            f'{gh_name}.tar.gz', f'{gh_name}/bin/gh')}
    if experiment:
        for name, repo, stem in (('rg', 'BurntSushi/ripgrep', 'ripgrep-{}-x86_64-unknown-linux-musl'),
                                 ('fd', 'sharkdp/fd', 'fd-{}-x86_64-unknown-linux-musl')):
            tag = _latest(repo)
            base = stem.format(tag)
            tools[name] = _release(cache / f'{name}-{tag}', f'https://github.com/{repo}/releases/download/{tag}/'
                                   f'{base}.tar.gz', f'{base}/{name}')
    return tools


def package_programs(package: str) -> list[Path]:
    """A Debian package's programs as dpkg lists them: its files under /usr/bin and /bin, one per name."""
    listed = subprocess.run(['/usr/bin/dpkg-query', '-L', package], capture_output=True, text=True, check=True).stdout
    found: dict[str, Path] = {}
    for line in listed.splitlines():
        p = Path(line)
        if str(p.parent) in ('/usr/bin', '/bin') and p.is_file():
            found.setdefault(p.name, p)
    return sorted(found.values())


def python_distributions(names: tuple[str, ...]) -> dict[str, Any]:
    """The installed distributions of these names, looked up in PYTHON_PATHS in that order (the runner is root; pytest
    is in the host user's site directory)."""
    from importlib.metadata import distributions
    found: dict[str, Any] = {}
    for dist in distributions(path=list(PYTHON_PATHS)):
        found.setdefault(dist.metadata['Name'].lower(), dist)
    return {name: found[name] for name in names}


def go_build(build: Path, command: Callable[..., dict[str, Any]], as_user: list[str], home: str) -> None:
    """frontend-go/ into build/engine-frontend as the given user: static (CGO_ENABLED=0), with the installed toolchain
    only (GOTOOLCHAIN=local), the user's build cache; the same flags as frontend-go/README.md."""
    command(as_user + [GO, '-C', ENGINE / 'frontend-go', 'build', '-trimpath', '-buildvcs=false',
                       '-o', build / 'engine-frontend', '.'],
            timeout=300, env={'HOME': home, 'CGO_ENABLED': '0', 'GOTOOLCHAIN': 'local'})


def mcp_build(build: Path, command: Callable[..., dict[str, Any]], as_user: list[str], home: str) -> Path:
    """mcp-go/ into build/engine-mcp as the given user, static, with MCP_BUILD's flags (mcp-go/README.md). The variables
    go through env(1) so that runners whose command() takes no environment can call it too."""
    out = build / 'engine-mcp'
    command(as_user + ['/usr/bin/env', f'HOME={home}', 'CGO_ENABLED=0', 'GOTOOLCHAIN=local', GO,
                       '-C', ENGINE / 'mcp-go', *MCP_BUILD, '-o', out, '.'], timeout=300)
    return out


def build_seed(seed: Path, build: Path, full: bool, frontend: str = 'go',
               experiment: bool = False) -> tuple[Seed, dict[str, Any]]:
    """full (7.2): also git (with git-remote-http/https), curl, node and npm, pip, uv and gh, and /bin/sh.
    frontend 'go' takes build/engine-frontend (go_build); 'python' takes the frontend venv. Every seed has the MCP
    server, build/engine-mcp (mcp_build), at MCP_SEED.
    experiment (deployment.md section 8, implies full): node v22.23.4 for node and npm, Pi, OpenCode, the work tools,
    pytest, ripgrep and fd; the lock records each one's version and the ELF files left out for their architecture."""
    assert frontend in FRONTENDS, frontend
    full = full or experiment
    node_home = NODE22 if experiment else NODE_HOME
    s = Seed(seed)
    s.file(build / 'w2-relay', 'bin/w2-relay')
    s.file(build / 'engine-mcp', MCP_SEED)          # mcp_build; its sha256 is in the manifest and the lock (H-23)
    s.file(CLAUDE, 'bin/claude')
    s.file(Path('/usr/bin/bash'), 'bin/bash')
    if frontend == 'python' or full:
        s.file(Path('/usr/bin/python3.12'), 'usr/bin/python3.12')
        s.tree(Path('/usr/lib/python3.12'), 'usr/lib/python3.12', lambda n: n in STDLIB_SKIP)
    if frontend == 'python':
        s.tree(VENV_SITE, 'usr/lib/python3/dist-packages',
               lambda n: n == '__pycache__' or (not full and (n == 'pip' or n.startswith('pip-'))))
        s.file(ENGINE / 'frontend/engine_frontend.py', 'frontend/engine_frontend.py')
    else:
        s.file(build / 'engine-frontend', 'frontend/engine-frontend')
        if full:                                      # pip alone: the pip item's package manager, not the frontend's
            for package in (VENV_SITE / 'pip', *VENV_SITE.glob('pip-*.dist-info')):
                s.tree(package, f'usr/lib/python3/dist-packages/{package.name}', lambda n: n == '__pycache__')
    tools = fetch_tools(experiment=experiment) if full else {}
    if full:
        s.link('bin/sh', 'bash')
        s.file(Path('/usr/bin/git'), 'usr/bin/git')
        s.file(Path('/usr/lib/git-core/git-remote-http'), 'usr/lib/git-core/git-remote-http')
        s.link('usr/lib/git-core/git-remote-https', 'git-remote-http')
        s.link('usr/lib/git-core/git', '../../bin/git')
        s.tree(Path('/usr/share/git-core/templates'), 'usr/share/git-core/templates', lambda n: False)
        s.file(Path('/usr/bin/curl'), 'usr/bin/curl')
        s.file(node_home / 'bin/node', 'usr/bin/node')
        s.tree(node_home / 'lib/node_modules/npm', 'usr/lib/node_modules/npm', lambda n: False)
        for name, tool in tools.items():
            s.file(tool['path'], f'usr/bin/{name}')
    pytest: dict[str, str] = {}
    if experiment:
        # the commands the derivation set names, as the agents call them (python3, npm, npx, pytest through python3)
        s.link('usr/bin/python3', 'python3.12')
        s.link('usr/bin/npm', '../lib/node_modules/npm/bin/npm-cli.js')
        s.link('usr/bin/npx', '../lib/node_modules/npm/bin/npx-cli.js')
        for package in WORK_PACKAGES:
            for program in package_programs(package):
                s.file(program, f'usr/bin/{program.name}')
        for name, dist in python_distributions(PYTEST).items():
            pytest[name] = dist.version
            site = Path(dist.locate_file(''))
            if dist.files is None:                  # Debian-built, no RECORD: its top-level packages and its metadata
                for top in (dist.read_text('top_level.txt') or name).split() + [f'{name}-{dist.version}.dist-info']:
                    s.tree(site / top, f'usr/lib/python3/dist-packages/{top}', lambda n: n == '__pycache__')
                continue
            for f in dist.files:
                if f.parts[0] != '..' and '__pycache__' not in f.parts and (site / f).is_file():
                    s.file(site / f, f'usr/lib/python3/dist-packages/{f.as_posix()}')
        s.tree(AGENTS / 'pi/node_modules', 'usr/lib/pi/node_modules', lambda n: False)
        s.link('usr/bin/pi', f'../lib/pi/node_modules/{PI_CLI}')
        s.file(OPENCODE, 'usr/bin/opencode')
    added = s.libraries()
    versions = {'claude': subprocess.run([str(CLAUDE), '--version'], capture_output=True, text=True,
                                         env={'HOME': '/tmp', 'PATH': '/usr/bin:/bin'}).stdout.strip(),
                'bash': subprocess.run(['/usr/bin/bash', '--version'], capture_output=True, text=True).stdout.splitlines()[0],
                'frontend': frontend,
                'mcp_sha256': s.entries[MCP_SEED]['digest'], 'mcp_build': MCP_BUILD,
                **({'python': platform.python_version()} if frontend == 'python' or full else {}),
                **({'mitmproxy': next(p.name for p in VENV_SITE.glob('mitmproxy-*.dist-info'))} if frontend == 'python'
                   else {}),
                'go': subprocess.run([str(GO), 'version'], capture_output=True, text=True).stdout.strip(),
                'glibc': platform.libc_ver()[1], 'libraries': sorted(added), 'not_found': sorted(s.missing)}
    if full:
        versions.update(
            git=subprocess.run(['/usr/bin/git', '--version'], capture_output=True, text=True).stdout.strip(),
            curl=subprocess.run(['/usr/bin/curl', '--version'], capture_output=True, text=True).stdout.splitlines()[0],
            node=subprocess.run([str(node_home / 'bin/node'), '--version'], capture_output=True, text=True).stdout.strip(),
            npm=json.loads((node_home / 'lib/node_modules/npm/package.json').read_text())['version'],
            pip=next(p.name for p in VENV_SITE.glob('pip-*.dist-info')),
            **{name: {'url': t['url'], 'archive_sha256': t['archive_sha256'], 'binary_sha256': t['binary_sha256']}
               for name, t in tools.items()})
    if experiment:
        def package_json(path: Path) -> str:
            return json.loads(path.read_text())['version']
        versions.update(
            pi=package_json(AGENTS / 'pi/node_modules/@earendil-works/pi-coding-agent/package.json'),
            opencode=package_json(AGENTS / 'opencode/node_modules/opencode-ai/package.json'),
            opencode_sha256=s.entries['usr/bin/opencode']['digest'],
            packages={p: subprocess.run(['/usr/bin/dpkg-query', '-W', '-f=${Version}', p], capture_output=True,
                                        text=True).stdout for p in WORK_PACKAGES},
            pytest=pytest, foreign_elf_left_out=sorted(s.foreign))
    lock = (json.dumps(versions, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
    s.file(None, 'dependency-lock.json', lock)
    return s, versions


def preflight(seed: Path, scratch: Path, full: bool, frontend: str = 'go', experiment: bool = False) -> dict[str, Any]:
    """The seed in the cell's layout (bin, lib, lib64, usr as links into /runtime) under chroot as an unmapped uid,
    before any engine: the frontend (Python: its imports; Go: the binary run without arguments, which prints its usage
    and exits 2) and each program's --version. A diagnostic, not a cell (no namespaces, no policy)."""
    full = full or experiment
    extra =([(f'{n}_version', [f'/usr/bin/{n}', '--version']) for n in ('pi', 'opencode', 'rg', 'fd')] +
             [('pytest_version', ['/usr/bin/python3', '-m', 'pytest', '--version'])] if experiment else [])
    probe = (('frontend_import', ['/runtime/usr/bin/python3.12', '-I', '-B', '-c',
                                  'import time; t=time.monotonic(); import mitmproxy.tools.dump, '
                                  'mitmproxy.options, mitmproxy.http; print(round(time.monotonic()-t, 2))'])
             if frontend == 'python' else ('frontend_usage', ['/runtime/frontend/engine-frontend']))
    top = scratch / 'preflight'
    for d in ('runtime', 'tmp', 'dev', 'proc'):
        (top / d).mkdir(parents=True)
    os.chmod(top / 'tmp', 0o1777)                    # writable like the cell's own /tmp (HOME there, 7.4 step 4b)
    for link in ('bin', 'lib', 'lib64', 'usr'):
        (top / link).symlink_to(f'/runtime/{link}')
    subprocess.run(['/usr/bin/mount', '--bind', '-o', 'ro', str(seed), str(top / 'runtime')], check=True)
    subprocess.run(['/usr/bin/mount', '--bind', '/dev', str(top / 'dev')], check=True)
    subprocess.run(['/usr/bin/mount', '-t', 'proc', 'proc', str(top / 'proc')], check=True)
    out: dict[str, Any] = {}
    try:
        for name, argv in (probe,
                           ('agent_version', ['/runtime/bin/claude', '--version']),
                           *([(f'{n}_version', [f'/usr/bin/{n}', '--version'])
                              for n in ('git', 'curl', 'node', 'uv', 'gh')] if full else []), *extra):
            started = time.monotonic()
            p = subprocess.run(['/usr/sbin/chroot', '--userspec=70000:70000', str(top), *argv], capture_output=True,
                               text=True, timeout=120,
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'HOME': '/tmp',
                                    'PI_SKIP_VERSION_CHECK': '1', 'PI_TELEMETRY': '0',
                                    'OPENCODE_DISABLE_AUTOUPDATE': '1'})
            out[name] = {'exit_code': p.returncode, 'stdout': p.stdout[-2000:], 'stderr': p.stderr[-2000:],
                         'elapsed_seconds': round(time.monotonic() - started, 2)}
    finally:
        for target in ('proc', 'dev', 'runtime'):
            subprocess.run(['/usr/bin/umount', str(top / target)], check=True)
    return out

