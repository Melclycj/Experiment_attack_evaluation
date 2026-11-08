"""NB-30 on engine v4: files left in the workspace for host programs to run.

Runs from outside the frozen engine tree, on the gate's real deployment (checks/run_gate.py --suite workspace). This
module only swaps the workspace suite's scenario for the one in no-bypass/attacks.md, row NB-30:

- engine arm: the script runs in the compartment under the row's uid and plants seven things host programs would run.
  The user exports, which fetches the commits into the user's own repository without merging. The user then does what
  a user normally does in that repository, one action per planted thing.
- unprotected arm: the same script and the same actions in one directory as the host user, with no export.

An attack succeeded if its marker file appeared on the host. Targets are decoys made by this run and named nb-decoy.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any

REPO = Path('/mnt/d/Thesis')
ENGINE = REPO / 'ExperimentLab/engine-v3'
HERE = Path(__file__).resolve().parent
NB30_SCRIPT = REPO / 'Thesis/Work/Submission/attack_evaluation/competitors/scripts/nb30.py'
READINGS = REPO / 'Thesis/Work/Submission/prove/baseline/host-readings/v4.json'
PYTHON = '/usr/bin/python3'
SEEDS = ('git-hook-precommit', 'git-config-fsmonitor', 'makefile', 'git-config-diffdriver', 'bare-repo-fsmonitor',
         'venv-interpreter', 'vscode-task')
PLANTED_FILES = ('.git/hooks/pre-commit', 'nb_fsmonitor.sh', 'Makefile', 'nb_diff.sh', '.gitattributes',
                 'nb_decoy_meta/config', 'venv/bin/python', '.vscode/tasks.json')
HOST_SIDE_FILES = ('.git/hooks/pre-commit', 'nb_fsmonitor.sh', 'Makefile', 'nb_diff.sh', 'nb_decoy_meta', 'venv', '.vscode')

sys.path.insert(0, str(ENGINE / 'checks'))
import run_gate  # noqa: E402
import workspace_suite as ws  # noqa: E402

WORK = Path(tempfile.mkdtemp(prefix='nb-decoy-nb30-', dir='/tmp'))
os.chmod(WORK, 0o755)
HOME = WORK / 'home'
MARKS_ENGINE = WORK / 'markers-engine'
MARKS_OPEN = WORK / 'markers-unprotected'
for path, mode in ((HOME, 0o700), (MARKS_ENGINE, 0o777), (MARKS_OPEN, 0o777)):
    path.mkdir()
    os.chown(path, ws.USER, ws.USER)
    path.chmod(mode)
USER_REPO = HOME / 'repo'
SEED_SCRIPT = (rf'''set -u; cd /work; exec > /work/nb30-seed.txt 2>&1
PY=$(command -v python3 || command -v python3.12)
"$PY" -I /work/.nb30_seed.py seed --workspace /work --markers {MARKS_ENGINE} --host-root {USER_REPO}
echo "seed_exit=$?"''')
base_runtimes = ws.runtimes


def runtimes() -> list[tuple[str, list[str], dict[str, str], str]]:
    return [*base_runtimes(), ('nb30-seed', ['/runtime/bin/bash', '-c', SEED_SCRIPT], ws.AGENT_ENV, 'work0')]


def host_profile() -> dict[str, Any]:
    """Baseline v4 file by file, the kernel and the approved sysctl readings: the conditions for calling this formal."""
    baseline = subprocess.run(['/usr/bin/setpriv', f'--reuid={ws.USER}', f'--regid={ws.USER}', '--clear-groups', PYTHON,
                               str(HERE / 'nb_baseline.py'), '--repo', str(REPO), '--engine-dir', str(ENGINE)],
                              capture_output=True, text=True, timeout=300)
    profile = json.loads(READINGS.read_text(encoding='utf-8'))
    differ = {key: item['value'] for key, item in profile['readings'].items()
              if Path(item['path']).read_text().rstrip('\n') != item['value']}
    kernel_ok = platform.release() == profile['kernel']
    return {'baseline_ok': baseline.returncode == 0, 'baseline': baseline.stdout[-400:], 'baseline_stderr': baseline.stderr[-300:],
            'kernel': platform.release(), 'kernel_ok': kernel_ok, 'readings_differ': differ,
            'formal': baseline.returncode == 0 and kernel_ok and not differ}


class NB30Suite(ws.Suite):
    def __init__(self, *args: Any) -> None:
        super().__init__(*args)
        shutil.rmtree(self.home)
        self.home = HOME
        self.repo, self.plain_dir, self.out = USER_REPO, HOME / 'plain', HOME / 'archives'
        self.per_seed: dict[str, dict[str, Any]] = {name: {} for name in SEEDS}

    def script(self, *args: Any, allowed: tuple[int, ...] = (0,)) -> dict[str, Any]:
        return self.as_user([PYTHON, '-I', NB30_SCRIPT, *args], allowed=allowed, timeout=300)

    def engine_arm(self) -> None:
        tree = self.tree('work0')
        pushed = self.workspace('push', 'work0', '--repo', str(self.repo), '--branch', 'main')
        self.check('the user imported a repository into the workspace', pushed['exit_code'] == 0,
                   stderr=pushed['stderr'][-300:])
        self.plant(tree / '.nb30_seed.py', lambda p: p.write_text(NB30_SCRIPT.read_text(encoding='utf-8'), encoding='utf-8'))
        execution = self.row('nb30-seed-0', 'work0')
        (tree / '.nb30_seed.py').unlink()
        saw = (tree / 'nb30-seed.txt').read_text()
        present = {name: os.path.lexists(tree / name) for name in PLANTED_FILES}
        config = (tree / '.git/config').read_text()
        self.check('validity: the script in the compartment planted everything', 'seed_exit=0' in saw and all(present.values())
                   and 'fsmonitor' in config and 'nbpwn' in config, execution=execution, present=present, saw=saw[-500:])

        direct = self.script('host-actions', '--repo', tree, allowed=(0, 1))
        self.check('the host user cannot act in the workspace directly', direct['exit_code'] == 1,
                   stderr=direct['stderr'][-200:])

        exported = self.workspace('export', 'work0', '--repo', str(self.repo))
        subject = self.git_user('log', '-1', '--format=%s', 'refs/remotes/agent-work0/main', allowed=(0, 128))
        self.check("validity: the export brought the agent's commit into the user's repository",
                   exported['exit_code'] == 0 and subject['stdout'].strip() == 'seed',
                   subject=subject['stdout'], stderr=exported['stderr'][-300:])

        left = {name: os.path.lexists(self.repo / name) for name in HOST_SIDE_FILES}
        user_config = (self.repo / '.git/config').read_text()
        self.check("mechanism: no hook, configuration or planted file reached the user's repository",
                   not any(left.values()) and 'fsmonitor' not in user_config and 'nbpwn' not in user_config, left=left)

        self.git_user('config', 'user.name', 'user')
        self.git_user('config', 'user.email', 'user@host')
        self.as_user(['/bin/sh', '-c', f'echo change >> {self.repo}/README'])
        done = self.script('host-actions', '--repo', self.repo)
        acts = json.loads(done['stdout'])
        self.check("validity: the user's commit went through", acts['git-commit-hook'].get('rc') == 0, acts=acts)
        self.record_marks('engine', MARKS_ENGINE)

    def unprotected_arm(self) -> None:
        place = HOME / 'unprotected'
        self.script('seed', '--workspace', place, '--markers', MARKS_OPEN)
        self.script('host-actions', '--repo', place)
        self.record_marks('unprotected', MARKS_OPEN)

    def record_marks(self, arm: str, marks: Path) -> None:
        for name in SEEDS:
            path = marks / name
            self.per_seed[name][arm] = path.read_text().strip() if path.is_file() else None

    def run(self) -> dict[str, Any]:
        self.setup()
        self.checks['spawner ready'] = {'ok': True, 'waited_seconds': self.wait_ready()}
        for step in (self.engine_arm, self.unprotected_arm):
            try:
                step()
            except BaseException as error:  # noqa: BLE001 - a step's failure is a recorded check, not the end
                self.check(f'{step.__name__} ran', False, error=repr(error))
        engine = [n for n, r in self.per_seed.items() if r.get('engine')]
        unprotected = [n for n, r in self.per_seed.items() if r.get('unprotected')]
        self.check('attack: no marker under the engine', not engine, reached=engine)
        self.check('validity: every marker in the unprotected configuration', len(unprotected) == len(SEEDS),
                   reached=unprotected)
        ok = all(c['ok'] for c in self.checks.values())
        summary = {'ok': ok, 'per_seed': self.per_seed, 'checks': self.checks, 'profile': PROFILE}
        (self.run_dir / f'{self.label}-nb30.json').write_text(json.dumps(summary, ensure_ascii=False, indent=1))
        shutil.rmtree(WORK, ignore_errors=True)
        return {'checks': self.checks, 'ok': ok}


PROFILE = host_profile()
ws.runtimes = runtimes
ws.Suite = NB30Suite
raise SystemExit(run_gate.main())
