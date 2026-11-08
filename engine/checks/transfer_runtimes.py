"""The two transfer runtimes and each workspace's two transfer plans, as a deployment registers them (agent-rm-model
3.1 传送 execution, 6.2 工作区内容经导入、推进、导出进出; validation.md S-24; deployment.md 第 5 节).

A transfer execution is an ordinary row of a reserved runtime: the engine knows it by the runtime id
(engine/startup.py TRANSFER_RUNTIMES), hangs no entries on it and refuses its every network request; only the
connection holding the workspace may start it. Its command is fixed here, in the runtime descriptor, and needs nothing
from the seed but bash and git (bash builtins only, no coreutils): every git call on the workspace repository runs with
core.hooksPath=/dev/null. It reads what the management client put into .engine/incoming, writes what the client takes
from .engine/outgoing (the client makes both directories and clears stale files first), and ends with one line in
.engine/result. The client reads that line only after every process of the row is gone (A-10), so a plain write is
enough.

push: fetch the user's bundle into refs/remotes/user/*, no tags, no submodule recursion. Into a workspace holding
nothing but .engine this is the git import: init, fetch, then check out the branch the client names in push.head.
export: bundle every local branch into .engine/outgoing/export.bundle.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

COMMON = r'''set -u
cd /work || exit 1
E=.engine
finish() { printf '%s\n' "$1" > "$E/result"; exit 0; }
g() { git -c core.hooksPath=/dev/null "$@"; }
'''
PUSH = COMMON + r'''[ -f "$E/incoming/push.bundle" ] || finish 'fail no-bundle'
fresh=0
if [ ! -e .git ]; then
  shopt -s dotglob nullglob
  for entry in *; do [ "$entry" = .engine ] || finish 'fail not-git'; done
  shopt -u dotglob nullglob
  g init -q . || finish 'fail init'
  fresh=1
fi
g fetch -q --no-tags --no-recurse-submodules "$E/incoming/push.bundle" '+refs/heads/*:refs/remotes/user/*' || finish 'fail fetch'
if [ "$fresh" = 1 ]; then
  b=''
  IFS= read -r -n 255 b < "$E/incoming/push.head"
  [ -n "$b" ] && g check-ref-format --branch "$b" > /dev/null || finish 'fail head'
  g checkout -q -B "$b" "refs/remotes/user/$b" || finish 'fail checkout'
fi
finish 'ok push'
'''
EXPORT = COMMON + r'''[ -d .git ] || finish 'fail not-git'
[ -d "$E/outgoing" ] || finish 'fail outgoing'
g bundle create -q "$E/outgoing/export.bundle" --branches || finish 'fail bundle'
finish 'ok export'
'''
SCRIPTS = {'push': PUSH, 'export': EXPORT}
RUNTIME_IDS = {'push': 'w2-transfer-push', 'export': 'w2-transfer-export'}     # engine/startup.py TRANSFER_RUNTIMES
ENV = {'PATH': '/bin:/usr/bin', 'LANG': 'C.UTF-8', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}


def plan_id(workspace: str, kind: str) -> str:
    """The name the management client starts (client/workspace.py transfer_plan)."""
    return f'{workspace}.{kind}'


def register(root: Path, catalog: dict[str, Any], save_json: Callable[[Path, Any], str], workspaces: list[str], *,
             component_digest: str, lock_digest: str, storage_profile_id: str, policy_id: str, policy_digest: str,
             profile_digest: str) -> None:
    """Add the two transfer runtimes (same seed as the deployment's other runtimes) and, per workspace, its push and
    export plans to a catalog being written under ``root``."""
    for kind, script in SCRIPTS.items():
        assert len(script) < 4096, kind                        # W2_STRING_MAX for one argv string
        runtime = RUNTIME_IDS[kind]
        descriptor = dict(runtime_id=runtime, artifact_digest=component_digest, dependency_digest=lock_digest,
                          layout_id='runtime-root-v1', storage_profile_id=storage_profile_id,
                          executable='/runtime/bin/bash', argv=['/runtime/bin/bash', '-c', script], cwd='/work', env=ENV,
                          protocol='w2-local/2', component_manifest_ref='components.json',
                          component_manifest_digest=component_digest)
        rd = save_json(root / f'{runtime}.json', descriptor)
        catalog['runtimes'].append({'descriptor_ref': f'{runtime}.json', 'descriptor_digest': rd,
                                    'seed_ref': 'seed', 'dependency_lock_ref': 'dependency-lock.json'})
        for workspace in workspaces:
            plan = dict(launch_plan_id=plan_id(workspace, kind), runtime_id=runtime, runtime_descriptor_digest=rd,
                        workspace_id=workspace, workspace_layout_id='private-work-v1', policy_id=policy_id,
                        policy_digest=policy_digest, isolation_profile_id='sandbox-native',
                        isolation_profile_digest=profile_digest)
            ref = f'plan-{plan_id(workspace, kind)}.json'
            catalog['plans'].append({'artifact_ref': ref, 'artifact_digest': save_json(root / ref, plan)})
