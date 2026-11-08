"""Engine start-up: self-check, mitigation opt-in, catalog and uid pool (conn E-01, rr E-08, si E-10).

Any failure refuses service. The self-check is the engine-side half of C3; it does not stand in for
the deployment's initial-user-namespace requirement (S13).
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
from typing import Any, Callable

from .ffi import Native
from .objects import Plan, WorkspaceRecord

UID_INVALID = 0xFFFFFFFF
PROTOCOL = 'w2-local/2'
ID = re.compile(r'[A-Za-z0-9._:-]{1,96}')   # conn E-02 ID rule
PR_GET_SPECULATION_CTRL = 52
PR_SET_SPECULATION_CTRL = 53
PR_SPEC_INDIRECT_BRANCH = 1
PR_SPEC_PRCTL = 1 << 0
PR_SPEC_ENABLE = 1 << 1
PR_SPEC_DISABLE = 1 << 2
PR_SPEC_FORCE_DISABLE = 1 << 3

ENVIRONMENT_PATHS = {
    'uid_map': '/proc/self/uid_map',
    'overflowuid': '/proc/sys/kernel/overflowuid',
    'overflowgid': '/proc/sys/kernel/overflowgid',
    'yama': '/proc/sys/kernel/yama/ptrace_scope',
    'ksm': '/sys/kernel/mm/ksm/run',
}


class StartupRefused(Exception):
    """The engine refuses service; the message names the failed check."""


@dataclass(frozen=True)
class Environment:
    overflowuid: int
    overflowgid: int
    readings: dict[str, str]


@dataclass(frozen=True)
class Catalog:
    catalog_digest: str
    storage_profile_digest: str
    plans: dict[str, Plan]
    workspaces: dict[str, tuple[str, str, str, int, int]]  # id -> (id, layout, source, uid, gid)


def check_environment(native: Native, paths: dict[str, str] = ENVIRONMENT_PATHS) -> Environment:
    """uid_map must be the identity map and overflowuid/gid readable. The same C parser as the
    spawner's start-up check also requires its yama/KSM readings (deployment preconditions)."""
    try:
        readings = {name: Path(path).read_text() for name, path in paths.items()}
    except OSError as error:
        raise StartupRefused(f'environment unreadable: {error}') from None
    values = native.environment_values(readings['uid_map'], readings['overflowuid'],
                                       readings['overflowgid'], readings['yama'], readings['ksm'])
    if values is None:
        raise StartupRefused('environment check failed: ' + json.dumps(readings))
    return Environment(values[0], values[1], readings)


def opt_in_indirect_branch(prctl: Callable[..., int] | None = None) -> str:
    """S14: opt this task into the indirect-branch mitigation before holding any secret."""
    if prctl is None:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    state = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, 0, 0, 0)
    if state == 0:
        return 'not_affected'
    if state < 0:
        raise StartupRefused(f'speculation control unreadable: errno {ctypes.get_errno()}')
    if state & PR_SPEC_PRCTL:
        # FORCE_DISABLE, as S14 names: once set, no later prctl in this task can turn the mitigation off again.
        if prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0):
            raise StartupRefused(f'speculation opt-in failed: errno {ctypes.get_errno()}')
        state = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, 0, 0, 0)
        if state < 0 or not state & PR_SPEC_FORCE_DISABLE:
            raise StartupRefused(f'speculation opt-in not in effect: {state}')
        return 'opted_in'
    if state & (PR_SPEC_DISABLE | PR_SPEC_FORCE_DISABLE):
        return 'kernel_enforced'
    raise StartupRefused(f'indirect-branch mitigation neither enforced nor controllable: {state}')


def new_epoch() -> str:
    """128-bit random engine_epoch, 32 lowercase hex (conn E-01)."""
    return secrets.token_hex(16)


def _strict(data: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f'duplicate key {key}')
            result[key] = value
        return result

    def constant(name: str) -> Any:
        raise ValueError(f'non-standard constant {name}')

    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)


def _digest(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def _artifact(root: Path, entry: dict[str, Any]) -> Any:
    data = (root / entry['artifact_ref']).read_bytes()
    if _digest(data) != entry['artifact_digest']:
        raise StartupRefused(f'artifact digest mismatch: {entry["artifact_ref"]}')
    return _strict(data)


def load_catalog(root: Path, name: str, env: Environment, engine_uid: int) -> Catalog:
    """Read the trusted start-up catalog and validate the workspace uid/gid pool (rr E-08 静态一对一)."""
    try:
        data = (root / name).read_bytes()
        catalog = _strict(data)
        storage_digest = catalog['storage_profile']['artifact_digest']
        _artifact(root, catalog['storage_profile'])
        workspaces: dict[str, tuple[str, str, str, int, int]] = {}
        for w in catalog['workspaces']:
            entry = (w['workspace_id'], w['workspace_layout_id'], w['source_ref'],
                     w['workspace_uid'], w['workspace_gid'])
            if entry[0] in workspaces:
                raise StartupRefused(f'duplicate workspace {entry[0]}')
            workspaces[entry[0]] = entry
        runtimes: dict[str, tuple[str, str]] = {}   # runtime_id -> (descriptor digest, adapter_id)
        for r in catalog['runtimes']:
            ref = {'artifact_ref': r['descriptor_ref'], 'artifact_digest': r['descriptor_digest']}
            descriptor = _artifact(root, ref)
            adapter_id = descriptor['adapter_id']
            if (descriptor['runtime_id'] in runtimes or descriptor['protocol'] != PROTOCOL
                    or type(adapter_id) is not str or not ID.fullmatch(adapter_id)):
                raise StartupRefused(f'invalid runtime {descriptor["runtime_id"]}')
            runtimes[descriptor['runtime_id']] = (r['descriptor_digest'], adapter_id)
        plans: dict[str, Plan] = {}
        for p in catalog['plans']:
            body = _artifact(root, p)
            runtime = runtimes.get(body['runtime_id'])
            if runtime is None or body['runtime_descriptor_digest'] != runtime[0]:
                raise StartupRefused(f'plan {body["launch_plan_id"]} names no catalog runtime')
            plan = Plan(body['launch_plan_id'], p['artifact_digest'], body['workspace_id'],
                        body['policy_digest'], body['isolation_profile_digest'], runtime[1])
            if plan.launch_plan_id in plans or plan.workspace_id not in workspaces:
                raise StartupRefused(f'invalid plan {plan.launch_plan_id}')
            plans[plan.launch_plan_id] = plan
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise StartupRefused(f'catalog unreadable: {error!r}') from None
    check_pool(workspaces.values(), env, engine_uid)
    return Catalog(_digest(data), storage_digest, plans, workspaces)


def check_pool(workspaces: Any, env: Environment, engine_uid: int) -> None:
    """The pool excludes 0, the overflow ids, invalid values, the engine and host accounts;
    workspace→uid and workspace→gid are one-to-one."""
    uids: set[int] = set()
    gids: set[int] = set()
    for workspace_id, _, _, uid, gid in workspaces:
        for value in (uid, gid):
            if type(value) is not int or not 0 < value < UID_INVALID - 1:
                raise StartupRefused(f'invalid id in pool: {workspace_id}')
        if uid in (env.overflowuid, engine_uid) or gid == env.overflowgid or uid in uids or gid in gids:
            raise StartupRefused(f'sentinel, engine or shared id in pool: {workspace_id}')
        try:
            pwd.getpwuid(uid)
        except KeyError:
            pass
        else:
            raise StartupRefused(f'pool uid is a host account: {uid}')
        uids.add(uid)
        gids.add(gid)


def workspace_records(catalog: Catalog) -> dict[str, WorkspaceRecord]:
    return {wid: WorkspaceRecord(wid, layout, source, uid, gid)
            for wid, (_, layout, source, uid, gid) in catalog.workspaces.items()}


def posture() -> dict[str, str]:
    """The engine's own uid/capability posture, for run evidence."""
    keep = {'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp'}
    lines = Path(f'/proc/{os.getpid()}/status').read_text().splitlines()
    return {k: v.strip() for line in lines if ':' in line for k, v in [line.split(':', 1)] if k in keep}
