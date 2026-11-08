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
import secrets
from typing import Any, Callable

from .ffi import Native
from .objects import Plan, WorkspaceRecord

UID_INVALID = 0xFFFFFFFF
PROTOCOL = 'w2-local/2'
PR_GET_SPECULATION_CTRL = 52
PR_SET_SPECULATION_CTRL = 53
PR_SPEC_INDIRECT_BRANCH = 1
PR_SPEC_PRCTL = 1 << 0
PR_SPEC_ENABLE = 1 << 1
PR_SPEC_DISABLE = 1 << 2
PR_SPEC_FORCE_DISABLE = 1 << 3

# agent-rm-model 3.1 传送 execution: the reserved runtime ids of the two transfer runtimes; a plan naming one of them is
# a transfer plan (validation.md S-24). The deployment registers them; nothing else may use these ids.
TRANSFER_RUNTIMES = {'w2-transfer-push': 'push', 'w2-transfer-export': 'export'}

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
    workspaces: dict[str, tuple[str, str, str, int, int]]  # id -> (id, layout, source, owner uid, owner gid)
    uid_range: tuple[int, int] = (0, 0)   # v2: uids are leased per execution from this reserved range (agent-rm-model 3.1)
    connector_uid: int = 0                # the one dedicated uid every connector runs as (3.7)
    pdp_uid: int = 0                      # the PDP's dedicated uid and group: the hook port admits only it (648d60f2 4.2)
    pdp_gid: int = 0
    worker_uid: int = 0                   # the one dedicated uid every row's file worker runs as (H-14)
    worker_gid: int = 0


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
    """Read the trusted start-up catalog and validate the reserved uid range (agent-rm-model 3.1; validation.md K-21,
    ER 131). workspace_uid/gid are the on-disk owner of each workspace, not an allocation."""
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
        runtimes: dict[str, str] = {}   # runtime_id -> descriptor digest
        for r in catalog['runtimes']:
            ref = {'artifact_ref': r['descriptor_ref'], 'artifact_digest': r['descriptor_digest']}
            descriptor = _artifact(root, ref)
            if descriptor['runtime_id'] in runtimes or descriptor['protocol'] != PROTOCOL:
                raise StartupRefused(f'invalid runtime {descriptor["runtime_id"]}')
            runtimes[descriptor['runtime_id']] = r['descriptor_digest']
        plans: dict[str, Plan] = {}
        for p in catalog['plans']:
            body = _artifact(root, p)
            runtime = runtimes.get(body['runtime_id'])
            if runtime is None or body['runtime_descriptor_digest'] != runtime:
                raise StartupRefused(f'plan {body["launch_plan_id"]} names no catalog runtime')
            plan = Plan(body['launch_plan_id'], p['artifact_digest'], body['workspace_id'],
                        body['policy_digest'], body['isolation_profile_digest'],
                        transfer=TRANSFER_RUNTIMES.get(body['runtime_id'], ''))
            if plan.launch_plan_id in plans or plan.workspace_id not in workspaces:
                raise StartupRefused(f'invalid plan {plan.launch_plan_id}')
            plans[plan.launch_plan_id] = plan
        first, last = catalog['uid_range']['first'], catalog['uid_range']['last']
        connector_uid = catalog['connector']['uid']
        pdp_uid, pdp_gid = catalog['pdp']['uid'], catalog['pdp']['gid']
        worker_uid, worker_gid = catalog['file_worker']['uid'], catalog['file_worker']['gid']
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise StartupRefused(f'catalog unreadable: {error!r}') from None
    check_range(first, last, connector_uid, workspaces.values(), env, engine_uid, pdp_uid)
    check_pdp(pdp_uid, pdp_gid, (first, last), connector_uid, env, engine_uid)
    check_worker(worker_uid, worker_gid, (first, last), (connector_uid, pdp_uid), workspaces.values(), env, engine_uid)
    return Catalog(_digest(data), storage_digest, plans, workspaces, (first, last), connector_uid, pdp_uid, pdp_gid,
                   worker_uid, worker_gid)


def check_worker(uid: Any, gid: Any, uid_range: tuple[int, int], others: tuple[int, ...], workspaces: Any,
                 env: Environment, engine_uid: int) -> None:
    """H-14: the file worker's dedicated uid is none of 0, the overflow id, the engine uid (in the prototype the host
    user), the connector's or the PDP's uid, a workspace owner's uid or a reserved uid; its group is not 0, the overflow
    group, a workspace owner's group or a reserved id either. It must not share a uid with the connector, which holds
    the credentials (定稿·部件)."""
    for value in (uid, gid):
        if type(value) is not int or not 0 < value < UID_INVALID - 1:
            raise StartupRefused('invalid file worker uid or gid')
    owners = {w[3] for w in workspaces} | {w[4] for w in workspaces}
    if (uid in (env.overflowuid, engine_uid, *others) or uid in owners or gid in owners or gid == env.overflowgid
            or uid_range[0] <= uid <= uid_range[1] or uid_range[0] <= gid <= uid_range[1]):
        raise StartupRefused('the file worker uid is a sentinel, the engine, connector, PDP or a workspace owner uid, '
                             'or a reserved uid')


def check_pdp(uid: Any, gid: Any, uid_range: tuple[int, int], connector_uid: int, env: Environment,
              engine_uid: int) -> None:
    """K-48, D-13: the PDP's uid is none of 0, the overflow id, the engine uid (in the prototype the host user), the
    connector uid or a reserved uid; its group is not 0 either. "The PDP can only tighten" rests on this."""
    for value in (uid, gid):
        if type(value) is not int or not 0 < value < UID_INVALID - 1:
            raise StartupRefused('invalid PDP uid or gid')
    if uid in (env.overflowuid, engine_uid, connector_uid) or gid == env.overflowgid             or uid_range[0] <= uid <= uid_range[1]:
        raise StartupRefused('the PDP uid is a sentinel, the engine uid, the connector uid or a reserved uid')


RANGE_MAX = 1024   # every uid of the range is checked against NSS at start-up; a larger range is refused


def check_range(first: Any, last: Any, connector_uid: Any, workspaces: Any, env: Environment, engine_uid: int,
                pdp_uid: Any = None) -> None:
    """The reserved range excludes 0, the overflow ids, invalid values, the engine uid, the connector uid, every
    workspace owner and every host account (ER 131 as rewritten for v2; validation.md K-21, S-15). No workspace is
    owned by the engine uid (in the prototype the host user), the connector uid or the PDP uid: the workspace owner is
    a dedicated uid no host process runs as (agent-rm-model 6.2 uid 行; validation.md S-22)."""
    for value in (first, last, connector_uid):
        if type(value) is not int or not 0 < value < UID_INVALID - 1:
            raise StartupRefused('invalid uid range or connector uid')
    if first > last or last - first + 1 > RANGE_MAX:
        raise StartupRefused('uid range empty or too large to verify')
    inside = range(first, last + 1)
    if env.overflowuid in inside or env.overflowgid in inside or engine_uid in inside or connector_uid in inside:
        raise StartupRefused('sentinel, engine or connector uid inside the reserved range')
    if connector_uid in (env.overflowuid, engine_uid):
        raise StartupRefused('connector uid is a sentinel or the engine uid')
    for workspace_id, _, _, uid, gid in workspaces:
        if type(uid) is not int or type(gid) is not int or uid in inside or gid in inside:
            raise StartupRefused(f'workspace owner inside the reserved range: {workspace_id}')
        if uid in (engine_uid, connector_uid) or (pdp_uid is not None and uid == pdp_uid):
            raise StartupRefused(f'workspace owned by the engine, connector or PDP uid: {workspace_id}')
    for uid in inside:
        try:
            pwd.getpwuid(uid)
        except KeyError:
            continue
        raise StartupRefused(f'reserved uid is a host account: {uid}')


def workspace_records(catalog: Catalog) -> dict[str, WorkspaceRecord]:
    return {wid: WorkspaceRecord(wid, layout, source, uid, gid)
            for wid, (_, layout, source, uid, gid) in catalog.workspaces.items()}


def posture() -> dict[str, str]:
    """The engine's own uid/capability posture, for run evidence."""
    keep = {'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp'}
    lines = Path(f'/proc/{os.getpid()}/status').read_text().splitlines()
    return {k: v.strip() for line in lines if ':' in line for k, v in [line.split(':', 1)] if k in keep}
