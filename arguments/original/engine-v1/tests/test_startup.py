"""Start-up self-check, mitigation opt-in and pool validation (conn E-01; rr E-08; S14)."""
from __future__ import annotations

import ctypes
import json
import hashlib
from pathlib import Path

import pytest

from engine.startup import (Environment, StartupRefused, check_environment, check_pool, load_catalog,
                            opt_in_indirect_branch)

GOOD = {'uid_map': '         0          0 4294967295\n', 'overflowuid': '65534\n', 'overflowgid': '65534\n',
        'yama': '1\n', 'ksm': '0\n'}
ENV = Environment(65534, 65534, {})


def write(tmp: Path, values: dict[str, str]) -> dict[str, str]:
    paths = {}
    for name, text in values.items():
        (tmp / name).write_text(text)
        paths[name] = str(tmp / name)
    return paths


def test_identity_map_accepted(native, tmp_path: Path) -> None:
    env = check_environment(native, write(tmp_path, GOOD))
    assert (env.overflowuid, env.overflowgid) == (65534, 65534)


@pytest.mark.parametrize('name,text', [('uid_map', '0 1000 1\n'), ('uid_map', '0 0 4294967295\n1 1 1\n'),
                                       ('uid_map', '0 0 4294967294\n'), ('overflowuid', 'x\n')])
def test_non_identity_map_refused(native, tmp_path: Path, name: str, text: str) -> None:
    with pytest.raises(StartupRefused):
        check_environment(native, write(tmp_path, {**GOOD, name: text}))


def test_unreadable_refused(native, tmp_path: Path) -> None:
    paths = write(tmp_path, GOOD)
    paths['overflowuid'] = str(tmp_path / 'missing')
    with pytest.raises(StartupRefused):
        check_environment(native, paths)


def test_indirect_branch_opt_in() -> None:
    calls = []
    state = {'value': 0b011}  # PRCTL | ENABLE

    def prctl(option, which, value, *_):
        calls.append((option, which, value))
        if option == 53:
            state['value'] = 0b1001  # PRCTL | FORCE_DISABLE
            return 0
        return state['value']

    assert opt_in_indirect_branch(prctl) == 'opted_in'
    assert (53, 1, 8) in calls   # PR_SPEC_FORCE_DISABLE, as S14 names

    def plain_disable_only(option, which, value, *_):   # a kernel that leaves plain DISABLE is not accepted
        return 0 if option == 53 else (0b011 if not calls_plain else 0b101)
    calls_plain = []
    def recording(option, which, value, *_):
        result = plain_disable_only(option, which, value)
        if option == 53:
            calls_plain.append(value)
        return result
    with pytest.raises(StartupRefused):
        opt_in_indirect_branch(recording)
    assert opt_in_indirect_branch(lambda *a: 0) == 'not_affected'
    assert opt_in_indirect_branch(lambda *a: 0b1000) == 'kernel_enforced'
    with pytest.raises(StartupRefused):
        opt_in_indirect_branch(lambda *a: 0b010)  # enabled and not controllable


def test_real_kernel_opt_in() -> None:
    assert opt_in_indirect_branch() in ('opted_in', 'not_affected', 'kernel_enforced')
    libc = ctypes.CDLL(None, use_errno=True)
    state = libc.prctl(52, 1, 0, 0, 0)
    assert state == 0 or state & 0b1100
    if state & 0b0001:   # per-task control on this kernel: the opt-in is forced, so it cannot be turned off again
        assert state & 0b1000
        assert libc.prctl(53, 1, 0b0010, 0, 0) == -1 and ctypes.get_errno() == 1   # PR_SPEC_ENABLE -> EPERM


@pytest.mark.parametrize('pool', [
    [('w', '', '', 0, 60000)],                       # uid 0
    [('w', '', '', 65534, 60000)],                   # overflow uid
    [('w', '', '', 60000, 65534)],                   # overflow gid
    [('w', '', '', 4242, 60000)],                    # engine uid
    [('w', '', '', 0xFFFFFFFF, 60000)],              # invalid value
    [('a', '', '', 60000, 60000), ('b', '', '', 60000, 60001)],  # shared uid
    [('a', '', '', 60000, 60000), ('b', '', '', 60001, 60000)],  # shared gid
    [('w', '', '', 1000, 60000)],                    # a host account on this machine
])
def test_pool_excludes_sentinels(pool) -> None:
    with pytest.raises(StartupRefused):
        check_pool(pool, ENV, engine_uid=4242)


def test_pool_accepts_disjoint() -> None:
    check_pool([('a', '', '', 60000, 60000), ('b', '', '', 60001, 60001)], ENV, engine_uid=1000)


def _save(path: Path, value) -> str:
    data = json.dumps(value).encode()
    path.write_bytes(data)
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def test_catalog_artifact_digest_checked(tmp_path: Path) -> None:
    storage = _save(tmp_path / 'storage.json', {'v': 1})
    runtime = _save(tmp_path / 'rt.json', {'runtime_id': 'rt', 'adapter_id': 'fixture', 'protocol': 'w2-local/2'})
    plan = {'launch_plan_id': 'p', 'workspace_id': 'w', 'policy_digest': 'x', 'isolation_profile_digest': 'y',
            'runtime_id': 'rt', 'runtime_descriptor_digest': runtime}
    good = _save(tmp_path / 'plan.json', plan)
    body = {'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage},
            'runtimes': [{'descriptor_ref': 'rt.json', 'descriptor_digest': runtime}],
            'workspaces': [{'workspace_id': 'w', 'workspace_layout_id': 'l', 'source_ref': 'w',
                            'workspace_uid': 60000, 'workspace_gid': 60000}],
            'plans': [{'artifact_ref': 'plan.json', 'artifact_digest': good}]}
    _save(tmp_path / 'catalog.json', body)
    catalog = load_catalog(tmp_path, 'catalog.json', ENV, 4242)
    assert catalog.plans['p'].launch_plan_digest == good and catalog.plans['p'].adapter_id == 'fixture'
    (tmp_path / 'plan.json').write_text(json.dumps({**plan, 'workspace_id': 'w '}))
    with pytest.raises(StartupRefused):
        load_catalog(tmp_path, 'catalog.json', ENV, 4242)


def test_catalog_plan_must_name_its_runtime_descriptor(tmp_path: Path) -> None:
    storage = _save(tmp_path / 'storage.json', {'v': 1})
    runtime = _save(tmp_path / 'rt.json', {'runtime_id': 'rt', 'adapter_id': 'fixture', 'protocol': 'w2-local/2'})
    plan = _save(tmp_path / 'plan.json', {'launch_plan_id': 'p', 'workspace_id': 'w', 'policy_digest': 'x',
                                          'isolation_profile_digest': 'y', 'runtime_id': 'rt',
                                          'runtime_descriptor_digest': 'sha256:' + '0' * 64})
    _save(tmp_path / 'catalog.json', {
        'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage},
        'runtimes': [{'descriptor_ref': 'rt.json', 'descriptor_digest': runtime}],
        'workspaces': [{'workspace_id': 'w', 'workspace_layout_id': 'l', 'source_ref': 'w',
                        'workspace_uid': 60000, 'workspace_gid': 60000}],
        'plans': [{'artifact_ref': 'plan.json', 'artifact_digest': plan}]})
    with pytest.raises(StartupRefused, match='names no catalog runtime'):
        load_catalog(tmp_path, 'catalog.json', ENV, 4242)
