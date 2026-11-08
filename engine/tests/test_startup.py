"""Start-up self-check, mitigation opt-in and pool validation (conn E-01; rr E-08; S14)."""
from __future__ import annotations

import ctypes
import json
import hashlib
from pathlib import Path

import pytest

from engine.startup import (Environment, StartupRefused, check_environment, check_range, load_catalog,
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


OWNER = [('w', '', '', 70997, 70997)]      # the dedicated workspace owner (agent-rm-model 3.1; D-17)


@pytest.mark.parametrize('first,last,connector,workspaces', [
    (0, 60003, 70999, OWNER),                 # uid 0 inside
    (65530, 65540, 70999, OWNER),             # overflow uid inside
    (4240, 4250, 70999, OWNER),               # engine uid inside
    (60000, 0xFFFFFFFF, 70999, OWNER),        # invalid value
    (60003, 60000, 70999, OWNER),             # empty range
    (60000, 70000, 70999, OWNER),             # too large to verify against NSS
    (60000, 60003, 60001, OWNER),             # connector uid inside the range
    (60000, 60003, 65534, OWNER),             # connector uid is the overflow uid
    (60000, 60003, 4242, OWNER),              # connector uid is the engine uid
    (60000, 60003, 70999, [('w', '', '', 60001, 1000)]),   # a workspace owner inside the range
    (999, 1001, 70999, OWNER),                # a host account on this machine
])
def test_range_excludes_sentinels(first, last, connector, workspaces) -> None:
    with pytest.raises(StartupRefused):
        check_range(first, last, connector, workspaces, ENV, engine_uid=4242)


def test_range_accepts_a_clean_reserve() -> None:
    check_range(60000, 60015, 70999, OWNER, ENV, engine_uid=1000, pdp_uid=70998)


@pytest.mark.parametrize('owner', [4242, 70999, 70998])
def test_no_workspace_is_owned_by_the_engine_the_connector_or_the_pdp(owner: int) -> None:
    """S-22: the workspace owner is a dedicated uid no host process runs as; the engine uid (4242 here, in the prototype
    the host user), the connector uid and the PDP uid are each refused as an owner."""
    with pytest.raises(StartupRefused, match='engine, connector or PDP'):
        check_range(60000, 60015, 70999, [('w', '', '', owner, 70997)], ENV, engine_uid=4242, pdp_uid=70998)


def test_a_plan_on_a_reserved_transfer_runtime_is_a_transfer_plan(tmp_path: Path) -> None:
    """S-24: the engine knows a transfer plan by its runtime's reserved id, nothing else; other plans carry no mark."""
    storage = _save(tmp_path / 'storage.json', {'v': 1})
    runtimes, plans = [], []
    for runtime_id, plan_id in (('w2-transfer-push', 'w.push'), ('w2-transfer-export', 'w.export'), ('shell', 'w.shell')):
        descriptor = _save(tmp_path / f'{runtime_id}.json', {'runtime_id': runtime_id, 'protocol': 'w2-local/2'})
        runtimes.append({'descriptor_ref': f'{runtime_id}.json', 'descriptor_digest': descriptor})
        plans.append({'artifact_ref': f'{plan_id}.json', 'artifact_digest': _save(tmp_path / f'{plan_id}.json', {
            'launch_plan_id': plan_id, 'workspace_id': 'w', 'policy_digest': 'x', 'isolation_profile_digest': 'y',
            'runtime_id': runtime_id, 'runtime_descriptor_digest': descriptor})})
    _save(tmp_path / 'catalog.json', {
        'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage}, 'runtimes': runtimes,
        'workspaces': [{'workspace_id': 'w', 'workspace_layout_id': 'l', 'source_ref': 'w',
                        'workspace_uid': 70997, 'workspace_gid': 70997}],
        'uid_range': {'first': 60000, 'last': 60015}, 'connector': {'uid': 70999}, 'file_worker': {'uid': 70996, 'gid': 70996}, 'pdp': {'uid': 70998, 'gid': 70998},
        'plans': plans})
    catalog = load_catalog(tmp_path, 'catalog.json', ENV, 4242)
    assert {p: catalog.plans[p].transfer for p in ('w.push', 'w.export', 'w.shell')} == {
        'w.push': 'push', 'w.export': 'export', 'w.shell': ''}


def _save(path: Path, value) -> str:
    data = json.dumps(value).encode()
    path.write_bytes(data)
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def test_catalog_artifact_digest_checked(tmp_path: Path) -> None:
    storage = _save(tmp_path / 'storage.json', {'v': 1})
    runtime = _save(tmp_path / 'rt.json', {'runtime_id': 'rt', 'protocol': 'w2-local/2'})
    plan = {'launch_plan_id': 'p', 'workspace_id': 'w', 'policy_digest': 'x', 'isolation_profile_digest': 'y',
            'runtime_id': 'rt', 'runtime_descriptor_digest': runtime}
    good = _save(tmp_path / 'plan.json', plan)
    body = {'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage},
            'runtimes': [{'descriptor_ref': 'rt.json', 'descriptor_digest': runtime}],
            'workspaces': [{'workspace_id': 'w', 'workspace_layout_id': 'l', 'source_ref': 'w',
                            'workspace_uid': 1000, 'workspace_gid': 1000}],
            'uid_range': {'first': 60000, 'last': 60015}, 'connector': {'uid': 70999}, 'file_worker': {'uid': 70996, 'gid': 70996}, 'pdp': {'uid': 70998, 'gid': 70998},
            'plans': [{'artifact_ref': 'plan.json', 'artifact_digest': good}]}
    _save(tmp_path / 'catalog.json', body)
    catalog = load_catalog(tmp_path, 'catalog.json', ENV, 4242)
    assert catalog.plans['p'].launch_plan_digest == good
    (tmp_path / 'plan.json').write_text(json.dumps({**plan, 'workspace_id': 'w '}))
    with pytest.raises(StartupRefused):
        load_catalog(tmp_path, 'catalog.json', ENV, 4242)


def test_catalog_plan_must_name_its_runtime_descriptor(tmp_path: Path) -> None:
    storage = _save(tmp_path / 'storage.json', {'v': 1})
    runtime = _save(tmp_path / 'rt.json', {'runtime_id': 'rt', 'protocol': 'w2-local/2'})
    plan = _save(tmp_path / 'plan.json', {'launch_plan_id': 'p', 'workspace_id': 'w', 'policy_digest': 'x',
                                          'isolation_profile_digest': 'y', 'runtime_id': 'rt',
                                          'runtime_descriptor_digest': 'sha256:' + '0' * 64})
    _save(tmp_path / 'catalog.json', {
        'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage},
        'runtimes': [{'descriptor_ref': 'rt.json', 'descriptor_digest': runtime}],
        'workspaces': [{'workspace_id': 'w', 'workspace_layout_id': 'l', 'source_ref': 'w',
                        'workspace_uid': 1000, 'workspace_gid': 1000}],
        'uid_range': {'first': 60000, 'last': 60015}, 'connector': {'uid': 70999}, 'file_worker': {'uid': 70996, 'gid': 70996}, 'pdp': {'uid': 70998, 'gid': 70998},
        'plans': [{'artifact_ref': 'plan.json', 'artifact_digest': plan}]})
    with pytest.raises(StartupRefused, match='names no catalog runtime'):
        load_catalog(tmp_path, 'catalog.json', ENV, 4242)


@pytest.mark.parametrize('pdp', [{'uid': 0, 'gid': 70998}, {'uid': 70998, 'gid': 0}, {'uid': 4242, 'gid': 70998},
                                 {'uid': 70999, 'gid': 70998}, {'uid': 60003, 'gid': 70998}, {'uid': 70998},
                                 {'uid': 65534, 'gid': 70998}])
def test_the_pdp_uid_has_no_privilege_and_no_other_role(tmp_path: Path, pdp: dict) -> None:
    """K-48, D-13: not 0, not the engine uid (4242 here), not the connector uid, not a reserved uid, not a sentinel."""
    storage = _save(tmp_path / 'storage.json', {'v': 1})
    _save(tmp_path / 'catalog.json', {
        'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage}, 'runtimes': [], 'workspaces': [],
        'uid_range': {'first': 60000, 'last': 60015}, 'connector': {'uid': 70999}, 'file_worker': {'uid': 70996, 'gid': 70996}, 'pdp': pdp, 'plans': []})
    with pytest.raises(StartupRefused):
        load_catalog(tmp_path, 'catalog.json', ENV, 4242)


@pytest.mark.parametrize('worker', [{'uid': 0, 'gid': 70996}, {'uid': 70996, 'gid': 0}, {'uid': 4242, 'gid': 70996},
                                    {'uid': 70999, 'gid': 70996}, {'uid': 70998, 'gid': 70996},
                                    {'uid': 70997, 'gid': 70996}, {'uid': 60003, 'gid': 70996},
                                    {'uid': 65534, 'gid': 70996}, {'uid': 70996, 'gid': 65534},
                                    {'uid': 70996, 'gid': 60003}, {'uid': 70996}, None],
                         ids=['uid-0', 'gid-0', 'engine', 'connector', 'pdp', 'workspace-owner', 'in-range', 'overflow',
                              'overflow-gid', 'gid-in-range', 'no-gid', 'missing'])
def test_the_worker_uid_has_no_privilege_and_no_other_role(tmp_path: Path, worker: dict | None) -> None:
    """H-14: the file worker's dedicated uid is not 0, a sentinel, the engine uid (4242 here), the connector's, the
    PDP's, a workspace owner's or a reserved uid; its group likewise; the catalog must name it."""
    storage = _save(tmp_path / 'storage.json', {'v': 1})
    body = {'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage}, 'runtimes': [],
            'workspaces': [{'workspace_id': 'w', 'workspace_layout_id': 'l', 'source_ref': 'w',
                            'workspace_uid': 70997, 'workspace_gid': 70997}],
            'uid_range': {'first': 60000, 'last': 60015}, 'connector': {'uid': 70999},
            'pdp': {'uid': 70998, 'gid': 70998}, 'plans': []}
    if worker is not None:
        body['file_worker'] = worker
    _save(tmp_path / 'catalog.json', body)
    with pytest.raises(StartupRefused):
        load_catalog(tmp_path, 'catalog.json', ENV, 4242)


def test_the_catalog_gives_the_worker_uid(tmp_path: Path) -> None:
    storage = _save(tmp_path / 'storage.json', {'v': 1})
    _save(tmp_path / 'catalog.json', {
        'storage_profile': {'artifact_ref': 'storage.json', 'artifact_digest': storage}, 'runtimes': [],
        'workspaces': [], 'uid_range': {'first': 60000, 'last': 60015}, 'connector': {'uid': 70999},
        'file_worker': {'uid': 70996, 'gid': 70996}, 'pdp': {'uid': 70998, 'gid': 70998}, 'plans': []})
    catalog = load_catalog(tmp_path, 'catalog.json', ENV, 4242)
    assert (catalog.worker_uid, catalog.worker_gid) == (70996, 70996)
