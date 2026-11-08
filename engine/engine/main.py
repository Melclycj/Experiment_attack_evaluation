"""Engine start: exec'd by w2-cell as the unprivileged engine, control endpoint on fd 3.

usage: engine LIBW2SANDBOX ROOT CATALOG EVIDENCE [--measure-completion]

EVIDENCE is an existing file in the run's evidence directory (trusted, not mounted into any agent); E-09 events are
appended there by the log worker. A refusal before the recorder exists is one JSON line on stdout.
--measure-completion is the measurement switch of the gate (README 完成记录开关): each completion report is also written as
a diagnostic. It changes no decision; without it, as the design has it, completion is not recorded.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import selectors
import sys

from .admin import AdminPort
from .credentials import CredentialStore
from .ffi import Native
from .hook import Hook
from .lifecycle import Lifecycle
from .loop import Clock, Loop
from .pdp import HookDirRefused, HookPort
from .records import Recorder
from .startup import (StartupRefused, check_environment, load_catalog, new_epoch,
                      opt_in_indirect_branch, posture, workspace_records)
from .workspaces import WorkspaceStore

CONTROL_FD = 3
REFUSED_EXIT = 3
CONTROL_LOST_EXIT = 1


@dataclass
class Engine:
    loop: Loop
    lifecycle: Lifecycle
    recorder: Recorder
    hook: Hook | None = None
    admin: AdminPort | None = None
    hook_port: HookPort | None = None


def build(library: Path, root: Path, catalog_name: str, evidence: str | None,
          control_fd: int = CONTROL_FD, clock: Clock | None = None, keep: int = 0,
          measure_completion: bool = False) -> Engine:
    """Self-check and the catalog first; the control endpoint is used only after both pass."""
    mitigation = opt_in_indirect_branch()     # before the engine holds any secret (S14)
    native = Native(library)
    env = check_environment(native)
    catalog = load_catalog(root, catalog_name, env, os.getuid())
    os.set_inheritable(control_fd, False)
    os.set_blocking(control_fd, False)
    epoch = new_epoch()
    clock = clock or Clock()
    recorder = Recorder(epoch, env.overflowuid, clock, evidence, keep=keep)
    recorder.diagnostic('startup_checked', epoch=epoch, uid_map=env.readings['uid_map'], overflowuid=env.overflowuid,
                        overflowgid=env.overflowgid, indirect_branch=mitigation, posture=posture(),
                        catalog_digest=catalog.catalog_digest)
    loop = Loop(clock)
    lifecycle = Lifecycle(loop, native, control_fd, epoch, catalog, workspace_records(catalog), recorder,
                          overflowuid=env.overflowuid)
    # v2 core (block 3): the workspace tables and credential records under <root>/state (engine uid, 0700; K-33), the
    # hook that judges every request, and the management port. The state directory is created by w2-cell.
    state_dir = root / 'state'
    # H-22 (按失败即关，用户 2026-11-05 确认): no host file object may hold or lie in the deployment root, the state directory or
    # the directory of the record file
    protected = [str(root), str(state_dir)] + ([os.path.dirname(os.path.abspath(evidence))] if evidence else [])
    tables = WorkspaceStore(state_dir, protected=protected)
    tables.load()
    # The deployment catalog is the trusted party that names the workspaces (D-10): each catalog workspace without a
    # mirror yet gets its table (default fallback entry) registered by root identity here; a root that does not read
    # (missing, nested) leaves that workspace unavailable, never an empty table (K-19, K-20).
    for wid, (_, _, source, _, _) in catalog.workspaces.items():
        if wid in tables.tables:
            continue
        try:
            tables.register(wid, str(root / source))
        except (OSError, ValueError) as error:          # EntryInvalid is a ValueError
            recorder.diagnostic('workspace_table_refused', workspace_id=wid, reason=str(error))
    credentials = CredentialStore(state_dir)
    credentials.load()
    if credentials.broken:
        recorder.diagnostic('credential_records_unreadable', records=credentials.broken)
    hook = Hook(loop, recorder, tables, credentials, recorder.diagnostic, measure_completion,
                opener=native.open_beneath)                     # H-10: the one way a host file is opened
    lifecycle.hook, lifecycle.tables = hook, tables
    admin = AdminPort(loop, recorder, state_dir, hook, tables, credentials, lifecycle,
                      {wid: str(root / source) for wid, (_, _, source, _, _) in catalog.workspaces.items()})
    # the hook port in <root>/hook, made by the deployment for the PDP's group (648d60f2 4.2; K-48), and the record
    # writer's wake pipe, always registered: a moved receipt is read in the round it lands (K-53)
    try:
        hook_port = HookPort(loop, recorder, root / 'hook', catalog.pdp_uid, catalog.pdp_gid, os.getuid(), hook, tables)
    except (HookDirRefused, OSError) as error:
        raise StartupRefused(f'hook port: {error}') from None
    loop.watch(recorder.wake_r, selectors.EVENT_READ, hook.on_wake)
    lifecycle.start()
    return Engine(loop, lifecycle, recorder, hook, admin, hook_port)


def refused(error: StartupRefused) -> int:
    sys.stdout.write(json.dumps({'event': 'startup_refused', 'reason': str(error)}) + '\n')
    sys.stdout.flush()
    return REFUSED_EXIT


def main(argv: list[str]) -> int:
    if len(argv) not in (4, 5) or argv[4:] not in ([], ['--measure-completion']):
        sys.stderr.write(__doc__ or '')
        return 2
    try:
        engine = build(Path(argv[0]), Path(argv[1]), argv[2], argv[3], measure_completion=len(argv) == 5)
    except StartupRefused as error:
        return refused(error)
    # The trusted caller has no transport in this build (the design defines none); the production entry
    # serves the control link only, and the trusted entries are called in-process by the integration driver.
    while not engine.lifecycle.control.dead:
        engine.loop.run_once(1.0)
    if engine.admin is not None:
        engine.admin.close()
    if engine.hook_port is not None:
        engine.hook_port.close()
    engine.recorder.close()
    return CONTROL_LOST_EXIT
