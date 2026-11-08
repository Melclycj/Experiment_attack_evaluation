"""Engine start: exec'd by w2-cell as the unprivileged engine, control endpoint on fd 3.

usage: engine LIBW2SANDBOX ROOT CATALOG BUSINESS EVIDENCE

EVIDENCE is an existing file in the run's evidence directory (trusted, not mounted into any agent); E-09 events are
appended there by the log worker. A refusal before the recorder exists is one JSON line on stdout.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys

from .business import BusinessCatalog, load_business
from .ffi import Native
from .lifecycle import Lifecycle
from .loop import Clock, Loop
from .records import Recorder
from .startup import (StartupRefused, check_environment, load_catalog, new_epoch,
                      opt_in_indirect_branch, posture, workspace_records)

CONTROL_FD = 3
REFUSED_EXIT = 3
CONTROL_LOST_EXIT = 1


@dataclass
class Engine:
    loop: Loop
    lifecycle: Lifecycle
    recorder: Recorder
    business: BusinessCatalog


def build(library: Path, root: Path, catalog_name: str, business_name: str, evidence: str | None,
          control_fd: int = CONTROL_FD, clock: Clock | None = None, keep: int = 0) -> Engine:
    """Self-check and both catalogs first; the control endpoint is used only after all pass."""
    mitigation = opt_in_indirect_branch()     # before the engine holds any secret (S14)
    native = Native(library)
    env = check_environment(native)
    catalog = load_catalog(root, catalog_name, env, os.getuid())
    business = load_business(root, business_name)
    os.set_inheritable(control_fd, False)
    os.set_blocking(control_fd, False)
    epoch = new_epoch()
    clock = clock or Clock()
    recorder = Recorder(epoch, env.overflowuid, clock, evidence, keep=keep)
    recorder.diagnostic('startup_checked', epoch=epoch, uid_map=env.readings['uid_map'], overflowuid=env.overflowuid,
                        overflowgid=env.overflowgid, indirect_branch=mitigation, posture=posture(),
                        catalog_digest=catalog.catalog_digest,
                        business_catalog_digest=business.business_catalog_digest)
    loop = Loop(clock)
    lifecycle = Lifecycle(loop, native, control_fd, epoch, catalog, workspace_records(catalog), recorder,
                          overflowuid=env.overflowuid, resources=business.resources)
    lifecycle.start()
    return Engine(loop, lifecycle, recorder, business)


def refused(error: StartupRefused) -> int:
    sys.stdout.write(json.dumps({'event': 'startup_refused', 'reason': str(error)}) + '\n')
    sys.stdout.flush()
    return REFUSED_EXIT


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        sys.stderr.write(__doc__ or '')
        return 2
    try:
        engine = build(Path(argv[0]), Path(argv[1]), argv[2], argv[3], argv[4])
    except StartupRefused as error:
        return refused(error)
    # The trusted caller has no transport in this build (the design defines none); the production entry
    # serves the control link only, and the trusted entries are called in-process by the integration driver.
    while not engine.lifecycle.control.dead:
        engine.loop.run_once(1.0)
    engine.recorder.close()
    return CONTROL_LOST_EXIT
