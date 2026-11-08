"""The gate's derivation suite on engine v4, started from outside the frozen tree.

checks/derive_cell.py was written before the workspace rework and has not run on engine-v3 until now. It treats the
workspace root as the agent's working directory and reads it as the host user. On v4 the root belongs to the storage
uid and the cell mounts its fixed subdirectory TREE, so clearing the root removes TREE (spawn_failed at work_mount,
ENOENT) and the host user cannot read the files. engine-v3 is frozen at baseline v4, so nothing there is changed.
This wrapper changes two things in the running process only:

- clear_workspace empties TREE and leaves TREE itself in place;
- each item's judge reads a fresh copy of TREE owned by the host user, so the judges keep their meaning: the same
  checks on the same files, run as the same user.

Everything else is run_gate.py as committed. Arguments pass through unchanged.
"""
import os
from dataclasses import replace
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, '/mnt/d/Thesis/ExperimentLab/engine-v3/checks')
import run_gate  # noqa: E402  (also puts native/checks on sys.path)
import derive_cell  # noqa: E402
from run_sandbox_checks import TREE  # noqa: E402

HOST_USER = 1000
COPY_ROOT = Path(tempfile.mkdtemp(prefix='derive-copy-'))
os.chmod(COPY_ROOT, 0o755)
VIEW = COPY_ROOT / 'work'
original_items = derive_cell.items


def clear_tree(work: Path) -> None:
    for child in (Path(work) / TREE).iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def sync_view(tree: Path) -> None:
    if VIEW.exists():
        shutil.rmtree(VIEW)
    try:
        shutil.copytree(tree, VIEW, symlinks=True)
    except shutil.Error as error:           # a socket or FIFO in the workspace: the regular files are what the judges read
        print('derive copy skipped:', error, flush=True)
    for path, dirs, files in os.walk(VIEW):
        os.chown(path, HOST_USER, HOST_USER)
        for name in dirs + files:
            os.lchown(os.path.join(path, name), HOST_USER, HOST_USER)


def items(agents, work, as_user, names=()):
    tree = Path(work) / TREE
    out = []
    for item in original_items(agents, VIEW, as_user, names):
        def judged(requests, tail, judge=item.judge):
            sync_view(tree)
            return judge(requests, tail)
        out.append(replace(item, judge=judged))
    return out


derive_cell.items = items
derive_cell.clear_workspace = clear_tree
raise SystemExit(run_gate.main())
