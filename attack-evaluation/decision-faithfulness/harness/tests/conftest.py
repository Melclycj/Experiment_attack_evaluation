"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Offline tests: normal user, no engine, attack, listener, namespace, cgroup or mount (plan step 7). Socket pairs stand
in where bytes must move. The pinned engine (a9eff999, baseline v4) is read through git archive into a temporary directory.
"""
from __future__ import annotations

import io
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

HARNESS = Path(__file__).resolve().parents[1]
UNIT = HARNESS.parent
SCRIPTS = UNIT / "scripts"
REPO = UNIT.parents[4]
for p in (str(HARNESS), str(SCRIPTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from df_common import ENGINE_COMMIT, ENGINE_PATH  # noqa: E402


@pytest.fixture(scope="session")
def engine_snapshot(tmp_path_factory) -> Path:
    out = subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(REPO), "archive", "--format=tar",
                          ENGINE_COMMIT, f"{ENGINE_PATH}/connector", f"{ENGINE_PATH}/engine",
                          f"{ENGINE_PATH}/client"], capture_output=True, check=True).stdout
    dest = tmp_path_factory.mktemp("ev3")
    with tarfile.open(fileobj=io.BytesIO(out)) as tar:
        tar.extractall(dest, filter="data")
    return dest / ENGINE_PATH


@pytest.fixture(scope="session")
def canonical(engine_snapshot):
    if str(engine_snapshot) not in sys.path:
        sys.path.insert(0, str(engine_snapshot))
    from connector import canonical as c
    assert Path(c.__file__).resolve().is_relative_to(engine_snapshot.resolve())
    return c
