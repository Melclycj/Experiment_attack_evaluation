"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Measurement wrapper the batch's catalog names as the connector's executable: the spawner starts the connector with
stdio on /dev/null, and tests.md 1.3 reads the connector's own records (request_refused, upstream_failure,
connection_closed). The wrapper checks that it runs as the connector uid with fds 3 and 4 the inherited sockets, points
fd 2 at a fresh file in the batch's connector-log directory, and execs the pinned connector unchanged, fds 3 and 4
intact. The connector code is not touched; only its stderr is kept.

    python3 -I -B df_connector_log.py LOG_DIR CONNECTOR --library LIB --ca-file CA ... UID EXECUTION
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys

CONNECTOR_UID = 70999


def check(argv: list[str]) -> tuple[Path, Path, list[str]]:
    if len(argv) < 4:
        raise SystemExit("usage: df_connector_log.py LOG_DIR CONNECTOR ARGS... UID EXECUTION")
    log_dir, connector, args = Path(argv[0]), Path(argv[1]), argv[2:]
    if not log_dir.is_absolute() or ".." in log_dir.parts or not log_dir.name.startswith("nb-decoy-"):
        raise SystemExit("log directory does not read")
    if not connector.is_absolute() or connector.name != "connector":
        raise SystemExit("connector path does not read")
    if not args[-2].isdecimal() or not re.fullmatch(r"[A-Za-z0-9_:.-]{1,128}", args[-1]):
        raise SystemExit("row uid or execution id does not read")
    return log_dir, connector, args


def main(argv: list[str]) -> int:
    log_dir, connector, args = check(argv)
    if os.getuid() != CONNECTOR_UID:
        raise SystemExit("the wrapper runs as the connector uid only")
    info = log_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != CONNECTOR_UID or stat.S_IMODE(info.st_mode) != 0o700:
        raise SystemExit("private connector log directory required")
    for fd in (3, 4):                               # before opening anything: a missing fd must not be reused
        if not stat.S_ISSOCK(os.fstat(fd).st_mode):
            raise SystemExit(f"fd {fd} is not the inherited socket")
    name = "nb-decoy-connector-" + re.sub(r"[^A-Za-z0-9_-]", "-", args[-1]) + ".log"
    out = os.open(log_dir / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    if out <= 4:
        raise SystemExit("log descriptor collided with the inherited ones")
    os.dup2(out, 2, inheritable=True)
    os.close(out)
    os.execv(sys.executable, [sys.executable, "-I", "-B", str(connector), *args])
    return 127


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
