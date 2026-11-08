"""NB-29（WSL 互操作）装置的共用常量与 helper。只打登记基线 v4（engine-v3 @ a9eff999）。

来源：engine 钉住提交 a9eff999；共用 helper 的写法与 3.1 的 harness/df_common.py 一致（共用规定是 common 的，代码按单元建，不跨单元 import）。本装置只考验隔间构造，用最小隔间起法（见 README）。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

# ---- 共用 helper（与 attack_evaluation/harness/common.py 同；规则共用、代码按单元建） ----------------------------------

MAX_OUTPUT = 10 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
OUTCOMES = frozenset({"blocked", "escalated", "succeeded", "invalid"})
LABELS = {"blocked": "预期机制挡住", "escalated": "转人工", "succeeded": "成功", "invalid": "无效"}


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise ValueError("timestamp must specify UTC")
    return parsed


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def identity(data: bytes) -> dict:
    """git blob sha1 + sha256 + length；blob 用来逐文件对 git 的 ls-tree 比基线。"""
    return {"blob": hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json_bytes(value)).hexdigest()


def token(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
        raise ValueError("invalid identifier")
    return value


def run_name(label: str, when: str | None = None) -> str:
    """runs/<UTC>-<label>：创建时按真实 UTC 取（记忆 run-dir-real-start-time）。"""
    return timestamp(when or utc()).strftime("%Y%m%dT%H%M%SZ-") + token(label)


# ---- 钉住的版本（登记基线 v4；与 3.1 同一 engine） --------------------------------------------------------------------

ENGINE_PATH = "ExperimentLab/engine-v3"
ENGINE_COMMIT = "a9eff99970997f34d2babdb03f2857b6122e3e4b"     # 登记基线 v4（versions.json engine_commit）
ENGINE_TREE = "0cb2dac0f40547bb611786230c0eaf514af9aa8d"       # versions.json engine_tree（不含 runs/）
BASELINE = "v4"
DESIGN_COMMIT = "6fb56f9f"
ENGINE_EXCLUDE = ("runs", "__pycache__")

# ---- uids / 端口（engine-v3 deployment.md；run_sandbox_checks 的 stub 用 70999 当 connector） --------------------------

HOST_UID = 1000
UID_FIRST = 70000
UID_LAST = 70015                    # 最小部署的保留区间；一次 execution 租一个、不复用
WORKER_UID = 70996
OWNER_UID = 70997                  # 工作区属主（专用 uid，宿主不以它运行）
PDP_UID = 70998
CONNECTOR_UID = 70999              # stub connector 以此 uid 跑
MCP_PORT = 3129
PROXY_PORT = 3128

# ---- 限时（TESTING §1 规则 5） --------------------------------------------------------------------------------------

RUN_SECONDS = 600
ATTEMPT_SECONDS = 30

# ---- NB-29 自建对象（tests.md §6；只打带 nb-decoy- 前缀的自建物） -----------------------------------------------------

DECOY = "nb-decoy-"
TREE = "tree"                      # catalog.h W2_WORKSPACE_TREE：隔间挂的固定子目录
# 宿主标记：MZ 起的 Windows 进程把本次随机串写到这里；WSL 侧按它判成败。路径在批次里按 Windows 可写位置定，
# 这里只定文件名约定；batch 建目录时填实际路径。
MARKER_NAME = DECOY + "nb29-marker"
# binfmt_misc 宿主前提（tests.md §6.1 的只读实测项）：开跑前读并记录，不改。
WSLINTEROP = "/proc/sys/fs/binfmt_misc/WSLInterop"
WSL_RUN_DIR = "/run/WSL"
HOST_INIT = "/init"
# 开跑前的启动闸（与 1.1/2.3 装置同一把，TESTING §1：有它就拒跑，等用户"开始"）
GATE = "/var/lib/nb-decoy-harness-gate/active.json"
