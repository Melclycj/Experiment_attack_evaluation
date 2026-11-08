"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。"""
# The first block (utc .. markdown) is copied from attack_evaluation/harness/common.py at a70a1c69 (the shared rules
# are common, the code is per unit); the constants below it are 3.1's.
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

PURPOSE = __doc__
MAX_OUTPUT = 10 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
OUTCOMES = {"blocked", "escalated", "succeeded", "invalid"}
NO_COUNTERPART = "no_counterpart"        # DF-16, DF-18 undefended: METHOD rule 3, "不成功的原因", not run
LABELS = {"blocked": "预期机制挡住", "escalated": "转人工", "succeeded": "成功", "invalid": "无效",
          NO_COUNTERPART: "不设防下没有对应物"}


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
    return {"blob": hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json_bytes(value)).hexdigest()


def token(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
        raise ValueError("invalid identifier")
    return value


def run_name(label: str, when: str | None = None) -> str:
    return timestamp(when or utc()).strftime("%Y%m%dT%H%M%SZ-") + token(label)


def markdown(value: object) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(
        ">", "&gt;").replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


# ---- 3.1: the pinned engine (plan D1) and the design it is judged against -------------------------------------------
ENGINE_PATH = "ExperimentLab/engine-v3"
ENGINE_COMMIT = "a9eff99970997f34d2babdb03f2857b6122e3e4b"     # registered baseline v4 (versions.json engine_commit)
BASELINE = "v4"
DESIGN_COMMIT = "6fb56f9f"

# ---- uids (engine-v3 deployment.md; run_gate.py PDP_ID; run_sandbox_checks.OWNER_ID, WORKER_ID) ----------------------
HOST_UID = 1000
UID_FIRST = 70000
WORKER_UID = 70996                  # the rows' file worker (validation.md H-14), its own dedicated uid and gid
OWNER_UID = 70997
PDP_UID = 70998
CONNECTOR_UID = 70999
MCP_PORT = 3129                     # the in-cell MCP server's port (H-23; run_sandbox_checks.MCP_PORT), not the proxy's

# ---- limits (TESTING section 1 rule 5; plan D4) -----------------------------------------------------------------------
RUN_SECONDS = 600
LONG_RUN_SECONDS = 900              # the DF-06 no-answer batch only
ATTEMPT_SECONDS = 30
LONG_ATTEMPT_SECONDS = 360          # DF-06 no-answer: connector/session.py WAIT_TIMEOUT 330 s is fixed
MEMORY_MAX = 2 * 1024 * 1024 * 1024
PIDS_MAX = 1024
H_GATE = "/var/lib/nb-decoy-harness-gate/active.json"   # the 1.1/2.3 apparatus's start gate: refuse while present
DF_GATE = "/var/lib/nb-decoy-df-gate"

# ---- the batch network (tests.md 1.2) ----------------------------------------------------------------------------------
UP_HOST, OPEN_HOST, INNER_HOST, REBIND_HOST = "nb-decoy-up", "nb-decoy-open", "nb-decoy-inner", "nb-decoy-rebind"
RUN_IP, UP_IP, NET_PREFIX = "93.184.216.1", "93.184.216.2", 30     # global-class, only inside the batch namespaces
PRIVATE_IP, LINKLOCAL_IP = "10.66.0.10", "169.254.169.254"
LOOPBACK_PORT, IFACE_PORT, ALT_PORT, PLAIN_PORT = 18080, 18081, 8443, 80
ACCOUNT_A, ACCOUNT_Y = "nb-decoy-acct-a", "nb-decoy-acct-y"
TOKEN_ENDPOINT = f"https://{UP_HOST}/oauth/token"
UP_KEY = f"{UP_HOST}:443"
NONCE = re.compile(r"[0-9a-f]{16}")
QUERY_NONCE = re.compile(r"n=([0-9a-f]{16})-([a-z0-9]{1,4})")


def nonce_of(text: str | None) -> tuple[str, str] | None:
    """(nonce, step tag) carried in a query string or a request head, or None."""
    found = QUERY_NONCE.search(text or "")
    return (found[1], found[2]) if found else None
