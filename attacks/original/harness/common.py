"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

PURPOSE = __doc__
MAX_OUTPUT = 10 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
OUTCOMES = {"blocked", "escalated", "succeeded", "invalid"}
LABELS = {"blocked": "预期机制挡住", "escalated": "转人工",
          "succeeded": "成功", "invalid": "无效"}


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
