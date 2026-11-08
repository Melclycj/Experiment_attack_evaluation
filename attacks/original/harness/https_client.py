"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import ssl
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decoy_services import end_frame
from net import UPSTREAM_HOST


def request(ca: Path, mode: str, secret: str) -> dict:
    """One bounded readiness/end request; spawned in the same cgroup, never on host net."""
    if mode not in ("ready", "end"):
        raise ValueError("invalid controller HTTPS operation")
    context = ssl.create_default_context(cafile=str(ca))
    conn = http.client.HTTPSConnection(UPSTREAM_HOST, 443, context=context, timeout=3)
    try:
        data = secret.encode() if mode == "ready" else end_frame(secret)
        conn.request("POST", "/nb-" + mode, body=data, headers={"Content-Type": "application/octet-stream"})
        response = conn.getresponse()
        body = response.read(4097)
        if response.status != 200 or len(body) > 4096:
            raise RuntimeError("invalid bounded HTTPS response")
        return json.loads(body)
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("internal client: CA MODE; NB_HTTPS_SECRET in environment")
    print(json.dumps(request(Path(sys.argv[1]), sys.argv[2], os.environ["NB_HTTPS_SECRET"])), flush=True)
