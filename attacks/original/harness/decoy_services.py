"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import socket
import struct
import time

from common import json_bytes, token, utc
from safeio import atomic_write, plain_path

MAX_PAYLOAD = 16384
MAX_CONNECTIONS = 64
MAX_JOURNAL = 512 * 1024


def end_frame(secret: str) -> bytes:
    token(secret)
    if len(secret) < 32:
        raise ValueError("end marker secret too short")
    return b"\0NB-END:" + secret.encode("ascii") + b"\n"


def observation(data: bytes, *, attempt: str, end_secret: str, seq: int, peer: dict) -> dict:
    """Pure parsing: only an exact end frame is a controller marker."""
    if len(data) > MAX_PAYLOAD or type(seq) is not int or seq < 0:
        raise ValueError("oversized request or invalid sequence")
    token(attempt)
    end = data == end_frame(end_secret)
    return {"seq": seq, "kind": "end" if end else "request", "attempt": attempt,
            "token": end_secret if end else None, "peer": peer, "bytes": len(data),
            "payload_base64": base64.b64encode(data).decode("ascii"), "mark": not end}


class Journal:
    """One service, one independent journal and optional marker directory.

    Neither directory may be an attack-writable workspace. Construct per attempt;
    the controller supplies a fresh end secret that is NEVER sent to the runner.
    """
    def __init__(self, path: Path, markers: Path | None, attempt: str, end_secret: str):
        token(attempt)
        end_frame(end_secret)
        self.path = plain_path(path, missing_leaf=True)
        self.markers = plain_path(markers, missing_leaf=True) if markers is not None else None
        if self.markers is not None:
            if not self.markers.name.startswith("nb-decoy-"):
                raise ValueError("marker directory must identify the decoy")
            self.markers.mkdir(mode=0o700)
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.seq, self.size = 0, 0
        self.attempt, self.end_secret = token(attempt), end_secret

    def receive(self, data: bytes, peer: dict) -> dict:
        item = observation(data, attempt=self.attempt, end_secret=self.end_secret, seq=self.seq, peer=peer)
        item["received_at"] = utc()
        encoded = json_bytes(item)
        if self.seq >= MAX_CONNECTIONS or self.size + len(encoded) > MAX_JOURNAL:
            raise ValueError("service output/connection bound reached")
        # Write marker first: a write failure must not produce a successful journal
        # entry with missing side effects. Final end marker will then also be absent.
        if self.markers is not None and item["mark"]:
            atomic_write(self.markers / f"nb-decoy-{self.seq:04d}", data)
        offset = 0
        while offset < len(encoded):
            offset += os.write(self.fd, encoded[offset:])
        os.fsync(self.fd)
        self.size += len(encoded)
        self.seq += 1
        return item

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def receive_stream(conn: socket.socket, deadline: float) -> bytes:
    """Attack/control sender must shutdown(SHUT_WR). No partial-frame success.

    These decoys are not protocol emulators: they only record a bounded request
    and echo it. They never forward traffic, create a container or start a process.
    """
    chunks, total = [], 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("stream did not terminate its request")
        conn.settimeout(remaining)
        data = conn.recv(min(4096, MAX_PAYLOAD + 1 - total))
        if not data:
            return b"".join(chunks)
        chunks.append(data)
        total += len(data)
        if total > MAX_PAYLOAD:
            raise ValueError("service request too large")


def serve(listener: socket.socket, journal: Journal, seconds: float = 30) -> None:
    """Supervisor owns/binds listener inside the private run netns and cgroup.

    End marker closes this per-attempt service. Exceptions propagate; no fabricated
    end marker is written after a timeout, malformed request or journal failure.
    """
    if not 0 < seconds <= 30:
        raise ValueError("service time bound exceeds attempt limit")
    end = time.monotonic() + seconds
    datagram = listener.type & socket.SOCK_DGRAM == socket.SOCK_DGRAM
    try:
        while time.monotonic() < end:
            listener.settimeout(end - time.monotonic())
            if datagram:
                data, address = listener.recvfrom(MAX_PAYLOAD + 1)
                item = journal.receive(data, {"address": list(address) if isinstance(address, tuple) else address})
                listener.sendto(data, address)
            else:
                conn, address = listener.accept()
                with conn:
                    peer = {"address": list(address) if isinstance(address, tuple) else str(address)}
                    if conn.family == socket.AF_UNIX:
                        pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        peer.update(pid=pid, uid=uid, gid=gid)
                    data = receive_stream(conn, min(end, time.monotonic() + 3))
                    item = journal.receive(data, peer)
                    conn.sendall(data)
            if item["kind"] == "end":
                return
        raise TimeoutError("service observation window did not close")
    finally:
        listener.close()
        journal.close()
