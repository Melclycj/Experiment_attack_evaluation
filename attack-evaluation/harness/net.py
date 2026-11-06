"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import secrets
import time

from cleanup import mounted_id
from env import check_namespaces
from host import namespaces
from safeio import atomic_write, plain_path, read_owned

IP = "/usr/sbin/ip"
UPSTREAM_HOST = "nb-decoy-upstream.test"
QUESTION_HOST = "nb-decoy-question.test"
# Global-class IPs satisfy connector address policy, but exist ONLY in disconnected
# run/decoy namespaces. There is no default route, physical device, NAT or forwarding.
RUN_IP, UPSTREAM_IP, PREFIX = "93.184.216.1", "93.184.216.2", 30


def validate_links(rows: list[dict]) -> None:
    if len(rows) != 1 or rows[0].get("ifname") != "lo":
        raise RuntimeError("fresh run namespace must contain only loopback")


def hosts_bytes(previous: bytes, names=(UPSTREAM_HOST,)) -> bytes:
    if len(previous) > 65536 or b"\0" in previous:
        raise ValueError("invalid hosts input")
    allowed = (UPSTREAM_HOST, QUESTION_HOST)
    if any(name.startswith('nb-decoy-cb-') for name in names):
        from cb_profile import NAMES
        allowed = NAMES
    if not names or len(set(names)) != len(names) or any(
            name not in allowed for name in names):
        raise ValueError("only this run's decoy hostnames are allowed")
    for line in previous.decode("utf-8").splitlines():
        words = line.split("#", 1)[0].split()
        if set(names).intersection(words[1:]):
            raise ValueError("decoy hostname already exists in hosts")
    return previous.rstrip(b"\n") + ("\n" + "".join(f"{UPSTREAM_IP} {name}\n" for name in names)).encode()


def mount_owned(resources, command, argv, target: Path) -> None:
    """Register a completed mount even if command output/timeout processing fails.

    Only a new visible mount at the exact allowed target may be registered. The
    registry's mnt_id check later prevents unmounting a pre-existing hosts layer.
    """
    target = plain_path(target)
    if target != Path("/etc/hosts") and not any(root == target or root in target.parents
                                              for root in resources.roots):
        raise ValueError("mount target outside registered roots")
    before = mounted_id(target)
    try:
        command(argv, timeout=10)
    finally:
        after = mounted_id(target)
        if after != before:
            resources.add_mount(target, Path("/proc/self/mountinfo").read_text())
    if after == before:
        raise RuntimeError("mount command did not create a new mount")


class PrivateNetwork:
    """Network setup only, not a server. All helpers use the cgroup supervisor.

    close() MUST run after stopping engine and before cgroup.kill: it releases
    controller-held netns fds, so killing the holders destroys namespaces/veths.
    No named netns mounts, host interfaces, host routes or host sysctls are edited.
    """
    def __init__(self, command, resources, host: dict):
        self.command, self.resources, self.host = command, resources, host
        self.holders, self.fds = [], []
        self.closed = False
        self.prepared = False
        self.started = False

    def _holder(self):
        remaining = self.command.deadline.left(540)
        child = self.command.start(["/usr/bin/unshare", "--net", "/usr/bin/sleep", str(remaining)],
                                   timeout=remaining)
        self.holders.append(child)
        end = time.monotonic() + self.command.deadline.left(5)
        before = namespaces()["net"]
        while True:
            if child.proc.poll() is not None:
                raise RuntimeError("decoy namespace holder exited")
            path = Path(f"/proc/{child.proc.pid}/ns/net")
            if os.readlink(path) != before:
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                self.fds.append(fd)
                if os.readlink(f"/proc/self/fd/{fd}") == before:
                    raise RuntimeError("holder namespace changed during pinning")
                return child, fd
            if time.monotonic() >= end:
                raise TimeoutError("decoy namespace was not created")
            self.command.pump(.02)

    def in_namespace(self, fd: int, argv: list[str], **kwargs) -> dict:
        if self.closed or fd not in self.fds:
            raise ValueError("namespace does not belong to this run")
        return self.command(["/usr/bin/nsenter", f"--net=/proc/{os.getpid()}/fd/{fd}", "--", *argv], **kwargs)

    def prepare(self) -> dict:
        if self.started or self.closed:
            raise RuntimeError("network setup is single-use")
        self.started = True
        check_namespaces(self.host["namespaces"], namespaces(), Path("/proc/self/mountinfo").read_text())
        links = json.loads(self.command([IP, "-j", "link", "show"])["stdout"])
        validate_links(links)
        if not ipaddress.ip_address(UPSTREAM_IP).is_global:
            raise RuntimeError("connector requires a global-class test address")
        self.command([IP, "link", "set", "lo", "up"])
        upstream, upstream_fd = self._holder()
        candidate, candidate_fd = self._holder()  # NB-26: no veth, initial user namespace
        suffix = secrets.token_hex(2)
        run_if, peer_if = f"nb-decoy-r{suffix}", f"nb-decoy-u{suffix}"
        # Create via a pinned upstream netns fd. Move the peer to the controller's
        # own live PID namespace entry (PID 1), never a potentially recycled holder PID.
        self.in_namespace(upstream_fd, [IP, "link", "add", peer_if, "type", "veth", "peer",
                                       "name", run_if, "netns", str(os.getpid())])
        self.command([IP, "address", "add", f"{RUN_IP}/{PREFIX}", "dev", run_if])
        self.command([IP, "link", "set", run_if, "up"])
        self.in_namespace(upstream_fd, [IP, "link", "set", "lo", "up"])
        self.in_namespace(upstream_fd, [IP, "address", "add", f"{UPSTREAM_IP}/{PREFIX}", "dev", peer_if])
        self.in_namespace(upstream_fd, [IP, "link", "set", peer_if, "up"])
        routes = json.loads(self.command([IP, "-j", "route", "show", "table", "all"])["stdout"])
        if any(row.get("dst") in ("default", "0.0.0.0/0") for row in routes):
            raise RuntimeError("unexpected default route")
        self.prepared = True
        return {"hostname": UPSTREAM_HOST, "address": UPSTREAM_IP,
                "run_interface": run_if, "peer_interface": peer_if,
                "upstream": {"pid": upstream.proc.pid, "fd": upstream_fd},
                "candidate": {"pid": candidate.proc.pid, "fd": candidate_fd}, "routes": routes}

    def bind_hosts(self, generated: Path, names=(UPSTREAM_HOST,)) -> None:
        if not self.prepared or self.closed:
            raise RuntimeError("private network is not ready")
        generated = plain_path(generated, missing_leaf=True)
        if not any(root in generated.parents for root in self.resources.roots):
            raise ValueError("hosts copy outside owned scratch")
        atomic_write(generated, hosts_bytes(read_owned(Path("/etc/hosts"), 65536), names))
        generated.chmod(0o644)
        mount_owned(self.resources, self.command, ["/usr/bin/mount", "--bind", str(generated), "/etc/hosts"],
                    Path("/etc/hosts"))

    def close(self) -> None:
        while self.fds:
            os.close(self.fds.pop())
        self.closed = True
