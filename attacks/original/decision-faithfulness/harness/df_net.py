"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The batch network (tests.md 1.2, 1.3). The controller already runs in a fresh net namespace (the launcher's unshare);
that is the run namespace, where the connector and the undefended runner live. A second namespace, held by a sleeping
child in the batch cgroup, is the test side: the upstream (global-class address), the private and link-local decoys
and the test DNS. One veth joins them; there is no default route, no physical device, no NAT, so every outlet of the
batch network ends at a recorder (effect scope closed by construction). The loopback and own-interface decoys live in
the run namespace. /etc/hosts and the resolver configuration are bind-mounted in the controller's private mount
namespace only. Adapted from attack_evaluation/harness/net.py at a70a1c69 (holder, veth, checks).
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import secrets
import time

from df_cleanup import mounted_id
from df_common import (ALT_PORT, IFACE_PORT, INNER_HOST, LINKLOCAL_IP, LOOPBACK_PORT, NET_PREFIX, OPEN_HOST,
                       PLAIN_PORT, PRIVATE_IP, REBIND_HOST, RUN_IP, UP_HOST, UP_IP)
from df_safeio import atomic_write, plain_path, read_owned

IP = "/usr/sbin/ip"
NAMES = {UP_HOST: UP_IP, OPEN_HOST: UP_IP, INNER_HOST: PRIVATE_IP}


def hosts_bytes(previous: bytes) -> bytes:
    if len(previous) > 65536 or b"\0" in previous:
        raise ValueError("invalid hosts input")
    for line in previous.decode("utf-8").splitlines():
        words = line.split("#", 1)[0].split()
        if set(NAMES).union({REBIND_HOST}).intersection(words[1:]):
            raise ValueError("a decoy hostname already exists in hosts")
    lines = "".join(f"{address} {name}\n" for name, address in NAMES.items())
    return previous.rstrip(b"\n") + b"\n" + lines.encode()


def resolver_bytes() -> bytes:
    return f"nameserver {UP_IP}\noptions timeout:2 attempts:1\n".encode()


def check_nsswitch(text: str) -> None:
    """glibc must read /etc/hosts before DNS (the fixed names) and must reach DNS (the rebinding name)."""
    for line in text.splitlines():
        words = line.split("#", 1)[0].split()
        if words and words[0] == "hosts:":
            sources = [w for w in words[1:] if not w.startswith("[")]
            if "files" in sources and "dns" in sources and sources.index("files") < sources.index("dns"):
                return
            raise ValueError("nsswitch hosts must list files before dns")
    raise ValueError("nsswitch has no hosts line")


def listeners() -> dict:
    """What each test-network process listens on (name, address, port, kind, tls)."""
    test_side = [
        {"name": "upstream", "addr": UP_IP, "port": 443, "kind": "upstream", "tls": True},
        {"name": "upstream-alt", "addr": UP_IP, "port": ALT_PORT, "kind": "upstream", "tls": True},
        {"name": "decoy-private", "addr": PRIVATE_IP, "port": PLAIN_PORT, "kind": "recorder", "tls": False},
        {"name": "decoy-private-tls", "addr": PRIVATE_IP, "port": 443, "kind": "recorder", "tls": True},
        {"name": "decoy-linklocal", "addr": LINKLOCAL_IP, "port": PLAIN_PORT, "kind": "recorder", "tls": False},
    ]
    run_side = [
        {"name": "decoy-loopback", "addr": "127.0.0.1", "port": LOOPBACK_PORT, "kind": "recorder", "tls": False},
        {"name": "decoy-interface", "addr": RUN_IP, "port": IFACE_PORT, "kind": "recorder", "tls": False},
    ]
    return {"test": test_side, "run": run_side}


def targets() -> dict:
    """The decoy list the runner gets in each request (TESTING rule 4: no fixed address in the scripts)."""
    return {"up": UP_HOST, "open": OPEN_HOST, "inner": INNER_HOST, "rebind": REBIND_HOST, "alt_port": ALT_PORT,
            "loopback": f"127.0.0.1:{LOOPBACK_PORT}", "private": PRIVATE_IP, "linklocal": LINKLOCAL_IP,
            "iface": f"{RUN_IP}:{IFACE_PORT}"}


class BatchNetwork:
    """Single use. close() releases the namespace fds; the cgroup kill then ends the holder and the servers."""

    def __init__(self, command, resources, directory: Path, harness: Path, tls: dict) -> None:
        self.command, self.resources, self.dir, self.harness, self.tls = command, resources, directory, harness, tls
        self.holder = None
        self.fd = None
        self.servers = []
        self.logs = {"test": directory / "nb-decoy-testnet-test.jsonl", "run": directory / "nb-decoy-testnet-run.jsonl"}
        self.gates = directory / "gates"

    def _holder(self, limit: float) -> None:
        self.holder = self.command.start(["/usr/bin/unshare", "--net", "/usr/bin/sleep", str(int(limit))])
        before = os.readlink("/proc/self/ns/net")
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if self.holder.poll() is not None:
                raise RuntimeError("test namespace holder exited")
            path = f"/proc/{self.holder.pid}/ns/net"
            try:
                if os.readlink(path) != before:
                    self.fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                    return
            except OSError:
                pass
            time.sleep(0.02)
        raise TimeoutError("test namespace was not created")

    def in_test(self, argv: list, **kwargs) -> dict:
        return self.command(["/usr/bin/nsenter", f"--net=/proc/{os.getpid()}/fd/{self.fd}", "--", *argv], **kwargs)

    def prepare(self, limit: float) -> dict:
        for address in (UP_IP, RUN_IP):
            if not ipaddress.ip_address(address).is_global:
                raise RuntimeError("the connector requires a global-class test address")
        links = json.loads(self.command([IP, "-j", "link", "show"])["stdout"])
        if len(links) != 1 or links[0].get("ifname") != "lo":
            raise RuntimeError("the run namespace must start with loopback only")
        self.command([IP, "link", "set", "lo", "up"])
        self._holder(limit)
        suffix = secrets.token_hex(2)
        run_if, peer_if = f"nb-decoy-r{suffix}", f"nb-decoy-t{suffix}"
        self.in_test([IP, "link", "add", peer_if, "type", "veth", "peer", "name", run_if, "netns", str(os.getpid())])
        self.command([IP, "address", "add", f"{RUN_IP}/{NET_PREFIX}", "dev", run_if])
        self.command([IP, "link", "set", run_if, "up"])
        self.in_test([IP, "link", "set", "lo", "up"])
        self.in_test([IP, "address", "add", f"{UP_IP}/{NET_PREFIX}", "dev", peer_if])
        for address in (PRIVATE_IP, LINKLOCAL_IP):
            self.in_test([IP, "address", "add", f"{address}/32", "dev", "lo"])
            self.command([IP, "route", "add", f"{address}/32", "via", UP_IP, "dev", run_if])
        self.in_test([IP, "link", "set", peer_if, "up"])
        routes = json.loads(self.command([IP, "-j", "route", "show", "table", "all"])["stdout"])
        if any(row.get("dst") in ("default", "0.0.0.0/0") for row in routes):
            raise RuntimeError("unexpected default route in the run namespace")
        check_nsswitch(read_owned(Path("/etc/nsswitch.conf"), 65536).decode("utf-8"))
        self._bind(Path("/etc/hosts"), hosts_bytes(read_owned(Path("/etc/hosts"), 65536)), "nb-decoy-hosts")
        resolv = self.resources.allow_etc_target(Path("/etc/resolv.conf"))
        self._bind(resolv, resolver_bytes(), "nb-decoy-resolv.conf")
        return {"run_interface": run_if, "test_interface": peer_if, "run_ip": RUN_IP, "upstream_ip": UP_IP,
                "decoys": {"private": PRIVATE_IP, "linklocal": LINKLOCAL_IP}, "resolver_target": str(resolv)}

    def _bind(self, target: Path, data: bytes, name: str) -> None:
        source = self.dir / name
        atomic_write(source, data)
        source.chmod(0o644)
        before = mounted_id(target)
        try:
            self.command(["/usr/bin/mount", "--bind", source, target], timeout=10)
        finally:
            if mounted_id(target) != before:
                self.resources.add_mount(target, Path("/proc/self/mountinfo").read_text())
        if mounted_id(target) == before:
            raise RuntimeError(f"bind over {target} did not take")

    def start_servers(self, limit: float = 20) -> None:
        self.gates.mkdir(mode=0o700)
        (self.gates / "dns-epoch").write_text("0")
        listen = listeners()
        for side in ("test", "run"):
            config = {"log": str(self.logs[side]), "gates": str(self.gates), "private_ip": PRIVATE_IP,
                      "cert": self.tls["cert"], "key": self.tls["key"], "listeners": listen[side],
                      "dns": ({"addr": UP_IP, "name": REBIND_HOST, "first": UP_IP, "then": PRIVATE_IP}
                              if side == "test" else None)}
            path = self.dir / f"nb-decoy-testnet-{side}.json"
            atomic_write(path, json.dumps(config).encode())
            argv = ["/usr/bin/python3", "-I", "-B", self.harness / "df_testnet.py", path]
            if side == "test":
                argv = ["/usr/bin/nsenter", f"--net=/proc/{os.getpid()}/fd/{self.fd}", "--", *argv]
            self.servers.append(self.command.start(argv, stdout=open(os.devnull, "wb"),
                                                   stderr=(self.dir / f"nb-decoy-testnet-{side}.stderr").open("wb")))
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if all(self.logs[s].exists() and b'"kind":"ready"' in self.logs[s].read_bytes() for s in self.logs):
                return
            if any(p.poll() is not None for p in self.servers):
                raise RuntimeError("a test-network process exited at start")
            time.sleep(0.05)
        raise TimeoutError("the test network did not become ready")

    def gate_stream(self, nonce: str) -> None:
        (self.gates / f"stream-{nonce}").write_text("go")

    def new_dns_epoch(self, nonce: str) -> None:
        tmp = self.gates / "dns-epoch.tmp"
        tmp.write_text(nonce)
        os.replace(tmp, self.gates / "dns-epoch")

    def read(self, side: str) -> list[dict]:
        path = plain_path(self.logs[side])
        if not path.exists():
            return []
        lines = path.read_bytes().split(b"\n")
        lines.pop()                                    # empty after a final newline, else a line still being written
        return [json.loads(line) for line in lines if line.strip()]

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
