"""Unprivileged unit-test harness: the real C library, a scripted spawner on a real SEQPACKET pair."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import socket
import resource
import subprocess
import sys
import tempfile
from typing import Any, Iterator

import pytest

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

from engine.ffi import Native  # noqa: E402
from engine.lifecycle import Lifecycle  # noqa: E402
from engine.loop import MS, Loop  # noqa: E402
from engine.objects import Plan, WorkspaceRecord  # noqa: E402
from engine.records import Recorder  # noqa: E402
from engine.startup import Catalog  # noqa: E402

EPOCH = 'a' * 32
DIGEST = 'sha256:' + '1' * 64


@pytest.fixture(scope='session')
def library() -> Iterator[Path]:
    given = os.environ.get('ENGINE_TEST_LIB')
    if given:
        yield Path(given)
        return
    with tempfile.TemporaryDirectory(prefix='engine-test-build-') as build:
        subprocess.run(['make', '-s', '-C', str(ENGINE / 'native'), f'BUILD_DIR={build}',
                        f'{build}/libw2sandbox.so'], check=True)
        yield Path(build) / 'libw2sandbox.so'


@pytest.fixture(scope='session')
def native(library: Path) -> Native:
    return Native(library)


class FakeClock:
    real = False

    def __init__(self) -> None:
        self.now = 1_000_000 * MS

    def now_ns(self) -> int:
        return self.now

    def advance(self, ms: int) -> None:
        self.now += ms * MS


OVERFLOWUID = int(Path('/proc/sys/kernel/overflowuid').read_text())
SELF = 20   # the one workspace whose uid is this test process's: the kernel stamps the expected uid


def plan(i: int) -> Plan:
    return Plan(f'observe-{i}', f'sha256:{i:064x}', f'work{i}', DIGEST, 'sha256:' + '2' * 64, 'fixture')


def catalog() -> Catalog:
    workspaces = {f'work{i}': (f'work{i}', 'private-work-v1', f'work{i}', 60000 + i, 60000 + i)
                  for i in range(SELF)}
    workspaces[f'work{SELF}'] = (f'work{SELF}', 'private-work-v1', f'work{SELF}', os.getuid(), os.getgid())
    return Catalog('sha256:' + 'c' * 64, 'sha256:' + 'd' * 64,
                   {f'observe-{i}': plan(i) for i in range(SELF + 1)}, workspaces)


class Spawner:
    """Scripted peer. Sends through the real C sender so records may carry SCM_RIGHTS."""

    def __init__(self, native: Native, sock: socket.socket) -> None:
        self.native, self.sock, self.seq = native, sock, 0
        self.received: list[dict[str, Any]] = []

    def wire(self, kind: str, ex: Any = None, seq: int | None = None, **fields: Any) -> bytes:
        if seq is None:
            self.seq += 1
            seq = self.seq
        body: dict[str, Any] = dict(v=1, type=kind, engine_epoch=EPOCH, seq=str(seq))
        if ex is not None:
            body.update(execution_id=ex.execution_id, lease_id=ex.lease_id)
        body.update(fields)
        return json.dumps(body, separators=(',', ':')).encode()

    def raw(self, wire: bytes, fd: int = -1) -> None:
        assert self.native.lib.w2_send_control(self.sock.fileno(), wire, len(wire), fd) == 1

    def send(self, kind: str, ex: Any = None, fd: int = -1, **fields: Any) -> bytes:
        wire = self.wire(kind, ex, **fields)
        self.raw(wire, fd)
        return wire

    def drain(self) -> list[dict[str, Any]]:
        out = []
        while True:
            try:
                data = self.sock.recv(16384, socket.MSG_DONTWAIT)
            except BlockingIOError:
                break
            if not data:  # engine closed its control end
                break
            out.append(json.loads(data))
        self.received += out
        return out

    def ready(self) -> None:
        init = self.drain()[0]
        assert init['type'] == 'control_init' and init['seq'] == '1'
        self.send('control_ready', **{k: init[k] for k in ('catalog_digest', 'protocol',
                                                           'runtime_storage_protocol', 'storage_profile_digest')})

    # Spawner-side facts, in the shapes the reused C parser accepts.
    def prepared(self, ex: Any, **override: Any) -> socket.socket:
        engine_end, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        engine_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        fields = dict(launch_plan_digest=ex.launch_plan_digest, policy_digest=ex.plan.policy_digest,
                      isolation_profile_digest=ex.plan.isolation_profile_digest, child_pid=4242, sealed=True,
                      copy_id=ex.execution_id + ':r')
        fields.update(override)
        self.send('spawn_prepared', ex, fd=engine_end.fileno(), **fields)
        engine_end.close()
        child_end.settimeout(2)
        return child_end

    def failed(self, ex: Any, stage: str = 'validate') -> bytes:
        return self.send('spawn_failed', ex, stage=stage, error_code='os_error', os_errno=None)

    def empty(self, ex: Any, basis: str = 'pid1_reaped') -> bytes:
        terminal = dict(exit_code=None, signal=9) if basis == 'pid1_reaped' else dict(exit_code=None, signal=None)
        return self.send('execution_empty', ex, basis=basis, last_stage='exec', **terminal)

    def runtime(self, ex: Any, state: str = 'released') -> bytes:
        fields = (dict(basis='tree_removed', reason='none', attempt=1, os_errno=None) if state == 'released'
                  else dict(basis='unconfirmed', reason='delete_failed', attempt=1, os_errno=5))
        return self.send('runtime_status', ex, copy_id=ex.execution_id + ':r', state=state, **fields)


class Gate:
    """Wraps the real library; sends of the chosen record types report NOTHING or UNCERTAIN."""

    def __init__(self, inner: Native) -> None:
        self.inner, self.lib = inner, inner.lib
        self.result: Any = None          # None: pass through; else a Sent value
        self.types: tuple[str, ...] = ('spawn', 'stop')

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def recv_control(self, fd: int) -> Any:
        return self.inner.recv_control(fd)

    def send_control(self, fd: int, wire: bytes) -> Any:
        kind = json.loads(wire)['type']
        if self.result is not None and kind in self.types:
            return self.result
        return self.inner.send_control(fd, wire)


class Harness:
    def __init__(self, native: Native, wrap: Any = None, ready: bool = True, resources: Any = None,
                 catalog_: Any = None) -> None:
        engine_end, spawner_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        engine_end.setblocking(False)
        self.clock = FakeClock()
        self.loop = Loop(self.clock)  # type: ignore[arg-type]
        self.recorder = Recorder(EPOCH, OVERFLOWUID, self.clock, None, keep=100_000)
        self.native = wrap(native) if wrap else native
        self.workspaces = {wid: WorkspaceRecord(wid, layout, source, uid, gid)
                           for wid, (_, layout, source, uid, gid) in catalog().workspaces.items()}
        self.lc = Lifecycle(self.loop, self.native, engine_end.detach(), EPOCH, catalog_ or catalog(),
                            self.workspaces, self.recorder, overflowuid=OVERFLOWUID, resources=resources)
        self.spawner = Spawner(native, spawner_end)
        self.lc.start()
        if ready:
            self.spawner.ready()
        self.pump()

    def pump(self, rounds: int = 5) -> None:
        for _ in range(rounds):
            self.loop.run_once(0)

    def launch(self, i: int = 0) -> Any:
        ex = self.lc.launch(f'work{i}', f'observe-{i}', f'agent-{i}')
        self.pump()
        return ex

    def events(self, name: str) -> list[dict[str, Any]]:
        """E-09 events of one kind, or diagnostics of one name with their detail merged in."""
        return [e if e['kind'] != 'diagnostic' else {**e, **e['detail']} for e in self.recorder.events
                if e['kind'] == name or (e['kind'] == 'diagnostic' and e['name'] == name)]

    def faulted(self) -> bool:
        self.pump()
        return self.lc.control.dead


@pytest.fixture
def h(native: Native) -> Harness:
    return Harness(native)


def open_fds() -> set[int]:
    """Open descriptor numbers, probed with fcntl so the probe opens none itself: listing /proc/self/fd holds a
    directory fd during the listing, and a leaked descriptor can sit on that number in a later snapshot."""
    soft = min(resource.getrlimit(resource.RLIMIT_NOFILE)[0], 1 << 16)
    found = set()
    for fd in range(soft):
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError:
            continue
        found.add(fd)
    return found

