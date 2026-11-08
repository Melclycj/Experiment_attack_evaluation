"""The two VM-type core competitors measured in a later round: Gondolin and Kairos (protocol.md 1, 3.1, 9; how each
is installed and why it is set up this way: setup/gondolin.md, setup/kairos.md).

Common to both: a unit is one VM (2 vCPU, 4 GiB, as Docker Sandboxes) plus the host processes made for it, all in
units/u<i>; no cgroup limits, the VM's own settings are its quota. Units start one after another, each checked up
before the next. The terminal holder (`script`, and for Kairos the namespace launcher `unshare` and the FIFO holder)
sits in holders/u<i>: a measurement facility. A unit counts as dead when its launcher or VMM is gone or its workload
has left the guest (k6 while idle, Claude Code while resident). Each pass starts with one model call through the
object's own path, from a unit of its own (u0) that is gone again before baseline 2 (protocol.md 2.2); it must be a
POST /v1/messages answered 200. Its evidence goes into the next repetition's record. Waits end at once when a stop
line is crossed (memory.ObjectPass sets stop_event).

Gondolin (user 2026-10-31: one VM per Node process, as its own CLI and pi example run an agent): a unit is the Node
process running /opt/gondolin/sota-unit.mjs plus its QEMU; no shared parts. The launcher starts k6 (idle) at once and
takes signals: SIGUSR2 model check, SIGUSR1 resident, SIGTERM close. Only u0 installs the response hook that logs
status lines (it makes Gondolin buffer responses instead of streaming them). Its terminal is set to 40x120 first: in
a 0x0 terminal Claude Code stops after its terminal queries (setup/gondolin.md 2.4).

Kairos (user 2026-10-31: one whole Kairos stack per VM, each in its own namespaces, code unmodified): a unit is
everything in its network namespace except the launcher and `script`. The shared part is measurement plumbing only
(forwarding, NAT and the model-API-only rule, net-up.sh), no process. The guest's unit.sh starts k6 (idle) and reads
lines from the unit's terminal, written into a per-unit FIFO: "check" model check, "ping <n>" k6 still running?,
"go" resident.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from .objects import ADAPTERS, AGENT_USER, AS_AGENT, CGBASE, ROOT_ENV, Adapter, Unit, prompt_verdict

UNIT_UP_TIMEOUT, CHECK_TIMEOUT, GONE_TIMEOUT, PING_TIMEOUT = 120, 180, 60, 15
API_HOST, API_PATH, API_STATUS = "api.anthropic.com", "/v1/messages", 200

GONDOLIN = "/opt/gondolin"                       # npm package and sota-unit.mjs
G_IMAGE = "/opt/sota-gondolin/image"            # Debian-rootfs guest image (setup/gondolin.md 2.2)
G_ROOT = "/var/lib/sotamem-gondolin"
G_NODE = "/opt/node-v22.23.4-linux-x64/bin"     # Gondolin needs Node >= 22.19
G_HOME = f"/home/{AGENT_USER}"

K_SETUP = "/opt/sota-setup/kairos"              # net-up/down, unit-up/down (setup/kairos.md 2.3)
K_DEPLOY = "/opt/kairos/deploy"                 # commit KAIROS_COMMIT, unmodified
K_VOL = "/var/lib/sotamem-kairos"               # btrfs volume: base image (holds the key), unit dirs, logs
K_FIFO = "/run/sotamem-kairos"                  # the units' terminal FIFOs, nothing else
KAIROS_COMMIT = "52563455095f3a1eaa882fe5717f02a347c32462"
# A Kairos unit's own processes, by a piece of their command line, and how many (setup/kairos.md 2.4).
K_STACK = {"cloud-hypervisor": 1, "virtiofsd": 2, "fs_monitor.py": 2, "mitmdump": 1, "dnsmasq": 1, "serve.py": 1}

QEMU_COMM, CH_COMM = "qemu-system-x86", "cloud-hyperviso"   # /proc/<pid>/comm, 15 characters
RC = re.compile(r"sota: check rc=(\d+)")
G_CLAUDE_SHA = "4f4178ce41d83e23341ebfbaecdbcf8ea6bf7baea0690025abe49eeec3a5d01d"   # 2.1.312 linux-x64 (protocol.md 9)
K_CLAUDE_SHA = "78adef63924b762580b039c9ff0dd2ae44eb06171d467db62fd9040442505f76"   # 2.1.312 linux-x64-musl


class WaitTimeout(RuntimeError):
    """A wait ran out of time (other RuntimeErrors, such as the agent's, are not timeouts)."""


def gondolin_model_ok(events: list[dict]) -> tuple[bool, dict]:
    """The launcher's events after a check: POST /v1/messages on api.anthropic.com answered 200, and exit code 0."""
    http = [e for e in events if e.get("kind") == "http"]
    check = next((e for e in events if e.get("kind") == "check"), None)
    hit = any(e.get("method") == "POST" and e.get("host") == API_HOST and e.get("path") == API_PATH
              and e.get("status") == API_STATUS for e in http)
    return check is not None and check.get("exit") == 0 and hit, {"http": http, "check": check}


def kairos_model_ok(net_events: list[dict], screen: str) -> tuple[bool, dict]:
    """Kairos's net_events after a check: POST /v1/messages on api.anthropic.com answered 200 (method from the
    request event of the same flow), and unit.sh's rc=0. Only method, host, path and status are kept: request events
    carry the headers, the key among them."""
    methods = {e.get("flow"): e.get("method") for e in net_events if e.get("kind") == "request"}
    responses = [{"method": methods.get(e.get("flow")), "host": e.get("host"),
                  "path": urlsplit(str(e.get("url", ""))).path, "status": e.get("status")}
                 for e in net_events if e.get("kind") == "response"]
    found = RC.findall(screen)
    rc = found[-1] if found else None
    hit = any(r["method"] == "POST" and r["host"] == API_HOST and r["path"] == API_PATH and r["status"] == API_STATUS
              for r in responses)
    return rc == "0" and hit, {"responses": responses, "rc": rc}


def _jsonl(path: Path) -> list[dict]:
    out = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    except OSError:
        pass
    return out


def _cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        return ""


def _comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return ""


def _pids_matching(*parts: str) -> list[int]:
    """Processes whose command line contains every part, read from /proc (a pgrep inside `sh -c` would count the
    shell itself, whose command line holds the pattern)."""
    return [int(d.name) for d in Path("/proc").iterdir() if d.name.isdigit()
            and (cmd := _cmdline(int(d.name))) and all(x in cmd for x in parts)]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _out(argv: list[str], timeout: float = 60) -> str:
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=ROOT_ENV)
    return (r.stdout + r.stderr).strip()


def _debugfs_sha(image: str, path: str) -> str:
    """sha256 of one file inside an ext4 image, read without mounting it. Streamed: the driver's own memory (a
    measurement facility) must not grow by the file's size before baseline 1."""
    h, size = hashlib.sha256(), 0
    with subprocess.Popen(["debugfs", "-R", f"cat {path}", image], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as proc:
        for block in iter(lambda: proc.stdout.read(1 << 20), b""):
            h.update(block)
            size += len(block)
    return h.hexdigest() if size and proc.returncode == 0 else ""


class _VmObject(Adapter):
    VMM_COMM = ""
    stop_event = None   # memory.ObjectPass sets the watch's breach event

    def __init__(self, agent_getter, key: str) -> None:
        super().__init__(agent_getter, key)
        self.model_check: dict = {}
        self.state = ""

    # ---- helpers ----
    def _wait_for(self, pred, timeout: float, what: str) -> None:
        deadline = time.monotonic() + timeout
        while not pred():
            if self.stop_event is not None and self.stop_event.is_set():
                from .memory import StopRun   # late: memory imports objects, which imports this module
                raise StopRun(f"limit crossed while waiting for {what}")
            if time.monotonic() > deadline:
                raise WaitTimeout(f"{what}: not within {timeout:.0f} s")
            time.sleep(1)

    def _unit_cg(self, i: int) -> str:
        return self.agent.call("mkcg", rel=f"units/u{i}")["path"]

    def _holders_cg(self, i: int) -> str:
        return self.agent.call("mkcg", rel=f"holders/u{i}")["path"]

    def _to_holders(self, i: int, pids: list[int]) -> None:
        cg = self._holders_cg(i)
        for pid in pids:
            self.agent.call("write", path=f"{cg}/cgroup.procs", text=str(pid))

    def _unit_pids(self, i: int) -> list[int]:
        return self._pids(f"{CGBASE}/units/u{i}")

    def _vmms(self, i: int) -> int:
        return sum(_comm(p) == self.VMM_COMM for p in self._unit_pids(i))

    def _launcher_alive(self, u: Unit) -> bool:
        pid = u.handles.get("spawn")
        return bool(pid) and bool(self.agent.call("alive", pids=[pid]).get(str(pid)))

    def _kill_unit_groups(self, i: int) -> list[str]:
        errors = []
        for group in ("units", "holders"):
            try:
                r = self.agent.call("killcg", path=f"{CGBASE}/{group}/u{i}")
                if r.get("remaining"):
                    errors.append(f"u{i}: {r['remaining']} processes left in {group}/u{i}")
            except Exception as exc:
                errors.append(f"u{i}: killcg {group}: {type(exc).__name__}: {exc}")
        return errors

    def _rm(self, *paths: str) -> list[str]:
        try:
            r = self.agent.call("exec", argv=["rm", "-rf", *paths], env=ROOT_ENV, timeout=120)
            return [] if r["rc"] == 0 else [f"rm {paths}: {r['stdout'][-200:]}"]
        except Exception as exc:
            return [f"rm {paths}: {type(exc).__name__}: {exc}"]

    # ---- lifecycle ----
    def workload_dead(self, u: Unit) -> str:
        """Why the unit's workload is gone from the guest ("" = it is running)."""
        return ""

    def alive(self) -> list[str]:
        dead = []
        for u in self.units:
            why = ("launcher exited" if not self._launcher_alive(u) else "") \
                or (f"{n} VMMs" if (n := self._vmms(u.index)) != 1 else "") or self.workload_dead(u)
            if why:
                dead.append(f"{u.name}: {why}")
        return dead

    def create_units(self, n: int) -> list[Unit]:
        """One after another: each unit is registered before anything of it starts (so a failure leaves it to
        destroy_units) and checked up before the next starts. Units still registered from a failed teardown are
        torn down first; if that fails again nothing new is built (their cgroups and names would be reused)."""
        if self.units:
            self.destroy_units()
        self.state = "starting"
        for i in range(1, n + 1):
            u = self._new_unit(i)
            self.units.append(u)
            self._launch(u)
            self._up(u)
        return self.units

    def destroy_units(self) -> None:
        """Every unit is torn down even if one fails; the register is cleared only when all went cleanly, so the
        pass's cleanup tries again."""
        errors = self._teardown(self.units)
        if errors:
            raise RuntimeError(f"{self.name}: teardown incomplete: {errors}")
        self.units, self.state = [], ""

    def _model_check_unit(self, run) -> None:
        """u0: launched, checked and torn down here. If its teardown fails it joins the register, so the pass's
        cleanup tries again, and the error names the check's own failure too (it would otherwise be replaced)."""
        u = self._new_unit(0)
        failure: BaseException | None = None
        try:
            self._launch(u, check_unit=True)
            self._up(u)
            run(u)
        except BaseException as exc:
            failure = exc
            raise
        finally:
            errors = self._teardown([u])
            if errors:
                self.units.append(u)
                first = f"; before that: {type(failure).__name__}: {failure}" if failure else ""
                raise RuntimeError(f"{self.name}: model check unit teardown incomplete: {errors}{first}") from failure

    def prompt_evidence(self) -> dict[str, dict]:
        return {u.name: prompt_verdict(self._screen(u.handles["screen"])) for u in self.units}

    def rep_notes(self) -> dict:
        check, self.model_check = self.model_check, {}
        return {"model_check": check} if check else {}

    def _record(self, facts: dict) -> None:
        """The object's versions and image hashes (no key) in the run directory."""
        if self.run_dir is None:
            return
        dest = Path(self.run_dir) / "objects"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{self.name}.json").write_text(json.dumps(facts, indent=1), encoding="utf-8")


class Gondolin(_VmObject):
    name = "gondolin"
    VMM_COMM = QEMU_COMM

    def _env(self, check_unit: bool) -> dict[str, str]:
        env = {"HOME": G_HOME, "USER": AGENT_USER, "PATH": f"{G_NODE}:/usr/bin:/bin", "TERM": "xterm-256color",
               "LANG": "C.UTF-8", "SOTA_ANTHROPIC_API_KEY": self.key}   # environment only, never argv
        if check_unit:
            env["SOTA_LOG_HTTP"] = "1"
        return env

    def prepare(self) -> None:
        manifest = Path(G_IMAGE, "manifest.json")
        if not manifest.exists():
            raise RuntimeError(f"no Gondolin guest image at {G_IMAGE} (setup/gondolin.md 2.2)")
        self.stop_shared()
        self._run(["install", "-d", "-o", AGENT_USER, "-g", AGENT_USER, "-m", "0700", G_ROOT])
        m = json.loads(manifest.read_text(encoding="utf-8"))
        package = Path(GONDOLIN, "node_modules/@earendil-works/gondolin/package.json")
        claude = _debugfs_sha(f"{G_IMAGE}/rootfs.ext4", "/opt/sota/claude")
        if claude != G_CLAUDE_SHA:   # also catches an image left by a build that failed its own check
            raise RuntimeError(f"{G_IMAGE} does not hold Claude Code 2.1.312 ({claude or 'unreadable'}): rebuild it")
        self._record({
            "gondolin": json.loads(package.read_text(encoding="utf-8"))["version"],
            "node": _out([f"{G_NODE}/node", "--version"]),
            "qemu": _out(["qemu-system-x86_64", "--version"]).splitlines()[0],
            "image_build_id": m.get("buildId"), "image_oci_source": m.get("ociSource"),
            "image_manifest_sha256": _sha256(str(manifest)),
            "claude_in_image_sha256": claude, "launcher_sha256": _sha256(f"{GONDOLIN}/sota-unit.mjs")})

    def _new_unit(self, i: int) -> Unit:
        root = Path(G_ROOT, f"u{i}")
        return Unit(i, f"u{i}", {"root": str(root), "screen": str(root / "screen.log")})

    def _launch(self, u: Unit, check_unit: bool = False) -> None:
        root = Path(u.handles["root"])
        self._run(["rm", "-rf", str(root)])
        self._run(["install", "-d", "-o", AGENT_USER, "-g", AGENT_USER, "-m", "0700", str(root), str(root / "work")])
        cmd = f"stty rows 40 cols 120; exec node {GONDOLIN}/sota-unit.mjs {root}/work {G_IMAGE} {root}/events.jsonl"
        r = self.agent.call("spawn", cgroup=self._unit_cg(u.index),
                            argv=[*AS_AGENT, "script", "-qfc", cmd, u.handles["screen"]],
                            cwd=GONDOLIN, env=self._env(check_unit), log=str(root / "unit.out"), pty=False)
        u.handles["spawn"] = r["pid"]

    def _events(self, u: Unit) -> list[dict]:
        return _jsonl(Path(u.handles["root"], "events.jsonl"))

    def _has(self, u: Unit, kind: str, **match) -> bool:
        return any(e.get("kind") == kind and all(e.get(k) == v for k, v in match.items()) for e in self._events(u))

    def _up(self, u: Unit) -> None:
        def up() -> bool:
            if not self._launcher_alive(u):
                raise RuntimeError(f"{u.name}: launcher exited before idle: {self._screen(u.handles['screen'])[-400:]}")
            events = self._events(u)
            if "node" not in u.handles:   # known as soon as the VM exists, so a unit stuck before idle can be closed
                u.handles.update({"node": e["node_pid"] for e in events if e.get("node_pid")})
            return any(e.get("kind") == "state" and e.get("state") == "idle" for e in events)
        self._wait_for(up, UNIT_UP_TIMEOUT, f"Gondolin {u.name} idle")
        self._to_holders(u.index, [u.handles["spawn"]])   # script: holds the terminal

    def workload_dead(self, u: Unit) -> str:
        kinds = {e.get("kind") for e in self._events(u)}
        if "unhandled" in kinds:
            return "launcher error"
        if self.state == "idle" and "probe-exit" in kinds:
            return "k6 exited in the guest"
        if self.state == "resident" and "agent-exit" in kinds:
            return "Claude Code exited in the guest"
        return ""

    def _signal(self, u: Unit, sig: str) -> None:
        self._run(["kill", f"-{sig}", str(u.handles["node"])], check=False)

    def start_shared(self) -> None:
        """No shared parts. The model check runs in u0, closed before baseline 2."""
        def run(u: Unit) -> None:
            self._signal(u, "USR2")
            self._wait_for(lambda: self._has(u, "check"), CHECK_TIMEOUT, "Gondolin model check")
            ok, evidence = gondolin_model_ok(self._events(u))
            self.model_check = {"unit": "u0", "ok": ok, **evidence}
            if not ok:
                raise RuntimeError(f"Gondolin model check did not get POST {API_PATH} {API_STATUS}: {evidence}")
        self._model_check_unit(run)

    def set_state(self, state: str) -> None:
        if state == "idle":
            self.state = "idle"   # the launcher starts k6 as soon as its VM is up (create_units waits for that)
            return
        if state != "resident":
            raise ValueError(state)
        self.state = "resident"
        for u in self.units:
            self._signal(u, "USR1")
        self._wait_for(lambda: all(self._has(u, "state", state="resident") for u in self.units), UNIT_UP_TIMEOUT,
                       "Gondolin units resident")

    def _teardown(self, units: list[Unit]) -> list[str]:
        """SIGTERM: the launcher closes its VM (Gondolin deletes the qcow2 overlay, its sockets and the session
        entry); whatever is left after GONE_TIMEOUT is killed with the cgroup, and its leftovers are removed here."""
        signalled = [u for u in units if u.handles.get("node")]
        for u in signalled:
            try:
                self._signal(u, "TERM")
            except Exception:
                pass   # the cgroup kill below still ends it
        deadline = time.monotonic() + GONE_TIMEOUT   # only units that got SIGTERM can close by themselves
        while any(self._unit_pids(u.index) for u in signalled) and time.monotonic() < deadline:
            time.sleep(0.5)
        errors = [e for u in units for e in self._kill_unit_groups(u.index)]
        try:
            if not self._pids(f"{CGBASE}/units"):
                r = self.agent.call("exec", env=ROOT_ENV, timeout=60, argv=[
                    "sh", "-c", f"rm -rf /tmp/gondolin-* {G_HOME}/.cache/gondolin/sessions/*"])
                if r["rc"] != 0:
                    errors.append(f"removing Gondolin leftovers: {r['stdout'][-200:]}")
        except Exception as exc:
            errors.append(f"removing Gondolin leftovers: {type(exc).__name__}: {exc}")
        for u in units:
            errors += self._rm(u.handles["root"])
        return errors

    def residue(self) -> list[str]:
        sessions = Path(G_HOME, ".cache/gondolin/sessions")
        counts = {"QEMU processes": len(_pids_matching("qemu-system-x86_64", G_IMAGE)),
                  "launcher processes": len(_pids_matching(f"{GONDOLIN}/sota-unit.mjs", "node")),
                  "files in /tmp": len(list(Path("/tmp").glob("gondolin-*"))),
                  "session entries": len(list(sessions.iterdir())) if sessions.is_dir() else 0,
                  "unit directories": len(list(Path(G_ROOT).glob("u*"))),
                  "unit processes": len(self._pids(f"{CGBASE}/units")),
                  "holder processes": len(self._pids(f"{CGBASE}/holders"))}
        return [f"{count} Gondolin {what} left" for what, count in counts.items() if count]


class Kairos(_VmObject):
    name = "kairos"
    VMM_COMM = CH_COMM

    def __init__(self, agent_getter, key: str) -> None:
        super().__init__(agent_getter, key)
        self.pings = 0

    def prepare(self) -> None:
        self._run(["sh", "-c", f"mountpoint -q {K_VOL} || mount -o loop {K_VOL}.btrfs {K_VOL}"], env=ROOT_ENV)
        base = Path(K_VOL, "base.ext4")
        if not base.exists():
            raise RuntimeError(f"no Kairos base image at {base} (setup/kairos.md 2.2)")
        unit_sh = _debugfs_sha(str(base), "/opt/sota/unit.sh")
        if unit_sh != _sha256(f"{K_SETUP}/unit.sh"):
            raise RuntimeError(f"{base} holds another unit.sh than {K_SETUP}/unit.sh: rebuild it (build-base.sh)")
        claude = _debugfs_sha(str(base), "/opt/sota/claude")
        if claude != K_CLAUDE_SHA:
            raise RuntimeError(f"{base} does not hold Claude Code 2.1.312 musl ({claude or 'unreadable'}): rebuild it")
        commit = Path(K_DEPLOY).parent.joinpath("COMMIT").read_text().strip()   # written from the archive at install
        if commit != KAIROS_COMMIT:
            raise RuntimeError(f"{K_DEPLOY} is commit {commit}, not {KAIROS_COMMIT}")
        self.stop_shared()
        self._run(["mkdir", "-p", f"{K_VOL}/logs"])
        self._record({
            "kairos_commit": commit, "cloud_hypervisor": _out(["cloud-hypervisor", "--version"]),
            "virtiofsd": _out(["virtiofsd", "--version"]),
            "guest_kernel_sha256": _sha256(f"{K_DEPLOY}/images/vmlinux-6.2.0"),
            "kairos_image_sha256_at_build": Path(K_VOL, "kairos-image.sha256").read_text().strip(),
            "base_sha256_at_build": Path(K_VOL, "base.sha256").read_text().strip(),
            "python_packages": [ln for ln in Path("/opt/venv-kairos/freeze.txt").read_text().splitlines()
                                if ln.lower().startswith(("mitmproxy==", "fusepy=="))],
            "claude_in_base_sha256": claude, "unit_sh_sha256": unit_sh,
            "setup_scripts_sha256": {p.name: _sha256(str(p)) for p in sorted(Path(K_SETUP).glob("*.sh"))}})

    def start_shared(self) -> None:
        """The plumbing (net-up.sh), then the model check in u0, gone before baseline 2."""
        net = self._run(["bash", f"{K_SETUP}/net-up.sh"], env=ROOT_ENV).strip()

        def run(u: Unit) -> None:
            self._line(u, "check")
            self._wait_for(lambda: self._screen_has(u, RC.pattern, regex=True), CHECK_TIMEOUT, "Kairos model check")
            sessions = sorted(Path(K_VOL, "u0", "lib", "sessions").glob("2*"))
            events = _jsonl(sessions[-1] / "net_events.jsonl") if sessions else []
            ok, evidence = kairos_model_ok(events, self._screen(u.handles["screen"]))
            self.model_check = {"unit": "u0", "ok": ok, "net": net, **evidence}
            if not ok:
                raise RuntimeError(f"Kairos model check did not get POST {API_PATH} {API_STATUS}: {evidence}")
        self._model_check_unit(run)

    def stop_shared(self) -> None:
        r = self.agent.call("exec", argv=["bash", f"{K_SETUP}/net-down.sh"], env=ROOT_ENV, timeout=120)
        if r["rc"] != 0:
            raise RuntimeError(f"Kairos net-down failed: {r['stdout'][-400:]}")

    def _new_unit(self, i: int) -> Unit:
        return Unit(i, f"u{i}", {"fifo": f"{K_FIFO}/u{i}.in", "screen": f"{K_VOL}/u{i}/screen.log"})

    def _launch(self, u: Unit, check_unit: bool = False) -> None:
        i, fifo = u.index, u.handles["fifo"]
        # a failed earlier teardown may have left the unit's directory; its old screen would pass _up at once
        self._run(["sh", "-c", f"rm -rf {K_VOL}/u{i} && mkdir -p {K_FIFO} && rm -f {fifo} && mkfifo -m 0600 {fifo}"])
        # keeps the FIFO open read-write so the unit never reads EOF between the lines the driver writes
        self.agent.call("spawn", cgroup=self._holders_cg(i), argv=["sh", "-c", 'exec sleep infinity 3<>"$0"', fifo],
                        cwd="/", env=ROOT_ENV, log="/dev/null", pty=False)
        r = self.agent.call("spawn", cgroup=self._unit_cg(i), argv=["sh", "-c", 'exec bash "$0" "$1" < "$2"',
                                                                     f"{K_SETUP}/unit-up.sh", str(i), fifo],
                            cwd="/", env=ROOT_ENV, log=f"{K_VOL}/logs/u{i}.out", pty=False)
        u.handles["spawn"] = r["pid"]

    def _screen_has(self, u: Unit, marker: str, regex: bool = False) -> bool:
        return self.agent.call("exec", argv=["grep", "-a", "-q", "-P" if regex else "-F", marker, u.handles["screen"]],
                               timeout=30)["rc"] == 0

    def _stack(self, i: int) -> dict[str, int]:
        cmds = [_cmdline(p) for p in self._unit_pids(i)]
        return {part: sum(part in c for c in cmds) for part in K_STACK}

    def _up(self, u: Unit) -> None:
        def up() -> bool:
            if not self._launcher_alive(u):
                raise RuntimeError(f"{u.name}: unit exited before idle: {self._screen(u.handles['screen'])[-400:]}")
            return self._screen_has(u, "sota: idle")
        self._wait_for(up, UNIT_UP_TIMEOUT, f"Kairos {u.name} idle")
        launcher = u.handles["spawn"]   # after the execs in unit-up.sh this pid is `unshare`
        script = [int(p) for p in self._run(["pgrep", "-P", str(launcher)], check=False).split()]
        self._to_holders(u.index, [launcher, *script])
        stack = self._stack(u.index)
        if stack != K_STACK:
            raise RuntimeError(f"{u.name}: incomplete Kairos stack {stack}, expected {K_STACK}")

    def _line(self, u: Unit, text: str) -> None:
        self._run(["timeout", "10", "sh", "-c", f"printf '%s\\n' '{text}' > {u.handles['fifo']}"])

    def workload_dead(self, u: Unit) -> str:
        stack = self._stack(u.index)   # at least each part: a short-lived child of the same name is not a death
        if any(stack[part] < n for part, n in K_STACK.items()):
            return f"stack incomplete {stack}"
        if self.state != "idle":
            return ""   # resident: Claude Code exiting ends run.sh and the whole unit, seen by alive()
        self.pings += 1
        token = f"sota: pong {self.pings} "
        self._line(u, f"ping {self.pings}")
        try:
            self._wait_for(lambda: self._screen_has(u, token), PING_TIMEOUT, f"Kairos {u.name} ping")
        except WaitTimeout:
            return "no answer to ping"
        return "" if self._screen_has(u, token + "ok") else "k6 exited in the guest"

    def set_state(self, state: str) -> None:
        if state == "idle":
            self.state = "idle"   # unit.sh starts k6 as soon as the guest is up (create_units waits for that)
            return
        if state != "resident":
            raise ValueError(state)
        self.state = "resident"
        for u in self.units:
            self._line(u, "go")

    def _teardown(self, units: list[Unit]) -> list[str]:
        errors = []
        for u in units:
            try:
                r = self.agent.call("exec", argv=["bash", f"{K_SETUP}/unit-down.sh", str(u.index)], env=ROOT_ENV,
                                    timeout=120)
                if r["rc"] != 0:
                    errors.append(f"{u.name}: unit-down: {r['stdout'][-300:]}")
            except Exception as exc:
                errors.append(f"{u.name}: unit-down: {type(exc).__name__}: {exc}")
            errors += self._kill_unit_groups(u.index)
            errors += self._rm(u.handles["fifo"], f"{K_VOL}/logs/u{u.index}.out")
        return errors

    def residue(self) -> list[str]:
        netns = self._run(["ip", "netns", "list"], check=False, env=ROOT_ENV)
        links = self._run(["ip", "-br", "link"], check=False, env=ROOT_ENV)
        rules = self._run(["iptables", "-S"], check=False, env=ROOT_ENV)
        nat = self._run(["iptables", "-t", "nat", "-S"], check=False, env=ROOT_ENV)
        counts = {"namespaces": netns.count("sotakai"),
                  "veth links": sum(ln.startswith("kh") for ln in links.splitlines()),
                  "VMs": len(_pids_matching("cloud-hypervisor", K_DEPLOY)),
                  "filter rules": sum("SOTA_KAIROS" in ln or "kh+" in ln for ln in rules.splitlines()),
                  "nat rules": sum("10.201." in ln for ln in nat.splitlines()),
                  "ip_forward not restored": int(Path(K_VOL, "ip_forward.before").exists()),
                  "netns resolver files": len(list(Path("/etc/netns").glob("sotakai*"))),
                  "FIFOs": len(list(Path(K_FIFO).glob("*"))) if Path(K_FIFO).is_dir() else 0,
                  "unit directories (hold the key)": len(list(Path(K_VOL).glob("u[0-9]*"))),
                  "unit processes": len(self._pids(f"{CGBASE}/units")),
                  "holder processes": len(self._pids(f"{CGBASE}/holders"))}
        return [f"{count} Kairos {what} left" for what, count in counts.items() if count]


def _step(left: list[str], what: str, argv: list[str], timeout: float = 120) -> None:
    """One sweep step; its failure is recorded with stdout and stderr and never stops the steps after it."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=ROOT_ENV)
        if r.returncode != 0:
            left.append(f"{what}: {(r.stdout + r.stderr).strip()[-300:]}")
    except Exception as exc:
        left.append(f"{what}: {type(exc).__name__}: {exc}")


def sweep() -> list[str]:
    """After every run, also after a Python exception or SIGINT/SIGTERM in the driver: end every Gondolin and Kairos
    unit and the Kairos plumbing, kill whatever is left in the measurement's units and holders cgroups, and remove the
    two objects' unit directories (a Kairos unit's root file system copy and session records hold the key). The
    Kairos base image and its volume stay: they are deleted with the key at the end of the measurement (protocol.md 8).
    Each step is independent. Runs as root on the server without the agent. Returns what is still left."""
    left: list[str] = []
    try:
        namespaces = _out(["ip", "netns", "list"]).split()
    except Exception as exc:
        namespaces, left = [], [f"ip netns list: {type(exc).__name__}: {exc}"]
    for ns in namespaces:
        if ns.startswith("sotakai") and ns[len("sotakai"):].isdigit():
            _step(left, ns, ["bash", f"{K_SETUP}/unit-down.sh", ns[len("sotakai"):]])
    if Path(K_SETUP, "net-down.sh").exists():
        _step(left, "Kairos net-down", ["bash", f"{K_SETUP}/net-down.sh"])
    for group in ("units", "holders"):   # cgroup v2: writing 1 to cgroup.kill kills the whole subtree
        kill = Path(CGBASE, group, "cgroup.kill")
        if kill.exists():
            try:
                kill.write_text("1")
            except OSError as exc:
                left.append(f"{group} cgroup.kill: {exc}")
    for pid in _pids_matching(f"{GONDOLIN}/sota-unit.mjs", "node") + _pids_matching("qemu-system-x86_64", G_IMAGE):
        _step(left, f"kill {pid}", ["kill", "-9", str(pid)], timeout=30)
    time.sleep(1)
    _step(left, "remove unit files", ["sh", "-c", f"rm -rf /tmp/gondolin-* {G_HOME}/.cache/gondolin/sessions/* "
                                                  f"{G_ROOT}/u* {K_VOL}/u[0-9]* {K_VOL}/logs {K_FIFO}"], timeout=300)
    still = (_pids_matching(f"{GONDOLIN}/sota-unit.mjs", "node") + _pids_matching("qemu-system-x86_64", G_IMAGE),
             _pids_matching("cloud-hypervisor", K_DEPLOY))
    left += [f"{len(p)} {what} still running" for what, p in zip(("Gondolin processes", "Kairos VMs"), still) if p]
    left += [f"{d} still there" for d in (*Path(K_VOL).glob("u[0-9]*"), *Path(G_ROOT).glob("u*"))]
    return left


ADAPTERS.update({cls.name: cls for cls in (Gondolin, Kairos)})
