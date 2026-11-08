"""Object adapters for the memory column on the Linux measurement server (protocol.md 1, 3.1, 9).

An adapter knows how to start the object's shared parts, build N units, put the units in each state
("idle": the k6 probe resident and idle; "resident": interactive Claude Code at its prompt, probe stopped),
tear everything down, and which cgroups hold the unit and shared processes. Every unit runs the same Claude Code
binary (2.1.312) with the same pre-seeded config (onboarding, folder trust and API-key dialogs already done).
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .client import Agent

WORK = "/var/lib/sotamem"
KEY_FILE = "/root/.sota-anthropic-key"  # root 0600; the key alone
CGBASE = "/sys/fs/cgroup/sotamem"
# Measurement facilities: the driver and agent (harness) and processes that hold unit sessions (holders).
HARNESS = [f"{CGBASE}/harness", f"{CGBASE}/holders"]
SYSTEM_SLICE = "/sys/fs/cgroup/system.slice"
DOCKER_SCOPES = f"{SYSTEM_SLICE}/docker-*.scope"  # native Docker, systemd cgroup driver: one scope per container
UNIT_CPU_MAX, UNIT_MEM_MAX = "200000 100000", str(4 * 2**30)  # protocol.md 1: 2 vCPU, 4 GiB per unit
# The same idle script as /opt/sota-setup/agent/idle-sleep.js (setup/nono.md 6.8), used by every object; the
# OpenShell image's idle.js is the equivalent one-VU, 24 h, sleep-only script (setup/openshell.md 3.4).
IDLE_JS = ("// k6 idle load: one VU that only sleeps. No requests are made.\n"
           "import { sleep } from 'k6';\n"
           "export const options = {\n"
           "  scenarios: { idle: { executor: 'constant-vus', vus: 1, duration: '24h', gracefulStop: '0s' } },\n"
           "};\n"
           "export default function () { sleep(3600); }\n")
K6_ARGS = ["run", "--no-usage-report", "--quiet", "idle.js"]  # k6 v2 has no --no-summary
CLAUDE_ENV = {"DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
              "TERM": "xterm-256color"}
CLAUDE_VERSION = "2.1.312"
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]")
DIALOG_MARKERS = ("Do you trust", "Do you want to use this API key", "Choose the text style", "Select login method",
                  "Make auto mode your default")
AGENT_USER = "jerry"  # uid 1001 on the server; the nono and Connection Escrow units run as this user too
AS_AGENT = ["setpriv", f"--reuid={AGENT_USER}", f"--regid={AGENT_USER}", "--init-groups"]


def prompt_verdict(screen: str) -> dict:
    """Is a Claude Code screen at its input prompt (and not in a dialog)? Evidence kept per unit (protocol.md 3.1)."""
    text = ANSI.sub("", screen)
    dialogs = [m for m in DIALOG_MARKERS if m in text]
    return {"at_prompt": "❯" in text and not dialogs, "dialogs": dialogs, "tail": text.strip()[-300:]}


def api_key() -> str:
    key = Path(KEY_FILE).read_text(encoding="utf-8").strip()
    if not key:
        raise RuntimeError(f"{KEY_FILE} is empty")
    return key


def claude_state(work: str, key: str) -> str:
    """The pre-seeded .claude.json: onboarding done, the work folder trusted, the API key approved."""
    return json.dumps({"hasCompletedOnboarding": True, "theme": "dark", "autoUpdates": False, "numStartups": 1,
                       "customApiKeyResponses": {"approved": [key[-20:]], "rejected": []},
                       "projects": {work: {"hasTrustDialogAccepted": True, "allowedTools": []}}})


@dataclass
class Unit:
    index: int
    name: str
    handles: dict = field(default_factory=dict)


class Adapter:
    name = "base"
    needs_docker = False  # Docker's daemons are then this object's shared parts (protocol.md 9)

    def __init__(self, agent_getter, key: str) -> None:
        self._agent_getter = agent_getter
        self.key = key
        self.units: list[Unit] = []
        self.run_dir: Path | None = None   # set by the object pass; where an object may keep its own records

    @property
    def agent(self) -> Agent:
        return self._agent_getter()

    def groups(self) -> dict[str, list[str]]:
        return {"unit": [f"{CGBASE}/units"], "shared": [f"{CGBASE}/shared"]}

    def prepare(self) -> None:
        """Bring the object to "not started" before baseline 1 (protocol.md 3.1)."""
        self.stop_shared()

    def start_shared(self) -> None:
        pass

    def stop_shared(self) -> None:
        pass

    def create_units(self, n: int) -> list[Unit]:
        raise NotImplementedError

    def set_state(self, state: str) -> None:
        raise NotImplementedError

    def alive(self) -> list[str]:
        """Names of units whose held process has exited (empty = all alive)."""
        return []

    def destroy_units(self) -> None:
        raise NotImplementedError

    def residue(self) -> list[str]:
        return []

    def prompt_evidence(self) -> dict[str, dict]:
        """After the resident window: per unit, whether its Claude Code screen shows the input prompt."""
        return {}

    def rep_notes(self) -> dict:
        """Object-specific facts of the repetition just finished, kept in its record (empty = none)."""
        return {}

    def interference(self) -> list[str]:
        """Object-specific reasons the window just read was interfered with (protocol.md 4), cleared when read."""
        return []

    def teardown(self) -> None:
        """Remove what prepare() installed for the measurement (nothing for most objects)."""

    def _run(self, argv: list[str], timeout: float = 300, check: bool = True, env: dict | None = None) -> str:
        r = self.agent.call("exec", argv=argv, env=env, timeout=timeout)
        if check and r["rc"] != 0:
            raise RuntimeError(f"{' '.join(argv[:4])} failed ({r['rc']}): {r['stdout'][-600:]}")
        return r["stdout"]

    def _screen(self, path: str) -> str:
        return self._run(["sh", "-c", f"tail -c 8000 '{path}' 2>/dev/null"], check=False)

    def _pids(self, spec: str) -> list[int]:
        return self.agent.call("pids", path=spec)["pids"]


ROOT_ENV = {"HOME": "/root", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}


def _systemctl(agent: Agent, *args: str) -> int:
    return agent.call("exec", argv=["systemctl", *args], env=ROOT_ENV, timeout=180)["rc"]


def docker_up(agent: Agent) -> bool:
    """Judged from systemd, not by asking the daemon: a docker CLI call would socket-activate a stopped daemon."""
    return _systemctl(agent, "is-active", "--quiet", "docker.service") == 0


def docker_service(agent: Agent, running: bool) -> None:
    """Start or stop Docker's daemons (dockerd and containerd; the socket unit too, so nothing restarts them)."""
    if running:
        if _systemctl(agent, "start", "containerd.service", "docker.socket", "docker.service") != 0:
            raise RuntimeError("systemctl start docker failed")
        deadline = time.monotonic() + 120
        while agent.call("exec", argv=["docker", "info", "--format", "{{.ServerVersion}}"], env=ROOT_ENV,
                         timeout=60)["rc"] != 0:
            if time.monotonic() > deadline:
                raise RuntimeError("Docker did not answer within 120 s of starting")
            time.sleep(2)
        return
    _systemctl(agent, "stop", "docker.socket", "docker.service", "containerd.service")
    left = [u for u in ("docker.socket", "docker.service", "containerd.service")
            if _systemctl(agent, "is-active", "--quiet", u) == 0]
    if left:
        raise RuntimeError(f"still active after stop: {left}")


class Bare(Adapter):
    """Claude Code and the probe as plain processes, started exactly as the nono and Connection Escrow units are
    (setup/connection-escrow.md 6.6): the same seed script (/opt/sota-setup/common/seed-claude-home.sh: onboarding
    and trust done, key through apiKeyHelper), the same environment, the same user, the same
    `script -qfc claude /dev/null` and k6 idle script; only the sandbox is missing. Each unit is a cgroup."""
    name = "bare"
    UNITS = "/var/tmp/sota-bare"
    AGENT_CMD = "claude"   # what `script -qfc` runs in the resident state

    def _env(self, root: str) -> dict[str, str]:
        return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": f"{root}/home", "USER": AGENT_USER,
                "TERM": "xterm-256color", "LANG": "C.UTF-8", "CLAUDE_CONFIG_DIR": f"{root}/home/.claude",
                "CLAUDE_CODE_TMPDIR": f"{root}/home/.claude/tmp", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "DISABLE_AUTOUPDATER": "1", "SOTA_ANTHROPIC_API_KEY": self.key}

    def create_units(self, n: int) -> list[Unit]:
        self.units = []
        for i in range(1, n + 1):
            root = f"{self.UNITS}/u{i}"
            self._run(["rm", "-rf", root])
            self._run(["sh", "/opt/sota-setup/common/seed-claude-home.sh", root, AGENT_USER])
            self.agent.call("mkcg", rel=f"units/u{i}", cpu_max=UNIT_CPU_MAX, mem_max=UNIT_MEM_MAX)
            self.units.append(Unit(i, f"u{i}", {"root": root}))
        return self.units

    def _spawn(self, u: Unit, leaf: str, argv: list[str]) -> int:
        root = u.handles["root"]
        cg = self.agent.call("mkcg", rel=f"units/u{u.index}/{leaf}")["path"]
        r = self.agent.call("spawn", cgroup=cg, argv=[*AS_AGENT, *argv], cwd=f"{root}/work", env=self._env(root),
                            log=f"{root}/{leaf}.log", pty=False)
        return r["pid"]

    def set_state(self, state: str) -> None:
        for u in self.units:
            if state == "idle":
                u.handles["probe"] = self._spawn(u, "probe", ["k6", "run", "--no-usage-report", "--quiet",
                                                              "/opt/sota-setup/agent/idle-sleep.js"])
            elif state == "resident":
                self.agent.call("killcg", path=f"{CGBASE}/units/u{u.index}/probe")
                u.handles.pop("probe", None)
                u.handles["agent"] = self._spawn(u, "agent", ["script", "-qfc", self.AGENT_CMD, "/dev/null"])
            else:
                raise ValueError(state)

    def alive(self) -> list[str]:
        pids = {u.name: u.handles.get("agent") or u.handles.get("probe") for u in self.units}
        status = self.agent.call("alive", pids=[p for p in pids.values() if p])
        return [name for name, pid in pids.items() if not pid or not status.get(str(pid))]

    def prompt_evidence(self) -> dict[str, dict]:
        return {u.name: prompt_verdict(self._screen(f"{u.handles['root']}/agent.log")) for u in self.units}

    def destroy_units(self) -> None:
        for u in self.units:
            self.agent.call("killcg", path=f"{CGBASE}/units/u{u.index}")
            self._run(["rm", "-rf", u.handles["root"]])
        self.units = []

    def residue(self) -> list[str]:
        left = self._pids(f"{CGBASE}/units")
        return [f"{len(left)} processes left under {CGBASE}/units"] if left else []


class BareApiOnly(Bare):
    """Bare with the network condition every other object imposes: the units' user may reach only the model API
    (TCP 443 to the addresses api.anthropic.com resolves to at start) and loopback (the local resolver); every other
    connection is refused at once. Added 2026-10-30 (user approved) because nono and Connection Escrow came out
    13-19 MiB below plain bare, whose Claude Code reaches GitHub and downloads.claude.ai. The rules live in a chain of
    their own, added with the shared parts and removed with them."""
    name = "bare-api-only"
    CHAIN = "SOTA_BARE_API"

    def _ipt(self, tool: str, *args: str) -> int:
        return self.agent.call("exec", argv=[tool, *args], env=ROOT_ENV, timeout=60)["rc"]

    def start_shared(self) -> None:
        self.stop_shared()
        ips = sorted({ln.split()[0] for ln in self._run(["getent", "ahostsv4", "api.anthropic.com"]).splitlines()
                      if ln.strip()})
        if not ips:
            raise RuntimeError("api.anthropic.com did not resolve")
        for tool in ("iptables", "ip6tables"):
            self._run([tool, "-N", self.CHAIN], env=ROOT_ENV)
            self._run([tool, "-A", self.CHAIN, "-o", "lo", "-j", "ACCEPT"], env=ROOT_ENV)
            if tool == "iptables":
                for ip in ips:
                    self._run([tool, "-A", self.CHAIN, "-d", ip, "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
                              env=ROOT_ENV)
            self._run([tool, "-A", self.CHAIN, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"],
                      env=ROOT_ENV)
            self._run([tool, "-A", self.CHAIN, "-j", "REJECT"], env=ROOT_ENV)
            self._run([tool, "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", AGENT_USER, "-j", self.CHAIN],
                      env=ROOT_ENV)

    def stop_shared(self) -> None:
        for tool in ("iptables", "ip6tables"):
            while self._ipt(tool, "-D", "OUTPUT", "-m", "owner", "--uid-owner", AGENT_USER, "-j", self.CHAIN) == 0:
                pass
            self._ipt(tool, "-F", self.CHAIN)
            self._ipt(tool, "-X", self.CHAIN)

    def residue(self) -> list[str]:
        left = [t for t in ("iptables", "ip6tables") if self._ipt(t, "-L", self.CHAIN, "-n") == 0]
        return super().residue() + ([f"{self.CHAIN} still in {left}"] if left else [])


class BareApiOnlyTerm(BareApiOnly):
    """bare-api-only with Claude Code's terminal set to 40x120, as the Gondolin units need (setup/gondolin.md 2.4);
    every other object's Claude Code draws in script's 0x0 terminal. Paired with bare-api-only at one tier it measures
    what the terminal size alone changes in Claude Code's resident memory (user 2026-11-01)."""
    name = "bare-api-only-term"
    AGENT_CMD = "stty rows 40 cols 120; claude"   # no exec: the same script -> sh -> claude tree as bare-api-only


class _Scripted(Adapter):
    """An object driven by its setup scripts under /opt/sota-setup/<dir> (setup/<object>.md)."""
    script_dir = ""

    def _sh(self, script: str, *args: str, timeout: float = 300) -> str:
        r = self.agent.call("exec", argv=["sh", f"/opt/sota-setup/{self.script_dir}/{script}", *args],
                            timeout=timeout)
        # nono's unit-down.sh ends with an rmdir of the shared parent that fails while other units exist, so
        # its exit status is 1 after a clean stop; judge it by its own report instead.
        if script == "unit-down.sh" and "still alive" not in r["stdout"]:
            return r["stdout"]
        if r["rc"] != 0:
            raise RuntimeError(f"{script} {' '.join(args)} failed ({r['rc']}): {(r['stdout'] + r['stderr'])[-600:]}")
        return r["stdout"]


class Nono(_Scripted):
    """One nono session per unit (supervisor with its in-process proxy, sandboxed child); no shared parts.
    Claude Code takes the per-session placeholder token through apiKeyHelper (setup/nono.md 8)."""
    name, script_dir = "nono", "nono"

    def create_units(self, n: int) -> list[Unit]:
        self.units = []
        for i in range(1, n + 1):
            self.agent.call("mkcg", rel=f"units/u{i}", cpu_max=UNIT_CPU_MAX, mem_max=UNIT_MEM_MAX)
            self.units.append(Unit(i, f"u{i}", {}))
        return self.units

    def set_state(self, state: str) -> None:
        for u in self.units:
            if state == "idle":
                leaf = self.agent.call("mkcg", rel=f"units/u{u.index}/probe")["path"]
                self._sh("unit-up.sh", str(u.index), "k6", leaf)
                u.handles["leaf"] = leaf
            elif state == "resident":
                self._sh("unit-down.sh", str(u.index))
                self.agent.call("killcg", path=f"{CGBASE}/units/u{u.index}/probe")
                leaf = self.agent.call("mkcg", rel=f"units/u{u.index}/agent")["path"]
                self._sh("unit-up.sh", str(u.index), "claude", leaf)
                u.handles["leaf"] = leaf
            else:
                raise ValueError(state)

    def alive(self) -> list[str]:
        return [u.name for u in self.units if len(self._pids(u.handles["leaf"])) < 2]

    def prompt_evidence(self) -> dict[str, dict]:
        return {u.name: prompt_verdict(self._screen(f"/var/tmp/sota-nono/u{u.index}/out.raw")) for u in self.units}

    def destroy_units(self) -> None:
        for u in self.units:
            self._sh("unit-down.sh", str(u.index))
            self.agent.call("killcg", path=f"{CGBASE}/units/u{u.index}")
        self.units = []

    def residue(self) -> list[str]:
        left = self._pids(f"{CGBASE}/units")
        dirs = self._run(["sh", "-c", "ls /var/tmp/sota-nono 2>/dev/null"], check=False).split()
        return ([f"{len(left)} processes under {CGBASE}/units"] if left else []) + \
               ([f"unit dirs left: {dirs}"] if dirs else [])


class ConnectionEscrow(_Scripted):
    """Single-machine mode: verifier, interceptor and eBPF are shared parts; a unit is a pre-registered slot cgroup
    /sys/fs/cgroup/sota-escrow/u<K> (16 slots, the highest tier). No credential custody: the agent holds the key."""
    name, script_dir = "connection-escrow", "escrow"
    SLOTS = 16
    SLOT_ROOT = "/sys/fs/cgroup/sota-escrow"

    def groups(self) -> dict[str, list[str]]:
        return {"unit": [self.SLOT_ROOT], "shared": [f"{CGBASE}/shared"]}

    def prepare(self) -> None:
        self._sh("shared-down.sh")

    def start_shared(self) -> None:
        self._sh("shared-up.sh", str(self.SLOTS), timeout=600)
        shared = self.agent.call("mkcg", rel="shared")["path"]
        for pid in self._sh("shared-pids.sh").split():
            self.agent.call("write", path=f"{shared}/cgroup.procs", text=pid)
        for k in range(1, self.SLOTS + 1):
            self.agent.call("write", path=f"{self.SLOT_ROOT}/u{k}/cpu.max", text=UNIT_CPU_MAX)
            self.agent.call("write", path=f"{self.SLOT_ROOT}/u{k}/memory.max", text=UNIT_MEM_MAX)

    def stop_shared(self) -> None:
        self._sh("shared-down.sh")
        self.agent.call("killcg", path=f"{CGBASE}/shared")

    def create_units(self, n: int) -> list[Unit]:
        if n > self.SLOTS:
            raise RuntimeError(f"{n} units > {self.SLOTS} pre-registered slots")
        self.units = [Unit(i, f"u{i}", {}) for i in range(1, n + 1)]
        return self.units

    def set_state(self, state: str) -> None:
        for u in self.units:
            if state == "idle":
                self._sh("unit-up.sh", str(u.index), "k6")
            elif state == "resident":
                self._sh("unit-down.sh", str(u.index))
                self._sh("unit-up.sh", str(u.index), "claude")
            else:
                raise ValueError(state)

    def alive(self) -> list[str]:
        return [u.name for u in self.units if not self._pids(f"{self.SLOT_ROOT}/u{u.index}")]

    def prompt_evidence(self) -> dict[str, dict]:
        return {u.name: prompt_verdict(self._screen(f"/var/tmp/sota-escrow/u{u.index}/out.raw"))
                for u in self.units}

    def destroy_units(self) -> None:
        for u in self.units:
            self._sh("unit-down.sh", str(u.index))
        self.units = []

    def residue(self) -> list[str]:
        left = self._pids(self.SLOT_ROOT)
        return [f"{len(left)} processes in escrow slots"] if left else []


class _Dockerised(Adapter):
    """An object whose units are Docker containers on the native daemon. Docker's daemons are shared parts: stopped
    before baseline 1, started after it. Unit group: every container scope plus the containerd shims serving them
    (during this object's pass the only containers are its own; one listed in both groups counts as unit)."""
    needs_docker = True

    def groups(self) -> dict[str, list[str]]:
        return {"unit": [f"glob:{DOCKER_SCOPES}", f"shim:{DOCKER_SCOPES}"],
                "shared": [f"{SYSTEM_SLICE}/docker.service", f"{SYSTEM_SLICE}/containerd.service",
                           f"{CGBASE}/shared"]}

    def prepare(self) -> None:
        if docker_up(self.agent):
            self.stop_own()
        docker_service(self.agent, False)
        self.stop_host_parts()

    def start_shared(self) -> None:
        docker_service(self.agent, True)
        self.start_own()

    def stop_shared(self) -> None:
        if docker_up(self.agent):
            self.stop_own()
        self.stop_host_parts()
        docker_service(self.agent, False)
        self.agent.call("killcg", path=f"{CGBASE}/shared")

    def start_own(self) -> None:
        """The object's own shared parts, after Docker is up."""

    def stop_own(self) -> None:
        """Remove the object's containers and shared parts that need Docker to stop."""

    def stop_host_parts(self) -> None:
        """Stop the object's host processes that do not need Docker (safe with Docker down)."""

    def residue(self) -> list[str]:
        out = []
        if docker_up(self.agent):
            out.append("Docker still running")
        left = self._pids(f"glob:{DOCKER_SCOPES}")
        return out + ([f"{len(left)} container processes left"] if left else [])

    def _docker(self, *args: str, timeout: float = 300, check: bool = True) -> str:
        return self._run(["docker", *args], timeout=timeout, check=check, env=ROOT_ENV)


OSH_IMAGE = "measure/openshell-agent:cc2.1.312-k6v2.3.0"


class OpenShell(_Dockerised):
    """One sandbox (workload container + its supervisor container) per unit; the gateway and Docker's daemons are
    shared parts. Provider cc-strict (setup/openshell.md). Quota: only the workload container gets 2 CPU / 4 GiB
    (docker update); the supervisor container has none."""
    name = "openshell"

    def start_own(self) -> None:
        self._run(["bash", "/root/osh-setup/gateway-start.sh"], timeout=180, env=ROOT_ENV)
        # The gateway keeps sandbox records across restarts; a record left by an earlier session makes the first
        # create fail with "already exists" (seen 2026-10-30), so leftovers are deleted before baseline 2.
        self.stop_own()
        shared = self.agent.call("mkcg", rel="shared")["path"]
        for pid in self._run(["pgrep", "-f", "^/usr/local/bin/openshell-gateway$"], env=ROOT_ENV).split():
            self.agent.call("write", path=f"{shared}/cgroup.procs", text=pid)

    def stop_own(self) -> None:
        for n in self._sandboxes():
            self._run(["openshell", "sandbox", "delete", n], check=False, env=ROOT_ENV)

    def stop_host_parts(self) -> None:
        self._run(["bash", "/root/osh-setup/gateway-stop.sh"], check=False, env=ROOT_ENV)

    def _sandboxes(self) -> list[str]:
        out = self._run(["openshell", "sandbox", "list"], check=False, env=ROOT_ENV)
        return [ln.split()[0] for ln in out.splitlines()[1:] if ln.strip() and ln.split()[0].startswith("sotamem-")]

    def _containers(self, name: str, role: str = "") -> list[str]:
        filt = ["--filter", f"label=openshell.ai/sandbox-name={name}"]
        if role:
            filt += ["--filter", f"label=openshell.ai/isolation-role={role}"]
        return self._docker("ps", "-q", *filt, check=False).split()

    def create_units(self, n: int) -> list[Unit]:
        self.units = [Unit(i, f"sotamem-u{i}", {}) for i in range(1, n + 1)]
        return self.units

    def _create(self, u: Unit, main: list[str], tty: bool) -> None:
        argv = ["openshell", "sandbox", "create", "--name", u.name, "--from", OSH_IMAGE, "--provider", "cc-strict",
                "--detach", *(["--tty"] if tty else []), "--", *main]
        self._run(argv, timeout=600, env=ROOT_ENV)
        for c in self._containers(u.name, "sandbox"):
            self._docker("update", "--cpus", "2", "--memory", "4g", "--memory-swap", "4g", c)

    def _delete(self, u: Unit) -> None:
        self._run(["openshell", "sandbox", "delete", u.name], check=False, env=ROOT_ENV)
        deadline = time.monotonic() + 60
        while self._containers(u.name) and time.monotonic() < deadline:
            time.sleep(1)

    def set_state(self, state: str) -> None:
        for u in self.units:
            if state == "idle":
                self._create(u, ["/usr/local/bin/k6", "run", "--quiet", "/usr/local/lib/measure/idle.js"], tty=False)
            elif state == "resident":
                self._delete(u)
                self._create(u, ["/usr/local/lib/measure/cc-start.sh"], tty=True)
            else:
                raise ValueError(state)

    def alive(self) -> list[str]:
        return [u.name for u in self.units if len(self._containers(u.name)) < 2]

    def prompt_evidence(self) -> dict[str, dict]:
        """Only the first unit: attaching takes about 10 s and redraws the terminal (setup/openshell.md 5)."""
        if not self.units:
            return {}
        u = self.units[0]
        # /root/osh-setup/screen-check.sh with its stdin holder cut from `sleep 60` to `sleep 12`: the pipe only has
        # to outlive the 10 s attach (the original makes every check take a full minute). No byte is sent.
        cmd = (f"( sleep 12 ) | timeout 10 script -qfc \"stty rows 40 cols 120 2>/dev/null; "
               f"openshell sandbox connect {u.name}\" /root/osh-setup/{u.name}-screen.raw >/dev/null 2>&1; "
               f"cat /root/osh-setup/{u.name}-screen.raw")
        screen = self._run(["bash", "-c", cmd], timeout=60, check=False, env=ROOT_ENV)
        return {u.name: prompt_verdict(screen)}

    def destroy_units(self) -> None:
        for u in self.units:
            self._delete(u)
        self.units = []

    def residue(self) -> list[str]:
        gw = self._run(["pgrep", "-f", "^/usr/local/bin/openshell-gateway$"], check=False, env=ROOT_ENV).split()
        return ([f"gateway still running: {gw}"] if gw else []) + super().residue()


AV = "/opt/sota-setup/agent-vault"
# Agent Vault binds each run's forwarder on that run's own Docker network gateway, but host.docker.internal in the
# container resolves to docker0 (172.17.0.1) and its firewall only allows that address; this rule hands the
# container's connections to docker0 over to the forwarder on the bridge it came in on (setup/agent-vault.md,
# server section). It widens nothing: only the container's own allowed path is redirected.
AV_MATCH = ["-i", "br-+", "-d", "172.17.0.1/32", "-p", "tcp", "-j", "REDIRECT"]  # nat PREROUTING


class AgentVault(_Dockerised):
    """One `agent-vault vault run --isolation=container` per unit: the host-side `vault run` (with the unit's
    forwarder) and its `docker run` client, the container and its shim. The Agent Vault server and Docker's daemons
    are shared parts. Credential custody: the container holds a placeholder; the proxy injects the real key."""
    name = "agent-vault"

    def groups(self) -> dict[str, list[str]]:
        g = super().groups()
        return {"unit": [f"{CGBASE}/units", *g["unit"]], "shared": g["shared"]}

    def _rule(self, op: str, *pos: str) -> int:
        return self.agent.call("exec", argv=["iptables", "-t", "nat", op, "PREROUTING", *pos, *AV_MATCH],
                               env=ROOT_ENV, timeout=60)["rc"]

    def start_own(self) -> None:
        self._run(["bash", f"{AV}/server-start.sh"], timeout=120, env=ROOT_ENV)
        shared = self.agent.call("mkcg", rel="shared")["path"]
        for pid in self._run(["pgrep", "-f", "(^|/)agent-vault server"], env=ROOT_ENV).split():
            self.agent.call("write", path=f"{shared}/cgroup.procs", text=pid)
        if self._rule("-C") != 0 and self._rule("-I", "1") != 0:
            raise RuntimeError("could not add the Agent Vault redirect rule")

    def stop_own(self) -> None:
        for i in range(1, 17):
            self._run(["bash", f"{AV}/unit-down.sh", str(i)], timeout=120, check=False, env=ROOT_ENV)

    def stop_host_parts(self) -> None:
        while self._rule("-C") == 0:
            if self._rule("-D") != 0:
                break
        self._run(["bash", f"{AV}/server-stop.sh"], timeout=60, check=False, env=ROOT_ENV)

    def create_units(self, n: int) -> list[Unit]:
        self.units = []
        for i in range(1, n + 1):
            self.agent.call("mkcg", rel=f"units/u{i}", cpu_max=UNIT_CPU_MAX, mem_max=UNIT_MEM_MAX)
            self.units.append(Unit(i, f"u{i}", {}))
        return self.units

    def _up(self, u: Unit, kind: str) -> None:
        """Start the unit, then move its host-side processes (vault run, docker client) into the unit's cgroup and
        give the container the unit's quota. The terminal holders (setsid bash, sleep, script) stay in the
        measurement facilities' group."""
        self._run(["bash", f"{AV}/unit-up.sh", str(u.index), kind], timeout=180, env=ROOT_ENV)
        c, vr, dc, _net = self._run(["bash", f"{AV}/unit-container.sh", str(u.index), "-v"], env=ROOT_ENV).split()
        for pid in (vr, dc):
            self.agent.call("write", path=f"{CGBASE}/units/u{u.index}/cgroup.procs", text=pid)
        self._docker("update", "--cpus", "2", "--memory", "4g", "--memory-swap", "4g", c)

    def set_state(self, state: str) -> None:
        for u in self.units:
            if state == "idle":
                self._up(u, "k6")
            elif state == "resident":
                self._run(["bash", f"{AV}/unit-down.sh", str(u.index)], timeout=120, env=ROOT_ENV)
                self._up(u, "claude")
            else:
                raise ValueError(state)

    def alive(self) -> list[str]:
        return [u.name for u in self.units
                if self.agent.call("exec", argv=["bash", f"{AV}/unit-container.sh", str(u.index)], env=ROOT_ENV,
                                   timeout=60)["rc"] != 0]

    def prompt_evidence(self) -> dict[str, dict]:
        return {u.name: prompt_verdict(self._screen(f"/var/lib/sota-av/u{u.index}/screen.log")) for u in self.units}

    def destroy_units(self) -> None:
        for u in self.units:
            self._run(["bash", f"{AV}/unit-down.sh", str(u.index)], timeout=120, check=False, env=ROOT_ENV)
            self.agent.call("killcg", path=f"{CGBASE}/units/u{u.index}")
        self._run(["rm", "-rf", "/var/lib/sota-av"], check=False)
        self.units = []

    def residue(self) -> list[str]:
        vr = self._run(["pgrep", "-f", "(^|/)agent-vault vault run"], check=False, env=ROOT_ENV).split()
        srv = self._run(["pgrep", "-f", "(^|/)agent-vault server"], check=False, env=ROOT_ENV).split()
        rule = self._rule("-C") == 0
        return ([f"vault run still running: {vr}"] if vr else []) + ([f"server still running: {srv}"] if srv else []) \
            + (["redirect rule still present"] if rule else []) + super().residue()


AS_AGENT_SUDO = ["sudo", "-u", AGENT_USER, "-H"]  # sbx keeps its daemon and state per user; jerry is in kvm
DSB_ROOT, DSB_TOOLS = f"{WORK}/dsb", f"{WORK}/dsb-tools"
NERDBOX = "^/usr/libexec/containerd-shim-nerdbox-v1"


class DockerSandboxes(Adapter):
    """One sandbox (microVM) per unit, 2 CPU / 4 GiB as VM settings; the sbx daemon is the shared part. On the host a
    unit is one containerd-shim-nerdbox-v1 process (the VMM; its PSS includes the guest memory it has touched).
    The workspace carries the same Claude Code 2.1.312 binary and seeded config as the other objects; the
    template's own Claude Code (2.1.306, bypass-permissions settings) is not used. Credentials go through the
    sandbox's custody path: apiKeyHelper prints the template's placeholder and its proxy injects the stored key
    (setup/docker-sandboxes.md). A sandbox stops by itself once no session is open, so a state switch opens the new
    session before closing the old one."""
    name = "docker-sandboxes"
    PREFIX = "sotamem-"

    def _sbx(self, *args: str, timeout: float = 300, check: bool = True) -> dict:
        r = self.agent.call("exec", argv=[*AS_AGENT_SUDO, "sbx", *args], env=ROOT_ENV, cwd="/tmp", timeout=timeout)
        if check and r["rc"] != 0:
            raise RuntimeError(f"sbx {' '.join(args[:3])} failed ({r['rc']}): {r['stdout'][-600:]}")
        return r

    def _daemon_up(self) -> bool:
        return bool(self._run(["pgrep", "-f", "^/usr/bin/sbx daemon"], check=False).split())

    def _move(self, pattern: str, rel: str) -> None:
        cg = self.agent.call("mkcg", rel=rel)["path"]
        for pid in self._run(["pgrep", "-f", pattern], check=False).split():
            self.agent.call("write", path=f"{cg}/cgroup.procs", text=pid)

    def start_shared(self) -> None:
        self._sbx("ls", timeout=180)  # starts the daemon in the background when it is not running
        deadline = time.monotonic() + 120
        while self._sbx("daemon", "status", timeout=60, check=False)["rc"] != 0:
            if time.monotonic() > deadline:
                raise RuntimeError("sbx daemon did not report running")
            time.sleep(2)
        self._move("^/usr/bin/sbx daemon", "shared")

    def stop_shared(self) -> None:
        if self._daemon_up():
            names = [ln.split()[0] for ln in self._sbx("ls", check=False)["stdout"].splitlines()[1:]
                     if ln.split() and ln.split()[0].startswith(self.PREFIX)]
            if names:
                self._sbx("rm", "--force", *names, timeout=300, check=False)
            self._sbx("daemon", "stop", timeout=120, check=False)
        self.agent.call("killcg", path=f"{CGBASE}/shared")

    def create_units(self, n: int) -> list[Unit]:
        self._run(["sh", "-c", f"test -x {DSB_TOOLS}/claude || (mkdir -p {DSB_TOOLS} && "
                               f"cp \"$(readlink -f /usr/local/bin/claude)\" {DSB_TOOLS}/claude && "
                               f"cp \"$(readlink -f /usr/local/bin/k6)\" {DSB_TOOLS}/k6)"])
        self.units = []
        for i in range(1, n + 1):
            ws = f"{DSB_ROOT}/u{i}"
            self._run(["rm", "-rf", ws])
            self._run(["mkdir", "-p", f"{ws}/config"])
            self._run(["ln", f"{DSB_TOOLS}/claude", f"{DSB_TOOLS}/k6", ws])  # hard links: one copy on the host
            self.agent.call("write", path=f"{ws}/idle.js", text=IDLE_JS)
            self.agent.call("write", path=f"{ws}/config/.claude.json", text=json.dumps({
                "hasCompletedOnboarding": True, "lastOnboardingVersion": CLAUDE_VERSION, "theme": "dark",
                "projects": {ws: {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True,
                                  "allowedTools": []}}}))
            self.agent.call("write", path=f"{ws}/config/settings.json",
                            text=json.dumps({"apiKeyHelper": "echo proxy-managed"}))
            self._run(["chown", "-R", f"{AGENT_USER}:{AGENT_USER}", ws, DSB_TOOLS])
            name = f"{self.PREFIX}u{i}"
            self._sbx("create", "claude", ws, "--name", name, "--cpus", "2", "--memory", "4g", timeout=600)
            self.units.append(Unit(i, name, {"ws": ws}))
        return self.units

    def _hold(self, u: Unit, leaf: str, argv: list[str]) -> int:
        cg = self.agent.call("mkcg", rel=f"holders/u{u.index}/{leaf}")["path"]
        ws = u.handles["ws"]
        env = [x for k, v in {"CLAUDE_CONFIG_DIR": f"{ws}/config", **CLAUDE_ENV}.items() for x in ("-e", f"{k}={v}")]
        r = self.agent.call("spawn", cgroup=cg, argv=[*AS_AGENT_SUDO, "sbx", "exec", "-i", "-w", ws, *env, u.name,
                                                      *argv], cwd="/tmp", env=ROOT_ENV,
                            log=f"{DSB_ROOT}/u{u.index}.{leaf}.log", pty=False)
        return r["pid"]

    def _units_cgroup(self) -> None:
        """The VMM processes go into the units group (no limits: the VM's own settings are its quota). Called after
        every state change, since a sandbox that restarted has a new VMM process under the daemon."""
        self._move(NERDBOX, "units/vm")

    def set_state(self, state: str) -> None:
        for u in self.units:
            if state == "idle":
                u.handles["probe"] = self._hold(u, "probe", ["./k6", *K6_ARGS])
            elif state == "resident":
                # k6 does not read stdin, so closing its session leaves it running: end it inside the VM first.
                self._sbx("exec", u.name, "sh", "-c", "pkill -x k6; sleep 1; ! pgrep -x k6", timeout=60)
                u.handles["agent"] = self._hold(u, "agent", ["script", "-qfc", "./claude", "screen.log"])
                self.agent.call("killcg", path=f"{CGBASE}/holders/u{u.index}/probe")
                u.handles.pop("probe", None)
            else:
                raise ValueError(state)
        time.sleep(3)
        self._units_cgroup()

    def alive(self) -> list[str]:
        pids = {u.name: u.handles.get("agent") or u.handles.get("probe") for u in self.units}
        status = self.agent.call("alive", pids=[p for p in pids.values() if p])
        dead = [name for name, pid in pids.items() if not pid or not status.get(str(pid))]
        vms = len(self._run(["pgrep", "-f", NERDBOX], check=False).split())
        return dead + ([f"{vms} VMs for {len(self.units)} units"] if vms < len(self.units) else [])

    def prompt_evidence(self) -> dict[str, dict]:
        return {u.name: prompt_verdict(self._screen(f"{u.handles['ws']}/screen.log")) for u in self.units}

    def destroy_units(self) -> None:
        self.agent.call("killcg", path=f"{CGBASE}/holders")
        if self.units and self._daemon_up():
            self._sbx("rm", "--force", *[u.name for u in self.units], timeout=300, check=False)
        self.agent.call("killcg", path=f"{CGBASE}/units/vm")
        self._run(["rm", "-rf", DSB_ROOT], check=False)
        self.units = []

    def residue(self) -> list[str]:
        """Judged from processes: `sbx ls` would start the daemon again."""
        vms = self._run(["pgrep", "-f", NERDBOX], check=False).split()
        daemon = self._daemon_up()
        return ([f"{len(vms)} sandbox VMs still running"] if vms else []) + (["sbx daemon running"] if daemon else [])


ADAPTERS = {cls.name: cls for cls in (Bare, BareApiOnly, BareApiOnlyTerm, Nono, ConnectionEscrow, OpenShell, AgentVault,
                                      DockerSandboxes)}

# builds on the classes above and adds its adapters to ADAPTERS
from . import engine_object  # noqa: E402,F401
from . import vm_objects  # noqa: E402,F401
