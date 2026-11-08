"""This thesis's engine as a measured object (protocol.md 1 "本论文", 3.1, 9): the archived version v4,
ExperimentLab/engine-v3 @ a9eff999 (prove/baseline v4), with the Go frontend.

One unit = one execution (a row): the cell (pid 1 = the runtime, the pty relay, the in-cell Go frontend and the in-cell
MCP server; all at the row's leased uid) plus the row's two processes outside the cell, the connector (uid 70999) and
the file worker (uid 70996). The shared part is the core: the w2-cell spawner and its storage worker (root), the engine
(uid 1000) and the simple PDP (uid 70998), one per host. The engine makes no cgroups, so the driver places each row's
processes in the unit's cgroup itself: the cell by its uid (the row list gives it), the connector and the file worker
by the argv the spawner gives them (it ends with the row's uid and execution id). How long each row took from
`row start` to the last move is kept per unit.

Rules, fixed for the whole run (protocol.md 1): the model API host is an exact allow entry without approval, any
method and path (as the other objects reach it); the other hosts Claude Code contacts at start (OTHER_HOSTS) are exact
deny entries without approval. No fallback deny: the engine refuses on any covering deny before it looks at allows
(engine/matching.py, K-43 step 1), so a fallback deny would cut the model API off too (it did, in the first runs:
runs/20261031T024500Z-engine-mode-probe). The fallback entry v4 gives every workspace by default (any host's GET
allowed, never asked) is deleted, so every other host is refused, as the protocol allows only the model API (user
2026-11-06). No host file is registered. With no entry that asks, the engine asks nothing (engine/hook.py asks only
for approval-always entries); the question window stays as a guard: a question is answered deny-once at once, logged,
and stops the block as a configuration error. Each pass starts with one model call through the engine
(the "check" runtime, Claude Code in print mode) that must come back allowed, with the credential placed, and 2xx
before baseline 2 (protocol.md 2.2); the core runs with the measurement switch (engine-v3 README 完成记录开关) because
v4 records a request's completion only there. The admin client runs as the engine uid, as in the engine's own gate.
The core's records (E-09 events, core and PDP logs, rules, questions, deployment and seed manifest) are copied into
the run directory when the core stops.

"idle": each unit is a row of the "probe" runtime (k6's idle script). "resident": the probe rows are stopped and
each unit starts a row of the "claude" runtime (interactive Claude Code at its prompt). No client is attached during
the window (the relay drains the terminal); the prompt evidence attaches after it.

Two deployments of v4: EngineV4 ("copy": each execution gets its own verified reflink copy of the runtime seed) and
EngineV4Shared ("shared", v4's default: every cell binds the one verified seed read-only).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from .objects import ADAPTERS, CGBASE, ROOT_ENV, UNIT_CPU_MAX, UNIT_MEM_MAX, WORK, Adapter, Unit, prompt_verdict

ENGINE_V4 = Path("/opt/thesis/ExperimentLab/engine-v3")      # prove/baseline v4, its 188 files as exported
DRIVER_HOME = Path(__file__).resolve().parents[1]
UNITS, UID_FIRST, ENGINE_UID = 16, 70000, 1000
# The dedicated ids outside the execution range, as the engine's own checks deploy them (engine_deploy.load checks
# them against run_sandbox_checks): the row's connector and file worker, the workspace storage owner, the PDP.
CONNECTOR_UID, FILE_WORKER_UID, OWNER_UID, PDP_UID = 70999, 70996, 70997, 70998
ROW_UIDS = {"connector": CONNECTOR_UID, "file_worker": FILE_WORKER_UID}   # outside the cell, one of each per row
# The engine leases a fresh uid per execution and never reuses one within a start (lifecycle.py: the lowest free uid
# "that this engine start has not used yet"); one driver pass starts up to 124 rows (31 units x 2 states x 2
# repetitions), so the range is wider than the 16 concurrent units (engine startup allows up to 1024).
UID_COUNT = 512
# A unit's processes when it is up: in the cell pid 1 (k6 or Claude Code, MAIN) and these three helpers, by comm;
# outside it one connector and one file worker (ROW_UIDS).
CELL_HELPERS = ("w2-relay", "engine-frontend", "engine-mcp")
HOST, ACCOUNT = "api.anthropic.com:443", "measure"
PLACEHOLDER = "sk-ant-api03-sotamem-placeholder-0000000000000000000000000000000000000000000000000000"
MAIN = {"probe": "k6", "claude": "claude"}  # the comm of each runtime's pid 1 once it has exec'd
# The other hosts Claude Code 2.1.312 contacts at start (engine gate 7.2 trace, runs/20261031T024500Z-engine-mode-probe)
OTHER_HOSTS = ("platform.claude.com:443", "claude.ai:443", "downloads.claude.ai:443")
ENTRIES = 1 + len(OTHER_HOSTS)    # what each workspace holds once registered: the allow, the denies, no fallback
# sudo leaves RLIMIT_CORE at 0/0 on the server; the cell child sets {1,1} (child.c, fd_cleanup stage) and cannot raise
# the hard limit, so the core starts with 0/unlimited as on WSL (engine-v2 run 20261030T144100Z-server-sandbox).
CORE_LIMIT = ["/usr/bin/prlimit", "--core=0:unlimited"]
# Whether a socket file left behind still has a listener: exit STALE when it is a socket and the connection is refused
# (no one listens), 0 when it connects, NOT_A_SOCKET for any other kind of file (connect would be refused on it too);
# a path that is gone ends with a traceback and exit 1.
STALE, NOT_A_SOCKET = 3, 4
SOCKET_PROBE = ("import os, socket, stat, sys\n"
                "if not stat.S_ISSOCK(os.lstat(sys.argv[1]).st_mode):\n"
                f"    sys.exit({NOT_A_SOCKET})\n"
                "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "try:\n"
                "    s.connect(sys.argv[1])\n"
                "except ConnectionRefusedError:\n"
                f"    sys.exit({STALE})\n")
# The simple PDP as its dedicated uid, the same setpriv line as the engine's gate (engine-v3/checks/run_gate.py)
PDP_AS = ["/usr/bin/setpriv", f"--reuid={PDP_UID}", f"--regid={PDP_UID}", "--clear-groups", "--bounding-set=-all",
          "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]


def _engine_checks():
    """AS_USER, PYTHON, SPAWNER_CAPS from the engine's own check runner (one home for them)."""
    sys.path.insert(0, str(ENGINE_V4 / "native/checks"))
    sys.path.insert(0, str(ENGINE_V4 / "checks"))
    from run_engine_checks import AS_USER, PYTHON, SPAWNER_CAPS  # noqa: E402
    return AS_USER, PYTHON, SPAWNER_CAPS


def read_events(text: str) -> list[dict]:
    """The core's E-09 records as written so far. The record writer appends asynchronously (engine/records.py), so a
    last line without its newline may be half written: it is left out."""
    lines = text.split("\n")
    return [json.loads(line) for line in (lines if text.endswith("\n") else lines[:-1]) if line.strip()]


def model_requests(events: list[dict], execution: str) -> list[dict]:
    """One row's network requests, paired by seq as the engine's gate pairs them (run_gate.py requests_of):
    admission, decision, and the completion, which v4 writes only under the measurement switch, as a
    request_completed diagnostic. A file request's seq is the file port's own (H-20), so its records are left out by
    their admission numbers."""
    files = {(e.get("detail") or {}).get("admission") for e in events if e["kind"] == "request_admitted"
             and (e.get("detail") or {}).get("request_kind") == "file"}
    by_seq: dict = {}
    for e in events:
        d = e.get("detail") or {}
        if e["kind"] == "diagnostic" and e.get("name") == "request_completed" and d.get("execution_id") == execution:
            by_seq.setdefault(d.get("seq"), {})["completed"] = d
        elif ((e.get("control_binding") or {}).get("execution_id") == execution
              and e["kind"] in ("request_admitted", "request_decided") and "seq" in d
              and d.get("admission") not in files):
            by_seq.setdefault(d["seq"], {})[e["kind"]] = {"outcome": e.get("outcome"), **d}
    out = []
    for seq, r in sorted(by_seq.items(), key=lambda x: (x[0] is None, x[0] or 0)):
        a, dec, done = r.get("request_admitted", {}), r.get("request_decided", {}), r.get("completed", {})
        out.append({"seq": seq,
                    "request": [a.get("method"), a.get("host"), (a.get("path") or "").split("?")[0]] if a else None,
                    "decision": dec.get("outcome"), "credential": dec.get("credential"),
                    "result": done.get("result"), "status": done.get("status")})
    return out


def entry_counts_off(ws_list: str, workspaces: list[str], want: int) -> dict[str, str | None]:
    """The workspaces of `admin ws list` (client/render.py: workspace= root= state= entries=) that do not hold exactly
    `want` entries, with what they hold (None: not listed)."""
    counts = {w: n for w, n in re.findall(r"workspace=(\S+) .*?entries=(\d+)", ws_list)}
    return {w: counts.get(w) for w in workspaces if counts.get(w) != str(want)}


def model_call_ok(requests: list[dict]) -> bool:
    """protocol.md 1 and 2.2 on the engine: POST /v1/messages allowed, the credential placed, answered 2xx."""
    return any(r["request"] and r["request"][0] == "POST" and r["request"][2].startswith("/v1/messages")
               and r["decision"] == "allow" and r["credential"] == "placed"
               and isinstance(r["status"], int) and 200 <= r["status"] < 300 for r in requests)


class QuestionWatcher:
    """`engine-client admin questions` as the user's window: every question answered deny-once at once and logged."""

    def __init__(self, argv: list[str], log: Path) -> None:
        self.log, self.count, self.new = log, 0, []
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        pending = b""
        while True:
            data = self.proc.stdout.read1(65536)
            if not data:
                return
            pending += data
            while (m := re.search(rb"answer question (\d+) \[[^\]]*\]: ", pending)):
                text, pending = pending[:m.start()], pending[m.end():]
                self.proc.stdin.write(b"deny-once\n")
                self.proc.stdin.flush()
                self.count += 1
                body = text.decode("utf-8", "replace")
                # client/render.py question_lines: host and port on lines of their own
                host = re.search(r"^\s+host\s+(\S+)\s*$", body, re.M)
                port = re.search(r"^\s+port\s+(\d+)\s*$", body, re.M)
                q = {"t": time.time(), "qid": int(m.group(1)), "text": body[-3000:],
                     "host_port": f"{host.group(1)}:{port.group(1)}" if host and port else None}
                self.new.append(q)
                with self.log.open("a") as fh:
                    fh.write(json.dumps(q) + "\n")

    def stop(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()


class EngineV4(Adapter):
    name = "engine-v4-copy"
    MODE = "copy"
    ENGINE_DIR, FRONTEND = ENGINE_V4, "go"

    def __init__(self, agent_getter, key: str) -> None:
        super().__init__(agent_getter, key)
        self.as_user, self.python, self.spawner_caps = _engine_checks()
        self.base = Path(f"{WORK}/{self.name}")
        self.deploy = self.base / "deploy"
        self.watcher: QuestionWatcher | None = None
        self.engine_pid: int | None = None
        self.pdp_pid: int | None = None
        self.notes: list[dict] = []
        self.rules: dict = {}   # the rules as registered and the model check, kept with the next repetition's record
        self.stamp: str | None = None
        self.evidence: Path | None = None
        self.archive_errors: list[str] = []   # a required record not copied into the run directory (residue())

    # ---- helpers ----
    def _client(self, *args: str, env: dict | None = None, check: bool = True, timeout: float = 60) -> dict:
        argv = [*self.as_user, *self.python, str(self.ENGINE_DIR / "bin/engine-client"), "--root", str(self.deploy),
                *args]
        r = self.agent.call("exec", argv=argv, env={**ROOT_ENV, **(env or {})}, timeout=timeout)
        if check and r["rc"] != 0:
            raise RuntimeError(f"engine-client {' '.join(args[:3])} failed ({r['rc']}): {r['stdout'][-600:]}")
        return r

    def _rows(self) -> dict[str, dict]:
        r = self._client("admin", "row", "list", check=False)
        if r["rc"] != 0:
            return {}
        rows = {}
        for line in r["stdout"].splitlines():
            f = dict(x.split("=", 1) for x in line.split() if "=" in x)
            if "execution" in f:
                rows[f["execution"]] = {"workspace": f.get("workspace"), "state": f.get("state"),
                                        "uid": int(f["uid"]) if f.get("uid", "").isdigit() else None}
        return rows

    def _wait_rows_gone(self, executions: set[str], timeout: float = 90) -> list[str]:
        deadline = time.monotonic() + timeout
        while (left := executions & set(self._rows())) and time.monotonic() < deadline:
            time.sleep(0.5)
        return sorted(left)

    def _deploy_cmd(self, *args: str, timeout: float = 300) -> str:
        r = self.agent.call("exec", argv=["python3", "-m", "driver.engine_deploy", *args], env=ROOT_ENV,
                            cwd=str(DRIVER_HOME), timeout=timeout)
        if r["rc"] != 0:
            raise RuntimeError(f"engine_deploy {args[0]} failed ({r['rc']}): {r['stdout'][-1500:]}")
        return r["stdout"]

    def _state(self) -> dict:
        return json.loads(Path(self.base / "deployment.json").read_text())

    def _trace_has(self, word: str, timeout: float, what: str) -> None:
        deadline = time.monotonic() + timeout
        while self._run(["grep", "-c", word, str(self.evidence)], check=False).strip() in ("", "0"):
            if time.monotonic() > deadline:
                raise RuntimeError(f"{what} not in the core's records within {timeout:.0f} s")
            time.sleep(1)

    # ---- object lifecycle ----
    def groups(self) -> dict[str, list[str]]:
        return {"unit": [f"{CGBASE}/units"], "shared": [f"{CGBASE}/shared"]}

    def prepare(self) -> None:
        """The deployment is the installed product: built once (before baseline 1) and kept; the core is stopped."""
        self.stop_shared()
        if not (self.base / "deployment.json").exists():
            self._deploy_cmd("build", str(self.base), self.MODE, str(self.ENGINE_DIR), self.FRONTEND, timeout=1800)
            self._settle_after_build()
        state = self._state()
        if (state["mode"], state["engine"], state["frontend"]) != (self.MODE, str(self.ENGINE_DIR), self.FRONTEND):
            raise RuntimeError(f"{self.base} holds another deployment: {state['mode']} {state['engine']} "
                               f"{state['frontend']}")

    def _settle_after_build(self, window: float = 15, max_wait: float = 180, mib: float = 20) -> None:
        """Building the deployment (native and Go builds, the seed, its hashes, the loop images) leaves memory that
        the host gives back over minutes; read before that, baseline 1 sits high and the pass's cleanup check, which
        judges the difference either way, fails although nothing is left (mini trial 20261031T032431Z: baseline 1
        1554 MiB, after cleanup 1046). Write back and drop the page cache, then wait until used memory is steady."""
        self.agent.call("drop_caches")
        start, seen = time.monotonic(), []
        while time.monotonic() - start < max_wait:
            seen.append((time.monotonic(), self.agent.call("meminfo")["used_mib"]))
            recent = [v for t, v in seen if t >= seen[-1][0] - window]
            if seen[-1][0] - start >= window and max(recent) - min(recent) < mib:
                return
            time.sleep(1)

    def start_shared(self) -> None:
        shared = self.agent.call("mkcg", rel="shared")["path"]
        stamp = self.stamp = time.strftime("%Y%m%dT%H%M%S")
        evidence = self.evidence = self.base / f"evidence/events-{stamp}.jsonl"
        # the PDP's group reads the trace, never writes it; the engine uid writes it (run_gate.py)
        self._run(["install", "-o", str(ENGINE_UID), "-g", str(PDP_UID), "-m", "640", "/dev/null", str(evidence)])
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
        # The simple PDP (P-01) first, as the gate starts it: it connects once the hook port is up (pdp/simple.py).
        r = self.agent.call("spawn", cgroup=shared, argv=[*PDP_AS, *self.python, str(self.ENGINE_DIR / "bin/simple-pdp"),
                                                          str(self.deploy / "hook/pdp.sock")],
                            cwd="/", env=env, log=str(self.base / f"pdp-{stamp}.log"), pty=False)
        self.pdp_pid = r["pid"]
        build = self.base / "build"
        argv = [*CORE_LIMIT, *self.spawner_caps, str(build / "w2-cell"), str(self.deploy), "catalog.json",
                str(ENGINE_UID), str(ENGINE_UID), *self.python, str(self.ENGINE_DIR / "bin/engine"),
                str(build / "libw2sandbox.so"), str(self.deploy), "catalog.json", str(evidence), "--measure-completion"]
        r = self.agent.call("spawn", cgroup=shared, argv=argv, cwd="/", env=env,
                            log=str(self.base / f"engine-{stamp}.log"), pty=False)
        self.engine_pid = r["pid"]
        deadline = time.monotonic() + 120
        while self._client("admin", "ws", "list", check=False)["rc"] != 0:
            if time.monotonic() > deadline:
                raise RuntimeError("the engine's management port did not come up within 120 s")
            time.sleep(1)
        self._client("admin", "cred", "put", HOST, ACCOUNT, "api-key", "--truth-env", "W2_TRUTH",
                     env={"W2_TRUTH": self.key})
        commands = []
        for i in range(1, UNITS + 1):
            commands.append(["entry", "put", f"work{i}", "exact", "allow", HOST, "--account", ACCOUNT,
                             "--approval", "never"])
            commands += [["entry", "put", f"work{i}", "exact", "deny", h, "--approval", "never"] for h in OTHER_HOSTS]
        for c in commands:
            self._client("admin", *c)
        # v4's default fallback entry in every workspace (engine/workspaces.py FALLBACK_DEFAULT: any host's GET allowed,
        # never asked) goes, so every other host is refused (protocol.md 1). The deletion is written to the workspace
        # table, so a later core start on this deployment finds it absent.
        fallback = {}
        for i in range(1, UNITS + 1):
            r = self._client("admin", "entry", "del", f"work{i}", "fallback", check=False)
            if r["rc"] != 0 and "no such entry" not in r["stdout"]:
                raise RuntimeError(f"deleting work{i}'s fallback entry failed ({r['rc']}): {r['stdout'][-300:]}")
            fallback[f"work{i}"] = "deleted" if r["rc"] == 0 else "absent"
        ws_list = self._client("admin", "ws", "list")["stdout"]
        off = entry_counts_off(ws_list, [f"work{i}" for i in range(1, UNITS + 1)], ENTRIES)
        if off:
            raise RuntimeError(f"workspaces not holding exactly the {ENTRIES} registered entries: {off}")
        self.rules = {"commands": commands, "fallback": fallback, "ws_list": ws_list}
        (self.base / f"rules-{stamp}.txt").write_text(json.dumps(self.rules, indent=1))
        client = [*self.as_user, *self.python, str(self.ENGINE_DIR / "bin/engine-client"), "--root", str(self.deploy)]
        self.watcher = QuestionWatcher([*client, "admin", "questions"], self.base / "questions.jsonl")
        # The spawner reports control_ready after verifying the seed; the PDP is connected before any row asks it.
        # Baseline 2 is read after both.
        self._trace_has("control_ready", 180, "the spawner's control_ready")
        self._trace_has("pdp_connected", 60, "the PDP's connection")
        self.rules["model_check"] = self._model_check()
        (self.base / f"rules-{stamp}.txt").write_text(json.dumps(self.rules, indent=1))

    def _model_check(self) -> dict:
        """One Claude Code call in print mode through the engine (row of the "check" runtime on work1); the core's
        records must show POST /v1/messages allowed with the credential placed and answered 2xx."""
        t0 = time.monotonic()
        while True:
            r = self._client("admin", "row", "start", "work1", "check-1", check=False)
            if r["rc"] == 0:
                break
            if "control not ready" not in r["stdout"] or time.monotonic() > t0 + 120:
                raise RuntimeError(f"model check: row start failed: {r['stdout'][-600:]}")
            time.sleep(1)
        execution = re.search(r"execution=(\S+)", r["stdout"]).group(1)
        left = self._wait_rows_gone({execution}, timeout=180)
        if left:
            self._client("admin", "row", "stop", execution, check=False)
            raise RuntimeError(f"model check: row {execution} still running after 180 s")
        out = model_requests(read_events(self.evidence.read_text()), execution)
        if not model_call_ok(out):
            raise RuntimeError(f"model check through the engine did not get a 2xx: {out}")
        return {"execution": execution, "seconds": round(time.monotonic() - t0, 1), "requests": out}

    def _archive(self) -> None:
        """Copy the stopped core's records and the deployment's configuration into the run directory (no credential
        store; every file checked for the key). A file that exists but is not copied (a read or write error, or the key
        in it) makes residue() fail, so the run stops visibly incomplete. A file that was never produced, because the
        start failed before it (the rules before registration ended, the logs before the spawn), is only noted: that
        failure is already the pass's own error. The question log exists only once a question came."""
        if self.run_dir is None or self.stamp is None:
            return
        dest = Path(self.run_dir) / "engine" / f"{self.name}-{self.stamp}"
        dest.mkdir(parents=True, exist_ok=True)
        required = [self.evidence, self.base / f"engine-{self.stamp}.log", self.base / f"pdp-{self.stamp}.log",
                    self.base / f"rules-{self.stamp}.txt", self.base / "deployment.json",
                    *sorted(self.deploy.glob("*.json")),      # catalog, its artifacts, the runtimes, every plan
                    self.deploy / "seed/dependency-lock.json", self.deploy / "w2/claude.json",
                    self.deploy / "w2/idle.js"]
        optional = [self.base / "questions.jsonl"]
        errors, notes = [], []
        for f in [*required, *(f for f in optional if f.exists())]:
            if not Path(f).exists():
                notes.append(f"{f}: never produced")
                continue
            try:
                data = Path(f).read_bytes()
                if self.key.encode() in data or self.key[-20:].encode() in data:
                    errors.append(f"{f}: holds the key, not copied")
                    continue
                (dest / (f"w2-{Path(f).name}" if Path(f).parent.name == "w2" else Path(f).name)).write_bytes(data)
            except OSError as exc:
                errors.append(f"{f}: {exc}")
        if errors or notes:
            (dest / "copy-errors.txt").write_text("".join(f"not copied: {e}\n" for e in errors) +
                                                  "".join(f"{n}\n" for n in notes))
        self.archive_errors += errors
        self.stamp = None

    def stop_shared(self) -> None:
        """SIGTERM to the engine first: it closes the control channel and the spawner exits on EOF (as run_gate does);
        then the PDP, which would otherwise keep reconnecting (pdp/simple.py; SIGTERM ends it). A pid is signalled only
        while it is still in the shared group (a core that died may have left its pid to another process)."""
        if self.watcher is not None:
            self.watcher.stop()
            self.watcher = None
        shared = f"{CGBASE}/shared"
        if self._pids(shared):
            if self.engine_pid in self._pids(shared):
                self._run(["kill", "-TERM", str(self.engine_pid)], check=False)
            deadline = time.monotonic() + 60
            while set(self._pids(shared)) - {self.pdp_pid} and time.monotonic() < deadline:
                time.sleep(0.5)
            if self.pdp_pid in self._pids(shared):
                self._run(["kill", "-TERM", str(self.pdp_pid)], check=False)
            deadline = time.monotonic() + 20
            while self._pids(shared) and time.monotonic() < deadline:
                time.sleep(0.5)
        self.engine_pid = self.pdp_pid = None
        self.agent.call("killcg", path=shared)
        self._archive()

    def teardown(self) -> None:
        if (self.base / "deployment.json").exists():
            self._deploy_cmd("teardown", str(self.base))

    # ---- units ----
    def create_units(self, n: int) -> list[Unit]:
        if n > UNITS:
            raise RuntimeError(f"{n} units > {UNITS} workspaces")
        self._deploy_cmd("capool", str(self.base), str(2 * n + 2))
        self._run(["mkdir", "-p", str(self.base / "screens")])
        self.units, self.notes = [], []
        for i in range(1, n + 1):
            self.agent.call("mkcg", rel=f"units/u{i}", cpu_max=UNIT_CPU_MAX, mem_max=UNIT_MEM_MAX)
            self.units.append(Unit(i, f"u{i}", {}))
        return self.units

    def _start_row(self, u: Unit, runtime: str) -> None:
        t0 = time.monotonic()
        deadline = t0 + 180
        while True:
            r = self._client("admin", "row", "start", f"work{u.index}", f"{runtime}-{u.index}", check=False)
            if r["rc"] == 0:
                break
            if "control not ready" not in r["stdout"] or time.monotonic() > deadline:
                raise RuntimeError(f"{u.name}: row start {runtime} failed: {r['stdout'][-600:]}")
            time.sleep(1)
        started_s = time.monotonic() - t0
        execution = re.search(r"execution=(\S+)", r["stdout"]).group(1)
        uid = self._rows().get(execution, {}).get("uid")
        if uid is None:
            raise RuntimeError(f"{u.name}: {execution} not in the row list")
        cg = f"{CGBASE}/units/u{u.index}"
        last_move, quiet, moves = time.monotonic(), 0, 0
        while quiet < 2:
            a = self.agent.call("adopt", cgroup=cg, uid=uid, execution=execution, row_uids=ROW_UIDS)
            if a["moved"]:
                last_move, moves = time.monotonic(), moves + a["moved"]
            up = (any(c.startswith(MAIN[runtime]) for c in a["cell"])
                  and all(a["outside"][name] == 1 for name in ROW_UIDS))
            quiet = quiet + 1 if up and not a["moved"] else 0
            if time.monotonic() > deadline:
                raise RuntimeError(f"{u.name}: row {execution} not up within 180 s: {a}")
            time.sleep(0.2)
        u.handles.update(execution=execution, uid=uid, runtime=runtime)
        self.notes.append({"unit": u.name, "runtime": runtime, "execution": execution, "uid": uid,
                           "row_start_s": round(started_s, 3), "moved_by_s": round(last_move - t0, 3),
                           "moved": moves, "cell": a["cell"], "outside": a["outside"]})

    def _stop_rows(self) -> None:
        rows = {u.handles["execution"] for u in self.units if u.handles.get("execution")}
        for ex in rows:
            self._client("admin", "row", "stop", ex, check=False)
        left = self._wait_rows_gone(rows)
        if left:
            raise RuntimeError(f"rows still listed 90 s after stop: {left}")

    def set_state(self, state: str) -> None:
        if state == "idle":
            for u in self.units:
                self._start_row(u, "probe")
        elif state == "resident":
            self._stop_rows()
            for u in self.units:
                self._start_row(u, "claude")
        else:
            raise ValueError(state)

    def alive(self) -> list[str]:
        """Units whose row is not ACTIVE or that miss one of their six processes, by role (pid 1, the three cell
        helpers, one connector, one file worker), or hold one outside the unit's cgroup; the core or the PDP gone from
        the shared group; a dead question window; and any question at all: the registration has no entry that asks,
        so a question means it is not what protocol.md 1 says, a configuration error that stops the block."""
        rows = self._rows()
        started = [u for u in self.units if u.handles.get("execution")]
        census = self.agent.call("rowcensus", row_uids=ROW_UIDS, rows=[
            {"cgroup": f"{CGBASE}/units/u{u.index}", "uid": u.handles["uid"], "execution": u.handles["execution"]}
            for u in started])["rows"]
        dead = [u.name for u in self.units if not u.handles.get("execution")]
        for u, c in zip(started, census):
            state = rows.get(u.handles["execution"], {}).get("state")
            if (state != "ACTIVE" or not {MAIN[u.handles["runtime"]], *CELL_HELPERS} <= set(c["cell"])
                    or any(c["outside"][name] != 1 for name in ROW_UIDS) or c["elsewhere"]):
                dead.append(f"{u.name} (state {state}, cell {c['cell']}, outside {c['outside']}, "
                            f"not in the unit cgroup {c['elsewhere']})")
        shared = set(self._pids(f"{CGBASE}/shared"))
        dead += [f"the {what} left the shared group" for what, pid in (("engine core", self.engine_pid),
                                                                        ("PDP", self.pdp_pid))
                 if pid is not None and pid not in shared]
        if self.watcher is not None:
            if self.watcher.proc.poll() is not None:
                dead.append(f"the question window exited ({self.watcher.proc.returncode})")
            if self.watcher.count:     # counted for the core run, never reset: every later check stops too
                dead.append(f"{self.watcher.count} question(s) prompted (the registration asks nothing): "
                            f"configuration error; logged in questions.jsonl")
        return dead

    def prompt_evidence(self) -> dict[str, dict]:
        """After the window, every unit at once: attach for a few seconds from a 40x120 terminal (the size change makes
        Claude Code redraw its whole screen; the relay keeps no past screen), as OpenShell's screen check does. The
        stdin pipe outlives the attach; nothing is typed. The relay keeps the row alive after the client is gone."""
        client = " ".join(f"'{a}'" for a in [*self.as_user, *self.python, str(self.ENGINE_DIR / "bin/engine-client"),
                                              "--root",
                                              str(self.deploy), "attach"])
        screens = {u.name: self.base / f"screens/u{u.index}.raw" for u in self.units}
        jobs = "\n".join(f"( sleep 9 ) | timeout 6 script -qfc \"stty rows 40 cols 120 2>/dev/null; exec {client} "
                         f"'{u.handles['execution']}'\" '{screens[u.name]}' >/dev/null 2>&1 &" for u in self.units)
        self._run(["bash", "-c", jobs + "\nwait"], timeout=60, check=False)
        return {name: prompt_verdict(self._screen(str(path))) for name, path in screens.items()}

    def rep_notes(self) -> dict:
        notes, self.notes = self.notes, []
        questions = self.watcher.new if self.watcher else []
        if self.watcher:
            self.watcher.new = []
        rules, self.rules = self.rules, {}
        return {"rows": notes, "questions": questions, **({"rules": rules} if rules else {})}

    def destroy_units(self) -> None:
        try:
            self._stop_rows()
        finally:
            self.agent.call("killcg", path=f"{CGBASE}/holders")
            for u in self.units:
                self.agent.call("killcg", path=f"{CGBASE}/units/u{u.index}")
            self._run(["rm", "-rf", str(self.base / "screens")], check=False)
            self.units = []

    def residue(self) -> list[str]:
        out = []
        if self._pids(f"{CGBASE}/shared"):
            out.append("engine core or PDP still running")
        uids = [*range(UID_FIRST, UID_FIRST + UID_COUNT), CONNECTOR_UID, FILE_WORKER_UID, OWNER_UID, PDP_UID]
        procs = self.agent.call("uidprocs", uids=uids)["procs"]
        if procs:
            out.append(f"{len(procs)} row or PDP processes left: {[(p['pid'], p['uid'], p['comm']) for p in procs][:8]}")
        # rows/ and the store: no execution or copy left
        for d in ("rows", "store/objects"):
            left = self._run(["sh", "-c", f"ls -A {self.deploy}/{d} 2>/dev/null"], check=False).split()
            if left:
                out.append(f"{d} not empty: {left[:4]}")
        # hook/: the core unlinks pdp.sock only on its own exit path (engine/main.py after the control link dies); a
        # core stopped with SIGTERM, as here and in the engine's gate, leaves the file, and the next start unlinks it
        # before binding (engine/pdp.py HookPort; smoke 20261105T121843). Residue is anything else there, or a
        # pdp.sock that still accepts a connection.
        hook = self.deploy / "hook"
        left = self._run(["sh", "-c", f"ls -A {hook} 2>/dev/null"], check=False).split()
        if [n for n in left if n != "pdp.sock"]:
            out.append(f"hook not empty: {left[:4]}")
        if "pdp.sock" in left:
            r = self.agent.call("exec", argv=["python3", "-I", "-c", SOCKET_PROBE, str(hook / "pdp.sock")],
                                env=ROOT_ENV, timeout=30)
            if r["rc"] != STALE:
                out.append(f"hook/pdp.sock is not a stale socket (probe exit {r['rc']}): {r['stdout'][-200:]}")
        if self._pids(f"{CGBASE}/units"):
            out.append("processes left under units")
        # killcg removes each unit's cgroup and the shared one once they are empty; a leaf left means it did not
        leaves = self._run(["sh", "-c", f"ls -d {CGBASE}/shared {CGBASE}/units/u* 2>/dev/null"], check=False).split()
        if leaves:
            out.append(f"cgroups not removed: {leaves[:4]}")
        if self.archive_errors:
            out.append(f"records not archived: {self.archive_errors[:4]}")
        return out


class EngineV4Shared(EngineV4):
    name = "engine-v4-shared"
    MODE = "shared"


def teardown_deployments() -> list[str]:
    """Unmount and remove every engine deployment under WORK (end of a run: the engine's credential store in each
    deployment holds the model key), and every half-built one too (a build killed from outside, e.g. at its timeout,
    leaves its mounts but no deployment.json). Returns what could not be removed."""
    left = []
    for base in sorted(p for p in Path(WORK).glob("engine*") if p.is_dir()):
        try:
            r = subprocess.run([sys.executable, "-m", "driver.engine_deploy", "teardown", str(base)],
                               cwd=DRIVER_HOME, capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                left.append(f"{base}: {(r.stdout + r.stderr)[-400:]}")
        except (OSError, subprocess.SubprocessError) as exc:   # one failure must not skip the other deployments
            left.append(f"{base}: {type(exc).__name__}: {exc}")
    return left


ENGINE_ADAPTERS = {cls.name: cls for cls in (EngineV4, EngineV4Shared)}
ADAPTERS.update(ENGINE_ADAPTERS)
