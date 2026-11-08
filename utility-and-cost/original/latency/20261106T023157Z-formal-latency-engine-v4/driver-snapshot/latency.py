"""One request through this thesis's engine against the same request made directly (protocol.md 3.3, the v4 round; plan
engine-v4-request-latency). Run as root on the measurement server, from the driver's parent directory:

    python3 -m driver.latency config/latency-engine-v4.json formal      # or: trial

One k6 v2.3.0, one VU, one request at a time. The engine arm runs k6 in a cell of engine v4's default shared placement,
through the in-cell frontend; the direct arm runs it on the host as an ordinary user under the same quota. The upstream
is nginx in a network namespace of its own, reached over a veth. Each entry names the upstream's non-global address
(--address) and the connector trusts the test CA (--ca-file), both settings of the engine as shipped. No model API,
no Claude Code. The core runs without the measurement switch: --measure-completion adds a record per request, so a run
with it would not be the default path. Whether a request succeeded is read from k6 and the upstream's log instead.

CPUs: nginx on vCPU 0-3, this driver and its agent on vCPU 4, everything measured on vCPU 5-15 (protocol.md 2.4).
Each pass starts a fresh core; the order of the blocks and of the two arms within a block is shuffled from the seed.
The evidence files and k6's raw output are kept gzipped in the run directory. The credential here is a random test
value, never a real key, so nothing of the model key is read.
"""
from __future__ import annotations

import gzip
import json
import os
import platform
import random
import secrets
import shutil
import signal
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import analyze_latency, client
from .engine_object import ENGINE_V4, MAIN, ROW_UIDS, EngineV4Shared, entry_counts_off
from .objects import AS_AGENT, CGBASE, ROOT_ENV, UNIT_CPU_MAX, UNIT_MEM_MAX, WORK

EXP = Path(__file__).resolve().parents[1]
UPSTREAM_CPUS, DRIVER_CPU, MEASURED_CPUS = "0-3", 4, "5-15"
NS, HOST_IF, NS_IF = "latup", "lat0", "lat1"
HOST_ADDR, UPSTREAM_ADDR = "10.77.0.1", "10.77.0.2"
HOSTS = {"plain": "plain.lat.test", "cred": "cred.lat.test"}
PORTS = {"keepalive": 443, "clientcold": 443, "bothcold": 8443}
HOSTS_MARK = "# sota-latency"
ACCOUNT = "measure"
UPSTREAM_DIR = Path(WORK) / "lat-upstream"
LOG_FORMAT = ("$msec $request_time $connection $connection_requests $ssl_session_reused $ssl_protocol $request_method "
              "$request_uri $status $request_length $bytes_sent $host")
BLOCK_WAIT_S = 2400
FSYNC_ROUNDS, CALIBRATION_ROUNDS = 2000, 30_000_000


@dataclass(frozen=True)
class Block:
    cls: str     # plain or cred
    conn: str    # keepalive, clientcold or bothcold
    size: str    # small: GET, 1 KiB back; big: POST 64 KiB, 1 MiB back

    @property
    def id(self) -> str:
        return f"{self.cls}-{self.conn}-{self.size}"


BLOCKS = (*(Block(c, k, "small") for c in HOSTS for k in PORTS), Block("cred", "keepalive", "big"))


def k6_script() -> str:
    """The same script for both arms. Each path is unique, so the client, the upstream and the records can be matched.
    Setup waits so that the driver has placed the row's processes before the first request."""
    return """import http from 'k6/http';
import { sleep } from 'k6';
const E = __ENV;
export const options = {
  scenarios: { block: { executor: 'per-vu-iterations', vus: 1, iterations: Number(E.N), maxDuration: '35m' } },
  noConnectionReuse: E.CONN !== 'keepalive',
  discardResponseBodies: true,
  setupTimeout: '120s',
  systemTags: ['status', 'proto', 'scenario', 'group'],
};
const BASE = `https://${E.HOST}:${E.PORT}`;
const PARAMS = { timeout: '30s', headers: E.KEY ? { 'x-api-key': E.KEY } : {} };
const BODY = E.SIZE === 'big' ? 'x'.repeat(64 * 1024) : null;
export function setup() { sleep(Number(E.SETTLE)); return { run: String(Date.now()) }; }
export default function (data) {
  const path = `/${E.BLOCK}/${data.run}/${__ITER}`;
  if (BODY) { http.post(`${BASE}/big${path}`, BODY, PARAMS); } else { http.get(`${BASE}${path}`, PARAMS); }
}
"""


def k6_args(block: Block, config: dict, key: str, out: str, script: str) -> list[str]:
    env = {"N": config["warmup"] + config["measured"], "CONN": block.conn, "SIZE": block.size, "BLOCK": block.id,
           "HOST": HOSTS[block.cls], "PORT": PORTS[block.conn], "SETTLE": config["settle_s"]}
    if block.cls == "cred":
        env["KEY"] = key
    pairs = [x for k, v in env.items() for x in ("-e", f"{k}={v}")]
    return ["run", "--no-usage-report", "--quiet", *pairs, f"--out=json={out}", script]


def nginx_conf(base: Path, truth: str) -> str:
    def server(host: str, port: int, cold: bool) -> str:
        reuse = ("keepalive_timeout 0; ssl_session_cache off; ssl_session_tickets off;" if cold else
                 "keepalive_timeout 75s; keepalive_requests 1000000; ssl_session_cache shared:s:1m;")
        guard = 'if ($key_ok = 0) { return 403; }' if host == HOSTS["cred"] else ""
        return f"""  server {{
    listen {UPSTREAM_ADDR}:{port} ssl;
    server_name {host};
    {reuse}
    {guard}
    root {base}/www;
    location / {{ rewrite ^ /body-1k break; }}
    location /big/ {{
      client_max_body_size 2m;
      client_body_buffer_size 128k;
      rewrite ^ /big-1m break;
      proxy_pass http://big_response;
      proxy_method GET;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_buffering off;
    }}
  }}
"""
    servers = "".join(server(h, p, c) for h in HOSTS.values() for p, c in ((443, False), (8443, True)))
    return f"""worker_processes 2;
pid {base}/nginx.pid;
error_log {base}/error.log;
events {{ worker_connections 1024; }}
http {{
  default_type application/octet-stream;
  sendfile on;
  tcp_nodelay on;
  log_format lat '{LOG_FORMAT}';
  access_log {base}/access.log lat;
  ssl_protocols TLSv1.3;
  ssl_certificate {base}/leaf.pem;
  ssl_certificate_key {base}/leaf.key;
  map $http_x_api_key $key_ok {{ "{truth}" 1; default 0; }}
  # The big block's response: nginx reads the whole request body first (a static handler would answer before reading
  # it), then passes this 1 MiB on. Both arms go through it.
  upstream big_response {{ server 127.0.0.1:8081; keepalive 8; }}
  server {{ listen 127.0.0.1:8081; access_log off; root {base}/www; location = /big-1m {{ }} }}
{servers}}}
"""


def register_commands(workspace: str = "work1") -> tuple[list[list[str]], list[list[str]]]:
    """(credentials, entries): both hosts at both ports, exact allows naming the upstream's address; the credential
    only on the cred host. Nothing asks."""
    named = ["--address", f"{UPSTREAM_ADDR}/32", "--approval", "never"]
    creds, entries = [], []
    for port in sorted(set(PORTS.values())):
        creds.append(["cred", "put", f"{HOSTS['cred']}:{port}", ACCOUNT, "api-key", "--truth-env", "W2_TRUTH"])
        entries.append(["entry", "put", workspace, "exact", "allow", f"{HOSTS['cred']}:{port}", "--account", ACCOUNT, *named])
        entries.append(["entry", "put", workspace, "exact", "allow", f"{HOSTS['plain']}:{port}", *named])
    return creds, entries


def plan_order(seed: int, number: int) -> list[tuple[Block, list[str]]]:
    rng = random.Random(seed * 1000 + number)
    blocks = list(BLOCKS)
    rng.shuffle(blocks)
    return [(b, rng.sample(["direct", "engine"], 2)) for b in blocks]


def throttled(stat_text: str) -> tuple[int, int]:
    fields = dict(line.split() for line in stat_text.splitlines() if line.strip())
    return int(fields.get("nr_throttled", 0)), int(fields.get("throttled_usec", 0))


def add_hosts_line(text: str) -> str:
    return text.rstrip("\n") + f"\n{UPSTREAM_ADDR} {HOSTS['plain']} {HOSTS['cred']} {HOSTS_MARK}\n"


def remove_hosts_line(text: str) -> str:
    return "".join(line for line in text.splitlines(keepends=True) if HOSTS_MARK not in line)


class Upstream:
    """nginx in its own network namespace, a test CA, the two host names in /etc/hosts. stop() undoes all of it."""

    def __init__(self, truth: str) -> None:
        self.truth, self.proc, self.offset = truth, None, 0
        self.ca = UPSTREAM_DIR / "ca.pem"

    def _sh(self, *argv: str) -> None:
        subprocess.run(argv, check=True, capture_output=True, text=True, timeout=120)

    def _certs(self) -> None:
        d = UPSTREAM_DIR
        self._sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "3",
                 "-keyout", str(d / "ca.key"), "-out", str(d / "ca.pem"), "-subj", "/CN=sota latency test CA")
        self._sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", str(d / "leaf.key"), "-out", str(d / "leaf.csr"), "-subj", f"/CN={HOSTS['plain']}")
        (d / "san.txt").write_text(f"subjectAltName=DNS:{HOSTS['plain']},DNS:{HOSTS['cred']}\n")
        self._sh("openssl", "x509", "-req", "-in", str(d / "leaf.csr"), "-CA", str(d / "ca.pem"), "-CAkey", str(d / "ca.key"),
                 "-CAcreateserial", "-days", "3", "-out", str(d / "leaf.pem"), "-extfile", str(d / "san.txt"))
        os.chmod(d / "ca.pem", 0o644)

    def start(self) -> None:
        d = UPSTREAM_DIR
        (d / "www").mkdir(parents=True)
        (d / "www/body-1k").write_bytes(os.urandom(1024))
        (d / "www/big-1m").write_bytes(os.urandom(1024 * 1024))
        self._certs()
        (d / "nginx.conf").write_text(nginx_conf(d, self.truth))
        (d / "access.log").touch()
        self._sh("ip", "netns", "add", NS)
        self._sh("ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", NS_IF)
        self._sh("ip", "link", "set", NS_IF, "netns", NS)
        self._sh("ip", "addr", "add", f"{HOST_ADDR}/30", "dev", HOST_IF)
        self._sh("ip", "link", "set", HOST_IF, "up")
        self._sh("ip", "netns", "exec", NS, "ip", "addr", "add", f"{UPSTREAM_ADDR}/30", "dev", NS_IF)
        self._sh("ip", "netns", "exec", NS, "ip", "link", "set", NS_IF, "up")
        self._sh("ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up")
        hosts = Path("/etc/hosts")
        hosts.write_text(add_hosts_line(hosts.read_text()))
        self.proc = subprocess.Popen(["ip", "netns", "exec", NS, "taskset", "-c", UPSTREAM_CPUS, "nginx", "-c", str(d / "nginx.conf"),
                                      "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=open(d / "nginx.err", "ab"),
                                     start_new_session=True)
        ctx = ssl.create_default_context(cafile=str(self.ca))
        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(f"https://{HOSTS['plain']}/ready", context=ctx, timeout=3) as r:
                    if r.status == 200 and len(r.read()) == 1024:
                        break
            except OSError as exc:
                if time.monotonic() > deadline:
                    raise RuntimeError(f"upstream not answering: {exc}") from exc
                time.sleep(0.5)
        self.offset = (d / "access.log").stat().st_size

    def take_log(self, dest: Path) -> None:
        """What the upstream logged since the last call, into dest (gzip). Each block's lines stand alone."""
        with (UPSTREAM_DIR / "access.log").open("rb") as fh:
            fh.seek(self.offset)
            data = fh.read()
            self.offset = fh.tell()
        with gzip.open(dest, "wb") as out:
            out.write(data)

    def stop(self) -> list[str]:
        left = []
        if self.proc is not None and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                left.append("nginx had to be killed")
        hosts = Path("/etc/hosts")
        if HOSTS_MARK in hosts.read_text():
            hosts.write_text(remove_hosts_line(hosts.read_text()))
        if NS in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout:
            subprocess.run(["ip", "netns", "del", NS], capture_output=True)
        if Path(f"/sys/class/net/{HOST_IF}").exists():
            subprocess.run(["ip", "link", "del", HOST_IF], capture_output=True)
        return left


class LatencyEngine(EngineV4Shared):
    """v4's shared deployment with one workspace, one runtime per block and the upstream's test CA."""
    name = "engine-v4-latency"
    CORE_SWITCHES = ()
    PIN = ("taskset", "-c", MEASURED_CPUS)

    def __init__(self, agent_getter, key: str, config: dict, placeholder: str, ca: Path, rows: int) -> None:
        super().__init__(agent_getter, key)
        self.config, self.placeholder, self.ca, self.rows_wanted = config, placeholder, ca, rows

    def _runtimes(self) -> dict[str, list[str]]:
        out = {}
        for b in BLOCKS:
            args = k6_args(b, self.config, self.placeholder, f"/work/k6-{b.id}.json", "/w2/latency.js")
            out[b.id] = ["/runtime/bin/bash", "-c", "exec /runtime/bin/k6 " + " ".join(args)]
        return out

    def prepare(self) -> None:
        from . import engine_deploy    # Linux only (pwd, grp)
        self.stop_shared()
        if (self.base / "deployment.json").exists():
            raise RuntimeError(f"{self.base} is already deployed")
        engine_deploy.RUNTIMES.clear()
        engine_deploy.RUNTIMES.update(self._runtimes())
        engine_deploy.UNITS = 1
        MAIN.update({b.id: "k6" for b in BLOCKS})
        state = engine_deploy.build(self.base, self.MODE, self.ENGINE_DIR, self.FRONTEND)
        (self.deploy / "w2/latency.js").write_text(k6_script())
        os.chmod(self.deploy / "w2/latency.js", 0o444)
        ca = self.deploy / "lat-ca.pem"
        shutil.copy(self.ca, ca)
        os.chmod(ca, 0o644)
        _, _, sandbox = engine_deploy.load(self.ENGINE_DIR)
        catalog = json.loads((self.deploy / "catalog.json").read_text())
        catalog["connector"]["argv"] += ["--ca-file", str(ca)]
        state["catalog_digest"] = sandbox.save_json(self.deploy / "catalog.json", catalog)
        (self.base / "deployment.json").write_text(json.dumps(state, indent=1) + "\n")
        engine_deploy.capool(self.deploy, self.rows_wanted, self.ENGINE_DIR)
        self.tree = sandbox.TREE

    def _register(self, stamp: str) -> None:
        creds, entries = register_commands()
        for c in creds:
            self._client("admin", *c, env={"W2_TRUTH": self.key})
        for c in entries:
            self._client("admin", *c)
        r = self._client("admin", "entry", "del", "work1", "fallback", check=False)
        if r["rc"] != 0 and "no such entry" not in r["stdout"]:
            raise RuntimeError(f"deleting the fallback entry failed: {r['stdout'][-300:]}")
        ws_list = self._client("admin", "ws", "list")["stdout"]
        off = entry_counts_off(ws_list, ["work1"], len(entries))
        if off:
            raise RuntimeError(f"work1 does not hold exactly the {len(entries)} registered entries: {off}")
        self.rules = {"credentials": creds, "entries": entries, "fallback": "deleted" if r["rc"] == 0 else "absent",
                      "ws_list": ws_list}
        (self.base / f"rules-{stamp}.txt").write_text(json.dumps(self.rules, indent=1))

    def _model_check(self) -> dict:
        return {"not_run": "no model API in this measurement"}

    def output_of(self, block: Block) -> Path:
        return self.base / "workspaces/work1" / self.tree / f"k6-{block.id}.json"


def calibrate() -> float:
    """Single-threaded fixed work (protocol.md 2.4), on this driver's CPU."""
    start, total = time.perf_counter(), 0
    for i in range(CALIBRATION_ROUNDS):
        total += i & 7
    return time.perf_counter() - start


def fsync_probe(directory: Path) -> dict:
    """How long one append and fsync takes on the disk that holds the engine's records."""
    path, samples = directory / "fsync-probe.tmp", []
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        for _ in range(FSYNC_ROUNDS):
            t0 = time.perf_counter()
            os.write(fd, b"x" * 4096)
            os.fsync(fd)
            samples.append((time.perf_counter() - t0) * 1000)
    finally:
        os.close(fd)
        path.unlink()
    return {"median": analyze_latency.nearest_rank(samples, 0.5), "p99": analyze_latency.nearest_rank(samples, 0.99),
            "mean": statistics.fmean(samples)}


class Run:
    def __init__(self, run_dir: Path, config: dict, agent: client.Agent, engine: LatencyEngine, upstream: Upstream) -> None:
        self.dir, self.config, self.agent, self.engine, self.upstream = run_dir, config, agent, engine, upstream
        self.direct_dir = engine.base / "workspaces/direct"
        self.unit = None

    def _save_k6(self, source: Path, stem: str) -> str:
        dest = self.dir / "k6" / f"{stem}.json.gz"
        dest.parent.mkdir(exist_ok=True)
        with source.open("rb") as src, gzip.open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
        source.unlink()
        return str(dest.relative_to(self.dir))

    def _stat(self, cgroup: str) -> tuple[int, int]:
        return throttled(Path(cgroup, "cpu.stat").read_text())

    def _wait_empty(self, cgroup: str) -> None:
        """Polls the cgroup, not the core: an admin call during the block would be load on the path measured."""
        deadline = time.monotonic() + BLOCK_WAIT_S
        while self.agent.call("pids", path=cgroup)["pids"]:
            if time.monotonic() > deadline:
                raise RuntimeError(f"{cgroup} still has processes after {BLOCK_WAIT_S} s")
            time.sleep(1)

    def engine_arm(self, block: Block) -> dict:
        cgroup = f"{CGBASE}/units/u1"
        before = self._stat(cgroup)
        self.engine._start_row(self.unit, block.id)
        execution = self.unit.handles["execution"]
        self._wait_empty(cgroup)
        left = self.engine._wait_rows_gone({execution}, timeout=60)
        if left:
            raise RuntimeError(f"row {execution} still listed after its k6 ended")
        return {"execution": execution, "before": before, "after": self._stat(cgroup),
                "source": self.engine.output_of(block), "note": self.engine.notes[-1]}

    def direct_arm(self, block: Block, key: str) -> dict:
        cgroup = self.agent.call("mkcg", rel="units/direct", cpu_max=UNIT_CPU_MAX, mem_max=UNIT_MEM_MAX)["path"]
        out = self.direct_dir / f"k6-{block.id}.json"
        argv = [*LatencyEngine.PIN, *AS_AGENT, "/usr/local/bin/k6", *k6_args(block, self.config, key, str(out), "latency.js")]
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": str(self.direct_dir), "SSL_CERT_FILE": str(self.engine.deploy / "lat-ca.pem")}
        before = self._stat(cgroup)
        pid = self.agent.call("spawn", cgroup=cgroup, argv=argv, cwd=str(self.direct_dir), env=env,
                              log=str(self.dir / "k6-direct.log"), pty=False)["pid"]
        # By the process, not the cgroup: right after the spawn the process has not entered the cgroup yet.
        deadline = time.monotonic() + BLOCK_WAIT_S
        while self.agent.call("alive", pids=[pid])[str(pid)]:
            if time.monotonic() > deadline:
                raise RuntimeError(f"direct k6 still running after {BLOCK_WAIT_S} s")
            time.sleep(1)
        after = self._stat(cgroup)
        self.agent.call("killcg", path=cgroup)
        return {"before": before, "after": after, "source": out}

    def block(self, number: int, order: int, block: Block, arm: str) -> None:
        start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        load0 = os.getloadavg()[0]
        r = self.engine_arm(block) if arm == "engine" else self.direct_arm(block, self.engine.key)
        stem = f"p{number}-{block.id}-{arm}"
        k6_file = self._save_k6(r["source"], stem)
        up_file = self.dir / "upstream" / f"{stem}.log.gz"
        up_file.parent.mkdir(exist_ok=True)
        self.upstream.take_log(up_file)
        rec = {"pass": number, "order": order, "block": block.id, "cls": block.cls, "conn": block.conn, "size": block.size,
               "arm": arm, "start_utc": start, "end_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
               "load_at_start": load0, "throttled_periods": r["after"][0] - r["before"][0],
               "throttled_usec": r["after"][1] - r["before"][1], "k6_file": k6_file,
               "upstream_file": str(up_file.relative_to(self.dir)), "execution": r.get("execution"), "row": r.get("note")}
        with (self.dir / "blocks.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        print(f"{start} pass {number} {block.id} {arm} done", flush=True)

    def one_pass(self, number: int) -> None:
        reading = {"pass": number, "calibration_s": calibrate(), "fsync_ms": fsync_probe(self.engine.base / "evidence"),
                   "start_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        with (self.dir / "passes.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(reading) + "\n")
        self.engine.start_shared()
        self.unit = self.engine.create_units(1)[0]
        for order, (block, arms) in enumerate(plan_order(self.config["seed"], number)):
            for arm in arms:
                self.block(number, order, block, arm)
        questions = self.engine.watcher.count if self.engine.watcher else None
        self.engine.destroy_units()
        self.engine.stop_shared()
        if questions:
            raise RuntimeError(f"{questions} question(s) prompted: the registration asks nothing")
        for path in (self.dir / "engine").glob("*/events-*.jsonl"):
            with path.open("rb") as src, gzip.open(path.with_suffix(".jsonl.gz"), "wb") as out:
                shutil.copyfileobj(src, out)
            path.unlink()


def preflight() -> list[str]:
    problems = []
    if os.cpu_count() != 16:
        problems.append(f"{os.cpu_count()} CPUs, expected 16")
    for unit in ("docker.service", "containerd.service"):
        if subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0:
            problems.append(f"{unit} is running")
    if Path(WORK).exists():
        problems.append(f"{WORK} exists")
    if Path(CGBASE).exists() and any(Path(CGBASE).rglob("cgroup.procs")) and subprocess.run(["sh", "-c", f"cat {CGBASE}/*/cgroup.procs {CGBASE}/*/*/cgroup.procs 2>/dev/null | grep -q ."]).returncode == 0:
        problems.append(f"processes under {CGBASE}")
    if not shutil.which("nginx"):
        problems.append("nginx is not installed")
    if subprocess.run(["pgrep", "-x", "nginx"], capture_output=True).returncode == 0:
        problems.append("nginx is already running")
    if NS in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout:
        problems.append(f"network namespace {NS} exists")
    if HOSTS_MARK in Path("/etc/hosts").read_text():
        problems.append("/etc/hosts already has the test hosts")
    load = os.getloadavg()[0]
    if load > 1:
        problems.append(f"load average {load:.2f}")
    return problems


def versions() -> dict:
    def out(*argv: str) -> str:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return (p.stdout + p.stderr).strip()[:300]
    return {"kernel": platform.release(), "k6": out("/usr/local/bin/k6", "version"), "nginx": out("nginx", "-v"),
            "openssl": out("openssl", "version"), "python": sys.version.split()[0],
            "disk": out("lsblk", "-d", "-o", "NAME,MODEL,SIZE"), "cpu": out("sh", "-c", "grep -m1 'model name' /proc/cpuinfo")}


def main(argv: list[str]) -> int:
    config_path, mode = Path(argv[0]), argv[1]
    if mode not in ("trial", "formal"):
        raise SystemExit(__doc__)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    os.sched_setaffinity(0, {DRIVER_CPU})
    problems = preflight()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = EXP / "runs" / f"{stamp}-{mode}-{config['label']}"
    run_dir.mkdir(parents=True)
    shutil.copy2(config_path, run_dir / "config.json")
    shutil.copytree(Path(__file__).resolve().parent, run_dir / "driver-snapshot", ignore=shutil.ignore_patterns("__pycache__"))
    meta = {"mode": mode, "command": " ".join(sys.argv), "start_utc": stamp, "versions": versions(), "preflight": problems,
            "engine": str(ENGINE_V4), "row_uids": ROW_UIDS}
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    if problems:
        print("preflight:", problems)
        return 2

    def _on_term(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _on_term)
    truth, placeholder = secrets.token_hex(20), "0" * 40
    Path(WORK).mkdir(mode=0o755, parents=True)
    agent = client.Agent(run_dir, 5.0)
    upstream = Upstream(truth)
    rows = (len(BLOCKS) + 1) * config["passes"] + 4
    engine = LatencyEngine(lambda: agent, truth, config, placeholder, upstream.ca, rows)
    engine.run_dir = run_dir
    status, left = "completed", []
    try:
        upstream.start()
        (run_dir / "nginx.conf").write_text(nginx_conf(UPSTREAM_DIR, "<test value>"))
        engine.prepare()
        run = Run(run_dir, config, agent, engine, upstream)
        run.direct_dir.mkdir(mode=0o755)
        shutil.chown(run.direct_dir, user="jerry", group="jerry")
        (run.direct_dir / "latency.js").write_text(k6_script())
        for number in range(1, config["passes"] + 1):
            run.one_pass(number)
    except KeyboardInterrupt:
        status = "interrupted"
    except Exception as exc:
        status = f"error: {type(exc).__name__}: {exc}"
    finally:
        for step in (engine.destroy_units if engine.units else (lambda: None), engine.stop_shared):
            try:
                step()
            except Exception as exc:
                left.append(f"{getattr(step, '__name__', 'step')}: {type(exc).__name__}: {exc}")
        try:
            left += engine.residue()
            engine.teardown()
        except Exception as exc:
            left.append(f"teardown: {type(exc).__name__}: {exc}")
        left += upstream.stop()
        for leftover in (UPSTREAM_DIR,):
            shutil.rmtree(leftover, ignore_errors=True)
        try:
            Path(WORK).rmdir()
        except OSError as exc:
            left.append(f"{WORK} not empty: {exc}")
        agent.close()
        summary = {"status": status, "finished_utc": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), "left": left}
        (run_dir / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(run_dir, json.dumps(summary))
    return 0 if status == "completed" and not left else 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
