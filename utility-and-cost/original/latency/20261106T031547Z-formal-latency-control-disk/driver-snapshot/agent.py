"""Host agent of the memory driver (protocol.md 2.1, 2.5, 3.1). Runs as root on the Linux measurement server,
stdlib only.

One long-lived process per run: it is the holder of every unit it spawns (each unit's stdin is a pipe it keeps
open), it samples the host once per second into a JSONL file, and it answers one JSON command per stdin line
with one JSON reply per stdout line.

Process groups are cgroup v2 subtrees: under /sys/fs/cgroup/sotamem (units/u<i>, shared, harness) and any other
path an object names (for example Docker's container scopes). PSS is summed over every process found in a group's
subtree; a process listed in two groups counts in the first only. At start the agent moves itself and its parent
(the driver) into sotamem/harness, the measurement facilities' group.
"""
from __future__ import annotations

import glob
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

CG_ROOT_TEXT = "/sys/fs/cgroup"
CG_ROOT = Path(CG_ROOT_TEXT)
BASE = CG_ROOT / "sotamem"
KIB = 1024


def meminfo() -> dict[str, float]:
    """Selected /proc/meminfo fields in MiB, the host's used memory (MemTotal - MemAvailable, the protocol's main
    host-level reading on the server), swap in use and the root file system's free space in GiB."""
    want = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree", "Cached", "Shmem", "Committed_AS", "CommitLimit"}
    out = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        name, _, rest = line.partition(":")
        if name in want:
            out[name] = int(rest.split()[0]) / KIB
    out["used_mib"] = out["MemTotal"] - out["MemAvailable"]
    out["swap_used_mib"] = out["SwapTotal"] - out["SwapFree"]
    st = os.statvfs("/")
    out["disk_free_gib"] = st.f_bavail * st.f_frsize / 2**30
    return out


def pss_mib(pid: int) -> float | None:
    """PSS of one process in MiB, or None if it is gone or unreadable."""
    try:
        for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
            if line.startswith("Pss:"):
                return int(line.split()[1]) / KIB
    except (OSError, ValueError):
        return None
    return 0.0


def cgroup_pids(path: Path) -> list[int]:
    """Every pid in the cgroup subtree rooted at path (empty if the path does not exist)."""
    pids: list[int] = []
    if not path.is_dir():
        return pids
    for root, _dirs, files in os.walk(path):
        if "cgroup.procs" in files:
            try:
                pids += [int(x) for x in Path(root, "cgroup.procs").read_text().split()]
            except (OSError, ValueError):
                continue
    return pids


def file_reading(spec: str, max_age: float = 5.0) -> tuple[float, int] | None:
    """One column pair of the last line "<epoch s> <procs> <pss kB> [<procs> <pss kB> ...]" of an external
    sampler's log (processes this agent cannot see, e.g. in Docker Desktop's PID namespace). spec is
    "<path>#unit" (first pair) or "<path>#shared" (second pair). None if missing, malformed or older than max_age."""
    path, _, col = spec.partition("#")
    pair = {"unit": 0, "shared": 1}.get(col or "unit", 0)
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 512))
            lines = fh.read().decode("utf-8", "replace").split("\n")
        for line in reversed(lines):
            parts = line.split()
            if len(parts) >= 3 + 2 * pair and len(parts) % 2 == 1 and all(x.isdigit() for x in parts):
                t, n, kb = int(parts[0]), int(parts[1 + 2 * pair]), int(parts[2 + 2 * pair])
                return (kb / KIB, n) if time.time() - t <= max_age else None
    except OSError:
        return None
    return None


def shim_pids(scope_glob: str) -> list[int]:
    """containerd shims serving the containers whose cgroup directories match scope_glob (a shim's cmdline names its
    container with `-id <id>`; native Docker keeps the shims in containerd's own cgroup, not the container's)."""
    ids = {d.rsplit("-", 1)[-1].removesuffix(".scope") for d in glob.glob(scope_glob)}
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            if not (d / "comm").read_text().startswith("containerd-shim"):
                continue
            argv = (d / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if b"-id" in argv:
            i = argv.index(b"-id")
            if i + 1 < len(argv) and argv[i + 1].decode("utf-8", "replace") in ids:
                out.append(int(d.name))
    return out


def spec_pids(spec: str) -> list[int]:
    """Pids of one group entry: a cgroup path, "glob:<pattern>" (every matching cgroup directory) or
    "shim:<pattern>" (the shims of the containers in matching cgroup directories)."""
    if spec.startswith("glob:"):
        return [pid for d in sorted(glob.glob(spec[5:])) for pid in cgroup_pids(Path(d))]
    if spec.startswith("shim:"):
        return shim_pids(spec[5:])
    return cgroup_pids(Path(spec))


def group_reading(groups: dict[str, list[str]]) -> dict[str, dict]:
    seen: set[int] = set()
    out = {}
    for name, paths in groups.items():
        total, count, missing = 0.0, 0, 0
        for p in paths:
            if p.startswith("file:"):
                r = file_reading(p[5:])
                if r is None:
                    missing += 1
                else:
                    total, count = total + r[0], count + r[1]
                continue
            for pid in spec_pids(p):
                if pid in seen:
                    continue
                seen.add(pid)
                v = pss_mib(pid)
                if v is None:
                    missing += 1
                    continue
                total += v
                count += 1
        out[name] = {"pss_mib": total, "procs": count, "vanished": missing}
    # Every other process is external (protocol.md 4: only external processes' changes count as interference).
    total, count = 0.0, 0
    for d in Path("/proc").iterdir():
        if d.name.isdigit() and int(d.name) not in seen:
            v = pss_mib(int(d.name))
            if v is not None:
                total, count = total + v, count + 1
    out["external"] = {"pss_mib": total, "procs": count, "vanished": 0}
    return out


class Sampler(threading.Thread):
    def __init__(self, out: Path, interval: float) -> None:
        super().__init__(daemon=True)
        self.out, self.interval = out, interval
        self.groups: dict[str, list[str]] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.errors = 0

    def set_groups(self, groups: dict[str, list[str]]) -> None:
        with self.lock:
            self.groups = {k: list(v) for k, v in groups.items()}

    def run(self) -> None:
        next_tick = time.monotonic()
        with open(self.out, "a", encoding="utf-8") as fh:
            while not self.stop_event.is_set():
                next_tick += self.interval
                try:
                    with self.lock:
                        groups = dict(self.groups)
                    row = {"t": time.time(), "mono": time.monotonic(), **meminfo(), "groups": group_reading(groups)}
                    fh.write(json.dumps(row) + "\n")
                    fh.flush()
                except Exception as exc:  # keep sampling; the driver checks window coverage
                    self.errors += 1
                    fh.write(json.dumps({"t": time.time(), "error": f"{type(exc).__name__}: {exc}"}) + "\n")
                    fh.flush()
                self.stop_event.wait(max(0.0, next_tick - time.monotonic()))


def uid_procs(uids: list[int]) -> list[dict]:
    """Every process whose real uid is in uids: pid, uid, comm and argv (for the engine's rows; protocol.md 1)."""
    want, out = set(uids), []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            uid = int(next(ln.split()[1] for ln in (d / "status").read_text().splitlines() if ln.startswith("Uid:")))
            if uid not in want:
                continue
            out.append({"pid": int(d.name), "uid": uid, "comm": (d / "comm").read_text().strip(),
                        "argv": [a.decode("utf-8", "replace") for a in (d / "cmdline").read_bytes().split(b"\0")[:-1]]})
        except (OSError, StopIteration, ValueError):
            continue
    return out


def row_role(p: dict, uid: int, execution: str, name_of: dict[int, str]) -> str | None:
    """Which part of the engine row (uid, execution) process p is: "cell" (its real uid is the row's uid), the name
    of a row process outside the cell (its dedicated uid in name_of, argv ending in "<uid> <execution>": spawner.c
    start_row_process), or None."""
    if p["uid"] == uid:
        return "cell"
    name = name_of.get(p["uid"])
    return name if name is not None and p["argv"][-2:] == [str(uid), execution] else None


def adopt(cgroup: str, uid: int, execution: str, row_uids: dict[str, int]) -> dict:
    """Move one engine row's processes into cgroup: the cell and the row's processes outside it, each at its
    dedicated uid in row_uids (name -> uid: the connector, the file worker). The engine makes no cgroups (protocol.md
    1), so this is the measurement's own placement. Returns what was moved and what is there."""
    moved, cell = 0, []
    outside = {name: 0 for name in row_uids}
    name_of = {v: k for k, v in row_uids.items()}
    procs = Path(cgroup) / "cgroup.procs"
    here = {int(x) for x in procs.read_text().split()}
    for p in uid_procs([uid, *row_uids.values()]):
        role = row_role(p, uid, execution, name_of)
        if role is None:
            continue
        if p["pid"] not in here:
            try:
                procs.write_text(str(p["pid"]))
                moved += 1
            except OSError:
                continue  # exited between the scan and the move
        if role == "cell":
            cell.append(p["comm"])
        else:
            outside[role] += 1
    return {"moved": moved, "cell": sorted(cell), "outside": outside}


def live_cgroup(pid: int) -> str | None:
    """The cgroup v2 path of a live process (as /proc/<pid>/cgroup gives it, e.g. /sotamem/units/u1); None for a
    zombie or a process that is gone."""
    try:
        state = next(ln.split()[1] for ln in Path(f"/proc/{pid}/status").read_text().splitlines()
                     if ln.startswith("State:"))
        cgroup = Path(f"/proc/{pid}/cgroup").read_text().strip().split("::", 1)[-1]
    except (OSError, StopIteration):
        return None
    return None if state == "Z" else cgroup


def row_census(rows: list[dict], row_uids: dict[str, int]) -> list[dict]:
    """Read-only, one scan of /proc for all rows: for each engine row {cgroup, uid, execution}, the comms of its live
    cell processes, the count of each row process outside the cell, and how many of all these sit in another cgroup.
    Each process's own /proc/<pid>/cgroup is read: a process that exited since the scan, or a zombie waiting for its
    parent (a short-lived child of Claude Code), is no part of the row and not counted at all."""
    name_of = {v: k for k, v in row_uids.items()}
    procs = uid_procs([*{r["uid"] for r in rows}, *row_uids.values()])
    out = []
    for r in rows:
        unit = r["cgroup"][len(CG_ROOT_TEXT):] if r["cgroup"].startswith(CG_ROOT_TEXT + "/") else r["cgroup"]
        cell, outside, elsewhere = [], {name: 0 for name in row_uids}, 0
        for p in procs:
            role = row_role(p, r["uid"], r["execution"], name_of)
            if role is None or (where := live_cgroup(p["pid"])) is None:
                continue
            elsewhere += where != unit
            if role == "cell":
                cell.append(p["comm"])
            else:
                outside[role] += 1
        out.append({"cell": sorted(cell), "outside": outside, "elsewhere": elsewhere})
    return out


def make_cgroup(rel: str, cpu_max: str | None, mem_max: str | None) -> str:
    """Create BASE/rel (parents enable the cpu and memory controllers) and set limits; returns the path."""
    path = BASE / rel
    for parent in [CG_ROOT, *reversed([p for p in path.parents if str(p).startswith(str(BASE))])]:
        parent.mkdir(exist_ok=True)
        ctl = parent / "cgroup.subtree_control"
        if parent != path and ctl.exists():
            enabled = ctl.read_text().split()
            for c in ("cpu", "memory"):
                if c not in enabled:
                    ctl.write_text(f"+{c}")
    path.mkdir(exist_ok=True)
    if cpu_max:
        (path / "cpu.max").write_text(cpu_max)
    if mem_max:
        (path / "memory.max").write_text(mem_max)
    return str(path)


def kill_cgroup(path: str, timeout: float = 30.0) -> dict:
    """cgroup.kill the subtree, wait until it is empty, remove the directories (deepest first)."""
    p = Path(path)
    if not p.is_dir():
        return {"removed": True, "remaining": 0}
    (p / "cgroup.kill").write_text("1")
    deadline = time.monotonic() + timeout
    while cgroup_pids(p) and time.monotonic() < deadline:
        time.sleep(0.2)
    remaining = len(cgroup_pids(p))
    if remaining == 0:
        for root, dirs, _files in sorted(os.walk(p), key=lambda x: -len(x[0])):
            try:
                os.rmdir(root)
            except OSError:
                pass
    return {"removed": not p.exists(), "remaining": remaining}


class Agent:
    def __init__(self, run_dir: Path, interval: float) -> None:
        self.sampler = Sampler(run_dir / "host-samples.jsonl", interval)
        self.children: dict[int, tuple[subprocess.Popen, subprocess.Popen]] = {}
        self.cgroup_of: dict[int, str] = {}

    def spawn(self, cgroup: str, argv: list[str], cwd: str, env: dict[str, str], log: str,
              pty: bool) -> dict:
        """Start argv inside cgroup with stdin held open by a `sleep infinity` pipe. The holder stays outside the
        unit's cgroup: it is a measurement facility, as in the nono and Connection Escrow setup scripts. With pty,
        argv runs under `script -qfc` so it gets a terminal; the screen goes to log."""
        procs_file = str(Path(cgroup) / "cgroup.procs")
        enter = ["sh", "-c", 'echo $$ > "$0" && exec "$@"', procs_file]
        holder = subprocess.Popen(["sleep", "infinity"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        if pty:
            command = " ".join(_quote(a) for a in argv)
            target = ["script", "-qfc", command, log]
            out = subprocess.DEVNULL
        else:
            target = argv
            out = open(log, "ab")
        proc = subprocess.Popen(enter + target, cwd=cwd, env=env, stdin=holder.stdout, stdout=out,
                                stderr=subprocess.STDOUT, start_new_session=True)
        holder.stdout.close()  # the child holds the read end now
        self.children[proc.pid] = (proc, holder)
        self.cgroup_of[proc.pid] = cgroup
        return {"pid": proc.pid, "holder": holder.pid}

    def release_under(self, path: str) -> int:
        """End the stdin holders (and forget the children) of every unit spawned under cgroup path."""
        released = 0
        for pid, cg in list(self.cgroup_of.items()):
            if cg == path or cg.startswith(path.rstrip("/") + "/"):
                proc, holder = self.children.pop(pid)
                del self.cgroup_of[pid]
                for p in (holder, proc):
                    if p.poll() is None:
                        try:
                            os.killpg(p.pid, signal.SIGKILL)
                        except OSError:
                            pass
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                released += 1
        return released

    def alive(self, pids: list[int]) -> dict:
        return {str(p): (p in self.children and self.children[p][0].poll() is None) for p in pids}

    def handle(self, cmd: dict) -> dict:
        op = cmd["op"]
        if op == "ping":
            return {"ok": True, "t": time.time(), "mono": time.monotonic()}
        if op == "meminfo":
            return meminfo()
        if op == "drop_caches":  # the recovery step that replaces the WSL restart on the server (protocol.md 3.1)
            os.sync()
            Path("/proc/sys/vm/drop_caches").write_text("3")
            return {"ok": True}
        if op == "groups":
            self.sampler.set_groups(cmd["groups"])
            return {"ok": True}
        if op == "reading":
            return {"t": time.time(), **meminfo(), "groups": group_reading(cmd["groups"])}
        if op == "mkcg":
            return {"path": make_cgroup(cmd["rel"], cmd.get("cpu_max"), cmd.get("mem_max"))}
        if op == "killcg":
            result = kill_cgroup(cmd["path"], cmd.get("timeout", 30.0))
            result["holders_released"] = self.release_under(cmd["path"])
            return result
        if op == "pids":
            return {"pids": spec_pids(cmd["path"])}
        if op == "spawn":
            return self.spawn(cmd["cgroup"], cmd["argv"], cmd["cwd"], cmd["env"], cmd["log"], cmd.get("pty", False))
        if op == "alive":
            return self.alive(cmd["pids"])
        if op == "uidprocs":
            return {"procs": uid_procs(cmd["uids"])}
        if op == "adopt":
            return adopt(cmd["cgroup"], cmd["uid"], cmd["execution"], cmd["row_uids"])
        if op == "rowcensus":
            return {"rows": row_census(cmd["rows"], cmd["row_uids"])}
        if op == "exec":
            # Output goes to a temporary file, not a pipe: setup scripts leave background processes (stdin
            # holders, units) that inherit the output descriptors, and a pipe would then never reach EOF.
            with tempfile.TemporaryFile() as out:
                r = subprocess.run(cmd["argv"], stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   timeout=cmd.get("timeout", 600), env=cmd.get("env"), cwd=cmd.get("cwd"))
                out.seek(0)
                text = out.read().decode("utf-8", "replace")
            return {"rc": r.returncode, "stdout": text[-4000:], "stderr": ""}
        if op == "write":
            Path(cmd["path"]).parent.mkdir(parents=True, exist_ok=True)
            Path(cmd["path"]).write_text(cmd["text"], encoding="utf-8")
            if "mode" in cmd:
                os.chmod(cmd["path"], int(cmd["mode"], 8))
            return {"ok": True}
        raise ValueError(f"unknown op {op!r}")

    def serve(self) -> None:
        BASE.mkdir(exist_ok=True)
        harness = make_cgroup("harness", None, None)
        for pid in (os.getpid(), os.getppid()):
            try:
                Path(harness, "cgroup.procs").write_text(str(pid))
            except OSError:
                pass  # the driver may not be root-movable (e.g. started outside); recorded as "other" then
        self.sampler.start()
        print(json.dumps({"ready": True, "pid": os.getpid()}), flush=True)
        for line in sys.stdin:
            if not line.strip():
                continue
            cmd: dict = {}
            try:
                cmd = json.loads(line)
                reply = {"id": cmd.get("id"), "ok": True, "result": self.handle(cmd)}
            except Exception as exc:
                reply = {"id": cmd.get("id"), "ok": False, "error": f"{type(exc).__name__}: {exc}"}
            print(json.dumps(reply), flush=True)
        self.sampler.stop_event.set()
        for proc, holder in self.children.values():
            for p in (proc, holder):
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except OSError:
                        pass


def _quote(arg: str) -> str:
    return "'" + arg.replace("'", "'\\''") + "'"


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "serve":
        sys.exit("usage: agent.py serve <run_dir> <interval_s>")
    Agent(Path(sys.argv[2]), float(sys.argv[3])).serve()
