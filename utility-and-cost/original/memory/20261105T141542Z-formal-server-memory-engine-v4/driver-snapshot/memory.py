"""The memory column for one object in one pass, on the Linux measurement server (protocol.md 3.1, 4, 5; the
idle and resident states only).

Per object pass: baseline 1 (object not started), start shared parts, baseline 2, then for each tier (ascending) and
repetition: pre-build check against baseline 2, build N units, read "idle", switch to "resident", read, record the
units' prompt evidence, destroy. Then stop shared parts and check the host is back at baseline 1. Cleanup always
runs. Every reading is one JSON record. All host readings come from the agent's 1 Hz samples (agent.py).
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import client, objects

CGBASE = "/sys/fs/cgroup/sotamem"


class StopRun(Exception):
    """A stop line was crossed or a state could not be read; the current tier is abandoned."""


class StopNight(Exception):
    """Cleanup could not restore the baseline; later objects would be contaminated (protocol.md 5)."""


@dataclass(frozen=True)
class Timing:
    interval: float = 1.0
    baseline_window: float = 15
    min_settle: dict = field(default_factory=lambda: {"idle": 15, "resident": 150})
    max_settle: float = 180
    stable_window: float = 10
    stable_mib: float = 20
    stable_mib_per_unit: float = 5
    window: float = 10
    tolerance_mib: float = 300
    recovery_wait: float = 20
    cleanup_wait: float = 180
    min_coverage: float = 0.8


@dataclass(frozen=True)
class Limits:
    min_available_mib: float = 3072
    max_used_ratio: float = 0.90
    min_disk_free_gib: float = 5.0
    interference_mib: float = 300
    projection_factor: float = 1.25


def host_breach(row: dict | None, limits: Limits) -> str:
    """First violated stop line for one host sample, or '' (protocol.md 4, adapted to the server)."""
    if row is None:
        return ""
    if row["MemAvailable"] < limits.min_available_mib:
        return f"available {row['MemAvailable']:.0f} MiB < {limits.min_available_mib:.0f}"
    if row["used_mib"] / row["MemTotal"] > limits.max_used_ratio:
        return f"used {row['used_mib'] / row['MemTotal']:.2f} of total > {limits.max_used_ratio}"
    if row["swap_used_mib"] > 0:
        return f"swap in use ({row['swap_used_mib']:.0f} MiB)"
    if row["disk_free_gib"] < limits.min_disk_free_gib:
        return f"disk free {row['disk_free_gib']:.1f} GiB < {limits.min_disk_free_gib}"
    return ""


class Watch(threading.Thread):
    """Judges the stop lines once per second on the newest sample and latches the first breach."""

    def __init__(self, ctx: "Ctx") -> None:
        super().__init__(daemon=True)
        self.ctx = ctx
        self.breach, self.breach_event = "", threading.Event()
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.wait(self.ctx.timing.interval):
            agent = self.ctx.agent
            reason = host_breach(agent.latest() if agent else None, self.ctx.limits)
            if reason and not self.breach:
                self.breach = reason
                self.breach_event.set()

    def reset_breach(self) -> None:
        self.breach = ""
        self.breach_event.clear()

    def stop(self) -> None:
        self._stop.set()


@dataclass
class Ctx:
    run_dir: Path
    timing: Timing
    limits: Limits
    agent: client.Agent | None = None
    watch: Watch | None = None

    def log(self, kind: str, **fields) -> None:
        _append(self.run_dir / "events.jsonl", {"t": time.time(), "event": kind, **fields})

    def record(self, kind: str, **fields) -> dict:
        rec = {"t": time.time(), "kind": kind, **fields}
        _append(self.run_dir / "memory-records.jsonl", rec)
        return rec


def _append(path: Path, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj) + "\n")


def _wait(ctx: Ctx, seconds: float) -> None:
    if ctx.watch.breach_event.wait(seconds):
        raise StopRun(f"limit: {ctx.watch.breach}")


def other_mib(row: dict) -> float:
    """The "external" reading: PSS of every process outside the measured groups (unit, shared, harness). Not host
    used memory minus the groups' PSS: PSS also counts reclaimable file pages that used memory leaves out (a VMM's
    mapped images, seen 2026-10-30), and that gap is not an external process."""
    return row["groups"]["external"]["pss_mib"]


def _mean(rows: list[dict]) -> dict:
    keys = ("MemTotal", "MemAvailable", "used_mib", "swap_used_mib", "Cached", "Committed_AS", "disk_free_gib")
    out = {k: sum(r[k] for r in rows) / len(rows) for k in keys}
    names = set().union(*(r["groups"].keys() for r in rows))
    out["groups"] = {g: {k: sum(r["groups"].get(g, {}).get(k, 0) for r in rows) / len(rows)
                         for k in ("pss_mib", "procs", "vanished")} for g in names}
    out["other_mib"] = sum(other_mib(r) for r in rows) / len(rows)
    return out


def reading(ctx: Ctx, seconds: float) -> dict:
    """Read `seconds` of host samples; raises StopRun if the agent covered too little of the window."""
    t0 = time.time()
    _wait(ctx, seconds)
    t1 = time.time()
    rows = ctx.agent.window(t0, t1)
    need = max(1, int(ctx.timing.min_coverage * seconds / ctx.timing.interval))
    if len(rows) < need:
        raise StopRun(f"coverage: {len(rows)} samples < {need}")
    return {"t0": t0, "t1": t1, "host": _mean(rows), "first": rows[0], "last": rows[-1], "_rows": rows}


def _strip(r: dict) -> dict:
    """A reading as recorded: the raw rows stay in the sample file, not in every record."""
    return {k: v for k, v in r.items() if not k.startswith("_")}


def settle(ctx: Ctx, state: str, n: int) -> tuple[float, bool]:
    """Wait at least min_settle, then until host used memory varied by less than the threshold over the last
    stable_window seconds (at most max_settle)."""
    t, start = ctx.timing, time.time()
    threshold = max(t.stable_mib, t.stable_mib_per_unit * n)
    while True:
        elapsed = time.time() - start
        if elapsed >= t.min_settle[state]:
            now = time.time()
            rows = ctx.agent.window(now - t.stable_window, now)
            if len(rows) >= 2:
                vals = [r["used_mib"] for r in rows]
                if max(vals) - min(vals) < threshold:
                    return elapsed, False
            if elapsed >= t.max_settle:
                return elapsed, True
        _wait(ctx, 1.0)


def read_state(ctx: Ctx, obj, state: str, n: int, base: dict) -> dict:
    settle_s, timed_out = settle(ctx, state, n)
    dead = obj.alive()
    if dead:
        raise StopRun(f"{state}: units exited early: {dead}")
    r = reading(ctx, ctx.timing.window)
    dead = obj.alive()
    if dead:
        raise StopRun(f"{state}: units exited during the window: {dead}")
    rows = r["_rows"]
    vals = [row["used_mib"] for row in rows]
    threshold = max(ctx.timing.stable_mib, ctx.timing.stable_mib_per_unit * n)
    others = [other_mib(row) for row in rows]
    other_drift = others[-1] - others[0]
    other_vs_base = r["host"]["other_mib"] - base["host"]["other_mib"]
    object_interference = obj.interference()
    interfered = max(abs(other_drift), abs(other_vs_base)) > ctx.limits.interference_mib or bool(object_interference)
    # A window in which some unit process's PSS could not be read gives no usable non-shared value
    # (protocol.md 2.5): flagged, kept out of the clean results.
    pss_incomplete = any(row["groups"].get("unit", {}).get("vanished", 0)
                         or row["groups"].get("unit", {}).get("procs", 0) == 0 for row in rows)
    return {"state": state, "n": n, "settle_s": settle_s, "settle_timed_out": timed_out,
            "unstable": (max(vals) - min(vals)) > threshold, "stable_range_mib": max(vals) - min(vals),
            "other_drift_mib": other_drift, "other_vs_base_mib": other_vs_base, "interfered": interfered,
            **({"object_interference": object_interference} if object_interference else {}),
            "pss_incomplete": pss_incomplete, **_strip(r)}


def within(r: dict, ref: dict, tol: float) -> list[str]:
    """Which of host used / available differ from ref by more than tol, either way (empty = recovered)."""
    out = []
    if abs(r["host"]["used_mib"] - ref["host"]["used_mib"]) > tol:
        out.append("used")
    if abs(r["host"]["MemAvailable"] - ref["host"]["MemAvailable"]) > tol:
        out.append("available")
    return out


def project(points: list[tuple[int, float]], n: int, factor: float) -> float:
    """Straight-line extrapolation of a cost to n units through the per-tier means of the measured points (the
    repetitions of one tier are one point), times factor."""
    by_n: dict[int, list[float]] = {}
    for m, v in points:
        by_n.setdefault(m, []).append(v)
    points = [(m, sum(vs) / len(vs)) for m, vs in sorted(by_n.items())]
    if not points:
        return 0.0
    if len(points) == 1:
        n0, v0 = points[0]
        return v0 / n0 * n * factor
    (n1, v1), (n2, v2) = points[-2], points[-1]
    slope = (v2 - v1) / (n2 - n1) if n2 != n1 else v2 / n2
    return (v2 + slope * (n - n2)) * factor


class ObjectPass:
    def __init__(self, ctx: Ctx, obj, tiers: list[int], reps: int, pass_no: int, time_cap_s: float) -> None:
        self.ctx, self.obj, self.tiers, self.reps, self.pass_no = ctx, obj, tiers, reps, pass_no
        obj.run_dir = ctx.run_dir
        obj.stop_event = ctx.watch.breach_event if ctx.watch else None   # adapters that wait end their waits on it
        self.deadline = time.monotonic() + time_cap_s
        self.b1 = self.b2 = None
        self.missed = 0

    def _rec(self, kind: str, **fields) -> dict:
        if isinstance(fields.get("reading"), dict):
            fields["reading"] = _strip(fields["reading"])
        return self.ctx.record(kind, object=self.obj.name, pass_no=self.pass_no, **fields)

    def _groups(self) -> dict[str, list[str]]:
        return {**self.obj.groups(), "harness": objects.HARNESS}

    def _poll(self, ref: dict, wait: float, cleanup: bool) -> tuple[dict, list[str], list[str]]:
        """5 s readings until recovered against ref or `wait` has passed; returns (reading, raw off, judged off)."""
        deadline = time.monotonic() + wait
        while True:
            r = reading(self.ctx, 5)
            raw, off = self._cleanup_off(r) if cleanup else ((x := within(r, ref, self.ctx.timing.tolerance_mib)), x)
            if not off or time.monotonic() >= deadline:
                return r, raw, off

    def _prebuild(self) -> dict | None:
        """Back at baseline 2 before building? If not within recovery_wait: drop the page cache and look again; still
        off means this tier is missing (protocol.md 3.1; baselines are never re-read in place of recovery)."""
        t = self.ctx.timing
        r, _, off = self._poll(self.b2, t.recovery_wait, cleanup=False)
        if not off:
            return r
        self.ctx.log("prebuild_not_recovered", object=self.obj.name, off=off)
        self.ctx.agent.call("drop_caches")
        r, _, off = self._poll(self.b2, 10, cleanup=False)
        return None if off else {**r, "after_drop_caches": True}

    def run(self) -> dict:
        """The whole pass; cleanup and the cleanup check always run (protocol.md 5), whatever failed before."""
        ctx, obj, t = self.ctx, self.obj, self.ctx.timing
        measured: list[tuple[int, dict]] = []
        stop_reason, error = "", ""
        try:
            ctx.watch.reset_breach()
            ctx.agent.call("groups", groups=self._groups())
            obj.prepare()
            _wait(ctx, t.min_settle["idle"])
            self.b1 = reading(ctx, t.baseline_window)
            self._rec("baseline1", reading=self.b1)
            obj.start_shared()
            _wait(ctx, t.min_settle["idle"])
            self.b2 = reading(ctx, t.baseline_window)
            self._rec("baseline2", reading=self.b2)
            for n in self.tiers:
                if self._projected_breach(measured, n):
                    self._rec("tier_skipped", n=n, reason="projection")
                    break
                for rep in range(1, self.reps + 1):
                    if time.monotonic() > self.deadline:
                        self._rec("tier_missing", n=n, rep=rep, reason="object time cap")
                        stop_reason = "time cap"
                        break
                    res = self._rep(n, rep)
                    if res.get("stop"):
                        stop_reason = res["stop"]
                        break
                    if res.get("resident"):
                        measured.append((n, res["resident"]))
                if stop_reason:
                    break
        except StopRun as exc:   # a stop line crossed before the tiers (e.g. in an object's model check): stop, not error
            stop_reason = str(exc)
            self._rec("pass_stopped", reason=stop_reason)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._rec("pass_error", error=error)
        finally:
            self._cleanup()
        return {"object": obj.name, "pass_no": self.pass_no, "stop_reason": stop_reason, "error": error,
                "tiers_measured": sorted({n for n, _ in measured})}

    def _rep(self, n: int, rep: int) -> dict:
        ctx, obj = self.ctx, self.obj
        for attempt in range(1, 4):
            pre = self._prebuild()
            if pre is None:
                self.missed += 1
                self._rec("tier_missing", n=n, rep=rep, reason="not back at baseline 2 after dropping caches")
                if self.missed >= 2:
                    return {"stop": "baseline not recovered twice"}
                return {}
            self._rec("prebuild", n=n, rep=rep, attempt=attempt, reading=pre)
            states = {}
            try:
                t_build = time.monotonic()
                obj.create_units(n)
                _wait(ctx, 0)  # a stop line crossed while building ends the tier now (latched by the watch)
                obj.set_state("idle")
                _wait(ctx, 0)
                build_s = time.monotonic() - t_build
                states["idle"] = read_state(ctx, obj, "idle", n, self.b2)
                obj.set_state("resident")
                _wait(ctx, 0)
                states["resident"] = read_state(ctx, obj, "resident", n, self.b2)
                try:  # after the window: reading a screen may redraw a terminal
                    prompt = obj.prompt_evidence()
                except Exception as exc:
                    prompt = {"error": f"{type(exc).__name__}: {exc}"}
                states["resident"]["prompt"] = prompt
                states["resident"]["not_at_prompt"] = [u for u, v in prompt.items()
                                                       if isinstance(v, dict) and v.get("at_prompt") is False]
            except StopRun as exc:
                self._rec("rep_stopped", n=n, rep=rep, attempt=attempt, reason=str(exc), states=states,
                          notes=obj.rep_notes())
                return {"stop": str(exc)}
            except Exception as exc:
                self._rec("rep_error", n=n, rep=rep, attempt=attempt, error=f"{type(exc).__name__}: {exc}",
                          notes=obj.rep_notes(),
                          states=states)
                return {"stop": f"error: {exc}"}
            finally:
                try:
                    obj.destroy_units()
                except Exception as exc:
                    ctx.log("destroy_error", object=obj.name, error=f"{type(exc).__name__}: {exc}")
            interfered = any(s["interfered"] for s in states.values())
            notes = obj.rep_notes()
            self._rec("rep", n=n, rep=rep, attempt=attempt, build_s=build_s, interfered=interfered, states=states,
                      **({"notes": notes} if notes else {}))
            if not interfered:
                return states
            ctx.log("rep_interfered", object=obj.name, n=n, rep=rep, attempt=attempt)
        return states  # still interfered after two reruns: kept, marked, analysis puts it in the appendix

    def _projected_breach(self, measured: list[tuple[int, dict]], n: int) -> bool:
        """Units scale from baseline 2 (shared parts already up); the shared parts' fixed cost is not per unit."""
        if not measured:
            return False
        lim, b2 = self.ctx.limits, self.b2["host"]
        used = [(m, s["host"]["used_mib"] - b2["used_mib"]) for m, s in measured]
        avail = [(m, b2["MemAvailable"] - s["host"]["MemAvailable"]) for m, s in measured]
        f = lim.projection_factor
        if b2["MemAvailable"] - project(avail, n, f) < lim.min_available_mib:
            return True
        return (b2["used_mib"] + project(used, n, f)) / b2["MemTotal"] > lim.max_used_ratio

    def _cleanup(self) -> None:
        """Destroy units, stop shared parts, then check against baseline 1. A latched stop line is cleared first,
        so the check's own readings do not abort it. A failed check stops the night."""
        obj = self.obj
        for step, fn in (("destroy_units", obj.destroy_units), ("stop_shared", obj.stop_shared)):
            try:
                fn()
            except Exception as exc:
                self.ctx.log("cleanup_step_error", object=obj.name, step=step, error=f"{type(exc).__name__}: {exc}")
        self.ctx.watch.reset_breach()
        if self.b1 is None:
            residue = obj.residue()
            if residue:
                raise StopNight(f"{obj.name}: residue after a pass that never reached baseline 1: {residue}")
            return
        self._final_check()

    def _cleanup_off(self, r: dict) -> tuple[list[str], list[str]]:
        """(raw, judged): which readings are off baseline 1. The judged comparison first removes the change of the
        external reading since baseline 1 (protocol.md 9, cleanup rule); the raw result is kept too."""
        tol = self.ctx.timing.tolerance_mib
        raw = within(r, self.b1, tol)
        ext = r["host"]["other_mib"] - self.b1["host"]["other_mib"]
        adj = {**r, "host": {**r["host"], "used_mib": r["host"]["used_mib"] - ext,
                              "MemAvailable": r["host"]["MemAvailable"] + ext}}
        return raw, within(adj, self.b1, tol)

    def _final_check(self) -> None:
        r, raw, off = self._poll(self.b1, self.ctx.timing.cleanup_wait, cleanup=True)
        residue = self.obj.residue()
        if not off and not residue:
            self._rec("cleanup_ok", reading=r, raw_off=raw)
            return
        self._rec("cleanup_retry", off=off, raw_off=raw, residue=residue)
        self.ctx.agent.call("drop_caches")
        r, raw, off = self._poll(self.b1, self.ctx.timing.cleanup_wait, cleanup=True)
        residue = self.obj.residue()
        if off or residue:
            self._rec("cleanup_failed", off=off, raw_off=raw, residue=residue, reading=r)
            raise StopNight(f"{self.obj.name}: cleanup did not restore baseline ({off}, {residue})")
        self._rec("cleanup_ok", reading=r, raw_off=raw, after_drop_caches=True)
