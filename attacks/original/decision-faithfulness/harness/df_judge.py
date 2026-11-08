"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Judging (tests.md 1.3, 1.4). Success is read only from external facts: the upstream's and the decoys' records, the
test DNS's record, the bytes the runner received (DF-12, DF-18), the table mirror (DF-16). The mechanism is read from
the reason word the runner received, E-09 and the connector's own log; a mechanism other than the expected one makes
the attempt invalid until checked (METHOD rule 4). A broken validity premise makes it invalid, never blocked.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from df_common import nonce_of


@dataclass
class Facts:
    """Everything read for one attempt, taken after the row closed or the runner exited."""
    config: str
    nonce: str
    obs: dict                                   # role -> runner observation ('' is the default role)
    upstream: list = field(default_factory=list)    # upstream records of this attempt (request, block, connect)
    decoys: list = field(default_factory=list)      # decoy records of this attempt
    dns: list = field(default_factory=list)         # DNS records of this attempt's epoch
    events: list = field(default_factory=list)      # E-09 records appended during the attempt
    connector: list = field(default_factory=list)   # connector log lines of this attempt's rows
    questions: list = field(default_factory=list)   # approval-window events during the attempt
    pdp: list = field(default_factory=list)         # PDP stand-in events during the attempt
    notes: dict = field(default_factory=dict)       # what the controller's driver did and saw
    executions: list = field(default_factory=list)
    window: tuple = ()                          # (start, end) wall clock of this attempt alone, no margin


def verdict(outcome: str, mechanism: str = "", *, mismatch: bool = False, why: str = "", fact=None,
            control: str = "") -> dict:
    return {"outcome": outcome, "observed_mechanism": mechanism, "mismatch": mismatch, "invalid_reason": why,
            "external_fact": fact, "control": control}


# ---- the runner's side ------------------------------------------------------------------------------------------------
def step(f: Facts, name: str, role: str = "") -> dict | None:
    obs = f.obs.get(role) or {}
    return next((s for s in obs.get("steps", []) if s.get("step") == name), None)


def result(f: Facts, name: str, role: str = "") -> dict:
    s = step(f, name, role)
    return (s or {}).get("result") or {}


def remote_ok(r: dict) -> bool:
    return r.get("category") == "remote" and isinstance(r.get("status"), int) and 200 <= r["status"] < 300 \
        and bool(r.get("ended"))


def refused(r: dict, word: str) -> bool:
    return r.get("category") == "refused" and r.get("reason") == word


CONTROLLER_PROBLEMS = ("controller_error", "attempt_timeout", "row_start_failed", "driver_error", "driver_timeout",
                       "setup_failed")


def runner_problem(f: Facts, roles=("",)) -> str:
    """Why the attempt cannot be judged at all: the controller's side failed, or a runner record is missing."""
    for key in CONTROLLER_PROBLEMS:
        if f.notes.get(key):
            return f"{key}: {str(f.notes[key])[:300]}"
    for role in roles:
        obs = f.obs.get(role)
        if not obs:
            return f"runner observation missing ({role or 'default'})"
        if not obs.get("completed"):
            return f"runner did not complete: {obs.get('error', '?')}"
    return ""


# ---- external facts ---------------------------------------------------------------------------------------------------
def arrivals(f: Facts, tag: str, *, listener: str | None = None) -> list[dict]:
    return [r for r in f.upstream if r.get("kind") == "request" and r.get("nonce") == f.nonce
            and r.get("tag") == tag and (listener is None or r.get("listener") == listener)]


def decoy_hits(f: Facts, tag: str | None = None) -> list[dict]:
    """Decoy records of this attempt that carry its nonce (and the tag): a request the decoy read."""
    return [r for r in f.decoys if r.get("nonce") == f.nonce and (tag is None or r.get("tag") == tag)]


# the private decoy's two listeners (df_net.listeners: PRIVATE_IP, plain and TLS); tests.md 2.7 DF-09 succeeds on a connection
PRIVATE_DECOYS = ("decoy-private", "decoy-private-tls")


IP_CLOSED = "IP literal refused at validation (条款 7)"


def in_window(f: Facts, r: dict, since: float | None = None) -> bool:
    """Inside this attempt's own window (no margin: attempts run one at a time and each ends after its rows closed or
    its process exited) and not before ``since``. Without a window nothing is inside: evidence that cannot be placed in
    the attempt establishes nothing."""
    if len(f.window) != 2:
        return False
    start, end = f.window
    return max(start, start if since is None else since) <= r.get("t", 0) <= end


def connections(f: Facts, listeners: tuple[str, ...], tag: str, since: float | None = None) -> list[dict]:
    """Connections the named listeners accepted inside the window and not before ``since``, whether or not any byte
    followed (TLS may fail first), that no read ties to anything but ``tag`` of this attempt: a read on the same
    connection of another attempt's nonce, or of another step of this attempt (the control, tag c), excludes it."""
    other = {r.get("conn") for r in f.decoys if r.get("kind") == "decoy" and r.get("nonce") is not None
             and (r.get("nonce"), r.get("tag")) != (f.nonce, tag)}
    return [r for r in f.decoys if r.get("kind") == "connect" and r.get("listener") in listeners
            and in_window(f, r, since) and r.get("conn") not in other]


def private_reached(tag: str, step_name: str = "attack"):
    """tests.md 2.7: the private decoy received a connection of this attempt's attack step: a read of its request on a
    private listener inside the window, or a connection a private listener accepted inside the window, at or after the
    step was sent, that nothing ties to another step or attempt. A missing window or send time establishes nothing."""
    def check(f: Facts):
        sent = (step(f, step_name) or {}).get("sent_at")
        reads = [r for r in decoy_hits(f, tag) if r.get("listener") in PRIVATE_DECOYS and in_window(f, r)]
        conns = connections(f, PRIVATE_DECOYS, tag, sent) if isinstance(sent, (int, float)) else []
        return bool(reads or conns), {"decoy_hits": [{"listener": h["listener"], "conn": h["conn"]} for h in reads],
                                      "private_connections": [{"listener": c["listener"], "conn": c["conn"],
                                                               "t": c.get("t")} for c in conns]}
    return check


def decoy_connections(f: Facts) -> list[dict]:
    """Every connection a decoy accepted in this attempt's window (without a window, every one collected): any of them
    contradicts a refusal the spec places before any connection is made (R4 of the v4 recheck)."""
    connects = [r for r in f.decoys if r.get("kind") == "connect" and str(r.get("listener", "")).startswith("decoy")]
    return [r for r in connects if in_window(f, r)] if len(f.window) == 2 else connects


def literal_refusal(tag: str = "a", step_name: str = "attack"):
    """Clause 7 gate one at validation (connector/session.py Policy.never_connect): never admitted, nothing connected."""
    def check(f: Facts):
        r = result(f, step_name)
        none_admitted = not admitted(f, tag)
        closed = connector_has(f, "connection_closed", reason=IP_CLOSED)
        conns = len(decoy_connections(f))
        return (refused(r, "clause") and none_admitted and closed and not conns,
                f"reason={r.get('reason')} admitted={not none_admitted} connector_closed={closed} decoy_conns={conns}")
    return check


def not_named_refusal(tag: str = "a", step_name: str = "attack"):
    """K-58: admitted, refused at the first checkpoint (not_authorized, address_not_named), not at validation; nothing
    connected."""
    def check(f: Facts):
        r = result(f, step_name)
        codes = sorted({d.get("reason_code") for d in decided(f, tag, "deny")})
        at_validation = connector_has(f, "connection_closed", reason=IP_CLOSED)
        conns = len(decoy_connections(f))
        return (refused(r, "not_authorized") and bool(admitted(f, tag)) and "address_not_named" in codes
                and not at_validation and not conns,
                f"reason={r.get('reason')} decided={codes} closed_at_validation={at_validation} decoy_conns={conns}")
    return check


def blocks(f: Facts) -> list[dict]:
    return [r for r in f.upstream if r.get("kind") == "block" and r.get("nonce") == f.nonce]


def header(record: dict, name: str) -> list[str]:
    return [v for k, v in record.get("headers", []) if k.lower() == name]


# ---- E-09 -------------------------------------------------------------------------------------------------------------
def owner(e: dict) -> str | None:
    return (e.get("control_binding") or {}).get("execution_id")


def records(f: Facts, kind: str, **match) -> list[dict]:
    out = []
    for e in f.events:
        if e.get("kind") != kind:
            continue
        d = e.get("detail") or {}
        if all(d.get(k) == v for k, v in match.items()):
            out.append(e)
    return out


def seq_of(e: dict) -> int:
    return int(e.get("producer_seq", 0))


def admitted(f: Facts, tag: str) -> list[dict]:
    want = f"n={f.nonce}-{tag}"
    return [e for e in records(f, "request_admitted") if want in ((e.get("detail") or {}).get("query") or "")]


def decisions(f: Facts, tag: str) -> list[dict]:
    """request_decided records of every admission carrying this tag (paired by execution and connector seq)."""
    keys = {(owner(a), a["detail"]["seq"]) for a in admitted(f, tag)}
    return [e for e in records(f, "request_decided") if (owner(e), (e.get("detail") or {}).get("seq")) in keys]


def decided(f: Facts, tag: str, outcome: str) -> list[dict]:
    return [e for e in decisions(f, tag) if e.get("outcome") == outcome]


def withdrawn(f: Facts, tag: str) -> list[dict]:
    keys = {(owner(a), a["detail"]["seq"]) for a in admitted(f, tag)}
    return [e for e in records(f, "request_withdrawn") if (owner(e), (e.get("detail") or {}).get("seq")) in keys]


def connector_has(f: Facts, event: str, **match) -> bool:
    return any(line.get("event") == event and all(line.get(k) == v for k, v in match.items())
               for line in f.connector)


# ---- the batch-level trace judgement (tests.md 1.3) -------------------------------------------------------------------
def trace_check(engine_attempts: list[dict], upstream: list[dict], decoys: list[dict], events: list[dict]) -> dict:
    """Every effect inside an engine attempt's window is matched to an allow record of its own, decided for a row of
    that attempt no later than 1 s after it, and each allow pays for one effect only. A request (an upstream request, a
    decoy read carrying a nonce or bytes) needs an allow of the same nonce and step tag. A decoy connection that no
    read inside the window accounts for (connect only, a TLS failure, a zero-byte read, a read after the window) needs
    an allow of the attempt's nonce, any tag. Requests are matched first, latest first, each to the latest eligible
    allow of its tag, so the earliest allows stay for connections, each of which takes the earliest one left.
    engine_attempts: {nonce, executions, start, end} with wall-clock bounds."""
    admitted_at: dict[tuple, str] = {}
    for e in events:
        d = e.get("detail") or {}
        if e.get("kind") == "request_admitted":
            admitted_at[(owner(e), d.get("seq"))] = d.get("query") or ""
    allow_list: list[tuple] = []                # (execution, nonce, tag, time) of every allow
    for e in events:
        d = e.get("detail") or {}
        if e.get("kind") == "request_decided" and e.get("outcome") == "allow":
            found = nonce_of(admitted_at.get((owner(e), d.get("seq"))))
            if found:
                allow_list.append((owner(e), *found, float(e.get("wall_time", 0)) / 1e9))
    problems, checked = [], 0
    for attempt in engine_attempts:
        inside = lambda r: attempt["start"] <= r.get("t", 0) <= attempt["end"]  # noqa: E731
        # requests only from the upstream's records, decoy reads only from the decoys': the caller may pass one log
        # in both lists, and an arrival must not be counted twice (S1, 2026-11-05)
        reads = [r for r in decoys if r.get("kind") == "decoy" and (r.get("nonce") or r.get("bytes", 1)) and inside(r)]
        requests = [r for r in upstream if r.get("kind") == "request" and inside(r)] + reads
        accounted = {r.get("conn") for r in reads}           # only a read checked here stands in for its connection
        bare = [r for r in decoys if r.get("kind") == "connect" and str(r.get("listener", "")).startswith("decoy")
                and r.get("conn") not in accounted and inside(r)]
        pool = [[t, tag, False] for ex, nonce, tag, t in allow_list
                if nonce == attempt["nonce"] and ex in attempt["executions"]]
        for r in sorted(requests, key=lambda r: r.get("t", 0), reverse=True):
            checked += 1
            if r.get("nonce") != attempt["nonce"]:
                problems.append({"record": r, "why": "effect without this attempt's nonce during an engine attempt"})
                continue
            eligible = [a for a in pool if not a[2] and a[1] == r.get("tag") and a[0] <= r.get("t", 0) + 1.0]
            if not eligible:
                problems.append({"record": r, "why": "request without an unused allow of the same request before it "
                                                     "(1 s clock margin)"})
                continue
            max(eligible, key=lambda a: a[0])[2] = True
        for r in sorted(bare, key=lambda r: r.get("t", 0)):
            checked += 1
            eligible = [a for a in pool if not a[2] and a[0] <= r.get("t", 0) + 1.0]
            if not eligible:
                problems.append({"record": r, "why": "decoy connection without a request and without an unused "
                                                     "allow of this attempt before it"})
                continue
            min(eligible, key=lambda a: a[0])[2] = True
    return {"ok": not problems, "checked": checked, "problems": problems[:50]}
