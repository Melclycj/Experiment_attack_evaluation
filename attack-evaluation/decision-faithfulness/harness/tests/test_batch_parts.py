"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Registry, pairing and completion, the trace judgement, the self-check variants against the pinned source, the
network's file contents, the test network's handlers (socket pairs, no listener) and the runner's synchronisation.
"""
from __future__ import annotations

import json
import py_compile
import shutil
import socket
import struct
import threading

import pytest

import df_net
import df_record
import df_registry
import df_variants
from df_judge import trace_check
from factory import N


# ---- registry, pairing, completion ----------------------------------------------------------------------------------
def test_registry_counts():
    df_registry.check_registry()


def test_batch_adds_the_controls():
    ids = [c.id for c in df_registry.batch_cases(["DF-12/entry-del", "DF-05/302"])]
    for pc in ("PC-ALLOW", "PC-FALLBACK", "PC-STREAM", "PC-CRED"):
        assert pc in ids
    with pytest.raises(ValueError):
        df_registry.batch_cases(["DF-02/anything"])


def row(subgoal, config, outcome):
    return {"subgoal": subgoal, "config": config, "outcome": outcome, "positive": False}


def test_pairing_rules():
    rows = df_record.pair([row("A", "engine", "blocked"), row("A", "undefended", "succeeded"),
                           row("B", "engine", "blocked"), row("B", "undefended", "invalid"),
                           row("C", "engine", "blocked"), row("C", "undefended", "no_counterpart"),
                           row("D", "engine", "escalated")])
    got = {(r["subgoal"], r["config"]): r["outcome"] for r in rows}
    assert got[("A", "engine")] == "blocked" and got[("B", "engine")] == "invalid"
    assert got[("C", "engine")] == "blocked" and got[("D", "engine")] == "invalid"


def test_completion_and_bound():
    rows = [row("A", "engine", "blocked"), row("A", "undefended", "succeeded"), row("B", "engine", "invalid"),
            row("B", "undefended", "succeeded")]
    done = df_record.completion(rows, [{"outcome": "passed"}], {"ok": True}, True)
    assert done["subgoals"] == 2 and done["subgoals_with_valid_pair"] == 1 and done["positive_controls_passed"]
    assert df_record.upper_bound(1, 0) == 0.975 and df_record.upper_bound(1, 1) is None


# ---- trace judgement ---------------------------------------------------------------------------------------------------
def admitted(tag, seq, ex="ex-1"):
    return {"kind": "request_admitted", "control_binding": {"execution_id": ex},
            "detail": {"seq": seq, "query": f"n={N}-{tag}"}}


def allowed(seq, ex="ex-1"):
    return {"kind": "request_decided", "outcome": "allow", "wall_time": str(100 * 10**9),
            "control_binding": {"execution_id": ex}, "detail": {"seq": seq}}


def arrival(tag, t=100.5, nonce=N):
    return {"kind": "request", "nonce": nonce, "tag": tag, "t": t}


ATTEMPT = [{"nonce": N, "executions": ["ex-1"], "start": 99.0, "end": 102.0}]


def test_trace_ok_and_violations():
    events = [admitted("a", 1), allowed(1)]
    assert trace_check(ATTEMPT, [arrival("a")], [], events)["ok"]
    assert not trace_check(ATTEMPT, [arrival("a"), arrival("a")], [], events)["ok"]      # twice, one allow
    assert not trace_check(ATTEMPT, [arrival("b")], [], events)["ok"]                    # never allowed
    assert not trace_check(ATTEMPT, [arrival("a", nonce="f" * 16)], [], events)["ok"]    # foreign nonce
    assert not trace_check(ATTEMPT, [], [{"kind": "decoy", "nonce": N, "tag": "a", "t": 100.6}], [])["ok"]
    assert trace_check(ATTEMPT, [arrival("a", t=150.0)], [], [])["ok"]                   # outside the window
    same_log = [arrival("a")]                                                             # one log passed twice
    assert trace_check(ATTEMPT, same_log, same_log, events)["ok"]


# ---- self-check variants against a9eff999 ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", sorted(df_variants.VARIANTS))
def test_variant_anchor_applies_once_and_compiles(name, engine_snapshot, tmp_path):
    copy = tmp_path / "engine"
    shutil.copytree(engine_snapshot, copy)
    info = df_variants.apply(copy, name)
    py_compile.compile(str(copy / info["file"]), doraise=True)
    assert info["flips"] and all(f in df_registry.REGISTRY for f in info["flips"])


@pytest.mark.parametrize("group", sorted(df_variants.GROUPS))
def test_variant_group_applies_together(group, engine_snapshot, tmp_path):
    copy = tmp_path / "engine"
    shutil.copytree(engine_snapshot, copy)
    for info in df_variants.apply_all(copy, group):
        py_compile.compile(str(copy / info["file"]), doraise=True)
    cases = df_registry.batch_cases(df_variants.flips(group), controls=False)
    assert not any(c.positive for c in cases)


def test_groups_cover_every_variant_once():
    grouped = [n for g in df_variants.GROUPS.values() for n in g]
    assert sorted(grouped) == sorted(df_variants.VARIANTS)


def test_selfcheck_reads_flips():
    rows = [row("DF-05/302", "engine", "succeeded"), row("DF-05/307", "engine", "blocked"),
            row("DF-05/308", "engine", "succeeded")]
    assert not df_variants.selfcheck("follow-3xx", rows)["passed"]


# ---- the batch network's files -----------------------------------------------------------------------------------------
def test_hosts_resolver_nsswitch():
    hosts = df_net.hosts_bytes(b"127.0.0.1 localhost\n")
    assert b"93.184.216.2 nb-decoy-up\n" in hosts and b"10.66.0.10 nb-decoy-inner\n" in hosts
    assert b"nb-decoy-rebind" not in hosts
    with pytest.raises(ValueError):
        df_net.hosts_bytes(b"1.2.3.4 nb-decoy-up\n")
    assert df_net.resolver_bytes().startswith(b"nameserver 93.184.216.2\n")
    df_net.check_nsswitch("hosts: files mdns4_minimal [NOTFOUND=return] dns\n")
    with pytest.raises(ValueError):
        df_net.check_nsswitch("hosts: dns files\n")
    names = {(s["addr"], s["port"]) for side in df_net.listeners().values() for s in side}
    assert ("10.66.0.10", 443) in names and ("127.0.0.1", 18080) in names


def test_network_log_read_skips_a_line_being_written(tmp_path):
    net = df_net.BatchNetwork(None, None, tmp_path, tmp_path, {})
    net.logs["test"].write_bytes(b'{"kind":"ready"}\n{"kind":"request","nonce":"ab')
    assert net.read("test") == [{"kind": "ready"}]


# ---- the test network's handlers ---------------------------------------------------------------------------------------
def server(tmp_path):
    import df_testnet
    gates = tmp_path / "gates"
    gates.mkdir()
    return df_testnet.Server({"log": str(tmp_path / "log.jsonl"), "gates": str(gates), "private_ip": "10.66.0.10",
                              "listeners": []}), tmp_path / "log.jsonl", gates


def dns_query(name, qtype, qid=7):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", qtype, 1)
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q


def test_dns_first_then_private_per_epoch(tmp_path):
    srv, _, gates = server(tmp_path)
    spec = {"name": "nb-decoy-rebind", "first": "93.184.216.2", "then": "10.66.0.10"}
    (gates / "dns-epoch").write_text("e1")
    answers = [srv.dns_answer(dns_query("nb-decoy-rebind", 1), spec)[1]["answer"] for _ in range(2)]
    assert answers == ["93.184.216.2", "10.66.0.10"]
    assert srv.dns_answer(dns_query("nb-decoy-rebind", 28), spec)[1]["answer"] is None
    reply, record = srv.dns_answer(dns_query("other.name", 1), spec)
    assert record["answer"] is None and struct.unpack(">H", reply[2:4])[0] & 0xF == 3
    (gates / "dns-epoch").write_text("e2")
    assert srv.dns_answer(dns_query("nb-decoy-rebind", 1), spec)[1]["answer"] == "93.184.216.2"


def exchange(srv, raw: bytes, *, gate=None) -> bytes:
    a, b = socket.socketpair()
    t = threading.Thread(target=srv._guard, args=(srv._upstream, b, {"name": "upstream", "port": 443}, "upstream:1"))
    t.start()
    a.sendall(raw)
    if gate:
        gate()
    a.settimeout(5)
    out = b""
    while True:
        try:
            part = a.recv(65536)
        except socket.timeout:
            break
        if not part:
            break
        out += part
        if b"0\r\n\r\n" in out or (b"content-length: 0" in out and out.endswith(b"\r\n\r\n")):
            break
    a.close()
    t.join(5)
    return out


def test_upstream_redirect_drop_and_stream(tmp_path):
    srv, log, gates = server(tmp_path)
    got = exchange(srv, f"GET /redirect/307?n={N}-a HTTP/1.1\r\nhost: x\r\n\r\n".encode())
    assert got.startswith(b"HTTP/1.1 307") and f"location: http://10.66.0.10/landing?n={N}-f".encode() in got
    assert exchange(srv, f"GET /close-after-read?n={N}-a HTTP/1.1\r\nhost: x\r\n\r\n".encode()) == b""
    got = exchange(srv, f"GET /stream?n={N}-a HTTP/1.1\r\nhost: x\r\n\r\n".encode(),
                   gate=lambda: (gates / f"stream-{N}").write_text("go"))
    assert b"nb-decoy-block-1" in got and f"DF-MARK-{N}".encode() in got
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["action"] for r in records if r["kind"] == "request" and "action" in r] == ["dropped", "stream"]
    assert [r["block"] for r in records if r["kind"] == "block"] == [1, 2]


# ---- the runner's synchronisation and observation ------------------------------------------------------------------------
def test_runner_marks_waits_and_writes(tmp_path):
    import df_runner
    req = {"attack": "DF-03", "sub": "recorded-deny", "nonce": N, "config": "undefended",
           "targets": {"up": "nb-decoy-up", "placeholder": "p"}}
    ctx = df_runner.Ctx(req, str(tmp_path))
    assert ctx.url("up", "/ok", "c", port=8443) == f"https://nb-decoy-up:8443/ok?n={N}-c"
    ctx.mark("controlled")
    assert (tmp_path / f"df-{N}-mark-controlled").exists()
    (tmp_path / f"df-{N}-go-deny-set").write_text("go")
    assert ctx.wait("deny-set", 1) and not ctx.wait("never", 0.2)
    df_runner.write_obs(str(tmp_path), N, {"ok": True})
    assert json.loads((tmp_path / f"df-{N}-obs.json").read_text()) == {"ok": True}
    for attack in sorted({c.attack for c in df_registry.REGISTRY.values()}):
        assert callable(df_runner.load(attack).run)
