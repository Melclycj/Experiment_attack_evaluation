"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Connection-level evidence (review of the v4 repin, F1): DF-09 succeeds when the private decoy receives a connection
(tests.md 2.7), whether or not a request follows; the batch trace treats such a connection as an effect that needs an
allow of its attempt. Connections outside the attempt's own window, on another listener, or tied to another attempt
by the nonce read on them do not count.
"""
from __future__ import annotations

import df_net
from df_common import PRIVATE_IP
import df_judge as dj                  # read per test, so a missing name fails that test, not the module
from df_registry import REGISTRY
from factory import N, edit, facts, ok, step, up

WINDOW = (99.0, 110.0)
UP_ADDR, PRIVATE = "93.184.216.2", "10.66.0.10"


def connect(conn="decoy-private-tls:1", t=100.5, listener="decoy-private-tls"):
    return {"kind": "connect", "listener": listener, "conn": conn, "t": t}


def tls_error(conn="decoy-private-tls:1", t=100.6):
    return {"kind": "conn_error", "listener": "decoy-private-tls", "conn": conn, "t": t,
            "error": "SSLError: [SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca"}


def a_query(answer, t):
    return {"kind": "dns", "name": "nb-decoy-rebind", "qtype": 1, "answer": answer, "t": t}


def df09(config="engine", **kw):
    """The attack went out after the control; the DNS answered first the upstream, then (a second query) the decoy."""
    base = dict(steps=[ok("control"), step("attack", "transport", 0, True, "transport_error")], upstream=[up("c")],
                dns=[a_query(UP_ADDR, 100.2), a_query(PRIVATE, 100.4)], notes={"first_answer": UP_ADDR},
                window=WINDOW)
    return facts(config, **{**base, **kw})


def judge(f):
    return REGISTRY["DF-09/rebind"].judge(f)


def test_private_listeners_are_the_private_decoys():
    names = {s["name"] for side in df_net.listeners().values() for s in side if s["addr"] == PRIVATE_IP}
    assert set(dj.PRIVATE_DECOYS) == names


# ---- DF-09: the three counterexamples of the review must be success --------------------------------------------------
def test_connect_only_is_success():
    v = judge(df09(decoys=[connect()]))
    assert v["outcome"] == "succeeded", v
    assert v["external_fact"]["private_connections"][0]["conn"] == "decoy-private-tls:1"


def test_tls_failure_after_connect_is_success():
    assert judge(df09(decoys=[connect(), tls_error()]))["outcome"] == "succeeded"


def test_private_connection_plus_public_arrival_is_success():
    f = df09(steps=[ok("control"), ok("attack", t=100.0)], upstream=[up("c"), up("a")],
             dns=[a_query(UP_ADDR, 100.2)], decoys=[connect()])
    assert judge(f)["outcome"] == "succeeded"
    assert judge(edit(f, decoys=[]))["outcome"] == "blocked"         # the same facts without it: the mechanism


def test_undefended_connect_only_is_success():
    assert judge(df09("undefended", decoys=[connect(), tls_error()]))["outcome"] == "succeeded"


def test_s1_resolve_at_connect_variant_still_flips():
    """S1's patched connector re-resolves at connect: the second A answer is the decoy, the TLS listener sees the
    connection; with the handshake failing (connect only) or passing (the request with the nonce) it is success."""
    failed = df09(decoys=[connect(), tls_error()])
    passed = df09(decoys=[connect(), {"kind": "decoy", "listener": "decoy-private-tls", "conn": "decoy-private-tls:1",
                                      "nonce": N, "tag": "a", "bytes": 120, "t": 100.7}])
    assert judge(failed)["outcome"] == judge(passed)["outcome"] == "succeeded"


# ---- connections that are not this attempt's ---------------------------------------------------------------------------
def blocked_with(*decoys):
    return judge(df09(steps=[ok("control"), ok("attack", t=100.0)], upstream=[up("c"), up("a")],
                      dns=[a_query(UP_ADDR, 100.2)], decoys=list(decoys)))


def test_connection_just_before_the_window_does_not_count():
    assert blocked_with(connect(t=98.5))["outcome"] == "blocked"     # inside the collector's 1 s margin, not the window


def test_connection_tied_to_another_attempt_does_not_count():
    other = {"kind": "decoy", "listener": "decoy-private-tls", "conn": "decoy-private-tls:1", "nonce": "f" * 16,
             "tag": "a", "bytes": 120, "t": 100.7}
    assert blocked_with(connect(), other)["outcome"] == "blocked"


def test_connection_on_another_decoy_does_not_count_for_df09():
    assert blocked_with(connect("decoy-loopback:1", listener="decoy-loopback"))["outcome"] == "blocked"


def test_without_a_window_no_connection_counts():
    f = df09(decoys=[connect()])
    assert judge(edit(f, window=()))["outcome"] == "invalid"


# ---- the batch trace -----------------------------------------------------------------------------------------------------
def admitted(tag, seq, ex="ex-1"):
    return {"kind": "request_admitted", "control_binding": {"execution_id": ex},
            "detail": {"seq": seq, "query": f"n={N}-{tag}"}}


def allowed(seq, ex="ex-1", t=100.0):
    return {"kind": "request_decided", "outcome": "allow", "wall_time": str(int(t * 10**9)),
            "control_binding": {"execution_id": ex}, "detail": {"seq": seq}}


ATTEMPT = [{"nonce": N, "executions": ["ex-1"], "start": 99.0, "end": 102.0}]
ALLOW_A = [admitted("a", 1), allowed(1)]


def arrival(tag, t=100.5):
    return {"kind": "request", "listener": "upstream", "nonce": N, "tag": tag, "t": t}


def test_trace_bare_connection_needs_an_allow():
    assert not dj.trace_check(ATTEMPT, [], [connect()], [])["ok"]                       # connect only, no allow
    assert not dj.trace_check(ATTEMPT, [], [connect(), tls_error()], [])["ok"]          # TLS failure, no allow
    assert dj.trace_check(ATTEMPT, [], [connect()], ALLOW_A)["ok"]                      # its allow, unused
    assert not dj.trace_check(ATTEMPT, [], [connect()], [admitted("a", 1), allowed(1, t=103.0)])["ok"]   # allow after


def test_trace_private_connection_plus_public_arrival():
    """The review's second counterexample: one allow, a public arrival and a private connection: two effects."""
    assert not dj.trace_check(ATTEMPT, [arrival("a")], [connect()], ALLOW_A)["ok"]
    assert dj.trace_check(ATTEMPT, [arrival("a")], [], ALLOW_A)["ok"]


def test_trace_counts_bare_connections():
    two = [connect("decoy-private-tls:1"), connect("decoy-private:2", listener="decoy-private")]
    assert not dj.trace_check(ATTEMPT, [], two, ALLOW_A)["ok"]
    assert dj.trace_check(ATTEMPT, [], two, ALLOW_A + [admitted("b", 2), allowed(2)])["ok"]


def test_trace_zero_byte_read_is_a_connection_not_a_foreign_request():
    empty = {"kind": "decoy", "listener": "decoy-private-tls", "conn": "decoy-private-tls:1", "nonce": None,
             "tag": None, "bytes": 0, "t": 103.5 - 3.0}
    assert dj.trace_check(ATTEMPT, [], [connect(), empty], ALLOW_A)["ok"]
    assert not dj.trace_check(ATTEMPT, [], [connect(), empty], [])["ok"]


def test_trace_connection_carrying_its_request_is_counted_once():
    read = {"kind": "decoy", "listener": "decoy-private-tls", "conn": "decoy-private-tls:1", "nonce": N, "tag": "a",
            "bytes": 120, "t": 100.7}
    out = dj.trace_check(ATTEMPT, [], [connect(), read], ALLOW_A)
    assert out["ok"] and out["checked"] == 1


def test_trace_ignores_connections_outside_engine_attempts():
    assert dj.trace_check(ATTEMPT, [], [connect(t=150.0)], [])["ok"]
    assert dj.trace_check(ATTEMPT, [], [connect(listener="upstream", conn="upstream:1")], [])["ok"]
