"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Regression fixtures for the second cold recheck of the v4 repin (output/attack-eval-v4/recheck-d-codex.md, R1-R6):
each test is one of the recheck's counterexamples and fails on the code before that round's fixes.
"""
from __future__ import annotations

import gzip
import hashlib
import platform
import sys

import pytest

import df_baseline
import df_judge as dj
from df_registry import REGISTRY
from factory import N, decoy, edit, up
from test_connections import admitted, allowed, arrival, connect, df09
from test_judges import S, name_private

WIDE = [{"nonce": N, "executions": ["ex-1"], "start": 99.0, "end": 110.0}]


def df09_judge(f):
    return REGISTRY["DF-09/rebind"].judge(f)


def control_read(conn, t):
    return {"kind": "decoy", "listener": "decoy-private-tls", "conn": conn, "nonce": N, "tag": "c", "bytes": 90,
            "t": t}


# ---- R1: DF-09 attribution ---------------------------------------------------------------------------------------------
def test_r1_control_step_connection_before_the_attack_is_not_success():
    f = df09(upstream=[up("c"), up("a")],
             decoys=[connect("decoy-private-tls:9", t=99.5), control_read("decoy-private-tls:9", 99.6)])
    assert df09_judge(f)["outcome"] != "succeeded"


def test_r1_connection_carrying_the_control_tag_is_not_success():
    f = df09(upstream=[up("c"), up("a")],
             decoys=[connect("decoy-private-tls:9", t=100.5), control_read("decoy-private-tls:9", 100.6)])
    assert df09_judge(f)["outcome"] != "succeeded"


def test_r1_attack_read_on_a_non_private_listener_is_not_success():
    f = df09(upstream=[up("c"), up("a")], decoys=[decoy("a", "decoy-loopback")])
    assert df09_judge(f)["outcome"] != "succeeded"


def test_r1_attack_read_outside_the_window_is_not_success():
    f = df09(upstream=[up("c"), up("a")], decoys=[dict(decoy("a", "decoy-private"), t=111.0)])
    assert df09_judge(f)["outcome"] != "succeeded"


# ---- R2: each effect consumes its own prior allow ----------------------------------------------------------------------
def test_r2_a_consumed_control_allow_does_not_pay_for_a_later_connection():
    events = [admitted("c", 1), allowed(1, t=100.0), admitted("a", 2), allowed(2, t=106.0)]
    out = dj.trace_check(WIDE, [arrival("c", t=100.5)], [connect(t=102.0)], events)
    assert not out["ok"], out


def test_r2_two_early_connections_one_early_allow_one_late_allow():
    events = [admitted("a", 1), allowed(1, t=100.0), admitted("b", 2), allowed(2, t=106.0)]
    two = [connect("decoy-private-tls:1", t=101.0), connect("decoy-private:2", t=101.5, listener="decoy-private")]
    assert not dj.trace_check(WIDE, [], two, events)["ok"]


# ---- R3: a read after the window does not erase an in-window connection --------------------------------------------------
def test_r3_read_after_the_window_keeps_the_connection_an_effect():
    late = {"kind": "decoy", "listener": "decoy-private-tls", "conn": "decoy-private-tls:1", "nonce": N, "tag": "a",
            "bytes": 120, "t": 111.0}
    out = dj.trace_check(WIDE, [], [connect(t=109.5), late], [])
    assert not out["ok"] and out["checked"] >= 1, out


# ---- R4: a connection contradicts a refusal the spec places before any connection -----------------------------------------
PRE_CONNECT = ("DF-03/name-private", "DF-03/ip-private", "DF-03/ip-loopback", "DF-03/ip-linklocal",
               "DF-03/ip-interface")


def test_r4_name_private_with_a_private_connection_is_not_blocked():
    f = edit(name_private(), decoys=[connect(t=100.5)])
    assert REGISTRY["DF-03/name-private"].judge(f)["outcome"] != "blocked"


@pytest.mark.parametrize("sid", PRE_CONNECT)
def test_r4_pre_connect_refusals_with_a_decoy_connection_are_not_blocked(sid):
    f = S[sid][0]()
    assert REGISTRY[sid].judge(f)["outcome"] == "blocked"                    # the expected facts alone still block
    assert REGISTRY[sid].judge(edit(f, decoys=f.decoys + [connect(t=100.5)]))["outcome"] != "blocked"


# ---- R5, R6: host-readings evidence -------------------------------------------------------------------------------------
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/sys")


def profile(tmp_path, **override):
    config = tmp_path / "config.gz"
    config.write_bytes(gzip.compress(b"CONFIG_TEST=y\n"))
    data = {"version": df_baseline.BASELINE, "kernel": platform.release(), "approved_by_user": "2026-11-06",
            "sources": ["test fixture"], "config_sha256": hashlib.sha256(b"CONFIG_TEST=y\n").hexdigest(),
            "readings": {"kernel.ostype": {"path": "/proc/sys/kernel/ostype", "value": "Linux"}},
            "required": ["kernel.ostype"]}
    data.update(override)
    return data, config


@linux_only
def test_r6_well_formed_profile_holds(tmp_path):
    data, config = profile(tmp_path)
    assert df_baseline.profile_reasons(data, platform.release(), config) == []


@linux_only
@pytest.mark.parametrize("field,value", [("sources", 7), ("sources", []), ("sources", [""]),
                                         ("approved_by_user", {"not_approved": True}),
                                         ("approved_by_user", "yes"), ("approved_by_user", "2026-13-40")])
def test_r6_malformed_approval_or_sources_is_a_trial_reason(tmp_path, field, value):
    data, config = profile(tmp_path, **{field: value})
    assert df_baseline.profile_reasons(data, platform.release(), config)


@linux_only
def test_r5_nul_in_a_sysctl_path_is_a_trial_reason_not_an_exception(tmp_path):
    data, config = profile(tmp_path, readings={"kernel.ostype": {"path": "/proc/sys/kernel/ost\x00ype",
                                                                 "value": "Linux"}})
    assert df_baseline.profile_reasons(data, platform.release(), config)


@linux_only
def test_r5_corrupt_gzip_payload_is_a_trial_reason_not_an_exception(tmp_path):
    data, config = profile(tmp_path)
    good = config.read_bytes()
    config.write_bytes(good[:10] + b"\xff" * 16 + good[-8:])            # valid gzip header, corrupt deflate data
    assert df_baseline.profile_reasons(data, platform.release(), config)
