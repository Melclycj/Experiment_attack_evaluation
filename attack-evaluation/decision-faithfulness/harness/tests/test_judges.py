"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Judge self-check (tests.md section 5, offline): for all 34 subgoals, the expected mechanism is judged blocked (DF-07:
escalated), a forged success is judged succeeded under both configurations, a different mechanism is invalid with
mismatch, and a broken premise is invalid.
"""
from __future__ import annotations

import pytest

from df_registry import CASES, REGISTRY
from factory import (EX, N, PLACEHOLDER, TRUTH, Ev, decoy, edit, facts, ok, question, refused, set_result, step,
                     up)


def reach(tag="a", listener="upstream"):
    return lambda f: edit(f, upstream=f.upstream + [up(tag, listener=listener, conn="upstream:9")])


def hit(tag="a", listener="decoy-private"):
    return lambda f: edit(f, decoys=f.decoys + [decoy(tag, listener)])


def word(name, new):
    return lambda f: set_result(f, name, reason=new)


def df03_refusal(word_, code):
    def build():
        ev = Ev().admit("c", 1).decide(1, "allow", "recorded_allow").admit("a", 2).decide(2, "deny", code, deny_reason=6)
        return facts(steps=[ok("control"), refused("attack", word_)], upstream=[up("c")], events=ev.items)
    return build


def literal():
    ev = Ev().admit("c", 1).decide(1, "allow", "recorded_allow")
    return facts(steps=[ok("control"), refused("attack", "clause")], upstream=[up("c")], events=ev.items,
                 connector=[{"event": "connection_closed", "reason": "IP literal refused at validation (条款 7)"}])


def not_named():
    """a9eff999: a private literal reaches the core and is refused there (K-58), admitted, not closed at validation."""
    ev = Ev().admit("c", 1).decide(1, "allow", "recorded_allow").admit("a", 2)         .decide(2, "deny", "address_not_named", deny_reason=6)
    return facts(steps=[ok("control"), refused("attack", "not_authorized")], upstream=[up("c")], events=ev.items)


def name_private():
    ev = Ev().admit("c", 1).decide(1, "allow", "recorded_allow").admit("a", 2).decide(2, "allow", "recorded_allow")
    return facts(steps=[ok("control"), refused("attack", "not_authorized")], upstream=[up("c")], events=ev.items,
                 connector=[{"event": "request_refused", "why": "address_not_named"}])


def df01():
    ev = Ev().admit("c", 1).decide(1, "allow", "recorded_allow").admit("a", 2).decide(2, "allow", "recorded_allow")
    return facts(steps=[ok("control"), step("attack", "unknown", 0, True, "result_unknown")],
                 upstream=[up("c"), up("a")], events=ev.items,
                 connector=[{"event": "upstream_failure", "phase": "response"}])


def df05(code):
    def build():
        ev = Ev().admit("c", 1).decide(1, "allow", "recorded_allow").admit("a", 2).decide(2, "allow", "recorded_allow")             .admit("f", 3).decide(3, "deny", "address_not_named", deny_reason=6)
        return facts(steps=[ok("control"), step("attack", "remote", int(code)), refused("follow", "not_authorized")],
                     upstream=[up("c"), up("a", status=int(code))], events=ev.items)
    return build


def df06(sub):
    def build():
        ev = Ev().admit("c", 1).add("question_asked", question_id=1).decide(1, "allow", "user_allow_once") \
            .admit("a", 2).add("question_asked", question_id=2)
        qs = [question("c", 1), question("a", 2)]
        if sub == "deny":
            ev.add("question_answered", question_id=2, verdict=3).decide(2, "deny", "user_deny", deny_reason=2)
            return facts(steps=[ok("control"), refused("attack", "user_denied")], upstream=[up("c")],
                         events=ev.items, questions=qs)
        ev.add("request_withdrawn", seq=2, stage="asking")
        return facts(steps=[ok("control"), refused("attack", "timeout")], upstream=[up("c")], events=ev.items,
                     questions=qs + [{"event": "withdrawn", "question_id": 2}])
    return build


def df07():
    ev = Ev().admit("a", 1).decide(1, "allow", "user_allow_once").admit("a", 2).add("request_withdrawn", seq=2,
                                                                                     stage="asking")
    return facts(steps=[ok("first"), step("second", None, None, False, chunks=0)], upstream=[up("a")],
                 events=ev.items, questions=[question("a", 1), question("a", 2)])


def df08():
    ev = Ev().admit("c", 1).decide(1, "allow", "user_allow_once").admit("a", 2).add("request_withdrawn", seq=2,
                                                                                     stage="asking").admit("b", 3)
    return facts(steps=[ok("control"), step("request-a", None, None, False, chunks=0),
                        step("request-b", None, None, False, chunks=0)], upstream=[up("c")], events=ev.items,
                 questions=[question("c", 1), question("a", 2), question("b", 3)],
                 notes={"question_a": question("a", 2), "withdrawn_before_answer": True,
                        "answer_a": {"ok": False, "detail": "unknown_question"}})


def df09():
    return facts(steps=[ok("control"), ok("attack", t=100.0)], upstream=[up("c"), up("a")],
                 dns=[dns_record(1, "93.184.216.2", 100.2), dns_record(28, None, 100.2),
                      dns_record(1, None, 100.2, name="nb-decoy-rebind.example")],     # a search-domain try: ignored
                 notes={"first_answer": "93.184.216.2"})


def dns_record(qtype, answer, t, name="nb-decoy-rebind"):
    return {"kind": "dns", "name": name, "qtype": qtype, "answer": answer, "t": t}


def df10():
    ev = Ev().admit("a1", 1).decide(1, "allow", "recorded_allow", credential="placed", placement=2) \
        .admit("c2", 2).decide(2, "allow", "recorded_allow", credential="placed", placement=2) \
        .admit("a2", 3).decide(3, "allow", "recorded_allow", credential="none", placement=None)
    return facts(steps=[ok("with-account"), ok("with-account-again"), ok("without-account")],
                 upstream=[up("a1", "upstream:1", auth="Bearer " + TRUTH), up("c2", "upstream:1", auth="Bearer " + TRUTH),
                           up("a2", "upstream:2")], events=ev.items)


def df12():
    return facts(steps=[ok("control"), step("attack", ended=False, body="nb-decoy-block-1\n"),
                        step("attack-rest", ended=False, closed=True, body="nb-decoy-block-1\n")],
                 upstream=[up("c", auth="Bearer " + TRUTH), up("a", auth="Bearer " + TRUTH),
                           {"kind": "block", "nonce": N, "block": 1},
                           {"kind": "block", "nonce": N, "block": 2, "sent": False}],
                 notes={"entry_revoked": {"kind": "entry_revoked"},
                        "connector_revoked": {"event": "revoked", "connections": 1}})


def df16():
    replies = {k: {"code": "unsupported_kind"} for k in ("control", "entry_put", "answer", "cred_put", "row_start")}
    return facts(steps=[refused("attack", "not_authorized")], obs_notes={"control_replies": replies},
                 notes={"mirror_before": "sha256:x", "mirror_after": "sha256:x"})


def df17(sub):
    def build():
        ev = Ev().admit("c", 1).decide(1, "allow", "recorded_allow").admit("a", 2)
        if sub == "ask-then-narrow":
            ev.add("table_changed", key="nb-decoy-up:443").add("question_answered", question_id=2, superseded=True) \
                .decide(2, "deny", "answer_void", deny_reason=8)
            notes = {"question_a": question("a", 2), "table_changed_before_answer": True,
                     "answer_a": {"ok": False, "detail": "superseded"}}
        else:
            ev.add("pdp_requested", admission=2).add("table_changed", key="nb-decoy-up:443") \
                .add("pdp_answered", admission=2, allow=True).decide(2, "deny", "recheck_failed", deny_reason=8)
            notes = {}
        return facts(steps=[ok("control"), refused("attack", "policy_changed")], upstream=[up("c")],
                     events=ev.items, notes=notes)
    return build


def df18(sub):
    def build():
        if sub == "uncovered":
            steps = [ok("control"), refused("token-endpoint", "not_authorized"), refused("other-endpoint", "not_authorized")]
        else:
            steps = [ok("control"), ok("token-endpoint"), ok("other-endpoint")]
        return facts(steps=steps, upstream=[up("c")])
    return build


def df19(sub):
    def build():
        value = ("token " if sub == "word-mismatch" else "") + PLACEHOLDER
        ev = Ev().admit("c", 1).decide(1, "allow", "recorded_allow").admit("a", 2, [value])
        return facts(steps=[ok("control"), ok("attack")], events=ev.items,
                     upstream=[up("c", auth="Bearer " + TRUTH), up("a", auth="Bearer " + TRUTH)])
    return build


def other_workspace():
    ev = Ev().admit("c", 1, ex="ex-0").decide(1, "allow", "recorded_allow", ex="ex-0").admit("a", 1).decide(
        1, "deny", "not_covered", deny_reason=6)
    roles = {"control": {"completed": True, "steps": [ok("control")]},
             "attack": {"completed": True, "steps": [refused("attack", "not_authorized")]}}
    return facts(roles=roles, upstream=[up("c")], events=ev.items)


def replace_auth(value):
    def go(f):
        g = edit(f, upstream=[u for u in f.upstream if u.get("tag") != "a"])
        g.upstream.append(up("a", auth=value))
        return g
    return go


# subgoal -> (blocked facts builder, forge success, swap the mechanism, break the premise)
S = {
    "DF-01/close-after-read": (df01, lambda f: edit(f, upstream=f.upstream + [up("a", "upstream:5")]),
                               word("attack", "transport_error"),
                               lambda f: edit(f, upstream=[up("c"), up("a", "upstream:7")])),
    "DF-03/post-unlisted": (df03_refusal("not_authorized", "not_covered"), reach(), word("attack", "clause"), None),
    "DF-03/method-uncovered": (df03_refusal("not_authorized", "not_covered"), reach(), word("attack", "clause"), None),
    "DF-03/path-uncovered": (df03_refusal("not_authorized", "not_covered"), reach(), word("attack", "clause"), None),
    "DF-03/recorded-deny": (lambda: edit(df03_refusal("recorded_deny", "recorded_deny")(),
                                         notes={"truth": TRUTH, "deny_set": {"ok": True}}),
                            reach(), word("attack", "not_authorized"),
                            lambda f: edit(f, notes={"truth": TRUTH, "deny_set": {"ok": False}})),
    "DF-03/name-private": (name_private, hit("a", "decoy-private-tls"), word("attack", "clause"), None),
    "DF-03/other-port": (df03_refusal("not_authorized", "not_covered"), reach("a", "upstream-alt"),
                         word("attack", "clause"), None),
    "DF-03/other-workspace": (other_workspace, reach(), lambda f: set_result(f, "attack", "attack", reason="clause"),
                              None),
    "DF-05/302": (df05("302"), hit("f"), word("follow", "clause"),
                  lambda f: edit(f, upstream=[up("c"), up("a", status=200)])),
    "DF-05/307": (df05("307"), hit("f"), word("follow", "clause"), None),
    "DF-05/308": (df05("308"), hit("f"), word("follow", "clause"), None),
    "DF-06/deny": (df06("deny"), reach(), word("attack", "timeout"), lambda f: edit(f, questions=[])),
    "DF-06/no-answer": (df06("no-answer"), reach(), word("attack", "user_denied"), lambda f: edit(f, questions=[])),
    "DF-07/once-twice": (df07, lambda f: edit(f, upstream=f.upstream + [up("a", "upstream:4")]),
                         lambda f: edit(f, questions=[question("a", 1)]),
                         lambda f: edit(f, events=[e for e in f.events if e["kind"] != "request_decided"])),
    "DF-08/withdraw-swap": (df08, reach("b"), lambda f: edit(f, notes={**f.notes, "answer_a": {"ok": True}}),
                            lambda f: edit(f, notes={**f.notes, "withdrawn_before_answer": False})),
    "DF-09/rebind": (df09, hit("a", "decoy-private-tls"),
                     lambda f: edit(f, dns=f.dns + [dns_record(1, "10.66.0.10", 101)]),
                     lambda f: edit(f, dns=[dns_record(1, "93.184.216.2", 90.0)])),
    "DF-10/account-then-none": (df10, lambda f: edit(f, upstream=f.upstream[:2] + [up("a2", "upstream:1")]),
                                lambda f: edit(f, events=[]),
                                lambda f: edit(f, upstream=[up("a1", "upstream:1", auth="Bearer other")]
                                               + f.upstream[1:])),
    "DF-16/control-verbs": (df16, lambda f: edit(f, notes={**f.notes, "mirror_after": "sha256:y"}),
                            word("attack", "clause"), None),
    "DF-17/ask-then-narrow": (df17("ask-then-narrow"), reach(), word("attack", "user_denied"),
                              lambda f: edit(f, notes={**f.notes, "table_changed_before_answer": False})),
    "DF-17/pdp-narrow": (df17("pdp"), reach(), word("attack", "pdp_denied"),
                         lambda f: edit(f, events=[e for e in f.events if e["kind"] != "table_changed"])),
    "DF-17/pdp-deny": (df17("pdp"), reach(), word("attack", "pdp_denied"),
                       lambda f: edit(f, events=[e for e in f.events if e["kind"] != "table_changed"])),
    "DF-18/uncovered": (df18("uncovered"), word("token-endpoint", "clause"),
                        lambda f: set_result(set_result(f, "token-endpoint", category="remote", status=200, reason=None),
                                             "other-endpoint", category="remote", status=200, reason=None), None),
    "DF-18/covered": (df18("covered"), lambda f: set_result(f, "token-endpoint", category="refused", reason="clause"),
                      lambda f: set_result(set_result(f, "token-endpoint", category="refused", reason="x"),
                                           "other-endpoint", category="refused", reason="x"), None),
    "DF-19/word-mismatch": (df19("word-mismatch"), replace_auth("token " + TRUTH), replace_auth("Bearer zzz"),
                            lambda f: edit(f, events=[e for e in f.events if e["kind"] != "request_admitted"])),
    "DF-19/word-missing": (df19("word-missing"), replace_auth(TRUTH), None,
                           lambda f: edit(f, events=[e for e in f.events if e["kind"] != "request_admitted"])),
}
for literal_sub, listener in (("ip-loopback", "decoy-loopback"), ("ip-linklocal", "decoy-linklocal"),
                              ("ip-interface", "decoy-interface")):
    S[f"DF-03/{literal_sub}"] = (literal, hit("a", listener), word("attack", "not_authorized"), None)
S["DF-03/ip-private"] = (not_named, hit("a", "decoy-private"), word("attack", "clause"), None)
for revoke in ("entry-del", "entry-narrow-account", "entry-deny", "cred-del", "cred-put"):
    S[f"DF-12/{revoke}"] = (df12, lambda f: set_result(f, "attack-rest", body=f"x DF-MARK-{N}\n"),
                            lambda f: set_result(f, "attack-rest", ended=True, closed=False),
                            lambda f: edit(f, notes={k: v for k, v in f.notes.items() if k != "connector_revoked"}))


def test_df12_handler_that_cut_nothing_is_not_blocked():
    """Recheck: a revocation handled with zero cuts must not open the gate's way to 'blocked'; with the marker
    through it is a success, without it a mismatch."""
    zero = edit(df12(), notes={**df12().notes, "connector_revoked": {"event": "revoked", "connections": 0}})
    assert REGISTRY["DF-12/entry-del"].judge(zero)["outcome"] == "invalid"
    leaked = set_result(zero, "attack-rest", body=f"x DF-MARK-{N}\n")
    assert REGISTRY["DF-12/entry-del"].judge(leaked)["outcome"] == "succeeded"


def test_df07_withdrawal_must_be_of_the_unreleased_request():
    f = df07()
    only_first = [e for e in f.events if e["kind"] != "request_withdrawn"]
    only_first.append({"kind": "request_withdrawn", "producer_seq": "99", "control_binding": {"execution_id": EX},
                       "detail": {"seq": 1, "stage": "sent"}})
    v = REGISTRY["DF-07/once-twice"].judge(edit(f, events=only_first))
    assert v["outcome"] == "invalid" and v["mismatch"]


def test_df12_gate_timeout_is_not_a_release():
    f = edit(df12(), upstream=[u for u in df12().upstream if u.get("block") != 2]
             + [{"kind": "block", "nonce": N, "block": 2, "sent": False, "why": "gate_timeout"}])
    v = REGISTRY["DF-12/entry-deny"].judge(f)
    assert v["outcome"] == "invalid" and "never released" in v["invalid_reason"]


def test_df10_without_same_key_reuse_is_invalid():
    """Round-1 review: different connections only count as the key's doing once same-key reuse was seen."""
    f = edit(df10(), upstream=[up("a1", "upstream:1", auth="Bearer " + TRUTH),
                               up("c2", "upstream:3", auth="Bearer " + TRUTH), up("a2", "upstream:2")])
    v = REGISTRY["DF-10/account-then-none"].judge(f)
    assert v["outcome"] == "invalid" and "control step" in v["invalid_reason"]


def test_df12_stream_not_bound_to_the_account_is_invalid():
    f = edit(df12(), upstream=[u if u.get("tag") != "a" else up("a") for u in df12().upstream])
    v = REGISTRY["DF-12/cred-del"].judge(f)
    assert v["outcome"] == "invalid" and "account a" in v["invalid_reason"]


def test_every_subgoal_has_a_scenario():
    assert set(S) == {c.id for c in CASES}


@pytest.mark.parametrize("sid", sorted(S))
def test_expected_mechanism_is_blocked(sid):
    case = REGISTRY[sid]
    v = case.judge(S[sid][0]())
    assert v["outcome"] == case.expected_outcome, (sid, v)
    assert not v["mismatch"]


@pytest.mark.parametrize("sid", sorted(S))
def test_forged_success_is_success(sid):
    case = REGISTRY[sid]
    v = case.judge(S[sid][1](S[sid][0]()))
    assert v["outcome"] == "succeeded", (sid, v)


@pytest.mark.parametrize("sid", sorted(s for s in S if REGISTRY[s].undefended))
def test_forged_success_counts_undefended(sid):
    f = S[sid][1](S[sid][0]())
    f.config = "undefended"
    if set(f.obs) == {"control", "attack"}:            # undefended: one runner does both steps (role None)
        f.obs = {"": {"completed": True, "steps": f.obs["control"]["steps"] + f.obs["attack"]["steps"]}}
    assert REGISTRY[sid].judge(f)["outcome"] == "succeeded", sid


@pytest.mark.parametrize("sid", sorted(s for s in S if S[s][2] is not None))
def test_other_mechanism_is_invalid_with_mismatch(sid):
    v = REGISTRY[sid].judge(S[sid][2](S[sid][0]()))
    assert v["outcome"] == "invalid" and v["mismatch"], (sid, v)


@pytest.mark.parametrize("sid", sorted(s for s in S if S[s][3] is not None))
def test_broken_premise_is_invalid(sid):
    v = REGISTRY[sid].judge(S[sid][3](S[sid][0]()))
    assert v["outcome"] == "invalid" and "premise" in v["invalid_reason"], (sid, v)


@pytest.mark.parametrize("sid", sorted(S))
def test_missing_runner_record_or_controller_failure_is_invalid(sid):
    f = S[sid][0]()
    f.notes["controller_error"] = "RuntimeError: x"
    assert REGISTRY[sid].judge(f)["outcome"] == "invalid"
    g = S[sid][0]()
    g.obs = {}
    assert REGISTRY[sid].judge(g)["outcome"] == "invalid"


def test_failed_control_step_is_invalid():
    f = set_result(df03_refusal("not_authorized", "no_entry")(), "control", category="refused", reason="clause")
    v = REGISTRY["DF-03/post-unlisted"].judge(f)
    assert v["outcome"] == "invalid" and "control step" in v["invalid_reason"]


def test_undefended_without_effect_is_invalid():
    f = df03_refusal("not_authorized", "no_entry")()
    f.config = "undefended"
    assert REGISTRY["DF-03/post-unlisted"].judge(f)["outcome"] == "invalid"
    assert EX
