"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

One judge per subgoal, written from tests.md section 2: control step, validity premise, the external fact that is
success, and the mechanism expected when it is absent. Order (METHOD rule 4): runner record complete, control step
passed, premise holds, then success; an engine attempt without success is blocked (escalated for DF-07) only when the
observed mechanism is the expected one, otherwise invalid with mismatch. An undefended attempt that does not reach
its target is invalid (the pairing then makes the engine side invalid too, tests.md 1.4).
"""
from __future__ import annotations

from df_common import REBIND_HOST
from df_judge import (Facts, admitted, arrivals, blocks, connector_has, decided, decoy_connections, decoy_hits, header,
                      literal_refusal, not_named_refusal, owner, private_reached, records, refused, remote_ok, result,
                      runner_problem, seq_of, step, verdict, withdrawn)


def decide(f: Facts, *, control, valid, effect, mechanism, roles=("",), escalate=False) -> dict:
    problem = runner_problem(f, roles)
    if problem:
        return verdict("invalid", why=problem)
    ok, seen = control(f)
    if not ok:
        return verdict("invalid", why="control step did not pass: " + seen, control=seen)
    ok, why = valid(f)
    if not ok:
        return verdict("invalid", why="validity premise failed: " + why, control=seen)
    hit, fact = effect(f)
    if hit:
        return verdict("succeeded", fact=fact, control=seen)
    if f.config != "engine":
        return verdict("invalid", why="undefended attempt did not reach its target", fact=fact, control=seen)
    ok, mechanism_seen = mechanism(f)
    if ok:
        return verdict("escalated" if escalate else "blocked", mechanism_seen, fact=fact, control=seen)
    return verdict("invalid", mechanism_seen, mismatch=True, fact=fact, control=seen,
                   why="effect absent but the observed mechanism is not the expected one")


def always(_f) -> tuple[bool, str]:
    return True, ""


def ok_step(name: str, role: str = ""):
    def check(f: Facts) -> tuple[bool, str]:
        r = result(f, name, role)
        return remote_ok(r), f"{name}: {r.get('category')} {r.get('status')} ended={r.get('ended')}"
    return check


def reached(tag: str, listener: str | None = None):
    def check(f: Facts):
        hits = arrivals(f, tag, listener=listener)
        return bool(hits), {"upstream_arrivals": len(hits), "listener": listener}
    return check


def decoy(tag: str):
    def check(f: Facts):
        hits = decoy_hits(f, tag)
        return bool(hits), {"decoy_hits": [{"listener": h["listener"], "conn": h["conn"]} for h in hits]}
    return check


def refusal(word: str, *bases: str, step_name: str = "attack", tag: str = "a"):
    """Refused with the reason word; E-09 decided deny with one of the bases (reason_code)."""
    def check(f: Facts):
        r = result(f, step_name)
        denies = decided(f, tag, "deny")
        codes = sorted({d.get("reason_code") for d in denies})
        ok = refused(r, word) and (not bases or any(c in bases for c in codes))
        return ok, f"reason={r.get('reason')} decided={codes}"
    return check


# ---- DF-01 ------------------------------------------------------------------------------------------------------------
def df01(f: Facts) -> dict:
    def valid(f):
        c, a = arrivals(f, "c"), arrivals(f, "a")
        return bool(c and a and a[0]["conn"] == c[0]["conn"]), "attack not on the reused upstream connection"

    def effect(f):
        a = arrivals(f, "a")
        return len(a) >= 2, {"arrivals": len(a), "conns": [x["conn"] for x in a]}

    def mechanism(f):
        r = result(f, "attack")
        ok = r.get("category") == "unknown" and r.get("reason") == "result_unknown" \
            and connector_has(f, "upstream_failure")
        return ok, f"category={r.get('category')} reason={r.get('reason')} upstream_failure={ok}"
    return decide(f, control=ok_step("control"), valid=valid, effect=effect, mechanism=mechanism)


# ---- DF-03 ------------------------------------------------------------------------------------------------------------
def df03(sub: str):
    deny_set = lambda f: (bool((f.notes.get("deny_set") or {}).get("ok")) or f.config != "engine",  # noqa: E731
                          "the deny entry was not recorded")
    table = {
        # the fallback entry always exists, so an uncovered request matches it and is not_covered (round-1 review)
        "post-unlisted": (always, reached("a"), refusal("not_authorized", "not_covered")),
        "method-uncovered": (always, reached("a"), refusal("not_authorized", "not_covered")),
        "path-uncovered": (always, reached("a"), refusal("not_authorized", "not_covered")),
        "recorded-deny": (deny_set, reached("a"), refusal("recorded_deny", "recorded_deny")),
        "other-port": (always, reached("a", "upstream-alt"), refusal("not_authorized", "not_covered")),
        "other-workspace": (always, reached("a"), refusal("not_authorized", "not_covered")),
    }
    for literal in ("ip-loopback", "ip-linklocal", "ip-interface"):
        table[literal] = (always, decoy("a"), literal_refusal())
    # a private literal passes gate one; the fallback names no non-global address (engine/hook.py literal_not_named)
    table["ip-private"] = (always, decoy("a"), not_named_refusal())

    def name_private(f):
        r = result(f, "attack")
        allowed = bool(decided(f, "a", "allow"))
        refused_at_connect = connector_has(f, "request_refused", why="address_not_named")
        conns = len(decoy_connections(f))               # "refused before connecting": a connection contradicts it (R4)
        return (refused(r, "not_authorized") and allowed and refused_at_connect and not conns,
                f"reason={r.get('reason')} allow_recorded={allowed} connector_refused_not_named={refused_at_connect} "
                f"decoy_conns={conns}")
    table["name-private"] = (always, decoy("a"), name_private)
    valid, effect, mechanism = table[sub]

    def judge(f: Facts) -> dict:
        if sub == "other-workspace" and f.config == "engine":
            return decide(f, control=ok_step("control", "control"), valid=valid, effect=effect,
                          mechanism=_role(mechanism, "attack"), roles=("control", "attack"))
        return decide(f, control=ok_step("control"), valid=valid, effect=effect, mechanism=mechanism)
    return judge


def _role(mechanism, role: str):
    """Run a mechanism check against one role's observation (the other-workspace attack row)."""
    def check(f: Facts):
        view = Facts(**{**f.__dict__, "obs": {"": f.obs.get(role) or {}}})
        return mechanism(view)
    return check


# ---- DF-05 ------------------------------------------------------------------------------------------------------------
def df05(sub: str):
    def valid(f):
        sent = [r for r in arrivals(f, "a") if r.get("status") == int(sub)]
        return bool(sent), f"the upstream did not answer {sub}"

    def mechanism(f):
        r = result(f, "attack")
        follow = not_named_refusal("f", "follow")(f)
        ok = r.get("category") == "remote" and r.get("status") == int(sub) and follow[0]
        return ok, f"attack={r.get('category')} {r.get('status')}; follow: {follow[1]}"
    return lambda f: decide(f, control=ok_step("control"), valid=valid, effect=decoy("f"), mechanism=mechanism)


# ---- DF-06 ------------------------------------------------------------------------------------------------------------
def asked(f: Facts, tag: str) -> list[dict]:
    return [q for q in f.questions if q.get("event") == "question" and f"n={f.nonce}-{tag}" in q.get("query", "")]


def df06(sub: str):
    def valid(f):
        return (f.config != "engine" or bool(asked(f, "a"))), "no question reached the management port"

    def mechanism(f):
        r = result(f, "attack")
        if sub == "deny":
            answered = [e for e in records(f, "question_answered") if (e.get("detail") or {}).get("verdict") == 3]
            return refused(r, "user_denied") and bool(answered), f"reason={r.get('reason')} deny_answers={len(answered)}"
        stage = [e["detail"].get("stage") for e in withdrawn(f, "a")]
        gone = [q for q in f.questions if q.get("event") == "withdrawn"]
        return (refused(r, "timeout") and "asking" in stage and bool(gone),
                f"reason={r.get('reason')} withdrawn_stage={stage} window_withdrawals={len(gone)}")
    return lambda f: decide(f, control=ok_step("control"), valid=valid, effect=reached("a"), mechanism=mechanism)


# ---- DF-07 ------------------------------------------------------------------------------------------------------------
def df07(f: Facts) -> dict:
    def valid(f):
        if f.config != "engine":
            return True, ""
        bases = {d.get("reason_code") for d in decided(f, "a", "allow")}
        return "user_allow_once" in bases, f"first request not released by allow-once ({sorted(bases)})"

    def effect(f):
        a = arrivals(f, "a")
        return len(a) >= 2, {"arrivals": len(a)}

    def mechanism(f):
        """Asked again, released once, and the second request withdrawn after the runner gave up (tests.md 2.5);
        both requests carry tag a, so the withdrawal must be of an admission that was never allowed (round-2)."""
        released = {(owner(e), e["detail"].get("seq")) for e in decided(f, "a", "allow")}
        questions = asked(f, "a")
        gone = [e for e in withdrawn(f, "a") if (owner(e), e["detail"].get("seq")) not in released]
        return (len(questions) >= 2 and len(arrivals(f, "a")) == 1 and bool(gone),
                f"questions={len(questions)} withdrawn={[e['detail'].get('stage') for e in gone]}")
    return decide(f, control=ok_step("first"), valid=valid, effect=effect, mechanism=mechanism, escalate=True)


# ---- DF-08 ------------------------------------------------------------------------------------------------------------
def df08(f: Facts) -> dict:
    def valid(f):
        if f.config != "engine":
            return step(f, "request-b") is not None, "request B was not sent"
        return (bool(f.notes.get("question_a")) and bool(f.notes.get("withdrawn_before_answer")),
                "A's question or its withdrawal record before the answer is missing")

    def mechanism(f):
        reply = f.notes.get("answer_a") or {}
        return (reply.get("ok") is False and bool(asked(f, "b")) and not arrivals(f, "b"),
                f"answer_to_A={'OK' if reply.get('ok') else reply.get('detail')} b_questions={len(asked(f, 'b'))}")
    return decide(f, control=ok_step("control"), valid=valid, effect=reached("b"), mechanism=mechanism)


# ---- DF-09 ------------------------------------------------------------------------------------------------------------
def df09(f: Facts) -> dict:
    # only the rebinding name: a search-domain variant is answered NXDOMAIN and must not count (round-2 review)
    a_queries = lambda f: [d for d in f.dns if d.get("qtype") == 1 and d.get("name") == REBIND_HOST]  # noqa: E731

    def valid(f):
        s = step(f, "attack") or {}
        queries = a_queries(f)
        early = [d for d in queries if d["t"] < s.get("sent_at", 0) - 0.5]
        ok = bool(queries) and not early and queries[0].get("answer") == f.notes.get("first_answer")
        return ok, f"A queries={len(queries)} before_attack={len(early)}"

    def mechanism(f):
        n = len(a_queries(f))
        return bool(arrivals(f, "a")) and n == 1, f"upstream_arrivals={len(arrivals(f, 'a'))} A_queries={n}"
    return decide(f, control=ok_step("control"), valid=valid, effect=private_reached("a"), mechanism=mechanism)


# ---- DF-10 ------------------------------------------------------------------------------------------------------------
def df10(f: Facts) -> dict:
    def control(f):
        """All three answered, and the two same-account requests shared one upstream connection: reuse happens, so a
        new connection for the third request is the key's doing, not a connector that never reuses (round-1 review)."""
        steps = [ok_step(s)(f) for s in ("with-account", "with-account-again", "without-account")]
        a1, c2 = arrivals(f, "a1"), arrivals(f, "c2")
        reused = bool(a1 and c2) and a1[0]["conn"] == c2[0]["conn"]
        return all(s[0] for s in steps) and reused, "; ".join(s[1] for s in steps) + f"; same-key reuse={reused}"

    def valid(f):
        first = arrivals(f, "a1")
        return (bool(first) and header(first[0], "authorization") == ["Bearer " + f.notes["truth"]],
                "the first request did not carry the generated credential header")

    def effect(f):
        c2, a2 = arrivals(f, "c2"), arrivals(f, "a2")
        same = bool(c2 and a2) and c2[0]["conn"] == a2[0]["conn"]
        return same, {"conn_with": c2[0]["conn"] if c2 else None, "conn_without": a2[0]["conn"] if a2 else None}

    def mechanism(f):
        one, two = decided(f, "a1", "allow"), decided(f, "a2", "allow")
        ok = bool(one and two) and one[0]["detail"].get("placement") == 2 \
            and two[0]["detail"].get("credential") == "none"
        return ok, f"first={[d['detail'].get('credential') for d in one]} second={[d['detail'].get('credential') for d in two]}"
    return decide(f, control=control, valid=valid, effect=effect, mechanism=mechanism)


# ---- DF-12 ------------------------------------------------------------------------------------------------------------
def df12(f: Facts) -> dict:
    marker = f"DF-MARK-{f.nonce}"

    def valid(f):
        r = result(f, "attack")
        # released: sent, or failed on a cut connection; a gate that timed out was never released (round-1 recheck)
        second = [b for b in blocks(f) if b.get("block") == 2 and b.get("why") != "gate_timeout"]
        bound = arrivals(f, "a")
        if not bound or header(bound[0], "authorization") != ["Bearer " + f.notes["truth"]]:
            return False, "the stream was not sent as account a (generated Bearer header missing upstream)"
        if not r.get("chunks") or not second:
            return False, "first block not received, or the second block never released"
        if f.config == "engine" and not (f.notes.get("entry_revoked") and f.notes.get("connector_revoked")):
            return False, "the revocation was not both issued (E-09) and handled (connector log) before the release"
        return True, ""

    def effect(f):
        body = result(f, "attack-rest").get("body", "")
        return marker in body, {"marker_received": marker in body}

    def mechanism(f):
        r = result(f, "attack-rest")
        matched = (f.notes.get("connector_revoked") or {}).get("connections")    # links matched, cut() called
        return (not r.get("ended") and bool(r.get("closed")) and bool(f.notes.get("entry_revoked")) and bool(matched),
                f"ended={r.get('ended')} closed={r.get('closed')} connector_matched={matched}")
    return decide(f, control=ok_step("control"), valid=valid, effect=effect, mechanism=mechanism)


# ---- DF-16 ------------------------------------------------------------------------------------------------------------
def df16(f: Facts) -> dict:
    replies = lambda f: (f.obs.get("") or {}).get("notes", {}).get("control_replies") or {}  # noqa: E731

    def control(f):
        reply = replies(f).get("control") or {}
        return reply.get("code") == "unsupported_kind", f"control reply={reply}"

    def effect(f):
        changed = f.notes.get("mirror_before") != f.notes.get("mirror_after")
        return changed or bool(arrivals(f, "a")), {"mirror_changed": changed, "post_arrived": bool(arrivals(f, "a"))}

    def mechanism(f):
        codes = {k: (v or {}).get("code") for k, v in replies(f).items() if k != "control"}
        ok = len(codes) == 4 and set(codes.values()) == {"unsupported_kind"} and \
            refused(result(f, "attack"), "not_authorized")
        return ok, f"verb replies={codes}"
    return decide(f, control=control, valid=always, effect=effect, mechanism=mechanism)


# ---- DF-17 ------------------------------------------------------------------------------------------------------------
def df17(sub: str):
    def valid(f):
        if f.config != "engine":
            return True, ""
        if sub == "ask-then-narrow":
            return (bool(f.notes.get("question_a")) and bool(f.notes.get("table_changed_before_answer")),
                    "the table change did not land while the question was open")
        return pdp_window(f, "a")

    def mechanism(f):
        r = result(f, "attack")
        codes = sorted({d.get("reason_code") for d in decided(f, "a", "deny")})
        if sub == "ask-then-narrow":
            void = [e for e in records(f, "question_answered", superseded=True)]
            reply = f.notes.get("answer_a") or {}
            return (refused(r, "policy_changed") and bool(void) and reply.get("ok") is False,
                    f"reason={r.get('reason')} superseded={len(void)} decided={codes}")
        return refused(r, "policy_changed") and "recheck_failed" in codes, f"reason={r.get('reason')} decided={codes}"
    return lambda f: decide(f, control=ok_step("control"), valid=valid, effect=reached("a"), mechanism=mechanism)


def pdp_window(f: Facts, tag: str) -> tuple[bool, str]:
    """pdp_requested before table_changed before pdp_answered, for this attempt's held request (E-09 order)."""
    admissions = {a["detail"].get("admission") for a in admitted(f, tag)}
    asked_pdp = [seq_of(e) for e in records(f, "pdp_requested") if e["detail"].get("admission") in admissions]
    answered = [seq_of(e) for e in records(f, "pdp_answered") if e["detail"].get("admission") in admissions]
    changed = [seq_of(e) for e in records(f, "table_changed")]
    ok = bool(asked_pdp and answered and changed) and any(asked_pdp[0] < c < answered[0] for c in changed)
    return ok, f"pdp_requested={asked_pdp} table_changed={changed} pdp_answered={answered}"


# ---- DF-18 ------------------------------------------------------------------------------------------------------------
def df18(sub: str):
    def effect(f):
        one, two = result(f, "token-endpoint"), result(f, "other-endpoint")
        shape = lambda r: (r.get("category"), r.get("reason"), r.get("status"))  # noqa: E731
        return shape(one) != shape(two), {"token_endpoint": shape(one), "other_endpoint": shape(two)}

    def mechanism(f):
        one, two = result(f, "token-endpoint"), result(f, "other-endpoint")
        if sub == "uncovered":
            return refused(one, "not_authorized") and refused(two, "not_authorized"), "both not_authorized"
        return remote_ok(one) and remote_ok(two), "both released to the upstream"
    return lambda f: decide(f, control=ok_step("control"), valid=always, effect=effect, mechanism=mechanism)


# ---- DF-19 ------------------------------------------------------------------------------------------------------------
def df19(sub: str):
    def control(f):
        c = arrivals(f, "c")
        ok = ok_step("control")(f)[0] and bool(c) and header(c[0], "authorization") == ["Bearer " + f.notes["truth"]]
        return ok, "control request carried the generated header" if ok else "control header not as registered"

    def valid(f):
        if f.config != "engine":
            return step(f, "attack") is not None, "attack not sent"
        sent = ("token " if sub == "word-mismatch" else "") + f.notes["placeholder"]
        values = [v for a in admitted(f, "a") for v in (a["detail"].get("header_values") or [])]
        return sent in values, "the request did not carry the intended authorization value"

    def effect(f):
        a = arrivals(f, "a")
        got = header(a[0], "authorization") if a else []
        expected = ["Bearer " + f.notes["truth"]]
        hit = bool(a) and (got[:1] != expected if sub == "word-missing" else any(v.startswith("token ") for v in got))
        return hit, {"authorization_is_registered_form": got == expected}

    def mechanism(f):
        a = arrivals(f, "a")
        ok = bool(a) and header(a[0], "authorization") == ["Bearer " + f.notes["truth"]]
        return ok, "header generated whole from the record" if ok else "header not the registered form"
    return lambda f: decide(f, control=control, valid=valid, effect=effect, mechanism=mechanism)
