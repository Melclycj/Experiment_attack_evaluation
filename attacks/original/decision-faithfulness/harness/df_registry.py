"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The 34 subgoals of the 13 attack numbers and the 7 positive controls (tests.md sections 2 and 4), each with its setup
over the management port, its rows, its controller driver, its judge and its expected mechanism with the location at
a9eff999 (tests.md section 3). The registry is closed: a batch names entries of it and nothing else.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import df_drivers as d
import df_judges as j
from df_common import ACCOUNT_A, ACCOUNT_Y, ATTEMPT_SECONDS, LONG_ATTEMPT_SECONDS, TOKEN_ENDPOINT, UP_KEY
from df_judge import Facts, arrivals, blocks, decided, header, remote_ok, result, runner_problem

MATCH = "engine/matching.py match; engine/hook.py Hook.check; connector/session.py DENY_WORDS (public word)"
# clause 7 at a9eff999: gate one (never connected, named or not) refuses a literal at validation; a private literal the
# covering cell does not name is the table's refusal at the first checkpoint (K-58); a resolved address the same at connect
CLAUSE7 = ("connector/session.py Session._request (IP literal, Policy.never_connect); "
           "connector/upstream.py first_gate, NEVER_CONNECT, interface_addresses, is_local_address")
NOT_NAMED = "engine/hook.py literal_not_named, Hook.check (K-58); connector/session.py DENY_WORDS (public word)"


@dataclass(frozen=True)
class Case:
    id: str
    attack: str
    sub: str
    expected: str                       # the expected blocking mechanism (engine); tests.md 2.x
    location: str                       # its place at a9eff999; tests.md section 3
    judge: Callable[[Facts], dict]
    setup: tuple = ()                   # ("entry", ws, key, kwargs) | ("cred", account, endpoint)
    driver: Callable | None = None
    rows: tuple = (("work0", None),)    # engine rows in order: (workspace, role)
    undefended: bool = True             # False: no counterpart (METHOD rule 3), not run
    pdp: str = "simple"                 # "hold": the stand-in, armed with the attack tag
    limit: float = ATTEMPT_SECONDS
    extra: dict = field(default_factory=dict)
    dns_epoch: bool = False
    mirror: bool = False
    positive: bool = False
    expected_outcome: str = "blocked"


def entry(key: str = UP_KEY, ws: str = "work0", **kw) -> tuple:
    return ("entry", ws, key, kw)


def cred(account: str = ACCOUNT_A, endpoint: str = "") -> tuple:
    return ("cred", account, endpoint)


WITH_A = (cred(), entry(methods=["GET"], accounts=[ACCOUNT_A]))
ASK_POST = (entry(methods=["POST"], approval="always"),)

CASES: list[Case] = [
    Case("DF-01/close-after-read", "DF-01", "close-after-read",
         "one send per allow, no retry: result_unknown to the cell (C-22)", "connector/upstream.py Exchange.run", j.df01),
    Case("DF-03/post-unlisted", "DF-03", "post-unlisted", "no entry covers it: not_authorized (K-08)", MATCH,
         j.df03("post-unlisted")),
    Case("DF-03/method-uncovered", "DF-03", "method-uncovered", "entry does not cover the method: not_authorized",
         MATCH, j.df03("method-uncovered"), setup=(entry(methods=["GET"]),)),
    Case("DF-03/path-uncovered", "DF-03", "path-uncovered", "entry does not cover the path: not_authorized",
         MATCH, j.df03("path-uncovered"), setup=(entry(methods=["POST"], prefixes=["/ok"]),)),
    Case("DF-03/recorded-deny", "DF-03", "recorded-deny", "recorded deny: recorded_deny", MATCH,
         j.df03("recorded-deny"), driver=d.recorded_deny),
    *[Case(f"DF-03/{s}", "DF-03", s, "private IP literal the covering cell does not name: not_authorized at the first "
           "checkpoint (K-58)", NOT_NAMED, j.df03(s)) if s == "ip-private" else
      Case(f"DF-03/{s}", "DF-03", s, "IP literal refused at validation, clause 7 gate one (C-19, C-35)", CLAUSE7,
           j.df03(s)) for s in ("ip-loopback", "ip-private", "ip-linklocal", "ip-interface")],
    Case("DF-03/name-private", "DF-03", "name-private",
         "allowed, then refused before connecting: the resolved address is not global and not named, "
         "not_authorized (C-19)", "connector/upstream.py Policy.refusal, Exchange._connect", j.df03("name-private")),
    Case("DF-03/other-port", "DF-03", "other-port", "the key carries the port; only the fallback covers 8443",
         MATCH, j.df03("other-port"), setup=(entry(methods=["POST"]),)),
    Case("DF-03/other-workspace", "DF-03", "other-workspace", "only the row's own workspace table is read",
         MATCH, j.df03("other-workspace"), setup=(entry(ws="work1", methods=["POST"]),),
         rows=(("work1", "control"), ("work0", "attack"))),
    *[Case(f"DF-05/{s}", "DF-05", s, "the connector does not follow 3xx; the client's follow is a new request to a "
           "private literal no cell names, not_authorized (C-18, K-58)", "connector/upstream.py Exchange._relay; "
           + NOT_NAMED, j.df05(s))
      for s in ("302", "307", "308")],
    Case("DF-06/deny", "DF-06", "deny", "ask every time; the user's deny: user_denied (K-13)",
         "engine/hook.py Hook._ask, Hook.answer", j.df06("deny"), setup=ASK_POST, driver=d.approval("deny-once")),
    Case("DF-06/no-answer", "DF-06", "no-answer", "no answer: withdrawn at the 330 s total limit, timeout (C-15, K-16)",
         "connector/session.py Session._await; engine/hook.py Hook.withdraw", j.df06("no-answer"), setup=ASK_POST,
         driver=d.approval(None), limit=LONG_ATTEMPT_SECONDS),
    Case("DF-07/once-twice", "DF-07", "once-twice", "allow-once covers the one request; the second is asked again",
         "engine/hook.py Hook.answer, Hook._ask", j.df07, setup=ASK_POST, driver=d.once_twice,
         extra={"second_wait": 6}, expected_outcome="escalated"),
    Case("DF-08/withdraw-swap", "DF-08", "withdraw-swap",
         "the answer binds the question; a withdrawn question takes no answer (K-16, K-45)",
         "engine/hook.py Hook.answer, Hook.withdraw", j.df08, setup=ASK_POST, driver=d.withdraw_swap,
         extra={"b_wait": 8}),
    Case("DF-09/rebind", "DF-09", "rebind", "resolved once, whole list filtered, only checked addresses connected (C-19)",
         "connector/upstream.py Exchange.run, Exchange._connect", j.df09, dns_epoch=True),
    Case("DF-10/account-then-none", "DF-10", "account-then-none",
         "upstream connections keyed by host, port, scheme and account (C-21, clause 8)",
         "connector/upstream.py Exchange.run, Exchange.links", j.df10, setup=WITH_A),
    *[Case(f"DF-12/{s}", "DF-12", s, "revocation cuts the account's open upstream connections (K-31, C-26)",
           "engine/hook.py Hook.table_changed, Hook.credential_changed; connector/upstream.py Registry.revoke",
           j.df12, setup=WITH_A, driver=d.revoke(s))
      for s in ("entry-del", "entry-narrow-account", "entry-deny", "cred-del", "cred-put")],
    Case("DF-16/control-verbs", "DF-16", "control-verbs", "the control port's verb set is empty: unsupported_kind (K-04)",
         "engine/phases.py DataPlane._unsupported", j.df16, undefended=False, mirror=True),
    Case("DF-17/ask-then-narrow", "DF-17", "ask-then-narrow",
         "second checkpoint: the cell changed while asking, the answer is void, policy_changed (K-45)",
         "engine/hook.py Hook.answer", j.df17("ask-then-narrow"), setup=ASK_POST, driver=d.ask_then_narrow),
    *[Case(f"DF-17/pdp-{s}", "DF-17", f"pdp-{s}",
           "third checkpoint: versions moved, the cell no longer covers it, policy_changed (K-46)",
           "engine/hook.py Hook._third_checkpoint", j.df17(f"pdp-{s}"), setup=(entry(methods=["POST"]),),
           driver=d.pdp_change(s), pdp="hold") for s in ("narrow", "deny")],
    *[Case(f"DF-18/{s}", "DF-18", s, "clause 10 endpoints come from the row's own accounts (K-25, K-32)",
           "engine/hook.py Hook.check; engine/matching.py usable_accounts, endpoint_hit", j.df18(s), undefended=False,
           setup=(cred(ACCOUNT_Y, TOKEN_ENDPOINT), entry(ws="work1", methods=["POST"], accounts=[ACCOUNT_Y]))
           + ((entry(methods=["POST"]),) if s == "covered" else ()))
      for s in ("uncovered", "covered")],
    *[Case(f"DF-19/{s}", "DF-19", s, "the header value is generated whole from the record (C-16)",
           "connector/upstream.py header_value, placed_headers", j.df19(s), setup=WITH_A)
      for s in ("word-mismatch", "word-missing")],
]


# ---- positive controls (tests.md section 4): engine only; "全部拒绝不算通过" ----------------------------------------
def positive(check):
    def judge(f: Facts) -> dict:
        problem = runner_problem(f)
        if problem:
            return {"outcome": "failed", "why": problem, "observed_mechanism": ""}
        ok, seen = check(f)
        return {"outcome": "passed" if ok else "failed", "why": "" if ok else seen, "observed_mechanism": seen}
    return judge


def once(tag: str = "a", step_name: str = "attack"):
    return lambda f: (remote_ok(result(f, step_name)) and len(arrivals(f, tag)) == 1,
                      f"{step_name}: {result(f, step_name).get('status')} arrivals={len(arrivals(f, tag))}")


def pc_cell(f: Facts):
    ok = remote_ok(result(f, "first")) and remote_ok(result(f, "second")) and not f.notes.get("second_question") \
        and len(arrivals(f, "a1")) == 1 and len(arrivals(f, "a2")) == 1
    return ok, f"second asked={bool(f.notes.get('second_question'))}"


def pc_cred(f: Facts):
    a = arrivals(f, "a")
    ok = once()(f)[0] and header(a[0], "authorization") == ["Bearer " + f.notes["truth"]]
    return ok, "generated header" if ok else "header not the registered form"


def pc_recheck(f: Facts):
    window = j.pdp_window(f, "a")
    return once()(f)[0] and window[0], window[1]


def pc_stream(f: Facts):
    r = result(f, "attack-rest")
    ok = r.get("ended") and f"DF-MARK-{f.nonce}" in r.get("body", "") and \
        any(b.get("block") == 2 and b.get("sent") for b in blocks(f))
    return bool(ok), f"ended={r.get('ended')}"


def pc_fallback(f: Facts):
    keys = {(x["detail"].get("key_kind")) for x in decided(f, "a", "allow")}
    return once()(f)[0] and keys == {3}, f"matched key kinds={sorted(keys)}"


def pc_once(f: Facts):
    bases = {x.get("reason_code") for x in decided(f, "a", "allow")}
    return once()(f)[0] and bases == {"user_allow_once"}, f"bases={sorted(bases)}"


POSITIVE: list[Case] = [
    Case("PC-ALLOW", "PC-ALLOW", "-", "released", MATCH, positive(once()), setup=(entry(methods=["POST"]),),
         undefended=False, positive=True, expected_outcome="passed"),
    Case("PC-FALLBACK", "PC-FALLBACK", "-", "released by the fallback", MATCH, positive(pc_fallback),
         undefended=False, positive=True, expected_outcome="passed"),
    Case("PC-ONCE", "PC-ONCE", "-", "released exactly once", "engine/hook.py Hook.answer", positive(pc_once),
         setup=ASK_POST, driver=d.answer_once, undefended=False, positive=True, expected_outcome="passed"),
    Case("PC-CELL", "PC-CELL", "-", "never asked again", "engine/hook.py Hook._answer_cell", positive(pc_cell),
         setup=ASK_POST, driver=d.answer_cell, undefended=False, positive=True, expected_outcome="passed"),
    Case("PC-CRED", "PC-CRED", "-", "Bearer truth placed", "connector/upstream.py header_value", positive(pc_cred),
         setup=WITH_A, undefended=False, positive=True, expected_outcome="passed"),
    Case("PC-RECHECK", "PC-RECHECK", "-", "versions moved, same cell, released", "engine/hook.py Hook._third_checkpoint",
         positive(pc_recheck), setup=(entry(methods=["POST"]),), driver=d.pdp_change("other-key"), pdp="hold",
         undefended=False, positive=True, expected_outcome="passed"),
    Case("PC-STREAM", "PC-STREAM", "-", "both blocks and RESP_END", "connector/upstream.py Exchange._relay",
         positive(pc_stream), driver=d.stream_release, undefended=False, positive=True, expected_outcome="passed"),
]

REGISTRY = {c.id: c for c in CASES + POSITIVE}
ALWAYS = ("PC-ALLOW", "PC-FALLBACK")                 # every batch (tests.md section 4)
RELATED = {"DF-06": ("PC-ONCE",), "DF-07": ("PC-ONCE", "PC-CELL"), "DF-08": ("PC-ONCE",), "DF-10": ("PC-CRED",),
           "DF-12": ("PC-STREAM", "PC-CRED"), "DF-17": ("PC-RECHECK", "PC-ONCE"), "DF-19": ("PC-CRED",)}


def batch_cases(ids: list[str], controls: bool = True) -> list[Case]:
    """The attack subgoals named, plus the positive controls every batch runs and those related to its attacks.
    A self-check batch on a deliberately wrong engine (controls=False) runs the named subgoals only."""
    unknown = [i for i in ids if i not in REGISTRY]
    if unknown or len(set(ids)) != len(ids):
        raise ValueError(f"not in the registry, or named twice: {unknown or ids}")
    chosen = [REGISTRY[i] for i in ids]
    if not controls:
        return chosen
    controls = list(ALWAYS) + [p for c in chosen for p in RELATED.get(c.attack, ())]
    for pid in controls:
        if pid not in ids:
            ids = [*ids, pid]
            chosen.append(REGISTRY[pid])
    return chosen


def check_registry() -> None:
    """34 subgoals over 13 attack numbers, 7 positive controls (tests.md)."""
    attacks = sorted({c.attack for c in CASES})
    assert len(CASES) == 34, len(CASES)
    assert len(attacks) == 13, attacks
    assert len(POSITIVE) == 7
    assert len(REGISTRY) == 41
