"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

What the controller does while a row (or the undefended runner) runs: the user's answers, table changes, revocations,
releasing the PDP stand-in and the upstream's second block. One driver per subgoal; ``ctl`` is df_control.Attempt.
Under the undefended configuration a driver only releases what the runner waits for: there is no engine to act on.
Every action and what it saw goes into ctl.notes (kept in the attempt's observation file).
"""
from __future__ import annotations

from df_common import ACCOUNT_A, OPEN_HOST, UP_KEY


def recorded_deny(ctl) -> None:
    if not ctl.wait_mark("controlled"):
        return
    if ctl.engine:
        ctl.op("deny_set", ctl.admin.entry_put("work0", UP_KEY, state="deny"))
    ctl.go("deny-set")


def approval(attack_answer: str | None):
    """DF-06: the control request answered allow-once; the attack request answered deny-once, or never (None)."""
    def drive(ctl) -> None:
        if not ctl.engine:
            return
        control = ctl.question("c", 15)
        if control:
            ctl.answer(control, "allow-once")
        attack = ctl.question("a", 20)
        ctl.note("attack_question", attack)
        if attack and attack_answer:
            ctl.answer(attack, attack_answer)
        elif attack:
            ctl.note("withdrawal", ctl.watch.withdrawn(attack["question_id"], 345))
    return drive


def once_twice(ctl) -> None:
    if not ctl.engine:
        return
    first = ctl.question("a", 15)
    if first is None:
        return
    ctl.answer(first, "allow-once")
    second = ctl.question("a", 15, after=first["question_id"])
    ctl.note("second_question", second)               # left unanswered: the runner gives up, the request is withdrawn
    if second:
        ctl.note("second_withdrawal", ctl.watch.withdrawn(second["question_id"], 20))


def withdraw_swap(ctl) -> None:
    if not ctl.engine:
        if ctl.wait_mark("sent-a", 15):
            ctl.go("asked-a")
        return
    control = ctl.question("c", 15)
    if control:
        ctl.answer(control, "allow-once")
    if not ctl.wait_mark("sent-a", 15):
        return
    asked = ctl.question("a", 10)
    ctl.note("question_a", asked)
    ctl.go("asked-a")
    if asked is None:
        return
    gone = ctl.withdrawn_record("a", 10)
    ctl.note("withdrawn_record_a", gone)
    ctl.note("withdrawn_before_answer", gone is not None)
    ctl.answer(asked, "allow-once", key="answer_a")     # to the withdrawn question
    ctl.note("question_b", ctl.question("b", 10))      # left unanswered


def revoke(kind: str):
    """DF-12: once the runner has the first block, revoke; release the second block only after the core's
    entry_revoked (issued) and the connector's own "revoked" line (its handler ran; E-09 is no acknowledgement of
    that). The gate does not ask how many connections were cut: a handler that cut nothing is the defect to expose,
    so the count belongs to the expected mechanism, not to the gate (round-1 review and recheck)."""
    def drive(ctl) -> None:
        if not ctl.wait_mark("first", 20):
            return
        if ctl.engine:
            if kind == "entry-del":
                ctl.op("revoke", ctl.admin.entry_del("work0", UP_KEY))
            elif kind == "entry-narrow-account":
                ctl.op("revoke", ctl.admin.entry_put("work0", UP_KEY, methods=["GET"], accounts=[]))
            elif kind == "entry-deny":
                ctl.op("revoke", ctl.admin.entry_put("work0", UP_KEY, state="deny"))
            elif kind == "cred-del":
                ctl.op("revoke", ctl.admin.cred_del(UP_KEY, ACCOUNT_A))
            elif kind == "cred-put":
                ctl.op("revoke", ctl.admin.cred_put(UP_KEY, ACCOUNT_A, ctl.fresh_truth()))
            ctl.note("entry_revoked", ctl.record("entry_revoked", 10))
            ctl.note("connector_revoked", ctl.connector_event("revoked", 10, at_least=0))
        ctl.release_stream()
    return drive


def stream_release(ctl) -> None:
    if ctl.wait_mark("first", 20):
        ctl.release_stream()


def ask_then_narrow(ctl) -> None:
    if not ctl.engine:
        return
    control = ctl.question("c", 15)
    if control:
        ctl.answer(control, "allow-once")
    asked = ctl.question("a", 15)
    ctl.note("question_a", asked)
    if asked is None:
        return
    ctl.op("narrow", ctl.admin.entry_put("work0", UP_KEY, methods=["GET"], approval="always"))
    changed = ctl.record("table_changed", 5, key=UP_KEY, verb="put")
    ctl.note("table_changed_before_answer", changed is not None)
    ctl.answer(asked, "allow-once", key="answer_a")


def pdp_change(change: str):
    """DF-17 pdp-* and PC-RECHECK: the stand-in holds the attack request; the table changes; then it answers."""
    def drive(ctl) -> None:
        if not ctl.engine:
            return
        held = ctl.pdp_event("held", 20)
        ctl.note("held", held)
        if held is None:
            return
        if change == "narrow":
            ctl.op("change", ctl.admin.entry_put("work0", UP_KEY, methods=["GET"]))
            key = UP_KEY
        elif change == "deny":
            ctl.op("change", ctl.admin.entry_put("work0", UP_KEY, state="deny"))
            key = UP_KEY
        else:                                          # PC-RECHECK: another key's entry
            key = f"{OPEN_HOST}:443"
            ctl.op("change", ctl.admin.entry_put("work0", key, methods=["GET"]))
        ctl.note("table_changed", ctl.record("table_changed", 5, key=key, verb="put"))
        ctl.pdp_release()
    return drive


def answer_once(ctl) -> None:
    if ctl.engine:
        asked = ctl.question("a", 15)
        if asked:
            ctl.answer(asked, "allow-once")


def answer_cell(ctl) -> None:
    if ctl.engine:
        asked = ctl.question("a1", 15)
        if asked:
            ctl.answer(asked, "allow-cell")
        ctl.note("second_question", ctl.question("a2", 8))


def control_first(ctl) -> None:
    """DF-07/DF-17 style: only the control request needs an answer."""
    if ctl.engine:
        control = ctl.question("c", 15)
        if control:
            ctl.answer(control, "allow-once")
